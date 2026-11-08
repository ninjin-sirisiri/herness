//! Host-owned provider stream bridge and ChatGPT model catalog.
//!
//! The pi-ai registry supplies the OpenAI Responses, Anthropic Messages, and
//! OpenAI-compatible chat-completions paths. This module owns the routing
//! decision, resolves the selected connection's credential before every
//! request, and adds the host-only guarantees that are not part of the SDK:
//!
//! * ChatGPT plan usage always goes to the public Responses endpoint and the
//!   public model catalog; it never uses a backend-api endpoint.
//! * A credential failure is returned as a failed assistant message, never as
//!   an empty successful response.
//! * A ChatGPT `length` completion (the Responses API's incomplete result) is
//!   converted to an error because only `response.completed` is success.
//!
//! No pi type is re-exported from this crate.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use herness_core::{
    ArgumentViolation, AuthMethod, ConnectionDirectory, ConnectionId, ConnectionSettings,
    CoreError, CredentialPort, Endpoint, Origin, Provider, ProviderFailureKind,
    RedirectAuthDecision, redirect_auth_decision,
};
use pi_ai::{
    AssistantMessage, AssistantMessageEvent, AssistantMessageEventStream, Context, Model,
    StopReason, StreamOptions, event_channel,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, LOCATION};
use serde_json::Value;

use crate::error::{
    engine_invalid_response, engine_unavailable, provider_failure, provider_status_failure,
};

/// StreamFn type expected by `pi-embedded`/`pi-agent`.
pub(crate) type HostStreamFn =
    Arc<dyn Fn(&Model, &Context, StreamOptions) -> AssistantMessageEventStream + Send + Sync>;

/// Provider base URLs used by the adapter.
///
/// Production hosts use [`Self::official`]. Tests and local integration runs
/// use [`Self::for_loopback`]; a non-loopback override is rejected so an OAuth
/// token cannot be redirected to an arbitrary host by configuration alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoints {
    openai_base: String,
    anthropic_base: String,
}

impl ProviderEndpoints {
    /// The public provider endpoints.
    pub fn official() -> Self {
        Self {
            openai_base: "https://api.openai.com/v1".to_owned(),
            anthropic_base: "https://api.anthropic.com".to_owned(),
        }
    }

    /// Loopback endpoints for integration tests. Both values must resolve to a
    /// loopback host.
    pub fn for_loopback(
        openai_base: impl Into<String>,
        anthropic_base: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let openai = parse_loopback("openaiBase", openai_base.into())?;
        let anthropic = parse_loopback("anthropicBase", anthropic_base.into())?;
        Ok(Self {
            openai_base: openai,
            anthropic_base: anthropic,
        })
    }

    /// OpenAI Responses base URL, including the version path.
    pub fn openai_base(&self) -> &str {
        &self.openai_base
    }

    /// Anthropic Messages base URL.
    pub fn anthropic_base(&self) -> &str {
        &self.anthropic_base
    }

    /// Public ChatGPT model-catalog URL.
    fn models_url(&self) -> String {
        join_url(&self.openai_base, "models")
    }
}

fn parse_loopback(field: &str, value: String) -> Result<String, CoreError> {
    let endpoint = Endpoint::parse(&value).map_err(|_| CoreError::InvalidValue {
        field: field.to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: "must be a valid http(s) URL".to_owned(),
        },
    })?;
    if !endpoint.is_loopback() {
        return Err(CoreError::InvalidValue {
            field: field.to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: "test endpoint must be loopback".to_owned(),
            },
        });
    }
    Ok(endpoint.as_url())
}

fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// One ChatGPT model the selected account may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatGptModel {
    slug: String,
    display_name: String,
}

impl ChatGptModel {
    /// Value to send as `model` on a Responses request.
    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Human-facing name from the catalog.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Public model catalog for a ChatGPT-login connection.
pub(crate) struct ChatGptCatalog {
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    endpoints: ProviderEndpoints,
    client: reqwest::Client,
}

impl ChatGptCatalog {
    /// Creates a catalog client. Redirects are handled explicitly so an
    /// `Authorization` header is never forwarded to a different origin.
    pub(crate) fn new(
        credentials: Arc<dyn CredentialPort + Send + Sync>,
        directory: ConnectionDirectory,
        endpoints: ProviderEndpoints,
    ) -> Result<Self, CoreError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| engine_unavailable())?;
        Ok(Self {
            credentials,
            directory,
            endpoints,
            client,
        })
    }

    /// Fetches the selected account's model catalog. Only entries whose
    /// `visibility` is exactly `list` are returned, in server order, using
    /// `slug` as the model identifier.
    pub(crate) async fn list(
        &self,
        connection: ConnectionId,
    ) -> Result<Vec<ChatGptModel>, CoreError> {
        let settings = self
            .directory
            .get(connection)
            .map_err(|_| engine_invalid_response())?;
        if settings.auth_method() != AuthMethod::ChatGptLogin {
            return Err(engine_invalid_response());
        }
        let credential = self.credentials.resolve(&connection)?;
        let token = credential.expose_secret();
        let body = self.get_json(&self.endpoints.models_url(), token).await?;
        parse_catalog(&body)
    }

    async fn get_json(&self, url: &str, token: &str) -> Result<String, CoreError> {
        let mut current = url.to_owned();
        for _ in 0..5 {
            let response = self
                .client
                .get(&current)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(ACCEPT, "application/json")
                .send()
                .await
                .map_err(|_| provider_failure(Provider::OpenAi, ProviderFailureKind::Network))?;
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        provider_failure(Provider::OpenAi, ProviderFailureKind::InvalidResponse)
                    })?;
                let origin = Origin::parse(&current).map_err(|_| {
                    provider_failure(Provider::OpenAi, ProviderFailureKind::InvalidResponse)
                })?;
                match redirect_auth_decision(&origin, location) {
                    RedirectAuthDecision::AttachAuthorization => {
                        current = location.to_owned();
                        continue;
                    }
                    RedirectAuthDecision::DropAuthorization { .. } => {
                        // The next origin would need its own credential and
                        // authorization decision. Never resend this one.
                        return Err(provider_failure(
                            Provider::OpenAi,
                            ProviderFailureKind::Authentication,
                        ));
                    }
                }
            }
            if !(200..300).contains(&status) {
                return Err(provider_failure(
                    Provider::OpenAi,
                    provider_status_failure(status),
                ));
            }
            return response
                .text()
                .await
                .map_err(|_| provider_failure(Provider::OpenAi, ProviderFailureKind::Network));
        }
        Err(provider_failure(
            Provider::OpenAi,
            ProviderFailureKind::Network,
        ))
    }
}

fn parse_catalog(body: &str) -> Result<Vec<ChatGptModel>, CoreError> {
    let value: Value = serde_json::from_str(body).map_err(|_| engine_invalid_response())?;
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(engine_invalid_response)?;
    let mut result = Vec::new();
    for model in models {
        if model.get("visibility").and_then(Value::as_str) != Some("list") {
            continue;
        }
        let Some(slug) = model.get("slug").and_then(Value::as_str) else {
            continue;
        };
        let slug = slug.trim();
        if slug.is_empty()
            || slug.chars().any(char::is_control)
            || slug.chars().any(char::is_whitespace)
        {
            continue;
        }
        let display_name = model
            .get("display_name")
            .or_else(|| model.get("displayName"))
            .and_then(Value::as_str)
            .unwrap_or(slug)
            .trim();
        result.push(ChatGptModel {
            slug: slug.to_owned(),
            display_name: if display_name.is_empty() {
                slug.to_owned()
            } else {
                display_name.to_owned()
            },
        });
    }
    Ok(result)
}

/// Builds the pi-ai model description for one connection.
pub(crate) fn model_for(
    settings: &ConnectionSettings,
    endpoints: &ProviderEndpoints,
) -> Result<Model, CoreError> {
    let (api, provider, base_url) = match settings.provider() {
        Provider::OpenAi => (
            "openai-responses",
            "openai",
            endpoints.openai_base().to_owned(),
        ),
        Provider::Anthropic => (
            "anthropic-messages",
            "anthropic",
            endpoints.anthropic_base().to_owned(),
        ),
        Provider::OpenAiCompatible => (
            "openai-completions",
            "openai-compatible",
            settings
                .endpoint()
                .ok_or_else(engine_invalid_response)?
                .as_url(),
        ),
    };
    Ok(Model {
        id: settings.model().to_owned(),
        name: settings.model().to_owned(),
        api: api.to_owned(),
        provider: provider.to_owned(),
        base_url,
        max_tokens: 4096,
        context_window: 128_000,
        ..Model::default()
    })
}

/// Per-run provider bridge. The connection settings are frozen at run start;
/// only the credential is resolved again for every request.
pub(crate) struct StreamBridge {
    connection: ConnectionId,
    chatgpt: bool,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
}

impl StreamBridge {
    pub(crate) fn new(
        connection: ConnectionId,
        settings: &ConnectionSettings,
        credentials: Arc<dyn CredentialPort + Send + Sync>,
    ) -> Self {
        Self {
            connection,
            chatgpt: settings.auth_method() == AuthMethod::ChatGptLogin,
            credentials,
        }
    }

    pub(crate) fn stream_fn(self: Arc<Self>) -> HostStreamFn {
        Arc::new(
            move |model: &Model, context: &Context, options: StreamOptions| {
                let secret = match self.credentials.resolve(&self.connection) {
                    Ok(credential) => credential.expose_secret().to_owned(),
                    Err(error) => return credential_error_stream(model, &error),
                };
                let mut options = options.clone();
                options.api_key = Some(secret);
                // A hidden provider retry could duplicate a request that the host
                // already recorded. Retries are a host decision, not an SDK one.
                options.max_retries = Some(0);
                options.timeout_ms = Some(120_000);
                let inner = pi_ai::stream(model, context, options);
                if !self.chatgpt {
                    return inner;
                }
                let (sender, output) = event_channel();
                let model = model.clone();
                tokio::spawn(async move {
                    let mut inner = inner;
                    let mut terminal = false;
                    while let Some(event) = inner.next().await {
                        match event {
                            AssistantMessageEvent::Done {
                                reason: StopReason::Length,
                                message,
                            } => {
                                let mut error = message;
                                error.stop_reason = StopReason::Error;
                                error.error_message =
                                    Some("ChatGPT response was incomplete".to_owned());
                                sender.push(AssistantMessageEvent::Error {
                                    reason: StopReason::Error,
                                    error,
                                });
                                return;
                            }
                            AssistantMessageEvent::Done { .. }
                            | AssistantMessageEvent::Error { .. } => {
                                terminal = true;
                                sender.push(event);
                            }
                            other => sender.push(other),
                        }
                    }
                    if !terminal {
                        sender.push(AssistantMessageEvent::Error {
                            reason: StopReason::Error,
                            error: failed_message(
                                &model,
                                "provider stream ended without a completion event",
                            ),
                        });
                    }
                });
                output
            },
        )
    }
}

fn credential_error_stream(model: &Model, error: &CoreError) -> AssistantMessageEventStream {
    let message = match error {
        CoreError::AuthenticationRequired { .. } => "provider authentication required",
        CoreError::CredentialUnavailable { .. } => "provider credential unavailable",
        _ => "provider credential could not be resolved",
    };
    pi_ai::error_stream(model, StopReason::Error, message)
}

pub(crate) fn failed_message(model: &Model, message: &str) -> AssistantMessage {
    let mut error = AssistantMessage::empty(model);
    error.stop_reason = StopReason::Error;
    error.error_message = Some(message.to_owned());
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_keeps_only_listed_slugs_in_server_order() {
        let body = serde_json::json!({
            "models": [
                {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"},
                {"slug": "hidden-model", "display_name": "Hidden", "visibility": "none"},
                {"slug": "gpt-6.1-mini", "display_name": "GPT 6.1 Mini", "visibility": "list"},
                {"display_name": "No slug", "visibility": "list"},
                {"slug": "bad slug", "display_name": "Bad", "visibility": "list"}
            ]
        })
        .to_string();
        let models = parse_catalog(&body).expect("catalog");
        assert_eq!(
            models.iter().map(ChatGptModel::slug).collect::<Vec<_>>(),
            vec!["gpt-6.1-sol", "gpt-6.1-mini"]
        );
        assert_eq!(models[0].display_name(), "GPT 6.1 Sol");
    }

    #[test]
    fn catalog_rejects_a_response_without_a_models_array() {
        let error = parse_catalog(r#"{"data":[]}"#).expect_err("must reject");
        assert!(matches!(
            error,
            CoreError::EngineUnavailable {
                failure: herness_core::EngineFailureKind::InvalidResponse
            }
        ));
    }

    #[test]
    fn loopback_endpoint_override_rejects_a_remote_host() {
        let error =
            ProviderEndpoints::for_loopback("https://api.openai.com/v1", "http://127.0.0.1:1234")
                .expect_err("remote override must be rejected");
        assert!(matches!(error, CoreError::InvalidValue { .. }));
    }

    #[test]
    fn models_url_joins_the_version_path_once() {
        let endpoints =
            ProviderEndpoints::for_loopback("http://127.0.0.1:8080/v1", "http://127.0.0.1:8081")
                .expect("loopback");
        assert_eq!(endpoints.models_url(), "http://127.0.0.1:8080/v1/models");
    }

    #[test]
    fn model_for_maps_every_provider_to_its_wire_api() {
        let endpoints = ProviderEndpoints::official();
        let openai = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("openai");
        assert_eq!(
            model_for(&openai, &endpoints).unwrap().api,
            "openai-responses"
        );
        let anthropic = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::Anthropic,
            "claude-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("anthropic");
        assert_eq!(
            model_for(&anthropic, &endpoints).unwrap().api,
            "anthropic-messages"
        );
        let compatible = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAiCompatible,
            "local-test",
            AuthMethod::ApiKey,
            Some(Endpoint::parse("http://127.0.0.1:11434/v1").expect("endpoint")),
            None,
        )
        .expect("compatible");
        assert_eq!(
            model_for(&compatible, &endpoints).unwrap().api,
            "openai-completions"
        );
    }
}
