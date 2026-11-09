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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use herness_core::{
    AgentId, ArgumentViolation, AttemptId, AuthMethod, ConnectionDirectory, ConnectionId,
    ConnectionSettings, CoreError, CredentialPort, Endpoint, EndpointClass, EventSubject, ModelId,
    ModelRequestGatePort, ModelRequestObservation, Origin, ProjectId, Provider,
    ProviderFailureKind, RedirectAuthDecision, RequestGateIntent, RequestGateOutcome, RequestId,
    RequestOutcome, RequestPurpose, RunControl, RunId, RunSubject, SessionId, TokenCount,
    TokenUsage, redirect_auth_decision,
};
use pi_ai::{
    AssistantMessage, AssistantMessageEvent, AssistantMessageEventStream, Context, Model,
    StopReason, StreamOptions, event_channel,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, LOCATION};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
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
    let capabilities = settings
        .capabilities()
        .map_err(|_| provider_failure(settings.provider(), ProviderFailureKind::Refused))?;
    if !capabilities.allows_agent_execution() {
        // An assessment-only connection must never start or continue an agent
        // run, even when its provider has an agent wire format.
        return Err(provider_failure(
            capabilities.provider(),
            ProviderFailureKind::Refused,
        ));
    }
    let (api, provider, base_url) = match capabilities.endpoint_class() {
        EndpointClass::OpenAiResponses => (
            "openai-responses",
            "openai",
            endpoints.openai_base().to_owned(),
        ),
        EndpointClass::AnthropicMessages => (
            "anthropic-messages",
            "anthropic",
            endpoints.anthropic_base().to_owned(),
        ),
        EndpointClass::OpenAiCompletions => (
            "openai-completions",
            "openai-compatible",
            settings
                .endpoint()
                .ok_or_else(engine_invalid_response)?
                .as_url(),
        ),
        // TypeSafe System One and OpenAI Decisions are assessment-only. Any
        // capability/usage mismatch is a refusal, never a silent switch.
        EndpointClass::TypeSafeSystemOne | EndpointClass::OpenAiDecisions => {
            return Err(provider_failure(
                capabilities.provider(),
                ProviderFailureKind::Refused,
            ));
        }
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

/// Injected pre-send gate shared by every stream invocation in this engine.
pub(crate) type SharedRequestGate = Arc<Mutex<Box<dyn ModelRequestGatePort + Send>>>;

/// Purpose label recorded for a normal supervised agent run request.
const AGENT_RUN_PURPOSE: &str = "agent_run";

/// Per-run provider bridge. The connection settings are frozen at run start;
/// only the credential is resolved again for every request.
pub(crate) struct StreamBridge {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
    connection: ConnectionId,
    chatgpt: bool,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    control: RunControl,
    gate: SharedRequestGate,
}

impl StreamBridge {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
        connection: ConnectionId,
        settings: &ConnectionSettings,
        credentials: Arc<dyn CredentialPort + Send + Sync>,
        control: RunControl,
        gate: SharedRequestGate,
    ) -> Self {
        Self {
            project_id,
            agent_id,
            session_id,
            run_id,
            connection,
            chatgpt: settings.auth_method() == AuthMethod::ChatGptLogin,
            credentials,
            control,
            gate,
        }
    }

    pub(crate) fn stream_fn(self: Arc<Self>) -> HostStreamFn {
        Arc::new(
            move |model: &Model, context: &Context, options: StreamOptions| {
                let request_id = RequestId::new(self.project_id);
                let attempt_id = AttemptId::new(self.project_id);
                let control = self.control.snapshot();
                let subject = match RunSubject::new(
                    self.project_id,
                    self.agent_id,
                    self.session_id,
                    self.run_id,
                ) {
                    Ok(subject) => EventSubject::Run(subject),
                    Err(_) => return failure_stream(model, "model request subject is unavailable"),
                };
                let purpose = match RequestPurpose::new(AGENT_RUN_PURPOSE) {
                    Ok(purpose) => purpose,
                    Err(_) => return failure_stream(model, "model request purpose is unavailable"),
                };
                let intent = match RequestGateIntent::new(
                    request_id,
                    attempt_id,
                    self.connection,
                    purpose,
                    subject,
                    control,
                ) {
                    Ok(intent) => intent,
                    Err(_) => return failure_stream(model, "model request intent is invalid"),
                };
                if !control.permits_send() {
                    return failure_stream(model, "model request stopped before send");
                }
                match admit_request(&self.gate, &intent) {
                    Err(_) => {
                        return failure_stream(
                            model,
                            "model request was not admitted by the host gate",
                        );
                    }
                    Ok(RequestGateOutcome::Refuse { .. }) => {
                        record_preflight_failure(
                            &self.gate,
                            request_id,
                            attempt_id,
                            ProviderFailureKind::Refused,
                        );
                        return failure_stream(model, "model request was refused by the host gate");
                    }
                    Ok(RequestGateOutcome::Admit) => {}
                }

                let secret = match self.credentials.resolve(&self.connection) {
                    Ok(credential) => credential.expose_secret().to_owned(),
                    Err(error) => {
                        record_preflight_failure(
                            &self.gate,
                            request_id,
                            attempt_id,
                            credential_failure_kind(&error),
                        );
                        return credential_error_stream(model, &error);
                    }
                };

                // The intent is durable. Sending may start only after the
                // send-started observation is durable too.
                if !record_observation(
                    &self.gate,
                    ModelRequestObservation::new(
                        request_id,
                        attempt_id,
                        RequestOutcome::SendStarted,
                        None,
                        None,
                        TokenUsage::unknown(),
                    ),
                ) {
                    return failure_stream(
                        model,
                        "model request observation could not be persisted",
                    );
                }
                // A stop or deadline can arrive while the credential was being
                // resolved. Re-check the shared control immediately before the
                // provider call; no HTTP request may start after this point.
                if !self.control.permits_side_effect() {
                    let _ = record_observation(
                        &self.gate,
                        ModelRequestObservation::new(
                            request_id,
                            attempt_id,
                            RequestOutcome::Cancelled,
                            None,
                            None,
                            TokenUsage::unknown(),
                        ),
                    );
                    return failure_stream(model, "model request stopped before send");
                }

                let mut options = options.clone();
                options.api_key = Some(secret);
                // A hidden provider retry could duplicate a request that the host
                // already recorded. Retries are a host decision, not an SDK one.
                options.max_retries = Some(0);
                options.timeout_ms = Some(120_000);

                let usage = Arc::new(Mutex::new(UsageTracker::default()));
                let prior_hook = options.on_provider_stream_event.take();
                {
                    let usage = Arc::clone(&usage);
                    options.on_provider_stream_event =
                        Some(Arc::new(move |event: &Value, model: &Model| {
                            usage
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .observe(event);
                            if let Some(hook) = &prior_hook {
                                hook(event, model);
                            }
                        }));
                }
                let cancel = options.cancel.clone();
                let inner = pi_ai::stream(model, context, options);
                let (sender, output) = event_channel();
                let model = model.clone();
                let chatgpt = self.chatgpt;
                let gate = Arc::clone(&self.gate);
                let control = self.control.clone();
                tokio::spawn(async move {
                    drive_stream(
                        inner, sender, model, chatgpt, gate, control, cancel, request_id,
                        attempt_id, usage,
                    )
                    .await;
                });
                output
            },
        )
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_stream(
    mut inner: AssistantMessageEventStream,
    sender: pi_ai::EventSender,
    model: Model,
    chatgpt: bool,
    gate: SharedRequestGate,
    control: RunControl,
    cancel: CancellationToken,
    request_id: RequestId,
    attempt_id: AttemptId,
    usage: Arc<Mutex<UsageTracker>>,
) {
    while let Some(event) = inner.next().await {
        let event = if chatgpt {
            match event {
                AssistantMessageEvent::Done {
                    reason: StopReason::Length,
                    message,
                } => {
                    let mut error = message;
                    error.stop_reason = StopReason::Error;
                    error.error_message = Some("ChatGPT response was incomplete".to_owned());
                    AssistantMessageEvent::Error {
                        reason: StopReason::Error,
                        error,
                    }
                }
                other => other,
            }
        } else {
            event
        };
        match event {
            AssistantMessageEvent::Done { reason, message } => {
                let snapshot = control.snapshot();
                let cancelled = cancel.is_cancelled()
                    || !snapshot.permits_send()
                    || matches!(message.stop_reason, StopReason::Aborted);
                let failed = matches!(message.stop_reason, StopReason::Error);
                let (outcome, failure) = if cancelled {
                    (RequestOutcome::Cancelled, None)
                } else if failed {
                    (
                        RequestOutcome::SendResultUnknown,
                        Some(ProviderFailureKind::Unknown),
                    )
                } else {
                    (RequestOutcome::Completed, None)
                };
                let observed_usage = if outcome == RequestOutcome::Completed {
                    usage
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .usage(&message)
                } else {
                    TokenUsage::unknown()
                };
                let observation = ModelRequestObservation::new(
                    request_id,
                    attempt_id,
                    outcome,
                    failure,
                    model_id(&message),
                    observed_usage,
                );
                if !record_observation(&gate, observation) {
                    sender.push(AssistantMessageEvent::Error {
                        reason: StopReason::Error,
                        error: failed_message(
                            &model,
                            "model request observation could not be persisted",
                        ),
                    });
                    return;
                }
                sender.push(AssistantMessageEvent::Done { reason, message });
                return;
            }
            AssistantMessageEvent::Error { reason, error } => {
                let snapshot = control.snapshot();
                let cancelled = matches!(error.stop_reason, StopReason::Aborted)
                    || cancel.is_cancelled()
                    || !snapshot.permits_send();
                let (outcome, failure) = if cancelled {
                    (RequestOutcome::Cancelled, None)
                } else {
                    (
                        RequestOutcome::SendResultUnknown,
                        Some(ProviderFailureKind::Unknown),
                    )
                };
                let observation = ModelRequestObservation::new(
                    request_id,
                    attempt_id,
                    outcome,
                    failure,
                    reported_model_id(&error),
                    TokenUsage::unknown(),
                );
                if !record_observation(&gate, observation) {
                    sender.push(AssistantMessageEvent::Error {
                        reason: StopReason::Error,
                        error: failed_message(
                            &model,
                            "model request observation could not be persisted",
                        ),
                    });
                    return;
                }
                sender.push(AssistantMessageEvent::Error { reason, error });
                return;
            }
            other => sender.push(other),
        }
    }
    let _ = record_observation(
        &gate,
        ModelRequestObservation::new(
            request_id,
            attempt_id,
            RequestOutcome::SendResultUnknown,
            Some(ProviderFailureKind::Unknown),
            None,
            TokenUsage::unknown(),
        ),
    );
    sender.push(AssistantMessageEvent::Error {
        reason: StopReason::Error,
        error: failed_message(&model, "provider stream ended without a completion event"),
    });
}

fn admit_request(
    gate: &SharedRequestGate,
    intent: &RequestGateIntent,
) -> Result<RequestGateOutcome, CoreError> {
    gate.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .admit(intent)
}

fn record_observation(
    gate: &SharedRequestGate,
    observation: Result<ModelRequestObservation, CoreError>,
) -> bool {
    let Ok(observation) = observation else {
        return false;
    };
    gate.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe(&observation)
        .is_ok()
}

fn record_preflight_failure(
    gate: &SharedRequestGate,
    request_id: RequestId,
    attempt_id: AttemptId,
    failure: ProviderFailureKind,
) {
    // A refusal may happen before the intent is durable. The observation then
    // fails explicitly; it must never turn into a fabricated send or usage.
    let _ = record_observation(
        gate,
        ModelRequestObservation::new(
            request_id,
            attempt_id,
            RequestOutcome::PreflightFailed,
            Some(failure),
            None,
            TokenUsage::unknown(),
        ),
    );
}

fn credential_failure_kind(error: &CoreError) -> ProviderFailureKind {
    match error {
        CoreError::AuthenticationRequired { .. } | CoreError::CredentialUnavailable { .. } => {
            ProviderFailureKind::Authentication
        }
        _ => ProviderFailureKind::Unknown,
    }
}

fn model_id(message: &AssistantMessage) -> Option<ModelId> {
    message
        .response_model
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| (!message.model.trim().is_empty()).then_some(message.model.as_str()))
        .and_then(|value| ModelId::new(value).ok())
}

fn reported_model_id(message: &AssistantMessage) -> Option<ModelId> {
    message
        .response_model
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| ModelId::new(value).ok())
}

/// Usage fields actually reported by the provider stream.
///
/// `pi_ai::Usage` uses plain `u64` values, so a missing field is
/// indistinguishable from a reported zero in the terminal message. This tracker
/// observes the raw provider events before normalization and remembers which
/// fields were present.
#[derive(Debug, Default)]
struct UsageTracker {
    input: Option<u64>,
    output: Option<u64>,
    cache_read: Option<u64>,
    cache_write: Option<u64>,
}

impl UsageTracker {
    fn observe(&mut self, event: &Value) {
        self.visit(event);
    }

    fn visit(&mut self, value: &Value) {
        match value {
            Value::Object(map) => {
                if let Some(usage) = map.get("usage").filter(|value| value.is_object()) {
                    self.apply(usage);
                }
                for child in map.values() {
                    self.visit(child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.visit(item);
                }
            }
            _ => {}
        }
    }

    fn apply(&mut self, usage: &Value) {
        if let Some(value) = first_u64(usage, &["/input_tokens", "/prompt_tokens"]) {
            self.input = Some(value);
        }
        if let Some(value) = first_u64(usage, &["/output_tokens", "/completion_tokens"]) {
            self.output = Some(value);
        }
        if let Some(value) = first_u64(
            usage,
            &[
                "/cache_read_input_tokens",
                "/input_tokens_details/cached_tokens",
                "/prompt_tokens_details/cached_tokens",
                "/cached_tokens",
                "/prompt_cache_hit_tokens",
            ],
        ) {
            self.cache_read = Some(value);
        }
        if let Some(value) = first_u64(
            usage,
            &[
                "/cache_creation_input_tokens",
                "/input_tokens_details/cache_write_tokens",
                "/prompt_tokens_details/cache_write_tokens",
                "/cache_write_tokens",
            ],
        ) {
            self.cache_write = Some(value);
        }
    }

    fn usage(&self, message: &AssistantMessage) -> TokenUsage {
        TokenUsage::new(
            reported_count(self.input, message.usage.input),
            reported_count(self.output, message.usage.output),
            reported_count(self.cache_read, message.usage.cache_read),
            reported_count(self.cache_write, message.usage.cache_write),
        )
    }
}

fn first_u64(value: &Value, pointers: &[&str]) -> Option<u64> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_u64))
}

fn reported_count(tracked: Option<u64>, reported: u64) -> TokenCount {
    match tracked {
        Some(_) => TokenCount::Known(reported),
        // A non-zero value must have come from the provider even if this
        // tracker did not recognize the event shape. Zero stays unknown because
        // it may be the SDK's default rather than a reported count.
        None if reported > 0 => TokenCount::Known(reported),
        None => TokenCount::Unknown,
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

fn failure_stream(model: &Model, message: &str) -> AssistantMessageEventStream {
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
    fn assessment_only_connections_never_build_an_agent_model() {
        use herness_core::{
            ConnectionCapabilityDeclaration, EndpointClass, InputCapabilities, Provider,
        };

        let endpoints =
            ProviderEndpoints::for_loopback("http://127.0.0.1:18080/v1", "http://127.0.0.1:18081")
                .unwrap();
        let jev = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::TypeSafe,
            "jev-1.14.0",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .unwrap();
        assert!(
            model_for(&jev, &endpoints).is_err(),
            "Jev System One must not start an agent run"
        );

        let decisions = ConnectionSettings::new_with_capabilities(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-6-luna",
            AuthMethod::ApiKey,
            None,
            None,
            ConnectionCapabilityDeclaration::new(
                EndpointClass::OpenAiDecisions,
                InputCapabilities::text_only(),
            ),
        )
        .unwrap();
        assert!(
            model_for(&decisions, &endpoints).is_err(),
            "OpenAI Decisions must not start an agent run"
        );

        let openai = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .unwrap();
        assert!(model_for(&openai, &endpoints).is_ok());
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
