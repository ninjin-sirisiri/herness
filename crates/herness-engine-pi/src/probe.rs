//! Opt-in real provider probe used by `herness-desktop --real-check`.
//!
//! Nothing in the engine, trusted UI, or normal test suite calls this module.
//! The desktop binary reaches it only through the explicit Phase B controller
//! command, after the human has approved the selected connection, model, and
//! synthetic prompt.
//!
//! The probe sends one minimal single-turn text request through the same
//! `pi-ai` provider routes the engine uses. It never falls back to another
//! provider or model, never retries, and returns only sanitized outcome data.
//! Provider error text, response bodies, token material, and raw URLs are not
//! part of any returned value.

use std::sync::Arc;
use std::time::Instant;

use herness_core::{
    AuthMethod, ConnectionDirectory, ConnectionId, ConnectionSettings, CoreError, CredentialPort,
    Provider,
};
use pi_ai::{Context, Message, StopReason, StreamOptions, UserContent, UserMessage, now_ms};

use crate::stream::{ChatGptCatalog, ProviderEndpoints, model_for};

/// Synthetic prompt sent by the opt-in probe.
///
/// Phase B presents this exact string to the human before approval.
pub const REAL_CHECK_PROMPT: &str = "Reply with the single word: herness-ok.";

/// Maximum output tokens requested by the probe.
pub const REAL_CHECK_MAX_OUTPUT_TOKENS: u64 = 32;

/// Sanitized request terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeTerminal {
    /// The provider completed a normal turn.
    Completed,
    /// The response ended at the length limit rather than a completed turn.
    Incomplete,
}

impl ProbeTerminal {
    /// Stable evidence label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Token usage reported by the provider, when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeUsage {
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Total billed tokens as reported by the provider.
    pub total_tokens: u64,
}

/// Sanitized result of one real provider request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// Selected provider.
    pub provider: Provider,
    /// Selected model, never substituted.
    pub model: String,
    /// Wire route label.
    pub endpoint_class: &'static str,
    /// Non-secret endpoint origin for a user-supplied compatible endpoint.
    pub endpoint_origin: Option<String>,
    /// Request terminal.
    pub terminal: ProbeTerminal,
    /// Model-request latency.
    pub latency_ms: u64,
    /// ChatGPT catalog latency, when the catalog was fetched.
    pub catalog_latency_ms: Option<u64>,
    /// Number of selectable catalog models, when fetched.
    pub catalog_model_count: Option<usize>,
    /// Provider-reported usage, when available.
    pub usage: Option<ProbeUsage>,
}

/// Sanitized probe failure. No variant carries provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    /// The connection id is not registered.
    ConnectionNotFound,
    /// The requested mode is not valid for this provider/auth combination.
    UnsupportedConnection,
    /// The selected model is absent from the account's model catalog.
    ModelNotInCatalog,
    /// No credential is stored for the connection.
    AuthenticationRequired,
    /// The credential is expired, unreadable, or could not be refreshed.
    CredentialUnavailable,
    /// The provider request failed, was aborted, or ended without a completion.
    ProviderFailed,
    /// The adapter could not build the request.
    Internal,
}

impl ProbeFailure {
    /// Stable evidence label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionNotFound => "connection_not_found",
            Self::UnsupportedConnection => "unsupported_connection",
            Self::ModelNotInCatalog => "model_not_in_catalog",
            Self::AuthenticationRequired => "authentication_required",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::ProviderFailed => "provider_failed",
            Self::Internal => "internal_error",
        }
    }

    /// Whether the failure is a missing or unusable credential.
    pub const fn is_auth_failure(self) -> bool {
        matches!(
            self,
            Self::AuthenticationRequired | Self::CredentialUnavailable
        )
    }

    /// Whether the failure is a configuration or model-selection problem.
    pub const fn is_configuration_failure(self) -> bool {
        matches!(
            self,
            Self::ConnectionNotFound | Self::UnsupportedConnection | Self::ModelNotInCatalog
        )
    }
}

/// Lists the ChatGPT model catalog without sending a model request.
///
/// Only models whose `visibility` is exactly `list` are returned, in server
/// order. Non-ChatGPT connections are rejected rather than guessed.
pub fn list_chatgpt_models(
    directory: &ConnectionDirectory,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    endpoints: &ProviderEndpoints,
    connection: ConnectionId,
) -> Result<Vec<crate::ChatGptModel>, ProbeFailure> {
    let settings = directory
        .get(connection)
        .map_err(|_| ProbeFailure::ConnectionNotFound)?;
    if settings.auth_method() != AuthMethod::ChatGptLogin {
        return Err(ProbeFailure::UnsupportedConnection);
    }
    let runtime = build_runtime()?;
    let catalog = ChatGptCatalog::new(credentials, directory.clone(), endpoints.clone())
        .map_err(|_| ProbeFailure::Internal)?;
    runtime
        .block_on(catalog.list(connection))
        .map_err(classify_core_error)
}

/// Sends one minimal request through the selected connection.
pub fn probe_connection(
    directory: &ConnectionDirectory,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    endpoints: &ProviderEndpoints,
    connection: ConnectionId,
) -> Result<ProbeOutcome, ProbeFailure> {
    let settings = directory
        .get(connection)
        .map_err(|_| ProbeFailure::ConnectionNotFound)?;
    // Resolve before any provider call so a missing credential always fails
    // without contacting the network.
    let resolved = credentials
        .resolve(&connection)
        .map_err(classify_core_error)?;
    let api_key = resolved.expose_secret().to_owned();
    let runtime = build_runtime()?;
    let model = model_for(&settings, endpoints).map_err(|_| ProbeFailure::Internal)?;

    let mut catalog_latency_ms = None;
    let mut catalog_model_count = None;
    if settings.auth_method() == AuthMethod::ChatGptLogin {
        let catalog = ChatGptCatalog::new(
            Arc::clone(&credentials),
            directory.clone(),
            endpoints.clone(),
        )
        .map_err(|_| ProbeFailure::Internal)?;
        let started = Instant::now();
        let models = runtime
            .block_on(catalog.list(connection))
            .map_err(classify_core_error)?;
        catalog_latency_ms = Some(elapsed_millis(started));
        catalog_model_count = Some(models.len());
        if !models
            .iter()
            .any(|candidate| candidate.slug() == settings.model())
        {
            // Never substitute another catalog entry.
            return Err(ProbeFailure::ModelNotInCatalog);
        }
    }

    let context = Context {
        system_prompt: None,
        messages: vec![Message::User(UserMessage {
            content: UserContent::Text(REAL_CHECK_PROMPT.to_owned()),
            timestamp: now_ms(),
        })],
        tools: Vec::new(),
    };
    let options = StreamOptions {
        api_key: Some(api_key),
        max_tokens: Some(REAL_CHECK_MAX_OUTPUT_TOKENS),
        // A hidden provider retry could duplicate a real request. Retrying is a
        // human decision, so the probe never does it.
        max_retries: Some(0),
        timeout_ms: Some(120_000),
        ..StreamOptions::default()
    };

    let started = Instant::now();
    let message = runtime.block_on(async {
        pi_ai::stream(&model, &context, options)
            .result(&model)
            .await
    });
    let latency_ms = elapsed_millis(started);
    let terminal = match message.stop_reason {
        StopReason::Stop => ProbeTerminal::Completed,
        StopReason::Length => ProbeTerminal::Incomplete,
        // The provider error text is deliberately dropped.
        StopReason::Error
        | StopReason::Aborted
        | StopReason::Pending
        | StopReason::Deferred
        | StopReason::ToolUse => return Err(ProbeFailure::ProviderFailed),
    };
    let usage =
        (message.usage.input > 0 || message.usage.output > 0 || message.usage.total_tokens > 0)
            .then_some(ProbeUsage {
                input_tokens: message.usage.input,
                output_tokens: message.usage.output,
                total_tokens: message.usage.total_tokens,
            });

    Ok(ProbeOutcome {
        provider: settings.provider(),
        model: settings.model().to_owned(),
        endpoint_class: endpoint_class(&settings),
        endpoint_origin: endpoint_origin(&settings),
        terminal,
        latency_ms,
        catalog_latency_ms,
        catalog_model_count,
        usage,
    })
}

fn build_runtime() -> Result<tokio::runtime::Runtime, ProbeFailure> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("herness-real-probe")
        .build()
        .map_err(|_| ProbeFailure::Internal)
}

fn classify_core_error(error: CoreError) -> ProbeFailure {
    match error {
        CoreError::AuthenticationRequired { .. } => ProbeFailure::AuthenticationRequired,
        CoreError::CredentialUnavailable { .. } => ProbeFailure::CredentialUnavailable,
        CoreError::EngineUnavailable { .. } => ProbeFailure::ProviderFailed,
        _ => ProbeFailure::Internal,
    }
}

/// Wire route label for one selected connection.
pub const fn endpoint_class(settings: &ConnectionSettings) -> &'static str {
    match (settings.provider(), settings.auth_method()) {
        (Provider::OpenAi, AuthMethod::ChatGptLogin) => "chatgpt_responses",
        (Provider::OpenAi, AuthMethod::ApiKey) => "openai_responses",
        (Provider::Anthropic, _) => "anthropic_messages",
        (Provider::OpenAiCompatible, _) => "openai_completions",
        (Provider::TypeSafe, _) => "typesafe_system_one",
    }
}

fn endpoint_origin(settings: &ConnectionSettings) -> Option<String> {
    settings.endpoint().map(|endpoint| endpoint.as_url())
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use herness_core::{
        AuthMethod, ConnectionAdmin, ConnectionId, CoreError, CredentialAvailability,
        CredentialPort, Endpoint, Provider, ResolvedCredential,
    };

    use super::*;

    struct NoCredential;

    impl CredentialPort for NoCredential {
        fn availability(
            &self,
            _connection: &ConnectionId,
        ) -> Result<CredentialAvailability, CoreError> {
            Ok(CredentialAvailability::Unavailable)
        }

        fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
            Err(CoreError::AuthenticationRequired {
                connection: *connection,
            })
        }
    }

    fn directory_with(settings: ConnectionSettings) -> (ConnectionDirectory, ConnectionId) {
        let admin = ConnectionAdmin::new();
        let connection = settings.connection_id();
        admin.add(settings).expect("connection");
        (admin.directory(), connection)
    }

    #[test]
    fn probe_rejects_an_unknown_connection() {
        let admin = ConnectionAdmin::new();
        let error = probe_connection(
            &admin.directory(),
            Arc::new(NoCredential),
            &ProviderEndpoints::official(),
            ConnectionId::new(),
        )
        .expect_err("unknown connection");
        assert_eq!(error, ProbeFailure::ConnectionNotFound);
    }

    #[test]
    fn probe_reports_missing_auth_before_building_a_request() {
        let settings = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("settings");
        let (directory, connection) = directory_with(settings);
        let error = probe_connection(
            &directory,
            Arc::new(NoCredential),
            &ProviderEndpoints::official(),
            connection,
        )
        .expect_err("missing credential");
        assert_eq!(error, ProbeFailure::AuthenticationRequired);
        assert!(error.is_auth_failure());
        assert_eq!(error.as_str(), "authentication_required");
    }

    #[test]
    fn model_catalog_listing_rejects_non_chatgpt_connections_without_a_request() {
        let settings = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::Anthropic,
            "claude-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("settings");
        let (directory, connection) = directory_with(settings);
        let error = list_chatgpt_models(
            &directory,
            Arc::new(NoCredential),
            &ProviderEndpoints::official(),
            connection,
        )
        .expect_err("not chatgpt");
        assert_eq!(error, ProbeFailure::UnsupportedConnection);
    }

    #[test]
    fn endpoint_classes_are_distinct_per_provider_route() {
        let openai = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("openai");
        let chatgpt = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ChatGptLogin,
            None,
            None,
        )
        .expect("chatgpt");
        let anthropic = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::Anthropic,
            "claude-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("anthropic");
        let compatible = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAiCompatible,
            "local-test",
            AuthMethod::ApiKey,
            Some(Endpoint::parse("http://127.0.0.1:11434/v1").expect("endpoint")),
            None,
        )
        .expect("compatible");
        assert_eq!(endpoint_class(&openai), "openai_responses");
        assert_eq!(endpoint_class(&chatgpt), "chatgpt_responses");
        assert_eq!(endpoint_class(&anthropic), "anthropic_messages");
        assert_eq!(endpoint_class(&compatible), "openai_completions");
        assert_eq!(
            endpoint_origin(&compatible).as_deref(),
            Some("http://127.0.0.1:11434/v1")
        );
        assert_eq!(endpoint_origin(&openai), None);
    }
}
