//! Non-secret connection information safe to expose to UI and events.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::IdKind;

/// Identifier of a provider connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(Uuid);

impl ConnectionId {
    /// Generates a new random connection identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ConnectionId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| CoreError::InvalidId {
                id_kind: IdKind::Connection,
                value: value.to_owned(),
            })
    }
}

impl Serialize for ConnectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ConnectionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Model provider behind a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// OpenAI API.
    #[serde(rename = "openai")]
    OpenAi,
    /// Anthropic API.
    Anthropic,
    /// A user-specified OpenAI-compatible endpoint.
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
    /// TypeSafe System One assessment provider (Jev).
    ///
    /// This provider is assessment-only and never starts an agent run.
    #[serde(rename = "typesafe")]
    TypeSafe,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenAi => f.write_str("openai"),
            Self::Anthropic => f.write_str("anthropic"),
            Self::OpenAiCompatible => f.write_str("openai_compatible"),
            Self::TypeSafe => f.write_str("typesafe"),
        }
    }
}

/// Authentication method for a connection. No credential material is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// API key stored in the macOS Keychain.
    ApiKey,
    /// ChatGPT login stored in the macOS Keychain.
    #[serde(rename = "chatgpt_login")]
    ChatGptLogin,
}

/// Non-secret availability of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    /// The connection can be used.
    Available,
    /// A human login is required before use.
    LoginRequired,
    /// A credential must be saved, re-entered, or refreshed by a human.
    AuthRequired,
    /// The connection is not usable.
    Unavailable,
}

/// Public non-secret view of a connection.
///
/// This type intentionally contains no API key, OAuth token, authorization
/// header, or provider response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    connection_id: ConnectionId,
    provider: Provider,
    model: String,
    auth_method: AuthMethod,
    status: ConnectionStatus,
}

impl ConnectionInfo {
    /// Creates a validated non-secret connection view.
    pub fn new(
        connection_id: ConnectionId,
        provider: Provider,
        model: impl Into<String>,
        auth_method: AuthMethod,
        status: ConnectionStatus,
    ) -> Result<Self, CoreError> {
        let model = model.into();
        let trimmed = model.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "model".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self {
            connection_id,
            provider,
            model: trimmed.to_owned(),
            auth_method,
            status,
        })
    }

    /// Connection identifier.
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Provider kind.
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Selected model name.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Authentication method.
    pub const fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    /// Non-secret availability status.
    pub const fn status(&self) -> ConnectionStatus {
        self.status
    }
}

impl<'de> Deserialize<'de> for ConnectionInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            connection_id: ConnectionId,
            provider: Provider,
            model: String,
            auth_method: AuthMethod,
            status: ConnectionStatus,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.connection_id,
            wire.provider,
            wire.model,
            wire.auth_method,
            wire.status,
        )
        .map_err(de::Error::custom)
    }
}

/// Wire endpoint class of a connection.
///
/// The class identifies the request shape independently of the provider and
/// authentication method. Assessment-only classes must never reach an agent
/// run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    /// OpenAI Responses API.
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    /// Anthropic Messages API.
    AnthropicMessages,
    /// OpenAI-compatible chat-completions endpoint.
    #[serde(rename = "openai_completions")]
    OpenAiCompletions,
    /// TypeSafe System One assessment endpoint.
    #[serde(rename = "typesafe_system_one")]
    TypeSafeSystemOne,
    /// OpenAI Decisions assessment endpoint.
    #[serde(rename = "openai_decisions")]
    OpenAiDecisions,
}

impl EndpointClass {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::OpenAiCompletions => "openai_completions",
            Self::TypeSafeSystemOne => "typesafe_system_one",
            Self::OpenAiDecisions => "openai_decisions",
        }
    }

    /// Whether this endpoint class is assessment-only.
    pub const fn is_assessment_only(self) -> bool {
        matches!(self, Self::TypeSafeSystemOne | Self::OpenAiDecisions)
    }
}

/// One input modality a connection can receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputModality {
    /// Text, code, diffs, and logs.
    Text,
    /// Image bytes.
    Image,
}

/// Input capabilities declared for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputCapabilities {
    text: bool,
    image: bool,
}

impl InputCapabilities {
    /// Declares which input modalities are available.
    pub const fn new(text: bool, image: bool) -> Self {
        Self { text, image }
    }

    /// Text-only connection.
    pub const fn text_only() -> Self {
        Self {
            text: true,
            image: false,
        }
    }

    /// Text and image connection.
    pub const fn text_and_image() -> Self {
        Self {
            text: true,
            image: true,
        }
    }

    /// Whether text input is available.
    pub const fn supports_text(self) -> bool {
        self.text
    }

    /// Whether image input is available.
    pub const fn supports_image(self) -> bool {
        self.image
    }

    /// Whether the connection accepts `modality`.
    pub const fn supports(self, modality: InputModality) -> bool {
        match modality {
            InputModality::Text => self.text,
            InputModality::Image => self.image,
        }
    }
}

/// How a connection may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionUsage {
    /// The connection may run an agent and may also be used for assessment.
    AgentExecution,
    /// The connection is assessment-only and must be rejected before an agent
    /// run sends any request.
    AssessmentOnly,
}

impl ConnectionUsage {
    /// Whether agent execution is permitted.
    pub const fn allows_agent_execution(self) -> bool {
        matches!(self, Self::AgentExecution)
    }

    /// Whether assessment requests are permitted.
    pub const fn allows_assessment(self) -> bool {
        matches!(self, Self::AgentExecution | Self::AssessmentOnly)
    }
}

/// Non-secret capability declaration stored with connection settings.
///
/// A declaration selects the endpoint class and input modalities explicitly.
/// The usage is derived from the endpoint class: assessment endpoint classes
/// are always [`ConnectionUsage::AssessmentOnly`] and agent endpoint classes
/// are always [`ConnectionUsage::AgentExecution`]. This keeps a settings file
/// from declaring an assessment endpoint usable for an agent run.
///
/// The declaration contains no api key, OAuth token, authorization header, or
/// provider response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionCapabilityDeclaration {
    endpoint_class: EndpointClass,
    input: InputCapabilities,
}

impl ConnectionCapabilityDeclaration {
    /// Declares an endpoint class and the input modalities it accepts.
    pub const fn new(endpoint_class: EndpointClass, input: InputCapabilities) -> Self {
        Self {
            endpoint_class,
            input,
        }
    }

    /// Declared endpoint class.
    pub const fn endpoint_class(self) -> EndpointClass {
        self.endpoint_class
    }

    /// Declared input capabilities.
    pub const fn input(self) -> InputCapabilities {
        self.input
    }

    /// Usage implied by the endpoint class.
    pub const fn usage(self) -> ConnectionUsage {
        if self.endpoint_class.is_assessment_only() {
            ConnectionUsage::AssessmentOnly
        } else {
            ConnectionUsage::AgentExecution
        }
    }
}

/// Non-secret capabilities of one connection.
///
/// This value contains no api key, OAuth token, authorization header, or
/// provider response body. It distinguishes normal agent execution from
/// assessment-only TypeSafe/Jev System One and OpenAI Decisions connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionCapabilities {
    connection_id: ConnectionId,
    provider: Provider,
    auth_method: AuthMethod,
    endpoint_class: EndpointClass,
    input: InputCapabilities,
    usage: ConnectionUsage,
}

impl ConnectionCapabilities {
    /// Creates validated non-secret capabilities for one connection.
    pub fn new(
        connection_id: ConnectionId,
        provider: Provider,
        auth_method: AuthMethod,
        endpoint_class: EndpointClass,
        input: InputCapabilities,
        usage: ConnectionUsage,
    ) -> Result<Self, CoreError> {
        let expected_provider = match endpoint_class {
            EndpointClass::OpenAiResponses => Provider::OpenAi,
            EndpointClass::AnthropicMessages => Provider::Anthropic,
            EndpointClass::OpenAiCompletions => Provider::OpenAiCompatible,
            EndpointClass::TypeSafeSystemOne => Provider::TypeSafe,
            EndpointClass::OpenAiDecisions => Provider::OpenAi,
        };
        if provider != expected_provider {
            return Err(invalid_capability(
                "endpointClass",
                "endpoint class does not match the connection provider",
            ));
        }

        if endpoint_class == EndpointClass::OpenAiDecisions && auth_method != AuthMethod::ApiKey {
            return Err(invalid_capability(
                "authMethod",
                "OpenAI Decisions requires an API key; ChatGPT login is not accepted",
            ));
        }
        if provider == Provider::TypeSafe && auth_method != AuthMethod::ApiKey {
            return Err(invalid_capability(
                "authMethod",
                "TypeSafe System One requires an API key",
            ));
        }
        if endpoint_class.is_assessment_only() && usage != ConnectionUsage::AssessmentOnly {
            return Err(invalid_capability(
                "usage",
                "assessment-only endpoints cannot be used for agent execution",
            ));
        }
        if !endpoint_class.is_assessment_only() && usage == ConnectionUsage::AssessmentOnly {
            return Err(invalid_capability(
                "usage",
                "an agent endpoint cannot be declared assessment-only",
            ));
        }

        Ok(Self {
            connection_id,
            provider,
            auth_method,
            endpoint_class,
            input,
            usage,
        })
    }

    /// Connection identifier.
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Provider kind.
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Authentication method.
    pub const fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    /// Endpoint class.
    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }

    /// Declared input capabilities.
    pub const fn input(&self) -> InputCapabilities {
        self.input
    }

    /// Intended connection usage.
    pub const fn usage(&self) -> ConnectionUsage {
        self.usage
    }

    /// Whether this connection may start or continue an agent run.
    pub const fn allows_agent_execution(&self) -> bool {
        self.usage.allows_agent_execution()
    }

    /// Whether this connection may carry assessment requests.
    pub const fn allows_assessment(&self) -> bool {
        self.usage.allows_assessment()
    }
}

impl<'de> Deserialize<'de> for ConnectionCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            connection_id: ConnectionId,
            provider: Provider,
            auth_method: AuthMethod,
            endpoint_class: EndpointClass,
            input: InputCapabilities,
            usage: ConnectionUsage,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.connection_id,
            wire.provider,
            wire.auth_method,
            wire.endpoint_class,
            wire.input,
            wire.usage,
        )
        .map_err(de::Error::custom)
    }
}

fn invalid_capability(field: &str, detail: &str) -> CoreError {
    CoreError::InvalidValue {
        field: field.to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: detail.to_owned(),
        },
    }
}
