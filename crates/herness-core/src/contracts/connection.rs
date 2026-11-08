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
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenAi => f.write_str("openai"),
            Self::Anthropic => f.write_str("anthropic"),
            Self::OpenAiCompatible => f.write_str("openai_compatible"),
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
