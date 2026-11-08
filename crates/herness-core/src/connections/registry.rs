//! Non-secret connection settings and the human-owned connection registry.
//!
//! Settings contain a provider, model, authentication method, optional
//! OpenAI-compatible endpoint, and an opaque credential reference. They never
//! contain an API key, OAuth token, or authorization header.
//!
//! The registry is split into a write-only-for-humans [`ConnectionAdmin`] and
//! a read-only [`ConnectionDirectory`]. Only the trusted host composition may
//! hold `ConnectionAdmin`; tools, skills, the engine, and model output receive
//! `ConnectionDirectory` at most and cannot add, change, or re-point a
//! connection.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::contracts::connection::{
    AuthMethod, ConnectionId, ConnectionInfo, ConnectionStatus, Provider,
};
use crate::contracts::errors::CoreError;

use super::credential::CredentialRef;
use super::endpoint::Endpoint;
use super::error::ConnectionError;

/// Explicit acknowledgment that a remote plain-HTTP endpoint exposes
/// credentials to the network.
///
/// The value is recorded in [`ConnectionSettings`]; there is no implicit or
/// model-inferred acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsecureRemoteHttp {
    /// The human accepted the risk of sending credentials over remote plain
    /// HTTP.
    Acknowledged,
}

/// Non-secret configuration of one provider connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSettings {
    connection_id: ConnectionId,
    provider: Provider,
    model: String,
    auth_method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<Endpoint>,
    credential_ref: CredentialRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_http_acknowledged: Option<InsecureRemoteHttp>,
}

impl ConnectionSettings {
    /// Creates validated non-secret connection settings.
    ///
    /// * OpenAI, Anthropic, and ChatGPT-login connections use their built-in
    ///   endpoint; a custom endpoint is rejected. A ChatGPT OAuth connection is
    ///   represented by [`Provider::OpenAi`] with [`AuthMethod::ChatGptLogin`].
    /// * OpenAI-compatible connections require an explicit endpoint and an API
    ///   key.
    /// * Remote plain HTTP requires `insecure_remote_http` to be
    ///   [`InsecureRemoteHttp::Acknowledged`]. The acknowledgment is stored
    ///   with the settings. Loopback plain HTTP does not require it.
    pub fn new(
        connection_id: ConnectionId,
        provider: Provider,
        model: impl Into<String>,
        auth_method: AuthMethod,
        endpoint: Option<Endpoint>,
        insecure_remote_http: Option<InsecureRemoteHttp>,
    ) -> Result<Self, ConnectionError> {
        let model = model.into();
        let trimmed = model.trim();
        if trimmed.is_empty() {
            return Err(ConnectionError::EmptyModel);
        }

        if auth_method == AuthMethod::ChatGptLogin && provider != Provider::OpenAi {
            return Err(ConnectionError::AuthMethodNotSupported {
                provider,
                auth_method,
            });
        }

        let endpoint = match provider {
            Provider::OpenAiCompatible => {
                let endpoint = endpoint.ok_or(ConnectionError::EndpointRequired)?;
                Some(endpoint)
            }
            Provider::OpenAi | Provider::Anthropic => {
                if endpoint.is_some() {
                    return Err(ConnectionError::EndpointNotAllowed { provider });
                }
                None
            }
        };

        let insecure_http_acknowledged = match &endpoint {
            Some(endpoint) if endpoint.requires_insecure_remote_http_ack() => {
                match insecure_remote_http {
                    Some(InsecureRemoteHttp::Acknowledged) => {
                        Some(InsecureRemoteHttp::Acknowledged)
                    }
                    None => return Err(ConnectionError::RemoteHttpRequiresAcknowledgment),
                }
            }
            _ => None,
        };

        Ok(Self {
            connection_id,
            provider,
            model: trimmed.to_owned(),
            auth_method,
            endpoint,
            credential_ref: CredentialRef::for_connection(connection_id, auth_method),
            insecure_http_acknowledged,
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

    /// Custom OpenAI-compatible endpoint, if any.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    /// Opaque credential reference. This is not a secret and never contains
    /// key material.
    pub const fn credential_ref(&self) -> &CredentialRef {
        &self.credential_ref
    }

    /// Recorded remote plain-HTTP danger acknowledgment, if required.
    pub const fn insecure_http_acknowledged(&self) -> Option<InsecureRemoteHttp> {
        self.insecure_http_acknowledged
    }

    /// Builds the public non-secret connection view for the given status.
    pub fn public_info(&self, status: ConnectionStatus) -> Result<ConnectionInfo, CoreError> {
        ConnectionInfo::new(
            self.connection_id,
            self.provider,
            self.model.clone(),
            self.auth_method,
            status,
        )
    }
}

impl<'de> Deserialize<'de> for ConnectionSettings {
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
            endpoint: Option<Endpoint>,
            credential_ref: CredentialRef,
            insecure_http_acknowledged: Option<InsecureRemoteHttp>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let settings = Self::new(
            wire.connection_id,
            wire.provider,
            wire.model,
            wire.auth_method,
            wire.endpoint,
            wire.insecure_http_acknowledged,
        )
        .map_err(de::Error::custom)?;
        if settings.credential_ref != wire.credential_ref {
            return Err(de::Error::custom(
                ConnectionError::CredentialReferenceMismatch,
            ));
        }
        Ok(settings)
    }
}

#[derive(Debug, Default)]
struct RegistryInner {
    connections: RwLock<BTreeMap<ConnectionId, ConnectionSettings>>,
}

/// Human-only writer for connection settings.
///
/// The trusted host composition creates this value and passes only
/// [`ConnectionDirectory`] to tools and the engine. Keeping the writer separate
/// makes a model- or skill-driven connection change a deliberate host wiring
/// mistake rather than an ordinary API call.
#[derive(Debug, Clone)]
pub struct ConnectionAdmin {
    directory: ConnectionDirectory,
}

impl ConnectionAdmin {
    /// Creates an empty connection registry.
    pub fn new() -> Self {
        Self {
            directory: ConnectionDirectory {
                inner: Arc::new(RegistryInner::default()),
            },
        }
    }

    /// Read-only handle for tools, the engine, and status display.
    pub fn directory(&self) -> ConnectionDirectory {
        self.directory.clone()
    }

    /// Registers a new connection.
    pub fn add(&self, settings: ConnectionSettings) -> Result<(), ConnectionError> {
        let mut connections = self
            .directory
            .inner
            .connections
            .write()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        if connections.contains_key(&settings.connection_id) {
            return Err(ConnectionError::DuplicateConnection {
                connection: settings.connection_id,
            });
        }
        connections.insert(settings.connection_id, settings);
        Ok(())
    }

    /// Replaces the settings of an existing connection.
    ///
    /// Replacing settings can change the credential reference. The old vault
    /// item is not deleted automatically; the human settings flow must remove
    /// it explicitly so a stale secret is not silently reused under a new
    /// configuration.
    pub fn update(&self, settings: ConnectionSettings) -> Result<(), ConnectionError> {
        let mut connections = self
            .directory
            .inner
            .connections
            .write()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        let entry = connections.get_mut(&settings.connection_id).ok_or(
            ConnectionError::UnknownConnection {
                connection: settings.connection_id,
            },
        )?;
        *entry = settings;
        Ok(())
    }

    /// Removes a connection.
    ///
    /// This does not delete the vault item. The human settings flow must call
    /// the credential writer's `remove` first, and must not reuse a connection
    /// id for a different configuration, so a later lookup cannot pick up stale
    /// secret material.
    pub fn remove(&self, connection: ConnectionId) -> Result<(), ConnectionError> {
        let mut connections = self
            .directory
            .inner
            .connections
            .write()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        connections
            .remove(&connection)
            .map(|_| ())
            .ok_or(ConnectionError::UnknownConnection { connection })
    }
}

impl Default for ConnectionAdmin {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only view of registered connection settings.
#[derive(Debug, Clone)]
pub struct ConnectionDirectory {
    inner: Arc<RegistryInner>,
}

impl ConnectionDirectory {
    /// Looks up exactly one connection. This never falls back to another
    /// connection with the same provider or model.
    pub fn get(&self, connection: ConnectionId) -> Result<ConnectionSettings, ConnectionError> {
        let connections = self
            .inner
            .connections
            .read()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        connections
            .get(&connection)
            .cloned()
            .ok_or(ConnectionError::UnknownConnection { connection })
    }

    /// Lists all registered settings ordered by connection id.
    pub fn list(&self) -> Result<Vec<ConnectionSettings>, ConnectionError> {
        let connections = self
            .inner
            .connections
            .read()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        Ok(connections.values().cloned().collect())
    }

    /// Number of registered connections.
    pub fn len(&self) -> Result<usize, ConnectionError> {
        let connections = self
            .inner
            .connections
            .read()
            .map_err(|_| ConnectionError::RegistryUnavailable)?;
        Ok(connections.len())
    }

    /// Whether no connection is registered.
    pub fn is_empty(&self) -> Result<bool, ConnectionError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(value: &str) -> Endpoint {
        Endpoint::parse(value).unwrap()
    }

    #[test]
    fn provider_kinds_and_endpoint_rules_are_enforced() {
        let api_key = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .unwrap();
        assert!(api_key.endpoint().is_none());

        let compatible = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAiCompatible,
            "local-model",
            AuthMethod::ApiKey,
            Some(endpoint("http://127.0.0.1:11434/v1")),
            None,
        )
        .unwrap();
        assert_eq!(
            compatible.endpoint().unwrap().as_url(),
            "http://127.0.0.1:11434/v1"
        );
        assert!(compatible.insecure_http_acknowledged().is_none());

        let missing = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAiCompatible,
            "local-model",
            AuthMethod::ApiKey,
            None,
            None,
        );
        assert_eq!(missing.unwrap_err(), ConnectionError::EndpointRequired);

        let not_allowed = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ApiKey,
            Some(endpoint("https://proxy.example.com/v1")),
            None,
        );
        assert!(matches!(
            not_allowed.unwrap_err(),
            ConnectionError::EndpointNotAllowed {
                provider: Provider::OpenAi
            }
        ));

        let chatgpt_for_anthropic = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::Anthropic,
            "claude",
            AuthMethod::ChatGptLogin,
            None,
            None,
        );
        assert!(matches!(
            chatgpt_for_anthropic.unwrap_err(),
            ConnectionError::AuthMethodNotSupported { .. }
        ));
    }

    #[test]
    fn remote_plain_http_requires_and_records_the_acknowledgment() {
        let connection = ConnectionId::new();
        let endpoint = endpoint("http://api.example.com/v1");
        let missing = ConnectionSettings::new(
            connection,
            Provider::OpenAiCompatible,
            "model",
            AuthMethod::ApiKey,
            Some(endpoint.clone()),
            None,
        );
        assert_eq!(
            missing.unwrap_err(),
            ConnectionError::RemoteHttpRequiresAcknowledgment
        );

        let settings = ConnectionSettings::new(
            connection,
            Provider::OpenAiCompatible,
            "model",
            AuthMethod::ApiKey,
            Some(endpoint),
            Some(InsecureRemoteHttp::Acknowledged),
        )
        .unwrap();
        assert_eq!(
            settings.insecure_http_acknowledged(),
            Some(InsecureRemoteHttp::Acknowledged)
        );
    }

    #[test]
    fn settings_round_trip_without_secret_fields() {
        let settings = ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAiCompatible,
            "model",
            AuthMethod::ApiKey,
            Some(endpoint("https://compat.example.com/v1/")),
            None,
        )
        .unwrap();
        let encoded = serde_json::to_value(&settings).unwrap();
        assert_eq!(encoded["provider"], "openai_compatible");
        assert_eq!(encoded["endpoint"], "https://compat.example.com/v1");
        assert!(encoded.get("token").is_none());
        assert!(encoded.get("secret").is_none());
        assert_eq!(
            serde_json::from_value::<ConnectionSettings>(encoded.clone()).unwrap(),
            settings
        );

        let mut with_secret = encoded.clone();
        with_secret["token"] = serde_json::json!("sk-should-not-be-accepted");
        assert!(serde_json::from_value::<ConnectionSettings>(with_secret).is_err());

        let mut wrong_reference = encoded;
        wrong_reference["credentialRef"] = serde_json::json!("connection/other/api_key");
        assert!(serde_json::from_value::<ConnectionSettings>(wrong_reference).is_err());
    }
}
