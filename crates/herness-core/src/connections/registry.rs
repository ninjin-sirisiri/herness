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
    AuthMethod, ConnectionCapabilities, ConnectionCapabilityDeclaration, ConnectionId,
    ConnectionInfo, ConnectionStatus, ConnectionUsage, EndpointClass, InputCapabilities,
    InputModality, Provider,
};
use crate::contracts::errors::CoreError;

use super::credential::{CredentialRef, VaultAccount};
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
    /// Selected account-scoped vault key for a ChatGPT connection. `None`
    /// means the connection-level credential reference is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_account: Option<VaultAccount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_http_acknowledged: Option<InsecureRemoteHttp>,
    /// Explicit endpoint class and input modalities. Absent for legacy
    /// settings, which keep the H1 provider defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<ConnectionCapabilityDeclaration>,
}

impl ConnectionSettings {
    /// Creates validated non-secret connection settings.
    ///
    /// * OpenAI, Anthropic, ChatGPT-login, and TypeSafe System One connections
    ///   use their built-in endpoint; a custom endpoint is rejected. A ChatGPT
    ///   OAuth connection is represented by [`Provider::OpenAi`] with
    ///   [`AuthMethod::ChatGptLogin`].
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
        Self::new_with_optional_capabilities(
            connection_id,
            provider,
            model,
            auth_method,
            endpoint,
            insecure_remote_http,
            None,
        )
    }

    /// Creates validated settings with an explicit capability declaration.
    ///
    /// The declaration is non-secret. It selects the endpoint class and input
    /// modalities; usage is derived from the class. TypeSafe/Jev System One
    /// and OpenAI Decisions declarations are assessment-only and therefore
    /// cannot be used for an agent run. A custom endpoint is still allowed only
    /// for [`Provider::OpenAiCompatible`], and an OpenAI Decisions declaration
    /// still requires an API key.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_capabilities(
        connection_id: ConnectionId,
        provider: Provider,
        model: impl Into<String>,
        auth_method: AuthMethod,
        endpoint: Option<Endpoint>,
        insecure_remote_http: Option<InsecureRemoteHttp>,
        capabilities: ConnectionCapabilityDeclaration,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_optional_capabilities(
            connection_id,
            provider,
            model,
            auth_method,
            endpoint,
            insecure_remote_http,
            Some(capabilities),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_optional_capabilities(
        connection_id: ConnectionId,
        provider: Provider,
        model: impl Into<String>,
        auth_method: AuthMethod,
        endpoint: Option<Endpoint>,
        insecure_remote_http: Option<InsecureRemoteHttp>,
        capabilities: Option<ConnectionCapabilityDeclaration>,
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
            Provider::OpenAi | Provider::Anthropic | Provider::TypeSafe => {
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

        let settings = Self {
            connection_id,
            provider,
            model: trimmed.to_owned(),
            auth_method,
            endpoint,
            credential_ref: CredentialRef::for_connection(connection_id, auth_method),
            vault_account: None,
            insecure_http_acknowledged,
            capabilities,
        };
        // Validate the effective capability set before it can be registered.
        // This rejects provider/authentication/endpoint-class mismatches,
        // ChatGPT login on Decisions, and assessment-only classes on an agent
        // usage before any settings are stored.
        settings.capabilities()?;
        Ok(settings)
    }

    /// Returns a copy of these settings with a different capability
    /// declaration.
    ///
    /// The declaration is validated against the provider and authentication
    /// method. The same custom-endpoint rules as [`Self::new`] apply; a
    /// declaration never re-points a connection to another origin.
    pub fn with_capabilities(
        mut self,
        declaration: ConnectionCapabilityDeclaration,
    ) -> Result<Self, ConnectionError> {
        self.capabilities = Some(declaration);
        self.capabilities()?;
        Ok(self)
    }

    /// Effective non-secret capabilities of this connection.
    ///
    /// Settings without an explicit declaration keep the H1 provider defaults:
    /// OpenAI Responses, Anthropic Messages, or OpenAI-compatible completions,
    /// all usable for agent execution and assessment. TypeSafe always resolves
    /// to the assessment-only System One endpoint. A declared assessment
    /// endpoint class resolves to [`ConnectionUsage::AssessmentOnly`].
    pub fn capabilities(&self) -> Result<ConnectionCapabilities, ConnectionError> {
        let (endpoint_class, input) = match self.capabilities {
            Some(declaration) => (declaration.endpoint_class(), declaration.input()),
            None => (
                default_endpoint_class(self.provider),
                InputCapabilities::text_only(),
            ),
        };
        let usage = if endpoint_class.is_assessment_only() {
            ConnectionUsage::AssessmentOnly
        } else {
            ConnectionUsage::AgentExecution
        };
        ConnectionCapabilities::new(
            self.connection_id,
            self.provider,
            self.auth_method,
            endpoint_class,
            input,
            usage,
        )
        .map_err(|error| ConnectionError::CapabilityDeclarationRejected {
            detail: error.to_string(),
        })
    }

    /// Declared input capabilities, before provider defaults are applied.
    pub const fn declared_capabilities(&self) -> Option<ConnectionCapabilityDeclaration> {
        self.capabilities
    }

    /// Whether the connection supports `modality`.
    pub fn supports_input(&self, modality: InputModality) -> Result<bool, ConnectionError> {
        Ok(self.capabilities()?.input().supports(modality))
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

    /// Vault account used for the currently selected ChatGPT account, if any.
    pub fn vault_account(&self) -> VaultAccount {
        self.vault_account
            .clone()
            .unwrap_or_else(|| VaultAccount::from_credential_ref(&self.credential_ref))
    }

    /// Selected account-scoped ChatGPT vault key, if this connection has one.
    pub fn selected_chatgpt_account(&self) -> Option<&VaultAccount> {
        self.vault_account.as_ref()
    }

    /// Returns a copy of these settings with the selected ChatGPT account
    /// changed.
    ///
    /// The account key must be a ChatGPT account key for this exact connection;
    /// any other value is rejected rather than written into settings.
    pub fn select_chatgpt_account(&self, account: VaultAccount) -> Result<Self, ConnectionError> {
        if self.auth_method != AuthMethod::ChatGptLogin
            || !account.is_chatgpt_account_for(self.connection_id)
        {
            return Err(ConnectionError::InvalidCredentialAccount);
        }
        let mut settings = self.clone();
        settings.vault_account = Some(account);
        Ok(settings)
    }

    /// Returns a copy of these settings with no account-scoped ChatGPT
    /// credential selected.
    pub fn clear_chatgpt_account(&self) -> Self {
        let mut settings = self.clone();
        settings.vault_account = None;
        settings
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
            #[serde(default)]
            vault_account: Option<VaultAccount>,
            insecure_http_acknowledged: Option<InsecureRemoteHttp>,
            #[serde(default)]
            capabilities: Option<ConnectionCapabilityDeclaration>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let settings = Self::new_with_optional_capabilities(
            wire.connection_id,
            wire.provider,
            wire.model,
            wire.auth_method,
            wire.endpoint,
            wire.insecure_http_acknowledged,
            wire.capabilities,
        )
        .map_err(de::Error::custom)?;
        if settings.credential_ref != wire.credential_ref {
            return Err(de::Error::custom(
                ConnectionError::CredentialReferenceMismatch,
            ));
        }
        let settings = match wire.vault_account {
            Some(account) => settings
                .select_chatgpt_account(account)
                .map_err(de::Error::custom)?,
            None => settings,
        };
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

const fn default_endpoint_class(provider: Provider) -> EndpointClass {
    match provider {
        Provider::OpenAi => EndpointClass::OpenAiResponses,
        Provider::Anthropic => EndpointClass::AnthropicMessages,
        Provider::OpenAiCompatible => EndpointClass::OpenAiCompletions,
        Provider::TypeSafe => EndpointClass::TypeSafeSystemOne,
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

    /// Returns the effective non-secret capabilities of one connection.
    ///
    /// This never falls back to another connection or provider.
    pub fn capabilities(
        &self,
        connection: ConnectionId,
    ) -> Result<ConnectionCapabilities, ConnectionError> {
        self.get(connection)?.capabilities()
    }

    /// Lists the effective capabilities of every registered connection.
    pub fn list_capabilities(&self) -> Result<Vec<ConnectionCapabilities>, ConnectionError> {
        self.list()?
            .iter()
            .map(ConnectionSettings::capabilities)
            .collect()
    }

    /// Returns capabilities for a connection that may start an agent run.
    ///
    /// Assessment-only connections are rejected with
    /// [`ConnectionError::AgentExecutionNotAllowed`]. Callers must use this
    /// (or [`ConnectionCapabilities::allows_agent_execution`]) before an agent
    /// send; there is no provider or connection fallback.
    pub fn agent_execution_capabilities(
        &self,
        connection: ConnectionId,
    ) -> Result<ConnectionCapabilities, ConnectionError> {
        let capabilities = self.capabilities(connection)?;
        if !capabilities.allows_agent_execution() {
            return Err(ConnectionError::AgentExecutionNotAllowed { connection });
        }
        Ok(capabilities)
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
    fn chatgpt_account_selection_is_connection_scoped_and_round_trips() {
        let connection = ConnectionId::new();
        let settings = ConnectionSettings::new(
            connection,
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ChatGptLogin,
            None,
            None,
        )
        .unwrap();
        let account =
            VaultAccount::for_chatgpt_account(connection, "oaiapp_one", "subject-one").unwrap();
        let selected = settings.select_chatgpt_account(account.clone()).unwrap();
        assert_eq!(selected.selected_chatgpt_account(), Some(&account));
        assert_eq!(selected.vault_account(), account);

        let other_connection = ConnectionId::new();
        let other =
            VaultAccount::for_chatgpt_account(other_connection, "oaiapp_one", "subject-one")
                .unwrap();
        assert_eq!(
            settings.select_chatgpt_account(other).unwrap_err(),
            ConnectionError::InvalidCredentialAccount
        );

        let api_key = ConnectionSettings::new(
            connection,
            Provider::OpenAi,
            "gpt-5",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            api_key.select_chatgpt_account(account.clone()).unwrap_err(),
            ConnectionError::InvalidCredentialAccount
        );

        let json = serde_json::to_value(&selected).unwrap();
        assert_eq!(json["vaultAccount"], account.as_str());
        let decoded: ConnectionSettings = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, selected);
        assert_eq!(
            decoded.clear_chatgpt_account().vault_account().as_str(),
            settings.credential_ref().as_str()
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
