//! Write-only credential storage, per-connection resolution, and refresh
//! serialization.
//!
//! Secrets live only in a [`CredentialVault`] implementation (the macOS
//! Keychain in the desktop crate). The connection registry stores an opaque
//! [`CredentialRef`], never the secret. Saving is restricted to a
//! [`CredentialWriter`] handle; the engine receives only a [`CredentialBroker`]
//! and can resolve a credential for one selected connection. There is no
//! read-back API for the settings UI.
//!
//! Resolution never falls back to another provider, model, or connection. A
//! missing, expired, undecodable, or inaccessible credential stops the request
//! with a structured error.
//!
//! Refresh is serialized per connection. Concurrent resolves for the same
//! connection perform at most one refresh; resolves for different connections
//! use independent locks and do not block each other.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::contracts::connection::{AuthMethod, ConnectionId, ConnectionInfo, ConnectionStatus};
use crate::contracts::errors::{CoreError, CredentialFailureKind};
use crate::contracts::time::Timestamp;
use crate::ports::credential::{
    CredentialAvailability, CredentialKind, CredentialPort, ResolvedCredential, SecretString,
};

use super::error::{ConnectionError, VaultFailure};
use super::registry::{ConnectionDirectory, ConnectionSettings};

/// Keychain service name shared by every herness credential item.
pub const VAULT_SERVICE: &str = "com.herness.credentials";

/// Version of the credential payload stored in the vault.
pub const CREDENTIAL_FORMAT_VERSION: u32 = 1;

/// Longest accepted vault account key, in Unicode scalar values.
const MAX_VAULT_ACCOUNT_CHARS: usize = 256;

/// Opaque reference to one credential item.
///
/// The reference is derived from the connection id and authentication method.
/// It contains no secret and is safe to serialize with connection settings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(String);

impl CredentialRef {
    /// Derives the reference for a connection and authentication method.
    pub fn for_connection(connection: ConnectionId, auth_method: AuthMethod) -> Self {
        let method = match auth_method {
            AuthMethod::ApiKey => "api_key",
            AuthMethod::ChatGptLogin => "chatgpt_login",
        };
        Self(format!("connection/{connection}/{method}"))
    }

    /// Reference string. This is an opaque identifier, not a credential.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Account key passed to a credential vault.
///
/// The key is derived from [`CredentialRef`] and is not secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultAccount(String);

impl VaultAccount {
    /// Creates a validated account key.
    pub fn new(value: impl Into<String>) -> Result<Self, ConnectionError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.chars().count() > MAX_VAULT_ACCOUNT_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(ConnectionError::InvalidVaultAccount);
        }
        Ok(Self(value))
    }

    /// Derives the vault account for a credential reference.
    pub fn from_credential_ref(reference: &CredentialRef) -> Self {
        Self(reference.0.clone())
    }

    /// Account key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VaultAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Storage boundary for secret credential payloads.
///
/// Implementations must keep the payload in the operating-system credential
/// store. They must report failures as [`VaultFailure`] and must not fall back
/// to a plaintext file, environment variable, or database row.
pub trait CredentialVault: Send + Sync {
    /// Creates or replaces the payload for one account.
    fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure>;

    /// Reads one payload. `Ok(None)` means the account does not exist.
    fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure>;

    /// Deletes one payload. A missing account may be reported as
    /// [`VaultFailure::MissingItem`] and is treated as already removed by
    /// [`CredentialAdmin::remove`].
    fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure>;
}

/// A complete OAuth token set kept in the vault.
///
/// The access token is the per-request secret. The refresh token, when present,
/// allows a human-authorized refresh to replace the whole set atomically. No
/// field is serializable or printable in cleartext.
pub struct OAuthTokenSet {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    expires_at: Option<Timestamp>,
}

impl OAuthTokenSet {
    /// Creates a token set.
    pub const fn new(
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        expires_at: Option<Timestamp>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
        }
    }

    /// Access token secret.
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// Refresh token secret, if the provider issued one.
    pub fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    /// Expiry timestamp, if known.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Whether the token set must be refreshed at `now`.
    ///
    /// An expiry equal to `now` is treated as expired, so a request is never
    /// sent with a token that is about to be rejected.
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn into_access_token(self) -> SecretString {
        self.access_token
    }
}

impl fmt::Debug for OAuthTokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Secret material accepted by [`CredentialWriter::save`].
pub enum CredentialMaterial {
    /// A provider API key.
    ApiKey(SecretString),
    /// An OAuth access/refresh token set.
    OAuthTokenSet(OAuthTokenSet),
}

impl CredentialMaterial {
    /// Credential kind represented by this material.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::ApiKey(_) => CredentialKind::ApiKey,
            Self::OAuthTokenSet(_) => CredentialKind::OAuthToken,
        }
    }
}

impl fmt::Debug for CredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("CredentialMaterial::ApiKey([REDACTED])"),
            Self::OAuthTokenSet(_) => f.write_str("CredentialMaterial::OAuthTokenSet([REDACTED])"),
        }
    }
}

/// Adapter boundary for refreshing an expired OAuth token set.
///
/// The refresh happens while the per-connection resolve lock is held, so one
/// connection never runs two refreshes concurrently. Return a sanitized
/// [`CredentialFailureKind`]; never return a provider body or token in the
/// error.
pub trait CredentialRefresher: Send + Sync {
    /// Refreshes the token set for the exact connection that was selected.
    fn refresh(
        &self,
        connection: ConnectionId,
        current: &OAuthTokenSet,
    ) -> Result<OAuthTokenSet, CredentialFailureKind>;
}

/// Write-only credential handle for the trusted human settings flow.
///
/// This trait deliberately has no read method. The settings UI can save or
/// remove a credential but cannot read it back after saving.
pub trait CredentialWriter {
    /// Saves or replaces the credential for one registered connection.
    fn save(
        &self,
        connection: ConnectionId,
        credential: CredentialMaterial,
    ) -> Result<(), CoreError>;

    /// Removes the credential for one registered connection.
    fn remove(&self, connection: ConnectionId) -> Result<(), CoreError>;
}

/// Non-secret availability of one connection for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// A credential is present and usable.
    Available,
    /// A human ChatGPT login is required.
    LoginRequired,
    /// A credential is missing, expired, or otherwise needs human action.
    AuthRequired,
    /// The connection cannot be used. The failure is sanitized.
    Unavailable {
        /// Sanitized credential failure.
        failure: CredentialFailureKind,
    },
}

impl ConnectionState {
    /// Maps the connection state to the public non-secret status.
    pub const fn status(self) -> ConnectionStatus {
        match self {
            Self::Available => ConnectionStatus::Available,
            Self::LoginRequired => ConnectionStatus::LoginRequired,
            Self::AuthRequired => ConnectionStatus::AuthRequired,
            Self::Unavailable { .. } => ConnectionStatus::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureNote {
    attempt: u64,
    version: u64,
    kind: CredentialFailureKind,
}

#[derive(Debug, Default)]
struct CredentialGate {
    lock: Mutex<()>,
    version: AtomicU64,
    failed_attempts: AtomicU64,
    last_failure: Mutex<Option<FailureNote>>,
}

struct CredentialInner<V: CredentialVault> {
    directory: ConnectionDirectory,
    vault: V,
    refresher: Option<Box<dyn CredentialRefresher>>,
    gates: Mutex<BTreeMap<ConnectionId, Arc<CredentialGate>>>,
}

impl<V: CredentialVault> CredentialInner<V> {
    fn gate(&self, connection: ConnectionId) -> Arc<CredentialGate> {
        let mut gates = self
            .gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        gates
            .entry(connection)
            .or_insert_with(|| Arc::new(CredentialGate::default()))
            .clone()
    }
}

/// Factory for credential admin and broker handles.
///
/// The trusted host creates one service and gives [`CredentialAdmin`] only to
/// the human settings flow and [`CredentialBroker`] to the engine. The service
/// itself should not be handed to tools or model-driven code.
pub struct CredentialService<V: CredentialVault> {
    inner: Arc<CredentialInner<V>>,
}

impl<V: CredentialVault> CredentialService<V> {
    /// Creates a service without a refresh adapter. Expired OAuth token sets
    /// resolve to a structured failure.
    pub fn new(directory: ConnectionDirectory, vault: V) -> Self {
        Self {
            inner: Arc::new(CredentialInner {
                directory,
                vault,
                refresher: None,
                gates: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Creates a service with a refresh adapter.
    pub fn with_refresher(
        directory: ConnectionDirectory,
        vault: V,
        refresher: impl CredentialRefresher + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(CredentialInner {
                directory,
                vault,
                refresher: Some(Box::new(refresher)),
                gates: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Write-only handle for the human settings flow.
    pub fn admin(&self) -> CredentialAdmin<V> {
        CredentialAdmin {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Read/resolve handle for the engine.
    pub fn broker(&self) -> CredentialBroker<V> {
        CredentialBroker {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V: CredentialVault> CredentialPort for CredentialService<V> {
    fn availability(&self, connection: &ConnectionId) -> Result<CredentialAvailability, CoreError> {
        self.broker().availability(connection)
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.broker().resolve(connection)
    }
}

/// Write-only credential handle.
///
/// This handle has no method that returns a secret. It is intended for the
/// trusted settings flow only.
pub struct CredentialAdmin<V: CredentialVault> {
    inner: Arc<CredentialInner<V>>,
}

impl<V: CredentialVault> CredentialAdmin<V> {
    /// Saves an API key for one connection.
    pub fn save_api_key(
        &self,
        connection: ConnectionId,
        api_key: SecretString,
    ) -> Result<(), CoreError> {
        self.save(connection, CredentialMaterial::ApiKey(api_key))
    }

    /// Saves an OAuth token set for one connection.
    pub fn save_oauth_token_set(
        &self,
        connection: ConnectionId,
        token_set: OAuthTokenSet,
    ) -> Result<(), CoreError> {
        self.save(connection, CredentialMaterial::OAuthTokenSet(token_set))
    }
}

impl<V: CredentialVault> Clone for CredentialAdmin<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V: CredentialVault> CredentialWriter for CredentialAdmin<V> {
    fn save(
        &self,
        connection: ConnectionId,
        credential: CredentialMaterial,
    ) -> Result<(), CoreError> {
        // Confirm the connection exists before taking its resolve gate.
        self.settings(connection)?;
        let gate = self.inner.gate(connection);
        let _guard = gate
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Re-read settings under the gate so a human settings update cannot
        // leave this save writing to a stale credential reference.
        let settings = self.settings(connection)?;
        if credential.kind() != expected_kind(settings.auth_method()) {
            return Err(credential_unavailable(
                connection,
                CredentialFailureKind::InvalidCredentialData,
            ));
        }
        let account = VaultAccount::from_credential_ref(settings.credential_ref());
        let encoded = encode_credential(&credential);
        self.inner
            .vault
            .set(&account, &encoded)
            .map_err(|failure| {
                credential_unavailable(connection, failure.credential_failure_kind())
            })?;

        gate.version.fetch_add(1, Ordering::SeqCst);
        *gate
            .last_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        Ok(())
    }

    fn remove(&self, connection: ConnectionId) -> Result<(), CoreError> {
        self.settings(connection)?;
        let gate = self.inner.gate(connection);
        let _guard = gate
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let settings = self.settings(connection)?;
        let account = VaultAccount::from_credential_ref(settings.credential_ref());
        match self.inner.vault.delete(&account) {
            Ok(()) | Err(VaultFailure::MissingItem) => {}
            Err(failure) => {
                return Err(credential_unavailable(
                    connection,
                    failure.credential_failure_kind(),
                ));
            }
        }

        gate.version.fetch_add(1, Ordering::SeqCst);
        *gate
            .last_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        Ok(())
    }
}

impl<V: CredentialVault> CredentialAdmin<V> {
    fn settings(&self, connection: ConnectionId) -> Result<ConnectionSettings, CoreError> {
        self.inner
            .directory
            .get(connection)
            .map_err(|_| credential_unavailable(connection, CredentialFailureKind::NotConfigured))
    }
}

/// Read-only credential handle used by the engine for each request.
pub struct CredentialBroker<V: CredentialVault> {
    inner: Arc<CredentialInner<V>>,
}

impl<V: CredentialVault> Clone for CredentialBroker<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V: CredentialVault> CredentialBroker<V> {
    /// Non-secret state for one connection.
    pub fn state(&self, connection: ConnectionId) -> Result<ConnectionState, CoreError> {
        self.state_at(connection, Timestamp::now())
    }

    /// Non-secret state at an explicit time. Used by tests and deterministic
    /// hosts; per-request resolution should use [`Self::resolve`].
    pub fn state_at(
        &self,
        connection: ConnectionId,
        now: Timestamp,
    ) -> Result<ConnectionState, CoreError> {
        let settings = self.settings(connection)?;
        let account = VaultAccount::from_credential_ref(settings.credential_ref());
        let bytes = match self.inner.vault.get(&account) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Ok(match settings.auth_method() {
                    AuthMethod::ApiKey => ConnectionState::AuthRequired,
                    AuthMethod::ChatGptLogin => ConnectionState::LoginRequired,
                });
            }
            Err(failure) => {
                return Ok(ConnectionState::Unavailable {
                    failure: failure.credential_failure_kind(),
                });
            }
        };
        let stored = match decode_credential(&bytes) {
            Ok(stored) => stored,
            Err(()) => {
                return Ok(ConnectionState::Unavailable {
                    failure: CredentialFailureKind::InvalidCredentialData,
                });
            }
        };
        Ok(match (settings.auth_method(), stored) {
            (AuthMethod::ApiKey, StoredCredential::ApiKey(_)) => ConnectionState::Available,
            (AuthMethod::ChatGptLogin, StoredCredential::OAuthTokenSet(set)) => {
                if set.is_expired_at(now) {
                    ConnectionState::AuthRequired
                } else {
                    ConnectionState::Available
                }
            }
            _ => ConnectionState::Unavailable {
                failure: CredentialFailureKind::InvalidCredentialData,
            },
        })
    }

    /// Public non-secret connection view including its current status.
    pub fn connection_info(&self, connection: ConnectionId) -> Result<ConnectionInfo, CoreError> {
        let settings = self.settings(connection)?;
        let state = self.state(connection)?;
        settings.public_info(state.status())
    }

    /// Resolves the credential for one request at an explicit time.
    ///
    /// Concurrent resolves for the same connection are serialized. A failed
    /// refresh is returned; an expired token is never returned as if it were
    /// fresh, and a refreshed token is stored before it is used.
    pub fn resolve_at(
        &self,
        connection: ConnectionId,
        now: Timestamp,
    ) -> Result<ResolvedCredential, CoreError> {
        // Confirm the connection exists before taking its resolve gate.
        self.settings(connection)?;
        let gate = self.inner.gate(connection);
        let observed_failures = gate.failed_attempts.load(Ordering::SeqCst);
        let _guard = gate
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Re-read under the gate so a settings update that changes the
        // credential reference is observed before this resolution continues.
        let settings = self.settings(connection)?;
        let version = gate.version.load(Ordering::SeqCst);

        if let Some(kind) = coalesced_failure(&gate, observed_failures, version) {
            return Err(credential_unavailable(connection, kind));
        }

        let account = VaultAccount::from_credential_ref(settings.credential_ref());
        let bytes = match self.inner.vault.get(&account) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(CoreError::AuthenticationRequired { connection }),
            Err(failure) => {
                return Err(credential_unavailable(
                    connection,
                    failure.credential_failure_kind(),
                ));
            }
        };
        let stored = decode_credential(&bytes).map_err(|()| {
            credential_unavailable(connection, CredentialFailureKind::InvalidCredentialData)
        })?;

        match (settings.auth_method(), stored) {
            (AuthMethod::ApiKey, StoredCredential::ApiKey(secret)) => {
                Ok(ResolvedCredential::new(CredentialKind::ApiKey, secret))
            }
            (AuthMethod::ChatGptLogin, StoredCredential::OAuthTokenSet(token_set)) => {
                if !token_set.is_expired_at(now) {
                    return Ok(ResolvedCredential::new(
                        CredentialKind::OAuthToken,
                        token_set.into_access_token(),
                    ));
                }
                let Some(refresher) = self.inner.refresher.as_ref() else {
                    return Err(credential_unavailable(
                        connection,
                        CredentialFailureKind::Expired,
                    ));
                };
                match refresher.refresh(connection, &token_set) {
                    Ok(refreshed) if !refreshed.is_expired_at(now) => {
                        let encoded = encode_oauth_token_set(&refreshed);
                        self.inner
                            .vault
                            .set(&account, &encoded)
                            .map_err(|failure| {
                                credential_unavailable(
                                    connection,
                                    failure.credential_failure_kind(),
                                )
                            })?;
                        gate.version.fetch_add(1, Ordering::SeqCst);
                        *gate
                            .last_failure
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                        Ok(ResolvedCredential::new(
                            CredentialKind::OAuthToken,
                            refreshed.into_access_token(),
                        ))
                    }
                    Ok(_) => {
                        record_refresh_failure(
                            &gate,
                            version,
                            CredentialFailureKind::RefreshFailed,
                        );
                        Err(credential_unavailable(
                            connection,
                            CredentialFailureKind::RefreshFailed,
                        ))
                    }
                    Err(kind) => {
                        record_refresh_failure(&gate, version, kind);
                        Err(credential_unavailable(connection, kind))
                    }
                }
            }
            _ => Err(credential_unavailable(
                connection,
                CredentialFailureKind::InvalidCredentialData,
            )),
        }
    }

    fn settings(&self, connection: ConnectionId) -> Result<ConnectionSettings, CoreError> {
        self.inner
            .directory
            .get(connection)
            .map_err(|_| credential_unavailable(connection, CredentialFailureKind::NotConfigured))
    }
}

impl<V: CredentialVault> CredentialPort for CredentialBroker<V> {
    fn availability(&self, connection: &ConnectionId) -> Result<CredentialAvailability, CoreError> {
        Ok(match self.state(*connection)? {
            ConnectionState::Available => CredentialAvailability::Available,
            ConnectionState::LoginRequired => CredentialAvailability::LoginRequired,
            ConnectionState::AuthRequired | ConnectionState::Unavailable { .. } => {
                CredentialAvailability::Unavailable
            }
        })
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.resolve_at(*connection, Timestamp::now())
    }
}

// Placeholder extension removed.

fn record_refresh_failure(gate: &CredentialGate, version: u64, kind: CredentialFailureKind) {
    let attempt = gate.failed_attempts.fetch_add(1, Ordering::SeqCst) + 1;
    *gate
        .last_failure
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(FailureNote {
        attempt,
        version,
        kind,
    });
}

/// Returns a failure that completed after `observed_failures` while this
/// resolver was waiting, provided the stored credential has not been replaced.
/// The check coalesces concurrent failures without permanently caching a
/// transient one: an attempt that starts after the failure retries.
fn coalesced_failure(
    gate: &CredentialGate,
    observed_failures: u64,
    version: u64,
) -> Option<CredentialFailureKind> {
    let guard = gate
        .last_failure
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let note = (*guard)?;
    (note.attempt > observed_failures && note.version == version).then_some(note.kind)
}

const fn expected_kind(auth_method: AuthMethod) -> CredentialKind {
    match auth_method {
        AuthMethod::ApiKey => CredentialKind::ApiKey,
        AuthMethod::ChatGptLogin => CredentialKind::OAuthToken,
    }
}

fn credential_unavailable(connection: ConnectionId, failure: CredentialFailureKind) -> CoreError {
    CoreError::CredentialUnavailable {
        connection,
        failure,
    }
}

enum StoredCredential {
    ApiKey(SecretString),
    OAuthTokenSet(OAuthTokenSet),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialWire {
    format: u32,
    kind: CredentialWireKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix_millis: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialWireKind {
    ApiKey,
    OAuthTokenSet,
}

fn encode_credential(credential: &CredentialMaterial) -> Vec<u8> {
    let wire = match credential {
        CredentialMaterial::ApiKey(secret) => CredentialWire {
            format: CREDENTIAL_FORMAT_VERSION,
            kind: CredentialWireKind::ApiKey,
            secret: Some(secret.expose_secret().to_owned()),
            access_token: None,
            refresh_token: None,
            expires_at_unix_millis: None,
        },
        CredentialMaterial::OAuthTokenSet(token_set) => oauth_wire(token_set),
    };
    serde_json::to_vec(&wire).expect("serializing credential wire values cannot fail")
}

fn encode_oauth_token_set(token_set: &OAuthTokenSet) -> Vec<u8> {
    let wire = oauth_wire(token_set);
    serde_json::to_vec(&wire).expect("serializing credential wire values cannot fail")
}

fn oauth_wire(token_set: &OAuthTokenSet) -> CredentialWire {
    CredentialWire {
        format: CREDENTIAL_FORMAT_VERSION,
        kind: CredentialWireKind::OAuthTokenSet,
        secret: None,
        access_token: Some(token_set.access_token.expose_secret().to_owned()),
        refresh_token: token_set
            .refresh_token
            .as_ref()
            .map(|token| token.expose_secret().to_owned()),
        expires_at_unix_millis: token_set.expires_at.map(Timestamp::as_unix_millis),
    }
}

fn decode_credential(bytes: &[u8]) -> Result<StoredCredential, ()> {
    let wire: CredentialWire = serde_json::from_slice(bytes).map_err(|_| ())?;
    if wire.format != CREDENTIAL_FORMAT_VERSION {
        return Err(());
    }
    match wire.kind {
        CredentialWireKind::ApiKey => {
            if wire.access_token.is_some()
                || wire.refresh_token.is_some()
                || wire.expires_at_unix_millis.is_some()
            {
                return Err(());
            }
            let secret = wire.secret.ok_or(())?;
            Ok(StoredCredential::ApiKey(
                SecretString::new(secret).map_err(|_| ())?,
            ))
        }
        CredentialWireKind::OAuthTokenSet => {
            if wire.secret.is_some() {
                return Err(());
            }
            let access_token = wire.access_token.ok_or(())?;
            let access_token = SecretString::new(access_token).map_err(|_| ())?;
            let refresh_token = match wire.refresh_token {
                Some(value) => Some(SecretString::new(value).map_err(|_| ())?),
                None => None,
            };
            Ok(StoredCredential::OAuthTokenSet(OAuthTokenSet::new(
                access_token,
                refresh_token,
                wire.expires_at_unix_millis.map(Timestamp::from_unix_millis),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_refs_are_opaque_connection_keys() {
        let connection = ConnectionId::new();
        let api_key = CredentialRef::for_connection(connection, AuthMethod::ApiKey);
        let login = CredentialRef::for_connection(connection, AuthMethod::ChatGptLogin);
        assert_eq!(api_key.as_str(), format!("connection/{connection}/api_key"));
        assert_ne!(api_key, login);
    }

    #[test]
    fn encoded_credentials_round_trip_without_debug_exposure() {
        let secret = SecretString::new("canary-value").unwrap();
        let material = CredentialMaterial::ApiKey(secret);
        assert!(!format!("{material:?}").contains("canary-value"));
        let encoded = encode_credential(&material);
        match decode_credential(&encoded).unwrap() {
            StoredCredential::ApiKey(decoded) => {
                assert_eq!(decoded.expose_secret(), "canary-value");
            }
            StoredCredential::OAuthTokenSet(_) => panic!("wrong credential kind"),
        }
    }

    #[test]
    fn unknown_credential_format_is_rejected() {
        let bytes = br#"{"format":99,"kind":"api_key","secret":"x"}"#;
        assert!(decode_credential(bytes).is_err());
        let bytes = br#"{"format":1,"kind":"api_key","secret":"x","extra":true}"#;
        assert!(decode_credential(bytes).is_err());
    }

    #[test]
    fn concurrent_failure_coalescing_is_bounded_by_attempt_and_credential_version() {
        let gate = CredentialGate::default();
        assert_eq!(coalesced_failure(&gate, 0, 0), None);

        record_refresh_failure(&gate, 0, CredentialFailureKind::RefreshFailed);
        assert_eq!(
            coalesced_failure(&gate, 0, 0),
            Some(CredentialFailureKind::RefreshFailed)
        );
        // A resolver that started after observing the failure may retry.
        assert_eq!(coalesced_failure(&gate, 1, 0), None);
        // A saved or refreshed credential invalidates the cached failure.
        assert_eq!(coalesced_failure(&gate, 0, 1), None);
    }
}
