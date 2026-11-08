//! End-to-end ChatGPT authorization attempt management.
//!
//! The service starts the loopback listener before opening the browser, keeps
//! one fresh state/nonce/PKCE set per attempt, exchanges only with the issued
//! client ID and the exact callback URI, validates the ID token, saves secrets
//! only after validation, and selects a new account only after a successful
//! save.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use herness_core::{
    CHATGPT_PLAN_SCOPE, ConnectionAdmin, ConnectionDirectory, ConnectionId, ConnectionSettings,
    CoreError, CredentialAdmin, CredentialBroker, CredentialFailureKind, CredentialPort,
    CredentialRefresher, CredentialService, CredentialVault, OAuthTokenSet, OAuthTokenSetDetails,
    ResolvedCredential, SecretString, Timestamp, VaultAccount, redact_url,
};

use super::error::{AuthError, IdTokenFailure, JwksError, TokenTransportError};
use super::host_id::{HostId, HostIdManager, HostIdStore};
use super::jwk::JwksSource;
use super::listener::{AuthorizationCallback, CallbackListener};
use super::pkce::AttemptSecrets;
use super::registry::AccountDirectory;
use super::transport::{
    RefreshRequest, RemoteRevokeStatus, RevokeRequest, TokenExchangeRequest, TokenTransport,
};
use super::types::{
    AUTHORIZATION_ENDPOINT, AuthRequiredReason, ChatGptAccount, ChatGptAccountRef,
    ChatGptAuthState, Clock, ISSUER, IssuedClientId, REQUESTED_SCOPES, RESOURCE, TermsConfirmation,
    TermsGate, VerifiedIdentity,
};

/// Opens the system browser at an authorization URL.
///
/// Task 8 never opens a browser in tests and never contacts a network service.
/// Task 11 supplies the real system-browser implementation.
pub trait BrowserOpener: Send + Sync {
    /// Opens the URL. The implementation must not copy it into logs.
    fn open(&self, authorization_url: &str) -> Result<(), AuthError>;
}

/// Configuration for the ChatGPT flow.
#[derive(Debug, Clone)]
pub struct ChatGptAuthConfig {
    /// Application name sent only on first dynamic registration.
    pub agent_name: String,
    /// Preferred loopback port. A conflict falls back to an ephemeral port.
    pub preferred_redirect_port: Option<u16>,
    /// Maximum wait for the loopback callback.
    pub callback_timeout: Duration,
    /// Terms confirmation recorded by the research gate.
    pub terms: TermsConfirmation,
}

impl ChatGptAuthConfig {
    /// Creates a closed configuration.
    ///
    /// The host must explicitly select the confirmed local, unpublished gate
    /// with [`TermsConfirmation::local_unpublished`]. This keeps an accidental
    /// publication or distribution from silently enabling ChatGPT login.
    pub fn new(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: agent_name.into(),
            preferred_redirect_port: None,
            callback_timeout: Duration::from_secs(300),
            terms: TermsConfirmation {
                confirmed_on: "2026-11-08",
                gate: TermsGate::Closed(super::error::TermsGateReason::ConditionsUnconfirmed),
            },
        }
    }

    /// Sets the preferred loopback port.
    pub fn with_preferred_port(mut self, port: u16) -> Self {
        self.preferred_redirect_port = Some(port);
        self
    }

    /// Sets the callback timeout.
    pub fn with_callback_timeout(mut self, timeout: Duration) -> Self {
        self.callback_timeout = timeout;
        self
    }

    /// Replaces the terms confirmation gate.
    pub fn with_terms(mut self, terms: TermsConfirmation) -> Self {
        self.terms = terms;
        self
    }
}

/// How a sign-in attempt selects its registration.
#[derive(Clone)]
pub enum SignInMode {
    /// Register a new client with `dynamic_agent_client` and `agent_name_hint`.
    NewAccount,
    /// Reuse a saved issued client ID and optional retained hints.
    Reauthorize(ChatGptAccountRef),
}

impl fmt::Debug for SignInMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewAccount => f.write_str("SignInMode::NewAccount"),
            Self::Reauthorize(_) => f.write_str("SignInMode::Reauthorize([REDACTED])"),
        }
    }
}

/// One human sign-in request.
#[derive(Clone, Debug)]
pub struct SignInRequest {
    connection: ConnectionId,
    mode: SignInMode,
}

impl SignInRequest {
    /// Requests a new account registration.
    pub fn new_account(connection: ConnectionId) -> Self {
        Self {
            connection,
            mode: SignInMode::NewAccount,
        }
    }

    /// Requests reauthorization of a saved account.
    pub fn reauthorize(connection: ConnectionId, account: ChatGptAccountRef) -> Self {
        Self {
            connection,
            mode: SignInMode::Reauthorize(account),
        }
    }

    /// Selected connection.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }
}

/// Authorization URL wrapper whose debug output drops all query parameters and
/// user information.
pub struct AuthorizationUrl(String);

impl AuthorizationUrl {
    fn new(value: String) -> Self {
        Self(value)
    }

    /// URL for the browser opener. Never log this value directly.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// URL safe for logs and diagnostics.
    pub fn redacted(&self) -> String {
        redact_url(&self.0)
    }
}

impl fmt::Debug for AuthorizationUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AuthorizationUrl")
            .field(&self.redacted())
            .finish()
    }
}

/// Registration state selected for one authorization attempt.
#[derive(Clone, Debug)]
pub enum ClientRegistration {
    /// First-time dynamic registration with `dynamic_agent_client`.
    Unregistered,
    /// Saved issued client ID for a returning account.
    Registered(IssuedClientId),
}

/// A bound, single-use authorization attempt.
pub struct PendingAuthorization {
    connection: ConnectionId,
    registration: ClientRegistration,
    expected_account: Option<ChatGptAccount>,
    state: String,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    authorization_url: AuthorizationUrl,
    listener: CallbackListener,
    callback: Mutex<Option<AuthorizationCallback>>,
    consumed: AtomicBool,
    cancelled: AtomicBool,
}

impl PendingAuthorization {
    /// Authorization URL to hand to the browser. Never log directly.
    pub fn authorization_url(&self) -> &str {
        self.authorization_url.as_str()
    }

    /// Authorization URL with query parameters removed for logging.
    pub fn redacted_authorization_url(&self) -> String {
        self.authorization_url.redacted()
    }

    /// Exact loopback redirect URI used in both the authorization request and
    /// code exchange.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Connection this attempt belongs to.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Whether the attempt has already been completed or cancelled.
    pub fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::SeqCst)
    }

    /// Whether the human cancelled this attempt.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Waits for the loopback callback. Each attempt accepts one callback.
    pub fn wait_for_callback(&self, timeout: Duration) -> Result<AuthorizationCallback, AuthError> {
        if self.consumed.load(Ordering::SeqCst) {
            return Err(AuthError::AttemptConsumed);
        }
        if let Some(callback) = self
            .callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            return Ok(callback.clone());
        }
        let callback = self.listener.wait(timeout)?;
        *self
            .callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(callback.clone());
        Ok(callback)
    }

    /// Cancels this attempt and closes the listener without exchanging a code.
    pub fn cancel(&self) {
        if !self.consumed.swap(true, Ordering::SeqCst) {
            self.cancelled.store(true, Ordering::SeqCst);
            self.listener.close();
            *self
                .callback
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }

    fn take_callback(&self) -> Option<AuthorizationCallback> {
        self.callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn state_matches(&self, callback: &AuthorizationCallback) -> bool {
        callback.matches_state(&self.state)
    }

    fn nonce(&self) -> &str {
        &self.nonce
    }

    fn code_verifier(&self) -> &str {
        &self.code_verifier
    }
}

impl fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthorization")
            .field("connection", &self.connection)
            .field("registration", &self.registration)
            .field("expected_account", &self.expected_account)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("authorization_url", &self.authorization_url.redacted())
            .field("consumed", &self.is_consumed())
            .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Result of a fully validated sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInOutcome {
    /// Verified account registration.
    pub account: ChatGptAccount,
    /// Whether the granted scopes permit ChatGPT plan inference.
    pub plan_enabled: bool,
    /// Granted scopes from the token response.
    pub granted_scopes: Vec<String>,
}

/// Result of local sign-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutOutcome {
    /// Account that was signed out.
    pub account: ChatGptAccount,
    /// Always true when this method returns successfully.
    pub local_credentials_removed: bool,
    /// Honest status of remote revocation; never confirmed by this build.
    pub remote_revoke: RemoteRevokeStatus,
    /// The issued client ID mapping was retained for a later sign-in.
    pub issued_client_retained: bool,
    /// The host ID was retained.
    pub host_id_retained: bool,
}

/// ChatGPT OAuth service.
pub struct ChatGptAuth<V: CredentialVault + Clone> {
    directory: ConnectionDirectory,
    admin: ConnectionAdmin,
    service: CredentialService<V>,
    credential_admin: CredentialAdmin<V>,
    broker: CredentialBroker<V>,
    vault: V,
    host_ids: HostIdManager,
    accounts: Arc<dyn AccountDirectory>,
    transport: Arc<dyn TokenTransport>,
    jwks: Arc<dyn JwksSource>,
    clock: Arc<dyn Clock>,
    browser: Arc<dyn BrowserOpener>,
    config: ChatGptAuthConfig,
    active: Mutex<BTreeMap<ConnectionId, Weak<PendingAuthorization>>>,
}

impl<V: CredentialVault + Clone> ChatGptAuth<V> {
    /// Builds the service and wires the Task 7 refresh machinery.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admin: ConnectionAdmin,
        vault: V,
        accounts: Arc<dyn AccountDirectory>,
        host_id_store: Arc<dyn HostIdStore>,
        transport: Arc<dyn TokenTransport>,
        jwks: Arc<dyn JwksSource>,
        clock: Arc<dyn Clock>,
        browser: Arc<dyn BrowserOpener>,
        config: ChatGptAuthConfig,
    ) -> Result<Self, AuthError> {
        let refresher = ChatGptRefresher {
            transport: Arc::clone(&transport),
            jwks: Arc::clone(&jwks),
            clock: Arc::clone(&clock),
        };
        let service =
            CredentialService::with_refresher(admin.directory(), vault.clone(), refresher);
        Ok(Self {
            directory: admin.directory(),
            admin,
            credential_admin: service.admin(),
            broker: service.broker(),
            service,
            vault,
            host_ids: HostIdManager::new(host_id_store),
            accounts,
            transport,
            jwks,
            clock,
            browser,
            config,
            active: Mutex::new(BTreeMap::new()),
        })
    }

    /// Confirmed terms status for this build.
    pub const fn terms(&self) -> TermsGate {
        self.config.terms.gate
    }

    /// Starts a new authorization attempt.
    ///
    /// The loopback listener is bound first, then fresh state/nonce/PKCE values
    /// are generated, then the browser opener is called.
    pub fn begin_sign_in(
        &self,
        request: &SignInRequest,
    ) -> Result<Arc<PendingAuthorization>, AuthError> {
        if !self.config.terms.gate.permits_login() {
            return Err(AuthError::TermsGateClosed {
                reason: self
                    .config
                    .terms
                    .gate
                    .reason()
                    .unwrap_or(super::error::TermsGateReason::ConditionsUnconfirmed),
            });
        }
        let connection = request.connection;
        self.chatgpt_settings(connection)?;

        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active.retain(|_, pending| {
                pending
                    .upgrade()
                    .is_some_and(|pending| !pending.is_consumed())
            });
            if active
                .get(&connection)
                .is_some_and(|pending| pending.upgrade().is_some())
            {
                return Err(AuthError::AttemptInProgress);
            }
        }

        let (registration, expected_account, agent_name_hint, id_token_hint, login_hint) =
            match &request.mode {
                SignInMode::NewAccount => {
                    if self.config.agent_name.trim().is_empty() {
                        return Err(AuthError::AgentNameRequired);
                    }
                    (
                        ClientRegistration::Unregistered,
                        None,
                        Some(self.config.agent_name.trim().to_owned()),
                        None,
                        None,
                    )
                }
                SignInMode::Reauthorize(reference) => {
                    let account = self
                        .accounts
                        .find_ref(connection, reference)?
                        .ok_or(AuthError::AccountNotFound { connection })?;
                    let token_set = self
                        .broker
                        .account_token_set_at(connection, account.vault_account())
                        .map_err(map_core_error)?;
                    let id_token_hint = token_set
                        .as_ref()
                        .and_then(|set| set.id_token())
                        .map(|token| token.expose_secret().to_owned());
                    let login_hint = account.email().map(str::to_owned).or_else(|| {
                        token_set
                            .as_ref()
                            .and_then(|set| set.account_email())
                            .map(str::to_owned)
                    });
                    (
                        ClientRegistration::Registered(account.client_id().clone()),
                        Some(account),
                        None,
                        id_token_hint,
                        login_hint,
                    )
                }
            };

        let host_id = self
            .host_ids
            .ensure()
            .map_err(|failure| AuthError::HostId { failure })?;
        let listener = CallbackListener::bind(self.config.preferred_redirect_port)?;
        let secrets = AttemptSecrets::generate()?;
        let redirect_uri = listener.redirect_uri();

        let mut query = Vec::new();
        let client_id = match &registration {
            ClientRegistration::Unregistered => "dynamic_agent_client",
            ClientRegistration::Registered(client_id) => client_id.as_str(),
        };
        query.push(("client_id".to_owned(), client_id.to_owned()));
        if let Some(agent_name) = agent_name_hint.as_deref() {
            query.push(("agent_name_hint".to_owned(), agent_name.to_owned()));
        }
        query.push(("ext_agent_host_id".to_owned(), host_id.as_str().to_owned()));
        if let Some(id_token) = id_token_hint.as_deref() {
            query.push(("id_token_hint".to_owned(), id_token.to_owned()));
        }
        if let Some(login_hint) = login_hint.as_deref() {
            query.push(("login_hint".to_owned(), login_hint.to_owned()));
        }
        query.push(("response_type".to_owned(), "code".to_owned()));
        query.push(("redirect_uri".to_owned(), redirect_uri.clone()));
        query.push(("scope".to_owned(), REQUESTED_SCOPES.join(" ")));
        query.push(("resource".to_owned(), RESOURCE.to_owned()));
        query.push(("state".to_owned(), secrets.state().to_owned()));
        query.push(("nonce".to_owned(), secrets.nonce().to_owned()));
        query.push(("code_challenge_method".to_owned(), "S256".to_owned()));
        query.push((
            "code_challenge".to_owned(),
            secrets.code_challenge().to_owned(),
        ));
        let encoded = query
            .into_iter()
            .map(|(key, value)| format!("{}={}", encode_component(&key), encode_component(&value)))
            .collect::<Vec<_>>()
            .join("&");
        let authorization_url =
            AuthorizationUrl::new(format!("{AUTHORIZATION_ENDPOINT}?{encoded}"));

        if let Err(error) = self
            .browser
            .open(authorization_url.as_str())
            .map_err(|_| AuthError::BrowserUnavailable)
        {
            listener.close();
            return Err(error);
        }

        let pending = Arc::new(PendingAuthorization {
            connection,
            registration,
            expected_account,
            state: secrets.state().to_owned(),
            nonce: secrets.nonce().to_owned(),
            code_verifier: secrets.code_verifier().to_owned(),
            redirect_uri,
            authorization_url,
            listener,
            callback: Mutex::new(None),
            consumed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        });
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active.retain(|_, pending| {
                pending
                    .upgrade()
                    .is_some_and(|pending| !pending.is_consumed())
            });
            if active
                .get(&connection)
                .is_some_and(|pending| pending.upgrade().is_some())
            {
                pending.listener.close();
                return Err(AuthError::AttemptInProgress);
            }
            active.insert(connection, Arc::downgrade(&pending));
        }
        Ok(pending)
    }

    /// Waits for the pending callback, using the configured timeout.
    pub fn wait_for_callback(
        &self,
        pending: &PendingAuthorization,
    ) -> Result<AuthorizationCallback, AuthError> {
        pending.wait_for_callback(self.config.callback_timeout)
    }

    /// Validates the callback and token response, then saves the account.
    ///
    /// The attempt is single-use: a second completion is a callback replay and
    /// never exchanges a code again. Existing credentials are not replaced
    /// until the new login is fully validated and saved.
    pub fn complete_sign_in(
        &self,
        pending: &Arc<PendingAuthorization>,
    ) -> Result<SignInOutcome, AuthError> {
        if pending
            .consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return if pending.cancelled.load(Ordering::SeqCst) {
                Err(AuthError::Cancelled)
            } else {
                Err(AuthError::CallbackReplay)
            };
        }
        self.remove_active(pending);
        pending.listener.close();
        let callback = pending.take_callback().ok_or(AuthError::CallbackTimeout)?;
        if !pending.state_matches(&callback) {
            return Err(AuthError::StateMismatch);
        }
        if let Some(error) = callback.error() {
            if error == "access_denied" {
                return Err(AuthError::AccessDenied);
            }
            return Err(AuthError::InvalidCallback {
                violation: super::error::CallbackViolation::AuthorizationError,
            });
        }
        let issued_client_id = match &pending.registration {
            ClientRegistration::Unregistered => {
                let value = callback
                    .client_id()
                    .ok_or(AuthError::MissingIssuedClientId)?;
                IssuedClientId::new(value)?
            }
            ClientRegistration::Registered(expected) => match callback.client_id() {
                Some(value) => {
                    let received = IssuedClientId::new(value)?;
                    if &received != expected {
                        return Err(AuthError::ClientMismatch);
                    }
                    expected.clone()
                }
                None => expected.clone(),
            },
        };
        let code = callback.code().ok_or(AuthError::MissingCode)?;
        let response = self
            .transport
            .exchange(&TokenExchangeRequest::new(
                issued_client_id.as_str(),
                code,
                pending.code_verifier(),
                &pending.redirect_uri,
                RESOURCE,
            ))
            .map_err(|failure| AuthError::Transport { failure })?;
        let parts = response.into_parts();
        let now = self.clock.now();
        let id_token = parts.id_token.as_ref().ok_or(AuthError::MissingIdToken)?;
        let keys = self
            .jwks
            .jwks()
            .map_err(|failure: JwksError| AuthError::Jwks { failure })?;
        let identity = super::jwt::validate_id_token(
            id_token.expose_secret(),
            &keys,
            issued_client_id.as_str(),
            Some(pending.nonce()),
            now,
        )
        .map_err(|failure: IdTokenFailure| AuthError::IdToken { failure })?;

        if let Some(expected) = &pending.expected_account
            && expected.subject() != identity.subject
        {
            return Err(AuthError::AccountMismatch);
        }

        let account = ChatGptAccount::new(
            pending.connection,
            issued_client_id.clone(),
            &identity,
            identity.email.clone(),
        )?;
        let scopes = parts
            .scope
            .as_deref()
            .map(parse_scopes)
            .or_else(|| callback.scope().map(parse_scopes))
            .unwrap_or_default();
        let plan_enabled = scopes.iter().any(|scope| scope == CHATGPT_PLAN_SCOPE);
        if !plan_enabled && pending.expected_account.is_some() {
            // A returning account's plan permission was revoked or downgraded.
            // Keep the previously validated material rather than replacing a
            // usable credential with a plan-less one.
            return Err(AuthError::PlanScopeMissing);
        }
        let expires_at = expiry_at(now, parts.expires_in)?;
        let token_set = OAuthTokenSet::with_details(
            parts.access_token,
            parts.refresh_token,
            Some(expires_at),
            OAuthTokenSetDetails {
                id_token: parts.id_token,
                granted_scopes: scopes.clone(),
                plan_usage: Some(plan_enabled),
                account_subject: Some(identity.subject.clone()),
                issued_client_id: Some(issued_client_id.as_str().to_owned()),
                account_email: identity.email.clone(),
            },
        );

        self.credential_admin
            .save_chatgpt_account_token_set(pending.connection, account.vault_account(), token_set)
            .map_err(map_core_error)?;
        if let Err(error) = self.accounts.upsert(account.clone()) {
            let _ = self
                .credential_admin
                .remove_chatgpt_account(pending.connection, account.vault_account());
            return Err(error);
        }

        if plan_enabled {
            let settings = self.chatgpt_settings(pending.connection)?;
            let selected = settings
                .select_chatgpt_account(account.vault_account().clone())
                .map_err(|_| AuthError::SettingsUnavailable)?;
            self.admin
                .update(selected)
                .map_err(|_| AuthError::SettingsUnavailable)?;
        }

        Ok(SignInOutcome {
            account,
            plan_enabled,
            granted_scopes: scopes,
        })
    }

    /// Cancels a pending attempt without exchanging its code.
    pub fn cancel_sign_in(&self, pending: &Arc<PendingAuthorization>) -> Result<(), AuthError> {
        pending.cancel();
        self.remove_active(pending);
        Ok(())
    }

    /// Non-secret state of the selected account for one connection.
    pub fn state(&self, connection: ConnectionId) -> Result<ChatGptAuthState, AuthError> {
        let settings = self.chatgpt_settings(connection)?;
        let Some(selected) = settings.selected_chatgpt_account() else {
            return Ok(ChatGptAuthState::LoginRequired);
        };
        let account = self
            .accounts
            .accounts(connection)?
            .into_iter()
            .find(|account| account.vault_account() == selected);
        let token_set = match self.broker.account_token_set_at(connection, selected) {
            Ok(token_set) => token_set,
            Err(error) => {
                return Ok(ChatGptAuthState::Unavailable {
                    reason: match map_core_error(error) {
                        AuthError::Vault { .. } => AuthRequiredReason::VaultUnavailable,
                        _ => AuthRequiredReason::InvalidCredentialData,
                    },
                });
            }
        };
        let Some(token_set) = token_set else {
            return Ok(ChatGptAuthState::LoginRequired);
        };
        if token_set.is_expired_at(self.clock.now()) {
            return Ok(ChatGptAuthState::AuthRequired {
                account,
                reason: AuthRequiredReason::Expired,
            });
        }
        if !token_set.plan_scope_satisfied() {
            return Ok(match account {
                Some(account) => ChatGptAuthState::AuthenticatedWithoutPlan { account },
                None => ChatGptAuthState::Unavailable {
                    reason: AuthRequiredReason::PlanScopeMissing,
                },
            });
        }
        Ok(ChatGptAuthState::Available { account })
    }

    /// State of one saved account, including an authenticated account that was
    /// not selected because its plan scope was missing.
    pub fn account_state(
        &self,
        connection: ConnectionId,
        reference: &ChatGptAccountRef,
    ) -> Result<ChatGptAuthState, AuthError> {
        self.chatgpt_settings(connection)?;
        let account = self
            .accounts
            .find_ref(connection, reference)?
            .ok_or(AuthError::AccountNotFound { connection })?;
        let token_set = self
            .broker
            .account_token_set_at(connection, account.vault_account())
            .map_err(map_core_error)?;
        let Some(token_set) = token_set else {
            return Ok(ChatGptAuthState::LoginRequired);
        };
        if token_set.is_expired_at(self.clock.now()) {
            return Ok(ChatGptAuthState::AuthRequired {
                account: Some(account),
                reason: AuthRequiredReason::Expired,
            });
        }
        if !token_set.plan_scope_satisfied() {
            return Ok(ChatGptAuthState::AuthenticatedWithoutPlan { account });
        }
        Ok(ChatGptAuthState::Available {
            account: Some(account),
        })
    }

    /// Saved accounts for a connection, without secrets.
    pub fn accounts(&self, connection: ConnectionId) -> Result<Vec<ChatGptAccount>, AuthError> {
        self.chatgpt_settings(connection)?;
        self.accounts.accounts(connection)
    }

    /// Write-only credential handle for the trusted host adapter.
    pub fn credential_admin(&self) -> CredentialAdmin<V> {
        self.service.admin()
    }

    /// Read/resolve credential port backed by the ChatGPT refresh machinery.
    ///
    /// The desktop host shares this port with the engine so an expired ChatGPT
    /// access token is refreshed through the same per-connection gate instead
    /// of falling back to an unrefreshed credential.
    pub fn credential_port(&self) -> Arc<dyn CredentialPort + Send + Sync>
    where
        V: 'static,
    {
        Arc::new(self.service.broker())
    }

    /// Reads the selected token set without refreshing. Intended for the
    /// trusted host adapter, not for UI display.
    pub fn token_set_at(
        &self,
        connection: ConnectionId,
    ) -> Result<Option<OAuthTokenSet>, CoreError> {
        self.broker.token_set_at(connection)
    }

    /// Reads one account-scoped token set without refreshing.
    pub fn account_token_set_at(
        &self,
        connection: ConnectionId,
        account: &VaultAccount,
    ) -> Result<Option<OAuthTokenSet>, CoreError> {
        self.broker.account_token_set_at(connection, account)
    }

    /// Resolves the selected account's access token and refreshes it through
    /// the Task 7 per-connection serialized path when needed.
    pub fn resolve_at(
        &self,
        connection: ConnectionId,
        now: Timestamp,
    ) -> Result<ResolvedCredential, CoreError> {
        self.broker.resolve_at(connection, now)
    }

    /// Resolves at the system clock's current time.
    pub fn resolve(&self, connection: ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.resolve_at(connection, self.clock.now())
    }

    /// Forces one refresh through the per-connection gate.
    ///
    /// Used only by the opt-in real-connection controller, which must verify
    /// refresh without waiting for the access token to expire. The refreshed
    /// token set is validated and saved before it is returned.
    pub fn force_refresh(&self, connection: ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.broker.refresh_at(connection, self.clock.now())
    }

    /// Signed-out account selected in the persisted settings.
    ///
    /// This path does not depend on the in-memory account registration
    /// directory. It reconstructs the non-secret account reference from the
    /// stored token set's verified subject and issued client ID, so the opt-in
    /// real-connection sign-out works in a fresh controller process.
    pub fn sign_out_selected(&self, connection: ConnectionId) -> Result<SignOutOutcome, AuthError> {
        let settings = self.chatgpt_settings(connection)?;
        let selected = settings
            .selected_chatgpt_account()
            .cloned()
            .ok_or(AuthError::AccountNotFound { connection })?;
        let token_set = self
            .broker
            .account_token_set_at(connection, &selected)
            .map_err(map_core_error)?
            .ok_or(AuthError::AccountNotFound { connection })?;
        let client_id = token_set
            .issued_client_id()
            .ok_or(AuthError::InvalidTokenResponse)?;
        let subject = token_set
            .account_subject()
            .ok_or(AuthError::InvalidTokenResponse)?;
        let reference = ChatGptAccountRef::new(IssuedClientId::new(client_id)?, subject)?;
        let email = token_set.account_email().map(str::to_owned);
        self.sign_out_registration(connection, selected, &reference, email)
    }

    /// Signs out one account.
    ///
    /// Remote revocation is attempted when a refresh token exists. Provider
    /// confirmation is reported only when the transport received an empty HTTP
    /// 200 from the discovered revocation endpoint. The local vault item
    /// (access, refresh, and retained ID token) is removed, and the selected
    /// account is cleared. The non-secret client/account mapping and host ID are
    /// retained for a later sign-in.
    pub fn sign_out(
        &self,
        connection: ConnectionId,
        reference: &ChatGptAccountRef,
    ) -> Result<SignOutOutcome, AuthError> {
        self.chatgpt_settings(connection)?;
        let account = self
            .accounts
            .find_ref(connection, reference)?
            .ok_or(AuthError::AccountNotFound { connection })?;
        self.sign_out_registration(
            connection,
            account.vault_account().clone(),
            reference,
            account.email().map(str::to_owned),
        )
    }

    fn sign_out_registration(
        &self,
        connection: ConnectionId,
        vault_account: VaultAccount,
        reference: &ChatGptAccountRef,
        email: Option<String>,
    ) -> Result<SignOutOutcome, AuthError> {
        let account = ChatGptAccount::new(
            connection,
            reference.client_id().clone(),
            &VerifiedIdentity {
                issuer: ISSUER.to_owned(),
                subject: reference.subject().to_owned(),
                email: email.clone(),
            },
            email,
        )?;
        if account.vault_account() != &vault_account {
            return Err(AuthError::AccountMismatch);
        }
        let token_set = self
            .broker
            .account_token_set_at(connection, &vault_account)
            .map_err(map_core_error)?;

        let remote_revoke = match token_set.as_ref().and_then(|set| set.refresh_token()) {
            Some(refresh_token) => {
                let request =
                    RevokeRequest::new(account.client_id().as_str(), refresh_token.expose_secret());
                match self.transport.revoke_confirmed(&request) {
                    Ok(true) => RemoteRevokeStatus::Confirmed,
                    Ok(false) => RemoteRevokeStatus::RequestAcceptedUnverified,
                    Err(_) => RemoteRevokeStatus::FailedUnverified,
                }
            }
            None => RemoteRevokeStatus::NotAttempted,
        };

        self.credential_admin
            .remove_chatgpt_account(connection, account.vault_account())
            .map_err(map_core_error)?;

        let current = self.chatgpt_settings(connection)?;
        if current
            .selected_chatgpt_account()
            .is_some_and(|selected| selected == account.vault_account())
        {
            self.admin
                .update(current.clear_chatgpt_account())
                .map_err(|_| AuthError::SettingsUnavailable)?;
        }

        // Confirm the vault no longer contains the account record.
        let stored =
            self.vault
                .get(account.vault_account())
                .map_err(|failure| AuthError::Vault {
                    failure: failure.credential_failure_kind(),
                })?;
        if stored.is_some() {
            return Err(AuthError::Vault {
                failure: CredentialFailureKind::InvalidCredentialData,
            });
        }

        Ok(SignOutOutcome {
            account,
            local_credentials_removed: true,
            remote_revoke,
            issued_client_retained: true,
            host_id_retained: true,
        })
    }

    /// Persisted host ID for this installation, creating it when necessary.
    pub fn host_id(&self) -> Result<HostId, AuthError> {
        self.host_ids
            .ensure()
            .map_err(|failure| AuthError::HostId { failure })
    }

    fn chatgpt_settings(&self, connection: ConnectionId) -> Result<ConnectionSettings, AuthError> {
        let settings = self
            .directory
            .get(connection)
            .map_err(|_| AuthError::NotChatGptConnection { connection })?;
        if settings.provider() != herness_core::Provider::OpenAi
            || settings.auth_method() != herness_core::AuthMethod::ChatGptLogin
        {
            return Err(AuthError::NotChatGptConnection { connection });
        }
        Ok(settings)
    }

    fn remove_active(&self, pending: &Arc<PendingAuthorization>) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active
            .get(&pending.connection())
            .is_some_and(|stored| stored.ptr_eq(&Arc::downgrade(pending)))
        {
            active.remove(&pending.connection());
        }
    }
}

/// Refresher used by the Task 7 per-connection serialized resolve path.
struct ChatGptRefresher {
    transport: Arc<dyn TokenTransport>,
    jwks: Arc<dyn JwksSource>,
    clock: Arc<dyn Clock>,
}

impl CredentialRefresher for ChatGptRefresher {
    fn refresh(
        &self,
        _connection: ConnectionId,
        current: &OAuthTokenSet,
    ) -> Result<OAuthTokenSet, CredentialFailureKind> {
        let client_id = current
            .issued_client_id()
            .filter(|value| *value != herness_core::CHATGPT_DYNAMIC_AGENT_CLIENT)
            .ok_or(CredentialFailureKind::InvalidCredentialData)?;
        let refresh_token = current
            .refresh_token()
            .ok_or(CredentialFailureKind::Expired)?;
        let response = self
            .transport
            .refresh(&RefreshRequest::new(
                client_id,
                refresh_token.expose_secret(),
                RESOURCE,
            ))
            .map_err(map_transport_to_credential)?;
        let parts = response.into_parts();
        let now = self.clock.now();
        let expires_at =
            expiry_at(now, parts.expires_in).map_err(|_| CredentialFailureKind::RefreshFailed)?;

        let id_token = match parts.id_token {
            Some(token) => {
                let keys = self
                    .jwks
                    .jwks()
                    .map_err(|_| CredentialFailureKind::RefreshFailed)?;
                let identity = super::jwt::validate_id_token(
                    token.expose_secret(),
                    &keys,
                    client_id,
                    None,
                    now,
                )
                .map_err(|_| CredentialFailureKind::RefreshFailed)?;
                if current
                    .account_subject()
                    .is_some_and(|subject| subject != identity.subject)
                {
                    return Err(CredentialFailureKind::RefreshFailed);
                }
                Some(token)
            }
            None => current.id_token().map(|token| {
                SecretString::new(token.expose_secret().to_owned())
                    .expect("an existing non-empty secret remains non-empty")
            }),
        };

        let scopes = match parts.scope.as_deref().map(parse_scopes) {
            Some(scopes) if !scopes.is_empty() => scopes,
            _ => current.granted_scopes().to_vec(),
        };
        if !scopes.is_empty() && !scopes.iter().any(|scope| scope == CHATGPT_PLAN_SCOPE) {
            return Err(CredentialFailureKind::PlanScopeMissing);
        }
        let refresh_token = match parts.refresh_token {
            Some(token) => token,
            None => SecretString::new(refresh_token.expose_secret().to_owned())
                .map_err(|_| CredentialFailureKind::RefreshFailed)?,
        };
        let subject = current.account_subject().map(str::to_owned);
        let client_id = Some(client_id.to_owned());
        let email = current.account_email().map(str::to_owned);
        let plan_usage = if scopes.is_empty() {
            current.plan_usage()
        } else {
            Some(true)
        };
        Ok(OAuthTokenSet::with_details(
            parts.access_token,
            Some(refresh_token),
            Some(expires_at),
            OAuthTokenSetDetails {
                id_token,
                granted_scopes: scopes,
                plan_usage,
                account_subject: subject,
                issued_client_id: client_id,
                account_email: email,
            },
        ))
    }
}

fn map_transport_to_credential(failure: TokenTransportError) -> CredentialFailureKind {
    match failure {
        TokenTransportError::InvalidGrant => CredentialFailureKind::RefreshFailed,
        TokenTransportError::Network
        | TokenTransportError::Rejected
        | TokenTransportError::InvalidResponse
        | TokenTransportError::Unavailable
        | TokenTransportError::RevocationUnconfirmed => CredentialFailureKind::RefreshFailed,
    }
}

fn map_core_error(error: CoreError) -> AuthError {
    match error {
        CoreError::CredentialUnavailable { failure, .. } => AuthError::Vault { failure },
        _ => AuthError::SettingsUnavailable,
    }
}

fn expiry_at(now: Timestamp, expires_in: u64) -> Result<Timestamp, AuthError> {
    let millis = expires_in
        .checked_mul(1000)
        .ok_or(AuthError::InvalidTokenResponse)?;
    now.as_unix_millis()
        .checked_add(millis)
        .map(Timestamp::from_unix_millis)
        .ok_or(AuthError::InvalidTokenResponse)
}

fn parse_scopes(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

fn encode_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}
