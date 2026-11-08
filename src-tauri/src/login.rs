//! ChatGPT login boundary for the trusted main window.
//!
//! The WebView never sees a token, authorization URL, or provider password. The
//! host starts the official loopback flow, opens the authorization page in the
//! macOS system browser, and reports only non-secret state. Cancelling closes
//! the loopback listener through the Task 8 service.
//!
//! The token-exchange transport is deliberately not implemented in this task:
//! Task 8 confirmed the flow with mocked transports and Task 13 owns the
//! separately approved real connection. This build therefore reports that
//! completion is unavailable instead of pretending a login succeeded.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use herness_core::{ConnectionAdmin, ConnectionId};
use herness_engine_pi::auth::{
    AuthError, BrowserOpener, ChatGptAccount, ChatGptAuth, ChatGptAuthConfig, ChatGptAuthState,
    FileHostIdStore, InMemoryAccountDirectory, JwkSet, JwksError, JwksSource, PendingAuthorization,
    RefreshRequest, RevokeRequest, SignInRequest, StaticJwks, SystemClock, TermsConfirmation,
    TokenExchangeRequest, TokenResponse, TokenTransport, TokenTransportError,
};
use serde::Serialize;

use crate::credentials::MacKeychainVault;

/// Non-secret login state returned to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    /// Terms confirmation selected by this build.
    terms: String,
    /// Why login is closed, when it is closed.
    terms_reason: Option<String>,
    /// `not_started`, `pending`, or a Task 8 credential state label.
    state: String,
    /// Whether this process has a live loopback attempt.
    pending: bool,
    /// Token exchange availability in this build.
    transport: String,
    /// Non-secret account label, when one is selected.
    account_subject: Option<String>,
}

impl LoginStatus {
    fn new(state: &str, pending: bool, account_subject: Option<String>) -> Self {
        Self {
            terms: "local_unpublished_use".to_owned(),
            terms_reason: None,
            state: state.to_owned(),
            pending,
            transport: "unavailable_in_this_build".to_owned(),
            account_subject,
        }
    }
}

/// Opens authorization pages with the macOS system browser.
///
/// The URL is passed as a single process argument and never logged. Only HTTPS
/// authorization URLs are accepted.
pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, authorization_url: &str) -> Result<(), AuthError> {
        if !authorization_url.starts_with("https://") {
            return Err(AuthError::BrowserUnavailable);
        }
        std::process::Command::new("/usr/bin/open")
            .arg("-u")
            .arg(authorization_url)
            .spawn()
            .map(|_| ())
            .map_err(|_| AuthError::BrowserUnavailable)
    }
}

/// Token transport placeholder for the local, unpublished H1 build.
struct UnavailableTransport;

impl TokenTransport for UnavailableTransport {
    fn exchange(
        &self,
        _request: &TokenExchangeRequest,
    ) -> Result<TokenResponse, TokenTransportError> {
        Err(TokenTransportError::Unavailable)
    }

    fn refresh(&self, _request: &RefreshRequest) -> Result<TokenResponse, TokenTransportError> {
        Err(TokenTransportError::Unavailable)
    }

    fn revoke(&self, _request: &RevokeRequest) -> Result<(), TokenTransportError> {
        Err(TokenTransportError::Unavailable)
    }
}

/// JWKS placeholder paired with the unavailable transport.
struct UnavailableJwks;

impl JwksSource for UnavailableJwks {
    fn jwks(&self) -> Result<JwkSet, JwksError> {
        Err(JwksError::Unavailable)
    }
}

/// Per-process ChatGPT login manager.
pub struct LoginManager {
    auth: ChatGptAuth<MacKeychainVault>,
    pending: Mutex<BTreeMap<ConnectionId, Arc<PendingAuthorization>>>,
}

impl LoginManager {
    /// Builds the official flow with the confirmed local/unpublished terms gate.
    ///
    /// The gate is chosen explicitly because this workspace is a local,
    /// unpublished, non-commercial development build. Publication or commercial
    /// distribution must select a closed gate instead.
    pub fn new(
        admin: ConnectionAdmin,
        vault: MacKeychainVault,
        app_data_root: PathBuf,
    ) -> Result<Self, String> {
        let host_id = FileHostIdStore::new(app_data_root.join("chatgpt-host-id"));
        let config =
            ChatGptAuthConfig::new("herness").with_terms(TermsConfirmation::local_unpublished());
        let auth = ChatGptAuth::new(
            admin,
            vault,
            Arc::new(InMemoryAccountDirectory::new()),
            Arc::new(host_id),
            Arc::new(UnavailableTransport),
            Arc::new(UnavailableJwks),
            Arc::new(SystemClock),
            Arc::new(SystemBrowser),
            config,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            auth,
            pending: Mutex::new(BTreeMap::new()),
        })
    }

    /// Starts a new-account authorization attempt and opens the system browser.
    pub fn start(&self, connection: ConnectionId) -> Result<LoginStatus, String> {
        let pending = self
            .auth
            .begin_sign_in(&SignInRequest::new_account(connection))
            .map_err(login_error)?;
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(connection, Arc::clone(&pending));
        Ok(LoginStatus::new("pending", true, None))
    }

    /// Cancels a live attempt and closes its loopback listener.
    pub fn cancel(&self, connection: ConnectionId) -> Result<LoginStatus, String> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&connection);
        if let Some(pending) = pending {
            self.auth.cancel_sign_in(&pending).map_err(login_error)?;
        }
        self.status(connection)
    }

    /// Returns non-secret state without reading token values into the UI.
    pub fn status(&self, connection: ConnectionId) -> Result<LoginStatus, String> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&connection)
            .is_some_and(|pending| !pending.is_consumed());
        let state = self.auth.state(connection).map_err(login_error)?;
        let (label, account) = match state {
            ChatGptAuthState::LoginRequired => ("login_required", None),
            ChatGptAuthState::Available { account } => ("available", account_subject(account)),
            ChatGptAuthState::AuthenticatedWithoutPlan { account } => (
                "authenticated_without_plan",
                Some(account.subject().to_owned()),
            ),
            ChatGptAuthState::AuthRequired { account, .. } => {
                ("auth_required", account_subject(account))
            }
            ChatGptAuthState::Unavailable { .. } => ("unavailable", None),
        };
        Ok(LoginStatus::new(
            if pending { "pending" } else { label },
            pending,
            account,
        ))
    }
}

fn account_subject(account: Option<ChatGptAccount>) -> Option<String> {
    account.map(|account| account.subject().to_owned())
}

fn login_error(error: AuthError) -> String {
    // AuthError Display never contains a token, code, state, or raw URL.
    error.to_string()
}

/// Terms label for the UI when no login manager can be built.
pub fn closed_terms_status() -> LoginStatus {
    LoginStatus {
        terms: "closed".to_owned(),
        terms_reason: Some("terms_confirmation_unavailable".to_owned()),
        state: "unavailable".to_owned(),
        pending: false,
        transport: "unavailable_in_this_build".to_owned(),
        account_subject: None,
    }
}

// Keep the static JWKS constructor referenced so the unavailable pair remains a
// deliberate, replaceable seam rather than an accidental import.
#[allow(dead_code)]
fn empty_jwks() -> StaticJwks {
    StaticJwks::new(JwkSet::default())
}
