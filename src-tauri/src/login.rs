//! ChatGPT login boundary for the trusted main window.
//!
//! The WebView never sees a token, authorization URL, or provider password. The
//! host starts the official loopback flow, opens the authorization page in the
//! macOS system browser, waits for the callback on a host-owned worker thread,
//! and reports only non-secret state.
//!
//! Task 13 connects the real HTTPS token transport and OIDC discovery/JWKS
//! path. Real login, refresh, and sign-out remain opt-in: the terms gate is
//! closed unless this trusted app explicitly selects
//! [`TermsConfirmation::local_unpublished`], and the Phase B runbook is the only
//! approved way to exercise a real provider.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use herness_core::{
    ConnectionAdmin, ConnectionId, CredentialAdmin, CredentialPort, CredentialVault,
};
use herness_engine_pi::auth::{
    AuthError, BrowserOpener, ChatGptAccount, ChatGptAuth, ChatGptAuthConfig, ChatGptAuthState,
    FileHostIdStore, InMemoryAccountDirectory, JwksSource, PendingAuthorization, SignInRequest,
    SystemClock, TermsConfirmation, TokenTransport, official_auth_components,
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
    /// Token transport configured in this build. Real login is still unverified
    /// until the Phase B runbook records its evidence.
    transport: String,
    /// Non-secret account label, when one is selected.
    account_subject: Option<String>,
    /// Sanitized completion error, when the last completed attempt failed.
    error: Option<String>,
}

impl LoginStatus {
    fn new(
        state: &str,
        pending: bool,
        account_subject: Option<String>,
        error: Option<String>,
    ) -> Self {
        Self {
            terms: "local_unpublished_use".to_owned(),
            terms_reason: None,
            state: state.to_owned(),
            pending,
            transport: "https_configured_unverified".to_owned(),
            account_subject,
            error,
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

/// Sanitized result of a completed background attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LoginCompletion {
    error: Option<String>,
}

/// Per-process ChatGPT login manager.
pub struct LoginManager<V: CredentialVault + Clone = MacKeychainVault> {
    auth: Arc<ChatGptAuth<V>>,
    pending: Arc<Mutex<BTreeMap<ConnectionId, Arc<PendingAuthorization>>>>,
    completions: Arc<Mutex<BTreeMap<ConnectionId, LoginCompletion>>>,
    generations: Arc<Mutex<BTreeMap<ConnectionId, u64>>>,
}

impl LoginManager<MacKeychainVault> {
    /// Builds the official flow with the confirmed local/unpublished terms gate
    /// and the real HTTPS transport.
    ///
    /// The gate is chosen explicitly because this workspace is a local,
    /// unpublished, non-commercial development build. Publication or commercial
    /// distribution must select a closed gate instead.
    pub fn new(
        admin: ConnectionAdmin,
        vault: MacKeychainVault,
        app_data_root: PathBuf,
    ) -> Result<Self, String> {
        Self::with_browser(
            admin,
            vault,
            app_data_root,
            Arc::new(SystemBrowser),
            TermsConfirmation::local_unpublished(),
        )
    }
}

impl<V: CredentialVault + Clone + 'static> LoginManager<V> {
    /// Builds the service with an explicit browser and terms gate.
    ///
    /// Production uses [`SystemBrowser`] and the local/unpublished gate. Tests
    /// inject a recording browser so no real browser is opened.
    pub fn with_browser(
        admin: ConnectionAdmin,
        vault: V,
        app_data_root: PathBuf,
        browser: Arc<dyn BrowserOpener>,
        terms: TermsConfirmation,
    ) -> Result<Self, String> {
        let (transport, jwks) = official_auth_components().map_err(|error| error.to_string())?;
        Self::with_components(
            admin,
            vault,
            app_data_root,
            browser,
            terms,
            Arc::new(transport),
            Arc::new(jwks),
        )
    }

    /// Builds the service with explicit transport and JWKS boundaries.
    #[allow(clippy::too_many_arguments)]
    pub fn with_components(
        admin: ConnectionAdmin,
        vault: V,
        app_data_root: PathBuf,
        browser: Arc<dyn BrowserOpener>,
        terms: TermsConfirmation,
        transport: Arc<dyn TokenTransport>,
        jwks: Arc<dyn JwksSource>,
    ) -> Result<Self, String> {
        let host_id = FileHostIdStore::new(app_data_root.join("chatgpt-host-id"));
        let config = ChatGptAuthConfig::new("herness").with_terms(terms);
        let auth = ChatGptAuth::new(
            admin,
            vault,
            Arc::new(InMemoryAccountDirectory::new()),
            Arc::new(host_id),
            transport,
            jwks,
            Arc::new(SystemClock),
            browser,
            config,
        )
        .map_err(login_error)?;
        Ok(Self {
            auth: Arc::new(auth),
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            completions: Arc::new(Mutex::new(BTreeMap::new())),
            generations: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Starts a new-account authorization attempt and opens the system browser.
    ///
    /// The callback wait and token exchange run on a host worker thread. The
    /// trusted UI polls [`Self::status`] and never receives a token, code, or
    /// authorization URL.
    pub fn start(&self, connection: ConnectionId) -> Result<LoginStatus, String> {
        let pending = self
            .auth
            .begin_sign_in(&SignInRequest::new_account(connection))
            .map_err(login_error)?;
        let generation = {
            let mut generations = self
                .generations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let generation = generations.entry(connection).or_insert(0);
            *generation = generation.saturating_add(1);
            *generation
        };
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(connection, Arc::clone(&pending));
        self.completions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&connection);
        if let Err(error) = self.spawn_completion(connection, Arc::clone(&pending), generation) {
            let _ = self.auth.cancel_sign_in(&pending);
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&connection);
            return Err(error);
        }
        self.status(connection)
    }

    fn spawn_completion(
        &self,
        connection: ConnectionId,
        pending: Arc<PendingAuthorization>,
        generation: u64,
    ) -> Result<(), String> {
        let auth = Arc::clone(&self.auth);
        let pending_map = Arc::clone(&self.pending);
        let completions = Arc::clone(&self.completions);
        let generations = Arc::clone(&self.generations);
        std::thread::Builder::new()
            .name("herness-chatgpt-login".to_owned())
            .spawn(move || {
                let result = auth
                    .wait_for_callback(&pending)
                    .and_then(|_| auth.complete_sign_in(&pending));
                let cancelled = pending.is_cancelled();
                if result.is_err() && !cancelled {
                    let _ = auth.cancel_sign_in(&pending);
                }
                {
                    let mut map = pending_map
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if map
                        .get(&connection)
                        .is_some_and(|current| Arc::ptr_eq(current, &pending))
                    {
                        map.remove(&connection);
                    }
                }
                let still_current = generations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&connection)
                    .is_some_and(|current| *current == generation);
                if !still_current {
                    return;
                }
                let error = if cancelled {
                    None
                } else {
                    result.err().map(|error| error.to_string())
                };
                completions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(connection, LoginCompletion { error });
            })
            .map(|_| ())
            .map_err(|_| "the ChatGPT login worker could not start".to_owned())
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
        {
            let mut generations = self
                .generations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let generation = generations.entry(connection).or_insert(0);
            *generation = generation.saturating_add(1);
        }
        self.completions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&connection);
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
        let completion_error = if pending {
            None
        } else {
            self.completions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&connection)
                .and_then(|completion| completion.error.clone())
        };
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
            completion_error,
        ))
    }

    /// Write-only credential handle sharing this login's refresh machinery.
    pub fn credential_admin(&self) -> CredentialAdmin<V> {
        self.auth.credential_admin()
    }

    /// Credential port sharing this login's refresh machinery.
    pub fn credential_port(&self) -> Arc<dyn CredentialPort + Send + Sync> {
        self.auth.credential_port()
    }

    /// Selected token set without refreshing. Never exposed to the UI.
    pub fn token_set_at(
        &self,
        connection: ConnectionId,
    ) -> Result<Option<herness_core::OAuthTokenSet>, herness_core::CoreError> {
        self.auth.token_set_at(connection)
    }

    /// Forces one refresh through the per-connection serialized credential
    /// gate. Used only by the explicit controller real-check.
    pub fn force_refresh(&self, connection: ConnectionId) -> Result<(), herness_core::CoreError> {
        self.auth.force_refresh(connection).map(|_| ())
    }

    /// Signs out the selected account, attempting remote revocation.
    pub fn sign_out_selected(
        &self,
        connection: ConnectionId,
    ) -> Result<herness_engine_pi::auth::SignOutOutcome, AuthError> {
        self.auth.sign_out_selected(connection)
    }

    /// Account directory view used by the trusted UI and real-check.
    pub fn accounts(&self, connection: ConnectionId) -> Result<Vec<ChatGptAccount>, AuthError> {
        self.auth.accounts(connection)
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
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use herness_core::{AuthMethod, ConnectionSettings, Provider, VaultAccount, VaultFailure};

    use super::*;

    #[derive(Default)]
    struct RecordingBrowser {
        urls: Mutex<Vec<String>>,
    }

    impl BrowserOpener for RecordingBrowser {
        fn open(&self, authorization_url: &str) -> Result<(), AuthError> {
            self.urls
                .lock()
                .expect("browser urls")
                .push(authorization_url.to_owned());
            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct TestVault {
        items: Arc<Mutex<BTreeMap<VaultAccount, Vec<u8>>>>,
    }

    impl CredentialVault for TestVault {
        fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
            self.items
                .lock()
                .map_err(|_| VaultFailure::Unavailable)?
                .insert(account.clone(), data.to_vec());
            Ok(())
        }

        fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
            Ok(self
                .items
                .lock()
                .map_err(|_| VaultFailure::Unavailable)?
                .get(account)
                .cloned())
        }

        fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure> {
            self.items
                .lock()
                .map_err(|_| VaultFailure::Unavailable)?
                .remove(account);
            Ok(())
        }
    }

    fn chatgpt_connection() -> (ConnectionAdmin, ConnectionId) {
        let admin = ConnectionAdmin::new();
        let connection = ConnectionId::new();
        admin
            .add(
                ConnectionSettings::new(
                    connection,
                    Provider::OpenAi,
                    "gpt-test",
                    AuthMethod::ChatGptLogin,
                    None,
                    None,
                )
                .expect("settings"),
            )
            .expect("connection");
        (admin, connection)
    }

    #[test]
    fn start_opens_the_system_browser_and_cancel_closes_the_attempt() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (admin, connection) = chatgpt_connection();
        let browser = Arc::new(RecordingBrowser::default());
        let manager = LoginManager::with_browser(
            admin,
            TestVault::default(),
            temp.path().to_path_buf(),
            browser.clone(),
            TermsConfirmation::local_unpublished(),
        )
        .expect("login manager");

        let started = manager.start(connection).expect("start login");
        assert!(started.pending);
        assert_eq!(started.terms, "local_unpublished_use");
        assert_eq!(started.transport, "https_configured_unverified");
        assert_eq!(started.error, None);
        let urls = browser.urls.lock().expect("urls");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("https://auth.openai.com/"));
        drop(urls);

        let cancelled = manager.cancel(connection).expect("cancel login");
        assert!(!cancelled.pending);
        assert_eq!(cancelled.state, "login_required");
        assert_eq!(cancelled.error, None);
    }

    #[test]
    fn the_terms_gate_uses_the_explicit_local_unpublished_confirmation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (admin, connection) = chatgpt_connection();
        let browser = Arc::new(RecordingBrowser::default());
        let manager = LoginManager::with_browser(
            admin,
            TestVault::default(),
            temp.path().to_path_buf(),
            browser,
            TermsConfirmation::local_unpublished(),
        )
        .expect("login manager");
        assert_eq!(
            manager.auth.terms(),
            herness_engine_pi::auth::TermsGate::LocalUnpublishedUse
        );
        assert!(manager.status(connection).is_ok());
    }

    #[test]
    fn the_system_browser_rejects_non_https_urls_without_launching() {
        assert!(SystemBrowser.open("http://example.com/").is_err());
        assert!(SystemBrowser.open("file:///tmp/page.html").is_err());
    }
}
