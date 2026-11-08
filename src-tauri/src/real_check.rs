//! Opt-in real-connection check for the desktop binary.
//!
//! The controller invokes this module only through `herness-desktop
//! --real-check <connection-id> [--list-models|--refresh|--sign-out]` or
//! `herness-desktop --forget-connection <connection-id>`. The Tauri app and the
//! normal workspace tests never call it.
//!
//! Every mode selects exactly one already-stored connection and the credential
//! resolved through the Keychain broker. There is no provider/model fallback.
//! Evidence is sanitized: provider, auth method, model, endpoint class, terminal
//! status, latency, provider-reported usage, catalog model names, and a fixed
//! failure label. Tokens, API keys, ID tokens, authorization URLs, raw provider
//! bodies, and raw provider error text are never written.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use herness_core::{
    ConnectionAdmin, ConnectionId, ConnectionSettings, CredentialAdmin, CredentialVault,
    CredentialWriter, Timestamp,
};
use herness_engine_pi::auth::{RemoteRevokeStatus, SignOutOutcome};
use herness_engine_pi::{ChatGptModel, ProbeFailure, ProbeUsage, ProviderEndpoints, probe};
use serde::Serialize;

use crate::credentials::MacKeychainVault;
use crate::host::DesktopHost;
use crate::login::LoginManager;

/// Evidence schema version written by this build.
pub const REAL_CHECK_EVIDENCE_VERSION: u32 = 1;

/// Synthetic prompt presented to the human before a request check.
pub const REAL_CHECK_PROMPT: &str = herness_engine_pi::REAL_CHECK_PROMPT;

/// One controller mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealCheckMode {
    /// One minimal text request through the selected provider route.
    Request,
    /// ChatGPT model catalog read only.
    ListModels,
    /// ChatGPT access-token refresh only.
    Refresh,
    /// ChatGPT local sign-out plus remote revocation attempt.
    SignOut,
    /// Delete the stored credential and remove the connection from host state.
    Forget,
}

impl RealCheckMode {
    /// Stable evidence label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::ListModels => "list_models",
            Self::Refresh => "refresh",
            Self::SignOut => "sign_out",
            Self::Forget => "forget",
        }
    }

    /// Whether this mode is limited to ChatGPT-login connections.
    pub const fn requires_chatgpt(self) -> bool {
        matches!(self, Self::ListModels | Self::Refresh | Self::SignOut)
    }
}

/// Parsed real-check request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealCheckArgs {
    /// Selected stored connection.
    pub connection: ConnectionId,
    /// Selected mode.
    pub mode: RealCheckMode,
}

/// Controller action parsed from the binary arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliAction {
    /// Run one check mode.
    RealCheck(RealCheckArgs),
    /// Forget a test connection and its credential.
    Forget(ConnectionId),
}

/// Parses the controller flags, ignoring unrelated application flags.
pub fn parse_cli(args: impl IntoIterator<Item = String>) -> Result<Option<CliAction>, String> {
    let mut args = args.into_iter();
    let mut real_check: Option<String> = None;
    let mut forget: Option<String> = None;
    let mut mode = RealCheckMode::Request;
    let mut mode_set = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--real-check" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--real-check requires a connection id".to_owned())?;
                if real_check.replace(value).is_some() {
                    return Err("--real-check was supplied more than once".to_owned());
                }
            }
            "--forget-connection" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--forget-connection requires a connection id".to_owned())?;
                if forget.replace(value).is_some() {
                    return Err("--forget-connection was supplied more than once".to_owned());
                }
            }
            "--list-models" => set_mode(&mut mode, &mut mode_set, RealCheckMode::ListModels)?,
            "--refresh" => set_mode(&mut mode, &mut mode_set, RealCheckMode::Refresh)?,
            "--sign-out" => set_mode(&mut mode, &mut mode_set, RealCheckMode::SignOut)?,
            _ => {}
        }
    }
    if real_check.is_some() && forget.is_some() {
        return Err("--real-check and --forget-connection are mutually exclusive".to_owned());
    }
    if let Some(value) = forget {
        if mode_set {
            return Err("a mode flag cannot be combined with --forget-connection".to_owned());
        }
        let connection = value
            .parse::<ConnectionId>()
            .map_err(|_| "--forget-connection requires a UUID connection id".to_owned())?;
        return Ok(Some(CliAction::Forget(connection)));
    }
    if let Some(value) = real_check {
        let connection = value
            .parse::<ConnectionId>()
            .map_err(|_| "--real-check requires a UUID connection id".to_owned())?;
        return Ok(Some(CliAction::RealCheck(RealCheckArgs {
            connection,
            mode,
        })));
    }
    if mode_set {
        return Err("--list-models, --refresh, and --sign-out require --real-check".to_owned());
    }
    Ok(None)
}

fn set_mode(
    mode: &mut RealCheckMode,
    mode_set: &mut bool,
    selected: RealCheckMode,
) -> Result<(), String> {
    if *mode_set && *mode != selected {
        return Err("only one real-check mode can be selected".to_owned());
    }
    *mode = selected;
    *mode_set = true;
    Ok(())
}

/// Sanitized evidence written for every attempt, including failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealCheckEvidence {
    /// Evidence schema version.
    pub schema_version: u32,
    /// Attempt time.
    pub checked_at_unix_ms: u64,
    /// Selected connection.
    pub connection_id: String,
    /// Selected provider, or `unknown`.
    pub provider: String,
    /// Selected authentication method, or `unknown`.
    pub auth_method: String,
    /// Selected model, or `unknown`.
    pub model: String,
    /// Controller mode.
    pub mode: String,
    /// Wire route or operation class.
    pub endpoint_class: String,
    /// Non-secret custom endpoint origin, if applicable.
    pub endpoint_origin: Option<String>,
    /// `completed`, `incomplete`, `listed`, `refreshed`, `signed_out`,
    /// `credential_removed`, or `failed`.
    pub terminal_status: String,
    /// Fixed sanitized failure label, if any.
    pub failure: Option<String>,
    /// Model-request or token-operation latency.
    pub latency_ms: Option<u64>,
    /// ChatGPT catalog latency.
    pub catalog_latency_ms: Option<u64>,
    /// Number of selectable catalog models.
    pub catalog_model_count: Option<usize>,
    /// Provider-reported usage, if available.
    pub usage: Option<RealCheckUsage>,
    /// Selectable ChatGPT catalog entries for `list_models`.
    pub models: Option<Vec<RealCheckModel>>,
    /// Remote revocation status for ChatGPT sign-out.
    pub remote_revoke: Option<String>,
    /// Whether local credentials were removed.
    pub local_credentials_removed: Option<bool>,
}

/// Sanitized usage evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealCheckUsage {
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Total tokens.
    pub total_tokens: u64,
}

/// One selectable catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealCheckModel {
    /// Model identifier sent on a request.
    pub slug: String,
    /// Human-facing name.
    pub display_name: String,
}

/// Result of one controller invocation.
pub struct RealCheckReport {
    /// Sanitized evidence.
    pub evidence: RealCheckEvidence,
    /// Process exit code.
    pub exit_code: i32,
    /// Sanitized one-line summary for stdout.
    pub summary: String,
    /// Evidence path when it was written.
    pub evidence_path: Option<PathBuf>,
}

/// Dependencies for a testable controller run.
pub struct RealCheckContext<'a, V: CredentialVault + Clone + 'static> {
    /// The one desktop host opened from private app state.
    pub host: &'a mut DesktopHost,
    /// ChatGPT login control, when the production composition built it.
    pub login: Option<&'a LoginManager<V>>,
    /// Write-only credential handle sharing the same gate as `login`.
    pub credential_admin: &'a CredentialAdmin<V>,
    /// Provider endpoints (official in production).
    pub endpoints: ProviderEndpoints,
    /// Directory for sanitized evidence files.
    pub evidence_dir: PathBuf,
}

/// Runs one real-check mode.
pub fn run_with<V: CredentialVault + Clone + 'static>(
    context: &mut RealCheckContext<'_, V>,
    args: RealCheckArgs,
) -> RealCheckReport {
    let connection = args.connection;
    let settings = context.host.directory().get(connection).ok();
    let mut evidence = base_evidence(connection, args.mode, settings.as_ref());

    if settings.is_none() {
        evidence.failure = Some(ProbeFailure::ConnectionNotFound.as_str().to_owned());
        evidence.terminal_status = "failed".to_owned();
        return finish(context, evidence, 2);
    }
    let settings = settings.expect("checked");
    if args.mode.requires_chatgpt()
        && settings.auth_method() != herness_core::AuthMethod::ChatGptLogin
    {
        evidence.failure = Some(ProbeFailure::UnsupportedConnection.as_str().to_owned());
        evidence.terminal_status = "failed".to_owned();
        return finish(context, evidence, 2);
    }

    match args.mode {
        RealCheckMode::Request => {
            match probe::probe_connection(
                context.host.directory(),
                Arc::clone(context.host.credentials()),
                &context.endpoints,
                connection,
            ) {
                Ok(outcome) => {
                    evidence.endpoint_class = outcome.endpoint_class.to_owned();
                    evidence.endpoint_origin = outcome.endpoint_origin;
                    evidence.terminal_status = outcome.terminal.as_str().to_owned();
                    evidence.latency_ms = Some(outcome.latency_ms);
                    evidence.catalog_latency_ms = outcome.catalog_latency_ms;
                    evidence.catalog_model_count = outcome.catalog_model_count;
                    evidence.usage = outcome.usage.map(usage_evidence);
                    finish(context, evidence, 0)
                }
                Err(failure) => {
                    evidence.failure = Some(failure.as_str().to_owned());
                    evidence.terminal_status = "failed".to_owned();
                    let code = if failure.is_auth_failure() {
                        3
                    } else if failure.is_configuration_failure() {
                        2
                    } else {
                        4
                    };
                    finish(context, evidence, code)
                }
            }
        }
        RealCheckMode::ListModels => {
            evidence.endpoint_class = "chatgpt_model_catalog".to_owned();
            let started = std::time::Instant::now();
            match probe::list_chatgpt_models(
                context.host.directory(),
                Arc::clone(context.host.credentials()),
                &context.endpoints,
                connection,
            ) {
                Ok(models) => {
                    evidence.terminal_status = "listed".to_owned();
                    evidence.latency_ms = Some(elapsed_millis(started));
                    evidence.catalog_model_count = Some(models.len());
                    evidence.models = Some(models.into_iter().map(model_evidence).collect());
                    finish(context, evidence, 0)
                }
                Err(failure) => {
                    evidence.failure = Some(failure.as_str().to_owned());
                    evidence.terminal_status = "failed".to_owned();
                    let code = if failure.is_auth_failure() {
                        3
                    } else if failure.is_configuration_failure() {
                        2
                    } else {
                        4
                    };
                    finish(context, evidence, code)
                }
            }
        }
        RealCheckMode::Refresh => {
            evidence.endpoint_class = "chatgpt_token_refresh".to_owned();
            let Some(login) = context.login else {
                evidence.failure = Some("login_unavailable".to_owned());
                evidence.terminal_status = "failed".to_owned();
                return finish(context, evidence, 2);
            };
            let started = std::time::Instant::now();
            match login.force_refresh(connection) {
                Ok(()) => {
                    evidence.terminal_status = "refreshed".to_owned();
                    evidence.latency_ms = Some(elapsed_millis(started));
                    finish(context, evidence, 0)
                }
                Err(error) => {
                    evidence.failure = Some(credential_failure_label(&error));
                    evidence.terminal_status = "failed".to_owned();
                    finish(context, evidence, 3)
                }
            }
        }
        RealCheckMode::SignOut => {
            evidence.endpoint_class = "chatgpt_revocation".to_owned();
            let Some(login) = context.login else {
                evidence.failure = Some("login_unavailable".to_owned());
                evidence.terminal_status = "failed".to_owned();
                return finish(context, evidence, 2);
            };
            let started = std::time::Instant::now();
            match login.sign_out_selected(connection) {
                Ok(outcome) => {
                    evidence.terminal_status = "signed_out".to_owned();
                    evidence.latency_ms = Some(elapsed_millis(started));
                    apply_sign_out(&mut evidence, &outcome);
                    finish(context, evidence, 0)
                }
                Err(error) => {
                    evidence.failure = Some("sign_out_failed".to_owned());
                    evidence.terminal_status = "failed".to_owned();
                    let _ = error;
                    finish(context, evidence, 6)
                }
            }
        }
        RealCheckMode::Forget => {
            evidence.endpoint_class = "credential_deletion".to_owned();
            forget_with(context, connection, evidence)
        }
    }
}

/// Deletes one test connection and its Keychain item, attempting revocation
/// first for a ChatGPT login.
pub fn run_forget_with<V: CredentialVault + Clone + 'static>(
    context: &mut RealCheckContext<'_, V>,
    connection: ConnectionId,
) -> RealCheckReport {
    let settings = context.host.directory().get(connection).ok();
    let mut evidence = base_evidence(connection, RealCheckMode::Forget, settings.as_ref());
    evidence.endpoint_class = "credential_deletion".to_owned();
    if settings.is_none() {
        let mut evidence = evidence;
        evidence.failure = Some(ProbeFailure::ConnectionNotFound.as_str().to_owned());
        evidence.terminal_status = "failed".to_owned();
        return finish(context, evidence, 2);
    }
    forget_with(context, connection, evidence)
}

fn forget_with<V: CredentialVault + Clone + 'static>(
    context: &mut RealCheckContext<'_, V>,
    connection: ConnectionId,
    mut evidence: RealCheckEvidence,
) -> RealCheckReport {
    let settings = context
        .host
        .directory()
        .get(connection)
        .expect("caller checked the connection");
    if settings.auth_method() == herness_core::AuthMethod::ChatGptLogin {
        let Some(login) = context.login else {
            evidence.failure = Some("login_unavailable".to_owned());
            evidence.terminal_status = "failed".to_owned();
            return finish(context, evidence, 2);
        };
        let started = std::time::Instant::now();
        match login.sign_out_selected(connection) {
            Ok(outcome) => apply_sign_out(&mut evidence, &outcome),
            // A previous sign-out already cleared the selected account. The
            // connection can still be forgotten; any unreachable orphan item
            // is recorded and removed with the documented manual cleanup.
            Err(herness_engine_pi::auth::AuthError::AccountNotFound { .. }) => {
                evidence.remote_revoke = Some("not_attempted".to_owned());
                evidence.local_credentials_removed = Some(true);
            }
            Err(_) => {
                evidence.failure = Some("sign_out_failed".to_owned());
                evidence.terminal_status = "failed".to_owned();
                return finish(context, evidence, 6);
            }
        }
        evidence.latency_ms = Some(elapsed_millis(started));
    }
    // Remove any legacy base credential item as well as the account-scoped
    // item that sign-out already deleted. A missing item is not a failure.
    if context.credential_admin.remove(connection).is_err() {
        evidence.failure = Some("credential_removal_failed".to_owned());
        evidence.terminal_status = "failed".to_owned();
        return finish(context, evidence, 6);
    }
    if context.host.forget_connection(connection).is_err() {
        evidence.failure = Some("forget_failed".to_owned());
        evidence.terminal_status = "failed".to_owned();
        return finish(context, evidence, 6);
    }
    evidence.terminal_status = if evidence.remote_revoke.is_some() {
        "signed_out".to_owned()
    } else {
        "credential_removed".to_owned()
    };
    finish(context, evidence, 0)
}

fn apply_sign_out(evidence: &mut RealCheckEvidence, outcome: &SignOutOutcome) {
    evidence.remote_revoke = Some(revoke_label(outcome.remote_revoke).to_owned());
    evidence.local_credentials_removed = Some(outcome.local_credentials_removed);
}

fn revoke_label(status: RemoteRevokeStatus) -> &'static str {
    match status {
        RemoteRevokeStatus::NotAttempted => "not_attempted",
        RemoteRevokeStatus::Confirmed => "confirmed",
        RemoteRevokeStatus::RequestAcceptedUnverified => "request_accepted_unverified",
        RemoteRevokeStatus::FailedUnverified => "failed_unverified",
    }
}

fn base_evidence(
    connection: ConnectionId,
    mode: RealCheckMode,
    settings: Option<&ConnectionSettings>,
) -> RealCheckEvidence {
    RealCheckEvidence {
        schema_version: REAL_CHECK_EVIDENCE_VERSION,
        checked_at_unix_ms: Timestamp::now().as_unix_millis(),
        connection_id: connection.to_string(),
        provider: settings
            .map(|settings| settings.provider().to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        auth_method: settings
            .map(|settings| match settings.auth_method() {
                herness_core::AuthMethod::ApiKey => "api_key".to_owned(),
                herness_core::AuthMethod::ChatGptLogin => "chatgpt_login".to_owned(),
            })
            .unwrap_or_else(|| "unknown".to_owned()),
        model: settings
            .map(|settings| settings.model().to_owned())
            .unwrap_or_else(|| "unknown".to_owned()),
        mode: mode.as_str().to_owned(),
        endpoint_class: settings
            .map(|settings| probe::endpoint_class(settings).to_owned())
            .unwrap_or_else(|| "unregistered".to_owned()),
        endpoint_origin: settings
            .and_then(|settings| settings.endpoint().map(|endpoint| endpoint.as_url())),
        terminal_status: "failed".to_owned(),
        failure: None,
        latency_ms: None,
        catalog_latency_ms: None,
        catalog_model_count: None,
        usage: None,
        models: None,
        remote_revoke: None,
        local_credentials_removed: None,
    }
}

fn usage_evidence(usage: ProbeUsage) -> RealCheckUsage {
    RealCheckUsage {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens: usage.total_tokens,
    }
}

fn model_evidence(model: ChatGptModel) -> RealCheckModel {
    RealCheckModel {
        slug: model.slug().to_owned(),
        display_name: model.display_name().to_owned(),
    }
}

fn credential_failure_label(error: &herness_core::CoreError) -> String {
    match error {
        herness_core::CoreError::AuthenticationRequired { .. } => {
            "authentication_required".to_owned()
        }
        herness_core::CoreError::CredentialUnavailable { .. } => {
            "credential_unavailable".to_owned()
        }
        _ => "refresh_failed".to_owned(),
    }
}

fn elapsed_millis(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn finish<V: CredentialVault + Clone + 'static>(
    context: &RealCheckContext<'_, V>,
    mut evidence: RealCheckEvidence,
    exit_code: i32,
) -> RealCheckReport {
    let evidence_path = match write_evidence(&context.evidence_dir, &evidence) {
        Ok(path) => Some(path),
        Err(_) => {
            evidence.failure = Some("evidence_write_failed".to_owned());
            evidence.terminal_status = "failed".to_owned();
            None
        }
    };
    let exit_code = if evidence_path.is_none() {
        7
    } else {
        exit_code
    };
    let summary = summary(&evidence, evidence_path.as_deref());
    RealCheckReport {
        evidence,
        exit_code,
        summary,
        evidence_path,
    }
}

fn summary(evidence: &RealCheckEvidence, path: Option<&Path>) -> String {
    let suffix = path
        .map(|path| format!(" evidence={}", path.display()))
        .unwrap_or_default();
    match evidence.failure.as_deref() {
        Some(failure) => format!(
            "REAL_CHECK_FAILED: mode={} provider={} model={} failure={}{suffix}",
            evidence.mode, evidence.provider, evidence.model, failure
        ),
        None => {
            let mut line = format!(
                "REAL_CHECK_OK: mode={} provider={} model={} terminal={}",
                evidence.mode, evidence.provider, evidence.model, evidence.terminal_status
            );
            if let Some(latency) = evidence.latency_ms {
                line.push_str(&format!(" latency_ms={latency}"));
            }
            if let Some(usage) = evidence.usage {
                line.push_str(&format!(
                    " input_tokens={} output_tokens={} total_tokens={}",
                    usage.input_tokens, usage.output_tokens, usage.total_tokens
                ));
            }
            if let Some(revoke) = evidence.remote_revoke.as_deref() {
                line.push_str(&format!(" remote_revoke={revoke}"));
            }
            line.push_str(&suffix);
            line
        }
    }
}

fn write_evidence(directory: &Path, evidence: &RealCheckEvidence) -> Result<PathBuf, String> {
    fs::create_dir_all(directory).map_err(|_| "evidence directory".to_owned())?;
    let path = directory.join(format!(
        "real-check-{}-{}-{}.json",
        evidence.checked_at_unix_ms, evidence.connection_id, evidence.mode
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&path)
        .map_err(|_| "evidence file".to_owned())?;
    serde_json::to_writer_pretty(&mut file, evidence)
        .map_err(|_| "evidence serialization".to_owned())?;
    file.write_all(b"\n")
        .map_err(|_| "evidence write".to_owned())?;
    Ok(path)
}

/// Runs the controller action against the real private app state.
pub fn run_production(action: CliAction) -> i32 {
    let Ok(root) = app_data_root() else {
        eprintln!("REAL_CHECK_FAILED: failure=app_data_root_unavailable");
        return 2;
    };
    if fs::create_dir_all(&root).is_err() {
        eprintln!("REAL_CHECK_FAILED: failure=app_data_root_unavailable");
        return 2;
    }
    let connections = ConnectionAdmin::new();
    let vault = MacKeychainVault::default();
    let login = match LoginManager::new(connections.clone(), vault, root.clone()) {
        Ok(login) => login,
        Err(_) => {
            eprintln!("REAL_CHECK_FAILED: failure=chatgpt_login_unavailable");
            return 2;
        }
    };
    let credentials = login.credential_port();
    let credential_admin = login.credential_admin();
    let (mut host, _) = match DesktopHost::open(
        &root,
        connections,
        credentials,
        ProviderEndpoints::official(),
    ) {
        Ok(host) => host,
        Err(_) => {
            eprintln!("REAL_CHECK_FAILED: failure=host_unavailable");
            return 2;
        }
    };
    let mut context = RealCheckContext {
        host: &mut host,
        login: Some(&login),
        credential_admin: &credential_admin,
        endpoints: ProviderEndpoints::official(),
        evidence_dir: root.join("real-check"),
    };
    let report = match action {
        CliAction::RealCheck(args) => run_with(&mut context, args),
        CliAction::Forget(connection) => run_forget_with(&mut context, connection),
    };
    println!("{}", report.summary);
    report.exit_code
}

/// Binary entry for the controller flags.
pub fn main_entry(args: impl IntoIterator<Item = String>) -> Option<i32> {
    match parse_cli(args) {
        Ok(Some(action)) => Some(run_production(action)),
        Ok(None) => None,
        Err(message) => {
            eprintln!("REAL_CHECK_USAGE: {message}");
            Some(2)
        }
    }
}

fn app_data_root() -> Result<PathBuf, ()> {
    if let Ok(value) = std::env::var("HERNESS_APP_DATA_ROOT") {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(());
        }
        return Ok(path);
    }
    let home = std::env::var("HOME").map_err(|_| ())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("dev.herness.desktop")
        .join("herness"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use herness_core::{
        AuthMethod, ConnectionSettings, CredentialService, Provider, SecretString, VaultAccount,
        VaultFailure,
    };
    use herness_engine_pi::auth::{AuthError, BrowserOpener, TermsConfirmation};
    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct RecordingBrowser;

    impl BrowserOpener for RecordingBrowser {
        fn open(&self, _authorization_url: &str) -> Result<(), AuthError> {
            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct FakeVault {
        items: Arc<Mutex<BTreeMap<VaultAccount, Vec<u8>>>>,
        gets: Arc<Mutex<usize>>,
    }

    impl CredentialVault for FakeVault {
        fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
            self.items
                .lock()
                .map_err(|_| VaultFailure::Unavailable)?
                .insert(account.clone(), data.to_vec());
            Ok(())
        }

        fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
            *self.gets.lock().map_err(|_| VaultFailure::Unavailable)? += 1;
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

    fn api_key_settings() -> ConnectionSettings {
        ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("settings")
    }

    fn chatgpt_settings() -> ConnectionSettings {
        ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-test",
            AuthMethod::ChatGptLogin,
            None,
            None,
        )
        .expect("settings")
    }

    struct Harness {
        _temp: TempDir,
        root: PathBuf,
        admin: ConnectionAdmin,
        vault: FakeVault,
    }

    fn harness(settings: Option<ConnectionSettings>) -> Harness {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().to_path_buf();
        let admin = ConnectionAdmin::new();
        if let Some(settings) = settings {
            admin.add(settings).expect("connection");
        }
        Harness {
            _temp: temp,
            root,
            admin,
            vault: FakeVault::default(),
        }
    }

    fn open_host(harness: &Harness, service: &CredentialService<FakeVault>) -> DesktopHost {
        DesktopHost::open(
            &harness.root,
            harness.admin.clone(),
            Arc::new(service.broker()),
            ProviderEndpoints::official(),
        )
        .expect("host")
        .0
    }

    #[test]
    fn parse_cli_supports_each_explicit_mode() {
        let connection = ConnectionId::new();
        assert_eq!(
            parse_cli(vec!["--real-check".to_owned(), connection.to_string()]).expect("parse"),
            Some(CliAction::RealCheck(RealCheckArgs {
                connection,
                mode: RealCheckMode::Request
            }))
        );
        assert_eq!(
            parse_cli(vec![
                "--real-check".to_owned(),
                connection.to_string(),
                "--list-models".to_owned()
            ])
            .expect("parse"),
            Some(CliAction::RealCheck(RealCheckArgs {
                connection,
                mode: RealCheckMode::ListModels
            }))
        );
        assert_eq!(
            parse_cli(vec![
                "--forget-connection".to_owned(),
                connection.to_string()
            ])
            .expect("parse"),
            Some(CliAction::Forget(connection))
        );
        assert_eq!(parse_cli(Vec::<String>::new()).expect("parse"), None);
    }

    #[test]
    fn parse_cli_rejects_ambiguous_or_invalid_flags() {
        assert!(parse_cli(vec!["--real-check".to_owned()]).is_err());
        assert!(parse_cli(vec!["--real-check".to_owned(), "not-a-uuid".to_owned()]).is_err());
        assert!(parse_cli(vec!["--refresh".to_owned()]).is_err());
        assert!(
            parse_cli(vec![
                "--real-check".to_owned(),
                ConnectionId::new().to_string(),
                "--refresh".to_owned(),
                "--sign-out".to_owned()
            ])
            .is_err()
        );
        assert!(
            parse_cli(vec![
                "--real-check".to_owned(),
                ConnectionId::new().to_string(),
                "--forget-connection".to_owned(),
                ConnectionId::new().to_string()
            ])
            .is_err()
        );
    }

    #[test]
    fn evidence_serialization_has_no_secret_fields() {
        let evidence = base_evidence(
            ConnectionId::new(),
            RealCheckMode::Request,
            Some(&api_key_settings()),
        );
        let json = serde_json::to_string(&evidence).expect("serialize");
        for forbidden in [
            "accessToken",
            "apiKey",
            "idToken",
            "authorization",
            "refreshToken",
        ] {
            assert!(!json.contains(forbidden), "unexpected field {forbidden}");
        }
        assert!(json.contains("inputTokens") || json.contains("usage"));
    }

    #[test]
    fn an_unknown_connection_writes_a_sanitized_failure_and_reads_no_credential() {
        let harness = harness(None);
        let service = CredentialService::new(harness.admin.directory(), harness.vault.clone());
        let mut host = open_host(&harness, &service);
        let credential_admin = service.admin();
        let mut context = RealCheckContext {
            host: &mut host,
            login: None::<&LoginManager<FakeVault>>,
            credential_admin: &credential_admin,
            endpoints: ProviderEndpoints::official(),
            evidence_dir: harness.root.join("real-check"),
        };
        let report = run_with(
            &mut context,
            RealCheckArgs {
                connection: ConnectionId::new(),
                mode: RealCheckMode::Request,
            },
        );
        assert_eq!(report.exit_code, 2);
        assert_eq!(
            report.evidence.failure.as_deref(),
            Some("connection_not_found")
        );
        assert_eq!(report.evidence.provider, "unknown");
        assert!(report.evidence_path.is_some());
        assert_eq!(*harness.vault.gets.lock().expect("gets"), 0);
    }

    #[test]
    fn a_missing_api_key_fails_before_any_provider_request() {
        let settings = api_key_settings();
        let connection = settings.connection_id();
        let harness = harness(Some(settings));
        let service = CredentialService::new(harness.admin.directory(), harness.vault.clone());
        let mut host = open_host(&harness, &service);
        let credential_admin = service.admin();
        let mut context = RealCheckContext {
            host: &mut host,
            login: None::<&LoginManager<FakeVault>>,
            credential_admin: &credential_admin,
            endpoints: ProviderEndpoints::official(),
            evidence_dir: harness.root.join("real-check"),
        };
        let report = run_with(
            &mut context,
            RealCheckArgs {
                connection,
                mode: RealCheckMode::Request,
            },
        );
        assert_eq!(report.exit_code, 3);
        assert_eq!(
            report.evidence.failure.as_deref(),
            Some("authentication_required")
        );
        assert!(report.evidence_path.is_some());
    }

    #[test]
    fn forgetting_a_never_logged_in_chatgpt_connection_succeeds() {
        let settings = chatgpt_settings();
        let connection = settings.connection_id();
        let harness = harness(Some(settings));
        let login = LoginManager::with_browser(
            harness.admin.clone(),
            harness.vault.clone(),
            harness.root.clone(),
            Arc::new(RecordingBrowser),
            TermsConfirmation::local_unpublished(),
        )
        .expect("login manager");
        let credentials = login.credential_port();
        let credential_admin = login.credential_admin();
        let mut host = DesktopHost::open(
            &harness.root,
            harness.admin.clone(),
            credentials,
            ProviderEndpoints::official(),
        )
        .expect("host")
        .0;
        let mut context = RealCheckContext {
            host: &mut host,
            login: Some(&login),
            credential_admin: &credential_admin,
            endpoints: ProviderEndpoints::official(),
            evidence_dir: harness.root.join("real-check"),
        };
        let report = run_forget_with(&mut context, connection);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.evidence.terminal_status, "signed_out");
        assert_eq!(
            report.evidence.remote_revoke.as_deref(),
            Some("not_attempted")
        );
        assert_eq!(report.evidence.local_credentials_removed, Some(true));
        assert!(host.directory().get(connection).is_err());
    }

    #[test]
    fn provide_forget_removes_the_vault_item_and_persisted_connection() {
        let settings = api_key_settings();
        let connection = settings.connection_id();
        let harness = harness(Some(settings));
        let service = CredentialService::new(harness.admin.directory(), harness.vault.clone());
        let credential_admin = service.admin();
        credential_admin
            .save_api_key(
                connection,
                SecretString::new("test-key-canary").expect("secret"),
            )
            .expect("save key");
        let mut host = open_host(&harness, &service);
        let mut context = RealCheckContext {
            host: &mut host,
            login: None::<&LoginManager<FakeVault>>,
            credential_admin: &credential_admin,
            endpoints: ProviderEndpoints::official(),
            evidence_dir: harness.root.join("real-check"),
        };
        let report = run_forget_with(&mut context, connection);
        assert_eq!(report.exit_code, 0);
        assert_eq!(
            report.evidence.terminal_status.as_str(),
            "credential_removed"
        );
        assert!(harness.vault.items.lock().expect("items").is_empty());
        drop(host);

        let reopened_admin = ConnectionAdmin::new();
        let reopened_service =
            CredentialService::new(reopened_admin.directory(), FakeVault::default());
        let reopened = DesktopHost::open(
            &harness.root,
            reopened_admin,
            Arc::new(reopened_service.broker()),
            ProviderEndpoints::official(),
        )
        .expect("reopen")
        .0;
        assert!(reopened.runtime().persisted_connections().is_empty());
    }
}
