//! Trusted Tauri command layer.
//!
//! Every command first verifies that the caller is the single local `main`
//! webview. The capability file and generated app-command permissions already
//! restrict exposure; this layer is defense in depth and does not rely on the
//! configuration being correct.
//!
//! Secrets enter only through the write-only `save_api_key` argument and are
//! immediately wrapped in `SecretString`. No command returns a credential,
//! authorization URL, token, or provider error body.

use std::sync::MutexGuard;

use herness_core::runtime::{
    AgentSpec, ApprovalOutcome, DenialOutcome, EventBatch, ProjectView, ReconciliationReport,
    RunView, RuntimeSnapshot, StopOutcome,
};
use herness_core::{
    ArgumentViolation, AuthMethod, ConnectionId, ConnectionInfo, ConnectionSettings, CoreError,
    Endpoint, Event, HistoryLimit, InsecureRemoteHttp, OperationId, PermissionMode, ProjectId,
    Provider, RunId, SecretString, StopReason,
};
use herness_supervision::operations::{HumanOperation, SupervisionOperationRequest};
use herness_supervision::{
    DisclosureDataKind, ProfilePurpose, ProviderOrigin, SupervisionId, SupervisionRequestId,
    TargetVersion,
};
use serde::Serialize;
use tauri::{Manager, State};

use crate::app::AppState;
use crate::guard;
use crate::host::DesktopHost;
use crate::lifecycle::quit::{self as quit_flow, QuitChoice, QuitSnapshot};
use crate::supervision::{
    BudgetView, ChangeSupervisionRequest, ConfirmationKind, CreateSupervisionRequest, EvidenceView,
    PlanRequestActor, PurposeStatusView, RecoveryView, SupervisionView,
};

/// Structured, non-secret error returned by the supervision command layer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandFailure {
    code: &'static str,
    message: String,
}

impl CommandFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn guard(error: String) -> Self {
        Self::new("untrusted_source", error)
    }

    fn supervision(error: herness_supervision::SupervisionError) -> Self {
        if let herness_supervision::SupervisionError::Unsupported { feature } = &error
            && feature.contains("human confirmation")
        {
            return Self::new("human_confirmation_required", feature.clone());
        }
        Self::new("supervision", error.to_string())
    }

    fn invalid(field: &str, detail: impl Into<String>) -> Self {
        Self::new(
            "invalid_request",
            format!("invalid {field}: {}", detail.into()),
        )
    }
}

fn verify_supervision_source(window: &tauri::WebviewWindow) -> Result<(), CommandFailure> {
    verify_source(window).map_err(CommandFailure::guard)
}

fn parse_purpose(value: &str) -> Result<ProfilePurpose, CommandFailure> {
    match value.trim().to_ascii_lowercase().as_str() {
        "completion" => Ok(ProfilePurpose::Completion),
        "html" => Ok(ProfilePurpose::Html),
        "permission" => Ok(ProfilePurpose::Permission),
        other => Err(CommandFailure::invalid(
            "purpose",
            format!("unknown purpose {other:?}"),
        )),
    }
}

fn parse_data_kind(value: &str) -> Result<DisclosureDataKind, CommandFailure> {
    match value.trim().to_ascii_lowercase().as_str() {
        "text" => Ok(DisclosureDataKind::Text),
        "code" => Ok(DisclosureDataKind::Code),
        "diff" => Ok(DisclosureDataKind::Diff),
        "log" => Ok(DisclosureDataKind::Log),
        "image" => Ok(DisclosureDataKind::Image),
        other => Err(CommandFailure::invalid(
            "dataKinds",
            format!("unknown data kind {other:?}"),
        )),
    }
}

/// Non-secret aggregate the UI reloads after every window reopen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrontendState {
    selected_project: Option<ProjectId>,
    projects: Vec<ProjectView>,
    connections: Vec<ConnectionInfo>,
    permission_mode: PermissionMode,
    policy_version: u64,
    automatic_mode_available: bool,
    automatic_mode_reason: &'static str,
    reconciliation: ReconciliationReport,
}

/// Non-secret result of draining engine events for one project.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PollResult {
    events: Vec<Event>,
    snapshot: RuntimeSnapshot,
}

fn verify_source(window: &tauri::WebviewWindow) -> Result<(), String> {
    let window_handle = window.as_ref().window();
    let window_label = window_handle.label();
    let webview_label = window.label();
    let url = window
        .url()
        .map_err(|_| "the invoking document URL is unavailable".to_owned())?;
    guard::verify(window_label, webview_label, Some(url.as_str()))
        .map_err(|error| error.to_string())
}

fn lock_host(state: &AppState) -> Result<MutexGuard<'_, DesktopHost>, String> {
    state
        .host
        .lock()
        .map_err(|_| "the host runtime is unavailable".to_owned())
}

fn parse_limit(limit: Option<u16>) -> Result<HistoryLimit, String> {
    HistoryLimit::new(limit.unwrap_or(100)).map_err(|error| error.to_string())
}

fn invalid(field: &str, detail: &str) -> String {
    CoreError::InvalidValue {
        field: field.to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: detail.to_owned(),
        },
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Project and connection state
// ---------------------------------------------------------------------------

/// Returns projects, connections, and policy state for a fresh page load.
#[tauri::command(async)]
pub fn frontend_state(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> Result<FrontendState, String> {
    verify_source(&window)?;
    let host = lock_host(&state)?;
    let projects = host
        .runtime()
        .projects()
        .map_err(|error| error.to_string())?;
    let connections = host.connection_infos()?;
    let policy = host.policy();
    let selected = *state
        .selected_project
        .lock()
        .map_err(|_| "the selected project is unavailable".to_owned())?;
    let selected =
        selected.filter(|project| projects.iter().any(|view| view.project_id() == *project));
    let reconciliation = state
        .reconciliation
        .lock()
        .map_err(|_| "the reconciliation report is unavailable".to_owned())?
        .clone();
    Ok(FrontendState {
        selected_project: selected,
        projects,
        connections,
        permission_mode: policy.mode(),
        policy_version: policy.version().get(),
        automatic_mode_available: false,
        automatic_mode_reason: "no verified permission-evaluation profile is configured; automatic decisions are unavailable",
        reconciliation,
    })
}

/// Marks the trusted UI ready after its first successful host-state load.
#[tauri::command(async)]
pub fn ui_ready(window: tauri::WebviewWindow) -> Result<(), String> {
    verify_source(&window)?;
    crate::lifecycle::mark_ui_ready();
    Ok(())
}

/// Opens a project directory and selects it for this window.
#[tauri::command(async)]
pub fn open_project(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    path: String,
) -> Result<ProjectView, String> {
    verify_source(&window)?;
    let mut host = lock_host(&state)?;
    let view = host.open_project(&path)?;
    *state
        .selected_project
        .lock()
        .map_err(|_| "the selected project is unavailable".to_owned())? = Some(view.project_id());
    Ok(view)
}

/// Lists opened projects in stable identifier order.
#[tauri::command(async)]
pub fn list_projects(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<ProjectView>, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime()
        .projects()
        .map_err(|error| error.to_string())
}

/// Selects an already opened project.
#[tauri::command(async)]
pub fn select_project(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<ProjectView, String> {
    verify_source(&window)?;
    let view = lock_host(&state)?
        .runtime()
        .project(project)
        .map_err(|error| error.to_string())?;
    *state
        .selected_project
        .lock()
        .map_err(|_| "the selected project is unavailable".to_owned())? = Some(project);
    Ok(view)
}

/// Returns one project and its non-secret capability summary.
#[tauri::command(async)]
pub fn project_view(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<ProjectView, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime()
        .project(project)
        .map_err(|error| error.to_string())
}

/// Registers a human-configured provider connection.
#[tauri::command(async)]
pub fn add_connection(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    provider: Provider,
    model: String,
    auth_method: AuthMethod,
    endpoint: Option<String>,
    insecure_http_acknowledged: Option<bool>,
) -> Result<ConnectionInfo, String> {
    verify_source(&window)?;
    let endpoint = match endpoint {
        Some(value) if !value.trim().is_empty() => {
            Some(Endpoint::parse(value.trim()).map_err(|error| error.to_string())?)
        }
        _ => None,
    };
    let acknowledgment = insecure_http_acknowledged
        .filter(|acknowledged| *acknowledged)
        .map(|_| InsecureRemoteHttp::Acknowledged);
    let settings = ConnectionSettings::new(
        ConnectionId::new(),
        provider,
        model,
        auth_method,
        endpoint,
        acknowledgment,
    )
    .map_err(|error| error.to_string())?;
    let connection = settings.connection_id();
    let mut host = lock_host(&state)?;
    host.register_connection(settings)?;
    host.connection_infos()?
        .into_iter()
        .find(|info| info.connection_id() == connection)
        .ok_or_else(|| "the new connection is not visible".to_owned())
}

/// Lists non-secret connection status.
#[tauri::command(async)]
pub fn list_connections(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<ConnectionInfo>, String> {
    verify_source(&window)?;
    lock_host(&state)?.connection_infos()
}

/// Saves an API key to the Keychain. The value is never returned.
#[tauri::command(async)]
pub fn save_api_key(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
    api_key: String,
) -> Result<(), String> {
    verify_source(&window)?;
    // Wrap immediately; the String is dropped after this scope and is never
    // returned, logged, or stored outside the Keychain.
    let secret = SecretString::new(api_key).map_err(|error| error.to_string())?;
    lock_host(&state)?
        .directory()
        .get(connection)
        .map_err(|error| error.to_string())?;
    state
        .credential_admin
        .save_api_key(connection, secret)
        .map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// ChatGPT login
// ---------------------------------------------------------------------------

/// Starts an official ChatGPT authorization attempt in the system browser.
#[tauri::command(async)]
pub fn start_chatgpt_login(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
) -> Result<crate::login::LoginStatus, String> {
    verify_source(&window)?;
    let login = state
        .login
        .lock()
        .map_err(|_| "the login service is unavailable".to_owned())?;
    login
        .as_ref()
        .ok_or_else(|| "ChatGPT login is unavailable in this build".to_owned())?
        .start(connection)
}

/// Cancels a live ChatGPT attempt and closes its loopback listener.
#[tauri::command(async)]
pub fn cancel_chatgpt_login(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
) -> Result<crate::login::LoginStatus, String> {
    verify_source(&window)?;
    let login = state
        .login
        .lock()
        .map_err(|_| "the login service is unavailable".to_owned())?;
    login
        .as_ref()
        .ok_or_else(|| "ChatGPT login is unavailable in this build".to_owned())?
        .cancel(connection)
}

/// Returns non-secret ChatGPT login state.
#[tauri::command(async)]
pub fn chatgpt_login_status(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
) -> Result<crate::login::LoginStatus, String> {
    verify_source(&window)?;
    let status = {
        let login = state
            .login
            .lock()
            .map_err(|_| "the login service is unavailable".to_owned())?;
        match login.as_ref() {
            Some(login) => login.status(connection),
            None => Ok(crate::login::closed_terms_status()),
        }
    };
    // A completed login may select a non-secret account-scoped vault key in the
    // shared registry. Persist that selection; secrets remain in the Keychain.
    if let Ok(mut host) = state.host.lock() {
        let _ = host.persist_connection_settings();
    }
    status
}

/// Lists the selected ChatGPT account's model catalog.
#[tauri::command(async)]
pub fn chatgpt_models(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
) -> Result<Vec<herness_engine_pi::ChatGptModel>, String> {
    verify_source(&window)?;
    lock_host(&state)?.list_chatgpt_models(connection)
}

/// Changes only the non-secret model name of an existing connection.
#[tauri::command(async)]
pub fn set_connection_model(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    connection: ConnectionId,
    model: String,
) -> Result<ConnectionInfo, String> {
    verify_source(&window)?;
    lock_host(&state)?.set_connection_model(connection, model)
}

// ---------------------------------------------------------------------------
// Runs, approvals, snapshot, history
// ---------------------------------------------------------------------------

/// Creates a host-owned agent and starts one run.
#[tauri::command(async)]
pub fn start_run(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    connection: ConnectionId,
    instructions: String,
) -> Result<RunView, String> {
    verify_source(&window)?;
    if instructions.trim().is_empty() {
        return Err(invalid("instructions", "instructions must not be empty"));
    }
    let mut host = lock_host(&state)?;
    let agent = host
        .runtime_mut()
        .create_agent(project, AgentSpec::new("main", "implementer", connection))
        .map_err(|error| error.to_string())?;
    let run = host
        .runtime_mut()
        .start_run(project, agent.agent_id(), instructions.clone())
        .map_err(|error| error.to_string())?;
    host.runtime_mut()
        .submit_input(project, run.run_id(), instructions)
        .map_err(|error| error.to_string())?;
    Ok(run)
}

/// Requests a coordinated stop for one run.
#[tauri::command(async)]
pub fn stop_run(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    run: RunId,
) -> Result<StopOutcome, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime_mut()
        .stop_run(project, run, StopReason::UserRequest)
        .map_err(|error| error.to_string())
}

/// Resumes a paused or interrupted run after re-checking the current context.
#[tauri::command(async)]
pub fn resume_run(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    run: RunId,
) -> Result<RunView, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime_mut()
        .resume_run(project, run)
        .map_err(|error| error.to_string())
}

/// Returns a fresh project snapshot.
///
/// This command is read-only with respect to execution. Engine events are
/// drained by the host-owned pump, and committed events are read through
/// `history`. The `events` field remains for the existing UI shape; it is
/// always empty because the WebView is not the execution driver.
#[tauri::command(async)]
pub fn poll_project(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<PollResult, String> {
    verify_source(&window)?;
    let host = lock_host(&state)?;
    let snapshot = host
        .runtime()
        .snapshot(project)
        .map_err(|error| error.to_string())?;
    Ok(PollResult {
        events: Vec::new(),
        snapshot,
    })
}

/// Returns the stable reconnect snapshot for one project.
#[tauri::command(async)]
pub fn snapshot(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<RuntimeSnapshot, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime()
        .snapshot(project)
        .map_err(|error| error.to_string())
}

/// Returns committed events in ascending sequence order.
#[tauri::command(async)]
pub fn history(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    limit: Option<u16>,
) -> Result<EventBatch, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime()
        .subscribe(project, None, parse_limit(limit)?)
        .map_err(|error| error.to_string())
}

/// Approves the exact frozen operation and executes it once.
#[tauri::command(async)]
pub fn approve(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    operation: OperationId,
) -> Result<ApprovalOutcome, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime_mut()
        .approve(project, operation)
        .map_err(|error| error.to_string())
}

/// Denies the exact frozen operation without executing it.
#[tauri::command(async)]
pub fn deny(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    operation: OperationId,
) -> Result<DenialOutcome, String> {
    verify_source(&window)?;
    lock_host(&state)?
        .runtime_mut()
        .deny(project, operation)
        .map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// H2 supervision
// ---------------------------------------------------------------------------

/// Creates one supervision target from human-confirmed conditions.
#[tauri::command(async)]
pub fn supervision_create(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    request: CreateSupervisionRequest,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Create);
    host.supervision_create(PlanRequestActor::Human, request, Some(confirmation))
        .map_err(CommandFailure::supervision)
}

/// Lists saved supervision targets for one project.
#[tauri::command(async)]
pub fn supervision_list(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<Vec<SupervisionView>, CommandFailure> {
    verify_supervision_source(&window)?;
    lock_host(&state)
        .map_err(|error| CommandFailure::new("host_unavailable", error))?
        .supervision_list(project)
        .map_err(CommandFailure::supervision)
}

/// Returns one saved supervision view.
#[tauri::command(async)]
pub fn supervision_get(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    lock_host(&state)
        .map_err(|error| CommandFailure::new("host_unavailable", error))?
        .supervision_get(project, supervision)
        .map_err(CommandFailure::supervision)
}

/// Starts the first run of a ready target.
#[tauri::command(async)]
pub fn supervision_start(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Start);
    host.supervision_start(
        project,
        supervision,
        request_id,
        expected_revision,
        Some(confirmation),
    )
    .map_err(CommandFailure::supervision)
}

fn stop_or_cancel(
    host: &mut DesktopHost,
    request_id: SupervisionRequestId,
    supervision: SupervisionId,
    expected_revision: u64,
    cancel: bool,
    kind: ConfirmationKind,
) -> Result<SupervisionView, CommandFailure> {
    let operation = if cancel {
        HumanOperation::Cancel
    } else {
        HumanOperation::Stop
    };
    let request =
        SupervisionOperationRequest::new(request_id, supervision, operation, expected_revision)
            .map_err(CommandFailure::supervision)?;
    let confirmation = host.confirm_supervision(kind);
    host.supervision_stop(request, cancel, Some(confirmation))
        .map_err(CommandFailure::supervision)
}

/// Stops one target through the H1 cooperative stop path.
#[tauri::command(async)]
pub fn supervision_stop(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    stop_or_cancel(
        &mut host,
        request_id,
        supervision,
        expected_revision,
        false,
        ConfirmationKind::Stop,
    )
}

/// Cancels one target and retains its history and artifacts.
#[tauri::command(async)]
pub fn supervision_cancel(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    stop_or_cancel(
        &mut host,
        request_id,
        supervision,
        expected_revision,
        true,
        ConfirmationKind::Stop,
    )
}

/// Resumes a stopped/waiting target after the recovery gate.
#[tauri::command(async)]
pub fn supervision_resume(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let request = SupervisionOperationRequest::new(
        request_id,
        supervision,
        HumanOperation::Resume,
        expected_revision,
    )
    .map_err(CommandFailure::supervision)?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Resume);
    host.supervision_resume(request, Some(confirmation))
        .map_err(CommandFailure::supervision)
}

/// Reassesses a target without replaying an old input.
#[tauri::command(async)]
pub fn supervision_reassess(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let request = SupervisionOperationRequest::new(
        request_id,
        supervision,
        HumanOperation::Reassess,
        expected_revision,
    )
    .map_err(CommandFailure::supervision)?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Reassess);
    host.supervision_reassess(request, Some(confirmation))
        .map_err(CommandFailure::supervision)
}

/// Changes approved conditions, profile, consent, or budget explicitly.
#[tauri::command(async)]
pub fn supervision_change(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
    request_id: SupervisionRequestId,
    expected_revision: u64,
    change: ChangeSupervisionRequest,
) -> Result<SupervisionView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Change);
    host.supervision_change(
        project,
        supervision,
        request_id,
        expected_revision,
        PlanRequestActor::Human,
        change,
        Some(confirmation),
    )
    .map_err(CommandFailure::supervision)
}

/// Configures a per-purpose assessment profile.
#[tauri::command(async)]
pub fn supervision_profile(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    purpose: String,
    connection: ConnectionId,
    model: String,
) -> Result<PurposeStatusView, CommandFailure> {
    verify_supervision_source(&window)?;
    let purpose = parse_purpose(&purpose)?;
    let host = lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    let confirmation = host.confirm_supervision(ConfirmationKind::Profile);
    host.supervision_configure_profile(
        PlanRequestActor::Human,
        project,
        purpose,
        connection,
        &model,
        Some(confirmation),
    )
    .map_err(CommandFailure::supervision)
}

/// Grants or revokes per-purpose disclosure consent.
#[tauri::command(async)]
#[allow(clippy::too_many_arguments)]
pub fn supervision_consent(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    purpose: String,
    action: String,
    origin: Option<String>,
    data_kinds: Option<Vec<String>>,
    targets: Option<Vec<String>>,
    target_version: Option<u64>,
) -> Result<PurposeStatusView, CommandFailure> {
    verify_supervision_source(&window)?;
    let purpose = parse_purpose(&purpose)?;
    let host = lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    match action.trim().to_ascii_lowercase().as_str() {
        "grant" => {
            let origin = origin.ok_or_else(|| CommandFailure::invalid("origin", "required"))?;
            let origin = ProviderOrigin::parse(origin).map_err(CommandFailure::supervision)?;
            let data_kinds = data_kinds
                .unwrap_or_default()
                .into_iter()
                .map(|kind| parse_data_kind(&kind))
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
            let targets = targets.unwrap_or_default();
            let target_version = TargetVersion::new(target_version.unwrap_or(1))
                .map_err(CommandFailure::supervision)?;
            let confirmation = host.confirm_supervision(ConfirmationKind::Consent);
            host.supervision_grant_consent(
                PlanRequestActor::Human,
                project,
                purpose,
                origin,
                data_kinds,
                targets,
                target_version,
                Some(confirmation),
            )
            .map_err(CommandFailure::supervision)
        }
        "revoke" => {
            let confirmation = host.confirm_supervision(ConfirmationKind::Consent);
            host.supervision_revoke_consent(
                PlanRequestActor::Human,
                project,
                purpose,
                Some(confirmation),
            )
            .map_err(CommandFailure::supervision)
        }
        other => Err(CommandFailure::invalid(
            "action",
            format!("unknown consent action {other:?}"),
        )),
    }
}

/// Returns evidence summaries for one target.
#[tauri::command(async)]
pub fn supervision_evidence(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
) -> Result<Vec<EvidenceView>, CommandFailure> {
    verify_supervision_source(&window)?;
    Ok(lock_host(&state)
        .map_err(|error| CommandFailure::new("host_unavailable", error))?
        .supervision_get(project, supervision)
        .map_err(CommandFailure::supervision)?
        .evidence)
}

/// Returns the durable budget view for one target.
#[tauri::command(async)]
pub fn supervision_budget(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
) -> Result<Option<BudgetView>, CommandFailure> {
    verify_supervision_source(&window)?;
    Ok(lock_host(&state)
        .map_err(|error| CommandFailure::new("host_unavailable", error))?
        .supervision_get(project, supervision)
        .map_err(CommandFailure::supervision)?
        .budget)
}

/// Returns the read-only recovery report for one target.
#[tauri::command(async)]
pub fn supervision_recovery(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
    supervision: SupervisionId,
) -> Result<RecoveryView, CommandFailure> {
    verify_supervision_source(&window)?;
    let mut host =
        lock_host(&state).map_err(|error| CommandFailure::new("host_unavailable", error))?;
    host.supervision_recovery(project, supervision)
        .map_err(CommandFailure::supervision)
}

// ---------------------------------------------------------------------------
// Explicit quit and shutdown state
// ---------------------------------------------------------------------------

/// Starts the explicit quit flow. New runs and tool decisions are refused from
/// this point.
#[tauri::command(async)]
pub fn quit_app(
    window: tauri::WebviewWindow,
    _state: State<'_, AppState>,
) -> Result<QuitSnapshot, String> {
    verify_source(&window)?;
    Ok(quit_flow::request_quit(window.app_handle()))
}

/// Returns non-secret quit state for the trusted UI prompt.
#[tauri::command(async)]
pub fn quit_state(window: tauri::WebviewWindow) -> Result<QuitSnapshot, String> {
    verify_source(&window)?;
    Ok(quit_flow::coordinator().snapshot())
}

/// Applies the human choice after the coordinated-stop grace.
#[tauri::command(async)]
pub fn quit_choice(
    window: tauri::WebviewWindow,
    choice: QuitChoice,
) -> Result<QuitSnapshot, String> {
    verify_source(&window)?;
    quit_flow::choose(window.app_handle(), choice)
}
