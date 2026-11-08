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
    AgentSpec, ApprovalOutcome, DenialOutcome, EventBatch, ProjectView, RunView, RuntimeSnapshot,
    StopOutcome,
};
use herness_core::{
    ArgumentViolation, AuthMethod, ConnectionId, ConnectionInfo, ConnectionSettings, CoreError,
    Endpoint, Event, HistoryLimit, InsecureRemoteHttp, OperationId, PermissionMode, ProjectId,
    Provider, RunId, SecretString, StopReason,
};
use serde::Serialize;
use tauri::State;

use crate::app::AppState;
use crate::guard;
use crate::host::DesktopHost;

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
    Ok(FrontendState {
        selected_project: selected,
        projects,
        connections,
        permission_mode: policy.mode(),
        policy_version: policy.version().get(),
        automatic_mode_available: false,
        automatic_mode_reason: "H2 evaluator is not connected; automatic decisions are unavailable",
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
    let view = host
        .runtime_mut()
        .open_project(&path)
        .map_err(|error| error.to_string())?;
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
    let host = lock_host(&state)?;
    host.connections()
        .add(settings)
        .map_err(|error| error.to_string())?;
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
    let login = state
        .login
        .lock()
        .map_err(|_| "the login service is unavailable".to_owned())?;
    match login.as_ref() {
        Some(login) => login.status(connection),
        None => Ok(crate::login::closed_terms_status()),
    }
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

/// Drains engine events and returns a fresh project snapshot.
#[tauri::command(async)]
pub fn poll_project(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    project: ProjectId,
) -> Result<PollResult, String> {
    verify_source(&window)?;
    let mut host = lock_host(&state)?;
    let snapshot = host
        .runtime()
        .snapshot(project)
        .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    for run in snapshot.runs() {
        if matches!(
            run.state(),
            herness_core::RunState::Running | herness_core::RunState::AwaitingApproval
        ) {
            events.extend(
                host.runtime_mut()
                    .poll_run(project, run.run_id())
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    let snapshot = host
        .runtime()
        .snapshot(project)
        .map_err(|error| error.to_string())?;
    Ok(PollResult { events, snapshot })
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
