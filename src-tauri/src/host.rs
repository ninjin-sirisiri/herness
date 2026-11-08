//! Desktop composition of the host runtime.
//!
//! This module owns the one process-wide store, engine adapter, and runtime used
//! by the Tauri shell. It contains no Tauri types, so the same composition is
//! exercised by the desktop integration test with fake credentials and a
//! loopback provider. No second engine or executor is created: allowed tools
//! continue to execute inside `PiEngine`, and the runtime executor is reached
//! only for an operation the adapter explicitly reported as awaiting approval.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_core::runtime::{
    ProjectView, ReconciliationReport, RunToolContext, Runtime, RuntimeDependencies,
    RuntimeToolExecutor, ToolExecution,
};
use herness_core::{
    ArgumentViolation, BashExecutor, Checkpoint, CheckpointCommit, ConnectionAdmin,
    ConnectionDirectory, CoreError, EventDraft, FileLockRegistry, FileObservation, FileToolOutput,
    FrozenOperation, HistoryPage, HistoryQuery, NativeFileTools, OperationEvidence, OperationId,
    OperationIntent, OperationRecord, OperationResult, PermissionPolicy, PolicyAdmin,
    ProcessSupervisor, ProjectId, ProjectRoot, RunId, StorePort, ToolExecutor, ToolName,
};
use herness_engine_pi::{PiEngine, PiEngineConfig, ProviderEndpoints};
use herness_store::{Store, StoreConfig};

/// The concrete runtime composed by the desktop shell.
pub type DesktopRuntime = Runtime<Store, PiEngine<Store>, DesktopToolExecutor>;

/// Process-wide desktop host.
pub struct DesktopHost {
    runtime: DesktopRuntime,
    connections: ConnectionAdmin,
    directory: ConnectionDirectory,
    credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
    app_data_root: PathBuf,
}

impl DesktopHost {
    /// Opens the private store and restores runtime state.
    ///
    /// Restore is read-only and never starts an engine or executes a tool. The
    /// caller owns the returned reconciliation report.
    pub fn open(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
    ) -> Result<(Self, ReconciliationReport), String> {
        let config = StoreConfig::new(app_data_root.as_ref()).map_err(|error| error.to_string())?;
        let store = Store::open(config).map_err(|error| error.to_string())?;
        let store = Arc::new(Mutex::new(store));
        let directory = connections.directory();
        let policy = PolicyAdmin::new();
        let engine = PiEngine::new(
            Arc::clone(&store),
            Arc::clone(&credentials),
            directory.clone(),
            PiEngineConfig::new(policy.policy().clone()).with_endpoints(endpoints),
        )
        .map_err(|error| error.to_string())?;
        let executor = DesktopToolExecutor::new(Arc::clone(&store));
        let dependencies = RuntimeDependencies::new(
            store,
            engine,
            Arc::clone(&credentials),
            directory.clone(),
            policy,
            executor,
        );
        let (runtime, report) =
            Runtime::restore(dependencies).map_err(|error| error.to_string())?;
        Ok((
            Self {
                runtime,
                connections,
                directory,
                credentials,
                app_data_root: app_data_root.as_ref().to_path_buf(),
            },
            report,
        ))
    }

    /// Runtime used by the trusted command layer.
    pub const fn runtime(&self) -> &DesktopRuntime {
        &self.runtime
    }

    /// Mutable runtime used by the trusted command layer.
    pub const fn runtime_mut(&mut self) -> &mut DesktopRuntime {
        &mut self.runtime
    }

    /// Human-only connection registry.
    pub const fn connections(&self) -> &ConnectionAdmin {
        &self.connections
    }

    /// Read-only connection directory shared with the engine and runtime.
    pub const fn directory(&self) -> &ConnectionDirectory {
        &self.directory
    }

    /// Credential port shared with the engine.
    pub fn credentials(&self) -> &Arc<dyn herness_core::CredentialPort + Send + Sync> {
        &self.credentials
    }

    /// Current non-secret permission policy.
    pub fn policy(&self) -> &PermissionPolicy {
        self.runtime.policy()
    }

    /// Opens a project, rejecting the private application-data area.
    ///
    /// The store and its checkpoints must never live inside the project the
    /// agent can edit, and the app-data directory (or a child) is never a
    /// valid project. `Runtime::open_project` still performs the canonical
    /// readable-directory checks.
    pub fn open_project(&mut self, path: impl AsRef<Path>) -> Result<ProjectView, String> {
        let config = StoreConfig::new(&self.app_data_root).map_err(|error| error.to_string())?;
        config
            .ensure_outside_project(path.as_ref())
            .map_err(|error| error.to_string())?;
        let project = std::fs::canonicalize(path.as_ref())
            .map_err(|error| format!("project is not readable: {error}"))?;
        let app_data = std::fs::canonicalize(&self.app_data_root)
            .unwrap_or_else(|_| self.app_data_root.clone());
        if project == app_data || project.starts_with(&app_data) {
            return Err(
                "the application data directory or its children cannot be opened as a project"
                    .to_owned(),
            );
        }
        self.runtime
            .open_project(&project)
            .map_err(|error| error.to_string())
    }

    /// Non-secret connection views for the UI.
    pub fn connection_infos(&self) -> Result<Vec<herness_core::ConnectionInfo>, String> {
        let settings = self.directory.list().map_err(|error| error.to_string())?;
        settings
            .into_iter()
            .map(|settings| {
                let status = match self.credentials.availability(&settings.connection_id()) {
                    Ok(herness_core::CredentialAvailability::Available) => {
                        herness_core::ConnectionStatus::Available
                    }
                    Ok(herness_core::CredentialAvailability::LoginRequired) => {
                        herness_core::ConnectionStatus::LoginRequired
                    }
                    Ok(herness_core::CredentialAvailability::Unavailable) => {
                        herness_core::ConnectionStatus::AuthRequired
                    }
                    Err(_) => herness_core::ConnectionStatus::Unavailable,
                };
                settings
                    .public_info(status)
                    .map_err(|error| error.to_string())
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Store handle shared by the executor and the engine.
// ---------------------------------------------------------------------------

/// Store handle that can be cloned into the runtime executor.
#[derive(Clone)]
pub struct SharedStore(Arc<Mutex<Store>>);

impl SharedStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StorePort for SharedStore {
    fn commit_checkpoint(
        &mut self,
        commit: CheckpointCommit,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        self.lock().commit(commit).map_err(Into::into)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        <Store as StorePort>::load_checkpoint(&self.lock(), run)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        <Store as StorePort>::history(&self.lock(), query)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        <Store as StorePort>::pending_operations(&self.lock(), project)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        <Store as StorePort>::operation(&self.lock(), operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_operation_result(&mut self.lock(), operation, result)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        <Store as StorePort>::record_operation_result_with_events(
            &mut self.lock(),
            operation,
            result,
            events,
        )
    }
}

// ---------------------------------------------------------------------------
// Runtime executor for adapter-reported awaiting-approval operations.
// ---------------------------------------------------------------------------

/// Executes only the frozen operations the trusted engine adapter refused to run
/// because a human decision was required.
///
/// The adapter never executes an awaiting operation, so reaching this executor
/// means the human approved it. File and shell tools persist their intent and
/// result through the same `StorePort` contract used by the engine adapter.
pub struct DesktopToolExecutor {
    store: SharedStore,
    locks: Arc<FileLockRegistry>,
    supervisor: ProcessSupervisor,
    files: Option<NativeFileTools<SharedStore>>,
    shell: Option<BashExecutor<SharedStore>>,
}

impl DesktopToolExecutor {
    fn new(store: Arc<Mutex<Store>>) -> Self {
        Self {
            store: SharedStore(store),
            locks: Arc::new(FileLockRegistry::new()),
            supervisor: ProcessSupervisor::new(),
            files: None,
            shell: None,
        }
    }

    fn missing_context() -> CoreError {
        CoreError::InvalidValue {
            field: "runContext".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: "the runtime must enter a run before executing a tool".to_owned(),
            },
        }
    }
}

impl RuntimeToolExecutor for DesktopToolExecutor {
    fn enter_run(&mut self, context: RunToolContext) -> Result<(), CoreError> {
        let root = ProjectRoot::new(context.cwd().as_path())?;
        self.files = Some(NativeFileTools::with_lock_registry(
            root,
            context.agent_id(),
            context.session_id(),
            self.store.clone(),
            Arc::clone(&self.locks),
        )?);
        self.shell = Some(BashExecutor::new(
            context.agent_id(),
            context.session_id(),
            self.store.clone(),
            herness_core::SystemLauncher,
            self.supervisor.clone(),
        )?);
        Ok(())
    }
}

impl ToolExecutor for DesktopToolExecutor {
    type Output = ToolExecution;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<ToolExecution, CoreError> {
        match operation.tool() {
            ToolName::Read | ToolName::Search | ToolName::Write | ToolName::Edit => {
                let files = self.files.as_mut().ok_or_else(Self::missing_context)?;
                match files.execute(operation)? {
                    FileToolOutput::Change(change) => {
                        let evidence = OperationEvidence::new(
                            vec![FileObservation::new(
                                change.path().clone(),
                                change.before_version().cloned(),
                                Some(change.after_version().clone()),
                            )],
                            false,
                        );
                        Ok(ToolExecution::applied(
                            evidence,
                            serde_json::to_value(&change).unwrap_or(serde_json::Value::Null),
                        ))
                    }
                    other => Ok(ToolExecution::observed(
                        serde_json::to_value(&other).unwrap_or(serde_json::Value::Null),
                    )),
                }
            }
            ToolName::Bash => {
                let shell = self.shell.as_mut().ok_or_else(Self::missing_context)?;
                let output = shell.execute(operation)?;
                let evidence = OperationEvidence::empty().with_shell(output.observation().clone());
                let summary = serde_json::to_value(&output).unwrap_or(serde_json::Value::Null);
                Ok(ToolExecution::new(output.outcome(), evidence, summary))
            }
        }
    }
}
