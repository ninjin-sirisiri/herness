//! Black-box tests for the host runtime composition.
//!
//! The tests use the real SQLite store, temporary project directories, a
//! scripted fake engine, fake non-secret credentials, and the real native file
//! executor behind a counting wrapper. No network, real Keychain, Tauri, or
//! real provider is involved.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use herness_core::runtime::{
    AgentSpec, ReconciliationReport, ReconciliationSource, RunToolContext, Runtime,
    RuntimeDependencies, RuntimeError, RuntimeToolExecutor, SubscriptionCursor, ToolExecution,
};
use herness_core::*;
use herness_store::{Store, StoreConfig};
use serde_json::json;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Store handle shared with executors and the scripted engine.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StoreHandle(Arc<Mutex<Store>>);

impl StoreHandle {
    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.lock().expect("store lock")
    }
}

impl StorePort for StoreHandle {
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
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
    ) -> Result<CommitReceipt, CoreError> {
        <Store as StorePort>::record_operation_result_with_events(
            &mut self.lock(),
            operation,
            result,
            events,
        )
    }
}

// ---------------------------------------------------------------------------
// Scripted engine.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EngineState {
    starts: Vec<EngineStart>,
    inputs: Vec<(RunId, String)>,
    stops: Vec<(RunId, StopReport)>,
    resumes: Vec<RunId>,
    checkpoint_calls: BTreeMap<RunId, usize>,
    events: BTreeMap<RunId, Vec<EngineEvent>>,
    start_observed_durable_event: Vec<bool>,
}

impl EngineState {
    fn reset(&mut self) {
        self.starts.clear();
        self.inputs.clear();
        self.stops.clear();
        self.resumes.clear();
        self.checkpoint_calls.clear();
        self.events.clear();
        self.start_observed_durable_event.clear();
    }

    fn request_count(&self) -> usize {
        self.starts.len()
            + self.inputs.len()
            + self.stops.len()
            + self.resumes.len()
            + self.checkpoint_calls.values().sum::<usize>()
    }
}

struct FakeEngine {
    state: Arc<Mutex<EngineState>>,
    store: Arc<Mutex<Store>>,
    stop_report: StopReport,
    reject_input: bool,
}

impl FakeEngine {
    fn new(
        state: Arc<Mutex<EngineState>>,
        store: Arc<Mutex<Store>>,
        stop_report: StopReport,
        reject_input: bool,
    ) -> Self {
        Self {
            state,
            store,
            stop_report,
            reject_input,
        }
    }
}

impl EnginePort for FakeEngine {
    fn start(&mut self, start: EngineStart) -> Result<(), CoreError> {
        let durable = {
            let store = self.store.lock().expect("store lock");
            let page =
                <Store as StorePort>::history(&store, HistoryQuery::first(start.project_id()))
                    .map_err(ErrorForTest::core)?;
            page.events().iter().any(|event| {
                event.run_id() == start.run_id() && event.kind().as_str() == "run.started"
            })
        };
        let mut state = self.state.lock().expect("engine lock");
        state.starts.push(start);
        state.start_observed_durable_event.push(durable);
        Ok(())
    }

    fn send_input(&mut self, run: &RunId, input: EngineInput) -> Result<(), CoreError> {
        if self.reject_input {
            return Err(CoreError::InvalidRunTransition {
                from: RunState::Running,
                to: RunState::Running,
            });
        }
        let EngineInput::Text(text) = input;
        self.state
            .lock()
            .expect("engine lock")
            .inputs
            .push((*run, text));
        Ok(())
    }

    fn request_stop(&mut self, run: &RunId, _reason: StopReason) -> Result<StopReport, CoreError> {
        self.state
            .lock()
            .expect("engine lock")
            .stops
            .push((*run, self.stop_report));
        Ok(self.stop_report)
    }

    fn resume(&mut self, run: &RunId, _checkpoint: Checkpoint) -> Result<(), CoreError> {
        self.state.lock().expect("engine lock").resumes.push(*run);
        Ok(())
    }

    fn checkpoint(&mut self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        self.state
            .lock()
            .expect("engine lock")
            .checkpoint_calls
            .entry(*run)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        Ok(Some(Checkpoint::new(
            *run,
            CheckpointFormatVersion::new(1).expect("checkpoint version"),
            CheckpointPayload::new(b"fake-engine-checkpoint".to_vec()),
        )))
    }

    fn poll_events(&mut self, run: &RunId) -> Result<Vec<EngineEvent>, CoreError> {
        Ok(self
            .state
            .lock()
            .expect("engine lock")
            .events
            .remove(run)
            .unwrap_or_default())
    }
}

// Small conversion helper so the fake can map store errors into CoreError.
struct ErrorForTest;

impl ErrorForTest {
    fn core(error: impl Into<CoreError>) -> CoreError {
        error.into()
    }
}

// ---------------------------------------------------------------------------
// Fake credentials and evaluator.
// ---------------------------------------------------------------------------

struct FakeCredentials {
    availability: Mutex<BTreeMap<ConnectionId, CredentialAvailability>>,
}

impl FakeCredentials {
    fn new(connection: ConnectionId, availability: CredentialAvailability) -> Self {
        let mut map = BTreeMap::new();
        map.insert(connection, availability);
        Self {
            availability: Mutex::new(map),
        }
    }

    fn set(&self, connection: ConnectionId, availability: CredentialAvailability) {
        self.availability
            .lock()
            .expect("credential lock")
            .insert(connection, availability);
    }
}

impl CredentialPort for FakeCredentials {
    fn availability(&self, connection: &ConnectionId) -> Result<CredentialAvailability, CoreError> {
        Ok(self
            .availability
            .lock()
            .expect("credential lock")
            .get(connection)
            .copied()
            .unwrap_or(CredentialAvailability::Unavailable))
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        Err(CoreError::AuthenticationRequired {
            connection: *connection,
        })
    }
}

struct FakeEvaluator {
    availability: EvaluatorAvailability,
}

impl PermissionEvaluatorPort for FakeEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        self.availability
    }

    fn evaluate(&mut self, _request: &EvaluationRequest) -> Result<PermissionDecision, CoreError> {
        Ok(PermissionDecision::Ask)
    }
}

// ---------------------------------------------------------------------------
// Counting native file executor.
// ---------------------------------------------------------------------------

struct TestExecutor {
    store: StoreHandle,
    calls: Arc<AtomicUsize>,
    context: Option<RunToolContext>,
    fail_with: Option<CoreError>,
}

impl TestExecutor {
    fn new(store: Arc<Mutex<Store>>, calls: Arc<AtomicUsize>) -> Self {
        Self {
            store: StoreHandle(store),
            calls,
            context: None,
            fail_with: None,
        }
    }
}

impl RuntimeToolExecutor for TestExecutor {
    fn enter_run(&mut self, context: RunToolContext) -> Result<(), CoreError> {
        self.context = Some(context);
        Ok(())
    }
}

impl ToolExecutor for TestExecutor {
    type Output = ToolExecution;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<ToolExecution, CoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = &self.fail_with {
            return Err(error.clone());
        }
        let context = self
            .context
            .as_ref()
            .expect("runtime must set a run context before execution");
        let root = ProjectRoot::new(context.cwd().as_path())?;
        let mut files = NativeFileTools::new(
            root,
            context.agent_id(),
            context.session_id(),
            self.store.clone(),
        )?;
        let output = files.execute(operation)?;
        Ok(match output {
            FileToolOutput::Change(change) => ToolExecution::applied(
                OperationEvidence::new(
                    vec![FileObservation::new(
                        change.path().clone(),
                        change.before_version().cloned(),
                        Some(change.after_version().clone()),
                    )],
                    false,
                ),
                serde_json::to_value(&change).unwrap_or_default(),
            ),
            other => ToolExecution::observed(serde_json::to_value(&other).unwrap_or_default()),
        })
    }
}

// ---------------------------------------------------------------------------
// Test host.
// ---------------------------------------------------------------------------

type HostRuntime = Runtime<Store, FakeEngine, TestExecutor>;

struct Options {
    policy: PolicyAdmin,
    evaluator: Option<Box<dyn PermissionEvaluatorPort + Send + Sync>>,
    credential: CredentialAvailability,
    register_connection: bool,
    stop_report: StopReport,
    reject_input: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: PolicyAdmin::new(),
            evaluator: None,
            credential: CredentialAvailability::Available,
            register_connection: true,
            stop_report: StopReport::Stopped,
            reject_input: false,
        }
    }
}

struct TestHost {
    _temp: TempDir,
    project_a: PathBuf,
    project_b: PathBuf,
    store: Arc<Mutex<Store>>,
    engine_state: Arc<Mutex<EngineState>>,
    credentials: Arc<FakeCredentials>,
    directory: ConnectionDirectory,
    connection: ConnectionId,
    calls: Arc<AtomicUsize>,
    policy: PolicyAdmin,
    evaluator: Option<Box<dyn PermissionEvaluatorPort + Send + Sync>>,
    stop_report: StopReport,
    reject_input: bool,
    runtime: HostRuntime,
}

impl TestHost {
    fn new() -> Self {
        Self::with_options(Options::default())
    }

    fn with_options(options: Options) -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let project_a = temp.path().join("project-a");
        let project_b = temp.path().join("project-b");
        fs::create_dir_all(&project_a).expect("project a");
        fs::create_dir_all(&project_b).expect("project b");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("store config");
        let store = Arc::new(Mutex::new(Store::open(config).expect("store")));
        let connection = ConnectionId::new();
        let admin = ConnectionAdmin::new();
        if options.register_connection {
            admin
                .add(
                    ConnectionSettings::new(
                        connection,
                        Provider::OpenAi,
                        "gpt-test",
                        AuthMethod::ApiKey,
                        None,
                        None,
                    )
                    .expect("connection settings"),
                )
                .expect("register connection");
        }
        let directory = admin.directory();
        let credentials = Arc::new(FakeCredentials::new(connection, options.credential));
        let engine_state = Arc::new(Mutex::new(EngineState::default()));
        let engine = FakeEngine::new(
            Arc::clone(&engine_state),
            Arc::clone(&store),
            options.stop_report,
            options.reject_input,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = TestExecutor::new(Arc::clone(&store), Arc::clone(&calls));
        let deps = RuntimeDependencies::new(
            Arc::clone(&store),
            engine,
            credentials.clone(),
            directory.clone(),
            options.policy.clone(),
            executor,
        );
        let runtime = match options.evaluator {
            Some(evaluator) => {
                Runtime::restore(deps.with_evaluator(evaluator))
                    .expect("restore runtime")
                    .0
            }
            None => Runtime::restore(deps).expect("restore runtime").0,
        };
        Self {
            _temp: temp,
            project_a,
            project_b,
            store,
            engine_state,
            credentials,
            directory,
            connection,
            calls,
            policy: options.policy,
            evaluator: None,
            stop_report: options.stop_report,
            reject_input: options.reject_input,
            runtime,
        }
    }

    fn open_both(&mut self) -> (ProjectId, ProjectId) {
        let a = self
            .runtime
            .open_project(&self.project_a)
            .expect("open project a")
            .project_id();
        let b = self
            .runtime
            .open_project(&self.project_b)
            .expect("open project b")
            .project_id();
        (a, b)
    }

    fn restart(&mut self) -> ReconciliationReport {
        let engine = FakeEngine::new(
            Arc::clone(&self.engine_state),
            Arc::clone(&self.store),
            self.stop_report,
            self.reject_input,
        );
        let executor = TestExecutor::new(Arc::clone(&self.store), Arc::clone(&self.calls));
        let deps = RuntimeDependencies::new(
            Arc::clone(&self.store),
            engine,
            self.credentials.clone(),
            self.directory.clone(),
            self.policy.clone(),
            executor,
        );
        let deps = match self.evaluator.take() {
            Some(evaluator) => deps.with_evaluator(evaluator),
            None => deps,
        };
        let (runtime, report) = Runtime::restore(deps).expect("restore runtime");
        self.runtime = runtime;
        report
    }

    fn push_event(&self, run: RunId, event: EngineEvent) {
        self.engine_state
            .lock()
            .expect("engine lock")
            .events
            .entry(run)
            .or_default()
            .push(event);
    }

    fn engine_state(&self) -> std::sync::MutexGuard<'_, EngineState> {
        self.engine_state.lock().expect("engine lock")
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn reset_request_counters(&self) {
        self.engine_state().reset();
        self.calls.store(0, Ordering::SeqCst);
    }
}

fn write_arguments(path: &str, content: &str) -> ToolArguments {
    ToolArguments::Write(WriteArgs {
        path: NonEmptyText::new(path).expect("path"),
        content: content.to_owned(),
        rationale: Rationale::new("record the note").expect("rationale"),
    })
}

fn read_allow_rule() -> PermissionRule {
    PermissionRule::allow(
        RuleTarget::Tool {
            tool: ToolName::Read,
        },
        MatchMethod::AnyInvocation,
    )
    .expect("read rule")
}

fn canonical(path: &Path) -> AbsolutePath {
    AbsolutePath::new(
        fs::canonicalize(path)
            .expect("canonical path")
            .to_str()
            .expect("utf8 path"),
    )
    .expect("absolute path")
}

fn commit_intent(
    store: &Arc<Mutex<Store>>,
    project: ProjectId,
    project_root: &Path,
    run: RunId,
    tool: ToolName,
    arguments: ToolArguments,
) -> OperationId {
    let policy = PermissionPolicy::initial();
    let operation = FrozenOperation::new(
        OperationId::new(project),
        run,
        tool,
        arguments,
        canonical(project_root),
        policy.version(),
        PermissionMode::Configured,
    )
    .expect("frozen operation");
    let operation_id = operation.operation_id();
    let checkpoint = Checkpoint::new(
        run,
        CheckpointFormatVersion::new(1).expect("checkpoint version"),
        CheckpointPayload::new(b"pending-operation".to_vec()),
    );
    let intent = OperationIntent::new(operation, Timestamp::now());
    store
        .lock()
        .expect("store lock")
        .commit(CheckpointCommit::new(checkpoint, Some(intent), Vec::new()).expect("commit"))
        .expect("intent commit");
    operation_id
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn project_open_refuses_unreadable_paths_and_reports_capabilities() {
    let mut host = TestHost::new();
    let missing = host.project_a.join("missing");
    assert!(matches!(
        host.runtime.open_project(&missing),
        Err(RuntimeError::ProjectUnreadable { .. })
    ));

    let file = host._temp.path().join("plain-file");
    fs::write(&file, "not a directory").expect("file");
    assert!(matches!(
        host.runtime.open_project(&file),
        Err(RuntimeError::ProjectNotDirectory { .. })
    ));

    let first = host.runtime.open_project(&host.project_a).expect("open");
    assert_eq!(first.path(), &canonical(&host.project_a));
    assert_eq!(first.connections().len(), 1);
    assert_eq!(first.connections()[0].status(), ConnectionStatus::Available);
    assert!(
        !first
            .capability_status(HostCapability::HtmlWorker)
            .is_available()
    );
    assert!(
        !first
            .capability_status(HostCapability::SddTaskController)
            .is_available()
    );
    assert!(
        first
            .capability_status(HostCapability::SkillRead)
            .is_available()
    );
    assert!(
        !first.toolchain().deficiencies().is_empty(),
        "an empty toolchain configuration must report deficiencies, not hide them"
    );

    let again = host.runtime.open_project(&host.project_a).expect("reopen");
    assert_eq!(again.project_id(), first.project_id());
    let other = host.runtime.open_project(&host.project_b).expect("open b");
    assert_ne!(other.project_id(), first.project_id());
}

#[test]
fn two_projects_and_multiple_agents_stay_isolated() {
    let mut host = TestHost::new();
    let (a, b) = host.open_both();
    let a1 = host
        .runtime
        .create_agent(a, AgentSpec::new("a1", "implementer", host.connection))
        .expect("agent a1");
    let a2 = host
        .runtime
        .create_agent(a, AgentSpec::new("a2", "reviewer", host.connection))
        .expect("agent a2");
    let b1 = host
        .runtime
        .create_agent(b, AgentSpec::new("b1", "implementer", host.connection))
        .expect("agent b1");
    assert_ne!(a1.agent_id(), a2.agent_id());
    assert_ne!(a1.session_id(), a2.session_id());

    let run_a1 = host
        .runtime
        .start_run(a, a1.agent_id(), "first a")
        .expect("run a1");
    let run_a2 = host
        .runtime
        .start_run(a, a2.agent_id(), "second a")
        .expect("run a2");
    let run_b1 = host
        .runtime
        .start_run(b, b1.agent_id(), "first b")
        .expect("run b1");
    assert_eq!(run_a1.project_id(), a);
    assert_eq!(run_b1.project_id(), b);
    assert_ne!(run_a1.run_id(), run_a2.run_id());
    assert_eq!(host.engine_state().starts.len(), 3);
    assert!(
        host.engine_state()
            .start_observed_durable_event
            .iter()
            .all(|durable| *durable),
        "run.started must be committed before EnginePort::start"
    );

    let snapshot_a = host.runtime.snapshot(a).expect("snapshot a");
    let snapshot_b = host.runtime.snapshot(b).expect("snapshot b");
    assert_eq!(snapshot_a.runs().len(), 2);
    assert_eq!(snapshot_b.runs().len(), 1);
    assert_eq!(snapshot_a.last_sequence(), 2);
    assert_eq!(snapshot_b.last_sequence(), 1);

    let batch_a = host
        .runtime
        .subscribe(a, None, HistoryLimit::new(50).expect("limit"))
        .expect("batch a");
    assert!(batch_a.events().iter().all(|event| event.project_id() == a));
    let batch_b = host
        .runtime
        .subscribe(b, None, HistoryLimit::new(50).expect("limit"))
        .expect("batch b");
    assert!(batch_b.events().iter().all(|event| event.project_id() == b));

    assert!(matches!(
        host.runtime.run(b, run_a1.run_id()),
        Err(RuntimeError::CrossProject { .. })
    ));
    assert!(matches!(
        host.runtime.subscribe(
            b,
            Some(SubscriptionCursor::new(a, batch_a.last_sequence())),
            HistoryLimit::new(10).expect("limit")
        ),
        Err(RuntimeError::CrossProject { .. })
    ));
}

#[test]
fn start_refuses_missing_connection_authentication_capability_and_automatic_mode() {
    // Unknown connection: agent creation itself is refused.
    let mut missing = TestHost::with_options(Options {
        register_connection: false,
        ..Options::default()
    });
    let (project, _) = missing.open_both();
    assert!(matches!(
        missing.runtime.create_agent(
            project,
            AgentSpec::new("a", "implementer", ConnectionId::new())
        ),
        Err(RuntimeError::UnknownConnection { .. })
    ));
    assert_eq!(missing.engine_state().starts.len(), 0);

    // Missing credential status.
    let mut login = TestHost::with_options(Options {
        credential: CredentialAvailability::LoginRequired,
        ..Options::default()
    });
    let (project, _) = login.open_both();
    let agent = login
        .runtime
        .create_agent(
            project,
            AgentSpec::new("a", "implementer", login.connection),
        )
        .expect("agent");
    assert!(matches!(
        login.runtime.start_run(project, agent.agent_id(), "work"),
        Err(RuntimeError::ConnectionUnavailable {
            status: ConnectionStatus::LoginRequired,
            ..
        })
    ));
    assert_eq!(login.engine_state().starts.len(), 0);

    // Unavailable capability.
    let mut capability = TestHost::new();
    let (project, _) = capability.open_both();
    let agent = capability
        .runtime
        .create_agent(
            project,
            AgentSpec::new("a", "implementer", capability.connection)
                .requiring(HostCapability::HtmlWorker),
        )
        .expect("agent");
    assert!(matches!(
        capability
            .runtime
            .start_run(project, agent.agent_id(), "work"),
        Err(RuntimeError::CapabilityUnavailable {
            capability: HostCapability::HtmlWorker,
            ..
        })
    ));
    assert_eq!(capability.engine_state().starts.len(), 0);

    // Automatic mode without an available evaluator.
    let mut automatic = TestHost::with_options(Options {
        policy: {
            let mut admin = PolicyAdmin::new();
            admin
                .set_mode(PermissionMode::Automatic, EvaluatorAvailability::Available)
                .expect("automatic policy");
            admin
        },
        evaluator: Some(Box::new(FakeEvaluator {
            availability: EvaluatorAvailability::Unavailable,
        })),
        ..Options::default()
    });
    let (project, _) = automatic.open_both();
    let agent = automatic
        .runtime
        .create_agent(
            project,
            AgentSpec::new("a", "implementer", automatic.connection),
        )
        .expect("agent");
    assert!(matches!(
        automatic
            .runtime
            .start_run(project, agent.agent_id(), "work"),
        Err(RuntimeError::PermissionModeUnavailable {
            mode: PermissionMode::Automatic
        })
    ));
    assert_eq!(automatic.engine_state().starts.len(), 0);
}

#[test]
fn awaiting_approval_stops_before_side_effect_and_approve_executes_once() {
    let mut host = TestHost::new();
    let (project, other) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");

    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("notes.txt", "hello"),
        },
    );
    let committed = host
        .runtime
        .poll_run(project, run.run_id())
        .expect("poll tool call");
    assert!(
        committed
            .iter()
            .any(|event| event.kind().as_str() == "run.awaiting_approval")
    );
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::AwaitingApproval
    );
    let pending = host.runtime.pending_approvals(project).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].restored());
    assert!(pending[0].reusable());
    let operation = pending[0].operation().clone();
    assert!(!host.project_a.join("notes.txt").exists());
    assert_eq!(host.calls(), 0);

    // Cross-project approval is rejected before execution.
    assert!(matches!(
        host.runtime.approve(other, operation.operation_id()),
        Err(RuntimeError::CrossProject { .. })
    ));
    assert_eq!(host.calls(), 0);

    let approved = host
        .runtime
        .approve(project, operation.operation_id())
        .expect("approve");
    assert!(approved.executed());
    assert_eq!(approved.outcome(), OperationOutcome::Applied);
    assert_eq!(
        fs::read_to_string(host.project_a.join("notes.txt")).expect("file"),
        "hello"
    );
    assert_eq!(host.calls(), 1);
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Running
    );
    assert!(host.runtime.pending_approvals(project).unwrap().is_empty());
    let inputs = host.engine_state().inputs.clone();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].0, run.run_id());
    assert!(inputs[0].1.contains("outcome=applied"));

    // A second approval cannot execute again.
    assert!(matches!(
        host.runtime.approve(project, operation.operation_id()),
        Err(RuntimeError::ApprovalUnknown { .. })
    ));
    assert_eq!(host.calls(), 1);
    let result = host
        .store
        .lock()
        .unwrap()
        .operation(&operation.operation_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        result.result().unwrap().outcome(),
        OperationOutcome::Applied
    );

    let batch = host
        .runtime
        .subscribe(project, None, HistoryLimit::new(100).unwrap())
        .unwrap();
    let kinds = batch
        .events()
        .iter()
        .map(|event| event.kind().as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"run.awaiting_approval"));
    assert!(kinds.contains(&"run.operation_completed"));
    assert!(kinds.contains(&"run.approval_resolved"));
}

#[test]
fn deny_never_executes_and_approve_after_deny_fails() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("denied.txt", "nope"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let operation = host.runtime.pending_approvals(project).unwrap()[0]
        .operation()
        .operation_id();

    let denied = host.runtime.deny(project, operation).expect("deny");
    assert_eq!(denied.operation_id(), operation);
    assert!(!host.project_a.join("denied.txt").exists());
    assert_eq!(host.calls(), 0);
    assert!(host.runtime.pending_approvals(project).unwrap().is_empty());
    assert!(matches!(
        host.runtime.approve(project, operation),
        Err(RuntimeError::ApprovalUnknown { .. })
    ));
    assert_eq!(host.calls(), 0);
    assert!(!host.project_a.join("denied.txt").exists());

    let inputs = &host.engine_state().inputs;
    assert_eq!(inputs.len(), 1);
    assert!(inputs[0].1.contains("denied"));
}

#[test]
fn stale_approval_after_policy_bump_and_argument_change_is_rejected() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("stale.txt", "original"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let approval = host.runtime.pending_approvals(project).unwrap()[0].clone();
    let operation = approval.operation();

    // A different operation with the same identity/arguments is still stale
    // when the final arguments displayed to the human changed.
    let changed = FrozenOperation::new(
        operation.operation_id(),
        operation.run_id(),
        operation.tool(),
        write_arguments("stale.txt", "tampered"),
        operation.cwd().clone(),
        operation.policy_version(),
        operation.permission_mode(),
    )
    .unwrap();
    assert!(matches!(
        host.runtime.approve_with_expected_operation(
            project,
            operation.operation_id(),
            Some(&changed)
        ),
        Err(RuntimeError::ApprovalInvalid { .. })
    ));
    assert_eq!(host.calls(), 0);

    // A policy-version bump invalidates the stored approval.
    let version = host
        .runtime
        .policy_admin_mut()
        .bump_version()
        .expect("bump");
    assert_eq!(version.get(), 2);
    assert!(matches!(
        host.runtime.approve(project, operation.operation_id()),
        Err(RuntimeError::ApprovalInvalid { .. })
    ));
    assert_eq!(host.calls(), 0);
    assert!(!host.project_a.join("stale.txt").exists());
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Interrupted
    );
    assert!(host.runtime.pending_approvals(project).unwrap().is_empty());
}

#[test]
fn stale_approval_after_run_resume_is_rejected() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("resume.txt", "hello"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let operation = host.runtime.pending_approvals(project).unwrap()[0]
        .operation()
        .operation_id();

    let stopped = host
        .runtime
        .stop_run(project, run.run_id(), StopReason::UserRequest)
        .expect("stop");
    assert_eq!(stopped.report(), StopReport::Stopped);
    assert_eq!(stopped.run().state(), RunState::Paused);
    assert!(stopped.checkpoint_saved());
    assert!(host.runtime.pending_approvals(project).unwrap().is_empty());

    let resumed = host
        .runtime
        .resume_run(project, run.run_id())
        .expect("resume");
    assert_eq!(resumed.state(), RunState::Running);
    assert_eq!(host.engine_state().resumes.len(), 1);
    assert!(matches!(
        host.runtime.approve(project, operation),
        Err(RuntimeError::ApprovalUnknown { .. })
    ));
    assert_eq!(host.calls(), 0);
    assert!(!host.project_a.join("resume.txt").exists());
}

#[test]
fn stop_resume_and_idle_are_distinct_from_failure_and_completion() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");

    // Unconfirmed stop becomes interrupted, not paused or failed.
    let uncertain = host
        .runtime
        .start_run(project, agent.agent_id(), "first")
        .expect("run");
    host.engine_state().stops.clear();
    let mut unconfirmed_host = TestHost::with_options(Options {
        stop_report: StopReport::Unconfirmed,
        ..Options::default()
    });
    // Use the separate host for the actual unconfirmed case.
    let (p, _) = unconfirmed_host.open_both();
    let a = unconfirmed_host
        .runtime
        .create_agent(
            p,
            AgentSpec::new("a", "implementer", unconfirmed_host.connection),
        )
        .expect("agent");
    let r = unconfirmed_host
        .runtime
        .start_run(p, a.agent_id(), "work")
        .expect("run");
    let outcome = unconfirmed_host
        .runtime
        .stop_run(p, r.run_id(), StopReason::UserRequest)
        .expect("stop");
    assert_eq!(outcome.report(), StopReport::Unconfirmed);
    assert_eq!(outcome.run().state(), RunState::Interrupted);
    assert_ne!(outcome.run().state(), RunState::Failed);

    // Confirmed stop -> paused -> resume same run.
    let stopped = host
        .runtime
        .stop_run(project, uncertain.run_id(), StopReason::UserRequest)
        .expect("stop");
    assert_eq!(stopped.run().state(), RunState::Paused);
    let resumed = host
        .runtime
        .resume_run(project, uncertain.run_id())
        .expect("resume");
    assert_eq!(resumed.run_id(), uncertain.run_id());
    assert_eq!(resumed.state(), RunState::Running);

    // A failed engine state is not rewritten as idle.
    host.push_event(
        uncertain.run_id(),
        EngineEvent::Failure {
            failure: EngineFailureKind::InvalidResponse,
        },
    );
    host.push_event(
        uncertain.run_id(),
        EngineEvent::StateChanged(RunState::Failed),
    );
    host.push_event(
        uncertain.run_id(),
        EngineEvent::StateChanged(RunState::Idle),
    );
    host.runtime.poll_run(project, uncertain.run_id()).unwrap();
    assert_eq!(
        host.runtime
            .run(project, uncertain.run_id())
            .unwrap()
            .state(),
        RunState::Failed
    );

    // Idle is quiescence only; a later run is a separate run.
    let idle = host
        .runtime
        .start_run(project, agent.agent_id(), "second")
        .expect("run");
    host.push_event(idle.run_id(), EngineEvent::StateChanged(RunState::Idle));
    host.runtime.poll_run(project, idle.run_id()).unwrap();
    assert_eq!(
        host.runtime.run(project, idle.run_id()).unwrap().state(),
        RunState::Idle
    );
    assert!(matches!(
        host.runtime.resume_run(project, idle.run_id()),
        Err(RuntimeError::InvalidRunTransition {
            from: RunState::Idle,
            ..
        })
    ));
    let next = host
        .runtime
        .start_run(project, agent.agent_id(), "third")
        .expect("new run");
    assert_ne!(next.run_id(), idle.run_id());
    assert_eq!(host.runtime.snapshot(project).unwrap().runs().len(), 3);
}

#[test]
fn allowed_read_executes_without_an_operation_result_record() {
    let mut policy = PolicyAdmin::new();
    policy.add_rule(read_allow_rule()).expect("allow read");
    let mut host = TestHost::with_options(Options {
        policy,
        ..Options::default()
    });
    let (project, _) = host.open_both();
    fs::write(host.project_a.join("notes.txt"), "read me").unwrap();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "read notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Read,
            arguments: ToolArguments::Read(ReadArgs {
                path: NonEmptyText::new("notes.txt").expect("path"),
                offset: None,
                limit: None,
            }),
        },
    );
    let committed = host.runtime.poll_run(project, run.run_id()).unwrap();
    assert_eq!(host.calls(), 1);
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Running
    );
    let completed = committed
        .iter()
        .find(|event| event.kind().as_str() == "run.operation_completed")
        .expect("completed event");
    assert_eq!(completed.payload().as_value()["outcome"], "not_applied");
    let operation_id = completed.operation_id().expect("operation id on event");
    assert!(
        host.store
            .lock()
            .unwrap()
            .operation(&operation_id)
            .unwrap()
            .is_none(),
        "a read has no side-effect intent/result row"
    );
    let inputs = host.engine_state().inputs.clone();
    assert_eq!(inputs.len(), 1);
    assert!(inputs[0].1.contains("read me"));
}

#[test]
fn resume_rechecks_current_credentials_and_permission() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "work")
        .expect("run");
    host.runtime
        .stop_run(project, run.run_id(), StopReason::UserRequest)
        .expect("stop");
    host.credentials
        .set(host.connection, CredentialAvailability::LoginRequired);
    assert!(matches!(
        host.runtime.resume_run(project, run.run_id()),
        Err(RuntimeError::ConnectionUnavailable {
            status: ConnectionStatus::LoginRequired,
            ..
        })
    ));
    assert_eq!(host.engine_state().resumes.len(), 0);
    host.credentials
        .set(host.connection, CredentialAvailability::Available);
    let resumed = host
        .runtime
        .resume_run(project, run.run_id())
        .expect("resume after re-auth");
    assert_eq!(resumed.state(), RunState::Running);
    assert_eq!(host.engine_state().resumes.len(), 1);
}

#[test]
fn restore_makes_zero_requests_and_reports_reconciliation() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("awaiting.txt", "hello"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let restored_approval = host.runtime.pending_approvals(project).unwrap()[0].clone();

    // Applied write evidence.
    fs::write(host.project_a.join("applied.txt"), "done").unwrap();
    let applied = commit_intent(
        &host.store,
        project,
        &host.project_a,
        RunId::new(project),
        ToolName::Write,
        write_arguments("applied.txt", "done"),
    );
    // Not-applied write evidence.
    let missing = commit_intent(
        &host.store,
        project,
        &host.project_a,
        RunId::new(project),
        ToolName::Write,
        write_arguments("missing.txt", "nope"),
    );
    // Ambiguous edit evidence.
    fs::write(host.project_a.join("ambiguous.txt"), "neither old nor new").unwrap();
    let ambiguous = commit_intent(
        &host.store,
        project,
        &host.project_a,
        RunId::new(project),
        ToolName::Edit,
        ToolArguments::Edit(EditArgs {
            path: NonEmptyText::new("ambiguous.txt").expect("path"),
            old_text: "before".to_owned(),
            new_text: "after".to_owned(),
            rationale: Rationale::new("change it").expect("rationale"),
            expected_version: None,
        }),
    );
    // Shell uncertainty.
    let shell = commit_intent(
        &host.store,
        project,
        &host.project_a,
        RunId::new(project),
        ToolName::Bash,
        ToolArguments::Bash(BashArgs {
            command: NonEmptyText::new("touch made-by-shell").expect("command"),
            purpose: Purpose::new("test uncertainty").expect("purpose"),
            timeout_ms: None,
        }),
    );

    host.reset_request_counters();
    let report = host.restart();
    assert_eq!(host.engine_state().request_count(), 0);
    assert_eq!(host.calls(), 0);
    assert!(!host.project_a.join("made-by-shell").exists());

    let project_report = report
        .projects()
        .iter()
        .find(|entry| entry.project_id() == project)
        .expect("project report");
    assert_eq!(project_report.project_id(), project);
    assert_eq!(
        project_report.permission().mode(),
        PermissionMode::Configured
    );
    assert!(!project_report.permission().evaluator_available());
    assert!(!project_report.permission().automatic_mode_usable());
    assert_eq!(project_report.connections().len(), 1);
    assert_eq!(
        project_report.connections()[0].status(),
        ConnectionStatus::Available
    );

    let run_report = project_report
        .runs()
        .iter()
        .find(|entry| entry.run_id() == run.run_id())
        .expect("run report");
    assert_eq!(run_report.previous_state(), RunState::AwaitingApproval);
    assert_eq!(run_report.state(), RunState::Interrupted);
    assert!(run_report.awaiting_approval());

    let pending = &project_report.pending_approvals()[0];
    assert!(pending.restored());
    assert!(!pending.reusable());
    assert!(matches!(
        host.runtime
            .approve(project, restored_approval.operation().operation_id()),
        Err(RuntimeError::ApprovalRestored { .. })
    ));
    assert_eq!(host.calls(), 0);

    let classify = |operation: OperationId| {
        project_report
            .operations()
            .iter()
            .find(|entry| entry.operation_id() == operation)
            .expect("operation report")
            .clone()
    };
    let applied_report = classify(applied);
    assert_eq!(applied_report.outcome(), OperationOutcome::Applied);
    assert_eq!(
        applied_report.source(),
        ReconciliationSource::NativeFileContent
    );
    let missing_report = classify(missing);
    assert_eq!(missing_report.outcome(), OperationOutcome::NotApplied);
    let ambiguous_report = classify(ambiguous);
    assert_eq!(ambiguous_report.outcome(), OperationOutcome::Unverifiable);
    let shell_report = classify(shell);
    assert_eq!(shell_report.outcome(), OperationOutcome::Unverifiable);
    assert_eq!(shell_report.source(), ReconciliationSource::ShellUncertain);

    let snapshot = host.runtime.snapshot(project).unwrap();
    assert_eq!(
        snapshot
            .runs()
            .iter()
            .find(|entry| entry.run_id() == run.run_id())
            .expect("run view")
            .state(),
        RunState::Interrupted
    );
}

#[test]
fn subscription_reconnect_matches_final_state_without_duplicates_or_loss() {
    let mut host = TestHost::new();
    let (project, other) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "talk")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::TextCompleted {
            text: "hello".to_owned(),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();

    let limit = HistoryLimit::new(1).expect("limit");
    let mut cursor = None;
    let mut replayed: Vec<(u64, String)> = Vec::new();
    loop {
        let batch = host
            .runtime
            .subscribe(project, cursor, limit)
            .expect("subscribe");
        if batch.events().is_empty() {
            break;
        }
        for event in batch.events() {
            replayed.push((event.sequence(), event.kind().as_str().to_owned()));
        }
        cursor = Some(SubscriptionCursor::new(project, batch.last_sequence()));
        if batch.last_sequence() >= host.runtime.last_sequence(project).unwrap() {
            break;
        }
    }

    let full = host
        .runtime
        .subscribe(project, None, HistoryLimit::new(100).expect("limit"))
        .expect("full");
    let expected = full
        .events()
        .iter()
        .map(|event| (event.sequence(), event.kind().as_str().to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        replayed, expected,
        "reconnect must not duplicate or lose events"
    );
    assert_eq!(
        full.last_sequence(),
        host.runtime.snapshot(project).unwrap().last_sequence()
    );
    assert!(matches!(
        host.runtime.subscribe(
            other,
            Some(SubscriptionCursor::new(project, full.last_sequence())),
            HistoryLimit::new(10).unwrap()
        ),
        Err(RuntimeError::CrossProject { .. })
    ));

    // Redelivery is a read, not an execution.
    let calls_before = host.calls();
    for _ in 0..3 {
        let again = host
            .runtime
            .subscribe(project, None, HistoryLimit::new(100).unwrap())
            .unwrap();
        assert_eq!(again.events(), full.events());
    }
    assert_eq!(host.calls(), calls_before);
}

#[test]
fn redelivery_after_approval_does_not_re_execute() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("once.txt", "one"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let operation = host.runtime.pending_approvals(project).unwrap()[0]
        .operation()
        .operation_id();
    host.runtime.approve(project, operation).unwrap();
    assert_eq!(host.calls(), 1);

    let batch = host
        .runtime
        .subscribe(project, None, HistoryLimit::new(100).unwrap())
        .unwrap();
    assert!(
        batch
            .events()
            .iter()
            .any(|event| event.kind().as_str() == "run.operation_completed")
    );
    for _ in 0..5 {
        host.runtime
            .subscribe(project, None, HistoryLimit::new(100).unwrap())
            .unwrap();
    }
    assert_eq!(host.calls(), 1);
    assert_eq!(
        fs::read_to_string(host.project_a.join("once.txt")).unwrap(),
        "one"
    );
    assert!(matches!(
        host.runtime.approve(project, operation),
        Err(RuntimeError::ApprovalUnknown { .. })
    ));
}

#[test]
fn child_agents_cannot_widen_the_parent_grant() {
    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let parent = host
        .runtime
        .create_agent(
            project,
            AgentSpec::new("parent", "implementer", host.connection)
                .with_scope(vec![read_allow_rule()]),
        )
        .expect("parent");
    assert!(matches!(
        host.runtime.create_agent(
            project,
            AgentSpec::new("child", "worker", host.connection).child_of(parent.agent_id())
        ),
        Err(RuntimeError::GrantWidening { .. })
    ));
    let child = host
        .runtime
        .create_agent(
            project,
            AgentSpec::new("child", "worker", host.connection)
                .child_of(parent.agent_id())
                .with_scope(vec![read_allow_rule()]),
        )
        .expect("narrow child");
    let run = host
        .runtime
        .start_run(project, child.agent_id(), "read only")
        .expect("run");
    assert_eq!(run.state(), RunState::Running);
    assert_eq!(host.runtime.snapshot(project).unwrap().runs().len(), 1);
}

// Silence unused imports for the scripted engine conversion helper on non-error
// paths.
#[allow(dead_code)]
fn _assert_json_payloads() {
    let _ = json!({});
}

#[test]
fn explicit_shutdown_refuses_new_work_saves_checkpoints_and_restores() {
    use herness_core::runtime::ShutdownOutcome;

    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("shutdown.txt", "not yet"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::AwaitingApproval
    );

    let settings = host
        .directory
        .get(host.connection)
        .expect("registered settings");
    host.runtime
        .record_connection_settings(settings)
        .expect("persist settings");

    let started = host.runtime.begin_shutdown().expect("begin shutdown");
    assert_eq!(started.outcome(), ShutdownOutcome::InProgress);
    assert!(host.runtime.is_shutting_down());
    assert!(matches!(
        host.runtime.start_run(project, agent.agent_id(), "later"),
        Err(RuntimeError::ShuttingDown)
    ));
    assert!(matches!(
        host.runtime.submit_input(project, run.run_id(), "later"),
        Err(RuntimeError::ShuttingDown)
    ));
    let operation = host.runtime.pending_approvals(project).unwrap()[0]
        .operation()
        .operation_id();
    assert!(matches!(
        host.runtime.approve(project, operation),
        Err(RuntimeError::ShuttingDown)
    ));

    let stopped = host
        .runtime
        .stop_all_for_shutdown()
        .expect("stop all for shutdown");
    assert!(stopped.all_inactive());
    assert!(stopped.save_succeeded());
    assert!(stopped.unconfirmed_runs().is_empty());
    assert_eq!(stopped.outcome(), ShutdownOutcome::Completed);
    let stopped_run = host.runtime.run(project, run.run_id()).unwrap();
    assert_eq!(stopped_run.state(), RunState::Paused);
    assert_eq!(
        stopped
            .runs()
            .iter()
            .find(|entry| entry.run_id() == run.run_id())
            .map(|entry| entry.checkpoint_saved()),
        Some(true)
    );
    let finished = host.runtime.finish_shutdown().expect("finish shutdown");
    assert_eq!(finished.outcome(), ShutdownOutcome::Completed);

    host.reset_request_counters();
    let report = host.restart();
    assert_eq!(host.engine_state().request_count(), 0);
    let previous = report.previous_shutdown().expect("previous shutdown");
    assert_eq!(previous.outcome(), ShutdownOutcome::Completed);
    assert_eq!(previous.stopped_runs(), 1);
    assert!(previous.unconfirmed_runs().is_empty());
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Paused
    );
    assert_eq!(host.runtime.persisted_connections().len(), 1);
    assert!(host.runtime.pending_approvals(project).unwrap().is_empty());
}

#[test]
fn unconfirmed_shutdown_stop_is_interrupted_and_never_reported_as_saved() {
    use herness_core::runtime::ShutdownOutcome;

    let mut host = TestHost::with_options(Options {
        stop_report: StopReport::Unconfirmed,
        ..Options::default()
    });
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "work")
        .expect("run");

    host.runtime.begin_shutdown().expect("begin shutdown");
    let stopped = host
        .runtime
        .stop_all_for_shutdown()
        .expect("stop all for shutdown");
    assert_eq!(stopped.outcome(), ShutdownOutcome::CompletedWithUnconfirmed);
    assert!(!stopped.save_succeeded());
    assert_eq!(stopped.unconfirmed_runs(), &[run.run_id()]);
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Interrupted
    );

    host.reset_request_counters();
    let report = host.restart();
    assert_eq!(host.engine_state().request_count(), 0);
    assert_eq!(
        report.previous_shutdown().unwrap().outcome(),
        ShutdownOutcome::CompletedWithUnconfirmed
    );
    assert_eq!(
        report.previous_shutdown().unwrap().unconfirmed_runs(),
        &[run.run_id()]
    );
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Interrupted
    );
}

#[test]
fn forced_shutdown_leaves_operation_intents_pending_for_reconciliation() {
    use herness_core::runtime::{ReconciliationSource, ShutdownOutcome};

    let mut host = TestHost::new();
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "run a shell command")
        .expect("run");
    let arguments = ToolArguments::Bash(BashArgs {
        command: NonEmptyText::new("sleep 30").expect("command"),
        purpose: Purpose::new("pending shell operation").expect("purpose"),
        timeout_ms: None,
    });
    let operation = commit_intent(
        &host.store,
        project,
        &host.project_a,
        run.run_id(),
        ToolName::Bash,
        arguments,
    );

    host.runtime.begin_shutdown().expect("begin shutdown");
    let forced = host.runtime.force_shutdown().expect("force shutdown");
    assert_eq!(forced.outcome(), ShutdownOutcome::Forced);
    assert!(!forced.save_succeeded());
    assert_eq!(forced.unconfirmed_runs(), &[run.run_id()]);
    assert!(forced.remaining_runs().is_empty());
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Interrupted
    );
    assert!(
        host.engine_state().stops.is_empty(),
        "force shutdown must not claim a coordinated stop"
    );

    let unresolved = host
        .store
        .lock()
        .expect("store lock")
        .unresolved_operations(&project)
        .expect("unresolved operations");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].intent().operation().operation_id(), operation);

    host.reset_request_counters();
    let report = host.restart();
    assert_eq!(host.engine_state().request_count(), 0);
    let project_report = report
        .projects()
        .iter()
        .find(|entry| entry.project_id() == project)
        .expect("project report");
    let reconciled = project_report
        .operations()
        .iter()
        .find(|entry| entry.operation_id() == operation)
        .expect("pending operation is reconciled");
    assert_eq!(reconciled.outcome(), OperationOutcome::Unverifiable);
    assert_eq!(reconciled.source(), ReconciliationSource::ShellUncertain);
    assert_eq!(
        host.runtime.run(project, run.run_id()).unwrap().state(),
        RunState::Interrupted
    );
}

#[test]
fn deferred_host_messages_are_discarded_and_visible_in_reconciliation() {
    let mut host = TestHost::with_options(Options {
        reject_input: true,
        ..Options::default()
    });
    let (project, _) = host.open_both();
    let agent = host
        .runtime
        .create_agent(project, AgentSpec::new("a", "implementer", host.connection))
        .expect("agent");
    let run = host
        .runtime
        .start_run(project, agent.agent_id(), "write notes")
        .expect("run");
    host.push_event(
        run.run_id(),
        EngineEvent::ToolCall {
            tool: ToolName::Write,
            arguments: write_arguments("deferred.txt", "not yet"),
        },
    );
    host.runtime.poll_run(project, run.run_id()).unwrap();
    let operation = host.runtime.pending_approvals(project).unwrap()[0]
        .operation()
        .operation_id();
    host.runtime.deny(project, operation).expect("deny");

    host.runtime.begin_shutdown().expect("begin shutdown");
    let stopped = host
        .runtime
        .stop_all_for_shutdown()
        .expect("stop all for shutdown");
    assert_eq!(stopped.discarded_deferred_messages(), 1);
    assert!(stopped.save_succeeded());

    host.reset_request_counters();
    let report = host.restart();
    assert_eq!(host.engine_state().request_count(), 0);
    assert_eq!(report.discarded_deferred_messages(), 1);
    assert_eq!(
        report
            .previous_shutdown()
            .expect("previous shutdown")
            .discarded_deferred_messages(),
        1
    );
    assert_eq!(
        host.engine_state().inputs.len(),
        0,
        "a discarded host result must never be replayed after restart"
    );
}
