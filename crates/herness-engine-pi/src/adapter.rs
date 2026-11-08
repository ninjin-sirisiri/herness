//! `EnginePort` implementation over pi-embedded.
//!
//! One independent pi-embedded runtime and session is created per run. Its SDK
//! snapshot is committed through [`EngineStore`] as a versioned opaque
//! checkpoint, and its session events are translated to host engine events
//! only after the corresponding snapshot save returned.
//!
//! The pi-embedded runtime is given exactly the five host tools. Its own file
//! and shell tools are never registered. Every tool invocation runs through the
//! host [`ToolGateway`] and the existing [`NativeFileTools`] / [`BashExecutor`];
//! the operation intent and the current engine checkpoint are committed in one
//! transaction before any side effect.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use herness_core::{
    AbsolutePath, AuthMethod, BashExecutor, ConnectionDirectory, ConnectionId, ConversationFailure,
    CoreError, CredentialPort, EngineEvent, EngineInput, EnginePort, EngineStart,
    EvaluationContext, FileFailure, FileLockRegistry, FileToolOutput, FrozenOperation, GrantScope,
    NativeFileTools, OperationId, PermissionOutcome, PermissionPolicy, ProcessSupervisor,
    ProjectRoot, Provider, ProviderFailureKind, RunId, RunState, ShellFailure, StopReason,
    StopReport, StorePort, SystemLauncher, ToolArguments, ToolExecutor, ToolGateway, ToolName,
};
use pi_embedded::SessionStatus;
use pi_embedded::{
    CreateSessionOptions, EmbeddedHost, EmbeddedRuntime, EmbeddedSession, EmbeddedTool, FnTool,
    Subscription, ToolContext, ToolDeclaration, ToolEffect, ToolResult,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{
    engine_invalid_response, engine_unavailable, provider_failure, sanitized_detail,
};
use crate::events::{EventQueue, EventTranslator};
use crate::session_store::{
    ENGINE_TOOL_AWAITING_EVENT_KIND, ENGINE_TOOL_DENIED_EVENT_KIND, EngineCheckpoint,
    EngineSessionStore, EngineStore, RunAuditMetadata,
};
use crate::stream::{ChatGptCatalog, ChatGptModel, ProviderEndpoints, StreamBridge, model_for};

/// How a run's SDK session is opened.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoreKind {
    /// A new empty session with the system prompt.
    Create,
    /// Reopen this run's durable checkpoint.
    Resume,
    /// Copy a stable previous conversation into a new run.
    Continuation,
}

/// Adapter configuration owned by the trusted host composition.
#[derive(Debug, Clone)]
pub struct PiEngineConfig {
    endpoints: ProviderEndpoints,
    policy: PermissionPolicy,
}

impl Default for PiEngineConfig {
    fn default() -> Self {
        Self {
            endpoints: ProviderEndpoints::official(),
            policy: PermissionPolicy::initial(),
        }
    }
}

impl PiEngineConfig {
    /// Creates a configuration with the public provider endpoints.
    pub fn new(policy: PermissionPolicy) -> Self {
        Self {
            endpoints: ProviderEndpoints::official(),
            policy,
        }
    }

    /// Replaces the provider base URLs. Production hosts keep the official
    /// endpoints; integration tests pass loopback endpoints.
    pub fn with_endpoints(mut self, endpoints: ProviderEndpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Provider endpoints in use.
    pub fn endpoints(&self) -> &ProviderEndpoints {
        &self.endpoints
    }
}

/// Host-owned pi engine adapter.
///
/// The adapter owns a multi-threaded tokio runtime because pi-embedded is
/// async while [`EnginePort`] is synchronous. Sessions are isolated: every run
/// has its own embedded runtime, session store, event queue, tool gateway, and
/// process supervisor.
pub struct PiEngine<S: StorePort + Send + 'static> {
    runtime: tokio::runtime::Runtime,
    store: Arc<Mutex<S>>,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    config: PiEngineConfig,
    policy: Arc<RwLock<PermissionPolicy>>,
    file_locks: Arc<FileLockRegistry>,
    catalog: Arc<ChatGptCatalog>,
    runs: HashMap<RunId, Arc<RunContext<S>>>,
}

impl<S: StorePort + Send + 'static> PiEngine<S> {
    /// Creates an adapter over the host store and credential boundary.
    pub fn new(
        store: Arc<Mutex<S>>,
        credentials: Arc<dyn CredentialPort + Send + Sync>,
        directory: ConnectionDirectory,
        config: PiEngineConfig,
    ) -> Result<Self, CoreError> {
        let catalog = Arc::new(ChatGptCatalog::new(
            Arc::clone(&credentials),
            directory.clone(),
            config.endpoints.clone(),
        )?);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("herness-engine-pi")
            .build()
            .map_err(|_| engine_unavailable())?;
        let policy = Arc::new(RwLock::new(config.policy.clone()));
        Ok(Self {
            runtime,
            store,
            credentials,
            directory,
            config,
            policy,
            file_locks: Arc::new(FileLockRegistry::new()),
            catalog,
            runs: HashMap::new(),
        })
    }

    /// Replaces the permission policy used by subsequent tool re-checks.
    ///
    /// The host must build the policy through `PolicyAdmin` so its version is
    /// newer. An authorization issued for an older version is rejected when the
    /// gateway re-checks it.
    pub fn replace_policy(&self, policy: PermissionPolicy) {
        *self
            .policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = policy;
    }

    /// Runs one engine future on the adapter runtime and waits for its result.
    ///
    /// Tauri commands and other hosts may call the synchronous [`EnginePort`]
    /// from inside another tokio runtime. `Runtime::block_on` panics in that
    /// situation, so the future is scheduled on the adapter runtime and the
    /// caller waits on a channel instead. The adapter runtime keeps its worker
    /// threads running independently.
    fn run_on_engine<F, T>(&self, future: F) -> Result<T, CoreError>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        run_on_runtime(&self.runtime, future)
    }

    /// Lists the selected ChatGPT account's public model catalog.
    ///
    /// Only models intended for display (`visibility: "list"`) are returned,
    /// in server order, and `slug` is the model identifier. Non-ChatGPT
    /// connections have no host catalog and are rejected rather than guessed.
    pub fn list_chatgpt_models(
        &self,
        connection: ConnectionId,
    ) -> Result<Vec<ChatGptModel>, CoreError> {
        let catalog = Arc::clone(&self.catalog);
        self.run_on_engine(async move { catalog.list(connection).await })?
    }

    fn build_run(
        &self,
        start: EngineStart,
        restore: Option<EngineCheckpoint>,
        kind: RestoreKind,
    ) -> Result<Arc<RunContext<S>>, CoreError> {
        let settings = self
            .directory
            .get(start.connection())
            .map_err(|_| engine_unavailable())?;
        if settings.auth_method() == AuthMethod::ChatGptLogin && restore.is_none() {
            // The catalog is checked when a run starts. Restoring a saved run
            // must not make a network request or re-resolve a model choice.
            let catalog = Arc::clone(&self.catalog);
            let connection = start.connection();
            let models = self.run_on_engine(async move { catalog.list(connection).await })??;
            if !models.iter().any(|model| model.slug() == settings.model()) {
                // The selected model is not available to this account. Never
                // substitute another model or provider.
                return Err(provider_failure(
                    Provider::OpenAi,
                    ProviderFailureKind::Refused,
                ));
            }
        }
        let model = model_for(&settings, &self.config.endpoints)?;
        let root = ProjectRoot::new(start.cwd().as_path())?;
        let audit = RunAuditMetadata {
            project_id: start.project_id(),
            agent_id: start.agent_id(),
            session_id: start.session_id(),
            run_id: start.run_id(),
            connection: start.connection(),
            cwd: start.cwd().clone(),
            instructions: start.instructions().to_owned(),
        };
        let store = match (&restore, kind) {
            (Some(restore), RestoreKind::Continuation) => EngineStore::seeded(
                Arc::clone(&self.store),
                audit.clone(),
                restore.snapshot.clone(),
            ),
            _ => EngineStore::new(Arc::clone(&self.store), audit.clone()),
        };
        if let Some(restore) = &restore
            && kind != RestoreKind::Continuation
        {
            store.set_snapshot(restore.snapshot.clone());
        }
        let queue = EventQueue::new();
        let supervisor = ProcessSupervisor::new();
        let files = NativeFileTools::with_lock_registry(
            root,
            start.agent_id(),
            start.session_id(),
            store.clone(),
            Arc::clone(&self.file_locks),
        )?;
        let shell = BashExecutor::new(
            start.agent_id(),
            start.session_id(),
            store.clone(),
            SystemLauncher,
            supervisor.clone(),
        )?;
        let gateway = ToolGateway::new(HostExecutors { files, shell });
        let tools = Arc::new(ToolRuntime {
            run_id: start.run_id(),
            project_id: start.project_id(),
            cwd: start.cwd().clone(),
            requested_work: start.instructions().to_owned(),
            policy: Arc::clone(&self.policy),
            gateway: Mutex::new(gateway),
            store: store.clone(),
            queue: queue.clone(),
            stopping: AtomicBool::new(false),
            supervisor,
        });
        let stream = Arc::new(StreamBridge::new(
            start.connection(),
            &settings,
            Arc::clone(&self.credentials),
        ));
        let session_store = Arc::new(EngineSessionStore::new(store.clone(), queue.clone()));
        let host = EmbeddedHost {
            store: session_store,
            capabilities: Vec::new(),
            stream: stream.stream_fn(),
            tools: tools.tools(),
            compactor: None,
            compact_at_characters: None,
            lifecycle: None,
            listener_error: None,
        };
        let embedded = EmbeddedRuntime::new(host).map_err(|_| engine_unavailable())?;
        let session_id = start.session_id().to_string();
        let instructions = start.instructions().trim().to_owned();
        let restore_present = restore.is_some();
        let restore_for_session = restore;
        let session = self
            .run_on_engine(async move {
                match restore_for_session {
                    Some(_) => embedded.restore(&session_id).await,
                    None => {
                        embedded
                            .create(CreateSessionOptions {
                                id: session_id,
                                model,
                                system_prompt: (!instructions.is_empty()).then_some(instructions),
                            })
                            .await
                    }
                }
            })?
            .map_err(|_| engine_unavailable())?;
        let translator = Arc::new(Mutex::new(EventTranslator::new()));
        let subscription = session.subscribe({
            let queue = queue.clone();
            let translator = Arc::clone(&translator);
            move |event| {
                let mapped = translator
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .translate(event);
                queue.extend(mapped);
            }
        });
        if restore_present {
            // The SDK emits its recovery event before restore returns, so the
            // listener cannot see it. The recovery save is already durable;
            // publish the resulting state after subscribing.
            queue.push(EngineEvent::StateChanged(map_status(
                session.snapshot().status,
            )));
        }
        Ok(Arc::new(RunContext {
            session,
            queue,
            store,
            tools,
            _subscription: Mutex::new(Some(subscription)),
        }))
    }
}

impl<S: StorePort + Send + 'static> PiEngine<S> {
    fn latest_checkpoint(
        &self,
        run: &RunId,
    ) -> Result<Option<herness_core::Checkpoint>, CoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.load_checkpoint(run)
    }

    /// Validates a continuation without starting anything. The returned
    /// checkpoint is the previous conversation copied into the new run.
    fn validate_continuation(
        &self,
        start: &EngineStart,
        previous: &herness_core::Checkpoint,
    ) -> Result<EngineCheckpoint, CoreError> {
        let previous_run = previous.run_id();
        if previous_run == start.run_id() {
            return Err(CoreError::InvalidValue {
                field: "runId".to_owned(),
                violation: herness_core::ArgumentViolation::Invalid {
                    detail: "a continuation run must have a new run identifier".to_owned(),
                },
            });
        }
        let Some(stored) = self.latest_checkpoint(&previous_run)? else {
            return Err(not_continuable(
                previous_run,
                ConversationFailure::MissingCheckpoint,
            ));
        };
        if stored.format_version() != previous.format_version()
            || stored.payload().as_bytes() != previous.payload().as_bytes()
        {
            return Err(not_continuable(
                previous_run,
                ConversationFailure::CheckpointNotLatest,
            ));
        }
        let parsed = crate::session_store::parse_checkpoint(previous, previous_run)
            .map_err(|_| not_continuable(previous_run, ConversationFailure::CorruptCheckpoint))?;
        if parsed.meta.project_id != start.project_id()
            || parsed.meta.agent_id != start.agent_id()
            || parsed.meta.session_id != start.session_id()
            || parsed.meta.connection != start.connection()
            || parsed.meta.cwd != *start.cwd()
            || parsed.meta.instructions != start.instructions()
        {
            return Err(not_continuable(
                previous_run,
                ConversationFailure::ScopeMismatch,
            ));
        }
        if let Some(context) = self.runs.get(&previous_run) {
            let live = context.session.snapshot();
            if live.status != SessionStatus::Idle || live.needs_response || live.partial.is_some() {
                return Err(not_continuable(
                    previous_run,
                    ConversationFailure::PreviousRunNotStable,
                ));
            }
            if !context.tools.supervisor.active_groups().is_empty() {
                return Err(not_continuable(
                    previous_run,
                    ConversationFailure::ManagedProcess,
                ));
            }
            if live
                .invocations
                .iter()
                .any(|invocation| invocation.phase != pi_embedded::InvocationPhase::Completed)
            {
                return Err(not_continuable(
                    previous_run,
                    ConversationFailure::PendingInvocation,
                ));
            }
        }
        let snapshot = &parsed.snapshot;
        if snapshot.status != SessionStatus::Idle
            || snapshot.needs_response
            || snapshot.partial.is_some()
        {
            return Err(not_continuable(
                previous_run,
                ConversationFailure::PreviousRunNotStable,
            ));
        }
        if snapshot
            .invocations
            .iter()
            .any(|invocation| invocation.phase != pi_embedded::InvocationPhase::Completed)
        {
            return Err(not_continuable(
                previous_run,
                ConversationFailure::PendingInvocation,
            ));
        }
        Ok(parsed)
    }

    /// Validates a resume without opening a session or sending anything.
    fn validate_resume(
        &self,
        run: &RunId,
        checkpoint: &herness_core::Checkpoint,
    ) -> Result<EngineCheckpoint, CoreError> {
        if checkpoint.run_id() != *run {
            return Err(CoreError::MismatchedRun {
                expected: *run,
                found: checkpoint.run_id(),
            });
        }
        let parsed = crate::session_store::parse_checkpoint(checkpoint, *run)?;
        let Some(stored) = self.latest_checkpoint(run)? else {
            return Err(not_resumable(run, ConversationFailure::MissingCheckpoint));
        };
        if stored.format_version() != checkpoint.format_version()
            || stored.payload().as_bytes() != checkpoint.payload().as_bytes()
        {
            return Err(not_resumable(run, ConversationFailure::CheckpointNotLatest));
        }
        if let Some(context) = self.runs.get(run) {
            let snapshot = context.session.snapshot();
            if matches!(
                snapshot.status,
                SessionStatus::Running | SessionStatus::AwaitingApproval
            ) {
                return Err(not_resumable(run, ConversationFailure::StopUnconfirmed));
            }
            if !context.tools.supervisor.active_groups().is_empty() {
                return Err(not_resumable(run, ConversationFailure::ManagedProcess));
            }
            ensure_resumable_snapshot(*run, &snapshot)?;
        } else {
            ensure_resumable_snapshot(*run, &parsed.snapshot)?;
        }
        Ok(parsed)
    }
}

fn ensure_resumable_snapshot(
    run: RunId,
    snapshot: &pi_embedded::SessionSnapshot,
) -> Result<(), CoreError> {
    if snapshot.status == SessionStatus::Disposed {
        return Err(not_resumable(
            &run,
            ConversationFailure::PreviousRunNotStable,
        ));
    }
    if snapshot
        .invocations
        .iter()
        .any(|invocation| invocation.phase != pi_embedded::InvocationPhase::Completed)
    {
        return Err(not_resumable(&run, ConversationFailure::PendingInvocation));
    }
    Ok(())
}

fn not_continuable(previous_run: RunId, reason: ConversationFailure) -> CoreError {
    CoreError::NotContinuable {
        previous_run,
        reason,
    }
}

fn not_resumable(run: &RunId, reason: ConversationFailure) -> CoreError {
    CoreError::NotResumable { run: *run, reason }
}

impl<S: StorePort + Send + 'static> EnginePort for PiEngine<S> {
    fn tool_execution_authority(&self) -> herness_core::ToolExecutionAuthority {
        herness_core::ToolExecutionAuthority::Adapter
    }

    fn start(&mut self, start: EngineStart) -> Result<(), CoreError> {
        let run_id = start.run_id();
        if self.runs.contains_key(&run_id) {
            return Err(engine_invalid_response());
        }
        let context = self.build_run(start, None, RestoreKind::Create)?;
        self.runs.insert(run_id, context.clone());
        context
            .queue
            .push(EngineEvent::StateChanged(RunState::Idle));
        Ok(())
    }

    fn start_continuation(
        &mut self,
        start: EngineStart,
        previous: herness_core::Checkpoint,
    ) -> Result<(), CoreError> {
        let parsed = self.validate_continuation(&start, &previous)?;
        let run_id = start.run_id();
        if self.runs.contains_key(&run_id) {
            return Err(engine_invalid_response());
        }
        let context = self.build_run(start, Some(parsed), RestoreKind::Continuation)?;
        self.runs.insert(run_id, context);
        Ok(())
    }

    fn check_continuation(
        &self,
        start: &EngineStart,
        previous: &herness_core::Checkpoint,
    ) -> Result<(), CoreError> {
        self.validate_continuation(start, previous).map(|_| ())
    }

    fn send_input(&mut self, run: &RunId, input: EngineInput) -> Result<(), CoreError> {
        let EngineInput::Text(text) = input;
        if text.trim().is_empty() {
            return Err(CoreError::InvalidValue {
                field: "input".to_owned(),
                violation: herness_core::ArgumentViolation::Empty,
            });
        }
        let context = self.runs.get(run).cloned().ok_or_else(engine_unavailable)?;
        let snapshot = context.session.snapshot();
        let unresolved = snapshot.needs_response
            || snapshot
                .invocations
                .iter()
                .any(|invocation| invocation.phase != pi_embedded::InvocationPhase::Completed);
        if matches!(
            snapshot.status,
            SessionStatus::Running | SessionStatus::AwaitingApproval | SessionStatus::Disposed
        ) || unresolved
        {
            return Err(CoreError::InvalidRunTransition {
                from: map_status(snapshot.status),
                to: RunState::Running,
            });
        }
        let session = context.session.clone();
        self.runtime.spawn(async move {
            // Errors are reported through the session state and events.
            let _ = session.submit(&text).await;
        });
        Ok(())
    }

    fn request_stop(&mut self, run: &RunId, _reason: StopReason) -> Result<StopReport, CoreError> {
        let Some(context) = self.runs.get(run).cloned() else {
            return Ok(StopReport::NotRunning);
        };
        if !matches!(
            context.session.snapshot().status,
            SessionStatus::Running | SessionStatus::AwaitingApproval
        ) {
            return Ok(StopReport::NotRunning);
        }
        context.tools.stopping.store(true, Ordering::SeqCst);
        // Refuse new managed processes and signal existing groups before the
        // SDK cancellation is waited on. `stop_all` owns the bounded grace and
        // SIGKILL escalation so this synchronous stop can actually return even
        // when a shell ignores SIGTERM. An unconfirmed group is never reported
        // as a confirmed stop.
        context.tools.supervisor.begin_stop();
        let supervisor_report = context
            .tools
            .supervisor
            .stop_all(herness_core::DEFAULT_STOP_GRACE);
        let groups_confirmed = supervisor_report.all_confirmed();
        let session = context.session.clone();
        let cancellation = self.run_on_engine(async move { session.cancel().await });
        let report = match cancellation {
            Ok(Ok(())) if groups_confirmed => StopReport::Stopped,
            Ok(Ok(())) | Ok(Err(_)) | Err(_) => StopReport::Unconfirmed,
        };
        if report == StopReport::Stopped {
            context
                .queue
                .push(EngineEvent::StateChanged(RunState::Interrupted));
        }
        Ok(report)
    }

    fn check_resume(
        &self,
        run: &RunId,
        checkpoint: &herness_core::Checkpoint,
    ) -> Result<(), CoreError> {
        self.validate_resume(run, checkpoint).map(|_| ())
    }

    fn resume(
        &mut self,
        run: &RunId,
        checkpoint: herness_core::Checkpoint,
    ) -> Result<(), CoreError> {
        let parsed = self.validate_resume(run, &checkpoint)?;
        if self.runs.contains_key(run) {
            // The live session was confirmed stopped and has no unfinished
            // invocation. Reuse it without restoring a second session, sending
            // input, or executing a tool.
            return Ok(());
        }
        let meta = parsed.meta.clone();
        let start = EngineStart::new(
            meta.project_id,
            meta.agent_id,
            meta.session_id,
            *run,
            meta.connection,
            meta.cwd.clone(),
            meta.instructions.clone(),
        )?;
        let context = self.build_run(start, Some(parsed), RestoreKind::Resume)?;
        self.runs.insert(*run, context);
        Ok(())
    }

    fn checkpoint(&mut self, run: &RunId) -> Result<Option<herness_core::Checkpoint>, CoreError> {
        if let Some(context) = self.runs.get(run)
            && let Some(checkpoint) = context.store.current_checkpoint()?
        {
            return Ok(Some(checkpoint));
        }
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.load_checkpoint(run)
    }

    fn poll_events(&mut self, run: &RunId) -> Result<Vec<EngineEvent>, CoreError> {
        Ok(self
            .runs
            .get(run)
            .map(|context| context.queue.drain())
            .unwrap_or_default())
    }
}

struct RunContext<S> {
    session: EmbeddedSession,
    queue: EventQueue,
    store: EngineStore<S>,
    tools: Arc<ToolRuntime<S>>,
    _subscription: Mutex<Option<Subscription>>,
}

struct ToolRuntime<S> {
    run_id: RunId,
    project_id: herness_core::ProjectId,
    cwd: AbsolutePath,
    requested_work: String,
    policy: Arc<RwLock<PermissionPolicy>>,
    gateway: Mutex<ToolGateway<HostExecutors<S>>>,
    store: EngineStore<S>,
    queue: EventQueue,
    stopping: AtomicBool,
    supervisor: ProcessSupervisor,
}

impl<S: StorePort + Send + 'static> ToolRuntime<S> {
    fn tools(self: &Arc<Self>) -> Vec<Arc<dyn EmbeddedTool>> {
        vec![
            self.make_tool(ToolName::Read),
            self.make_tool(ToolName::Search),
            self.make_tool(ToolName::Write),
            self.make_tool(ToolName::Edit),
            self.make_tool(ToolName::Bash),
        ]
    }

    fn make_tool(self: &Arc<Self>, tool: ToolName) -> Arc<dyn EmbeddedTool> {
        let declaration = declaration(tool);
        let runtime = Arc::clone(self);
        Arc::new(FnTool::new(declaration, move |args, context| {
            let runtime = Arc::clone(&runtime);
            Box::pin(async move { runtime.execute_host_tool(tool, args, context).await })
        }))
    }

    async fn execute_host_tool(
        self: Arc<Self>,
        tool: ToolName,
        args: pi_ai::JsonObject,
        context: ToolContext,
    ) -> anyhow::Result<ToolResult> {
        let cancel = context.cancel.clone();
        let invocation_id = context.invocation_id.clone();
        if cancel.is_cancelled() || self.stopping.load(Ordering::SeqCst) {
            return Ok(ToolResult::failure("tool cancelled before start"));
        }
        let runtime = Arc::clone(&self);
        let blocking_cancel = cancel.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            runtime.execute_blocking(tool, args, &invocation_id, &blocking_cancel)
        })
        .await;
        match outcome {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(HostToolFailure::Known(detail))) => Ok(ToolResult::failure(detail)),
            Ok(Err(HostToolFailure::Uncertain(detail))) => {
                // The side effect may have happened. Stop this run; never
                // retry the tool automatically.
                self.stopping.store(true, Ordering::SeqCst);
                self.supervisor.begin_stop();
                cancel.cancel();
                Err(anyhow::anyhow!(detail))
            }
            Err(_) => Ok(ToolResult::failure("tool execution task failed")),
        }
    }

    fn execute_blocking(
        &self,
        tool: ToolName,
        args: pi_ai::JsonObject,
        invocation_id: &str,
        cancel: &CancellationToken,
    ) -> Result<ToolResult, HostToolFailure> {
        if cancel.is_cancelled() || self.stopping.load(Ordering::SeqCst) {
            return Err(HostToolFailure::Known(
                "tool cancelled before execution".to_owned(),
            ));
        }
        let arguments = parse_arguments(tool, args)?;
        // Read the current human policy for each invocation. An authorization
        // from an older policy version is rejected at the final re-check.
        let policy = self
            .policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let grant = GrantScope::for_run(self.project_id, &policy);
        let operation = FrozenOperation::new(
            stable_operation_id(self.run_id, invocation_id),
            self.run_id,
            tool,
            arguments,
            self.cwd.clone(),
            policy.version(),
            policy.mode(),
        )
        .map_err(|error| HostToolFailure::Known(sanitized_detail(&error)))?;
        let mut gateway = self
            .gateway
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcome = gateway
            .authorize(
                &policy,
                &grant,
                &operation,
                &EvaluationContext::new(self.requested_work.clone(), Vec::new()),
                None,
            )
            .map_err(|error| HostToolFailure::Known(sanitized_detail(&error)))?;
        let authorization = match outcome {
            PermissionOutcome::Allow { authorization } => authorization,
            PermissionOutcome::Deny { .. } => {
                self.store
                    .commit_tool_audit(&operation, ENGINE_TOOL_DENIED_EVENT_KIND, "policy_denied")
                    .map_err(|_| {
                        HostToolFailure::Known("tool policy audit could not be recorded".to_owned())
                    })?;
                return Err(HostToolFailure::Known(
                    "tool denied by host permission policy".to_owned(),
                ));
            }
            PermissionOutcome::AwaitingApproval { .. } => {
                self.store
                    .commit_tool_audit(
                        &operation,
                        ENGINE_TOOL_AWAITING_EVENT_KIND,
                        "human_approval_required",
                    )
                    .map_err(|_| {
                        HostToolFailure::Known("tool policy audit could not be recorded".to_owned())
                    })?;
                // Hand the exact frozen operation to the host. This adapter never
                // executes an awaiting operation; the host records it and, only
                // after an explicit human decision, executes it once.
                self.queue.push(EngineEvent::ToolApprovalRequired {
                    operation: operation.clone(),
                });
                return Err(HostToolFailure::Known(
                    "tool requires host approval and was not executed".to_owned(),
                ));
            }
        };
        if cancel.is_cancelled() || self.stopping.load(Ordering::SeqCst) {
            return Err(HostToolFailure::Known(
                "tool cancelled before execution".to_owned(),
            ));
        }
        // Re-read the policy immediately before execution. A policy change
        // between authorization and execution invalidates the old decision.
        let current_policy = self
            .policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if current_policy.version() != operation.policy_version() {
            return Err(HostToolFailure::Known(
                "permission policy changed before execution; re-evaluate the tool".to_owned(),
            ));
        }
        // The executor behind the gateway records the operation intent and
        // the engine checkpoint in one transaction before its side effect.
        // `EngineStore` substitutes this run's engine snapshot for the
        // executor's audit checkpoint, so the same guarantee holds even though
        // the concrete transaction is owned by the executor.
        match gateway.execute(&current_policy, &operation, &authorization) {
            Ok(output) => {
                let value = serde_json::to_value(output).map_err(|_| {
                    HostToolFailure::Uncertain("tool result could not be serialized".to_owned())
                })?;
                Ok(ToolResult::json(value))
            }
            Err(herness_core::GatewayError::Approval(error)) => Err(HostToolFailure::Known(
                format!("permission check failed: {error}"),
            )),
            Err(herness_core::GatewayError::Executor(error)) => {
                if side_effect_is_uncertain(&error) {
                    Err(HostToolFailure::Uncertain(sanitized_detail(&error)))
                } else {
                    Err(HostToolFailure::Known(sanitized_detail(&error)))
                }
            }
        }
    }
}

enum HostToolFailure {
    Known(String),
    Uncertain(String),
}

fn side_effect_is_uncertain(error: &CoreError) -> bool {
    match error {
        CoreError::FileToolFailed {
            failure: FileFailure::Unverifiable { .. },
            ..
        } => true,
        CoreError::ShellToolFailed { failure, .. } => matches!(
            failure,
            ShellFailure::Unverifiable { .. }
                | ShellFailure::Unconfirmed { .. }
                | ShellFailure::Stopped { .. }
                | ShellFailure::TimedOut { .. }
        ),
        _ => false,
    }
}

fn parse_arguments(
    tool: ToolName,
    args: pi_ai::JsonObject,
) -> Result<ToolArguments, HostToolFailure> {
    let value = serde_json::json!({
        "tool": tool.as_str(),
        "arguments": args,
    });
    serde_json::from_value(value).map_err(|error| {
        let detail = format!("invalid {} arguments: {error}", tool.as_str());
        HostToolFailure::Known(detail.chars().take(512).collect())
    })
}

/// Deterministic operation id for one SDK tool call: the same run and tool-call
/// id can never create a second operation or side effect.
fn stable_operation_id(run: RunId, invocation_id: &str) -> OperationId {
    let mut hasher = Sha256::new();
    hasher.update(run.local_id().as_bytes());
    hasher.update(b"\0");
    hasher.update(invocation_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    OperationId::from_parts(run.project_id(), Uuid::from_bytes(bytes))
}

fn map_status(status: SessionStatus) -> RunState {
    match status {
        SessionStatus::Idle | SessionStatus::Disposed => RunState::Idle,
        SessionStatus::Running => RunState::Running,
        SessionStatus::AwaitingApproval => RunState::AwaitingApproval,
        SessionStatus::Paused => RunState::Paused,
        SessionStatus::Interrupted => RunState::Interrupted,
    }
}

struct HostExecutors<S> {
    files: NativeFileTools<EngineStore<S>>,
    shell: BashExecutor<EngineStore<S>, SystemLauncher>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "output", rename_all = "snake_case")]
enum HostToolOutput {
    File(Box<FileToolOutput>),
    Shell(Box<herness_core::BashOutput>),
}

impl<S: StorePort> ToolExecutor for HostExecutors<S> {
    type Output = HostToolOutput;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<Self::Output, CoreError> {
        match operation.tool() {
            ToolName::Read | ToolName::Search | ToolName::Write | ToolName::Edit => self
                .files
                .execute(operation)
                .map(|output| HostToolOutput::File(Box::new(output))),
            ToolName::Bash => self
                .shell
                .execute(operation)
                .map(|output| HostToolOutput::Shell(Box::new(output))),
        }
    }
}

fn declaration(tool: ToolName) -> ToolDeclaration {
    let (description, parameters) = match tool {
        ToolName::Read => (
            "Read a UTF-8 file from the project. Paths are resolved under the project root.",
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "offset": {"type": "integer", "minimum": 1},
                    "limit": {"type": "integer", "minimum": 1}
                }
            }),
        ),
        ToolName::Search => (
            "Search project files. Returns matching file, line, and text.",
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "minLength": 1},
                    "path": {"type": "string", "minLength": 1},
                    "glob": {"type": "string", "minLength": 1},
                    "maxResults": {"type": "integer", "minimum": 1}
                }
            }),
        ),
        ToolName::Write => (
            "Create a new file. A non-empty rationale describing why the file is created is required.",
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "content", "rationale"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "content": {"type": "string"},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 1000}
                }
            }),
        ),
        ToolName::Edit => (
            "Edit an existing file with an exact old/new text replacement. A non-empty rationale is required.",
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "oldText", "newText", "rationale"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "oldText": {"type": "string"},
                    "newText": {"type": "string"},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "expectedVersion": {"type": "string", "minLength": 1}
                }
            }),
        ),
        ToolName::Bash => (
            "Run a shell command in the project working directory. A non-empty command purpose is required and recorded separately from output.",
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["command", "purpose"],
                "properties": {
                    "command": {"type": "string", "minLength": 1},
                    "purpose": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "timeoutMs": {"type": "integer", "minimum": 1}
                }
            }),
        ),
    };
    ToolDeclaration {
        name: tool.as_str().to_owned(),
        description: description.to_owned(),
        parameters,
        capabilities: Vec::new(),
        // The host gateway owns review and approval. Marking the SDK
        // declaration as a read effect prevents a second, SDK-local approval
        // path from bypassing or shadowing the host one. Side-effect
        // uncertainty is handled explicitly by the tool handler.
        effect: ToolEffect::Read,
        approval: false,
    }
}

/// Schedules a future on `runtime` and waits for it without entering a nested
/// runtime. Safe to call from another tokio worker.
fn run_on_runtime<F, T>(runtime: &tokio::runtime::Runtime, future: F) -> Result<T, CoreError>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = tx.send(future.await);
    });
    rx.recv().map_err(|_| engine_unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use herness_core::ProjectId;

    #[test]
    fn operation_ids_are_stable_within_a_run_and_unique_across_runs() {
        let project = ProjectId::new();
        let run = RunId::new(project);
        let first = stable_operation_id(run, "call-1");
        let same = stable_operation_id(run, "call-1");
        let other_call = stable_operation_id(run, "call-2");
        let other_run = stable_operation_id(RunId::new(project), "call-1");
        assert_eq!(first, same);
        assert_ne!(first, other_call);
        assert_ne!(first, other_run);
        assert_eq!(first.project_id(), project);
    }

    #[test]
    fn every_registered_declaration_is_one_of_the_five_host_tools() {
        let names: Vec<String> = [
            ToolName::Read,
            ToolName::Search,
            ToolName::Write,
            ToolName::Edit,
            ToolName::Bash,
        ]
        .into_iter()
        .map(|tool| declaration(tool).name)
        .collect();
        assert_eq!(names, vec!["read", "search", "write", "edit", "bash"]);
    }

    #[test]
    fn engine_bridge_survives_being_called_from_another_tokio_runtime() {
        let engine_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("engine runtime");
        let host_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("host runtime");
        let value = host_runtime.block_on(async {
            run_on_runtime(&engine_runtime, async { 7_u32 }).expect("bridge result")
        });
        assert_eq!(value, 7);
    }

    #[test]
    fn write_and_bash_declarations_require_rationale_and_purpose() {
        assert_eq!(
            declaration(ToolName::Write).parameters["required"],
            serde_json::json!(["path", "content", "rationale"])
        );
        assert_eq!(
            declaration(ToolName::Bash).parameters["required"],
            serde_json::json!(["command", "purpose"])
        );
        assert!(!declaration(ToolName::Bash).approval);
        assert_eq!(declaration(ToolName::Bash).effect, ToolEffect::Read);
    }
}
