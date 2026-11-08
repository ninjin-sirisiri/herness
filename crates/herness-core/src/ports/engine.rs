//! Engine adapter port.
//!
//! Adapters translate their SDK into these host-owned types. SDK structs,
//! checkpoint internals, and raw provider errors never appear here.

use crate::contracts::checkpoint::Checkpoint;
use crate::contracts::connection::ConnectionId;
use crate::contracts::errors::{CoreError, EngineFailureKind};
use crate::contracts::ids::{AgentId, ProjectId, ProjectScope, RunId, SessionId};
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::tools::{ToolArguments, ToolName};

pub use crate::contracts::request::StopReason;

/// Request to start one run in an independent engine session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineStart {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    run_id: RunId,
    connection: ConnectionId,
    cwd: AbsolutePath,
    instructions: String,
}

impl EngineStart {
    /// Creates a validated run-start request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        run_id: RunId,
        connection: ConnectionId,
        cwd: AbsolutePath,
        instructions: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let scope = ProjectScope::new(project_id);
        scope.verify(&agent_id)?;
        scope.verify(&session_id)?;
        scope.verify(&run_id)?;
        Ok(Self {
            project_id,
            agent_id,
            session_id,
            run_id,
            connection,
            cwd,
            instructions: instructions.into(),
        })
    }

    /// Project that owns the run.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent that owns the session.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Engine session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Run identifier.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Connection whose credentials may be resolved per request.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Frozen working directory.
    pub fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }

    /// Initial host-owned instructions for the engine.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }
}

/// Input delivered to an existing run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineInput {
    /// A user or host text message.
    Text(String),
}

/// Result of a stop request. Unconfirmed stops are never reported as stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReport {
    /// The engine acknowledged the stop.
    Stopped,
    /// The run was already inactive.
    NotRunning,
    /// The host could not confirm the stop.
    Unconfirmed,
}

/// Event emitted by an engine adapter for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// The engine entered a new run state.
    StateChanged(RunState),
    /// A streamed text delta for display.
    TextDelta {
        /// Delta text.
        text: String,
    },
    /// A completed assistant text message.
    TextCompleted {
        /// Complete text.
        text: String,
    },
    /// A complete tool request ready for host schema and permission handling.
    ToolCall {
        /// Requested tool.
        tool: ToolName,
        /// Complete final arguments.
        arguments: ToolArguments,
    },
    /// An adapter refused to execute a frozen tool operation because host
    /// policy required a human decision.
    ///
    /// The adapter must not run this operation later. It reports the exact
    /// frozen operation so the host can show it and, after an explicit human
    /// approval, execute it once through the host runtime. The operation is
    /// data only: no credential or model text is included.
    ToolApprovalRequired {
        /// Exact operation that was not executed.
        operation: crate::contracts::operation::FrozenOperation,
    },
    /// A sanitized engine failure.
    Failure {
        /// Failure kind with no raw SDK error text.
        failure: EngineFailureKind,
    },
}

/// Which component executes an allowed tool operation.
///
/// The host composition uses this to avoid two executors for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolExecutionAuthority {
    /// The host runtime executes allowed operations through its own gateway.
    Host,
    /// The engine adapter executes allowed operations internally and reports
    /// only awaiting-approval operations to the host.
    Adapter,
}

/// Port implemented by the pi-rust engine adapter.
pub trait EnginePort {
    /// Authority for allowed tool execution.
    ///
    /// `Host` is the default so an adapter that delegates tools to the runtime
    /// keeps working. An adapter that executes host tools internally must
    /// return `Adapter`; the runtime then treats `ToolCall` frames as
    /// observations and never executes the same operation again.
    fn tool_execution_authority(&self) -> ToolExecutionAuthority {
        ToolExecutionAuthority::Host
    }

    /// Starts an independent engine run.
    fn start(&mut self, start: EngineStart) -> Result<(), CoreError>;

    /// Starts a new run that continues the conversation in `previous`.
    ///
    /// The new run must use `start.run_id()` for every new tool operation,
    /// event, and checkpoint while keeping the previous conversation and system
    /// prompt. Implementations must not re-send previous input, reuse a previous
    /// approval, or fall back to a fresh unrelated session when the conversation
    /// cannot be preserved. A build without this capability returns the
    /// explicit unsupported error.
    fn start_continuation(
        &mut self,
        start: EngineStart,
        previous: Checkpoint,
    ) -> Result<(), CoreError> {
        let _ = (start, previous);
        Err(CoreError::UnsupportedPortFeature {
            feature: crate::contracts::errors::PortFeature::Continuation,
        })
    }

    /// Checks whether `start` can continue `previous` without side effects.
    ///
    /// The host calls this before persisting the new run so a conversation that
    /// cannot be preserved is refused without creating a run or sending input.
    /// The default accepts the preflight because an adapter without checkpoint
    /// semantics has nothing to validate; adapters that own SDK snapshots must
    /// return an explicit `NotContinuable` error instead of guessing.
    fn check_continuation(
        &self,
        start: &EngineStart,
        previous: &Checkpoint,
    ) -> Result<(), CoreError> {
        let _ = (start, previous);
        Ok(())
    }

    /// Sends input to an existing run.
    fn send_input(&mut self, run: &RunId, input: EngineInput) -> Result<(), CoreError>;

    /// Requests a coordinated stop. The caller must handle `Unconfirmed`.
    fn request_stop(&mut self, run: &RunId, reason: StopReason) -> Result<StopReport, CoreError>;

    /// Checks whether `run` can be restored from `checkpoint` without a model
    /// request or a tool execution.
    ///
    /// The host calls this before changing the run to `running`. The default
    /// accepts the preflight; adapters that own SDK snapshots must return
    /// `CoreError::NotResumable` when the snapshot could replay input or a tool.
    fn check_resume(&self, run: &RunId, checkpoint: &Checkpoint) -> Result<(), CoreError> {
        let _ = (run, checkpoint);
        Ok(())
    }

    /// Resumes a run from an adapter-owned checkpoint.
    fn resume(&mut self, run: &RunId, checkpoint: Checkpoint) -> Result<(), CoreError>;

    /// Captures the current adapter-owned checkpoint for a run.
    fn checkpoint(&mut self, run: &RunId) -> Result<Option<Checkpoint>, CoreError>;

    /// Drains queued engine events for a run.
    fn poll_events(&mut self, run: &RunId) -> Result<Vec<EngineEvent>, CoreError>;
}
