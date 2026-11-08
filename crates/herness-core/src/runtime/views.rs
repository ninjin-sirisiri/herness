//! Stable, non-secret runtime views for UI reconnect and later phases.

use serde::{Deserialize, Serialize};

use crate::contracts::connection::{ConnectionId, ConnectionInfo};
use crate::contracts::events::Event;
use crate::contracts::ids::{AgentId, IdKind, InputId, OperationId, ProjectId, RunId, SessionId};
use crate::contracts::operation::{FrozenOperation, OperationOutcome};
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::contracts::time::Timestamp;
use crate::permissions::{DecisionBinding, PermissionMode, PolicyVersion};
use crate::ports::engine::StopReport;
use crate::runtime::error::RuntimeError;
use crate::skills::{HostCapabilities, HostCapability};

/// One opened project and its non-secret capability summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectView {
    project_id: ProjectId,
    path: AbsolutePath,
    connections: Vec<ConnectionInfo>,
    capabilities: HostCapabilities,
    toolchain: crate::skills::ToolchainReport,
}

impl ProjectView {
    /// Creates a project view.
    pub(crate) const fn new(
        project_id: ProjectId,
        path: AbsolutePath,
        connections: Vec<ConnectionInfo>,
        capabilities: HostCapabilities,
        toolchain: crate::skills::ToolchainReport,
    ) -> Self {
        Self {
            project_id,
            path,
            connections,
            capabilities,
            toolchain,
        }
    }

    /// Stable project identifier.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical real path.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// Non-secret connection status summary.
    pub fn connections(&self) -> &[ConnectionInfo] {
        &self.connections
    }

    /// Host capability report. H1 marks `HtmlWorker` and `SddTaskController`
    /// unavailable.
    pub const fn capabilities(&self) -> HostCapabilities {
        self.capabilities
    }

    /// Toolchain detection report, including deficiencies.
    pub const fn toolchain(&self) -> &crate::skills::ToolchainReport {
        &self.toolchain
    }

    /// Returns the structured unavailability reason for one capability.
    pub fn capability_status(&self, capability: HostCapability) -> crate::skills::CapabilityStatus {
        self.capabilities.status(capability)
    }
}

/// One host-created agent conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentView {
    project_id: ProjectId,
    agent_id: AgentId,
    session_id: SessionId,
    name: String,
    role: String,
    connection: ConnectionId,
    parent: Option<AgentId>,
    required_capabilities: Vec<HostCapability>,
    created_at: Timestamp,
}

impl AgentView {
    /// Creates an agent view.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        project_id: ProjectId,
        agent_id: AgentId,
        session_id: SessionId,
        name: String,
        role: String,
        connection: ConnectionId,
        parent: Option<AgentId>,
        required_capabilities: Vec<HostCapability>,
        created_at: Timestamp,
    ) -> Self {
        Self {
            project_id,
            agent_id,
            session_id,
            name,
            role,
            connection,
            parent,
            required_capabilities,
            created_at,
        }
    }

    /// Owning project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Agent identifier.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Independent conversation session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Human-readable agent name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Host-assigned role.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Selected connection.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Parent agent when this agent was host-created as a child.
    pub const fn parent(&self) -> Option<AgentId> {
        self.parent
    }

    /// Capabilities this agent requires.
    pub fn required_capabilities(&self) -> &[HostCapability] {
        &self.required_capabilities
    }

    /// Creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
}

/// One host-started run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunView {
    project_id: ProjectId,
    run_id: RunId,
    agent_id: AgentId,
    session_id: SessionId,
    connection: ConnectionId,
    state: RunState,
    instructions: String,
    mode: PermissionMode,
    policy_version: PolicyVersion,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl RunView {
    /// Creates a run view.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        project_id: ProjectId,
        run_id: RunId,
        agent_id: AgentId,
        session_id: SessionId,
        connection: ConnectionId,
        state: RunState,
        instructions: String,
        mode: PermissionMode,
        policy_version: PolicyVersion,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Self {
        Self {
            project_id,
            run_id,
            agent_id,
            session_id,
            connection,
            state,
            instructions,
            mode,
            policy_version,
            created_at,
            updated_at,
        }
    }

    /// Owning project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Run identifier.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Agent that owns the run.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session that owns the run.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Selected connection.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Current run state. `idle` is quiescence, not task completion.
    pub const fn state(&self) -> RunState {
        self.state
    }

    /// Frozen host instructions for the run.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// Permission mode captured at start.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Policy version captured at start.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Last state change.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

/// One pending approval shown to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    project_id: ProjectId,
    run_id: RunId,
    agent_id: AgentId,
    session_id: SessionId,
    operation: FrozenOperation,
    binding: DecisionBinding,
    reason: String,
    requested_at: Timestamp,
    restored: bool,
    reusable: bool,
}

impl PendingApproval {
    /// Creates a pending approval view.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        project_id: ProjectId,
        run_id: RunId,
        agent_id: AgentId,
        session_id: SessionId,
        operation: FrozenOperation,
        binding: DecisionBinding,
        reason: String,
        requested_at: Timestamp,
        restored: bool,
        reusable: bool,
    ) -> Self {
        Self {
            project_id,
            run_id,
            agent_id,
            session_id,
            operation,
            binding,
            reason,
            requested_at,
            restored,
            reusable,
        }
    }

    /// Owning project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Run waiting for the decision.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Agent that owns the run.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Session that owns the run.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Exact frozen operation the human is being asked about.
    pub const fn operation(&self) -> &FrozenOperation {
        &self.operation
    }

    /// Decision binding captured at evaluation time.
    pub const fn binding(&self) -> &DecisionBinding {
        &self.binding
    }

    /// Non-secret reason label.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// When the request was recorded.
    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    /// Whether this approval was loaded from a previous process.
    pub const fn restored(&self) -> bool {
        self.restored
    }

    /// Whether the approval can be executed without re-evaluation.
    ///
    /// Restored approvals are never reusable.
    pub const fn reusable(&self) -> bool {
        self.reusable
    }
}

/// A project-bound live subscription cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionCursor {
    project_id: ProjectId,
    after_sequence: u64,
}

impl SubscriptionCursor {
    /// Creates a cursor for one project.
    pub const fn new(project_id: ProjectId, after_sequence: u64) -> Self {
        Self {
            project_id,
            after_sequence,
        }
    }

    /// Project whose event stream this cursor addresses.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Last delivered sequence. `0` means "from the beginning".
    pub const fn after_sequence(&self) -> u64 {
        self.after_sequence
    }
}

impl<'de> Deserialize<'de> for SubscriptionCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            after_sequence: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(wire.project_id, wire.after_sequence))
    }
}

impl SubscriptionCursor {
    /// Rejects a cursor minted for another project.
    pub(crate) fn verify(&self, project: ProjectId) -> Result<(), RuntimeError> {
        if self.project_id == project {
            Ok(())
        } else {
            Err(RuntimeError::CrossProject {
                id_kind: IdKind::Project,
                expected: project,
                found: self.project_id,
            })
        }
    }
}

/// One ascending batch of committed events.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventBatch {
    events: Vec<Event>,
    last_sequence: u64,
}

impl EventBatch {
    /// Creates a batch. `last_sequence` is the reconnect cursor.
    pub(crate) const fn new(events: Vec<Event>, last_sequence: u64) -> Self {
        Self {
            events,
            last_sequence,
        }
    }

    /// Committed events in ascending sequence order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Last delivered sequence, or the incoming cursor when no event was new.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

/// Stable UI snapshot used on reconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshot {
    project_id: ProjectId,
    runs: Vec<RunView>,
    pending_approvals: Vec<PendingApproval>,
    last_sequence: u64,
}

impl RuntimeSnapshot {
    /// Creates a snapshot.
    pub(crate) const fn new(
        project_id: ProjectId,
        runs: Vec<RunView>,
        pending_approvals: Vec<PendingApproval>,
        last_sequence: u64,
    ) -> Self {
        Self {
            project_id,
            runs,
            pending_approvals,
            last_sequence,
        }
    }

    /// Project this snapshot belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Current run states.
    pub fn runs(&self) -> &[RunView] {
        &self.runs
    }

    /// Pending approvals, including restored ones that require re-evaluation.
    pub fn pending_approvals(&self) -> &[PendingApproval] {
        &self.pending_approvals
    }

    /// Last committed project sequence.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

/// Result of an explicit stop request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopOutcome {
    run: RunView,
    report: StopReport,
    checkpoint_saved: bool,
}

impl StopOutcome {
    /// Creates a stop outcome.
    pub(crate) const fn new(run: RunView, report: StopReport, checkpoint_saved: bool) -> Self {
        Self {
            run,
            report,
            checkpoint_saved,
        }
    }

    /// Run after the stop request.
    pub const fn run(&self) -> &RunView {
        &self.run
    }

    /// Engine stop report. `Unconfirmed` maps to `interrupted`, never `paused`.
    pub const fn report(&self) -> StopReport {
        self.report
    }

    /// Whether a checkpoint was persisted with the stop.
    pub const fn checkpoint_saved(&self) -> bool {
        self.checkpoint_saved
    }
}

/// Whether a run's engine state belongs to this process or was restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMode {
    /// The run was started or resumed in this process, so the live engine
    /// session may be reused after a confirmed stop.
    SameProcess,
    /// The run was restored from durable state in this process. Its engine
    /// session must be rebuilt from the checkpoint.
    Restored,
}

impl RecoveryMode {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameProcess => "same_process",
            Self::Restored => "restored",
        }
    }
}

/// Result of starting a new run that continues a previous conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuationOutcome {
    run: RunView,
    input_id: InputId,
}

impl ContinuationOutcome {
    /// Creates a continuation outcome.
    pub(crate) const fn new(run: RunView, input_id: InputId) -> Self {
        Self { run, input_id }
    }

    /// New run that carries the conversation.
    pub const fn run(&self) -> &RunView {
        &self.run
    }

    /// Accepted input submitted to the new run.
    pub const fn input_id(&self) -> InputId {
        self.input_id
    }
}

/// Result of an approved operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalOutcome {
    operation_id: OperationId,
    executed: bool,
    outcome: OperationOutcome,
    run: RunView,
}

impl ApprovalOutcome {
    /// Creates an approval outcome.
    pub(crate) const fn new(
        operation_id: OperationId,
        executed: bool,
        outcome: OperationOutcome,
        run: RunView,
    ) -> Self {
        Self {
            operation_id,
            executed,
            outcome,
            run,
        }
    }

    /// Operation that was approved.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Whether the executor was reached. `false` means a re-check failed first.
    pub const fn executed(&self) -> bool {
        self.executed
    }

    /// Recorded operation outcome.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    /// Run after the decision.
    pub const fn run(&self) -> &RunView {
        &self.run
    }
}

/// Result of an explicit denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialOutcome {
    operation_id: OperationId,
    run: RunView,
}

impl DenialOutcome {
    /// Creates a denial outcome.
    pub(crate) const fn new(operation_id: OperationId, run: RunView) -> Self {
        Self { operation_id, run }
    }

    /// Operation that was denied.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Run after the decision.
    pub const fn run(&self) -> &RunView {
        &self.run
    }
}
