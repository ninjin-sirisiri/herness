//! The deterministic serial Task coordinator.
//!
//! # What it decides
//!
//! [`TaskCoordinator::advance`] performs one decision per call, over the ports
//! only:
//!
//! 1. it loads the execution's stored snapshot and checks the expected
//!    revision;
//! 2. it selects **the first** Task whose progression is not `complete`, in plan
//!    order, and refuses when `snapshot.current_task` names a different Task.
//!    No other Task is ever selected, so two Tasks never run at once;
//! 3. before any side effect it verifies the current approval (revision, plan
//!    digest and revision, checkout, branch, baseline, and every Task identity)
//!    and the fixed BASE;
//! 4. a never-dispatched Task is dispatched with the intent persisted first: the
//!    deterministic dispatch request ID, BASE, manifest and packet digests, and
//!    the plan revision go into the dispatch journal and the manifest row before
//!    the one child exists. Then the one child is created (or reconciled from
//!    the stored reservation) and the snapshot records `running`, the H2
//!    reference, and the child in one transaction;
//! 5. an already-dispatched Task is never dispatched again. Its stored H2 result
//!    is re-read on every call; a delivered notification is never a progress
//!    condition, so a duplicate completion notification advances nothing;
//! 6. when H2 reports the Task's conditions met, the combined Task budget is
//!    re-read and admitted **before** any host processing ("met after the limit"
//!    is refused, not completed), then the host completion seam is asked. A seam
//!    that is not connected yields an explicit
//!    [`CoordinatorOutcome::CompletionNotConnected`] with a durable
//!    `waiting_human` snapshot, and the next Task does not start.
//!
//! # What it never does
//!
//! It does not create a second child for one Task, does not start a second Task
//! while one is active, does not consume the H3 barrier or run a host commit
//! itself, and never turns an `completed` H2 record, an unknown H2 state, or a
//! stale completion into an H4 Task completion.

use std::collections::BTreeMap;

use herness_core::contracts::ProjectId;
use herness_supervision::{BudgetPolicy, ExecutionScope, SupervisionId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::budget::{TaskBudget, TaskBudgetExhaustion};
use crate::contract::{
    ContinuationLimits, ExecutionOperation, ExecutionOperationRequest, ExecutionOperationResult,
};
use crate::durable::{DispatchManifest, DurableExecutionStorePort, TaskReservation};
use crate::error::SddExecutionError;
use crate::ids::{
    ChildIdentity, ControlRequestId, DispatchRequestId, ExecutionId, ExecutionRevision,
    H2SupervisionRef, TaskRef,
};
use crate::journal::{
    DispatchContent, DispatchJournalEntry, DispatchRequest, DispatchResult, RequestIdentity,
};
use crate::ports::{ChildDispatchPlan, ChildDispatchPort, ExecutionStorePort};
use crate::snapshot::{
    BudgetConsumption, CommitRange, ExecutionSnapshot, NoChangeRecord, SnapshotBudget,
    SnapshotInput, TaskSnapshot,
};
use crate::state::{
    AppliedRevision, ConflictReason, ExecutionState, HumanAction, RecoveryReason, StopReason,
    StopRecord, TaskPhase, TaskProgression,
};
use crate::version::Sha256Digest;

// ---------------------------------------------------------------------------
// Stored H2 status
// ---------------------------------------------------------------------------

/// The stored H2 state of one Task's child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// Approved and not yet running.
    Ready,
    /// A child run is active.
    Running,
    /// Required checks are running.
    Verifying,
    /// Condition assessments are in flight.
    Assessing,
    /// A human action is required.
    WaitingHuman,
    /// Stopped by a human, stagnation, budget, or recovery.
    Stopped,
    /// Unrecoverable failure.
    Failed,
    /// Cancelled.
    Cancelled,
    /// Every approved condition was met for a fixed snapshot.
    Completed,
    /// A state this build cannot interpret. It is never completion.
    Unknown,
}

impl ChildState {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Verifying => "verifying",
            Self::Assessing => "assessing",
            Self::WaitingHuman => "waiting_human",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the child is still progressing.
    pub const fn is_working(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Running | Self::Verifying | Self::Assessing
        )
    }

    /// The H4 Task phase this H2 state shows for an active Task.
    pub const fn task_phase(self) -> TaskPhase {
        match self {
            Self::Ready | Self::Running | Self::Unknown => TaskPhase::Running,
            Self::Verifying | Self::Assessing | Self::Completed => TaskPhase::Verifying,
            Self::WaitingHuman => TaskPhase::WaitingHuman,
            Self::Stopped => TaskPhase::Stopped,
            Self::Failed => TaskPhase::Failed,
            Self::Cancelled => TaskPhase::Cancelled,
        }
    }
}

/// Why H2 recorded an explicit stop.
///
/// It is H2's own `StopCause` mapped onto H4's stop vocabulary, so an H4 stop
/// keeps the exact cause and never invents one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStopCause {
    /// A human requested the stop.
    UserRequest,
    /// Three consecutive evaluation cycles made no progress.
    Stagnation,
    /// A finite H2 budget limit was reached.
    Budget,
    /// A managed process or engine stop was not confirmed.
    StopUnconfirmed,
    /// Recovery requires reconciliation before any new run.
    RecoveryReconciliation,
    /// A cause this build cannot interpret. It is never completion.
    Unknown,
}

impl ChildStopCause {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserRequest => "user_request",
            Self::Stagnation => "stagnation",
            Self::Budget => "budget",
            Self::StopUnconfirmed => "stop_unconfirmed",
            Self::RecoveryReconciliation => "recovery_reconciliation",
            Self::Unknown => "unknown",
        }
    }

    /// Maps H2's own stop cause.
    pub fn of(cause: &herness_supervision::StopCause) -> Self {
        match cause {
            herness_supervision::StopCause::UserRequest => Self::UserRequest,
            herness_supervision::StopCause::Stagnation => Self::Stagnation,
            herness_supervision::StopCause::Budget(_) => Self::Budget,
            herness_supervision::StopCause::StopUnconfirmed => Self::StopUnconfirmed,
            herness_supervision::StopCause::RecoveryReconciliation => Self::RecoveryReconciliation,
        }
    }
}

/// The stored H2 result of one Task's child, re-read from H2's own records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildStatus {
    supervision_id: SupervisionId,
    state: ChildState,
    active_seconds: u64,
    additional_runs: u32,
    consecutive_stalls: u32,
    completion_stale: bool,
    stop_cause: Option<ChildStopCause>,
    evidence: Vec<herness_supervision::EvidenceId>,
}

impl ChildStatus {
    /// Records one stored H2 status.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        supervision_id: SupervisionId,
        state: ChildState,
        active_seconds: u64,
        additional_runs: u32,
        consecutive_stalls: u32,
        completion_stale: bool,
        evidence: Vec<herness_supervision::EvidenceId>,
    ) -> Self {
        Self {
            supervision_id,
            state,
            active_seconds,
            additional_runs,
            consecutive_stalls,
            completion_stale,
            stop_cause: None,
            evidence,
        }
    }

    /// Records H2's own stop cause.
    #[must_use]
    pub const fn with_stop_cause(mut self, cause: ChildStopCause) -> Self {
        self.stop_cause = Some(cause);
        self
    }

    /// H2's explicit stop cause, when H2 recorded one.
    pub const fn stop_cause(&self) -> Option<ChildStopCause> {
        self.stop_cause
    }

    /// The H2 target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// The stored H2 state.
    pub const fn state(&self) -> ChildState {
        self.state
    }

    /// H2's cumulative active seconds for this target.
    pub const fn active_seconds(&self) -> u64 {
        self.active_seconds
    }

    /// H2's additional runs for this target.
    pub const fn additional_runs(&self) -> u32 {
        self.additional_runs
    }

    /// H2's consecutive stall count.
    ///
    /// H2 owns the counter and stops at its own three cycles. An adapter that
    /// cannot read the counter reports zero and relies on H2's `stagnation` stop
    /// cause, which [`stopped_reason`] maps to the same H4 stall stop.
    pub const fn consecutive_stalls(&self) -> u32 {
        self.consecutive_stalls
    }

    /// Whether H2 recorded the completion as stale for the current content.
    pub const fn completion_stale(&self) -> bool {
        self.completion_stale
    }

    /// Evidence the stored record cites.
    pub fn evidence(&self) -> &[herness_supervision::EvidenceId] {
        &self.evidence
    }
}

/// Re-reads the stored H2 result of one dispatch request.
///
/// The coordinator calls this on every advance and never accepts a notification
/// payload as progress: a duplicate notification re-reads the same stored result
/// and advances nothing.
pub trait ChildStatusPort {
    /// Returns the stored status of the target created for `request_id`.
    ///
    /// `None` means H2 records no target for that request. It is never
    /// completion.
    fn status(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError>;
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// The immutable launch of one approved Task.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskLaunch {
    instructions: String,
    scope: ExecutionScope,
    budget: BudgetPolicy,
    manifest_digest: Sha256Digest,
    packet_digest: Sha256Digest,
}

impl TaskLaunch {
    /// Records one launch.
    pub fn new(
        instructions: impl Into<String>,
        scope: ExecutionScope,
        budget: BudgetPolicy,
        manifest_digest: Sha256Digest,
        packet_digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        let instructions = instructions.into();
        if instructions.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "taskLaunch.instructions".to_owned(),
                detail: "the immutable Task packet must not be empty".to_owned(),
            });
        }
        budget
            .validate()
            .map_err(|error| SddExecutionError::InvalidValue {
                field: "taskLaunch.budget".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(Self {
            instructions,
            scope,
            budget,
            manifest_digest,
            packet_digest,
        })
    }

    /// The exact immutable packet text.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// The approved execution scope.
    pub const fn scope(&self) -> &ExecutionScope {
        &self.scope
    }

    /// The approved finite H2 budget.
    pub const fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// Dispatch manifest digest.
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    /// Immutable Task packet digest.
    pub const fn packet_digest(&self) -> &Sha256Digest {
        &self.packet_digest
    }
}

/// Why one Task has no launch yet.
///
/// A refusal is an explicit human wait or an unavailable capability; it is never
/// a truncated packet and never a fabricated dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchRefusal {
    /// The approval has no Task with this number.
    UnknownTask {
        /// Plan-assigned Task number.
        number: u32,
    },
    /// The approved context cannot be rebuilt as approved.
    Context {
        /// Non-secret explanation.
        detail: String,
    },
    /// The context does not fit the packet bounds. A human must narrow the
    /// approved scope; nothing is truncated.
    Capacity {
        /// Non-secret explanation naming what does not fit.
        detail: String,
    },
    /// A required host capability is not connected.
    Unavailable {
        /// Missing feature label.
        feature: String,
    },
}

impl LaunchRefusal {
    /// The stop reason the coordinator records.
    pub fn stop_reason(&self) -> StopReason {
        match self {
            Self::UnknownTask { .. } => StopReason::Conflict,
            Self::Unavailable { .. } => StopReason::CapabilityUnavailable,
            Self::Context { .. } | Self::Capacity { .. } => StopReason::HumanDecisionRequired,
        }
    }

    /// The human action the coordinator requires.
    pub fn human_action(&self) -> HumanAction {
        match self {
            Self::UnknownTask { .. } => HumanAction::ResolveConflict,
            Self::Unavailable { .. } => HumanAction::ProvideCapability,
            Self::Context { .. } | Self::Capacity { .. } => HumanAction::ResolveHumanDecision,
        }
    }
}

/// Builds one Task's immutable launch from the approved plan revision.
///
/// The desktop packet adapter is the production implementation. It starts no
/// child and performs no Git operation.
pub trait TaskLaunchPort {
    /// Builds one Task's launch or refuses with an explicit human wait.
    fn launch(&mut self, task: TaskRef) -> Result<TaskLaunch, LaunchRefusal>;
}

// ---------------------------------------------------------------------------
// Host completion seam
// ---------------------------------------------------------------------------

/// Which host completion capability is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionFeature {
    /// The H3 `H4Barrier` consumption of Task 16.
    HtmlBarrier,
    /// The host stage/hook/commit of Task 17.
    HostCommit,
}

impl CompletionFeature {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HtmlBarrier => "html_barrier",
            Self::HostCommit => "host_commit",
        }
    }
}

/// Whether the host completion path is wired for a Task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionWiring {
    /// The barrier and the host commit are connected.
    Connected,
    /// One required capability is not connected. Nothing is inferred.
    NotConnected {
        /// The missing capability.
        feature: CompletionFeature,
    },
    /// The HTML barrier is connected and runs first; the host commit is still
    /// missing, so a synced barrier is followed by an explicit refusal and never
    /// a fabricated completion. Task 17 replaces this with [`Self::Connected`].
    BarrierConnected {
        /// The still-missing capability.
        missing: CompletionFeature,
    },
}

impl CompletionWiring {
    /// The barrier is connected; only `missing` remains.
    pub const fn barrier_connected(missing: CompletionFeature) -> Self {
        Self::BarrierConnected { missing }
    }

    /// Whether the connected completion path may run.
    ///
    /// A fully connected seam and a barrier-connected seam both run; the
    /// barrier-connected seam refuses inside the host completion after its
    /// barrier, which the coordinator records as a durable human wait.
    pub const fn may_run(self) -> bool {
        !matches!(self, Self::NotConnected { .. })
    }
}

/// One Task's connected host completion request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCompletionRequest {
    task: TaskRef,
    execution_id: ExecutionId,
    expected_revision: ExecutionRevision,
    supervision_id: SupervisionId,
    commit_authorization: crate::approval::CommitAuthorization,
    commit_policy: crate::approval::CommitPolicy,
    evidence: Vec<herness_supervision::EvidenceId>,
    remaining_seconds: u64,
}

impl TaskCompletionRequest {
    /// Records one completion request.
    ///
    /// The execution identity, the stored revision, and the approved commit
    /// authorization travel with the request, so the host commit is authorized
    /// only by the approval the human already gave — never by a value the
    /// completion seam could invent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        execution_id: ExecutionId,
        expected_revision: ExecutionRevision,
        supervision_id: SupervisionId,
        commit_authorization: crate::approval::CommitAuthorization,
        commit_policy: crate::approval::CommitPolicy,
        evidence: Vec<herness_supervision::EvidenceId>,
        remaining_seconds: u64,
    ) -> Self {
        Self {
            task,
            execution_id,
            expected_revision,
            supervision_id,
            commit_authorization,
            commit_policy,
            evidence,
            remaining_seconds,
        }
    }

    /// The Task to complete.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Execution that owns the Task.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Execution revision the completion writes against.
    pub const fn expected_revision(&self) -> ExecutionRevision {
        self.expected_revision
    }

    /// The H2 target that met the conditions.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// The approved host commit and hook authorization.
    pub const fn commit_authorization(&self) -> crate::approval::CommitAuthorization {
        self.commit_authorization
    }

    /// The approved commit policy.
    pub const fn commit_policy(&self) -> crate::approval::CommitPolicy {
        self.commit_policy
    }

    /// Evidence the stored H2 record cites.
    pub fn evidence(&self) -> &[herness_supervision::EvidenceId] {
        &self.evidence
    }

    /// Remaining combined Task seconds. The host commit budget is the shorter of
    /// 30 s and this value.
    pub const fn remaining_seconds(&self) -> u64 {
        self.remaining_seconds
    }
}

/// The result of one connected host completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCompletion {
    /// The Task is complete with its commit range or no-change record.
    Complete {
        /// Range when HEAD advanced.
        commit_range: Option<CommitRange>,
        /// Record when the Task changed no approved source content.
        no_change: Option<NoChangeRecord>,
        /// Measured host processing seconds past H2's accounting.
        ///
        /// The coordinator charges these to the same Task, so the combined total
        /// is H2's supervision consumption plus this value.
        host_seconds: u64,
    },
    /// The host completion stopped and needs a human.
    HumanWait {
        /// Stop reason and required action.
        stop: StopRecord,
    },
}

/// Runs the host's own completion of one Task after H2 met its conditions.
///
/// Task 16 and Task 17 supply the connected implementation. This build's
/// production composition is [`NotConnectedCompletion`], whose wiring is always
/// [`CompletionWiring::NotConnected`], so no Task advances past H2 completion.
pub trait TaskCompletionPort {
    /// Whether the barrier and host commit are wired for this Task.
    fn wiring(&self, task: TaskRef) -> CompletionWiring;

    /// Runs the connected completion path.
    fn complete(
        &mut self,
        request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError>;
}

/// Builds the completion wiring from the two host halves.
///
/// A missing barrier is [`CompletionWiring::NotConnected`]. A connected barrier
/// with a missing commit is [`CompletionWiring::BarrierConnected`], which runs
/// the HTML barrier and then refuses explicitly rather than completing.
pub const fn completion_wiring(
    barrier_connected: bool,
    commit_connected: bool,
    missing: CompletionFeature,
) -> CompletionWiring {
    if !barrier_connected {
        return CompletionWiring::NotConnected {
            feature: CompletionFeature::HtmlBarrier,
        };
    }
    if !commit_connected {
        return CompletionWiring::BarrierConnected { missing };
    }
    CompletionWiring::Connected
}

/// The explicit "not connected" completion seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotConnectedCompletion {
    feature: CompletionFeature,
}

impl NotConnectedCompletion {
    /// The production default: the barrier is not connected yet.
    pub const fn new() -> Self {
        Self {
            feature: CompletionFeature::HtmlBarrier,
        }
    }

    /// Reports one specific missing capability.
    pub const fn missing(feature: CompletionFeature) -> Self {
        Self { feature }
    }

    /// The capability this seam reports missing.
    pub const fn feature(self) -> CompletionFeature {
        self.feature
    }
}

impl Default for NotConnectedCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskCompletionPort for NotConnectedCompletion {
    fn wiring(&self, _task: TaskRef) -> CompletionWiring {
        CompletionWiring::NotConnected {
            feature: self.feature,
        }
    }

    fn complete(
        &mut self,
        _request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        Err(crate::ports::unsupported(
            crate::ports::ExecutionFeature::HtmlBarrier,
        ))
    }
}

/// One notification delivered by H2 or a UI.
///
/// The coordinator deliberately does not read its payload: every call re-reads
/// the stored H2 result, so a duplicate completion notification cannot advance
/// a Task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildNotification {
    dispatch: DispatchRequestId,
}

impl ChildNotification {
    /// Records one delivered notification.
    pub const fn new(dispatch: DispatchRequestId) -> Self {
        Self { dispatch }
    }

    /// The dispatch request it names.
    pub const fn dispatch(self) -> DispatchRequestId {
        self.dispatch
    }
}

// ---------------------------------------------------------------------------
// App-wide serial state
// ---------------------------------------------------------------------------

/// The single app-wide implementer slot and the one checkout claim per
/// checkout/branch pair.
#[derive(Debug, Default)]
pub struct SerialExecutionState {
    slot: Option<ExecutionId>,
    claims: BTreeMap<(String, String), ExecutionId>,
}

impl SerialExecutionState {
    /// Creates an idle serial state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The execution currently holding the app-wide implementer slot.
    pub const fn holder(&self) -> Option<ExecutionId> {
        self.slot
    }

    /// Whether `execution` owns the checkout and branch of `claim`.
    pub fn owns(&self, claim: &crate::contract::CheckoutClaim) -> bool {
        self.claims
            .get(&(
                claim.canonical_checkout_root().to_owned(),
                claim.branch().to_owned(),
            ))
            .is_some_and(|holder| *holder == claim.execution_id())
    }

    /// Acquires the one implementer slot for `execution`.
    pub fn acquire_slot(&mut self, execution: ExecutionId) -> Result<(), SddExecutionError> {
        match self.slot {
            Some(holder) if holder != execution => Err(ownership_conflict()),
            _ => {
                self.slot = Some(execution);
                Ok(())
            }
        }
    }

    /// Releases the slot when `execution` holds it.
    pub fn release_slot(&mut self, execution: ExecutionId) {
        if self.slot == Some(execution) {
            self.slot = None;
        }
    }

    /// Claims the checkout and branch for `execution`.
    pub fn claim_checkout(
        &mut self,
        claim: &crate::contract::CheckoutClaim,
    ) -> Result<(), SddExecutionError> {
        let key = (
            claim.canonical_checkout_root().to_owned(),
            claim.branch().to_owned(),
        );
        match self.claims.get(&key) {
            Some(holder) if *holder != claim.execution_id() => Err(ownership_conflict()),
            _ => {
                self.claims.insert(key, claim.execution_id());
                Ok(())
            }
        }
    }

    /// Releases every checkout claim of `execution`.
    pub fn release_checkout(&mut self, execution: ExecutionId) {
        self.claims.retain(|_, holder| *holder != execution);
    }
}

// ---------------------------------------------------------------------------
// Ports and request
// ---------------------------------------------------------------------------

/// The ports one advance uses.
pub struct CoordinatorPorts<'a> {
    /// Snapshots, journals, and the transactional operation commit.
    pub store: &'a mut dyn CoordinatorStorePort,
    /// The immutable launch of each Task.
    pub launch: &'a mut dyn TaskLaunchPort,
    /// Creates or reconciles the one child.
    pub dispatch: &'a mut dyn ChildDispatchPort,
    /// Re-reads the stored H2 result.
    pub children: &'a mut dyn ChildStatusPort,
    /// The host barrier and commit seam.
    pub completion: &'a mut dyn TaskCompletionPort,
    /// The app-wide slot and checkout claims.
    pub serial: &'a mut SerialExecutionState,
}

/// One durable store that supports both the execution port and the supporting
/// H4 records.
pub trait CoordinatorStorePort: ExecutionStorePort + DurableExecutionStorePort {}

impl<T: ExecutionStorePort + DurableExecutionStorePort> CoordinatorStorePort for T {}

/// One advance request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorRequest {
    identity: RequestIdentity<crate::ids::ControlKind>,
    approval_id: crate::ids::ApprovalId,
    expected_approval_revision: u64,
}

impl CoordinatorRequest {
    /// Creates one advance request guard.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        expected_revision: ExecutionRevision,
        approval_id: crate::ids::ApprovalId,
        expected_approval_revision: u64,
    ) -> Result<Self, SddExecutionError> {
        if expected_approval_revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "coordinator.approvalRevision".to_owned(),
                detail: "approval revisions start at one".to_owned(),
            });
        }
        Ok(Self {
            identity: RequestIdentity::new(
                project_id,
                execution_id,
                request_id,
                expected_revision,
            )?,
            approval_id,
            expected_approval_revision,
        })
    }

    /// The project, execution, request, and revision guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::ControlKind> {
        &self.identity
    }

    /// The approval identity the advance uses.
    pub const fn approval_id(&self) -> crate::ids::ApprovalId {
        self.approval_id
    }

    /// The approval revision the advance expects.
    pub const fn expected_approval_revision(&self) -> u64 {
        self.expected_approval_revision
    }
}

/// What one advance decided.
#[derive(Debug, Clone, PartialEq)]
pub enum CoordinatorOutcome {
    /// The request was already applied; its stored result is returned and no
    /// side effect runs again.
    Replayed {
        /// Stored resulting revision.
        revision: ExecutionRevision,
    },
    /// Another execution holds the app-wide implementer slot.
    Busy {
        /// Execution currently holding the slot.
        holder: ExecutionId,
    },
    /// One Task's intent and H2 binding were persisted and its one child was
    /// dispatched, or reconciled from the persisted reservation.
    Dispatched {
        /// Dispatched Task.
        task: TaskRef,
        /// Deterministic dispatch request.
        request_id: DispatchRequestId,
        /// The one H2 target.
        supervision_id: SupervisionId,
        /// The one H1 child.
        child: ChildIdentity,
        /// Revision after the advance.
        revision: ExecutionRevision,
    },
    /// The Task's child is still working; nothing changed.
    AwaitingChild {
        /// Current Task.
        task: TaskRef,
        /// Stored H2 state.
        state: ChildState,
    },
    /// The Task completed through the connected host path.
    TaskCompleted {
        /// Completed Task.
        task: TaskRef,
        /// Revision after the durable completion.
        revision: ExecutionRevision,
    },
    /// The Task stopped or needs a human, so no further Task starts.
    Stopped {
        /// Task that stopped, when one is current.
        task: Option<TaskRef>,
        /// Recorded stop.
        stop: StopRecord,
        /// Revision after the durable stop.
        revision: ExecutionRevision,
    },
    /// The Task's conditions were met, but the host completion path is not
    /// connected. The next Task does not start.
    CompletionNotConnected {
        /// Task awaiting the missing capability.
        task: TaskRef,
        /// The missing capability.
        feature: CompletionFeature,
        /// Revision after the durable wait.
        revision: ExecutionRevision,
    },
    /// The Task's budget was exhausted, including "met after the limit". It is
    /// not completion.
    BudgetRefused {
        /// Task whose budget is exhausted.
        task: TaskRef,
        /// The exhausted limit.
        exhaustion: TaskBudgetExhaustion,
        /// Revision after the durable stop.
        revision: ExecutionRevision,
    },
    /// Every Task is complete and the finish handoff is pending.
    ReadyForFinish {
        /// Revision of the finished snapshot.
        revision: ExecutionRevision,
    },
    /// The execution is already terminal.
    Finished {
        /// Terminal state.
        state: ExecutionState,
    },
}

/// The deterministic serial coordinator.
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskCoordinator;

impl TaskCoordinator {
    /// Creates the coordinator.
    pub const fn new() -> Self {
        Self
    }

    /// Advances one step.
    pub fn advance(
        ports: &mut CoordinatorPorts<'_>,
        request: &CoordinatorRequest,
    ) -> Result<CoordinatorOutcome, SddExecutionError> {
        let identity = *request.identity();
        let project_id = identity.project_id();
        let execution_id = identity.execution_id();

        // A re-delivered advance returns its stored result before anything else.
        if let Some(record) =
            ports
                .store
                .operation_record(project_id, execution_id, identity.request_id())?
            && let Some(result) = record.outcome()
        {
            return Ok(CoordinatorOutcome::Replayed {
                revision: result.resulting_revision(),
            });
        }

        let stored = ports.store.load(project_id, execution_id)?.ok_or_else(|| {
            SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StateUnreadable,
                details: crate::error::FailureDetails::none().boxed(),
            }
        })?;
        let snapshot = stored.snapshot().clone();
        if stored.revision() != identity.expected_revision() {
            return Err(SddExecutionError::RevisionConflict {
                expected: identity.expected_revision(),
                found: stored.revision(),
            });
        }
        if snapshot.state().is_terminal() {
            return Ok(CoordinatorOutcome::Finished {
                state: snapshot.state(),
            });
        }
        if matches!(
            snapshot.state(),
            ExecutionState::WaitingHuman | ExecutionState::Stopped
        ) {
            let stop = snapshot
                .stop()
                .ok_or_else(|| SddExecutionError::InvalidSnapshot {
                    field: "snapshot.stop".to_owned(),
                    detail: "a waiting or stopped execution must record its stop".to_owned(),
                })?;
            return Ok(CoordinatorOutcome::Stopped {
                task: snapshot.current_task(),
                stop,
                revision: stored.revision(),
            });
        }

        // Exactly one Task: the first not complete in plan order.
        let selected = select_task(&snapshot)?;

        // Ownership and current-input checks run before any side effect.
        if let Some(holder) = ports.serial.holder()
            && holder != execution_id
        {
            return Ok(CoordinatorOutcome::Busy { holder });
        }
        let approval = current_approval(ports.store, request)?;
        verify_workspace(&snapshot)?;
        // The approval must still describe this exact plan digest and revision,
        // checkout, branch, baseline, and Task list.
        snapshot.ensure_approval_applies(&approval)?;

        match selected {
            None => finish(ports, &snapshot, request),
            Some(task) => match task.progression() {
                TaskProgression::Pending => dispatch_task(ports, &snapshot, request, task),
                TaskProgression::Active => observe_task(ports, &snapshot, request, &approval, task),
                TaskProgression::Complete => unreachable!("a complete Task is never selected"),
            },
        }
    }

    /// Handles one delivered notification.
    ///
    /// The payload is deliberately ignored: the stored H2 result is re-read, so
    /// a duplicate completion notification advances nothing and never creates a
    /// second child.
    pub fn on_notification(
        ports: &mut CoordinatorPorts<'_>,
        request: &CoordinatorRequest,
        _notification: ChildNotification,
    ) -> Result<CoordinatorOutcome, SddExecutionError> {
        Self::advance(ports, request)
    }
}

// ---------------------------------------------------------------------------
// Selection and verification
// ---------------------------------------------------------------------------

fn select_task(snapshot: &ExecutionSnapshot) -> Result<Option<&TaskSnapshot>, SddExecutionError> {
    let first = snapshot
        .tasks()
        .iter()
        .find(|task| !task.progression().is_complete());
    if let Some(task) = first
        && let Some(current) = snapshot.current_task()
        && current != task.task()
    {
        return Err(SddExecutionError::Conflict {
            reason: ConflictReason::TaskNotReady,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    Ok(first)
}

fn current_approval(
    store: &mut dyn CoordinatorStorePort,
    request: &CoordinatorRequest,
) -> Result<crate::approval::ExecutionApproval, SddExecutionError> {
    let approval = store
        .latest_approval(request.identity().project_id(), request.approval_id())?
        .ok_or_else(|| SddExecutionError::ApprovalRequired {
            reason: crate::state::ApprovalRequirement::StartApproval,
            details: crate::error::FailureDetails::none().boxed(),
        })?;
    if approval.revision() != request.expected_approval_revision() {
        return Err(SddExecutionError::Conflict {
            reason: ConflictReason::StaleRevision,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    Ok(approval)
}

fn verify_workspace(snapshot: &ExecutionSnapshot) -> Result<(), SddExecutionError> {
    // The fixed BASE is what a dispatch binds. It is written once by the start
    // guard; a snapshot without it cannot dispatch.
    if snapshot.workspace().baseline().is_none() {
        return Err(SddExecutionError::RecoveryRequired {
            reason: RecoveryReason::StateUnreadable,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Finish
// ---------------------------------------------------------------------------

fn finish(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    if snapshot.state() == ExecutionState::ReadyForFinish {
        return Ok(CoordinatorOutcome::ReadyForFinish {
            revision: snapshot.revision(),
        });
    }
    let mut draft = SnapshotDraft::from(snapshot, snapshot.revision().next());
    draft.state = ExecutionState::ReadyForFinish;
    draft.current_task = None;
    let next = draft.build()?;
    let revision = write_final(
        ports,
        request,
        snapshot.revision(),
        ExecutionOperation::Resume,
        &next,
    )?;
    ports.serial.release_slot(request.identity().execution_id());
    ports
        .serial
        .release_checkout(request.identity().execution_id());
    Ok(CoordinatorOutcome::ReadyForFinish { revision })
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch_task(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    task: &TaskSnapshot,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let identity = *request.identity();
    let project = identity.project_id();
    let execution = identity.execution_id();
    let target = task.task();

    // App-wide one implementer, one checkout owner. The slot is acquired before
    // any durable intent so a refused claim writes nothing.
    ports.serial.acquire_slot(execution)?;
    let claim = crate::contract::CheckoutClaim::new(
        snapshot.workspace().canonical_checkout_root(),
        snapshot.workspace().branch(),
        execution,
    )?;
    if let Err(error) = ports.serial.claim_checkout(&claim) {
        ports.serial.release_slot(execution);
        return Err(error);
    }

    // The budget is admitted before any launch side effect.
    let budget = task_budget(snapshot, task);
    if let Err(exhaustion) = budget.admit_run() {
        return stop_for_budget(ports, snapshot, request, task, exhaustion);
    }

    // Build the immutable launch. A refusal is an explicit human wait; nothing
    // is truncated.
    let launch = match ports.launch.launch(target) {
        Ok(launch) => launch,
        Err(refusal) => return refuse_launch(ports, snapshot, request, task, refusal),
    };
    let baseline = snapshot.workspace().baseline().cloned().ok_or_else(|| {
        SddExecutionError::RecoveryRequired {
            reason: RecoveryReason::StateUnreadable,
            details: crate::error::FailureDetails::none().boxed(),
        }
    })?;

    let request_id = dispatch_request_id(execution, target);
    let content = DispatchContent::new(
        target,
        snapshot.plan().approved_revision(),
        baseline.clone(),
        launch.manifest_digest().clone(),
        launch.packet_digest().clone(),
    )?;

    // 1. Intent first. The dispatch request ID, BASE, manifest and packet
    //    digests, and the approved plan revision are durable before any child
    //    exists. A recorded intent or result is reused, never replaced.
    let stored_entry = ports.store.dispatch_entry(project, execution, request_id)?;
    let journal = match stored_entry {
        Some(entry) => entry,
        None => {
            let dispatch_identity =
                RequestIdentity::new(project, execution, request_id, identity.expected_revision())?;
            let dispatch_request = DispatchRequest::new(dispatch_identity, content.clone())?;
            let intent = DispatchJournalEntry::intent(
                *dispatch_request.identity(),
                dispatch_request.content(),
            )?;
            ports.store.record_dispatch(&intent)?;
            intent
        }
    };
    // The immutable manifest is recorded exactly once.
    if ports
        .store
        .manifest(project, execution, request_id)?
        .is_none()
    {
        ports.store.record_manifest(&DispatchManifest::new(
            execution,
            request_id,
            target,
            snapshot.plan().approved_revision(),
            baseline,
            launch.manifest_digest().clone(),
            launch.packet_digest().clone(),
        )?)?;
    }

    // 2. The one child, once per request. A stored result is reused; a bare
    //    intent is reconciled without creating anything.
    let dispatched = match journal.outcome() {
        Some(dispatched) => *dispatched,
        None => {
            let dispatch_identity = *journal.identity();
            let dispatch_request = DispatchRequest::new(dispatch_identity, content.clone())?;
            let plan = ChildDispatchPlan::new(
                dispatch_request,
                launch.scope().clone(),
                launch.budget().clone(),
            );
            let dispatched = match ports.dispatch.dispatch(&plan) {
                Ok(dispatched) => dispatched,
                Err(error) => {
                    // A dispatch failure stops the Task before any fabricated
                    // completion. It is an unavailable capability, never a silent
                    // success.
                    return refuse_launch(
                        ports,
                        snapshot,
                        request,
                        task,
                        LaunchRefusal::Unavailable {
                            feature: format!("h4.childDispatch: {error}"),
                        },
                    );
                }
            };
            ensure_single_dispatch(dispatched, project)?;
            ports
                .store
                .record_dispatch(&journal.clone().recorded(dispatched))?;
            dispatched
        }
    };
    ports.store.reserve_task(&TaskReservation::new(
        execution,
        target,
        request_id,
        dispatched.supervision_id(),
        dispatched.child(),
    )?)?;

    // 3. Then the durable state that names the one target and child.
    let mut draft = SnapshotDraft::from(snapshot, snapshot.revision().next());
    if draft.state == ExecutionState::Ready {
        draft.state = ExecutionState::Running;
    }
    draft.current_task = Some(target);
    draft.budget = SnapshotBudget::new(
        budget.consumption().snapshot_consumption(),
        BudgetConsumption::zero(),
    );
    draft.tasks = replace_task(
        snapshot,
        target,
        TaskEdit {
            phase: TaskPhase::Running,
            h2: Some(H2SupervisionRef::new(dispatched.supervision_id())),
            child: Some(dispatched.child()),
            commit_range: None,
            no_change: None,
            evidence: Vec::new(),
            stop: None,
        },
    )?;
    let next = draft.build()?;
    let revision = write_final(
        ports,
        request,
        snapshot.revision(),
        ExecutionOperation::ApproveAndStart,
        &next,
    )?;
    // The slot and the checkout claim stay held while this Task is active, so no
    // second Task can start before it completes or stops.
    Ok(CoordinatorOutcome::Dispatched {
        task: target,
        request_id,
        supervision_id: dispatched.supervision_id(),
        child: dispatched.child(),
        revision,
    })
}

fn ensure_single_dispatch(
    dispatched: DispatchResult,
    project: ProjectId,
) -> Result<(), SddExecutionError> {
    if dispatched.supervision_id().project_id() != project {
        return Err(SddExecutionError::CrossProjectReference {
            id_kind: "dispatch result".to_owned(),
            expected: project,
            found: dispatched.supervision_id().project_id(),
        });
    }
    Ok(())
}

/// The deterministic dispatch request of one Task.
///
/// The same execution and Task always yield the same request ID, so a crash
/// between the recorded intent and the recorded reservation re-uses the stored
/// mapping instead of creating a second child.
pub fn dispatch_request_id(execution: ExecutionId, task: TaskRef) -> DispatchRequestId {
    let mut hasher = Sha256::new();
    hasher.update(b"h4.task.dispatch\0");
    hasher.update(execution.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(task.stable_id().to_string().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    DispatchRequestId::from_parts(execution.project_id(), Uuid::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Observation, continuation, and completion
// ---------------------------------------------------------------------------

fn observe_task(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    approval: &crate::approval::ExecutionApproval,
    task: &TaskSnapshot,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let identity = *request.identity();
    let execution = identity.execution_id();
    let target = task.task();
    let h2 = task
        .h2_reference()
        .ok_or_else(|| SddExecutionError::InvalidSnapshot {
            field: "task.h2Reference".to_owned(),
            detail: "an active Task must name its H2 target".to_owned(),
        })?;
    let request_id = dispatch_request_id(execution, target);

    // The stored H2 result is the only progress input.
    let Some(status) = ports
        .children
        .status(identity.project_id(), execution, request_id)?
    else {
        // The Task names an H2 target but H2 records no result for its request:
        // reconcile, never re-dispatch.
        return stop_execution(
            ports,
            snapshot,
            request,
            task,
            StopReason::RecoveryRequired,
            HumanAction::ConfirmRecovery,
        );
    };
    if status.supervision_id() != h2.supervision_id() {
        return Err(ownership_conflict());
    }

    // Combined budget: H2 supervision plus the host's own processing. The value
    // is monotonic and never reset by a resume.
    let mut budget = task_budget(snapshot, task);
    budget.observe_h2(status.active_seconds(), status.additional_runs());
    budget.observe_stalls(status.consecutive_stalls());

    match status.state() {
        state if state.is_working() => Ok(CoordinatorOutcome::AwaitingChild {
            task: target,
            state,
        }),
        ChildState::Completed => {
            budget.mark_h2_completed();
            // "Met after the limit" is refused, not completed.
            if let Err(exhaustion) = budget.admit_completion() {
                return stop_for_budget(ports, snapshot, request, task, exhaustion);
            }
            // A completion that no longer covers the current content is not
            // completion.
            if status.completion_stale() {
                return stop_execution(
                    ports,
                    snapshot,
                    request,
                    task,
                    StopReason::HumanDecisionRequired,
                    HumanAction::ResolveHumanDecision,
                );
            }
            complete_task(ports, snapshot, request, approval, task, &status, budget)
        }
        ChildState::WaitingHuman => stop_execution(
            ports,
            snapshot,
            request,
            task,
            StopReason::HumanDecisionRequired,
            HumanAction::ResolveHumanDecision,
        ),
        ChildState::Stopped => {
            let (reason, action) = stopped_reason(&status, &budget);
            stop_execution(ports, snapshot, request, task, reason, action)
        }
        ChildState::Failed => stop_execution(
            ports,
            snapshot,
            request,
            task,
            StopReason::InternalFailure,
            HumanAction::ResolveInternalFailure,
        ),
        ChildState::Cancelled => {
            let stop = StopRecord::new(StopReason::CancelRequested, None)?;
            stop_with_record(ports, snapshot, request, task, stop)
        }
        // An unknown or unstoppable state is never completion.
        ChildState::Unknown => stop_execution(
            ports,
            snapshot,
            request,
            task,
            StopReason::RecoveryRequired,
            HumanAction::ConfirmRecovery,
        ),
        ChildState::Ready | ChildState::Running | ChildState::Verifying | ChildState::Assessing => {
            unreachable!("working states are handled above")
        }
    }
}

/// The H4 stop reason of an H2-stopped child.
///
/// H2's own cause wins; the combined budget only refines an unclassified stop.
fn stopped_reason(status: &ChildStatus, budget: &TaskBudget) -> (StopReason, HumanAction) {
    match status.stop_cause() {
        Some(ChildStopCause::Stagnation) => (StopReason::ChildStalled, HumanAction::ClearStall),
        Some(ChildStopCause::Budget) => (StopReason::BudgetExhausted, HumanAction::RaiseBudget),
        Some(ChildStopCause::UserRequest) => (StopReason::PauseRequested, HumanAction::ConfirmStop),
        Some(ChildStopCause::StopUnconfirmed) => {
            (StopReason::StopUnconfirmed, HumanAction::ConfirmStop)
        }
        Some(ChildStopCause::RecoveryReconciliation) => {
            (StopReason::RecoveryRequired, HumanAction::ConfirmRecovery)
        }
        Some(ChildStopCause::Unknown) | None => {
            if status.consecutive_stalls() >= budget.limits().max_consecutive_stalls() {
                (StopReason::ChildStalled, HumanAction::ClearStall)
            } else if budget.remaining_seconds() == 0 || budget.remaining_additional_runs() == 0 {
                (StopReason::BudgetExhausted, HumanAction::RaiseBudget)
            } else if status.state() == ChildState::Stopped {
                (
                    StopReason::SupervisionLimitReached,
                    HumanAction::ResolveLimit,
                )
            } else {
                (StopReason::RecoveryRequired, HumanAction::ConfirmRecovery)
            }
        }
    }
}

fn complete_task(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    approval: &crate::approval::ExecutionApproval,
    task: &TaskSnapshot,
    status: &ChildStatus,
    budget: TaskBudget,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let target = task.task();
    let identity = *request.identity();

    // The host path must be wired before the Task may leave H2's completion. The
    // missing capability is explicit; nothing is inferred. A barrier-connected
    // seam runs its HTML barrier first and refuses the still-missing commit
    // inside the completion, so a non-synced result holds the Task with the
    // right HTML reason instead of a blanket capability error.
    let wiring = ports.completion.wiring(target);
    if !wiring.may_run()
        && let CompletionWiring::NotConnected { feature } = wiring
    {
        let outcome = stop_execution(
            ports,
            snapshot,
            request,
            task,
            StopReason::CapabilityUnavailable,
            HumanAction::ProvideCapability,
        )?;
        let revision = match &outcome {
            CoordinatorOutcome::Stopped { revision, .. } => *revision,
            other => return Ok(other.clone()),
        };
        return Ok(CoordinatorOutcome::CompletionNotConnected {
            task: target,
            feature,
            revision,
        });
    }

    // 1. Record `committing` before the host side effect.
    let mut committing = SnapshotDraft::from(snapshot, snapshot.revision().next());
    if committing.state == ExecutionState::Running {
        committing.state = ExecutionState::Committing;
    }
    committing.current_task = Some(target);
    committing.budget = SnapshotBudget::new(
        budget.consumption().snapshot_consumption(),
        BudgetConsumption::zero(),
    );
    committing.tasks = replace_task(
        snapshot,
        target,
        TaskEdit {
            phase: TaskPhase::Committing,
            h2: task.h2_reference(),
            child: task.child(),
            commit_range: None,
            no_change: None,
            evidence: status.evidence().to_vec(),
            stop: None,
        },
    )?;
    let committing = committing.build()?;
    write_step(
        ports,
        request,
        "committing",
        snapshot.revision(),
        ExecutionOperation::Resume,
        &committing,
    )?;

    let completion_request = TaskCompletionRequest::new(
        target,
        identity.execution_id(),
        committing.revision(),
        status.supervision_id(),
        approval.commit(),
        task.commit_policy(),
        status.evidence().to_vec(),
        budget.remaining_seconds(),
    );
    let completion = ports.completion.complete(&completion_request)?;
    match completion {
        TaskCompletion::HumanWait { stop } => {
            stop_with_record(ports, &committing, request, task, stop)
        }
        TaskCompletion::Complete {
            commit_range,
            no_change,
            host_seconds,
        } => {
            // Host processing after H2 completion is charged to the same Task.
            let mut charged = budget;
            charged.charge_host_processing(host_seconds);
            // Host processing is charged to the same Task. If it pushed the Task
            // past its finite seconds, the Task is not complete.
            if charged.consumption().active_seconds() > charged.limits().max_time_seconds() {
                let exhaustion = TaskBudgetExhaustion::new(
                    crate::state::BudgetExhaustionReason::ActiveSeconds,
                    charged.limits().max_time_seconds(),
                    charged.consumption().active_seconds(),
                );
                return stop_for_budget(ports, &committing, request, task, exhaustion);
            }
            let mut next = SnapshotDraft::from(&committing, committing.revision().next());
            next.budget = SnapshotBudget::new(
                charged.consumption().snapshot_consumption(),
                BudgetConsumption::zero(),
            );
            next.tasks = replace_task(
                &committing,
                target,
                TaskEdit {
                    phase: TaskPhase::Complete,
                    h2: task.h2_reference(),
                    child: task.child(),
                    commit_range,
                    no_change,
                    evidence: status.evidence().to_vec(),
                    stop: None,
                },
            )?;
            let all_complete = next
                .tasks
                .iter()
                .all(|task| task.progression() == TaskProgression::Complete);
            next.current_task = None;
            if all_complete {
                next.state = ExecutionState::ReadyForFinish;
            } else if next.state == ExecutionState::Committing {
                next.state = ExecutionState::Running;
            }
            let next = next.build()?;
            let revision = write_final(
                ports,
                request,
                committing.revision(),
                ExecutionOperation::Resume,
                &next,
            )?;
            ports.serial.release_slot(request.identity().execution_id());
            if all_complete {
                return Ok(CoordinatorOutcome::ReadyForFinish { revision });
            }
            Ok(CoordinatorOutcome::TaskCompleted {
                task: target,
                revision,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Durable refusals
// ---------------------------------------------------------------------------

fn stop_for_budget(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    task: &TaskSnapshot,
    exhaustion: TaskBudgetExhaustion,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let stop = StopRecord::new(exhaustion.stop_reason(), Some(exhaustion.human_action()))?;
    let outcome = stop_with_record(ports, snapshot, request, task, stop)?;
    let revision = match &outcome {
        CoordinatorOutcome::Stopped { revision, .. } => *revision,
        other => return Ok(other.clone()),
    };
    Ok(CoordinatorOutcome::BudgetRefused {
        task: task.task(),
        exhaustion,
        revision,
    })
}

fn stop_execution(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    task: &TaskSnapshot,
    reason: StopReason,
    action: HumanAction,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let stop = StopRecord::new(reason, Some(action))?;
    stop_with_record(ports, snapshot, request, task, stop)
}

fn stop_with_record(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    task: &TaskSnapshot,
    stop: StopRecord,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    let mut draft = SnapshotDraft::from(snapshot, snapshot.revision().next());
    draft.state = ExecutionState::WaitingHuman;
    draft.stop = Some(stop);
    // A pending Task stays pending: only an already active Task moves to
    // `waiting_human`, and never to a fabricated completion.
    if task.progression() == TaskProgression::Active {
        draft.current_task = Some(task.task());
        draft.tasks = replace_task(
            snapshot,
            task.task(),
            TaskEdit {
                phase: TaskPhase::WaitingHuman,
                h2: task.h2_reference(),
                child: task.child(),
                commit_range: None,
                no_change: None,
                evidence: task.evidence().to_vec(),
                stop: Some(stop),
            },
        )?;
    }
    let next = draft.build()?;
    let revision = write_final(
        ports,
        request,
        snapshot.revision(),
        ExecutionOperation::Pause,
        &next,
    )?;
    ports.serial.release_slot(request.identity().execution_id());
    ports
        .serial
        .release_checkout(request.identity().execution_id());
    Ok(CoordinatorOutcome::Stopped {
        task: Some(task.task()),
        stop,
        revision,
    })
}

fn refuse_launch(
    ports: &mut CoordinatorPorts<'_>,
    snapshot: &ExecutionSnapshot,
    request: &CoordinatorRequest,
    task: &TaskSnapshot,
    refusal: LaunchRefusal,
) -> Result<CoordinatorOutcome, SddExecutionError> {
    stop_execution(
        ports,
        snapshot,
        request,
        task,
        refusal.stop_reason(),
        refusal.human_action(),
    )
}

// ---------------------------------------------------------------------------
// Task budget helper
// ---------------------------------------------------------------------------

/// The combined Task budget of one stored Task snapshot.
///
/// The snapshot's budget describes the current Task, so resuming keeps exactly
/// the consumption already charged for it. A Task that was never started has no
/// consumption.
fn task_budget(snapshot: &ExecutionSnapshot, task: &TaskSnapshot) -> TaskBudget {
    let limits = ContinuationLimits::h4_default();
    if snapshot.current_task() == Some(task.task()) {
        TaskBudget::from_snapshot(limits, snapshot.budget().consumed(), 0)
            .unwrap_or_else(|_| TaskBudget::new(limits))
    } else {
        TaskBudget::new(limits)
    }
}

// ---------------------------------------------------------------------------
// Snapshot construction helpers
// ---------------------------------------------------------------------------

/// The mutable parts of one next snapshot.
struct SnapshotDraft {
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    state: ExecutionState,
    plan: crate::snapshot::SnapshotPlan,
    workspace: crate::snapshot::SnapshotWorkspace,
    current_task: Option<TaskRef>,
    tasks: Vec<TaskSnapshot>,
    stop: Option<StopRecord>,
    budget: SnapshotBudget,
    applied_revision: AppliedRevision,
    final_project_sequence: Option<crate::ids::ProjectSequence>,
}

impl SnapshotDraft {
    fn from(snapshot: &ExecutionSnapshot, revision: ExecutionRevision) -> Self {
        Self {
            project_id: snapshot.project_id(),
            execution_id: snapshot.execution_id(),
            revision,
            state: snapshot.state(),
            plan: snapshot.plan().clone(),
            workspace: snapshot.workspace().clone(),
            current_task: snapshot.current_task(),
            tasks: snapshot.tasks().to_vec(),
            stop: snapshot.stop(),
            budget: snapshot.budget(),
            applied_revision: snapshot.applied_revision(),
            final_project_sequence: snapshot.final_project_sequence(),
        }
    }

    fn build(self) -> Result<ExecutionSnapshot, SddExecutionError> {
        ExecutionSnapshot::new(SnapshotInput {
            project_id: self.project_id,
            execution_id: self.execution_id,
            revision: self.revision,
            state: self.state,
            plan: self.plan,
            workspace: self.workspace,
            current_task: self.current_task,
            tasks: self.tasks,
            stop: self.stop,
            budget: self.budget,
            applied_revision: self.applied_revision,
            final_project_sequence: self.final_project_sequence,
        })
    }
}

/// The Task fields one decision changes.
struct TaskEdit {
    phase: TaskPhase,
    h2: Option<H2SupervisionRef>,
    child: Option<ChildIdentity>,
    commit_range: Option<CommitRange>,
    no_change: Option<NoChangeRecord>,
    evidence: Vec<herness_supervision::EvidenceId>,
    stop: Option<StopRecord>,
}

fn replace_task(
    snapshot: &ExecutionSnapshot,
    task_ref: TaskRef,
    edit: TaskEdit,
) -> Result<Vec<TaskSnapshot>, SddExecutionError> {
    let index = snapshot
        .tasks()
        .iter()
        .position(|task| task.task() == task_ref)
        .ok_or_else(|| SddExecutionError::InvalidSnapshot {
            field: "snapshot.tasks".to_owned(),
            detail: "the selected Task is not in the snapshot".to_owned(),
        })?;
    let previous = &snapshot.tasks()[index];
    let updated = TaskSnapshot::new(
        task_ref,
        edit.phase.implied_progression(),
        edit.phase,
        edit.h2,
        edit.child,
        previous.commit_policy(),
        edit.commit_range,
        edit.no_change,
        edit.evidence,
        edit.stop,
        previous.applied_revision(),
    )?;
    let mut tasks = snapshot.tasks().to_vec();
    tasks[index] = updated;
    Ok(tasks)
}

// ---------------------------------------------------------------------------
// Transactional write
// ---------------------------------------------------------------------------

/// Writes one decision's snapshot, operation result, and event in one
/// transaction.
///
/// `expected` is the revision currently stored. An intermediate step of one
/// advance passes a step-derived request ID and the revision its own previous
/// step wrote; the terminal step passes the caller's request ID, so a
/// re-delivery of the same advance returns the stored result instead of
/// repeating a side effect.
fn write(
    ports: &mut CoordinatorPorts<'_>,
    project: ProjectId,
    execution: ExecutionId,
    request_id: ControlRequestId,
    expected: ExecutionRevision,
    operation: ExecutionOperation,
    next: &ExecutionSnapshot,
) -> Result<ExecutionRevision, SddExecutionError> {
    let request =
        ExecutionOperationRequest::new(project, execution, request_id, expected, operation)?;
    let result = ExecutionOperationResult::new(operation, next.clone())?;
    let record = request.recorded(result)?;
    let stored = ports
        .store
        .commit_operation(project, execution, Some(expected), next, &record)?;
    if stored != next.revision() {
        // A stored result for this step does not describe the revision this
        // advance is writing: the durable state moved, so refuse instead of
        // reporting a revision the store did not write.
        return Err(SddExecutionError::RevisionConflict {
            expected: next.revision(),
            found: stored,
        });
    }
    Ok(next.revision())
}

/// The caller's request ID for an intermediate step of one advance.
fn step_id_of(request: &CoordinatorRequest, step: &str) -> ControlRequestId {
    step_request_id(
        request.identity().request_id(),
        step,
        request.identity().project_id(),
    )
}

/// Writes one intermediate revision of a multi-step advance.
fn write_step(
    ports: &mut CoordinatorPorts<'_>,
    request: &CoordinatorRequest,
    step: &str,
    expected: ExecutionRevision,
    operation: ExecutionOperation,
    next: &ExecutionSnapshot,
) -> Result<ExecutionRevision, SddExecutionError> {
    write(
        ports,
        request.identity().project_id(),
        request.identity().execution_id(),
        step_id_of(request, step),
        expected,
        operation,
        next,
    )
}

/// Writes the terminal revision of one advance under the caller's request ID.
fn write_final(
    ports: &mut CoordinatorPorts<'_>,
    request: &CoordinatorRequest,
    expected: ExecutionRevision,
    operation: ExecutionOperation,
    next: &ExecutionSnapshot,
) -> Result<ExecutionRevision, SddExecutionError> {
    write(
        ports,
        request.identity().project_id(),
        request.identity().execution_id(),
        request.identity().request_id(),
        expected,
        operation,
        next,
    )
}

/// Derives one step's request ID from the advance request and a stable label.
pub fn step_request_id(base: ControlRequestId, step: &str, project: ProjectId) -> ControlRequestId {
    let mut hasher = Sha256::new();
    hasher.update(b"h4.coordinator.step\0");
    hasher.update(base.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(step.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ControlRequestId::from_parts(project, Uuid::from_bytes(bytes))
}

fn ownership_conflict() -> SddExecutionError {
    SddExecutionError::Conflict {
        reason: ConflictReason::OwnershipConflict,
        details: crate::error::FailureDetails::none().boxed(),
    }
}
