//! Durable supervision recovery, explicit human reconciliation, and quit marks.
//!
//! Recovery loads a supervision record together with the durable model-request
//! intents/observations, unresolved H1 operations, budget ledger, and H1
//! run/process/checkpoint facts. [`RecoveryService::recover`] is read-only: it
//! never starts a run, sends or retries a model request, executes a tool,
//! resumes a run, or changes the stored record. [`RecoveryService::reconcile`]
//! may persist only a local `waiting_human` transition and a one-time stale
//! completion notification; it still performs none of those external actions.
//!
//! The classification is conservative. A persisted request intent without a
//! durable terminal observation is never treated as "never sent"; an unknown
//! send, an unresolved operation, a possibly running managed process, a stop
//! that H1 did not confirm, a missing/ambiguous restored checkpoint, or a
//! terminal provider observation that was not yet applied to the supervision
//! state all remain waiting for an explicit human reconciliation. Delayed
//! responses are reported as history only and are never applied.

use std::collections::BTreeMap;

use herness_core::contracts::{
    AttemptId, ModelRequestObservation, ProjectId, RequestId, RequestOutcome, RunId, RunState,
    Timestamp,
};
use herness_core::runtime::RecoveryMode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::budget::ledger::ClockReading;
use crate::budget::{BudgetLimit, BudgetUsage};
use crate::command::{CommandResult, SupervisionCommand};
use crate::conditions::ConditionVersion;
use crate::contract::SupervisionContract;
use crate::error::SupervisionError;
use crate::evidence::TargetVersion;
use crate::ids::{CheckId, ConditionId, SupervisionId, SupervisionRequestId};
use crate::ports::{ClockPort, StoredBudgetRecord, SupervisionStorePort};
use crate::state::{
    DecisionInvalidation, HumanAction, StopCause, SupervisionReason, SupervisionRecord,
    SupervisionState,
};
use crate::supervisor::{OwnerNotificationPort, SupervisorNotification};

/// One durable model-request attempt loaded for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequestAttempt {
    request_id: RequestId,
    attempt_id: AttemptId,
    run_id: Option<RunId>,
    activity_kind: Option<String>,
    purpose: String,
    recorded_at: Timestamp,
    observation: Option<ModelRequestObservation>,
    observed_at: Option<Timestamp>,
}

impl RecoveryRequestAttempt {
    /// Creates one recovery request view.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: RequestId,
        attempt_id: AttemptId,
        run_id: Option<RunId>,
        activity_kind: Option<String>,
        purpose: impl Into<String>,
        recorded_at: Timestamp,
        observation: Option<ModelRequestObservation>,
        observed_at: Option<Timestamp>,
    ) -> Self {
        Self {
            request_id,
            attempt_id,
            run_id,
            activity_kind,
            purpose: purpose.into(),
            recorded_at,
            observation,
            observed_at,
        }
    }

    /// Host-owned request identifier.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Send-attempt identifier.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Run subject, when the request belongs to a run.
    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }

    /// Host-activity kind, when the request belongs to a host activity.
    pub fn activity_kind(&self) -> Option<&str> {
        self.activity_kind.as_deref()
    }

    /// Host-owned purpose label.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// When the intent was persisted.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// Durable send/terminal observation, when one exists.
    pub const fn observation(&self) -> Option<&ModelRequestObservation> {
        self.observation.as_ref()
    }

    /// When the current observation was persisted.
    pub const fn observed_at(&self) -> Option<Timestamp> {
        self.observed_at
    }

    fn belongs_to(&self, record: &SupervisionRecord) -> bool {
        if let Some(run) = self.run_id {
            return record.run_group().contains(&run)
                || record.supervisor().current_run() == Some(run);
        }
        self.activity_kind
            .as_deref()
            .is_some_and(|kind| kind.starts_with("supervision"))
    }
}

/// One unresolved operation loaded from the H1 store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOperation {
    operation_id: String,
    run_id: RunId,
    tool: String,
    pending: bool,
}

impl RecoveryOperation {
    /// Creates one read-only operation summary.
    pub fn new(operation_id: impl Into<String>, run_id: RunId, tool: impl Into<String>) -> Self {
        Self {
            operation_id: operation_id.into(),
            run_id,
            tool: tool.into(),
            pending: true,
        }
    }

    /// Sanitized operation identifier.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Run the operation belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Tool label.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Whether the operation has no durable result.
    pub const fn pending(&self) -> bool {
        self.pending
    }
}

/// One read-consistent recovery snapshot from the durable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySnapshot {
    records: Vec<SupervisionRecord>,
    requests: Vec<RecoveryRequestAttempt>,
    unresolved_operations: Vec<RecoveryOperation>,
    checkpoints: BTreeMap<RunId, bool>,
}

impl RecoverySnapshot {
    /// Creates a snapshot from already-read values.
    pub fn new(
        records: Vec<SupervisionRecord>,
        requests: Vec<RecoveryRequestAttempt>,
        unresolved_operations: Vec<RecoveryOperation>,
        checkpoints: BTreeMap<RunId, bool>,
    ) -> Self {
        Self {
            records,
            requests,
            unresolved_operations,
            checkpoints,
        }
    }

    /// Supervision records for the project.
    pub fn records(&self) -> &[SupervisionRecord] {
        &self.records
    }

    /// Durable model-request attempts.
    pub fn requests(&self) -> &[RecoveryRequestAttempt] {
        &self.requests
    }

    /// Unresolved H1 operations.
    pub fn unresolved_operations(&self) -> &[RecoveryOperation] {
        &self.unresolved_operations
    }

    /// Checkpoint presence by run.
    pub fn checkpoints(&self) -> &BTreeMap<RunId, bool> {
        &self.checkpoints
    }
}

/// Read-only durable facts needed by recovery.
///
/// A store implements this with one read transaction so records, requests,
/// operations, and checkpoints come from the same durable view. The trait is
/// additive over [`SupervisionStorePort`]; recovery's write path uses only the
/// latter's command journal and compare-and-swap.
pub trait RecoveryFactsPort: SupervisionStorePort {
    /// Loads one consistent recovery snapshot for a project.
    fn recovery_snapshot(
        &self,
        project_id: ProjectId,
    ) -> Result<RecoverySnapshot, SupervisionError>;
}

/// Read-only budget view used by recovery.
pub trait RecoveryBudgetRead {
    /// Loads the durable ledger without charging or creating anything.
    fn load_recovery_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError>;

    /// Excludes human-waiting time when reconciliation commits `waiting_human`.
    ///
    /// The default is a no-op for a read-only store view. A durable
    /// `BudgetLedger` overrides it to persist `waiting_human` before the record
    /// transition.
    fn mark_recovery_waiting_human(&mut self) -> Result<(), SupervisionError> {
        Ok(())
    }

    /// Stops active-time accrual for a completed/stale record during reconcile.
    fn mark_recovery_app_stopped(&mut self) -> Result<(), SupervisionError> {
        Ok(())
    }
}

/// One managed child process reported by H1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedProcessState {
    process_id: String,
    running: bool,
    stop_confirmed: bool,
}

impl ManagedProcessState {
    /// Creates one process fact.
    pub fn new(process_id: impl Into<String>, running: bool, stop_confirmed: bool) -> Self {
        Self {
            process_id: process_id.into(),
            running,
            stop_confirmed,
        }
    }

    /// Non-secret process label.
    pub fn process_id(&self) -> &str {
        &self.process_id
    }

    /// Whether the process may still be running.
    pub const fn running(&self) -> bool {
        self.running
    }

    /// Whether H1 confirmed its stop.
    pub const fn stop_confirmed(&self) -> bool {
        self.stop_confirmed
    }

    fn blocks_resume(&self) -> bool {
        self.running || !self.stop_confirmed
    }
}

/// Checkpoint availability for the current run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCheckpoint {
    /// No checkpoint exists for the run.
    Missing,
    /// One applicable checkpoint exists.
    Present,
    /// The checkpoint cannot be matched unambiguously to the current run.
    Ambiguous(String),
}

/// H1 stop fact for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryStopState {
    /// No stop was requested.
    #[default]
    NotRequested,
    /// H1 confirmed the stop.
    Confirmed,
    /// H1 could not confirm the stop.
    Unconfirmed,
}

/// Read-only H1 facts used by recovery and the explicit resume gate.
pub trait RecoveryRuntimePort {
    /// Current H1 run state.
    fn run_state(&mut self, run: RunId) -> Result<RunState, SupervisionError>;

    /// Whether the run belongs to this process or was restored.
    fn recovery_mode(&mut self, run: RunId) -> Result<RecoveryMode, SupervisionError>;

    /// Managed child processes that may still be running.
    fn managed_processes(
        &mut self,
        run: RunId,
    ) -> Result<Vec<ManagedProcessState>, SupervisionError>;

    /// Checkpoint availability for the run.
    fn checkpoint(&mut self, run: RunId) -> Result<RecoveryCheckpoint, SupervisionError>;

    /// Durable stop confirmation for the run.
    fn stop_state(&mut self, run: RunId) -> Result<RecoveryStopState, SupervisionError>;

    /// Whether the current H1 permission context/grant still authorizes work
    /// for this supervision record.
    ///
    /// This is a read-only check. The host composition maps it to the current
    /// policy, agent/session grant, execution scope, and connection status.
    fn permissions_current(&mut self, record: &SupervisionRecord)
    -> Result<bool, SupervisionError>;
}

/// Why an intent/observation remains unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedRequestKind {
    /// The intent was saved but no send-started or terminal observation exists.
    IntentOnly,
    /// Sending started and no terminal observation was saved.
    SendStarted,
    /// A terminal observation exists but was not applied to supervision state.
    TerminalObservedStateNotSaved,
    /// Sending may have happened and the result is unknown.
    SendUnknown,
}

impl UnresolvedRequestKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntentOnly => "intent_only",
            Self::SendStarted => "send_started",
            Self::TerminalObservedStateNotSaved => "terminal_observed_state_not_saved",
            Self::SendUnknown => "send_unknown",
        }
    }
}

/// One unresolved request attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRequest {
    attempt_id: AttemptId,
    kind: UnresolvedRequestKind,
    purpose: String,
}

impl UnresolvedRequest {
    /// Creates one unresolved attempt.
    pub fn new(
        attempt_id: AttemptId,
        kind: UnresolvedRequestKind,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            attempt_id,
            kind,
            purpose: purpose.into(),
        }
    }

    /// Attempt that must be reconciled.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Why it remains unresolved.
    pub const fn kind(&self) -> UnresolvedRequestKind {
        self.kind
    }

    /// Host-owned purpose label.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

/// Why a durable observation is history only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryOnlyReason {
    /// A preflight failure definitely did not send.
    DefinitelyNotSent,
    /// The observation was already reflected in the saved supervision state.
    AlreadyApplied,
    /// The observation arrived after the record stopped progressing.
    DelayedAfterStateChange,
}

/// One terminal observation kept only as history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryOnlyRequest {
    attempt_id: AttemptId,
    outcome: RequestOutcome,
    reason: HistoryOnlyReason,
}

impl HistoryOnlyRequest {
    /// Creates one history-only observation.
    pub const fn new(
        attempt_id: AttemptId,
        outcome: RequestOutcome,
        reason: HistoryOnlyReason,
    ) -> Self {
        Self {
            attempt_id,
            outcome,
            reason,
        }
    }

    /// Attempt this observation belongs to.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Observed outcome.
    pub const fn outcome(&self) -> RequestOutcome {
        self.outcome
    }

    /// Why it is not applied.
    pub const fn reason(&self) -> HistoryOnlyReason {
        self.reason
    }
}

/// One approved/current version that differs from the stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum VersionMismatch {
    /// Condition version changed.
    Conditions {
        /// Stored version.
        record: ConditionVersion,
        /// Approved/current version.
        approved: ConditionVersion,
    },
    /// The condition or required-check set changed without a version change.
    ConditionContent {
        /// Stored condition IDs.
        record_conditions: Vec<ConditionId>,
        /// Approved condition IDs.
        approved_conditions: Vec<ConditionId>,
        /// Stored required check IDs.
        record_checks: Vec<CheckId>,
        /// Approved required check IDs.
        approved_checks: Vec<CheckId>,
        /// Approved condition version for invalidation history.
        approved_version: ConditionVersion,
    },
    /// Target version changed.
    Target {
        /// Stored version.
        record: TargetVersion,
        /// Approved/current version.
        approved: TargetVersion,
    },
    /// Assessment profile binding changed.
    Profile,
    /// Disclosure consent binding changed or was revoked.
    Consent,
    /// Finite budget policy changed.
    BudgetPolicy,
    /// Budget policy version changed.
    BudgetPolicyVersion {
        /// Stored version.
        record: u64,
        /// Approved/current version.
        approved: u64,
    },
    /// The condition approval is expired or no longer valid.
    Approval,
}

/// Budget facts reported by recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBudgetReport {
    usage: BudgetUsage,
    remaining_active_seconds: u64,
    can_start_run: bool,
    unresolved_charges: usize,
    policy_matches: bool,
    policy_version_matches: bool,
}

impl RecoveryBudgetReport {
    /// Effective usage including the open interval, without a write.
    pub const fn usage(&self) -> BudgetUsage {
        self.usage
    }

    /// Remaining active seconds under the stored/approved policy.
    pub const fn remaining_active_seconds(&self) -> u64 {
        self.remaining_active_seconds
    }

    /// Whether the ledger currently permits another run.
    pub const fn can_start_run(&self) -> bool {
        self.can_start_run
    }

    /// Number of unresolved money reservations that keep counting.
    pub const fn unresolved_charges(&self) -> usize {
        self.unresolved_charges
    }

    /// Whether the stored policy equals the approved policy.
    pub const fn policy_matches(&self) -> bool {
        self.policy_matches
    }

    /// Whether the stored policy version equals the approved version.
    pub const fn policy_version_matches(&self) -> bool {
        self.policy_version_matches
    }

    fn empty(policy: &crate::budget::BudgetPolicy) -> Self {
        Self {
            usage: BudgetUsage::empty(),
            remaining_active_seconds: policy.active_seconds(),
            can_start_run: true,
            unresolved_charges: 0,
            policy_matches: true,
            policy_version_matches: true,
        }
    }
}

impl Default for RecoveryBudgetReport {
    fn default() -> Self {
        Self::empty(&crate::budget::BudgetPolicy::h2_default())
    }
}

/// Structured reason that blocks resume/reassessment or requires a human.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RecoveryBlockReason {
    /// A model request attempt remains unresolved.
    UnresolvedRequest {
        /// Attempt identifier.
        attempt: String,
        /// Classification.
        classification: UnresolvedRequestKind,
    },
    /// An H1 operation has no durable result.
    UnresolvedOperation {
        /// Operation identifier.
        operation: String,
    },
    /// A managed process may still be running.
    ManagedProcess {
        /// Run that owns the process.
        run: RunId,
        /// Process label.
        process: String,
    },
    /// The current run has no checkpoint.
    CheckpointMissing {
        /// Run identifier.
        run: RunId,
    },
    /// The checkpoint cannot be matched unambiguously.
    CheckpointAmbiguous {
        /// Run identifier.
        run: RunId,
        /// Sanitized detail.
        detail: String,
    },
    /// H1 did not confirm the stop.
    StopUnconfirmed {
        /// Run identifier, when a run exists.
        run: Option<RunId>,
    },
    /// The H1 run is still active.
    RunActive {
        /// Run identifier.
        run: RunId,
    },
    /// The budget ledger exists for a record with runs but cannot be read.
    BudgetMissing,
    /// A money reservation has unknown usage and keeps counting.
    UnresolvedBudgetCharge {
        /// Attempt identifier.
        attempt: String,
    },
    /// A finite budget limit is already reached.
    BudgetExhausted {
        /// Reached limit.
        limit: BudgetLimit,
    },
    /// The stored record is already in a terminal state.
    StateNotResumable {
        /// Current state.
        state: SupervisionState,
    },
    /// The approved condition version/content differs from the record.
    ConditionsChanged,
    /// The approved target differs from the record.
    TargetChanged,
    /// The approved profile differs from the record.
    ProfileChanged,
    /// The approved consent differs from the record.
    ConsentChanged,
    /// The approved budget policy differs from the record.
    BudgetChanged,
    /// The current H1 permission context no longer authorizes the work.
    PermissionsChanged,
    /// The condition approval is no longer valid.
    ApprovalInvalid,
}

/// Overall recovery disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDisposition {
    /// No durable blocker; an explicit human operation may proceed.
    Recoverable,
    /// A human must reconcile requests/operations/processes/versions first.
    WaitingHuman,
    /// The record is stopped and its cause must be resolved.
    Stopped,
    /// The record is completed and its snapshot still applies.
    Completed,
    /// The record is completed but related inputs changed. Notify only.
    CompletedStale,
    /// The record is failed or cancelled.
    Terminal,
}

/// Counters proving recovery performed no external work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySideEffects {
    /// Model requests sent.
    pub model_requests: u32,
    /// Runs started.
    pub runs_started: u32,
    /// Tool executions.
    pub tool_executions: u32,
    /// Automatic resumes.
    pub auto_resumes: u32,
}

impl RecoverySideEffects {
    /// Creates a zero counter set.
    pub const fn zero() -> Self {
        Self {
            model_requests: 0,
            runs_started: 0,
            tool_executions: 0,
            auto_resumes: 0,
        }
    }

    /// Whether every counter is zero.
    pub const fn is_zero(self) -> bool {
        self.model_requests == 0
            && self.runs_started == 0
            && self.tool_executions == 0
            && self.auto_resumes == 0
    }
}

/// Structured, read-only recovery report.
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    project_id: ProjectId,
    supervision_id: SupervisionId,
    revision: u64,
    state: SupervisionState,
    reason: SupervisionReason,
    disposition: RecoveryDisposition,
    resumable: bool,
    unresolved_requests: Vec<UnresolvedRequest>,
    history_only_requests: Vec<HistoryOnlyRequest>,
    unresolved_operations: Vec<RecoveryOperation>,
    managed_processes: Vec<ManagedProcessState>,
    checkpoint: Option<RecoveryCheckpoint>,
    recovery_mode: Option<RecoveryMode>,
    budget: RecoveryBudgetReport,
    version_mismatches: Vec<VersionMismatch>,
    block_reasons: Vec<RecoveryBlockReason>,
    required_actions: Vec<HumanAction>,
    stale_completion: bool,
    side_effects: RecoverySideEffects,
    notified: bool,
}

impl RecoveryReport {
    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Revision observed by the read-only recovery query.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Current stored state.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Current stored reason.
    pub fn reason(&self) -> &SupervisionReason {
        &self.reason
    }

    /// Overall disposition.
    pub const fn disposition(&self) -> RecoveryDisposition {
        self.disposition
    }

    /// Whether an explicit resume/reassessment may proceed.
    pub const fn resumable(&self) -> bool {
        self.resumable
    }

    /// Unresolved model requests.
    pub fn unresolved_requests(&self) -> &[UnresolvedRequest] {
        &self.unresolved_requests
    }

    /// Terminal observations kept only as history.
    pub fn history_only_requests(&self) -> &[HistoryOnlyRequest] {
        &self.history_only_requests
    }

    /// Unresolved H1 operations.
    pub fn unresolved_operations(&self) -> &[RecoveryOperation] {
        &self.unresolved_operations
    }

    /// Managed processes that may still run.
    pub fn managed_processes(&self) -> &[ManagedProcessState] {
        &self.managed_processes
    }

    /// Checkpoint availability for the current run.
    pub const fn checkpoint(&self) -> Option<&RecoveryCheckpoint> {
        self.checkpoint.as_ref()
    }

    /// Same-process or restored H1 recovery mode.
    pub const fn recovery_mode(&self) -> Option<RecoveryMode> {
        self.recovery_mode
    }

    /// Budget facts preserved across reopen.
    pub const fn budget(&self) -> &RecoveryBudgetReport {
        &self.budget
    }

    /// Version/profile/consent/limit mismatches.
    pub fn version_mismatches(&self) -> &[VersionMismatch] {
        &self.version_mismatches
    }

    /// Structured blockers.
    pub fn block_reasons(&self) -> &[RecoveryBlockReason] {
        &self.block_reasons
    }

    /// Human actions required before any resume/reassessment.
    pub fn required_actions(&self) -> &[HumanAction] {
        &self.required_actions
    }

    /// Whether the completed snapshot is marked stale.
    pub const fn stale_completion(&self) -> bool {
        self.stale_completion
    }

    /// Side-effect counters. Always zero for recovery.
    pub const fn side_effects(&self) -> RecoverySideEffects {
        self.side_effects
    }

    /// Whether `reconcile` delivered the one-time stale-completion notice.
    pub const fn notified(&self) -> bool {
        self.notified
    }
}

/// Outcome of reconciling local supervision state.
#[derive(Debug, Clone)]
pub struct RecoveryReconciliation {
    report: RecoveryReport,
    committed: bool,
}

impl RecoveryReconciliation {
    /// Report after local reconciliation.
    pub const fn report(&self) -> &RecoveryReport {
        &self.report
    }

    /// Whether a `waiting_human` transition was committed.
    pub const fn committed(&self) -> bool {
        self.committed
    }

    /// Consumes the outcome and returns the report.
    pub fn into_report(self) -> RecoveryReport {
        self.report
    }
}

/// Recovery controller over read-only facts and the durable command journal.
pub struct RecoveryService<'a> {
    facts: &'a mut dyn RecoveryFactsPort,
    runtime: &'a mut dyn RecoveryRuntimePort,
    budget: &'a mut dyn RecoveryBudgetRead,
    clock: &'a dyn ClockPort,
}

impl<'a> RecoveryService<'a> {
    /// Creates a read-only recovery service.
    pub fn new(
        facts: &'a mut dyn RecoveryFactsPort,
        runtime: &'a mut dyn RecoveryRuntimePort,
        budget: &'a mut dyn RecoveryBudgetRead,
        clock: &'a dyn ClockPort,
    ) -> Self {
        Self {
            facts,
            runtime,
            budget,
            clock,
        }
    }

    /// Loads the durable state and returns a report without writing anything.
    pub fn recover(
        &mut self,
        contract: &SupervisionContract,
        expected_policy_version: u64,
    ) -> Result<RecoveryReport, SupervisionError> {
        let project = contract.project_id();
        let supervision = contract.subject().supervision_id();
        let snapshot = self.facts.recovery_snapshot(project)?;
        let Some(record) = snapshot
            .records()
            .iter()
            .find(|record| record.supervision_id() == supervision)
            .cloned()
        else {
            return Err(SupervisionError::UnknownSupervision);
        };
        self.build_report(&record, &snapshot, contract, expected_policy_version)
    }

    /// Persists only local waiting/notification state, never an external action.
    ///
    /// This may move applied decisions to invalidated history, set
    /// `waiting_human`, and deliver one stale-completion notification guarded by
    /// the idempotent command journal.
    pub fn reconcile(
        &mut self,
        contract: &SupervisionContract,
        expected_policy_version: u64,
        notifications: &mut dyn OwnerNotificationPort,
    ) -> Result<RecoveryReconciliation, SupervisionError> {
        let project = contract.project_id();
        let supervision = contract.subject().supervision_id();
        let snapshot = self.facts.recovery_snapshot(project)?;
        let Some(record) = snapshot
            .records()
            .iter()
            .find(|record| record.supervision_id() == supervision)
            .cloned()
        else {
            return Err(SupervisionError::UnknownSupervision);
        };
        let mut report =
            self.build_report(&record, &snapshot, contract, expected_policy_version)?;

        // One durable notification per stale completion observation.
        if let Some(stale) = record.completion_stale() {
            let request_id = recovery_request_id(
                record.project_id(),
                record.supervision_id(),
                "stale-completion",
                &format!(
                    "{}:{}",
                    stale.previous_target_version().get(),
                    stale.current_target_version().get()
                ),
            );
            if self.facts.command_result(request_id)?.is_none() {
                let notification = SupervisorNotification::new(
                    record.project_id(),
                    record.supervision_id(),
                    record.revision(),
                    record.state(),
                    record.reason().clone(),
                    record.unmet_conditions().to_vec(),
                    self.clock.now(),
                );
                notifications.notify(&notification)?;
                let result = CommandResult::new(
                    request_id,
                    record.project_id(),
                    record.supervision_id(),
                    SupervisionCommand::Reassess,
                    record.revision(),
                    record.state(),
                    record.reason().clone(),
                )?;
                self.facts.record_command_result(&result)?;
                report.notified = true;
                self.budget.mark_recovery_app_stopped()?;
            }
        }

        let mut committed = false;
        let keep_terminal_or_unconfirmed = matches!(
            record.state(),
            SupervisionState::Completed | SupervisionState::Failed | SupervisionState::Cancelled
        ) || matches!(
            record.reason(),
            crate::state::SupervisionReason::Stopped {
                cause: StopCause::StopUnconfirmed
            }
        );
        if report.disposition == RecoveryDisposition::WaitingHuman && !keep_terminal_or_unconfirmed
        {
            let action = report
                .required_actions
                .first()
                .copied()
                .unwrap_or(HumanAction::ReconcileRecovery);
            let invalidation = recovery_invalidation(&report.version_mismatches);
            let mut next = record.clone();
            next.mark_recovery_waiting(action, invalidation)?;
            next.supervisor_mut().phase = crate::supervisor::SupervisorPhase::Finished;
            next.supervisor_mut().pending_assessment = None;
            next.set_command_revision(record.revision().saturating_add(1));
            self.budget.mark_recovery_waiting_human()?;
            let request_id = recovery_request_id(
                record.project_id(),
                record.supervision_id(),
                "waiting-human",
                &record.revision().to_string(),
            );
            let result = CommandResult::new(
                request_id,
                record.project_id(),
                record.supervision_id(),
                SupervisionCommand::Reassess,
                next.revision(),
                next.state(),
                next.reason().clone(),
            )?;
            match self.facts.commit_command(
                record.project_id(),
                record.supervision_id(),
                Some(record.revision()),
                &next,
                &result,
            ) {
                Ok(revision) => {
                    report.revision = revision;
                    report.state = next.state();
                    report.reason = next.reason().clone();
                    committed = true;
                }
                Err(SupervisionError::RevisionConflict { .. }) => {
                    let found = self
                        .facts
                        .load(record.project_id(), record.supervision_id())?
                        .map_or(record.revision(), |current| current.revision());
                    return Err(SupervisionError::RevisionConflict {
                        expected: record.revision(),
                        found,
                    });
                }
                Err(error) => return Err(error),
            }
        }

        Ok(RecoveryReconciliation { report, committed })
    }

    fn build_report(
        &mut self,
        record: &SupervisionRecord,
        snapshot: &RecoverySnapshot,
        contract: &SupervisionContract,
        expected_policy_version: u64,
    ) -> Result<RecoveryReport, SupervisionError> {
        let now = self.clock.now();
        let budgets = self.read_budget(record, contract, expected_policy_version)?;
        let current_run = record
            .supervisor()
            .current_run()
            .or_else(|| record.run_group().runs().last().copied());

        let mut block_reasons = Vec::new();
        let mut required_actions = Vec::new();

        let mut unresolved_requests = Vec::new();
        let mut history_only_requests = Vec::new();
        let record_is_evaluating = matches!(
            record.state(),
            SupervisionState::Verifying | SupervisionState::Assessing
        );
        for request in snapshot.requests() {
            if !request.belongs_to(record) {
                continue;
            }
            match request.observation() {
                None => {
                    let item = UnresolvedRequest::new(
                        request.attempt_id(),
                        UnresolvedRequestKind::IntentOnly,
                        request.purpose(),
                    );
                    push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                    block_reasons.push(RecoveryBlockReason::UnresolvedRequest {
                        attempt: request.attempt_id().to_string(),
                        classification: item.kind(),
                    });
                    unresolved_requests.push(item);
                }
                Some(observation) => match observation.outcome() {
                    RequestOutcome::SendStarted => {
                        let item = UnresolvedRequest::new(
                            request.attempt_id(),
                            UnresolvedRequestKind::SendStarted,
                            request.purpose(),
                        );
                        push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                        block_reasons.push(RecoveryBlockReason::UnresolvedRequest {
                            attempt: request.attempt_id().to_string(),
                            classification: item.kind(),
                        });
                        unresolved_requests.push(item);
                    }
                    RequestOutcome::SendResultUnknown => {
                        let item = UnresolvedRequest::new(
                            request.attempt_id(),
                            UnresolvedRequestKind::SendUnknown,
                            request.purpose(),
                        );
                        push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                        block_reasons.push(RecoveryBlockReason::UnresolvedRequest {
                            attempt: request.attempt_id().to_string(),
                            classification: item.kind(),
                        });
                        unresolved_requests.push(item);
                    }
                    RequestOutcome::Completed | RequestOutcome::Cancelled => {
                        if record_is_evaluating
                            || record.supervisor().pending_assessment().is_some()
                        {
                            let item = UnresolvedRequest::new(
                                request.attempt_id(),
                                UnresolvedRequestKind::TerminalObservedStateNotSaved,
                                request.purpose(),
                            );
                            push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                            block_reasons.push(RecoveryBlockReason::UnresolvedRequest {
                                attempt: request.attempt_id().to_string(),
                                classification: item.kind(),
                            });
                            unresolved_requests.push(item);
                        } else {
                            let reason = if record.state().blocks_completion()
                                || matches!(
                                    record.state(),
                                    SupervisionState::Completed
                                        | SupervisionState::Stopped
                                        | SupervisionState::Failed
                                        | SupervisionState::Cancelled
                                ) {
                                HistoryOnlyReason::DelayedAfterStateChange
                            } else {
                                HistoryOnlyReason::AlreadyApplied
                            };
                            history_only_requests.push(HistoryOnlyRequest::new(
                                request.attempt_id(),
                                observation.outcome(),
                                reason,
                            ));
                        }
                    }
                    RequestOutcome::PreflightFailed => {
                        history_only_requests.push(HistoryOnlyRequest::new(
                            request.attempt_id(),
                            observation.outcome(),
                            HistoryOnlyReason::DefinitelyNotSent,
                        ));
                    }
                },
            }
        }

        let unresolved_operations = snapshot
            .unresolved_operations()
            .iter()
            .filter(|operation| record.run_group().contains(&operation.run_id()))
            .cloned()
            .collect::<Vec<_>>();
        for operation in &unresolved_operations {
            block_reasons.push(RecoveryBlockReason::UnresolvedOperation {
                operation: operation.operation_id().to_owned(),
            });
            push_action(&mut required_actions, HumanAction::ReconcileRecovery);
        }

        let mut managed_processes = Vec::new();
        let mut checkpoint = None;
        let mut recovery_mode = None;
        if let Some(run) = current_run {
            managed_processes = self.runtime.managed_processes(run)?;
            for process in &managed_processes {
                if process.blocks_resume() {
                    block_reasons.push(RecoveryBlockReason::ManagedProcess {
                        run,
                        process: process.process_id().to_owned(),
                    });
                    push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                }
            }

            let mode = self.runtime.recovery_mode(run)?;
            recovery_mode = Some(mode);
            let status = self.runtime.checkpoint(run)?;
            match &status {
                RecoveryCheckpoint::Present => {}
                RecoveryCheckpoint::Missing => {
                    if mode == RecoveryMode::Restored && needs_checkpoint(record.state()) {
                        block_reasons.push(RecoveryBlockReason::CheckpointMissing { run });
                        push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                    }
                }
                RecoveryCheckpoint::Ambiguous(detail) => {
                    block_reasons.push(RecoveryBlockReason::CheckpointAmbiguous {
                        run,
                        detail: detail.clone(),
                    });
                    push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                }
            }
            checkpoint = Some(status);

            let run_state = self.runtime.run_state(run)?;
            let stop_state = self.runtime.stop_state(run)?;
            if stop_state == RecoveryStopState::Unconfirmed
                || run_state == RunState::Interrupted
                || matches!(
                    record.reason(),
                    crate::state::SupervisionReason::Stopped {
                        cause: StopCause::StopUnconfirmed
                    }
                )
            {
                block_reasons.push(RecoveryBlockReason::StopUnconfirmed { run: Some(run) });
                push_action(&mut required_actions, HumanAction::ReconcileRecovery);
            } else if matches!(run_state, RunState::Running | RunState::AwaitingApproval)
                && matches!(
                    record.state(),
                    SupervisionState::Stopped | SupervisionState::WaitingHuman
                )
            {
                block_reasons.push(RecoveryBlockReason::RunActive { run });
                push_action(&mut required_actions, HumanAction::ReconcileRecovery);
            }
        }

        let mut version_mismatches = Vec::new();
        if record.condition_version() != contract.conditions().condition_version() {
            version_mismatches.push(VersionMismatch::Conditions {
                record: record.condition_version(),
                approved: contract.conditions().condition_version(),
            });
        }
        let mut record_conditions = record.condition_ids().to_vec();
        let mut approved_conditions = contract.conditions().condition_ids();
        record_conditions.sort();
        approved_conditions.sort();
        let mut record_checks = record.required_checks().to_vec();
        let mut approved_checks = contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect::<Vec<_>>();
        record_checks.sort();
        approved_checks.sort();
        if record_conditions != approved_conditions || record_checks != approved_checks {
            version_mismatches.push(VersionMismatch::ConditionContent {
                record_conditions,
                approved_conditions,
                record_checks,
                approved_checks,
                approved_version: contract.conditions().condition_version(),
            });
        }
        if record.target_version() != contract.evidence_target().version() {
            version_mismatches.push(VersionMismatch::Target {
                record: record.target_version(),
                approved: contract.evidence_target().version(),
            });
        }
        if record.profile() != contract.profile() {
            version_mismatches.push(VersionMismatch::Profile);
        }
        if record.consent() != contract.consent() {
            version_mismatches.push(VersionMismatch::Consent);
        }
        if contract.conditions().require_approval(now).is_err() {
            version_mismatches.push(VersionMismatch::Approval);
        }
        if !record.state().is_terminal_without_completion()
            && record.state() != SupervisionState::Completed
            && !self.runtime.permissions_current(record)?
        {
            block_reasons.push(RecoveryBlockReason::PermissionsChanged);
            push_action(&mut required_actions, HumanAction::ReconcileRecovery);
        }
        if !budgets.report.policy_matches {
            version_mismatches.push(VersionMismatch::BudgetPolicy);
        }
        if !budgets.report.policy_version_matches {
            version_mismatches.push(VersionMismatch::BudgetPolicyVersion {
                record: budgets.stored_policy_version,
                approved: expected_policy_version,
            });
        }
        for mismatch in &version_mismatches {
            match mismatch {
                VersionMismatch::Conditions { .. } | VersionMismatch::ConditionContent { .. } => {
                    block_reasons.push(RecoveryBlockReason::ConditionsChanged);
                    push_action(&mut required_actions, HumanAction::ConfirmConditions);
                }
                VersionMismatch::Target { .. } => {
                    block_reasons.push(RecoveryBlockReason::TargetChanged);
                    push_action(&mut required_actions, HumanAction::ConfirmTarget);
                }
                VersionMismatch::Profile => {
                    block_reasons.push(RecoveryBlockReason::ProfileChanged);
                    push_action(&mut required_actions, HumanAction::ConfirmAssessmentProfile);
                }
                VersionMismatch::Consent => {
                    block_reasons.push(RecoveryBlockReason::ConsentChanged);
                    push_action(&mut required_actions, HumanAction::GrantDisclosureConsent);
                }
                VersionMismatch::BudgetPolicy | VersionMismatch::BudgetPolicyVersion { .. } => {
                    block_reasons.push(RecoveryBlockReason::BudgetChanged);
                    push_action(&mut required_actions, HumanAction::ReconcileRecovery);
                }
                VersionMismatch::Approval => {
                    block_reasons.push(RecoveryBlockReason::ApprovalInvalid);
                    push_action(&mut required_actions, HumanAction::ConfirmConditions);
                }
            }
        }

        let budget_report = budgets.report;
        if budgets.missing && !record.run_group().runs().is_empty() {
            block_reasons.push(RecoveryBlockReason::BudgetMissing);
            push_action(&mut required_actions, HumanAction::ReconcileRecovery);
        }
        for attempt in &budgets.unresolved {
            block_reasons.push(RecoveryBlockReason::UnresolvedBudgetCharge {
                attempt: attempt.to_string(),
            });
            push_action(&mut required_actions, HumanAction::ReconcileRecovery);
        }
        if !record.state().is_terminal_without_completion()
            && record.state() != SupervisionState::Completed
        {
            if !budget_report.can_start_run {
                block_reasons.push(RecoveryBlockReason::BudgetExhausted {
                    limit: BudgetLimit::RunCount,
                });
                push_action(&mut required_actions, HumanAction::ReconcileRecovery);
            } else if budget_report.remaining_active_seconds == 0 {
                block_reasons.push(RecoveryBlockReason::BudgetExhausted {
                    limit: BudgetLimit::ActiveSeconds,
                });
                push_action(&mut required_actions, HumanAction::ReconcileRecovery);
            }
        }

        let stale_completion = record.completion_stale().is_some();
        let disposition = if record.state() == SupervisionState::Completed {
            if stale_completion {
                RecoveryDisposition::CompletedStale
            } else {
                RecoveryDisposition::Completed
            }
        } else if record.state().is_terminal_without_completion() {
            RecoveryDisposition::Terminal
        } else if !block_reasons.is_empty() {
            if matches!(
                record.reason(),
                crate::state::SupervisionReason::Stopped {
                    cause: StopCause::StopUnconfirmed
                }
            ) || record.state() == SupervisionState::Stopped
                && block_reasons
                    .iter()
                    .any(|reason| matches!(reason, RecoveryBlockReason::StopUnconfirmed { .. }))
            {
                RecoveryDisposition::Stopped
            } else {
                RecoveryDisposition::WaitingHuman
            }
        } else if record.state() == SupervisionState::Stopped {
            RecoveryDisposition::Stopped
        } else {
            RecoveryDisposition::Recoverable
        };

        let resumable = matches!(
            record.state(),
            SupervisionState::Stopped | SupervisionState::WaitingHuman
        ) && block_reasons.is_empty();

        Ok(RecoveryReport {
            project_id: record.project_id(),
            supervision_id: record.supervision_id(),
            revision: record.revision(),
            state: record.state(),
            reason: record.reason().clone(),
            disposition,
            resumable,
            unresolved_requests,
            history_only_requests,
            unresolved_operations,
            managed_processes,
            checkpoint,
            recovery_mode,
            budget: budget_report,
            version_mismatches,
            block_reasons,
            required_actions,
            stale_completion,
            side_effects: RecoverySideEffects::zero(),
            notified: false,
        })
    }

    fn read_budget(
        &mut self,
        record: &SupervisionRecord,
        contract: &SupervisionContract,
        expected_policy_version: u64,
    ) -> Result<BudgetFacts, SupervisionError> {
        let stored = self
            .budget
            .load_recovery_budget(record.project_id(), record.supervision_id())?;
        let Some(stored) = stored else {
            return Ok(BudgetFacts {
                report: RecoveryBudgetReport::empty(contract.budget()),
                missing: true,
                stored_policy_version: 0,
                unresolved: Vec::new(),
            });
        };
        let record_value = stored.record();
        let reading = ClockReading::new(self.clock.now(), 0);
        let usage = record_value.effective_usage(reading);
        let stored_policy = record_value.policy();
        let remaining = usage.remaining_active_seconds(stored_policy);
        let can_start = usage.permits_run_start(stored_policy);
        let unresolved = record_value
            .money_reservations()
            .iter()
            .filter(|(_, reservation)| {
                matches!(
                    reservation.state(),
                    crate::budget::ledger::MoneyReservationState::Unresolved
                )
            })
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>();
        Ok(BudgetFacts {
            report: RecoveryBudgetReport {
                usage,
                remaining_active_seconds: remaining,
                can_start_run: can_start,
                unresolved_charges: unresolved.len(),
                policy_matches: stored_policy == contract.budget(),
                policy_version_matches: record_value.policy_version() == expected_policy_version,
            },
            missing: false,
            stored_policy_version: record_value.policy_version(),
            unresolved,
        })
    }
}

struct BudgetFacts {
    report: RecoveryBudgetReport,
    missing: bool,
    stored_policy_version: u64,
    unresolved: Vec<AttemptId>,
}

fn needs_checkpoint(state: SupervisionState) -> bool {
    matches!(
        state,
        SupervisionState::Stopped | SupervisionState::WaitingHuman
    )
}

fn push_action(actions: &mut Vec<HumanAction>, action: HumanAction) {
    if !actions.contains(&action) {
        actions.push(action);
    }
}

fn recovery_invalidation(mismatches: &[VersionMismatch]) -> Option<DecisionInvalidation> {
    match mismatches.first()? {
        VersionMismatch::Conditions { approved, .. } => {
            Some(DecisionInvalidation::ConditionsChanged { to: *approved })
        }
        VersionMismatch::ConditionContent {
            approved_version, ..
        } => Some(DecisionInvalidation::ConditionsChanged {
            to: *approved_version,
        }),
        VersionMismatch::Target { approved, .. } => {
            Some(DecisionInvalidation::TargetChanged { to: *approved })
        }
        VersionMismatch::Profile => Some(DecisionInvalidation::ProfileChanged),
        VersionMismatch::Consent => Some(DecisionInvalidation::ConsentChanged),
        VersionMismatch::BudgetPolicy
        | VersionMismatch::BudgetPolicyVersion { .. }
        | VersionMismatch::Approval => Some(DecisionInvalidation::LimitsChanged),
    }
}

fn recovery_request_id(
    project: ProjectId,
    supervision: SupervisionId,
    action: &str,
    discriminator: &str,
) -> SupervisionRequestId {
    SupervisionRequestId::from_parts(
        project,
        deterministic_uuid(&[
            "supervision.recovery",
            &supervision.to_string(),
            action,
            discriminator,
            &project.to_string(),
        ]),
    )
}

fn deterministic_uuid(parts: &[&str]) -> Uuid {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// One quit-mark outcome for a supervision record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitSupervisionMark {
    supervision_id: SupervisionId,
    state: SupervisionState,
    reason: crate::state::SupervisionReason,
    changed: bool,
}

impl QuitSupervisionMark {
    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// State after the quit mark.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Reason after the quit mark.
    pub fn reason(&self) -> &crate::state::SupervisionReason {
        &self.reason
    }

    /// Whether this call committed a new record revision.
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

/// Result of marking supervision records before process exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitSupervisionReport {
    marks: Vec<QuitSupervisionMark>,
    failed: u32,
}

impl QuitSupervisionReport {
    /// One mark per loaded record.
    pub fn marks(&self) -> &[QuitSupervisionMark] {
        &self.marks
    }

    /// Records whose compare-and-swap could not be committed.
    pub const fn failed(&self) -> u32 {
        self.failed
    }
}

/// Marks active supervision records for quit without resuming or claiming a
/// stop that H1 did not confirm.
///
/// `stop_facts` maps each current run to whether H1 confirmed its coordinated
/// stop. A missing fact is treated as unconfirmed. Terminal records are left
/// unchanged. The hook never starts a run, sends a request, or executes a tool.
pub fn mark_active_supervision_for_quit(
    store: &mut dyn SupervisionStorePort,
    clock: &dyn ClockPort,
    records: impl IntoIterator<Item = SupervisionRecord>,
    stop_facts: &BTreeMap<RunId, bool>,
) -> Result<QuitSupervisionReport, SupervisionError> {
    let mut marks = Vec::new();
    let mut failed = 0u32;
    for supplied in records {
        let Some(current) = store.load(supplied.project_id(), supplied.supervision_id())? else {
            continue;
        };
        if matches!(
            current.state(),
            SupervisionState::Completed
                | SupervisionState::Stopped
                | SupervisionState::Failed
                | SupervisionState::Cancelled
        ) {
            marks.push(QuitSupervisionMark {
                supervision_id: current.supervision_id(),
                state: current.state(),
                reason: current.reason().clone(),
                changed: false,
            });
            continue;
        }
        let run = current
            .supervisor()
            .current_run()
            .or_else(|| current.run_group().runs().last().copied());
        let confirmed = run.is_none_or(|run| stop_facts.get(&run).copied().unwrap_or(false));
        let cause = if confirmed {
            StopCause::RecoveryReconciliation
        } else {
            StopCause::StopUnconfirmed
        };
        let mut next = current.clone();
        next.stop(cause)?;
        next.supervisor_mut().phase = crate::supervisor::SupervisorPhase::Finished;
        next.supervisor_mut().pending_assessment = None;
        next.set_command_revision(current.revision().saturating_add(1));
        let request_id = recovery_request_id(
            current.project_id(),
            current.supervision_id(),
            "quit-stop",
            &current.revision().to_string(),
        );
        let result = CommandResult::new(
            request_id,
            current.project_id(),
            current.supervision_id(),
            SupervisionCommand::Stop,
            next.revision(),
            next.state(),
            next.reason().clone(),
        )?;
        match store.commit_command(
            current.project_id(),
            current.supervision_id(),
            Some(current.revision()),
            &next,
            &result,
        ) {
            Ok(_) => marks.push(QuitSupervisionMark {
                supervision_id: next.supervision_id(),
                state: next.state(),
                reason: next.reason().clone(),
                changed: true,
            }),
            Err(SupervisionError::RevisionConflict { .. }) => {
                failed = failed.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
        let _ = clock.now();
    }
    Ok(QuitSupervisionReport { marks, failed })
}
