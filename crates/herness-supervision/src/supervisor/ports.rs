//! Side-effect boundaries used by the deterministic supervisor.
//!
//! The supervisor never calls H1, H2 assessment adapters, a database, or the
//! Tauri owner directly. Each port below is implemented by a composition layer
//! (Task 16) or by a deterministic fake in tests. Request values carry only
//! project-scoped IDs, versions, host-generated deficiency text, and evidence
//! IDs; no provider body, credential, or conversation text is part of them.

use herness_core::contracts::{InputId, InputProgress, ProjectId, RunId, RunState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::assessment::{AssessmentRequest, AssessmentResult};
use crate::budget::ledger::BudgetClockPort;
use crate::budget::ledger::BudgetLedger;
use crate::conditions::{Condition, ConditionVersion};
use crate::consent::ConsentBinding;
use crate::error::SupervisionError;
use crate::evidence::{
    CheckStatus, EvidenceRecord, RequiredCheckResult, TargetVersion, VerificationOperation,
};
use crate::freshness::{TargetManifest, TargetReadSet, WorkspaceSnapshotPort};
use crate::ids::{
    BudgetRequestId, CheckId, ConditionId, EvidenceId, SupervisionId, SupervisionRequestId,
};
use crate::ports::{BudgetStorePort, ClockPort, EvidenceStorePort, SupervisionStorePort};
use crate::profiles::{AdapterVersion, ProfileBinding, ProfileThresholds, RubricVersion};
use crate::state::{SupervisionReason, SupervisionState};

/// H1-owned runtime operations needed by one supervisor.
///
/// Start and continuation requests name the run and input IDs the supervisor
/// already persisted, so a repeated request with the same ID can be answered
/// without starting a second run. The runtime implementation must use the same
/// child agent/session and the unchanged approved execution scope.
pub trait SupervisionRuntimePort {
    /// Starts the first child run and submits its initial input.
    fn start_child(&mut self, request: &ChildRunStart) -> Result<(), SupervisionError>;

    /// Starts one additional run in the same child conversation.
    fn continue_child(&mut self, request: &ChildRunContinuation) -> Result<(), SupervisionError>;

    /// Reads the acceptance/start/completion correspondence of one input.
    fn input_progress(&mut self, input_id: InputId) -> Result<InputProgress, SupervisionError>;

    /// Reads the current H1 run state.
    fn run_state(&mut self, run_id: RunId) -> Result<RunState, SupervisionError>;

    /// Requests a cooperative stop and reports whether H1 confirmed it.
    fn request_stop(&mut self, run_id: RunId) -> Result<StopDisposition, SupervisionError>;

    /// Captures the current bounded target manifest.
    fn target_snapshot(
        &mut self,
        request: &TargetSnapshotRequest,
    ) -> Result<TargetManifest, SupervisionError>;
}

/// One first-run start intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildRunStart {
    request_id: SupervisionRequestId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    run_id: RunId,
    input_id: InputId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    consent: ConsentBinding,
    instruction: Option<String>,
}

impl ChildRunStart {
    /// Creates one start intent. IDs must be allocated by the supervisor and
    /// persisted before this value is sent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: SupervisionRequestId,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        run_id: RunId,
        input_id: InputId,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        profile: ProfileBinding,
        consent: ConsentBinding,
        instruction: Option<String>,
    ) -> Self {
        Self {
            request_id,
            project_id,
            supervision_id,
            run_id,
            input_id,
            condition_version,
            target_version,
            profile,
            consent,
            instruction,
        }
    }

    /// Stable runtime request ID.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// New run.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// New input.
    pub const fn input_id(&self) -> InputId {
        self.input_id
    }

    /// Fixed condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Fixed target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Fixed assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed disclosure consent.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Owner-supplied initial instruction, when any.
    pub fn instruction(&self) -> Option<&str> {
        self.instruction.as_deref()
    }
}

/// One additional-run continuation intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildRunContinuation {
    request_id: SupervisionRequestId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    previous_run_id: RunId,
    run_id: RunId,
    input_id: InputId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    consent: ConsentBinding,
    deficiency: ContinuationDeficiency,
}

impl ChildRunContinuation {
    /// Creates one continuation intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: SupervisionRequestId,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        previous_run_id: RunId,
        run_id: RunId,
        input_id: InputId,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        profile: ProfileBinding,
        consent: ConsentBinding,
        deficiency: ContinuationDeficiency,
    ) -> Self {
        Self {
            request_id,
            project_id,
            supervision_id,
            previous_run_id,
            run_id,
            input_id,
            condition_version,
            target_version,
            profile,
            consent,
            deficiency,
        }
    }

    /// Stable runtime request ID.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Run whose conversation is continued.
    pub const fn previous_run_id(&self) -> RunId {
        self.previous_run_id
    }

    /// New run identifier.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// New input identifier.
    pub const fn input_id(&self) -> InputId {
        self.input_id
    }

    /// Unchanged condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Unchanged target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Unchanged assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Unchanged disclosure consent.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Host-generated deficiency and evidence to return to the child.
    pub const fn deficiency(&self) -> &ContinuationDeficiency {
        &self.deficiency
    }
}

/// Non-secret correction content sent to the same child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContinuationDeficiency {
    instruction: String,
    failed_checks: Vec<FailedCheck>,
    unmet_conditions: Vec<ConditionId>,
    evidence: Vec<EvidenceId>,
}

impl ContinuationDeficiency {
    /// Creates a deficiency from explicit host observations.
    pub fn new(
        instruction: impl AsRef<str>,
        failed_checks: Vec<FailedCheck>,
        unmet_conditions: Vec<ConditionId>,
        evidence: Vec<EvidenceId>,
    ) -> Result<Self, SupervisionError> {
        let instruction = instruction.as_ref().trim();
        if instruction.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "continuation.instruction".to_owned(),
                detail: "a continuation needs a non-empty deficiency".to_owned(),
            });
        }
        if instruction.chars().count() > 4_000 {
            return Err(SupervisionError::InvalidValue {
                field: "continuation.instruction".to_owned(),
                detail: "must contain at most 4000 characters".to_owned(),
            });
        }
        Ok(Self {
            instruction: instruction.to_owned(),
            failed_checks,
            unmet_conditions,
            evidence,
        })
    }

    /// Host-generated correction instruction.
    pub fn instruction(&self) -> &str {
        &self.instruction
    }

    /// Required checks that did not pass.
    pub fn failed_checks(&self) -> &[FailedCheck] {
        &self.failed_checks
    }

    /// Conditions still unmet.
    pub fn unmet_conditions(&self) -> &[ConditionId] {
        &self.unmet_conditions
    }

    /// Evidence the child should inspect.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }
}

/// One non-passing required check in a continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailedCheck {
    check_id: CheckId,
    status: CheckStatus,
    evidence_id: Option<EvidenceId>,
}

impl FailedCheck {
    /// Creates one non-passing check description.
    pub const fn new(
        check_id: CheckId,
        status: CheckStatus,
        evidence_id: Option<EvidenceId>,
    ) -> Self {
        Self {
            check_id,
            status,
            evidence_id,
        }
    }

    /// Check identifier.
    pub const fn check_id(&self) -> CheckId {
        self.check_id
    }

    /// Distinguished non-passing status.
    pub const fn status(&self) -> CheckStatus {
        self.status
    }

    /// Evidence recorded for the attempt, when any.
    pub const fn evidence_id(&self) -> Option<EvidenceId> {
        self.evidence_id
    }
}

/// Result of one cooperative stop request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopDisposition {
    /// H1 confirmed that the run is stopped or idle.
    Confirmed,
    /// H1 could not confirm the stop. No new run or reassessment may start.
    Unconfirmed,
}

/// Bounded target snapshot request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSnapshotRequest {
    project_id: ProjectId,
    supervision_id: SupervisionId,
    target_version: TargetVersion,
    read_set: Vec<String>,
}

impl TargetSnapshotRequest {
    /// Creates a request for one approved target version and read set.
    pub fn new(
        project_id: ProjectId,
        supervision_id: SupervisionId,
        target_version: TargetVersion,
        read_set: Vec<String>,
    ) -> Self {
        Self {
            project_id,
            supervision_id,
            target_version,
            read_set,
        }
    }

    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Target version to record in the manifest.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Approved bounded read-set paths.
    pub fn read_set(&self) -> &[String] {
        &self.read_set
    }
}

/// One H1-authorized required-check execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckExecutionRequest {
    project_id: ProjectId,
    supervision_id: SupervisionId,
    condition_id: ConditionId,
    check_id: CheckId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    evidence_id: EvidenceId,
    sequence: u64,
    operation: VerificationOperation,
    read_set: Vec<String>,
}

impl CheckExecutionRequest {
    /// Creates one exact check execution request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        supervision_id: SupervisionId,
        condition_id: ConditionId,
        check_id: CheckId,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        evidence_id: EvidenceId,
        sequence: u64,
        operation: VerificationOperation,
        read_set: Vec<String>,
    ) -> Self {
        Self {
            project_id,
            supervision_id,
            condition_id,
            check_id,
            condition_version,
            target_version,
            evidence_id,
            sequence,
            operation,
            read_set,
        }
    }

    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Condition this check supports.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Required check.
    pub const fn check_id(&self) -> CheckId {
        self.check_id
    }

    /// Fixed condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Fixed target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Evidence identifier to write.
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    /// Next project evidence sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Exact command or equivalent operation.
    pub const fn operation(&self) -> &VerificationOperation {
        &self.operation
    }

    /// Approved bounded read set.
    pub fn read_set(&self) -> &[String] {
        &self.read_set
    }
}

/// Result of one required-check execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckExecution {
    result: RequiredCheckResult,
    evidence: Option<EvidenceRecord>,
}

impl CheckExecution {
    /// Creates an execution outcome. A passing result requires evidence.
    pub fn new(result: RequiredCheckResult, evidence: Option<EvidenceRecord>) -> Self {
        Self { result, evidence }
    }

    /// Distinguished check result.
    pub const fn result(&self) -> &RequiredCheckResult {
        &self.result
    }

    /// Evidence recorded for the attempt.
    pub const fn evidence(&self) -> Option<&EvidenceRecord> {
        self.evidence.as_ref()
    }
}

/// H1-owned authorization and execution boundary for required checks.
pub trait RequiredCheckPort {
    /// Executes one check only through the H1 permission boundary.
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError>;
}

/// Profile facts the supervisor needs to build an exact assessment request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProfileFacts {
    adapter_version: AdapterVersion,
    rubric_version: RubricVersion,
    thresholds: ProfileThresholds,
}

impl AssessmentProfileFacts {
    /// Creates profile facts for one fixed binding.
    pub const fn new(
        adapter_version: AdapterVersion,
        rubric_version: RubricVersion,
        thresholds: ProfileThresholds,
    ) -> Self {
        Self {
            adapter_version,
            rubric_version,
            thresholds,
        }
    }

    /// Adapter implementation version.
    pub const fn adapter_version(&self) -> &AdapterVersion {
        &self.adapter_version
    }

    /// Rubric version.
    pub const fn rubric_version(&self) -> &RubricVersion {
        &self.rubric_version
    }

    /// Adoption thresholds.
    pub const fn thresholds(&self) -> ProfileThresholds {
        self.thresholds
    }
}

/// Per-condition, tool-free assessment boundary.
pub trait ConditionAssessmentPort {
    /// Whether a condition needs a semantic model judgment.
    ///
    /// The default is conservative: every condition is assessed. A host that
    /// has an approved deterministic condition may return false; the
    /// supervisor then requires every required check of that condition to pass
    /// with applicable evidence and records the host-owned result without a
    /// model request.
    fn requires_assessment(&self, _condition: &Condition) -> bool {
        true
    }

    /// Resolves the exact facts of a fixed profile binding. No fallback exists.
    fn profile(&self, binding: ProfileBinding) -> Result<AssessmentProfileFacts, SupervisionError>;

    /// Runs one already-persisted condition assessment request.
    fn assess(&mut self, request: &AssessmentRequest)
    -> Result<AssessmentResult, SupervisionError>;
}

/// Budget operations the controller may perform.
///
/// The concrete durable [`BudgetLedger`] implements this trait. The supervisor
/// cannot reset consumed runs or active seconds through this boundary.
pub trait SupervisionBudgetPort {
    /// Remaining active seconds after charging the open interval.
    fn remaining_active_seconds(&mut self) -> Result<u64, SupervisionError>;

    /// Whether one more run is permitted under the finite run cap.
    fn can_start_run(&mut self) -> Result<bool, SupervisionError>;

    /// Consumes one run count and makes the ledger active.
    fn start_run(&mut self, request: BudgetRequestId) -> Result<(), SupervisionError>;

    /// Marks one started run finished without refunding it.
    fn finish_run(&mut self, request: BudgetRequestId) -> Result<(), SupervisionError>;

    /// Excludes human-waiting time from the active budget.
    fn wait_for_human(&mut self) -> Result<(), SupervisionError>;

    /// Stops active-time accrual for a terminal state.
    fn app_stop(&mut self) -> Result<(), SupervisionError>;
}

impl<S: BudgetStorePort, C: BudgetClockPort> SupervisionBudgetPort for BudgetLedger<S, C> {
    fn remaining_active_seconds(&mut self) -> Result<u64, SupervisionError> {
        BudgetLedger::remaining_active_seconds(self)
    }

    fn can_start_run(&mut self) -> Result<bool, SupervisionError> {
        let policy = self.record().policy().clone();
        let usage = self.effective_usage()?;
        Ok(usage.permits_run_start(&policy))
    }

    fn start_run(&mut self, request: BudgetRequestId) -> Result<(), SupervisionError> {
        BudgetLedger::start_run(self, request).map(|_| ())
    }

    fn finish_run(&mut self, request: BudgetRequestId) -> Result<(), SupervisionError> {
        BudgetLedger::finish_run(self, request).map(|_| ())
    }

    fn wait_for_human(&mut self) -> Result<(), SupervisionError> {
        BudgetLedger::wait_for_human(self)
    }

    fn app_stop(&mut self) -> Result<(), SupervisionError> {
        BudgetLedger::app_stop(self)
    }
}

/// One owner-facing, non-secret notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisorNotification {
    notification_id: String,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    revision: u64,
    state: SupervisionState,
    reason: SupervisionReason,
    unmet_conditions: Vec<ConditionId>,
    observed_at: Timestamp,
}

impl SupervisorNotification {
    /// Creates one idempotency-keyed notification.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        supervision_id: SupervisionId,
        revision: u64,
        state: SupervisionState,
        reason: SupervisionReason,
        unmet_conditions: Vec<ConditionId>,
        observed_at: Timestamp,
    ) -> Self {
        let notification_id = format!(
            "supervision:{}:{}:{}:{}",
            project_id, supervision_id, revision, state
        );
        Self {
            notification_id,
            project_id,
            supervision_id,
            revision,
            state,
            reason,
            unmet_conditions,
            observed_at,
        }
    }

    /// Stable idempotency key.
    pub fn notification_id(&self) -> &str {
        &self.notification_id
    }

    /// Project owner.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Stored revision that was committed before this notification.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Committed state.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Committed reason.
    pub const fn reason(&self) -> &SupervisionReason {
        &self.reason
    }

    /// Conditions still unmet.
    pub fn unmet_conditions(&self) -> &[ConditionId] {
        &self.unmet_conditions
    }

    /// When the notification was created.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
}

/// Owner notification boundary.
pub trait OwnerNotificationPort {
    /// Delivers one notification after the state has been committed.
    fn notify(&mut self, notification: &SupervisorNotification) -> Result<(), SupervisionError>;
}

/// All side-effect boundaries for one controller tick.
pub struct SupervisorPorts<'a> {
    /// H1 runtime control.
    pub runtime: &'a mut dyn SupervisionRuntimePort,
    /// H1-authorized required-check execution.
    pub checks: &'a mut dyn RequiredCheckPort,
    /// Tool-free per-condition assessment.
    pub assessment: &'a mut dyn ConditionAssessmentPort,
    /// Durable evidence records.
    pub evidence: &'a mut dyn EvidenceStorePort,
    /// Durable supervision records and the idempotent command journal.
    pub store: &'a mut dyn SupervisionStorePort,
    /// Durable budget ledger.
    pub budget: &'a mut dyn SupervisionBudgetPort,
    /// Host clock.
    pub clock: &'a dyn ClockPort,
    /// Owner notification.
    pub notifications: &'a mut dyn OwnerNotificationPort,
}

/// Convenience constructors used by the composition layer and tests.
pub fn target_read_set_from_manifest(read_set: &[String]) -> TargetReadSet {
    TargetReadSet::Declared(read_set.to_vec())
}

/// Captures a bounded manifest from an injected workspace reader.
///
/// This helper exists so hosts and tests can implement
/// [`SupervisionRuntimePort::target_snapshot`] without reimplementing the
/// existing Task 5 freshness rules.
pub fn capture_target_snapshot<W: WorkspaceSnapshotPort + ?Sized>(
    workspace: &W,
    request: &TargetSnapshotRequest,
) -> Result<TargetManifest, SupervisionError> {
    crate::freshness::capture_manifest(
        workspace,
        request.project_id(),
        request.target_version(),
        target_read_set_from_manifest(request.read_set()),
    )
}
