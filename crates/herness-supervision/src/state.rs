//! H2 supervision state, reasons, unmet conditions, and completion priority.
//!
//! These values are separate from H1 run states. A `completed` supervision
//! record means every approved condition was met for the recorded snapshot.
//! Stopped, human-waiting, limit-reached, and unrecoverable states take priority
//! over completion.

use serde::{Deserialize, Serialize};

use herness_core::contracts::{ContractVersion, ProjectId, RunId, Timestamp};

use crate::approval::ApprovalActor;
use crate::assessment::{AssessmentResult, ConditionVerdict};
use crate::budget::{BudgetLimit, BudgetUsage};
use crate::conditions::ConditionVersion;
use crate::consent::ConsentBinding;
use crate::contract::{RunGroup, SupervisionContract};
use crate::error::SupervisionError;
use crate::evidence::{ContentDigest, TargetVersion};
use crate::ids::{CheckId, ConditionId, EvidenceId, SupervisionId, verify_core_id, verify_scoped};
use crate::profiles::{ProfileBinding, ProfileThresholds};
use crate::supervisor::SupervisorState;
use crate::version::current_contract_version;

/// State of one supervised child-agent effort.
///
/// The H1 run states remain unchanged and separate. A supervision state may be
/// `running` while the current H1 run is `idle`, and an H1 `idle` never means
/// completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionState {
    /// Approved conditions and budget are ready; no run is active.
    Ready,
    /// An initial or additional child run is active.
    Running,
    /// Required checks are running against a stable target.
    Verifying,
    /// Condition assessments are in flight.
    Assessing,
    /// A human action is required before progress.
    WaitingHuman,
    /// Stopped by a human, stagnation, budget, unconfirmed stop, or recovery
    /// reconciliation. The cause must be resolved before resuming.
    Stopped,
    /// Unrecoverable failure. Not completion.
    Failed,
    /// Explicitly cancelled. Not completion.
    Cancelled,
    /// Every approved condition was met for the recorded snapshot.
    Completed,
}

impl SupervisionState {
    /// Every H2 state.
    pub const ALL: [Self; 9] = [
        Self::Ready,
        Self::Running,
        Self::Verifying,
        Self::Assessing,
        Self::WaitingHuman,
        Self::Stopped,
        Self::Failed,
        Self::Cancelled,
        Self::Completed,
    ];

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
        }
    }

    /// Whether this state takes priority over a completion decision.
    pub const fn blocks_completion(self) -> bool {
        matches!(
            self,
            Self::WaitingHuman | Self::Stopped | Self::Failed | Self::Cancelled
        )
    }

    /// Whether this is a terminal non-completed state.
    pub const fn is_terminal_without_completion(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }
}

impl std::fmt::Display for SupervisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Human action required in `waiting_human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanAction {
    /// Approve or deny a tool operation.
    ApproveOperation,
    /// Confirm a changed condition set.
    ConfirmConditions,
    /// Confirm a changed assessment profile.
    ConfirmAssessmentProfile,
    /// Confirm a changed target scope.
    ConfirmTarget,
    /// Grant or renew disclosure consent.
    GrantDisclosureConsent,
    /// Re-authenticate a connection.
    Reauthenticate,
    /// Decide an assessment the model could not decide.
    DecideAssessment,
    /// Reconcile an unknown request or recovery state.
    ReconcileRecovery,
}

/// Why supervision stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCause {
    /// A human requested the stop.
    UserRequest,
    /// Three consecutive evaluation cycles made no progress.
    Stagnation,
    /// A finite budget limit was reached.
    Budget(BudgetLimit),
    /// A managed process or engine stop was not confirmed.
    StopUnconfirmed,
    /// Recovery requires reconciliation before any new run.
    RecoveryReconciliation,
}

/// Unrecoverable failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionFailure {
    /// The required verification path is unavailable.
    VerificationUnavailable,
    /// The assessment path is unavailable and cannot be retried.
    AssessmentUnavailable,
    /// The current target or conversation cannot be assessed safely.
    TargetUnstable,
    /// Recovery found state that cannot be reconciled safely.
    UnrecoverableRecovery,
}

/// Why supervision was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelCause {
    /// A human cancelled the supervision target.
    UserRequest,
}

/// Current state reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SupervisionReason {
    /// Approved and waiting to start.
    AwaitingStart,
    /// A child run is active.
    RunActive {
        /// Run currently active.
        run: RunId,
    },
    /// Required checks are running.
    Verifying {
        /// Checks in flight.
        checks: Vec<CheckId>,
    },
    /// Condition assessments are running.
    Assessing {
        /// Conditions in flight.
        conditions: Vec<ConditionId>,
    },
    /// A human action is required.
    WaitingHuman {
        /// Required action.
        action: HumanAction,
    },
    /// Stopped for a structured cause.
    Stopped {
        /// Stop cause.
        cause: StopCause,
    },
    /// Unrecoverable failure.
    Failed {
        /// Failure category.
        failure: SupervisionFailure,
    },
    /// Explicit cancellation.
    Cancelled {
        /// Cancellation cause.
        cause: CancelCause,
    },
    /// Completed against a fixed snapshot.
    Completed {
        /// Completion snapshot.
        snapshot: CompletionSnapshot,
    },
    /// Conditions changed and require human or approved-owner confirmation.
    ConditionsChanged {
        /// Previous version.
        from: ConditionVersion,
        /// New version.
        to: ConditionVersion,
    },
    /// The target snapshot changed and requires re-verification.
    TargetChanged {
        /// Previous version.
        from: TargetVersion,
        /// New version.
        to: TargetVersion,
    },
}

impl SupervisionReason {
    /// State this reason describes.
    pub const fn state(&self) -> SupervisionState {
        match self {
            Self::AwaitingStart => SupervisionState::Ready,
            Self::RunActive { .. } => SupervisionState::Running,
            Self::Verifying { .. } => SupervisionState::Verifying,
            Self::Assessing { .. } => SupervisionState::Assessing,
            Self::WaitingHuman { .. }
            | Self::ConditionsChanged { .. }
            | Self::TargetChanged { .. } => SupervisionState::WaitingHuman,
            Self::Stopped { .. } => SupervisionState::Stopped,
            Self::Failed { .. } => SupervisionState::Failed,
            Self::Cancelled { .. } => SupervisionState::Cancelled,
            Self::Completed { .. } => SupervisionState::Completed,
        }
    }

    /// Stable wire label.
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::AwaitingStart => "awaiting_start",
            Self::RunActive { .. } => "run_active",
            Self::Verifying { .. } => "verifying",
            Self::Assessing { .. } => "assessing",
            Self::WaitingHuman { .. } => "waiting_human",
            Self::Stopped { .. } => "stopped",
            Self::Failed { .. } => "failed",
            Self::Cancelled { .. } => "cancelled",
            Self::Completed { .. } => "completed",
            Self::ConditionsChanged { .. } => "conditions_changed",
            Self::TargetChanged { .. } => "target_changed",
        }
    }
}

/// Fixed snapshot that a completion claim covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionSnapshot {
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    consent: ConsentBinding,
    verified_checks: Vec<CheckId>,
    evidence: Vec<EvidenceId>,
    observation_digest: ContentDigest,
    completed_at: Timestamp,
}

impl CompletionSnapshot {
    /// Creates a non-empty completion snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        profile: ProfileBinding,
        consent: ConsentBinding,
        verified_checks: Vec<CheckId>,
        evidence: Vec<EvidenceId>,
        observation_digest: ContentDigest,
        completed_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        if evidence.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "completion.evidence".to_owned(),
                detail: "a completion snapshot must cite evidence".to_owned(),
            });
        }
        Ok(Self {
            condition_version,
            target_version,
            profile,
            consent,
            verified_checks,
            evidence,
            observation_digest,
            completed_at,
        })
    }

    /// Condition version covered.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Target version covered.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Fixed profile covered.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed consent covered.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Required checks that passed.
    pub fn verified_checks(&self) -> &[CheckId] {
        &self.verified_checks
    }

    /// Evidence cited.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }

    /// Digest of the observed input set.
    pub fn observation_digest(&self) -> &ContentDigest {
        &self.observation_digest
    }

    /// When completion was confirmed.
    pub const fn completed_at(&self) -> Timestamp {
        self.completed_at
    }
}

/// A related input change observed after completion.
///
/// The completed state and its recorded snapshot are retained. This value only
/// marks that the snapshot no longer applies to the current project inputs. It
/// never starts a new run, resumes supervision, or reverses the completion
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaleCompletion {
    previous_target_version: TargetVersion,
    current_target_version: TargetVersion,
    changed_paths: Vec<String>,
    affected_evidence: Vec<EvidenceId>,
    observed_at: Timestamp,
}

impl StaleCompletion {
    /// Creates a stale-snapshot marker for related input changes.
    pub fn new(
        previous_target_version: TargetVersion,
        current_target_version: TargetVersion,
        changed_paths: Vec<String>,
        affected_evidence: Vec<EvidenceId>,
        observed_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        if changed_paths.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "staleCompletion.changedPaths".to_owned(),
                detail: "a stale snapshot requires at least one changed input".to_owned(),
            });
        }
        Ok(Self {
            previous_target_version,
            current_target_version,
            changed_paths,
            affected_evidence,
            observed_at,
        })
    }

    /// Target version the completion snapshot covered.
    pub const fn previous_target_version(&self) -> TargetVersion {
        self.previous_target_version
    }

    /// Target version observed now.
    pub const fn current_target_version(&self) -> TargetVersion {
        self.current_target_version
    }

    /// Changed input paths that no longer match the snapshot.
    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    /// Evidence whose applicability was lost.
    pub fn affected_evidence(&self) -> &[EvidenceId] {
        &self.affected_evidence
    }

    /// When the change was observed.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
}

/// A higher-priority condition that blocks completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CompletionBlocker {
    /// The supervision state itself blocks completion.
    State {
        /// Current state.
        state: SupervisionState,
    },
    /// A human action is pending.
    HumanAction {
        /// Required action.
        action: HumanAction,
    },
    /// A finite budget limit was reached.
    Limit {
        /// Reached limit.
        limit: BudgetLimit,
    },
    /// Supervision is stopped for another cause.
    Stopped {
        /// Stop cause.
        cause: StopCause,
    },
    /// Supervision failed unrecoverably.
    Unrecoverable {
        /// Failure category.
        failure: SupervisionFailure,
    },
    /// Approved conditions are still unmet.
    UnmetConditions {
        /// Unmet condition IDs.
        conditions: Vec<ConditionId>,
    },
    /// The supplied completion snapshot is for stale versions.
    StaleSnapshot,
    /// Required verification checks are not present in the completion snapshot.
    RequiredChecksNotPassed {
        /// Missing required checks.
        checks: Vec<CheckId>,
    },
    /// No completion snapshot was supplied.
    MissingSnapshot,
}

/// One decision applied to the current record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedDecision {
    condition_id: ConditionId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    verdict: ConditionVerdict,
    evidence: Vec<EvidenceId>,
}

impl AppliedDecision {
    /// Condition the decision belongs to.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Applied verdict. `Insufficient` is never applied.
    pub const fn verdict(&self) -> ConditionVerdict {
        self.verdict
    }

    /// Condition version applied.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Target version applied.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Evidence cited.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }
}

/// Why an old decision was invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum DecisionInvalidation {
    /// The condition version changed.
    ConditionsChanged {
        /// New version.
        to: ConditionVersion,
    },
    /// The target version changed.
    TargetChanged {
        /// New version.
        to: TargetVersion,
    },
    /// The assessment profile changed.
    ProfileChanged,
    /// The disclosure consent changed or was revoked.
    ConsentChanged,
    /// The finite budget policy or its version changed.
    LimitsChanged,
    /// An approved owner replaced the generation for a newer target snapshot.
    GenerationSuperseded {
        /// New target version.
        to: TargetVersion,
    },
}

/// A decision preserved only as history after a version change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvalidatedDecision {
    decision: AppliedDecision,
    invalidation: DecisionInvalidation,
}

impl InvalidatedDecision {
    /// Decision preserved for history.
    pub fn decision(&self) -> &AppliedDecision {
        &self.decision
    }

    /// Why it no longer applies.
    pub const fn invalidation(&self) -> DecisionInvalidation {
        self.invalidation
    }
}

/// Kind of an explicit supervision version/limit change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Completion conditions and required checks.
    Conditions,
    /// Evidence target version.
    Target,
    /// Assessment or permission profile.
    Profile,
    /// Disclosure consent.
    Consent,
    /// Finite budget policy or its version.
    Budget,
    /// Execution scope / permission description.
    Permissions,
    /// Approved-owner generation replacement within the same target.
    Supersede,
}

impl ChangeKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conditions => "conditions",
            Self::Target => "target",
            Self::Profile => "profile",
            Self::Consent => "consent",
            Self::Budget => "budget",
            Self::Permissions => "permissions",
            Self::Supersede => "supersede",
        }
    }
}

/// One explicit version/limit change preserved with the record.
///
/// The before/after fields are opaque, non-secret host labels. Budget usage is
/// copied before and after so a later reader can see that consumed budget was
/// never reset by the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisionChangeRecord {
    kind: ChangeKind,
    actor: ApprovalActor,
    before: String,
    after: String,
    budget_before: BudgetUsage,
    budget_after: BudgetUsage,
    changed_at: Timestamp,
}

impl SupervisionChangeRecord {
    /// Creates one recorded change.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ChangeKind,
        actor: ApprovalActor,
        before: impl Into<String>,
        after: impl Into<String>,
        budget_before: BudgetUsage,
        budget_after: BudgetUsage,
        changed_at: Timestamp,
    ) -> Self {
        Self {
            kind,
            actor,
            before: before.into(),
            after: after.into(),
            budget_before,
            budget_after,
            changed_at,
        }
    }

    /// Kind of change.
    pub const fn kind(&self) -> ChangeKind {
        self.kind
    }

    /// Actor that requested the change.
    pub fn actor(&self) -> &ApprovalActor {
        &self.actor
    }

    /// Non-secret before label.
    pub fn before(&self) -> &str {
        &self.before
    }

    /// Non-secret after label.
    pub fn after(&self) -> &str {
        &self.after
    }

    /// Budget usage before the change.
    pub const fn budget_before(&self) -> BudgetUsage {
        self.budget_before
    }

    /// Budget usage after the change.
    pub const fn budget_after(&self) -> BudgetUsage {
        self.budget_after
    }

    /// When the change was committed.
    pub const fn changed_at(&self) -> Timestamp {
        self.changed_at
    }
}

/// Outcome of applying one assessment result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentApplication {
    /// The decision was applied to the current record.
    Applied,
    /// The result was insufficient or uncertain and was not applied.
    NotDecided,
    /// The result was for stale versions/profile and was kept only as history.
    Stale,
}

/// Durable supervision state for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisionRecord {
    contract_version: ContractVersion,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    revision: u64,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    consent: ConsentBinding,
    run_group: RunGroup,
    condition_ids: Vec<ConditionId>,
    required_checks: Vec<CheckId>,
    state: SupervisionState,
    reason: SupervisionReason,
    unmet_conditions: Vec<ConditionId>,
    applied_decisions: Vec<AppliedDecision>,
    invalidated_decisions: Vec<InvalidatedDecision>,
    completion: Option<CompletionSnapshot>,
    #[serde(default)]
    completion_stale: Option<StaleCompletion>,
    #[serde(default)]
    supervisor: SupervisorState,
    #[serde(default)]
    change_log: Vec<SupervisionChangeRecord>,
}

impl SupervisionRecord {
    /// Creates a ready record from an approved contract.
    pub fn new(contract: &SupervisionContract) -> Self {
        let condition_ids = contract.conditions().condition_ids();
        let required_checks = contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect();
        Self {
            contract_version: current_contract_version(),
            project_id: contract.project_id(),
            supervision_id: contract.subject().supervision_id(),
            revision: 1,
            condition_version: contract.conditions().condition_version(),
            target_version: contract.evidence_target().version(),
            profile: contract.profile(),
            consent: contract.consent(),
            run_group: contract.run_group().clone(),
            unmet_conditions: condition_ids.clone(),
            condition_ids,
            required_checks,
            state: SupervisionState::Ready,
            reason: SupervisionReason::AwaitingStart,
            applied_decisions: Vec::new(),
            invalidated_decisions: Vec::new(),
            completion: None,
            completion_stale: None,
            supervisor: SupervisorState::default(),
            change_log: Vec::new(),
        }
    }

    /// Contract version.
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Current compare-and-set revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Current condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Current target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Fixed profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed consent.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Run group.
    pub fn run_group(&self) -> &RunGroup {
        &self.run_group
    }

    /// Current state.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Current reason.
    pub fn reason(&self) -> &SupervisionReason {
        &self.reason
    }

    /// Conditions not currently met.
    pub fn unmet_conditions(&self) -> &[ConditionId] {
        &self.unmet_conditions
    }

    /// Every condition in the current set.
    pub fn condition_ids(&self) -> &[ConditionId] {
        &self.condition_ids
    }

    /// Required verification checks for the current condition set.
    pub fn required_checks(&self) -> &[CheckId] {
        &self.required_checks
    }

    /// Applied decisions.
    pub fn applied_decisions(&self) -> &[AppliedDecision] {
        &self.applied_decisions
    }

    /// Decisions preserved only as history.
    pub fn invalidated_decisions(&self) -> &[InvalidatedDecision] {
        &self.invalidated_decisions
    }

    /// Completion snapshot, if completed.
    pub fn completion(&self) -> Option<&CompletionSnapshot> {
        self.completion.as_ref()
    }

    /// Related input change observed after completion, if any.
    pub fn completion_stale(&self) -> Option<&StaleCompletion> {
        self.completion_stale.as_ref()
    }

    /// Additive deterministic supervisor bookkeeping.
    pub const fn supervisor(&self) -> &SupervisorState {
        &self.supervisor
    }

    /// Explicit version and limit changes preserved in order.
    pub fn change_log(&self) -> &[SupervisionChangeRecord] {
        &self.change_log
    }

    /// Appends one explicit change record.
    pub(crate) fn push_change(&mut self, change: SupervisionChangeRecord) {
        self.change_log.push(change);
    }

    /// Marks recovery as waiting for a human without adopting a newer version.
    ///
    /// Applied decisions are moved to invalidated history when a version,
    /// profile, consent, or limit mismatch made them inapplicable. The current
    /// record versions stay unchanged until an explicit human operation
    /// approves the new version.
    pub fn mark_recovery_waiting(
        &mut self,
        action: HumanAction,
        invalidation: Option<DecisionInvalidation>,
    ) -> Result<(), SupervisionError> {
        if let Some(invalidation) = invalidation {
            self.invalidate_all(invalidation);
        }
        self.wait_for_human(action)
    }

    pub(crate) fn supervisor_mut(&mut self) -> &mut SupervisorState {
        &mut self.supervisor
    }

    /// Marks the completion snapshot stale without changing the completed state
    /// or starting/resuming anything.
    pub fn mark_completion_stale(
        &mut self,
        stale: StaleCompletion,
    ) -> Result<(), SupervisionError> {
        if self.state != SupervisionState::Completed || self.completion.is_none() {
            return Err(SupervisionError::InvalidStateReason {
                state: self.state,
                reason: "stale_completion".to_owned(),
            });
        }
        self.completion_stale = Some(stale);
        Ok(())
    }

    /// Sets the state and a reason that describes that state.
    pub fn set_state(
        &mut self,
        state: SupervisionState,
        reason: SupervisionReason,
    ) -> Result<(), SupervisionError> {
        if reason.state() != state {
            return Err(SupervisionError::InvalidStateReason {
                state,
                reason: reason.kind_label().to_owned(),
            });
        }
        self.state = state;
        self.reason = reason;
        if state != SupervisionState::Completed {
            self.completion = None;
            self.completion_stale = None;
        }
        Ok(())
    }

    /// Records a new run in the group and enters `running`.
    pub fn begin_run(&mut self, run: RunId) -> Result<(), SupervisionError> {
        verify_core_id(&run, self.project_id)?;
        self.run_group.push(run)?;
        self.set_state(
            SupervisionState::Running,
            SupervisionReason::RunActive { run },
        )
    }

    /// Enters `verifying`.
    pub fn begin_verification(&mut self, checks: Vec<CheckId>) -> Result<(), SupervisionError> {
        for check in &checks {
            verify_scoped(check, self.project_id)?;
        }
        self.set_state(
            SupervisionState::Verifying,
            SupervisionReason::Verifying { checks },
        )
    }

    /// Enters `assessing`.
    pub fn begin_assessment(
        &mut self,
        conditions: Vec<ConditionId>,
    ) -> Result<(), SupervisionError> {
        for condition in &conditions {
            verify_scoped(condition, self.project_id)?;
        }
        self.set_state(
            SupervisionState::Assessing,
            SupervisionReason::Assessing { conditions },
        )
    }

    /// Enters `waiting_human`.
    pub fn wait_for_human(&mut self, action: HumanAction) -> Result<(), SupervisionError> {
        self.set_state(
            SupervisionState::WaitingHuman,
            SupervisionReason::WaitingHuman { action },
        )
    }

    /// Stops the supervision target and clears any completion.
    pub fn stop(&mut self, cause: StopCause) -> Result<(), SupervisionError> {
        self.completion = None;
        self.set_state(
            SupervisionState::Stopped,
            SupervisionReason::Stopped { cause },
        )
    }

    /// Records an unrecoverable failure.
    pub fn fail(&mut self, failure: SupervisionFailure) -> Result<(), SupervisionError> {
        self.completion = None;
        self.set_state(
            SupervisionState::Failed,
            SupervisionReason::Failed { failure },
        )
    }

    /// Records an explicit cancellation.
    pub fn cancel(&mut self, cause: CancelCause) -> Result<(), SupervisionError> {
        self.completion = None;
        self.set_state(
            SupervisionState::Cancelled,
            SupervisionReason::Cancelled { cause },
        )
    }

    /// Applies one assessment result to the current versions.
    ///
    /// A stale result is stored only in the invalidated history and returns
    /// [`AssessmentApplication::Stale`]. `Insufficient`, uncertainty, and a
    /// below-threshold result never change the unmet set.
    pub fn apply_assessment(
        &mut self,
        result: &AssessmentResult,
        thresholds: ProfileThresholds,
    ) -> Result<AssessmentApplication, SupervisionError> {
        verify_scoped(&result.supervision_id(), self.project_id)?;
        if result.project_id() != self.project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "assessment".to_owned(),
                expected: self.project_id,
                found: result.project_id(),
            });
        }
        if !self.condition_ids.contains(&result.condition_id()) {
            return Err(SupervisionError::UnknownConditionReference {
                reference: result.condition_id().to_string(),
            });
        }
        if !result.applies_to(self.condition_version, self.target_version, self.profile) {
            let invalidation = if result.condition_version() != self.condition_version {
                DecisionInvalidation::ConditionsChanged {
                    to: self.condition_version,
                }
            } else if result.target_version() != self.target_version {
                DecisionInvalidation::TargetChanged {
                    to: self.target_version,
                }
            } else {
                DecisionInvalidation::ProfileChanged
            };
            self.invalidated_decisions.push(InvalidatedDecision {
                decision: AppliedDecision {
                    condition_id: result.condition_id(),
                    condition_version: result.condition_version(),
                    target_version: result.target_version(),
                    profile: result.profile(),
                    verdict: result.reported_verdict(),
                    evidence: result.evidence().to_vec(),
                },
                invalidation,
            });
            return Ok(AssessmentApplication::Stale);
        }

        let Some(verdict) = result.adopted_verdict(thresholds) else {
            return Ok(AssessmentApplication::NotDecided);
        };

        if verdict.is_met() {
            self.unmet_conditions
                .retain(|id| *id != result.condition_id());
        } else if !self.unmet_conditions.contains(&result.condition_id()) {
            self.unmet_conditions.push(result.condition_id());
        }
        let decision = AppliedDecision {
            condition_id: result.condition_id(),
            condition_version: result.condition_version(),
            target_version: result.target_version(),
            profile: result.profile(),
            verdict,
            evidence: result.evidence().to_vec(),
        };
        if let Some(existing) = self
            .applied_decisions
            .iter_mut()
            .find(|existing| existing.condition_id == decision.condition_id)
        {
            *existing = decision;
        } else {
            self.applied_decisions.push(decision);
        }
        Ok(AssessmentApplication::Applied)
    }

    /// Applies a host-owned deterministic condition result.
    ///
    /// This is used only when every required check for the condition currently
    /// passes with applicable evidence and the injected assessment plan marks
    /// the condition as provable without a semantic model judgment. It records
    /// the same applied-decision shape as an adopted model `met` result.
    pub fn apply_deterministic_condition(
        &mut self,
        condition_id: ConditionId,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        evidence: Vec<EvidenceId>,
    ) -> Result<(), SupervisionError> {
        verify_scoped(&condition_id, self.project_id)?;
        if !self.condition_ids.contains(&condition_id) {
            return Err(SupervisionError::UnknownConditionReference {
                reference: condition_id.to_string(),
            });
        }
        if condition_version != self.condition_version || target_version != self.target_version {
            return Err(SupervisionError::StaleAssessment {
                current_condition_version: self.condition_version.get(),
                assessment_condition_version: condition_version.get(),
                current_target_version: self.target_version.get(),
                assessment_target_version: target_version.get(),
            });
        }
        if evidence.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "deterministicCondition.evidence".to_owned(),
                detail: "a deterministic condition result must cite evidence".to_owned(),
            });
        }
        for evidence_id in &evidence {
            verify_scoped(evidence_id, self.project_id)?;
        }
        self.unmet_conditions.retain(|id| *id != condition_id);
        let decision = AppliedDecision {
            condition_id,
            condition_version,
            target_version,
            profile: self.profile,
            verdict: ConditionVerdict::Met,
            evidence,
        };
        if let Some(existing) = self
            .applied_decisions
            .iter_mut()
            .find(|existing| existing.condition_id == condition_id)
        {
            *existing = decision;
        } else {
            self.applied_decisions.push(decision);
        }
        Ok(())
    }

    /// Preserves an assessment result only as history.
    ///
    /// This is used when a result arrives after a condition, target, profile,
    /// or consent revision. The current unmet set and applied decisions are
    /// never changed by this method.
    pub fn record_invalidated_assessment(
        &mut self,
        result: &AssessmentResult,
        invalidation: DecisionInvalidation,
    ) -> Result<(), SupervisionError> {
        verify_scoped(&result.supervision_id(), self.project_id)?;
        if result.project_id() != self.project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "assessment".to_owned(),
                expected: self.project_id,
                found: result.project_id(),
            });
        }
        if !self.condition_ids.contains(&result.condition_id()) {
            return Err(SupervisionError::UnknownConditionReference {
                reference: result.condition_id().to_string(),
            });
        }
        self.invalidated_decisions.push(InvalidatedDecision {
            decision: AppliedDecision {
                condition_id: result.condition_id(),
                condition_version: result.condition_version(),
                target_version: result.target_version(),
                profile: result.profile(),
                verdict: result.reported_verdict(),
                evidence: result.evidence().to_vec(),
            },
            invalidation,
        });
        Ok(())
    }

    /// Changes the condition version after a human or approved-owner decision.
    ///
    /// Every applied decision moves to history, completion is cleared, and all
    /// conditions become unmet until re-verified and re-assessed.
    pub fn revise_conditions(
        &mut self,
        actor: ApprovalActor,
        new_version: ConditionVersion,
        condition_ids: Vec<ConditionId>,
        required_checks: Vec<CheckId>,
    ) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "change completion conditions".to_owned(),
            });
        }
        if new_version <= self.condition_version {
            return Err(SupervisionError::InvalidValue {
                field: "conditionVersion".to_owned(),
                detail: "a revised condition version must be greater than the current version"
                    .to_owned(),
            });
        }
        for condition in &condition_ids {
            verify_scoped(condition, self.project_id)?;
        }
        for check in &required_checks {
            verify_scoped(check, self.project_id)?;
        }
        self.invalidate_all(DecisionInvalidation::ConditionsChanged { to: new_version });
        let from = self.condition_version;
        self.condition_version = new_version;
        self.condition_ids = condition_ids.clone();
        self.required_checks = required_checks;
        self.unmet_conditions = condition_ids;
        self.completion = None;
        self.revision = self.revision.saturating_add(1);
        self.set_state(
            SupervisionState::WaitingHuman,
            SupervisionReason::ConditionsChanged {
                from,
                to: new_version,
            },
        )
    }

    /// Changes the target version after a human or approved-owner decision.
    pub fn revise_target(
        &mut self,
        actor: ApprovalActor,
        new_version: TargetVersion,
    ) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "change the evidence target".to_owned(),
            });
        }
        if new_version <= self.target_version {
            return Err(SupervisionError::InvalidValue {
                field: "targetVersion".to_owned(),
                detail: "a revised target version must be greater than the current version"
                    .to_owned(),
            });
        }
        self.invalidate_all(DecisionInvalidation::TargetChanged { to: new_version });
        let from = self.target_version;
        self.target_version = new_version;
        self.unmet_conditions = self.condition_ids.clone();
        self.completion = None;
        self.revision = self.revision.saturating_add(1);
        self.set_state(
            SupervisionState::WaitingHuman,
            SupervisionReason::TargetChanged {
                from,
                to: new_version,
            },
        )
    }

    /// Changes the fixed assessment profile after a human or approved-owner
    /// decision. Old decisions remain only as history.
    pub fn revise_profile(
        &mut self,
        actor: ApprovalActor,
        profile: ProfileBinding,
    ) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "change the assessment profile".to_owned(),
            });
        }
        verify_scoped(&profile.profile_id(), self.project_id)?;
        self.invalidate_all(DecisionInvalidation::ProfileChanged);
        self.profile = profile;
        self.unmet_conditions = self.condition_ids.clone();
        self.completion = None;
        self.revision = self.revision.saturating_add(1);
        self.set_state(
            SupervisionState::WaitingHuman,
            SupervisionReason::WaitingHuman {
                action: HumanAction::ConfirmAssessmentProfile,
            },
        )
    }

    /// Changes the fixed disclosure consent after a human or approved-owner
    /// decision. Old decisions remain only as history.
    pub fn revise_consent(
        &mut self,
        actor: ApprovalActor,
        consent: ConsentBinding,
    ) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "change disclosure consent".to_owned(),
            });
        }
        verify_scoped(&consent.consent_id(), self.project_id)?;
        self.invalidate_all(DecisionInvalidation::ConsentChanged);
        self.consent = consent;
        self.unmet_conditions = self.condition_ids.clone();
        self.completion = None;
        self.revision = self.revision.saturating_add(1);
        self.set_state(
            SupervisionState::WaitingHuman,
            SupervisionReason::WaitingHuman {
                action: HumanAction::GrantDisclosureConsent,
            },
        )
    }

    /// Applies an approved-owner generation replacement in the same target.
    ///
    /// The contract must name the same project and target, carry a strictly
    /// newer target version, and keep the same condition content when the
    /// condition version does not advance. Every applied decision moves to
    /// history, the completion snapshot is cleared, and the controller returns
    /// to `ready` without clearing the run group, evaluation history, or
    /// budget. Consumed budget is owned by the durable ledger and is never
    /// touched here.
    pub fn apply_generation(
        &mut self,
        contract: &SupervisionContract,
    ) -> Result<(), SupervisionError> {
        if contract.project_id() != self.project_id
            || contract.subject().supervision_id() != self.supervision_id
        {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supersession contract".to_owned(),
                expected: self.project_id,
                found: contract.project_id(),
            });
        }
        let target_version = contract.evidence_target().version();
        if target_version <= self.target_version {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: crate::error::OwnerSupersessionRejection::TargetUnchanged,
            });
        }
        let condition_version = contract.conditions().condition_version();
        let condition_ids = contract.conditions().condition_ids();
        let required_checks = contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect::<Vec<_>>();
        if condition_version < self.condition_version {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: crate::error::OwnerSupersessionRejection::ConditionsMismatch,
            });
        }
        if condition_version == self.condition_version
            && (condition_ids != self.condition_ids || required_checks != self.required_checks)
        {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: crate::error::OwnerSupersessionRejection::ConditionsMismatch,
            });
        }
        if contract.conditions().approval().is_none() {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: crate::error::OwnerSupersessionRejection::ConditionsMismatch,
            });
        }

        self.invalidate_all(DecisionInvalidation::GenerationSuperseded { to: target_version });
        self.condition_version = condition_version;
        self.condition_ids = condition_ids.clone();
        self.required_checks = required_checks;
        self.target_version = target_version;
        self.profile = contract.profile();
        self.consent = contract.consent();
        self.unmet_conditions = condition_ids;
        self.completion = None;
        self.completion_stale = None;
        self.revision = self.revision.saturating_add(1);
        self.set_state(SupervisionState::Ready, SupervisionReason::AwaitingStart)?;
        let state = self.supervisor_mut();
        state.phase = crate::supervisor::SupervisorPhase::Idle;
        state.current_run = None;
        state.current_input = None;
        state.current_budget_request = None;
        state.continuation_of = None;
        state.pending_deficiency = None;
        state.stagnation_cycles = 0;
        state.cycle_baseline = None;
        state.last_progress = None;
        state.last_target_digest = None;
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        Ok(())
    }

    /// Higher-priority blockers currently visible without a proposed snapshot.
    pub fn completion_blockers(&self) -> Vec<CompletionBlocker> {
        let mut blockers = Vec::new();
        match &self.reason {
            SupervisionReason::WaitingHuman { action } => {
                blockers.push(CompletionBlocker::State { state: self.state });
                blockers.push(CompletionBlocker::HumanAction { action: *action });
            }
            SupervisionReason::Stopped { cause } => {
                blockers.push(CompletionBlocker::State { state: self.state });
                blockers.push(CompletionBlocker::Stopped { cause: *cause });
                if let StopCause::Budget(limit) = cause {
                    blockers.push(CompletionBlocker::Limit { limit: *limit });
                }
            }
            SupervisionReason::Failed { failure } => {
                blockers.push(CompletionBlocker::State { state: self.state });
                blockers.push(CompletionBlocker::Unrecoverable { failure: *failure });
            }
            SupervisionReason::Cancelled { .. } => {
                blockers.push(CompletionBlocker::State { state: self.state });
            }
            _ if self.state.blocks_completion() => {
                blockers.push(CompletionBlocker::State { state: self.state });
            }
            _ => {}
        }
        if !self.unmet_conditions.is_empty() {
            blockers.push(CompletionBlocker::UnmetConditions {
                conditions: self.unmet_conditions.clone(),
            });
        }
        blockers
    }

    /// Whether progress may still happen without human input.
    pub fn can_progress(&self) -> bool {
        !self.state.blocks_completion()
    }

    /// Attempts to complete the record against a fixed snapshot.
    ///
    /// Stopped, human-waiting, budget/recovery stops, unrecoverable failure,
    /// cancellation, and unmet conditions take priority over completion.
    pub fn complete(&mut self, snapshot: CompletionSnapshot) -> Result<(), SupervisionError> {
        let mut blockers = self.completion_blockers();
        if snapshot.condition_version != self.condition_version
            || snapshot.target_version != self.target_version
            || snapshot.profile != self.profile
            || snapshot.consent != self.consent
        {
            blockers.push(CompletionBlocker::StaleSnapshot);
        }
        let missing_checks = self
            .required_checks
            .iter()
            .filter(|check| !snapshot.verified_checks.contains(check))
            .copied()
            .collect::<Vec<_>>();
        if !missing_checks.is_empty() {
            blockers.push(CompletionBlocker::RequiredChecksNotPassed {
                checks: missing_checks,
            });
        }
        if !blockers.is_empty() {
            return Err(SupervisionError::CompletionBlocked { blockers });
        }
        self.state = SupervisionState::Completed;
        self.reason = SupervisionReason::Completed {
            snapshot: snapshot.clone(),
        };
        self.completion = Some(snapshot);
        self.completion_stale = None;
        Ok(())
    }

    /// Resets controller bookkeeping for an explicit human resume.
    ///
    /// The record becomes ready for a new run. Old run/input identifiers and
    /// prepared deficiencies are cleared so no previous input or approval is
    /// replayed. Consumed budget and evaluation history stay untouched.
    pub(crate) fn reset_for_resume(&mut self) {
        self.set_state(SupervisionState::Ready, SupervisionReason::AwaitingStart)
            .expect("ready/awaiting_start is a valid pair");
        let state = self.supervisor_mut();
        state.phase = crate::supervisor::SupervisorPhase::Idle;
        state.current_run = None;
        state.current_input = None;
        state.current_budget_request = None;
        state.continuation_of = None;
        state.pending_deficiency = None;
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        state.stagnation_cycles = 0;
        state.cycle_baseline = None;
        state.last_target_digest = None;
    }

    /// Resets controller bookkeeping for an explicit human reassessment.
    ///
    /// Verification starts again from the current conditions and target. The
    /// previous run is not resumed and no input is replayed.
    pub(crate) fn reset_for_reassess(&mut self) -> Result<(), SupervisionError> {
        self.begin_verification(self.required_checks.clone())?;
        let state = self.supervisor_mut();
        state.phase = crate::supervisor::SupervisorPhase::Evaluating;
        // Reassessment reuses the last stable run/input only for observing the
        // target and input correspondence. It never resumes or replays that
        // run; a new run requires an explicit resume.
        state.continuation_of = None;
        state.pending_deficiency = None;
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        state.last_target_digest = None;
        state.stagnation_cycles = 0;
        state.cycle_baseline = None;
        Ok(())
    }

    fn invalidate_all(&mut self, invalidation: DecisionInvalidation) {
        for decision in self.applied_decisions.drain(..) {
            self.invalidated_decisions.push(InvalidatedDecision {
                decision,
                invalidation,
            });
        }
    }

    pub(crate) fn set_command_revision(&mut self, revision: u64) {
        self.revision = revision;
    }
}
