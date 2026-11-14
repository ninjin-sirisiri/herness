//! Versioned execution snapshots.
//!
//! A snapshot is the full H4 state a later UI, restart, or finish handoff reads:
//! the execution identity and revision, the plan digest and approved revision,
//! the checkout and branch, the current Task, every Task's progression, phase,
//! H2 reference, child, commit range or no-change record, and evidence
//! references, the stop reason and required action, consumed and reserved
//! budget, the applied revision, and the final project sequence.
//!
//! References that are not established stay `None`. A snapshot never fabricates
//! an H2 target, a child, a commit range, a baseline, or a project sequence.

use herness_core::contracts::ProjectId;
use herness_supervision::{EvidenceId, Money};
use serde::{Deserialize, Serialize};

use crate::approval::{CommitPolicy, ExecutionApproval};
use crate::error::{ApprovalRejection, SddExecutionError};
use crate::ids::{
    Baseline, ChildIdentity, CommitSha, ExecutionId, ExecutionRevision, H2SupervisionRef,
    PlanRevision, ProjectSequence, TaskNumber, TaskRef,
};
use crate::plan::PlanPath;
use crate::state::{AppliedRevision, ExecutionState, StopRecord, TaskPhase, TaskProgression};
use crate::version::{ExecutionContractVersion, PlanDigest};

/// The plan identity one execution applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotPlan {
    plan_path: PlanPath,
    digest: PlanDigest,
    approved_revision: PlanRevision,
}

impl SnapshotPlan {
    /// Creates a plan identity.
    pub const fn new(
        plan_path: PlanPath,
        digest: PlanDigest,
        approved_revision: PlanRevision,
    ) -> Self {
        Self {
            plan_path,
            digest,
            approved_revision,
        }
    }

    /// Approved plan path.
    pub fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Approved exact-bytes digest.
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }

    /// Newest approved plan revision.
    pub const fn approved_revision(&self) -> PlanRevision {
        self.approved_revision
    }
}

/// The checkout, branch, and baseline one execution uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotWorkspace {
    canonical_checkout_root: String,
    branch: String,
    base_branch: String,
    #[serde(default)]
    baseline: Option<Baseline>,
}

impl SnapshotWorkspace {
    /// Creates a workspace identity. The checkout root must be absolute.
    pub fn new(
        canonical_checkout_root: impl Into<String>,
        branch: impl Into<String>,
        base_branch: impl Into<String>,
        baseline: Option<Baseline>,
    ) -> Result<Self, SddExecutionError> {
        let canonical_checkout_root = canonical_checkout_root.into();
        let branch = branch.into();
        let base_branch = base_branch.into();
        if canonical_checkout_root.trim().is_empty() {
            return Err(invalid("workspace.checkoutRoot", "must not be empty"));
        }
        if !std::path::Path::new(&canonical_checkout_root).is_absolute() {
            return Err(invalid(
                "workspace.checkoutRoot",
                "must be an absolute path",
            ));
        }
        if branch.trim().is_empty() {
            return Err(invalid("workspace.branch", "must not be empty"));
        }
        if base_branch.trim().is_empty() {
            return Err(invalid("workspace.baseBranch", "must not be empty"));
        }
        Ok(Self {
            canonical_checkout_root,
            branch,
            base_branch,
            baseline,
        })
    }

    /// Canonical absolute checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Fixed baseline commit, when established.
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }
}

/// One completed Task's commit range from the fixed baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitRange {
    base: Baseline,
    head: CommitSha,
}

impl CommitRange {
    /// Creates a commit range.
    pub fn new(base: Baseline, head: CommitSha) -> Result<Self, SddExecutionError> {
        if base.as_str() == head.as_str() {
            return Err(invalid(
                "commitRange",
                "a required Task must advance HEAD from the baseline",
            ));
        }
        Ok(Self { base, head })
    }

    /// Range base.
    pub const fn base(&self) -> &Baseline {
        &self.base
    }

    /// Range head.
    pub const fn head(&self) -> &CommitSha {
        &self.head
    }

    /// `base7..head7` form used by the progress ledger.
    pub fn short_range(&self) -> String {
        format!("{}..{}", self.base.short(), self.head.short())
    }

    /// `base..head` full form.
    pub fn full_range(&self) -> String {
        format!("{}..{}", self.base, self.head)
    }
}

/// Recorded proof that a `no_change` Task changed no approved source content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoChangeRecord {
    source_unchanged: bool,
    evidence: Vec<EvidenceId>,
    #[serde(default)]
    detail: Option<String>,
}

impl NoChangeRecord {
    /// Records a verified no-change result.
    pub fn new(
        source_unchanged: bool,
        evidence: Vec<EvidenceId>,
        detail: Option<String>,
    ) -> Result<Self, SddExecutionError> {
        if !source_unchanged {
            return Err(invalid(
                "noChange.sourceUnchanged",
                "a no_change Task must record that the source is unchanged",
            ));
        }
        if evidence.is_empty() {
            return Err(invalid(
                "noChange.evidence",
                "a no_change Task needs evidence references",
            ));
        }
        Ok(Self {
            source_unchanged,
            evidence,
            detail,
        })
    }

    /// Whether the source was verified unchanged.
    pub const fn source_unchanged(&self) -> bool {
        self.source_unchanged
    }

    /// Evidence that established the no-change result.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }

    /// Optional non-secret detail.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// One Task's durable state in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSnapshot {
    task: TaskRef,
    progression: TaskProgression,
    phase: TaskPhase,
    #[serde(default)]
    h2_reference: Option<H2SupervisionRef>,
    #[serde(default)]
    child: Option<ChildIdentity>,
    commit_policy: CommitPolicy,
    #[serde(default)]
    commit_range: Option<CommitRange>,
    #[serde(default)]
    no_change: Option<NoChangeRecord>,
    #[serde(default)]
    evidence: Vec<EvidenceId>,
    #[serde(default)]
    stop: Option<StopRecord>,
    applied_revision: AppliedRevision,
}

impl TaskSnapshot {
    /// Creates a Task snapshot and validates its progression and phase.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        progression: TaskProgression,
        phase: TaskPhase,
        h2_reference: Option<H2SupervisionRef>,
        child: Option<ChildIdentity>,
        commit_policy: CommitPolicy,
        commit_range: Option<CommitRange>,
        no_change: Option<NoChangeRecord>,
        evidence: Vec<EvidenceId>,
        stop: Option<StopRecord>,
        applied_revision: AppliedRevision,
    ) -> Result<Self, SddExecutionError> {
        let value = Self {
            task,
            progression,
            phase,
            h2_reference,
            child,
            commit_policy,
            commit_range,
            no_change,
            evidence,
            stop,
            applied_revision,
        };
        value.validate(task.project_id())?;
        Ok(value)
    }

    /// Task identity and number.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Progression.
    pub const fn progression(&self) -> TaskProgression {
        self.progression
    }

    /// Current phase.
    pub const fn phase(&self) -> TaskPhase {
        self.phase
    }

    /// H2 supervision reference, when a target exists.
    pub const fn h2_reference(&self) -> Option<H2SupervisionRef> {
        self.h2_reference
    }

    /// H1 child identity, when a child exists.
    pub const fn child(&self) -> Option<ChildIdentity> {
        self.child
    }

    /// Approved commit policy.
    pub const fn commit_policy(&self) -> CommitPolicy {
        self.commit_policy
    }

    /// Completed commit range, when the Task advanced HEAD.
    pub fn commit_range(&self) -> Option<&CommitRange> {
        self.commit_range.as_ref()
    }

    /// No-change record, when the Task applied the `no_change` policy.
    pub const fn no_change(&self) -> Option<&NoChangeRecord> {
        self.no_change.as_ref()
    }

    /// Evidence references recorded for this Task.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }

    /// Stop reason and required action, when stopped or waiting.
    pub const fn stop(&self) -> Option<StopRecord> {
        self.stop
    }

    /// Plan revision currently applied to this Task.
    pub const fn applied_revision(&self) -> AppliedRevision {
        self.applied_revision
    }

    /// Validates the Task snapshot against `project`.
    pub fn validate(&self, project: ProjectId) -> Result<(), SddExecutionError> {
        self.task.ensure_project(project)?;
        if self.progression != self.phase.implied_progression() {
            return Err(invalid(
                "task.progression",
                "progression must agree with the Task phase",
            ));
        }
        if let Some(h2) = self.h2_reference {
            h2.ensure_project(project)?;
        }
        if let Some(child) = self.child {
            child.ensure_project(project)?;
            if self.h2_reference.is_none() {
                return Err(invalid(
                    "task.child",
                    "a child requires the H2 supervision reference that owns it",
                ));
            }
        }
        self.applied_revision.validate()?;
        match self.progression {
            TaskProgression::Complete => {
                if self.phase != TaskPhase::Complete {
                    return Err(invalid(
                        "task.phase",
                        "a complete Task must have the complete phase",
                    ));
                }
                self.validate_completion()?;
                if self.stop.is_some() {
                    return Err(invalid(
                        "task.stop",
                        "a complete Task must not carry a stop record",
                    ));
                }
            }
            TaskProgression::Pending => {
                if self.commit_range.is_some() || self.no_change.is_some() {
                    return Err(invalid(
                        "task.completion",
                        "an unfinished Task must not carry completion evidence",
                    ));
                }
                if self.phase.requires_human_action() || self.phase.is_terminal() {
                    return Err(invalid(
                        "task.phase",
                        "a pending Task cannot be waiting, stopped, or terminal",
                    ));
                }
            }
            TaskProgression::Active => {
                if self.commit_range.is_some() || self.no_change.is_some() {
                    return Err(invalid(
                        "task.completion",
                        "an active Task must not carry completion evidence",
                    ));
                }
            }
        }
        if self.phase.requires_human_action() {
            let stop = self.stop.ok_or_else(|| {
                invalid(
                    "task.stop",
                    "a waiting or stopped Task must record the reason and action",
                )
            })?;
            if stop.required_action().is_none() {
                return Err(invalid(
                    "task.stop.requiredAction",
                    "a waiting or stopped Task must name the human action",
                ));
            }
        } else if let Some(stop) = self.stop
            && stop.required_action().is_some()
            && !self.phase.is_terminal()
        {
            return Err(invalid(
                "task.stop",
                "only a waiting or stopped Task may require a human action",
            ));
        }
        Ok(())
    }

    fn validate_completion(&self) -> Result<(), SddExecutionError> {
        match self.commit_policy {
            CommitPolicy::Required => {
                if self.commit_range.is_none() {
                    return Err(invalid(
                        "task.commitRange",
                        "a complete required Task must record its commit range",
                    ));
                }
                if self.no_change.is_some() {
                    return Err(invalid(
                        "task.noChange",
                        "a required Task cannot carry a no-change record",
                    ));
                }
            }
            CommitPolicy::NoChange => {
                if self.commit_range.is_some() {
                    return Err(invalid(
                        "task.commitRange",
                        "a no_change Task must not record a commit range",
                    ));
                }
                if self.no_change.is_none() {
                    return Err(invalid(
                        "task.noChange",
                        "a complete no_change Task must record its evidence",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Applies one Task phase transition or refuses it.
    pub fn transition_phase(&mut self, next: TaskPhase) -> Result<(), SddExecutionError> {
        self.phase = self.phase.transition_to(next)?;
        self.progression = next.implied_progression();
        Ok(())
    }
}

/// Budget consumed and reserved for one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetConsumption {
    active_seconds: u64,
    additional_runs: u32,
    #[serde(default)]
    money: Option<Money>,
}

impl BudgetConsumption {
    /// Creates a consumption value.
    pub const fn new(active_seconds: u64, additional_runs: u32, money: Option<Money>) -> Self {
        Self {
            active_seconds,
            additional_runs,
            money,
        }
    }

    /// No consumption.
    pub const fn zero() -> Self {
        Self {
            active_seconds: 0,
            additional_runs: 0,
            money: None,
        }
    }

    /// Cumulative active seconds.
    pub const fn active_seconds(self) -> u64 {
        self.active_seconds
    }

    /// Additional child runs.
    pub const fn additional_runs(self) -> u32 {
        self.additional_runs
    }

    /// Optional money amount.
    pub const fn money(self) -> Option<Money> {
        self.money
    }
}

/// Consumed and reserved budget. A resume or re-approval never zeroes either
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotBudget {
    consumed: BudgetConsumption,
    reserved: BudgetConsumption,
}

impl SnapshotBudget {
    /// Creates a budget snapshot.
    pub const fn new(consumed: BudgetConsumption, reserved: BudgetConsumption) -> Self {
        Self { consumed, reserved }
    }

    /// Consumed budget.
    pub const fn consumed(self) -> BudgetConsumption {
        self.consumed
    }

    /// Reserved budget.
    pub const fn reserved(self) -> BudgetConsumption {
        self.reserved
    }
}

/// Input to [`ExecutionSnapshot::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInput {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
    /// Durable revision this snapshot writes.
    pub revision: ExecutionRevision,
    /// Execution state.
    pub state: ExecutionState,
    /// Approved plan identity.
    pub plan: SnapshotPlan,
    /// Checkout, branch, and baseline.
    pub workspace: SnapshotWorkspace,
    /// Current Task, when one is active or about to be dispatched.
    pub current_task: Option<TaskRef>,
    /// Every Task in plan order.
    pub tasks: Vec<TaskSnapshot>,
    /// Execution-level stop reason and required action.
    pub stop: Option<StopRecord>,
    /// Consumed and reserved budget.
    pub budget: SnapshotBudget,
    /// Plan revision currently applied.
    pub applied_revision: AppliedRevision,
    /// Last observed H1 project sequence, when established.
    pub final_project_sequence: Option<ProjectSequence>,
}

/// One complete, versioned H4 execution snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionSnapshot {
    contract_version: ExecutionContractVersion,
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    state: ExecutionState,
    plan: SnapshotPlan,
    workspace: SnapshotWorkspace,
    #[serde(default)]
    current_task: Option<TaskRef>,
    tasks: Vec<TaskSnapshot>,
    #[serde(default)]
    stop: Option<StopRecord>,
    budget: SnapshotBudget,
    applied_revision: AppliedRevision,
    #[serde(default)]
    final_project_sequence: Option<ProjectSequence>,
}

impl ExecutionSnapshot {
    /// Creates a snapshot and validates every invariant.
    pub fn new(input: SnapshotInput) -> Result<Self, SddExecutionError> {
        let value = Self {
            contract_version: ExecutionContractVersion::CURRENT,
            project_id: input.project_id,
            execution_id: input.execution_id,
            revision: input.revision,
            state: input.state,
            plan: input.plan,
            workspace: input.workspace,
            current_task: input.current_task,
            tasks: input.tasks,
            stop: input.stop,
            budget: input.budget,
            applied_revision: input.applied_revision,
            final_project_sequence: input.final_project_sequence,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the snapshot again after decoding.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        crate::version::ensure_current_version(self.contract_version)?;
        let project = self.project_id;
        self.execution_id.validate_in(project)?;
        if self.tasks.is_empty() {
            return Err(invalid("snapshot.tasks", "must contain at least one Task"));
        }
        let mut numbers = Vec::new();
        let mut stable_ids = Vec::new();
        let mut active = Vec::new();
        for task in &self.tasks {
            task.validate(project)?;
            if numbers.contains(&task.task.number()) {
                return Err(invalid("snapshot.tasks", "Task numbers must be unique"));
            }
            if stable_ids.contains(&task.task.stable_id()) {
                return Err(invalid(
                    "snapshot.tasks",
                    "Task stable IDs must be unique inside one execution",
                ));
            }
            if task.progression == TaskProgression::Active {
                active.push(task.task);
            }
            numbers.push(task.task.number());
            stable_ids.push(task.task.stable_id());
        }
        for (index, number) in numbers.iter().enumerate() {
            if number.get() != u32::try_from(index + 1).unwrap_or(u32::MAX) {
                return Err(invalid(
                    "snapshot.tasks",
                    "Task numbers must be contiguous from one",
                ));
            }
        }
        if active.len() > 1 {
            return Err(invalid(
                "snapshot.tasks",
                "at most one Task may be active in one execution",
            ));
        }
        if let Some(current) = self.current_task {
            current.ensure_project(project)?;
            let task = self.task(current.number()).ok_or_else(|| {
                invalid(
                    "snapshot.currentTask",
                    "must reference a Task in this snapshot",
                )
            })?;
            if task.task.stable_id() != current.stable_id() {
                return Err(invalid(
                    "snapshot.currentTask",
                    "must carry the Task's stable identity, not only its number",
                ));
            }
            if task.progression == TaskProgression::Complete {
                return Err(invalid(
                    "snapshot.currentTask",
                    "cannot reference a complete Task",
                ));
            }
        }
        self.applied_revision.validate()?;
        if self.state == ExecutionState::Preview
            && self.applied_revision.state() != crate::state::AppliedRevisionState::NotApplied
        {
            return Err(invalid(
                "snapshot.appliedRevision",
                "a preview has no applied plan revision",
            ));
        }
        if self.state == ExecutionState::ReadyForFinish {
            if self.current_task.is_some() {
                return Err(invalid(
                    "snapshot.currentTask",
                    "a finished execution has no current Task",
                ));
            }
            if self
                .tasks
                .iter()
                .any(|task| task.progression != TaskProgression::Complete)
            {
                return Err(invalid(
                    "snapshot.state",
                    "ready_for_finish requires every Task to be complete",
                ));
            }
        }
        if self.state.requires_human_action() {
            let stop = self.stop.ok_or_else(|| {
                invalid(
                    "snapshot.stop",
                    "a waiting or stopped execution must record its stop reason",
                )
            })?;
            if stop.required_action().is_none() {
                return Err(invalid(
                    "snapshot.stop.requiredAction",
                    "a waiting or stopped execution must name the human action",
                ));
            }
        } else if let Some(stop) = self.stop
            && stop.required_action().is_some()
            && !self.state.is_terminal()
        {
            return Err(invalid(
                "snapshot.stop",
                "only a waiting or stopped execution may require a human action",
            ));
        }
        Ok(())
    }

    /// Contract version.
    pub const fn contract_version(&self) -> ExecutionContractVersion {
        self.contract_version
    }

    /// Project that owns the execution.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Durable revision.
    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    /// Execution state.
    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    /// Approved plan identity.
    pub fn plan(&self) -> &SnapshotPlan {
        &self.plan
    }

    /// Checkout, branch, and baseline.
    pub fn workspace(&self) -> &SnapshotWorkspace {
        &self.workspace
    }

    /// Current Task, when one is selected.
    pub const fn current_task(&self) -> Option<TaskRef> {
        self.current_task
    }

    /// Every Task in plan order.
    pub fn tasks(&self) -> &[TaskSnapshot] {
        &self.tasks
    }

    /// Execution-level stop record.
    pub const fn stop(&self) -> Option<StopRecord> {
        self.stop
    }

    /// Consumed and reserved budget.
    pub const fn budget(&self) -> SnapshotBudget {
        self.budget
    }

    /// Plan revision currently applied.
    pub const fn applied_revision(&self) -> AppliedRevision {
        self.applied_revision
    }

    /// Last observed H1 project sequence, when established.
    pub const fn final_project_sequence(&self) -> Option<ProjectSequence> {
        self.final_project_sequence
    }

    /// Finds one Task by number.
    pub fn task(&self, number: TaskNumber) -> Option<&TaskSnapshot> {
        self.tasks.iter().find(|task| task.task.number() == number)
    }

    /// Finds one Task by stable identity.
    pub fn task_by_stable_id(&self, stable_id: crate::ids::TaskStableId) -> Option<&TaskSnapshot> {
        self.tasks
            .iter()
            .find(|task| task.task.stable_id() == stable_id)
    }

    /// The active Task, when exactly one exists.
    pub fn active_task(&self) -> Option<&TaskSnapshot> {
        self.tasks
            .iter()
            .find(|task| task.progression == TaskProgression::Active)
    }

    /// Whether every Task is complete.
    pub fn is_complete(&self) -> bool {
        self.tasks
            .iter()
            .all(|task| task.progression == TaskProgression::Complete)
    }

    /// Applies one execution state transition or refuses it.
    pub fn transition_state(&mut self, next: ExecutionState) -> Result<(), SddExecutionError> {
        self.state = self.state.transition_to(next)?;
        Ok(())
    }

    /// Returns a copy of this snapshot held in `waiting_human` at `revision`.
    ///
    /// Nothing else changes: every Task progression, phase, commit range,
    /// no-change record, baseline, and evidence reference is carried over. The
    /// current Task stays current, so a resume targets the same Task instead of
    /// skipping it. The stop record supplies the reason and the required human
    /// action, which `waiting_human` demands.
    pub fn held_waiting_human(
        &self,
        revision: ExecutionRevision,
        stop: StopRecord,
    ) -> Result<Self, SddExecutionError> {
        if stop.required_action().is_none() {
            return Err(invalid(
                "snapshot.stop.requiredAction",
                "a waiting_human hold must name the human action",
            ));
        }
        let state = match self.state {
            ExecutionState::WaitingHuman => ExecutionState::WaitingHuman,
            // A `ready_for_finish` execution still needs its compatibility
            // ledger. A failed ledger write must keep it short of finish, so the
            // safety hold is allowed from that state as the one exception to the
            // terminal rule. `failed` and `cancelled` remain refused: they are
            // already unusable, and holding them would invent progress.
            ExecutionState::ReadyForFinish => ExecutionState::WaitingHuman,
            other => other.transition_to(ExecutionState::WaitingHuman)?,
        };
        let next = Self {
            contract_version: self.contract_version,
            project_id: self.project_id,
            execution_id: self.execution_id,
            revision,
            state,
            plan: self.plan.clone(),
            workspace: self.workspace.clone(),
            current_task: self.current_task,
            tasks: self.tasks.clone(),
            stop: Some(stop),
            budget: self.budget,
            applied_revision: self.applied_revision,
            final_project_sequence: self.final_project_sequence,
        };
        next.validate()?;
        Ok(next)
    }

    /// Rejects an execution that belongs to another project.
    pub fn ensure_project(&self, project: ProjectId) -> Result<(), SddExecutionError> {
        self.execution_id.validate_in(project)
    }

    /// Ensures `approval` may be applied to this snapshot.
    ///
    /// This refuses another project's approval, a different plan digest or
    /// revision, and a different checkout, branch, or baseline.
    pub fn ensure_approval_applies(
        &self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        if approval.project_id() != self.project_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        if approval.plan().digest() != self.plan.digest() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::PlanDigestMismatch {
                    expected: self.plan.digest().clone(),
                    found: approval.plan().digest().clone(),
                },
            });
        }
        if approval.plan().plan_revision() != self.plan.approved_revision() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::PlanRevisionMismatch {
                    expected: self.plan.approved_revision(),
                    found: approval.plan().plan_revision(),
                },
            });
        }
        if approval.workspace().canonical_checkout_root()
            != self.workspace.canonical_checkout_root()
        {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "canonicalCheckoutRoot".to_owned(),
                },
            });
        }
        if approval.workspace().branch() != self.workspace.branch() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "branch".to_owned(),
                },
            });
        }
        if approval.workspace().base_branch() != self.workspace.base_branch() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "baseBranch".to_owned(),
                },
            });
        }
        if approval.workspace().baseline() != self.workspace.baseline() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "baseline".to_owned(),
                },
            });
        }
        if approval.tasks().len() != self.tasks.len()
            || approval
                .tasks()
                .iter()
                .zip(&self.tasks)
                .any(|(approved, snapshot)| approved.task() != snapshot.task)
        {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "tasks".to_owned(),
                },
            });
        }
        Ok(())
    }
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidSnapshot {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}
