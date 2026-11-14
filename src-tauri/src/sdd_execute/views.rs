//! Versioned read-only views for the trusted desktop surface (Task 21).
//!
//! These are the values `/ui` and H5 read. They are projections of durable H4
//! state and never carry a UI-only success flag: a snapshot says what the store
//! recorded, a failure says which of the ten H4 classes applies, and an
//! unestablished reference stays `null` instead of being invented.
//!
//! # What is displayed
//!
//! * [`SddSnapshotView`] carries the fields the specification lists: version,
//!   project, execution ID and revision, plan digest and approved revision,
//!   checkout/branch/baseline, the current Task, every Task's stable ID,
//!   number, progression, phase, H2 reference, commit range or `no_change`
//!   record, evidence references, the stop reason and required action, consumed
//!   and reserved budget, the applied revision, and the final project sequence.
//! * [`SddDisplayState`] adds the display distinctions the specification calls
//!   out separately — `html_unsynced`, `undecidable`, `git_result_unknown`,
//!   `plan_changed`, `budget_exhausted`, and `recovery_required` — derived from
//!   the recorded stop and the stored Git journal, never from a notification.
//! * [`SddStartDisclosureView`] shows the exact scope, the fixed consents, the
//!   host commit authorization, every Task's finite limits, the multi-Task and
//!   separately approved H3 cycle cost warning, and every capability this build
//!   cannot verify.
//! * [`SddFinishHandoffView`] carries the finish inputs (checkout, branch, base
//!   branch, full baseline, plan identity, each Task's real range or
//!   `no_change`, the plan `finalChecks`, the unconfirmed items, and the
//!   stacked-PR incompatibility) plus the reasons it is not ready.
//!
//! Nothing here performs a side effect, and nothing here starts work.

use herness_core::contracts::ProjectId;
use herness_sdd_execute::{
    AppliedRevision, BudgetConsumption, CommitRange, ExecutionId, ExecutionSnapshot,
    ExecutionState, HumanAction, NoChangeRecord, SddExecutionError, SnapshotBudget, StopReason,
    StopRecord, TaskProgression, TaskSnapshot,
};
use serde::Serialize;

use crate::sdd_execute::pack::ImportPreview;

/// Version of every H4 desktop view.
///
/// A consumer that reads another version rejects the value instead of guessing.
pub const SDD_VIEW_VERSION: u32 = 1;

/// Multi-Task cost warning shown beside the start disclosure, the snapshot, and
/// the finish handoff.
///
/// H4 runs one Task at a time and never adds a plan-wide budget, so the human
/// sees the number of Tasks and their per-Task limits before approving.
pub const MULTI_TASK_COST_WARNING: &str = "This plan runs one Task at a time. Each Task's finite limits apply separately, so a plan with \
     several Tasks can consume several times the model cost and time of a single Task. A resume or \
     a plan re-approval never refunds consumed budget.";

/// H3 cost warning: the H3 authoring slot is separately approved and separate
/// from the Task budget.
pub const H3_CYCLE_COST_WARNING: &str = "H3 HTML authoring and Html assessment are approved separately from this execution and keep \
     their own cycle budget. H4 never raises an H3 limit; a synchronizing Task can therefore \
     incur H3 model cost at the same time as its own Task work.";

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// One required desktop port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SddPort {
    /// The durable H4 snapshot, journals, approvals, and control records.
    ExecutionStore,
    /// The exact plan reader and its periodic observation.
    PlanSource,
    /// The pack `sdd-plan-inspect` bridge.
    PlanInspector,
    /// The checkout selection and preparation adapter.
    Workspace,
    /// The H2 child dispatch adapter.
    ChildDispatch,
    /// The H3 `H4Barrier` reader.
    HtmlBarrier,
    /// The H1 host Git commit boundary.
    HostGit,
    /// The compatibility progress-ledger writer.
    ProgressLedger,
    /// A human-confirmed approval saved from the trusted main window.
    TrustedApproval,
    /// The current saved approval revision, re-read from the store.
    CurrentApproval,
}

impl SddPort {
    /// Every port a complete `SddTaskController` needs.
    pub const ALL: [Self; 10] = [
        Self::ExecutionStore,
        Self::PlanSource,
        Self::PlanInspector,
        Self::Workspace,
        Self::ChildDispatch,
        Self::HtmlBarrier,
        Self::HostGit,
        Self::ProgressLedger,
        Self::TrustedApproval,
        Self::CurrentApproval,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionStore => "execution_store",
            Self::PlanSource => "plan_source",
            Self::PlanInspector => "plan_inspector",
            Self::Workspace => "workspace",
            Self::ChildDispatch => "child_dispatch",
            Self::HtmlBarrier => "html_barrier",
            Self::HostGit => "host_git",
            Self::ProgressLedger => "progress_ledger",
            Self::TrustedApproval => "trusted_approval",
            Self::CurrentApproval => "current_approval",
        }
    }
}

/// One port's availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddPortStateView {
    capability: &'static str,
    available: bool,
    detail: String,
}

impl SddPortStateView {
    /// Stable capability label.
    pub const fn capability(&self) -> &'static str {
        self.capability
    }

    /// Whether the port is really present.
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Sanitized explanation.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// The complete `SddTaskController` capability report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddCapabilityReportView {
    version: u32,
    checked: bool,
    available: bool,
    states: Vec<SddPortStateView>,
}

impl SddCapabilityReportView {
    /// Builds a report from explicit checks.
    ///
    /// A port that was not checked is reported unavailable, so a partial report
    /// can never make the controller available.
    pub fn from_checks(checks: impl IntoIterator<Item = (SddPort, bool, String)>) -> Self {
        let mut found = std::collections::BTreeMap::new();
        for (port, available, detail) in checks {
            found.insert(port, (available, detail));
        }
        let states = SddPort::ALL
            .into_iter()
            .map(|port| match found.remove(&port) {
                Some((available, detail)) => SddPortStateView {
                    capability: port.as_str(),
                    available,
                    detail,
                },
                None => SddPortStateView {
                    capability: port.as_str(),
                    available: false,
                    detail: "this port was not checked in this process".to_owned(),
                },
            })
            .collect::<Vec<_>>();
        let available = states.iter().all(SddPortStateView::available);
        Self {
            version: SDD_VIEW_VERSION,
            checked: true,
            available,
            states,
        }
    }

    /// A report for a controller that has not evaluated its ports yet.
    pub fn unchecked() -> Self {
        Self {
            version: SDD_VIEW_VERSION,
            checked: false,
            available: false,
            states: SddPort::ALL
                .into_iter()
                .map(|port| SddPortStateView {
                    capability: port.as_str(),
                    available: false,
                    detail: "the ports have not been checked in this process".to_owned(),
                })
                .collect(),
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Whether every required port is present.
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Whether this process evaluated the ports.
    pub const fn checked(&self) -> bool {
        self.checked
    }

    /// Every port in stable order.
    pub fn states(&self) -> &[SddPortStateView] {
        &self.states
    }

    /// Missing ports only.
    pub fn missing(&self) -> Vec<&SddPortStateView> {
        self.states
            .iter()
            .filter(|state| !state.available)
            .collect()
    }

    /// One short line naming every missing port, for a failure message.
    pub fn missing_line(&self) -> String {
        self.missing()
            .iter()
            .map(|state| format!("{}: {}", state.capability, state.detail))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// ---------------------------------------------------------------------------
// Failure taxonomy
// ---------------------------------------------------------------------------

/// One H4 failure or refusal as the UI sees it.
///
/// `code` is one of the ten specification values, or `invalid_request` for a
/// malformed command. A non-taxonomy error never borrows a failure class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddFailureView {
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
    storable_failure: bool,
}

impl SddFailureView {
    /// Builds the view for one typed H4 error.
    ///
    /// A typed failure keeps its own class. A structural error that the H4
    /// contract defines as a conflict (a stale compare-and-set revision, a
    /// reused request ID with different content, or an already-recorded different
    /// result) is reported as `conflict` rather than as `unavailable`; every
    /// other error keeps the `unavailable` default.
    pub fn of(error: &SddExecutionError) -> Self {
        let code = match error.failure_code() {
            Some(code) => code.as_str(),
            None => match error {
                SddExecutionError::RevisionConflict { .. }
                | SddExecutionError::DuplicateRequestConflict { .. }
                | SddExecutionError::DuplicateResultConflict { .. } => "conflict",
                _ => "unavailable",
            },
        };
        let details = error
            .failure_details()
            .filter(|details| {
                details.h1().is_some() || details.h2().is_some() || details.h3().is_some()
            })
            .and_then(|details| serde_json::to_value(details).ok());
        Self {
            code,
            message: error.to_string(),
            details,
            storable_failure: error.failure_code().is_some(),
        }
    }

    /// A malformed or unsupported command.
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            message: detail.into(),
            details: None,
            storable_failure: false,
        }
    }

    /// The controller is missing one or more required ports.
    pub fn unavailable(feature: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: "unavailable",
            message: format!("{}: {}", feature.into(), detail.into()),
            details: None,
            storable_failure: true,
        }
    }

    /// The trusted-main guard refused the caller.
    pub fn untrusted(detail: impl Into<String>) -> Self {
        Self {
            code: "untrusted_source",
            message: detail.into(),
            details: None,
            storable_failure: false,
        }
    }

    /// Stable short code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Non-secret message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether the code is one of the ten specification failure classes.
    pub const fn is_specification_failure(&self) -> bool {
        self.storable_failure
    }
}

/// Maps any H4 error onto the failure view.
pub fn failure_of(error: &SddExecutionError) -> SddFailureView {
    SddFailureView::of(error)
}

// ---------------------------------------------------------------------------
// Display state
// ---------------------------------------------------------------------------

/// The state the trusted UI shows.
///
/// It refines [`ExecutionState`] with the separate distinctions the
/// specification requires, so `html_not_synced`, an undecidable human wait, and
/// an unknown Git result are never collapsed into a generic `waiting_human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SddDisplayState {
    /// An imported, unapproved preview.
    Preview,
    /// Approved and startable.
    Ready,
    /// A child is working.
    Running,
    /// Waiting for required H3 synchronization.
    HtmlUnsynced,
    /// H2 is verifying.
    Verifying,
    /// The host is committing.
    Committing,
    /// A human decision is required, and it is not a plan, HTML, or Git fact.
    Undecidable,
    /// Waiting for a human for another reason.
    WaitingHuman,
    /// A stop was requested.
    Stopping,
    /// The stop is confirmed.
    Stopped,
    /// The plan bytes changed, moved, disappeared, or were unstable.
    PlanChanged,
    /// A finite budget is exhausted.
    BudgetExhausted,
    /// Durable state, a process, or Git needs reconciliation.
    RecoveryRequired,
    /// A host commit result cannot be determined.
    GitResultUnknown,
    /// Recovery must be confirmed by a human.
    ApprovalRequired,
    /// A required capability is unavailable.
    CapabilityUnavailable,
    /// Unrecoverable failure.
    Failed,
    /// Explicit cancellation.
    Cancelled,
    /// Every Task complete; the integration choice is pending.
    ReadyForFinish,
}

impl SddDisplayState {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::HtmlUnsynced => "html_unsynced",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::Undecidable => "undecidable",
            Self::WaitingHuman => "waiting_human",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::PlanChanged => "plan_changed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::RecoveryRequired => "recovery_required",
            Self::GitResultUnknown => "git_result_unknown",
            Self::ApprovalRequired => "approval_required",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReadyForFinish => "ready_for_finish",
        }
    }

    /// The specification failure class this display state reports, when it maps
    /// onto one. A human decision wait and a plain stop map onto none.
    pub const fn failure_code(self) -> Option<&'static str> {
        match self {
            Self::HtmlUnsynced => Some("html_not_synced"),
            Self::PlanChanged => Some("plan_changed"),
            Self::BudgetExhausted => Some("budget_exhausted"),
            Self::RecoveryRequired => Some("recovery_required"),
            Self::GitResultUnknown => Some("git_result_unknown"),
            Self::CapabilityUnavailable => Some("unavailable"),
            Self::ApprovalRequired => Some("approval_required"),
            _ => None,
        }
    }
}

/// The display state derived from the recorded snapshot and stop.
pub fn display_state(
    state: ExecutionState,
    stop: Option<StopRecord>,
    git_unknown: bool,
) -> SddDisplayState {
    if git_unknown {
        return SddDisplayState::GitResultUnknown;
    }
    if let Some(stop) = stop {
        match stop.reason() {
            StopReason::PlanChanged
            | StopReason::PlanMissing
            | StopReason::PlanMoved
            | StopReason::PlanObservationUnstable
            | StopReason::ApprovalStale => return SddDisplayState::PlanChanged,
            StopReason::HtmlNotApproved
            | StopReason::HtmlMissing
            | StopReason::HtmlMismatch
            | StopReason::HtmlUnsynced
            | StopReason::HtmlOrphaned => return SddDisplayState::HtmlUnsynced,
            StopReason::BudgetExhausted | StopReason::SupervisionLimitReached => {
                return SddDisplayState::BudgetExhausted;
            }
            StopReason::GitResultUnknown => return SddDisplayState::GitResultUnknown,
            StopReason::RecoveryRequired | StopReason::StopUnconfirmed => {
                return SddDisplayState::RecoveryRequired;
            }
            StopReason::CapabilityUnavailable => {
                return SddDisplayState::CapabilityUnavailable;
            }
            StopReason::ApprovalMissing
            | StopReason::ConsentMissing
            | StopReason::HumanDecisionRequired => {
                // `human_decision_required` is also how H3's undecidable
                // assessment reaches H4: the decision itself is the human's.
                if stop.required_action() == Some(HumanAction::ResolveHumanDecision) {
                    return SddDisplayState::Undecidable;
                }
                return SddDisplayState::ApprovalRequired;
            }
            StopReason::PauseRequested
            | StopReason::CancelRequested
            | StopReason::ChildStalled
            | StopReason::Blocked
            | StopReason::NeedsContext
            | StopReason::Conflict
            | StopReason::InternalFailure => {}
        }
    }
    match state {
        ExecutionState::Preview => SddDisplayState::Preview,
        ExecutionState::Ready => SddDisplayState::Ready,
        ExecutionState::Running => SddDisplayState::Running,
        ExecutionState::WaitingHtml => SddDisplayState::HtmlUnsynced,
        ExecutionState::Verifying => SddDisplayState::Verifying,
        ExecutionState::Committing => SddDisplayState::Committing,
        ExecutionState::WaitingHuman => SddDisplayState::WaitingHuman,
        ExecutionState::Stopping => SddDisplayState::Stopping,
        ExecutionState::Stopped => SddDisplayState::Stopped,
        ExecutionState::Failed => SddDisplayState::Failed,
        ExecutionState::Cancelled => SddDisplayState::Cancelled,
        ExecutionState::ReadyForFinish => SddDisplayState::ReadyForFinish,
    }
}

// ---------------------------------------------------------------------------
// Snapshot view
// ---------------------------------------------------------------------------

/// One recorded stop reason with the human action it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddStopView {
    reason: &'static str,
    required_action: Option<&'static str>,
}

impl SddStopView {
    /// Projects one stop record.
    pub fn of(stop: StopRecord) -> Self {
        Self {
            reason: stop.reason().as_str(),
            required_action: stop.required_action().map(HumanAction::as_str),
        }
    }

    /// Recorded reason label.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Required human action, when one is recorded.
    pub const fn required_action(&self) -> Option<&'static str> {
        self.required_action
    }
}

/// One Task's real commit range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddCommitRangeView {
    base: String,
    head: String,
    short: String,
}

impl SddCommitRangeView {
    /// Projects one recorded range.
    pub fn of(range: &CommitRange) -> Self {
        Self {
            base: range.base().to_string(),
            head: range.head().to_string(),
            short: range.short_range(),
        }
    }

    /// Full base SHA.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Full head SHA.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// The seven-character ledger form.
    pub fn short(&self) -> &str {
        &self.short
    }
}

/// One `no_change` Task's evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddNoChangeView {
    source_unchanged: bool,
    evidence: Vec<String>,
    detail: Option<String>,
}

impl SddNoChangeView {
    /// Projects one recorded no-change record.
    pub fn of(record: &NoChangeRecord) -> Self {
        Self {
            source_unchanged: record.source_unchanged(),
            evidence: record
                .evidence()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            detail: record.detail().map(str::to_owned),
        }
    }

    /// Whether the approved source was verified unchanged.
    pub const fn source_unchanged(&self) -> bool {
        self.source_unchanged
    }
}

/// One Task as the trusted UI reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddTaskView {
    stable_id: String,
    number: u32,
    progression: &'static str,
    phase: &'static str,
    h2: Option<String>,
    child: Option<String>,
    commit_policy: &'static str,
    commit_range: Option<SddCommitRangeView>,
    no_change: Option<SddNoChangeView>,
    evidence: Vec<String>,
    stop: Option<SddStopView>,
    applied_revision: AppliedRevisionView,
}

impl SddTaskView {
    /// Projects one Task snapshot.
    pub fn of(task: &TaskSnapshot) -> Self {
        Self {
            stable_id: task.task().stable_id().to_string(),
            number: task.task().number().get(),
            progression: task.progression().as_str(),
            phase: task.phase().as_str(),
            h2: task
                .h2_reference()
                .map(|h2| h2.supervision_id().to_string()),
            child: task.child().map(|child| child.agent_id().to_string()),
            commit_policy: task.commit_policy().as_str(),
            commit_range: task.commit_range().map(SddCommitRangeView::of),
            no_change: task.no_change().map(SddNoChangeView::of),
            evidence: task
                .evidence()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            stop: task.stop().map(SddStopView::of),
            applied_revision: AppliedRevisionView::of(task.applied_revision()),
        }
    }

    /// Plan-assigned Task number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Task progression label.
    pub const fn progression(&self) -> &'static str {
        self.progression
    }

    /// Task phase label.
    pub const fn phase(&self) -> &'static str {
        self.phase
    }
}

/// The plan revision applied to one Task or the execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedRevisionView {
    state: &'static str,
    revision: Option<u64>,
}

impl AppliedRevisionView {
    /// Projects one applied revision.
    pub fn of(applied: AppliedRevision) -> Self {
        Self {
            state: applied.state().as_str(),
            revision: applied.revision().map(|revision| revision.get()),
        }
    }

    /// `not_applied`, `current`, or `stale`.
    pub const fn state(&self) -> &'static str {
        self.state
    }
}

/// The approved plan identity in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddPlanIdentityView {
    path: String,
    digest: String,
    approved_revision: u64,
}

/// The checkout, branch, and fixed baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddWorkspaceIdentityView {
    checkout: String,
    branch: String,
    base_branch: String,
    baseline: Option<String>,
}

/// Consumed and reserved budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddBudgetConsumptionView {
    active_seconds: u64,
    additional_runs: u32,
    money_micros: Option<u64>,
}

impl SddBudgetConsumptionView {
    /// Projects one consumption value.
    pub fn of(consumption: BudgetConsumption) -> Self {
        Self {
            active_seconds: consumption.active_seconds(),
            additional_runs: consumption.additional_runs(),
            money_micros: consumption.money().map(herness_supervision::Money::micros),
        }
    }

    /// Cumulative active seconds.
    pub const fn active_seconds(&self) -> u64 {
        self.active_seconds
    }
}

/// Consumed and reserved budget in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddBudgetView {
    consumed: SddBudgetConsumptionView,
    reserved: SddBudgetConsumptionView,
}

impl SddBudgetView {
    /// Projects one budget.
    pub fn of(budget: SnapshotBudget) -> Self {
        Self {
            consumed: SddBudgetConsumptionView::of(budget.consumed()),
            reserved: SddBudgetConsumptionView::of(budget.reserved()),
        }
    }

    /// Consumed budget.
    pub const fn consumed(&self) -> SddBudgetConsumptionView {
        self.consumed
    }
}

/// One complete versioned execution snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddSnapshotView {
    version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: u64,
    state: &'static str,
    plan: SddPlanIdentityView,
    workspace: SddWorkspaceIdentityView,
    current_task: Option<u32>,
    tasks: Vec<SddTaskView>,
    stop: Option<SddStopView>,
    budget: SddBudgetView,
    applied_revision: AppliedRevisionView,
    final_project_sequence: Option<u64>,
    project_sequence: u64,
    display_state: &'static str,
    failure_code: Option<&'static str>,
    required_action: Option<&'static str>,
    git_result_unknown: Option<String>,
}

impl SddSnapshotView {
    /// Projects one durable snapshot.
    ///
    /// `project_sequence` is the observed H1 sequence of the project and
    /// `git_result_unknown` is the newest stored Git journal entry when its
    /// result is not established. Nothing is invented: an absent baseline, H2
    /// reference, child, range, or sequence stays `None`.
    pub fn of(
        snapshot: &ExecutionSnapshot,
        project_sequence: u64,
        git_result_unknown: Option<String>,
    ) -> Self {
        let stop = snapshot.stop();
        let state = display_state(snapshot.state(), stop, git_result_unknown.is_some());
        let applied = snapshot.applied_revision();
        Self {
            version: SDD_VIEW_VERSION,
            project_id: snapshot.project_id(),
            execution_id: snapshot.execution_id(),
            revision: snapshot.revision().get(),
            state: snapshot.state().as_str(),
            plan: SddPlanIdentityView {
                path: snapshot.plan().plan_path().as_str().to_owned(),
                digest: snapshot.plan().digest().as_str().to_owned(),
                approved_revision: snapshot.plan().approved_revision().get(),
            },
            workspace: SddWorkspaceIdentityView {
                checkout: snapshot.workspace().canonical_checkout_root().to_owned(),
                branch: snapshot.workspace().branch().to_owned(),
                base_branch: snapshot.workspace().base_branch().to_owned(),
                baseline: snapshot.workspace().baseline().map(ToString::to_string),
            },
            current_task: snapshot.current_task().map(|task| task.number().get()),
            tasks: snapshot.tasks().iter().map(SddTaskView::of).collect(),
            stop: stop.map(SddStopView::of),
            budget: SddBudgetView::of(snapshot.budget()),
            applied_revision: AppliedRevisionView::of(applied),
            final_project_sequence: snapshot
                .final_project_sequence()
                .map(herness_sdd_execute::ProjectSequence::get),
            project_sequence,
            display_state: state.as_str(),
            failure_code: state.failure_code(),
            required_action: stop
                .and_then(|stop| stop.required_action())
                .map(HumanAction::as_str),
            git_result_unknown,
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Durable revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Display state label.
    pub const fn display_state(&self) -> &'static str {
        self.display_state
    }

    /// The specification failure class this state reports, when it maps onto one.
    pub const fn failure_code(&self) -> Option<&'static str> {
        self.failure_code
    }

    /// Every Task in plan order.
    pub fn tasks(&self) -> &[SddTaskView] {
        &self.tasks
    }

    /// Consumed and reserved budget.
    pub const fn budget(&self) -> SddBudgetView {
        self.budget
    }

    /// Project sequence observed with this snapshot.
    pub const fn project_sequence(&self) -> u64 {
        self.project_sequence
    }

    /// The detail of an unestablished host commit result, when one exists.
    pub fn git_result_unknown(&self) -> Option<&str> {
        self.git_result_unknown.as_deref()
    }

    /// The approved plan identity.
    pub const fn plan(&self) -> &SddPlanIdentityView {
        &self.plan
    }

    /// The checkout, branch, and fixed baseline.
    pub const fn workspace(&self) -> &SddWorkspaceIdentityView {
        &self.workspace
    }
}

/// One reconnect answer: the saved snapshot plus the sequence it was read at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddSubscribeView {
    version: u32,
    snapshot: SddSnapshotView,
    sequence: u64,
    changed: bool,
}

impl SddSubscribeView {
    /// Wraps one snapshot and the sequence the caller last saw.
    pub fn of(snapshot: SddSnapshotView, since: Option<u64>) -> Self {
        let sequence = snapshot.project_sequence;
        Self {
            version: SDD_VIEW_VERSION,
            changed: since.is_none_or(|previous| previous < sequence),
            snapshot,
            sequence,
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The saved snapshot. It is the only progress input; the view never
    /// merges a command result into it.
    pub const fn snapshot(&self) -> &SddSnapshotView {
        &self.snapshot
    }

    /// Whether the sequence advanced past the caller's.
    pub const fn changed(&self) -> bool {
        self.changed
    }

    /// Current project sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

// ---------------------------------------------------------------------------
// Preview view
// ---------------------------------------------------------------------------

/// One approved-relevant Task inside a preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddPreviewTaskView {
    number: u32,
    title: String,
    stable_id: String,
    conditions: Vec<String>,
    checks: Vec<String>,
    html_targets: Vec<String>,
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    allow_shell: bool,
    commit_policy: &'static str,
    deliverables: Vec<String>,
}

impl SddPreviewTaskView {
    /// Plan-assigned number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Check identifiers.
    pub fn checks(&self) -> &[String] {
        &self.checks
    }
}

/// One read-only plan preview.
///
/// A preview permits no implementation: it has no model port, no worktree
/// creation, and no commit. It does not claim the prose matches the structured
/// block, and it does not claim the spec is approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddPreviewView {
    version: u32,
    project_id: ProjectId,
    project_root: String,
    plan_path: String,
    plan_digest: String,
    plan_revision: u64,
    byte_length: u64,
    schema_version: u32,
    pack_fingerprint: String,
    inspector_protocol: String,
    global_constraints_digest: String,
    spec_refs: Vec<String>,
    external_sources: Vec<String>,
    tasks: Vec<SddPreviewTaskView>,
    final_check_ids: Vec<String>,
    diagnostics: Vec<String>,
    side_effects: &'static str,
    format_last_checked: &'static str,
}

impl SddPreviewView {
    /// Projects one verified import.
    pub fn of(project_id: ProjectId, preview: &ImportPreview) -> Self {
        let parsed = preview.preview().parsed();
        let plan_revision = herness_sdd_execute::PlanRevision::INITIAL;
        let tasks = preview
            .preview()
            .tasks()
            .iter()
            .map(|task| {
                let stable = crate::sdd_execute::registry::derivation_uuid(
                    "h4.task.stable",
                    &format!(
                        "{}#{}",
                        preview.preview().plan_path().as_str(),
                        task.number()
                    ),
                );
                SddPreviewTaskView {
                    number: task.number(),
                    title: task.title().to_owned(),
                    stable_id: herness_sdd_execute::TaskStableId::from_parts(project_id, stable)
                        .to_string(),
                    conditions: task
                        .conditions()
                        .iter()
                        .map(|condition| format!("{}: {}", condition.id(), condition.title()))
                        .collect(),
                    checks: task
                        .checks()
                        .iter()
                        .map(|check| check.id().to_owned())
                        .collect(),
                    html_targets: task.html_targets().to_vec(),
                    read_paths: task.read_paths().to_vec(),
                    write_paths: task.write_paths().to_vec(),
                    allow_shell: task.allow_shell(),
                    commit_policy: task.commit_policy().as_str(),
                    deliverables: task
                        .deliverables()
                        .iter()
                        .map(|deliverable| deliverable.path().to_owned())
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        Self {
            version: SDD_VIEW_VERSION,
            project_id,
            project_root: preview.project_root().to_owned(),
            plan_path: preview.preview().plan_path().as_str().to_owned(),
            plan_digest: preview.preview().digest().as_str().to_owned(),
            plan_revision: plan_revision.get(),
            byte_length: preview.preview().byte_length(),
            schema_version: parsed.schema_version(),
            pack_fingerprint: preview.binding().fingerprint().as_str().to_owned(),
            inspector_protocol: preview.binding().protocol().name().to_owned(),
            global_constraints_digest: herness_sdd_execute::Sha256Digest::sha256(
                parsed.global_constraints().text().as_bytes(),
            )
            .as_str()
            .to_owned(),
            spec_refs: preview
                .specs()
                .snapshots()
                .iter()
                .map(|snapshot| format!("{}:{}", snapshot.source(), snapshot.path()))
                .collect(),
            external_sources: preview
                .preview()
                .spec_refs()
                .iter()
                .filter(|spec| !spec.is_project())
                .map(|spec| format!("{}:{}", spec.source(), spec.path()))
                .collect(),
            tasks,
            final_check_ids: parsed.final_check_ids().to_vec(),
            diagnostics: Vec::new(),
            side_effects: "none: preview reads the plan and its specs and sends nothing",
            format_last_checked: "the pack inspector checked structure and references only; it does not prove prose \
                 agreement or spec approval",
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Plan digest.
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    /// Every Task in plan order.
    pub fn tasks(&self) -> &[SddPreviewTaskView] {
        &self.tasks
    }
}

// ---------------------------------------------------------------------------
// Start disclosure
// ---------------------------------------------------------------------------

/// One Task's finite limits, as the human approves them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddTaskLimitView {
    number: u32,
    title: String,
    stable_id: String,
    active_seconds: u64,
    additional_runs: u32,
    money_limit_micros: Option<u64>,
    checks: usize,
    html_targets: Vec<String>,
    commit_policy: &'static str,
}

impl SddTaskLimitView {
    /// Plan-assigned number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Finite active seconds.
    pub const fn active_seconds(&self) -> u64 {
        self.active_seconds
    }

    /// Finite additional child runs.
    pub const fn additional_runs(&self) -> u32 {
        self.additional_runs
    }

    /// Money cap in micro-dollars, when one exists.
    pub const fn money_limit_micros(&self) -> Option<u64> {
        self.money_limit_micros
    }
}

/// One approved send scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddScopeView {
    project_id: ProjectId,
    checkout: String,
    branch: String,
    base_branch: String,
    isolated_worktree: bool,
    connection_id: String,
    profile_id: String,
    profile_version: u64,
    profile_purpose: &'static str,
    consents: Vec<String>,
    consent_target_scopes: Vec<u64>,
    host_commit: bool,
    run_hooks: bool,
}

impl SddScopeView {
    /// Canonical checkout.
    pub fn checkout(&self) -> &str {
        &self.checkout
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Approved consents in display form.
    pub fn consents(&self) -> &[String] {
        &self.consents
    }

    /// Whether the host stages and commits.
    pub const fn host_commit(&self) -> bool {
        self.host_commit
    }

    /// Whether repository hooks run.
    pub const fn run_hooks(&self) -> bool {
        self.run_hooks
    }
}

/// The complete start disclosure a human confirms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddStartDisclosureView {
    version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    approval_id: String,
    approval_revision: u64,
    plan_path: String,
    plan_digest: String,
    plan_revision: u64,
    scope: SddScopeView,
    tasks: Vec<SddTaskLimitView>,
    task_count: u32,
    multi_task_cost_warning: &'static str,
    h3_cycle_cost_warning: &'static str,
    unverified_capabilities: Vec<String>,
    limits: SddLimitsView,
    confirmation: &'static str,
}

/// The fixed numeric limits one start discloses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddLimitsView {
    max_concurrent_tasks: u32,
    max_supervision_seconds: u64,
    max_additional_runs: u32,
    max_consecutive_stalls: u32,
    host_commit_timeout_seconds: u64,
    plan_reconcile_seconds: u64,
    inspector_timeout_seconds: u64,
    max_plan_bytes: u64,
}

impl SddLimitsView {
    /// The approved specification values.
    pub const fn approved() -> Self {
        Self {
            max_concurrent_tasks: herness_sdd_execute::MAX_CONCURRENT_TASK_EXECUTIONS,
            max_supervision_seconds: herness_sdd_execute::H4_MAX_SUPERVISION_SECONDS,
            max_additional_runs: herness_sdd_execute::H4_MAX_ADDITIONAL_RUNS,
            max_consecutive_stalls: herness_sdd_execute::H4_MAX_CONSECUTIVE_STALLS,
            host_commit_timeout_seconds: herness_sdd_execute::HOST_COMMIT_TIMEOUT_SECONDS,
            plan_reconcile_seconds: herness_sdd_execute::PLAN_RECONCILE_INTERVAL_MILLIS / 1_000,
            inspector_timeout_seconds: herness_sdd_execute::INSPECTOR_TIMEOUT_SECONDS,
            max_plan_bytes: herness_sdd_execute::MAX_PLAN_BYTES,
        }
    }

    /// Maximum concurrent Task executions (always one).
    pub const fn max_concurrent_tasks(&self) -> u32 {
        self.max_concurrent_tasks
    }

    /// Cumulative supervision seconds per Task.
    pub const fn max_supervision_seconds(&self) -> u64 {
        self.max_supervision_seconds
    }
}

impl SddStartDisclosureView {
    /// Builds the disclosure from the human-confirmed approval.
    /// `unverified` names every capability this build cannot verify for the
    /// project. It is displayed, never hidden.
    pub fn of(
        execution: ExecutionId,
        approval: &herness_sdd_execute::ExecutionApproval,
        unverified: Vec<String>,
    ) -> Self {
        Self::from_content(
            execution,
            approval.approval_id(),
            approval.revision(),
            approval.content(),
            unverified,
        )
    }

    /// Builds the disclosure from approved content and its identity.
    pub fn from_content(
        execution: ExecutionId,
        approval_id: herness_sdd_execute::ApprovalId,
        approval_revision: u64,
        content: &herness_sdd_execute::ApprovalContent,
        unverified: Vec<String>,
    ) -> Self {
        let workspace = content.workspace();
        let connection = content.connection();
        let profile = connection.profile();
        let tasks = content
            .tasks()
            .iter()
            .map(|task| SddTaskLimitView {
                number: task.task().number().get(),
                title: task.title().to_owned(),
                stable_id: task.task().stable_id().to_string(),
                active_seconds: task.budget().active_seconds(),
                additional_runs: task.budget().additional_runs(),
                money_limit_micros: task.budget().money_cap().map(|cap| cap.limit().micros()),
                checks: task.checks().len(),
                html_targets: task.html_targets().to_vec(),
                commit_policy: task.commit_policy().as_str(),
            })
            .collect::<Vec<_>>();
        Self {
            version: SDD_VIEW_VERSION,
            project_id: content.workspace().project_id(),
            execution_id: execution,
            approval_id: approval_id.to_string(),
            approval_revision,
            plan_path: content.plan().plan_path().as_str().to_owned(),
            plan_digest: content.plan().digest().as_str().to_owned(),
            plan_revision: content.plan().plan_revision().get(),
            scope: SddScopeView {
                project_id: content.workspace().project_id(),
                checkout: workspace.canonical_checkout_root().to_owned(),
                branch: workspace.branch().to_owned(),
                base_branch: workspace.base_branch().to_owned(),
                isolated_worktree: workspace.isolated_worktree(),
                connection_id: connection.connection_id().to_string(),
                profile_id: profile.profile_id().to_string(),
                profile_version: profile.version().get(),
                profile_purpose: profile.purpose().as_str(),
                consents: connection
                    .consents()
                    .iter()
                    .map(|consent| {
                        format!(
                            "{}@{} (targets v{})",
                            consent.consent_id(),
                            consent.version(),
                            consent.target_scope_version().get()
                        )
                    })
                    .collect(),
                consent_target_scopes: connection
                    .consents()
                    .iter()
                    .map(|consent| consent.target_scope_version().get())
                    .collect(),
                host_commit: content.commit().host_commit(),
                run_hooks: content.commit().run_hooks(),
            },
            task_count: u32::try_from(tasks.len()).unwrap_or(u32::MAX),
            tasks,
            multi_task_cost_warning: MULTI_TASK_COST_WARNING,
            h3_cycle_cost_warning: H3_CYCLE_COST_WARNING,
            unverified_capabilities: unverified,
            limits: SddLimitsView::approved(),
            confirmation: "starting requires a human confirmation minted by the trusted main window; a plan \
                 string, a report, an environment variable, a receipt, an ApprovedOwner value, or \
                 an H4SddTask value never starts anything",
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Every Task's finite limits.
    pub fn tasks(&self) -> &[SddTaskLimitView] {
        &self.tasks
    }

    /// The approved scope: checkout, branch, connection, profile, consents, and
    /// the host commit authorization.
    pub const fn scope(&self) -> &SddScopeView {
        &self.scope
    }

    /// The fixed numeric limits.
    pub const fn limits(&self) -> SddLimitsView {
        self.limits
    }

    /// Number of Tasks in the plan.
    pub const fn task_count(&self) -> u32 {
        self.task_count
    }

    /// The multi-Task cost warning.
    pub const fn multi_task_cost_warning(&self) -> &'static str {
        self.multi_task_cost_warning
    }

    /// The separately approved H3 cycle warning.
    pub const fn h3_cycle_cost_warning(&self) -> &'static str {
        self.h3_cycle_cost_warning
    }

    /// Capabilities this build cannot verify.
    pub fn unverified_capabilities(&self) -> &[String] {
        &self.unverified_capabilities
    }

    /// The statement that only the trusted main window can confirm a start.
    pub const fn confirmation(&self) -> &'static str {
        self.confirmation
    }
}

// ---------------------------------------------------------------------------
// Finish handoff
// ---------------------------------------------------------------------------

/// One reason the execution is not ready to finish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddFinishBlockerView {
    kind: &'static str,
    detail: String,
    task: Option<u32>,
    check: Option<String>,
}

impl SddFinishBlockerView {
    /// Projects one finish blocker.
    pub fn of(blocker: &herness_sdd_execute::FinishBlocker) -> Self {
        let (kind, task, check) = match blocker {
            herness_sdd_execute::FinishBlocker::TaskNotComplete { task } => {
                ("task_not_complete", Some(*task), None)
            }
            herness_sdd_execute::FinishBlocker::ExecutionState { .. } => {
                ("execution_state", None, None)
            }
            herness_sdd_execute::FinishBlocker::OpenStop { .. } => ("open_stop", None, None),
            herness_sdd_execute::FinishBlocker::ApprovalStale { .. } => {
                ("approval_stale", None, None)
            }
            herness_sdd_execute::FinishBlocker::MissingFinalCheck { check } => {
                ("missing_final_check", None, Some(check.clone()))
            }
            herness_sdd_execute::FinishBlocker::IncompleteFinalCheck { check, .. } => {
                ("incomplete_final_check", None, Some(check.clone()))
            }
            herness_sdd_execute::FinishBlocker::StaleEvidence { .. } => {
                ("stale_evidence", None, None)
            }
            herness_sdd_execute::FinishBlocker::SpecReflection { .. } => {
                ("spec_reflection", None, None)
            }
        };
        Self {
            kind,
            detail: blocker.detail(),
            task,
            check,
        }
    }

    /// One durable reason the handoff is not ready.
    pub fn durable(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            task: None,
            check: None,
        }
    }

    /// Stable blocker label.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Non-secret explanation.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// One Task's completion in the handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddHandoffTaskView {
    number: u32,
    line: String,
    commit_range: Option<SddCommitRangeView>,
    no_change: Option<SddNoChangeView>,
}

impl SddHandoffTaskView {
    /// Projects one Task completion.
    pub fn of(entry: &herness_sdd_execute::TaskCompletionEntry) -> Self {
        match entry {
            herness_sdd_execute::TaskCompletionEntry::Range {
                number,
                base,
                head,
                short,
            } => Self {
                number: *number,
                line: entry.describe(),
                commit_range: Some(SddCommitRangeView {
                    base: base.clone(),
                    head: head.clone(),
                    short: short.clone(),
                }),
                no_change: None,
            },
            herness_sdd_execute::TaskCompletionEntry::NoChange { number, detail } => Self {
                number: *number,
                line: entry.describe(),
                commit_range: None,
                no_change: Some(SddNoChangeView {
                    source_unchanged: true,
                    evidence: Vec::new(),
                    detail: detail.clone(),
                }),
            },
        }
    }

    /// Task number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The `Task N: …` ledger line.
    pub fn line(&self) -> &str {
        &self.line
    }
}

/// The finish handoff, or the reasons it is not available.
///
/// `ready` is only `true` when the durable finish decision accepted the current
/// final state. A snapshot that is merely `ready_for_finish` by state is not
/// enough: the recorded final evidence must still cover the current content, and
/// this build records that decision in Task 22/25's composition. Until then the
/// view reports the explicit blocker instead of declaring success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddFinishHandoffView {
    version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: u64,
    state: &'static str,
    display_state: &'static str,
    ready: bool,
    checkout: String,
    branch: String,
    base_branch: String,
    baseline: Option<String>,
    plan_path: String,
    plan_digest: String,
    plan_revision: u64,
    final_check_ids: Vec<String>,
    tasks: Vec<SddHandoffTaskView>,
    unconfirmed: Vec<String>,
    stacked_pr_incompatibility: Option<String>,
    blockers: Vec<SddFinishBlockerView>,
    human_choice_required: bool,
    side_effects: &'static str,
}

impl SddFinishHandoffView {
    /// Builds a handoff view that is not ready yet.
    ///
    /// It names every durable finish input it can read and the exact reasons the
    /// decision did not accept, so the UI shows the real state instead of an
    /// invented completion.
    pub fn not_ready(
        snapshot: &ExecutionSnapshot,
        final_check_ids: Vec<String>,
        blockers: Vec<SddFinishBlockerView>,
    ) -> Self {
        let tasks = snapshot
            .tasks()
            .iter()
            .filter(|task| task.progression() == TaskProgression::Complete)
            .map(|task| {
                let number = task.task().number().get();
                SddHandoffTaskView {
                    number,
                    line: match task.commit_range() {
                        Some(range) => {
                            format!("Task {number}: complete (commits {})", range.short_range())
                        }
                        None => format!("Task {number}: complete (no_change)"),
                    },
                    commit_range: task.commit_range().map(SddCommitRangeView::of),
                    no_change: task.no_change().map(SddNoChangeView::of),
                }
            })
            .collect::<Vec<_>>();
        let stop = snapshot.stop();
        Self {
            version: SDD_VIEW_VERSION,
            project_id: snapshot.project_id(),
            execution_id: snapshot.execution_id(),
            revision: snapshot.revision().get(),
            state: snapshot.state().as_str(),
            display_state: display_state(snapshot.state(), stop, false).as_str(),
            ready: false,
            checkout: snapshot.workspace().canonical_checkout_root().to_owned(),
            branch: snapshot.workspace().branch().to_owned(),
            base_branch: snapshot.workspace().base_branch().to_owned(),
            baseline: snapshot.workspace().baseline().map(ToString::to_string),
            plan_path: snapshot.plan().plan_path().as_str().to_owned(),
            plan_digest: snapshot.plan().digest().as_str().to_owned(),
            plan_revision: snapshot.plan().approved_revision().get(),
            final_check_ids,
            tasks,
            unconfirmed: vec![
                "the final-state evidence decision is not part of this read".to_owned(),
            ],
            stacked_pr_incompatibility: stacked_pr_notice(snapshot),
            blockers,
            human_choice_required: true,
            side_effects: "none: presenting a handoff is not permission for a push, merge, PR, or publication",
        }
    }

    /// Builds the accepted handoff.
    pub fn accepted(
        handoff: &herness_sdd_execute::FinishHandoff,
        snapshot: &ExecutionSnapshot,
    ) -> Self {
        Self {
            version: SDD_VIEW_VERSION,
            project_id: snapshot.project_id(),
            execution_id: snapshot.execution_id(),
            revision: snapshot.revision().get(),
            state: snapshot.state().as_str(),
            display_state: display_state(snapshot.state(), snapshot.stop(), false).as_str(),
            ready: true,
            checkout: handoff.checkout().to_owned(),
            branch: handoff.branch().to_owned(),
            base_branch: handoff.base_branch().to_owned(),
            baseline: Some(handoff.baseline().to_string()),
            plan_path: handoff.plan_path().to_owned(),
            plan_digest: handoff.plan_digest().as_str().to_owned(),
            plan_revision: handoff.plan_revision(),
            final_check_ids: handoff.final_check_ids().to_vec(),
            tasks: handoff
                .task_completions()
                .iter()
                .map(SddHandoffTaskView::of)
                .collect(),
            unconfirmed: handoff.unconfirmed().to_vec(),
            stacked_pr_incompatibility: handoff.stacked_pr_incompatibility(),
            blockers: Vec::new(),
            human_choice_required: true,
            side_effects: "none: presenting a handoff is not permission for a push, merge, PR, or publication",
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Whether the durable decision accepted the current final state.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Every reason it is not ready.
    pub fn blockers(&self) -> &[SddFinishBlockerView] {
        &self.blockers
    }

    /// The integration choice is always the human's.
    pub const fn human_choice_required(&self) -> bool {
        self.human_choice_required
    }

    /// Every Task's real range or `no_change`.
    pub fn tasks(&self) -> &[SddHandoffTaskView] {
        &self.tasks
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Full `Branch baseline` SHA, when one is fixed.
    pub fn baseline(&self) -> Option<&str> {
        self.baseline.as_deref()
    }

    /// The theoretical side effects of presenting the handoff. Always none.
    pub const fn side_effects(&self) -> &'static str {
        self.side_effects
    }
}

fn stacked_pr_notice(snapshot: &ExecutionSnapshot) -> Option<String> {
    let no_change = snapshot
        .tasks()
        .iter()
        .filter(|task| {
            task.progression() == TaskProgression::Complete && task.commit_range().is_none()
        })
        .map(|task| task.task().number().get())
        .collect::<Vec<_>>();
    if no_change.is_empty() {
        return None;
    }
    Some(format!(
        "Task(s) {} completed with no commit range. The existing stack-prs flow requires a \
         non-empty range per Task, so a stacked-PR integration is unavailable for this execution.",
        no_change
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

/// The result of one approve-and-start.
///
/// It reports what is actually durable: the saved approval revision and the
/// `ready` snapshot with its start intent. `child_started` is `false` here
/// because the host dispatches the first Task from the stored snapshot; the UI
/// therefore never invents a running execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddStartView {
    version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    approval_id: String,
    approval_revision: u64,
    replayed: bool,
    child_started: bool,
    next_step: &'static str,
    disclosure: SddStartDisclosureView,
    snapshot: SddSnapshotView,
}

impl SddStartView {
    /// Builds the view from the durable values.
    pub fn new(
        approval: &herness_sdd_execute::ExecutionApproval,
        replayed: bool,
        disclosure: SddStartDisclosureView,
        snapshot: SddSnapshotView,
    ) -> Self {
        Self {
            version: SDD_VIEW_VERSION,
            project_id: approval.project_id(),
            execution_id: snapshot.execution_id(),
            approval_id: approval.approval_id().to_string(),
            approval_revision: approval.revision(),
            replayed,
            child_started: false,
            next_step: "the host dispatches the first incomplete Task from the saved snapshot",
            disclosure,
            snapshot,
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Saved approval revision.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// Whether the stored revision and snapshot were returned instead of writing
    /// again.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Whether this call created a child. It is `false`: the saved snapshot is
    /// the start intent.
    pub const fn child_started(&self) -> bool {
        self.child_started
    }

    /// The disclosure the human confirmed.
    pub const fn disclosure(&self) -> &SddStartDisclosureView {
        &self.disclosure
    }

    /// The saved snapshot.
    pub const fn snapshot(&self) -> &SddSnapshotView {
        &self.snapshot
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// The result of one idempotent update operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddOperationView {
    version: u32,
    operation: &'static str,
    replayed: bool,
    revision: u64,
    state: &'static str,
    display_state: &'static str,
    required_action: Option<&'static str>,
    project_sequence: u64,
    child_stop_requested: bool,
}

impl SddOperationView {
    /// Projects one operation result.
    pub fn of(
        operation: herness_sdd_execute::ExecutionOperation,
        replayed: bool,
        snapshot: &ExecutionSnapshot,
        project_sequence: u64,
        child_stop_requested: bool,
    ) -> Self {
        let stop = snapshot.stop();
        let state = display_state(snapshot.state(), stop, false);
        Self {
            version: SDD_VIEW_VERSION,
            operation: operation.as_str(),
            replayed,
            revision: snapshot.revision().get(),
            state: snapshot.state().as_str(),
            display_state: state.as_str(),
            required_action: stop
                .and_then(|stop| stop.required_action())
                .map(HumanAction::as_str),
            project_sequence,
            child_stop_requested,
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Whether the stored result was returned instead of repeating the effect.
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Resulting durable revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Resulting display state.
    pub const fn display_state(&self) -> &'static str {
        self.display_state
    }
}

// ---------------------------------------------------------------------------
// Resume
// ---------------------------------------------------------------------------

/// The result of one human resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SddResumeView {
    version: u32,
    outcome: &'static str,
    replayed: bool,
    revision: Option<u64>,
    state: Option<&'static str>,
    task: Option<u32>,
    commit_range: Option<SddCommitRangeView>,
    blockers: Vec<String>,
}

impl SddResumeView {
    /// Projects one resume outcome.
    pub fn of(outcome: &herness_sdd_execute::ResumeOutcome) -> Self {
        use herness_sdd_execute::ResumeOutcome;
        match outcome {
            ResumeOutcome::Resumed { task, revision, .. } => Self {
                version: SDD_VIEW_VERSION,
                outcome: "resumed",
                replayed: false,
                revision: Some(revision.get()),
                state: None,
                task: task.map(|task| task.number().get()),
                commit_range: None,
                blockers: Vec::new(),
            },
            ResumeOutcome::CommitLinked {
                task,
                range,
                revision,
                ..
            } => Self {
                version: SDD_VIEW_VERSION,
                outcome: "commit_linked",
                replayed: false,
                revision: Some(revision.get()),
                state: None,
                task: Some(task.number().get()),
                commit_range: Some(SddCommitRangeView::of(range)),
                blockers: Vec::new(),
            },
            ResumeOutcome::Blocked {
                blockers, revision, ..
            } => Self {
                version: SDD_VIEW_VERSION,
                outcome: "blocked",
                replayed: false,
                revision: revision.map(herness_sdd_execute::ExecutionRevision::get),
                state: None,
                task: None,
                commit_range: None,
                blockers: crate::sdd_execute::recovery::blocker_lines(blockers),
            },
            ResumeOutcome::Replayed { revision } => Self {
                version: SDD_VIEW_VERSION,
                outcome: "replayed",
                replayed: true,
                revision: Some(revision.get()),
                state: None,
                task: None,
                commit_range: None,
                blockers: Vec::new(),
            },
            ResumeOutcome::Finished { state, revision } => Self {
                version: SDD_VIEW_VERSION,
                outcome: "finished",
                replayed: false,
                revision: Some(revision.get()),
                state: Some(state.as_str()),
                task: None,
                commit_range: None,
                blockers: Vec::new(),
            },
        }
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Outcome label.
    pub const fn outcome(&self) -> &'static str {
        self.outcome
    }

    /// Blockers, when the resume was refused.
    pub fn blockers(&self) -> &[String] {
        &self.blockers
    }

    /// Resulting revision, when one was written.
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ten_specification_codes_are_distinct_and_displayed() {
        let states = [
            SddDisplayState::HtmlUnsynced,
            SddDisplayState::PlanChanged,
            SddDisplayState::BudgetExhausted,
            SddDisplayState::RecoveryRequired,
            SddDisplayState::GitResultUnknown,
        ];
        let codes = states
            .iter()
            .filter_map(|state| state.failure_code())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "html_not_synced",
                "plan_changed",
                "budget_exhausted",
                "recovery_required",
                "git_result_unknown"
            ]
        );
        assert_eq!(SddDisplayState::Undecidable.failure_code(), None);
    }

    #[test]
    fn a_git_unknown_journal_is_its_own_display_state() {
        let stop = StopRecord::new(StopReason::PauseRequested, Some(HumanAction::ConfirmStop))
            .expect("a stop");
        assert_eq!(
            display_state(ExecutionState::Running, Some(stop), true),
            SddDisplayState::GitResultUnknown
        );
        assert_eq!(
            display_state(ExecutionState::Running, Some(stop), false),
            SddDisplayState::Running
        );
    }

    #[test]
    fn an_undecidable_human_wait_is_not_a_plan_or_html_failure() {
        let stop = StopRecord::new(
            StopReason::HumanDecisionRequired,
            Some(HumanAction::ResolveHumanDecision),
        )
        .expect("a stop");
        let state = display_state(ExecutionState::WaitingHuman, Some(stop), false);
        assert_eq!(state, SddDisplayState::Undecidable);
        assert_eq!(state.as_str(), "undecidable");
        assert_eq!(state.failure_code(), None);
    }
}
