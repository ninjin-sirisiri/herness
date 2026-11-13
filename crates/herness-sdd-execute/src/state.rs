//! H4 execution states, Task progression and phases, stop reasons, and the
//! human action a stop requires.
//!
//! H4 states are separate from H1 run states and from H2 supervision states. An
//! H2 `completed` record is never an H4 Task completion; a Task becomes
//! `complete` only after H4's own verification, HTML barrier, host commit, and
//! durable write.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::PlanRevision;

/// State of one H4 execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    /// An imported, not yet approved plan preview.
    Preview,
    /// Approved and startable.
    Ready,
    /// A child is working on the current Task.
    Running,
    /// Waiting for the required H3 HTML synchronization.
    WaitingHtml,
    /// H2 is verifying the Task's conditions and evidence.
    Verifying,
    /// The target is fixed and the host Git side effects and result are being
    /// reconciled. This is not Task completion.
    Committing,
    /// A human decision, approval, consent, capability, or budget is required.
    WaitingHuman,
    /// A stop was requested and confirmation is pending.
    Stopping,
    /// The stop is confirmed, or recovery reconciliation is pending.
    Stopped,
    /// Unrecoverable failure. Not completion.
    Failed,
    /// Explicitly cancelled. Not completion.
    Cancelled,
    /// Every Task is complete, final full-suite evidence covers the final
    /// content, and an integration choice is pending.
    ReadyForFinish,
}

impl ExecutionState {
    /// Every execution state.
    pub const ALL: [Self; 12] = [
        Self::Preview,
        Self::Ready,
        Self::Running,
        Self::WaitingHtml,
        Self::Verifying,
        Self::Committing,
        Self::WaitingHuman,
        Self::Stopping,
        Self::Stopped,
        Self::Failed,
        Self::Cancelled,
        Self::ReadyForFinish,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::WaitingHtml => "waiting_html",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::WaitingHuman => "waiting_human",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReadyForFinish => "ready_for_finish",
        }
    }

    /// Whether the state is terminal for this execution. Further work needs a
    /// new execution or a human decision; `stopped` and `waiting_human` are not
    /// terminal because a human may resume.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::ReadyForFinish)
    }

    /// Whether the snapshot must carry a stop record with a required human
    /// action.
    pub const fn requires_human_action(self) -> bool {
        matches!(self, Self::WaitingHuman | Self::Stopped)
    }

    /// Whether this state may move to `next`.
    ///
    /// The legal flow is: `preview` → `ready` → `running` → one of
    /// `waiting_html`/`verifying`/`committing` → next Task or
    /// `ready_for_finish`. `waiting_human` and `stopped` may resume to the same
    /// Task; `stopping` confirms to `stopped`. `failed`, `cancelled`, and
    /// `ready_for_finish` are terminal.
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Preview => matches!(next, Self::Ready | Self::Failed | Self::Cancelled),
            Self::Ready => matches!(
                next,
                Self::Running
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Running => matches!(
                next,
                Self::WaitingHtml
                    | Self::Verifying
                    | Self::Committing
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::WaitingHtml => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Verifying => matches!(
                next,
                Self::Running
                    | Self::Committing
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Committing => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::ReadyForFinish
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::WaitingHuman => matches!(
                next,
                Self::Ready
                    | Self::Running
                    | Self::WaitingHtml
                    | Self::Verifying
                    | Self::Committing
                    | Self::Stopping
                    | Self::Stopped
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Stopping => matches!(next, Self::Stopped | Self::Failed | Self::Cancelled),
            Self::Stopped => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::WaitingHuman
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Failed | Self::Cancelled | Self::ReadyForFinish => false,
        }
    }

    /// Applies one transition or returns a typed refusal.
    pub fn transition_to(self, next: Self) -> Result<Self, crate::error::SddExecutionError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(crate::error::SddExecutionError::IllegalStateTransition {
                from: self.as_str().to_owned(),
                to: next.as_str().to_owned(),
            })
        }
    }
}

impl fmt::Display for ExecutionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-Task progression. It is not an H1 run state and not an H2 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskProgression {
    /// Not started.
    Pending,
    /// Started and not yet complete.
    Active,
    /// Complete after H4's own evidence, barrier, commit, and durable write.
    Complete,
}

impl TaskProgression {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Complete => "complete",
        }
    }

    /// Whether the Task is finished.
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

impl fmt::Display for TaskProgression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Phase of one Task. The execution state's `preview`, `ready`, and
/// `ready_for_finish` are execution-only; a Task uses `ready` before its first
/// dispatch and `complete` after its commit and durable write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPhase {
    /// Approved and not dispatched.
    Ready,
    /// A child is working.
    Running,
    /// Waiting for required HTML synchronization.
    WaitingHtml,
    /// H2 is verifying.
    Verifying,
    /// Host commit in progress.
    Committing,
    /// A human decision is required.
    WaitingHuman,
    /// A stop was requested.
    Stopping,
    /// The stop is confirmed or recovery is pending.
    Stopped,
    /// Unrecoverable failure. Not completion.
    Failed,
    /// Explicitly cancelled. Not completion.
    Cancelled,
    /// Complete after commit and durable write.
    Complete,
}

impl TaskPhase {
    /// Every Task phase.
    pub const ALL: [Self; 11] = [
        Self::Ready,
        Self::Running,
        Self::WaitingHtml,
        Self::Verifying,
        Self::Committing,
        Self::WaitingHuman,
        Self::Stopping,
        Self::Stopped,
        Self::Failed,
        Self::Cancelled,
        Self::Complete,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::WaitingHtml => "waiting_html",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::WaitingHuman => "waiting_human",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
        }
    }

    /// The progression this phase implies.
    pub const fn implied_progression(self) -> TaskProgression {
        match self {
            Self::Ready => TaskProgression::Pending,
            Self::Complete => TaskProgression::Complete,
            _ => TaskProgression::Active,
        }
    }

    /// Whether this phase requires a stop record with a required human action.
    pub const fn requires_human_action(self) -> bool {
        matches!(self, Self::WaitingHuman | Self::Stopped)
    }

    /// Whether this phase is terminal for the Task.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Complete)
    }

    /// Whether this Task phase may move to `next`.
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Ready => matches!(next, Self::Running | Self::Failed | Self::Cancelled),
            Self::Running => matches!(
                next,
                Self::WaitingHtml
                    | Self::Verifying
                    | Self::Committing
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::WaitingHtml => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Verifying => matches!(
                next,
                Self::Running
                    | Self::Committing
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Committing => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::Complete
                    | Self::WaitingHuman
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::WaitingHuman => matches!(
                next,
                Self::Running
                    | Self::WaitingHtml
                    | Self::Verifying
                    | Self::Stopping
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Stopping => matches!(next, Self::Stopped | Self::Failed | Self::Cancelled),
            Self::Stopped => matches!(
                next,
                Self::Running
                    | Self::Verifying
                    | Self::WaitingHuman
                    | Self::Failed
                    | Self::Cancelled
            ),
            Self::Failed | Self::Cancelled | Self::Complete => false,
        }
    }

    /// Applies one Task transition or returns a typed refusal.
    pub fn transition_to(self, next: Self) -> Result<Self, crate::error::SddExecutionError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(crate::error::SddExecutionError::IllegalStateTransition {
                from: self.as_str().to_owned(),
                to: next.as_str().to_owned(),
            })
        }
    }
}

impl fmt::Display for TaskPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an execution or Task is stopped or waiting for a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// A human asked to pause.
    PauseRequested,
    /// A human asked to cancel.
    CancelRequested,
    /// A human decision is required to continue.
    HumanDecisionRequired,
    /// The plan bytes changed.
    PlanChanged,
    /// The plan is no longer readable at its approved path.
    PlanMissing,
    /// The plan was moved.
    PlanMoved,
    /// Plan observation is unstable.
    PlanObservationUnstable,
    /// A stop is not yet confirmed.
    StopUnconfirmed,
    /// H3 requires settings approval.
    HtmlNotApproved,
    /// A required HTML document is missing.
    HtmlMissing,
    /// The saved HTML state does not match the current source.
    HtmlMismatch,
    /// A required HTML document is not synced.
    HtmlUnsynced,
    /// A removed or moved source left orphaned HTML.
    HtmlOrphaned,
    /// No current execution approval exists.
    ApprovalMissing,
    /// The approval no longer matches the current inputs.
    ApprovalStale,
    /// Required disclosure consent is missing.
    ConsentMissing,
    /// A required capability is unavailable.
    CapabilityUnavailable,
    /// The Task budget is exhausted.
    BudgetExhausted,
    /// An H2 supervision limit was reached.
    SupervisionLimitReached,
    /// The child stalled for the configured consecutive cycles.
    ChildStalled,
    /// The child reported BLOCKED.
    Blocked,
    /// The child reported NEEDS_CONTEXT.
    NeedsContext,
    /// Durable state, a process, or Git needs reconciliation.
    RecoveryRequired,
    /// The host commit result cannot be determined.
    GitResultUnknown,
    /// Inputs conflicted with a recorded request or another owner.
    Conflict,
    /// An unexpected host failure.
    InternalFailure,
}

impl StopReason {
    /// Every stop reason.
    pub const ALL: [Self; 26] = [
        Self::PauseRequested,
        Self::CancelRequested,
        Self::HumanDecisionRequired,
        Self::PlanChanged,
        Self::PlanMissing,
        Self::PlanMoved,
        Self::PlanObservationUnstable,
        Self::StopUnconfirmed,
        Self::HtmlNotApproved,
        Self::HtmlMissing,
        Self::HtmlMismatch,
        Self::HtmlUnsynced,
        Self::HtmlOrphaned,
        Self::ApprovalMissing,
        Self::ApprovalStale,
        Self::ConsentMissing,
        Self::CapabilityUnavailable,
        Self::BudgetExhausted,
        Self::SupervisionLimitReached,
        Self::ChildStalled,
        Self::Blocked,
        Self::NeedsContext,
        Self::RecoveryRequired,
        Self::GitResultUnknown,
        Self::Conflict,
        Self::InternalFailure,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PauseRequested => "pause_requested",
            Self::CancelRequested => "cancel_requested",
            Self::HumanDecisionRequired => "human_decision_required",
            Self::PlanChanged => "plan_changed",
            Self::PlanMissing => "plan_missing",
            Self::PlanMoved => "plan_moved",
            Self::PlanObservationUnstable => "plan_observation_unstable",
            Self::StopUnconfirmed => "stop_unconfirmed",
            Self::HtmlNotApproved => "html_not_approved",
            Self::HtmlMissing => "html_missing",
            Self::HtmlMismatch => "html_mismatch",
            Self::HtmlUnsynced => "html_unsynced",
            Self::HtmlOrphaned => "html_orphaned",
            Self::ApprovalMissing => "approval_missing",
            Self::ApprovalStale => "approval_stale",
            Self::ConsentMissing => "consent_missing",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::BudgetExhausted => "budget_exhausted",
            Self::SupervisionLimitReached => "supervision_limit_reached",
            Self::ChildStalled => "child_stalled",
            Self::Blocked => "blocked",
            Self::NeedsContext => "needs_context",
            Self::RecoveryRequired => "recovery_required",
            Self::GitResultUnknown => "git_result_unknown",
            Self::Conflict => "conflict",
            Self::InternalFailure => "internal_failure",
        }
    }

    /// The human action this reason normally requires.
    pub const fn default_required_action(self) -> Option<HumanAction> {
        match self {
            Self::PauseRequested | Self::CancelRequested | Self::InternalFailure => None,
            Self::HumanDecisionRequired => Some(HumanAction::ResolveHumanDecision),
            Self::PlanChanged | Self::PlanMissing | Self::PlanMoved => {
                Some(HumanAction::ResolvePlanChange)
            }
            Self::PlanObservationUnstable => Some(HumanAction::ResolvePlanChange),
            Self::StopUnconfirmed => Some(HumanAction::ConfirmStop),
            Self::HtmlNotApproved | Self::HtmlMissing | Self::HtmlMismatch | Self::HtmlUnsynced => {
                Some(HumanAction::ResolveHtmlSync)
            }
            Self::HtmlOrphaned => Some(HumanAction::ResolveOrphanedHtml),
            Self::ApprovalMissing => Some(HumanAction::GrantExecutionApproval),
            Self::ApprovalStale => Some(HumanAction::ApprovePlanRevision),
            Self::ConsentMissing => Some(HumanAction::RenewConsent),
            Self::CapabilityUnavailable => Some(HumanAction::ProvideCapability),
            Self::BudgetExhausted => Some(HumanAction::RaiseBudget),
            Self::SupervisionLimitReached => Some(HumanAction::ResolveLimit),
            Self::ChildStalled => Some(HumanAction::ClearStall),
            Self::Blocked => Some(HumanAction::ResolveBlockedTask),
            Self::NeedsContext => Some(HumanAction::ResolveNeedsContext),
            Self::RecoveryRequired => Some(HumanAction::ConfirmRecovery),
            Self::GitResultUnknown => Some(HumanAction::ConfirmGitRecovery),
            Self::Conflict => Some(HumanAction::ResolveConflict),
        }
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Human action required before the execution can continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanAction {
    /// Approve a changed plan revision.
    ApprovePlanRevision,
    /// Grant a current execution approval.
    GrantExecutionApproval,
    /// Confirm that a stop completed.
    ConfirmStop,
    /// Confirm recovery after a crash or unconfirmed stop.
    ConfirmRecovery,
    /// Confirm a host commit result.
    ConfirmGitRecovery,
    /// Resolve a plan change or unstable plan observation.
    ResolvePlanChange,
    /// Resolve required HTML synchronization.
    ResolveHtmlSync,
    /// Decide what to do with orphaned HTML.
    ResolveOrphanedHtml,
    /// Resolve a BLOCKED Task.
    ResolveBlockedTask,
    /// Provide the missing context a Task reported.
    ResolveNeedsContext,
    /// Renew disclosure consent.
    RenewConsent,
    /// Provide a required capability.
    ProvideCapability,
    /// Raise the finite Task budget.
    RaiseBudget,
    /// Resolve a reached supervision limit.
    ResolveLimit,
    /// Clear a stall with a human decision.
    ClearStall,
    /// Resolve a conflict.
    ResolveConflict,
    /// Make the human decision a Task blocked on.
    ResolveHumanDecision,
    /// Choose the integration path after finish handoff.
    ChooseFinishIntegration,
    /// Resolve an unexpected host failure.
    ResolveInternalFailure,
}

impl HumanAction {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApprovePlanRevision => "approve_plan_revision",
            Self::GrantExecutionApproval => "grant_execution_approval",
            Self::ConfirmStop => "confirm_stop",
            Self::ConfirmRecovery => "confirm_recovery",
            Self::ConfirmGitRecovery => "confirm_git_recovery",
            Self::ResolvePlanChange => "resolve_plan_change",
            Self::ResolveHtmlSync => "resolve_html_sync",
            Self::ResolveOrphanedHtml => "resolve_orphaned_html",
            Self::ResolveBlockedTask => "resolve_blocked_task",
            Self::ResolveNeedsContext => "resolve_needs_context",
            Self::RenewConsent => "renew_consent",
            Self::ProvideCapability => "provide_capability",
            Self::RaiseBudget => "raise_budget",
            Self::ResolveLimit => "resolve_limit",
            Self::ClearStall => "clear_stall",
            Self::ResolveConflict => "resolve_conflict",
            Self::ResolveHumanDecision => "resolve_human_decision",
            Self::ChooseFinishIntegration => "choose_finish_integration",
            Self::ResolveInternalFailure => "resolve_internal_failure",
        }
    }
}

impl fmt::Display for HumanAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reason recorded for a plan change or an unstable observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanChangeReason {
    /// The bytes at the approved path changed.
    BytesChanged,
    /// The plan is missing.
    Missing,
    /// The plan moved.
    Moved,
    /// Observation was unstable between reads.
    UnstableObservation,
}

/// Reason a required HTML document blocks Task progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlSyncReason {
    /// H3 settings are not approved.
    NotApproved,
    /// A required document is missing.
    Missing,
    /// The saved HTML state does not match the source.
    Mismatch,
    /// The document is not currently synced.
    Unsynced,
    /// A removed or moved source left orphaned output.
    Orphaned,
}

/// Reason recovery is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    /// A child or process stop is not confirmed.
    StopUnconfirmed,
    /// A request outcome was not observed.
    UnknownRequest,
    /// A host commit may or may not exist.
    GitResultUnconfirmed,
    /// Durable state could not be read.
    StateUnreadable,
    /// A stored version is not supported.
    VersionMismatch,
}

/// The finite budget that was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetExhaustionReason {
    /// Cumulative active seconds.
    ActiveSeconds,
    /// Additional child runs.
    AdditionalRuns,
    /// Consecutive stalls.
    ConsecutiveStalls,
    /// Optional money cap.
    MoneyCap,
}

/// Why a host commit result is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitUnknownReason {
    /// The commit budget expired.
    Timeout,
    /// A stop was requested during the commit.
    Stopped,
    /// The process result was not observed.
    UnobservedProcess,
    /// The journal write after the side effect failed.
    JournalWriteFailed,
    /// The resulting head could not be read.
    HeadUnreadable,
}

/// Why an update was refused as a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    /// The expected execution revision is not current.
    StaleRevision,
    /// The same request ID carries different content.
    DuplicateContent,
    /// The index or worktree has unrelated changes.
    DirtyIndex,
    /// An external edit raced the fixed target.
    ConcurrentEdit,
    /// Another execution owns the checkout and branch.
    OwnershipConflict,
    /// The Task is not in a state that can be dispatched or committed.
    TaskNotReady,
}

/// What a missing approval gate covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// An execution approval is required to start.
    StartApproval,
    /// A new approved plan revision is required.
    PlanRevisionApproval,
    /// Disclosure consent is required.
    DisclosureConsent,
    /// A capability is required.
    Capability,
    /// H3 settings approval is required.
    H3Settings,
    /// Host commit and hook authorization is required.
    HostCommit,
}

/// The stop reason and the human action it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopRecord {
    reason: StopReason,
    #[serde(default)]
    required_action: Option<HumanAction>,
}

impl StopRecord {
    /// Creates a stop record.
    pub fn new(
        reason: StopReason,
        required_action: Option<HumanAction>,
    ) -> Result<Self, crate::error::SddExecutionError> {
        if reason.default_required_action().is_some() && required_action.is_none() {
            return Err(crate::error::SddExecutionError::InvalidValue {
                field: "stop.requiredAction".to_owned(),
                detail: "a stop that needs a human decision must name the action".to_owned(),
            });
        }
        Ok(Self {
            reason,
            required_action,
        })
    }

    /// Stop reason.
    pub const fn reason(self) -> StopReason {
        self.reason
    }

    /// Required human action.
    pub const fn required_action(self) -> Option<HumanAction> {
        self.required_action
    }
}

/// How the current execution relates to one approved plan revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppliedRevisionState {
    /// No plan revision is applied yet.
    NotApplied,
    /// The newest approved revision is applied.
    Current,
    /// A newer approved revision exists; history is retained.
    Stale,
}

impl AppliedRevisionState {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::Current => "current",
            Self::Stale => "stale",
        }
    }
}

/// The plan revision currently applied and whether it is current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedRevision {
    state: AppliedRevisionState,
    #[serde(default)]
    revision: Option<PlanRevision>,
}

impl AppliedRevision {
    /// No revision applied yet.
    pub const fn not_applied() -> Self {
        Self {
            state: AppliedRevisionState::NotApplied,
            revision: None,
        }
    }

    /// The newest approved revision is applied.
    pub const fn current(revision: PlanRevision) -> Self {
        Self {
            state: AppliedRevisionState::Current,
            revision: Some(revision),
        }
    }

    /// An older revision is applied while a newer one is approved.
    pub const fn stale(revision: PlanRevision) -> Self {
        Self {
            state: AppliedRevisionState::Stale,
            revision: Some(revision),
        }
    }

    /// Applied state.
    pub const fn state(self) -> AppliedRevisionState {
        self.state
    }

    /// Applied revision, absent only when nothing is applied.
    pub const fn revision(self) -> Option<PlanRevision> {
        self.revision
    }

    /// Validates that the state and revision agree.
    pub fn validate(self) -> Result<(), crate::error::SddExecutionError> {
        let consistent = match self.state {
            AppliedRevisionState::NotApplied => self.revision.is_none(),
            AppliedRevisionState::Current | AppliedRevisionState::Stale => self.revision.is_some(),
        };
        if consistent {
            Ok(())
        } else {
            Err(crate::error::SddExecutionError::InvalidValue {
                field: "appliedRevision".to_owned(),
                detail: "the applied state and revision disagree".to_owned(),
            })
        }
    }
}
