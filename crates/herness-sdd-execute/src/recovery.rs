//! Post-crash reconciliation over saved state, and the human-confirmed resume.
//!
//! H4 keeps its intent, effect, and result in separate durable rows, so a crash
//! can leave a recorded intent without its result, a recorded result without its
//! snapshot, or a snapshot that no longer describes the checkout. This module
//! turns those rows into a deterministic classification and, after a human
//! confirmation, the one state transition that is safe.
//!
//! # Restore is read-only
//!
//! [`reconcile`] is a pure function over already-read values: the stored
//! snapshot, the saved journal rows, the observed H2 child states, the observed
//! checkout, and the observed progress document. It opens no port, starts no
//! child, sends no request, stages nothing, and writes nothing. The desktop
//! startup path assembles its inputs and then stores the resulting report, so a
//! restart restores approvals, Tasks, journals, budget, the stop latch, and the
//! plan-change latch without re-sending anything.
//!
//! # What each record becomes
//!
//! | Saved record | `Established` | `NotRun` | `Unknown` |
//! | --- | --- | --- | --- |
//! | Dispatch journal | a recorded dispatch result | no record and no reservation | an intent without a result, or a reservation without its journal |
//! | H2 child | a readable stored child state with a confirmed stop | no H2 target yet | the target is named but H2 has no record, an unconfirmed stop, or an unreadable state |
//! | Git journal | a commit observed with the saved parent, tree, trailers, and path bytes | no entry, or a recorded pre-commit rejection | an intent or an unknown result with no matching commit |
//! | Progress journal | the destination carries the recorded document digest | a recorded failed write | an unconfirmed write whose digest does not match |
//! | Control record | a stored operation result | — | an intent without its result (the snapshot revision decides, so it never blocks) |
//!
//! A recorded intent, an unknown result, and an unconfirmed process stop are
//! therefore **never** classified `NotRun`. Only the absence of a record, or a
//! recorded rejection that the host observed before the side effect, is
//! `NotRun`.
//!
//! # The human resume
//!
//! [`resume`] requires a [`HumanResume`] minted by the trusted desktop path,
//! re-checks the current approval inputs (plan bytes and parsed result, spec
//! snapshots, checkout, branch, baseline, connection, profile, consents, host
//! commit authorization, H3 boundary, and every Task's scope and budget), and
//! re-observes the plan through the gate. It then links exactly one clearly
//! established commit — the journal result first, then the Task completion — and
//! marks that Task `complete` so it is not dispatched again. Every remaining
//! unknown record becomes a durable `waiting_human` hold with the human action
//! that names it; nothing is retried and nothing is reset.
//!
//! Git and SQLite are not one transaction: a crash between the journal result
//! and the snapshot leaves an established commit with an unfinished Task, which
//! the next reconciliation classifies identically, so linking is idempotent.

use herness_core::contracts::ProjectId;

use crate::approval::ExecutionApproval;
use crate::approval_registry::{ApprovalInputs, ApprovalRevisionStorePort};
use crate::budget::{TaskBudget, TaskBudgetConsumption};
use crate::contract::{
    ContinuationLimits, ControlRecord, ExecutionOperation, ExecutionOperationRequest,
    ExecutionOperationResult,
};
use crate::coordinator::{ChildState, ChildStatus, ChildStopCause};
use crate::durable::{DurableExecutionStorePort, TaskReservation};
use crate::error::SddExecutionError;
use crate::git::{CommitObservation, CommitRecovery, classify_recorded};
use crate::ids::{
    ApprovalId, ControlRequestId, ExecutionId, ExecutionRevision, H2SupervisionRef, TaskRef,
};
use crate::journal::{
    DispatchJournalEntry, GitCommitOutcome, GitJournalEntry, GitJournalState, ProgressJournalEntry,
    ProgressWriteOutcome, RequestIdentity,
};
use crate::plan_changes::{
    PlanChange, PlanChangeGatePort, PlanChangeLatch, PlanChangeLatchStorePort,
};
use crate::ports::{ExecutionStorePort, StoredExecution};
use crate::snapshot::{
    BudgetConsumption, CommitRange, ExecutionSnapshot, SnapshotBudget, SnapshotInput, TaskSnapshot,
};
use crate::state::{
    ApprovalRequirement, ConflictReason, ExecutionState, HumanAction, RecoveryReason, StopReason,
    StopRecord, TaskPhase, TaskProgression,
};
use crate::version::Sha256Digest;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// One durable record kind the reconciliation inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryRecordKind {
    /// The one child dispatch of a Task: the H4 "send". H4 does not journal an
    /// H2 model request separately, so this record is the H4 send boundary.
    Dispatch,
    /// The stored H2 child state, including an unconfirmed stop.
    Process,
    /// The host commit journal of a Task.
    Git,
    /// The compatibility-ledger write.
    Progress,
    /// One idempotent control operation.
    Control,
}

impl RecoveryRecordKind {
    /// Every record kind.
    pub const ALL: [Self; 5] = [
        Self::Dispatch,
        Self::Process,
        Self::Git,
        Self::Progress,
        Self::Control,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::Process => "process",
            Self::Git => "git",
            Self::Progress => "progress",
            Self::Control => "control",
        }
    }
}

/// What one saved record reconciles to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryClass {
    /// The record and the observed state agree; the effect is known to exist.
    Established,
    /// The effect provably never started.
    NotRun,
    /// The effect cannot be determined. It is never retried or reset.
    Unknown,
}

impl RecoveryClass {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::NotRun => "not_run",
            Self::Unknown => "unknown",
        }
    }
}

/// One classified record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    kind: RecoveryRecordKind,
    task: Option<TaskRef>,
    request: Option<String>,
    class: RecoveryClass,
    detail: String,
    blocking: bool,
}

impl RecoveryItem {
    fn new(
        kind: RecoveryRecordKind,
        task: Option<TaskRef>,
        request: Option<String>,
        class: RecoveryClass,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            task,
            request,
            class,
            detail: detail.into(),
            blocking: false,
        }
    }

    fn blocking(mut self, blocking: bool) -> Self {
        self.blocking = blocking;
        self
    }

    /// Record kind.
    pub const fn kind(&self) -> RecoveryRecordKind {
        self.kind
    }

    /// Task the record belongs to, when it is Task-scoped.
    pub const fn task(&self) -> Option<TaskRef> {
        self.task
    }

    /// Idempotent request the record was saved under, when it has one.
    pub fn request(&self) -> Option<&str> {
        self.request.as_deref()
    }

    /// Classification.
    pub const fn class(&self) -> RecoveryClass {
        self.class
    }

    /// Non-secret explanation.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Whether this record may hold the human resume. An unknown record of an
    /// already complete Task is reported but does not block, because that Task is
    /// never dispatched or committed again.
    pub const fn is_blocking(&self) -> bool {
        self.blocking
    }
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// Every saved and observed value one reconciliation reads.
///
/// The desktop startup path fills it from the durable store, the H2 records, one
/// read-only checkout observation, and the exact progress-document bytes. It
/// holds no port and performs no I/O itself.
#[derive(Debug, Clone, Default)]
pub struct RecoveryFacts {
    dispatch: Vec<DispatchJournalEntry>,
    git: Vec<GitJournalEntry>,
    progress: Vec<ProgressJournalEntry>,
    control: Vec<ControlRecord>,
    reservations: Vec<TaskReservation>,
    children: Vec<ChildStatus>,
    observation: Option<CommitObservation>,
    documents: Vec<(String, Option<Sha256Digest>)>,
}

impl RecoveryFacts {
    /// No saved record and no observation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the saved dispatch journal rows.
    #[must_use]
    pub fn with_dispatch(mut self, entries: Vec<DispatchJournalEntry>) -> Self {
        self.dispatch = entries;
        self
    }

    /// Records the saved Git journal rows.
    #[must_use]
    pub fn with_git(mut self, entries: Vec<GitJournalEntry>) -> Self {
        self.git = entries;
        self
    }

    /// Records the saved progress journal rows.
    #[must_use]
    pub fn with_progress(mut self, entries: Vec<ProgressJournalEntry>) -> Self {
        self.progress = entries;
        self
    }

    /// Records the saved control-operation rows.
    #[must_use]
    pub fn with_control(mut self, records: Vec<ControlRecord>) -> Self {
        self.control = records;
        self
    }

    /// Records the saved Task reservations.
    #[must_use]
    pub fn with_reservations(mut self, reservations: Vec<TaskReservation>) -> Self {
        self.reservations = reservations;
        self
    }

    /// Records one observed H2 child state.
    #[must_use]
    pub fn with_child(mut self, status: ChildStatus) -> Self {
        self.children.push(status);
        self
    }

    /// Records the read-only checkout observation.
    #[must_use]
    pub fn with_observation(mut self, observation: CommitObservation) -> Self {
        self.observation = Some(observation);
        self
    }

    /// Records the observed bytes digest of one progress document.
    ///
    /// The outer `None` records that the document is absent, which is the
    /// expected state before the first write.
    #[must_use]
    pub fn with_document(mut self, path: impl Into<String>, digest: Option<Sha256Digest>) -> Self {
        self.documents.push((path.into(), digest));
        self
    }

    /// The saved dispatch journal rows.
    pub fn dispatch(&self) -> &[DispatchJournalEntry] {
        &self.dispatch
    }

    /// The saved Git journal rows.
    pub fn git(&self) -> &[GitJournalEntry] {
        &self.git
    }

    /// The saved progress journal rows.
    pub fn progress(&self) -> &[ProgressJournalEntry] {
        &self.progress
    }

    /// The saved control-operation rows.
    pub fn control(&self) -> &[ControlRecord] {
        &self.control
    }

    /// The saved Task reservations.
    pub fn reservations(&self) -> &[TaskReservation] {
        &self.reservations
    }

    /// The observed H2 child states.
    pub fn children(&self) -> &[ChildStatus] {
        &self.children
    }

    /// The read-only checkout observation, when one was obtained.
    pub fn observation(&self) -> Option<&CommitObservation> {
        self.observation.as_ref()
    }

    /// The observed digest of one progress document.
    pub fn document(&self, path: &str) -> Option<Option<&Sha256Digest>> {
        self.documents
            .iter()
            .find(|(stored, _)| stored == path)
            .map(|(_, digest)| digest.as_ref())
    }
}

/// The other saved values one reconciliation reports.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoveryContext<'a> {
    /// The current open or cleared plan-change latch, when one exists.
    pub plan_change: Option<&'a PlanChangeLatch>,
    /// The newest stored approval revision, when one exists.
    pub approval: Option<&'a ExecutionApproval>,
}

impl<'a> RecoveryContext<'a> {
    /// No latch and no approval.
    pub const fn none() -> Self {
        Self {
            plan_change: None,
            approval: None,
        }
    }

    /// Records the plan-change latch.
    #[must_use]
    pub const fn with_plan_change(mut self, latch: &'a PlanChangeLatch) -> Self {
        self.plan_change = Some(latch);
        self
    }

    /// Records the stored approval.
    #[must_use]
    pub const fn with_approval(mut self, approval: &'a ExecutionApproval) -> Self {
        self.approval = Some(approval);
        self
    }
}

/// One clearly established commit that a human resume may still link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCommit {
    entry: GitJournalEntry,
    commit: crate::ids::CommitSha,
    tree: crate::ids::TreeSha,
    parent: crate::ids::CommitSha,
    range: CommitRange,
}

impl PendingCommit {
    /// The saved journal row.
    pub const fn entry(&self) -> &GitJournalEntry {
        &self.entry
    }

    /// The observed commit object.
    pub const fn commit(&self) -> &crate::ids::CommitSha {
        &self.commit
    }

    /// The observed tree.
    pub const fn tree(&self) -> &crate::ids::TreeSha {
        &self.tree
    }

    /// The observed parent.
    pub const fn parent(&self) -> &crate::ids::CommitSha {
        &self.parent
    }

    /// `BASE..commit` range the link records.
    pub const fn range(&self) -> &CommitRange {
        &self.range
    }
}

/// The reconciled state of one Task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryTaskState {
    task: TaskRef,
    progression: TaskProgression,
    phase: TaskPhase,
    h2_reference: Option<H2SupervisionRef>,
    commit_range: Option<CommitRange>,
    stop: Option<StopRecord>,
    pending_commit: Option<PendingCommit>,
}

impl RecoveryTaskState {
    /// The Task.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Durable progression.
    pub const fn progression(&self) -> TaskProgression {
        self.progression
    }

    /// Durable phase.
    pub const fn phase(&self) -> TaskPhase {
        self.phase
    }

    /// H2 target reference, when one exists.
    pub const fn h2_reference(&self) -> Option<H2SupervisionRef> {
        self.h2_reference
    }

    /// Completed commit range, when the Task advanced HEAD.
    pub fn commit_range(&self) -> Option<&CommitRange> {
        self.commit_range.as_ref()
    }

    /// Durable stop record.
    pub const fn stop(&self) -> Option<StopRecord> {
        self.stop
    }

    /// The established commit that is not linked into the durable state yet.
    pub const fn pending_commit(&self) -> Option<&PendingCommit> {
        self.pending_commit.as_ref()
    }

    /// Whether the Task is complete.
    pub const fn is_complete(&self) -> bool {
        self.progression.is_complete()
    }
}

/// One execution's reconciled state. It is the restore result: nothing here was
/// written and nothing here started or sent anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    project_id: ProjectId,
    execution_id: ExecutionId,
    saved_revision: ExecutionRevision,
    state: ExecutionState,
    approval_id: Option<ApprovalId>,
    approval_revision: Option<u64>,
    tasks: Vec<RecoveryTaskState>,
    items: Vec<RecoveryItem>,
    stop: Option<StopRecord>,
    plan_change: Option<PlanChangeLatch>,
    budget: TaskBudgetConsumption,
    remaining_seconds: u64,
}

impl RecoveryReport {
    /// Project that owns the execution.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Durable revision the report was built from.
    pub const fn saved_revision(&self) -> ExecutionRevision {
        self.saved_revision
    }

    /// Durable execution state.
    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    /// Stored approval identity, when one exists.
    pub const fn approval_id(&self) -> Option<ApprovalId> {
        self.approval_id
    }

    /// Stored approval revision, when one exists.
    pub const fn approval_revision(&self) -> Option<u64> {
        self.approval_revision
    }

    /// Every Task in plan order.
    pub fn tasks(&self) -> &[RecoveryTaskState] {
        &self.tasks
    }

    /// Every classified record.
    pub fn items(&self) -> &[RecoveryItem] {
        &self.items
    }

    /// The durable execution-level stop record.
    pub const fn stop(&self) -> Option<StopRecord> {
        self.stop
    }

    /// The plan-change latch, open or cleared.
    pub const fn plan_change(&self) -> Option<&PlanChangeLatch> {
        self.plan_change.as_ref()
    }

    /// Whether an open plan-change latch holds new dispatch and commit.
    pub fn plan_change_open(&self) -> bool {
        self.plan_change
            .as_ref()
            .is_some_and(PlanChangeLatch::is_open)
    }

    /// Consumed combined Task budget.
    pub const fn budget(&self) -> TaskBudgetConsumption {
        self.budget
    }

    /// Remaining combined Task seconds.
    pub const fn remaining_seconds(&self) -> u64 {
        self.remaining_seconds
    }

    /// External requests issued while restoring. It is always zero: the restore
    /// reads saved values only.
    pub const fn external_requests(&self) -> u32 {
        0
    }

    /// The Task whose established commit is not linked yet.
    pub fn pending_link(&self) -> Option<&RecoveryTaskState> {
        self.tasks
            .iter()
            .find(|task| task.pending_commit.is_some() && !task.is_complete())
    }

    /// Every record classified `Unknown`.
    pub fn unknown(&self) -> impl Iterator<Item = &RecoveryItem> {
        self.items
            .iter()
            .filter(|item| item.class == RecoveryClass::Unknown)
    }

    /// Every record classified `Established`.
    pub fn established(&self) -> impl Iterator<Item = &RecoveryItem> {
        self.items
            .iter()
            .filter(|item| item.class == RecoveryClass::Established)
    }

    /// Every record classified `NotRun`.
    pub fn not_run(&self) -> impl Iterator<Item = &RecoveryItem> {
        self.items
            .iter()
            .filter(|item| item.class == RecoveryClass::NotRun)
    }

    /// The unknown records that hold the human resume.
    pub fn blockers(&self) -> impl Iterator<Item = &RecoveryItem> {
        self.items
            .iter()
            .filter(|item| item.class == RecoveryClass::Unknown && item.blocking)
    }

    /// Whether every record reconciles and no established commit is unlinked.
    pub fn is_clean(&self) -> bool {
        self.blockers().next().is_none() && self.pending_link().is_none()
    }
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// Reconciles one execution from already-read values.
///
/// It performs no I/O and mutates nothing. An unknown approval does not prevent
/// the report; it is simply absent.
pub fn reconcile(
    stored: &StoredExecution,
    facts: &RecoveryFacts,
    context: RecoveryContext<'_>,
) -> Result<RecoveryReport, SddExecutionError> {
    let snapshot = stored.snapshot();
    let mut items = Vec::new();
    let mut tasks = Vec::with_capacity(snapshot.tasks().len());
    let mut consecutive_stalls = 0u32;

    for task in snapshot.tasks() {
        let task_ref = task.task();
        let complete = task.progression().is_complete();

        items.push(classify_dispatch(snapshot.execution_id(), task_ref, facts).blocking(!complete));

        let (process, stalls) = classify_process(task_ref, task.h2_reference(), facts);
        consecutive_stalls = consecutive_stalls.max(stalls);
        items.push(process.blocking(!complete));

        let (git, pending) = classify_git(task_ref, complete, facts);
        items.push(git.blocking(!complete));

        tasks.push(RecoveryTaskState {
            task: task_ref,
            progression: task.progression(),
            phase: task.phase(),
            h2_reference: task.h2_reference(),
            commit_range: task.commit_range().cloned(),
            stop: task.stop(),
            pending_commit: pending.filter(|_| !complete),
        });
    }

    items.extend(classify_progress(facts));
    items.extend(classify_control(facts));

    let combined = TaskBudget::from_snapshot(
        ContinuationLimits::h4_default(),
        snapshot.budget().consumed(),
        consecutive_stalls,
    )?;

    Ok(RecoveryReport {
        project_id: snapshot.project_id(),
        execution_id: snapshot.execution_id(),
        saved_revision: stored.revision(),
        state: snapshot.state(),
        approval_id: context.approval.map(ExecutionApproval::approval_id),
        approval_revision: context.approval.map(ExecutionApproval::revision),
        tasks,
        items,
        stop: snapshot.stop(),
        plan_change: context.plan_change.cloned(),
        budget: combined.consumption(),
        remaining_seconds: combined.remaining_seconds(),
    })
}

fn classify_dispatch(execution: ExecutionId, task: TaskRef, facts: &RecoveryFacts) -> RecoveryItem {
    let expected = crate::coordinator::dispatch_request_id(execution, task);
    let entry = facts
        .dispatch
        .iter()
        .find(|entry| entry.identity().request_id() == expected);
    let reserved = facts
        .reservations
        .iter()
        .any(|reservation| reservation.task() == task);
    let request = Some(expected.to_string());
    let kind = RecoveryRecordKind::Dispatch;

    if let Some(entry) = entry {
        let (class, detail) = if entry.outcome().is_some() {
            (
                RecoveryClass::Established,
                "a dispatch result is recorded, so the one child exists and is never re-dispatched",
            )
        } else {
            (
                RecoveryClass::Unknown,
                "the dispatch intent is recorded without its result, so the child may exist",
            )
        };
        return RecoveryItem::new(kind, Some(task), request, class, detail);
    }
    if reserved {
        return RecoveryItem::new(
            kind,
            Some(task),
            None,
            RecoveryClass::Unknown,
            "a Task reservation exists without its dispatch journal",
        );
    }
    RecoveryItem::new(
        kind,
        Some(task),
        None,
        RecoveryClass::NotRun,
        "no dispatch intent was recorded, so no child was created",
    )
}

fn classify_process(
    task: TaskRef,
    h2: Option<H2SupervisionRef>,
    facts: &RecoveryFacts,
) -> (RecoveryItem, u32) {
    let Some(h2) = h2 else {
        return (
            RecoveryItem::new(
                RecoveryRecordKind::Process,
                Some(task),
                None,
                RecoveryClass::NotRun,
                "the Task names no H2 target",
            ),
            0,
        );
    };
    let status = facts
        .children
        .iter()
        .find(|status| status.supervision_id() == h2.supervision_id());
    let Some(status) = status else {
        return (
            RecoveryItem::new(
                RecoveryRecordKind::Process,
                Some(task),
                None,
                RecoveryClass::Unknown,
                "the Task names an H2 target that H2 does not record",
            ),
            0,
        );
    };
    let stalls = status.consecutive_stalls();
    if status.state() == ChildState::Stopped
        && status.stop_cause() == Some(ChildStopCause::StopUnconfirmed)
    {
        return (
            RecoveryItem::new(
                RecoveryRecordKind::Process,
                Some(task),
                None,
                RecoveryClass::Unknown,
                STOP_UNCONFIRMED,
            ),
            stalls,
        );
    }
    if status.state() == ChildState::Unknown {
        return (
            RecoveryItem::new(
                RecoveryRecordKind::Process,
                Some(task),
                None,
                RecoveryClass::Unknown,
                "the stored H2 child state cannot be interpreted",
            ),
            stalls,
        );
    }
    (
        RecoveryItem::new(
            RecoveryRecordKind::Process,
            Some(task),
            None,
            RecoveryClass::Established,
            format!("the stored H2 child state is {}", status.state().as_str()),
        ),
        stalls,
    )
}

const STOP_UNCONFIRMED: &str = "the child stop is not confirmed; it is never reported as stopped";

fn classify_git(
    task: TaskRef,
    complete: bool,
    facts: &RecoveryFacts,
) -> (RecoveryItem, Option<PendingCommit>) {
    let entries = facts
        .git
        .iter()
        .filter(|entry| entry.intent().task() == task)
        .collect::<Vec<_>>();
    let request = entries
        .last()
        .map(|entry| entry.identity().request_id().to_string());
    let kind = RecoveryRecordKind::Git;

    let Some(entry) = entries.last() else {
        let detail = if complete {
            "the Task records its completion and no Git journal exists"
        } else {
            "no commit intent was recorded, so no host commit ran"
        };
        return (
            RecoveryItem::new(kind, Some(task), None, RecoveryClass::NotRun, detail),
            None,
        );
    };

    let recovery = match facts.observation() {
        Some(observation) => classify_recorded(entry.intent(), entry.outcome(), observation),
        None => CommitRecovery::Unknown {
            detail: "the checkout could not be observed".to_owned(),
        },
    };
    match recovery {
        CommitRecovery::Established {
            commit,
            tree,
            parent,
            range,
        } => (
            RecoveryItem::new(
                kind,
                Some(task),
                request,
                RecoveryClass::Established,
                "the checkout carries exactly the saved commit and its content",
            ),
            Some(PendingCommit {
                entry: (*entry).clone(),
                commit,
                tree,
                parent,
                range,
            }),
        ),
        CommitRecovery::NotRun => {
            // Only a recorded rejection is a proven non-commit. An intent or an
            // unknown result whose HEAD simply did not move is still unknown.
            let class = match entry.state() {
                GitJournalState::Rejected => RecoveryClass::NotRun,
                _ => RecoveryClass::Unknown,
            };
            let detail = match class {
                RecoveryClass::NotRun => {
                    "the host recorded a refusal before creating a commit".to_owned()
                }
                _ => "the intent is recorded and HEAD is still the expected parent, but the \
                       commit result was not observed; it is never executed again"
                    .to_owned(),
            };
            (
                RecoveryItem::new(kind, Some(task), request, class, detail),
                None,
            )
        }
        CommitRecovery::Unknown { detail } => (
            RecoveryItem::new(kind, Some(task), request, RecoveryClass::Unknown, detail),
            None,
        ),
    }
}

fn classify_progress(facts: &RecoveryFacts) -> Vec<RecoveryItem> {
    facts
        .progress
        .iter()
        .map(|entry| {
            let content = entry.content();
            let expected = content.document_digest();
            let observed = facts.document(content.output_path());
            let matches = matches!(observed, Some(Some(digest)) if digest == expected);
            let request = Some(entry.identity().request_id().to_string());
            let (class, detail) = match (entry.outcome(), matches) {
                (Some(ProgressWriteOutcome::Written { .. }), true) => (
                    RecoveryClass::Established,
                    "the ledger carries the recorded document digest",
                ),
                (Some(ProgressWriteOutcome::Written { .. }), false) => (
                    RecoveryClass::Unknown,
                    "the recorded ledger digest is not the digest on disk",
                ),
                (Some(ProgressWriteOutcome::Failed { .. }), _) => (
                    RecoveryClass::NotRun,
                    "the host recorded a failed ledger write",
                ),
                (Some(ProgressWriteOutcome::Unknown) | None, true) => (
                    RecoveryClass::Established,
                    "the ledger already carries the intended document",
                ),
                (Some(ProgressWriteOutcome::Unknown) | None, false) => (
                    RecoveryClass::Unknown,
                    "the ledger write result was not confirmed and the document does not match",
                ),
            };
            RecoveryItem::new(RecoveryRecordKind::Progress, None, request, class, detail)
        })
        .collect()
}

fn classify_control(facts: &RecoveryFacts) -> Vec<RecoveryItem> {
    facts
        .control
        .iter()
        .map(|record| {
            let request = Some(record.identity().request_id().to_string());
            let (class, detail) = if record.outcome().is_some() {
                (
                    RecoveryClass::Established,
                    "the operation result is recorded",
                )
            } else {
                (
                    RecoveryClass::Unknown,
                    "the operation intent has no stored result; the snapshot revision decides \
                     whether it applied, so it never re-runs",
                )
            };
            RecoveryItem::new(RecoveryRecordKind::Control, None, request, class, detail)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Quit
// ---------------------------------------------------------------------------

/// The execution-level stop a quit records before the stop is confirmed.
pub fn quit_stop_requested() -> Result<StopRecord, SddExecutionError> {
    StopRecord::new(StopReason::PauseRequested, Some(HumanAction::ConfirmStop))
}

/// The execution-level stop a quit records once H1 reported the stop.
///
/// A stop H1 did not confirm is `StopUnconfirmed`; it is never recorded as a
/// confirmed stop.
pub fn quit_stop_recorded(confirmed: bool) -> Result<StopRecord, SddExecutionError> {
    if confirmed {
        StopRecord::new(
            StopReason::RecoveryRequired,
            Some(HumanAction::ConfirmRecovery),
        )
    } else {
        StopRecord::new(StopReason::StopUnconfirmed, Some(HumanAction::ConfirmStop))
    }
}

/// Whether a quit must not touch this execution.
pub fn quit_skips(snapshot: &ExecutionSnapshot) -> bool {
    matches!(
        snapshot.state(),
        ExecutionState::Preview
            | ExecutionState::Stopped
            | ExecutionState::Failed
            | ExecutionState::Cancelled
            | ExecutionState::ReadyForFinish
    )
}

/// Returns the snapshot a quit writes to close dispatch, sends, and commits.
///
/// The state becomes `waiting_human` with the stop a human must confirm. That is
/// a state the coordinator refuses before any side effect, so a restarted
/// process cannot dispatch, send, or commit while the stop is only requested.
pub fn quit_requested_snapshot(
    snapshot: &ExecutionSnapshot,
    revision: ExecutionRevision,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    snapshot.held_waiting_human(revision, quit_stop_requested()?)
}

/// Returns the snapshot a quit writes once the H1 stop facts are known.
///
/// A confirmed stop becomes `stopped` with `recovery_required`; an unconfirmed
/// stop becomes `stopped` with `stop_unconfirmed`. Both keep every Task
/// progression, commit range, no-change record, evidence, baseline, and the
/// consumed budget.
pub fn quit_confirmed_snapshot(
    snapshot: &ExecutionSnapshot,
    revision: ExecutionRevision,
    confirmed: bool,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let stop = quit_stop_recorded(confirmed)?;
    let state = match snapshot.state() {
        ExecutionState::Stopped | ExecutionState::Stopping => ExecutionState::Stopped,
        other => match other.transition_to(ExecutionState::Stopped) {
            Ok(stopped) => stopped,
            // A ready, running, waiting_html, verifying, or committing execution
            // reaches `stopped` through the `waiting_human` hold a quit writes
            // first. The transition is not skipped: the state machine still
            // requires every intermediate step.
            Err(_) => other
                .transition_to(ExecutionState::WaitingHuman)?
                .transition_to(ExecutionState::Stopped)?,
        },
    };
    ExecutionSnapshot::new(SnapshotInput {
        project_id: snapshot.project_id(),
        execution_id: snapshot.execution_id(),
        revision,
        state,
        plan: snapshot.plan().clone(),
        workspace: snapshot.workspace().clone(),
        current_task: snapshot.current_task(),
        tasks: snapshot.tasks().to_vec(),
        stop: Some(stop),
        budget: snapshot.budget(),
        applied_revision: snapshot.applied_revision(),
        final_project_sequence: snapshot.final_project_sequence(),
    })
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// Enumeration of the durable rows one crash reconciliation inspects.
///
/// [`ExecutionStorePort`] reads one request at a time, which is enough for an
/// idempotent re-delivery but not for a recovery that does not know the request
/// IDs a crashed process used. The SQLite store implements this over the same
/// tables with the same payload validation.
pub trait RecoveryEnumerationPort {
    /// Every stored execution, in project and execution order.
    fn stored_executions(&self) -> Result<Vec<StoredExecution>, SddExecutionError>;

    /// The saved dispatch journal rows of one execution.
    fn dispatch_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<DispatchJournalEntry>, SddExecutionError>;

    /// The saved Git journal rows of one execution.
    fn git_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<GitJournalEntry>, SddExecutionError>;

    /// The saved progress journal rows of one execution.
    fn progress_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ProgressJournalEntry>, SddExecutionError>;

    /// The saved control-operation rows of one execution.
    fn control_records(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ControlRecord>, SddExecutionError>;

    /// The saved Task reservations of one execution.
    fn task_reservations(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<TaskReservation>, SddExecutionError>;
}

/// The durable store one resume needs.
pub trait RecoveryStorePort:
    ExecutionStorePort
    + DurableExecutionStorePort
    + ApprovalRevisionStorePort
    + PlanChangeLatchStorePort
    + RecoveryEnumerationPort
{
}

impl<T> RecoveryStorePort for T where
    T: ExecutionStorePort
        + DurableExecutionStorePort
        + ApprovalRevisionStorePort
        + PlanChangeLatchStorePort
        + RecoveryEnumerationPort
{
}

// ---------------------------------------------------------------------------
// Human resume
// ---------------------------------------------------------------------------

/// Proof that the trusted desktop path asked a human to resume one execution.
///
/// The field is private and the only constructor is
/// [`HumanResume::after_main_window_confirmation`], which the desktop command
/// layer calls after its main-window guard accepted a confirmation of kind
/// `Resume`. A plan, a request payload, a model tool, or a repository string
/// cannot produce one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanResume {
    _private: (),
}

impl HumanResume {
    /// Records a human resume confirmed through the trusted main window.
    pub const fn after_main_window_confirmation() -> Self {
        Self { _private: () }
    }

    /// Whether the resume was confirmed. It is always true: a value of this type
    /// cannot be built without the confirmation.
    pub const fn is_confirmed(self) -> bool {
        true
    }
}

/// One human resume request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeRequest {
    identity: RequestIdentity<crate::ids::ControlKind>,
    confirmation: HumanResume,
    approval_id: ApprovalId,
    expected_approval_revision: u64,
}

impl ResumeRequest {
    /// Creates one resume request.
    ///
    /// The request guard, the approval identity, and the approval revision are
    /// mandatory. `confirmation` is the only proof a human asked for this.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        expected_revision: ExecutionRevision,
        confirmation: HumanResume,
        approval_id: ApprovalId,
        expected_approval_revision: u64,
    ) -> Result<Self, SddExecutionError> {
        if approval_id.project_id() != project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "resume approval".to_owned(),
                expected: project_id,
                found: approval_id.project_id(),
            });
        }
        if expected_approval_revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "resume.expectedApprovalRevision".to_owned(),
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
            confirmation,
            approval_id,
            expected_approval_revision,
        })
    }

    /// The project, execution, request, and revision guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::ControlKind> {
        &self.identity
    }

    /// The human confirmation.
    pub const fn confirmation(&self) -> HumanResume {
        self.confirmation
    }

    /// The approval identity the resume uses.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// The approval revision the human based the resume on.
    pub const fn expected_approval_revision(&self) -> u64 {
        self.expected_approval_revision
    }
}

/// Why a resume did not continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeBlocker {
    /// A record is unknown, so nothing may be re-sent.
    Unresolved {
        /// Record kind.
        kind: RecoveryRecordKind,
        /// Task the record belongs to, when it is Task-scoped.
        task: Option<TaskRef>,
        /// Idempotent request, when one exists.
        request: Option<String>,
        /// Non-secret explanation.
        detail: String,
    },
    /// A process stop is not confirmed.
    StopUnconfirmed {
        /// Task whose child stop is unconfirmed, when one exists.
        task: Option<TaskRef>,
    },
    /// The plan-change latch is still open.
    PlanChangeOpen {
        /// The change the latch holds.
        change: Box<PlanChange>,
    },
    /// The Task budget is exhausted. A resume never refills it.
    BudgetExhausted {
        /// The human action that resolves it.
        action: HumanAction,
        /// Non-secret explanation.
        detail: String,
    },
}

impl ResumeBlocker {
    /// The human action that resolves the blocker.
    pub fn human_action(&self) -> HumanAction {
        match self {
            Self::Unresolved { kind, .. } => match kind {
                RecoveryRecordKind::Git => HumanAction::ConfirmGitRecovery,
                RecoveryRecordKind::Process => HumanAction::ConfirmStop,
                _ => HumanAction::ConfirmRecovery,
            },
            Self::StopUnconfirmed { .. } => HumanAction::ConfirmStop,
            Self::PlanChangeOpen { .. } => HumanAction::ResolvePlanChange,
            Self::BudgetExhausted { action, .. } => *action,
        }
    }

    /// The stop reason a recorded blocker uses.
    pub fn stop_reason(&self) -> StopReason {
        match self {
            Self::Unresolved {
                kind: RecoveryRecordKind::Git,
                ..
            } => StopReason::GitResultUnknown,
            Self::Unresolved { .. } => StopReason::RecoveryRequired,
            Self::StopUnconfirmed { .. } => StopReason::StopUnconfirmed,
            Self::PlanChangeOpen { change } => change.stop_reason(),
            Self::BudgetExhausted { action, .. } => match action {
                HumanAction::ClearStall => StopReason::ChildStalled,
                _ => StopReason::BudgetExhausted,
            },
        }
    }
}

/// What one human resume decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeOutcome {
    /// One clearly established commit was linked and its Task is complete.
    CommitLinked {
        /// The completed Task.
        task: TaskRef,
        /// The linked `BASE..commit` range.
        range: CommitRange,
        /// Resulting durable revision.
        revision: ExecutionRevision,
        /// Resulting snapshot.
        snapshot: Box<ExecutionSnapshot>,
    },
    /// The execution resumed to its current Task.
    Resumed {
        /// Current Task, absent when every Task is complete.
        task: Option<TaskRef>,
        /// Resulting durable revision.
        revision: ExecutionRevision,
        /// Resulting snapshot.
        snapshot: Box<ExecutionSnapshot>,
    },
    /// Something still needs a human. The hold is durable.
    Blocked {
        /// Every blocker, so one review can address them all.
        blockers: Vec<ResumeBlocker>,
        /// The recorded stop, absent when the plan-change latch already holds.
        stop: Option<StopRecord>,
        /// Resulting durable revision, absent when nothing was written.
        revision: Option<ExecutionRevision>,
    },
    /// The same request was already applied.
    Replayed {
        /// Stored resulting revision.
        revision: ExecutionRevision,
    },
    /// The execution is terminal.
    Finished {
        /// Terminal state.
        state: ExecutionState,
        /// Durable revision.
        revision: ExecutionRevision,
    },
}

impl ResumeOutcome {
    /// Whether the execution may continue.
    pub const fn may_continue(&self) -> bool {
        matches!(self, Self::CommitLinked { .. } | Self::Resumed { .. })
    }

    /// The blockers of a blocked outcome.
    pub fn blockers(&self) -> &[ResumeBlocker] {
        match self {
            Self::Blocked { blockers, .. } => blockers,
            _ => &[],
        }
    }
}

/// Resumes one execution after a human confirmation.
///
/// # Order
///
/// 1. A re-delivered request returns its stored result.
/// 2. The human confirmation, the expected execution revision, and the expected
///    approval revision are checked before anything else.
/// 3. The observed approval inputs are verified against the approved content —
///    plan bytes, parsed result, spec snapshots, checkout, branch, baseline,
///    connection, profile, consents, host commit and hook authorization, H3
///    boundary, and every Task's scope and typed budget.
/// 4. The plan is re-observed through the gate. A change holds the execution and
///    creates no state from this call.
/// 5. The saved records are reconciled. At most one clearly established commit
///    is linked: the journal result is written first, then the Task completion,
///    so the Task is never dispatched or committed again.
/// 6. Every remaining unknown record, an unconfirmed stop, an open plan-change
///    latch, or an exhausted budget is a durable `waiting_human` hold.
/// 7. Otherwise the execution returns to `ready`/`running`/`ready_for_finish`
///    with the stop cleared and the consumed budget preserved.
pub fn resume(
    store: &mut dyn RecoveryStorePort,
    request: &ResumeRequest,
    facts: &RecoveryFacts,
    gate: Option<&mut dyn PlanChangeGatePort>,
    inputs: &ApprovalInputs,
) -> Result<ResumeOutcome, SddExecutionError> {
    let identity = *request.identity();
    let project = identity.project_id();
    let execution = identity.execution_id();

    if !request.confirmation.is_confirmed() {
        return Err(SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::Resume,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }

    if let Some(record) = store.operation_record(project, execution, identity.request_id())?
        && let Some(result) = record.outcome()
    {
        return Ok(ResumeOutcome::Replayed {
            revision: result.resulting_revision(),
        });
    }

    let stored =
        store
            .load(project, execution)?
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StateUnreadable,
                details: crate::error::FailureDetails::none().boxed(),
            })?;
    let snapshot = stored.snapshot().clone();
    if stored.revision() != identity.expected_revision() {
        return Err(SddExecutionError::RevisionConflict {
            expected: identity.expected_revision(),
            found: stored.revision(),
        });
    }
    if snapshot.state() == ExecutionState::Preview {
        return Err(SddExecutionError::Conflict {
            reason: ConflictReason::TaskNotReady,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    if snapshot.state().is_terminal() {
        return Ok(ResumeOutcome::Finished {
            state: snapshot.state(),
            revision: stored.revision(),
        });
    }
    let approval = store
        .latest_approval_revision(project, request.approval_id)?
        .ok_or_else(|| SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            details: crate::error::FailureDetails::none().boxed(),
        })?;
    if approval.revision() != request.expected_approval_revision {
        return Err(SddExecutionError::Conflict {
            reason: ConflictReason::StaleRevision,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    inputs.verify(approval.content())?;

    if let Some(gate) = gate {
        let decision =
            gate.check_before_side_effect(execution, request.approval_id, approval.plan())?;
        if let Some(latch) = decision.latch() {
            return Ok(ResumeOutcome::Blocked {
                blockers: vec![ResumeBlocker::PlanChangeOpen {
                    change: Box::new(latch.change().clone()),
                }],
                stop: None,
                revision: None,
            });
        }
    }

    let latch = store.plan_change_latch(project, execution)?;
    if let Some(latch) = &latch
        && latch.is_open()
    {
        return Ok(ResumeOutcome::Blocked {
            blockers: vec![ResumeBlocker::PlanChangeOpen {
                change: Box::new(latch.change().clone()),
            }],
            stop: None,
            revision: None,
        });
    }

    let report = reconcile(
        &stored,
        facts,
        RecoveryContext {
            plan_change: latch.as_ref(),
            approval: Some(&approval),
        },
    )?;
    let target_revision = snapshot.revision().next();

    // One established commit is linked before anything else. The journal result
    // is durable first; a crash between the two writes is reconciled again.
    let mut tasks = snapshot.tasks().to_vec();
    let mut linked: Option<(TaskRef, CommitRange)> = None;
    if let Some(pending) = report
        .pending_link()
        .and_then(RecoveryTaskState::pending_commit)
    {
        let recorded = pending.entry().clone().record(GitCommitOutcome::Committed {
            commit: pending.commit().clone(),
            tree: pending.tree().clone(),
            parent: pending.parent().clone(),
        });
        store.record_git(&recorded)?;
        let task_ref = report
            .pending_link()
            .map(RecoveryTaskState::task)
            .expect("the pending link names its Task");
        let stored_task =
            snapshot
                .task(task_ref.number())
                .ok_or_else(|| SddExecutionError::InvalidSnapshot {
                    field: "snapshot.tasks".to_owned(),
                    detail: "the linked Task is not in the snapshot".to_owned(),
                })?;
        let updated = TaskSnapshot::new(
            task_ref,
            TaskProgression::Complete,
            TaskPhase::Complete,
            stored_task.h2_reference(),
            stored_task.child(),
            stored_task.commit_policy(),
            Some(pending.range().clone()),
            None,
            stored_task.evidence().to_vec(),
            None,
            stored_task.applied_revision(),
        )?;
        let index = tasks
            .iter()
            .position(|task| task.task() == task_ref)
            .expect("the linked Task is in the snapshot order");
        tasks[index] = updated;
        linked = Some((task_ref, pending.range().clone()));
    }

    let mut blockers = resume_blockers(&report, &tasks);
    // Continuing work needs a confirmed stop. `ready` is the one safe
    // "unstopped" state: no child exists, so there is no process to confirm.
    // Every other unstopped state — `running`, `waiting_html`, `verifying`,
    // `committing`, `stopping`, and the `waiting_human` hold a quit writes before
    // the stop is confirmed — may hide a live process. A resume holds then, and
    // any established commit is still linked into the held snapshot so the fact
    // is not lost.
    if blockers.is_empty() && !resume_may_continue(snapshot.state()) {
        blockers.push(ResumeBlocker::StopUnconfirmed {
            task: snapshot.current_task(),
        });
    }
    let (state, current_task) = if blockers.is_empty() {
        resumed_state(&snapshot, &tasks)
    } else {
        // A blocked resume must not regress a confirmed stop: moving `stopped`
        // back to `waiting_human` would lose the confirmation a plan revision
        // approval requires.
        let state = match snapshot.state() {
            ExecutionState::Stopped | ExecutionState::WaitingHuman => snapshot.state(),
            _ => ExecutionState::WaitingHuman,
        };
        (state, snapshot.current_task())
    };
    let stop = match blockers.first() {
        Some(blocker) => Some(StopRecord::new(
            blocker.stop_reason(),
            Some(blocker.human_action()),
        )?),
        None => None,
    };
    let next = ExecutionSnapshot::new(SnapshotInput {
        project_id: snapshot.project_id(),
        execution_id: snapshot.execution_id(),
        revision: target_revision,
        state,
        plan: snapshot.plan().clone(),
        workspace: snapshot.workspace().clone(),
        current_task,
        tasks,
        stop,
        budget: SnapshotBudget::new(
            report.budget().snapshot_consumption(),
            BudgetConsumption::zero(),
        ),
        applied_revision: snapshot.applied_revision(),
        final_project_sequence: snapshot.final_project_sequence(),
    })?;

    let record = operation_record(request, identity.expected_revision(), &next)?;
    store.commit_operation(
        project,
        execution,
        Some(snapshot.revision()),
        &next,
        &record,
    )?;

    if !blockers.is_empty() {
        return Ok(ResumeOutcome::Blocked {
            blockers,
            stop,
            revision: Some(target_revision),
        });
    }
    match linked {
        Some((task, range)) => Ok(ResumeOutcome::CommitLinked {
            task,
            range,
            revision: target_revision,
            snapshot: Box::new(next),
        }),
        None => Ok(ResumeOutcome::Resumed {
            task: current_task,
            revision: target_revision,
            snapshot: Box::new(next),
        }),
    }
}

/// Every blocker of one reconcile report, after the linked Task completions.
fn resume_blockers(report: &RecoveryReport, tasks: &[TaskSnapshot]) -> Vec<ResumeBlocker> {
    let mut blockers = Vec::new();
    for item in report.items() {
        if item.class() != RecoveryClass::Unknown || !item.is_blocking() {
            continue;
        }
        // A Task that is complete now will not be dispatched or committed again,
        // so its historical unknown is reported but does not hold the resume.
        let complete = item.task().is_some_and(|task| {
            tasks
                .iter()
                .find(|stored| stored.task() == task)
                .is_some_and(|stored| stored.progression().is_complete())
        });
        if complete {
            continue;
        }
        if item.kind() == RecoveryRecordKind::Process && item.detail() == STOP_UNCONFIRMED {
            blockers.push(ResumeBlocker::StopUnconfirmed { task: item.task() });
            continue;
        }
        blockers.push(ResumeBlocker::Unresolved {
            kind: item.kind(),
            task: item.task(),
            request: item.request().map(str::to_owned),
            detail: item.detail().to_owned(),
        });
    }
    if report.remaining_seconds() == 0 {
        blockers.push(ResumeBlocker::BudgetExhausted {
            action: HumanAction::RaiseBudget,
            detail: "the finite Task budget is exhausted; a resume does not refill it".to_owned(),
        });
    }
    blockers
}

/// Whether a resume from this state may start new work without an extra human
/// stop confirmation.
///
/// `stopped` carries a confirmed stop and `ready` proves no child was ever
/// created. Everything else may hold a process H4 cannot prove is gone.
pub const fn resume_may_continue(state: ExecutionState) -> bool {
    matches!(state, ExecutionState::Stopped | ExecutionState::Ready)
}

/// The state and current Task a clean resume writes.
///
/// The state is the reconciled decision rather than a chain of transitions, the
/// same way [`crate::coordinator`]'s finish step writes `ready_for_finish`: the
/// snapshot constructor validates every invariant, and the recorded stop is
/// cleared because the human confirmed it. A Task that never dispatched resumes
/// `ready`; an already dispatched Task resumes `running`, so the coordinator
/// continues it instead of creating a second child.
fn resumed_state(
    _snapshot: &ExecutionSnapshot,
    tasks: &[TaskSnapshot],
) -> (ExecutionState, Option<TaskRef>) {
    let next = tasks
        .iter()
        .find(|task| task.progression() != TaskProgression::Complete);
    let Some(next) = next else {
        return (ExecutionState::ReadyForFinish, None);
    };
    let state = if next.progression() == TaskProgression::Pending {
        ExecutionState::Ready
    } else {
        ExecutionState::Running
    };
    (state, Some(next.task()))
}

fn operation_record(
    request: &ResumeRequest,
    expected: ExecutionRevision,
    next: &ExecutionSnapshot,
) -> Result<ControlRecord, SddExecutionError> {
    let identity = *request.identity();
    let operation = ExecutionOperationRequest::new(
        identity.project_id(),
        identity.execution_id(),
        identity.request_id(),
        expected,
        ExecutionOperation::Resume,
    )?;
    let result = ExecutionOperationResult::new(ExecutionOperation::Resume, next.clone())?;
    operation.recorded(result)
}

// ---------------------------------------------------------------------------
// Observing helpers used by the desktop assembly
// ---------------------------------------------------------------------------

/// The paths one recovery observation must read.
///
/// Every saved intent's explicit paths are included, so a commit whose result was
/// never stored is compared against the exact content it claimed to commit.
pub fn observation_paths(entries: &[GitJournalEntry]) -> Vec<String> {
    let mut paths = Vec::new();
    for entry in entries {
        for path in entry.intent().paths() {
            if !paths.iter().any(|stored| stored == path.path()) {
                paths.push(path.path().to_owned());
            }
        }
    }
    paths.sort();
    paths
}

/// Builds the read-only observation request one recovery needs.
///
/// It names the saved branch of the newest intent, or the execution's own branch
/// when no intent was saved, and every explicit path of every saved intent.
pub fn observation_request(
    project_id: ProjectId,
    branch: &str,
    entries: &[GitJournalEntry],
) -> Result<crate::git::ObservationRequest, SddExecutionError> {
    crate::git::ObservationRequest::new(
        project_id,
        observed_branch(entries).unwrap_or(branch),
        observation_paths(entries),
    )
}

/// The saved branch of the newest Git intent, when one exists.
pub fn observed_branch(entries: &[GitJournalEntry]) -> Option<&str> {
    entries.last().map(|entry| entry.intent().branch())
}
