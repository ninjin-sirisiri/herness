//! Desktop Task finalization: fix the target, record the intent, commit, and
//! re-read the result.
//!
//! This is the commit half of H4's [`TaskCompletionPort`]. It connects Task
//! 16's synced HTML barrier to Task 17's deterministic finalize flow:
//!
//! 1. read the checkout's changes against the fixed BASE plus the untracked
//!    paths, and fix the target set with
//!    [`herness_sdd_execute::select_targets`] — Task changes inside the approved
//!    write scope plus the companions and receipts the final barrier just
//!    verified; nothing else is ever staged;
//! 2. build the intent with the hook digest observed **before** staging;
//! 3. call [`herness_sdd_execute::finalize_task`], which persists the intent,
//!    runs the approved host boundary, records the result, and re-reads the
//!    checkout;
//! 4. report `Complete` only for an observed commit range or a verified
//!    no-change record; every hold becomes a durable human wait.
//!
//! # What is never done
//!
//! No `reset`, `restore`, `checkout`, `clean`, `amend`, `rebase`, `merge`, or
//! second commit attempt exists in this module. An unrelated dirty path is left
//! untouched and unstaged: the Task holds instead of discarding it, and the
//! next attempt is a human decision.
//!
//! # Authorization
//!
//! The authorization comes only from the
//! [`CommitAuthorization`](herness_sdd_execute::CommitAuthorization) on the
//! completion request, which the H4 approval registry minted from a human
//! decision. No string, model request, preview, or tool payload reaches
//! `HostCommitApproval::authorize` here.

use herness_core::{AbsolutePath, ProjectId};
use herness_sdd_execute::{
    Baseline, ChangedPath, CommitPolicy, CommitRequestId, CommitTarget, ConflictReason,
    ControlRecord, DispatchJournalEntry, DispatchRequestId, ExecutionId, ExecutionRevision,
    ExecutionSnapshot, ExecutionStorePort, FailureDetails, FinalizePorts, GitJournalEntry,
    HumanAction, ProgressJournalEntry, ProgressJournalId, SddExecutionError, StopReason,
    StoredExecution, TaskCommitRequest, TaskCompletion, TaskCompletionRequest, TaskFinalizeOutcome,
    TaskRef, VerifiedPath, commit_request_id, finalize_task, select_targets,
};

use crate::sdd_execute::barrier::{HostCommitCompletion, VerifiedDocuments};
use crate::sdd_execute::finalize::{
    ApprovedCommitIdentity, GitCheckoutObserver, HOST_COMMIT_FEATURE, HOST_COMMIT_OBSERVE_FEATURE,
};
use crate::sdd_execute::git::{GitChange, GitChangeKind};
use crate::supervision::store::StoreHandle;

/// The approved facts of one Task commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCommitExpectation {
    task: TaskRef,
    title: String,
    policy: CommitPolicy,
    write_scope: Vec<String>,
    base: Baseline,
    tracked: Vec<VerifiedPath>,
    remaining_seconds: u64,
}

impl TaskCommitExpectation {
    /// Records the approved target scope and the verified documents of the Task.
    pub fn new(
        task: TaskRef,
        title: impl Into<String>,
        policy: CommitPolicy,
        write_scope: Vec<String>,
        base: Baseline,
        remaining_seconds: u64,
    ) -> Self {
        Self {
            task,
            title: title.into(),
            policy,
            write_scope,
            base,
            tracked: Vec::new(),
            remaining_seconds,
        }
    }

    /// Records the tracked documents whose verified bytes must not move.
    #[must_use]
    pub fn with_tracked(mut self, tracked: Vec<VerifiedPath>) -> Self {
        self.tracked = tracked;
        self
    }

    /// The Task this expectation describes.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Approved commit policy.
    pub const fn policy(&self) -> CommitPolicy {
        self.policy
    }

    /// Approved write scope.
    pub fn write_scope(&self) -> &[String] {
        &self.write_scope
    }

    /// Fixed BASE.
    pub const fn base(&self) -> &Baseline {
        &self.base
    }
}

/// The real host commit half: target selection, intent, boundary, and re-read.
///
/// One instance is bound to one Task at a time by [`Self::bind_task`]; the
/// coordinator asks it to complete exactly that Task. The Git journal and the
/// completion result land in the same shared store as the rest of H4's state.
pub struct DesktopHostCommit<G> {
    store: StoreHandle,
    git: G,
    checkout: GitCheckoutObserver,
    identity: ApprovedCommitIdentity,
    expectation: Option<TaskCommitExpectation>,
}

impl<G> DesktopHostCommit<G> {
    /// Creates the commit half over the shared store, boundary, and observer.
    pub fn new(
        store: StoreHandle,
        git: G,
        checkout: GitCheckoutObserver,
        identity: ApprovedCommitIdentity,
    ) -> Self {
        Self {
            store,
            git,
            checkout,
            identity,
            expectation: None,
        }
    }

    /// Binds the Task this commit half will finalize.
    pub fn bind_task(&mut self, expectation: TaskCommitExpectation) {
        self.expectation = Some(expectation);
    }

    /// The bound Task, when one exists.
    pub fn bound_task(&self) -> Option<TaskRef> {
        self.expectation.as_ref().map(TaskCommitExpectation::task)
    }

    /// The approved identity the boundary runs as.
    pub const fn identity(&self) -> &ApprovedCommitIdentity {
        &self.identity
    }

    /// The mutable boundary.
    pub const fn boundary_mut(&mut self) -> &mut G {
        &mut self.git
    }

    /// The mutable checkout observer.
    pub const fn observer_mut(&mut self) -> &mut GitCheckoutObserver {
        &mut self.checkout
    }

    /// Finalizes the bound Task and maps the result onto H4's completion.
    ///
    /// The verified derived artifacts of the final barrier are the only
    /// companion/receipt bytes this method will stage.
    pub fn finalize_bound(
        &mut self,
        request: &TaskCompletionRequest,
        verified: &VerifiedDocuments,
    ) -> Result<TaskCompletion, SddExecutionError>
    where
        G: herness_sdd_execute::HostGitPort,
    {
        let expectation = self.expectation.clone().ok_or_else(not_ready)?;
        if expectation.task != request.task() || request.commit_policy() != expectation.policy {
            return Err(not_ready());
        }
        let commit_request = match self.commit_request(&expectation, request, verified)? {
            Prepared::Request(request) => *request,
            Prepared::Hold(stop) => return Ok(TaskCompletion::HumanWait { stop }),
        };
        let mut store = StoreExecutionPort {
            store: self.store.clone(),
        };
        let mut ports = FinalizePorts {
            git: &mut self.git,
            store: &mut store,
            checkout: &mut self.checkout,
        };
        let outcome = finalize_task(&mut ports, &commit_request)?;
        match outcome {
            TaskFinalizeOutcome::Committed { range, .. } => Ok(TaskCompletion::Complete {
                commit_range: Some(range),
                no_change: None,
                host_seconds: 0,
            }),
            TaskFinalizeOutcome::NoChange { record } => Ok(TaskCompletion::Complete {
                commit_range: None,
                no_change: Some(record),
                host_seconds: 0,
            }),
            TaskFinalizeOutcome::Held { stop, .. } => {
                Ok(TaskCompletion::HumanWait { stop: stop.stop()? })
            }
        }
    }

    /// Builds the finalize request from the observed checkout, or the human wait
    /// that replaces it.
    fn commit_request(
        &mut self,
        expectation: &TaskCommitExpectation,
        request: &TaskCompletionRequest,
        verified: &VerifiedDocuments,
    ) -> Result<Prepared, SddExecutionError> {
        let root = self.identity.checkout_root().as_str().to_owned();
        let head = {
            let mut runner = self.checkout.runner();
            runner
                .head(&root)?
                .ok_or_else(|| SddExecutionError::RecoveryRequired {
                    reason: herness_sdd_execute::RecoveryReason::StateUnreadable,
                    details: FailureDetails::none().boxed(),
                })?
        };
        let targets = match expectation.policy {
            CommitPolicy::Required => {
                // The intent records that the index was clean before the host
                // staged anything. A staged change someone else left behind is
                // never the host's to discard, so the Task holds.
                if !self.index_clean(&root)? {
                    return Ok(Prepared::Hold(herness_sdd_execute::StopRecord::new(
                        StopReason::Conflict,
                        Some(HumanAction::ResolveConflict),
                    )?));
                }
                let derived =
                    crate::sdd_execute::finalize::verified_derived_targets(verified.derived())?;
                let changed = self.changed_paths(&root, &expectation.base)?;
                let selection = match select_targets(&changed, &expectation.write_scope, &derived) {
                    Ok(selection) => selection,
                    // An unrelated change, a deletion, or an unverified derived
                    // artifact is a human decision, never a narrowed target
                    // list.
                    Err(refusal) => return Ok(Prepared::Hold(refusal.stop()?)),
                };
                selection.targets().to_vec()
            }
            CommitPolicy::NoChange => Vec::new(),
        };
        let request_id: CommitRequestId =
            commit_request_id(request.execution_id(), expectation.task, &head);
        let pre_hook = self.pre_hook(&root, &targets)?;
        // The resulting tree can only be computed by staging, which is the side
        // effect this intent must precede. It therefore stays unasserted here;
        // the boundary still verifies the observed parent, branch, and changed
        // paths, and the finalize flow re-reads HEAD and the tree after the
        // commit.
        let request = TaskCommitRequest::new(
            expectation.task,
            request.execution_id(),
            request_id,
            request.expected_revision(),
            request.commit_authorization(),
            expectation.policy,
            expectation.title.clone(),
            self.identity.branch().to_owned(),
            expectation.base.clone(),
            head,
            None,
            targets,
            expectation.tracked.clone(),
            request.evidence().to_vec(),
            pre_hook,
            expectation.remaining_seconds,
        )?;
        Ok(Prepared::Request(Box::new(request)))
    }

    fn changed_paths(
        &mut self,
        root: &str,
        base: &Baseline,
    ) -> Result<Vec<ChangedPath>, SddExecutionError> {
        let mut runner = self.checkout.runner();
        let mut changes = runner.changes_since(root, base.as_str())?;
        for path in runner.untracked_paths(root)? {
            if !changes.iter().any(|change| change.path() == path) {
                changes.push(GitChange::new(path, GitChangeKind::Added));
            }
        }
        let mut changed = Vec::with_capacity(changes.len());
        for change in changes {
            changed.push(match change.kind() {
                GitChangeKind::Deleted => ChangedPath::deleted(change.path())?,
                GitChangeKind::Added | GitChangeKind::Modified => {
                    let bytes = read_checkout_file(root, change.path())?;
                    ChangedPath::for_bytes(change.path(), &bytes)?
                }
            });
        }
        Ok(changed)
    }

    fn pre_hook(
        &self,
        root: &str,
        targets: &[CommitTarget],
    ) -> Result<herness_sdd_execute::PreHookState, SddExecutionError> {
        let checkout = AbsolutePath::new(root)
            .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        let hooks = crate::sdd_execute::finalize::checkout_hooks_digest(&checkout)?;
        let staged = targets
            .iter()
            .map(|target| target.path().to_owned())
            .collect::<Vec<_>>();
        herness_sdd_execute::PreHookState::new(true, staged, Some(hooks), None)
    }

    /// Whether the current index holds no staged change.
    ///
    /// A staged change someone else left behind is never the host's to discard;
    /// the Task holds instead.
    fn index_clean(&mut self, root: &str) -> Result<bool, SddExecutionError> {
        let mut runner = self.checkout.runner();
        let status = runner.status(root)?;
        Ok(status.index_clean())
    }
}

impl<G> HostCommitCompletion for DesktopHostCommit<G>
where
    G: herness_sdd_execute::HostGitPort,
{
    fn commit_connected(&self) -> bool {
        true
    }

    fn commit(
        &mut self,
        request: &TaskCompletionRequest,
        verified: &VerifiedDocuments,
    ) -> Result<TaskCompletion, SddExecutionError> {
        self.finalize_bound(request, verified)
    }
}

// ---------------------------------------------------------------------------
// Store adapter
// ---------------------------------------------------------------------------

/// The `ExecutionStorePort` view over the shared store handle.
///
/// H4's finalize flow needs only the Git journal and the snapshot revision, so
/// this adapter forwards exactly the port's methods to the real store.
struct StoreExecutionPort {
    store: StoreHandle,
}

impl ExecutionStorePort for StoreExecutionPort {
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, SddExecutionError> {
        let store = self.store.lock();
        ExecutionStorePort::load(&*store, project_id, execution_id)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::compare_and_swap(
            &mut *store,
            project_id,
            execution_id,
            expected_revision,
            next,
        )
    }

    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, SddExecutionError> {
        let store = self.store.lock();
        ExecutionStorePort::dispatch_entry(&*store, project_id, execution_id, request_id)
    }

    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, SddExecutionError> {
        let store = self.store.lock();
        ExecutionStorePort::commit_entry(&*store, project_id, execution_id, request_id)
    }

    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, SddExecutionError> {
        let store = self.store.lock();
        ExecutionStorePort::progress_entry(&*store, project_id, execution_id, request_id)
    }

    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: herness_sdd_execute::ControlRequestId,
    ) -> Result<Option<ControlRecord>, SddExecutionError> {
        let store = self.store.lock();
        ExecutionStorePort::operation_record(&*store, project_id, execution_id, request_id)
    }

    fn record_dispatch(&mut self, entry: &DispatchJournalEntry) -> Result<(), SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::record_dispatch(&mut *store, entry)
    }

    fn record_git(&mut self, entry: &GitJournalEntry) -> Result<(), SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::record_git(&mut *store, entry)
    }

    fn record_progress(&mut self, entry: &ProgressJournalEntry) -> Result<(), SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::record_progress(&mut *store, entry)
    }

    fn record_operation(&mut self, record: &ControlRecord) -> Result<(), SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::record_operation(&mut *store, record)
    }

    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        let mut store = self.store.lock();
        ExecutionStorePort::commit_operation(
            &mut *store,
            project_id,
            execution_id,
            expected_revision,
            next,
            record,
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// What target selection produced: a request, or the human wait that replaces
/// it.
enum Prepared {
    /// The intent to finalize.
    Request(Box<TaskCommitRequest>),
    /// The Task holds before any Git side effect.
    Hold(herness_sdd_execute::StopRecord),
}

fn read_checkout_file(root: &str, path: &str) -> Result<Vec<u8>, SddExecutionError> {
    let joined = std::path::Path::new(root).join(path);
    std::fs::read(&joined).map_err(|error| {
        unavailable(
            HOST_COMMIT_OBSERVE_FEATURE,
            &format!(
                "{path} cannot be read for the commit target: {}",
                error.kind()
            ),
        )
    })
}

fn not_ready() -> SddExecutionError {
    SddExecutionError::Conflict {
        reason: ConflictReason::TaskNotReady,
        details: FailureDetails::none().boxed(),
    }
}

fn unavailable(feature: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}
