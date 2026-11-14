//! Host-owned H4 ports.
//!
//! Ports are side-effect boundaries only. This crate does not open a database,
//! spawn the pack inspector, run Git, call H1/H2/H3 implementations, read the
//! wall clock, or touch Tauri or Pi. Later tasks supply concrete adapters.
//!
//! Every port takes and returns H4 values or the public H2/H3 contract values
//! they name. No port exposes a concrete database, engine, or desktop type.

use herness_core::contracts::{ProjectId, Timestamp};
use herness_html_sync::{BarrierOutcome, BarrierRequest};
use herness_supervision::{BudgetPolicy, ExecutionScope, SupervisionId};

use crate::approval::CommitAuthorization;
use crate::contract::{ControlRecord, ExecutionOperationResult};
use crate::error::SddExecutionError;
use crate::ids::{
    Baseline, CommitRequestId, CommitSha, ControlRequestId, DispatchRequestId, ExecutionId,
    ExecutionRevision, ProgressJournalId,
};
use crate::journal::{
    DispatchJournalEntry, DispatchRequest, DispatchResult, GitCommitOutcome, GitJournalEntry,
    ProgressJournalEntry, ProgressWriteOutcome,
};
use crate::plan::{InspectRequest, InspectedPlan, InspectorCapabilities, PlanPath};
use crate::snapshot::ExecutionSnapshot;
use crate::version::PlanDigest;

/// Host clock. Tests inject a deterministic clock.
pub trait ClockPort {
    /// Current wall-clock timestamp.
    fn now(&self) -> Timestamp;
}

/// Exact plan bytes read from the approved project-relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSourceRead {
    source: Vec<u8>,
    digest: PlanDigest,
}

impl PlanSourceRead {
    /// Creates a read result and verifies the digest.
    pub fn new(source: Vec<u8>, digest: PlanDigest) -> Result<Self, SddExecutionError> {
        if digest != PlanDigest::sha256(&source) {
            return Err(SddExecutionError::InvalidValue {
                field: "planSource.digest".to_owned(),
                detail: "must be the digest of the exact bytes".to_owned(),
            });
        }
        Ok(Self { source, digest })
    }

    /// Exact bytes.
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Digest of the exact bytes.
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }
}

/// One periodic or pre-side-effect plan observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanObservation {
    digest: Option<PlanDigest>,
    byte_length: Option<u64>,
    stable: bool,
}

impl PlanObservation {
    /// Records an observed digest and length.
    pub fn observed(digest: PlanDigest, byte_length: u64, stable: bool) -> Self {
        Self {
            digest: Some(digest),
            byte_length: Some(byte_length),
            stable,
        }
    }

    /// Records that the plan is missing or unreadable.
    pub const fn missing() -> Self {
        Self {
            digest: None,
            byte_length: None,
            stable: false,
        }
    }

    /// Observed digest, absent when the plan could not be read.
    pub fn digest(&self) -> Option<&PlanDigest> {
        self.digest.as_ref()
    }

    /// Observed length, absent when the plan could not be read.
    pub const fn byte_length(&self) -> Option<u64> {
        self.byte_length
    }

    /// Whether two consecutive observations agreed.
    pub const fn is_stable(&self) -> bool {
        self.stable
    }
}

/// Reads the exact plan bytes the human approved.
pub trait PlanSourcePort {
    /// Reads the exact bytes at the approved path.
    fn read_plan(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<PlanSourceRead, SddExecutionError>;

    /// Observes the current plan without side effects. Used by the one-second
    /// reconciliation and every pre-side-effect check.
    fn observe(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<PlanObservation, SddExecutionError>;
}

/// Calls the pack `sdd-plan-inspect` protocol. The adapter owns the process,
/// argv, stdin, 30 second timeout, and exact-byte transport.
pub trait PlanInspectorPort {
    /// Reads the pack capability and execution-contract fingerprint.
    fn capabilities(&mut self) -> Result<InspectorCapabilities, SddExecutionError>;

    /// Parses one plan without writing a file or starting a model.
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectedPlan, SddExecutionError>;
}

/// One loaded execution snapshot with its durable revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExecution {
    revision: ExecutionRevision,
    snapshot: ExecutionSnapshot,
}

impl StoredExecution {
    /// Creates a loaded snapshot.
    pub fn new(
        revision: ExecutionRevision,
        snapshot: ExecutionSnapshot,
    ) -> Result<Self, SddExecutionError> {
        if revision != snapshot.revision() {
            return Err(SddExecutionError::InvalidValue {
                field: "storedExecution.revision".to_owned(),
                detail: "must equal the snapshot revision".to_owned(),
            });
        }
        Ok(Self { revision, snapshot })
    }

    /// Durable revision.
    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    /// Loaded snapshot.
    pub fn snapshot(&self) -> &ExecutionSnapshot {
        &self.snapshot
    }
}

/// Durable H4 state, idempotent request records, and atomic journal writes.
pub trait ExecutionStorePort {
    /// Loads the current snapshot, if any.
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, SddExecutionError>;

    /// Creates (`None`) or updates (`Some(revision)`) a snapshot atomically.
    ///
    /// A stale revision is rejected without writing state. The returned value
    /// is the stored revision.
    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError>;

    /// Returns the recorded dispatch entry for one request ID.
    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, SddExecutionError>;

    /// Returns the recorded Git entry for one request ID.
    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, SddExecutionError>;

    /// Returns the recorded progress entry for one request ID.
    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, SddExecutionError>;

    /// Returns the recorded control-operation result for one request ID.
    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<ControlRecord>, SddExecutionError>;

    /// Writes one dispatch intent or result exactly once.
    fn record_dispatch(&mut self, entry: &DispatchJournalEntry) -> Result<(), SddExecutionError>;

    /// Writes one Git intent or result exactly once.
    fn record_git(&mut self, entry: &GitJournalEntry) -> Result<(), SddExecutionError>;

    /// Writes one progress intent or result exactly once.
    fn record_progress(&mut self, entry: &ProgressJournalEntry) -> Result<(), SddExecutionError>;

    /// Writes one control-operation record exactly once.
    fn record_operation(&mut self, record: &ControlRecord) -> Result<(), SddExecutionError>;

    /// Atomically compares the revision, writes the next snapshot, and binds
    /// the operation result.
    ///
    /// The default performs the two port calls in order. Durable stores should
    /// override it with one transaction plus the project event so a crash
    /// cannot keep a new revision without its recorded result.
    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        let revision = self.compare_and_swap(project_id, execution_id, expected_revision, next)?;
        self.record_operation(record)?;
        Ok(revision)
    }
}

/// Read-only Git and worktree state of the selected checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceState {
    project_id: ProjectId,
    canonical_checkout_root: String,
    branch: String,
    base_branch: String,
    head: Option<CommitSha>,
    baseline: Option<Baseline>,
    worktree_clean: bool,
    index_clean: bool,
}

impl WorkspaceState {
    /// Creates a workspace state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        canonical_checkout_root: impl Into<String>,
        branch: impl Into<String>,
        base_branch: impl Into<String>,
        head: Option<CommitSha>,
        baseline: Option<Baseline>,
        worktree_clean: bool,
        index_clean: bool,
    ) -> Self {
        Self {
            project_id,
            canonical_checkout_root: canonical_checkout_root.into(),
            branch: branch.into(),
            base_branch: base_branch.into(),
            head,
            baseline,
            worktree_clean,
            index_clean,
        }
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical absolute checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Current branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Current HEAD, when the branch exists.
    pub fn head(&self) -> Option<&CommitSha> {
        self.head.as_ref()
    }

    /// Fixed baseline, when established.
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }

    /// Whether the worktree has no unrelated changes.
    pub const fn worktree_clean(&self) -> bool {
        self.worktree_clean
    }

    /// Whether the index has no unrelated changes.
    pub const fn index_clean(&self) -> bool {
        self.index_clean
    }

    /// Whether a start may proceed without discarding any change.
    pub const fn is_startable(&self) -> bool {
        self.worktree_clean && self.index_clean
    }
}

/// Explicit authorization for one workspace preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePreparation {
    project_id: ProjectId,
    canonical_checkout_root: String,
    base_branch: String,
    new_branch: String,
    create_isolated_worktree: bool,
    prepare_gitignore_commit: bool,
}

impl WorkspacePreparation {
    /// Prepares an existing checkout in place.
    pub fn in_place(
        project_id: ProjectId,
        canonical_checkout_root: impl Into<String>,
        base_branch: impl Into<String>,
        prepare_gitignore_commit: bool,
    ) -> Self {
        Self {
            project_id,
            canonical_checkout_root: canonical_checkout_root.into(),
            base_branch: base_branch.into(),
            new_branch: String::new(),
            create_isolated_worktree: false,
            prepare_gitignore_commit,
        }
    }

    /// Prepares a new isolated worktree and branch after explicit approval.
    pub fn isolated(
        project_id: ProjectId,
        canonical_checkout_root: impl Into<String>,
        base_branch: impl Into<String>,
        new_branch: impl Into<String>,
    ) -> Self {
        Self {
            project_id,
            canonical_checkout_root: canonical_checkout_root.into(),
            base_branch: base_branch.into(),
            new_branch: new_branch.into(),
            create_isolated_worktree: true,
            prepare_gitignore_commit: true,
        }
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Selected canonical checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// New branch name when isolation was approved.
    pub fn new_branch(&self) -> &str {
        &self.new_branch
    }

    /// Whether an isolated worktree may be created.
    pub const fn create_isolated_worktree(&self) -> bool {
        self.create_isolated_worktree
    }

    /// Whether the `.gitignore` preparation commit was approved.
    pub const fn prepare_gitignore_commit(&self) -> bool {
        self.prepare_gitignore_commit
    }
}

/// Reads and prepares the approved implementation checkout.
///
/// An isolated worktree is created only for [`WorkspacePreparation::isolated`];
/// an isolation failure never becomes implicit in-place permission.
pub trait WorkspacePort {
    /// Reads the current state without changing Git.
    fn state(
        &self,
        project_id: ProjectId,
        canonical_checkout_root: &str,
    ) -> Result<WorkspaceState, SddExecutionError>;

    /// Prepares the approved checkout and returns the resulting state.
    fn prepare(
        &mut self,
        request: &WorkspacePreparation,
    ) -> Result<WorkspaceState, SddExecutionError>;
}

/// Consumes H3's `H4Barrier` for one Task's required documents.
///
/// H4 gathers the current file bytes, revisions, fingerprints, and approval
/// before calling this port; a saved `Synced` response or repository receipt
/// alone is not trusted.
pub trait HtmlBarrierPort {
    /// Checks the requested version and dependent inputs against saved H3
    /// state.
    fn check(
        &mut self,
        request: &BarrierRequest,
        now: Timestamp,
    ) -> Result<BarrierOutcome, SddExecutionError>;
}

/// One child dispatch with its approved scope and budget.
#[derive(Debug, Clone, PartialEq)]
pub struct ChildDispatchPlan {
    request: DispatchRequest,
    scope: ExecutionScope,
    budget: BudgetPolicy,
}

impl ChildDispatchPlan {
    /// Creates a dispatch plan.
    pub fn new(request: DispatchRequest, scope: ExecutionScope, budget: BudgetPolicy) -> Self {
        Self {
            request,
            scope,
            budget,
        }
    }

    /// Idempotent dispatch request.
    pub fn request(&self) -> &DispatchRequest {
        &self.request
    }

    /// Bounded H2 execution scope.
    pub fn scope(&self) -> &ExecutionScope {
        &self.scope
    }

    /// Finite H2 budget.
    pub fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }
}

/// Creates the one H2 target and child for a dispatch request, or reconciles
/// the existing one after a crash.
pub trait ChildDispatchPort {
    /// Dispatches or continues the child.
    fn dispatch(&mut self, plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError>;

    /// Looks up an already created target by request ID. It never creates a new
    /// child.
    fn reconcile(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError>;
}

/// Performs host stage, hook, and commit work from a recorded intent.
pub trait HostGitPort {
    /// Runs the recorded intent. The intent must already be durable.
    fn commit(
        &mut self,
        entry: &GitJournalEntry,
        authorization: CommitAuthorization,
    ) -> Result<GitCommitOutcome, SddExecutionError>;

    /// Reconciles an unknown or too-late result. It never resets or repeats a
    /// commit.
    fn observe(&mut self, entry: &GitJournalEntry) -> Result<GitCommitOutcome, SddExecutionError>;
}

/// Writes the compatibility progress ledger from durable state.
pub trait ProgressLedgerPort {
    /// Reads the current document bytes, or `None` when it does not exist.
    ///
    /// The host reads before every write so an external edit is compared with
    /// durable state instead of being overwritten.
    fn read(&mut self, output_path: &str) -> Result<Option<Vec<u8>>, SddExecutionError>;

    /// Writes the recorded content with a temporary file and replacement.
    ///
    /// `expected` is the digest of the document the host read when it planned
    /// this write, or `None` when the document did not exist. A destination that
    /// no longer carries that digest is
    /// [`ProgressWriteOutcome::Failed`] with
    /// [`ProgressFailure::ExternalModification`]; the writer never replaces an
    /// unknown document.
    fn write(
        &mut self,
        entry: &ProgressJournalEntry,
        expected: Option<&crate::version::Sha256Digest>,
    ) -> Result<ProgressWriteOutcome, SddExecutionError>;
}

/// H4 operations a build may not implement yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFeature {
    /// Durable H4 state.
    ExecutionStore,
    /// Exact plan source reads and periodic observation.
    PlanSource,
    /// Pack `sdd-plan-inspect`.
    PlanInspector,
    /// Checkout selection and preparation.
    Workspace,
    /// H2 child dispatch.
    ChildDispatch,
    /// H3 `H4Barrier` consumption.
    HtmlBarrier,
    /// H1 host Git commit.
    HostGit,
    /// Progress ledger output.
    ProgressLedger,
    /// Wall clock.
    Clock,
}

impl ExecutionFeature {
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
            Self::Clock => "clock",
        }
    }
}

/// Explicit unavailable error for a port a build does not implement yet.
pub fn unsupported(feature: ExecutionFeature) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: feature.as_str().to_owned(),
        details: crate::error::FailureDetails::none().boxed(),
    }
}

/// One stored control result, exposed for later adapters.
pub type StoredControlResult = (ControlRecord, ExecutionOperationResult);

/// One supervision identifier, re-exported so adapters do not redefine it.
pub type SupervisionTargetId = SupervisionId;
