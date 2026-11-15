//! Real Git workspace adapter for H4's [`WorkspacePort`].
//!
//! The adapter answers three questions, and nothing else:
//!
//! 1. **Which checkout did the human already choose?** [`WorkspaceAdapter::decide`]
//!    honors the one-time SDD worktree decision — an existing `.sdd/progress.md`
//!    `Worktree:` line, an already linked worktree on the approved branch, or an
//!    answer recorded in the same conversation. Only a genuinely undecided state
//!    returns [`WorkspaceDecision::AskHuman`]; Task 21 renders that question and
//!    this module never invents an answer.
//! 2. **Is the selected checkout startable?** [`WorkspaceAdapter::start_check`]
//!    reads branch, HEAD, index, worktree, and the approved plan/spec versions.
//!    Only the *selected* checkout's dirt blocks a start. Dirt left behind in the
//!    original checkout is never read as permission, never touched, and never
//!    discarded: this module contains no `stash`, `reset`, `clean`, `checkout`,
//!    or history rewrite.
//! 3. **Prepare exactly what was approved.** [`WorkspaceAdapter::prepare`] creates
//!    an isolated worktree only for [`WorkspacePreparation::isolated`], makes the
//!    single permitted `.gitignore` preparation commit only through the approved
//!    host Git boundary, and then fixes the branch baseline as one full SHA, once,
//!    through [`BaselineRecord::record_if_absent`].
//!
//! # Safety properties
//!
//! * An isolation failure is *never* in-place permission. Every isolation failure
//!   returns a typed error before any in-place preparation runs, and leaves no
//!   worktree or branch behind: the worktree is added with `--detach` (so a
//!   failing `git worktree add` cannot create a branch), and the branch is created
//!   only after the worktree exists. If branch creation fails, only the worktree
//!   this call created is removed; an unconfirmed removal becomes
//!   `recovery_required`, never a silent "nothing happened".
//! * `.gitignore` is the only file the preparation commit may touch. Stage, gate,
//!   hook, and commit run in `herness_core`'s [`HostGitBoundary`]; this module
//!   never stages or commits by itself and never passes `--no-verify`.
//! * `state()` and `start_check()` only read. `git status` runs with
//!   `--no-optional-locks` and `GIT_OPTIONAL_LOCKS=0`, so the index is not
//!   refreshed.
//! * Nothing is written outside the selected checkout, except the
//!   `.git/worktrees/` metadata Git itself records when an approved isolated
//!   worktree is created inside the original repository.
//!
//! H4 has no dedicated isolation-failure class, so an isolation or preparation
//! refusal is reported as `unavailable` with the `workspace.isolation` or
//! `workspace.preparationCommit` feature prefix, and a commit that may exist but
//! could not be recorded is reported as `git_result_unknown`. Task 13 maps those
//! codes to the decision it shows a human; no path converts them into a usable
//! in-place state.
//!
//! # What a failed preparation commit leaves behind
//!
//! The adapter writes `.gitignore` and then asks the approved host Git boundary to
//! stage, gate, and commit it. If the boundary refuses after staging — the one
//! case is a failing document gate — the checkout keeps the written `.gitignore`
//! and the staged entry the boundary left, and no commit exists. The adapter
//! reports the refusal and fixes no baseline. It deliberately does not unstage or
//! restore the path: `git reset`, `git restore --staged`, and `checkout` discard
//! state, which this adapter may not do on a human's behalf. The next preparation
//! therefore refuses with `conflict`/`dirty_index` until a human resolves it, and
//! Task 13 surfaces that as a human decision instead of retrying silently.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use herness_core::contracts::ProjectId;
use herness_core::tools::process::SystemArgvLauncher;
use herness_core::{
    AbsolutePath, GitObjectId, HOST_COMMIT_TIMEOUT, HostCommitApproval, HostGitApprover,
    HostGitAuthorization, HostGitBoundary, HostGitError, HostGitGate, HostGitIntent,
    HostGitMessage, HostGitOutcome, HostGitPath, HostGitRefusal, HostGitReport, HostGitTrailer,
    HostGitUnknown, Purpose,
};
use herness_sdd_execute::{
    ApprovalRejection, ApprovalRequirement, Baseline, ConflictReason, FailureDetails,
    GitUnknownReason, PlanChangeReason, RecoveryReason, SddExecutionError, Sha256Digest,
    WorkspacePort, WorkspacePreparation, WorkspaceState,
};
use serde::Serialize;

use crate::sdd_execute::git::{GitRunner, GitWorktreeStatus};

/// Compatibility progress ledger read for the one-time worktree decision.
pub const PROGRESS_LEDGER_PATH: &str = ".sdd/progress.md";

/// The only file the approved preparation commit may edit.
pub const GITIGNORE_PATH: &str = ".gitignore";

/// The literal `.gitignore` line that ignores `.sdd/`.
pub const SDD_IGNORE_LINE: &str = ".sdd/";

/// Literal `.gitignore` lines this adapter accepts as already ignoring `.sdd/`.
///
/// Kept deliberately narrow: only the literal form of the directory rule counts.
/// Any other spelling (a bare `.sdd`, a negation, a pattern elsewhere) is not
/// treated as covering, so the approved preparation commit may still run and
/// append the exact line. That is a stricter reading than "already ignored", and
/// `git check-ignore` verifies the outcome afterwards.
const SDD_IGNORE_ALTERNATIVES: &[&str] = &[".sdd/", "/.sdd/"];

/// `unavailable` feature prefix used for a failed isolation step.
pub const ISOLATION_FEATURE: &str = "workspace.isolation";

/// `unavailable` feature prefix used for a failed preparation commit.
pub const PREPARATION_COMMIT_FEATURE: &str = "workspace.preparationCommit";

/// `unavailable` feature prefix used when the approved base branch does not
/// resolve in the selected checkout.
pub const BASE_BRANCH_FEATURE: &str = "workspace.baseBranch";

// ---------------------------------------------------------------------------
// One-time worktree decision
// ---------------------------------------------------------------------------

/// Where the honored one-time worktree decision came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSelectionSource {
    /// The `.sdd/progress.md` `Worktree:` line.
    ProgressLedger,
    /// A worktree already linked to the repository for the approved branch.
    LinkedWorktree,
    /// An answer recorded in the same conversation.
    ConversationAnswer,
}

impl WorkspaceSelectionSource {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProgressLedger => "progress_ledger",
            Self::LinkedWorktree => "linked_worktree",
            Self::ConversationAnswer => "conversation_answer",
        }
    }
}

/// One already-decided checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSelection {
    checkout_root: String,
    branch: String,
    isolated: bool,
    source: WorkspaceSelectionSource,
}

impl WorkspaceSelection {
    fn new(
        checkout_root: impl Into<String>,
        branch: impl Into<String>,
        isolated: bool,
        source: WorkspaceSelectionSource,
    ) -> Self {
        Self {
            checkout_root: checkout_root.into(),
            branch: branch.into(),
            isolated,
            source,
        }
    }

    /// Canonical absolute checkout root.
    pub fn checkout_root(&self) -> &str {
        &self.checkout_root
    }

    /// Branch the checkout is on, or will be created on.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Whether the checkout is an isolated worktree.
    pub const fn isolated(&self) -> bool {
        self.isolated
    }

    /// Which recorded decision was honored.
    pub const fn source(&self) -> WorkspaceSelectionSource {
        self.source
    }
}

/// A worktree answer recorded in the same conversation.
///
/// Task 13 stores the answer it received through the trusted approval UI and
/// Task 21 renders the question. This type is the only way an answer enters the
/// adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum WorkspaceSelectionAnswer {
    /// Use the existing checkout in place.
    InPlace,
    /// Create or reuse one explicit isolated worktree at the approved root.
    Isolated {
        /// Approved canonical root of the isolated worktree.
        checkout_root: String,
    },
}

/// Why the adapter has no usable recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum WorkspaceUndecided {
    /// The project has no progress ledger entry, no linked worktree, and no
    /// recorded answer.
    NoRecord,
    /// The progress ledger names a worktree that is no longer linked.
    RecordedWorktreeMissing {
        /// Recorded path.
        path: String,
    },
    /// A linked worktree for that path is on another branch.
    LinkedWorktreeOnOtherBranch {
        /// Linked path.
        path: String,
        /// Branch it is on.
        branch: String,
    },
    /// The selected checkout has no named branch.
    DetachedCheckout,
}

impl WorkspaceUndecided {
    /// Stable wire label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoRecord => "no_record",
            Self::RecordedWorktreeMissing { .. } => "recorded_worktree_missing",
            Self::LinkedWorktreeOnOtherBranch { .. } => "linked_worktree_on_other_branch",
            Self::DetachedCheckout => "detached_checkout",
        }
    }
}

/// The isolation question Task 21 must ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSelectionQuestion {
    original_checkout_root: String,
    base_branch: String,
    approved_branch: String,
    reason: WorkspaceUndecided,
}

impl WorkspaceSelectionQuestion {
    /// The existing checkout the plan was opened from.
    pub fn original_checkout_root(&self) -> &str {
        &self.original_checkout_root
    }

    /// Approved integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Branch the implementation is approved to use.
    pub fn approved_branch(&self) -> &str {
        &self.approved_branch
    }

    /// Why no recorded decision was usable.
    pub const fn reason(&self) -> &WorkspaceUndecided {
        &self.reason
    }
}

/// The outcome of resolving the one-time worktree decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum WorkspaceDecision {
    /// An existing decision was honored; nothing is asked.
    Reuse {
        /// Decided checkout.
        selection: WorkspaceSelection,
    },
    /// Only an undecided state asks the human.
    AskHuman {
        /// Question Task 21 renders.
        question: WorkspaceSelectionQuestion,
    },
}

impl WorkspaceDecision {
    /// The decided checkout, when one was honored.
    pub const fn selection(&self) -> Option<&WorkspaceSelection> {
        match self {
            Self::Reuse { selection } => Some(selection),
            Self::AskHuman { .. } => None,
        }
    }

    /// The question, when the human must decide.
    pub const fn question(&self) -> Option<&WorkspaceSelectionQuestion> {
        match self {
            Self::Reuse { .. } => None,
            Self::AskHuman { question } => Some(question),
        }
    }
}

/// Input to the one-time worktree decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSelectionInput {
    project_id: ProjectId,
    original_checkout_root: String,
    base_branch: String,
    approved_branch: String,
    #[serde(default)]
    answer: Option<WorkspaceSelectionAnswer>,
}

impl WorkspaceSelectionInput {
    /// Creates a decision input.
    pub fn new(
        project_id: ProjectId,
        original_checkout_root: impl Into<String>,
        base_branch: impl Into<String>,
        approved_branch: impl Into<String>,
        answer: Option<WorkspaceSelectionAnswer>,
    ) -> Self {
        Self {
            project_id,
            original_checkout_root: original_checkout_root.into(),
            base_branch: base_branch.into(),
            approved_branch: approved_branch.into(),
            answer,
        }
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Existing checkout the plan was opened from.
    pub fn original_checkout_root(&self) -> &str {
        &self.original_checkout_root
    }

    /// Approved integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Branch the implementation is approved to use.
    pub fn approved_branch(&self) -> &str {
        &self.approved_branch
    }

    /// Answer already recorded in this conversation, when there is one.
    pub const fn answer(&self) -> Option<&WorkspaceSelectionAnswer> {
        self.answer.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Approved facts
// ---------------------------------------------------------------------------

/// Whether a document is the execution plan or a referenced specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedDocumentKind {
    /// The approved execution plan.
    Plan,
    /// A reference specification the plan applies.
    Spec,
}

/// One approved document whose exact version must exist in the checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedDocument {
    path: String,
    kind: ApprovedDocumentKind,
    digest: Sha256Digest,
}

impl ApprovedDocument {
    /// Records a plan document with the digest of its exact approved bytes.
    pub fn plan(path: impl Into<String>, source: &[u8]) -> Result<Self, SddExecutionError> {
        Self::new(path, ApprovedDocumentKind::Plan, source)
    }

    /// Records a referenced specification with the digest of its exact bytes.
    pub fn spec(path: impl Into<String>, source: &[u8]) -> Result<Self, SddExecutionError> {
        Self::new(path, ApprovedDocumentKind::Spec, source)
    }

    /// Records the approved plan from the digest an approval already bound.
    ///
    /// The approval layer uses this after the preview captured the exact bytes,
    /// so the expectation compares the checkout against the approved digest
    /// instead of re-reading a document that may have moved.
    pub fn plan_at_digest(
        path: impl Into<String>,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        Self::from_digest(path, ApprovedDocumentKind::Plan, digest)
    }

    /// Records a referenced specification from its approved digest.
    pub fn spec_at_digest(
        path: impl Into<String>,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        Self::from_digest(path, ApprovedDocumentKind::Spec, digest)
    }

    fn from_digest(
        path: impl Into<String>,
        kind: ApprovedDocumentKind,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        herness_sdd_execute::validate_project_path("workspace.document.path", &path)?;
        Ok(Self { path, kind, digest })
    }

    fn new(
        path: impl Into<String>,
        kind: ApprovedDocumentKind,
        source: &[u8],
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        herness_sdd_execute::validate_project_path("workspace.document.path", &path)?;
        if source.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.document.source".to_owned(),
                detail: "must contain the exact approved bytes".to_owned(),
            });
        }
        Ok(Self {
            path,
            kind,
            digest: Sha256Digest::sha256(source),
        })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Document role.
    pub const fn kind(&self) -> ApprovedDocumentKind {
        self.kind
    }

    /// Digest of the approved bytes.
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// The approved facts one start must verify, registered by the approval layer.
///
/// Task 13 builds this from the immutable execution approval and the honored
/// worktree decision, registers it with [`WorkspaceAdapter::expect`], and then
/// calls `state`, `start_check`, or `prepare`. The adapter refuses to describe or
/// prepare a start it has no approved facts for, so it never invents a branch or
/// a base branch.
#[derive(Debug, Clone)]
pub struct WorkspaceExpectation {
    project_id: ProjectId,
    repository_root: String,
    branch: String,
    base_branch: String,
    execution_ref: String,
    approval_id: String,
    approval_revision: u64,
    documents: Vec<ApprovedDocument>,
    gate: Option<HostGitGate>,
}

impl WorkspaceExpectation {
    /// Creates the approved facts for one start.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        repository_root: impl Into<String>,
        branch: impl Into<String>,
        base_branch: impl Into<String>,
        execution_ref: impl Into<String>,
        approval_id: impl Into<String>,
        approval_revision: u64,
        documents: Vec<ApprovedDocument>,
    ) -> Result<Self, SddExecutionError> {
        let repository_root = repository_root.into();
        let branch = branch.into();
        let base_branch = base_branch.into();
        validate_branch("workspace.branch", &branch)?;
        validate_branch("workspace.baseBranch", &base_branch)?;
        if approval_revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.approvalRevision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        if documents.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.documents".to_owned(),
                detail: "the approved plan and its referenced specs are required".to_owned(),
            });
        }
        if !documents
            .iter()
            .any(|document| document.kind == ApprovedDocumentKind::Plan)
        {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.documents".to_owned(),
                detail: "the approved plan is required".to_owned(),
            });
        }
        Ok(Self {
            project_id,
            repository_root,
            branch,
            base_branch,
            execution_ref: execution_ref.into(),
            approval_id: approval_id.into(),
            approval_revision,
            documents,
            gate: None,
        })
    }

    /// Sets the approved staged-document gate the preparation commit runs.
    #[must_use]
    pub fn with_gate(mut self, gate: HostGitGate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Original checkout that owns the repository.
    pub fn repository_root(&self) -> &str {
        &self.repository_root
    }

    /// Approved implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Approved integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Approved documents.
    pub fn documents(&self) -> &[ApprovedDocument] {
        &self.documents
    }

    /// Approved staged-document gate, when the preparation commit is allowed.
    pub const fn gate(&self) -> Option<&HostGitGate> {
        self.gate.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Baseline record
// ---------------------------------------------------------------------------

/// Where the once-fixed branch baseline is kept.
pub trait BaselineRecord {
    /// Reads the recorded baseline, if any.
    fn read(&self, project_id: ProjectId) -> Result<Option<Baseline>, SddExecutionError>;

    /// Records the baseline once and returns the stored value.
    ///
    /// An identical existing baseline is returned unchanged. A different
    /// baseline is refused: a resume never replaces the recorded baseline.
    fn record_if_absent(
        &mut self,
        project_id: ProjectId,
        baseline: Baseline,
    ) -> Result<Baseline, SddExecutionError>;
}

/// In-memory baseline record for tests and single-process composition.
///
/// The durable implementation is Task 12's store; both share this shape so a
/// resume that observes another HEAD is refused in exactly one place.
#[derive(Debug, Default)]
pub struct MemoryBaselineRecord {
    baselines: BTreeMap<ProjectId, Baseline>,
}

impl MemoryBaselineRecord {
    /// Creates an empty record.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BaselineRecord for MemoryBaselineRecord {
    fn read(&self, project_id: ProjectId) -> Result<Option<Baseline>, SddExecutionError> {
        Ok(self.baselines.get(&project_id).cloned())
    }

    fn record_if_absent(
        &mut self,
        project_id: ProjectId,
        baseline: Baseline,
    ) -> Result<Baseline, SddExecutionError> {
        match self.baselines.get(&project_id) {
            Some(recorded) if *recorded == baseline => Ok(recorded.clone()),
            Some(_) => Err(baseline_conflict()),
            None => {
                self.baselines.insert(project_id, baseline.clone());
                Ok(baseline)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Preparation commit
// ---------------------------------------------------------------------------

/// Performs the single approved `.gitignore` preparation commit.
///
/// The adapter never stages or commits itself, so a composition that allows the
/// preparation commit binds an implementation here — see
/// [`HostGitPreparationCommit`], which wraps `herness_core`'s boundary.
pub trait PreparationCommitPort {
    /// Stages and commits exactly `.gitignore` for the approved preparation.
    fn commit(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
    ) -> Result<HostGitReport, SddExecutionError>;
}

/// Explicit refusal used when no host Git boundary is bound.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPreparationCommit;

impl PreparationCommitPort for NoPreparationCommit {
    fn commit(
        &mut self,
        _intent: &HostGitIntent,
        _authorization: &HostGitAuthorization,
    ) -> Result<HostGitReport, SddExecutionError> {
        Err(unavailable(
            PREPARATION_COMMIT_FEATURE,
            "no host Git boundary is bound to the workspace adapter",
        ))
    }
}

/// `herness_core`'s approved host Git boundary as the preparation-commit port.
pub struct HostGitPreparationCommit<L = SystemArgvLauncher, A = herness_core::RecordingHostGitAudit>
{
    boundary: HostGitBoundary<L, A>,
}

impl<L, A> HostGitPreparationCommit<L, A> {
    /// Wraps one boundary.
    pub const fn new(boundary: HostGitBoundary<L, A>) -> Self {
        Self { boundary }
    }

    /// The wrapped boundary, for reading the audit sink after a commit.
    pub const fn boundary(&self) -> &HostGitBoundary<L, A> {
        &self.boundary
    }
}

impl<L, A> PreparationCommitPort for HostGitPreparationCommit<L, A>
where
    L: herness_core::ArgvLauncher,
    A: herness_core::HostGitAuditPort,
{
    fn commit(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
    ) -> Result<HostGitReport, SddExecutionError> {
        self.boundary
            .commit(intent, authorization)
            .map_err(|error| {
                let detail = match error {
                    HostGitError::IntentNotPersisted { detail } => detail,
                };
                unavailable(PREPARATION_COMMIT_FEATURE, &detail)
            })
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Real Git workspace adapter.
///
/// `L` is the fixed-argv launcher, `C` the preparation-commit port, and `B` the
/// baseline record. Production binds [`SystemArgvLauncher`],
/// [`HostGitPreparationCommit`], and Task 12's durable record; tests bind a
/// counting launcher, a recording/real boundary, and [`MemoryBaselineRecord`].
pub struct WorkspaceAdapter<
    L = SystemArgvLauncher,
    C = NoPreparationCommit,
    B = MemoryBaselineRecord,
> {
    runner: Mutex<GitRunner<L>>,
    committer: Mutex<C>,
    baselines: Mutex<B>,
    expectations: Mutex<BTreeMap<ProjectId, WorkspaceExpectation>>,
}

impl<L, C, B> WorkspaceAdapter<L, C, B> {
    /// Creates an adapter from its three collaborating pieces.
    pub fn new(runner: GitRunner<L>, committer: C, baselines: B) -> Self {
        Self {
            runner: Mutex::new(runner),
            committer: Mutex::new(committer),
            baselines: Mutex::new(baselines),
            expectations: Mutex::new(BTreeMap::new()),
        }
    }

    /// Registers the approved facts one start must verify.
    ///
    /// Called by the approval layer before `state`, `start_check`, or `prepare`.
    pub fn expect(&self, expectation: WorkspaceExpectation) {
        self.expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(expectation.project_id, expectation);
    }

    /// Reads the registered approved facts.
    pub fn expectation(&self, project_id: ProjectId) -> Option<WorkspaceExpectation> {
        self.expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&project_id)
            .cloned()
    }

    fn lock_runner(&self) -> std::sync::MutexGuard<'_, GitRunner<L>> {
        self.runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<L, C, B: BaselineRecord> WorkspaceAdapter<L, C, B> {
    /// Reads the recorded baseline.
    pub fn baseline(&self, project_id: ProjectId) -> Result<Option<Baseline>, SddExecutionError> {
        self.baselines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read(project_id)
    }

    /// Records the baseline once and refuses to replace a different one.
    ///
    /// A resume that observes another HEAD fails here instead of overwriting the
    /// fixed baseline.
    pub fn record_baseline(
        &self,
        project_id: ProjectId,
        baseline: Baseline,
    ) -> Result<Baseline, SddExecutionError> {
        self.baselines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_if_absent(project_id, baseline)
    }
}

impl<L, C, B> WorkspaceAdapter<L, C, B>
where
    L: herness_core::ArgvLauncher,
    C: PreparationCommitPort,
    B: BaselineRecord,
{
    /// Resolves the one-time worktree decision without changing anything.
    pub fn decide(
        &self,
        input: &WorkspaceSelectionInput,
    ) -> Result<WorkspaceDecision, SddExecutionError> {
        let question = |reason: WorkspaceUndecided| WorkspaceDecision::AskHuman {
            question: WorkspaceSelectionQuestion {
                original_checkout_root: input.original_checkout_root.clone(),
                base_branch: input.base_branch.clone(),
                approved_branch: input.approved_branch.clone(),
                reason,
            },
        };

        let original = canonical_directory(input.original_checkout_root())?;
        let mut runner = self.lock_runner();
        let Some(repository) = runner.repository_root(&original)? else {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.originalCheckoutRoot".to_owned(),
                detail: "is not a Git working tree".to_owned(),
            });
        };
        if canonical_directory(&repository)? != original {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.originalCheckoutRoot".to_owned(),
                detail: "is not the root of its Git working tree".to_owned(),
            });
        }
        let worktrees = runner.worktrees(&repository)?;

        // 1. An answer recorded in this conversation is the most explicit
        //    decision and never asks again.
        if let Some(answer) = input.answer() {
            return match answer {
                WorkspaceSelectionAnswer::InPlace => {
                    let Some(branch) = runner.current_branch(&original)? else {
                        return Ok(question(WorkspaceUndecided::DetachedCheckout));
                    };
                    if branch != input.approved_branch() {
                        return Err(branch_mismatch());
                    }
                    Ok(WorkspaceDecision::Reuse {
                        selection: WorkspaceSelection::new(
                            original,
                            branch,
                            false,
                            WorkspaceSelectionSource::ConversationAnswer,
                        ),
                    })
                }
                WorkspaceSelectionAnswer::Isolated { checkout_root } => {
                    let root = canonical_planned_path(checkout_root)?;
                    if let Some(existing) = worktrees
                        .iter()
                        .find(|worktree| same_path(worktree.path(), &root))
                    {
                        let Some(branch) = existing.branch() else {
                            return Ok(question(WorkspaceUndecided::DetachedCheckout));
                        };
                        if branch != input.approved_branch() {
                            return Err(branch_mismatch());
                        }
                        Ok(WorkspaceDecision::Reuse {
                            selection: WorkspaceSelection::new(
                                root,
                                branch,
                                true,
                                WorkspaceSelectionSource::ConversationAnswer,
                            ),
                        })
                    } else if Path::new(&root).exists() {
                        Err(unavailable(
                            ISOLATION_FEATURE,
                            "the approved isolated root exists but is not a linked worktree",
                        ))
                    } else {
                        Ok(WorkspaceDecision::Reuse {
                            selection: WorkspaceSelection::new(
                                root,
                                input.approved_branch(),
                                true,
                                WorkspaceSelectionSource::ConversationAnswer,
                            ),
                        })
                    }
                }
            };
        }

        // 2. The `.sdd/progress.md` `Worktree:` line the existing SDD flow wrote.
        if let Some(recorded) = read_ledger_worktree(&original)? {
            let recorded_path = canonical_recorded_path(&recorded);
            if same_path(&recorded_path, &original) {
                return match runner.current_branch(&original)? {
                    Some(branch) if branch == input.approved_branch() => {
                        Ok(WorkspaceDecision::Reuse {
                            selection: WorkspaceSelection::new(
                                original,
                                branch,
                                false,
                                WorkspaceSelectionSource::ProgressLedger,
                            ),
                        })
                    }
                    Some(branch) => Ok(question(WorkspaceUndecided::LinkedWorktreeOnOtherBranch {
                        path: recorded_path,
                        branch: branch.to_owned(),
                    })),
                    None => Ok(question(WorkspaceUndecided::DetachedCheckout)),
                };
            }
            match worktrees
                .iter()
                .find(|worktree| same_path(worktree.path(), &recorded_path))
            {
                Some(worktree) => {
                    let Some(branch) = worktree.branch() else {
                        return Ok(question(WorkspaceUndecided::DetachedCheckout));
                    };
                    if branch != input.approved_branch() {
                        return Ok(question(WorkspaceUndecided::LinkedWorktreeOnOtherBranch {
                            path: recorded_path,
                            branch: branch.to_owned(),
                        }));
                    }
                    Ok(WorkspaceDecision::Reuse {
                        selection: WorkspaceSelection::new(
                            recorded_path,
                            branch.to_owned(),
                            true,
                            WorkspaceSelectionSource::ProgressLedger,
                        ),
                    })
                }
                None => Ok(question(WorkspaceUndecided::RecordedWorktreeMissing {
                    path: recorded_path,
                })),
            }
        } else {
            // 3. An already linked worktree on the approved branch.
            for worktree in &worktrees {
                if same_path(worktree.path(), &original) {
                    continue;
                }
                match worktree.branch() {
                    Some(branch) if branch == input.approved_branch() => {
                        return Ok(WorkspaceDecision::Reuse {
                            selection: WorkspaceSelection::new(
                                worktree.path(),
                                branch,
                                true,
                                WorkspaceSelectionSource::LinkedWorktree,
                            ),
                        });
                    }
                    _ => continue,
                }
            }

            // 4. Genuinely undecided.
            Ok(question(WorkspaceUndecided::NoRecord))
        }
    }

    /// Verifies the selected checkout before a start and reports its state.
    ///
    /// Verifies branch, base branch, and the approved plan/spec versions. Only
    /// the selected checkout's cleanliness decides `is_startable`.
    pub fn start_check(
        &self,
        project_id: ProjectId,
        canonical_checkout_root: &str,
    ) -> Result<WorkspaceState, SddExecutionError> {
        let expectation = self.require_expectation(project_id)?;
        let (state, _status) = self.read_state(project_id, canonical_checkout_root)?;
        self.verify_start(&state, &expectation, canonical_checkout_root)?;
        Ok(state)
    }

    /// Prepares the approved checkout and returns the resulting state.
    pub fn prepare_approved(
        &mut self,
        request: &WorkspacePreparation,
    ) -> Result<WorkspaceState, SddExecutionError> {
        let expectation = self.require_expectation(request.project_id())?;
        if request.create_isolated_worktree() {
            self.prepare_isolated(request, &expectation)
        } else {
            self.prepare_in_place(request, &expectation)
        }
    }

    fn prepare_isolated(
        &mut self,
        request: &WorkspacePreparation,
        expectation: &WorkspaceExpectation,
    ) -> Result<WorkspaceState, SddExecutionError> {
        let new_branch = request.new_branch();
        if new_branch.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.newBranch".to_owned(),
                detail: "an isolated preparation requires an approved new branch".to_owned(),
            });
        }
        validate_branch("workspace.newBranch", new_branch)?;
        if new_branch != expectation.branch() {
            return Err(branch_mismatch());
        }
        if request.base_branch() != expectation.base_branch() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "workspace.baseBranch".to_owned(),
                },
            });
        }

        let repository = canonical_directory(expectation.repository_root())?;
        let target = canonical_planned_path(request.canonical_checkout_root())?;
        if same_path(&repository, &target) {
            return Err(unavailable(
                ISOLATION_FEATURE,
                "the isolated root is the original checkout",
            ));
        }
        if Path::new(&target).exists() {
            return Err(unavailable(
                ISOLATION_FEATURE,
                "the approved isolated root already exists; it is never adopted",
            ));
        }
        let Some(parent) = Path::new(&target).parent() else {
            return Err(unavailable(
                ISOLATION_FEATURE,
                "the isolated root has no parent directory",
            ));
        };
        if !parent.is_dir() {
            return Err(unavailable(
                ISOLATION_FEATURE,
                "the isolated root's parent directory does not exist",
            ));
        }

        {
            let mut runner = self.lock_runner();
            if runner.repository_root(&repository)?.is_none() {
                return Err(SddExecutionError::InvalidValue {
                    field: "workspace.repositoryRoot".to_owned(),
                    detail: "is not a Git working tree".to_owned(),
                });
            }
            if runner
                .rev_parse_commit(&repository, request.base_branch())?
                .is_none()
            {
                return Err(SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::StartApproval,
                    details: FailureDetails::none().boxed(),
                });
            }
            if runner
                .rev_parse_commit(&repository, &format!("refs/heads/{new_branch}"))?
                .is_some()
            {
                return Err(unavailable(
                    ISOLATION_FEATURE,
                    "the approved new branch already exists",
                ));
            }
            // `--detach` cannot create a branch, so a failed add leaves no
            // branch behind and can never be adopted as in-place permission.
            let added =
                runner.add_detached_worktree(&repository, &target, request.base_branch())?;
            if !added.succeeded() {
                return Err(unavailable(ISOLATION_FEATURE, &added.detail()));
            }
        }

        let created = self
            .lock_runner()
            .create_branch_in_worktree(&target, new_branch)?;
        if !created.succeeded() {
            let removed = self.lock_runner().remove_worktree(&repository, &target)?;
            if !removed.succeeded() {
                return Err(SddExecutionError::RecoveryRequired {
                    reason: RecoveryReason::StateUnreadable,
                    details: FailureDetails::none().boxed(),
                });
            }
            return Err(unavailable(ISOLATION_FEATURE, &created.detail()));
        }

        self.finish_preparation(request, expectation, &target, true)
    }

    fn prepare_in_place(
        &mut self,
        request: &WorkspacePreparation,
        expectation: &WorkspaceExpectation,
    ) -> Result<WorkspaceState, SddExecutionError> {
        if request.base_branch() != expectation.base_branch() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "workspace.baseBranch".to_owned(),
                },
            });
        }
        let selected = canonical_directory(request.canonical_checkout_root())?;
        let repository = canonical_directory(expectation.repository_root())?;
        // In place means "use this already-selected checkout", which may be the
        // original root or an existing linked worktree of the same repository. It
        // must never mean "another repository", so the shared common Git
        // directory is what decides ownership.
        {
            let mut runner = self.lock_runner();
            let selected_repository = runner.common_git_dir(&selected)?;
            let expected_repository = runner.common_git_dir(&repository)?;
            match (selected_repository, expected_repository) {
                (Some(selected), Some(expected)) if selected == expected => {}
                _ => {
                    return Err(SddExecutionError::InvalidValue {
                        field: "workspace.canonicalCheckoutRoot".to_owned(),
                        detail: "an in-place preparation must be the approved repository"
                            .to_owned(),
                    });
                }
            }
        }
        self.finish_preparation(request, expectation, &selected, false)
    }

    fn finish_preparation(
        &mut self,
        request: &WorkspacePreparation,
        expectation: &WorkspaceExpectation,
        checkout_root: &str,
        isolated: bool,
    ) -> Result<WorkspaceState, SddExecutionError> {
        let (state, status) = self.read_state(request.project_id(), checkout_root)?;
        self.verify_start(&state, expectation, checkout_root)?;

        if !status.index_clean() {
            return Err(dirty());
        }
        // Only H4's own `.sdd/` scratch may be present and uncovered: the
        // approved preparation commit ignores it and cleans the worktree that
        // way. Any other change is a human decision and is never discarded.
        if !dirt_outside_sdd(&status).is_empty() {
            return Err(dirty());
        }
        let covered = gitignore_covers_sdd(checkout_root)?;
        if !covered && !request.prepare_gitignore_commit() {
            return Err(SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: FailureDetails::none().boxed(),
            });
        }
        if !covered {
            self.commit_gitignore(request, expectation, checkout_root, expectation.branch())?;
        }
        if !self
            .lock_runner()
            .is_ignored(checkout_root, PROGRESS_LEDGER_PATH)?
        {
            return Err(unavailable(
                PREPARATION_COMMIT_FEATURE,
                "the progress ledger path is not ignored after preparation",
            ));
        }

        let head = self
            .lock_runner()
            .head(checkout_root)?
            .ok_or_else(|| invalid("workspace.baseline", "the checkout has no commit"))?;
        let baseline = Baseline::parse(head.as_str())?;
        let recorded = self.record_baseline(request.project_id(), baseline)?;
        if recorded.as_str() != head.as_str() {
            return Err(baseline_conflict());
        }

        let (state, _status) = self.read_state(request.project_id(), checkout_root)?;
        self.verify_start(&state, expectation, checkout_root)?;
        if isolated && !state.is_startable() {
            return Err(unavailable(
                ISOLATION_FEATURE,
                "the new worktree is not clean after preparation",
            ));
        }
        Ok(state)
    }

    fn commit_gitignore(
        &mut self,
        request: &WorkspacePreparation,
        expectation: &WorkspaceExpectation,
        checkout_root: &str,
        branch: &str,
    ) -> Result<(), SddExecutionError> {
        let gate = expectation.gate().ok_or_else(|| {
            unavailable(
                PREPARATION_COMMIT_FEATURE,
                "no approved staged-document gate is bound",
            )
        })?;
        let existing = read_gitignore(checkout_root)?;
        let bytes = sdd_ignore_contents(&existing);
        let path = Path::new(checkout_root).join(GITIGNORE_PATH);
        std::fs::write(&path, &bytes).map_err(|error| {
            unavailable(
                PREPARATION_COMMIT_FEATURE,
                &format!("could not write .gitignore: {error}"),
            )
        })?;

        let parent = self
            .lock_runner()
            .head(checkout_root)?
            .ok_or_else(|| invalid("workspace.baseline", "the checkout has no commit"))?;
        let checkout = AbsolutePath::new(checkout_root)
            .map_err(|error| invalid("workspace.canonicalCheckoutRoot", &error.to_string()))?;
        let approval = HostCommitApproval::new(
            request.project_id(),
            expectation.approval_id.clone(),
            expectation.approval_revision,
            HostGitApprover::Human,
            checkout.clone(),
            branch,
            true,
            true,
        )
        .map_err(preparation_refusal)?;
        let authorization = approval.authorize().map_err(preparation_refusal)?;

        let purpose = Purpose::new("ignore the H4 progress ledger before the first Task")
            .map_err(|error| invalid("workspace.purpose", &error.to_string()))?;
        let message = HostGitMessage::new(
            "chore(sdd): ignore the H4 progress ledger",
            vec![
                HostGitTrailer::new("Herness-Execution", expectation.execution_ref.clone())
                    .map_err(preparation_refusal)?,
                HostGitTrailer::new("Herness-Approval", expectation.approval_id.clone())
                    .map_err(preparation_refusal)?,
            ],
        )
        .map_err(preparation_refusal)?;
        let request_id = format!("herness.workspace.gitignore.{}", expectation.approval_id);
        let intent = HostGitIntent::new(
            request.project_id(),
            request_id,
            purpose,
            expectation.execution_ref.clone(),
            1,
            "workspace preparation",
            expectation.approval_id.clone(),
            expectation.approval_revision,
            checkout,
            branch,
            GitObjectId::parse(parent.as_str()).map_err(preparation_refusal)?,
            None,
            vec![HostGitPath::for_bytes(GITIGNORE_PATH, &bytes).map_err(preparation_refusal)?],
            message,
            gate.clone(),
            HOST_COMMIT_TIMEOUT,
            None,
        )
        .map_err(preparation_refusal)?;

        let report = self
            .committer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .commit(&intent, &authorization)?;
        match report.outcome() {
            HostGitOutcome::Committed { commit, .. } => {
                if !report.result_recorded() {
                    return Err(SddExecutionError::GitResultUnknown {
                        reason: GitUnknownReason::JournalWriteFailed,
                        details: FailureDetails::none().boxed(),
                    });
                }
                if commit.as_str() == parent.as_str() {
                    return Err(unavailable(
                        PREPARATION_COMMIT_FEATURE,
                        "the preparation commit did not advance HEAD",
                    ));
                }
                Ok(())
            }
            HostGitOutcome::Rejected { reason } => {
                Err(unavailable(PREPARATION_COMMIT_FEATURE, &reason.to_string()))
            }
            HostGitOutcome::Unknown { reason } => Err(SddExecutionError::GitResultUnknown {
                reason: unknown_reason(*reason),
                details: FailureDetails::none().boxed(),
            }),
        }
    }

    /// Reads the selected checkout without changing Git.
    fn read_state(
        &self,
        project_id: ProjectId,
        canonical_checkout_root: &str,
    ) -> Result<(WorkspaceState, GitWorktreeStatus), SddExecutionError> {
        let expectation = self.require_expectation(project_id)?;
        let root = canonical_directory(canonical_checkout_root)?;
        let mut runner = self.lock_runner();
        let Some(repository) = runner.repository_root(&root)? else {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.canonicalCheckoutRoot".to_owned(),
                detail: "is not a Git working tree".to_owned(),
            });
        };
        if canonical_directory(&repository)? != root {
            return Err(SddExecutionError::InvalidValue {
                field: "workspace.canonicalCheckoutRoot".to_owned(),
                detail: "is not the root of its Git working tree".to_owned(),
            });
        }
        let head = runner.head(&root)?;
        let branch = runner.current_branch(&root)?.unwrap_or_default();
        let status = runner.status(&root)?;
        drop(runner);

        let baseline = self.baseline(project_id)?;
        let state = WorkspaceState::new(
            project_id,
            root,
            branch,
            expectation.base_branch().to_owned(),
            head,
            baseline,
            status.worktree_clean(),
            status.index_clean(),
        );
        Ok((state, status))
    }

    /// Verifies branch, base branch, and approved document versions.
    fn verify_start(
        &self,
        state: &WorkspaceState,
        expectation: &WorkspaceExpectation,
        checkout_root: &str,
    ) -> Result<(), SddExecutionError> {
        if state.branch() != expectation.branch() {
            return Err(branch_mismatch());
        }
        if state.base_branch() != expectation.base_branch() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "workspace.baseBranch".to_owned(),
                },
            });
        }
        verify_documents(checkout_root, expectation)?;
        let mut runner = self.lock_runner();
        if runner
            .rev_parse_commit(checkout_root, expectation.base_branch())?
            .is_none()
        {
            return Err(unavailable(
                BASE_BRANCH_FEATURE,
                "the approved base branch does not resolve in the selected checkout",
            ));
        }
        Ok(())
    }

    fn require_expectation(
        &self,
        project_id: ProjectId,
    ) -> Result<WorkspaceExpectation, SddExecutionError> {
        self.expectation(project_id)
            .ok_or_else(|| SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: FailureDetails::none().boxed(),
            })
    }
}

impl<L, C, B> WorkspacePort for WorkspaceAdapter<L, C, B>
where
    L: herness_core::ArgvLauncher,
    C: PreparationCommitPort,
    B: BaselineRecord,
{
    fn state(
        &self,
        project_id: ProjectId,
        canonical_checkout_root: &str,
    ) -> Result<WorkspaceState, SddExecutionError> {
        let (state, _status) = self.read_state(project_id, canonical_checkout_root)?;
        let expectation = self.require_expectation(project_id)?;
        if state.branch() != expectation.branch() {
            return Err(branch_mismatch());
        }
        Ok(state)
    }

    fn prepare(
        &mut self,
        request: &WorkspacePreparation,
    ) -> Result<WorkspaceState, SddExecutionError> {
        self.prepare_approved(request)
    }
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

fn dirt_outside_sdd(status: &GitWorktreeStatus) -> Vec<String> {
    status
        .paths()
        .filter(|path| {
            let path = *path;
            path != ".sdd" && !path.starts_with(".sdd/")
        })
        .map(str::to_owned)
        .collect()
}

fn verify_documents(
    checkout_root: &str,
    expectation: &WorkspaceExpectation,
) -> Result<(), SddExecutionError> {
    for document in expectation.documents() {
        let path = Path::new(checkout_root).join(document.path());
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => return Err(document_mismatch(document)),
        };
        if Sha256Digest::sha256(&bytes) != *document.digest() {
            return Err(document_mismatch(document));
        }
    }
    Ok(())
}

fn document_mismatch(document: &ApprovedDocument) -> SddExecutionError {
    match document.kind() {
        ApprovedDocumentKind::Plan => SddExecutionError::PlanChanged {
            reason: PlanChangeReason::Missing,
            details: FailureDetails::none().boxed(),
        },
        ApprovedDocumentKind::Spec => SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch {
                field: format!("spec:{}", document.path()),
            },
        },
    }
}

fn gitignore_covers_sdd(checkout_root: &str) -> Result<bool, SddExecutionError> {
    let contents = read_gitignore(checkout_root)?;
    Ok(contents.lines().any(|line| {
        let line = line.trim();
        SDD_IGNORE_ALTERNATIVES.contains(&line)
    }))
}

fn read_gitignore(checkout_root: &str) -> Result<String, SddExecutionError> {
    let path = Path::new(checkout_root).join(GITIGNORE_PATH);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(invalid(
            "workspace.gitignore",
            &format!("could not read .gitignore: {error}"),
        )),
    }
}

/// Appends the literal `.sdd/` line to the current `.gitignore` content.
fn sdd_ignore_contents(existing: &str) -> Vec<u8> {
    let mut contents = String::with_capacity(existing.len() + SDD_IGNORE_LINE.len() + 1);
    if !existing.is_empty() {
        contents.push_str(existing);
        if !existing.ends_with('\n') {
            contents.push('\n');
        }
    }
    contents.push_str(SDD_IGNORE_LINE);
    contents.push('\n');
    contents.into_bytes()
}

/// Reads the `Worktree:` line the existing SDD progress ledger records.
///
/// The existing SDD flow writes `Worktree: created <path>` and older ledgers
/// write a bare path; both are honored. A `(`-prefixed value is a comment and is
/// not a decision.
fn read_ledger_worktree(checkout_root: &str) -> Result<Option<String>, SddExecutionError> {
    let path = Path::new(checkout_root).join(PROGRESS_LEDGER_PATH);
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(invalid(
                "workspace.progressLedger",
                &format!("could not read {PROGRESS_LEDGER_PATH}: {error}"),
            ));
        }
    };
    for line in contents.lines() {
        let Some(value) = line.strip_prefix("Worktree:") else {
            continue;
        };
        let value = value.trim();
        let value = value.strip_prefix("created").unwrap_or(value).trim();
        if value.is_empty() || value.starts_with('(') {
            continue;
        }
        return Ok(Some(value.to_owned()));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Small value helpers
// ---------------------------------------------------------------------------

fn same_path(left: &str, right: &str) -> bool {
    fn normalize(value: &str) -> String {
        let path = Path::new(value);
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        canonical.to_string_lossy().into_owned()
    }
    normalize(left) == normalize(right)
}

fn canonical_directory(value: &str) -> Result<String, SddExecutionError> {
    let invalid_root = || SddExecutionError::InvalidValue {
        field: "workspace.checkoutRoot".to_owned(),
        detail: "must be an existing canonical absolute directory".to_owned(),
    };
    if value.trim().is_empty() || value.contains('\0') {
        return Err(invalid_root());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(invalid_root());
    }
    if path.components().any(|component| {
        !matches!(
            component,
            std::path::Component::RootDir
                | std::path::Component::CurDir
                | std::path::Component::Normal(_)
        )
    }) {
        return Err(invalid_root());
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| invalid_root())?;
    if !canonical.is_dir() {
        return Err(invalid_root());
    }
    Ok(canonical.to_string_lossy().into_owned())
}

/// Normalizes a path that may not exist yet.
fn canonical_planned_path(value: &str) -> Result<String, SddExecutionError> {
    let invalid_root = || SddExecutionError::InvalidValue {
        field: "workspace.checkoutRoot".to_owned(),
        detail: "must be an absolute path without '.', '..', or a symlink escape".to_owned(),
    };
    if value.trim().is_empty() || value.contains('\0') {
        return Err(invalid_root());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(invalid_root());
    }
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Normal(_) => {}
            _ => return Err(invalid_root()),
        }
    }
    match std::fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical.to_string_lossy().into_owned()),
        Err(_) => Ok(path.to_string_lossy().into_owned()),
    }
}

fn canonical_recorded_path(value: &str) -> String {
    std::fs::canonicalize(value)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| value.to_owned())
}

fn validate_branch(field: &str, branch: &str) -> Result<(), SddExecutionError> {
    let invalid_branch = |detail: &str| SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    };
    if branch.trim().is_empty() {
        return Err(invalid_branch("must not be empty"));
    }
    if branch == "HEAD" || branch == "@" {
        return Err(invalid_branch("must name a branch"));
    }
    if branch.starts_with('-')
        || branch.contains("..")
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with(".lock")
    {
        return Err(invalid_branch("is not a valid Git branch name"));
    }
    if branch
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_branch("is not a valid Git branch name"));
    }
    if branch
        .chars()
        .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Err(invalid_branch("is not a valid Git branch name"));
    }
    if branch
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid_branch("is not a valid Git branch name"));
    }
    Ok(())
}

fn branch_mismatch() -> SddExecutionError {
    SddExecutionError::ApprovalRejected {
        reason: ApprovalRejection::WorkspaceMismatch {
            field: "workspace.branch".to_owned(),
        },
    }
}

fn dirty() -> SddExecutionError {
    SddExecutionError::Conflict {
        reason: ConflictReason::DirtyIndex,
        details: FailureDetails::none().boxed(),
    }
}

fn baseline_conflict() -> SddExecutionError {
    SddExecutionError::Conflict {
        reason: ConflictReason::ConcurrentEdit,
        details: FailureDetails::none().boxed(),
    }
}

fn preparation_refusal(refusal: HostGitRefusal) -> SddExecutionError {
    unavailable(PREPARATION_COMMIT_FEATURE, &refusal.to_string())
}

fn unknown_reason(unknown: HostGitUnknown) -> GitUnknownReason {
    match unknown {
        HostGitUnknown::Timeout => GitUnknownReason::Timeout,
        HostGitUnknown::Stopped => GitUnknownReason::Stopped,
        HostGitUnknown::AuditWriteFailed => GitUnknownReason::JournalWriteFailed,
        HostGitUnknown::HeadUnreadable => GitUnknownReason::HeadUnreadable,
        _ => GitUnknownReason::UnobservedProcess,
    }
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

/// `unavailable` with the adapter's own feature detail.
pub(crate) fn unavailable(feature: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}
