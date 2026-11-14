//! Host commit finalization and Git recovery classification.
//!
//! This module is the deterministic decision layer between H2's completion and
//! the host's Git side effect. It owns no process and no database handle: it
//! drives [`HostGitPort`] and [`ExecutionStorePort`] in a fixed order and reads
//! the checkout through [`CommitObservationPort`].
//!
//! # Fixed order
//!
//! 1. validate the request (policy, explicit paths, budget) **in memory**;
//! 2. read the recorded Git journal for this Task's commit request. A recorded
//!    result is returned as stored and never repeated; two deliveries of one
//!    request therefore create at most one commit. A recorded intent without a
//!    result may already have produced a commit, so it is reported as unknown
//!    and left to human reconciliation instead of being retried;
//! 3. persist the exact intent — request, execution, Task, branch, expected
//!    parent, explicit paths with bytes and digests, message and trailers, and
//!    the pre-hook state — **before** any Git side effect;
//! 4. run the boundary, which stages only the approved paths, runs the normal
//!    hooks and the common staged-document gate, and commits;
//! 5. record the observed result;
//! 6. re-read HEAD, tree, parent, the commit message trailers, the index, and
//!    the bytes of every tracked document, and only then report completion.
//!
//! # What is never done
//!
//! No `reset`, `restore`, `checkout`, `clean`, `amend`, `rebase`, `merge`, or
//! second commit attempt exists here. A hook failure, a changed hook
//! configuration, an unrelated index entry, an external edit, an unconfirmed
//! process, or a failed durable write is a hold for a human, never a silently
//! repaired success. Git and SQLite are not one transaction, and a commit whose
//! completion could not be stored is reported as unknown.
//!
//! # required and no_change
//!
//! A `required` Task must advance HEAD from its BASE with exactly the approved
//! paths, so its target list must be non-empty. A `no_change` Task creates no
//! commit at all: it proves that every tracked document still carries the bytes
//! verified before the Task, records that evidence, and leaves HEAD where it
//! was.

use herness_core::contracts::ProjectId;
use herness_supervision::EvidenceId;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::approval::{CommitAuthorization, CommitPolicy};
use crate::error::SddExecutionError;
use crate::ids::{
    Baseline, CommitRequestId, CommitSha, ExecutionId, ExecutionRevision, TaskRef, TreeSha,
};
use crate::journal::{
    CommitMessage, CommittedPath, GitCommitIntent, GitCommitOutcome, GitJournalEntry, GitRejection,
    PreHookState, RequestIdentity,
};
use crate::plan::validate_project_path;
use crate::ports::{ExecutionStorePort, HostGitPort};
use crate::snapshot::{CommitRange, NoChangeRecord};
use crate::state::{GitUnknownReason, HumanAction, StopReason, StopRecord};
use crate::version::{HOST_COMMIT_TIMEOUT_SECONDS, Sha256Digest};

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// Why one path belongs to the approved commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetOrigin {
    /// A path inside the Task's approved write scope.
    TaskChange,
    /// An H3-produced HTML companion of a verified document.
    HtmlCompanion,
    /// An H3-produced evaluation receipt of a verified document.
    HtmlReceipt,
}

impl TargetOrigin {
    /// Stable label used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskChange => "task_change",
            Self::HtmlCompanion => "html_companion",
            Self::HtmlReceipt => "html_receipt",
        }
    }

    /// Whether the path is an H3-produced derived artifact.
    pub const fn is_derived(self) -> bool {
        matches!(self, Self::HtmlCompanion | Self::HtmlReceipt)
    }
}

/// One explicitly staged path with the exact content the host verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitTarget {
    path: String,
    bytes: u64,
    digest: Sha256Digest,
    origin: TargetOrigin,
}

impl CommitTarget {
    /// Creates one target from an already measured content digest.
    pub fn new(
        path: impl Into<String>,
        bytes: u64,
        digest: Sha256Digest,
        origin: TargetOrigin,
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        validate_project_path("commit.target.path", &path)?;
        Ok(Self {
            path,
            bytes,
            digest,
            origin,
        })
    }

    /// Creates one target from the exact bytes written at `path`.
    pub fn for_bytes(
        path: impl Into<String>,
        source: &[u8],
        origin: TargetOrigin,
    ) -> Result<Self, SddExecutionError> {
        Self::new(
            path,
            source.len() as u64,
            Sha256Digest::sha256(source),
            origin,
        )
    }

    /// Project-relative path passed to `git add` as one argv entry.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact byte length.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Digest of the exact bytes.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Why the path is committed.
    pub const fn origin(&self) -> TargetOrigin {
        self.origin
    }

    fn staged_path(&self) -> Result<CommittedPath, SddExecutionError> {
        CommittedPath::new(self.path.clone(), self.bytes, Some(self.digest.clone()))
    }
}

/// One path whose bytes were verified before the Task and must not move.
///
/// A `None` digest records that the path must still be absent, which is how a
/// deleted source is asserted rather than ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPath {
    path: String,
    digest: Option<Sha256Digest>,
}

impl VerifiedPath {
    /// Records one verified present path.
    pub fn present(
        path: impl Into<String>,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        Self::new(path, Some(digest))
    }

    /// Records one verified absent path.
    pub fn absent(path: impl Into<String>) -> Result<Self, SddExecutionError> {
        Self::new(path, None)
    }

    /// Records a path with an optional verified digest.
    pub fn new(
        path: impl Into<String>,
        digest: Option<Sha256Digest>,
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        validate_project_path("commit.verifiedPath", &path)?;
        Ok(Self { path, digest })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Verified digest, or `None` when the path must be absent.
    pub fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Target selection
// ---------------------------------------------------------------------------

/// One changed path the checkout reports against BASE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedPath {
    path: String,
    bytes: u64,
    digest: Option<Sha256Digest>,
}

impl ChangedPath {
    /// Records one changed path from its exact current bytes.
    pub fn for_bytes(path: impl Into<String>, source: &[u8]) -> Result<Self, SddExecutionError> {
        Self::new(
            path,
            source.len() as u64,
            Some(Sha256Digest::sha256(source)),
        )
    }

    /// Records one changed path with its measured length and digest.
    pub fn present(
        path: impl Into<String>,
        bytes: u64,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        Self::new(path, bytes, Some(digest))
    }

    /// Records one deleted path.
    pub fn deleted(path: impl Into<String>) -> Result<Self, SddExecutionError> {
        Self::new(path, 0, None)
    }

    /// Records one changed path.
    pub fn new(
        path: impl Into<String>,
        bytes: u64,
        digest: Option<Sha256Digest>,
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        validate_project_path("commit.changedPath", &path)?;
        Ok(Self {
            path,
            bytes,
            digest,
        })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact current byte length.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Exact current digest, or `None` when the path was deleted.
    pub fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }
}

/// Why the approved target set cannot be fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetRefusal {
    /// A changed path is outside the approved write scope and is not a verified
    /// H3-produced artifact.
    Unrelated {
        /// The unrelated path.
        path: String,
    },
    /// A path inside the approved scope was deleted. The host will not infer a
    /// deletion from an approved path.
    Deleted {
        /// The deleted path.
        path: String,
    },
    /// A derived artifact appeared without being verified by the barrier.
    UnverifiedDerived {
        /// The path.
        path: String,
    },
}

impl TargetRefusal {
    /// The durable stop this refusal becomes.
    pub fn stop(&self) -> Result<StopRecord, SddExecutionError> {
        match self {
            Self::Unrelated { .. } => {
                StopRecord::new(StopReason::Conflict, Some(HumanAction::ResolveConflict))
            }
            Self::Deleted { .. } | Self::UnverifiedDerived { .. } => StopRecord::new(
                StopReason::HumanDecisionRequired,
                Some(HumanAction::ResolveHumanDecision),
            ),
        }
    }
}

/// The exact target set of one Task commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSelection {
    targets: Vec<CommitTarget>,
    derived: Vec<CommitTarget>,
}

impl TargetSelection {
    /// Every target, in path order.
    pub fn targets(&self) -> &[CommitTarget] {
        &self.targets
    }

    /// The H3-produced subset.
    pub fn derived(&self) -> &[CommitTarget] {
        &self.derived
    }

    /// Whether the Task changed nothing in the approved scope.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// Fixes the committed target set from the observed changes against BASE.
///
/// Only a path inside the Task's approved write scope, or a **verified derived
/// artifact** the barrier just confirmed, may be committed. A changed path
/// outside both is an unrelated change and holds the Task; a deletion inside
/// the scope holds it; a derived-looking path the barrier did not verify holds
/// it. Nothing is ever widened to the whole worktree.
pub fn select_targets(
    changed: &[ChangedPath],
    write_scope: &[String],
    verified_derived: &[CommitTarget],
) -> Result<TargetSelection, TargetRefusal> {
    let mut targets = Vec::new();
    let mut derived = Vec::new();
    for path in changed {
        let in_scope = write_scope
            .iter()
            .any(|scope| path_within(path.path(), scope));
        let verified = verified_derived
            .iter()
            .find(|target| target.path() == path.path());
        match (in_scope, verified, path.digest()) {
            (_, Some(_), None) => {
                return Err(TargetRefusal::Deleted {
                    path: path.path().to_owned(),
                });
            }
            // A verified derived artifact must still carry the verified bytes.
            (_, Some(target), Some(digest)) if target.digest() != digest => {
                return Err(TargetRefusal::UnverifiedDerived {
                    path: path.path().to_owned(),
                });
            }
            (_, Some(target), Some(_)) => {
                derived.push(target.clone());
                targets.push(target.clone());
            }
            (true, None, None) => {
                return Err(TargetRefusal::Deleted {
                    path: path.path().to_owned(),
                });
            }
            (true, None, Some(digest)) => {
                // The path was validated by `ChangedPath` and the scope check
                // above, so it is constructed here without a second parse.
                targets.push(CommitTarget {
                    path: path.path().to_owned(),
                    bytes: path.bytes(),
                    digest: digest.clone(),
                    origin: TargetOrigin::TaskChange,
                });
            }
            (false, None, _) => {
                return Err(TargetRefusal::Unrelated {
                    path: path.path().to_owned(),
                });
            }
        }
    }
    targets.sort_by(|left, right| left.path().cmp(right.path()));
    derived.sort_by(|left, right| left.path().cmp(right.path()));
    Ok(TargetSelection { targets, derived })
}

/// Whether `path` is `scope` or inside it.
pub fn path_within(path: &str, scope: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Everything one Task finalization fixes before any Git side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCommitRequest {
    task: TaskRef,
    execution_id: ExecutionId,
    request_id: CommitRequestId,
    expected_revision: ExecutionRevision,
    approval: CommitAuthorization,
    policy: CommitPolicy,
    title: String,
    branch: String,
    base: Baseline,
    expected_parent: CommitSha,
    expected_tree: Option<TreeSha>,
    targets: Vec<CommitTarget>,
    tracked: Vec<VerifiedPath>,
    evidence: Vec<EvidenceId>,
    pre_hook: PreHookState,
    timeout_seconds: u64,
}

impl TaskCommitRequest {
    /// Creates one finalization request.
    ///
    /// The commit budget is the shorter of the approved 30 seconds and the
    /// remaining Task seconds. A `required` Task must name at least one target;
    /// a `no_change` Task must name none and must carry evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
        expected_revision: ExecutionRevision,
        approval: CommitAuthorization,
        policy: CommitPolicy,
        title: impl Into<String>,
        branch: impl Into<String>,
        base: Baseline,
        expected_parent: CommitSha,
        expected_tree: Option<TreeSha>,
        targets: Vec<CommitTarget>,
        tracked: Vec<VerifiedPath>,
        evidence: Vec<EvidenceId>,
        pre_hook: PreHookState,
        remaining_seconds: u64,
    ) -> Result<Self, SddExecutionError> {
        let project = execution_id.project_id();
        task.ensure_project(project)?;
        request_id.validate_in(project)?;
        let title = title.into();
        if title.trim().is_empty() || title.contains('\n') || title.contains('\r') {
            return Err(SddExecutionError::InvalidValue {
                field: "commit.title".to_owned(),
                detail: "must be non-empty single-line text".to_owned(),
            });
        }
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "commit.branch".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        let timeout_seconds = remaining_seconds.min(HOST_COMMIT_TIMEOUT_SECONDS);
        if timeout_seconds == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "commit.timeoutSeconds".to_owned(),
                detail: "the remaining Task time leaves no host commit budget".to_owned(),
            });
        }
        let mut ordered = targets;
        ordered.sort_by(|left, right| left.path.cmp(&right.path));
        if ordered.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(SddExecutionError::InvalidValue {
                field: "commit.targets".to_owned(),
                detail: "a target path must not be repeated".to_owned(),
            });
        }
        let mut tracked_paths: Vec<String> = Vec::with_capacity(tracked.len());
        for path in &tracked {
            if tracked_paths.iter().any(|seen| seen == path.path()) {
                return Err(SddExecutionError::InvalidValue {
                    field: "commit.tracked".to_owned(),
                    detail: "a tracked path must not be repeated".to_owned(),
                });
            }
            tracked_paths.push(path.path().to_owned());
        }
        match policy {
            CommitPolicy::Required => {
                if ordered.is_empty() {
                    return Err(SddExecutionError::InvalidValue {
                        field: "commit.targets".to_owned(),
                        detail: "a required Task must stage at least one approved path".to_owned(),
                    });
                }
            }
            CommitPolicy::NoChange => {
                if !ordered.is_empty() {
                    return Err(SddExecutionError::InvalidValue {
                        field: "commit.targets".to_owned(),
                        detail: "a no_change Task never creates a commit".to_owned(),
                    });
                }
                if evidence.is_empty() {
                    return Err(SddExecutionError::InvalidValue {
                        field: "commit.evidence".to_owned(),
                        detail: "a no_change Task needs evidence references".to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            task,
            execution_id,
            request_id,
            expected_revision,
            approval,
            policy,
            title,
            branch,
            base,
            expected_parent,
            expected_tree,
            targets: ordered,
            tracked,
            evidence,
            pre_hook,
            timeout_seconds,
        })
    }

    /// The Task being finalized.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Idempotent commit request.
    pub const fn request_id(&self) -> CommitRequestId {
        self.request_id
    }

    /// Execution revision the intent records.
    pub const fn expected_revision(&self) -> ExecutionRevision {
        self.expected_revision
    }

    /// The approved host commit and hook authorization.
    pub const fn approval(&self) -> CommitAuthorization {
        self.approval
    }

    /// Approved commit policy.
    pub const fn policy(&self) -> CommitPolicy {
        self.policy
    }

    /// Explicitly staged paths, in path order.
    pub fn targets(&self) -> &[CommitTarget] {
        &self.targets
    }

    /// Paths whose verified content must not move.
    pub fn tracked(&self) -> &[VerifiedPath] {
        &self.tracked
    }

    /// Commit budget actually used, in seconds.
    pub const fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// The recorded intent of this request.
    pub fn intent(&self) -> Result<GitCommitIntent, SddExecutionError> {
        let mut paths = Vec::with_capacity(self.targets.len());
        for target in &self.targets {
            paths.push(target.staged_path()?);
        }
        let message = CommitMessage::new(
            self.task,
            &self.title,
            self.execution_id,
            self.request_id,
            Vec::new(),
        )?;
        GitCommitIntent::new(
            self.task,
            self.branch.clone(),
            self.base.clone(),
            self.expected_parent.clone(),
            self.expected_tree.clone(),
            paths,
            message,
            self.pre_hook.clone(),
            self.timeout_seconds,
        )
    }

    /// The journal entry that must be durable before the side effect.
    pub fn journal_intent(&self) -> Result<GitJournalEntry, SddExecutionError> {
        let identity = RequestIdentity::new(
            self.task.project_id(),
            self.execution_id,
            self.request_id,
            self.expected_revision,
        )?;
        GitJournalEntry::new(identity, self.intent()?)
    }

    /// The observation this request needs after the side effect.
    pub fn observation_request(&self) -> ObservationRequest {
        let mut paths: Vec<String> = self
            .targets
            .iter()
            .map(|target| target.path.clone())
            .collect();
        for tracked in &self.tracked {
            if !paths.iter().any(|path| path == tracked.path()) {
                paths.push(tracked.path.clone());
            }
        }
        paths.sort();
        ObservationRequest {
            project_id: self.task.project_id(),
            branch: self.branch.clone(),
            paths,
        }
    }
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

/// The checkout state one finalization or one recovery comparison reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRequest {
    project_id: ProjectId,
    branch: String,
    paths: Vec<String>,
}

impl ObservationRequest {
    /// Creates one read-only observation request.
    ///
    /// The recovery path uses it for a saved intent whose original request is
    /// gone: it names the same project, branch, and explicit paths.
    pub fn new(
        project_id: ProjectId,
        branch: impl Into<String>,
        mut paths: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "observation.branch".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        for path in &paths {
            validate_project_path("observation.path", path)?;
        }
        paths.sort();
        paths.dedup();
        Ok(Self {
            project_id,
            branch,
            paths,
        })
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Implementation branch the checkout must be on.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Paths whose exact bytes are read.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }
}

/// One observed path with its exact content digest, or `None` when absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPath {
    path: String,
    digest: Option<Sha256Digest>,
}

impl ObservedPath {
    /// Records one observed path.
    pub fn new(path: impl Into<String>, digest: Option<Sha256Digest>) -> Self {
        Self {
            path: path.into(),
            digest,
        }
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Digest of the current bytes, or `None` when the path is absent.
    pub fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }
}

/// The read-only checkout state one observation returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitObservation {
    project_id: ProjectId,
    branch: Option<String>,
    head: Option<CommitSha>,
    head_tree: Option<TreeSha>,
    head_parent: Option<CommitSha>,
    head_message: String,
    index_clean: bool,
    staged_paths: Vec<String>,
    tracked: Vec<ObservedPath>,
}

impl CommitObservation {
    /// Records one observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        branch: Option<String>,
        head: Option<CommitSha>,
        head_tree: Option<TreeSha>,
        head_parent: Option<CommitSha>,
        head_message: impl Into<String>,
        index_clean: bool,
        staged_paths: Vec<String>,
        tracked: Vec<ObservedPath>,
    ) -> Self {
        Self {
            project_id,
            branch,
            head,
            head_tree,
            head_parent,
            head_message: head_message.into(),
            index_clean,
            staged_paths,
            tracked,
        }
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Observed branch, or `None` for a detached HEAD.
    pub fn branch(&self) -> Option<&str> {
        self.branch.as_deref()
    }

    /// Observed HEAD commit, or `None` for an unborn branch.
    pub fn head(&self) -> Option<&CommitSha> {
        self.head.as_ref()
    }

    /// Tree of the observed HEAD.
    pub fn head_tree(&self) -> Option<&TreeSha> {
        self.head_tree.as_ref()
    }

    /// First parent of the observed HEAD.
    pub fn head_parent(&self) -> Option<&CommitSha> {
        self.head_parent.as_ref()
    }

    /// Full commit message of the observed HEAD.
    pub fn head_message(&self) -> &str {
        &self.head_message
    }

    /// Whether the index holds no staged change.
    pub const fn index_clean(&self) -> bool {
        self.index_clean
    }

    /// Paths still staged in the index.
    pub fn staged_paths(&self) -> &[String] {
        &self.staged_paths
    }

    /// Observed tracked paths.
    pub fn tracked(&self) -> &[ObservedPath] {
        &self.tracked
    }

    /// The observed entry for one path.
    pub fn path(&self, path: &str) -> Option<&ObservedPath> {
        self.tracked.iter().find(|entry| entry.path == path)
    }

    /// The observed digest of one path. The outer `None` means the observation
    /// does not cover the path; the inner `None` means it is absent.
    pub fn digest_of(&self, path: &str) -> Option<Option<&Sha256Digest>> {
        self.path(path).map(ObservedPath::digest)
    }

    fn carries_trailers(&self, intent: &GitCommitIntent) -> bool {
        intent
            .message()
            .trailers()
            .iter()
            .all(|trailer| self.has_trailer(trailer.key(), trailer.value()))
    }

    fn has_trailer(&self, key: &str, value: &str) -> bool {
        let expected = format!("{key}: {value}");
        self.head_message
            .lines()
            .any(|line| line.trim_end() == expected)
    }
}

/// Reads the checkout without changing it.
///
/// The production adapter is the desktop Git runner: one fixed argv for HEAD,
/// tree, parent, message, index, and one confined read per tracked path. It
/// never stages, commits, or runs a hook.
pub trait CommitObservationPort {
    /// Reads the current branch, HEAD, index, and the requested path bytes.
    fn observe(
        &mut self,
        request: &ObservationRequest,
    ) -> Result<CommitObservation, SddExecutionError>;
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Why one Task did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeStop {
    /// Git refused before creating a commit.
    Rejected(GitRejection),
    /// The verified bytes moved, so linked evidence is no longer valid.
    EvidenceChanged {
        /// Non-secret paths that moved.
        paths: Vec<String>,
    },
    /// The commit result cannot be determined; a human reconciles it.
    ResultUnknown(GitUnknownReason),
}

impl FinalizeStop {
    /// The durable stop this hold becomes.
    pub fn stop(&self) -> Result<StopRecord, SddExecutionError> {
        match self {
            Self::Rejected(reason) => match reason {
                GitRejection::UnrelatedChanges | GitRejection::ConcurrentEdit => {
                    StopRecord::new(StopReason::Conflict, Some(HumanAction::ResolveConflict))
                }
                GitRejection::HookFailed
                | GitRejection::MessageRejected
                | GitRejection::StagingFailed => StopRecord::new(
                    StopReason::HumanDecisionRequired,
                    Some(HumanAction::ResolveHumanDecision),
                ),
                GitRejection::StoppedBeforeSideEffect => {
                    StopRecord::new(StopReason::PauseRequested, Some(HumanAction::ConfirmStop))
                }
            },
            Self::EvidenceChanged { .. } => StopRecord::new(
                StopReason::RecoveryRequired,
                Some(HumanAction::ConfirmRecovery),
            ),
            Self::ResultUnknown(_) => StopRecord::new(
                StopReason::GitResultUnknown,
                Some(HumanAction::ConfirmGitRecovery),
            ),
        }
    }

    /// Whether a commit object may exist.
    pub const fn may_have_committed(&self) -> bool {
        matches!(self, Self::ResultUnknown(_))
    }
}

/// The result of one Task finalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskFinalizeOutcome {
    /// HEAD advanced to the approved commit.
    Committed {
        /// `BASE..commit` range.
        range: CommitRange,
        /// The recorded journal entry.
        journal: GitJournalEntry,
    },
    /// The Task changed no approved source content, so no commit was created.
    NoChange {
        /// The recorded unchanged-source evidence.
        record: NoChangeRecord,
    },
    /// The Task did not complete; a human decides, and nothing is retried.
    Held {
        /// Why the Task is held.
        stop: FinalizeStop,
        /// The journal entry, when one was written.
        journal: Option<GitJournalEntry>,
    },
}

impl TaskFinalizeOutcome {
    /// The commit range, when HEAD advanced.
    pub const fn range(&self) -> Option<&CommitRange> {
        match self {
            Self::Committed { range, .. } => Some(range),
            _ => None,
        }
    }

    /// The no-change record, when the Task changed nothing.
    pub const fn no_change(&self) -> Option<&NoChangeRecord> {
        match self {
            Self::NoChange { record } => Some(record),
            _ => None,
        }
    }

    /// The journal entry, when one exists.
    pub const fn journal(&self) -> Option<&GitJournalEntry> {
        match self {
            Self::Committed { journal, .. } => Some(journal),
            Self::Held { journal, .. } => journal.as_ref(),
            Self::NoChange { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

/// The ports one finalization uses.
pub struct FinalizePorts<'a> {
    /// The approved host stage/hook/commit boundary.
    pub git: &'a mut dyn HostGitPort,
    /// Durable Git journal.
    pub store: &'a mut dyn ExecutionStorePort,
    /// Read-only checkout observation.
    pub checkout: &'a mut dyn CommitObservationPort,
}

/// Finalizes one Task: fixes the target, records the intent, commits, and
/// re-reads the result.
///
/// The call is idempotent for one commit request: a recorded result is returned
/// as stored, and a recorded intent without a result is reported as unknown
/// instead of being committed again.
pub fn finalize_task(
    ports: &mut FinalizePorts<'_>,
    request: &TaskCommitRequest,
) -> Result<TaskFinalizeOutcome, SddExecutionError> {
    match request.policy {
        CommitPolicy::Required => finalize_required(ports, request),
        CommitPolicy::NoChange => finalize_no_change(ports, request),
    }
}

fn finalize_required(
    ports: &mut FinalizePorts<'_>,
    request: &TaskCommitRequest,
) -> Result<TaskFinalizeOutcome, SddExecutionError> {
    let intent = request.journal_intent()?;
    let identity = *intent.identity();
    let project = identity.project_id();
    let execution = identity.execution_id();

    // A recorded request is never repeated. A duplicate returns the stored
    // result; a recorded intent without a result may already have produced a
    // commit, so it waits for a human instead of being retried.
    if let Some(stored) = ports
        .store
        .commit_entry(project, execution, request.request_id)?
    {
        if stored.fingerprint() != intent.fingerprint() {
            return Err(SddExecutionError::DuplicateRequestConflict {
                recorded: stored.fingerprint().to_string(),
                supplied: intent.fingerprint().to_string(),
            });
        }
        return match stored.outcome() {
            Some(outcome) => settle_recorded(ports, request, &stored, outcome.clone()),
            None => Ok(held(
                FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
                Some(stored),
            )),
        };
    }

    // The intent is durable before the first Git side effect. A failure here
    // starts no Git process at all.
    ports.store.record_git(&intent)?;

    let outcome = match ports.git.commit(&intent, request.approval) {
        Ok(outcome) => outcome,
        Err(_) => {
            // The port could not report what happened. The recorded intent stays
            // and a human reconciles; nothing is retried.
            let unknown = intent
                .clone()
                .mark_result_unknown(GitUnknownReason::UnobservedProcess);
            let recorded = record_if_possible(ports.store, &unknown);
            return Ok(held(
                FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
                recorded,
            ));
        }
    };
    let recorded_entry = intent.clone().record(outcome.clone());
    if ports.store.record_git(&recorded_entry).is_err() {
        // Git succeeded (or may have) and the durable result could not be
        // stored. This is an explicit unknown, never a rollback and never a
        // second attempt.
        return Ok(held(
            FinalizeStop::ResultUnknown(GitUnknownReason::JournalWriteFailed),
            Some(intent),
        ));
    }
    settle_recorded(ports, request, &recorded_entry, outcome)
}

fn settle_recorded(
    ports: &mut FinalizePorts<'_>,
    request: &TaskCommitRequest,
    journal: &GitJournalEntry,
    outcome: GitCommitOutcome,
) -> Result<TaskFinalizeOutcome, SddExecutionError> {
    match outcome {
        GitCommitOutcome::Committed {
            commit,
            tree,
            parent,
        } => settle_committed(ports, request, journal, commit, tree, parent),
        GitCommitOutcome::Rejected { reason } => {
            Ok(held(FinalizeStop::Rejected(reason), Some(journal.clone())))
        }
        GitCommitOutcome::Unknown { reason } => Ok(held(
            FinalizeStop::ResultUnknown(reason),
            Some(journal.clone()),
        )),
    }
}

fn settle_committed(
    ports: &mut FinalizePorts<'_>,
    request: &TaskCommitRequest,
    journal: &GitJournalEntry,
    commit: CommitSha,
    tree: TreeSha,
    parent: CommitSha,
) -> Result<TaskFinalizeOutcome, SddExecutionError> {
    if parent != request.expected_parent {
        return Ok(held(
            FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
            Some(journal.clone()),
        ));
    }
    if let Some(expected) = &request.expected_tree
        && *expected != tree
    {
        return Ok(held(
            FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
            Some(journal.clone()),
        ));
    }
    if commit.as_str() == request.base.as_str() {
        // A required Task must advance HEAD from BASE.
        return Ok(held(
            FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
            Some(journal.clone()),
        ));
    }

    // Re-read HEAD, tree, parent, trailers, the index, and the tracked bytes.
    // A read failure leaves the commit unconfirmed.
    let observation = match ports.checkout.observe(&request.observation_request()) {
        Ok(observation) => observation,
        Err(_) => {
            return Ok(held(
                FinalizeStop::ResultUnknown(GitUnknownReason::HeadUnreadable),
                Some(journal.clone()),
            ));
        }
    };
    match classify_commit(journal.intent(), &observation) {
        CommitRecovery::Established {
            commit: observed, ..
        } if observed == commit => {}
        _ => {
            return Ok(held(
                FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
                Some(journal.clone()),
            ));
        }
    }
    let moved = moved_paths(&observation, &request.tracked);
    if !moved.is_empty() {
        return Ok(held(
            FinalizeStop::EvidenceChanged { paths: moved },
            Some(journal.clone()),
        ));
    }
    let range = CommitRange::new(request.base.clone(), commit)?;
    Ok(TaskFinalizeOutcome::Committed {
        range,
        journal: journal.clone(),
    })
}

fn finalize_no_change(
    ports: &mut FinalizePorts<'_>,
    request: &TaskCommitRequest,
) -> Result<TaskFinalizeOutcome, SddExecutionError> {
    // A no_change Task creates no commit at all, so no Git journal is written.
    let observation = ports.checkout.observe(&request.observation_request())?;
    if observation.head() != Some(&request.expected_parent) {
        return Ok(held(
            FinalizeStop::ResultUnknown(GitUnknownReason::UnobservedProcess),
            None,
        ));
    }
    if !observation.index_clean() {
        return Ok(held(
            FinalizeStop::Rejected(GitRejection::UnrelatedChanges),
            None,
        ));
    }
    let moved = moved_paths(&observation, &request.tracked);
    if !moved.is_empty() {
        return Ok(held(FinalizeStop::EvidenceChanged { paths: moved }, None));
    }
    let record = NoChangeRecord::new(true, request.evidence.clone(), None)?;
    Ok(TaskFinalizeOutcome::NoChange { record })
}

/// Every tracked path whose bytes are not the verified bytes.
fn moved_paths(observation: &CommitObservation, tracked: &[VerifiedPath]) -> Vec<String> {
    let mut moved = Vec::new();
    for path in tracked {
        let observed = observation.digest_of(path.path()).flatten();
        let matches = match (path.digest(), observed) {
            (Some(expected), Some(observed)) => expected == observed,
            (None, None) => true,
            _ => false,
        };
        if !matches {
            moved.push(path.path().to_owned());
        }
    }
    moved
}

fn held(stop: FinalizeStop, journal: Option<GitJournalEntry>) -> TaskFinalizeOutcome {
    TaskFinalizeOutcome::Held { stop, journal }
}

fn record_if_possible(
    store: &mut dyn ExecutionStorePort,
    entry: &GitJournalEntry,
) -> Option<GitJournalEntry> {
    if store.record_git(entry).is_ok() {
        Some(entry.clone())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Recovery classification
// ---------------------------------------------------------------------------

/// What the checkout shows for one saved commit intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRecovery {
    /// The commit exists with the intended parent, tree, trailers, and content,
    /// and the index is clean. It is linked only after a human confirms.
    Established {
        /// Commit object name.
        commit: CommitSha,
        /// Resulting tree.
        tree: TreeSha,
        /// Parent the commit was created on.
        parent: CommitSha,
        /// `BASE..commit` range.
        range: CommitRange,
    },
    /// HEAD is still the expected parent, so no commit was created. The index
    /// may hold leftovers for a human to clean; nothing is reset here.
    NotRun,
    /// The checkout does not match the saved intent; a human reconciles.
    Unknown {
        /// Non-secret explanation.
        detail: String,
    },
}

/// Classifies one saved intent against the current checkout.
///
/// The comparison uses only the saved intent (`branch`, expected parent,
/// expected tree, the three required trailers, explicit paths with digests) and
/// the current observation. It mutates nothing: no reset, no re-commit, and no
/// journal write. A commit is `Established` only when every saved value matches
/// and the index is clean; otherwise a moved HEAD is `Unknown` and an unmoved
/// HEAD is `NotRun`.
///
/// The expected tree is asserted only when the intent recorded one. Staging is
/// the side effect the intent precedes, so a caller that cannot compute the tree
/// without staging records it as absent; [`classify_recorded`] then compares the
/// observed commit against the recorded result.
pub fn classify_commit(
    intent: &GitCommitIntent,
    observation: &CommitObservation,
) -> CommitRecovery {
    let head = match observation.head() {
        Some(head) => head,
        None => {
            return CommitRecovery::Unknown {
                detail: "the checkout has no commit at HEAD".to_owned(),
            };
        }
    };
    if *head == *intent.expected_parent() {
        return CommitRecovery::NotRun;
    }
    if observation.branch() != Some(intent.branch()) {
        return CommitRecovery::Unknown {
            detail: format!(
                "the checkout is not on the saved branch {}",
                intent.branch()
            ),
        };
    }
    if observation.head_parent() != Some(intent.expected_parent()) {
        return CommitRecovery::Unknown {
            detail: "HEAD is not the saved commit's direct child".to_owned(),
        };
    }
    if let Some(expected) = intent.expected_tree()
        && observation.head_tree() != Some(expected)
    {
        return CommitRecovery::Unknown {
            detail: "HEAD tree is not the expected tree".to_owned(),
        };
    }
    if !observation.carries_trailers(intent) {
        return CommitRecovery::Unknown {
            detail: "HEAD does not carry the saved trailers".to_owned(),
        };
    }
    if !observation.index_clean() {
        return CommitRecovery::Unknown {
            detail: "the index is not clean after the saved commit".to_owned(),
        };
    }
    for path in intent.paths() {
        let Some(expected) = path.digest() else {
            return CommitRecovery::Unknown {
                detail: format!("{} was saved without a digest", path.path()),
            };
        };
        let observed = observation.digest_of(path.path()).flatten();
        if observed != Some(expected) {
            return CommitRecovery::Unknown {
                detail: format!("{} does not carry the saved content", path.path()),
            };
        }
    }
    match CommitRange::new(intent.base().clone(), head.clone()) {
        Ok(range) => CommitRecovery::Established {
            commit: head.clone(),
            tree: observation
                .head_tree()
                .cloned()
                .unwrap_or_else(|| TreeSha::parse("0".repeat(40)).expect("a zero tree name")),
            parent: intent.expected_parent().clone(),
            range,
        },
        Err(_) => CommitRecovery::Unknown {
            detail: "the saved commit does not advance HEAD from BASE".to_owned(),
        },
    }
}

/// Classifies one saved intent and its recorded outcome against the checkout.
///
/// This is the Task 20 comparison. When the journal recorded a commit, the
/// observed commit, tree, and parent must equal the recorded ones, so a checkout
/// that moved to a *different* commit carrying the same trailers is `Unknown`
/// instead of `Established`.
pub fn classify_recorded(
    intent: &GitCommitIntent,
    recorded: Option<&GitCommitOutcome>,
    observation: &CommitObservation,
) -> CommitRecovery {
    let classified = classify_commit(intent, observation);
    let (
        Some(GitCommitOutcome::Committed {
            commit,
            tree,
            parent,
        }),
        CommitRecovery::Established {
            commit: observed_commit,
            tree: observed_tree,
            parent: observed_parent,
            ..
        },
    ) = (recorded, &classified)
    else {
        return classified;
    };
    if commit != observed_commit || tree != observed_tree || parent != observed_parent {
        return CommitRecovery::Unknown {
            detail: "the observed commit does not match the recorded result".to_owned(),
        };
    }
    classified
}

// ---------------------------------------------------------------------------
// Deterministic request identity
// ---------------------------------------------------------------------------

/// The deterministic commit request of one Task at one parent.
///
/// The same execution, Task, and expected parent always yield the same request,
/// so a crash between the recorded intent and the recorded result re-uses the
/// stored journal instead of creating a second commit.
pub fn commit_request_id(
    execution: ExecutionId,
    task: TaskRef,
    expected_parent: &CommitSha,
) -> CommitRequestId {
    commit_request_id_with_attempt(execution, task, expected_parent, 1)
}

/// The deterministic commit request of one explicit attempt.
///
/// An attempt greater than one is used only after a human resolved a recorded
/// refusal of the same Task at the same parent; it is never chosen
/// automatically.
pub fn commit_request_id_with_attempt(
    execution: ExecutionId,
    task: TaskRef,
    expected_parent: &CommitSha,
    attempt: u32,
) -> CommitRequestId {
    let mut hasher = Sha256::new();
    hasher.update(b"h4.task.commit\0");
    hasher.update(execution.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(task.stable_id().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(expected_parent.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(attempt.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    CommitRequestId::from_parts(execution.project_id(), Uuid::from_bytes(bytes))
}
