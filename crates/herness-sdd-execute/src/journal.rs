//! Dispatch, Git, progress, and control journals with request idempotency.
//!
//! Every update request carries the project, execution ID, request ID, and the
//! execution revision it expects. A duplicate request returns the stored
//! result, the same request ID with different content is refused, and a stale
//! revision is refused before any side effect. The decision order matters: a
//! re-delivered request whose revision is now stale still returns its stored
//! result instead of creating a second child or commit.

use herness_core::contracts::ProjectId;
use herness_supervision::SupervisionId;
use serde::{Deserialize, Serialize};

use crate::error::SddExecutionError;
use crate::ids::{
    Baseline, ChildIdentity, CommitRequestId, CommitSha, ExecutionId, ExecutionKeyKind,
    ExecutionRevision, ExecutionScopedId, PlanRevision, ProjectSequence, TaskRef, TreeSha,
};
use crate::plan::validate_project_path;
use crate::snapshot::CommitRange;
use crate::state::GitUnknownReason;
use crate::version::{HOST_COMMIT_TIMEOUT_SECONDS, RequestFingerprint, Sha256Digest};

/// Project, execution, request ID, and expected revision of one update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, bound = "")]
pub struct RequestIdentity<K: ExecutionKeyKind> {
    project_id: ProjectId,
    execution_id: ExecutionId,
    request_id: ExecutionScopedId<K>,
    expected_revision: ExecutionRevision,
}

impl<K: ExecutionKeyKind> RequestIdentity<K> {
    /// Creates a mandatory request guard.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ExecutionScopedId<K>,
        expected_revision: ExecutionRevision,
    ) -> Result<Self, SddExecutionError> {
        execution_id.validate_in(project_id)?;
        request_id.validate_in(project_id)?;
        Ok(Self {
            project_id,
            execution_id,
            request_id,
            expected_revision,
        })
    }

    /// Project that owns the request.
    pub const fn project_id(self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    /// Idempotent request identity.
    pub const fn request_id(self) -> ExecutionScopedId<K> {
        self.request_id
    }

    /// Execution revision the caller expects.
    pub const fn expected_revision(self) -> ExecutionRevision {
        self.expected_revision
    }

    /// Rejects a guard from another project.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SddExecutionError> {
        self.execution_id.validate_in(project)?;
        self.request_id.validate_in(project)
    }
}

/// Content that an idempotent request fingerprint binds.
pub trait JournalContent {
    /// Stable fingerprint of the content.
    fn content_fingerprint(&self) -> Result<RequestFingerprint, SddExecutionError>;
}

fn fingerprint_of<T: Serialize>(value: &T) -> Result<RequestFingerprint, SddExecutionError> {
    let bytes = serde_json::to_vec(value).map_err(|error| SddExecutionError::InvalidValue {
        field: "request.content".to_owned(),
        detail: format!("could not encode the request content: {error}"),
    })?;
    Ok(RequestFingerprint::sha256(&bytes))
}

/// Durable state of one journal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalEntryState {
    /// The intent is recorded; the side effect has not started.
    Intent,
    /// The result is recorded.
    Recorded,
}

/// The decision for one incoming update request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestDecision<O> {
    /// No record exists and the revision is current; perform the side effect.
    Proceed,
    /// The same request ID and content are already recorded; return the stored
    /// result.
    Duplicate {
        /// Stored outcome. It is `None` when only the intent was recorded and
        /// the effect must be reconciled instead of repeated.
        outcome: Option<O>,
    },
    /// The same request ID carries different content.
    ContentConflict {
        /// Fingerprint already recorded for the request ID.
        recorded: RequestFingerprint,
        /// Fingerprint supplied by the caller.
        supplied: RequestFingerprint,
    },
    /// The request ID is new but the expected revision is stale.
    StaleRevision {
        /// Revision the caller expected.
        expected: ExecutionRevision,
        /// Revision currently stored.
        found: ExecutionRevision,
    },
}

impl<O> RequestDecision<O> {
    /// Whether the caller may perform the side effect.
    pub const fn is_proceed(&self) -> bool {
        matches!(self, Self::Proceed)
    }

    /// The stored duplicate outcome, when this is a duplicate.
    pub fn duplicate_outcome(&self) -> Option<&O> {
        match self {
            Self::Duplicate { outcome } => outcome.as_ref(),
            _ => None,
        }
    }

    /// The typed refusal for this decision, before any side effect.
    ///
    /// A duplicate with a stored outcome is not a refusal: the caller returns
    /// the stored result. A duplicate that recorded only an intent, a content
    /// conflict, and a stale revision are refusals.
    pub fn refusal(&self, request: &str) -> Option<SddExecutionError> {
        match self {
            Self::Proceed => None,
            Self::Duplicate { outcome: Some(_) } => None,
            Self::Duplicate { outcome: None } => Some(SddExecutionError::DuplicateResultConflict {
                request: request.to_owned(),
            }),
            Self::ContentConflict { recorded, supplied } => {
                Some(SddExecutionError::DuplicateRequestConflict {
                    recorded: recorded.to_string(),
                    supplied: supplied.to_string(),
                })
            }
            Self::StaleRevision { expected, found } => Some(SddExecutionError::RevisionConflict {
                expected: *expected,
                found: *found,
            }),
        }
    }
}

/// One durable request record with its content fingerprint and stored outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    bound(
        serialize = "K: ExecutionKeyKind, O: Serialize",
        deserialize = "K: ExecutionKeyKind, O: Deserialize<'de>"
    )
)]
pub struct RequestRecord<K: ExecutionKeyKind, O> {
    identity: RequestIdentity<K>,
    fingerprint: RequestFingerprint,
    state: JournalEntryState,
    #[serde(default)]
    outcome: Option<O>,
}

impl<K: ExecutionKeyKind, O> RequestRecord<K, O> {
    /// Records an intent and its content fingerprint before any side effect.
    pub fn intent(
        identity: RequestIdentity<K>,
        content: &impl JournalContent,
    ) -> Result<Self, SddExecutionError> {
        Ok(Self {
            identity,
            fingerprint: content.content_fingerprint()?,
            state: JournalEntryState::Intent,
            outcome: None,
        })
    }

    /// Returns a recorded copy with one outcome.
    pub fn recorded(mut self, outcome: O) -> Self {
        self.state = JournalEntryState::Recorded;
        self.outcome = Some(outcome);
        self
    }

    /// Mandatory request guard.
    pub const fn identity(&self) -> &RequestIdentity<K> {
        &self.identity
    }

    /// Content fingerprint.
    pub fn fingerprint(&self) -> &RequestFingerprint {
        &self.fingerprint
    }

    /// Durable record state.
    pub const fn state(&self) -> JournalEntryState {
        self.state
    }

    /// Stored outcome.
    pub const fn outcome(&self) -> Option<&O> {
        self.outcome.as_ref()
    }
}

/// Decides one incoming update request against the stored record.
///
/// Duplicate detection runs before the stale-revision check so re-delivering a
/// start or commit request cannot create a second child or commit. A new
/// request ID with a stale revision is refused before any side effect.
pub fn decide_request<K, O>(
    stored: Option<&RequestRecord<K, O>>,
    incoming: &RequestIdentity<K>,
    content: &impl JournalContent,
    current_revision: ExecutionRevision,
) -> Result<RequestDecision<O>, SddExecutionError>
where
    K: ExecutionKeyKind,
    O: Clone,
{
    if let Some(record) = stored {
        if record.identity.project_id != incoming.project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "request record".to_owned(),
                expected: incoming.project_id,
                found: record.identity.project_id,
            });
        }
        if record.identity.execution_id != incoming.execution_id {
            return Err(SddExecutionError::InvalidValue {
                field: "requestId".to_owned(),
                detail: "the request ID is already recorded for another execution".to_owned(),
            });
        }
        if record.identity.request_id != incoming.request_id {
            return Err(SddExecutionError::InvalidValue {
                field: "requestId".to_owned(),
                detail: "the looked-up record carries a different request ID".to_owned(),
            });
        }
        let supplied = content.content_fingerprint()?;
        if supplied == record.fingerprint {
            return Ok(RequestDecision::Duplicate {
                outcome: record.outcome.clone(),
            });
        }
        return Ok(RequestDecision::ContentConflict {
            recorded: record.fingerprint.clone(),
            supplied,
        });
    }
    if incoming.expected_revision != current_revision {
        return Ok(RequestDecision::StaleRevision {
            expected: incoming.expected_revision,
            found: current_revision,
        });
    }
    Ok(RequestDecision::Proceed)
}

/// Inputs and scope manifest digest bound to one dispatch intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchContent {
    task: TaskRef,
    approved_plan_revision: PlanRevision,
    baseline: Baseline,
    manifest_digest: Sha256Digest,
    packet_digest: Sha256Digest,
}

impl DispatchContent {
    /// Creates dispatch content. The packet and manifest digests bind the exact
    /// context handed to the child.
    pub fn new(
        task: TaskRef,
        approved_plan_revision: PlanRevision,
        baseline: Baseline,
        manifest_digest: Sha256Digest,
        packet_digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        Ok(Self {
            task,
            approved_plan_revision,
            baseline,
            manifest_digest,
            packet_digest,
        })
    }

    /// Task to dispatch.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Approved plan revision.
    pub const fn approved_plan_revision(&self) -> PlanRevision {
        self.approved_plan_revision
    }

    /// Fixed baseline.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Input and scope manifest digest.
    pub fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    /// Immutable Task packet digest.
    pub fn packet_digest(&self) -> &Sha256Digest {
        &self.packet_digest
    }
}

impl JournalContent for DispatchContent {
    fn content_fingerprint(&self) -> Result<RequestFingerprint, SddExecutionError> {
        fingerprint_of(self)
    }
}

/// One dispatch request with its mandatory guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchRequest {
    identity: RequestIdentity<crate::ids::DispatchKind>,
    content: DispatchContent,
}

impl DispatchRequest {
    /// Creates a dispatch request.
    pub fn new(
        identity: RequestIdentity<crate::ids::DispatchKind>,
        content: DispatchContent,
    ) -> Result<Self, SddExecutionError> {
        if identity.request_id().project_id() != content.task.project_id()
            || identity.project_id() != content.task.project_id()
        {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "dispatch request".to_owned(),
                expected: identity.project_id(),
                found: content.task.project_id(),
            });
        }
        Ok(Self { identity, content })
    }

    /// Request guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::DispatchKind> {
        &self.identity
    }

    /// Dispatch content.
    pub const fn content(&self) -> &DispatchContent {
        &self.content
    }
}

/// The stored result of one dispatch. The child and H2 references are created
/// once; a duplicate request returns this value instead of a second child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchResult {
    supervision_id: SupervisionId,
    child: ChildIdentity,
}

impl DispatchResult {
    /// Records the created H2 target and child.
    pub fn new(
        supervision_id: SupervisionId,
        child: ChildIdentity,
    ) -> Result<Self, SddExecutionError> {
        let project = supervision_id.project_id();
        if child.agent_id().project_id() != project {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "dispatch result".to_owned(),
                expected: project,
                found: child.agent_id().project_id(),
            });
        }
        Ok(Self {
            supervision_id,
            child,
        })
    }

    /// H2 supervision target.
    pub const fn supervision_id(self) -> SupervisionId {
        self.supervision_id
    }

    /// H1 child and session.
    pub const fn child(self) -> ChildIdentity {
        self.child
    }
}

/// Durable dispatch journal record.
pub type DispatchJournalEntry = RequestRecord<crate::ids::DispatchKind, DispatchResult>;

/// One explicitly staged path with its byte length and optional digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommittedPath {
    path: String,
    bytes: u64,
    #[serde(default)]
    digest: Option<Sha256Digest>,
}

impl CommittedPath {
    /// Creates a staged path entry. Only explicit paths are staged; a wildcard
    /// stage is never represented.
    pub fn new(
        path: impl Into<String>,
        bytes: u64,
        digest: Option<Sha256Digest>,
    ) -> Result<Self, SddExecutionError> {
        let path = path.into();
        validate_project_path("commit.path", &path)?;
        Ok(Self {
            path,
            bytes,
            digest,
        })
    }

    /// Project-relative path passed to `git add` as one argv entry.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Byte length of the staged content.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Optional content digest.
    pub fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }
}

/// One commit trailer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitTrailer {
    key: String,
    value: String,
}

impl CommitTrailer {
    /// Creates a trailer.
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let key = key.into();
        let value = value.into();
        if key.trim().is_empty() || key.contains(':') || key.chars().any(char::is_whitespace) {
            return Err(invalid("commit.trailer.key", "must be one non-empty token"));
        }
        if value.trim().is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(invalid(
                "commit.trailer.value",
                "must be non-empty single-line text",
            ));
        }
        Ok(Self { key, value })
    }

    /// Trailer key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Trailer value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A commit message that always carries the execution, Task, and request
/// trailers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitMessage {
    subject: String,
    trailers: Vec<CommitTrailer>,
}

impl CommitMessage {
    /// Builds `Task N: title` and the required trailers.
    pub fn new(
        task: TaskRef,
        title: impl AsRef<str>,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
        extra: Vec<CommitTrailer>,
    ) -> Result<Self, SddExecutionError> {
        let title = title.as_ref().trim();
        if title.is_empty() || title.contains('\n') || title.contains('\r') {
            return Err(invalid(
                "commit.message",
                "the Task title must be single-line text",
            ));
        }
        let subject = format!("Task {}: {title}", task.number().get());
        let required = [
            CommitTrailer::new("Herness-Execution", execution_id.to_string())?,
            CommitTrailer::new("Herness-Task", task.number().get().to_string())?,
            CommitTrailer::new("Herness-Request", request_id.to_string())?,
        ];
        let mut trailers = required.to_vec();
        for trailer in extra {
            if trailers.iter().any(|existing| existing.key == trailer.key) {
                return Err(invalid(
                    "commit.trailer",
                    "a required trailer must not be repeated",
                ));
            }
            trailers.push(trailer);
        }
        Ok(Self { subject, trailers })
    }

    /// Subject line.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Every trailer, required first.
    pub fn trailers(&self) -> &[CommitTrailer] {
        &self.trailers
    }

    /// Finds one trailer.
    pub fn trailer(&self, key: &str) -> Option<&CommitTrailer> {
        self.trailers.iter().find(|trailer| trailer.key == key)
    }

    /// Rendered message with one blank line between subject and trailers.
    pub fn render(&self) -> String {
        let mut message = self.subject.clone();
        message.push_str("\n\n");
        for trailer in &self.trailers {
            message.push_str(&trailer.key);
            message.push_str(": ");
            message.push_str(&trailer.value);
            message.push('\n');
        }
        message
    }
}

/// Git index, hook configuration, and expected tree before the commit side
/// effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreHookState {
    index_clean: bool,
    staged_paths: Vec<String>,
    #[serde(default)]
    hooks_config_digest: Option<Sha256Digest>,
    #[serde(default)]
    expected_index_tree: Option<TreeSha>,
}

impl PreHookState {
    /// Records the state observed before staging and hooks.
    pub fn new(
        index_clean: bool,
        staged_paths: Vec<String>,
        hooks_config_digest: Option<Sha256Digest>,
        expected_index_tree: Option<TreeSha>,
    ) -> Result<Self, SddExecutionError> {
        if !index_clean {
            return Err(invalid(
                "commit.preHook.indexClean",
                "the index must be clean before the host stages explicit paths",
            ));
        }
        for path in &staged_paths {
            validate_project_path("commit.preHook.stagedPaths", path)?;
        }
        Ok(Self {
            index_clean,
            staged_paths,
            hooks_config_digest,
            expected_index_tree,
        })
    }

    /// Whether the index was clean.
    pub const fn index_clean(&self) -> bool {
        self.index_clean
    }

    /// Paths the host intends to stage.
    pub fn staged_paths(&self) -> &[String] {
        &self.staged_paths
    }

    /// Digest of the hook configuration that will run.
    pub fn hooks_config_digest(&self) -> Option<&Sha256Digest> {
        self.hooks_config_digest.as_ref()
    }

    /// Tree the index is expected to produce.
    pub fn expected_index_tree(&self) -> Option<&TreeSha> {
        self.expected_index_tree.as_ref()
    }
}

/// The complete intent recorded before the Git side effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitCommitIntent {
    task: TaskRef,
    branch: String,
    base: Baseline,
    expected_parent: CommitSha,
    #[serde(default)]
    expected_tree: Option<TreeSha>,
    paths: Vec<CommittedPath>,
    message: CommitMessage,
    pre_hook: PreHookState,
    timeout_seconds: u64,
}

impl GitCommitIntent {
    /// Creates a commit intent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        branch: impl Into<String>,
        base: Baseline,
        expected_parent: CommitSha,
        expected_tree: Option<TreeSha>,
        paths: Vec<CommittedPath>,
        message: CommitMessage,
        pre_hook: PreHookState,
        timeout_seconds: u64,
    ) -> Result<Self, SddExecutionError> {
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(invalid("commit.branch", "must not be empty"));
        }
        if paths.is_empty() {
            return Err(invalid(
                "commit.paths",
                "a required Task must stage at least one explicit path",
            ));
        }
        if timeout_seconds == 0 || timeout_seconds > HOST_COMMIT_TIMEOUT_SECONDS {
            return Err(invalid(
                "commit.timeoutSeconds",
                "must be greater than zero and at most the host commit budget",
            ));
        }
        Ok(Self {
            task,
            branch,
            base,
            expected_parent,
            expected_tree,
            paths,
            message,
            pre_hook,
            timeout_seconds,
        })
    }

    /// Committed Task.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Fixed baseline.
    pub fn base(&self) -> &Baseline {
        &self.base
    }

    /// Expected parent commit.
    pub fn expected_parent(&self) -> &CommitSha {
        &self.expected_parent
    }

    /// Expected resulting tree.
    pub fn expected_tree(&self) -> Option<&TreeSha> {
        self.expected_tree.as_ref()
    }

    /// Explicitly staged paths.
    pub fn paths(&self) -> &[CommittedPath] {
        &self.paths
    }

    /// Commit message and required trailers.
    pub fn message(&self) -> &CommitMessage {
        &self.message
    }

    /// State before hooks.
    pub fn pre_hook(&self) -> &PreHookState {
        &self.pre_hook
    }

    /// Commit budget in seconds.
    pub const fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

impl JournalContent for GitCommitIntent {
    fn content_fingerprint(&self) -> Result<RequestFingerprint, SddExecutionError> {
        fingerprint_of(self)
    }
}

/// Why the host refused or failed a commit without an unknown result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitRejection {
    /// The index or worktree held unrelated changes.
    UnrelatedChanges,
    /// Another process changed the index or HEAD first.
    ConcurrentEdit,
    /// A repository hook failed or changed the commit content.
    HookFailed,
    /// Staging an explicit path failed.
    StagingFailed,
    /// The commit message or trailers were rejected.
    MessageRejected,
    /// A stop was confirmed before the side effect.
    StoppedBeforeSideEffect,
}

/// The observed result of one host commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum GitCommitOutcome {
    /// The commit was created and observed.
    Committed {
        /// Commit object name.
        commit: CommitSha,
        /// Resulting tree.
        tree: TreeSha,
        /// Parent observed.
        parent: CommitSha,
    },
    /// The commit was refused before a side effect, or a hook failed.
    Rejected {
        /// Why the commit did not happen.
        reason: GitRejection,
    },
    /// The result cannot be determined and must be reconciled by a human.
    Unknown {
        /// Why the result is unknown.
        reason: GitUnknownReason,
    },
}

impl GitCommitOutcome {
    /// Whether a commit object may exist. An unknown result also may.
    pub const fn may_exist(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Unknown { .. })
    }

    /// Whether the outcome is explicitly unknown.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }
}

/// Durable state of one Git journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitJournalState {
    /// Intent recorded; the side effect has not started.
    Intent,
    /// The commit result was recorded.
    Committed,
    /// The commit was refused before a side effect.
    Rejected,
    /// The result is unknown; the Task waits for reconciliation.
    ResultUnknown,
}

/// One Git journal record: intent first, outcome after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitJournalEntry {
    request: RequestRecord<crate::ids::CommitKind, GitCommitOutcome>,
    intent: GitCommitIntent,
    state: GitJournalState,
}

impl GitJournalEntry {
    /// Records the intent before any Git side effect.
    pub fn new(
        identity: RequestIdentity<crate::ids::CommitKind>,
        intent: GitCommitIntent,
    ) -> Result<Self, SddExecutionError> {
        if identity.project_id() != intent.task.project_id() {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "commit request".to_owned(),
                expected: identity.project_id(),
                found: intent.task.project_id(),
            });
        }
        let request = RequestRecord::intent(identity, &intent)?;
        Ok(Self {
            request,
            intent,
            state: GitJournalState::Intent,
        })
    }

    /// Records an observed outcome.
    pub fn record(mut self, outcome: GitCommitOutcome) -> Self {
        self.state = match outcome {
            GitCommitOutcome::Committed { .. } => GitJournalState::Committed,
            GitCommitOutcome::Rejected { .. } => GitJournalState::Rejected,
            GitCommitOutcome::Unknown { .. } => GitJournalState::ResultUnknown,
        };
        self.request = self.request.recorded(outcome);
        self
    }

    /// Records an unknown or too-late result without inventing an outcome.
    pub fn mark_result_unknown(mut self, reason: GitUnknownReason) -> Self {
        self.state = GitJournalState::ResultUnknown;
        self.request = self.request.recorded(GitCommitOutcome::Unknown { reason });
        self
    }

    /// Mandatory request guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::CommitKind> {
        self.request.identity()
    }

    /// Recorded intent.
    pub fn intent(&self) -> &GitCommitIntent {
        &self.intent
    }

    /// Durable journal state.
    pub const fn state(&self) -> GitJournalState {
        self.state
    }

    /// Stored outcome.
    pub const fn outcome(&self) -> Option<&GitCommitOutcome> {
        self.request.outcome()
    }

    /// Decides a re-delivered commit request for the same Task.
    pub fn decide(
        &self,
        incoming: &RequestIdentity<crate::ids::CommitKind>,
        intent: &GitCommitIntent,
        current_revision: ExecutionRevision,
    ) -> Result<RequestDecision<GitCommitOutcome>, SddExecutionError> {
        decide_request(Some(&self.request), incoming, intent, current_revision)
    }
}

/// One completed Task line written to `.sdd/progress.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressTaskLine {
    task: TaskRef,
    #[serde(default)]
    range: Option<CommitRange>,
    no_change: bool,
}

impl ProgressTaskLine {
    /// Creates a progress line.
    pub fn new(
        task: TaskRef,
        range: Option<CommitRange>,
        no_change: bool,
    ) -> Result<Self, SddExecutionError> {
        if range.is_some() == no_change {
            return Err(invalid(
                "progress.line",
                "a line records either a commit range or a no_change result",
            ));
        }
        Ok(Self {
            task,
            range,
            no_change,
        })
    }

    /// The Task.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Commit range, absent for a no_change Task.
    pub fn range(&self) -> Option<&CommitRange> {
        self.range.as_ref()
    }

    /// Whether the Task recorded no change.
    pub const fn no_change(&self) -> bool {
        self.no_change
    }
}

/// Content of one progress-ledger write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressContent {
    output_path: String,
    worktree_path: String,
    branch: String,
    baseline: Baseline,
    completed: Vec<ProgressTaskLine>,
    rulings: Vec<String>,
    #[serde(default)]
    final_project_sequence: Option<ProjectSequence>,
    document_digest: Sha256Digest,
}

impl ProgressContent {
    /// Creates progress content. The ledger is a compatibility projection of
    /// durable state, not the source of truth.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        output_path: impl Into<String>,
        worktree_path: impl Into<String>,
        branch: impl Into<String>,
        baseline: Baseline,
        completed: Vec<ProgressTaskLine>,
        rulings: Vec<String>,
        final_project_sequence: Option<ProjectSequence>,
        document_digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        let output_path = output_path.into();
        validate_project_path("progress.outputPath", &output_path)?;
        let worktree_path = worktree_path.into();
        if worktree_path.trim().is_empty() {
            return Err(invalid("progress.worktreePath", "must not be empty"));
        }
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(invalid("progress.branch", "must not be empty"));
        }
        for ruling in &rulings {
            if ruling.trim().is_empty() {
                return Err(invalid("progress.rulings", "must not contain empty text"));
            }
        }
        Ok(Self {
            output_path,
            worktree_path,
            branch,
            baseline,
            completed,
            rulings,
            final_project_sequence,
            document_digest,
        })
    }

    /// ``.sdd/progress.md`` path.
    pub fn output_path(&self) -> &str {
        &self.output_path
    }

    /// Worktree path recorded by the ledger.
    pub fn worktree_path(&self) -> &str {
        &self.worktree_path
    }

    /// Branch recorded by the ledger.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Fixed baseline.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Completed Task lines.
    pub fn completed(&self) -> &[ProgressTaskLine] {
        &self.completed
    }

    /// Rulings recorded for later Tasks.
    pub fn rulings(&self) -> &[String] {
        &self.rulings
    }

    /// Last observed project sequence.
    pub const fn final_project_sequence(&self) -> Option<ProjectSequence> {
        self.final_project_sequence
    }

    /// Digest of the exact rendered and atomically replaced document.
    pub fn document_digest(&self) -> &Sha256Digest {
        &self.document_digest
    }
}

impl JournalContent for ProgressContent {
    fn content_fingerprint(&self) -> Result<RequestFingerprint, SddExecutionError> {
        fingerprint_of(self)
    }
}

/// Why a progress write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressFailure {
    /// The temporary file could not be written.
    TemporaryFileFailed,
    /// The replacement failed.
    ReplaceFailed,
    /// The existing file was changed by an external writer.
    ExternalModification,
    /// Durable state no longer matched the content being written.
    StaleState,
}

/// The observed progress write result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ProgressWriteOutcome {
    /// The document was written and the digest observed.
    Written {
        /// Digest after replacement.
        digest: Sha256Digest,
    },
    /// The write failed; the next Task stays gated.
    Failed {
        /// Structured failure.
        reason: ProgressFailure,
    },
    /// The result cannot be determined.
    Unknown,
}

/// Durable state of one progress journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressJournalState {
    /// Intent recorded; the write has not started.
    Intent,
    /// The write result is recorded.
    Recorded,
    /// The result is unknown.
    ResultUnknown,
}

/// One progress journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressJournalEntry {
    request: RequestRecord<crate::ids::ProgressKind, ProgressWriteOutcome>,
    content: ProgressContent,
    state: ProgressJournalState,
}

impl ProgressJournalEntry {
    /// Records the write intent before replacing the file.
    pub fn new(
        identity: RequestIdentity<crate::ids::ProgressKind>,
        content: ProgressContent,
    ) -> Result<Self, SddExecutionError> {
        let request = RequestRecord::intent(identity, &content)?;
        Ok(Self {
            request,
            content,
            state: ProgressJournalState::Intent,
        })
    }

    /// Records the observed write result.
    pub fn record(mut self, outcome: ProgressWriteOutcome) -> Self {
        self.state = if matches!(outcome, ProgressWriteOutcome::Unknown) {
            ProgressJournalState::ResultUnknown
        } else {
            ProgressJournalState::Recorded
        };
        self.request = self.request.recorded(outcome);
        self
    }

    /// Mandatory request guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::ProgressKind> {
        self.request.identity()
    }

    /// Written content.
    pub fn content(&self) -> &ProgressContent {
        &self.content
    }

    /// Durable journal state.
    pub const fn state(&self) -> ProgressJournalState {
        self.state
    }

    /// Stored outcome.
    pub const fn outcome(&self) -> Option<&ProgressWriteOutcome> {
        self.request.outcome()
    }
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}
