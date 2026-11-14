//! Host-only Git stage and commit boundary.
//!
//! This module is the only place in `herness-core` that mutates a Git
//! repository. It exists so an approved host commit can run without giving a
//! model tool, a tool argument payload, the plan preview path, or an IPC
//! request any way to reach Git.
//!
//! # Reachability
//!
//! [`HostGitAuthorization`] has no public constructor, no `Deserialize`
//! implementation, and no conversion from a string, a tool authorization, or a
//! [`crate::permissions::Authorization`]. Its only source is
//! [`HostCommitApproval::authorize`], which accepts only
//! [`HostGitApprover::Human`] with both host commit and hook execution
//! approved. [`HostGitBoundary`] does not implement
//! [`crate::tools::ToolExecutor`] and no [`crate::tools::ToolName`] names it, so
//! [`crate::tools::ToolGateway`] cannot dispatch to it.
//!
//! # Order of operations
//!
//! 1. identity and approval verification, entirely in memory;
//! 2. checkout, branch, HEAD, path form, bytes, content digest, and hook
//!    configuration verification, reading only the worktree and Git ref files;
//! 3. persist the intent and its host-activity event;
//! 4. index cleanliness, one read-only Git query;
//! 5. `git add -- <explicit paths>`;
//! 6. verify the index holds exactly the approved paths;
//! 7. run the approved common staged-document gate;
//! 8. `git commit --file - --cleanup=whitespace` with the message on stdin;
//! 9. observe the commit and verify branch, parent, tree, and changed paths;
//! 10. persist the observed result.
//!
//! Steps 1 and 2 have no Git side effect, create no commit, and spawn no
//! process at all. A failed intent write in step 3 also spawns nothing. A
//! failing hook in step 8 refuses without creating a commit. A timeout, stop,
//! or unconfirmed group in steps 4–9 is an unknown result the H4 Git journal
//! must reconcile; it is never success.
//!
//! # Deliberately absent
//!
//! There is no `push`, `pull`, `fetch`, `merge`, `rebase`, `amend`, `reset`,
//! `clean`, `checkout`, branch creation, or history rewrite. There is no
//! rollback of a Git success when the later durable write fails: Git and SQLite
//! are not one atomic transaction, and this boundary reports that explicitly
//! instead of hiding it. `--no-verify` is never passed, so repository hooks
//! always run, and no `sh -c` string is used: every Git invocation is a fixed
//! argv.
//!
//! # What it does not guarantee
//!
//! A Task commits modifications and new files. A deleted path is refused,
//! because the host cannot verify the content of something that does not exist
//! and deletion is the one operation this boundary will not infer from an
//! approved path list.
//!
//! Another process can still change the worktree or the index between a check
//! and the commit. The host verifies the created commit's branch, parent, tree,
//! and changed paths afterwards, so such a race becomes an unknown result or a
//! refusal, not a silent success. A hook may also modify files the host did not
//! stage; the host does not roll that back.

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::events::{EventDraft, EventKind, EventPayload};
use crate::contracts::ids::{HostActivityId, ProjectId};
use crate::contracts::path::AbsolutePath;
use crate::contracts::shell::ShellStopStatus;
use crate::contracts::time::Timestamp;
use crate::ports::runtime_store::RuntimeStore;
use crate::tools::Purpose;
use crate::tools::process::{
    ArgvLauncher, ArgvRequest, CaptureHandle, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_TIMEOUT_GRACE, ManagedChild, ManagedOwner, ProcessSupervisor,
    SystemArgvLauncher, spawn_failure, supervise,
};

/// Host-activity kind recorded for one host Git request.
pub const HOST_GIT_ACTIVITY_KIND: &str = "host_git.commit";
/// Event kind persisted before the first Git process.
pub const HOST_GIT_STARTED_EVENT_KIND: &str = "host_git.started";
/// Event kind persisted with the observed result.
pub const HOST_GIT_FINISHED_EVENT_KIND: &str = "host_git.finished";

/// Hard ceiling for stage, gate, hooks, and commit.
///
/// This is the approved H4 host commit budget. The caller supplies the
/// effective value, shortened to the remaining Task time when that is smaller,
/// and this boundary refuses anything larger.
pub const HOST_COMMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest number of explicitly staged paths in one request.
pub const MAX_HOST_GIT_PATHS: usize = 4_096;

/// Largest accepted staged-document gate argument, in bytes.
pub const MAX_HOST_GIT_GATE_ARG_BYTES: usize = 64 * 1024;

const MIN_COMMIT_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_HOOK_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ERROR_EXCERPT: usize = 300;

// ---------------------------------------------------------------------------
// Sealed authorization
// ---------------------------------------------------------------------------

/// Who approved the host commit.
///
/// Only [`HostGitApprover::Human`] is usable. The other variants exist so that a
/// caller which tries to source a commit from a model request or an owner-kind
/// value gets a typed refusal instead of an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostGitApprover {
    /// A human decision recorded by the host approval registry.
    Human,
    /// A model request or model-authored proposal.
    Model,
    /// An H1/H2/H3 owner-kind value.
    OwnerKind,
}

impl HostGitApprover {
    /// Stable label used in audit payloads and refusals.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Model => "model",
            Self::OwnerKind => "owner_kind",
        }
    }
}

/// The host-side approval one Git request must belong to.
///
/// The trusted host composition builds this from one immutable H4 execution
/// approval. It carries no credential and no model or plan text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCommitApproval {
    project_id: ProjectId,
    approval_id: String,
    approval_revision: u64,
    approver: HostGitApprover,
    checkout_root: AbsolutePath,
    branch: String,
    host_commit: bool,
    run_hooks: bool,
}

impl HostCommitApproval {
    /// Records the approved workspace and commit authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        approval_id: impl Into<String>,
        approval_revision: u64,
        approver: HostGitApprover,
        checkout_root: AbsolutePath,
        branch: impl Into<String>,
        host_commit: bool,
        run_hooks: bool,
    ) -> Result<Self, HostGitRefusal> {
        let approval_id = approval_id.into();
        validate_token("approvalId", &approval_id)?;
        if approval_revision == 0 {
            return Err(HostGitRefusal::InvalidField {
                field: "approvalRevision",
                detail: "must be greater than zero".to_owned(),
            });
        }
        let branch = branch.into();
        validate_branch(&branch)?;
        validate_canonical_absolute("checkoutRoot", checkout_root.as_str())?;
        Ok(Self {
            project_id,
            approval_id,
            approval_revision,
            approver,
            checkout_root,
            branch,
            host_commit,
            run_hooks,
        })
    }

    /// Project that owns the approved workspace.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approval identity the workspace belongs to.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Approval revision.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// Approved canonical checkout root.
    pub const fn checkout_root(&self) -> &AbsolutePath {
        &self.checkout_root
    }

    /// Approved implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Whether the host was approved to stage and commit.
    pub const fn host_commit(&self) -> bool {
        self.host_commit
    }

    /// Whether repository hooks were approved to run.
    pub const fn run_hooks(&self) -> bool {
        self.run_hooks
    }

    /// Turns the approval into the host-only authorization value.
    ///
    /// A non-human approver, an unapproved host commit, or an unapproved hook
    /// run is refused, so no usable authorization can come from a model
    /// request, an owner kind, or a partial approval.
    pub fn authorize(self) -> Result<HostGitAuthorization, HostGitRefusal> {
        if self.approver != HostGitApprover::Human {
            return Err(HostGitRefusal::NotAuthorized {
                detail: format!("approver is {}", self.approver.as_str()),
            });
        }
        if !self.host_commit {
            return Err(HostGitRefusal::NotAuthorized {
                detail: "host commit was not approved".to_owned(),
            });
        }
        if !self.run_hooks {
            return Err(HostGitRefusal::NotAuthorized {
                detail: "repository hook execution was not approved".to_owned(),
            });
        }
        Ok(HostGitAuthorization {
            approval_id: self.approval_id,
            approval_revision: self.approval_revision,
            project_id: self.project_id,
            checkout_root: self.checkout_root,
            branch: self.branch,
            _sealed: Sealed,
        })
    }
}

/// Proof that a human approved this exact workspace for a host commit.
///
/// The value is sealed: it has no public constructor, no `Deserialize`
/// implementation, and no `From<String>`/`From<&str>` conversion. Only
/// [`HostCommitApproval::authorize`] produces one.
#[derive(Debug, Clone)]
pub struct HostGitAuthorization {
    approval_id: String,
    approval_revision: u64,
    project_id: ProjectId,
    checkout_root: AbsolutePath,
    branch: String,
    _sealed: Sealed,
}

#[derive(Debug, Clone, Copy)]
struct Sealed;

impl HostGitAuthorization {
    /// Project the authorization covers.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approval identity.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Approval revision.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// Approved canonical checkout root.
    pub const fn checkout_root(&self) -> &AbsolutePath {
        &self.checkout_root
    }

    /// Approved branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }
}

// ---------------------------------------------------------------------------
// Intent values
// ---------------------------------------------------------------------------

/// One validated 40-character Git object name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GitObjectId(String);

impl GitObjectId {
    /// Parses a full object name.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, HostGitRefusal> {
        let value = value.as_ref().trim();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostGitRefusal::InvalidField {
                field: "gitObjectId",
                detail: "expected a 40-character hexadecimal Git object name".to_owned(),
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Full object name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One explicitly staged path with the exact content the host verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitPath {
    path: String,
    bytes: u64,
    digest: String,
}

impl HostGitPath {
    /// Creates one path entry with its exact `sha256:<hex>` content digest.
    pub fn new(
        path: impl Into<String>,
        bytes: u64,
        digest: impl AsRef<str>,
    ) -> Result<Self, HostGitRefusal> {
        let path = path.into();
        validate_relative_path(&path)?;
        let digest = validate_digest(digest.as_ref())?;
        Ok(Self {
            path,
            bytes,
            digest,
        })
    }

    /// Computes the digest and length of `bytes` for `path`.
    pub fn for_bytes(path: impl Into<String>, bytes: &[u8]) -> Result<Self, HostGitRefusal> {
        Self::new(path, bytes.len() as u64, digest_of(bytes))
    }

    /// Project-relative path passed to `git add` as one argv entry.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact verified byte length.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// `sha256:<hex>` content digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// One commit trailer supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitTrailer {
    key: String,
    value: String,
}

impl HostGitTrailer {
    /// Creates a trailer that identifies the execution, Task, and request.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, HostGitRefusal> {
        let key = key.into();
        let value = value.into();
        validate_token("trailer.key", &key)?;
        if key.contains(':') {
            return Err(HostGitRefusal::InvalidField {
                field: "trailer.key",
                detail: "must not contain ':'".to_owned(),
            });
        }
        if value.trim().is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(HostGitRefusal::InvalidField {
                field: "trailer.value",
                detail: "must be non-empty single-line text".to_owned(),
            });
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

/// A commit message with a single-line subject and required trailers.
///
/// The boundary renders and writes this message itself. A caller cannot pass a
/// raw message string that hides, reorders, or duplicates the identifying
/// trailers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitMessage {
    subject: String,
    trailers: Vec<HostGitTrailer>,
}

impl HostGitMessage {
    /// Creates a message. At least one identifying trailer is required.
    pub fn new(
        subject: impl Into<String>,
        trailers: Vec<HostGitTrailer>,
    ) -> Result<Self, HostGitRefusal> {
        let subject = subject.into();
        if subject.trim().is_empty() {
            return Err(HostGitRefusal::MessageRejected {
                detail: "the subject must not be empty".to_owned(),
            });
        }
        if subject.contains('\n') || subject.contains('\r') {
            return Err(HostGitRefusal::MessageRejected {
                detail: "the subject must be single-line text".to_owned(),
            });
        }
        if trailers.is_empty() {
            return Err(HostGitRefusal::MessageRejected {
                detail: "at least one identifying trailer is required".to_owned(),
            });
        }
        let mut seen: Vec<&str> = Vec::new();
        for trailer in &trailers {
            if seen.contains(&trailer.key.as_str()) {
                return Err(HostGitRefusal::MessageRejected {
                    detail: "a trailer key must not be repeated".to_owned(),
                });
            }
            seen.push(&trailer.key);
        }
        Ok(Self { subject, trailers })
    }

    /// Subject line.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Every trailer, in caller order.
    pub fn trailers(&self) -> &[HostGitTrailer] {
        &self.trailers
    }

    /// Rendered message: subject, one blank line, then one trailer per line.
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

/// The approved common staged-document validation gate.
///
/// The host runs this program instead of reimplementing document policy. It
/// runs after staging and before the commit, with the same deadline and
/// process-group control as Git, and it is never replaced by a shell string or
/// skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGitGate {
    program: AbsolutePath,
    args: Vec<String>,
    timeout: Option<Duration>,
}

impl HostGitGate {
    /// Creates a fixed-argv gate command.
    pub fn new(
        program: AbsolutePath,
        args: Vec<String>,
        timeout: Option<Duration>,
    ) -> Result<Self, HostGitRefusal> {
        validate_canonical_absolute("gate.program", program.as_str())?;
        if !program.as_path().is_file() {
            return Err(HostGitRefusal::InvalidField {
                field: "gate.program",
                detail: "must name an existing regular file".to_owned(),
            });
        }
        if args.len() > 64 {
            return Err(HostGitRefusal::InvalidField {
                field: "gate.args",
                detail: "must contain at most 64 arguments".to_owned(),
            });
        }
        for arg in &args {
            if arg.len() > MAX_HOST_GIT_GATE_ARG_BYTES || arg.contains('\0') {
                return Err(HostGitRefusal::InvalidField {
                    field: "gate.args",
                    detail: "an argument must be bounded text without NUL".to_owned(),
                });
            }
        }
        if timeout.is_some_and(|value| value < MIN_COMMIT_TIMEOUT) {
            return Err(HostGitRefusal::InvalidField {
                field: "gate.timeout",
                detail: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            program,
            args,
            timeout,
        })
    }

    /// Absolute program path.
    pub const fn program(&self) -> &AbsolutePath {
        &self.program
    }

    /// Fixed arguments.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Optional gate-local timeout, still bounded by the request deadline.
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// The approved Git author and committer identity.
///
/// H4 approval binds a Git identity for host commits. Passing it here keeps a
/// commit from depending on whatever identity happens to exist in the host's
/// global Git configuration, and it never overrides a repository hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGitActor {
    name: String,
    email: String,
}

impl HostGitActor {
    /// Creates a Git identity.
    pub fn new(name: impl Into<String>, email: impl Into<String>) -> Result<Self, HostGitRefusal> {
        let name = name.into();
        let email = email.into();
        if name.trim().is_empty()
            || name.chars().any(char::is_control)
            || name.contains('<')
            || name.contains('>')
        {
            return Err(HostGitRefusal::InvalidField {
                field: "actor.name",
                detail: "must be non-empty text without control characters or angle brackets"
                    .to_owned(),
            });
        }
        if email.trim().is_empty()
            || email.chars().any(char::is_control)
            || !email.contains('@')
            || email.contains('<')
            || email.contains('>')
        {
            return Err(HostGitRefusal::InvalidField {
                field: "actor.email",
                detail: "must be a non-empty e-mail address".to_owned(),
            });
        }
        Ok(Self { name, email })
    }

    /// Author and committer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Author and committer e-mail.
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// Everything the boundary verifies before it may touch Git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGitIntent {
    project_id: ProjectId,
    request_id: String,
    purpose: String,
    execution_ref: String,
    task_number: u32,
    task_label: String,
    approval_id: String,
    approval_revision: u64,
    checkout_root: AbsolutePath,
    branch: String,
    expected_parent: GitObjectId,
    expected_tree: Option<GitObjectId>,
    paths: Vec<HostGitPath>,
    message: HostGitMessage,
    gate: HostGitGate,
    timeout: Duration,
    expected_hooks_digest: Option<String>,
    actor: Option<HostGitActor>,
}

impl HostGitIntent {
    /// Creates a commit intent.
    ///
    /// The caller's request identity, purpose, Task, execution reference, and
    /// approval revision are values here, so a mismatch against the
    /// authorization is a typed refusal rather than an implicit trust.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        request_id: impl Into<String>,
        purpose: Purpose,
        execution_ref: impl Into<String>,
        task_number: u32,
        task_label: impl Into<String>,
        approval_id: impl Into<String>,
        approval_revision: u64,
        checkout_root: AbsolutePath,
        branch: impl Into<String>,
        expected_parent: GitObjectId,
        expected_tree: Option<GitObjectId>,
        paths: Vec<HostGitPath>,
        message: HostGitMessage,
        gate: HostGitGate,
        timeout: Duration,
        expected_hooks_digest: Option<String>,
    ) -> Result<Self, HostGitRefusal> {
        let request_id = request_id.into();
        validate_token("requestId", &request_id)?;
        let execution_ref = execution_ref.into();
        validate_token("executionRef", &execution_ref)?;
        let task_label = task_label.into();
        validate_text("taskLabel", &task_label)?;
        if task_number == 0 {
            return Err(HostGitRefusal::InvalidField {
                field: "taskNumber",
                detail: "must be greater than zero".to_owned(),
            });
        }
        let approval_id = approval_id.into();
        validate_token("approvalId", &approval_id)?;
        if approval_revision == 0 {
            return Err(HostGitRefusal::InvalidField {
                field: "approvalRevision",
                detail: "must be greater than zero".to_owned(),
            });
        }
        let branch = branch.into();
        validate_branch(&branch)?;
        validate_canonical_absolute("checkoutRoot", checkout_root.as_str())?;
        if paths.is_empty() {
            return Err(HostGitRefusal::InvalidField {
                field: "paths",
                detail: "a required Task must stage at least one explicit path".to_owned(),
            });
        }
        if paths.len() > MAX_HOST_GIT_PATHS {
            return Err(HostGitRefusal::InvalidField {
                field: "paths",
                detail: format!("must contain at most {MAX_HOST_GIT_PATHS} paths"),
            });
        }
        let mut ordered = paths;
        ordered.sort_by(|left, right| left.path.cmp(&right.path));
        if ordered.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(HostGitRefusal::InvalidField {
                field: "paths",
                detail: "a path must not be repeated".to_owned(),
            });
        }
        if timeout < MIN_COMMIT_TIMEOUT {
            return Err(HostGitRefusal::InvalidField {
                field: "timeout",
                detail: "must be greater than zero".to_owned(),
            });
        }
        if timeout > HOST_COMMIT_TIMEOUT {
            return Err(HostGitRefusal::InvalidField {
                field: "timeout",
                detail: format!(
                    "must not exceed the host commit budget of {} seconds",
                    HOST_COMMIT_TIMEOUT.as_secs()
                ),
            });
        }
        let expected_hooks_digest = match expected_hooks_digest {
            Some(digest) => Some(validate_digest(&digest)?),
            None => None,
        };
        Ok(Self {
            project_id,
            request_id,
            purpose: purpose.into_string(),
            execution_ref,
            task_number,
            task_label,
            approval_id,
            approval_revision,
            checkout_root,
            branch,
            expected_parent,
            expected_tree,
            paths: ordered,
            message,
            gate,
            timeout,
            expected_hooks_digest,
            actor: None,
        })
    }

    /// Sets the approved Git author and committer identity.
    #[must_use]
    pub fn with_actor(mut self, actor: HostGitActor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Approved Git author and committer identity, when one was supplied.
    pub const fn actor(&self) -> Option<&HostGitActor> {
        self.actor.as_ref()
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Idempotent request identity the H4 Git journal recorded.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Host-authored purpose. It is recorded as host activity, never as an agent
    /// rationale or a fabricated agent change reason.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// H4 execution reference.
    pub fn execution_ref(&self) -> &str {
        &self.execution_ref
    }

    /// Task number.
    pub const fn task_number(&self) -> u32 {
        self.task_number
    }

    /// Task label.
    pub fn task_label(&self) -> &str {
        &self.task_label
    }

    /// Approval identity.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Approval revision.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// Canonical checkout root.
    pub const fn checkout_root(&self) -> &AbsolutePath {
        &self.checkout_root
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Expected parent commit.
    pub const fn expected_parent(&self) -> &GitObjectId {
        &self.expected_parent
    }

    /// Expected resulting tree, when the caller could compute it.
    pub const fn expected_tree(&self) -> Option<&GitObjectId> {
        self.expected_tree.as_ref()
    }

    /// Explicitly staged paths in approved order.
    pub fn paths(&self) -> &[HostGitPath] {
        &self.paths
    }

    /// Commit message.
    pub const fn message(&self) -> &HostGitMessage {
        &self.message
    }

    /// Approved staged-document gate.
    pub const fn gate(&self) -> &HostGitGate {
        &self.gate
    }

    /// Total budget for stage, gate, hooks, and commit.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Expected hook configuration digest, when the caller recorded one.
    pub fn expected_hooks_digest(&self) -> Option<&str> {
        self.expected_hooks_digest.as_deref()
    }

    /// Deterministic host-activity identifier for this request.
    pub fn activity_id(&self) -> HostActivityId {
        let mut value = [0_u8; 16];
        value.copy_from_slice(
            &Sha256::digest(
                format!(
                    "host-git-activity\0{}\0{}",
                    self.project_id, self.request_id
                )
                .as_bytes(),
            )[..16],
        );
        HostActivityId::from_parts(self.project_id, Uuid::from_bytes(value))
    }

    /// Host-state key for the durable intent and result record.
    ///
    /// The project is part of the key, so two projects that reuse a request
    /// identity cannot overwrite each other's audit record.
    pub fn record_key(&self) -> String {
        format!("herness.host_git.{}.{}", self.project_id, self.request_id)
    }
}

// ---------------------------------------------------------------------------
// Refusals and unknown reasons
// ---------------------------------------------------------------------------

/// Why the host refused to stage or commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "code",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HostGitRefusal {
    /// A value did not validate.
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Non-secret explanation.
        detail: String,
    },
    /// The authorization does not cover this request.
    NotAuthorized {
        /// Non-secret explanation.
        detail: String,
    },
    /// The request and authorization name different approval revisions.
    ApprovalRevisionMismatch {
        /// Revision carried by the authorization.
        authorized: u64,
        /// Revision carried by the request.
        requested: u64,
    },
    /// The authorization covers another project.
    CrossProject {
        /// Project the authorization covers.
        authorized: ProjectId,
        /// Project the request names.
        requested: ProjectId,
    },
    /// The checkout root is not the approved, canonical working tree.
    CheckoutRejected {
        /// Non-secret explanation.
        detail: String,
    },
    /// The repository is on another branch than the approved one.
    BranchMismatch {
        /// Approved branch.
        expected: String,
        /// Observed branch, or `detached` for a detached HEAD.
        found: String,
    },
    /// The repository HEAD is not the approved parent.
    ParentMismatch {
        /// Approved parent.
        expected: GitObjectId,
        /// Observed HEAD.
        found: GitObjectId,
    },
    /// The index already held staged changes before the host staged anything.
    IndexNotClean,
    /// An explicitly staged path was not a regular file inside the checkout.
    PathRejected {
        /// Rejected project-relative path.
        path: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// The worktree content is not the approved content.
    ContentMismatch {
        /// Path whose content differs.
        path: String,
        /// Approved digest.
        expected: String,
        /// Observed digest.
        found: String,
    },
    /// The worktree file length is not the approved length.
    LengthMismatch {
        /// Path whose length differs.
        path: String,
        /// Approved byte length.
        expected: u64,
        /// Observed byte length.
        found: u64,
    },
    /// The index holds a path the host did not approve.
    UnexpectedIndexEntry {
        /// Path found in the index.
        path: String,
    },
    /// The hook configuration differs from the approved digest.
    HookConfigurationChanged {
        /// Approved digest.
        expected: String,
        /// Observed digest.
        found: String,
    },
    /// The commit message was rejected.
    MessageRejected {
        /// Non-secret explanation.
        detail: String,
    },
    /// `git add -- <paths>` failed.
    StagingFailed {
        /// Bounded, non-secret explanation.
        detail: String,
    },
    /// The approved common staged-document gate refused the staged content.
    GateFailed {
        /// Exit code, when the gate exited normally.
        exit_code: Option<i32>,
        /// Bounded, non-secret explanation.
        detail: String,
    },
    /// `git commit` failed, for example because a repository hook refused.
    CommitFailed {
        /// Exit code, when Git exited normally.
        exit_code: Option<i32>,
        /// Bounded, non-secret explanation.
        detail: String,
    },
    /// An object name could not be read.
    ObjectUnreadable {
        /// What the host tried to read.
        name: &'static str,
        /// Bounded, non-secret explanation.
        detail: String,
    },
    /// A host stop was observed before anything was staged.
    StoppedBeforeSideEffect,
    /// A Git or gate process could not be started.
    SpawnFailed {
        /// Sanitized operating-system error kind.
        detail: String,
    },
}

impl HostGitRefusal {
    /// Stable wire label.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidField { .. } => "invalid_field",
            Self::NotAuthorized { .. } => "not_authorized",
            Self::ApprovalRevisionMismatch { .. } => "approval_revision_mismatch",
            Self::CrossProject { .. } => "cross_project",
            Self::CheckoutRejected { .. } => "checkout_rejected",
            Self::BranchMismatch { .. } => "branch_mismatch",
            Self::ParentMismatch { .. } => "parent_mismatch",
            Self::IndexNotClean => "index_not_clean",
            Self::PathRejected { .. } => "path_rejected",
            Self::ContentMismatch { .. } => "content_mismatch",
            Self::LengthMismatch { .. } => "length_mismatch",
            Self::UnexpectedIndexEntry { .. } => "unexpected_index_entry",
            Self::HookConfigurationChanged { .. } => "hook_configuration_changed",
            Self::MessageRejected { .. } => "message_rejected",
            Self::StagingFailed { .. } => "staging_failed",
            Self::GateFailed { .. } => "gate_failed",
            Self::CommitFailed { .. } => "commit_failed",
            Self::ObjectUnreadable { .. } => "object_unreadable",
            Self::StoppedBeforeSideEffect => "stopped_before_side_effect",
            Self::SpawnFailed { .. } => "spawn_failed",
        }
    }

    /// Non-secret detail for audit payloads and refusals.
    pub fn detail(&self) -> String {
        match self {
            Self::InvalidField { field, detail } => format!("{field}: {detail}"),
            Self::NotAuthorized { detail }
            | Self::CheckoutRejected { detail }
            | Self::MessageRejected { detail }
            | Self::SpawnFailed { detail }
            | Self::StagingFailed { detail } => detail.clone(),
            Self::ApprovalRevisionMismatch {
                authorized,
                requested,
            } => {
                format!("the authorization covers approval revision {authorized}, not {requested}")
            }
            Self::CrossProject {
                authorized,
                requested,
            } => format!("the authorization covers project {authorized}, not {requested}"),
            Self::BranchMismatch { expected, found } => {
                format!("expected branch {expected}, found {found}")
            }
            Self::ParentMismatch { expected, found } => {
                format!("expected parent {expected}, found {found}")
            }
            Self::IndexNotClean => {
                "the index held staged changes before the host staged explicit paths".to_owned()
            }
            Self::PathRejected { path, detail } => format!("{path}: {detail}"),
            Self::ContentMismatch {
                path,
                expected,
                found,
            } => format!("{path}: expected {expected}, found {found}"),
            Self::LengthMismatch {
                path,
                expected,
                found,
            } => format!("{path}: expected {expected} bytes, found {found}"),
            Self::UnexpectedIndexEntry { path } => {
                format!("the index holds the unrequested path {path}")
            }
            Self::HookConfigurationChanged { expected, found } => {
                format!("expected hook digest {expected}, found {found}")
            }
            Self::GateFailed { exit_code, detail } => {
                format!("the staged-document gate failed ({exit_code:?}): {detail}")
            }
            Self::CommitFailed { exit_code, detail } => {
                format!("git commit failed ({exit_code:?}): {detail}")
            }
            Self::ObjectUnreadable { name, detail } => format!("{name}: {detail}"),
            Self::StoppedBeforeSideEffect => {
                "a host stop was observed before staging began".to_owned()
            }
        }
    }
}

impl fmt::Display for HostGitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

impl std::error::Error for HostGitRefusal {}

/// Why a commit result could not be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostGitUnknown {
    /// The stage/gate/hook/commit budget expired.
    Timeout,
    /// A host stop terminated the process group.
    Stopped,
    /// The process ended without a result the host could confirm.
    UnobservedProcess,
    /// The commit was observed but its durable record could not be written.
    AuditWriteFailed,
    /// The repository HEAD or another object could not be read after the
    /// commit.
    HeadUnreadable,
    /// The commit exists but its tree or changed paths differ from the approved
    /// content.
    ContentMismatch,
    /// The branch or parent moved somewhere the host did not request.
    UnexpectedBranchMovement,
    /// The index or the commit holds paths the host did not approve.
    UnexpectedPaths,
}

impl HostGitUnknown {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Stopped => "stopped",
            Self::UnobservedProcess => "unobserved_process",
            Self::AuditWriteFailed => "audit_write_failed",
            Self::HeadUnreadable => "head_unreadable",
            Self::ContentMismatch => "content_mismatch",
            Self::UnexpectedBranchMovement => "unexpected_branch_movement",
            Self::UnexpectedPaths => "unexpected_paths",
        }
    }
}

/// Furthest stage reached before the boundary stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostGitStage {
    /// Identity, checkout, branch, HEAD, and content verification.
    Verify,
    /// `git add -- <paths>`.
    Stage,
    /// The approved common staged-document gate.
    Gate,
    /// `git commit`.
    Commit,
    /// Post-commit observation.
    Observe,
}

impl HostGitStage {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Stage => "stage",
            Self::Gate => "gate",
            Self::Commit => "commit",
            Self::Observe => "observe",
        }
    }
}

/// What the approved gate did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostGitGateOutcome {
    /// The gate was not reached.
    NotRun,
    /// The gate exited successfully.
    Passed,
    /// The gate refused the staged content.
    Failed,
    /// A host stop terminated the gate.
    Stopped,
    /// The gate exceeded its budget.
    TimedOut,
    /// The gate ended without a confirmable result.
    Unconfirmed,
}

impl HostGitGateOutcome {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
            Self::TimedOut => "timed_out",
            Self::Unconfirmed => "unconfirmed",
        }
    }
}

/// Observed index state when the boundary stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostGitIndexState {
    /// The index matched HEAD.
    Clean,
    /// The approved paths were staged but no commit was created.
    ApprovedPathsStaged,
    /// The commit was created and the index matches the new HEAD.
    Committed,
    /// The index could not be classified.
    Unknown,
}

impl HostGitIndexState {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::ApprovedPathsStaged => "approved_paths_staged",
            Self::Committed => "committed",
            Self::Unknown => "unknown",
        }
    }
}

/// Observed termination of one managed Git or gate process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitTermination {
    pid: u32,
    pgid: u32,
    stop_status: ShellStopStatus,
    exit_code: Option<i32>,
    terminating_signal: Option<i32>,
    confirmed: bool,
}

impl HostGitTermination {
    /// Direct child pid.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Process-group id.
    pub const fn pgid(&self) -> u32 {
        self.pgid
    }

    /// Observed stop status.
    pub const fn stop_status(&self) -> ShellStopStatus {
        self.stop_status
    }

    /// Exit code, when the process exited normally.
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Terminating signal, when the process was killed.
    pub const fn terminating_signal(&self) -> Option<i32> {
        self.terminating_signal
    }

    /// Whether the host confirmed the whole process group is gone.
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }
}

/// The observed commit after a successful Git process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitCommitObservation {
    commit: GitObjectId,
    tree: GitObjectId,
    parent: GitObjectId,
}

impl HostGitCommitObservation {
    /// Commit object name.
    pub const fn commit(&self) -> &GitObjectId {
        &self.commit
    }

    /// Resulting tree.
    pub const fn tree(&self) -> &GitObjectId {
        &self.tree
    }

    /// Observed parent.
    pub const fn parent(&self) -> &GitObjectId {
        &self.parent
    }
}

/// The result of one host Git request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HostGitOutcome {
    /// The commit was created and its branch, parent, tree, and paths were
    /// observed.
    Committed {
        /// Commit object name.
        commit: GitObjectId,
        /// Resulting tree.
        tree: GitObjectId,
        /// Observed parent.
        parent: GitObjectId,
    },
    /// The request was refused. No commit was created.
    Rejected {
        /// Why the host refused.
        reason: HostGitRefusal,
    },
    /// The result cannot be determined and must be reconciled.
    Unknown {
        /// Why the result is unknown.
        reason: HostGitUnknown,
    },
}

impl HostGitOutcome {
    /// Whether a commit object may exist.
    ///
    /// A timeout, stop, or lost audit write during the commit stage may have
    /// created one; a refusal never did.
    pub const fn may_exist(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Unknown { .. })
    }

    /// Whether the outcome is explicitly unknown.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// Stable wire label.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Committed { .. } => "committed",
            Self::Rejected { .. } => "rejected",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Reason a refusal carries, when this is a refusal.
    pub const fn refusal(&self) -> Option<&HostGitRefusal> {
        match self {
            Self::Rejected { reason } => Some(reason),
            _ => None,
        }
    }

    /// Reason an unknown result carries, when this is unknown.
    pub const fn unknown_reason(&self) -> Option<HostGitUnknown> {
        match self {
            Self::Unknown { reason } => Some(*reason),
            _ => None,
        }
    }

    /// Observed commit name, when the outcome is a commit.
    pub const fn committed(&self) -> Option<&GitObjectId> {
        match self {
            Self::Committed { commit, .. } => Some(commit),
            _ => None,
        }
    }
}

/// What the boundary observed, independent of whether it could record it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGitReport {
    stage: HostGitStage,
    outcome: HostGitOutcome,
    observed: Option<HostGitCommitObservation>,
    gate: HostGitGateOutcome,
    hooks_digest: Option<String>,
    index_state: HostGitIndexState,
    termination: Option<HostGitTermination>,
    result_recorded: bool,
}

impl HostGitReport {
    /// Furthest stage reached.
    pub const fn stage(&self) -> HostGitStage {
        self.stage
    }

    /// Recorded outcome.
    pub const fn outcome(&self) -> &HostGitOutcome {
        &self.outcome
    }

    /// Observed commit, when one was seen.
    ///
    /// A report whose [`Self::result_recorded`] is false may still carry this
    /// value: the commit exists, the durable record does not, and the caller
    /// must reconcile instead of retrying.
    pub const fn observed(&self) -> Option<&HostGitCommitObservation> {
        self.observed.as_ref()
    }

    /// Gate and hook outcome.
    pub const fn gate_outcome(&self) -> HostGitGateOutcome {
        self.gate
    }

    /// Digest of the hook configuration that ran.
    pub fn hooks_digest(&self) -> Option<&str> {
        self.hooks_digest.as_deref()
    }

    /// Observed index state.
    pub const fn index_state(&self) -> HostGitIndexState {
        self.index_state
    }

    /// Termination of the last managed process group, when one ran.
    pub const fn termination(&self) -> Option<&HostGitTermination> {
        self.termination.as_ref()
    }

    /// Whether the result record was persisted.
    ///
    /// `false` with [`Self::observed`] set means Git succeeded and the durable
    /// write did not. The boundary does not roll the commit back.
    pub const fn result_recorded(&self) -> bool {
        self.result_recorded
    }
}

/// Why the boundary could not record its own intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostGitError {
    /// The intent and its audit event were not persisted, so no Git process was
    /// started.
    IntentNotPersisted {
        /// Sanitized store detail.
        detail: String,
    },
}

impl fmt::Display for HostGitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntentNotPersisted { detail } => {
                write!(f, "host Git intent was not persisted: {detail}")
            }
        }
    }
}

impl std::error::Error for HostGitError {}

// ---------------------------------------------------------------------------
// Audit port
// ---------------------------------------------------------------------------

/// Durable host Git intent and result records.
///
/// Implementations persist the record and its host-activity events atomically
/// and must write before returning success. A failed intent write means the
/// boundary starts no Git process. A failed result write is reported as an
/// unknown result for H4 reconciliation.
pub trait HostGitAuditPort {
    /// Persists the verified intent before the first Git side effect.
    fn record_intent(
        &mut self,
        intent: &HostGitIntent,
        activity_id: HostActivityId,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError>;

    /// Persists the observed result after the process groups ended.
    fn record_result(
        &mut self,
        intent: &HostGitIntent,
        activity_id: HostActivityId,
        report: &HostGitReport,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError>;
}

/// In-memory audit sink.
///
/// It keeps the exact records in a `Vec` for assertions. It is not durable and
/// production composition uses [`StoreHostGitAudit`] or an equivalent store
/// backed adapter.
#[derive(Debug, Default)]
pub struct RecordingHostGitAudit {
    intents: Vec<serde_json::Value>,
    results: Vec<serde_json::Value>,
}

impl RecordingHostGitAudit {
    /// Creates an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Recorded intent payloads.
    pub fn intents(&self) -> &[serde_json::Value] {
        &self.intents
    }

    /// Recorded result payloads.
    pub fn results(&self) -> &[serde_json::Value] {
        &self.results
    }
}

impl HostGitAuditPort for RecordingHostGitAudit {
    fn record_intent(
        &mut self,
        intent: &HostGitIntent,
        _activity_id: HostActivityId,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        let _ = events;
        self.intents.push(intent_record(intent));
        Ok(())
    }

    fn record_result(
        &mut self,
        _intent: &HostGitIntent,
        _activity_id: HostActivityId,
        report: &HostGitReport,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        let _ = events;
        self.results.push(report_record(report));
        Ok(())
    }
}

/// Audit sink that keeps the intent and result in the private host-state table
/// and appends the host-activity events in the same transaction.
///
/// The record is keyed by the request identity, so a re-delivered request
/// overwrites the same row instead of adding a second history entry. Git and
/// SQLite remain two separate systems: a failed write here does not roll back a
/// commit that already exists.
#[derive(Debug)]
pub struct StoreHostGitAudit<S> {
    store: S,
}

impl<S> StoreHostGitAudit<S> {
    /// Wraps a runtime store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrows the underlying store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Mutably borrows the underlying store.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

impl<S: RuntimeStore> HostGitAuditPort for StoreHostGitAudit<S> {
    fn record_intent(
        &mut self,
        intent: &HostGitIntent,
        _activity_id: HostActivityId,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        let record = serde_json::json!({
            "formatVersion": 1,
            "state": "intent",
            "intent": intent_record(intent),
            "result": serde_json::Value::Null,
        });
        let bytes = encode_record(&record)?;
        self.store
            .save_host_state_and_events(&intent.record_key(), &bytes, events)
            .map(|_| ())
    }

    fn record_result(
        &mut self,
        intent: &HostGitIntent,
        _activity_id: HostActivityId,
        report: &HostGitReport,
        events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        let record = serde_json::json!({
            "formatVersion": 1,
            "state": "result",
            "intent": intent_record(intent),
            "result": report_record(report),
        });
        let bytes = encode_record(&record)?;
        self.store
            .save_host_state_and_events(&intent.record_key(), &bytes, events)
            .map(|_| ())
    }
}

fn encode_record(value: &serde_json::Value) -> Result<Vec<u8>, CoreError> {
    serde_json::to_vec(value).map_err(|error| CoreError::InvalidValue {
        field: "hostGitRecord".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: error.to_string(),
        },
    })
}

fn intent_record(intent: &HostGitIntent) -> serde_json::Value {
    serde_json::json!({
        "formatVersion": 1,
        "actor": "host",
        "projectId": intent.project_id,
        "requestId": intent.request_id,
        "purpose": intent.purpose,
        "executionRef": intent.execution_ref,
        "taskNumber": intent.task_number,
        "taskLabel": intent.task_label,
        "approvalId": intent.approval_id,
        "approvalRevision": intent.approval_revision,
        "checkoutRoot": intent.checkout_root.as_str(),
        "branch": intent.branch,
        "expectedParent": intent.expected_parent.as_str(),
        "expectedTree": intent.expected_tree.as_ref().map(GitObjectId::as_str),
        "paths": intent.paths,
        "subject": intent.message.subject(),
        "trailers": intent.message.trailers,
        "gate": {
            "program": intent.gate.program.as_str(),
            "args": intent.gate.args,
        },
        "timeoutMs": intent.timeout.as_millis() as u64,
        "expectedHooksDigest": intent.expected_hooks_digest,
    })
}

fn report_record(report: &HostGitReport) -> serde_json::Value {
    serde_json::json!({
        "formatVersion": 1,
        "actor": "host",
        "stage": report.stage.as_str(),
        "outcome": report.outcome,
        "observed": report.observed,
        "gate": report.gate.as_str(),
        "hooksDigest": report.hooks_digest,
        "indexState": report.index_state.as_str(),
        "stopStatus": report.termination.map(|value| value.stop_status),
        "confirmed": report.termination.map(|value| value.confirmed),
        "resultRecorded": report.result_recorded,
    })
}

// ---------------------------------------------------------------------------
// Boundary
// ---------------------------------------------------------------------------

/// Host-only stage and commit boundary.
///
/// Construct it in the trusted host composition with the approved absolute Git
/// path and the supervisor shared with app quit and Task stop, so a stop
/// reaches the Git process group.
pub struct HostGitBoundary<L = SystemArgvLauncher, A = RecordingHostGitAudit> {
    git_program: AbsolutePath,
    launcher: L,
    audit: A,
    supervisor: ProcessSupervisor,
    output_limit: usize,
    timeout_grace: Duration,
    confirm_timeout: Duration,
    capture_timeout: Duration,
}

impl<L, A> HostGitBoundary<L, A> {
    /// Creates the boundary.
    pub fn new(
        git_program: AbsolutePath,
        launcher: L,
        audit: A,
        supervisor: ProcessSupervisor,
    ) -> Result<Self, HostGitRefusal> {
        validate_canonical_absolute("gitProgram", git_program.as_str())?;
        Ok(Self {
            git_program,
            launcher,
            audit,
            supervisor,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            timeout_grace: DEFAULT_TIMEOUT_GRACE,
            confirm_timeout: DEFAULT_CONFIRM_TIMEOUT,
            capture_timeout: DEFAULT_CAPTURE_TIMEOUT,
        })
    }

    /// Sets the per-stream capture retention.
    #[must_use]
    pub fn with_output_limit(mut self, limit: usize) -> Self {
        self.output_limit = limit;
        self
    }

    /// Sets the SIGTERM-to-SIGKILL grace for a timeout.
    #[must_use]
    pub fn with_timeout_grace(mut self, grace: Duration) -> Self {
        self.timeout_grace = grace;
        self
    }

    /// Sets the wait for a group to disappear after SIGKILL.
    #[must_use]
    pub fn with_confirm_timeout(mut self, timeout: Duration) -> Self {
        self.confirm_timeout = timeout;
        self
    }

    /// Sets the wait for output readers after the group is gone.
    #[must_use]
    pub fn with_capture_timeout(mut self, timeout: Duration) -> Self {
        self.capture_timeout = timeout;
        self
    }

    /// Shared process-group supervisor.
    pub const fn supervisor(&self) -> &ProcessSupervisor {
        &self.supervisor
    }

    /// Audit sink.
    pub const fn audit(&self) -> &A {
        &self.audit
    }

    /// Mutable audit sink, for tests and host wiring.
    pub const fn audit_mut(&mut self) -> &mut A {
        &mut self.audit
    }

    /// Absolute Git program path.
    pub const fn git_program(&self) -> &AbsolutePath {
        &self.git_program
    }
}

impl<L: ArgvLauncher, A: HostGitAuditPort> HostGitBoundary<L, A> {
    /// Verifies, stages, gates, and commits exactly the approved content.
    ///
    /// Every refusal and every observed result is returned as a report. The only
    /// error is an intent that could not be persisted, which guarantees that no
    /// Git process was started.
    pub fn commit(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
    ) -> Result<HostGitReport, HostGitError> {
        let deadline = Instant::now() + intent.timeout;
        let mut session = Session {
            git_program: &self.git_program,
            launcher: &mut self.launcher,
            audit: &mut self.audit,
            supervisor: &self.supervisor,
            output_limit: self.output_limit,
            timeout_grace: self.timeout_grace,
            confirm_timeout: self.confirm_timeout,
            capture_timeout: self.capture_timeout,
        };
        session.commit(intent, authorization, deadline)
    }

    /// Reads the current repository state without changing Git.
    ///
    /// This is the read-only half of the boundary and is safe to call from a
    /// status surface: it never stages, commits, or runs a hook.
    pub fn observe(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
    ) -> HostGitReport {
        let deadline = Instant::now() + intent.timeout;
        let mut session = Session {
            git_program: &self.git_program,
            launcher: &mut self.launcher,
            audit: &mut self.audit,
            supervisor: &self.supervisor,
            output_limit: self.output_limit,
            timeout_grace: self.timeout_grace,
            confirm_timeout: self.confirm_timeout,
            capture_timeout: self.capture_timeout,
        };
        session.observe(intent, authorization, deadline)
    }
}

/// One commit attempt. It borrows the boundary so the audit sink stays owned by
/// the boundary.
struct Session<'a, L, A> {
    git_program: &'a AbsolutePath,
    launcher: &'a mut L,
    audit: &'a mut A,
    supervisor: &'a ProcessSupervisor,
    output_limit: usize,
    timeout_grace: Duration,
    confirm_timeout: Duration,
    capture_timeout: Duration,
}

/// One low-level process result.
struct Executed {
    termination: HostGitTermination,
    stdout: String,
    stderr: String,
    spawn_error: Option<String>,
}

impl Executed {
    fn verdict(&self) -> Verdict {
        if self.spawn_error.is_some() {
            return Verdict::Failed;
        }
        if !self.termination.confirmed {
            return Verdict::Unknown(HostGitUnknown::UnobservedProcess);
        }
        match self.termination.stop_status {
            ShellStopStatus::Completed => Verdict::Success,
            ShellStopStatus::ExitedNonZero | ShellStopStatus::Killed => Verdict::Failed,
            ShellStopStatus::Timeout => Verdict::Unknown(HostGitUnknown::Timeout),
            ShellStopStatus::StopRequested => Verdict::Unknown(HostGitUnknown::Stopped),
            ShellStopStatus::Unconfirmed => Verdict::Unknown(HostGitUnknown::UnobservedProcess),
        }
    }

    fn detail(&self) -> String {
        if let Some(error) = &self.spawn_error {
            return error.clone();
        }
        let source = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        bounded_excerpt(source)
    }
}

enum Verdict {
    Success,
    Failed,
    Unknown(HostGitUnknown),
}

/// A process that was never started because a host stop had begun.
struct StopBeforeSpawn;

impl<'a, L: ArgvLauncher, A: HostGitAuditPort> Session<'a, L, A> {
    fn commit(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
        deadline: Instant,
    ) -> Result<HostGitReport, HostGitError> {
        // 1. Identity and approval values only. No spawn, no filesystem read.
        if let Err(refusal) = verify_identity(intent, authorization) {
            return Ok(self.record(
                intent,
                HostGitStage::Verify,
                HostGitOutcome::Rejected { reason: refusal },
                None,
                HostGitGateOutcome::NotRun,
                None,
                HostGitIndexState::Unknown,
                None,
            ));
        }

        // 2. Checkout, branch, HEAD, path, and content verification. Reads the
        // worktree and Git ref files only; it spawns nothing.
        let verification = match verify_worktree(intent) {
            Ok(value) => value,
            Err(refusal) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Verify,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    HostGitGateOutcome::NotRun,
                    None,
                    HostGitIndexState::Unknown,
                    None,
                ));
            }
        };
        let hooks_digest = verification.hooks_digest.clone();
        if let Some(expected) = intent.expected_hooks_digest() {
            match hooks_digest.as_deref() {
                Some(found) if found == expected => {}
                found => {
                    return Ok(self.record(
                        intent,
                        HostGitStage::Verify,
                        HostGitOutcome::Rejected {
                            reason: HostGitRefusal::HookConfigurationChanged {
                                expected: expected.to_owned(),
                                found: found.unwrap_or("absent").to_owned(),
                            },
                        },
                        None,
                        HostGitGateOutcome::NotRun,
                        hooks_digest,
                        HostGitIndexState::Unknown,
                        None,
                    ));
                }
            }
        }

        // 4. Persist the intent before the first Git side effect. A failed write
        // here guarantees that no Git process was started.
        let started = vec![self.event(
            intent,
            HOST_GIT_STARTED_EVENT_KIND,
            &serde_json::json!({
                "formatVersion": 1,
                "actor": "host",
                "observation": "intent",
                "intent": intent_record(intent),
                "hooksDigest": hooks_digest,
            }),
        )];
        if let Err(error) = self
            .audit
            .record_intent(intent, intent.activity_id(), started)
        {
            return Err(HostGitError::IntentNotPersisted {
                detail: error.to_string(),
            });
        }

        // 5. Index cleanliness. This is the first Git process; it is read-only
        // and runs after the intent is durable, so an intent-write failure never
        // spawns Git. A dirty index is refused before anything is staged.
        match self.staged_paths(intent, deadline) {
            Ok(paths) if paths.is_empty() => {}
            Ok(_) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Verify,
                    HostGitOutcome::Rejected {
                        reason: HostGitRefusal::IndexNotClean,
                    },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    None,
                ));
            }
            Err(StepFailure::Refused(refusal)) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Verify,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    None,
                ));
            }
            Err(StepFailure::Unknown {
                reason,
                termination,
            }) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Verify,
                    HostGitOutcome::Unknown { reason },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    termination,
                ));
            }
        }

        // 6. Stage exactly the verified paths.
        if self.supervisor.is_stopping() {
            return Ok(self.record(
                intent,
                HostGitStage::Stage,
                HostGitOutcome::Rejected {
                    reason: HostGitRefusal::StoppedBeforeSideEffect,
                },
                None,
                HostGitGateOutcome::NotRun,
                hooks_digest,
                HostGitIndexState::Clean,
                None,
            ));
        }
        let stage = match self.run(intent, deadline, self.stage_request(intent)) {
            Ok(executed) => executed,
            Err(StopBeforeSpawn) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Rejected {
                        reason: HostGitRefusal::StoppedBeforeSideEffect,
                    },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Clean,
                    None,
                ));
            }
        };
        match stage.verdict() {
            Verdict::Success => {}
            Verdict::Failed if stage.spawn_error.is_some() => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Rejected {
                        reason: HostGitRefusal::SpawnFailed {
                            detail: stage.detail(),
                        },
                    },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Clean,
                    Some(stage.termination),
                ));
            }
            Verdict::Failed => {
                let refusal = HostGitRefusal::StagingFailed {
                    detail: stage.detail(),
                };
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    Some(stage.termination),
                ));
            }
            Verdict::Unknown(reason) => {
                let index = self.classify_index(intent, deadline);
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Unknown { reason },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    index,
                    Some(stage.termination),
                ));
            }
        }

        // 7. The index must hold exactly the approved paths.
        match self.staged_paths(intent, deadline) {
            Ok(paths) => {
                if let Some(path) = paths
                    .into_iter()
                    .find(|path| !intent.paths.iter().any(|approved| approved.path == *path))
                {
                    return Ok(self.record(
                        intent,
                        HostGitStage::Stage,
                        HostGitOutcome::Rejected {
                            reason: HostGitRefusal::UnexpectedIndexEntry { path },
                        },
                        None,
                        HostGitGateOutcome::NotRun,
                        hooks_digest,
                        HostGitIndexState::ApprovedPathsStaged,
                        Some(stage.termination),
                    ));
                }
            }
            Err(StepFailure::Refused(refusal)) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    Some(stage.termination),
                ));
            }
            Err(StepFailure::Unknown {
                reason,
                termination,
            }) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Stage,
                    HostGitOutcome::Unknown { reason },
                    None,
                    HostGitGateOutcome::NotRun,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    termination,
                ));
            }
        }

        // 8. The approved common staged-document gate. It is never skipped.
        let gate_deadline = match intent.gate.timeout() {
            Some(gate_timeout) => deadline.min(Instant::now() + gate_timeout),
            None => deadline,
        };
        let gate = match self.run(intent, gate_deadline, self.gate_request(intent)) {
            Ok(executed) => executed,
            Err(StopBeforeSpawn) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Gate,
                    HostGitOutcome::Unknown {
                        reason: HostGitUnknown::Stopped,
                    },
                    None,
                    HostGitGateOutcome::Stopped,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    None,
                ));
            }
        };
        let gate_outcome = match gate.verdict() {
            Verdict::Success => HostGitGateOutcome::Passed,
            Verdict::Failed => HostGitGateOutcome::Failed,
            Verdict::Unknown(HostGitUnknown::Timeout) => HostGitGateOutcome::TimedOut,
            Verdict::Unknown(HostGitUnknown::Stopped) => HostGitGateOutcome::Stopped,
            Verdict::Unknown(_) => HostGitGateOutcome::Unconfirmed,
        };
        match gate.verdict() {
            Verdict::Success => {}
            Verdict::Failed if gate.spawn_error.is_some() => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Gate,
                    HostGitOutcome::Rejected {
                        reason: HostGitRefusal::SpawnFailed {
                            detail: gate.detail(),
                        },
                    },
                    None,
                    gate_outcome,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    Some(gate.termination),
                ));
            }
            Verdict::Failed => {
                let refusal = HostGitRefusal::GateFailed {
                    exit_code: gate.termination.exit_code,
                    detail: gate.detail(),
                };
                return Ok(self.record(
                    intent,
                    HostGitStage::Gate,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    gate_outcome,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    Some(gate.termination),
                ));
            }
            Verdict::Unknown(reason) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Gate,
                    HostGitOutcome::Unknown { reason },
                    None,
                    gate_outcome,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    Some(gate.termination),
                ));
            }
        }
        let gate_termination = gate.termination;

        // 9. Commit the index with the approved message on stdin. Repository
        // hooks run; `--no-verify` is never passed.
        let commit = match self.run(intent, deadline, self.commit_request(intent)?) {
            Ok(executed) => executed,
            Err(StopBeforeSpawn) => {
                return Ok(self.record(
                    intent,
                    HostGitStage::Commit,
                    HostGitOutcome::Unknown {
                        reason: HostGitUnknown::Stopped,
                    },
                    None,
                    gate_outcome,
                    hooks_digest,
                    HostGitIndexState::ApprovedPathsStaged,
                    Some(gate_termination),
                ));
            }
        };
        match commit.verdict() {
            Verdict::Success => {}
            Verdict::Failed if commit.spawn_error.is_some() => {
                let index = self.classify_index(intent, deadline);
                return Ok(self.record(
                    intent,
                    HostGitStage::Commit,
                    HostGitOutcome::Rejected {
                        reason: HostGitRefusal::SpawnFailed {
                            detail: commit.detail(),
                        },
                    },
                    None,
                    gate_outcome,
                    hooks_digest,
                    index,
                    Some(commit.termination),
                ));
            }
            Verdict::Failed => {
                let refusal = HostGitRefusal::CommitFailed {
                    exit_code: commit.termination.exit_code,
                    detail: commit.detail(),
                };
                let index = self.classify_index(intent, deadline);
                return Ok(self.record(
                    intent,
                    HostGitStage::Commit,
                    HostGitOutcome::Rejected { reason: refusal },
                    None,
                    gate_outcome,
                    hooks_digest,
                    index,
                    Some(commit.termination),
                ));
            }
            Verdict::Unknown(reason) => {
                let observed = self.observe_commit(intent, deadline).ok();
                let index = self.classify_index(intent, deadline);
                return Ok(self.record(
                    intent,
                    HostGitStage::Commit,
                    HostGitOutcome::Unknown { reason },
                    observed,
                    gate_outcome,
                    hooks_digest,
                    index,
                    Some(commit.termination),
                ));
            }
        }

        // 10. Observe the created commit and verify branch, parent, tree, and
        // paths. This is where an unexpected Git operation is detected.
        match self.verify_created_commit(intent, deadline) {
            Ok(observation) => Ok(self.record(
                intent,
                HostGitStage::Observe,
                HostGitOutcome::Committed {
                    commit: observation.commit.clone(),
                    tree: observation.tree.clone(),
                    parent: observation.parent.clone(),
                },
                Some(observation),
                gate_outcome,
                hooks_digest,
                HostGitIndexState::Committed,
                Some(commit.termination),
            )),
            Err(StepFailure::Refused(_)) => {
                // The commit process exited successfully but the resulting
                // objects could not be read, so the content is unverified.
                let observed = self.observe_commit(intent, deadline).ok();
                Ok(self.record(
                    intent,
                    HostGitStage::Observe,
                    HostGitOutcome::Unknown {
                        reason: HostGitUnknown::HeadUnreadable,
                    },
                    observed,
                    gate_outcome,
                    hooks_digest,
                    HostGitIndexState::Unknown,
                    Some(commit.termination),
                ))
            }
            Err(StepFailure::Unknown {
                reason,
                termination,
            }) => Ok(self.record(
                intent,
                HostGitStage::Observe,
                HostGitOutcome::Unknown { reason },
                None,
                gate_outcome,
                hooks_digest,
                HostGitIndexState::Unknown,
                termination.or(Some(commit.termination)),
            )),
        }
    }

    /// Reports the repository state for a recorded intent without changing Git.
    fn observe(
        &mut self,
        intent: &HostGitIntent,
        authorization: &HostGitAuthorization,
        deadline: Instant,
    ) -> HostGitReport {
        if let Err(refusal) = verify_identity(intent, authorization) {
            return self.record(
                intent,
                HostGitStage::Verify,
                HostGitOutcome::Rejected { reason: refusal },
                None,
                HostGitGateOutcome::NotRun,
                None,
                HostGitIndexState::Unknown,
                None,
            );
        }
        let hooks_digest = verify_worktree(intent)
            .ok()
            .and_then(|value| value.hooks_digest);
        let index = self.classify_index(intent, deadline);
        let observed = self.observe_commit(intent, deadline).ok();
        let outcome = match &observed {
            Some(observation) if observation.parent == intent.expected_parent => {
                HostGitOutcome::Committed {
                    commit: observation.commit.clone(),
                    tree: observation.tree.clone(),
                    parent: observation.parent.clone(),
                }
            }
            Some(_) => HostGitOutcome::Unknown {
                reason: HostGitUnknown::UnexpectedBranchMovement,
            },
            None => HostGitOutcome::Unknown {
                reason: HostGitUnknown::HeadUnreadable,
            },
        };
        self.record(
            intent,
            HostGitStage::Observe,
            outcome,
            observed,
            HostGitGateOutcome::NotRun,
            hooks_digest,
            index,
            None,
        )
    }

    /// Persists and returns a report.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        intent: &HostGitIntent,
        stage: HostGitStage,
        outcome: HostGitOutcome,
        observed: Option<HostGitCommitObservation>,
        gate: HostGitGateOutcome,
        hooks_digest: Option<String>,
        index_state: HostGitIndexState,
        termination: Option<HostGitTermination>,
    ) -> HostGitReport {
        let mut report = HostGitReport {
            stage,
            outcome,
            observed,
            gate,
            hooks_digest,
            index_state,
            termination,
            result_recorded: false,
        };
        let events = vec![self.event(
            intent,
            HOST_GIT_FINISHED_EVENT_KIND,
            &serde_json::json!({
                "formatVersion": 1,
                "actor": "host",
                "observation": "result",
                "requestId": intent.request_id,
                "purpose": intent.purpose,
                "taskNumber": intent.task_number,
                "approvalId": intent.approval_id,
                "approvalRevision": intent.approval_revision,
                "branch": intent.branch,
                "expectedParent": intent.expected_parent.as_str(),
                "expectedTree": intent.expected_tree.as_ref().map(GitObjectId::as_str),
                "report": report_record(&report),
            }),
        )];
        match self
            .audit
            .record_result(intent, intent.activity_id(), &report, events)
        {
            Ok(()) => {
                report.result_recorded = true;
                report
            }
            Err(_) => {
                // Git and the durable record are not one transaction. The H4
                // journal only sees what was persisted, so an unrecorded result
                // is always reported as unknown: the caller must reconcile
                // instead of acting on a value the journal cannot confirm.
                // Nothing is rolled back, and the observation is retained.
                report.outcome = HostGitOutcome::Unknown {
                    reason: HostGitUnknown::AuditWriteFailed,
                };
                report.result_recorded = false;
                report
            }
        }
    }

    fn event(&self, intent: &HostGitIntent, kind: &str, payload: &serde_json::Value) -> EventDraft {
        EventDraft::for_host_activity(
            intent.project_id,
            EventKind::new(HOST_GIT_ACTIVITY_KIND)
                .expect("the host Git activity kind is non-empty"),
            intent.activity_id(),
            EventKind::new(kind).expect("the host Git event kind is non-empty"),
            Timestamp::now(),
            EventPayload::new(payload.clone()),
        )
        .expect("the host activity identifiers are project-bound")
    }

    // -- process helpers ----------------------------------------------------

    /// Runs one managed process group under the shared supervisor.
    fn run(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
        request: ArgvRequest,
    ) -> Result<Executed, StopBeforeSpawn> {
        let Some(gate) = self.supervisor.begin_spawn() else {
            return Err(StopBeforeSpawn);
        };
        let mut child = match self.launcher.spawn_argv(&request) {
            Ok(child) => child,
            Err(error) => {
                drop(gate);
                // A process that was never created cannot have a side effect, so
                // this is a refusal rather than an unknown result.
                return Ok(Executed {
                    termination: HostGitTermination {
                        pid: 0,
                        pgid: 0,
                        stop_status: ShellStopStatus::Unconfirmed,
                        exit_code: None,
                        terminating_signal: None,
                        confirmed: false,
                    },
                    stdout: String::new(),
                    stderr: String::new(),
                    spawn_error: Some(format!("{:?}", spawn_failure(&error))),
                });
            }
        };
        let pid = child.pid();
        let pgid = pid;
        let lease =
            self.supervisor
                .register(ManagedOwner::HostActivity(intent.activity_id()), pid, pgid);
        drop(gate);
        let _lease = lease;

        let stdout = CaptureHandle::start(child.take_stdout(), self.output_limit);
        let stderr = CaptureHandle::start(child.take_stderr(), self.output_limit);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = if remaining.is_zero() {
            Duration::from_nanos(1)
        } else {
            remaining
        };
        let completion = supervise(
            &mut child,
            pgid,
            self.supervisor,
            Some(timeout),
            self.timeout_grace,
            self.confirm_timeout,
        );
        let stdout = stdout.wait(self.capture_timeout);
        let stderr = stderr.wait(self.capture_timeout);
        Ok(Executed {
            termination: HostGitTermination {
                pid,
                pgid,
                stop_status: completion.stop_status(),
                exit_code: completion.exit_code(),
                terminating_signal: completion.terminating_signal(),
                confirmed: completion.confirmed(),
            },
            stdout: stdout.text().to_owned(),
            stderr: stderr.text().to_owned(),
            spawn_error: None,
        })
    }

    fn stage_request(&self, intent: &HostGitIntent) -> ArgvRequest {
        let mut args = vec!["add".to_owned(), "--".to_owned()];
        args.extend(intent.paths.iter().map(|path| path.path.clone()));
        self.argv(intent, args)
    }

    fn gate_request(&self, intent: &HostGitIntent) -> ArgvRequest {
        let mut request = ArgvRequest::new(
            intent.gate.program.as_str(),
            intent.gate.args.clone(),
            intent.checkout_root.clone(),
        )
        .expect("the gate program is a validated absolute path");
        for (key, value) in git_environment() {
            request = request
                .with_env(key, value)
                .expect("the fixed environment entries are valid");
        }
        request
    }

    fn commit_request(&self, intent: &HostGitIntent) -> Result<ArgvRequest, HostGitError> {
        // `--cleanup=whitespace` keeps every trailer line, `--file -` reads the
        // message from stdin so it never appears in the process table, and no
        // `--no-verify` is ever passed.
        let args = vec![
            "commit".to_owned(),
            "--file".to_owned(),
            "-".to_owned(),
            "--cleanup=whitespace".to_owned(),
        ];
        Ok(self
            .argv(intent, args)
            .with_stdin(intent.message.render().into_bytes()))
    }

    fn argv(&self, intent: &HostGitIntent, args: Vec<String>) -> ArgvRequest {
        let mut request = ArgvRequest::new(
            self.git_program.as_str(),
            args,
            intent.checkout_root.clone(),
        )
        .expect("the Git program is a validated absolute path");
        for (key, value) in git_environment() {
            request = request
                .with_env(key, value)
                .expect("the fixed environment entries are valid");
        }
        if let Some(actor) = intent.actor() {
            for key in ["GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"] {
                request = request
                    .with_env(key, actor.name())
                    .expect("a validated actor name is a valid value");
            }
            for key in ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"] {
                request = request
                    .with_env(key, actor.email())
                    .expect("a validated actor e-mail is a valid value");
            }
        }
        request
    }

    fn read_only(
        &mut self,
        intent: &HostGitIntent,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Executed, StepFailure> {
        match self.run(intent, deadline, self.argv(intent, args)) {
            Ok(executed) => Ok(executed),
            Err(StopBeforeSpawn) => Err(StepFailure::Refused(
                HostGitRefusal::StoppedBeforeSideEffect,
            )),
        }
    }

    /// Paths currently staged in the index, in Git order.
    fn staged_paths(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<Vec<String>, StepFailure> {
        let executed = self.read_only(
            intent,
            vec![
                "diff".to_owned(),
                "--cached".to_owned(),
                "--name-only".to_owned(),
                "--no-renames".to_owned(),
                "-z".to_owned(),
            ],
            deadline,
        )?;
        match executed.verdict() {
            Verdict::Success => Ok(split_nul(&executed.stdout)),
            Verdict::Failed => Err(StepFailure::Refused(HostGitRefusal::ObjectUnreadable {
                name: "index",
                detail: executed.detail(),
            })),
            Verdict::Unknown(reason) => Err(StepFailure::Unknown {
                reason,
                termination: Some(executed.termination),
            }),
        }
    }

    /// Best-effort classification of the index for the report.
    fn classify_index(&mut self, intent: &HostGitIntent, deadline: Instant) -> HostGitIndexState {
        match self.staged_paths(intent, deadline) {
            Ok(paths) if paths.is_empty() => HostGitIndexState::Clean,
            Ok(paths)
                if paths
                    .iter()
                    .all(|path| intent.paths.iter().any(|approved| approved.path == *path)) =>
            {
                HostGitIndexState::ApprovedPathsStaged
            }
            Ok(_) => HostGitIndexState::Unknown,
            Err(_) => HostGitIndexState::Unknown,
        }
    }

    /// Resolves the current HEAD commit, when the repository has one.
    fn head_commit(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<GitObjectId, StepFailure> {
        let executed = self.read_only(
            intent,
            vec![
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "--quiet".to_owned(),
                "HEAD^{commit}".to_owned(),
            ],
            deadline,
        )?;
        match executed.verdict() {
            Verdict::Success => {
                let value = executed.stdout.trim();
                GitObjectId::parse(value).map_err(|_| StepFailure::Unknown {
                    reason: HostGitUnknown::HeadUnreadable,
                    termination: Some(executed.termination),
                })
            }
            Verdict::Failed => Err(StepFailure::Refused(HostGitRefusal::ObjectUnreadable {
                name: "HEAD",
                detail: executed.detail(),
            })),
            Verdict::Unknown(reason) => Err(StepFailure::Unknown {
                reason,
                termination: Some(executed.termination),
            }),
        }
    }

    /// Observes the commit that HEAD points at, without claiming it is the
    /// approved one.
    fn observe_commit(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<HostGitCommitObservation, StepFailure> {
        let commit = self.head_commit(intent, deadline)?;
        let tree = self.rev_parse(intent, "HEAD^{tree}", "HEAD tree", deadline)?;
        let parent = self.rev_parse(intent, "HEAD^{commit}^", "HEAD parent", deadline)?;
        Ok(HostGitCommitObservation {
            commit,
            tree,
            parent,
        })
    }

    fn rev_parse(
        &mut self,
        intent: &HostGitIntent,
        spec: &str,
        name: &'static str,
        deadline: Instant,
    ) -> Result<GitObjectId, StepFailure> {
        let executed = self.read_only(
            intent,
            vec![
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "--quiet".to_owned(),
                spec.to_owned(),
            ],
            deadline,
        )?;
        match executed.verdict() {
            Verdict::Success => {
                GitObjectId::parse(executed.stdout.trim()).map_err(|_| StepFailure::Unknown {
                    reason: HostGitUnknown::HeadUnreadable,
                    termination: Some(executed.termination),
                })
            }
            Verdict::Failed => Err(StepFailure::Refused(HostGitRefusal::ObjectUnreadable {
                name,
                detail: executed.detail(),
            })),
            Verdict::Unknown(reason) => Err(StepFailure::Unknown {
                reason,
                termination: Some(executed.termination),
            }),
        }
    }

    /// Verifies the commit the host just created.
    fn verify_created_commit(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<HostGitCommitObservation, StepFailure> {
        let observation = self.observe_commit(intent, deadline)?;
        if observation.parent != intent.expected_parent {
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::UnexpectedBranchMovement,
                termination: None,
            });
        }
        if let Some(expected) = intent.expected_tree()
            && observation.tree != *expected
        {
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::ContentMismatch,
                termination: None,
            });
        }
        let branch = self.current_branch(intent, deadline)?;
        if branch.as_deref() != Some(intent.branch.as_str()) {
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::UnexpectedBranchMovement,
                termination: None,
            });
        }
        let changed = self.changed_paths(intent, deadline)?;
        if changed
            .iter()
            .any(|path| !intent.paths.iter().any(|approved| approved.path == *path))
        {
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::UnexpectedPaths,
                termination: None,
            });
        }
        if intent
            .paths
            .iter()
            .any(|approved| !changed.iter().any(|path| path == &approved.path))
        {
            // A hook may have reverted or filtered an approved path; the commit
            // does not carry the approved content, so it is not a success.
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::ContentMismatch,
                termination: None,
            });
        }
        if !self.staged_paths(intent, deadline)?.is_empty() {
            return Err(StepFailure::Unknown {
                reason: HostGitUnknown::UnexpectedPaths,
                termination: None,
            });
        }
        Ok(observation)
    }

    fn current_branch(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<Option<String>, StepFailure> {
        let executed = self.read_only(
            intent,
            vec![
                "symbolic-ref".to_owned(),
                "--quiet".to_owned(),
                "--short".to_owned(),
                "HEAD".to_owned(),
            ],
            deadline,
        )?;
        match executed.verdict() {
            Verdict::Success => Ok(Some(executed.stdout.trim().to_owned())),
            Verdict::Failed => Ok(None),
            Verdict::Unknown(reason) => Err(StepFailure::Unknown {
                reason,
                termination: Some(executed.termination),
            }),
        }
    }

    fn changed_paths(
        &mut self,
        intent: &HostGitIntent,
        deadline: Instant,
    ) -> Result<Vec<String>, StepFailure> {
        let executed = self.read_only(
            intent,
            vec![
                "diff-tree".to_owned(),
                "--no-commit-id".to_owned(),
                "--name-only".to_owned(),
                "--no-renames".to_owned(),
                "-r".to_owned(),
                "-z".to_owned(),
                "HEAD".to_owned(),
            ],
            deadline,
        )?;
        match executed.verdict() {
            Verdict::Success => Ok(split_nul(&executed.stdout)),
            Verdict::Failed => Err(StepFailure::Refused(HostGitRefusal::ObjectUnreadable {
                name: "HEAD diff",
                detail: executed.detail(),
            })),
            Verdict::Unknown(reason) => Err(StepFailure::Unknown {
                reason,
                termination: Some(executed.termination),
            }),
        }
    }
}

/// Why a read-only or verification step stopped.
enum StepFailure {
    Refused(HostGitRefusal),
    Unknown {
        reason: HostGitUnknown,
        termination: Option<HostGitTermination>,
    },
}

// ---------------------------------------------------------------------------
// Value verification
// ---------------------------------------------------------------------------

/// Verifies the authorization and the request identity as values only.
fn verify_identity(
    intent: &HostGitIntent,
    authorization: &HostGitAuthorization,
) -> Result<(), HostGitRefusal> {
    if authorization.project_id != intent.project_id {
        return Err(HostGitRefusal::CrossProject {
            authorized: authorization.project_id,
            requested: intent.project_id,
        });
    }
    if authorization.approval_id != intent.approval_id {
        return Err(HostGitRefusal::NotAuthorized {
            detail: "the authorization covers another approval".to_owned(),
        });
    }
    if authorization.approval_revision != intent.approval_revision {
        return Err(HostGitRefusal::ApprovalRevisionMismatch {
            authorized: authorization.approval_revision,
            requested: intent.approval_revision,
        });
    }
    if authorization.checkout_root != intent.checkout_root {
        return Err(HostGitRefusal::CheckoutRejected {
            detail: "the authorization covers another checkout root".to_owned(),
        });
    }
    if authorization.branch != intent.branch {
        return Err(HostGitRefusal::BranchMismatch {
            expected: authorization.branch.clone(),
            found: intent.branch.clone(),
        });
    }
    if intent.purpose.trim().is_empty() {
        return Err(HostGitRefusal::InvalidField {
            field: "purpose",
            detail: "must not be empty".to_owned(),
        });
    }
    validate_token("requestId", &intent.request_id)?;
    validate_token("executionRef", &intent.execution_ref)?;
    validate_text("taskLabel", &intent.task_label)?;
    if intent.task_number == 0 {
        return Err(HostGitRefusal::InvalidField {
            field: "taskNumber",
            detail: "must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

/// What the worktree verification observed.
struct WorktreeVerification {
    hooks_digest: Option<String>,
}

/// Verifies the checkout root, branch, HEAD, hook configuration, and each
/// path's form, bytes, and digest.
///
/// This reads the worktree and the Git ref files only. It never spawns a
/// process and never writes anything, so every refusal here has zero side
/// effects and zero process spawns.
fn verify_worktree(intent: &HostGitIntent) -> Result<WorktreeVerification, HostGitRefusal> {
    let root = intent.checkout_root.as_path();
    let canonical = fs::canonicalize(root).map_err(|_| HostGitRefusal::CheckoutRejected {
        detail: "the checkout root does not exist".to_owned(),
    })?;
    if canonical.as_path() != root {
        return Err(HostGitRefusal::CheckoutRejected {
            detail: "the checkout root is not the canonical path".to_owned(),
        });
    }
    if !canonical.is_dir() {
        return Err(HostGitRefusal::CheckoutRejected {
            detail: "the checkout root is not a directory".to_owned(),
        });
    }

    let repository = Repository::locate(&canonical)?;
    match repository.branch()? {
        BranchState::Named(name) if name == intent.branch => {}
        BranchState::Named(found) => {
            return Err(HostGitRefusal::BranchMismatch {
                expected: intent.branch.clone(),
                found,
            });
        }
        BranchState::Detached => {
            return Err(HostGitRefusal::BranchMismatch {
                expected: intent.branch.clone(),
                found: "detached".to_owned(),
            });
        }
    }
    match repository.head()? {
        Some(head) if head == intent.expected_parent => {}
        Some(found) => {
            return Err(HostGitRefusal::ParentMismatch {
                expected: intent.expected_parent.clone(),
                found,
            });
        }
        None => {
            return Err(HostGitRefusal::ParentMismatch {
                expected: intent.expected_parent.clone(),
                found: GitObjectId::parse("0".repeat(40)).expect("a zero object name is valid"),
            });
        }
    }

    for path in &intent.paths {
        let joined = canonical.join(path.path());
        let metadata = fs::symlink_metadata(&joined).map_err(|_| HostGitRefusal::PathRejected {
            path: path.path.clone(),
            detail: "does not exist in the checkout".to_owned(),
        })?;
        if metadata.file_type().is_symlink() {
            // A symbolic link is refused rather than silently staged as its
            // target, which could live outside the approved checkout.
            return Err(HostGitRefusal::PathRejected {
                path: path.path.clone(),
                detail: "must not be a symbolic link".to_owned(),
            });
        }
        if !metadata.is_file() {
            return Err(HostGitRefusal::PathRejected {
                path: path.path.clone(),
                detail: "is not a regular file".to_owned(),
            });
        }
        let resolved = fs::canonicalize(&joined).map_err(|_| HostGitRefusal::PathRejected {
            path: path.path.clone(),
            detail: "cannot be resolved".to_owned(),
        })?;
        if !resolved.starts_with(&canonical) {
            return Err(HostGitRefusal::PathRejected {
                path: path.path.clone(),
                detail: "resolves outside the checkout".to_owned(),
            });
        }
        let bytes = fs::read(&joined).map_err(|_| HostGitRefusal::PathRejected {
            path: path.path.clone(),
            detail: "cannot be read".to_owned(),
        })?;
        if bytes.len() as u64 != path.bytes {
            return Err(HostGitRefusal::LengthMismatch {
                path: path.path.clone(),
                expected: path.bytes,
                found: bytes.len() as u64,
            });
        }
        let found = digest_of(&bytes);
        if found != path.digest {
            return Err(HostGitRefusal::ContentMismatch {
                path: path.path.clone(),
                expected: path.digest.clone(),
                found,
            });
        }
    }

    Ok(WorktreeVerification {
        hooks_digest: Some(repository.hooks_digest()?),
    })
}

// ---------------------------------------------------------------------------
// Git ref reading
// ---------------------------------------------------------------------------

/// Digest of the hook configuration the next commit in `checkout_root` would
/// run.
///
/// The H4 execution journal records this value before it stages anything, so a
/// hook that changed between the recorded intent and the commit is a refusal
/// rather than a silently different validation. It reads only the repository
/// configuration and the `pre-commit` hook bytes; it spawns nothing.
pub fn hooks_configuration_digest(checkout_root: &AbsolutePath) -> Result<String, HostGitRefusal> {
    Repository::locate(checkout_root.as_path())?.hooks_digest()
}

/// The per-worktree and common Git directories of one checkout.
#[derive(Debug, Clone)]
struct Repository {
    root: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
}

/// The branch part of HEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BranchState {
    /// HEAD points at `refs/heads/<name>`.
    Named(String),
    /// HEAD holds a raw object name.
    Detached,
}

impl Repository {
    /// Locates `.git` without invoking Git.
    fn locate(root: &Path) -> Result<Self, HostGitRefusal> {
        let dot_git = root.join(".git");
        let metadata =
            fs::symlink_metadata(&dot_git).map_err(|_| HostGitRefusal::CheckoutRejected {
                detail: "the checkout root is not a Git working tree".to_owned(),
            })?;
        let git_dir = if metadata.is_dir() {
            dot_git
        } else if metadata.is_file() {
            let text =
                fs::read_to_string(&dot_git).map_err(|_| HostGitRefusal::CheckoutRejected {
                    detail: "the .git file cannot be read".to_owned(),
                })?;
            let target = text
                .trim()
                .strip_prefix("gitdir:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| HostGitRefusal::CheckoutRejected {
                    detail: "the .git file has an unknown format".to_owned(),
                })?;
            let path = Path::new(target);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        } else {
            return Err(HostGitRefusal::CheckoutRejected {
                detail: "the checkout root has no usable .git entry".to_owned(),
            });
        };
        let git_dir = fs::canonicalize(&git_dir).map_err(|_| HostGitRefusal::CheckoutRejected {
            detail: "the Git directory does not exist".to_owned(),
        })?;
        let common_dir = match fs::read_to_string(git_dir.join("commondir")) {
            Ok(text) if !text.trim().is_empty() => {
                let path = Path::new(text.trim());
                let joined = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    git_dir.join(path)
                };
                fs::canonicalize(&joined).map_err(|_| HostGitRefusal::CheckoutRejected {
                    detail: "the Git common directory does not exist".to_owned(),
                })?
            }
            _ => git_dir.clone(),
        };
        Ok(Self {
            root: root.to_path_buf(),
            git_dir,
            common_dir,
        })
    }

    /// Reads `.git/HEAD`.
    fn head_file(&self) -> Result<String, HostGitRefusal> {
        fs::read_to_string(self.git_dir.join("HEAD")).map_err(|_| {
            HostGitRefusal::CheckoutRejected {
                detail: "the Git HEAD file cannot be read".to_owned(),
            }
        })
    }

    /// The branch HEAD points at, or a detached marker.
    fn branch(&self) -> Result<BranchState, HostGitRefusal> {
        let head = self.head_file()?;
        let trimmed = head.trim();
        match trimmed.strip_prefix("ref:") {
            Some(reference) => {
                let reference = reference.trim();
                let name = reference.strip_prefix("refs/heads/").ok_or_else(|| {
                    HostGitRefusal::CheckoutRejected {
                        detail: "HEAD does not point at a local branch".to_owned(),
                    }
                })?;
                Ok(BranchState::Named(name.to_owned()))
            }
            None => {
                if trimmed.len() == 40 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    Ok(BranchState::Detached)
                } else {
                    Err(HostGitRefusal::CheckoutRejected {
                        detail: "the Git HEAD file has an unknown format".to_owned(),
                    })
                }
            }
        }
    }

    /// Resolves the commit HEAD names, when the branch has one.
    fn head(&self) -> Result<Option<GitObjectId>, HostGitRefusal> {
        match self.branch()? {
            BranchState::Detached => {
                let head = self.head_file()?;
                GitObjectId::parse(head.trim()).map(Some).map_err(|_| {
                    HostGitRefusal::CheckoutRejected {
                        detail: "the detached HEAD name is not a SHA-1 object name".to_owned(),
                    }
                })
            }
            BranchState::Named(name) => {
                let reference = format!("refs/heads/{name}");
                match self.resolve_ref(&reference)? {
                    Some(value) => Ok(Some(value)),
                    None => {
                        // An unborn branch cannot be the approved parent.
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Resolves one reference from the loose files and `packed-refs`.
    fn resolve_ref(&self, reference: &str) -> Result<Option<GitObjectId>, HostGitRefusal> {
        for base in [&self.git_dir, &self.common_dir] {
            let path = base.join(reference);
            if let Ok(text) = fs::read_to_string(&path) {
                let value = text.trim();
                if let Ok(id) = GitObjectId::parse(value) {
                    return Ok(Some(id));
                }
                return Err(HostGitRefusal::CheckoutRejected {
                    detail: "a loose reference is not a SHA-1 object name".to_owned(),
                });
            }
        }
        let packed = self.common_dir.join("packed-refs");
        let Ok(text) = fs::read_to_string(&packed) else {
            return Ok(None);
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            let mut parts = line.splitn(2, ' ');
            let Some(object) = parts.next() else {
                continue;
            };
            let Some(name) = parts.next() else {
                continue;
            };
            if name.trim() != reference {
                continue;
            }
            return GitObjectId::parse(object).map(Some).map_err(|_| {
                HostGitRefusal::CheckoutRejected {
                    detail: "a packed reference is not a SHA-1 object name".to_owned(),
                }
            });
        }
        Ok(None)
    }

    /// Digest of the hook configuration the next commit would run.
    ///
    /// It covers the repository's `core.hooksPath` declaration and the
    /// `pre-commit` hook bytes, so a host can bind an approval to the hook it
    /// observed. A hook directory configured outside the repository by host-wide
    /// Git configuration is not part of this digest; see the module docs.
    fn hooks_digest(&self) -> Result<String, HostGitRefusal> {
        let (hooks_path, hook_bytes) = self.hook_configuration();
        let mut hasher = Sha256::new();
        hasher.update(b"herness.host-git.hooks\0");
        hasher.update(hooks_path.as_bytes());
        hasher.update(b"\0pre-commit\0");
        match hook_bytes {
            Some(bytes) => hasher.update(&bytes),
            None => hasher.update(b"absent"),
        }
        Ok(digest_of(&hasher.finalize()))
    }

    fn hook_configuration(&self) -> (String, Option<Vec<u8>>) {
        let config = self.common_dir.join("config");
        let mut hooks_path = String::from("hooks");
        if let Ok(text) = fs::read_to_string(&config) {
            let mut in_core = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') {
                    in_core = trimmed.eq_ignore_ascii_case("[core]");
                    continue;
                }
                if !in_core {
                    continue;
                }
                if let Some(value) = trimmed.strip_prefix("hooksPath")
                    && let Some(value) = value.trim_start().strip_prefix('=')
                {
                    hooks_path = value.trim().to_owned();
                }
            }
        }
        let hooks_dir = {
            // Git resolves a relative `core.hooksPath` against the working tree
            // root, not against the Git directory.
            let path = Path::new(&hooks_path);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                self.root.join(path)
            }
        };
        let hook = hooks_dir.join("pre-commit");
        let bytes = match fs::metadata(&hook) {
            Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_HOOK_FILE_BYTES => {
                fs::read(&hook).ok()
            }
            _ => None,
        };
        (hooks_path, bytes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn git_environment() -> Vec<(&'static str, &'static str)> {
    vec![
        // Never wait for interactive credentials; there is no network command.
        ("GIT_TERMINAL_PROMPT", "0"),
        // Stable, parseable output.
        ("LC_ALL", "C"),
        // No editor or pager can start inside a managed group.
        ("GIT_PAGER", "cat"),
        ("PAGER", "cat"),
        ("GIT_EDITOR", "true"),
    ]
}

fn split_nul(value: &str) -> Vec<String> {
    value
        .split('\0')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn digest_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{hex}")
}

fn validate_digest(value: &str) -> Result<String, HostGitRefusal> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(HostGitRefusal::InvalidField {
            field: "digest",
            detail: "must use the 'sha256:<hex>' form".to_owned(),
        });
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HostGitRefusal::InvalidField {
            field: "digest",
            detail: "must carry 64 hexadecimal characters".to_owned(),
        });
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}

/// Validates human-readable, non-secret single-line text.
fn validate_text(field: &'static str, value: &str) -> Result<(), HostGitRefusal> {
    if value.trim().is_empty() || value.len() > 512 {
        return Err(HostGitRefusal::InvalidField {
            field,
            detail: "must be non-empty trimmed text of at most 512 bytes".to_owned(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(HostGitRefusal::InvalidField {
            field,
            detail: "must not contain control characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), HostGitRefusal> {
    if value.is_empty() || value.len() > 512 {
        return Err(HostGitRefusal::InvalidField {
            field,
            detail: "must be non-empty and at most 512 bytes".to_owned(),
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@' | b'/')
    }) {
        return Err(HostGitRefusal::InvalidField {
            field,
            detail: "must contain only identifier characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<(), HostGitRefusal> {
    let invalid = |detail: &str| HostGitRefusal::InvalidField {
        field: "branch",
        detail: detail.to_owned(),
    };
    if branch.trim().is_empty() {
        return Err(invalid("must not be empty"));
    }
    if branch == "HEAD" || branch == "@" {
        return Err(invalid("must name a branch"));
    }
    if branch.starts_with('-')
        || branch.contains("..")
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with(".lock")
    {
        return Err(invalid("is not a valid Git branch name"));
    }
    if branch
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid("is not a valid Git branch name"));
    }
    if branch
        .chars()
        .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Err(invalid("is not a valid Git branch name"));
    }
    if branch
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid("is not a valid Git branch name"));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), HostGitRefusal> {
    let invalid = |detail: &str| HostGitRefusal::InvalidField {
        field: "path",
        detail: detail.to_owned(),
    };
    if path.trim().is_empty() {
        return Err(invalid("must not be empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(invalid("must be at most 4096 bytes"));
    }
    if path.contains('\0') || path.contains('\\') {
        return Err(invalid("must not contain NUL or a backslash"));
    }
    if path.starts_with('-') {
        return Err(invalid("must not start with '-'"));
    }
    if Path::new(path).is_absolute() {
        return Err(invalid("must be project-relative"));
    }
    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => return Err(invalid("must not contain '.'")),
            Component::ParentDir => return Err(invalid("must not contain '..'")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid("must be project-relative"));
            }
        }
    }
    Ok(())
}

fn validate_canonical_absolute(field: &'static str, value: &str) -> Result<(), HostGitRefusal> {
    let invalid = |detail: &str| HostGitRefusal::InvalidField {
        field,
        detail: detail.to_owned(),
    };
    if value.trim().is_empty() {
        return Err(invalid("must not be empty"));
    }
    if value.contains('\0') {
        return Err(invalid("must not contain NUL"));
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(invalid("must be an absolute path"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(invalid("must not contain '..' or '.'"));
    }
    Ok(())
}

/// Bounded, single-line, control-character-free excerpt of process output.
fn bounded_excerpt(value: &str) -> String {
    let mut text = String::new();
    for character in value.chars() {
        if character.is_control() {
            if character == '\n' || character == '\t' {
                text.push(' ');
            }
            continue;
        }
        text.push(character);
        if text.len() >= MAX_ERROR_EXCERPT {
            break;
        }
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "no output".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn an_argv_request_requires_an_absolute_program() {
        let cwd = AbsolutePath::new("/tmp").expect("absolute");
        assert!(ArgvRequest::new("git", Vec::new(), cwd.clone()).is_err());
        assert!(ArgvRequest::new("", Vec::new(), cwd.clone()).is_err());
        assert!(ArgvRequest::new("/usr/bin/git", Vec::new(), cwd).is_ok());
    }

    #[test]
    fn an_argv_request_never_goes_through_a_shell() {
        let root = std::env::temp_dir().join(format!(
            "herness-host-git-argv-{}-{}",
            std::process::id(),
            Timestamp::now().as_unix_millis()
        ));
        fs::create_dir_all(&root).expect("temporary directory");
        let cwd = AbsolutePath::new(root.to_string_lossy().into_owned()).expect("absolute");
        let marker = root.join("pwned");
        let tricky = format!("name;touch {}", marker.display());
        let request = ArgvRequest::new(
            "/bin/sh".to_owned(),
            vec![
                "-c".to_owned(),
                "printf '%s' \"$1\" > out".to_owned(),
                "sh".to_owned(),
                tricky.clone(),
            ],
            cwd,
        )
        .expect("request");
        let mut launcher = SystemArgvLauncher;
        let mut child = launcher.spawn_argv(&request).expect("spawn");
        let supervisor = ProcessSupervisor::new();
        let pid = child.pid();
        supervise(
            &mut child,
            pid,
            &supervisor,
            Some(Duration::from_secs(10)),
            DEFAULT_TIMEOUT_GRACE,
            DEFAULT_CONFIRM_TIMEOUT,
        );
        // The child received the metacharacters as one literal argv entry and
        // did not execute the embedded command.
        assert!(
            !marker.exists(),
            "the shell metacharacters must stay literal"
        );
        let out = fs::read_to_string(root.join("out")).expect("output file");
        assert_eq!(out, tricky);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_authorization_cannot_be_built_except_from_a_human_approval() {
        let project = ProjectId::new();
        let root = AbsolutePath::new("/tmp").expect("absolute");
        for approver in [HostGitApprover::Model, HostGitApprover::OwnerKind] {
            let approval = HostCommitApproval::new(
                project,
                "approval-1",
                1,
                approver,
                root.clone(),
                "main",
                true,
                true,
            )
            .expect("value");
            assert!(approval.authorize().is_err());
        }
        let approval = HostCommitApproval::new(
            project,
            "approval-1",
            1,
            HostGitApprover::Human,
            root,
            "main",
            true,
            true,
        )
        .expect("value");
        let authorization = approval.authorize().expect("human approval");
        assert_eq!(authorization.project_id(), project);
        assert_eq!(authorization.approval_revision(), 1);
    }

    #[test]
    fn a_trailer_key_must_not_be_repeated_and_paths_must_be_relative() {
        let lens = |key: &str| HostGitTrailer::new(key, "6").expect("trailer");
        assert!(
            HostGitMessage::new("subject", vec![lens("Herness-Task"), lens("Herness-Task")])
                .is_err()
        );
        assert!(HostGitMessage::new("subject", Vec::new()).is_err());
        assert!(HostGitMessage::new("two\nlines", vec![lens("Herness-Task")]).is_err());
        assert!(HostGitPath::new("..", 0, format!("sha256:{}", "0".repeat(64))).is_err());
        assert!(HostGitPath::new("/abs", 0, format!("sha256:{}", "0".repeat(64))).is_err());
        assert!(HostGitPath::new("ok/path.rs", 0, format!("sha256:{}", "0".repeat(64))).is_ok());
    }

    #[test]
    fn the_commit_timeout_ceiling_is_the_approved_budget() {
        assert_eq!(HOST_COMMIT_TIMEOUT, Duration::from_secs(30));
        let gate = HostGitGate::new(
            AbsolutePath::new("/bin/sh").expect("absolute"),
            Vec::new(),
            None,
        )
        .expect("gate");
        let intent = |timeout: Duration| {
            HostGitIntent::new(
                ProjectId::new(),
                "request-1",
                Purpose::new("budget").expect("purpose"),
                "execution-1",
                6,
                "Task label",
                "approval-1",
                1,
                AbsolutePath::new("/tmp").expect("absolute"),
                "main",
                GitObjectId::parse("a".repeat(40)).expect("parent"),
                None,
                vec![
                    HostGitPath::new("a.txt", 0, format!("sha256:{}", "0".repeat(64)))
                        .expect("path"),
                ],
                HostGitMessage::new(
                    "subject",
                    vec![HostGitTrailer::new("Herness-Task", "6").expect("trailer")],
                )
                .expect("message"),
                gate.clone(),
                timeout,
                None,
            )
        };
        assert!(intent(Duration::from_secs(30)).is_ok());
        assert!(intent(Duration::from_secs(31)).is_err());
        assert!(intent(Duration::ZERO).is_err());
    }
}
