//! Desktop host-commit adapter: the real `HostGitPort` and checkout observation.
//!
//! This module is the only desktop bridge between H4's
//! [`finalize_task`](herness_sdd_execute::finalize_task) decision and real Git.
//! It has two halves:
//!
//! * **The boundary.** [`HostGitCommitBoundary`] implements H4's
//!   [`HostGitPort`] over `herness_core`'s [`HostGitBoundary`]. It converts one
//!   recorded [`GitJournalEntry`] into the boundary's intent — the same explicit
//!   paths, bytes, digests, message, trailers, expected parent/tree, gate, and
//!   hook digest the journal holds — and turns the boundary's report back into a
//!   [`GitCommitOutcome`]. It never widens the path list, never passes
//!   `--no-verify`, and never resets or re-commits.
//! * **The observation.** [`GitCheckoutObserver`] reads branch, HEAD, tree,
//!   parent, the commit message, the index, and the exact bytes of each
//!   requested path with fixed argv. It is read-only: `git status` runs with
//!   `--no-optional-locks`, and nothing stages, commits, checks out, or writes.
//!
//! # Authorization
//!
//! The boundary's [`HostGitAuthorization`] is minted **only** here, from the
//! approved [`CommitAuthorization`] on the request plus the approved checkout,
//! branch, and approval identity. It is never read from a string, a model
//! request, a preview, or a tool payload: `HostCommitApproval::authorize`
//! refuses a non-human approver, an unapproved host commit, and an unapproved
//! hook run, and this module passes exactly the approved boolean pair.
//!
//! # What a refusal means
//!
//! A boundary refusal is a [`GitRejection`]: an unclean index, an unexpected
//! index entry, or a worktree content mismatch is an unrelated change; another
//! branch, parent, or checkout is a concurrent edit; a changed hook
//! configuration, a failed common gate, or a failed commit is a hook failure. A
//! timeout, stop, unconfirmed group, unreadable object, or unexpected branch,
//! tree, or path movement is `GitCommitOutcome::Unknown` and waits for a human.

use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use herness_core::{
    AbsolutePath, GitObjectId, HOST_COMMIT_TIMEOUT, HostCommitApproval, HostGitActor,
    HostGitApprover, HostGitAuditPort, HostGitAuthorization, HostGitBoundary, HostGitGate,
    HostGitIntent, HostGitMessage, HostGitOutcome, HostGitPath, HostGitRefusal, HostGitReport,
    HostGitTrailer, HostGitUnknown, Purpose, SystemArgvLauncher, hooks_configuration_digest,
};
use herness_sdd_execute::{
    CommitAuthorization, CommitObservation, CommitObservationPort, CommitRecovery, CommitSha,
    CommitTarget, FailureDetails, GitCommitIntent, GitCommitOutcome, GitJournalEntry, GitRejection,
    GitUnknownReason, HostGitPort, ObservationRequest, ObservedPath, Sha256Digest, TargetOrigin,
    TreeSha, classify_commit,
};

use crate::sdd_execute::crash::{self, CrashPoint};
use crate::sdd_execute::git::GitRunner;

/// `unavailable` feature prefix used for a failed host commit.
pub const HOST_COMMIT_FEATURE: &str = "sdd_execute.hostCommit";

/// `unavailable` feature prefix used for a failed checkout observation.
pub const HOST_COMMIT_OBSERVE_FEATURE: &str = "sdd_execute.hostCommitObserve";

/// The approved identity and checkout one Task commit runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCommitIdentity {
    project_id: herness_core::ProjectId,
    approval_id: String,
    approval_revision: u64,
    execution_ref: String,
    checkout_root: AbsolutePath,
    branch: String,
    actor: HostGitActor,
}

impl ApprovedCommitIdentity {
    /// Records the approved host-commit facts.
    pub fn new(
        project_id: herness_core::ProjectId,
        approval_id: impl Into<String>,
        approval_revision: u64,
        execution_ref: impl Into<String>,
        checkout_root: AbsolutePath,
        branch: impl Into<String>,
        actor: HostGitActor,
    ) -> Result<Self, herness_sdd_execute::SddExecutionError> {
        let approval_id = approval_id.into();
        if approval_id.trim().is_empty() {
            return Err(herness_sdd_execute::SddExecutionError::InvalidValue {
                field: "commit.approvalId".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if approval_revision == 0 {
            return Err(herness_sdd_execute::SddExecutionError::InvalidValue {
                field: "commit.approvalRevision".to_owned(),
                detail: "must be greater than zero".to_owned(),
            });
        }
        let execution_ref = execution_ref.into();
        if execution_ref.trim().is_empty() {
            return Err(herness_sdd_execute::SddExecutionError::InvalidValue {
                field: "commit.executionRef".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        let branch = branch.into();
        if branch.trim().is_empty() {
            return Err(herness_sdd_execute::SddExecutionError::InvalidValue {
                field: "commit.branch".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self {
            project_id,
            approval_id,
            approval_revision,
            execution_ref,
            checkout_root,
            branch,
            actor,
        })
    }

    /// Project that owns the approved checkout.
    pub const fn project_id(&self) -> herness_core::ProjectId {
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

    /// Execution reference recorded on the host activity.
    pub fn execution_ref(&self) -> &str {
        &self.execution_ref
    }

    /// Checkout the commit runs in.
    pub const fn checkout_root(&self) -> &AbsolutePath {
        &self.checkout_root
    }

    /// Approved implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Approved Git author and committer.
    pub const fn actor(&self) -> &HostGitActor {
        &self.actor
    }
}

/// A [`HostGitPort`] over `herness_core`'s host Git boundary.
///
/// The type owns the boundary and the approved identity. The H4 journal — not
/// this type — decides whether a second attempt is allowed, and nothing here
/// can widen the recorded path list.
pub struct HostGitCommitBoundary<L = SystemArgvLauncher, A = herness_core::RecordingHostGitAudit> {
    boundary: Mutex<HostGitBoundary<L, A>>,
    identity: ApprovedCommitIdentity,
    gate: HostGitGate,
}

impl<L, A> HostGitCommitBoundary<L, A> {
    /// Creates the adapter over one boundary, identity, and approved gate.
    pub fn new(
        boundary: HostGitBoundary<L, A>,
        identity: ApprovedCommitIdentity,
        gate: HostGitGate,
    ) -> Self {
        Self {
            boundary: Mutex::new(boundary),
            identity,
            gate,
        }
    }

    /// The approved identity.
    pub const fn identity(&self) -> &ApprovedCommitIdentity {
        &self.identity
    }

    /// The approved staged-document gate every commit runs.
    pub const fn gate(&self) -> &HostGitGate {
        &self.gate
    }

    /// The wrapped boundary, for reading the audit sink.
    pub fn boundary(&self) -> std::sync::MutexGuard<'_, HostGitBoundary<L, A>> {
        self.boundary
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn authorization(
        &self,
        approval: CommitAuthorization,
    ) -> Result<HostGitAuthorization, herness_sdd_execute::SddExecutionError> {
        HostCommitApproval::new(
            self.identity.project_id,
            self.identity.approval_id.clone(),
            self.identity.approval_revision,
            HostGitApprover::Human,
            self.identity.checkout_root.clone(),
            self.identity.branch.clone(),
            approval.host_commit(),
            approval.run_hooks(),
        )
        .map_err(|refusal| unavailable(HOST_COMMIT_FEATURE, &refusal.to_string()))?
        .authorize()
        .map_err(|refusal| unavailable(HOST_COMMIT_FEATURE, &refusal.to_string()))
    }

    fn intent(
        &self,
        entry: &GitJournalEntry,
    ) -> Result<HostGitIntent, herness_sdd_execute::SddExecutionError> {
        let intent = entry.intent();
        let message = HostGitMessage::new(
            intent.message().subject(),
            intent
                .message()
                .trailers()
                .iter()
                .map(|trailer| {
                    HostGitTrailer::new(trailer.key(), trailer.value())
                        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        let paths = intent
            .paths()
            .iter()
            .map(|path| {
                let digest = path.digest().ok_or_else(|| {
                    unavailable(
                        HOST_COMMIT_FEATURE,
                        "every committed path needs the exact content digest",
                    )
                })?;
                HostGitPath::new(path.path(), path.bytes(), digest.as_str())
                    .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let purpose = Purpose::new(format!(
            "commit Task {} through the approved host Git boundary",
            intent.task().number().get()
        ))
        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        let timeout = Duration::from_secs(intent.timeout_seconds()).min(HOST_COMMIT_TIMEOUT);
        let expected_parent = GitObjectId::parse(intent.expected_parent().as_str())
            .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        let expected_tree = match intent.expected_tree() {
            Some(tree) => Some(
                GitObjectId::parse(tree.as_str())
                    .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?,
            ),
            None => None,
        };
        let intent = HostGitIntent::new(
            intent.task().project_id(),
            entry.identity().request_id().to_string(),
            purpose,
            self.identity.execution_ref.clone(),
            intent.task().number().get(),
            format!("Task {}", intent.task().number().get()),
            self.identity.approval_id.clone(),
            self.identity.approval_revision,
            self.identity.checkout_root.clone(),
            intent.branch(),
            expected_parent,
            expected_tree,
            paths,
            message,
            self.gate.clone(),
            timeout,
            intent
                .pre_hook()
                .hooks_config_digest()
                .map(|digest| digest.as_str().to_owned()),
        )
        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        Ok(intent.with_actor(self.identity.actor.clone()))
    }
}

impl<L, A> HostGitPort for HostGitCommitBoundary<L, A>
where
    L: herness_core::ArgvLauncher,
    A: HostGitAuditPort,
{
    fn commit(
        &mut self,
        entry: &GitJournalEntry,
        authorization: CommitAuthorization,
    ) -> Result<GitCommitOutcome, herness_sdd_execute::SddExecutionError> {
        let authorization = self.authorization(authorization)?;
        let intent = self.intent(entry)?;
        // The journal intent is durable before this call. A crash here leaves a
        // recorded intent and no Git process, which recovery reports as unknown.
        crash::hit(CrashPoint::BeforeHostCommit);
        let report = self
            .boundary()
            .commit(&intent, &authorization)
            .map_err(|error| {
                // The boundary only errors when its own intent could not be
                // persisted, and then it started no Git process at all.
                unavailable(HOST_COMMIT_FEATURE, &error.to_string())
            })?;
        // The real commit exists here. The H4 journal result is recorded by the
        // caller after this returns, so a crash at this point leaves an
        // established commit with no result to attach to it.
        crash::hit(CrashPoint::AfterHostCommit);
        Ok(outcome_from_report(&report))
    }

    fn observe(
        &mut self,
        entry: &GitJournalEntry,
    ) -> Result<GitCommitOutcome, herness_sdd_execute::SddExecutionError> {
        // Observing never stages or commits, but the boundary still requires an
        // approval value that matches the recorded intent.
        let approval = CommitAuthorization::new(true, true)
            .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
        let authorization = self.authorization(approval)?;
        let intent = self.intent(entry)?;
        let report = self.boundary().observe(&intent, &authorization);
        Ok(outcome_from_report(&report))
    }
}

/// Maps one boundary report onto the H4 outcome without inventing a value.
pub fn outcome_from_report(report: &HostGitReport) -> GitCommitOutcome {
    match report.outcome() {
        HostGitOutcome::Committed {
            commit,
            tree,
            parent,
        } => match (
            CommitSha::parse(commit.as_str()),
            TreeSha::parse(tree.as_str()),
            CommitSha::parse(parent.as_str()),
        ) {
            (Ok(commit), Ok(tree), Ok(parent)) => GitCommitOutcome::Committed {
                commit,
                tree,
                parent,
            },
            _ => GitCommitOutcome::Unknown {
                reason: GitUnknownReason::HeadUnreadable,
            },
        },
        HostGitOutcome::Rejected { reason } => GitCommitOutcome::Rejected {
            reason: rejection_of(reason),
        },
        HostGitOutcome::Unknown { reason } => GitCommitOutcome::Unknown {
            reason: unknown_of(*reason),
        },
    }
}

/// Maps one H1 refusal onto H4's recorded rejection class.
pub fn rejection_of(refusal: &HostGitRefusal) -> GitRejection {
    match refusal {
        HostGitRefusal::IndexNotClean
        | HostGitRefusal::UnexpectedIndexEntry { .. }
        | HostGitRefusal::ContentMismatch { .. }
        | HostGitRefusal::LengthMismatch { .. }
        | HostGitRefusal::PathRejected { .. } => GitRejection::UnrelatedChanges,
        HostGitRefusal::ParentMismatch { .. }
        | HostGitRefusal::BranchMismatch { .. }
        | HostGitRefusal::CheckoutRejected { .. } => GitRejection::ConcurrentEdit,
        HostGitRefusal::HookConfigurationChanged { .. }
        | HostGitRefusal::GateFailed { .. }
        | HostGitRefusal::CommitFailed { .. } => GitRejection::HookFailed,
        HostGitRefusal::MessageRejected { .. } => GitRejection::MessageRejected,
        HostGitRefusal::StoppedBeforeSideEffect => GitRejection::StoppedBeforeSideEffect,
        // Everything else refused the request before any commit could exist: a
        // bad field, another approval, an unreadable object, or a process that
        // never started.
        HostGitRefusal::NotAuthorized { .. }
        | HostGitRefusal::ApprovalRevisionMismatch { .. }
        | HostGitRefusal::CrossProject { .. }
        | HostGitRefusal::InvalidField { .. }
        | HostGitRefusal::StagingFailed { .. }
        | HostGitRefusal::ObjectUnreadable { .. }
        | HostGitRefusal::SpawnFailed { .. } => GitRejection::StagingFailed,
    }
}

/// Maps one H1 unknown reason onto H4's recorded reason.
pub const fn unknown_of(unknown: HostGitUnknown) -> GitUnknownReason {
    match unknown {
        HostGitUnknown::Timeout => GitUnknownReason::Timeout,
        HostGitUnknown::Stopped => GitUnknownReason::Stopped,
        HostGitUnknown::UnobservedProcess => GitUnknownReason::UnobservedProcess,
        HostGitUnknown::AuditWriteFailed => GitUnknownReason::JournalWriteFailed,
        HostGitUnknown::HeadUnreadable => GitUnknownReason::HeadUnreadable,
        // A commit that exists with another tree, branch, or path set is not a
        // result the host can confirm; a human reconciles it.
        HostGitUnknown::ContentMismatch
        | HostGitUnknown::UnexpectedBranchMovement
        | HostGitUnknown::UnexpectedPaths => GitUnknownReason::UnobservedProcess,
    }
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

/// Read-only checkout observation over [`GitRunner`].
///
/// It reads the branch, HEAD, tree, parent, commit message, index, and exact
/// bytes of each requested path, and nothing else. A path outside the checkout
/// root, a symlink, or a directory is reported absent rather than read, so a
/// commit can never be confirmed from content the approved checkout does not
/// hold.
pub struct GitCheckoutObserver<L = SystemArgvLauncher> {
    runner: Mutex<GitRunner<L>>,
    checkout_root: AbsolutePath,
}

impl<L> GitCheckoutObserver<L> {
    /// Creates the observer over one checkout.
    pub fn new(runner: GitRunner<L>, checkout_root: AbsolutePath) -> Self {
        Self {
            runner: Mutex::new(runner),
            checkout_root,
        }
    }

    /// The observed checkout root.
    pub const fn checkout_root(&self) -> &AbsolutePath {
        &self.checkout_root
    }

    /// The locked Git runner.
    pub(crate) fn runner(&self) -> std::sync::MutexGuard<'_, GitRunner<L>> {
        self.runner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<L: herness_core::ArgvLauncher> CommitObservationPort for GitCheckoutObserver<L> {
    fn observe(
        &mut self,
        request: &ObservationRequest,
    ) -> Result<CommitObservation, herness_sdd_execute::SddExecutionError> {
        let root = self.checkout_root.as_str().to_owned();
        let (branch, head, tree, parent, message, status) = {
            let mut runner = self.runner();
            let branch = runner.current_branch(&root)?;
            let head = runner.head(&root)?;
            let tree = match &head {
                Some(_) => runner.rev_parse_tree(&root, "HEAD^{tree}")?,
                None => None,
            };
            let parent = match &head {
                Some(_) => runner.rev_parse_commit(&root, "HEAD^{commit}^")?,
                None => None,
            };
            let message = match &head {
                Some(_) => runner.commit_message(&root)?,
                None => String::new(),
            };
            let status = runner.status(&root)?;
            (branch, head, tree, parent, message, status)
        };

        let staged = status
            .entries()
            .iter()
            .filter(|entry| entry.index() != ' ' && entry.index() != '?')
            .map(|entry| entry.path().to_owned())
            .collect::<Vec<_>>();
        let mut tracked = Vec::with_capacity(request.paths().len());
        for path in request.paths() {
            tracked.push(ObservedPath::new(
                path.clone(),
                read_confined(self.checkout_root.as_path(), path)?,
            ));
        }
        Ok(CommitObservation::new(
            request.project_id(),
            branch,
            head,
            tree,
            parent,
            message,
            status.index_clean(),
            staged,
            tracked,
        ))
    }
}

/// Reads one project-relative path confined to `root`.
///
/// A missing path, a directory, a symlink, or a path that resolves outside the
/// root is `Ok(None)`: the observer reports absence instead of following it.
fn read_confined(
    root: &Path,
    relative: &str,
) -> Result<Option<Sha256Digest>, herness_sdd_execute::SddExecutionError> {
    let joined = root.join(relative);
    let metadata = match fs::symlink_metadata(&joined) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(unavailable(
                HOST_COMMIT_OBSERVE_FEATURE,
                &format!("{relative} cannot be inspected: {}", error.kind()),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }
    let resolved = match fs::canonicalize(&joined) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(unavailable(
                HOST_COMMIT_OBSERVE_FEATURE,
                &format!("{relative} cannot be resolved: {}", error.kind()),
            ));
        }
    };
    if !resolved.starts_with(root) {
        return Ok(None);
    }
    let bytes = fs::read(&joined).map_err(|error| {
        unavailable(
            HOST_COMMIT_OBSERVE_FEATURE,
            &format!("{relative} cannot be read: {}", error.kind()),
        )
    })?;
    Ok(Some(Sha256Digest::sha256(&bytes)))
}

// ---------------------------------------------------------------------------
// Derived artifacts and recovery helpers
// ---------------------------------------------------------------------------

/// The verified derived artifacts of one Task, taken from the barrier.
///
/// A companion or receipt is committed only when the barrier verified that
/// exact document at that exact revision, so an unrelated file that merely looks
/// like H3 output is never staged.
pub fn verified_derived_targets(
    documents: &[(String, Vec<u8>)],
) -> Result<Vec<CommitTarget>, herness_sdd_execute::SddExecutionError> {
    let mut targets = Vec::with_capacity(documents.len());
    for (path, bytes) in documents {
        let origin = if path.ends_with(".html") {
            TargetOrigin::HtmlCompanion
        } else {
            TargetOrigin::HtmlReceipt
        };
        targets.push(CommitTarget::for_bytes(path.clone(), bytes, origin)?);
    }
    targets.sort_by(|left, right| left.path().cmp(right.path()));
    Ok(targets)
}

/// Classifies a saved intent against one observation, for the recovery surface.
///
/// It mutates nothing: Task 20 calls it, shows the classification, and links a
/// commit to the ledger only after the human confirms.
pub fn recovery_of(intent: &GitCommitIntent, observation: &CommitObservation) -> CommitRecovery {
    classify_commit(intent, observation)
}

/// Classifies a saved intent and its recorded outcome, so a moved checkout is
/// `Unknown` instead of `Established`.
pub fn recovery_with_result(
    intent: &GitCommitIntent,
    recorded: Option<&GitCommitOutcome>,
    observation: &CommitObservation,
) -> CommitRecovery {
    herness_sdd_execute::classify_recorded(intent, recorded, observation)
}

/// The hook digest of the approved checkout, recorded in the intent before the
/// commit.
pub fn checkout_hooks_digest(
    checkout_root: &AbsolutePath,
) -> Result<Sha256Digest, herness_sdd_execute::SddExecutionError> {
    let digest = hooks_configuration_digest(checkout_root)
        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))?;
    Sha256Digest::parse(digest)
        .map_err(|error| unavailable(HOST_COMMIT_FEATURE, &error.to_string()))
}

fn unavailable(feature: &str, detail: &str) -> herness_sdd_execute::SddExecutionError {
    herness_sdd_execute::SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}
