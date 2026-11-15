//! The host-owned H4 start-approval registry and its idempotent start records.
//!
//! # What this module owns
//!
//! * [`StartApprovalRegistry`] records one immutable [`ExecutionApproval`]
//!   revision after the *trusted human path* confirms the exact current inputs,
//!   and returns only the newest revision as the current approval. A revision
//!   strictly increases for one approval identity; an identical re-post is a
//!   no-op that returns the stored revision, and a different value for an
//!   already recorded revision is refused.
//! * [`ApprovalInputs`] is the host's *observation* of the current inputs the
//!   approval binds: plan bytes and digest, parsed result, spec and external
//!   source snapshots, pack fingerprint, checkout and Git identity, every
//!   Task's conditions, scope, checks, HTML targets and budget, the execution
//!   connection, profile and per-purpose consent, the host commit and hook
//!   authorization, and the H3 settings boundary. [`StartApprovalRegistry::verify_current`]
//!   compares the current approval with that observation and returns a typed
//!   refusal instead of ever re-approving a stale value silently.
//! * [`StartRecord`] is the crash-safe start marker. It is written before
//!   workspace preparation and before any child starts, so a re-delivered start
//!   request returns the stored result, and an attempt that stopped between
//!   "starting" and "started" is reported as recovery instead of creating a
//!   second child.
//!
//! # What may approve
//!
//! Only an [`ApprovalActor::Human`] actor and an
//! [`ApprovalSource::ApprovalRegistry`] source naming the same approval identity
//! are accepted. Environment variables, repository documents, HTML meta,
//! receipts, request actors, owner kinds, model requests, and H3 configuration
//! approvals are rejected with [`ApprovalRejection::ForbiddenSource`]. An H3
//! approval is never an H4 start approval, and [`ExecutionApproval`] itself
//! repeats the same check, so a forged or re-used source cannot pass either
//! gate.
//!
//! This module performs no I/O. A store implements
//! [`ApprovalRevisionStorePort`] and [`StartRecordStorePort`]; the desktop
//! composition supplies the real store, the workspace adapter, and the one
//! start boundary.

use std::collections::BTreeMap;

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_supervision::{ApprovalActor, BudgetPolicy, ConsentBinding, ProfileBinding};
use serde::{Deserialize, Serialize};

use crate::approval::{
    ApprovalContent, ApprovalSource, CommitAuthorization, ExecutionApproval, ExecutionConnection,
    H3ApprovalBinding, PlanApproval, TaskApproval, WorkspaceApproval,
};
use crate::error::{ApprovalRejection, SddExecutionError};
use crate::ids::{ApprovalId, ControlRequestId, ExecutionId, TaskRef};
use crate::state::{ApprovalRequirement, ConflictReason, RecoveryReason};
use crate::version::Sha256Digest;

/// Format version of one stored start record.
pub const START_RECORD_FORMAT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Persistence ports
// ---------------------------------------------------------------------------

/// Durable storage for immutable execution-approval revisions.
///
/// Implementations must refuse to replace a recorded revision and must refuse
/// to record a revision that does not strictly advance the newest one. The
/// registry repeats both rules, so a store that already enforces them and one
/// that only stores bytes behave the same at this boundary.
pub trait ApprovalRevisionStorePort {
    /// Records one revision exactly once.
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError>;

    /// Loads one exact revision.
    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError>;

    /// Loads the newest recorded revision.
    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError>;

    /// Loads every recorded revision in ascending order.
    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError>;
}

/// Durable storage for the crash-safe start record of one request.
pub trait StartRecordStorePort {
    /// Loads the record for one request, if any.
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError>;

    /// Loads the one start record for one Task, whatever request created it.
    ///
    /// This is what makes "one child per Task" hold across re-delivered
    /// requests: a second request ID for an already started Task is refused
    /// instead of creating a second child. Implementations that cannot index by
    /// Task fail closed by returning the most recently written record they can
    /// observe, never by reporting `None`.
    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError>;

    /// Writes a record whose key already exists only when its phase does not go
    /// backwards and its started result is not replaced.
    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError>;
}

/// In-memory approval store for single-process composition and tests.
#[derive(Debug, Default, Clone)]
pub struct MemoryApprovalRevisionStore {
    revisions: BTreeMap<(ProjectId, ApprovalId), Vec<ExecutionApproval>>,
}

impl MemoryApprovalRevisionStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ApprovalRevisionStorePort for MemoryApprovalRevisionStore {
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        let key = (approval.project_id(), approval.approval_id());
        let recorded = self.revisions.entry(key).or_default();
        if let Some(stored) = recorded
            .iter()
            .find(|stored| stored.revision() == approval.revision())
        {
            if stored == approval {
                return Ok(());
            }
            return Err(duplicate_revision(approval));
        }
        if recorded
            .last()
            .is_some_and(|last| approval.revision() <= last.revision())
        {
            return Err(duplicate_revision(approval));
        }
        recorded.push(approval.clone());
        Ok(())
    }

    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Ok(self
            .revisions
            .get(&(project_id, approval_id))
            .and_then(|recorded| {
                recorded
                    .iter()
                    .find(|stored| stored.revision() == revision)
                    .cloned()
            }))
    }

    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Ok(self
            .revisions
            .get(&(project_id, approval_id))
            .and_then(|recorded| recorded.last().cloned()))
    }

    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        Ok(self
            .revisions
            .get(&(project_id, approval_id))
            .cloned()
            .unwrap_or_default())
    }
}

/// In-memory start-record store for single-process composition and tests.
#[derive(Debug, Default, Clone)]
pub struct MemoryStartRecordStore {
    records: BTreeMap<(ProjectId, ExecutionId, ControlRequestId), StartRecord>,
}

impl MemoryStartRecordStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl StartRecordStorePort for MemoryStartRecordStore {
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        Ok(self
            .records
            .get(&(project_id, execution_id, request_id))
            .cloned())
    }

    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        Ok(self
            .records
            .iter()
            .filter(|((stored_project, stored_execution, _), _)| {
                *stored_project == project_id && *stored_execution == execution_id
            })
            .map(|(_, record)| record)
            .find(|record| record.task() == task)
            .cloned())
    }

    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError> {
        let key = (
            record.project_id(),
            record.execution_id(),
            record.request_id(),
        );
        if let Some(stored) = self.records.get(&key) {
            stored.ensure_advance(record)?;
            if stored == record {
                return Ok(());
            }
        }
        self.records.insert(key, record.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Observed current inputs
// ---------------------------------------------------------------------------

/// The execution connection, profile, and consents as observed right now.
///
/// Unlike [`ExecutionConnection`], this value may carry an empty consent list
/// so a revoked consent is representable and refused with the disclosure
/// requirement instead of failing to build an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedConnection {
    connection_id: ConnectionId,
    profile: ProfileBinding,
    consents: Vec<ConsentBinding>,
}

impl ObservedConnection {
    /// Records the live connection, profile, and granted consents.
    pub const fn new(
        connection_id: ConnectionId,
        profile: ProfileBinding,
        consents: Vec<ConsentBinding>,
    ) -> Self {
        Self {
            connection_id,
            profile,
            consents,
        }
    }

    /// Records the currently granted consents for one approved connection.
    pub fn from_approved(connection: &ExecutionConnection, consents: Vec<ConsentBinding>) -> Self {
        Self {
            connection_id: connection.connection_id(),
            profile: connection.profile(),
            consents,
        }
    }

    /// H1 execution connection.
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Fixed H2 assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Consents that are granted right now.
    pub fn consents(&self) -> &[ConsentBinding] {
        &self.consents
    }

    /// Whether `approved` consent is currently granted with the same version.
    fn grants(&self, approved: &ConsentBinding) -> bool {
        self.consents.iter().any(|current| {
            current.consent_id() == approved.consent_id()
                && current.version() == approved.version()
                && current.purpose() == approved.purpose()
        })
    }
}

/// The host's observation of every input one approval binds.
///
/// The desktop composition builds it from a real preview, the live workspace
/// state, the stored plan revision, the live connection/profile/consent
/// configuration, and the live H3 settings. Passing it to
/// [`StartApprovalRegistry::verify_current`] is what prevents an approval from
/// being applied to different bytes, a different checkout, or a weaker
/// condition set.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalInputs {
    plan: PlanApproval,
    workspace: WorkspaceApproval,
    tasks: Vec<TaskApproval>,
    connection: ObservedConnection,
    commit: CommitAuthorization,
    h3: Option<H3ApprovalBinding>,
}

impl ApprovalInputs {
    /// Records the observed current inputs.
    pub fn new(
        plan: PlanApproval,
        workspace: WorkspaceApproval,
        tasks: Vec<TaskApproval>,
        connection: ObservedConnection,
        commit: CommitAuthorization,
        h3: Option<H3ApprovalBinding>,
    ) -> Self {
        Self {
            plan,
            workspace,
            tasks,
            connection,
            commit,
            h3,
        }
    }

    /// Observed plan inputs.
    pub fn plan(&self) -> &PlanApproval {
        &self.plan
    }

    /// Observed workspace identity.
    pub fn workspace(&self) -> &WorkspaceApproval {
        &self.workspace
    }

    /// Observed Task contracts.
    pub fn tasks(&self) -> &[TaskApproval] {
        &self.tasks
    }

    /// Observed connection, profile, and granted consents.
    pub fn connection(&self) -> &ObservedConnection {
        &self.connection
    }

    /// Observed host commit and hook authorization.
    pub const fn commit(&self) -> CommitAuthorization {
        self.commit
    }

    /// Observed H3 boundary, absent when H3 settings are not approved.
    pub fn h3(&self) -> Option<&H3ApprovalBinding> {
        self.h3.as_ref()
    }

    /// Project the observation belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.workspace.project_id()
    }

    /// Compares the observed inputs with one approved content.
    ///
    /// Every mismatch is a typed refusal. Nothing here changes an approval or
    /// writes a record.
    pub fn verify(&self, approved: &ApprovalContent) -> Result<(), SddExecutionError> {
        let project = approved.workspace().project_id();
        if self.workspace.project_id() != project {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        self.verify_plan(approved.plan())?;
        self.verify_workspace(approved.workspace())?;
        self.verify_tasks(approved.tasks())?;
        self.verify_connection(approved.connection())?;
        self.verify_commit(approved.commit())?;
        self.verify_h3(approved.h3())?;
        Ok(())
    }

    fn verify_plan(&self, approved: &PlanApproval) -> Result<(), SddExecutionError> {
        let observed = &self.plan;
        if approved.plan_path() != observed.plan_path() {
            return Err(changed("plan.path"));
        }
        if approved.digest() != observed.digest() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::PlanDigestMismatch {
                    expected: approved.digest().clone(),
                    found: observed.digest().clone(),
                },
            });
        }
        if approved.byte_length() != observed.byte_length() {
            return Err(changed("plan.byteLength"));
        }
        if approved.plan_revision() != observed.plan_revision() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::PlanRevisionMismatch {
                    expected: approved.plan_revision(),
                    found: observed.plan_revision(),
                },
            });
        }
        if approved.parsed() != observed.parsed() {
            return Err(changed("plan.parsed"));
        }
        if approved.spec_refs() != observed.spec_refs() {
            return Err(changed("plan.specRefs"));
        }
        if approved.sources() != observed.sources() {
            return Err(changed("plan.sources"));
        }
        if approved.pack() != observed.pack() {
            return Err(changed("plan.pack"));
        }
        Ok(())
    }

    fn verify_workspace(&self, approved: &WorkspaceApproval) -> Result<(), SddExecutionError> {
        let observed = &self.workspace;
        let mismatch = |field: &str| SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch {
                field: field.to_owned(),
            },
        };
        if approved.project_id() != observed.project_id() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        if approved.canonical_checkout_root() != observed.canonical_checkout_root() {
            return Err(mismatch("workspace.canonicalCheckoutRoot"));
        }
        if approved.git_identity() != observed.git_identity() {
            return Err(mismatch("workspace.gitIdentity"));
        }
        if approved.branch() != observed.branch() {
            return Err(mismatch("workspace.branch"));
        }
        if approved.base_branch() != observed.base_branch() {
            return Err(mismatch("workspace.baseBranch"));
        }
        if approved.isolated_worktree() != observed.isolated_worktree() {
            return Err(mismatch("workspace.isolatedWorktree"));
        }
        // The baseline is fixed by the one approved preparation. An approval
        // created before preparation carries `None`; it never authorizes a
        // replacement after a baseline exists.
        if let Some(approved_baseline) = approved.baseline()
            && observed.baseline() != Some(approved_baseline)
        {
            return Err(mismatch("workspace.baseline"));
        }
        Ok(())
    }

    fn verify_tasks(&self, approved: &[TaskApproval]) -> Result<(), SddExecutionError> {
        if approved.len() != self.tasks.len() {
            return Err(changed("approval.tasks"));
        }
        for (approved_task, observed_task) in approved.iter().zip(&self.tasks) {
            let number = approved_task.task().number().get();
            if approved_task.task() != observed_task.task() {
                return Err(changed(&format!("task.{number}.identity")));
            }
            if approved_task.title() != observed_task.title() {
                return Err(changed(&format!("task.{number}.title")));
            }
            if approved_task.conditions() != observed_task.conditions() {
                return Err(changed(&format!("task.{number}.conditions")));
            }
            if approved_task.scope() != observed_task.scope() {
                return Err(changed(&format!("task.{number}.scope")));
            }
            if approved_task.checks() != observed_task.checks() {
                return Err(changed(&format!("task.{number}.checks")));
            }
            if approved_task.html_targets() != observed_task.html_targets() {
                return Err(changed(&format!("task.{number}.htmlTargets")));
            }
            if approved_task.budget() != observed_task.budget() {
                return Err(changed(&format!("task.{number}.budget")));
            }
            if approved_task.commit_policy() != observed_task.commit_policy() {
                return Err(changed(&format!("task.{number}.commitPolicy")));
            }
            if approved_task.deliverables() != observed_task.deliverables() {
                return Err(changed(&format!("task.{number}.deliverables")));
            }
        }
        Ok(())
    }

    fn verify_connection(&self, approved: &ExecutionConnection) -> Result<(), SddExecutionError> {
        let observed = &self.connection;
        if observed.connection_id() != approved.connection_id() {
            return Err(changed("connection.connectionId"));
        }
        if observed.profile() != approved.profile() {
            return Err(changed("connection.profile"));
        }
        for consent in approved.consents() {
            if !observed.grants(consent) {
                return Err(SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::DisclosureConsent,
                    details: crate::error::FailureDetails::none().boxed(),
                });
            }
        }
        Ok(())
    }

    fn verify_commit(&self, approved: CommitAuthorization) -> Result<(), SddExecutionError> {
        if !self.commit.host_commit() || !self.commit.run_hooks() {
            return Err(SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::HostCommit,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
        if self.commit != approved {
            return Err(changed("commit"));
        }
        Ok(())
    }

    fn verify_h3(&self, approved: &H3ApprovalBinding) -> Result<(), SddExecutionError> {
        let Some(observed) = &self.h3 else {
            return Err(SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::H3Settings,
                details: crate::error::FailureDetails::none().boxed(),
            });
        };
        if observed.settings_version() != approved.settings_version() {
            return Err(SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::H3Settings,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
        for consent in approved.consents() {
            if !observed.consents().contains(consent) {
                return Err(SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::H3Settings,
                    details: crate::error::FailureDetails::none().boxed(),
                });
            }
        }
        for capability in approved.capabilities() {
            if !observed.capabilities().contains(capability) {
                return Err(SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::Capability,
                    details: crate::error::FailureDetails::none().boxed(),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// One trusted human post of the exact inputs the human confirmed.
///
/// The constructor verifies that `content` is structurally valid and that it
/// exactly matches `inputs`, so a caller cannot save an approval for bytes it
/// did not observe. Whether the caller is really the human UI is decided by the
/// desktop composition, which mints the single host confirmation before calling
/// [`StartApprovalRegistry::post_human_approval`]; the actor and source checks
/// here are the second gate.
#[derive(Debug, Clone)]
pub struct StartApprovalPost {
    approval_id: ApprovalId,
    approved_at: Timestamp,
    actor: ApprovalActor,
    source: ApprovalSource,
    content: ApprovalContent,
    inputs: ApprovalInputs,
}

impl StartApprovalPost {
    /// Builds one post and proves the content matches the observed inputs.
    pub fn new(
        approval_id: ApprovalId,
        approved_at: Timestamp,
        actor: ApprovalActor,
        source: ApprovalSource,
        content: ApprovalContent,
        inputs: ApprovalInputs,
    ) -> Result<Self, SddExecutionError> {
        if inputs.project_id() != approval_id.project_id() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        content.validate(approval_id.project_id())?;
        inputs.verify(&content)?;
        // `ExecutionApproval::new` repeats both checks; doing it here keeps an
        // unforgeable source out of the store even if a later step changes.
        let probe = ExecutionApproval::new(
            approval_id,
            actor.clone(),
            source.clone(),
            approved_at,
            content.clone(),
        )?;
        debug_assert_eq!(probe.revision(), 1);
        Ok(Self {
            approval_id,
            approved_at,
            actor,
            source,
            content,
            inputs,
        })
    }

    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// When the human confirmed it.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }

    /// Confirming actor.
    pub fn actor(&self) -> &ApprovalActor {
        &self.actor
    }

    /// Approval source.
    pub fn source(&self) -> &ApprovalSource {
        &self.source
    }

    /// Approved content.
    pub fn content(&self) -> &ApprovalContent {
        &self.content
    }

    /// Observed inputs the approval was checked against.
    pub fn inputs(&self) -> &ApprovalInputs {
        &self.inputs
    }
}

/// The host-owned start-approval registry.
#[derive(Debug, Clone)]
pub struct StartApprovalRegistry<S> {
    store: S,
}

impl<S: ApprovalRevisionStorePort> StartApprovalRegistry<S> {
    /// Creates a registry over a durable store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// The backing store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The backing store, for start records.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The current approval of one identity, or `None` when none was saved.
    pub fn current(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        ensure_project(project_id, approval_id.project_id())?;
        self.store.latest_approval_revision(project_id, approval_id)
    }

    /// Every recorded revision of one identity, oldest first.
    pub fn history(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        ensure_project(project_id, approval_id.project_id())?;
        self.store.approval_revisions(project_id, approval_id)
    }

    /// Records the post as the newest approval revision.
    ///
    /// A post whose content equals the current revision is an idempotent no-op
    /// that returns the stored revision. A different content advances the
    /// revision by exactly one; the same revision is never rewritten.
    pub fn post_human_approval(
        &mut self,
        post: &StartApprovalPost,
    ) -> Result<ExecutionApproval, SddExecutionError> {
        let approval_id = post.approval_id;
        let project = approval_id.project_id();
        let latest = self.store.latest_approval_revision(project, approval_id)?;
        let approval = match latest {
            Some(latest) => {
                if latest.content() == post.content() {
                    return Ok(latest);
                }
                latest.revise(
                    post.actor.clone(),
                    post.source.clone(),
                    latest.revision().saturating_add(1),
                    post.approved_at,
                    post.content.clone(),
                )?
            }
            None => ExecutionApproval::new(
                approval_id,
                post.actor.clone(),
                post.source.clone(),
                post.approved_at,
                post.content.clone(),
            )?,
        };
        self.store.record_approval_revision(&approval)?;
        Ok(approval)
    }

    /// Returns the current approval only when it is the expected revision and
    /// still matches the observed inputs.
    ///
    /// * a missing approval is `approval_required`;
    /// * an old revision is `conflict`/`stale_revision`, before any side effect;
    /// * a different project is `approval_rejected`/`other_project`;
    /// * any changed plan, source, pack, workspace, Task, connection, consent,
    ///   commit, budget, or H3 value is a typed refusal from
    ///   [`ApprovalInputs::verify`].
    pub fn verify_current(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        expected_revision: u64,
        inputs: &ApprovalInputs,
    ) -> Result<ExecutionApproval, SddExecutionError> {
        ensure_project(project_id, approval_id.project_id())?;
        if inputs.project_id() != project_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        let Some(current) = self
            .store
            .latest_approval_revision(project_id, approval_id)?
        else {
            return Err(SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: crate::error::FailureDetails::none().boxed(),
            });
        };
        // A forged stored row cannot act as a human approval even if it was
        // written by a buggy adapter.
        if !current.is_human() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ActorNotHuman {
                    actor: "stored approval".to_owned(),
                },
            });
        }
        if !current.is_registry() {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ForbiddenSource {
                    source: current.source().kind(),
                },
            });
        }
        current.content().validate(project_id)?;
        if current.revision() != expected_revision {
            return Err(SddExecutionError::Conflict {
                reason: ConflictReason::StaleRevision,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
        inputs.verify(current.content())?;
        ensure_budgets(current.tasks())?;
        Ok(current)
    }
}

/// Verifies that every approved Task still carries a finite, valid budget.
pub fn ensure_budgets(tasks: &[TaskApproval]) -> Result<(), SddExecutionError> {
    if tasks.is_empty() {
        return Err(SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    for task in tasks {
        task.budget()
            .validate()
            .map_err(|error| SddExecutionError::InvalidValue {
                field: format!("task.{}.budget", task.task().number().get()),
                detail: format!("{error}"),
            })?;
        if task.budget().active_seconds() == 0
            || task.budget().active_seconds() > crate::version::H4_MAX_SUPERVISION_SECONDS
        {
            return Err(SddExecutionError::BudgetExhausted {
                reason: crate::state::BudgetExhaustionReason::ActiveSeconds,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
    }
    Ok(())
}

/// The approved finite budget of one Task, for callers that only need the value.
pub fn task_budget(task: &TaskApproval) -> &BudgetPolicy {
    task.budget()
}

// ---------------------------------------------------------------------------
// Start records
// ---------------------------------------------------------------------------

/// How far one start request got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartPhase {
    /// The request may have prepared the workspace; no child was started.
    PreparingWorkspace,
    /// The one child start may have happened and its result is not recorded.
    Starting,
    /// The start completed and its result is stored.
    Started,
}

impl StartPhase {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreparingWorkspace => "preparing_workspace",
            Self::Starting => "starting",
            Self::Started => "started",
        }
    }
}

/// The stored result of one started child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartReceipt {
    reference: String,
    started: bool,
}

impl StartReceipt {
    /// Records one start result.
    pub fn new(reference: impl Into<String>, started: bool) -> Result<Self, SddExecutionError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "startReceipt.reference".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self { reference, started })
    }

    /// Opaque child or run reference. Never a credential or model text.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Whether a child was started.
    pub const fn started(&self) -> bool {
        self.started
    }
}

/// One crash-safe start record keyed by its start request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRecord {
    format_version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    request_id: ControlRequestId,
    approval_id: ApprovalId,
    approval_revision: u64,
    task: TaskRef,
    fingerprint: Sha256Digest,
    phase: StartPhase,
    #[serde(default)]
    receipt: Option<StartReceipt>,
}

impl StartRecord {
    /// Builds the pre-side-effect record for one request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        approval_id: ApprovalId,
        approval_revision: u64,
        task: TaskRef,
        fingerprint: Sha256Digest,
        phase: StartPhase,
        receipt: Option<StartReceipt>,
    ) -> Result<Self, SddExecutionError> {
        let project_id = execution_id.project_id();
        execution_id.validate_in(project_id)?;
        request_id.validate_in(project_id)?;
        task.ensure_project(project_id)?;
        ensure_project(project_id, approval_id.project_id())?;
        if approval_revision == 0 {
            return Err(SddExecutionError::InvalidValue {
                field: "start.approvalRevision".to_owned(),
                detail: "approval revisions start at one".to_owned(),
            });
        }
        match (phase, &receipt) {
            (StartPhase::Started, Some(_))
            | (StartPhase::PreparingWorkspace | StartPhase::Starting, None) => {}
            _ => {
                return Err(SddExecutionError::InvalidValue {
                    field: "start.receipt".to_owned(),
                    detail: "only a started record carries a result".to_owned(),
                });
            }
        }
        Ok(Self {
            format_version: START_RECORD_FORMAT_VERSION,
            project_id,
            execution_id,
            request_id,
            approval_id,
            approval_revision,
            task,
            fingerprint,
            phase,
            receipt,
        })
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Start request identity.
    pub const fn request_id(&self) -> ControlRequestId {
        self.request_id
    }

    /// Approval identity the start used.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Approval revision the start used.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// First Task the start covers.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Content fingerprint of the start request.
    pub const fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }

    /// Recorded phase.
    pub const fn phase(&self) -> StartPhase {
        self.phase
    }

    /// Stored start result, when the phase is `started`.
    pub fn receipt(&self) -> Option<&StartReceipt> {
        self.receipt.as_ref()
    }

    /// The same record after workspace preparation was confirmed.
    pub fn starting(&self) -> Self {
        let mut next = self.clone();
        next.phase = StartPhase::Starting;
        next
    }

    /// The same record after the one start completed.
    pub fn started(&self, receipt: StartReceipt) -> Self {
        let mut next = self.clone();
        next.phase = StartPhase::Started;
        next.receipt = Some(receipt);
        next
    }

    /// Refuses a write that would move the phase backwards or replace a result.
    pub fn ensure_advance(&self, next: &Self) -> Result<(), SddExecutionError> {
        if self.project_id != next.project_id
            || self.execution_id != next.execution_id
            || self.request_id != next.request_id
            || self.fingerprint != next.fingerprint
        {
            return Err(SddExecutionError::DuplicateRequestConflict {
                recorded: self.fingerprint.to_string(),
                supplied: next.fingerprint.to_string(),
            });
        }
        if next.phase < self.phase {
            return Err(SddExecutionError::DuplicateRequestConflict {
                recorded: self.phase.as_str().to_owned(),
                supplied: next.phase.as_str().to_owned(),
            });
        }
        if self.phase == StartPhase::Started && self.receipt != next.receipt {
            return Err(SddExecutionError::DuplicateResultConflict {
                request: self.request_id.to_string(),
            });
        }
        Ok(())
    }

    /// Recovery refusal for an attempt that may have started a child.
    pub fn unobserved_start(&self) -> SddExecutionError {
        SddExecutionError::RecoveryRequired {
            reason: RecoveryReason::UnknownRequest,
            details: crate::error::FailureDetails::none().boxed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_project(project_id: ProjectId, found: ProjectId) -> Result<(), SddExecutionError> {
    if project_id == found {
        Ok(())
    } else {
        Err(SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::OtherProject,
        })
    }
}

fn changed(field: &str) -> SddExecutionError {
    SddExecutionError::ApprovalRejected {
        reason: ApprovalRejection::CurrentInputsChanged {
            field: field.to_owned(),
        },
    }
}

fn duplicate_revision(approval: &ExecutionApproval) -> SddExecutionError {
    SddExecutionError::DuplicateResultConflict {
        request: format!(
            "{} revision {}",
            approval.approval_id(),
            approval.revision()
        ),
    }
}

/// Re-exported so a store adapter names the same record version it decodes.
pub const fn start_record_format_version() -> u32 {
    START_RECORD_FORMAT_VERSION
}
