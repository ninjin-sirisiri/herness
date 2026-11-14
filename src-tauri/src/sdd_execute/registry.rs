//! The desktop start-approval registry, the approval draft, and the start guard.
//!
//! # What one approval binds
//!
//! [`ApprovalDraft::build`] turns a real, side-effect-free
//! [`ImportPreview`](crate::sdd_execute::pack::ImportPreview) plus the current
//! host facts into one immutable [`ApprovalContent`]:
//!
//! * the exact plan bytes and digest, the parsed result with the verbatim Global
//!   Constraints, the referenced spec snapshots, the approved external read-only
//!   aliases and their approved read paths, and the pack execution-contract
//!   fingerprint;
//! * the project, canonical checkout root, Git identity, branch, base branch,
//!   and whether isolation was approved;
//! * every Task's conditions, scope, checks, HTML targets, deliverables, commit
//!   policy, and finite budget;
//! * the execution connection, the fixed H2 assessment profile, and the
//!   per-purpose disclosure consents;
//! * the host commit and hook authorization, and the H3 settings/consent/
//!   capability boundary.
//!
//! The same call returns the observed [`ApprovalInputs`] it verified the content
//! against, so [`StartApprovalPost::new`] can only save an approval for inputs
//! the host actually observed.
//!
//! # What may start
//!
//! [`StartComposition::approve_and_start`] refuses with zero child creation
//! unless, in this order:
//!
//! 1. the request does not conflict with a previously recorded start record
//!    (an identical request returns the stored result; a possibly started but
//!    unrecorded attempt is `recovery_required`; different content is a
//!    conflict);
//! 2. the *current* approval revision equals the expected revision and still
//!    matches the observed plan, pack, workspace, Tasks, connection, consent,
//!    budget, and H3 values;
//! 3. the one-time workspace decision resolves inside the approved scope;
//! 4. the selected checkout passes the approved plan/spec version check;
//! 5. the first Task's required HTML is currently synced;
//! 6. preparation succeeds (the single permitted `.gitignore` commit, then the
//!    baseline fixed once) and the selected checkout is clean;
//! 7. only then is the one start dispatched and its result recorded.
//!
//! External alias reads happen only through the approved [`SourceLayout`], and an
//! isolated worktree is created only for an approval whose `isolatedWorktree` is
//! set *and* a start request that selects isolation. An isolation failure is
//! never converted into in-place permission.
//!
//! # The trust boundary
//!
//! Only [`ApprovalActor::Human`] with [`ApprovalSource::ApprovalRegistry`] naming
//! the same approval identity can be saved. Every other actor and source — a
//! model request, a preview document, an `ApprovedOwner`, an environment
//! variable, a receipt, an H3 configuration approval — is refused by
//! [`ExecutionApproval::new`] before the store is touched. Task 21 calls this
//! module only after the trusted main-window guard accepted the IPC call; this
//! module deliberately accepts no "who am I" argument from the caller.

use herness_core::contracts::{ProjectId, Timestamp};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConditionVersion, ConsentBinding, ExecutionScope, H4OwnerApproval,
    H4OwnerApprovalRegistryPort, H4PacketBinding, OwnerRef, SupervisionError,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use herness_sdd_execute::{
    ApprovalContent, ApprovalId, ApprovalInputs, ApprovalRejection, ApprovalRequirement,
    ApprovalRevisionStorePort, ApprovalSource, Baseline, CommitAuthorization, ConflictReason,
    ControlRequestId, ExecutionApproval, ExecutionConnection, ExecutionId, FailureDetails,
    GitIdentity, H3ApprovalBinding, HtmlSyncReason, ObservedConnection, PackApproval, PlanApproval,
    PlanPath, PlanRevision, RecoveryReason, SddExecutionError, Sha256Digest, SourceLayout,
    StartApprovalPost, StartApprovalRegistry, StartPhase, StartReceipt, StartRecord,
    StartRecordStorePort, TaskApproval, TaskNumber, TaskRef, TaskStableId, WorkspaceApproval,
    WorkspacePreparation, WorkspaceState,
};

use crate::sdd_execute::pack::ImportPreview;
use crate::sdd_execute::workspace::{
    ApprovedDocument, WorkspaceAdapter, WorkspaceDecision, WorkspaceExpectation,
    WorkspaceSelectionAnswer, WorkspaceSelectionInput,
};

/// Approved H2 budget-policy version carried by every H4 Task launch.
///
/// A different budget is a different approval revision, never a silent
/// in-place edit of a policy version.
pub const H4_BUDGET_POLICY_VERSION: u64 = 1;

/// H2 condition-set version of one approved H4 Task.
pub const H4_CONDITION_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Verified preview facts
// ---------------------------------------------------------------------------

/// One Task's approval-ready contract copied from the verified preview.
#[derive(Debug, Clone)]
pub struct PreviewTaskFacts {
    number: u32,
    title: String,
    body: String,
    conditions: Vec<herness_sdd_execute::ApprovedCondition>,
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    allow_shell: bool,
    checks: Vec<herness_sdd_execute::ApprovedCheck>,
    html_targets: Vec<String>,
    deliverables: Vec<herness_sdd_execute::ApprovedDeliverable>,
    commit_policy: herness_sdd_execute::CommitPolicy,
}

impl PreviewTaskFacts {
    /// Records one Task's approval-ready contract from verified values.
    ///
    /// The desktop preview path builds these from [`ImportPreview`]; a host that
    /// already holds a verified preview (Task 15's coordinator replay) uses this
    /// constructor so the same values are re-bound instead of re-derived.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        number: u32,
        title: impl Into<String>,
        body: impl Into<String>,
        conditions: Vec<herness_sdd_execute::ApprovedCondition>,
        read_paths: Vec<String>,
        write_paths: Vec<String>,
        allow_shell: bool,
        checks: Vec<herness_sdd_execute::ApprovedCheck>,
        html_targets: Vec<String>,
        deliverables: Vec<herness_sdd_execute::ApprovedDeliverable>,
        commit_policy: herness_sdd_execute::CommitPolicy,
    ) -> Self {
        Self {
            number,
            title: title.into(),
            body: body.into(),
            conditions,
            read_paths,
            write_paths,
            allow_shell,
            checks,
            html_targets,
            deliverables,
            commit_policy,
        }
    }

    /// Plan-assigned number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Heading title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Declared HTML targets.
    pub fn html_targets(&self) -> &[String] {
        &self.html_targets
    }
}

/// The verified facts one real preview contributes to an approval.
///
/// Built only from [`ImportPreview`] and the human-approved [`SourceLayout`], so
/// an approval never binds a spec or alias the preview did not read, and never
/// reads an alias outside its approved read paths.
#[derive(Debug, Clone)]
pub struct PreviewFacts {
    project_root: String,
    plan_path: PlanPath,
    exact: herness_sdd_execute::ExactPlanBytes,
    parsed: herness_sdd_execute::ParsedPlanSummary,
    tasks: Vec<PreviewTaskFacts>,
    spec_refs: Vec<herness_sdd_execute::ApprovedSpecRef>,
    sources: Vec<herness_sdd_execute::ExternalSourceApproval>,
    pack: PackApproval,
}

impl PreviewFacts {
    /// Records verified preview facts directly.
    ///
    /// [`Self::from_import`] is the only production path. This constructor
    /// exists so the coordinator can re-bind an already verified preview and so
    /// the approval tests can build exact synthetic facts without a pack.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_root: impl Into<String>,
        plan_path: PlanPath,
        exact: herness_sdd_execute::ExactPlanBytes,
        parsed: herness_sdd_execute::ParsedPlanSummary,
        tasks: Vec<PreviewTaskFacts>,
        spec_refs: Vec<herness_sdd_execute::ApprovedSpecRef>,
        sources: Vec<herness_sdd_execute::ExternalSourceApproval>,
        pack: PackApproval,
    ) -> Result<Self, SddExecutionError> {
        if let Some(first) = tasks.first()
            && first.number != 1
        {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.tasks".to_owned(),
                detail: "Task numbers must be contiguous from one".to_owned(),
            });
        }
        if parsed.schema_version() != pack.plan_schema_version() {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.pack".to_owned(),
                detail: "the pack schema version must match the parsed plan".to_owned(),
            });
        }
        if tasks.is_empty() {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.tasks".to_owned(),
                detail: "at least one Task is required".to_owned(),
            });
        }
        Ok(Self {
            project_root: project_root.into(),
            plan_path,
            exact,
            parsed,
            tasks,
            spec_refs,
            sources,
            pack,
        })
    }

    /// Builds the facts from one real preview and the approved alias layout.
    pub fn from_import(
        preview: &ImportPreview,
        layout: &SourceLayout,
    ) -> Result<Self, SddExecutionError> {
        if layout.project_root() != preview.project_root() {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.layout".to_owned(),
                detail: "the alias layout root must be the preview project root".to_owned(),
            });
        }

        let mut tasks = Vec::with_capacity(preview.preview().tasks().len());
        for task in preview.preview().tasks() {
            tasks.push(PreviewTaskFacts {
                number: task.number(),
                title: task.title().to_owned(),
                body: task.parsed().body().text().to_owned(),
                conditions: task.conditions().to_vec(),
                read_paths: task.read_paths().to_vec(),
                write_paths: task.write_paths().to_vec(),
                allow_shell: task.allow_shell(),
                checks: task.checks().to_vec(),
                html_targets: task.html_targets().to_vec(),
                deliverables: task.deliverables().to_vec(),
                commit_policy: task.commit_policy(),
            });
        }

        let mut spec_refs = Vec::with_capacity(preview.specs().snapshots().len());
        for snapshot in preview.specs().snapshots() {
            spec_refs.push(snapshot.approved_spec_ref()?);
        }

        let mut sources = Vec::new();
        for alias in layout.aliases() {
            // An alias exists in the layout exactly when a human approved it. A
            // digest is recorded only for aliases the preview actually read, so
            // an approved-but-unused alias is not given a fabricated snapshot.
            if let Some(digest) = preview.specs().alias_digest(alias.alias()) {
                sources.push(herness_sdd_execute::ExternalSourceApproval::new(
                    alias.alias(),
                    alias.absolute_root(),
                    digest,
                    alias.read_paths().to_vec(),
                )?);
            }
        }

        let pack = PackApproval::new(
            preview.binding().protocol().clone(),
            preview.binding().schema_version(),
            preview.binding().fingerprint().clone(),
        )?;

        Ok(Self {
            project_root: layout.project_root().to_owned(),
            plan_path: preview.preview().plan_path().clone(),
            exact: preview.source().clone(),
            parsed: preview.preview().parsed().clone(),
            tasks,
            spec_refs,
            sources,
            pack,
        })
    }

    /// Canonical project root the preview was read from.
    pub fn project_root(&self) -> &str {
        &self.project_root
    }

    /// Approved plan path.
    pub const fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Exact plan bytes.
    pub const fn exact(&self) -> &herness_sdd_execute::ExactPlanBytes {
        &self.exact
    }

    /// Parsed result including the verbatim Global Constraints.
    pub const fn parsed(&self) -> &herness_sdd_execute::ParsedPlanSummary {
        &self.parsed
    }

    /// Task facts in plan order.
    pub fn tasks(&self) -> &[PreviewTaskFacts] {
        &self.tasks
    }

    /// Verified spec snapshots.
    pub fn spec_refs(&self) -> &[herness_sdd_execute::ApprovedSpecRef] {
        &self.spec_refs
    }

    /// Approved external read-only aliases.
    pub fn sources(&self) -> &[herness_sdd_execute::ExternalSourceApproval] {
        &self.sources
    }

    /// Approved pack contract.
    pub const fn pack(&self) -> &PackApproval {
        &self.pack
    }
}

// ---------------------------------------------------------------------------
// Approval draft
// ---------------------------------------------------------------------------

/// One human-confirmed set of host facts that becomes an approval revision.
#[derive(Debug, Clone)]
pub struct ApprovalDraft {
    execution: ExecutionId,
    approval_id: ApprovalId,
    project_id: ProjectId,
    preview: PreviewFacts,
    layout: SourceLayout,
    plan_revision: PlanRevision,
    canonical_checkout_root: String,
    git_identity: GitIdentity,
    branch: String,
    base_branch: String,
    isolated_worktree: bool,
    connection: ExecutionConnection,
    commit: CommitAuthorization,
    h3: H3ApprovalBinding,
    task_budgets: Vec<BudgetPolicy>,
}

impl ApprovalDraft {
    /// Creates a draft and verifies its structural identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution: ExecutionId,
        approval_id: ApprovalId,
        preview: PreviewFacts,
        layout: SourceLayout,
        plan_revision: PlanRevision,
        canonical_checkout_root: impl Into<String>,
        git_identity: GitIdentity,
        branch: impl Into<String>,
        base_branch: impl Into<String>,
        isolated_worktree: bool,
        connection: ExecutionConnection,
        commit: CommitAuthorization,
        h3: H3ApprovalBinding,
        task_budgets: Vec<BudgetPolicy>,
    ) -> Result<Self, SddExecutionError> {
        let project_id = approval_id.project_id();
        execution.validate_in(project_id)?;
        if task_budgets.len() != preview.tasks().len() {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.taskBudgets".to_owned(),
                detail: "exactly one finite budget per parsed Task is required".to_owned(),
            });
        }
        for budget in &task_budgets {
            budget
                .validate()
                .map_err(|error| SddExecutionError::InvalidValue {
                    field: "approval.taskBudgets".to_owned(),
                    detail: format!("{error}"),
                })?;
        }
        Ok(Self {
            execution,
            approval_id,
            project_id,
            preview,
            layout,
            plan_revision,
            canonical_checkout_root: canonical_checkout_root.into(),
            git_identity,
            branch: branch.into(),
            base_branch: base_branch.into(),
            isolated_worktree,
            connection,
            commit,
            h3,
            task_budgets,
        })
    }

    /// Execution identity the approval belongs to.
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Project the approval belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> PlanRevision {
        self.plan_revision
    }

    /// Whether isolation was approved.
    pub const fn isolated_worktree(&self) -> bool {
        self.isolated_worktree
    }

    /// Approved implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Approved base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Canonical approved checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Approved connection, profile, and consents.
    pub const fn connection(&self) -> &ExecutionConnection {
        &self.connection
    }

    /// Approved H3 boundary.
    pub const fn h3(&self) -> &H3ApprovalBinding {
        &self.h3
    }

    /// Verified preview facts.
    pub const fn preview(&self) -> &PreviewFacts {
        &self.preview
    }

    /// Stable Task identity of one plan number.
    ///
    /// It depends only on the project, the plan path, and the number, so a later
    /// plan revision keeps the same Task identity instead of re-deriving it from
    /// a conversation.
    pub fn task_ref(&self, number: TaskNumber) -> TaskRef {
        TaskRef::new(
            TaskStableId::from_parts(
                self.project_id,
                derivation_uuid(
                    "h4.task.stable",
                    &format!("{}#{}", self.preview.plan_path().as_str(), number.get()),
                ),
            ),
            number,
        )
    }

    /// Builds the approval content and the observed inputs it matched.
    pub fn build(&self) -> Result<ApprovalBuild, SddExecutionError> {
        if self.layout.project_root() != self.preview.project_root() {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.layout".to_owned(),
                detail: "the alias layout root must be the preview project root".to_owned(),
            });
        }
        let plan = PlanApproval::new(
            self.preview.plan_path().clone(),
            self.preview.exact().clone(),
            self.plan_revision,
            self.preview.parsed().clone(),
            self.preview.spec_refs().to_vec(),
            self.preview.sources().to_vec(),
            self.preview.pack().clone(),
        )?;
        let workspace = WorkspaceApproval::new(
            self.project_id,
            self.canonical_checkout_root.clone(),
            self.git_identity.clone(),
            self.branch.clone(),
            self.base_branch.clone(),
            self.isolated_worktree,
            None,
        )?;

        let mut tasks = Vec::with_capacity(self.preview.tasks().len());
        for (facts, budget) in self.preview.tasks().iter().zip(&self.task_budgets) {
            let scope = ExecutionScope::new(
                self.project_id,
                facts.read_paths.clone(),
                facts.write_paths.clone(),
                facts.allow_shell,
            )
            .map_err(|error| SddExecutionError::InvalidValue {
                field: format!("task.{}.scope", facts.number),
                detail: format!("{error}"),
            })?;
            tasks.push(TaskApproval::new(
                self.task_ref(TaskNumber::new(facts.number)?),
                facts.title.clone(),
                facts.conditions.clone(),
                scope,
                facts.checks.clone(),
                facts.html_targets.clone(),
                budget.clone(),
                facts.commit_policy,
                facts.deliverables.clone(),
            )?);
        }

        let content = ApprovalContent::new(
            plan.clone(),
            workspace.clone(),
            tasks.clone(),
            self.connection.clone(),
            self.commit,
            self.h3.clone(),
        )?;

        let inputs = ApprovalInputs::new(
            plan,
            workspace,
            tasks,
            ObservedConnection::from_approved(
                &self.connection,
                self.connection.consents().to_vec(),
            ),
            self.commit,
            Some(self.h3.clone()),
        );
        inputs.verify(&content)?;
        Ok(ApprovalBuild {
            approval_id: self.approval_id,
            draft: self.clone(),
            content,
            inputs,
        })
    }

    /// Approved documents that must exist inside the selected checkout.
    ///
    /// Only `project`-sourced documents live in the checkout. An approved
    /// external alias is read through its own confined root and never becomes a
    /// checkout document.
    pub fn checkout_documents(&self) -> Result<Vec<ApprovedDocument>, SddExecutionError> {
        let mut documents = Vec::with_capacity(1 + self.preview.spec_refs().len());
        documents.push(ApprovedDocument::plan_at_digest(
            self.preview.plan_path().as_str(),
            sha256_digest(self.preview.exact().digest().as_str())?,
        )?);
        for spec_ref in self.preview.spec_refs() {
            if spec_ref.source() != "project" {
                continue;
            }
            documents.push(ApprovedDocument::spec_at_digest(
                spec_ref.path(),
                spec_ref.digest().clone(),
            )?);
        }
        Ok(documents)
    }

    /// Registers the approved facts the workspace adapter must verify.
    pub fn workspace_expectation(
        &self,
        approval_revision: u64,
        gate: Option<herness_core::HostGitGate>,
    ) -> Result<WorkspaceExpectation, SddExecutionError> {
        let expectation = WorkspaceExpectation::new(
            self.project_id,
            self.canonical_checkout_root.clone(),
            self.branch.clone(),
            self.base_branch.clone(),
            self.execution.to_string(),
            self.approval_id.to_string(),
            approval_revision,
            self.checkout_documents()?,
        )?;
        Ok(match gate {
            Some(gate) => expectation.with_gate(gate),
            None => expectation,
        })
    }

    /// Builds the H2 owner-launch entry of one approved Task.
    pub fn owner_approval(
        &self,
        approval: &ExecutionApproval,
        task: TaskRef,
        now: Timestamp,
    ) -> Result<H4OwnerApproval, SddExecutionError> {
        let Some(task_approval) = approval.content().task(task.number()) else {
            return Err(SddExecutionError::InvalidValue {
                field: "approval.tasks".to_owned(),
                detail: "the requested Task is not part of this approval".to_owned(),
            });
        };
        let owner = h4_owner_ref(self.execution, task)?;
        let version = ConditionVersion::new(H4_CONDITION_VERSION).map_err(supervision_error)?;
        let conditions = crate::supervision::h4_launch::h4_approved_conditions(
            &owner,
            version,
            task_approval,
            now,
        )
        .map_err(supervision_error)?;
        let packet = self.packet_binding(approval, task)?;
        let pack_fingerprint = crate::supervision::h4_launch::h4_content_digest(&sha256_digest(
            approval.plan().pack().execution_contract().as_str(),
        )?)
        .map_err(supervision_error)?;
        let (execution_ref, task_ref) =
            crate::supervision::h4_launch::h4_launch_identity(self.execution, task)
                .map_err(supervision_error)?;
        let plan_digest = crate::supervision::h4_launch::h4_content_digest(&sha256_digest(
            approval.plan().digest().as_str(),
        )?)
        .map_err(supervision_error)?;
        let consent = approval
            .connection()
            .consents()
            .iter()
            .find(|consent| consent.purpose() == approval.connection().profile().purpose())
            .cloned()
            .ok_or_else(|| SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::DisclosureConsent,
                details: FailureDetails::none().boxed(),
            })?;
        H4OwnerApproval::new(
            self.project_id,
            owner,
            execution_ref,
            task_ref,
            approval.plan().plan_revision().get(),
            plan_digest,
            packet,
            pack_fingerprint,
            crate::supervision::h4_launch::h4_commit_authorization(
                approval.commit().host_commit(),
                approval.commit().run_hooks(),
            )
            .map_err(supervision_error)?,
            conditions.condition_version(),
            conditions.digest().clone(),
            task_approval.scope().clone(),
            approval.connection().profile(),
            consent,
            H4_BUDGET_POLICY_VERSION,
            task_approval.budget().clone(),
        )
        .map_err(supervision_error)
    }

    /// Immutable packet binding of one approved Task.
    ///
    /// The three digests are the exact approved Task body, the verbatim Global
    /// Constraints, and the composite of the approved spec snapshots, so the H2
    /// comparison covers the same text H4 hands to the child.
    pub fn packet_binding(
        &self,
        approval: &ExecutionApproval,
        task: TaskRef,
    ) -> Result<H4PacketBinding, SddExecutionError> {
        let body = self
            .preview
            .tasks()
            .iter()
            .find(|facts| facts.number == task.number().get())
            .map(|facts| facts.body.as_str())
            .ok_or_else(|| SddExecutionError::InvalidValue {
                field: "approval.tasks".to_owned(),
                detail: "the requested Task has no approved body".to_owned(),
            })?;
        let task_body = Sha256Digest::sha256(body.as_bytes());
        let constraints = approval.plan().parsed().global_constraints();
        let global_constraints = Sha256Digest::sha256(constraints.text().as_bytes());
        let spec_snapshot = spec_snapshot_digest(approval.plan().spec_refs());
        crate::supervision::h4_launch::h4_packet_binding(
            &task_body,
            &global_constraints,
            &spec_snapshot,
        )
        .map_err(supervision_error)
    }

    /// Approved H2 consents in declaration order.
    pub fn consents(&self) -> &[ConsentBinding] {
        self.connection.consents()
    }
}

/// One built approval: content, the inputs it matched, and its draft.
#[derive(Debug, Clone)]
pub struct ApprovalBuild {
    approval_id: ApprovalId,
    draft: ApprovalDraft,
    content: ApprovalContent,
    inputs: ApprovalInputs,
}

impl ApprovalBuild {
    /// Approved content.
    pub const fn content(&self) -> &ApprovalContent {
        &self.content
    }

    /// Observed inputs the content matched.
    pub const fn inputs(&self) -> &ApprovalInputs {
        &self.inputs
    }

    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// The draft that produced the content.
    pub const fn draft(&self) -> &ApprovalDraft {
        &self.draft
    }

    /// Wraps the build as the one trusted human post.
    ///
    /// The actor and source are fixed to human/registry, so a model, preview,
    /// owner, receipt, or H3 origin cannot be expressed through this API. Task
    /// 21 calls it only after the trusted main-window guard accepted the call.
    pub fn into_human_post(
        self,
        approved_at: Timestamp,
    ) -> Result<StartApprovalPost, SddExecutionError> {
        StartApprovalPost::new(
            self.approval_id,
            approved_at,
            ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry {
                approval_id: self.approval_id,
            },
            self.content,
            self.inputs,
        )
    }
}

// ---------------------------------------------------------------------------
// Host ports the guard needs
// ---------------------------------------------------------------------------

/// The workspace operations the start guard performs.
///
/// [`WorkspaceAdapter`] is the real implementation. Each method refuses when the
/// approved expectation was not registered first, so a start never invents a
/// branch or a base branch.
pub trait StartWorkspacePort {
    /// Registers the approved facts one start must verify.
    fn expect(&self, expectation: WorkspaceExpectation);

    /// Resolves the one-time worktree decision without changing anything.
    fn decide(
        &self,
        input: &WorkspaceSelectionInput,
    ) -> Result<WorkspaceDecision, SddExecutionError>;

    /// Verifies the selected checkout and reports its state.
    fn start_check(
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

impl<L, C, B> StartWorkspacePort for WorkspaceAdapter<L, C, B>
where
    L: herness_core::ArgvLauncher,
    C: crate::sdd_execute::workspace::PreparationCommitPort,
    B: crate::sdd_execute::workspace::BaselineRecord,
{
    fn expect(&self, expectation: WorkspaceExpectation) {
        WorkspaceAdapter::expect(self, expectation);
    }

    fn decide(
        &self,
        input: &WorkspaceSelectionInput,
    ) -> Result<WorkspaceDecision, SddExecutionError> {
        WorkspaceAdapter::decide(self, input)
    }

    fn start_check(
        &self,
        project_id: ProjectId,
        canonical_checkout_root: &str,
    ) -> Result<WorkspaceState, SddExecutionError> {
        WorkspaceAdapter::start_check(self, project_id, canonical_checkout_root)
    }

    fn prepare(
        &mut self,
        request: &WorkspacePreparation,
    ) -> Result<WorkspaceState, SddExecutionError> {
        WorkspaceAdapter::prepare_approved(self, request)
    }
}

/// The one child creation a start performs.
///
/// It is called at most once per start request. The composition records the
/// intent before calling it, so a crash cannot create a second child for the
/// same request.
pub trait StartChildPort {
    /// Creates the one child and returns an opaque reference.
    ///
    /// Never a credential, prompt, or model text; the reference only names the
    /// child/run so the result can be stored and returned.
    fn start_child(
        &mut self,
        execution: ExecutionId,
        task: TaskRef,
        approval_revision: u64,
    ) -> Result<String, SddExecutionError>;
}

/// One required-HTML check for the first Task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartHtmlRequest {
    project_id: ProjectId,
    checkout_root: String,
    targets: Vec<String>,
}

impl StartHtmlRequest {
    /// Records one check.
    pub fn new(
        project_id: ProjectId,
        checkout_root: impl Into<String>,
        targets: Vec<String>,
    ) -> Self {
        Self {
            project_id,
            checkout_root: checkout_root.into(),
            targets,
        }
    }

    /// Project that owns the documents.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Selected checkout the documents live in.
    pub fn checkout_root(&self) -> &str {
        &self.checkout_root
    }

    /// Required HTML targets of the first Task.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }
}

/// The H3 synchronization check the start guard performs.
///
/// Task 16 supplies the real `H4Barrier` implementation. This build ships
/// [`UnsyncedStartHtml`], which refuses every declared target instead of
/// pretending a document is synced. A Task with no HTML target needs no check.
pub trait StartHtmlPort {
    /// Establishes that every target is currently synced.
    fn ensure_synced(&mut self, request: &StartHtmlRequest) -> Result<(), SddExecutionError>;
}

/// The only H3 answer this build can prove: no target, nothing to sync.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsyncedStartHtml;

impl StartHtmlPort for UnsyncedStartHtml {
    fn ensure_synced(&mut self, request: &StartHtmlRequest) -> Result<(), SddExecutionError> {
        if request.targets.is_empty() {
            Ok(())
        } else {
            Err(SddExecutionError::HtmlNotSynced {
                reason: HtmlSyncReason::Unsynced,
                details: FailureDetails::none().boxed(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// H4 owner-approval registry
// ---------------------------------------------------------------------------

/// The current H4 plan approval, as the H2 owner-launch port sees it.
///
/// It answers only for the exact approved execution and Tasks currently
/// recorded. A missing, superseded, or changed entry is `None`, never a
/// synthetic approval. Because it is a distinct port from H2's H3 registry, an
/// H3 approval cannot satisfy it, and it cannot satisfy an H3 launch.
#[derive(Debug, Default, Clone)]
pub struct H4StartApprovalRegistry {
    current: Option<ApprovalContext>,
}

#[derive(Debug, Clone)]
struct ApprovalContext {
    draft: ApprovalDraft,
    approval: ExecutionApproval,
    approved_at: Timestamp,
}

impl H4StartApprovalRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the current entry with one saved approval revision.
    pub fn set_current(&mut self, draft: &ApprovalDraft, approval: &ExecutionApproval) {
        self.current = Some(ApprovalContext {
            draft: draft.clone(),
            approval: approval.clone(),
            approved_at: approval.approved_at(),
        });
    }

    /// Clears the current entry, so nothing can launch until a human approves
    /// again.
    pub fn clear(&mut self) {
        self.current = None;
    }

    /// The current approved execution and revision, if any.
    pub fn current(&self) -> Option<(ExecutionId, u64)> {
        self.current
            .as_ref()
            .map(|context| (context.draft.execution(), context.approval.revision()))
    }

    /// The owner approval of one Task of the current entry.
    pub fn owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        now: Timestamp,
    ) -> Result<Option<H4OwnerApproval>, SupervisionError> {
        let Some(context) = &self.current else {
            return Ok(None);
        };
        if context.approval.project_id() != project_id {
            return Ok(None);
        }
        for task in context.approval.tasks() {
            let candidate =
                h4_owner_ref(context.draft.execution(), task.task()).map_err(|error| {
                    SupervisionError::InvalidValue {
                        field: "h4StartApproval.owner".to_owned(),
                        detail: format!("{error}"),
                    }
                })?;
            if &candidate != owner {
                continue;
            }
            if context.approved_at > now {
                // A clock that moved backwards cannot validate an inherited
                // approval; refuse instead of trusting a future timestamp.
                return Ok(None);
            }
            let approval = context
                .draft
                .owner_approval(&context.approval, task.task(), now)
                .map_err(|error| SupervisionError::InvalidValue {
                    field: "h4StartApproval".to_owned(),
                    detail: format!("{error}"),
                })?;
            return Ok(Some(approval));
        }
        Ok(None)
    }
}

impl H4OwnerApprovalRegistryPort for H4StartApprovalRegistry {
    fn current_h4_owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        now: Timestamp,
    ) -> Result<Option<H4OwnerApproval>, SupervisionError> {
        self.owner_approval(project_id, owner, now)
    }
}

// ---------------------------------------------------------------------------
// Start request and outcome
// ---------------------------------------------------------------------------

/// One approve-and-start request.
///
/// Project, execution, approval identity, request identity, and the expected
/// approval revision are all mandatory. The observed inputs are the host's
/// current observation of every bound value; they are what the current approval
/// is verified against before any side effect.
#[derive(Debug, Clone)]
pub struct StartRequest {
    project_id: ProjectId,
    execution_id: ExecutionId,
    approval_id: ApprovalId,
    expected_approval_revision: u64,
    request_id: ControlRequestId,
    selection: Option<WorkspaceSelectionAnswer>,
    inputs: ApprovalInputs,
    gate: Option<herness_core::HostGitGate>,
}

impl StartRequest {
    /// Creates one start request.
    pub fn new(
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        expected_approval_revision: u64,
        request_id: ControlRequestId,
        selection: Option<WorkspaceSelectionAnswer>,
        inputs: ApprovalInputs,
        gate: Option<herness_core::HostGitGate>,
    ) -> Result<Self, SddExecutionError> {
        let project_id = execution_id.project_id();
        execution_id.validate_in(project_id)?;
        request_id.validate_in(project_id)?;
        if approval_id.project_id() != project_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        if inputs.project_id() != project_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        Ok(Self {
            project_id,
            execution_id,
            approval_id,
            expected_approval_revision,
            request_id,
            selection,
            inputs,
            gate,
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

    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Expected current approval revision.
    pub const fn expected_approval_revision(&self) -> u64 {
        self.expected_approval_revision
    }

    /// Idempotent start request identity.
    pub const fn request_id(&self) -> ControlRequestId {
        self.request_id
    }

    /// Answer already recorded in this conversation, when there is one.
    pub const fn selection(&self) -> Option<&WorkspaceSelectionAnswer> {
        self.selection.as_ref()
    }

    /// Observed current inputs.
    pub const fn inputs(&self) -> &ApprovalInputs {
        &self.inputs
    }

    /// Approved staged-document gate, when a preparation commit may run.
    pub const fn gate(&self) -> Option<&herness_core::HostGitGate> {
        self.gate.as_ref()
    }

    /// Deterministic content fingerprint of this request.
    ///
    /// It binds the approval identity and revision, the selected checkout, the
    /// approved plan digest, and every Task's number, budget, check count, and
    /// HTML targets, so the same request ID with different content is refused
    /// while a byte-identical re-delivery is answered from the record.
    pub fn fingerprint(&self) -> Result<Sha256Digest, SddExecutionError> {
        let content = serde_json::json!({
            "project": self.project_id.to_string(),
            "execution": self.execution_id.to_string(),
            "approval": self.approval_id.to_string(),
            "approvalRevision": self.expected_approval_revision,
            "selection": self.selection,
            "planDigest": self.inputs.plan().digest().as_str(),
            "workspace": self.inputs.workspace().canonical_checkout_root(),
            "branch": self.inputs.workspace().branch(),
            "tasks": self
                .inputs
                .tasks()
                .iter()
                .map(|task| {
                    serde_json::json!({
                        "number": task.task().number().get(),
                        "budgetSeconds": task.budget().active_seconds(),
                        "checks": task.checks().len(),
                        "htmlTargets": task.html_targets(),
                    })
                })
                .collect::<Vec<_>>(),
        });
        let bytes =
            serde_json::to_vec(&content).map_err(|error| SddExecutionError::InvalidValue {
                field: "startRequest".to_owned(),
                detail: format!("could not encode the request fingerprint: {error}"),
            })?;
        Ok(Sha256Digest::sha256(&bytes))
    }
}

/// Outcome of one approve-and-start call.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartOutcome {
    approval_id: ApprovalId,
    approval_revision: u64,
    request_id: ControlRequestId,
    receipt: StartReceipt,
    created_child: bool,
    checkout_root: String,
    #[serde(default)]
    baseline: Option<Baseline>,
}

impl StartOutcome {
    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Approval revision that authorized the start.
    pub const fn approval_revision(&self) -> u64 {
        self.approval_revision
    }

    /// Start request identity.
    pub const fn request_id(&self) -> ControlRequestId {
        self.request_id
    }

    /// Stored or recorded start result.
    pub const fn receipt(&self) -> &StartReceipt {
        &self.receipt
    }

    /// Whether this call created the child.
    pub const fn created_child(&self) -> bool {
        self.created_child
    }

    /// Selected checkout.
    pub fn checkout_root(&self) -> &str {
        &self.checkout_root
    }

    /// Baseline this call fixed, when it prepared the checkout.
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }
}

// ---------------------------------------------------------------------------
// The guard / composition
// ---------------------------------------------------------------------------

/// Approves one revision and starts it only when everything still matches.
pub struct StartComposition<S, W, C, H>
where
    S: ApprovalRevisionStorePort + StartRecordStorePort,
{
    registry: StartApprovalRegistry<S>,
    workspace: W,
    child: C,
    html: H,
}

impl<S, W, C, H> StartComposition<S, W, C, H>
where
    S: ApprovalRevisionStorePort + StartRecordStorePort,
    W: StartWorkspacePort,
    C: StartChildPort,
    H: StartHtmlPort,
{
    /// Creates one start composition over its durable store and adapters.
    pub fn new(store: S, workspace: W, child: C, html: H) -> Self {
        Self {
            registry: StartApprovalRegistry::new(store),
            workspace,
            child,
            html,
        }
    }

    /// The underlying approval registry.
    pub const fn registry(&self) -> &StartApprovalRegistry<S> {
        &self.registry
    }

    /// The underlying mutable approval registry.
    pub const fn registry_mut(&mut self) -> &mut StartApprovalRegistry<S> {
        &mut self.registry
    }

    /// The workspace adapter.
    pub const fn workspace(&self) -> &W {
        &self.workspace
    }

    /// The mutable workspace adapter.
    pub const fn workspace_mut(&mut self) -> &mut W {
        &mut self.workspace
    }

    /// Records the trusted human post as the current revision.
    ///
    /// The post already proved the content matches the inputs it was built from
    /// and that the actor and source are human/registry; the store refuses a
    /// rewritten revision.
    pub fn approve(
        &mut self,
        post: &StartApprovalPost,
    ) -> Result<ExecutionApproval, SddExecutionError> {
        self.registry.post_human_approval(post)
    }

    /// Records the trusted human post and starts the one child, or refuses.
    ///
    /// A duplicate request returns the stored result without creating a second
    /// child. Every refusal happens before the child port is called.
    pub fn approve_and_start(
        &mut self,
        draft: &ApprovalDraft,
        post: &StartApprovalPost,
        request: &StartRequest,
    ) -> Result<StartOutcome, SddExecutionError> {
        self.ensure_same_identity(draft, request)?;
        let approval = self.approve(post)?;
        if approval.revision() != request.expected_approval_revision() {
            // The human confirmed a different revision than this request bound:
            // the request is stale and must not start.
            return Err(SddExecutionError::Conflict {
                reason: ConflictReason::StaleRevision,
                details: FailureDetails::none().boxed(),
            });
        }
        self.start_with(draft, &approval, request)
    }

    /// Starts one already current approval.
    ///
    /// The current revision is re-read and re-verified against the request's
    /// observed inputs; a stale, revoked, or changed value refuses before any
    /// workspace or child side effect.
    pub fn start(
        &mut self,
        draft: &ApprovalDraft,
        request: &StartRequest,
    ) -> Result<StartOutcome, SddExecutionError> {
        self.ensure_same_identity(draft, request)?;
        let approval = self.registry.verify_current(
            request.project_id(),
            request.approval_id(),
            request.expected_approval_revision(),
            request.inputs(),
        )?;
        self.start_with(draft, &approval, request)
    }

    fn ensure_same_identity(
        &self,
        draft: &ApprovalDraft,
        request: &StartRequest,
    ) -> Result<(), SddExecutionError> {
        if request.execution_id() != draft.execution()
            || request.approval_id() != draft.approval_id()
            || request.project_id() != draft.project_id()
        {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        Ok(())
    }

    fn start_with(
        &mut self,
        draft: &ApprovalDraft,
        approval: &ExecutionApproval,
        request: &StartRequest,
    ) -> Result<StartOutcome, SddExecutionError> {
        // The approval that authorizes this call must still match the inputs the
        // request observed, and every Task budget must still be finite and
        // inside H2's limits. Nothing below runs otherwise.
        request.inputs().verify(approval.content())?;
        herness_sdd_execute::ensure_budgets(approval.tasks())?;

        let fingerprint = request.fingerprint()?;
        let task = approval
            .tasks()
            .first()
            .map(|task| task.task())
            .ok_or_else(|| SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: FailureDetails::none().boxed(),
            })?;

        // 1. One child per Task, whichever request ID asks: a Task that already
        //    started is answered from its record or refused as recovery, never
        //    started twice.
        if let Some(record) = self.registry.store().start_record_for_task(
            request.project_id(),
            request.execution_id(),
            task,
        )? && record.request_id() != request.request_id()
        {
            return Err(SddExecutionError::Conflict {
                reason: ConflictReason::TaskNotReady,
                details: FailureDetails::none().boxed(),
            });
        }

        // 2. Idempotency: a re-delivered request never creates a second child.
        if let Some(record) = self.registry.store().start_record(
            request.project_id(),
            request.execution_id(),
            request.request_id(),
        )? {
            if record.fingerprint() != &fingerprint {
                return Err(SddExecutionError::DuplicateRequestConflict {
                    recorded: record.fingerprint().to_string(),
                    supplied: fingerprint.to_string(),
                });
            }
            return match (record.phase(), record.receipt()) {
                (StartPhase::Started, Some(receipt)) => Ok(StartOutcome {
                    approval_id: approval.approval_id(),
                    approval_revision: approval.revision(),
                    request_id: request.request_id(),
                    receipt: receipt.clone(),
                    created_child: false,
                    checkout_root: request
                        .inputs()
                        .workspace()
                        .canonical_checkout_root()
                        .to_owned(),
                    baseline: request.inputs().workspace().baseline().cloned(),
                }),
                // The record was written but the one start's result is not
                // stored: reconcile instead of starting again.
                _ => Err(SddExecutionError::RecoveryRequired {
                    reason: RecoveryReason::UnknownRequest,
                    details: FailureDetails::none().boxed(),
                }),
            };
        }

        // 2. Verify the approved workspace facts, the one-time decision, the
        //    approved document versions, and the required HTML, all before any
        //    Git or child side effect.
        self.workspace
            .expect(draft.workspace_expectation(approval.revision(), request.gate().cloned())?);
        let decision = self.workspace.decide(&WorkspaceSelectionInput::new(
            request.project_id(),
            draft.canonical_checkout_root().to_owned(),
            draft.base_branch().to_owned(),
            draft.branch().to_owned(),
            request.selection().cloned(),
        ))?;
        let selection =
            decision
                .selection()
                .cloned()
                .ok_or_else(|| SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::StartApproval,
                    details: FailureDetails::none().boxed(),
                })?;
        if selection.isolated() && !draft.isolated_worktree() {
            // Isolation that no approval covers is never created implicitly.
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::WorkspaceMismatch {
                    field: "workspace.isolatedWorktree".to_owned(),
                },
            });
        }
        if std::path::Path::new(selection.checkout_root()).exists() {
            // An existing checkout is verified before anything is written. A
            // planned isolated root does not exist yet; preparation creates it
            // and then verifies the same approved documents itself.
            self.workspace
                .start_check(request.project_id(), selection.checkout_root())?;
        }

        let first_task = approval.tasks().first().expect("an approval has Tasks");
        self.html.ensure_synced(&StartHtmlRequest::new(
            request.project_id(),
            selection.checkout_root().to_owned(),
            first_task.html_targets().to_vec(),
        ))?;

        // 3. Record the intent before preparation, so a crash that prepared the
        //    workspace is observable instead of invisible.
        let intent = StartRecord::new(
            request.execution_id(),
            request.request_id(),
            approval.approval_id(),
            approval.revision(),
            task,
            fingerprint,
            StartPhase::PreparingWorkspace,
            None,
        )?;
        self.registry.store_mut().record_start(&intent)?;

        // 4. Prepare only the selected checkout. An isolated worktree is created
        //    only when the approval and the decision both selected it.
        let preparation = if selection.isolated() {
            WorkspacePreparation::isolated(
                request.project_id(),
                selection.checkout_root().to_owned(),
                draft.base_branch().to_owned(),
                draft.branch().to_owned(),
            )
        } else {
            WorkspacePreparation::in_place(
                request.project_id(),
                selection.checkout_root().to_owned(),
                draft.base_branch().to_owned(),
                true,
            )
        };
        let state = self.workspace.prepare(&preparation)?;
        let baseline =
            state
                .baseline()
                .cloned()
                .ok_or_else(|| SddExecutionError::RecoveryRequired {
                    reason: RecoveryReason::StateUnreadable,
                    details: FailureDetails::none().boxed(),
                })?;
        if !state.is_startable() {
            return Err(SddExecutionError::Conflict {
                reason: ConflictReason::DirtyIndex,
                details: FailureDetails::none().boxed(),
            });
        }

        // 5. The child may start now. `starting` is recorded first, so an
        //    interrupted start is reconciled instead of duplicated.
        self.registry.store_mut().record_start(&intent.starting())?;
        let reference =
            self.child
                .start_child(request.execution_id(), task, approval.revision())?;
        let receipt = StartReceipt::new(reference, true)?;
        self.registry
            .store_mut()
            .record_start(&intent.started(receipt.clone()))?;
        Ok(StartOutcome {
            approval_id: approval.approval_id(),
            approval_revision: approval.revision(),
            request_id: request.request_id(),
            receipt,
            created_child: true,
            checkout_root: state.canonical_checkout_root().to_owned(),
            baseline: Some(baseline),
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory store for tests and single-process composition
// ---------------------------------------------------------------------------

/// One in-memory store that implements both approval and start persistence.
#[derive(Debug, Default, Clone)]
pub struct MemoryStartStore {
    approvals: herness_sdd_execute::MemoryApprovalRevisionStore,
    starts: herness_sdd_execute::MemoryStartRecordStore,
}

impl MemoryStartStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ApprovalRevisionStorePort for MemoryStartStore {
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        self.approvals.record_approval_revision(approval)
    }

    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        self.approvals
            .approval_revision(project_id, approval_id, revision)
    }

    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        self.approvals
            .latest_approval_revision(project_id, approval_id)
    }

    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        self.approvals.approval_revisions(project_id, approval_id)
    }
}

impl StartRecordStorePort for MemoryStartStore {
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        self.starts
            .start_record(project_id, execution_id, request_id)
    }

    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        self.starts
            .start_record_for_task(project_id, execution_id, task)
    }

    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError> {
        self.starts.record_start(record)
    }
}

/// Derives a deterministic UUID from labelled parts.
pub fn derivation_uuid(label: &str, parts: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0u8]);
    hasher.update(parts.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// The H2 owner reference of one H4 Task.
pub fn h4_owner_ref(execution: ExecutionId, task: TaskRef) -> Result<OwnerRef, SddExecutionError> {
    crate::supervision::h4_launch::h4_owner_ref(execution, task).map_err(supervision_error)
}

fn spec_snapshot_digest(refs: &[herness_sdd_execute::ApprovedSpecRef]) -> Sha256Digest {
    let mut buffer = b"herness.h4.spec-snapshot\0".to_vec();
    for spec_ref in refs {
        buffer.extend_from_slice(spec_ref.source().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(spec_ref.path().as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(spec_ref.digest().as_str().as_bytes());
        buffer.push(0);
    }
    Sha256Digest::sha256(&buffer)
}

/// Re-wraps one role digest as the generic digest a launch compares.
fn sha256_digest(value: &str) -> Result<Sha256Digest, SddExecutionError> {
    Sha256Digest::parse(value)
}

fn supervision_error(error: SupervisionError) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: "h4StartApproval".to_owned(),
        detail: format!("{error}"),
    }
}
