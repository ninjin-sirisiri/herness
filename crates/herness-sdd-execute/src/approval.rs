//! One approved execution revision and its immutable content.
//!
//! An approval binds the exact plan bytes and digest, the parsed result and
//! verbatim Global Constraints, the spec and external-source snapshots, the
//! pack execution-contract fingerprint, the checkout and Git identity, the
//! branch and base branch, every Task's conditions, scope, checks, and HTML
//! targets, the execution connection and per-purpose disclosure consent, each
//! Task's finite budget, the host commit and hook authorization, and the H3
//! settings, consent, and capability boundary.
//!
//! Only the host-owned H4 approval registry may supply this value. Environment
//! variables, document declarations, receipts, request actors, owner kinds,
//! model requests, and H3 approvals are rejected as sources, and only a human
//! actor is accepted.

use std::collections::BTreeSet;
use std::fmt;

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, ExecutionScope, ProfileBinding,
};
use serde::{Deserialize, Serialize};

use crate::error::{ApprovalRejection, SddExecutionError};
use crate::ids::{ApprovalId, PlanRevision, TaskNumber, TaskRef};
use crate::plan::{
    ExactPlanBytes, InspectorProtocol, ParsedPlanSummary, PlanPath, validate_check_cwd,
    validate_project_path,
};
use crate::version::{PLAN_SCHEMA_VERSION, PackFingerprint, PlanDigest, Sha256Digest};

/// Every approval source kind the pack definition names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalSourceKind {
    /// The host-owned H4 approval registry. The only accepted source.
    ApprovalRegistry,
    /// An environment variable.
    EnvironmentVariable,
    /// A declaration inside a repository document.
    DocumentDeclaration,
    /// An HTML meta declaration.
    HtmlMeta,
    /// A completion receipt or other generated record.
    Receipt,
    /// The actor that sent a request.
    RequestActor,
    /// An H1/H2/H3 owner kind value.
    OwnerKind,
    /// A model request or model-authored proposal.
    ModelRequest,
    /// An H3 configuration approval.
    H3Approval,
}

impl ApprovalSourceKind {
    /// Every source kind.
    pub const ALL: [Self; 9] = [
        Self::ApprovalRegistry,
        Self::EnvironmentVariable,
        Self::DocumentDeclaration,
        Self::HtmlMeta,
        Self::Receipt,
        Self::RequestActor,
        Self::OwnerKind,
        Self::ModelRequest,
        Self::H3Approval,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApprovalRegistry => "h4-approval-registry",
            Self::EnvironmentVariable => "environment-variable",
            Self::DocumentDeclaration => "document-declaration",
            Self::HtmlMeta => "html-meta",
            Self::Receipt => "receipt",
            Self::RequestActor => "request-actor",
            Self::OwnerKind => "owner-kind",
            Self::ModelRequest => "model-request",
            Self::H3Approval => "h3-configuration-registry",
        }
    }

    /// Whether this source may approve an H4 execution.
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::ApprovalRegistry)
    }
}

impl fmt::Display for ApprovalSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where one execution approval claims to come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalSource {
    /// The host-owned approval registry.
    ApprovalRegistry {
        /// Registry approval identity.
        approval_id: ApprovalId,
    },
    /// An environment variable, which never approves.
    EnvironmentVariable {
        /// Variable name.
        name: String,
    },
    /// A declaration in a repository document, which never approves.
    DocumentDeclaration {
        /// Document path.
        path: String,
    },
    /// An HTML meta declaration, which never approves.
    HtmlMeta {
        /// Document path.
        path: String,
    },
    /// A generated receipt or completion report, which never approves.
    Receipt {
        /// Receipt reference.
        reference: String,
    },
    /// The actor that sent a request, which never approves.
    RequestActor {
        /// Actor reference.
        reference: String,
    },
    /// An owner kind value such as `ApprovedOwner` or `H4SddTask`.
    OwnerKind {
        /// Owner reference.
        reference: String,
    },
    /// A model request, which never approves.
    ModelRequest {
        /// Model request reference.
        reference: String,
    },
    /// An H3 configuration approval, which never approves H4 execution.
    H3Approval {
        /// H3 approval reference.
        approval_id: String,
    },
}

impl ApprovalSource {
    /// Source kind.
    pub const fn kind(&self) -> ApprovalSourceKind {
        match self {
            Self::ApprovalRegistry { .. } => ApprovalSourceKind::ApprovalRegistry,
            Self::EnvironmentVariable { .. } => ApprovalSourceKind::EnvironmentVariable,
            Self::DocumentDeclaration { .. } => ApprovalSourceKind::DocumentDeclaration,
            Self::HtmlMeta { .. } => ApprovalSourceKind::HtmlMeta,
            Self::Receipt { .. } => ApprovalSourceKind::Receipt,
            Self::RequestActor { .. } => ApprovalSourceKind::RequestActor,
            Self::OwnerKind { .. } => ApprovalSourceKind::OwnerKind,
            Self::ModelRequest { .. } => ApprovalSourceKind::ModelRequest,
            Self::H3Approval { .. } => ApprovalSourceKind::H3Approval,
        }
    }

    /// Whether this source is the approval registry.
    pub const fn is_registry(&self) -> bool {
        matches!(self, Self::ApprovalRegistry { .. })
    }

    /// Rejects every source except the registry.
    pub fn ensure_accepted(&self) -> Result<(), SddExecutionError> {
        if self.is_registry() {
            Ok(())
        } else {
            Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ForbiddenSource {
                    source: self.kind(),
                },
            })
        }
    }
}

/// Git author identity approved for host commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitIdentity {
    author_name: String,
    author_email: String,
}

impl GitIdentity {
    /// Creates a Git author identity.
    pub fn new(
        author_name: impl Into<String>,
        author_email: impl Into<String>,
    ) -> Result<Self, SddExecutionError> {
        let author_name = author_name.into();
        let author_email = author_email.into();
        if author_name.trim().is_empty()
            || author_name.chars().any(|character| character.is_control())
        {
            return Err(invalid(
                "workspace.gitIdentity.name",
                "must be non-empty text",
            ));
        }
        if author_email.trim().is_empty()
            || author_email.chars().any(|character| character.is_control())
            || !author_email.contains('@')
        {
            return Err(invalid(
                "workspace.gitIdentity.email",
                "must be a non-empty e-mail address",
            ));
        }
        Ok(Self {
            author_name,
            author_email,
        })
    }

    /// Author name.
    pub fn author_name(&self) -> &str {
        &self.author_name
    }

    /// Author e-mail.
    pub fn author_email(&self) -> &str {
        &self.author_email
    }
}

/// The checkout, branch, and Git identity approved for one execution.
///
/// The canonical root is the real implementation checkout. Approving an
/// external read-only source never grants a write to that repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceApproval {
    project_id: ProjectId,
    canonical_checkout_root: String,
    git_identity: GitIdentity,
    branch: String,
    base_branch: String,
    isolated_worktree: bool,
    #[serde(default)]
    baseline: Option<crate::ids::Baseline>,
}

impl WorkspaceApproval {
    /// Creates a workspace approval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        canonical_checkout_root: impl Into<String>,
        git_identity: GitIdentity,
        branch: impl Into<String>,
        base_branch: impl Into<String>,
        isolated_worktree: bool,
        baseline: Option<crate::ids::Baseline>,
    ) -> Result<Self, SddExecutionError> {
        let canonical_checkout_root = canonical_checkout_root.into();
        validate_canonical_root(&canonical_checkout_root)?;
        let branch = branch.into();
        validate_branch("workspace.branch", &branch)?;
        let base_branch = base_branch.into();
        validate_branch("workspace.baseBranch", &base_branch)?;
        Ok(Self {
            project_id,
            canonical_checkout_root,
            git_identity,
            branch,
            base_branch,
            isolated_worktree,
            baseline,
        })
    }

    /// Project that owns the checkout.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Canonical absolute checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Approved Git author identity.
    pub fn git_identity(&self) -> &GitIdentity {
        &self.git_identity
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Integration base branch.
    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    /// Whether the checkout is an isolated worktree created by explicit
    /// approval.
    pub const fn isolated_worktree(&self) -> bool {
        self.isolated_worktree
    }

    /// Baseline commit fixed after preparation, when one is established.
    pub fn baseline(&self) -> Option<&crate::ids::Baseline> {
        self.baseline.as_ref()
    }
}

fn validate_canonical_root(root: &str) -> Result<(), SddExecutionError> {
    if root.trim().is_empty() {
        return Err(invalid(
            "workspace.canonicalCheckoutRoot",
            "must not be empty",
        ));
    }
    if root.chars().any(|character| character.is_control()) {
        return Err(invalid(
            "workspace.canonicalCheckoutRoot",
            "must not contain control characters",
        ));
    }
    let path = std::path::Path::new(root);
    if !path.is_absolute() {
        return Err(invalid(
            "workspace.canonicalCheckoutRoot",
            "must be an absolute canonical path",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "workspace.canonicalCheckoutRoot",
            "must not contain '..'",
        ));
    }
    Ok(())
}

fn validate_branch(field: &str, branch: &str) -> Result<(), SddExecutionError> {
    let invalid_ref = |detail: &str| invalid(field, detail);
    if branch.trim().is_empty() {
        return Err(invalid_ref("must not be empty"));
    }
    if branch == "HEAD" || branch == "@" {
        return Err(invalid_ref("must name a branch"));
    }
    if branch.contains("..")
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with(".lock")
        || branch
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_ref("is not a valid Git branch name"));
    }
    if branch
        .chars()
        .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Err(invalid_ref("is not a valid Git branch name"));
    }
    Ok(())
}

/// How one condition is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionMode {
    /// Every referenced check must pass.
    Checks,
    /// H2 assesses the rubric.
    Assessment,
}

/// One approved condition inside a Task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCondition {
    id: String,
    title: String,
    rubric: String,
    mode: ConditionMode,
}

impl ApprovedCondition {
    /// Creates an approved condition.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        rubric: impl Into<String>,
        mode: ConditionMode,
    ) -> Result<Self, SddExecutionError> {
        let id = id.into();
        let title = title.into();
        let rubric = rubric.into();
        validate_identifier("condition.id", &id)?;
        if title.trim().is_empty() {
            return Err(invalid("condition.title", "must not be empty"));
        }
        if rubric.trim().is_empty() {
            return Err(invalid("condition.rubric", "must not be empty"));
        }
        Ok(Self {
            id,
            title,
            rubric,
            mode,
        })
    }

    /// Task-unique condition identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Approval rubric text.
    pub fn rubric(&self) -> &str {
        &self.rubric
    }

    /// Judgement mode.
    pub const fn mode(&self) -> ConditionMode {
        self.mode
    }
}

/// One approved check. The command is an approved shell string, never executed
/// while importing or approving a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCheck {
    id: String,
    condition_id: String,
    description: String,
    command: String,
    cwd: String,
    timeout_seconds: u64,
    input_paths: Vec<String>,
}

impl ApprovedCheck {
    /// Creates an approved check.
    pub fn new(
        id: impl Into<String>,
        condition_id: impl Into<String>,
        description: impl Into<String>,
        command: impl Into<String>,
        cwd: impl Into<String>,
        timeout_seconds: u64,
        input_paths: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let id = id.into();
        let condition_id = condition_id.into();
        let description = description.into();
        let command = command.into();
        let cwd = cwd.into();
        validate_identifier("check.id", &id)?;
        validate_identifier("check.conditionId", &condition_id)?;
        if description.trim().is_empty() {
            return Err(invalid("check.description", "must not be empty"));
        }
        if command.trim().is_empty() {
            return Err(invalid("check.command", "must not be empty"));
        }
        validate_check_cwd(&cwd)?;
        if timeout_seconds == 0 {
            return Err(invalid("check.timeoutSeconds", "must be greater than zero"));
        }
        for path in &input_paths {
            validate_project_path("check.inputPaths", path)?;
        }
        Ok(Self {
            id,
            condition_id,
            description,
            command,
            cwd,
            timeout_seconds,
            input_paths,
        })
    }

    /// Task-unique check identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Condition this check verifies.
    pub fn condition_id(&self) -> &str {
        &self.condition_id
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Approved command string. Not executed by this crate.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Working directory: `.` or a project-relative directory.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Explicit timeout in seconds.
    pub const fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// Input paths whose content must be bound to the evidence.
    pub fn input_paths(&self) -> &[String] {
        &self.input_paths
    }
}

/// Kind of a Task deliverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// One approved deliverable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedDeliverable {
    path: String,
    kind: DeliverableKind,
}

impl ApprovedDeliverable {
    /// Creates an approved deliverable.
    pub fn new(path: impl Into<String>, kind: DeliverableKind) -> Result<Self, SddExecutionError> {
        let path = path.into();
        validate_project_path("deliverable.path", &path)?;
        Ok(Self { path, kind })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Expected kind.
    pub const fn kind(&self) -> DeliverableKind {
        self.kind
    }
}

/// Task commit policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitPolicy {
    /// The Task must advance HEAD with its approved deliverables.
    Required,
    /// The Task changes no source content and creates no empty commit.
    NoChange,
}

impl CommitPolicy {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::NoChange => "no_change",
        }
    }
}

/// One Task's approved conditions, scope, checks, HTML targets, budget, and
/// commit policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskApproval {
    task: TaskRef,
    title: String,
    conditions: Vec<ApprovedCondition>,
    scope: ExecutionScope,
    checks: Vec<ApprovedCheck>,
    html_targets: Vec<String>,
    budget: BudgetPolicy,
    commit_policy: CommitPolicy,
    deliverables: Vec<ApprovedDeliverable>,
}

impl TaskApproval {
    /// Creates a Task approval and validates its internal references.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: TaskRef,
        title: impl Into<String>,
        conditions: Vec<ApprovedCondition>,
        scope: ExecutionScope,
        checks: Vec<ApprovedCheck>,
        html_targets: Vec<String>,
        budget: BudgetPolicy,
        commit_policy: CommitPolicy,
        deliverables: Vec<ApprovedDeliverable>,
    ) -> Result<Self, SddExecutionError> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(invalid("task.title", "must not be empty"));
        }
        if task.project_id() != scope.project_id() {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "Task execution scope".to_owned(),
                expected: task.project_id(),
                found: scope.project_id(),
            });
        }
        if conditions.is_empty() {
            return Err(invalid("task.conditions", "must not be empty"));
        }
        let mut condition_ids = BTreeSet::new();
        for condition in &conditions {
            if !condition_ids.insert(condition.id.clone()) {
                return Err(invalid(
                    "task.conditions",
                    "condition identifiers must be unique inside a Task",
                ));
            }
        }
        let mut check_ids = BTreeSet::new();
        for check in &checks {
            if !check_ids.insert(check.id.clone()) {
                return Err(invalid(
                    "task.checks",
                    "check identifiers must be unique inside a Task",
                ));
            }
            if !condition_ids.contains(&check.condition_id) {
                return Err(invalid(
                    "task.checks.conditionId",
                    "a check must reference a condition in the same Task",
                ));
            }
        }
        for condition in &conditions {
            if condition.mode == ConditionMode::Checks
                && !checks
                    .iter()
                    .any(|check| check.condition_id == condition.id)
            {
                return Err(invalid(
                    "task.conditions",
                    "a checks-mode condition requires at least one check",
                ));
            }
        }
        for target in &html_targets {
            validate_project_path("task.htmlTargets", target)?;
        }
        budget
            .validate()
            .map_err(|error| SddExecutionError::InvalidValue {
                field: "task.budget".to_owned(),
                detail: format!("{error}"),
            })?;
        if budget.active_seconds() > crate::version::H4_MAX_SUPERVISION_SECONDS {
            return Err(invalid(
                "task.budget.activeSeconds",
                "an approval may not exceed H2's cumulative supervision limit",
            ));
        }
        if budget.additional_runs() > crate::version::H4_MAX_ADDITIONAL_RUNS {
            return Err(invalid(
                "task.budget.additionalRuns",
                "an approval may not exceed H2's additional-run limit",
            ));
        }
        if commit_policy == CommitPolicy::NoChange {
            if !scope.write_paths().is_empty() {
                return Err(invalid(
                    "task.commitPolicy",
                    "a no_change Task must have an empty write scope",
                ));
            }
            if !deliverables.is_empty() {
                return Err(invalid(
                    "task.deliverables",
                    "a no_change Task must not declare deliverables",
                ));
            }
        } else {
            for deliverable in &deliverables {
                if !scope
                    .write_paths()
                    .iter()
                    .any(|write| path_within(deliverable.path(), write))
                {
                    return Err(invalid(
                        "task.deliverables",
                        "a deliverable must be inside the approved write scope",
                    ));
                }
            }
        }
        Ok(Self {
            task,
            title,
            conditions,
            scope,
            checks,
            html_targets,
            budget,
            commit_policy,
            deliverables,
        })
    }

    /// Task identity and number.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Task title from the heading.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Approved conditions.
    pub fn conditions(&self) -> &[ApprovedCondition] {
        &self.conditions
    }

    /// Bounded H2 execution scope.
    pub fn scope(&self) -> &ExecutionScope {
        &self.scope
    }

    /// Approved checks.
    pub fn checks(&self) -> &[ApprovedCheck] {
        &self.checks
    }

    /// Known required HTML documents. Change detection may add more.
    pub fn html_targets(&self) -> &[String] {
        &self.html_targets
    }

    /// Finite H2 budget.
    pub fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// Commit policy.
    pub const fn commit_policy(&self) -> CommitPolicy {
        self.commit_policy
    }

    /// Approved deliverables.
    pub fn deliverables(&self) -> &[ApprovedDeliverable] {
        &self.deliverables
    }
}

/// One approved spec reference and the digest of the snapshot the host will
/// hand to the child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedSpecRef {
    source: String,
    path: String,
    sections: Vec<String>,
    digest: Sha256Digest,
}

impl ApprovedSpecRef {
    /// Creates an approved spec reference.
    pub fn new(
        source: impl Into<String>,
        path: impl Into<String>,
        sections: Vec<String>,
        digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        let source = source.into();
        let path = path.into();
        validate_identifier("specRef.source", &source)?;
        validate_project_path("specRef.path", &path)?;
        if sections.is_empty() {
            return Err(invalid("specRef.sections", "must not be empty"));
        }
        for section in &sections {
            if section.trim().is_empty() {
                return Err(invalid(
                    "specRef.sections",
                    "must not contain empty headings",
                ));
            }
        }
        Ok(Self {
            source,
            path,
            sections,
            digest,
        })
    }

    /// `project` or a registered read-only alias.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Applied spec headings.
    pub fn sections(&self) -> &[String] {
        &self.sections
    }

    /// Digest of the snapshot bytes that were approved.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// One registered external read-only source approved for reading.
///
/// Approving a read-only source never grants a write to its repository or a
/// broader project-relative grant to the child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalSourceApproval {
    alias: String,
    absolute_root: String,
    digest: Sha256Digest,
    read_paths: Vec<String>,
}

impl ExternalSourceApproval {
    /// Creates an approved read-only source.
    pub fn new(
        alias: impl Into<String>,
        absolute_root: impl Into<String>,
        digest: Sha256Digest,
        read_paths: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        let alias = alias.into();
        let absolute_root = absolute_root.into();
        validate_identifier("source.alias", &alias)?;
        if absolute_root.trim().is_empty() {
            return Err(invalid("source.absoluteRoot", "must not be empty"));
        }
        if !std::path::Path::new(&absolute_root).is_absolute() {
            return Err(invalid("source.absoluteRoot", "must be an absolute path"));
        }
        if read_paths.is_empty() {
            return Err(invalid("source.readPaths", "must not be empty"));
        }
        for path in &read_paths {
            validate_project_path("source.readPaths", path)?;
        }
        Ok(Self {
            alias,
            absolute_root,
            digest,
            read_paths,
        })
    }

    /// Registered alias.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Approved absolute read-only root.
    pub fn absolute_root(&self) -> &str {
        &self.absolute_root
    }

    /// Digest of the snapshot bytes that were approved.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Bounded paths that may be sent to the child.
    pub fn read_paths(&self) -> &[String] {
        &self.read_paths
    }
}

/// The pack contract bound by one approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackApproval {
    protocol: InspectorProtocol,
    plan_schema_version: u32,
    execution_contract: PackFingerprint,
}

impl PackApproval {
    /// Creates a pack approval and rejects an unknown version.
    pub fn new(
        protocol: InspectorProtocol,
        plan_schema_version: u32,
        execution_contract: PackFingerprint,
    ) -> Result<Self, SddExecutionError> {
        protocol.ensure_current()?;
        if plan_schema_version != PLAN_SCHEMA_VERSION {
            return Err(SddExecutionError::UnsupportedPlanSchemaVersion {
                found: plan_schema_version,
                expected: PLAN_SCHEMA_VERSION,
            });
        }
        Ok(Self {
            protocol,
            plan_schema_version,
            execution_contract,
        })
    }

    /// Inspector protocol that produced the parse.
    pub fn protocol(&self) -> &InspectorProtocol {
        &self.protocol
    }

    /// Plan schema version that produced the parse.
    pub const fn plan_schema_version(&self) -> u32 {
        self.plan_schema_version
    }

    /// Pack execution-contract fingerprint.
    pub fn execution_contract(&self) -> &PackFingerprint {
        &self.execution_contract
    }
}

/// One approved plan revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanApproval {
    plan_path: PlanPath,
    source: ExactPlanBytes,
    plan_revision: PlanRevision,
    parsed: ParsedPlanSummary,
    spec_refs: Vec<ApprovedSpecRef>,
    sources: Vec<ExternalSourceApproval>,
    pack: PackApproval,
}

impl PlanApproval {
    /// Creates a plan approval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_path: PlanPath,
        source: ExactPlanBytes,
        plan_revision: PlanRevision,
        parsed: ParsedPlanSummary,
        spec_refs: Vec<ApprovedSpecRef>,
        sources: Vec<ExternalSourceApproval>,
        pack: PackApproval,
    ) -> Result<Self, SddExecutionError> {
        if spec_refs.is_empty() {
            return Err(invalid("plan.specRefs", "must not be empty"));
        }
        for spec_ref in &spec_refs {
            if spec_ref.source == "project" {
                continue;
            }
            if !sources.iter().any(|source| source.alias == spec_ref.source) {
                return Err(invalid(
                    "plan.specRefs.source",
                    "a non-project source must be an approved read-only alias",
                ));
            }
        }
        let mut aliases = BTreeSet::new();
        for source in &sources {
            if !aliases.insert(source.alias.clone()) {
                return Err(invalid("plan.sources", "aliases must be unique"));
            }
        }
        if parsed.schema_version() != pack.plan_schema_version {
            return Err(invalid(
                "plan.parsed.schemaVersion",
                "must equal the approved pack schema version",
            ));
        }
        Ok(Self {
            plan_path,
            source,
            plan_revision,
            parsed,
            spec_refs,
            sources,
            pack,
        })
    }

    /// Approved plan path.
    pub fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Exact approved bytes.
    pub fn source(&self) -> &ExactPlanBytes {
        &self.source
    }

    /// Exact approved bytes digest.
    pub fn digest(&self) -> &PlanDigest {
        self.source.digest()
    }

    /// Exact approved byte length.
    pub fn byte_length(&self) -> u64 {
        self.source.byte_length()
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> PlanRevision {
        self.plan_revision
    }

    /// Parsed result including the verbatim Global Constraints.
    pub fn parsed(&self) -> &ParsedPlanSummary {
        &self.parsed
    }

    /// Approved spec snapshots.
    pub fn spec_refs(&self) -> &[ApprovedSpecRef] {
        &self.spec_refs
    }

    /// Approved external read-only sources.
    pub fn sources(&self) -> &[ExternalSourceApproval] {
        &self.sources
    }

    /// Approved pack contract.
    pub fn pack(&self) -> &PackApproval {
        &self.pack
    }

    /// Rejects a plan whose parsed result and approved Task list disagree.
    pub fn ensure_matches_tasks(&self, tasks: &[TaskApproval]) -> Result<(), SddExecutionError> {
        let parsed = self.parsed.tasks();
        if parsed.len() != tasks.len() {
            return Err(invalid(
                "approval.tasks",
                "must match the parsed Task count",
            ));
        }
        for (parsed_task, task) in parsed.iter().zip(tasks) {
            if parsed_task.number() != task.task.number().get() {
                return Err(invalid(
                    "approval.tasks",
                    "Task numbers must match the parsed plan order",
                ));
            }
            if parsed_task.title() != task.title {
                return Err(invalid(
                    "approval.tasks",
                    "Task titles must match the parsed headings",
                ));
            }
        }
        Ok(())
    }
}

/// The execution connection, H2 assessment profile, and per-purpose
/// disclosure consent approved together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionConnection {
    connection_id: ConnectionId,
    profile: ProfileBinding,
    consents: Vec<ConsentBinding>,
}

impl ExecutionConnection {
    /// Creates a connection approval.
    pub fn new(
        connection_id: ConnectionId,
        profile: ProfileBinding,
        consents: Vec<ConsentBinding>,
    ) -> Result<Self, SddExecutionError> {
        if consents.is_empty() {
            return Err(invalid(
                "connection.consents",
                "at least one per-purpose consent is required",
            ));
        }
        if !consents
            .iter()
            .any(|consent| consent.purpose() == profile.purpose())
        {
            return Err(invalid(
                "connection.consents",
                "the assessment profile purpose needs its own consent",
            ));
        }
        Ok(Self {
            connection_id,
            profile,
            consents,
        })
    }

    /// H1 execution connection.
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Fixed H2 assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Per-purpose disclosure consent bindings.
    pub fn consents(&self) -> &[ConsentBinding] {
        &self.consents
    }

    /// Ensures every value belongs to `project`.
    pub fn ensure_project(&self, project: ProjectId) -> Result<(), SddExecutionError> {
        self.profile
            .ensure_project(project)
            .map_err(|error| SddExecutionError::InvalidValue {
                field: "connection.profile".to_owned(),
                detail: format!("{error}"),
            })?;
        for consent in &self.consents {
            if consent.consent_id().project_id() != project {
                return Err(SddExecutionError::CrossProjectReference {
                    id_kind: "disclosure consent".to_owned(),
                    expected: project,
                    found: consent.consent_id().project_id(),
                });
            }
            if consent.version() == 0 {
                return Err(invalid(
                    "connection.consents.version",
                    "must be greater than zero",
                ));
            }
        }
        Ok(())
    }
}

/// The host commit and hook authorization in one approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitAuthorization {
    host_commit: bool,
    run_hooks: bool,
}

impl CommitAuthorization {
    /// Records the approved host commit and hook behavior.
    ///
    /// The H4 delegation contract makes both mandatory: a human approval that
    /// omits either cannot start an execution because then no valid host commit
    /// path exists.
    pub fn new(host_commit: bool, run_hooks: bool) -> Result<Self, SddExecutionError> {
        if !host_commit || !run_hooks {
            return Err(invalid(
                "approval.commit",
                "host commit and repository hook execution are required",
            ));
        }
        Ok(Self {
            host_commit,
            run_hooks,
        })
    }

    /// Whether the host stages and commits.
    pub const fn host_commit(self) -> bool {
        self.host_commit
    }

    /// Whether repository hooks run.
    pub const fn run_hooks(self) -> bool {
        self.run_hooks
    }
}

/// The approved H3 settings, consent, and capability boundary.
///
/// These values only record what the human confirmed. They are not an H3
/// configuration approval and do not relax any H3 condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3ApprovalBinding {
    settings_version: u64,
    consents: Vec<ConsentId>,
    capabilities: Vec<String>,
}

impl H3ApprovalBinding {
    /// Creates the H3 boundary.
    pub fn new(
        settings_version: u64,
        consents: Vec<ConsentId>,
        capabilities: Vec<String>,
    ) -> Result<Self, SddExecutionError> {
        if settings_version == 0 {
            return Err(invalid("h3.settingsVersion", "must be greater than zero"));
        }
        let mut ids = BTreeSet::new();
        for consent in &consents {
            if !ids.insert(*consent) {
                return Err(invalid("h3.consents", "must not repeat a consent"));
            }
        }
        for capability in &capabilities {
            if capability.trim().is_empty() {
                return Err(invalid("h3.capabilities", "must not contain empty labels"));
            }
        }
        Ok(Self {
            settings_version,
            consents,
            capabilities,
        })
    }

    /// H3 settings record version the human confirmed.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// H3 disclosure consents that remain H3-owned.
    pub fn consents(&self) -> &[ConsentId] {
        &self.consents
    }

    /// H3 capability labels that were confirmed.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }
}

/// Everything one approval revision fixes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalContent {
    plan: PlanApproval,
    workspace: WorkspaceApproval,
    tasks: Vec<TaskApproval>,
    connection: ExecutionConnection,
    commit: CommitAuthorization,
    h3: H3ApprovalBinding,
}

impl ApprovalContent {
    /// Creates approval content and validates the cross-value bindings.
    pub fn new(
        plan: PlanApproval,
        workspace: WorkspaceApproval,
        tasks: Vec<TaskApproval>,
        connection: ExecutionConnection,
        commit: CommitAuthorization,
        h3: H3ApprovalBinding,
    ) -> Result<Self, SddExecutionError> {
        let project_id = workspace.project_id();
        let value = Self {
            plan,
            workspace,
            tasks,
            connection,
            commit,
            h3,
        };
        value.validate(project_id)?;
        Ok(value)
    }

    /// Validates every value against `project`.
    pub fn validate(&self, project: ProjectId) -> Result<(), SddExecutionError> {
        if self.workspace.project_id() != project {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "approved workspace".to_owned(),
                expected: project,
                found: self.workspace.project_id(),
            });
        }
        if self.tasks.is_empty() {
            return Err(invalid("approval.tasks", "must not be empty"));
        }
        let mut numbers = BTreeSet::new();
        for task in &self.tasks {
            task.task.ensure_project(project)?;
            if !numbers.insert(task.task.number()) {
                return Err(invalid(
                    "approval.tasks",
                    "Task numbers must be unique inside one plan",
                ));
            }
        }
        for (index, number) in numbers.iter().enumerate() {
            if number.get() != u32::try_from(index + 1).unwrap_or(u32::MAX) {
                return Err(invalid(
                    "approval.tasks",
                    "Task numbers must be contiguous from one",
                ));
            }
        }
        self.plan.ensure_matches_tasks(&self.tasks)?;
        self.connection.ensure_project(project)?;
        for consent in self.h3.consents() {
            if consent.project_id() != project {
                return Err(SddExecutionError::CrossProjectReference {
                    id_kind: "H3 consent".to_owned(),
                    expected: project,
                    found: consent.project_id(),
                });
            }
        }
        Ok(())
    }

    /// Approved plan revision.
    pub fn plan(&self) -> &PlanApproval {
        &self.plan
    }

    /// Approved workspace.
    pub fn workspace(&self) -> &WorkspaceApproval {
        &self.workspace
    }

    /// Approved Tasks.
    pub fn tasks(&self) -> &[TaskApproval] {
        &self.tasks
    }

    /// Approved connection, profile, and consent.
    pub fn connection(&self) -> &ExecutionConnection {
        &self.connection
    }

    /// Approved host commit and hook authorization.
    pub const fn commit(&self) -> CommitAuthorization {
        self.commit
    }

    /// Approved H3 boundary.
    pub fn h3(&self) -> &H3ApprovalBinding {
        &self.h3
    }

    /// Finds the Task approval for `number`.
    pub fn task(&self, number: TaskNumber) -> Option<&TaskApproval> {
        self.tasks.iter().find(|task| task.task.number() == number)
    }
}

/// One immutable H4 execution approval revision.
///
/// The value has no mutators. A new approved plan revision creates a new value
/// with a strictly greater revision and the same approval identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionApproval {
    approval_id: ApprovalId,
    project_id: ProjectId,
    revision: u64,
    actor: ApprovalActor,
    source: ApprovalSource,
    approved_at: Timestamp,
    content: ApprovalContent,
}

impl ExecutionApproval {
    /// Creates the first approval revision.
    ///
    /// Only a human actor and the approval registry source are accepted.
    pub fn new(
        approval_id: ApprovalId,
        actor: ApprovalActor,
        source: ApprovalSource,
        approved_at: Timestamp,
        content: ApprovalContent,
    ) -> Result<Self, SddExecutionError> {
        let project_id = approval_id.project_id();
        ensure_human_actor(&actor)?;
        ensure_registry_source(&source, approval_id)?;
        content.validate(project_id)?;
        Ok(Self {
            approval_id,
            project_id,
            revision: 1,
            actor,
            source,
            approved_at,
            content,
        })
    }

    /// Creates a new approval revision after a human decision.
    ///
    /// The revision must strictly increase; the approval identity, project, and
    /// registry source stay bound, so an old revision cannot be edited in place.
    pub fn revise(
        &self,
        actor: ApprovalActor,
        source: ApprovalSource,
        revision: u64,
        approved_at: Timestamp,
        content: ApprovalContent,
    ) -> Result<Self, SddExecutionError> {
        ensure_human_actor(&actor)?;
        ensure_registry_source(&source, self.approval_id)?;
        if revision <= self.revision {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::RevisionNotAdvanced {
                    current: self.revision,
                    supplied: revision,
                },
            });
        }
        content.validate(self.project_id)?;
        Ok(Self {
            approval_id: self.approval_id,
            project_id: self.project_id,
            revision,
            actor,
            source,
            approved_at,
            content,
        })
    }

    /// Approval identity.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Project that owns the approval.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approval revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Actor that issued the approval.
    pub fn actor(&self) -> &ApprovalActor {
        &self.actor
    }

    /// Approval source.
    pub fn source(&self) -> &ApprovalSource {
        &self.source
    }

    /// When the approval was recorded.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }

    /// Approved content.
    pub fn content(&self) -> &ApprovalContent {
        &self.content
    }

    /// Approved plan revision.
    pub fn plan(&self) -> &PlanApproval {
        self.content.plan()
    }

    /// Approved workspace.
    pub fn workspace(&self) -> &WorkspaceApproval {
        self.content.workspace()
    }

    /// Approved Tasks.
    pub fn tasks(&self) -> &[TaskApproval] {
        self.content.tasks()
    }

    /// Approved connection.
    pub fn connection(&self) -> &ExecutionConnection {
        self.content.connection()
    }

    /// Approved commit authorization.
    pub const fn commit(&self) -> CommitAuthorization {
        self.content.commit()
    }

    /// Approved H3 boundary.
    pub fn h3(&self) -> &H3ApprovalBinding {
        self.content.h3()
    }

    /// Whether the approval actor is human.
    pub fn is_human(&self) -> bool {
        matches!(self.actor, ApprovalActor::Human)
    }

    /// Whether the approval came from the registry.
    pub fn is_registry(&self) -> bool {
        self.source.is_registry()
    }
}

fn ensure_human_actor(actor: &ApprovalActor) -> Result<(), SddExecutionError> {
    if matches!(actor, ApprovalActor::Human) {
        Ok(())
    } else {
        Err(SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::ActorNotHuman {
                actor: actor_label(actor).to_owned(),
            },
        })
    }
}

fn actor_label(actor: &ApprovalActor) -> &'static str {
    match actor {
        ApprovalActor::Human => "human",
        ApprovalActor::ApprovedOwner { .. } => "approved_owner",
        ApprovalActor::Model => "model",
    }
}

fn ensure_registry_source(
    source: &ApprovalSource,
    approval_id: ApprovalId,
) -> Result<(), SddExecutionError> {
    source.ensure_accepted()?;
    if let ApprovalSource::ApprovalRegistry {
        approval_id: source_id,
    } = source
        && *source_id != approval_id
    {
        return Err(invalid(
            "approval.source.approvalId",
            "the registry source must name this approval",
        ));
    }
    Ok(())
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

fn path_within(path: &str, scope: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Validates a short stable identifier from the plan.
fn validate_identifier(field: &str, value: &str) -> Result<(), SddExecutionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if trimmed.chars().count() > 128 {
        return Err(invalid(field, "must contain at most 128 characters"));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(invalid(field, "must not contain control characters"));
    }
    Ok(())
}
