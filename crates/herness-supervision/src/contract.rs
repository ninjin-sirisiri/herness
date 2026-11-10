//! Supervision subject, execution scope, run group, and the approved contract.
//!
//! A contract is created only from conditions approved by a human or by an
//! already-approved H3/H4 owner. A model can propose conditions but cannot
//! approve or change any part of this value.

use serde::{Deserialize, Serialize};

use herness_core::contracts::{AgentId, ContractVersion, ProjectId, RunId, SessionId, Timestamp};

use crate::approval::{ApprovalActor, ApprovalBasis, ConditionApproval};
use crate::budget::BudgetPolicy;
use crate::conditions::ConditionSet;
use crate::consent::{ConsentBinding, ConsentBlock, DisclosureConsent, DisclosureRequest};
use crate::error::SupervisionError;
use crate::evidence::TargetScope;
use crate::ids::{RunGroupId, SupervisionId, verify_core_id, verify_scoped};
use crate::packet::WorkPacket;
use crate::profiles::{AssessmentProfile, ProfileBinding, ProfilePurpose};
use crate::version::current_contract_version;

/// Opaque kind of the owner that requested one supervised child agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    /// An H3 HTML job.
    H3HtmlJob,
    /// An H4 SDD Task.
    H4SddTask,
    /// A human started the supervision directly.
    Human,
}

impl OwnerKind {
    /// Whether this owner kind is an already-approved H3/H4 owner whose
    /// approval may be inherited.
    pub const fn is_approved_owner(self) -> bool {
        matches!(self, Self::H3HtmlJob | Self::H4SddTask)
    }
}

/// Opaque reference to an H3 job, H4 Task, or human decision.
///
/// The string is owned by the producing phase. H2 never parses it or infers
/// approval from prose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerRef {
    kind: OwnerKind,
    reference: String,
}

impl OwnerRef {
    /// Creates a non-empty opaque owner reference.
    pub fn new(kind: OwnerKind, reference: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let trimmed = reference.as_ref().trim();
        if trimmed.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "owner.reference".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if trimmed.chars().count() > 256 {
            return Err(SupervisionError::InvalidValue {
                field: "owner.reference".to_owned(),
                detail: "must contain at most 256 characters".to_owned(),
            });
        }
        Ok(Self {
            kind,
            reference: trimmed.to_owned(),
        })
    }

    /// Owner kind.
    pub const fn kind(&self) -> OwnerKind {
        self.kind
    }

    /// Opaque owner-owned reference.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Whether this reference names an already-approved H3/H4 owner.
    pub const fn is_approved_owner(&self) -> bool {
        self.kind.is_approved_owner()
    }
}

/// The child agent, project, and owner of one supervision target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisionSubject {
    project_id: ProjectId,
    supervision_id: SupervisionId,
    agent_id: AgentId,
    session_id: SessionId,
    owner: OwnerRef,
}

impl SupervisionSubject {
    /// Creates a subject whose supervision, agent, and session IDs share one
    /// project.
    pub fn new(
        project_id: ProjectId,
        supervision_id: SupervisionId,
        agent_id: AgentId,
        session_id: SessionId,
        owner: OwnerRef,
    ) -> Result<Self, SupervisionError> {
        verify_scoped(&supervision_id, project_id)?;
        verify_core_id(&agent_id, project_id)?;
        verify_core_id(&session_id, project_id)?;
        Ok(Self {
            project_id,
            supervision_id,
            agent_id,
            session_id,
            owner,
        })
    }

    /// Project that owns the supervision target.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Stable supervision target identifier.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Child agent.
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Child conversation session.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Opaque owner reference.
    pub fn owner(&self) -> &OwnerRef {
        &self.owner
    }
}

/// Paths and tools the supervised child may use.
///
/// This is a host-owned contract value; H1 remains the executor and enforces
/// its own grant boundary. The paths are project-relative and never a claim of
/// operating-system isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionScope {
    project_id: ProjectId,
    read_paths: Vec<String>,
    write_paths: Vec<String>,
    allow_shell: bool,
}

impl ExecutionScope {
    /// Creates a bounded execution scope.
    pub fn new(
        project_id: ProjectId,
        read_paths: Vec<String>,
        write_paths: Vec<String>,
        allow_shell: bool,
    ) -> Result<Self, SupervisionError> {
        if read_paths.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "executionScope.readPaths".to_owned(),
                detail: "must contain at least one bounded path".to_owned(),
            });
        }
        for (field, paths) in [("readPaths", &read_paths), ("writePaths", &write_paths)] {
            for path in paths {
                validate_relative_scope_path(field, path)?;
            }
        }
        Ok(Self {
            project_id,
            read_paths,
            write_paths,
            allow_shell,
        })
    }

    /// Project this scope belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Paths the child may read.
    pub fn read_paths(&self) -> &[String] {
        &self.read_paths
    }

    /// Paths the child may write.
    pub fn write_paths(&self) -> &[String] {
        &self.write_paths
    }

    /// Whether shell tools are inside the scope.
    pub const fn allow_shell(&self) -> bool {
        self.allow_shell
    }
}

fn validate_relative_scope_path(field: &str, path: &str) -> Result<(), SupervisionError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "path must not be empty".to_owned(),
        });
    }
    if trimmed == "*" || trimmed == "." || trimmed == "/" {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "an unbounded scope path is not allowed".to_owned(),
        });
    }
    if std::path::Path::new(trimmed).is_absolute() {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "scope paths must be project-relative".to_owned(),
        });
    }
    if trimmed.split('/').any(|part| part == "..") {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "a scope path must not escape the project".to_owned(),
        });
    }
    Ok(())
}

/// Runs that belong to one supervised continuation sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunGroup {
    id: RunGroupId,
    runs: Vec<RunId>,
}

impl RunGroup {
    /// Creates an empty run group.
    pub const fn new(id: RunGroupId) -> Self {
        Self {
            id,
            runs: Vec::new(),
        }
    }

    /// Run-group identifier.
    pub const fn id(&self) -> RunGroupId {
        self.id
    }

    /// Runs in the group, in start order.
    pub fn runs(&self) -> &[RunId] {
        &self.runs
    }

    /// Records one run, rejecting a run from another project.
    pub fn push(&mut self, run: RunId) -> Result<(), SupervisionError> {
        verify_core_id(&run, self.id.project_id())?;
        if !self.runs.contains(&run) {
            self.runs.push(run);
        }
        Ok(())
    }

    /// Whether the group contains `run`.
    pub fn contains(&self, run: &RunId) -> bool {
        self.runs.contains(run)
    }

    /// Rejects a deserialized group carrying a run from another project.
    pub fn validate(&self, project: ProjectId) -> Result<(), SupervisionError> {
        verify_scoped(&self.id, project)?;
        for run in &self.runs {
            verify_core_id(run, project)?;
        }
        Ok(())
    }
}

/// Approved H2 supervision contract for one child agent.
///
/// The value fixes the condition version, target version, assessment-profile
/// version, disclosure-consent version, finite budget, execution scope, and run
/// group. Any change increments [`SupervisionContract::revision`] and requires
/// a new approval; prior decisions must not be applied to the new version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisionContract {
    contract_version: ContractVersion,
    revision: u64,
    subject: SupervisionSubject,
    execution_scope: ExecutionScope,
    run_group: RunGroup,
    conditions: ConditionSet,
    evidence_target: TargetScope,
    profile: ProfileBinding,
    consent: ConsentBinding,
    budget: BudgetPolicy,
    work_packet: WorkPacket,
}

impl SupervisionContract {
    /// Creates an approved contract from an explicit human or approved-owner
    /// approval. A model actor is rejected even when approval data is supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: ApprovalActor,
        subject: SupervisionSubject,
        execution_scope: ExecutionScope,
        run_group: RunGroup,
        conditions: ConditionSet,
        evidence_target: TargetScope,
        profile: &AssessmentProfile,
        consent: &DisclosureConsent,
        budget: BudgetPolicy,
        work_packet: WorkPacket,
        now: Timestamp,
    ) -> Result<Self, SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "create a supervision contract".to_owned(),
            });
        }
        if let ApprovalActor::ApprovedOwner { owner, .. } = &actor
            && (owner != subject.owner() || !owner.is_approved_owner())
        {
            return Err(SupervisionError::ApprovalRejected {
                reason: crate::error::ApprovalRejection::ActorMismatch,
            });
        }

        let project = subject.project_id();
        verify_scoped(&subject.supervision_id, project)?;
        if execution_scope.project_id != project {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "execution scope".to_owned(),
                expected: project,
                found: execution_scope.project_id,
            });
        }
        if run_group.id.project_id() != project {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "run group".to_owned(),
                expected: project,
                found: run_group.id.project_id(),
            });
        }
        run_group.validate(project)?;
        conditions.ensure_project(project)?;
        evidence_target.ensure_project(project)?;
        consent.ensure_project(project)?;
        profile.binding().ensure_project(project)?;

        if profile.purpose() != consent.purpose() {
            return Err(SupervisionError::InvalidValue {
                field: "profile.purpose".to_owned(),
                detail: "the assessment profile purpose must match the disclosure purpose"
                    .to_owned(),
            });
        }
        if consent.target_scope_version() != evidence_target.version() {
            return Err(SupervisionError::InvalidValue {
                field: "consent.targetScopeVersion".to_owned(),
                detail: "consent must be bound to the current target scope version".to_owned(),
            });
        }
        conditions.require_approval(now)?;
        consent.require_granted()?;
        work_packet.ensure_binding(
            &execution_scope,
            conditions.condition_version(),
            profile.binding(),
            consent.binding(),
            &evidence_target,
            &budget,
        )?;

        Ok(Self {
            contract_version: current_contract_version(),
            revision: 1,
            subject,
            execution_scope,
            run_group,
            conditions,
            evidence_target,
            profile: profile.binding(),
            consent: consent.binding(),
            budget,
            work_packet,
        })
    }

    /// Contract version written by this build.
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    /// Monotonic contract revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Subject, owner, and child agent.
    pub fn subject(&self) -> &SupervisionSubject {
        &self.subject
    }

    /// Bounded execution scope.
    pub fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Run group.
    pub fn run_group(&self) -> &RunGroup {
        &self.run_group
    }

    /// Approved conditions and required checks.
    pub fn conditions(&self) -> &ConditionSet {
        &self.conditions
    }

    /// Evidence target scope and version.
    pub fn evidence_target(&self) -> &TargetScope {
        &self.evidence_target
    }

    /// Fixed assessment-profile binding.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed disclosure-consent binding.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Finite budget policy.
    pub fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// Immutable owner work packet fixed by the same approval.
    pub const fn work_packet(&self) -> &WorkPacket {
        &self.work_packet
    }

    /// Project that owns the contract.
    pub const fn project_id(&self) -> ProjectId {
        self.subject.project_id
    }

    /// Validates the contract again before a start or resume.
    pub fn validate_for_start(&self, now: Timestamp) -> Result<(), SupervisionError> {
        crate::version::ensure_current_version(self.contract_version)?;
        self.work_packet.verify()?;
        self.work_packet.ensure_binding(
            &self.execution_scope,
            self.conditions.condition_version(),
            self.profile,
            self.consent,
            &self.evidence_target,
            &self.budget,
        )?;
        self.conditions.require_approval(now)?;
        if self.profile.purpose() != self.consent.purpose() {
            return Err(SupervisionError::InvalidValue {
                field: "profile.purpose".to_owned(),
                detail: "the assessment profile purpose must match the disclosure purpose"
                    .to_owned(),
            });
        }
        if self.consent.target_scope_version() != self.evidence_target.version() {
            return Err(SupervisionError::InvalidValue {
                field: "consent.targetScopeVersion".to_owned(),
                detail: "consent must be bound to the current target scope version".to_owned(),
            });
        }
        Ok(())
    }

    /// Changes conditions after a human or approved-owner decision.
    ///
    /// A model actor is rejected. The new set must be approved and carry a
    /// strictly newer condition version. Prior completions and decisions are
    /// invalidated by the resulting contract revision.
    pub fn revise_conditions(
        &mut self,
        actor: ApprovalActor,
        conditions: ConditionSet,
        now: Timestamp,
    ) -> Result<(), SupervisionError> {
        self.reject_model(actor, "change completion conditions")?;
        conditions.ensure_project(self.project_id())?;
        if conditions.condition_version() <= self.conditions.condition_version() {
            return Err(SupervisionError::InvalidValue {
                field: "conditions.version".to_owned(),
                detail: "a revised condition set must have a newer version".to_owned(),
            });
        }
        conditions.require_approval(now)?;
        self.work_packet = self
            .work_packet
            .revised_conditions(conditions.condition_version())?;
        self.conditions = conditions;
        self.bump_revision();
        Ok(())
    }

    /// Changes the fixed assessment profile after a human or approved-owner
    /// decision. A model actor is rejected.
    pub fn revise_profile(
        &mut self,
        actor: ApprovalActor,
        profile: &AssessmentProfile,
    ) -> Result<(), SupervisionError> {
        self.reject_model(actor, "change the assessment profile")?;
        profile.binding().ensure_project(self.project_id())?;
        if profile.purpose() != self.consent.purpose() {
            return Err(SupervisionError::InvalidValue {
                field: "profile.purpose".to_owned(),
                detail: "the assessment profile purpose must match the disclosure purpose"
                    .to_owned(),
            });
        }
        self.profile = profile.binding();
        self.work_packet = self.work_packet.revised_profile(profile.binding())?;
        self.bump_revision();
        Ok(())
    }

    /// Changes the finite budget after a human or approved-owner decision.
    pub fn revise_budget(
        &mut self,
        actor: ApprovalActor,
        budget: BudgetPolicy,
    ) -> Result<(), SupervisionError> {
        self.reject_model(actor, "change the budget")?;
        self.budget = budget.clone();
        self.work_packet = self
            .work_packet
            .revised_budget(budget, self.work_packet.budget_policy_version())?;
        self.bump_revision();
        Ok(())
    }

    /// Changes the execution scope after a human or approved-owner decision.
    pub fn revise_permissions(
        &mut self,
        actor: ApprovalActor,
        scope: ExecutionScope,
    ) -> Result<(), SupervisionError> {
        self.reject_model(actor, "change the execution scope")?;
        if scope.project_id != self.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "execution scope".to_owned(),
                expected: self.project_id(),
                found: scope.project_id,
            });
        }
        self.execution_scope = scope;
        self.work_packet = self
            .work_packet
            .revised_scope(self.execution_scope.clone())?;
        self.bump_revision();
        Ok(())
    }

    /// Applies the disclosure gate for one would-be assessment request.
    pub fn authorize_disclosure(
        &self,
        consent: &DisclosureConsent,
        request: &DisclosureRequest,
    ) -> Result<(), ConsentBlock> {
        if consent.binding() != self.consent {
            return Err(ConsentBlock::VersionMismatch);
        }
        if request.purpose() != self.profile.purpose() {
            return Err(ConsentBlock::DifferentPurpose);
        }
        consent.authorize(request)
    }

    fn reject_model(&self, actor: ApprovalActor, action: &str) -> Result<(), SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: action.to_owned(),
            });
        }
        if let ApprovalActor::ApprovedOwner { owner, .. } = &actor
            && (owner != self.subject.owner() || !owner.is_approved_owner())
        {
            return Err(SupervisionError::ApprovalRejected {
                reason: crate::error::ApprovalRejection::ActorMismatch,
            });
        }
        Ok(())
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

/// Compares whether two approval bases are the same kind of decision.
///
/// Explicit human confirmation and inherited owner approval remain distinct
/// values; a caller must not silently treat one as the other.
pub fn same_approval_kind(left: &ApprovalBasis, right: &ApprovalBasis) -> bool {
    matches!(
        (left, right),
        (
            ApprovalBasis::ExplicitHuman { .. },
            ApprovalBasis::ExplicitHuman { .. }
        ) | (
            ApprovalBasis::InheritedOwner { .. },
            ApprovalBasis::InheritedOwner { .. }
        )
    )
}

/// Helper used by fixtures and later composition: verifies that an approval
/// record was issued for this project and condition set.
pub fn approval_matches_conditions(
    approval: &ConditionApproval,
    project: ProjectId,
    conditions: &ConditionSet,
) -> bool {
    approval.project_id() == project
        && approval.condition_version() == conditions.condition_version()
        && approval.conditions_digest() == conditions.digest()
}

/// Returns the profile purpose required for a disclosure request.
pub fn disclosure_purpose(profile: &AssessmentProfile) -> ProfilePurpose {
    profile.purpose()
}
