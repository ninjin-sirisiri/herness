//! Host-only approved-owner startup authority.
//!
//! H3 owns the current configuration-approval registry and H4 owns the current
//! plan-approval registry. This module defines the two registry ports and the
//! non-serializable authority token H2 requires before an approved owner may
//! start a target without a human confirmation. Naming an
//! [`OwnerKind::H3HtmlJob`] / [`OwnerKind::H4SddTask`], sending a serializable
//! [`crate::approval::ApprovalActor::ApprovedOwner`], or reusing an H3 approval
//! is never an authority by itself: the token is minted only after the current
//! registry entry matches every approved constraint.
//!
//! The two registries stay separate on purpose. [`authorize_owner_launch`]
//! serves the H3 configuration registry and keeps refusing H4 with
//! [`OwnerLaunchRejection::H4ApprovalUnavailable`], so an H3-shaped registry
//! implementation can never clear H4 approval. H4 approval is minted only by
//! [`authorize_h4_owner_launch`] from an
//! [`H4OwnerApprovalRegistryPort`], and only when the entry matches the plan
//! revision and digest, the immutable Task packet, the H2 condition set, scope,
//! profile, consent, finite budget, host-commit and hook approval, and the pack
//! execution-contract fingerprint.
//!
//! The token deliberately implements neither `Serialize` nor `Deserialize`,
//! has private fields, has no public constructor, and is not `Clone`. A receipt,
//! IPC payload, repo file, environment variable, or model output therefore
//! cannot be turned into a token.

use std::fmt;

use herness_core::contracts::{ProjectId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::approval::OwnerApprovalSource;
use crate::budget::BudgetPolicy;
use crate::conditions::{ConditionDigest, ConditionVersion};
use crate::consent::ConsentBinding;
use crate::contract::{ExecutionScope, OwnerKind, OwnerRef, SupervisionContract};
use crate::error::{OwnerLaunchRejection, SupervisionError};
use crate::evidence::ContentDigest;
use crate::ids::SupervisionId;
use crate::profiles::ProfileBinding;

/// Current owner approval reported by the phase that owns the registry.
///
/// H3 settings approval and H4 plan approval remain separate. This value
/// contains no credential, prompt, receipt, or model text. The target-level
/// [`SupervisionId`] is deliberately not part of the registry entry: H3 owns the
/// job-to-target mapping, and the minted token binds the target separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerApproval {
    project_id: ProjectId,
    owner: OwnerRef,
    source: OwnerApprovalSource,
    settings_version: u64,
    job_id: String,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
    execution_scope: ExecutionScope,
    profile: ProfileBinding,
    consent: ConsentBinding,
    budget_policy_version: u64,
    budget: BudgetPolicy,
}

impl OwnerApproval {
    /// Creates one current approval record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        owner: OwnerRef,
        source: OwnerApprovalSource,
        settings_version: u64,
        job_id: impl AsRef<str>,
        condition_version: ConditionVersion,
        conditions_digest: ConditionDigest,
        execution_scope: ExecutionScope,
        profile: ProfileBinding,
        consent: ConsentBinding,
        budget_policy_version: u64,
        budget: BudgetPolicy,
    ) -> Result<Self, SupervisionError> {
        let expected_source = match owner.kind() {
            OwnerKind::H3HtmlJob => Some(OwnerApprovalSource::H3ApprovedSettings),
            OwnerKind::H4SddTask => Some(OwnerApprovalSource::H4ApprovedPlan),
            OwnerKind::Human => None,
        };
        let Some(expected_source) = expected_source else {
            return Err(SupervisionError::OwnerLaunchRejected {
                reason: OwnerLaunchRejection::OwnerNotApproved,
            });
        };
        if source != expected_source {
            return Err(SupervisionError::OwnerLaunchRejected {
                reason: OwnerLaunchRejection::SourceMismatch,
            });
        }
        if settings_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "ownerApproval.settingsVersion".to_owned(),
                detail: "the approved settings version must be positive".to_owned(),
            });
        }
        if budget_policy_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "ownerApproval.budgetPolicyVersion".to_owned(),
                detail: "the approved budget policy version must be positive".to_owned(),
            });
        }
        let job_id = job_id.as_ref().trim();
        if job_id.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "ownerApproval.jobId".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if job_id.chars().count() > 256 {
            return Err(SupervisionError::InvalidValue {
                field: "ownerApproval.jobId".to_owned(),
                detail: "must contain at most 256 characters".to_owned(),
            });
        }
        if execution_scope.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "owner approval execution scope".to_owned(),
                expected: project_id,
                found: execution_scope.project_id(),
            });
        }
        profile.ensure_project(project_id)?;
        if consent.consent_id().project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "owner approval consent".to_owned(),
                expected: project_id,
                found: consent.consent_id().project_id(),
            });
        }
        if profile.purpose() != consent.purpose() {
            return Err(SupervisionError::InvalidValue {
                field: "ownerApproval.profile".to_owned(),
                detail: "the approved profile purpose must match the consent purpose".to_owned(),
            });
        }
        Ok(Self {
            project_id,
            owner,
            source,
            settings_version,
            job_id: job_id.to_owned(),
            condition_version,
            conditions_digest,
            execution_scope,
            profile,
            consent,
            budget_policy_version,
            budget,
        })
    }

    /// Builds the expected approval value from an already-approved contract.
    ///
    /// This is the request side and is not a registry source: it never proves
    /// that any owner approved anything. The opaque settings version and job ID
    /// are supplied by the owner phase; every other field comes from the
    /// contract so a caller cannot request a weaker constraint set than the one
    /// H2 approved.
    pub fn from_contract(
        contract: &SupervisionContract,
        budget_policy_version: u64,
        settings_version: u64,
        job_id: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        Self::new(
            contract.project_id(),
            contract.subject().owner().clone(),
            source_for_owner(contract.subject().owner().kind())?,
            settings_version,
            job_id,
            contract.conditions().condition_version(),
            contract.conditions().digest().clone(),
            contract.execution_scope().clone(),
            contract.profile(),
            contract.consent(),
            budget_policy_version,
            contract.budget().clone(),
        )
    }

    /// Project this approval belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approved owner.
    pub fn owner(&self) -> &OwnerRef {
        &self.owner
    }

    /// Phase-specific approval source.
    pub const fn source(&self) -> OwnerApprovalSource {
        self.source
    }

    /// H3/H4-owned settings or approval version.
    pub const fn settings_version(&self) -> u64 {
        self.settings_version
    }

    /// Opaque owner-owned job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Condition version covered by the approval.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact condition content digest covered by the approval.
    pub fn conditions_digest(&self) -> &ConditionDigest {
        &self.conditions_digest
    }

    /// Approved execution scope.
    pub fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Fixed assessment-profile binding.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed disclosure-consent binding.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Approved budget policy version.
    pub const fn budget_policy_version(&self) -> u64 {
        self.budget_policy_version
    }

    /// Finite approved budget policy.
    pub fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    fn ensure_matches(&self, requested: &Self) -> Result<(), SupervisionError> {
        if self.project_id != requested.project_id {
            return Err(rejected(OwnerLaunchRejection::ProjectMismatch));
        }
        if self.owner != requested.owner {
            return Err(rejected(OwnerLaunchRejection::OwnerMismatch));
        }
        if self.source != requested.source {
            return Err(rejected(OwnerLaunchRejection::SourceMismatch));
        }
        if self.settings_version != requested.settings_version {
            return Err(rejected(OwnerLaunchRejection::StaleSettings {
                requested: requested.settings_version,
                registered: self.settings_version,
            }));
        }
        if self.job_id != requested.job_id {
            return Err(rejected(OwnerLaunchRejection::JobMismatch));
        }
        if self.condition_version != requested.condition_version {
            return Err(rejected(OwnerLaunchRejection::StaleConditions {
                requested: requested.condition_version.get(),
                registered: self.condition_version.get(),
            }));
        }
        if self.conditions_digest != requested.conditions_digest {
            return Err(rejected(OwnerLaunchRejection::ConditionDigestMismatch));
        }
        if self.execution_scope != requested.execution_scope {
            return Err(rejected(OwnerLaunchRejection::ScopeMismatch));
        }
        if self.profile != requested.profile {
            return Err(rejected(OwnerLaunchRejection::ProfileMismatch));
        }
        if self.consent != requested.consent {
            return Err(rejected(OwnerLaunchRejection::ConsentMismatch));
        }
        if self.budget_policy_version != requested.budget_policy_version {
            return Err(rejected(
                OwnerLaunchRejection::BudgetPolicyVersionMismatch {
                    requested: requested.budget_policy_version,
                    registered: self.budget_policy_version,
                },
            ));
        }
        if self.budget != requested.budget {
            return Err(rejected(OwnerLaunchRejection::BudgetMismatch));
        }
        Ok(())
    }
}

/// One target-bound owner approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerLaunchBinding {
    supervision_id: SupervisionId,
    approval: OwnerApproval,
}

impl OwnerLaunchBinding {
    /// Binds one current approval to the exact H2 target.
    pub fn new(
        supervision_id: SupervisionId,
        approval: OwnerApproval,
    ) -> Result<Self, SupervisionError> {
        if supervision_id.project_id() != approval.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "owner launch target".to_owned(),
                expected: approval.project_id(),
                found: supervision_id.project_id(),
            });
        }
        Ok(Self {
            supervision_id,
            approval,
        })
    }

    /// Builds the exact target binding from an approved contract.
    pub fn from_contract(
        contract: &SupervisionContract,
        budget_policy_version: u64,
        settings_version: u64,
        job_id: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        Self::new(
            contract.subject().supervision_id(),
            OwnerApproval::from_contract(
                contract,
                budget_policy_version,
                settings_version,
                job_id,
            )?,
        )
    }

    /// Target that would be started.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Project that owns the target.
    pub const fn project_id(&self) -> ProjectId {
        self.approval.project_id
    }

    /// Exact current approval expected by the target.
    pub const fn approval(&self) -> &OwnerApproval {
        &self.approval
    }
}

/// Opaque stable identity of one H4 execution.
///
/// H2 never parses this value, derives a Task from it, or treats it as an
/// approval. It only proves that the current H4 registry entry and the target
/// being launched name the same execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct H4ExecutionRef(String);

impl H4ExecutionRef {
    /// Creates a non-empty opaque execution reference.
    pub fn new(reference: impl AsRef<str>) -> Result<Self, SupervisionError> {
        Ok(Self(validate_reference("h4Execution", reference.as_ref())?))
    }

    /// Opaque execution reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable H4 Task identity plus the plan's number.
///
/// The number is the plan label; the stable identity is what must not be
/// re-derived from a conversation or a heading.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H4TaskRef {
    stable_id: String,
    number: u32,
}

impl H4TaskRef {
    /// Creates one H4 Task reference.
    pub fn new(stable_id: impl AsRef<str>, number: u32) -> Result<Self, SupervisionError> {
        if number == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Task.number".to_owned(),
                detail: "Task numbers start at one".to_owned(),
            });
        }
        Ok(Self {
            stable_id: validate_reference("h4Task.stableId", stable_id.as_ref())?,
            number,
        })
    }

    /// Stable Task identity.
    pub fn stable_id(&self) -> &str {
        &self.stable_id
    }

    /// Plan-assigned Task number.
    pub const fn number(&self) -> u32 {
        self.number
    }
}

/// Digests of the immutable H4 Task packet.
///
/// The packet is the exact context the child receives first and on every
/// continuation. H2 compares the three digests rather than trusting a saved
/// packet, a plan body, or a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H4PacketBinding {
    task_body_digest: ContentDigest,
    global_constraints_digest: ContentDigest,
    spec_snapshot_digest: ContentDigest,
}

impl H4PacketBinding {
    /// Creates the packet binding from the three approved digests.
    pub const fn new(
        task_body_digest: ContentDigest,
        global_constraints_digest: ContentDigest,
        spec_snapshot_digest: ContentDigest,
    ) -> Self {
        Self {
            task_body_digest,
            global_constraints_digest,
            spec_snapshot_digest,
        }
    }

    /// Digest of the exact Task body handed to the child.
    pub const fn task_body_digest(&self) -> &ContentDigest {
        &self.task_body_digest
    }

    /// Digest of the verbatim Global Constraints section.
    pub const fn global_constraints_digest(&self) -> &ContentDigest {
        &self.global_constraints_digest
    }

    /// Digest of the referenced spec snapshot.
    pub const fn spec_snapshot_digest(&self) -> &ContentDigest {
        &self.spec_snapshot_digest
    }

    /// Field that differs, when this packet differs from `other`.
    fn mismatch(&self, other: &Self) -> Option<&'static str> {
        if self.task_body_digest != other.task_body_digest {
            Some("taskBodyDigest")
        } else if self.global_constraints_digest != other.global_constraints_digest {
            Some("globalConstraintsDigest")
        } else if self.spec_snapshot_digest != other.spec_snapshot_digest {
            Some("specSnapshotDigest")
        } else {
            None
        }
    }
}

impl fmt::Display for H4PacketBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "task={} constraints={} spec={}",
            self.task_body_digest, self.global_constraints_digest, self.spec_snapshot_digest
        )
    }
}

/// The host-commit and hook behavior the human approved for one execution.
///
/// Both are mandatory for H4: an execution without host commit and repository
/// hook execution has no valid completion path, so a missing approval is a
/// refusal rather than a weaker start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H4CommitAuthorization {
    host_commit: bool,
    run_hooks: bool,
}

impl H4CommitAuthorization {
    /// Records the approved host commit and hook behavior.
    pub fn new(host_commit: bool, run_hooks: bool) -> Result<Self, SupervisionError> {
        if !host_commit || !run_hooks {
            return Err(SupervisionError::InvalidValue {
                field: "h4Approval.commit".to_owned(),
                detail: "host commit and repository hook execution are required".to_owned(),
            });
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

    /// Whether both host commit and hook execution are authorized.
    ///
    /// A decoded value is not trusted by shape alone: every launch requires this
    /// to be `true` on both the registry entry and the request.
    pub const fn is_fully_authorized(self) -> bool {
        self.host_commit && self.run_hooks
    }
}

/// H4-owned identity one launch requests, independent of the H2 contract.
///
/// This is the request side only. It is not an approval: the H4 registry entry
/// is the only source of truth, and every field here is compared against it
/// before a token is minted. A coordinator builds it from the stored H4
/// approval and Task; nothing serializable is trusted on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H4LaunchRequest {
    execution: H4ExecutionRef,
    task: H4TaskRef,
    plan_revision: u64,
    plan_digest: ContentDigest,
    packet: H4PacketBinding,
    pack_fingerprint: ContentDigest,
    commit: H4CommitAuthorization,
}

impl H4LaunchRequest {
    /// Creates one H4 launch request.
    pub fn new(
        execution: H4ExecutionRef,
        task: H4TaskRef,
        plan_revision: u64,
        plan_digest: ContentDigest,
        packet: H4PacketBinding,
        pack_fingerprint: ContentDigest,
        commit: H4CommitAuthorization,
    ) -> Result<Self, SupervisionError> {
        if plan_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Launch.planRevision".to_owned(),
                detail: "plan revisions start at one".to_owned(),
            });
        }
        Ok(Self {
            execution,
            task,
            plan_revision,
            plan_digest,
            packet,
            pack_fingerprint,
            commit,
        })
    }

    /// Execution the launch belongs to.
    pub const fn execution(&self) -> &H4ExecutionRef {
        &self.execution
    }

    /// Task the launch belongs to.
    pub const fn task(&self) -> &H4TaskRef {
        &self.task
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    /// Digest of the exact approved plan bytes.
    pub const fn plan_digest(&self) -> &ContentDigest {
        &self.plan_digest
    }

    /// Immutable packet binding.
    pub const fn packet(&self) -> &H4PacketBinding {
        &self.packet
    }

    /// Pack execution-contract fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Approved host-commit and hook behavior.
    pub const fn commit(&self) -> H4CommitAuthorization {
        self.commit
    }
}

/// One current H4 approval entry reported by the H4 registry.
///
/// The value carries the H4-owned plan, Task, packet, pack, and commit
/// constraints plus the H2-owned condition set, scope, profile, consent, and
/// finite budget. It contains no credential, prompt, plan body, receipt, or
/// model text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H4OwnerApproval {
    project_id: ProjectId,
    owner: OwnerRef,
    execution: H4ExecutionRef,
    task: H4TaskRef,
    plan_revision: u64,
    plan_digest: ContentDigest,
    packet: H4PacketBinding,
    pack_fingerprint: ContentDigest,
    commit: H4CommitAuthorization,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
    execution_scope: ExecutionScope,
    profile: ProfileBinding,
    consent: ConsentBinding,
    budget_policy_version: u64,
    budget: BudgetPolicy,
}

impl H4OwnerApproval {
    /// Creates one current H4 approval record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: ProjectId,
        owner: OwnerRef,
        execution: H4ExecutionRef,
        task: H4TaskRef,
        plan_revision: u64,
        plan_digest: ContentDigest,
        packet: H4PacketBinding,
        pack_fingerprint: ContentDigest,
        commit: H4CommitAuthorization,
        condition_version: ConditionVersion,
        conditions_digest: ConditionDigest,
        execution_scope: ExecutionScope,
        profile: ProfileBinding,
        consent: ConsentBinding,
        budget_policy_version: u64,
        budget: BudgetPolicy,
    ) -> Result<Self, SupervisionError> {
        if owner.kind() != OwnerKind::H4SddTask {
            return Err(rejected(OwnerLaunchRejection::OwnerNotApproved));
        }
        if plan_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Approval.planRevision".to_owned(),
                detail: "plan revisions start at one".to_owned(),
            });
        }
        if budget_policy_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Approval.budgetPolicyVersion".to_owned(),
                detail: "the approved budget policy version must be positive".to_owned(),
            });
        }
        if execution_scope.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "H4 approval execution scope".to_owned(),
                expected: project_id,
                found: execution_scope.project_id(),
            });
        }
        profile.ensure_project(project_id)?;
        if consent.consent_id().project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "H4 approval consent".to_owned(),
                expected: project_id,
                found: consent.consent_id().project_id(),
            });
        }
        if profile.purpose() != consent.purpose() {
            return Err(SupervisionError::InvalidValue {
                field: "h4Approval.profile".to_owned(),
                detail: "the approved profile purpose must match the consent purpose".to_owned(),
            });
        }
        budget.validate()?;
        Ok(Self {
            project_id,
            owner,
            execution,
            task,
            plan_revision,
            plan_digest,
            packet,
            pack_fingerprint,
            commit,
            condition_version,
            conditions_digest,
            execution_scope,
            profile,
            consent,
            budget_policy_version,
            budget,
        })
    }

    /// Project this approval belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Approved H4 owner.
    pub const fn owner(&self) -> &OwnerRef {
        &self.owner
    }

    /// Approved execution.
    pub const fn execution(&self) -> &H4ExecutionRef {
        &self.execution
    }

    /// Approved Task.
    pub const fn task(&self) -> &H4TaskRef {
        &self.task
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    /// Approved plan digest.
    pub const fn plan_digest(&self) -> &ContentDigest {
        &self.plan_digest
    }

    /// Approved immutable packet binding.
    pub const fn packet(&self) -> &H4PacketBinding {
        &self.packet
    }

    /// Approved pack execution-contract fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Approved host-commit and hook behavior.
    pub const fn commit(&self) -> H4CommitAuthorization {
        self.commit
    }

    /// Condition version covered by the approval.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact condition content digest covered by the approval.
    pub const fn conditions_digest(&self) -> &ConditionDigest {
        &self.conditions_digest
    }

    /// Approved execution scope.
    pub const fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Fixed assessment-profile binding.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Fixed disclosure-consent binding.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }

    /// Approved budget policy version.
    pub const fn budget_policy_version(&self) -> u64 {
        self.budget_policy_version
    }

    /// Finite approved budget policy.
    pub const fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// The H4 identity part of this approval, as a launch request.
    pub fn launch_request(&self) -> H4LaunchRequest {
        H4LaunchRequest {
            execution: self.execution.clone(),
            task: self.task.clone(),
            plan_revision: self.plan_revision,
            plan_digest: self.plan_digest.clone(),
            packet: self.packet.clone(),
            pack_fingerprint: self.pack_fingerprint.clone(),
            commit: self.commit,
        }
    }

    fn ensure_matches_h4(&self, requested: &Self) -> Result<(), SupervisionError> {
        if self.project_id != requested.project_id {
            return Err(rejected(OwnerLaunchRejection::ProjectMismatch));
        }
        if self.owner != requested.owner {
            return Err(rejected(OwnerLaunchRejection::OwnerMismatch));
        }
        if self.execution != requested.execution {
            return Err(rejected(OwnerLaunchRejection::ExecutionMismatch));
        }
        if self.task != requested.task {
            return Err(rejected(OwnerLaunchRejection::TaskMismatch));
        }
        if self.plan_revision != requested.plan_revision {
            return Err(rejected(OwnerLaunchRejection::StalePlanRevision {
                requested: requested.plan_revision,
                registered: self.plan_revision,
            }));
        }
        if self.plan_digest != requested.plan_digest {
            return Err(rejected(OwnerLaunchRejection::PlanDigestMismatch));
        }
        if let Some(field) = self.packet.mismatch(&requested.packet) {
            return Err(rejected(OwnerLaunchRejection::PacketMismatch {
                field: field.to_owned(),
            }));
        }
        if self.pack_fingerprint != requested.pack_fingerprint {
            return Err(rejected(OwnerLaunchRejection::PackFingerprintMismatch));
        }
        if self.commit != requested.commit {
            return Err(rejected(OwnerLaunchRejection::CommitAuthorizationMismatch));
        }
        if self.condition_version != requested.condition_version {
            return Err(rejected(OwnerLaunchRejection::StaleConditions {
                requested: requested.condition_version.get(),
                registered: self.condition_version.get(),
            }));
        }
        if self.conditions_digest != requested.conditions_digest {
            return Err(rejected(OwnerLaunchRejection::ConditionDigestMismatch));
        }
        if self.execution_scope != requested.execution_scope {
            return Err(rejected(OwnerLaunchRejection::ScopeMismatch));
        }
        if self.profile != requested.profile {
            return Err(rejected(OwnerLaunchRejection::ProfileMismatch));
        }
        if self.consent != requested.consent {
            return Err(rejected(OwnerLaunchRejection::ConsentMismatch));
        }
        if self.budget_policy_version != requested.budget_policy_version {
            return Err(rejected(
                OwnerLaunchRejection::BudgetPolicyVersionMismatch {
                    requested: requested.budget_policy_version,
                    registered: self.budget_policy_version,
                },
            ));
        }
        if self.budget != requested.budget {
            return Err(rejected(OwnerLaunchRejection::BudgetMismatch));
        }
        Ok(())
    }
}

/// One target-bound H4 launch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H4OwnerLaunchBinding {
    supervision_id: SupervisionId,
    approval: H4OwnerApproval,
}

impl H4OwnerLaunchBinding {
    /// Binds one current H4 approval expectation to the exact H2 target.
    pub fn new(
        supervision_id: SupervisionId,
        approval: H4OwnerApproval,
    ) -> Result<Self, SupervisionError> {
        if supervision_id.project_id() != approval.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "H4 owner launch target".to_owned(),
                expected: approval.project_id(),
                found: supervision_id.project_id(),
            });
        }
        Ok(Self {
            supervision_id,
            approval,
        })
    }

    /// Builds the expected H4 approval from the approved H2 contract and the
    /// H4-owned identity.
    ///
    /// Every H2-owned field comes from the stored approved contract, so a
    /// caller cannot request a weaker condition set, scope, profile, consent,
    /// or budget than H2 recorded. The H4 fields are the request side and are
    /// compared against the current registry entry.
    pub fn from_contract(
        contract: &SupervisionContract,
        budget_policy_version: u64,
        launch: &H4LaunchRequest,
    ) -> Result<Self, SupervisionError> {
        let project_id = contract.project_id();
        Ok(Self {
            supervision_id: contract.subject().supervision_id(),
            approval: H4OwnerApproval {
                project_id,
                owner: contract.subject().owner().clone(),
                execution: launch.execution.clone(),
                task: launch.task.clone(),
                plan_revision: launch.plan_revision,
                plan_digest: launch.plan_digest.clone(),
                packet: launch.packet.clone(),
                pack_fingerprint: launch.pack_fingerprint.clone(),
                commit: launch.commit,
                condition_version: contract.conditions().condition_version(),
                conditions_digest: contract.conditions().digest().clone(),
                execution_scope: contract.execution_scope().clone(),
                profile: contract.profile(),
                consent: contract.consent(),
                budget_policy_version,
                budget: contract.budget().clone(),
            },
        })
    }

    /// Target that would be started.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Project that owns the target.
    pub const fn project_id(&self) -> ProjectId {
        self.approval.project_id
    }

    /// Exact current H4 approval expected by the target.
    pub const fn approval(&self) -> &H4OwnerApproval {
        &self.approval
    }
}

/// Host-owned source of the current H3 approval registry entry.
///
/// This port is implemented by the phase that owns the registry. H3 Task 14
/// supplies the real H3 configuration registry; this crate never reads repo
/// data, environment variables, receipts, or model claims itself. A missing,
/// revoked, superseded, expired, or mismatched entry is `None` or an explicit
/// error, never a synthetic approval.
pub trait OwnerApprovalRegistryPort {
    /// Returns the current approval for one project and owner.
    ///
    /// Implementations must not infer an approval from prose or the owner kind
    /// alone, and must not return a historical entry after a settings or job
    /// change.
    fn current_owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        now: Timestamp,
    ) -> Result<Option<OwnerApproval>, SupervisionError>;
}

/// Host-owned source of the current H4 plan-approval registry entry.
///
/// H4 owns this registry. It is deliberately a separate port from
/// [`OwnerApprovalRegistryPort`]: an H3 registry implementation cannot satisfy
/// it, and an H3 approval cannot be substituted for an H4 one. A missing,
/// revoked, superseded, changed, or mismatched entry is `None` or an explicit
/// error, never a synthetic approval.
pub trait H4OwnerApprovalRegistryPort {
    /// Returns the current H4 approval for one project and owner.
    ///
    /// Implementations must not infer an approval from prose, a plan body, a
    /// receipt, or the owner kind alone, and must not return a historical entry
    /// after a plan, Task, packet, pack, condition, scope, profile, consent, or
    /// budget change.
    fn current_h4_owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        now: Timestamp,
    ) -> Result<Option<H4OwnerApproval>, SupervisionError>;
}

/// Explicit "no H4 registry is composed in this build" source.
///
/// Using this port keeps [`OwnerLaunchRejection::H4ApprovalUnavailable`] in
/// force: a build that has not wired the real H4 registry (Task 13) cannot
/// authorize an H4 owner launch, and naming an owner, sending an
/// `ApprovedOwner` value, or presenting an H3 approval changes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredH4ApprovalRegistry;

impl H4OwnerApprovalRegistryPort for UnconfiguredH4ApprovalRegistry {
    fn current_h4_owner_approval(
        &self,
        _project_id: ProjectId,
        _owner: &OwnerRef,
        _now: Timestamp,
    ) -> Result<Option<H4OwnerApproval>, SupervisionError> {
        Err(rejected(OwnerLaunchRejection::H4ApprovalUnavailable))
    }
}

/// Mints the non-serializable host authority only after the current H3
/// configuration-registry entry matches every requested approved constraint.
///
/// H4 is rejected explicitly here because H4 approval is owned by
/// [`H4OwnerApprovalRegistryPort`] and minted only by
/// [`authorize_h4_owner_launch`]. An H3 registry implementation therefore can
/// never clear [`OwnerLaunchRejection::H4ApprovalUnavailable`], and an H3
/// approval can never authorize an H4 Task. Human owners and model-origin
/// claims are never accepted here; a human uses the separate confirmation path.
pub fn authorize_owner_launch(
    registry: &dyn OwnerApprovalRegistryPort,
    requested: &OwnerLaunchBinding,
    now: Timestamp,
) -> Result<HostOwnerAuthority, SupervisionError> {
    match requested.approval.owner.kind() {
        OwnerKind::H4SddTask => {
            return Err(rejected(OwnerLaunchRejection::H4ApprovalUnavailable));
        }
        OwnerKind::H3HtmlJob => {
            if requested.approval.source != OwnerApprovalSource::H3ApprovedSettings {
                return Err(rejected(OwnerLaunchRejection::SourceMismatch));
            }
        }
        OwnerKind::Human => {
            return Err(rejected(OwnerLaunchRejection::OwnerNotApproved));
        }
    }
    let Some(registered) =
        registry.current_owner_approval(requested.project_id(), &requested.approval.owner, now)?
    else {
        return Err(rejected(OwnerLaunchRejection::MissingRegistryEntry));
    };
    registered.ensure_matches(&requested.approval)?;
    Ok(HostOwnerAuthority {
        binding: requested.clone(),
        h4: None,
        _seal: (),
    })
}

/// Mints the non-serializable host authority for one H4 Task only after the
/// current H4 plan-approval registry entry matches every requested constraint.
///
/// The H2-owned half of the comparison (condition version and digest, scope,
/// profile, consent, budget version and limits) comes from the stored approved
/// contract; the H4-owned half (project, execution, Task, plan revision and
/// digest, packet digests, pack fingerprint, host commit and hook approval)
/// comes from the stored H4 approval. A name, an `ApprovedOwner` value, repo
/// text, a receipt, an environment variable, a request actor, the owner kind,
/// model output, or an H3 approval never authorizes.
pub fn authorize_h4_owner_launch(
    registry: &dyn H4OwnerApprovalRegistryPort,
    requested: &H4OwnerLaunchBinding,
    now: Timestamp,
) -> Result<HostOwnerAuthority, SupervisionError> {
    if requested.approval.owner.kind() != OwnerKind::H4SddTask {
        return Err(rejected(OwnerLaunchRejection::OwnerNotApproved));
    }
    let Some(registered) = registry.current_h4_owner_approval(
        requested.project_id(),
        &requested.approval.owner,
        now,
    )?
    else {
        return Err(rejected(OwnerLaunchRejection::MissingRegistryEntry));
    };
    if registered.owner.kind() != OwnerKind::H4SddTask {
        return Err(rejected(OwnerLaunchRejection::OwnerNotApproved));
    }
    registered.ensure_matches_h4(&requested.approval)?;
    if !registered.commit.is_fully_authorized() || !requested.approval.commit.is_fully_authorized()
    {
        return Err(rejected(OwnerLaunchRejection::CommitAuthorizationMismatch));
    }
    let binding = OwnerLaunchBinding::new(
        requested.supervision_id,
        OwnerApproval::new(
            registered.project_id,
            registered.owner,
            OwnerApprovalSource::H4ApprovedPlan,
            registered.plan_revision,
            h4_job_id(&registered.execution, &registered.task),
            registered.condition_version,
            registered.conditions_digest,
            registered.execution_scope,
            registered.profile,
            registered.consent,
            registered.budget_policy_version,
            registered.budget,
        )?,
    )?;
    Ok(HostOwnerAuthority {
        binding,
        h4: Some(H4AuthorityBinding::from(&requested.approval)),
        _seal: (),
    })
}

/// Stable H2 job identifier for one H4 execution and Task.
///
/// The value is derived from the opaque H4 identities so H2 can record which
/// execution and Task a target serves without parsing them. It is not an
/// approval and never authorizes anything on its own.
pub fn h4_job_id(execution: &H4ExecutionRef, task: &H4TaskRef) -> String {
    format!(
        "h4:{}:task:{}:{}",
        execution.as_str(),
        task.number(),
        task.stable_id()
    )
}

fn validate_reference(field: &str, value: &str) -> Result<String, SupervisionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must not be empty".to_owned(),
        });
    }
    if trimmed.chars().count() > 256 {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must contain at most 256 characters".to_owned(),
        });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must not contain control characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

/// Opaque, non-serializable proof that the current H4 registry approved one
/// exact Task launch.
///
/// It carries the H4 identity of the approved Task so the host can record the
/// execution/Task mapping after a start, and nothing else. It has no public
/// constructor and no `Serialize`/`Deserialize`.
#[derive(Debug)]
struct H4AuthorityBinding {
    execution: H4ExecutionRef,
    task: H4TaskRef,
    plan_revision: u64,
    plan_digest: ContentDigest,
    packet: H4PacketBinding,
    pack_fingerprint: ContentDigest,
}

impl From<&H4OwnerApproval> for H4AuthorityBinding {
    fn from(approval: &H4OwnerApproval) -> Self {
        Self {
            execution: approval.execution.clone(),
            task: approval.task.clone(),
            plan_revision: approval.plan_revision,
            plan_digest: approval.plan_digest.clone(),
            packet: approval.packet.clone(),
            pack_fingerprint: approval.pack_fingerprint.clone(),
        }
    }
}

/// Opaque, non-serializable proof that the current owner registry approved one
/// exact target launch.
///
/// There is no public constructor, no `Serialize`/`Deserialize` implementation,
/// and no `Clone`. It is minted only by [`authorize_owner_launch`] or
/// [`authorize_h4_owner_launch`] and consumed by the host start path.
#[derive(Debug)]
pub struct HostOwnerAuthority {
    binding: OwnerLaunchBinding,
    h4: Option<H4AuthorityBinding>,
    _seal: (),
}

impl HostOwnerAuthority {
    /// Project that owns the target.
    pub const fn project_id(&self) -> ProjectId {
        self.binding.project_id()
    }

    /// Exact target this authority covers.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.binding.supervision_id()
    }

    /// Approved owner.
    pub fn owner(&self) -> &OwnerRef {
        self.binding.approval.owner()
    }

    /// Current settings/approval version that was matched.
    pub const fn settings_version(&self) -> u64 {
        self.binding.approval.settings_version()
    }

    /// Current job identifier that was matched.
    pub fn job_id(&self) -> &str {
        self.binding.approval.job_id()
    }

    /// Execution/Task identity this H4 authority covers, when minted for H4.
    pub fn h4_target(&self) -> Option<(&H4ExecutionRef, &H4TaskRef)> {
        self.h4.as_ref().map(|h4| (&h4.execution, &h4.task))
    }

    /// Approved plan revision this H4 authority covers.
    pub fn h4_plan_revision(&self) -> Option<u64> {
        self.h4.as_ref().map(|h4| h4.plan_revision)
    }

    /// Approved plan digest this H4 authority covers.
    pub fn h4_plan_digest(&self) -> Option<&ContentDigest> {
        self.h4.as_ref().map(|h4| &h4.plan_digest)
    }

    /// Approved immutable packet binding this H4 authority covers.
    pub fn h4_packet(&self) -> Option<&H4PacketBinding> {
        self.h4.as_ref().map(|h4| &h4.packet)
    }

    /// Approved pack execution-contract fingerprint this H4 authority covers.
    pub fn h4_pack_fingerprint(&self) -> Option<&ContentDigest> {
        self.h4.as_ref().map(|h4| &h4.pack_fingerprint)
    }

    /// Whether this authority was minted from the H4 plan registry.
    pub const fn is_h4(&self) -> bool {
        self.h4.is_some()
    }

    /// Verifies that this authority was minted for the exact approved contract
    /// and budget version the host is about to start.
    pub fn ensure_contract_binding(
        &self,
        contract: &SupervisionContract,
        budget_policy_version: u64,
    ) -> Result<(), SupervisionError> {
        if contract.subject().supervision_id() != self.binding.supervision_id {
            return Err(rejected(OwnerLaunchRejection::TargetMismatch));
        }
        if contract.project_id() != self.binding.project_id() {
            return Err(rejected(OwnerLaunchRejection::ProjectMismatch));
        }
        if contract.subject().owner() != self.binding.approval.owner() {
            return Err(rejected(OwnerLaunchRejection::OwnerMismatch));
        }
        let expected = OwnerApproval::from_contract(
            contract,
            budget_policy_version,
            self.binding.approval.settings_version,
            self.binding.approval.job_id(),
        )?;
        self.binding.approval.ensure_matches(&expected)
    }
}

fn source_for_owner(kind: OwnerKind) -> Result<OwnerApprovalSource, SupervisionError> {
    match kind {
        OwnerKind::H3HtmlJob => Ok(OwnerApprovalSource::H3ApprovedSettings),
        OwnerKind::H4SddTask => Ok(OwnerApprovalSource::H4ApprovedPlan),
        OwnerKind::Human => Err(rejected(OwnerLaunchRejection::OwnerNotApproved)),
    }
}

fn rejected(reason: OwnerLaunchRejection) -> SupervisionError {
    SupervisionError::OwnerLaunchRejected { reason }
}
