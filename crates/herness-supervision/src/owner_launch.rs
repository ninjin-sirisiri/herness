//! Host-only approved-owner startup authority.
//!
//! H3 owns the current configuration-approval registry. This module defines
//! only the generic port and the non-serializable authority token H2 requires
//! before an approved owner may start a target without a human confirmation.
//! Naming an [`OwnerKind::H3HtmlJob`] or sending a serializable
//! [`crate::approval::ApprovalActor::ApprovedOwner`] is never an authority by
//! itself: the token is minted only after the current registry entry matches
//! every approved constraint.
//!
//! The token deliberately implements neither `Serialize` nor `Deserialize`,
//! has private fields, has no public constructor, and is not `Clone`. A receipt,
//! IPC payload, repo file, environment variable, or model output therefore
//! cannot be turned into a token. Only [`authorize_owner_launch`] mints one,
//! and only after a [`OwnerApprovalRegistryPort`] implementation reports the
//! current entry.

use herness_core::contracts::{ProjectId, Timestamp};

use crate::approval::OwnerApprovalSource;
use crate::budget::BudgetPolicy;
use crate::conditions::{ConditionDigest, ConditionVersion};
use crate::consent::ConsentBinding;
use crate::contract::{ExecutionScope, OwnerKind, OwnerRef, SupervisionContract};
use crate::error::{OwnerLaunchRejection, SupervisionError};
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

/// Host-owned source of the current H3/H4 approval registry entry.
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

/// Mints the non-serializable host authority only after the registry entry
/// matches every requested approved constraint.
///
/// H4 is rejected explicitly in this build because H4 approval is not
/// implemented. Human owners and model-origin claims are never accepted here;
/// a human uses the separate confirmation path.
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
        _seal: (),
    })
}

/// Opaque, non-serializable proof that the current owner registry approved one
/// exact target launch.
///
/// There is no public constructor, no `Serialize`/`Deserialize` implementation,
/// and no `Clone`. It is minted only by [`authorize_owner_launch`] and consumed
/// by the host start path.
#[derive(Debug)]
pub struct HostOwnerAuthority {
    binding: OwnerLaunchBinding,
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
