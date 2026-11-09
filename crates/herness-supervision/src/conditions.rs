//! Approved completion conditions and required verification checks.

use std::fmt;

use herness_core::contracts::{ProjectId, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approval::{ApprovalActor, ConditionApproval};
use crate::contract::OwnerRef;
use crate::error::{ApprovalRejection, SupervisionError};
use crate::evidence::VerificationOperation;
use crate::ids::{CheckId, ConditionId, verify_scoped};

/// Monotonic version of a completion-condition set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConditionVersion(u64);

impl ConditionVersion {
    /// Creates a positive condition version.
    pub fn new(value: u64) -> Result<Self, SupervisionError> {
        if value == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "conditionVersion".to_owned(),
                detail: "versions start at 1".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next version.
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// SHA-256 digest of the exact condition content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConditionDigest(String);

impl ConditionDigest {
    /// Hashes canonical serialized condition content.
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(format!("{:x}", hasher.finalize()))
    }

    /// Hex digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ConditionDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(
                "expected a 64-character SHA-256 hex digest",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

impl fmt::Display for ConditionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who produced one completion condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ConditionOrigin {
    /// A human wrote the condition.
    Human,
    /// An already-approved H3/H4 owner supplied the condition.
    ApprovedOwner {
        /// Approved owner that supplied it.
        owner: OwnerRef,
    },
    /// A model proposed the condition. It is unapproved until a human or
    /// approved owner confirms the exact condition set.
    ModelProposal,
}

/// One completion condition judged against a short rubric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Condition {
    id: ConditionId,
    title: String,
    rubric: String,
    required_checks: Vec<CheckId>,
    origin: ConditionOrigin,
}

impl Condition {
    /// Creates one condition with a non-empty title and rubric.
    pub fn new(
        id: ConditionId,
        title: impl AsRef<str>,
        rubric: impl AsRef<str>,
        required_checks: Vec<CheckId>,
        origin: ConditionOrigin,
    ) -> Result<Self, SupervisionError> {
        let title = non_empty("condition.title", title)?;
        let rubric = non_empty("condition.rubric", rubric)?;
        if let ConditionOrigin::ApprovedOwner { owner } = &origin
            && !owner.is_approved_owner()
        {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::OwnerNotApproved,
            });
        }
        Ok(Self {
            id,
            title,
            rubric,
            required_checks,
            origin,
        })
    }

    /// Condition identifier.
    pub const fn id(&self) -> ConditionId {
        self.id
    }

    /// Human-readable title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Per-condition rubric used to request an assessment.
    pub fn rubric(&self) -> &str {
        &self.rubric
    }

    /// Required verification checks that must pass before completion.
    pub fn required_checks(&self) -> &[CheckId] {
        &self.required_checks
    }

    /// Where the condition came from.
    pub fn origin(&self) -> &ConditionOrigin {
        &self.origin
    }
}

/// One required verification check and its exact operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequiredCheck {
    id: CheckId,
    condition_id: ConditionId,
    operation: VerificationOperation,
    description: String,
}

impl RequiredCheck {
    /// Creates a check bound to one condition in the same project.
    pub fn new(
        id: CheckId,
        condition_id: ConditionId,
        operation: VerificationOperation,
        description: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        verify_scoped(&id, condition_id.project_id())?;
        let description = non_empty("check.description", description)?;
        Ok(Self {
            id,
            condition_id,
            operation,
            description,
        })
    }

    /// Check identifier.
    pub const fn id(&self) -> CheckId {
        self.id
    }

    /// Condition this check supports.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Exact command or equivalent operation.
    pub fn operation(&self) -> &VerificationOperation {
        &self.operation
    }

    /// What this check verifies.
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Versioned, approved completion-condition set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionSet {
    project_id: ProjectId,
    condition_version: ConditionVersion,
    conditions: Vec<Condition>,
    checks: Vec<RequiredCheck>,
    approval: Option<ConditionApproval>,
    approver: Option<ApprovalActor>,
    digest: ConditionDigest,
}

impl ConditionSet {
    /// Creates an unapproved condition set at `version`.
    pub fn new(
        project_id: ProjectId,
        condition_version: ConditionVersion,
        conditions: Vec<Condition>,
        checks: Vec<RequiredCheck>,
    ) -> Result<Self, SupervisionError> {
        if conditions.is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "conditions".to_owned(),
                detail: "at least one completion condition is required".to_owned(),
            });
        }
        for condition in &conditions {
            verify_scoped(&condition.id, project_id)?;
        }
        for check in &checks {
            verify_scoped(&check.id, project_id)?;
            verify_scoped(&check.condition_id, project_id)?;
            if !conditions
                .iter()
                .any(|condition| condition.id == check.condition_id)
            {
                return Err(SupervisionError::UnknownConditionReference {
                    reference: check.condition_id.to_string(),
                });
            }
        }
        let mut condition_ids = conditions.iter().map(|c| c.id).collect::<Vec<_>>();
        condition_ids.sort();
        condition_ids.dedup();
        if condition_ids.len() != conditions.len() {
            return Err(SupervisionError::InvalidValue {
                field: "conditions".to_owned(),
                detail: "condition identifiers must be unique".to_owned(),
            });
        }
        let mut check_ids = checks.iter().map(|c| c.id).collect::<Vec<_>>();
        check_ids.sort();
        check_ids.dedup();
        if check_ids.len() != checks.len() {
            return Err(SupervisionError::InvalidValue {
                field: "checks".to_owned(),
                detail: "check identifiers must be unique".to_owned(),
            });
        }

        let mut set = Self {
            project_id,
            condition_version,
            conditions,
            checks,
            approval: None,
            approver: None,
            digest: ConditionDigest(String::new()),
        };
        set.digest = set.compute_digest();
        Ok(set)
    }

    /// Project that owns the set.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Current condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact-content digest used to bind approvals and assessments.
    pub fn digest(&self) -> &ConditionDigest {
        &self.digest
    }

    /// Conditions in this set.
    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// Required checks in this set.
    pub fn checks(&self) -> &[RequiredCheck] {
        &self.checks
    }

    /// Recorded approval, if any.
    pub fn approval(&self) -> Option<&ConditionApproval> {
        self.approval.as_ref()
    }

    /// Actor that recorded the approval, if any.
    pub fn approver(&self) -> Option<&ApprovalActor> {
        self.approver.as_ref()
    }

    /// Whether all conditions are still covered by a valid approval.
    pub fn is_approved(&self, now: Timestamp) -> bool {
        self.require_approval(now).is_ok()
    }

    /// Recomputes the content digest and rejects tampered condition content.
    pub fn verify_digest(&self) -> Result<(), SupervisionError> {
        if self.digest != self.compute_digest() {
            return Err(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::StaleDigest,
            });
        }
        Ok(())
    }

    /// Requires a valid approval for this exact version and content.
    pub fn require_approval(&self, now: Timestamp) -> Result<(), SupervisionError> {
        self.verify_digest()?;
        let approval = self
            .approval
            .as_ref()
            .ok_or(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::MissingApproval,
            })?;
        let approver = self
            .approver
            .clone()
            .ok_or(SupervisionError::ApprovalRejected {
                reason: ApprovalRejection::MissingApproval,
            })?;
        approval.validate(
            approver,
            self.project_id,
            self.condition_version,
            &self.digest,
            now,
        )
    }

    /// Records an approval for this exact condition set.
    ///
    /// The actor must match the approval basis. Model actors are rejected.
    pub fn approve(
        &mut self,
        actor: ApprovalActor,
        approval: ConditionApproval,
        now: Timestamp,
    ) -> Result<(), SupervisionError> {
        self.verify_digest()?;
        approval.validate(
            actor.clone(),
            self.project_id,
            self.condition_version,
            &self.digest,
            now,
        )?;
        self.approval = Some(approval);
        self.approver = Some(actor);
        Ok(())
    }

    /// Replaces the content with a newer, unapproved version.
    ///
    /// Model actors are rejected. The returned set has no approval and no
    /// previously applied decisions survive a version change.
    pub fn revise(
        &self,
        actor: ApprovalActor,
        condition_version: ConditionVersion,
        conditions: Vec<Condition>,
        checks: Vec<RequiredCheck>,
    ) -> Result<Self, SupervisionError> {
        if actor.is_model() {
            return Err(SupervisionError::ModelCannotApproveOrChange {
                action: "change completion conditions".to_owned(),
            });
        }
        if condition_version <= self.condition_version {
            return Err(SupervisionError::InvalidValue {
                field: "conditions.version".to_owned(),
                detail: "a revised condition set must have a newer version".to_owned(),
            });
        }
        Self::new(self.project_id, condition_version, conditions, checks)
    }

    /// Ensures the set belongs to `project`.
    pub fn ensure_project(&self, project: ProjectId) -> Result<(), SupervisionError> {
        if self.project_id == project {
            Ok(())
        } else {
            Err(SupervisionError::CrossProjectReference {
                id_kind: "condition set".to_owned(),
                expected: project,
                found: self.project_id,
            })
        }
    }

    /// All condition identifiers in stable order.
    pub fn condition_ids(&self) -> Vec<ConditionId> {
        self.conditions
            .iter()
            .map(|condition| condition.id)
            .collect()
    }

    fn compute_digest(&self) -> ConditionDigest {
        let canonical = (
            self.project_id,
            self.condition_version,
            &self.conditions,
            &self.checks,
        );
        let bytes = serde_json::to_vec(&canonical).expect("condition set is serializable");
        ConditionDigest::sha256(&bytes)
    }
}

fn non_empty(field: &str, value: impl AsRef<str>) -> Result<String, SupervisionError> {
    let trimmed = value.as_ref().trim();
    if trimmed.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must not be empty".to_owned(),
        });
    }
    if trimmed.chars().count() > 8_000 {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must contain at most 8000 characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}
