//! Approved completion conditions and required verification checks.

use std::fmt;

use herness_core::contracts::{ProjectId, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approval::{ApprovalActor, ConditionApproval};
use crate::contract::OwnerRef;
use crate::error::{ApprovalRejection, SupervisionError};
use crate::evidence::{CheckInvocation, VerificationOperation};
use crate::ids::{CheckId, ConditionId, verify_scoped};

/// Timeout the pre-mode host applied to every required check.
///
/// It is no longer a hardcoded host value. It is the exact legacy meaning of
/// one stored format-2 check, which recorded no timeout of its own, so the
/// explicit format-2 decoder applies it. A new check always carries its own
/// approved timeout.
pub const LEGACY_CHECK_TIMEOUT_SECONDS: u64 = 60;

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

/// How one completion condition is decided.
///
/// The mode is stored with the approved condition content and is part of the
/// condition-set digest. A condition is never decided by the other mode: a
/// `Checks` condition is met only when every required check passes, and an
/// `Assessment` condition uses the per-condition rubric assessment. A missing
/// or unknown wire value is rejected by the decoder; it is never treated as
/// either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionMode {
    /// Every referenced required check must pass with applicable evidence.
    Checks,
    /// The existing per-condition rubric assessment decides the condition.
    Assessment,
}

impl ConditionMode {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checks => "checks",
            Self::Assessment => "assessment",
        }
    }

    /// Parses only the exact wire values. Any other value is an explicit
    /// unsupported-contract error, never a default.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        match value.as_ref() {
            "checks" => Ok(Self::Checks),
            "assessment" => Ok(Self::Assessment),
            other => Err(SupervisionError::Unsupported {
                feature: format!(
                    "condition mode {other:?} is not supported; expected \"checks\" or \
                     \"assessment\""
                ),
            }),
        }
    }
}

/// One completion condition judged against a short rubric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Condition {
    id: ConditionId,
    title: String,
    rubric: String,
    mode: ConditionMode,
    required_checks: Vec<CheckId>,
    origin: ConditionOrigin,
}

impl Condition {
    /// Creates one condition with a non-empty title and rubric.
    pub fn new(
        id: ConditionId,
        title: impl AsRef<str>,
        rubric: impl AsRef<str>,
        mode: ConditionMode,
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
            mode,
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

    /// How this condition is decided.
    pub const fn mode(&self) -> ConditionMode {
        self.mode
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
    invocation: CheckInvocation,
    description: String,
}

impl RequiredCheck {
    /// Creates a check bound to one condition in the same project.
    pub fn new(
        id: CheckId,
        condition_id: ConditionId,
        operation: VerificationOperation,
        invocation: CheckInvocation,
        description: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        verify_scoped(&id, condition_id.project_id())?;
        let description = non_empty("check.description", description)?;
        Ok(Self {
            id,
            condition_id,
            operation,
            invocation,
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

    /// Approved working directory, timeout, and input paths.
    pub const fn invocation(&self) -> &CheckInvocation {
        &self.invocation
    }

    /// What this check verifies.
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Validates one approved check `cwd`: `.` or a bounded relative directory.
pub fn validate_check_cwd(cwd: &str) -> Result<(), SupervisionError> {
    let trimmed = cwd.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.contains('\\')
        || trimmed
            .split('/')
            .any(|part| part == ".." || part.is_empty())
        || (trimmed != "." && trimmed.split('/').any(|part| part == "."))
    {
        return Err(SupervisionError::InvalidValue {
            field: "check.cwd".to_owned(),
            detail: "cwd must be '.' or a project-relative directory inside the project root"
                .to_owned(),
        });
    }
    Ok(())
}

/// Validates one approved check input path.
pub fn validate_check_input_path(path: &str) -> Result<(), SupervisionError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == "*"
        || trimmed == "/"
        || trimmed.starts_with('/')
        || trimmed.contains('\\')
        || trimmed
            .split('/')
            .any(|part| part == ".." || part == "." || part.is_empty())
    {
        return Err(SupervisionError::InvalidValue {
            field: "check.inputPaths".to_owned(),
            detail: "input paths must be bounded project-relative paths".to_owned(),
        });
    }
    Ok(())
}

/// Requires every declared check input to be equal to or below one approved
/// scope path. An input outside the approved scope is refused before a check
/// runs, because its evidence could not be bound to an exact freshness scope.
pub fn ensure_inputs_in_scope(
    input_paths: &[String],
    scope: &[String],
) -> Result<(), SupervisionError> {
    if input_paths.is_empty() {
        return Ok(());
    }
    if scope.is_empty() {
        return Err(SupervisionError::InvalidValue {
            field: "check.inputPaths".to_owned(),
            detail: "a check with input paths needs a bounded approved scope".to_owned(),
        });
    }
    for input in input_paths {
        validate_check_input_path(input)?;
        let inside = scope.iter().any(|approved| {
            let approved = approved.trim_end_matches('/');
            input == approved || input.starts_with(&format!("{approved}/"))
        });
        if !inside {
            return Err(SupervisionError::InvalidValue {
                field: "check.inputPaths".to_owned(),
                detail: format!("input path {input:?} is outside the approved scope"),
            });
        }
    }
    Ok(())
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
        for condition in &conditions {
            let owned = checks
                .iter()
                .filter(|check| check.condition_id == condition.id)
                .map(|check| check.id)
                .collect::<Vec<_>>();
            let mut declared = condition.required_checks.clone();
            let mut actual = owned.clone();
            declared.sort();
            declared.dedup();
            actual.sort();
            actual.dedup();
            if declared.len() != condition.required_checks.len() {
                return Err(SupervisionError::InvalidValue {
                    field: "condition.requiredChecks".to_owned(),
                    detail: "required check identifiers must be unique".to_owned(),
                });
            }
            if declared != actual {
                return Err(SupervisionError::InvalidValue {
                    field: "condition.requiredChecks".to_owned(),
                    detail: "a condition's required checks must be exactly the checks that name it"
                        .to_owned(),
                });
            }
            if condition.mode == ConditionMode::Checks && declared.is_empty() {
                return Err(SupervisionError::InvalidValue {
                    field: "condition.mode".to_owned(),
                    detail: "a checks-mode condition requires at least one check".to_owned(),
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
