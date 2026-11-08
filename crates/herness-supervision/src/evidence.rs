//! Verification evidence, target fingerprints, and required-check results.
//!
//! The contract reuses the five-item evidence record from
//! `verification-before-completion`: executor (acquirer), exact command or
//! equivalent operation, actual result, target revision/fingerprints, and the
//! verification scope. H1 operation success is never converted into a passing
//! verification by this module; the status is explicit evidence data.

use std::fmt;

use herness_core::contracts::{ContractVersion, ProjectId, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::conditions::{ConditionDigest, ConditionVersion};
use crate::error::SupervisionError;
use crate::ids::{CheckId, ConditionId, EvidenceId, SupervisionId, verify_scoped};
use crate::version::current_contract_version;

/// Monotonic version of the assessed target snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TargetVersion(u64);

impl TargetVersion {
    /// Creates a positive target version.
    pub fn new(value: u64) -> Result<Self, SupervisionError> {
        if value == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "targetVersion".to_owned(),
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

/// Content digest of one file, manifest, or related input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Computes a SHA-256 digest.
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(format!("{:x}", hasher.finalize()))
    }

    /// Parses a lowercase or uppercase 64-character SHA-256 hex digest.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let value = value.as_ref().trim().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "contentDigest".to_owned(),
                detail: "expected a 64-character SHA-256 hex digest".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Hex digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One content path and the digest observed for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentFingerprint {
    path: String,
    digest: ContentDigest,
}

impl ContentFingerprint {
    /// Creates a fingerprint for a non-empty path.
    pub fn new(path: impl AsRef<str>, digest: ContentDigest) -> Result<Self, SupervisionError> {
        let path = path.as_ref().trim();
        if path.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "fingerprint.path".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self {
            path: path.to_owned(),
            digest,
        })
    }

    /// Path or manifest name.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Observed content digest.
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// Exact target snapshot version and content fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetScope {
    project_id: ProjectId,
    version: TargetVersion,
    read_set: Vec<String>,
    fingerprints: Vec<ContentFingerprint>,
}

impl TargetScope {
    /// Creates a bounded target snapshot.
    pub fn new(
        project_id: ProjectId,
        version: TargetVersion,
        read_set: Vec<String>,
        fingerprints: Vec<ContentFingerprint>,
    ) -> Result<Self, SupervisionError> {
        if read_set.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "target.readSet".to_owned(),
                detail: "must contain at least one bounded path".to_owned(),
            });
        }
        for path in &read_set {
            let trimmed = path.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed == "."
                || trimmed == "/"
                || trimmed.split('/').any(|part| part == "..")
            {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "target.readSet".to_owned(),
                    detail: "paths must be bounded and must not escape the project".to_owned(),
                });
            }
        }
        if fingerprints.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "target.fingerprints".to_owned(),
                detail: "at least one content fingerprint is required".to_owned(),
            });
        }
        Ok(Self {
            project_id,
            version,
            read_set,
            fingerprints,
        })
    }

    /// Project that owns the target.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Target version.
    pub const fn version(&self) -> TargetVersion {
        self.version
    }

    /// Paths included in the read set.
    pub fn read_set(&self) -> &[String] {
        &self.read_set
    }

    /// Content fingerprints observed for the target.
    pub fn fingerprints(&self) -> &[ContentFingerprint] {
        &self.fingerprints
    }

    /// Ensures the target belongs to `project`.
    pub fn ensure_project(&self, project: ProjectId) -> Result<(), SupervisionError> {
        if self.project_id == project {
            Ok(())
        } else {
            Err(SupervisionError::CrossProjectReference {
                id_kind: "target scope".to_owned(),
                expected: project,
                found: self.project_id,
            })
        }
    }
}

/// Exact command or equivalent operation used to acquire evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum VerificationOperation {
    /// An exact shell command.
    Command {
        /// The command as run.
        command: String,
    },
    /// An equivalent operation, such as a manual inspection.
    Equivalent {
        /// Non-secret description of the operation.
        operation: String,
    },
}

impl VerificationOperation {
    /// Creates an exact shell-command operation.
    pub fn command(command: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let command = non_empty("operation.command", command)?;
        Ok(Self::Command { command })
    }

    /// Creates an equivalent non-shell operation.
    pub fn equivalent(operation: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let operation = non_empty("operation.equivalent", operation)?;
        Ok(Self::Equivalent { operation })
    }

    /// Human-readable operation text.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Command { command } => command,
            Self::Equivalent { operation } => operation,
        }
    }
}

/// Who ran the verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAcquirer {
    /// The supervised child agent.
    ChildAgent,
    /// A CI or other automated external executor.
    Ci,
    /// A human observer.
    Human,
}

/// Actual result of the verification operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceOutcome {
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    signal: Option<i32>,
    timed_out: bool,
    truncated: bool,
    detail: String,
}

impl EvidenceOutcome {
    /// Creates an explicit observed result.
    pub fn new(
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        truncated: bool,
        detail: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        let detail = detail.as_ref().trim();
        if detail.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "outcome.detail".to_owned(),
                detail: "the actual result must be recorded".to_owned(),
            });
        }
        Ok(Self {
            exit_code,
            signal,
            timed_out,
            truncated,
            detail: detail.to_owned(),
        })
    }

    /// Exit code when the operation completed normally.
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Signal when the operation was terminated by a signal.
    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }

    /// Whether the operation timed out.
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// Whether the recorded result was truncated.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Short non-secret result description.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// The verified scope and its limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceScope {
    included: Vec<String>,
    limits: Vec<String>,
}

impl EvidenceScope {
    /// Creates a non-empty scope with explicit limits.
    pub fn new(included: Vec<String>, limits: Vec<String>) -> Result<Self, SupervisionError> {
        if included.is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "scope.included".to_owned(),
                detail: "a verification scope is required".to_owned(),
            });
        }
        if included.iter().any(|item| item.trim().is_empty()) {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "scope.included".to_owned(),
                detail: "scope items must not be empty".to_owned(),
            });
        }
        Ok(Self { included, limits })
    }

    /// What the evidence covers.
    pub fn included(&self) -> &[String] {
        &self.included
    }

    /// Known limits of the evidence.
    pub fn limits(&self) -> &[String] {
        &self.limits
    }
}

/// Distinguished result of one required check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check ran against the current target and passed.
    Pass,
    /// The check ran and failed. Any non-zero exit, signal, timeout, or
    /// truncation that weakens the observation stays a failure.
    Fail,
    /// The check was not run.
    NotRun,
    /// The check needed a tool, connection, or input that was unavailable.
    Unavailable,
    /// The check ran but the result does not establish pass or fail.
    Inconclusive,
}

impl CheckStatus {
    /// Whether this result may support completion.
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not_run",
            Self::Unavailable => "unavailable",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// Immutable record of one verification observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRecord {
    contract_version: ContractVersion,
    id: EvidenceId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    condition_id: Option<ConditionId>,
    check_id: Option<CheckId>,
    acquirer: EvidenceAcquirer,
    operation: VerificationOperation,
    outcome: EvidenceOutcome,
    target: TargetScope,
    scope: EvidenceScope,
    status: CheckStatus,
    sequence: u64,
    observed_at: Timestamp,
}

impl EvidenceRecord {
    /// Creates a validated evidence record covering all five contract items.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EvidenceId,
        supervision_id: SupervisionId,
        condition_id: Option<ConditionId>,
        check_id: Option<CheckId>,
        acquirer: EvidenceAcquirer,
        operation: VerificationOperation,
        outcome: EvidenceOutcome,
        target: TargetScope,
        scope: EvidenceScope,
        status: CheckStatus,
        sequence: u64,
        observed_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        let project_id = id.project_id();
        verify_scoped(&id, project_id)?;
        verify_scoped(&supervision_id, project_id)?;
        if let Some(condition_id) = condition_id {
            verify_scoped(&condition_id, project_id)?;
        }
        if let Some(check_id) = check_id {
            verify_scoped(&check_id, project_id)?;
        }
        target.ensure_project(project_id)?;
        if sequence == 0 {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "sequence".to_owned(),
                detail: "evidence sequence starts at 1".to_owned(),
            });
        }
        if operation.as_str().trim().is_empty() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "operation".to_owned(),
                detail: "an exact command or equivalent operation is required".to_owned(),
            });
        }
        Ok(Self {
            contract_version: current_contract_version(),
            id,
            project_id,
            supervision_id,
            condition_id,
            check_id,
            acquirer,
            operation,
            outcome,
            target,
            scope,
            status,
            sequence,
            observed_at,
        })
    }

    /// Contract version written by this build.
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    /// Evidence identifier.
    pub const fn id(&self) -> EvidenceId {
        self.id
    }

    /// Project that owns the evidence.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target this evidence was acquired for.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Condition this evidence supports, if any.
    pub const fn condition_id(&self) -> Option<ConditionId> {
        self.condition_id
    }

    /// Required check this evidence answers, if any.
    pub const fn check_id(&self) -> Option<CheckId> {
        self.check_id
    }

    /// Who acquired the evidence.
    pub const fn acquirer(&self) -> EvidenceAcquirer {
        self.acquirer
    }

    /// Exact command or equivalent operation.
    pub fn operation(&self) -> &VerificationOperation {
        &self.operation
    }

    /// Actual result.
    pub fn outcome(&self) -> &EvidenceOutcome {
        &self.outcome
    }

    /// Target version and content fingerprints.
    pub fn target(&self) -> &TargetScope {
        &self.target
    }

    /// Scope and limits.
    pub fn scope(&self) -> &EvidenceScope {
        &self.scope
    }

    /// Explicit pass/fail/not-run/unavailable/inconclusive result.
    pub const fn status(&self) -> CheckStatus {
        self.status
    }

    /// Project sequence at acquisition.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// When the observation was made.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Whether this evidence was acquired against the current target version.
    pub fn applies_to(&self, target_version: TargetVersion) -> bool {
        self.target.version() == target_version
    }
}

/// Result of one required check for a condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequiredCheckResult {
    check_id: CheckId,
    condition_id: ConditionId,
    status: CheckStatus,
    #[serde(default)]
    evidence_id: Option<EvidenceId>,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    observed_at: Timestamp,
}

impl RequiredCheckResult {
    /// Creates a check result. A passing result requires evidence.
    pub fn new(
        check_id: CheckId,
        condition_id: ConditionId,
        status: CheckStatus,
        evidence_id: Option<EvidenceId>,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        observed_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        verify_scoped(&check_id, condition_id.project_id())?;
        if let Some(evidence_id) = evidence_id {
            verify_scoped(&evidence_id, condition_id.project_id())?;
        }
        if status == CheckStatus::Pass && evidence_id.is_none() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "requiredCheck.evidenceId".to_owned(),
                detail: "a passing check requires recorded evidence".to_owned(),
            });
        }
        Ok(Self {
            check_id,
            condition_id,
            status,
            evidence_id,
            condition_version,
            target_version,
            observed_at,
        })
    }

    /// Builds a result from explicit evidence.
    ///
    /// The evidence status is preserved as-is. An H1 operation marked applied
    /// is not converted into a pass here.
    pub fn from_evidence(
        evidence: &EvidenceRecord,
        condition_version: ConditionVersion,
    ) -> Result<Self, SupervisionError> {
        let check_id = evidence
            .check_id
            .ok_or(SupervisionError::EvidenceContractViolation {
                field: "evidence.checkId".to_owned(),
                detail: "evidence for a required check must name the check".to_owned(),
            })?;
        let condition_id =
            evidence
                .condition_id
                .ok_or(SupervisionError::EvidenceContractViolation {
                    field: "evidence.conditionId".to_owned(),
                    detail: "evidence for a required check must name the condition".to_owned(),
                })?;
        Self::new(
            check_id,
            condition_id,
            evidence.status,
            Some(evidence.id),
            condition_version,
            evidence.target.version(),
            evidence.observed_at,
        )
    }

    /// Required check identifier.
    pub const fn check_id(&self) -> CheckId {
        self.check_id
    }

    /// Condition this check supports.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Distinguished result.
    pub const fn status(&self) -> CheckStatus {
        self.status
    }

    /// Evidence this result relies on, if any.
    pub const fn evidence_id(&self) -> Option<EvidenceId> {
        self.evidence_id
    }

    /// Condition version this result was observed for.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Target version this result was observed for.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Observation time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Whether this result may support completion.
    pub const fn is_pass(&self) -> bool {
        self.status.is_pass()
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
    if trimmed.chars().count() > 4_000 {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must contain at most 4000 characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Short hand for a fingerprint over exact bytes.
pub fn fingerprint_bytes(
    path: impl AsRef<str>,
    bytes: &[u8],
) -> Result<ContentFingerprint, SupervisionError> {
    ContentFingerprint::new(path, ContentDigest::sha256(bytes))
}

/// Digest of a condition set reused where a content digest is expected.
pub fn condition_content_digest(digest: &ConditionDigest) -> ContentDigest {
    ContentDigest(digest.as_str().to_owned())
}
