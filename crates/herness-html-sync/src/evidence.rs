//! Versioned H3 evaluation evidence, coverage, and condition-assessment plans.
//!
//! The H2 evidence record keeps the operation/outcome contract but not the full
//! evidence text or images. This module adds the minimum versioned
//! content-carrying surface H3 needs so the Html assessment adapters receive the
//! exact full documents. It never re-implements the H2 send gate: the desktop
//! assessment port still checks purpose, consent, budget, profile state, and
//! model-request recording.
//!
//! Two invariants are enforced here:
//!
//! * every source unit appears exactly once across an evaluation split, and
//! * a missing, partial, fake, stationary, stale, truncated, image-less, or
//!   secret-excluded required input can never become `completion_ready`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use herness_core::{ProjectId, Timestamp};
use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentRequest, AssessmentResult, ConditionVerdict,
};
use herness_supervision::conditions::{ConditionDigest, ConditionVersion};
use herness_supervision::evidence::{EvidenceScope, TargetVersion};
use herness_supervision::ids::{ConditionId, DecisionId, EvidenceId};
use herness_supervision::profiles::{
    ProfileBinding, ProfileInputs, ProfileThresholds, RubricVersion,
};
use herness_supervision::{ContentDigest, SupervisionError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{DocumentKey, SourceSnapshot};
use crate::error::H3Error;
use crate::ids::{CycleId, GenerationId};
use crate::rubric::{H3_RUBRIC_VERSION, RubricSet};
use crate::version::{H3_FORMAT_VERSION, H3Record};

/// Evidence pack schema.
pub const H3_EVIDENCE_SCHEMA: &str = "h3-html-evidence-v1";
/// Versioned content-carrying evidence schema.
pub const H3_EVIDENCE_CONTENT_SCHEMA: &str = "h3-evidence-content-v1";
/// Render manifest version accepted by the evidence layer.
pub const H3_RENDER_MANIFEST_VERSION: &str = "h3-render-manifest-v1";
/// The only accepted native render producer.
pub const NATIVE_RENDER_SOURCE: &str = "wkwebview-native";
/// The documented accessibility projection. This is not a native AX tree.
pub const HOST_JS_ACCESSIBILITY_SOURCE: &str = "host-js-aria-snapshot-v1";
/// Maximum UTF-8 bytes in one assessment slice by default.
pub const MAX_DEFAULT_SLICE_BYTES: usize = 20_000;
/// Maximum units in one information slice by default.
pub const MAX_DEFAULT_SLICE_UNITS: usize = 8;

/// The four H3 condition identities. Their wire labels are stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H3Condition {
    /// Source information and conditions are preserved.
    Information,
    /// Supplementary summaries, diagrams, and graphs are supported.
    Support,
    /// The unit conveys the document is findable and usable.
    Usability,
    /// The real render is available and usable.
    Render,
}

impl H3Condition {
    /// All conditions in fixed order.
    pub const ALL: [Self; 4] = [
        Self::Information,
        Self::Support,
        Self::Usability,
        Self::Render,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Information => "information",
            Self::Support => "support",
            Self::Usability => "usability",
            Self::Render => "render",
        }
    }

    /// Whether the condition needs approved image bytes.
    pub const fn is_image_required(self) -> bool {
        matches!(self, Self::Support | Self::Usability | Self::Render)
    }

    /// Parse a wire label.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|condition| condition.as_str() == value)
    }
}

impl fmt::Display for H3Condition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A project-scoped condition identity for each logical H3 condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionBinding {
    project_id: ProjectId,
    conditions: Vec<ConditionId>,
}

impl ConditionBinding {
    /// Binds the four H2 conditions in H3 order.
    pub fn new(
        project_id: ProjectId,
        conditions: [ConditionId; 4],
    ) -> Result<Self, EvidenceValidationError> {
        let mut seen = BTreeSet::new();
        for condition in conditions {
            condition.validate_in(project_id).map_err(|error| {
                EvidenceValidationError::InvalidValue {
                    field: "conditionBinding".to_owned(),
                    detail: error.to_string(),
                }
            })?;
            if !seen.insert(condition) {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "conditionBinding".to_owned(),
                    detail: "the four H3 conditions must be distinct".to_owned(),
                });
            }
        }
        Ok(Self {
            project_id,
            conditions: conditions.to_vec(),
        })
    }

    /// Project that owns the conditions.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Condition identifier for one logical H3 condition.
    pub fn id(&self, condition: H3Condition) -> ConditionId {
        self.conditions[condition as usize]
    }

    /// Logical condition for one H2 condition identifier.
    pub fn condition_for(&self, id: ConditionId) -> Option<H3Condition> {
        H3Condition::ALL
            .into_iter()
            .find(|condition| self.id(*condition) == id)
    }

    /// All bound identifiers in H3 order.
    pub fn ids(&self) -> &[ConditionId] {
        &self.conditions
    }
}

/// Where a required check or render artifact came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    /// The common SDD policy bridge ran in-process against the real pack.
    PackPolicy,
    /// A real non-privileged WKWebView capture.
    WkWebViewNative,
    /// A fixture or provider fake explicitly marked as such.
    Fake,
    /// A stationary/unit-only observation explicitly marked as such.
    Stationary,
}

impl EvidenceOrigin {
    /// Whether this is real native render evidence.
    pub const fn is_native_render(self) -> bool {
        matches!(self, Self::WkWebViewNative)
    }

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackPolicy => "pack-policy",
            Self::WkWebViewNative => "wkwebview-native",
            Self::Fake => "fake",
            Self::Stationary => "stationary",
        }
    }
}

/// Required check kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredCheckKind {
    /// Common structural validation through the real pack policy bridge.
    CommonStructural,
    /// A complete real render with the approved configuration matrix.
    RealRender,
}

impl RequiredCheckKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommonStructural => "common-structural",
            Self::RealRender => "real-render",
        }
    }
}

/// Distinguished result of a required check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCheckResult {
    /// The check ran against the current target and passed.
    Pass,
    /// The check ran and failed.
    Fail,
    /// The check was not run.
    NotRun,
    /// The check needed a capability or input that was unavailable.
    Unavailable,
    /// The check ran but does not establish pass or fail.
    Inconclusive,
}

impl EvidenceCheckResult {
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

/// One required check with its verifier, operation, actual result, target,
/// scope, and evidence reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequiredCheck {
    kind: RequiredCheckKind,
    status: EvidenceCheckResult,
    origin: EvidenceOrigin,
    verifier: String,
    operation: String,
    result: String,
    target_version: TargetVersion,
    scope: EvidenceScope,
    #[serde(default)]
    evidence_id: Option<EvidenceId>,
    observed_at: Timestamp,
}

impl RequiredCheck {
    /// Creates a required check. A pass from a fake/stationary render origin is
    /// rejected because a fake check can never be `met`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: RequiredCheckKind,
        status: EvidenceCheckResult,
        origin: EvidenceOrigin,
        verifier: impl Into<String>,
        operation: impl Into<String>,
        result: impl Into<String>,
        target_version: TargetVersion,
        scope: EvidenceScope,
        evidence_id: Option<EvidenceId>,
        observed_at: Timestamp,
    ) -> Result<Self, EvidenceValidationError> {
        let verifier = non_empty("check.verifier", verifier.into())?;
        let operation = non_empty("check.operation", operation.into())?;
        let result = non_empty("check.result", result.into())?;
        if kind == RequiredCheckKind::RealRender && status.is_pass() && !origin.is_native_render() {
            return Err(EvidenceValidationError::FakeRender);
        }
        Ok(Self {
            kind,
            status,
            origin,
            verifier,
            operation,
            result,
            target_version,
            scope,
            evidence_id,
            observed_at,
        })
    }

    /// Check kind.
    pub const fn kind(&self) -> RequiredCheckKind {
        self.kind
    }

    /// Distinguished result.
    pub const fn status(&self) -> EvidenceCheckResult {
        self.status
    }

    /// Evidence origin.
    pub const fn origin(&self) -> EvidenceOrigin {
        self.origin
    }

    /// Verifier label.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Exact operation or equivalent.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Actual result detail.
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Target version the check ran against.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// What the check covered and its limits.
    pub const fn scope(&self) -> &EvidenceScope {
        &self.scope
    }

    /// Evidence record identifier, when recorded in H2.
    pub const fn evidence_id(&self) -> Option<EvidenceId> {
        self.evidence_id
    }

    /// When the observation was made.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
}

/// Exactly one result for every mandatory check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckSet {
    format_version: u32,
    checks: Vec<RequiredCheck>,
}

impl CheckSet {
    /// Creates a complete check set.
    pub fn new(checks: Vec<RequiredCheck>) -> Result<Self, EvidenceValidationError> {
        for kind in [
            RequiredCheckKind::CommonStructural,
            RequiredCheckKind::RealRender,
        ] {
            let count = checks.iter().filter(|check| check.kind() == kind).count();
            if count != 1 {
                return Err(EvidenceValidationError::RequiredCheckMissing {
                    check: kind.as_str(),
                });
            }
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            checks,
        })
    }

    /// One check by kind.
    pub fn get(&self, kind: RequiredCheckKind) -> Option<&RequiredCheck> {
        self.checks.iter().find(|check| check.kind() == kind)
    }

    /// All checks in fixed order.
    pub fn checks(&self) -> &[RequiredCheck] {
        &self.checks
    }

    /// Whether the common structural validation passed.
    pub fn structural_pass(&self) -> bool {
        self.get(RequiredCheckKind::CommonStructural)
            .is_some_and(|check| check.status().is_pass())
    }

    /// Whether a real native render passed.
    pub fn render_pass(&self) -> bool {
        self.get(RequiredCheckKind::RealRender)
            .is_some_and(|check| check.status().is_pass() && check.origin().is_native_render())
    }

    /// Whether a render check exists.
    pub fn render_present(&self) -> bool {
        self.get(RequiredCheckKind::RealRender).is_some()
    }

    /// Whether the render evidence is explicitly fake or stationary.
    pub fn render_is_fake(&self) -> bool {
        self.get(RequiredCheckKind::RealRender)
            .is_some_and(|check| !check.origin().is_native_render())
    }

    /// Whether both mandatory checks passed.
    pub fn all_pass(&self) -> bool {
        self.structural_pass() && self.render_pass()
    }
}

impl H3Record for CheckSet {
    const RECORD: &'static str = "H3 required check set";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Exact input fingerprints bound before and after verification and assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceFingerprints {
    settings: ContentDigest,
    policy: ContentDigest,
    pack: ContentDigest,
    css: ContentDigest,
    resources: ContentDigest,
    candidate: ContentDigest,
    provenance: ContentDigest,
    source: ContentDigest,
    rubric: ContentDigest,
    profile: ProfileBinding,
    condition_version: ConditionVersion,
    condition_digest: ConditionDigest,
    target_version: TargetVersion,
}

impl EvidenceFingerprints {
    /// Creates an exact fingerprint bound to the candidate and profile.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        settings: ContentDigest,
        policy: ContentDigest,
        pack: ContentDigest,
        css: ContentDigest,
        resources: ContentDigest,
        candidate: ContentDigest,
        provenance: ContentDigest,
        source: ContentDigest,
        rubric: ContentDigest,
        profile: ProfileBinding,
        condition_version: ConditionVersion,
        condition_digest: ConditionDigest,
        target_version: TargetVersion,
    ) -> Self {
        Self {
            settings,
            policy,
            pack,
            css,
            resources,
            candidate,
            provenance,
            source,
            rubric,
            profile,
            condition_version,
            condition_digest,
            target_version,
        }
    }

    /// Settings fingerprint.
    pub const fn settings(&self) -> &ContentDigest {
        &self.settings
    }

    /// Policy fingerprint.
    pub const fn policy(&self) -> &ContentDigest {
        &self.policy
    }

    /// Pack fingerprint.
    pub const fn pack(&self) -> &ContentDigest {
        &self.pack
    }

    /// Shared CSS fingerprint.
    pub const fn css(&self) -> &ContentDigest {
        &self.css
    }

    /// Resource-set fingerprint.
    pub const fn resources(&self) -> &ContentDigest {
        &self.resources
    }

    /// Candidate HTML fingerprint.
    pub const fn candidate(&self) -> &ContentDigest {
        &self.candidate
    }

    /// Provenance fingerprint.
    pub const fn provenance(&self) -> &ContentDigest {
        &self.provenance
    }

    /// Source Markdown fingerprint.
    pub const fn source(&self) -> &ContentDigest {
        &self.source
    }

    /// Rubric fingerprint.
    pub const fn rubric(&self) -> &ContentDigest {
        &self.rubric
    }

    /// Fixed Html assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Condition digest.
    pub const fn condition_digest(&self) -> &ConditionDigest {
        &self.condition_digest
    }

    /// Target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Stable digest over the exact fingerprint set.
    pub fn digest(&self) -> ContentDigest {
        let bytes = serde_json::to_vec(self).expect("fingerprints are serializable");
        ContentDigest::sha256(&bytes)
    }

    /// Names of changed fields relative to a later observation.
    pub fn changed_fields(&self, later: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.settings != later.settings {
            changed.push("settings");
        }
        if self.policy != later.policy {
            changed.push("policy");
        }
        if self.pack != later.pack {
            changed.push("pack");
        }
        if self.css != later.css {
            changed.push("css");
        }
        if self.resources != later.resources {
            changed.push("resources");
        }
        if self.candidate != later.candidate {
            changed.push("candidate");
        }
        if self.provenance != later.provenance {
            changed.push("provenance");
        }
        if self.source != later.source {
            changed.push("source");
        }
        if self.rubric != later.rubric {
            changed.push("rubric");
        }
        if self.profile != later.profile {
            changed.push("profile");
        }
        if self.condition_version != later.condition_version {
            changed.push("conditionVersion");
        }
        if self.condition_digest != later.condition_digest {
            changed.push("conditionDigest");
        }
        if self.target_version != later.target_version {
            changed.push("targetVersion");
        }
        changed
    }
}

/// Fingerprint stages captured around verification and assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationBinding {
    pre_verification: EvidenceFingerprints,
    post_verification: EvidenceFingerprints,
    #[serde(default)]
    pre_assessment: Option<EvidenceFingerprints>,
    #[serde(default)]
    post_assessment: Option<EvidenceFingerprints>,
}

impl EvaluationBinding {
    /// Creates a verification binding.
    pub const fn verification(
        pre_verification: EvidenceFingerprints,
        post_verification: EvidenceFingerprints,
    ) -> Self {
        Self {
            pre_verification,
            post_verification,
            pre_assessment: None,
            post_assessment: None,
        }
    }

    /// Adds the assessment stage.
    #[must_use]
    pub fn with_assessment(
        mut self,
        pre_assessment: EvidenceFingerprints,
        post_assessment: EvidenceFingerprints,
    ) -> Self {
        self.pre_assessment = Some(pre_assessment);
        self.post_assessment = Some(post_assessment);
        self
    }

    /// Pre-verification fingerprints.
    pub const fn pre_verification(&self) -> &EvidenceFingerprints {
        &self.pre_verification
    }

    /// Post-verification fingerprints.
    pub const fn post_verification(&self) -> &EvidenceFingerprints {
        &self.post_verification
    }

    /// Stage at which the binding stopped being current.
    pub fn stale_stage(&self) -> Option<&'static str> {
        if self.pre_verification != self.post_verification {
            return Some("verification");
        }
        if let (Some(pre), Some(post)) = (&self.pre_assessment, &self.post_assessment)
            && pre != post
        {
            return Some("assessment");
        }
        None
    }

    /// Whether every captured stage is identical.
    pub fn is_current(&self) -> bool {
        self.stale_stage().is_none()
    }
}

/// One parsed source unit from the pack `source-units` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceUnitDefinition {
    id: String,
    kind: String,
    source_digest: ContentDigest,
    start: u64,
    end: u64,
    #[serde(default)]
    parent: Option<String>,
    text: String,
}

impl SourceUnitDefinition {
    /// Source unit identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Source kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Exact source digest.
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    /// UTF-8 byte start.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// UTF-8 byte end.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Parent unit identifier.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Full source unit text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One strict preservation requirement derived by the pack scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StrictRequirement {
    unit: String,
    category: String,
    value: String,
}

impl StrictRequirement {
    /// Source unit.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Strict category.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Exact value that must remain visible.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Parsed pack `source-units` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceUnits {
    format_version: u32,
    contract: String,
    status: String,
    source_path: String,
    source_digest: ContentDigest,
    byte_length: u64,
    units: Vec<SourceUnitDefinition>,
    unsupported: Vec<Value>,
    strict: Vec<StrictRequirement>,
}

impl SourceUnits {
    /// Parse and validate the exact `source-units` result.
    pub fn from_policy(value: &Value) -> Result<Self, EvidenceValidationError> {
        let contract = value
            .get("contract")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("sourceUnits.contract", "missing"))?;
        let status = value
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("sourceUnits.status", "missing"))?;
        let source = value
            .get("source")
            .ok_or_else(|| invalid("sourceUnits.source", "missing"))?;
        let source_path = source
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default();
        let source_digest = parse_digest(
            source
                .get("digest")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("sourceUnits.source.digest", "missing"))?,
            "sourceUnits.source.digest",
        )?;
        let byte_length = source
            .get("byte_length")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("sourceUnits.source.byteLength", "missing"))?;
        let unsupported = value
            .get("unsupported")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let units_value = value
            .get("units")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("sourceUnits.units", "missing"))?;
        let mut units = Vec::with_capacity(units_value.len());
        let mut seen = BTreeSet::new();
        for item in units_value {
            let id = string_field(item, "id", "sourceUnits.units[].id")?;
            if !seen.insert(id.clone()) {
                return Err(EvidenceValidationError::UnitDuplicate { unit: id });
            }
            let range = item
                .get("range")
                .ok_or_else(|| invalid("sourceUnits.units[].range", "missing"))?;
            units.push(SourceUnitDefinition {
                id,
                kind: string_field(item, "kind", "sourceUnits.units[].kind")?,
                source_digest: parse_digest(
                    &string_field(item, "source_digest", "sourceUnits.units[].source_digest")?,
                    "sourceUnits.units[].source_digest",
                )?,
                start: range
                    .get("start")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("sourceUnits.units[].range.start", "missing"))?,
                end: range
                    .get("end")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("sourceUnits.units[].range.end", "missing"))?,
                parent: item
                    .get("parent")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                text: string_field(item, "text", "sourceUnits.units[].text")?,
            });
        }
        let strict = value
            .get("strict")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        Ok(StrictRequirement {
                            unit: string_field(entry, "unit", "sourceUnits.strict[].unit")?,
                            category: string_field(
                                entry,
                                "category",
                                "sourceUnits.strict[].category",
                            )?,
                            value: string_field(entry, "value", "sourceUnits.strict[].value")?,
                        })
                    })
                    .collect::<Result<Vec<_>, EvidenceValidationError>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            contract: contract.to_owned(),
            status: status.to_owned(),
            source_path,
            source_digest,
            byte_length,
            units,
            unsupported,
            strict,
        })
    }

    /// Semantic contract declared by the pack.
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Scan status.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Exact source path.
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Exact source digest.
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    /// Exact source byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Parsed units in source order.
    pub fn units(&self) -> &[SourceUnitDefinition] {
        &self.units
    }

    /// Unsupported constructs. A non-empty list is a hold, never a pass.
    pub fn unsupported(&self) -> &[Value] {
        &self.unsupported
    }

    /// Strict preservation requirements.
    pub fn strict(&self) -> &[StrictRequirement] {
        &self.strict
    }

    /// Validate status, contract, count, and source digest against exact bytes.
    pub fn validate_against(
        &self,
        source_path: &str,
        source_bytes: &[u8],
    ) -> Result<(), EvidenceValidationError> {
        if self.contract != "semantic-v1" {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: self.contract.clone(),
            });
        }
        if self.status != "complete" {
            return Err(EvidenceValidationError::IncompleteSource {
                detail: format!("source scan status is {:?}", self.status),
            });
        }
        if !self.unsupported.is_empty() {
            return Err(EvidenceValidationError::UnsupportedSourceConstructs {
                count: self.unsupported.len(),
            });
        }
        if self.source_path != source_path {
            return Err(EvidenceValidationError::InvalidValue {
                field: "sourceUnits.source.path".to_owned(),
                detail: format!("expected {source_path:?}, found {:?}", self.source_path),
            });
        }
        let digest = ContentDigest::sha256(source_bytes);
        if digest != self.source_digest || self.byte_length != source_bytes.len() as u64 {
            return Err(EvidenceValidationError::SourceDigestMismatch);
        }
        for unit in &self.units {
            if unit.source_digest != digest {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "sourceDigest",
                });
            }
            if unit.end < unit.start || unit.end > self.byte_length {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "range",
                });
            }
        }
        Ok(())
    }
}

impl H3Record for SourceUnits {
    const RECORD: &'static str = "H3 source units";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// One declared provenance unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceUnit {
    id: String,
    kind: String,
    source_digest: ContentDigest,
    start: u64,
    end: u64,
    #[serde(default)]
    parent: Option<String>,
}

/// One provenance mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceMapping {
    unit: String,
    representation: String,
    targets: Vec<String>,
}

/// One provenance strict entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceStrict {
    unit: String,
    category: String,
    value: String,
    targets: Vec<String>,
}

/// One supplementary representation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceSupplementary {
    id: String,
    kind: String,
    units: Vec<String>,
    targets: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    diagram: Option<Value>,
    #[serde(default)]
    graph: Option<Value>,
}

/// Parsed embedded provenance mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    schema: String,
    version: u64,
    contract: String,
    source_path: String,
    source_digest: ContentDigest,
    units: Vec<ProvenanceUnit>,
    mappings: Vec<ProvenanceMapping>,
    strict: Vec<ProvenanceStrict>,
    supplementary: Vec<ProvenanceSupplementary>,
    calculations: Vec<Value>,
}

impl Provenance {
    /// Extract and validate the non-executed `template#sdd-provenance` JSON.
    pub fn from_html(html: &str) -> Result<Self, EvidenceValidationError> {
        let payload =
            extract_provenance_payload(html).ok_or(EvidenceValidationError::ProvenanceMissing)?;
        let value: Value = serde_json::from_str(&payload).map_err(|error| {
            EvidenceValidationError::ProvenanceInvalid {
                detail: error.to_string(),
            }
        })?;
        let schema = value
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provenance.schema", "missing"))?;
        if schema != "sdd-provenance" {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: schema.to_owned(),
            });
        }
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("provenance.version", "missing"))?;
        if version != 1 {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: format!("provenance-version-{version}"),
            });
        }
        let contract = value
            .get("contract")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provenance.contract", "missing"))?;
        let source = value
            .get("source")
            .ok_or_else(|| invalid("provenance.source", "missing"))?;
        let source_path = source
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provenance.source.path", "missing"))?
            .to_owned();
        let source_digest = parse_digest(
            source
                .get("digest")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("provenance.source.digest", "missing"))?,
            "provenance.source.digest",
        )?;
        let units = value
            .get("units")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("provenance.units", "missing"))?
            .iter()
            .map(|unit| {
                let range = unit
                    .get("range")
                    .ok_or_else(|| invalid("provenance.units[].range", "missing"))?;
                Ok(ProvenanceUnit {
                    id: string_field(unit, "id", "provenance.units[].id")?,
                    kind: string_field(unit, "kind", "provenance.units[].kind")?,
                    source_digest: parse_digest(
                        &string_field(unit, "source_digest", "provenance.units[].source_digest")?,
                        "provenance.units[].source_digest",
                    )?,
                    start: range
                        .get("start")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| invalid("provenance.units[].range.start", "missing"))?,
                    end: range
                        .get("end")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| invalid("provenance.units[].range.end", "missing"))?,
                    parent: unit
                        .get("parent")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, EvidenceValidationError>>()?;
        let mappings = value
            .get("mappings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("provenance.mappings", "missing"))?
            .iter()
            .map(|mapping| {
                Ok(ProvenanceMapping {
                    unit: string_field(mapping, "unit", "provenance.mappings[].unit")?,
                    representation: string_field(
                        mapping,
                        "representation",
                        "provenance.mappings[].representation",
                    )?,
                    targets: string_list(mapping, "targets", "provenance.mappings[].targets")?,
                })
            })
            .collect::<Result<Vec<_>, EvidenceValidationError>>()?;
        let strict = value
            .get("strict")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        Ok(ProvenanceStrict {
                            unit: string_field(entry, "unit", "provenance.strict[].unit")?,
                            category: string_field(
                                entry,
                                "category",
                                "provenance.strict[].category",
                            )?,
                            value: string_field(entry, "value", "provenance.strict[].value")?,
                            targets: string_list(entry, "targets", "provenance.strict[].targets")?,
                        })
                    })
                    .collect::<Result<Vec<_>, EvidenceValidationError>>()
            })
            .transpose()?
            .unwrap_or_default();
        let supplementary = value
            .get("supplementary")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        Ok(ProvenanceSupplementary {
                            id: string_field(entry, "id", "provenance.supplementary[].id")?,
                            kind: string_field(entry, "kind", "provenance.supplementary[].kind")?,
                            units: string_list(entry, "units", "provenance.supplementary[].units")?,
                            targets: string_list(
                                entry,
                                "targets",
                                "provenance.supplementary[].targets",
                            )?,
                            description: entry
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            diagram: entry.get("diagram").cloned(),
                            graph: entry.get("graph").cloned(),
                        })
                    })
                    .collect::<Result<Vec<_>, EvidenceValidationError>>()
            })
            .transpose()?
            .unwrap_or_default();
        let calculations = value
            .get("calculations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(Self {
            schema: schema.to_owned(),
            version,
            contract: contract.to_owned(),
            source_path,
            source_digest,
            units,
            mappings,
            strict,
            supplementary,
            calculations,
        })
    }

    /// Provenance schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Provenance version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Declared contract.
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Source path recorded in the candidate.
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Source digest recorded in the candidate.
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    /// Declared units.
    pub fn units(&self) -> &[ProvenanceUnit] {
        &self.units
    }

    /// Mappings.
    pub fn mappings(&self) -> &[ProvenanceMapping] {
        &self.mappings
    }

    /// Strict entries.
    pub fn strict(&self) -> &[ProvenanceStrict] {
        &self.strict
    }

    /// Supplementary entries.
    pub fn supplementary(&self) -> &[ProvenanceSupplementary] {
        &self.supplementary
    }

    /// Calculation entries.
    pub fn calculations(&self) -> &[Value] {
        &self.calculations
    }
}

/// Visible HTML target and scanner facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeadingFact {
    level: u8,
    text: String,
    #[serde(default)]
    id: Option<String>,
}

impl HeadingFact {
    /// Heading level 1-6.
    pub const fn level(&self) -> u8 {
        self.level
    }

    /// Normalized heading text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Element id, when present.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Facts extracted from the candidate HTML without executing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScannedHtml {
    visible_text: String,
    targets: BTreeMap<String, String>,
    hidden_targets: BTreeSet<String>,
    headings: Vec<HeadingFact>,
    landmarks: Vec<String>,
    navigation_targets: Vec<String>,
    focus_order: Vec<String>,
    block_order: Vec<String>,
}

impl ScannedHtml {
    /// Scan the candidate HTML. The scanner never executes scripts or reads a
    /// file; it only classifies tags and visible text.
    pub fn scan(html: &str) -> Self {
        scan_html(html)
    }

    /// Visible text in main, excluding template/head/aside/nav/hidden.
    pub fn visible_text(&self) -> &str {
        &self.visible_text
    }

    /// Outer HTML for each visible target id.
    pub fn target(&self, id: &str) -> Option<&str> {
        self.targets.get(id).map(String::as_str)
    }

    /// Visible target ids.
    pub fn targets(&self) -> &BTreeMap<String, String> {
        &self.targets
    }

    /// Target ids that exist only in hidden/template/head/aside/nav content.
    pub fn hidden_targets(&self) -> &BTreeSet<String> {
        &self.hidden_targets
    }

    /// Visible headings.
    pub fn headings(&self) -> &[HeadingFact] {
        &self.headings
    }

    /// Visible landmark labels.
    pub fn landmarks(&self) -> &[String] {
        &self.landmarks
    }

    /// Navigation link targets.
    pub fn navigation_targets(&self) -> &[String] {
        &self.navigation_targets
    }

    /// Static focus order.
    pub fn focus_order(&self) -> &[String] {
        &self.focus_order
    }

    /// Static block reading order.
    pub fn block_order(&self) -> &[String] {
        &self.block_order
    }
}

/// One source unit with full text, context, and visible mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnitEvidence {
    unit_id: String,
    kind: String,
    source_digest: ContentDigest,
    start: u64,
    end: u64,
    #[serde(default)]
    parent: Option<String>,
    text: String,
    related_context: String,
    representations: Vec<String>,
    targets: Vec<String>,
}

impl UnitEvidence {
    /// Source unit id.
    pub fn unit_id(&self) -> &str {
        &self.unit_id
    }

    /// Source kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Full source unit text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Related context (heading path, parent, neighbours).
    pub fn related_context(&self) -> &str {
        &self.related_context
    }

    /// Visible target ids.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Provenance representation labels for this unit.
    pub fn representations(&self) -> &[String] {
        &self.representations
    }

    /// Source byte range.
    pub const fn range(&self) -> (u64, u64) {
        (self.start, self.end)
    }
}

/// One strict value and its visible targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StrictEvidence {
    unit: String,
    category: String,
    value: String,
    targets: Vec<String>,
    preserved: bool,
}

impl StrictEvidence {
    /// Source unit.
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Strict category.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Exact value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Visible targets checked.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Whether the exact value is visible at every declared target.
    pub const fn preserved(&self) -> bool {
        self.preserved
    }
}

/// One supplementary representation and its declared roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplementaryEvidence {
    id: String,
    kind: String,
    #[serde(default)]
    description: Option<String>,
    roots: Vec<String>,
    targets: Vec<String>,
    supported: bool,
    diagram_nodes: u32,
    diagram_edges: u32,
    graph_series: u32,
    graph_values: u32,
    caption_present: bool,
    text_equivalent_present: bool,
    data_table_present: bool,
    color_only: bool,
}

impl SupplementaryEvidence {
    /// Supplementary id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Supplementary kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Declared source roots.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// Visible targets.
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Whether the declared roots are present and the target is visible.
    pub const fn supported(&self) -> bool {
        self.supported
    }

    /// Diagram node count.
    pub const fn diagram_nodes(&self) -> u32 {
        self.diagram_nodes
    }

    /// Diagram edge count.
    pub const fn diagram_edges(&self) -> u32 {
        self.diagram_edges
    }

    /// Graph series count.
    pub const fn graph_series(&self) -> u32 {
        self.graph_series
    }

    /// Whether a caption is visible.
    pub const fn caption_present(&self) -> bool {
        self.caption_present
    }

    /// Whether a text equivalent is visible.
    pub const fn text_equivalent_present(&self) -> bool {
        self.text_equivalent_present
    }

    /// Whether a data table is visible.
    pub const fn data_table_present(&self) -> bool {
        self.data_table_present
    }

    /// Whether colour alone carries the meaning.
    pub const fn color_only(&self) -> bool {
        self.color_only
    }
}

/// Supplementary/diagram evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupportEvidence {
    supplementary: Vec<SupplementaryEvidence>,
    calculation_count: u32,
}

impl SupportEvidence {
    /// Supplementary entries.
    pub fn supplementary(&self) -> &[SupplementaryEvidence] {
        &self.supplementary
    }

    /// Declared calculation count.
    pub const fn calculation_count(&self) -> u32 {
        self.calculation_count
    }
}

/// Whole-document usability facts, combining HTML structure and real render.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsabilityEvidence {
    headings: Vec<HeadingFact>,
    landmarks: Vec<String>,
    navigation_targets: Vec<String>,
    reading_order: Vec<String>,
    focus_order: Vec<String>,
    outline_valid: bool,
    reading_order_matches_visual: bool,
    page_horizontal_overflow: bool,
    overlapping_blocks: u32,
    readability_failures: u32,
    small_text_elements: u32,
    contrast_failures: u32,
    failed_images: u32,
    keyboard_reachable: bool,
}

impl UsabilityEvidence {
    /// Visible headings.
    pub fn headings(&self) -> &[HeadingFact] {
        &self.headings
    }

    /// Visible landmarks.
    pub fn landmarks(&self) -> &[String] {
        &self.landmarks
    }

    /// Navigation targets.
    pub fn navigation_targets(&self) -> &[String] {
        &self.navigation_targets
    }

    /// Reading order selectors.
    pub fn reading_order(&self) -> &[String] {
        &self.reading_order
    }

    /// Focus order selectors.
    pub fn focus_order(&self) -> &[String] {
        &self.focus_order
    }

    /// Whether heading levels are coherent.
    pub const fn outline_valid(&self) -> bool {
        self.outline_valid
    }

    /// Whether reading order agrees with visual order.
    pub const fn reading_order_matches_visual(&self) -> bool {
        self.reading_order_matches_visual
    }

    /// Whether the page has horizontal overflow.
    pub const fn page_horizontal_overflow(&self) -> bool {
        self.page_horizontal_overflow
    }

    /// Overlapping block count.
    pub const fn overlapping_blocks(&self) -> u32 {
        self.overlapping_blocks
    }

    /// Readability failure count.
    pub const fn readability_failures(&self) -> u32 {
        self.readability_failures
    }

    /// Small text element count.
    pub const fn small_text_elements(&self) -> u32 {
        self.small_text_elements
    }

    /// Contrast failure count.
    pub const fn contrast_failures(&self) -> u32 {
        self.contrast_failures
    }

    /// Failed image count.
    pub const fn failed_images(&self) -> u32 {
        self.failed_images
    }

    /// Whether keyboard focus is reachable.
    pub const fn keyboard_reachable(&self) -> bool {
        self.keyboard_reachable
    }
}

/// Render layout signals copied from the real manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderSignalEvidence {
    page_horizontal_overflow: bool,
    overflowing_elements: u32,
    overlapping_blocks: u32,
    readability_failures: u32,
    min_font_size_px: f64,
    min_line_height_ratio: f64,
    small_text_elements: u32,
    contrast_failures: u32,
    failed_images: u32,
    svg_elements: u32,
    aria_nodes: u32,
    headings: u32,
}

impl RenderSignalEvidence {
    /// Creates a signal record.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        page_horizontal_overflow: bool,
        overflowing_elements: u32,
        overlapping_blocks: u32,
        readability_failures: u32,
        min_font_size_px: f64,
        min_line_height_ratio: f64,
        small_text_elements: u32,
        contrast_failures: u32,
        failed_images: u32,
        svg_elements: u32,
        aria_nodes: u32,
        headings: u32,
    ) -> Self {
        Self {
            page_horizontal_overflow,
            overflowing_elements,
            overlapping_blocks,
            readability_failures,
            min_font_size_px,
            min_line_height_ratio,
            small_text_elements,
            contrast_failures,
            failed_images,
            svg_elements,
            aria_nodes,
            headings,
        }
    }

    /// Page-level horizontal overflow.
    pub const fn page_horizontal_overflow(&self) -> bool {
        self.page_horizontal_overflow
    }

    /// Overflowing element count.
    pub const fn overflowing_elements(&self) -> u32 {
        self.overflowing_elements
    }

    /// Overlapping block count.
    pub const fn overlapping_blocks(&self) -> u32 {
        self.overlapping_blocks
    }

    /// Readability failure count.
    pub const fn readability_failures(&self) -> u32 {
        self.readability_failures
    }

    /// Minimum font size in CSS px.
    pub const fn min_font_size_px(&self) -> f64 {
        self.min_font_size_px
    }

    /// Minimum line-height ratio.
    pub const fn min_line_height_ratio(&self) -> f64 {
        self.min_line_height_ratio
    }

    /// Small text element count.
    pub const fn small_text_elements(&self) -> u32 {
        self.small_text_elements
    }

    /// Contrast failure count.
    pub const fn contrast_failures(&self) -> u32 {
        self.contrast_failures
    }

    /// Failed image count.
    pub const fn failed_images(&self) -> u32 {
        self.failed_images
    }

    /// Inline SVG element count.
    pub const fn svg_elements(&self) -> u32 {
        self.svg_elements
    }

    /// Accessibility projection node count.
    pub const fn aria_nodes(&self) -> u32 {
        self.aria_nodes
    }

    /// Heading count.
    pub const fn headings(&self) -> u32 {
        self.headings
    }
}

/// Candidate fingerprints recorded by the render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderCandidateFingerprints {
    html: ContentDigest,
    css: ContentDigest,
    resources: ContentDigest,
    candidate: ContentDigest,
}

impl RenderCandidateFingerprints {
    /// Creates exact render candidate fingerprints.
    pub const fn new(
        html: ContentDigest,
        css: ContentDigest,
        resources: ContentDigest,
        candidate: ContentDigest,
    ) -> Self {
        Self {
            html,
            css,
            resources,
            candidate,
        }
    }

    /// HTML digest.
    pub const fn html(&self) -> &ContentDigest {
        &self.html
    }

    /// CSS digest.
    pub const fn css(&self) -> &ContentDigest {
        &self.css
    }

    /// Resource-set digest.
    pub const fn resources(&self) -> &ContentDigest {
        &self.resources
    }

    /// Aggregate candidate digest.
    pub const fn candidate(&self) -> &ContentDigest {
        &self.candidate
    }
}

/// One render configuration record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderConfigurationEvidence {
    id: String,
    viewport_width: u32,
    viewport_height: u32,
    appearance: String,
    page_zoom: f64,
    css_viewport_width: u32,
    css_viewport_height: u32,
    png_path: String,
    png_digest: ContentDigest,
    png_pixel_width: u32,
    png_pixel_height: u32,
    dom: Value,
    accessibility: Value,
}

impl RenderConfigurationEvidence {
    /// Creates one render configuration record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        viewport_width: u32,
        viewport_height: u32,
        appearance: impl Into<String>,
        page_zoom: f64,
        css_viewport_width: u32,
        css_viewport_height: u32,
        png_path: impl Into<String>,
        png_digest: ContentDigest,
        png_pixel_width: u32,
        png_pixel_height: u32,
        dom: Value,
        accessibility: Value,
    ) -> Result<Self, EvidenceValidationError> {
        let id = non_empty("renderConfiguration.id", id.into())?;
        let png_path = non_empty("renderConfiguration.pngPath", png_path.into())?;
        if viewport_width == 0
            || viewport_height == 0
            || css_viewport_width == 0
            || css_viewport_height == 0
            || png_pixel_width == 0
            || png_pixel_height == 0
        {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: format!("configuration {id:?} has an empty viewport or PNG size"),
            });
        }
        Ok(Self {
            id,
            viewport_width,
            viewport_height,
            appearance: appearance.into(),
            page_zoom,
            css_viewport_width,
            css_viewport_height,
            png_path,
            png_digest,
            png_pixel_width,
            png_pixel_height,
            dom,
            accessibility,
        })
    }

    /// Configuration id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Window CSS width.
    pub const fn viewport_width(&self) -> u32 {
        self.viewport_width
    }

    /// Window CSS height.
    pub const fn viewport_height(&self) -> u32 {
        self.viewport_height
    }

    /// Appearance label.
    pub fn appearance(&self) -> &str {
        &self.appearance
    }

    /// Page zoom factor.
    pub const fn page_zoom(&self) -> f64 {
        self.page_zoom
    }

    /// Layout viewport width after zoom.
    pub const fn css_viewport_width(&self) -> u32 {
        self.css_viewport_width
    }

    /// Layout viewport height after zoom.
    pub const fn css_viewport_height(&self) -> u32 {
        self.css_viewport_height
    }

    /// PNG relative path.
    pub fn png_path(&self) -> &str {
        &self.png_path
    }

    /// PNG digest.
    pub const fn png_digest(&self) -> &ContentDigest {
        &self.png_digest
    }

    /// PNG pixel width.
    pub const fn png_pixel_width(&self) -> u32 {
        self.png_pixel_width
    }

    /// PNG pixel height.
    pub const fn png_pixel_height(&self) -> u32 {
        self.png_pixel_height
    }

    /// DOM projection.
    pub const fn dom(&self) -> &Value {
        &self.dom
    }

    /// Accessibility projection.
    pub const fn accessibility(&self) -> &Value {
        &self.accessibility
    }
}

/// One approved render PNG. Bytes are kept only in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderPngEvidence {
    path: String,
    digest: ContentDigest,
    pixel_width: u32,
    pixel_height: u32,
    #[serde(skip)]
    bytes: Vec<u8>,
}

impl RenderPngEvidence {
    /// Creates one approved PNG record.
    pub fn new(
        path: impl Into<String>,
        bytes: Vec<u8>,
        pixel_width: u32,
        pixel_height: u32,
    ) -> Result<Self, EvidenceValidationError> {
        let path = non_empty("renderPng.path", path.into())?;
        if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: format!("{path:?} is not a PNG file"),
            });
        }
        if pixel_width == 0 || pixel_height == 0 {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: format!("{path:?} has no pixels"),
            });
        }
        let header_width = u32::from_be_bytes(
            bytes
                .get(16..20)
                .ok_or_else(|| EvidenceValidationError::IncompleteRender {
                    detail: format!("{path:?} lacks an IHDR width"),
                })?
                .try_into()
                .expect("four bytes"),
        );
        let header_height = u32::from_be_bytes(
            bytes
                .get(20..24)
                .ok_or_else(|| EvidenceValidationError::IncompleteRender {
                    detail: format!("{path:?} lacks an IHDR height"),
                })?
                .try_into()
                .expect("four bytes"),
        );
        if header_width != pixel_width || header_height != pixel_height {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: format!(
                    "{path:?} pixel size {pixel_width}x{pixel_height} does not match its IHDR"
                ),
            });
        }
        Ok(Self {
            path,
            digest: ContentDigest::sha256(&bytes),
            pixel_width,
            pixel_height,
            bytes,
        })
    }

    /// Relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact PNG digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Pixel width.
    pub const fn pixel_width(&self) -> u32 {
        self.pixel_width
    }

    /// Pixel height.
    pub const fn pixel_height(&self) -> u32 {
        self.pixel_height
    }

    /// Approved image bytes, when held in memory.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Render evidence in the versioned H3 shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderEvidence {
    format_version: u32,
    manifest_version: String,
    evidence_source: String,
    job_id: String,
    origin: EvidenceOrigin,
    complete: bool,
    configurations: Vec<RenderConfigurationEvidence>,
    accessibility_source: String,
    aria_nodes: u32,
    signals: RenderSignalEvidence,
    hidden_window: bool,
    isolation: bool,
    tauri_ipc_injected: bool,
    candidate: RenderCandidateFingerprints,
    pngs: Vec<RenderPngEvidence>,
    captured_at_unix_ms: u64,
}

impl RenderEvidence {
    /// Creates a native render record and validates the complete matrix.
    #[allow(clippy::too_many_arguments)]
    pub fn native(
        manifest_version: impl Into<String>,
        evidence_source: impl Into<String>,
        job_id: impl Into<String>,
        complete: bool,
        configurations: Vec<RenderConfigurationEvidence>,
        accessibility_source: impl Into<String>,
        aria_nodes: u32,
        signals: RenderSignalEvidence,
        hidden_window: bool,
        isolation: bool,
        tauri_ipc_injected: bool,
        candidate: RenderCandidateFingerprints,
        pngs: Vec<RenderPngEvidence>,
        captured_at_unix_ms: u64,
    ) -> Result<Self, EvidenceValidationError> {
        let render = Self::assemble(
            manifest_version,
            evidence_source,
            job_id,
            EvidenceOrigin::WkWebViewNative,
            complete,
            configurations,
            accessibility_source,
            aria_nodes,
            signals,
            hidden_window,
            isolation,
            tauri_ipc_injected,
            candidate,
            pngs,
            captured_at_unix_ms,
        );
        render.validate_native()?;
        Ok(render)
    }

    /// Creates an explicitly fake/stationary render for tests. This can never
    /// satisfy the real-render required check.
    #[allow(clippy::too_many_arguments)]
    pub fn fake(
        origin: EvidenceOrigin,
        complete: bool,
        configurations: Vec<RenderConfigurationEvidence>,
        accessibility_source: impl Into<String>,
        signals: RenderSignalEvidence,
        candidate: RenderCandidateFingerprints,
        pngs: Vec<RenderPngEvidence>,
    ) -> Result<Self, EvidenceValidationError> {
        if origin.is_native_render() {
            return Err(EvidenceValidationError::FakeRender);
        }
        Ok(Self::assemble(
            H3_RENDER_MANIFEST_VERSION,
            origin.as_str(),
            "fake-render-job",
            origin,
            complete,
            configurations,
            accessibility_source,
            signals.aria_nodes,
            signals,
            true,
            true,
            false,
            candidate,
            pngs,
            0,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        manifest_version: impl Into<String>,
        evidence_source: impl Into<String>,
        job_id: impl Into<String>,
        origin: EvidenceOrigin,
        complete: bool,
        configurations: Vec<RenderConfigurationEvidence>,
        accessibility_source: impl Into<String>,
        aria_nodes: u32,
        signals: RenderSignalEvidence,
        hidden_window: bool,
        isolation: bool,
        tauri_ipc_injected: bool,
        candidate: RenderCandidateFingerprints,
        pngs: Vec<RenderPngEvidence>,
        captured_at_unix_ms: u64,
    ) -> Self {
        Self {
            format_version: H3_FORMAT_VERSION,
            manifest_version: manifest_version.into(),
            evidence_source: evidence_source.into(),
            job_id: job_id.into(),
            origin,
            complete,
            configurations,
            accessibility_source: accessibility_source.into(),
            aria_nodes,
            signals,
            hidden_window,
            isolation,
            tauri_ipc_injected,
            candidate,
            pngs,
            captured_at_unix_ms,
        }
    }

    /// Render origin.
    pub const fn origin(&self) -> EvidenceOrigin {
        self.origin
    }

    /// Exact manifest version.
    pub fn manifest_version(&self) -> &str {
        &self.manifest_version
    }

    /// Manifest evidence source.
    pub fn evidence_source(&self) -> &str {
        &self.evidence_source
    }

    /// Job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Whether the capture is complete.
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Configuration records.
    pub fn configurations(&self) -> &[RenderConfigurationEvidence] {
        &self.configurations
    }

    /// Accessibility source label.
    pub fn accessibility_source(&self) -> &str {
        &self.accessibility_source
    }

    /// Accessibility projection node count.
    pub const fn aria_nodes(&self) -> u32 {
        self.aria_nodes
    }

    /// Layout signals.
    pub const fn signals(&self) -> &RenderSignalEvidence {
        &self.signals
    }

    /// Candidate fingerprints recorded by the render.
    pub const fn candidate(&self) -> &RenderCandidateFingerprints {
        &self.candidate
    }

    /// Approved PNG records.
    pub fn pngs(&self) -> &[RenderPngEvidence] {
        &self.pngs
    }

    /// Presentation configuration used for whole-document facts.
    pub fn primary(&self) -> Option<&RenderConfigurationEvidence> {
        self.configurations
            .iter()
            .find(|configuration| configuration.id == "desktop-light")
            .or_else(|| self.configurations.first())
    }

    /// Mobile configuration used for narrow-layout facts.
    pub fn mobile(&self) -> Option<&RenderConfigurationEvidence> {
        self.configurations
            .iter()
            .find(|configuration| configuration.id == "mobile-light")
            .or_else(|| self.configurations.get(4))
    }

    /// Validate the exact native matrix.
    pub fn validate_native(&self) -> Result<(), EvidenceValidationError> {
        if self.origin != EvidenceOrigin::WkWebViewNative {
            return Err(EvidenceValidationError::FakeRender);
        }
        if self.manifest_version != H3_RENDER_MANIFEST_VERSION
            || self.evidence_source != NATIVE_RENDER_SOURCE
        {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: "render manifest version or evidence source is not native".to_owned(),
            });
        }
        if !self.complete {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: "render manifest is incomplete".to_owned(),
            });
        }
        if self.tauri_ipc_injected {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: "render exposed a Tauri IPC bridge".to_owned(),
            });
        }
        if !self.hidden_window || !self.isolation {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: "hidden-window or data-store isolation proof is missing".to_owned(),
            });
        }
        if self.accessibility_source != HOST_JS_ACCESSIBILITY_SOURCE {
            return Err(EvidenceValidationError::NativeAccessibilityClaim);
        }
        let expected = [
            "desktop-light",
            "desktop-dark",
            "desktop-zoom-200",
            "desktop-zoom-200-dark",
            "mobile-light",
            "mobile-dark",
            "mobile-zoom-200",
            "mobile-zoom-200-dark",
        ];
        if self.configurations.len() != expected.len() {
            return Err(EvidenceValidationError::IncompleteRender {
                detail: format!(
                    "expected {} configurations, found {}",
                    expected.len(),
                    self.configurations.len()
                ),
            });
        }
        for (expected_id, configuration) in expected.iter().zip(&self.configurations) {
            if configuration.id != *expected_id {
                return Err(EvidenceValidationError::IncompleteRender {
                    detail: format!(
                        "configuration order mismatch: expected {expected_id:?}, found {:?}",
                        configuration.id
                    ),
                });
            }
            let png = self
                .pngs
                .iter()
                .find(|png| png.path == configuration.png_path)
                .ok_or_else(|| EvidenceValidationError::IncompleteRender {
                    detail: format!("PNG {:?} is missing", configuration.png_path),
                })?;
            if png.digest != configuration.png_digest
                || png.pixel_width != configuration.png_pixel_width
                || png.pixel_height != configuration.png_pixel_height
            {
                return Err(EvidenceValidationError::IncompleteRender {
                    detail: format!("PNG {:?} does not match its record", configuration.png_path),
                });
            }
            if png.bytes.is_empty() {
                return Err(EvidenceValidationError::IncompleteRender {
                    detail: format!(
                        "PNG {:?} bytes are unavailable for image evidence",
                        configuration.png_path
                    ),
                });
            }
            if configuration.dom.is_null() || configuration.accessibility.is_null() {
                return Err(EvidenceValidationError::IncompleteRender {
                    detail: format!(
                        "configuration {:?} lacks DOM/accessibility",
                        configuration.id
                    ),
                });
            }
        }
        Ok(())
    }

    /// Approved images for evidence content.
    pub fn images(&self) -> Vec<EvidenceImage> {
        self.pngs
            .iter()
            .filter(|png| !png.bytes.is_empty())
            .map(|png| EvidenceImage::new(png.path.clone(), "image/png", png.bytes.clone()))
            .collect()
    }

    /// Fingerprints match an exact candidate set.
    pub fn binds_candidate(
        &self,
        html: &ContentDigest,
        css: &ContentDigest,
        resources: &ContentDigest,
        candidate: &ContentDigest,
    ) -> bool {
        self.candidate.html == *html
            && self.candidate.css == *css
            && self.candidate.resources == *resources
            && self.candidate.candidate == *candidate
    }
}

/// Coverage of every source unit exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageReport {
    expected_units: Vec<String>,
    covered_units: Vec<String>,
}

impl CoverageReport {
    /// Creates an exact-once coverage report.
    pub fn new(expected: &[String], covered: &[String]) -> Result<Self, EvidenceValidationError> {
        if expected.is_empty() {
            return Err(EvidenceValidationError::SplitCoverage {
                detail: "the source has no units".to_owned(),
            });
        }
        let expected_set: BTreeSet<&String> = expected.iter().collect();
        let mut seen = BTreeSet::new();
        for unit in covered {
            if !expected_set.contains(unit) {
                return Err(EvidenceValidationError::UnitExtraneous { unit: unit.clone() });
            }
            if !seen.insert(unit) {
                return Err(EvidenceValidationError::UnitDuplicate { unit: unit.clone() });
            }
        }
        for unit in expected {
            if !seen.contains(unit) {
                return Err(EvidenceValidationError::UnitMissing { unit: unit.clone() });
            }
        }
        Ok(Self {
            expected_units: expected.to_vec(),
            covered_units: covered.to_vec(),
        })
    }

    /// Expected unit ids.
    pub fn expected_units(&self) -> &[String] {
        &self.expected_units
    }

    /// Covered unit ids.
    pub fn covered_units(&self) -> &[String] {
        &self.covered_units
    }

    /// Whether every expected unit was covered exactly once.
    pub fn is_complete(&self) -> bool {
        self.expected_units.len() == self.covered_units.len()
            && self
                .expected_units
                .iter()
                .all(|unit| self.covered_units.contains(unit))
    }
}

impl H3Record for CoverageReport {
    const RECORD: &'static str = "H3 coverage report";

    fn format_version(&self) -> u32 {
        H3_FORMAT_VERSION
    }
}

/// One part of a split evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitPart {
    index: u32,
    unit_ids: Vec<String>,
}

impl SplitPart {
    /// Part index.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Units evaluated in this part.
    pub fn unit_ids(&self) -> &[String] {
        &self.unit_ids
    }
}

/// A split evaluation that must still cover every source unit exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationSplit {
    parts: Vec<SplitPart>,
}

impl EvaluationSplit {
    /// Splits source units into contiguous bounded parts.
    pub fn contiguous(
        expected: &[String],
        max_units: usize,
    ) -> Result<Self, EvidenceValidationError> {
        if max_units == 0 {
            return Err(EvidenceValidationError::InvalidValue {
                field: "split.maxUnits".to_owned(),
                detail: "must be positive".to_owned(),
            });
        }
        if expected.is_empty() {
            return Err(EvidenceValidationError::SplitCoverage {
                detail: "the source has no units".to_owned(),
            });
        }
        let parts = expected
            .chunks(max_units)
            .enumerate()
            .map(|(index, units)| SplitPart {
                index: index as u32,
                unit_ids: units.to_vec(),
            })
            .collect::<Vec<_>>();
        let split = Self { parts };
        split.validate(expected)?;
        Ok(split)
    }

    /// Parts.
    pub fn parts(&self) -> &[SplitPart] {
        &self.parts
    }

    /// Validate exact-once coverage across parts.
    pub fn validate(&self, expected: &[String]) -> Result<(), EvidenceValidationError> {
        if self.parts.is_empty() {
            return Err(EvidenceValidationError::SplitCoverage {
                detail: "an evaluation split needs at least one part".to_owned(),
            });
        }
        let mut covered = Vec::new();
        for (position, part) in self.parts.iter().enumerate() {
            if part.index != position as u32 {
                return Err(EvidenceValidationError::SplitCoverage {
                    detail: format!("split part order is invalid at index {position}"),
                });
            }
            covered.extend(part.unit_ids.iter().cloned());
        }
        CoverageReport::new(expected, &covered)?;
        Ok(())
    }
}

impl H3Record for EvaluationSplit {
    const RECORD: &'static str = "H3 evaluation split";

    fn format_version(&self) -> u32 {
        H3_FORMAT_VERSION
    }
}

/// One content-carrying evidence document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDocumentContent {
    format_version: u32,
    schema: String,
    evidence_id: EvidenceId,
    kind: EvidenceContentKind,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(skip)]
    bytes: Option<Vec<u8>>,
    truncated: bool,
    secret_excluded: bool,
}

/// Content kind of one evidence document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceContentKind {
    /// UTF-8 text.
    Text,
    /// Approved image bytes.
    Image,
}

impl EvidenceDocumentContent {
    /// Creates a text evidence document.
    pub fn text(
        evidence_id: EvidenceId,
        text: impl Into<String>,
    ) -> Result<Self, EvidenceValidationError> {
        let text = text.into();
        if text.is_empty() {
            return Err(EvidenceValidationError::InvalidValue {
                field: "evidenceContent.text".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            schema: H3_EVIDENCE_CONTENT_SCHEMA.to_owned(),
            evidence_id,
            kind: EvidenceContentKind::Text,
            text: Some(text),
            media_type: None,
            bytes: None,
            truncated: false,
            secret_excluded: false,
        })
    }

    /// Creates an image evidence document.
    pub fn image(
        evidence_id: EvidenceId,
        media_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, EvidenceValidationError> {
        let media_type = non_empty("evidenceContent.mediaType", media_type.into())?;
        if !matches!(media_type.as_str(), "image/png" | "image/jpeg") {
            return Err(EvidenceValidationError::InvalidValue {
                field: "evidenceContent.mediaType".to_owned(),
                detail: "only PNG or JPEG image evidence is accepted".to_owned(),
            });
        }
        if bytes.is_empty() {
            return Err(EvidenceValidationError::ImageUnavailable {
                reason: "image bytes are empty".to_owned(),
            });
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            schema: H3_EVIDENCE_CONTENT_SCHEMA.to_owned(),
            evidence_id,
            kind: EvidenceContentKind::Image,
            text: None,
            media_type: Some(media_type),
            bytes: Some(bytes),
            truncated: false,
            secret_excluded: false,
        })
    }

    /// Marks the document as truncated. A truncated document is insufficient.
    #[must_use]
    pub fn truncated(mut self) -> Self {
        self.truncated = true;
        self
    }

    /// Marks the document as having excluded secret content. Such a document
    /// is insufficient, never met.
    #[must_use]
    pub fn secret_excluded(mut self) -> Self {
        self.secret_excluded = true;
        self
    }

    /// Evidence identifier.
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    /// Content kind.
    pub const fn kind(&self) -> EvidenceContentKind {
        self.kind
    }

    /// Text payload.
    pub fn text_payload(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Image media type.
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    /// Image bytes.
    pub fn image_bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }

    /// Whether the document was truncated.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether secret content was excluded.
    pub const fn has_secret_exclusion(&self) -> bool {
        self.secret_excluded
    }
}

impl H3Record for EvidenceDocumentContent {
    const RECORD: &'static str = "H3 evidence content";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Host-owned content source used by the Html assessment port.
pub trait EvidenceContentSource: Send + Sync {
    /// Returns one exact content document.
    fn document(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceDocumentContent>, SupervisionError>;
}

/// In-memory content store shared between the H3 adapter and the H2 port.
#[derive(Debug, Clone, Default)]
pub struct EvidenceContentStore {
    documents: Arc<Mutex<BTreeMap<EvidenceId, EvidenceDocumentContent>>>,
}

impl EvidenceContentStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces one document. Replacing with different content is a
    /// conflict; the same content is idempotent.
    pub fn insert(&self, document: EvidenceDocumentContent) -> Result<(), EvidenceValidationError> {
        let project = document.evidence_id.project_id();
        let mut documents = self
            .documents
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = documents.get(&document.evidence_id)
            && existing != &document
        {
            return Err(EvidenceValidationError::InvalidValue {
                field: "evidenceContent".to_owned(),
                detail: format!(
                    "evidence {} already has different content",
                    document.evidence_id
                ),
            });
        }
        let _ = project;
        documents.insert(document.evidence_id, document);
        Ok(())
    }

    /// Returns one document.
    pub fn get(&self, evidence_id: EvidenceId) -> Option<EvidenceDocumentContent> {
        self.documents
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&evidence_id)
            .cloned()
    }

    /// Number of stored documents.
    pub fn len(&self) -> usize {
        self.documents
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether no document is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every stored document in evidence-id order.
    pub fn documents(&self) -> Vec<EvidenceDocumentContent> {
        self.documents
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Adds every document from a rehydrated store.
    pub fn merge(&self, documents: &Self) -> Result<(), EvidenceValidationError> {
        for document in documents.documents() {
            self.insert(document)?;
        }
        Ok(())
    }

    /// Persists the exact content documents as one versioned JSON file.
    ///
    /// This is the minimum durable surface for H3 evidence content: the H2
    /// metadata record lives in SQLite, while the full text/image bytes are
    /// stored here inside the private application area. Image bytes are hex
    /// encoded because the transport model never serializes them directly.
    pub fn save(&self, path: &std::path::Path) -> Result<(), EvidenceValidationError> {
        let wire = PersistedEvidenceContent {
            format_version: H3_FORMAT_VERSION,
            schema: H3_EVIDENCE_CONTENT_SCHEMA.to_owned(),
            documents: self
                .documents()
                .into_iter()
                .map(PersistedDocument::from_document)
                .collect(),
        };
        let bytes =
            serde_json::to_vec(&wire).map_err(|error| EvidenceValidationError::Storage {
                detail: format!("evidence content could not be encoded: {error}"),
            })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| EvidenceValidationError::Storage {
                detail: format!("evidence content directory: {error}"),
            })?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes).map_err(|error| EvidenceValidationError::Storage {
            detail: format!("evidence content could not be written: {error}"),
        })?;
        std::fs::rename(&temporary, path).map_err(|error| EvidenceValidationError::Storage {
            detail: format!("evidence content could not be committed: {error}"),
        })?;
        Ok(())
    }

    /// Loads one previously persisted content file. A missing file is an empty
    /// store; a corrupt or unsupported file is an explicit error.
    pub fn load(path: &std::path::Path) -> Result<Self, EvidenceValidationError> {
        let store = Self::new();
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(error) => {
                return Err(EvidenceValidationError::Storage {
                    detail: format!("evidence content could not be read: {error}"),
                });
            }
        };
        let wire: PersistedEvidenceContent =
            serde_json::from_slice(&bytes).map_err(|error| EvidenceValidationError::Storage {
                detail: format!("evidence content could not be decoded: {error}"),
            })?;
        if wire.format_version != H3_FORMAT_VERSION || wire.schema != H3_EVIDENCE_CONTENT_SCHEMA {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: format!("{}/{}", wire.format_version, wire.schema),
            });
        }
        for document in wire.documents {
            store.insert(document.into_document()?)?;
        }
        Ok(store)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedEvidenceContent {
    format_version: u32,
    schema: String,
    documents: Vec<PersistedDocument>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedDocument {
    evidence_id: EvidenceId,
    kind: EvidenceContentKind,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    bytes_hex: Option<String>,
    truncated: bool,
    secret_excluded: bool,
}

impl PersistedDocument {
    fn from_document(document: EvidenceDocumentContent) -> Self {
        Self {
            evidence_id: document.evidence_id,
            kind: document.kind,
            text: document.text,
            media_type: document.media_type,
            bytes_hex: document.bytes.map(|bytes| encode_hex(&bytes)),
            truncated: document.truncated,
            secret_excluded: document.secret_excluded,
        }
    }

    fn into_document(self) -> Result<EvidenceDocumentContent, EvidenceValidationError> {
        let bytes = match self.bytes_hex {
            Some(hex) => Some(decode_hex(&hex)?),
            None => None,
        };
        Ok(EvidenceDocumentContent {
            format_version: H3_FORMAT_VERSION,
            schema: H3_EVIDENCE_CONTENT_SCHEMA.to_owned(),
            evidence_id: self.evidence_id,
            kind: self.kind,
            text: self.text,
            media_type: self.media_type,
            bytes,
            truncated: self.truncated,
            secret_excluded: self.secret_excluded,
        })
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, EvidenceValidationError> {
    if hex.len() % 2 != 0 {
        return Err(EvidenceValidationError::InvalidValue {
            field: "evidenceContent.bytesHex".to_owned(),
            detail: "odd-length hex payload".to_owned(),
        });
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    let digit = |value: u8| -> Result<u8, EvidenceValidationError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(EvidenceValidationError::InvalidValue {
                field: "evidenceContent.bytesHex".to_owned(),
                detail: "invalid hex digit".to_owned(),
            }),
        }
    };
    for pair in raw.chunks(2) {
        bytes.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    Ok(bytes)
}

impl EvidenceContentSource for EvidenceContentStore {
    fn document(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceDocumentContent>, SupervisionError> {
        if evidence_id.project_id() != project_id {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidenceContent.evidenceId".to_owned(),
                detail: "evidence content belongs to another project".to_owned(),
            });
        }
        Ok(self.get(evidence_id))
    }
}

/// The complete versioned evidence pack for one candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidencePack {
    format_version: u32,
    schema: String,
    project_id: ProjectId,
    document: DocumentKey,
    generation: GenerationId,
    cycle: CycleId,
    conditions: ConditionBinding,
    condition_version: ConditionVersion,
    condition_digest: ConditionDigest,
    target_version: TargetVersion,
    source: SourceSnapshot,
    candidate_digest: ContentDigest,
    provenance_digest: ContentDigest,
    fingerprints: EvidenceFingerprints,
    checks: CheckSet,
    information: Vec<UnitEvidence>,
    visible_targets: BTreeMap<String, String>,
    strict: Vec<StrictEvidence>,
    support: SupportEvidence,
    usability: UsabilityEvidence,
    render: RenderEvidence,
    coverage: CoverageReport,
    consistency: ConditionEvidenceSummary,
    created_at: Timestamp,
}

/// One condition evidence summary used by the whole-document assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionEvidenceSummary {
    conditions: Vec<ConditionEvidenceRef>,
    unit_ids: Vec<String>,
    visible_text_digest: ContentDigest,
}

/// One condition's evidence references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionEvidenceRef {
    condition: H3Condition,
    unit_ids: Vec<String>,
    parts: u32,
}

impl ConditionEvidenceSummary {
    /// Condition references.
    pub fn conditions(&self) -> &[ConditionEvidenceRef] {
        &self.conditions
    }

    /// Every unit id.
    pub fn unit_ids(&self) -> &[String] {
        &self.unit_ids
    }

    /// Digest of the candidate visible text.
    pub const fn visible_text_digest(&self) -> &ContentDigest {
        &self.visible_text_digest
    }
}

/// Inputs for building one evidence pack.
pub struct EvidenceBuildInput<'a> {
    /// Document key.
    pub document: DocumentKey,
    /// Generation id.
    pub generation: GenerationId,
    /// Sync cycle id.
    pub cycle: CycleId,
    /// Four H2 condition identities.
    pub conditions: ConditionBinding,
    /// Condition version.
    pub condition_version: ConditionVersion,
    /// Condition digest.
    pub condition_digest: ConditionDigest,
    /// Target version.
    pub target_version: TargetVersion,
    /// Exact source snapshot.
    pub source: SourceSnapshot,
    /// Exact source bytes.
    pub source_bytes: &'a [u8],
    /// Exact candidate HTML.
    pub candidate_html: &'a str,
    /// Exact candidate digest.
    pub candidate_digest: ContentDigest,
    /// Exact provenance digest.
    pub provenance_digest: ContentDigest,
    /// Exact pack `source-units` result.
    pub source_units: &'a SourceUnits,
    /// Mandatory checks.
    pub checks: CheckSet,
    /// Render evidence.
    pub render: RenderEvidence,
    /// Exact fingerprints.
    pub fingerprints: EvidenceFingerprints,
    /// Build time.
    pub created_at: Timestamp,
}

impl EvidencePack {
    /// Builds the evidence pack from parsed policy/render evidence. The common
    /// structural check must be present; a failed check is retained as failed,
    /// never repaired.
    pub fn build(input: EvidenceBuildInput<'_>) -> Result<Self, EvidenceValidationError> {
        let source_units = input.source_units;
        source_units.validate_against(input.document.target_path(), input.source_bytes)?;
        let provenance = Provenance::from_html(input.candidate_html)?;
        if provenance.contract != "semantic-v1" {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: provenance.contract.clone(),
            });
        }
        if provenance.source_path != input.document.target_path()
            || provenance.source_digest != *input.source.digest()
        {
            return Err(EvidenceValidationError::SourceDigestMismatch);
        }
        let candidate_digest = ContentDigest::sha256(input.candidate_html.as_bytes());
        if candidate_digest != input.candidate_digest {
            return Err(EvidenceValidationError::InvalidValue {
                field: "candidateDigest".to_owned(),
                detail: "candidate bytes changed while building evidence".to_owned(),
            });
        }
        if input.fingerprints.candidate() != &candidate_digest
            || input.fingerprints.source() != input.source.digest()
            || input.fingerprints.provenance() != &input.provenance_digest
            || input.fingerprints.condition_version() != input.condition_version
            || input.fingerprints.condition_digest() != &input.condition_digest
            || input.fingerprints.target_version() != input.target_version
        {
            return Err(EvidenceValidationError::StaleEvidence {
                stage: "evidence-build",
            });
        }
        let scanned = ScannedHtml::scan(input.candidate_html);
        let visible_text_digest = ContentDigest::sha256(scanned.visible_text().as_bytes());

        // Declared unit definitions must be exactly the fresh scan.
        let fresh: BTreeMap<&str, &SourceUnitDefinition> = source_units
            .units()
            .iter()
            .map(|unit| (unit.id(), unit))
            .collect();
        let mut declared = BTreeSet::new();
        for unit in provenance.units() {
            if !declared.insert(unit.id.clone()) {
                return Err(EvidenceValidationError::UnitDuplicate {
                    unit: unit.id.clone(),
                });
            }
            let Some(expected) = fresh.get(unit.id.as_str()) else {
                return Err(EvidenceValidationError::UnitExtraneous {
                    unit: unit.id.clone(),
                });
            };
            if unit.kind != expected.kind {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "kind",
                });
            }
            if unit.source_digest != expected.source_digest {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "sourceDigest",
                });
            }
            if unit.start != expected.start || unit.end != expected.end {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "range",
                });
            }
            if unit.parent != expected.parent {
                return Err(EvidenceValidationError::UnitMismatch {
                    unit: unit.id.clone(),
                    field: "parent",
                });
            }
        }
        for unit in source_units.units() {
            if !declared.contains(unit.id()) {
                return Err(EvidenceValidationError::UnitMissing {
                    unit: unit.id().to_owned(),
                });
            }
        }

        // Every unit must map to at least one visible target.
        let mut mappings: BTreeMap<&str, Vec<&ProvenanceMapping>> = BTreeMap::new();
        for mapping in provenance.mappings() {
            if mapping.targets.is_empty() {
                return Err(EvidenceValidationError::InvalidValue {
                    field: "provenance.mappings.targets".to_owned(),
                    detail: format!("unit {:?} has no targets", mapping.unit),
                });
            }
            if !fresh.contains_key(mapping.unit.as_str()) {
                return Err(EvidenceValidationError::UnitExtraneous {
                    unit: mapping.unit.clone(),
                });
            }
            for target in &mapping.targets {
                if scanned.hidden_targets().contains(target) && scanned.target(target).is_none() {
                    return Err(EvidenceValidationError::TargetHidden {
                        unit: mapping.unit.clone(),
                        target: target.clone(),
                    });
                }
                if scanned.target(target).is_none() {
                    return Err(EvidenceValidationError::TargetMissing {
                        unit: mapping.unit.clone(),
                        target: target.clone(),
                    });
                }
            }
            mappings
                .entry(mapping.unit.as_str())
                .or_default()
                .push(mapping);
        }
        let mut covered = Vec::new();
        let mut information = Vec::with_capacity(source_units.units().len());
        for unit in source_units.units() {
            let Some(entries) = mappings.get(unit.id()) else {
                return Err(EvidenceValidationError::UnitMissing {
                    unit: unit.id().to_owned(),
                });
            };
            let mut targets = BTreeSet::new();
            for entry in entries {
                for target in &entry.targets {
                    targets.insert(target.clone());
                }
            }
            let targets = targets.into_iter().collect::<Vec<_>>();
            let mut representations = entries
                .iter()
                .map(|entry| entry.representation.clone())
                .collect::<Vec<_>>();
            representations.sort();
            representations.dedup();
            covered.push(unit.id().to_owned());
            information.push(UnitEvidence {
                unit_id: unit.id().to_owned(),
                kind: unit.kind().to_owned(),
                source_digest: unit.source_digest().clone(),
                start: unit.start(),
                end: unit.end(),
                parent: unit.parent().map(str::to_owned),
                text: unit.text().to_owned(),
                related_context: related_context(unit, source_units.units()),
                representations,
                targets,
            });
        }
        let expected = source_units
            .units()
            .iter()
            .map(|unit| unit.id().to_owned())
            .collect::<Vec<_>>();
        let coverage = CoverageReport::new(&expected, &covered)?;

        // Strict values must survive visibly.
        let mut strict = Vec::new();
        for requirement in source_units
            .strict()
            .iter()
            .map(|requirement| {
                (
                    requirement.unit.clone(),
                    requirement.category.clone(),
                    requirement.value.clone(),
                    None,
                )
            })
            .chain(provenance.strict().iter().map(|requirement| {
                (
                    requirement.unit.clone(),
                    requirement.category.clone(),
                    requirement.value.clone(),
                    Some(requirement.targets.clone()),
                )
            }))
        {
            let (unit, category, value, declared_targets) = requirement;
            let targets = match declared_targets {
                Some(targets) if !targets.is_empty() => targets,
                _ => mappings
                    .get(unit.as_str())
                    .map(|entries| {
                        entries
                            .iter()
                            .flat_map(|entry| entry.targets.iter().cloned())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            };
            if targets.is_empty() {
                return Err(EvidenceValidationError::TargetMissing {
                    unit: unit.clone(),
                    target: "<mapping>".to_owned(),
                });
            }
            let mut preserved = true;
            for target in &targets {
                let Some(html) = scanned.target(target) else {
                    return Err(EvidenceValidationError::TargetMissing {
                        unit: unit.clone(),
                        target: target.clone(),
                    });
                };
                if !visible_value_present(html, &value) {
                    preserved = false;
                }
            }
            if !preserved {
                return Err(EvidenceValidationError::StrictValueMissing { unit, category });
            }
            strict.push(StrictEvidence {
                unit,
                category,
                value,
                targets,
                preserved,
            });
        }

        // Supplementary roots and diagram/graph structure.
        let mut supplementary = Vec::new();
        for entry in provenance.supplementary() {
            for root in &entry.units {
                if !fresh.contains_key(root.as_str()) {
                    return Err(EvidenceValidationError::SupplementaryRootMissing {
                        entry: entry.id.clone(),
                        unit: root.clone(),
                    });
                }
            }
            for target in &entry.targets {
                if scanned.target(target).is_none() {
                    return Err(EvidenceValidationError::TargetMissing {
                        unit: entry.id.clone(),
                        target: target.clone(),
                    });
                }
            }
            let (diagram_nodes, diagram_edges) = entry
                .diagram
                .as_ref()
                .map(|diagram| {
                    (
                        diagram
                            .get("nodes")
                            .and_then(Value::as_array)
                            .map(|nodes| nodes.len() as u32)
                            .unwrap_or(0),
                        diagram
                            .get("edges")
                            .and_then(Value::as_array)
                            .map(|edges| edges.len() as u32)
                            .unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));
            let graph = entry.graph.as_ref();
            let graph_series = graph
                .and_then(|graph| graph.get("series"))
                .and_then(Value::as_array)
                .map(|series| series.len() as u32)
                .unwrap_or(0);
            let graph_values = graph
                .and_then(|graph| graph.get("series"))
                .and_then(Value::as_array)
                .map(|series| {
                    series
                        .iter()
                        .map(|item| {
                            item.get("values")
                                .and_then(Value::as_array)
                                .map(|values| values.len() as u32)
                                .unwrap_or(0)
                        })
                        .sum()
                })
                .unwrap_or(0);
            let visible = entry
                .targets
                .iter()
                .filter_map(|target| scanned.target(target))
                .collect::<Vec<_>>()
                .join("\n");
            let caption_present =
                visible.to_ascii_lowercase().contains("<figcaption") || entry.description.is_some();
            let data_table_present = visible.to_ascii_lowercase().contains("<table");
            let text_equivalent_present = visible_text(&visible).chars().count() >= 20;
            let color_only = (visible.contains("stroke=") || visible.contains("fill="))
                && visible_text(&visible).trim().is_empty();
            supplementary.push(SupplementaryEvidence {
                id: entry.id.clone(),
                kind: entry.kind.clone(),
                description: entry.description.clone(),
                roots: entry.units.clone(),
                targets: entry.targets.clone(),
                supported: !entry.units.is_empty() && !entry.targets.is_empty(),
                diagram_nodes,
                diagram_edges,
                graph_series,
                graph_values,
                caption_present,
                text_equivalent_present,
                data_table_present,
                color_only,
            });
        }
        let support = SupportEvidence {
            supplementary,
            calculation_count: provenance.calculations().len() as u32,
        };

        // Whole-document usability facts combine static structure with render.
        if input.render.origin().is_native_render() {
            input.render.validate_native()?;
        }
        let primary_dom = input.render.primary().map(RenderConfigurationEvidence::dom);
        let primary_headings = primary_dom
            .and_then(|dom| dom.get("outline"))
            .and_then(|outline| outline.get("headings"))
            .and_then(Value::as_array)
            .map(|headings| {
                headings
                    .iter()
                    .map(|heading| HeadingFact {
                        level: heading.get("level").and_then(Value::as_u64).unwrap_or(0) as u8,
                        text: heading
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        id: heading
                            .get("selector")
                            .and_then(Value::as_str)
                            .and_then(|selector| selector.strip_prefix('#'))
                            .map(str::to_owned),
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|headings| !headings.is_empty())
            .unwrap_or_else(|| scanned.headings().to_vec());
        let landmarks = primary_dom
            .and_then(|dom| dom.get("outline"))
            .and_then(|outline| outline.get("landmarks"))
            .and_then(Value::as_array)
            .map(|landmarks| {
                landmarks
                    .iter()
                    .map(|landmark| {
                        let tag = landmark
                            .get("tag")
                            .and_then(Value::as_str)
                            .unwrap_or("landmark");
                        let name = landmark.get("name").and_then(Value::as_str).unwrap_or("");
                        if name.is_empty() {
                            tag.to_owned()
                        } else {
                            format!("{tag}: {name}")
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|landmarks| !landmarks.is_empty())
            .unwrap_or_else(|| scanned.landmarks().to_vec());
        let focus_order = primary_dom
            .and_then(|dom| dom.get("keyboard"))
            .and_then(|keyboard| keyboard.get("tabOrder"))
            .and_then(Value::as_array)
            .map(|order| {
                order
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|order| !order.is_empty())
            .unwrap_or_else(|| scanned.focus_order().to_vec());
        let reading_order = primary_dom
            .and_then(|dom| dom.get("blocks"))
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|block| block.get("selector").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|blocks| !blocks.is_empty())
            .unwrap_or_else(|| scanned.block_order().to_vec());
        let reading_order_matches_visual =
            reading_order_matches_visual(primary_dom, &reading_order);
        let outline_valid = outline_valid(&primary_headings);
        let keyboard_reachable = !focus_order.is_empty();
        let signals = input.render.signals();
        let usability = UsabilityEvidence {
            headings: primary_headings,
            landmarks,
            navigation_targets: scanned.navigation_targets().to_vec(),
            reading_order,
            focus_order,
            outline_valid,
            reading_order_matches_visual,
            page_horizontal_overflow: signals.page_horizontal_overflow(),
            overlapping_blocks: signals.overlapping_blocks(),
            readability_failures: signals.readability_failures(),
            small_text_elements: signals.small_text_elements(),
            contrast_failures: signals.contrast_failures(),
            failed_images: signals.failed_images(),
            keyboard_reachable,
        };

        let visible_targets = scanned
            .targets()
            .iter()
            .map(|(id, html)| (id.clone(), html.clone()))
            .collect::<BTreeMap<_, _>>();
        let condition_refs = H3Condition::ALL
            .into_iter()
            .map(|condition| ConditionEvidenceRef {
                condition,
                unit_ids: if condition == H3Condition::Information {
                    expected.clone()
                } else {
                    Vec::new()
                },
                parts: 1,
            })
            .collect::<Vec<_>>();
        let consistency = ConditionEvidenceSummary {
            conditions: condition_refs,
            unit_ids: expected,
            visible_text_digest,
        };

        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            schema: H3_EVIDENCE_SCHEMA.to_owned(),
            project_id: input.document.project_id(),
            document: input.document,
            generation: input.generation,
            cycle: input.cycle,
            conditions: input.conditions,
            condition_version: input.condition_version,
            condition_digest: input.condition_digest,
            target_version: input.target_version,
            source: input.source,
            candidate_digest: input.candidate_digest,
            provenance_digest: input.provenance_digest,
            fingerprints: input.fingerprints,
            checks: input.checks,
            information,
            visible_targets,
            strict,
            support,
            usability,
            render: input.render,
            coverage,
            consistency,
            created_at: input.created_at,
        })
    }

    /// Format version.
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Evidence schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document key.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Generation id.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Cycle id.
    pub const fn cycle(&self) -> CycleId {
        self.cycle
    }

    /// Four condition identities.
    pub const fn conditions(&self) -> &ConditionBinding {
        &self.conditions
    }

    /// Condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Condition digest.
    pub const fn condition_digest(&self) -> &ConditionDigest {
        &self.condition_digest
    }

    /// Target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Exact source snapshot.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Exact candidate digest.
    pub const fn candidate_digest(&self) -> &ContentDigest {
        &self.candidate_digest
    }

    /// Exact provenance digest.
    pub const fn provenance_digest(&self) -> &ContentDigest {
        &self.provenance_digest
    }

    /// Exact fingerprint binding.
    pub const fn fingerprints(&self) -> &EvidenceFingerprints {
        &self.fingerprints
    }

    /// Mandatory checks.
    pub const fn checks(&self) -> &CheckSet {
        &self.checks
    }

    /// Per-unit information evidence.
    pub fn information(&self) -> &[UnitEvidence] {
        &self.information
    }

    /// Visible target HTML.
    pub fn visible_targets(&self) -> &BTreeMap<String, String> {
        &self.visible_targets
    }

    /// Strict preservation evidence.
    pub fn strict(&self) -> &[StrictEvidence] {
        &self.strict
    }

    /// Supplementary evidence.
    pub const fn support(&self) -> &SupportEvidence {
        &self.support
    }

    /// Whole-document usability evidence.
    pub const fn usability(&self) -> &UsabilityEvidence {
        &self.usability
    }

    /// Render evidence.
    pub const fn render(&self) -> &RenderEvidence {
        &self.render
    }

    /// Exact-once coverage.
    pub const fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }

    /// Whole-document consistency evidence.
    pub const fn consistency(&self) -> &ConditionEvidenceSummary {
        &self.consistency
    }

    /// Build time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Revalidate the pack's internal invariants.
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if self.schema != H3_EVIDENCE_SCHEMA {
            return Err(EvidenceValidationError::UnsupportedSchema {
                found: self.schema.clone(),
            });
        }
        if !self.coverage.is_complete() {
            return Err(EvidenceValidationError::SplitCoverage {
                detail: "stored coverage is incomplete".to_owned(),
            });
        }
        let covered = self
            .information
            .iter()
            .map(|unit| unit.unit_id().to_owned())
            .collect::<Vec<_>>();
        CoverageReport::new(self.coverage.expected_units(), &covered)?;
        if self.checks.render_pass() {
            self.render.validate_native()?;
            if self.render.candidate.html != *self.fingerprints.candidate() {
                return Err(EvidenceValidationError::RenderFingerprintMismatch { field: "html" });
            }
            if self.render.candidate.css != *self.fingerprints.css() {
                return Err(EvidenceValidationError::RenderFingerprintMismatch { field: "css" });
            }
            if self.render.candidate.resources != *self.fingerprints.resources() {
                return Err(EvidenceValidationError::RenderFingerprintMismatch {
                    field: "resources",
                });
            }
        }
        Ok(())
    }

    /// Whether the evidence can support a real completion claim.
    pub fn native_render_available(&self) -> bool {
        self.checks.render_pass()
            && self.render.origin().is_native_render()
            && self.render.complete()
    }
}

impl H3Record for EvidencePack {
    const RECORD: &'static str = "H3 evidence pack";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// One image passed to an image-required assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceImage {
    path: String,
    media_type: String,
    bytes: Vec<u8>,
}

impl EvidenceImage {
    /// Creates an approved image.
    pub fn new(path: impl Into<String>, media_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            media_type: media_type.into(),
            bytes,
        }
    }

    /// Relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Image bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One assessment slice built from the evidence pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentSlice {
    id: String,
    condition: H3Condition,
    part: Option<u32>,
    whole_document: bool,
    unit_ids: Vec<String>,
    rubric: String,
    text: String,
    images: Vec<EvidenceImage>,
    image_required: bool,
}

impl AssessmentSlice {
    /// Stable slice id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Logical condition.
    pub const fn condition(&self) -> H3Condition {
        self.condition
    }

    /// Split part, when the condition was split.
    pub const fn part(&self) -> Option<u32> {
        self.part
    }

    /// Whether this is the whole-document consistency assessment.
    pub const fn whole_document(&self) -> bool {
        self.whole_document
    }

    /// Units evaluated in this slice.
    pub fn unit_ids(&self) -> &[String] {
        &self.unit_ids
    }

    /// Exact rubric.
    pub fn rubric(&self) -> &str {
        &self.rubric
    }

    /// Exact evidence text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Approved images.
    pub fn images(&self) -> &[EvidenceImage] {
        &self.images
    }

    /// Whether the condition requires images.
    pub const fn image_required(&self) -> bool {
        self.image_required
    }
}

/// A split, image-aware assessment plan over one evidence pack.
#[derive(Debug, Clone, PartialEq)]
pub struct AssessmentPlan {
    format_version: u32,
    conditions: ConditionBinding,
    condition_version: ConditionVersion,
    condition_digest: ConditionDigest,
    target_version: TargetVersion,
    rubric_version: RubricVersion,
    rubric_digest: ContentDigest,
    profile: ProfileBinding,
    profile_inputs: ProfileInputs,
    thresholds: ProfileThresholds,
    slices: Vec<AssessmentSlice>,
    missing_images: Vec<H3Condition>,
    truncated: Vec<String>,
    coverage: CoverageReport,
    checks: CheckSet,
    fingerprints: EvidenceFingerprints,
    render_origin: EvidenceOrigin,
}

impl AssessmentPlan {
    /// Builds a bounded assessment plan. A slice that cannot fit the profile
    /// text budget is recorded as truncated; it is never shortened silently.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        pack: &EvidencePack,
        rubrics: &RubricSet,
        profile: ProfileBinding,
        profile_inputs: ProfileInputs,
        thresholds: ProfileThresholds,
        max_units_per_part: usize,
        max_text_bytes: usize,
    ) -> Result<Self, EvidenceValidationError> {
        pack.validate()?;
        let expected = pack
            .coverage
            .expected_units()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let split = EvaluationSplit::contiguous(&expected, max_units_per_part.max(1))?;
        let mut slices = Vec::new();
        let mut truncated = Vec::new();
        let mut missing_images = Vec::new();
        let pack_images = pack.render.images();
        let image_ok = profile_inputs.supports_image() && !pack_images.is_empty();

        for part in split.parts() {
            let units = part
                .unit_ids()
                .iter()
                .filter_map(|id| pack.information.iter().find(|unit| unit.unit_id() == id))
                .collect::<Vec<_>>();
            let text = format_information_slice(&units, &pack.visible_targets);
            check_text_budget(
                &format!("information:{}", part.index()),
                &text,
                max_text_bytes,
            )?;
            slices.push(AssessmentSlice {
                id: format!("information:{}", part.index()),
                condition: H3Condition::Information,
                part: Some(part.index()),
                whole_document: false,
                unit_ids: part.unit_ids().to_vec(),
                rubric: rubrics
                    .condition(H3Condition::Information)
                    .expect("information rubric")
                    .rubric()
                    .to_owned(),
                text,
                images: Vec::new(),
                image_required: false,
            });
        }

        for condition in [
            H3Condition::Support,
            H3Condition::Usability,
            H3Condition::Render,
        ] {
            let rubric = rubrics
                .condition(condition)
                .expect("approved rubric has every condition");
            let text = match condition {
                H3Condition::Support => format_support_slice(&pack.support, pack),
                H3Condition::Usability => format_usability_slice(&pack.usability),
                H3Condition::Render => format_render_slice(&pack.render),
                H3Condition::Information => unreachable!(),
            };
            if text.len() > max_text_bytes {
                truncated.push(format!("{condition}:0"));
            }
            let image_required = rubric.image_required();
            if image_required && !image_ok {
                missing_images.push(condition);
            }
            slices.push(AssessmentSlice {
                id: format!("{condition}:0"),
                condition,
                part: Some(0),
                whole_document: false,
                unit_ids: expected.clone(),
                rubric: rubric.rubric().to_owned(),
                text,
                images: if image_required && image_ok {
                    pack_images.clone()
                } else {
                    Vec::new()
                },
                image_required,
            });
        }

        let consistency_text = format_consistency_slice(pack);
        if consistency_text.len() > max_text_bytes {
            truncated.push("consistency".to_owned());
        }
        let consistency_rubric = rubrics.document_consistency().to_owned();
        slices.push(AssessmentSlice {
            id: "consistency".to_owned(),
            condition: H3Condition::Information,
            part: None,
            whole_document: true,
            unit_ids: expected.clone(),
            rubric: consistency_rubric,
            text: consistency_text,
            images: if profile_inputs.supports_image() {
                pack_images
            } else {
                Vec::new()
            },
            image_required: false,
        });

        let rubric_digest = rubrics.digest();
        if rubric_digest != *pack.fingerprints.rubric() {
            return Err(EvidenceValidationError::StaleEvidence { stage: "rubric" });
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            conditions: pack.conditions.clone(),
            condition_version: pack.condition_version,
            condition_digest: pack.condition_digest.clone(),
            target_version: pack.target_version,
            rubric_version: RubricVersion::new(H3_RUBRIC_VERSION)
                .map_err(|error| invalid("rubricVersion", error.to_string()))?,
            rubric_digest,
            profile,
            profile_inputs,
            thresholds,
            slices,
            missing_images,
            truncated,
            coverage: pack.coverage.clone(),
            checks: pack.checks.clone(),
            fingerprints: pack.fingerprints.clone(),
            render_origin: pack.render.origin(),
        })
    }

    /// Slices in fixed order.
    pub fn slices(&self) -> &[AssessmentSlice] {
        &self.slices
    }

    /// Fixed profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Required profile inputs.
    pub const fn profile_inputs(&self) -> ProfileInputs {
        self.profile_inputs
    }

    /// Adoption thresholds.
    pub const fn thresholds(&self) -> ProfileThresholds {
        self.thresholds
    }

    /// Conditions whose images are missing.
    pub fn missing_images(&self) -> &[H3Condition] {
        &self.missing_images
    }

    /// Slices whose text exceeded the limit.
    pub fn truncated(&self) -> &[String] {
        &self.truncated
    }

    /// Exact coverage.
    pub const fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }

    /// Mandatory checks.
    pub const fn checks(&self) -> &CheckSet {
        &self.checks
    }

    /// Exact fingerprints.
    pub const fn fingerprints(&self) -> &EvidenceFingerprints {
        &self.fingerprints
    }

    /// Render origin.
    pub const fn render_origin(&self) -> EvidenceOrigin {
        self.render_origin
    }

    /// Whether a slice can be sent. Image-required conditions without images
    /// and truncated slices are not sent; they are recorded as insufficient.
    pub fn slice_is_sendable(&self, slice: &AssessmentSlice) -> bool {
        if self.truncated.iter().any(|id| id == slice.id()) {
            return false;
        }
        if slice.image_required() && !slice.images().is_empty() {
            return true;
        }
        if slice.image_required() {
            return false;
        }
        true
    }

    /// Every slice id that must have a recorded result.
    pub fn required_slice_ids(&self) -> Vec<String> {
        self.slices
            .iter()
            .map(|slice| slice.id().to_owned())
            .collect()
    }
}

/// One assessment result for one slice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SliceAssessment {
    slice_id: String,
    condition: H3Condition,
    part: Option<u32>,
    whole_document: bool,
    unit_ids: Vec<String>,
    request_id: DecisionId,
    evidence_ids: Vec<EvidenceId>,
    verdict: ConditionVerdict,
    adopted: bool,
    #[serde(default)]
    probability: Option<f64>,
    profile: ProfileBinding,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    rubric_version: RubricVersion,
    verifier: String,
    operation: String,
    result: String,
    rationale: String,
    scope: EvidenceScope,
    decided_at: Timestamp,
}

impl SliceAssessment {
    /// Builds a slice result from the H2 assessment result. The result must
    /// apply to the exact request, purpose, evidence, and versions.
    pub fn from_result(
        slice: &AssessmentSlice,
        request: &AssessmentRequest,
        result: &AssessmentResult,
        thresholds: ProfileThresholds,
        scope: EvidenceScope,
    ) -> Result<Self, EvidenceValidationError> {
        if request.condition_id() != result.condition_id()
            || request.condition_version() != result.condition_version()
            || request.target_version() != result.target_version()
            || request.profile() != result.profile()
            || request.rubric_version() != result.provenance().rubric_version()
        {
            return Err(EvidenceValidationError::AssessmentMismatch {
                detail: "the assessment result does not apply to the request".to_owned(),
            });
        }
        if result.purpose() != herness_supervision::ProfilePurpose::Html {
            return Err(EvidenceValidationError::AssessmentMismatch {
                detail: "the assessment result does not carry the Html purpose".to_owned(),
            });
        }
        if result.evidence().is_empty() {
            return Err(EvidenceValidationError::AssessmentMismatch {
                detail: "the assessment result cites no evidence".to_owned(),
            });
        }
        for evidence in result.evidence() {
            if !request.evidence().contains(evidence) {
                return Err(EvidenceValidationError::AssessmentMismatch {
                    detail: "the assessment result cites evidence outside the request".to_owned(),
                });
            }
        }
        let adopted = result.adopted_verdict(thresholds);
        let probability = match result.outcome() {
            AssessmentOutcome::Decision {
                selected,
                probabilities,
                ..
            } => Some(probabilities.probability(*selected)),
            AssessmentOutcome::NormalLlm { .. } => None,
        };
        let verdict = result.reported_verdict();
        let adopted_verdict = adopted.unwrap_or(ConditionVerdict::Insufficient);
        let provenance = result.provenance();
        let verifier = format!(
            "{}:{}",
            provenance.provider_kind().as_str(),
            provenance.model().as_str()
        );
        let operation = format!(
            "Html condition {} / {} slice {} / rubric {} / evidence {}",
            slice.condition(),
            if slice.whole_document() {
                "whole-document consistency"
            } else {
                "per-condition"
            },
            slice.id(),
            result.provenance().rubric_version().as_str(),
            request.evidence().len()
        );
        Ok(Self {
            slice_id: slice.id().to_owned(),
            condition: slice.condition(),
            part: slice.part(),
            whole_document: slice.whole_document(),
            unit_ids: slice.unit_ids().to_vec(),
            request_id: request.id(),
            evidence_ids: request.evidence().to_vec(),
            verdict: adopted_verdict,
            adopted: adopted.is_some(),
            probability,
            profile: result.profile(),
            condition_version: result.condition_version(),
            target_version: result.target_version(),
            rubric_version: result.provenance().rubric_version().clone(),
            verifier,
            operation,
            result: format!(
                "{} (reported {}, adopted {})",
                adopted_verdict.as_str(),
                verdict.as_str(),
                adopted.is_some()
            ),
            rationale: result.rationale().to_owned(),
            scope,
            decided_at: result.decided_at(),
        })
    }

    /// Slice id.
    pub fn slice_id(&self) -> &str {
        &self.slice_id
    }

    /// Conditional condition.
    pub const fn condition(&self) -> H3Condition {
        self.condition
    }

    /// Split part.
    pub const fn part(&self) -> Option<u32> {
        self.part
    }

    /// Whole-document consistency result.
    pub const fn whole_document(&self) -> bool {
        self.whole_document
    }

    /// Units covered by this slice.
    pub fn unit_ids(&self) -> &[String] {
        &self.unit_ids
    }

    /// Request identifier.
    pub const fn request_id(&self) -> DecisionId {
        self.request_id
    }

    /// Evidence identifiers.
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }

    /// Adopted verdict.
    pub const fn verdict(&self) -> ConditionVerdict {
        self.verdict
    }

    /// Whether the provider verdict was adopted under the H2 threshold.
    pub const fn adopted(&self) -> bool {
        self.adopted
    }

    /// Selected probability, when the provider reports one.
    pub const fn probability(&self) -> Option<f64> {
        self.probability
    }

    /// Fixed profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Verifier label.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Exact operation recorded.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Actual result description.
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Model rationale.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Evidence scope.
    pub const fn scope(&self) -> &EvidenceScope {
        &self.scope
    }

    /// Decision time.
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }

    /// Whether this slice supports completion.
    pub const fn is_met(&self) -> bool {
        self.adopted && matches!(self.verdict, ConditionVerdict::Met)
    }
}

/// One condition's aggregate adoption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionAdoption {
    condition: H3Condition,
    met: bool,
    parts_total: u32,
    parts_met: u32,
    evidence_ids: Vec<EvidenceId>,
}

impl ConditionAdoption {
    /// Logical condition.
    pub const fn condition(&self) -> H3Condition {
        self.condition
    }

    /// Whether every part was adopted met.
    pub const fn met(&self) -> bool {
        self.met
    }

    /// Parts expected.
    pub const fn parts_total(&self) -> u32 {
        self.parts_total
    }

    /// Parts adopted met.
    pub const fn parts_met(&self) -> u32 {
        self.parts_met
    }

    /// Evidence cited by all parts.
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// Final disposition of an applied evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationDisposition {
    state: EvaluationDispositionState,
    fixable_conditions: Vec<H3Condition>,
    waiting_human_reasons: Vec<String>,
    stale_stage: Option<String>,
}

/// Disposition states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationDispositionState {
    /// Every condition, check, and binding is current.
    CompletionReady,
    /// Fixable unmet conditions can go back to the same child.
    FixableUnmet,
    /// A human must resolve an image, consent, truncation, or stale input.
    WaitingHuman,
}

impl EvaluationDisposition {
    /// Disposition state.
    pub const fn state(&self) -> EvaluationDispositionState {
        self.state
    }

    /// Conditions that may go back to the same child.
    pub fn fixable_conditions(&self) -> &[H3Condition] {
        &self.fixable_conditions
    }

    /// Reasons a human must decide.
    pub fn waiting_human_reasons(&self) -> &[String] {
        &self.waiting_human_reasons
    }

    /// Stale stage, when the disposition is stale.
    pub fn stale_stage(&self) -> Option<&str> {
        self.stale_stage.as_deref()
    }
}

/// Applied evaluation result with exact coverage, checks, and binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedEvaluation {
    format_version: u32,
    plan_checks: CheckSet,
    binding: EvaluationBinding,
    slices: Vec<SliceAssessment>,
    conditions: Vec<ConditionAdoption>,
    consistency: Option<ConditionAdoption>,
    coverage: CoverageReport,
    completion_ready: bool,
    test_only: bool,
    disposition: EvaluationDisposition,
    missing_slices: Vec<String>,
    missing_images: Vec<H3Condition>,
    truncated: Vec<String>,
    recorded_at: Timestamp,
}

impl AppliedEvaluation {
    /// Applies slice results to a plan. Missing results are explicit failures;
    /// a stale binding or fake render never becomes completion-ready.
    pub fn apply(
        plan: &AssessmentPlan,
        results: Vec<SliceAssessment>,
        binding: EvaluationBinding,
        allow_fake_render_for_tests: bool,
        recorded_at: Timestamp,
    ) -> Result<Self, EvidenceValidationError> {
        let mut by_id: BTreeMap<&str, &SliceAssessment> = BTreeMap::new();
        for result in &results {
            if by_id.insert(result.slice_id(), result).is_some() {
                return Err(EvidenceValidationError::SplitCoverage {
                    detail: format!("duplicate assessment result for {}", result.slice_id()),
                });
            }
        }
        let mut missing_slices = Vec::new();
        for slice in &plan.slices {
            if !plan.slice_is_sendable(slice) {
                continue;
            }
            if !by_id.contains_key(slice.id()) {
                missing_slices.push(slice.id().to_owned());
            }
        }
        for result in &results {
            if !plan
                .slices
                .iter()
                .any(|slice| slice.id() == result.slice_id())
            {
                return Err(EvidenceValidationError::UnitExtraneous {
                    unit: result.slice_id().to_owned(),
                });
            }
        }
        if !missing_slices.is_empty() {
            return Err(EvidenceValidationError::MissingAssessment {
                condition: H3Condition::Information,
                part: None,
            });
        }

        let stale_stage = binding.stale_stage();
        let test_only = !plan.render_origin.is_native_render() || plan.checks.render_is_fake();
        let checks_ok = plan.checks.structural_pass()
            && (plan.checks.render_pass()
                || (allow_fake_render_for_tests && plan.checks.render_present()));
        let mut condition_adoptions = Vec::new();
        for condition in H3Condition::ALL {
            if condition == H3Condition::Information {
                let parts = plan
                    .slices
                    .iter()
                    .filter(|slice| {
                        slice.condition() == H3Condition::Information && !slice.whole_document()
                    })
                    .collect::<Vec<_>>();
                let mut parts_met = 0;
                let mut evidence_ids = Vec::new();
                for part in &parts {
                    if let Some(result) = by_id.get(part.id()) {
                        if result.is_met() {
                            parts_met += 1;
                        }
                        evidence_ids.extend(result.evidence_ids.iter().copied());
                    }
                }
                condition_adoptions.push(ConditionAdoption {
                    condition,
                    met: parts_met == parts.len() as u32 && !parts.is_empty(),
                    parts_total: parts.len() as u32,
                    parts_met,
                    evidence_ids,
                });
                continue;
            }
            let mut parts_met = 0;
            let mut parts_total = 0;
            let mut evidence_ids = Vec::new();
            for slice in plan
                .slices
                .iter()
                .filter(|slice| slice.condition() == condition && !slice.whole_document())
            {
                if !plan.slice_is_sendable(slice) {
                    continue;
                }
                parts_total += 1;
                if let Some(result) = by_id.get(slice.id()) {
                    if result.is_met() {
                        parts_met += 1;
                    }
                    evidence_ids.extend(result.evidence_ids.iter().copied());
                }
            }
            condition_adoptions.push(ConditionAdoption {
                condition,
                met: parts_total > 0 && parts_met == parts_total,
                parts_total,
                parts_met,
                evidence_ids,
            });
        }
        let consistency = plan
            .slices
            .iter()
            .find(|slice| slice.whole_document())
            .and_then(|slice| by_id.get(slice.id()))
            .map(|result| ConditionAdoption {
                condition: H3Condition::Information,
                met: result.is_met(),
                parts_total: 1,
                parts_met: u32::from(result.is_met()),
                evidence_ids: result.evidence_ids.clone(),
            });

        let mut fixable = Vec::new();
        let mut waiting = Vec::new();
        if let Some(stage) = stale_stage {
            waiting.push(format!("evidence became stale during {stage}"));
        }
        for condition in &plan.missing_images {
            waiting.push(format!(
                "{condition} requires approved images but the profile/consent does not supply them"
            ));
        }
        for slice in &plan.truncated {
            waiting.push(format!(
                "evidence slice {slice} exceeded the profile text limit"
            ));
        }
        if test_only {
            waiting.push(
                "the render is fake/stationary; only a real WKWebView capture can complete"
                    .to_owned(),
            );
        }
        if !plan.checks.structural_pass() {
            // A structural denial is caused by candidate content and the same
            // child can fix it.
            fixable.push(H3Condition::Information);
        }
        if !plan.checks.render_pass() {
            if plan.checks.render_present() && plan.render_origin.is_native_render() {
                fixable.push(H3Condition::Render);
            } else if !allow_fake_render_for_tests {
                waiting.push("the real render required check is not available".to_owned());
            }
        }
        for result in &results {
            match result.verdict() {
                ConditionVerdict::Unmet => {
                    if !fixable.contains(&result.condition()) {
                        fixable.push(result.condition());
                    }
                }
                ConditionVerdict::Insufficient => {
                    waiting.push(format!(
                        "condition {} is insufficient and needs human review",
                        result.condition()
                    ));
                }
                ConditionVerdict::Met => {}
            }
        }
        let completion_ready = stale_stage.is_none()
            && checks_ok
            && !test_only
            && plan.missing_images.is_empty()
            && plan.truncated.is_empty()
            && condition_adoptions.iter().all(ConditionAdoption::met)
            && consistency.as_ref().is_some_and(ConditionAdoption::met);
        let disposition = if stale_stage.is_some() || !waiting.is_empty() {
            EvaluationDisposition {
                state: EvaluationDispositionState::WaitingHuman,
                fixable_conditions: fixable,
                waiting_human_reasons: waiting,
                stale_stage: stale_stage.map(str::to_owned),
            }
        } else if !completion_ready {
            EvaluationDisposition {
                state: EvaluationDispositionState::FixableUnmet,
                fixable_conditions: fixable,
                waiting_human_reasons: Vec::new(),
                stale_stage: None,
            }
        } else {
            EvaluationDisposition {
                state: EvaluationDispositionState::CompletionReady,
                fixable_conditions: Vec::new(),
                waiting_human_reasons: Vec::new(),
                stale_stage: None,
            }
        };
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            plan_checks: plan.checks.clone(),
            binding,
            slices: results,
            conditions: condition_adoptions,
            consistency,
            coverage: plan.coverage.clone(),
            completion_ready,
            test_only,
            disposition,
            missing_slices,
            missing_images: plan.missing_images.clone(),
            truncated: plan.truncated.clone(),
            recorded_at,
        })
    }

    /// Format version.
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Mandatory checks.
    pub const fn checks(&self) -> &CheckSet {
        &self.plan_checks
    }

    /// Exact fingerprint binding.
    pub const fn binding(&self) -> &EvaluationBinding {
        &self.binding
    }

    /// Slice results.
    pub fn slices(&self) -> &[SliceAssessment] {
        &self.slices
    }

    /// Aggregate condition adoptions.
    pub fn conditions(&self) -> &[ConditionAdoption] {
        &self.conditions
    }

    /// Whole-document consistency adoption.
    pub const fn consistency(&self) -> Option<&ConditionAdoption> {
        self.consistency.as_ref()
    }

    /// Exact coverage.
    pub const fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }

    /// Whether the evaluation may support completion.
    pub const fn completion_ready(&self) -> bool {
        self.completion_ready
    }

    /// Whether the render was explicitly fake/stationary.
    pub const fn test_only(&self) -> bool {
        self.test_only
    }

    /// Disposition.
    pub const fn disposition(&self) -> &EvaluationDisposition {
        &self.disposition
    }

    /// Missing assessment slices, if any.
    pub fn missing_slices(&self) -> &[String] {
        &self.missing_slices
    }

    /// Conditions whose images were unavailable.
    pub fn missing_images(&self) -> &[H3Condition] {
        &self.missing_images
    }

    /// Truncated evidence slices.
    pub fn truncated(&self) -> &[String] {
        &self.truncated
    }

    /// Record time.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// Whether this evaluation still applies to the current fingerprints.
    pub fn applies_to(&self, current: &EvidenceFingerprints) -> bool {
        self.binding.is_current()
            && self
                .binding
                .post_assessment
                .as_ref()
                .unwrap_or(&self.binding.pre_verification)
                == current
            && self.binding.post_verification == *current
    }

    /// Returns the evaluation only when it is current; an old met result is
    /// never applied.
    pub fn current_or_stale(
        &self,
        current: &EvidenceFingerprints,
    ) -> Result<&Self, EvidenceValidationError> {
        if !self.applies_to(current) {
            return Err(EvidenceValidationError::StaleEvidence {
                stage: "application",
            });
        }
        Ok(self)
    }

    /// One condition adoption.
    pub fn condition(&self, condition: H3Condition) -> Option<&ConditionAdoption> {
        self.conditions
            .iter()
            .find(|adoption| adoption.condition == condition)
    }
}

impl H3Record for AppliedEvaluation {
    const RECORD: &'static str = "H3 applied evaluation";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Validation failures raised by the evidence layer.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValidationError {
    /// The source scan was incomplete.
    IncompleteSource { detail: String },
    /// Unsupported Markdown constructs are present.
    UnsupportedSourceConstructs { count: usize },
    /// The source digest does not match the exact bytes.
    SourceDigestMismatch,
    /// The provenance template is missing.
    ProvenanceMissing,
    /// The provenance payload is invalid.
    ProvenanceInvalid { detail: String },
    /// A source unit has no evidence.
    UnitMissing { unit: String },
    /// A unit appears more than once.
    UnitDuplicate { unit: String },
    /// An undeclared unit appears.
    UnitExtraneous { unit: String },
    /// A unit definition differs from the fresh scan.
    UnitMismatch { unit: String, field: &'static str },
    /// A mapping target does not exist.
    TargetMissing { unit: String, target: String },
    /// A mapping target is hidden.
    TargetHidden { unit: String, target: String },
    /// A strict value is no longer visible.
    StrictValueMissing { unit: String, category: String },
    /// A supplementary root does not exist.
    SupplementaryRootMissing { entry: String, unit: String },
    /// A mandatory check is missing.
    RequiredCheckMissing { check: &'static str },
    /// A mandatory check did not pass.
    RequiredCheckNotPass {
        check: &'static str,
        status: &'static str,
    },
    /// A fake render was presented as a passing check.
    FakeRender,
    /// The render is incomplete or malformed.
    IncompleteRender { detail: String },
    /// A render fingerprint does not match the candidate.
    RenderFingerprintMismatch { field: &'static str },
    /// Native AX was claimed from the host-side ARIA projection.
    NativeAccessibilityClaim,
    /// A slice exceeded the profile text limit.
    Truncated {
        part: String,
        bytes: usize,
        limit: usize,
    },
    /// Required image bytes are unavailable.
    ImageUnavailable { reason: String },
    /// Secret content was excluded from the evidence.
    SecretExcluded { evidence: String },
    /// Stored evidence no longer applies to the current fingerprints.
    StaleEvidence { stage: &'static str },
    /// A required slice has no assessment.
    MissingAssessment {
        condition: H3Condition,
        part: Option<u32>,
    },
    /// A result does not apply to its request.
    AssessmentMismatch { detail: String },
    /// A split does not cover every unit exactly once.
    SplitCoverage { detail: String },
    /// An unsupported schema/version was found.
    UnsupportedSchema { found: String },
    /// A value failed validation.
    InvalidValue { field: String, detail: String },
    /// Durable evidence content could not be read or written.
    Storage { detail: String },
}

impl fmt::Display for EvidenceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteSource { detail } => {
                write!(formatter, "incomplete source scan: {detail}")
            }
            Self::UnsupportedSourceConstructs { count } => {
                write!(formatter, "{count} source constructs are not covered")
            }
            Self::SourceDigestMismatch => formatter.write_str("source digest does not match"),
            Self::ProvenanceMissing => formatter.write_str("provenance template is missing"),
            Self::ProvenanceInvalid { detail } => {
                write!(formatter, "provenance is invalid: {detail}")
            }
            Self::UnitMissing { unit } => write!(formatter, "source unit {unit} is missing"),
            Self::UnitDuplicate { unit } => write!(formatter, "source unit {unit} appears twice"),
            Self::UnitExtraneous { unit } => write!(formatter, "source unit {unit} is undeclared"),
            Self::UnitMismatch { unit, field } => {
                write!(formatter, "source unit {unit} mismatches {field}")
            }
            Self::TargetMissing { unit, target } => {
                write!(formatter, "unit {unit} target {target} is missing")
            }
            Self::TargetHidden { unit, target } => {
                write!(formatter, "unit {unit} target {target} is hidden")
            }
            Self::StrictValueMissing { unit, category } => {
                write!(
                    formatter,
                    "strict {category} value for {unit} is not visible"
                )
            }
            Self::SupplementaryRootMissing { entry, unit } => {
                write!(formatter, "supplementary {entry} root {unit} is missing")
            }
            Self::RequiredCheckMissing { check } => {
                write!(formatter, "required check {check} is missing")
            }
            Self::RequiredCheckNotPass { check, status } => {
                write!(formatter, "required check {check} is {status}")
            }
            Self::FakeRender => formatter.write_str("a fake render cannot be a passing check"),
            Self::IncompleteRender { detail } => {
                write!(formatter, "render is incomplete: {detail}")
            }
            Self::RenderFingerprintMismatch { field } => {
                write!(formatter, "render {field} fingerprint does not match")
            }
            Self::NativeAccessibilityClaim => {
                formatter.write_str("native AX cannot be claimed from host-js-aria-snapshot-v1")
            }
            Self::Truncated { part, bytes, limit } => {
                write!(
                    formatter,
                    "slice {part} needs {bytes} bytes but the limit is {limit}"
                )
            }
            Self::ImageUnavailable { reason } => {
                write!(formatter, "image evidence is unavailable: {reason}")
            }
            Self::SecretExcluded { evidence } => {
                write!(formatter, "evidence {evidence} excluded secret content")
            }
            Self::StaleEvidence { stage } => write!(formatter, "evidence is stale at {stage}"),
            Self::MissingAssessment { condition, part } => {
                write!(
                    formatter,
                    "condition {condition} part {part:?} has no assessment"
                )
            }
            Self::AssessmentMismatch { detail } => {
                write!(formatter, "assessment mismatch: {detail}")
            }
            Self::SplitCoverage { detail } => write!(formatter, "split coverage: {detail}"),
            Self::UnsupportedSchema { found } => write!(formatter, "unsupported schema {found}"),
            Self::InvalidValue { field, detail } => write!(formatter, "{field}: {detail}"),
            Self::Storage { detail } => write!(formatter, "evidence storage: {detail}"),
        }
    }
}

impl std::error::Error for EvidenceValidationError {}

impl From<EvidenceValidationError> for H3Error {
    fn from(error: EvidenceValidationError) -> Self {
        match error {
            EvidenceValidationError::ImageUnavailable { reason } => H3Error::Unavailable {
                capability: "h3.evidence.image".to_owned(),
                detail: reason,
            },
            EvidenceValidationError::StaleEvidence { stage } => H3Error::Unavailable {
                capability: "h3.evidence.current".to_owned(),
                detail: format!("evidence is stale at {stage}"),
            },
            other => H3Error::invalid("evidence", other.to_string()),
        }
    }
}

fn invalid(field: impl Into<String>, detail: impl Into<String>) -> EvidenceValidationError {
    EvidenceValidationError::InvalidValue {
        field: field.into(),
        detail: detail.into(),
    }
}

fn non_empty(field: impl Into<String>, value: String) -> Result<String, EvidenceValidationError> {
    let field = field.into();
    if value.trim().is_empty() {
        return Err(EvidenceValidationError::InvalidValue {
            field,
            detail: "must not be empty".to_owned(),
        });
    }
    Ok(value)
}

fn parse_digest(
    value: &str,
    field: impl Into<String>,
) -> Result<ContentDigest, EvidenceValidationError> {
    let value = value.trim().strip_prefix("sha256:").unwrap_or(value.trim());
    ContentDigest::parse(value).map_err(|error| EvidenceValidationError::InvalidValue {
        field: field.into(),
        detail: error.to_string(),
    })
}

fn string_field(value: &Value, key: &str, field: &str) -> Result<String, EvidenceValidationError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid(field, "missing or not a string"))
}

fn string_list(
    value: &Value,
    key: &str,
    field: &str,
) -> Result<Vec<String>, EvidenceValidationError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "missing or not an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(field, "contains a non-string"))
        })
        .collect()
}

fn extract_provenance_payload(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let marker = "id=\"sdd-provenance\"";
    let mut search_from = 0;
    while let Some(relative) = lower[search_from..].find(marker) {
        let id_position = search_from + relative;
        let _tag_start = lower[..id_position].rfind("<template")?;
        let after_open = lower[id_position..]
            .find('>')
            .map(|offset| id_position + offset + 1)?;
        let close = lower[after_open..]
            .find("</template>")
            .map(|offset| after_open + offset)?;
        let candidate = &html[after_open..close];
        if !candidate.trim().is_empty() {
            return Some(candidate.to_owned());
        }
        search_from = close + 1;
    }
    None
}

fn related_context(unit: &SourceUnitDefinition, units: &[SourceUnitDefinition]) -> String {
    let position = units
        .iter()
        .position(|candidate| candidate.id == unit.id)
        .unwrap_or(0);
    let mut context = Vec::new();
    if let Some(parent) = unit.parent() {
        if let Some(parent_unit) = units.iter().find(|candidate| candidate.id() == parent) {
            context.push(format!(
                "parent {}: {}",
                parent_unit.kind(),
                truncate(parent_unit.text(), 240)
            ));
        }
    }
    for index in position.saturating_sub(2)..position {
        context.push(format!(
            "previous {}: {}",
            units[index].kind(),
            truncate(units[index].text(), 240)
        ));
    }
    if let Some(next) = units.get(position + 1) {
        context.push(format!(
            "next {}: {}",
            next.kind(),
            truncate(next.text(), 240)
        ));
    }
    let mut heading = None;
    for candidate in units.iter().take(position).rev() {
        if candidate.kind() == "heading" {
            heading = Some(candidate.text().to_owned());
            break;
        }
    }
    if let Some(heading) = heading {
        context.insert(0, format!("section: {heading}"));
    }
    context.join("\n")
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

fn visible_value_present(html: &str, value: &str) -> bool {
    if html.contains(value) {
        return true;
    }
    let normalized = value.replace("\r\n", "\n");
    let text = visible_text(html);
    text.contains(&normalized)
        || normalize_space(&text).contains(&normalize_space(&normalized))
        || normalize_space(html).contains(&normalize_space(&normalized))
}

fn visible_text(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn outline_valid(headings: &[HeadingFact]) -> bool {
    let Some(first) = headings.first() else {
        return true;
    };
    if first.level != 1 {
        return false;
    }
    let mut previous = first.level;
    for heading in &headings[1..] {
        if heading.level == 0 || heading.level > previous.saturating_add(1) {
            return false;
        }
        previous = heading.level;
    }
    true
}

fn reading_order_matches_visual(dom: Option<&Value>, reading_order: &[String]) -> bool {
    let Some(dom) = dom else {
        return true;
    };
    let Some(blocks) = dom.get("blocks").and_then(Value::as_array) else {
        return true;
    };
    let mut last_y = f64::NEG_INFINITY;
    let mut changed = false;
    for block in blocks {
        let selector = block.get("selector").and_then(Value::as_str).unwrap_or("");
        if matches!(selector, "main" | "header" | "nav" | "footer") {
            continue;
        }
        let Some(y) = block
            .get("rect")
            .and_then(|rect| rect.get("y"))
            .and_then(Value::as_f64)
        else {
            continue;
        };
        if y + 0.5 < last_y {
            return false;
        }
        last_y = y;
        changed = true;
    }
    if !changed {
        return true;
    }
    reading_order
        .iter()
        .filter(|selector| !matches!(selector.as_str(), "main" | "header" | "nav" | "footer"))
        .count()
        > 0
}

fn check_text_budget(id: &str, text: &str, limit: usize) -> Result<(), EvidenceValidationError> {
    if text.len() > limit {
        return Err(EvidenceValidationError::Truncated {
            part: id.to_owned(),
            bytes: text.len(),
            limit,
        });
    }
    Ok(())
}

fn format_information_slice(units: &[&UnitEvidence], targets: &BTreeMap<String, String>) -> String {
    let mut text = String::new();
    for unit in units {
        text.push_str(&format!(
            "## Source unit {} ({}, bytes {}-{})\n",
            unit.unit_id(),
            unit.kind(),
            unit.start,
            unit.end
        ));
        if !unit.related_context.is_empty() {
            text.push_str("Related context:\n");
            text.push_str(&unit.related_context);
            text.push('\n');
        }
        text.push_str("Full source text:\n");
        text.push_str(&unit.text);
        text.push_str(&format!(
            "\nProvenance representation: {}\nVisible HTML targets:\n",
            unit.representations.join(", ")
        ));
        for target in &unit.targets {
            text.push_str(&format!("### target #{target}\n"));
            if let Some(html) = targets.get(target) {
                text.push_str(html);
            } else {
                text.push_str("(target unavailable)");
            }
            text.push_str("\n\n");
        }
    }
    text
}

fn format_support_slice(support: &SupportEvidence, pack: &EvidencePack) -> String {
    let mut text = String::from("Supplementary representations and declared roots:\n");
    for entry in &support.supplementary {
        text.push_str(&format!(
            "\n## {} ({})\nRoots: {}\nTargets: {}\nDescription: {}\nDiagram nodes/edges: {}/{}\nGraph series/values: {}/{}\nCaption/text/table: {}/{}/{}\nSupported: {}\nColour-only: {}\n",
            entry.id,
            entry.kind,
            entry.roots.join(", "),
            entry.targets.join(", "),
            entry.description.as_deref().unwrap_or("(none)"),
            entry.diagram_nodes,
            entry.diagram_edges,
            entry.graph_series,
            entry.graph_values,
            entry.caption_present,
            entry.text_equivalent_present,
            entry.data_table_present,
            entry.supported,
            entry.color_only,
        ));
        for target in &entry.targets {
            if let Some(html) = pack.visible_targets.get(target) {
                text.push_str(&format!("Visible target #{target}:\n{html}\n"));
            }
        }
        for root in &entry.roots {
            if let Some(unit) = pack.information.iter().find(|unit| unit.unit_id() == root) {
                text.push_str(&format!(
                    "Root unit {} ({}):\n{}\n",
                    unit.unit_id(),
                    unit.kind(),
                    unit.text()
                ));
            }
        }
    }
    text.push_str(&format!(
        "\nDeclared calculations: {}\n",
        support.calculation_count
    ));
    text
}

fn format_usability_slice(usability: &UsabilityEvidence) -> String {
    let mut text = String::from("Whole-document usability facts:\nHeadings:\n");
    for heading in &usability.headings {
        text.push_str(&format!(
            "- h{} {:?} id={:?}\n",
            heading.level, heading.text, heading.id
        ));
    }
    text.push_str(&format!(
        "Landmarks: {:?}\nNavigation targets: {:?}\nReading order: {:?}\nFocus order: {:?}\nOutline valid: {}\nReading order matches visual: {}\nPage horizontal overflow: {}\nOverlapping blocks: {}\nReadability failures: {}\nSmall text: {}\nContrast failures: {}\nFailed images: {}\nKeyboard reachable: {}\n",
        usability.landmarks,
        usability.navigation_targets,
        usability.reading_order,
        usability.focus_order,
        usability.outline_valid,
        usability.reading_order_matches_visual,
        usability.page_horizontal_overflow,
        usability.overlapping_blocks,
        usability.readability_failures,
        usability.small_text_elements,
        usability.contrast_failures,
        usability.failed_images,
        usability.keyboard_reachable,
    ));
    text
}

fn format_render_slice(render: &RenderEvidence) -> String {
    let mut text = String::from("Real render evidence:\n");
    text.push_str(&format!(
        "Manifest: {} source={} job={} origin={} complete={}\nAccessibility: {} (nodes {}) — host-side ARIA snapshot, not native AX\nSignals: overflow={} overflowing={} overlap={} readability={} minFont={} minLine={} smallText={} contrast={} failedImages={} svg={} headings={}\n",
        render.manifest_version,
        render.evidence_source,
        render.job_id,
        render.origin.as_str(),
        render.complete,
        render.accessibility_source,
        render.aria_nodes,
        render.signals.page_horizontal_overflow,
        render.signals.overflowing_elements,
        render.signals.overlapping_blocks,
        render.signals.readability_failures,
        render.signals.min_font_size_px,
        render.signals.min_line_height_ratio,
        render.signals.small_text_elements,
        render.signals.contrast_failures,
        render.signals.failed_images,
        render.signals.svg_elements,
        render.signals.headings,
    ));
    for configuration in &render.configurations {
        text.push_str(&format!(
            "- {} {}x{} zoom={} appearance={} css={}x{} png={} {}x{} digest={}\n",
            configuration.id,
            configuration.viewport_width,
            configuration.viewport_height,
            configuration.page_zoom,
            configuration.appearance,
            configuration.css_viewport_width,
            configuration.css_viewport_height,
            configuration.png_path,
            configuration.png_pixel_width,
            configuration.png_pixel_height,
            configuration.png_digest,
        ));
        if let Some(note) = configuration
            .accessibility
            .get("note")
            .and_then(Value::as_str)
        {
            text.push_str(&format!("  accessibility note: {note}\n"));
        }
        if let Some(counts) = configuration.accessibility.get("counts") {
            text.push_str(&format!("  accessibility counts: {counts}\n"));
        }
        if let Some(nodes) = configuration
            .accessibility
            .get("nodes")
            .and_then(Value::as_array)
        {
            text.push_str("  accessibility nodes:\n");
            for node in nodes.iter().take(80) {
                let role = node.get("role").and_then(Value::as_str).unwrap_or("?");
                let name = node.get("name").and_then(Value::as_str).unwrap_or("");
                let level = node
                    .get("level")
                    .and_then(Value::as_u64)
                    .map(|level| format!(" level={level}"))
                    .unwrap_or_default();
                text.push_str(&format!("  - {role}{level} {name}\n"));
            }
        }
    }
    text
}

fn format_consistency_slice(pack: &EvidencePack) -> String {
    let mut text =
        String::from("Whole-document consistency evidence. Condition evidence summaries:\n");
    for reference in &pack.consistency.conditions {
        text.push_str(&format!(
            "- {} parts={} units={}\n",
            reference.condition,
            reference.parts,
            reference.unit_ids.len()
        ));
    }
    text.push_str("\nEvery source unit:\n");
    for unit in &pack.information {
        text.push_str(&format!(
            "\n## {} ({})\nFull text:\n{}\nVisible target ids: {:?}\n",
            unit.unit_id, unit.kind, unit.text, unit.targets
        ));
    }
    text.push_str("\nSupport evidence:\n");
    text.push_str(&format_support_slice(&pack.support, pack));
    text.push_str("\nUsability evidence:\n");
    text.push_str(&format_usability_slice(&pack.usability));
    text.push_str("\nRender evidence:\n");
    text.push_str(&format_render_slice(&pack.render));
    text.push_str("\nVisible document text:\n");
    text.push_str(
        pack.visible_targets
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
            .as_str(),
    );
    text.push_str(&format!(
        "\nVisible text digest: {}\n",
        pack.consistency.visible_text_digest
    ));
    text
}

#[derive(Debug)]
struct OpenElement {
    name: String,
    id: Option<String>,
    start: usize,
    targetable: bool,
    hidden: bool,
    template: bool,
    head: bool,
    nav: bool,
    aside: bool,
    main: bool,
    heading_level: Option<u8>,
}

#[derive(Debug)]
struct HeadingCapture {
    text: String,
}

#[derive(Debug)]
struct ParsedTag {
    end: usize,
    name: String,
    closing: bool,
    self_closing: bool,
    attrs: Vec<(String, String)>,
}

fn scan_html(html: &str) -> ScannedHtml {
    let mut open = Vec::<OpenElement>::new();
    let mut targets = BTreeMap::new();
    let mut hidden_targets = BTreeSet::new();
    let mut headings = Vec::new();
    let mut heading_captures = Vec::<HeadingCapture>::new();
    let mut landmarks = Vec::new();
    let mut navigation_targets = Vec::new();
    let mut focus_order = Vec::new();
    let mut block_order = Vec::new();
    let mut visible = String::new();
    let mut hidden_depth = 0usize;
    let mut template_depth = 0usize;
    let mut head_depth = 0usize;
    let mut nav_depth = 0usize;
    let mut aside_depth = 0usize;
    let mut main_depth = 0usize;
    let mut cursor = 0usize;
    let mut index = 0usize;

    while let Some(relative) = html[index..].find('<') {
        let start = index + relative;
        if start > cursor {
            let text = &html[cursor..start];
            if main_depth > 0
                && hidden_depth == 0
                && template_depth == 0
                && head_depth == 0
                && nav_depth == 0
                && aside_depth == 0
            {
                visible.push_str(text);
                if let Some(capture) = heading_captures.last_mut() {
                    capture.text.push_str(text);
                }
            }
        }
        if html[start..].starts_with("<!--") {
            if let Some(close) = html[start + 4..].find("-->") {
                index = start + 4 + close + 3;
                cursor = index;
                continue;
            }
            break;
        }
        if html[start..].starts_with("<!") {
            if let Some(close) = html[start..].find('>') {
                index = start + close + 1;
                cursor = index;
                continue;
            }
            break;
        }
        let Some(tag) = parse_tag(html, start) else {
            index = start + 1;
            continue;
        };
        if tag.closing {
            let mut pop_at = None;
            for position in (0..open.len()).rev() {
                if open[position].name == tag.name {
                    pop_at = Some(position);
                    break;
                }
            }
            if let Some(pop_at) = pop_at {
                while open.len() > pop_at {
                    let element = open.pop().expect("open element");
                    if element.hidden {
                        hidden_depth = hidden_depth.saturating_sub(1);
                    }
                    if element.template {
                        template_depth = template_depth.saturating_sub(1);
                    }
                    if element.head {
                        head_depth = head_depth.saturating_sub(1);
                    }
                    if element.nav {
                        nav_depth = nav_depth.saturating_sub(1);
                    }
                    if element.aside {
                        aside_depth = aside_depth.saturating_sub(1);
                    }
                    if element.main {
                        main_depth = main_depth.saturating_sub(1);
                    }
                    if let Some(level) = element.heading_level {
                        if let Some(capture) = heading_captures.pop() {
                            headings.push(HeadingFact {
                                level,
                                text: normalize_space(&capture.text),
                                id: element.id.clone(),
                            });
                        }
                    }
                    if let Some(id) = element.id {
                        if element.targetable && element.start < tag.end {
                            targets.insert(id, html[element.start..tag.end].to_owned());
                        }
                    }
                }
            }
            index = tag.end;
            cursor = tag.end;
            continue;
        }

        let name = tag.name.as_str();
        let id = attr(&tag.attrs, "id").map(str::to_owned);
        let aria_hidden =
            attr(&tag.attrs, "aria-hidden").is_some_and(|value| value.eq_ignore_ascii_case("true"));
        let hidden = aria_hidden || attr(&tag.attrs, "hidden").is_some();
        let is_template = name == "template";
        let is_head = name == "head";
        let is_nav = name == "nav";
        let is_aside = name == "aside";
        let is_main = name == "main";
        let heading_level = match name {
            "h1" => Some(1),
            "h2" => Some(2),
            "h3" => Some(3),
            "h4" => Some(4),
            "h5" => Some(5),
            "h6" => Some(6),
            _ => None,
        };
        let is_visible_context = main_depth > 0
            && hidden_depth == 0
            && template_depth == 0
            && head_depth == 0
            && nav_depth == 0
            && aside_depth == 0;
        let is_visible =
            is_visible_context && !hidden && !is_template && !is_head && !is_nav && !is_aside;

        if !is_visible && let Some(id) = &id {
            if !matches!(name, "html" | "body" | "main" | "head") {
                hidden_targets.insert(id.clone());
            }
        }

        // Navigation links live inside <nav>, which is intentionally not a
        // mapping target, but its targets are still usability facts.
        if nav_depth > 0 && name == "a" {
            if let Some(href) = attr(&tag.attrs, "href") {
                navigation_targets.push(href.to_owned());
            }
        }
        if template_depth == 0
            && head_depth == 0
            && (matches!(
                name,
                "header" | "nav" | "main" | "aside" | "footer" | "form"
            ) || (name == "section" && attr(&tag.attrs, "aria-label").is_some()))
        {
            let label = attr(&tag.attrs, "aria-label").unwrap_or("");
            let landmark = if label.is_empty() {
                name.to_owned()
            } else {
                format!("{name}: {label}")
            };
            if !landmarks.contains(&landmark) {
                landmarks.push(landmark);
            }
        }

        if is_visible {
            if heading_level.is_some() {
                heading_captures.push(HeadingCapture {
                    text: String::new(),
                });
            }
            if (matches!(name, "a" | "button" | "input" | "select" | "textarea")
                && (name != "a" || attr(&tag.attrs, "href").is_some()))
                || attr(&tag.attrs, "tabindex").is_some()
            {
                let selector = id
                    .as_ref()
                    .map(|id| format!("#{id}"))
                    .unwrap_or_else(|| name.to_owned());
                if !focus_order.contains(&selector) {
                    focus_order.push(selector);
                }
            }
            if matches!(
                name,
                "h1" | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "p"
                    | "table"
                    | "figure"
                    | "ul"
                    | "ol"
                    | "pre"
                    | "section"
            ) {
                let selector = id
                    .as_ref()
                    .map(|id| format!("#{id}"))
                    .unwrap_or_else(|| name.to_owned());
                if !block_order.contains(&selector) {
                    block_order.push(selector);
                }
            }
        }

        let element = OpenElement {
            name: name.to_owned(),
            id: id.clone(),
            start,
            targetable: is_visible && !matches!(name, "html" | "body" | "main" | "head"),
            hidden,
            template: is_template,
            head: is_head,
            nav: is_nav,
            aside: is_aside,
            main: is_main,
            heading_level,
        };
        if hidden {
            hidden_depth += 1;
        }
        if is_template {
            template_depth += 1;
        }
        if is_head {
            head_depth += 1;
        }
        if is_nav {
            nav_depth += 1;
        }
        if is_aside {
            aside_depth += 1;
        }
        if is_main {
            main_depth += 1;
        }

        let void = matches!(
            name,
            "area"
                | "base"
                | "br"
                | "col"
                | "embed"
                | "hr"
                | "img"
                | "input"
                | "link"
                | "meta"
                | "param"
                | "source"
                | "track"
                | "wbr"
                | "path"
                | "circle"
                | "ellipse"
                | "line"
                | "polygon"
                | "polyline"
                | "rect"
                | "stop"
                | "use"
        );
        if !tag.self_closing && !void {
            open.push(element);
        } else {
            // Self-closing and void elements with an id are visible targets on
            // their own.
            if is_visible && let Some(id) = id {
                if !matches!(name, "html" | "body" | "main" | "head") {
                    targets.insert(id, html[start..tag.end].to_owned());
                }
            }
        }

        // Raw-text elements are not parsed as markup.
        if matches!(name, "script" | "style" | "textarea" | "title") {
            let close_marker = format!("</{name}");
            if let Some(close) = html[tag.end..].to_ascii_lowercase().find(&close_marker) {
                index = tag.end + close;
                cursor = index;
                continue;
            }
        }
        index = tag.end;
        cursor = tag.end;
    }
    if cursor < html.len()
        && main_depth > 0
        && hidden_depth == 0
        && template_depth == 0
        && head_depth == 0
        && nav_depth == 0
        && aside_depth == 0
    {
        visible.push_str(&html[cursor..]);
    }

    ScannedHtml {
        visible_text: normalize_space(&visible),
        targets,
        hidden_targets,
        headings,
        landmarks,
        navigation_targets,
        focus_order,
        block_order,
    }
}

fn parse_tag(html: &str, start: usize) -> Option<ParsedTag> {
    let bytes = html.as_bytes();
    if bytes.get(start) != Some(&b'<') {
        return None;
    }
    let mut position = start + 1;
    let closing = if bytes.get(position) == Some(&b'/') {
        position += 1;
        true
    } else {
        false
    };
    while position < bytes.len() && bytes[position].is_ascii_whitespace() {
        position += 1;
    }
    let name_start = position;
    while position < bytes.len()
        && (bytes[position].is_ascii_alphanumeric()
            || matches!(bytes[position], b'-' | b':' | b'_'))
    {
        position += 1;
    }
    if position == name_start {
        return None;
    }
    let name = html[name_start..position].to_ascii_lowercase();
    let mut attrs = Vec::new();
    let mut self_closing = false;
    while position < bytes.len() {
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        if position >= bytes.len() {
            break;
        }
        match bytes[position] {
            b'>' => {
                position += 1;
                return Some(ParsedTag {
                    end: position,
                    name,
                    closing,
                    self_closing,
                    attrs,
                });
            }
            b'/' if bytes.get(position + 1) == Some(&b'>') => {
                self_closing = true;
                position += 2;
                return Some(ParsedTag {
                    end: position,
                    name,
                    closing,
                    self_closing,
                    attrs,
                });
            }
            _ => {}
        }
        let attr_start = position;
        while position < bytes.len()
            && !bytes[position].is_ascii_whitespace()
            && !matches!(bytes[position], b'=' | b'>' | b'/')
        {
            position += 1;
        }
        if position == attr_start {
            position += 1;
            continue;
        }
        let attr_name = html[attr_start..position].to_ascii_lowercase();
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        if bytes.get(position) != Some(&b'=') {
            attrs.push((attr_name, String::new()));
            continue;
        }
        position += 1;
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        let value = match bytes.get(position).copied() {
            Some(b'"') | Some(b'\'') => {
                let quote = bytes[position];
                position += 1;
                let value_start = position;
                while position < bytes.len() && bytes[position] != quote {
                    position += 1;
                }
                let value = html[value_start..position].to_owned();
                if position < bytes.len() {
                    position += 1;
                }
                value
            }
            _ => {
                let value_start = position;
                while position < bytes.len()
                    && !bytes[position].is_ascii_whitespace()
                    && !matches!(bytes[position], b'>' | b'/')
                {
                    position += 1;
                }
                html[value_start..position].to_owned()
            }
        };
        attrs.push((attr_name, value));
    }
    None
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn normalize_space(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
