//! Per-condition assessment requests, results, distributions, and permission
//! decisions.
//!
//! Completion is supported only by an adopted `met` result whose condition
//! version, target version, profile version, and evidence all match the current
//! request. `insufficient`, `ask`, uncertainty, missing evidence, and low
//! probability never support completion or execution.

use herness_core::contracts::{ModelId, ProjectId, Provider, Timestamp};
use serde::{Deserialize, Serialize};

use crate::conditions::ConditionVersion;
use crate::error::SupervisionError;
use crate::evidence::TargetVersion;
use crate::ids::{ConditionId, DecisionId, EvidenceId, SupervisionId, verify_scoped};
use crate::profiles::{
    AdapterVersion, H2_DISTRIBUTION_TOLERANCE, ProfileBinding, ProfilePurpose, ProfileThresholds,
    ProviderKind, RubricVersion,
};

/// Verdict for one completion condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionVerdict {
    /// The condition is satisfied.
    Met,
    /// The condition is not satisfied.
    Unmet,
    /// The available evidence or model answer cannot decide.
    Insufficient,
}

impl ConditionVerdict {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Met => "met",
            Self::Unmet => "unmet",
            Self::Insufficient => "insufficient",
        }
    }

    /// Whether this verdict may support completion when adopted.
    pub const fn is_met(self) -> bool {
        matches!(self, Self::Met)
    }
}

/// Provider-reported native confidence.
///
/// This value is never converted into a calibrated probability or compared
/// against the Decision probability thresholds. The scale label records the
/// provider's own scale because different providers must not be assumed to
/// share one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeConfidence {
    value: f64,
    scale: String,
}

impl NativeConfidence {
    /// Creates a finite provider-reported confidence with an explicit scale.
    pub fn new(value: f64, scale: impl AsRef<str>) -> Result<Self, SupervisionError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "confidence.value".to_owned(),
                detail: "must be finite and between 0 and 1".to_owned(),
            });
        }
        let scale = scale.as_ref().trim();
        if scale.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "confidence.scale".to_owned(),
                detail: "the provider-specific confidence scale must be named".to_owned(),
            });
        }
        Ok(Self {
            value,
            scale: scale.to_owned(),
        })
    }

    /// Reported value.
    pub const fn value(&self) -> f64 {
        self.value
    }

    /// Provider-specific scale label.
    pub fn scale(&self) -> &str {
        &self.scale
    }

    /// Native confidence is not a calibrated probability.
    pub const fn is_probability(&self) -> bool {
        false
    }
}

/// Complete probability distribution over the three condition verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionProbabilities {
    met: f64,
    unmet: f64,
    insufficient: f64,
}

impl ConditionProbabilities {
    /// Validates finite values in `0..=1` whose sum is within the H2 tolerance
    /// of one. The distribution is never silently normalized.
    pub fn new(met: f64, unmet: f64, insufficient: f64) -> Result<Self, SupervisionError> {
        let values = [
            ("met", met),
            ("unmet", unmet),
            ("insufficient", insufficient),
        ];
        for (field, value) in values {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(SupervisionError::AssessmentContractViolation {
                    field: format!("distribution.{field}"),
                    detail: "probability must be finite and between 0 and 1".to_owned(),
                });
            }
        }
        let sum = met + unmet + insufficient;
        if (sum - 1.0).abs() > H2_DISTRIBUTION_TOLERANCE {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "distribution.sum".to_owned(),
                detail: format!(
                    "probabilities must sum to 1 within {H2_DISTRIBUTION_TOLERANCE}; found {sum}"
                ),
            });
        }
        Ok(Self {
            met,
            unmet,
            insufficient,
        })
    }

    /// Probability of one verdict.
    pub const fn probability(self, verdict: ConditionVerdict) -> f64 {
        match verdict {
            ConditionVerdict::Met => self.met,
            ConditionVerdict::Unmet => self.unmet,
            ConditionVerdict::Insufficient => self.insufficient,
        }
    }

    /// Probability of `met`.
    pub const fn met(self) -> f64 {
        self.met
    }

    /// Probability of `unmet`.
    pub const fn unmet(self) -> f64 {
        self.unmet
    }

    /// Probability of `insufficient`.
    pub const fn insufficient(self) -> f64 {
        self.insufficient
    }
}

/// Origin of the short rationale stored with an assessment result.
///
/// Older results that predate this field deserialize as
/// [`RationaleOrigin::Unspecified`]; they never silently become model prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RationaleOrigin {
    /// The rationale text was provided by the model/provider answer.
    Model,
    /// The rationale is a host-owned note because the provider returned no
    /// usable rationale. It must never be presented as model reasoning.
    Host,
    /// The origin was not recorded by an older or fixture-created result.
    #[default]
    Unspecified,
}

/// Result shape reported by the assessment channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AssessmentOutcome {
    /// A normal LLM returns a schema-validated verdict plus its provider-native
    /// confidence, if reported.
    NormalLlm {
        /// Verdict from the structured response.
        verdict: ConditionVerdict,
        /// Provider-native confidence, not a probability.
        #[serde(default)]
        confidence: Option<NativeConfidence>,
    },
    /// A Jev or Decisions response returns a selected choice, the complete
    /// probability distribution, and the provider-native confidence when one
    /// was reported.
    Decision {
        /// Selected choice.
        selected: ConditionVerdict,
        /// Complete distribution over all choices.
        probabilities: ConditionProbabilities,
        /// Provider-native confidence retained separately from the
        /// probabilities. Adoption uses the selected probability, never this
        /// value.
        #[serde(default)]
        confidence: Option<NativeConfidence>,
    },
}

/// One assessment request for one condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentRequest {
    id: DecisionId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    condition_id: ConditionId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    rubric: String,
    profile: ProfileBinding,
    adapter_version: AdapterVersion,
    rubric_version: RubricVersion,
    evidence: Vec<EvidenceId>,
}

impl AssessmentRequest {
    /// Creates a validated per-condition assessment request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: DecisionId,
        supervision_id: SupervisionId,
        condition_id: ConditionId,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        rubric: impl AsRef<str>,
        profile: ProfileBinding,
        adapter_version: AdapterVersion,
        rubric_version: RubricVersion,
        evidence: Vec<EvidenceId>,
    ) -> Result<Self, SupervisionError> {
        let project_id = id.project_id();
        verify_scoped(&id, project_id)?;
        verify_scoped(&supervision_id, project_id)?;
        verify_scoped(&condition_id, project_id)?;
        profile.ensure_project(project_id)?;
        for evidence_id in &evidence {
            verify_scoped(evidence_id, project_id)?;
        }
        if evidence.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessment.evidence".to_owned(),
                detail: "an assessment needs at least one applicable evidence item".to_owned(),
            });
        }
        let rubric = rubric.as_ref().trim();
        if rubric.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessment.rubric".to_owned(),
                detail: "must not be empty".to_owned(),
            });
        }
        if rubric.chars().count() > 8_000 {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessment.rubric".to_owned(),
                detail: "must contain at most 8000 characters".to_owned(),
            });
        }
        Ok(Self {
            id,
            project_id,
            supervision_id,
            condition_id,
            condition_version,
            target_version,
            rubric: rubric.to_owned(),
            profile,
            adapter_version,
            rubric_version,
            evidence,
        })
    }

    /// Decision/request identifier.
    pub const fn id(&self) -> DecisionId {
        self.id
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Condition being assessed.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Condition version pinned by the request.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Target version pinned by the request.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Per-condition rubric.
    pub fn rubric(&self) -> &str {
        &self.rubric
    }

    /// Fixed assessment profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Adapter version pinned by the request.
    pub fn adapter_version(&self) -> &AdapterVersion {
        &self.adapter_version
    }

    /// Rubric version pinned by the request.
    pub fn rubric_version(&self) -> &RubricVersion {
        &self.rubric_version
    }

    /// Evidence included in this request and nowhere else.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }

    /// Purpose requested.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.profile.purpose()
    }
}

/// Why one provider produced an assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProvenance {
    provider: Provider,
    provider_kind: ProviderKind,
    #[serde(default)]
    purpose: Option<ProfilePurpose>,
    model: ModelId,
    #[serde(default)]
    reported_model: Option<ModelId>,
    adapter_version: AdapterVersion,
    rubric_version: RubricVersion,
}

impl AssessmentProvenance {
    /// Creates provenance for a provider/model/adapter/rubric combination.
    pub fn new(
        provider: Provider,
        provider_kind: ProviderKind,
        model: ModelId,
        adapter_version: AdapterVersion,
        rubric_version: RubricVersion,
    ) -> Result<Self, SupervisionError> {
        let provider_matches = match provider_kind {
            ProviderKind::NormalLlm => provider != Provider::TypeSafe,
            ProviderKind::Jev => provider == Provider::TypeSafe,
            ProviderKind::Decisions => provider == Provider::OpenAi,
        };
        if !provider_matches {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "provenance.provider".to_owned(),
                detail: "provider does not match the assessment provider kind".to_owned(),
            });
        }
        Ok(Self {
            provider,
            provider_kind,
            purpose: None,
            model,
            reported_model: None,
            adapter_version,
            rubric_version,
        })
    }

    /// Records the assessment purpose the adapter was asked to serve.
    ///
    /// `Completion` and `Html` share the condition request shape but are not
    /// interchangeable. The recorded purpose lets a consumer distinguish them
    /// without inferring it from the profile or provider.
    #[must_use]
    pub fn with_purpose(mut self, purpose: ProfilePurpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Assessment purpose, when the writer recorded it.
    ///
    /// Older payloads without this field return `None`; they are never
    /// silently treated as `Completion`.
    pub const fn purpose(&self) -> Option<ProfilePurpose> {
        self.purpose
    }

    /// Records the model identifier actually reported by the provider.
    ///
    /// The configured [`Self::model`] keeps the profile alias or fixed ID. A
    /// provider that reports a different version from the requested fixed ID
    /// still records that reported value for audit, but the adapter must
    /// reject the evaluation as non-reusable.
    pub fn with_reported_model(mut self, model: ModelId) -> Self {
        self.reported_model = Some(model);
        self
    }

    /// Provider-reported model identifier, when one was recorded.
    pub fn reported_model(&self) -> Option<&ModelId> {
        self.reported_model.as_ref()
    }

    /// Provider.
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Provider kind.
    pub const fn provider_kind(&self) -> ProviderKind {
        self.provider_kind
    }

    /// Real or alias model identifier reported for this assessment.
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// Adapter version.
    pub fn adapter_version(&self) -> &AdapterVersion {
        &self.adapter_version
    }

    /// Rubric version.
    pub fn rubric_version(&self) -> &RubricVersion {
        &self.rubric_version
    }
}

/// One condition-level assessment result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentResult {
    id: DecisionId,
    project_id: ProjectId,
    supervision_id: SupervisionId,
    condition_id: ConditionId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    profile: ProfileBinding,
    evidence: Vec<EvidenceId>,
    rationale: String,
    #[serde(default)]
    rationale_origin: RationaleOrigin,
    #[serde(default)]
    uncertainty: Option<String>,
    outcome: AssessmentOutcome,
    provenance: AssessmentProvenance,
    decided_at: Timestamp,
}

impl AssessmentResult {
    /// Creates a result bound to the exact request, evidence subset, and
    /// provenance versions.
    pub fn new(
        request: &AssessmentRequest,
        evidence: Vec<EvidenceId>,
        rationale: impl AsRef<str>,
        uncertainty: Option<String>,
        outcome: AssessmentOutcome,
        provenance: AssessmentProvenance,
        decided_at: Timestamp,
    ) -> Result<Self, SupervisionError> {
        if evidence.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessmentResult.evidence".to_owned(),
                detail: "a result must cite at least one requested evidence item".to_owned(),
            });
        }
        for evidence_id in &evidence {
            if !request.evidence.contains(evidence_id) {
                return Err(SupervisionError::AssessmentContractViolation {
                    field: "assessmentResult.evidence".to_owned(),
                    detail: "result cites an evidence ID that was not in the request".to_owned(),
                });
            }
        }
        let rationale = rationale.as_ref().trim();
        if rationale.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessmentResult.rationale".to_owned(),
                detail: "a short rationale is required".to_owned(),
            });
        }
        if rationale.chars().count() > 2_000 {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessmentResult.rationale".to_owned(),
                detail: "must contain at most 2000 characters".to_owned(),
            });
        }
        if provenance.adapter_version() != request.adapter_version()
            || provenance.rubric_version() != request.rubric_version()
        {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessmentResult.provenance".to_owned(),
                detail: "adapter and rubric versions must match the request".to_owned(),
            });
        }
        if provenance
            .purpose()
            .is_some_and(|purpose| purpose != request.purpose())
        {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessmentResult.provenance.purpose".to_owned(),
                detail: "the provenance purpose must match the requested assessment purpose"
                    .to_owned(),
            });
        }
        let uncertainty = uncertainty
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        Ok(Self {
            id: request.id,
            project_id: request.project_id,
            supervision_id: request.supervision_id,
            condition_id: request.condition_id,
            condition_version: request.condition_version,
            target_version: request.target_version,
            profile: request.profile,
            evidence,
            rationale: rationale.to_owned(),
            rationale_origin: RationaleOrigin::Unspecified,
            uncertainty,
            outcome,
            provenance,
            decided_at,
        })
    }

    /// Marks where the stored rationale text came from.
    ///
    /// A host-owned note must not be presented as model reasoning. This
    /// builder is additive; older results without the field remain
    /// [`RationaleOrigin::Unspecified`].
    pub fn with_rationale_origin(mut self, origin: RationaleOrigin) -> Self {
        self.rationale_origin = origin;
        self
    }

    /// Decision identifier.
    pub const fn id(&self) -> DecisionId {
        self.id
    }

    /// Project that owns the result.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Condition assessed.
    pub const fn condition_id(&self) -> ConditionId {
        self.condition_id
    }

    /// Condition version this result applies to.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Target version this result applies to.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Fixed profile.
    pub const fn profile(&self) -> ProfileBinding {
        self.profile
    }

    /// Assessment purpose recorded by the fixed profile binding.
    ///
    /// `Html` results are not Completion results; a consumer must compare this
    /// purpose and the binding before using a result for completion.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.profile.purpose()
    }

    /// Evidence cited by the result.
    pub fn evidence(&self) -> &[EvidenceId] {
        &self.evidence
    }

    /// Short model rationale, distinguished from internal reasoning.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Origin of the stored rationale text.
    pub const fn rationale_origin(&self) -> RationaleOrigin {
        self.rationale_origin
    }

    /// Model-reported uncertainty.
    pub fn uncertainty(&self) -> Option<&str> {
        self.uncertainty.as_deref()
    }

    /// Outcome shape.
    pub fn outcome(&self) -> &AssessmentOutcome {
        &self.outcome
    }

    /// Provenance.
    pub fn provenance(&self) -> &AssessmentProvenance {
        &self.provenance
    }

    /// When the result was recorded.
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }

    /// Verdict reported by the provider before adoption rules are applied.
    pub fn reported_verdict(&self) -> ConditionVerdict {
        match &self.outcome {
            AssessmentOutcome::NormalLlm { verdict, .. } => *verdict,
            AssessmentOutcome::Decision { selected, .. } => *selected,
        }
    }

    /// Whether the result is pinned to the current versions/profile.
    pub fn applies_to(
        &self,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        profile: ProfileBinding,
    ) -> bool {
        self.condition_version == condition_version
            && self.target_version == target_version
            && self.profile == profile
    }

    /// Verdict adopted under the profile thresholds.
    ///
    /// Normal LLM results use schema validity and the absence of reported
    /// uncertainty, not a fabricated probability threshold. Decision results
    /// require the selected `met`/`unmet` probability to meet the conservative
    /// threshold. `insufficient`, `ask`, and low confidence return `None`.
    pub fn adopted_verdict(&self, thresholds: ProfileThresholds) -> Option<ConditionVerdict> {
        if self.uncertainty.is_some() {
            return None;
        }
        match &self.outcome {
            AssessmentOutcome::NormalLlm { verdict, .. } => match verdict {
                ConditionVerdict::Met | ConditionVerdict::Unmet => Some(*verdict),
                ConditionVerdict::Insufficient => None,
            },
            AssessmentOutcome::Decision {
                selected,
                probabilities,
                ..
            } => {
                let threshold = match selected {
                    ConditionVerdict::Met => thresholds.completion_met()?,
                    ConditionVerdict::Unmet => thresholds.completion_unmet()?,
                    ConditionVerdict::Insufficient => return None,
                };
                let probability = probabilities.probability(*selected);
                if probability.is_finite() && probability >= threshold {
                    Some(*selected)
                } else {
                    None
                }
            }
        }
    }

    /// Whether this result supports completion at the given versions.
    pub fn supports_completion(
        &self,
        condition_version: ConditionVersion,
        target_version: TargetVersion,
        profile: ProfileBinding,
        thresholds: ProfileThresholds,
    ) -> bool {
        self.applies_to(condition_version, target_version, profile)
            && !self.evidence.is_empty()
            && self
                .adopted_verdict(thresholds)
                .is_some_and(ConditionVerdict::is_met)
    }
}

/// Permission verdict returned by an evaluator profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionVerdict {
    /// Execute the operation.
    Allow,
    /// Refuse the operation.
    Deny,
    /// Ask the human.
    Ask,
}

impl PermissionVerdict {
    /// Whether this verdict may authorize execution.
    pub const fn is_execution_verdict(self) -> bool {
        matches!(self, Self::Allow | Self::Deny)
    }
}

/// Complete probability distribution over permission choices.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionProbabilities {
    allow: f64,
    deny: f64,
    ask: f64,
}

impl PermissionProbabilities {
    /// Validates finite values in `0..=1` whose sum is within the H2 tolerance.
    pub fn new(allow: f64, deny: f64, ask: f64) -> Result<Self, SupervisionError> {
        let values = [("allow", allow), ("deny", deny), ("ask", ask)];
        for (field, value) in values {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(SupervisionError::AssessmentContractViolation {
                    field: format!("permissionDistribution.{field}"),
                    detail: "probability must be finite and between 0 and 1".to_owned(),
                });
            }
        }
        let sum = allow + deny + ask;
        if (sum - 1.0).abs() > H2_DISTRIBUTION_TOLERANCE {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "permissionDistribution.sum".to_owned(),
                detail: format!(
                    "probabilities must sum to 1 within {H2_DISTRIBUTION_TOLERANCE}; found {sum}"
                ),
            });
        }
        Ok(Self { allow, deny, ask })
    }

    /// Probability of one verdict.
    pub const fn probability(self, verdict: PermissionVerdict) -> f64 {
        match verdict {
            PermissionVerdict::Allow => self.allow,
            PermissionVerdict::Deny => self.deny,
            PermissionVerdict::Ask => self.ask,
        }
    }
}

/// One permission assessment result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum PermissionAssessment {
    /// A normal LLM returned an explicit allow or deny; uncertainty forces ask.
    NormalLlm {
        /// Explicit verdict.
        verdict: PermissionVerdict,
        /// Whether the model reported uncertainty.
        uncertain: bool,
    },
    /// A Decision provider returned a selected choice and complete distribution.
    Decision {
        /// Selected choice.
        selected: PermissionVerdict,
        /// Complete distribution.
        probabilities: PermissionProbabilities,
    },
}

impl PermissionAssessment {
    /// Verdict adopted under the profile thresholds.
    ///
    /// `ask`, uncertainty, and a below-threshold `allow`/`deny` return `None`.
    /// A normal LLM has no calibrated probability; an explicit, certain
    /// allow/deny is adopted, while its `ask` is not.
    pub fn adopted_verdict(&self, thresholds: ProfileThresholds) -> Option<PermissionVerdict> {
        match self {
            Self::NormalLlm { verdict, uncertain } => {
                if *uncertain || !verdict.is_execution_verdict() {
                    None
                } else {
                    Some(*verdict)
                }
            }
            Self::Decision {
                selected,
                probabilities,
            } => {
                if !selected.is_execution_verdict() {
                    return None;
                }
                let threshold = match selected {
                    PermissionVerdict::Allow => thresholds.permission_allow(),
                    PermissionVerdict::Deny => thresholds.permission_deny(),
                    PermissionVerdict::Ask => None,
                }?;
                let probability = probabilities.probability(*selected);
                if probability.is_finite() && probability >= threshold {
                    Some(*selected)
                } else {
                    None
                }
            }
        }
    }

    /// Whether this result authorizes execution. Only an adopted `allow` does.
    pub fn allows_execution(&self, thresholds: ProfileThresholds) -> bool {
        self.adopted_verdict(thresholds) == Some(PermissionVerdict::Allow)
    }
}
