//! Purpose-specific assessment profiles.
//!
//! A profile fixes the provider kind, connection, model, adapter/rubric
//! version, required input capabilities, confidence model, and adoption
//! thresholds. Profiles are never inferred from the run model. An unset,
//! unavailable, or incompatible profile is unusable; resolution never falls
//! back to another purpose, provider, model, or connection.
//!
//! The numeric thresholds are conservative initial values from the H2 design,
//! not a safety, accuracy, or calibration guarantee.

use std::collections::BTreeMap;

use herness_core::contracts::{
    ConnectionCapabilities, ConnectionId, ConnectionStatus, EndpointClass, InputModality, ModelId,
    ProjectId,
};
use serde::{Deserialize, Serialize};

use crate::error::SupervisionError;
use crate::ids::{ProfileId, verify_scoped};

/// Adoption threshold for a Decision-model `met` or `unmet` completion result.
pub const H2_COMPLETION_MET_THRESHOLD: f64 = 0.95;
/// Adoption threshold for `unmet`; the H2 design uses the same conservative
/// value for both positive and negative completion verdicts.
pub const H2_COMPLETION_UNMET_THRESHOLD: f64 = 0.95;
/// Adoption threshold for a Decision-model permission `allow`.
pub const H2_PERMISSION_ALLOW_THRESHOLD: f64 = 0.99;
/// Adoption threshold for a Decision-model permission `deny`.
pub const H2_PERMISSION_DENY_THRESHOLD: f64 = 0.99;
/// Maximum tolerated absolute error of a probability distribution's sum.
pub const H2_DISTRIBUTION_TOLERANCE: f64 = 0.001;

/// Purpose of one assessment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePurpose {
    /// Completion-condition assessment.
    Completion,
    /// HTML-specific quality assessment owned by H3.
    Html,
    /// H1 permission/allow-deny evaluation.
    Permission,
}

impl ProfilePurpose {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::Html => "html",
            Self::Permission => "permission",
        }
    }

    /// Whether this purpose is a condition assessment handled by the three
    /// condition adapters.
    ///
    /// `Html` is a distinct purpose, not a `Completion` fallback: the request,
    /// consent, origin, and recorded purpose stay Html. `Permission` has its
    /// own adapter, question, and record shape and is never accepted by the
    /// condition adapters.
    pub const fn is_condition_assessment(self) -> bool {
        matches!(self, Self::Completion | Self::Html)
    }
}

/// Provider shape behind an assessment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// A normal tool-free LLM assessment request with a structured schema.
    NormalLlm,
    /// TypeSafe Jev System One choice assessment.
    Jev,
    /// OpenAI Decisions choice assessment.
    Decisions,
}

impl ProviderKind {
    /// Whether this provider reports native probabilities that may be compared
    /// against the H2 adoption thresholds.
    pub const fn has_probabilities(self) -> bool {
        matches!(self, Self::Jev | Self::Decisions)
    }

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalLlm => "normal_llm",
            Self::Jev => "jev",
            Self::Decisions => "decisions",
        }
    }
}

/// Monotonic profile version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileVersion(u64);

impl ProfileVersion {
    /// Creates a positive profile version.
    pub fn new(value: u64) -> Result<Self, SupervisionError> {
        if value == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "profileVersion".to_owned(),
                detail: "versions start at 1".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Adapter implementation version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdapterVersion(String);

impl AdapterVersion {
    /// Creates a non-empty adapter version.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        Ok(Self(crate::profiles::non_empty("adapterVersion", value)?))
    }

    /// Version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rubric version sent with an assessment request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RubricVersion(String);

impl RubricVersion {
    /// Creates a non-empty rubric version.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        Ok(Self(crate::profiles::non_empty("rubricVersion", value)?))
    }

    /// Version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inputs a profile requires from its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileInputs {
    text: bool,
    image: bool,
    structured_output: bool,
}

impl ProfileInputs {
    /// Declares required input capabilities.
    pub const fn new(text: bool, image: bool, structured_output: bool) -> Self {
        Self {
            text,
            image,
            structured_output,
        }
    }

    /// Text is required.
    pub const fn text_only() -> Self {
        Self {
            text: true,
            image: false,
            structured_output: false,
        }
    }

    /// Text and structured output are required.
    pub const fn text_with_schema() -> Self {
        Self {
            text: true,
            image: false,
            structured_output: true,
        }
    }

    /// Whether text is required.
    pub const fn requires_text(self) -> bool {
        self.text
    }

    /// Whether image bytes are required.
    pub const fn requires_image(self) -> bool {
        self.image
    }

    /// Whether structured output is required.
    pub const fn requires_structured_output(self) -> bool {
        self.structured_output
    }
}

/// Conservative adoption thresholds for one profile.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileThresholds {
    completion_met: Option<f64>,
    completion_unmet: Option<f64>,
    permission_allow: Option<f64>,
    permission_deny: Option<f64>,
    distribution_tolerance: f64,
}

impl ProfileThresholds {
    /// Thresholds for a normal LLM.
    ///
    /// Normal LLMs do not report calibrated selection probabilities, so no
    /// numeric probability threshold is fabricated for them.
    pub const fn normal_llm() -> Self {
        Self {
            completion_met: None,
            completion_unmet: None,
            permission_allow: None,
            permission_deny: None,
            distribution_tolerance: H2_DISTRIBUTION_TOLERANCE,
        }
    }

    /// H2 conservative Decision thresholds.
    pub const fn decisions() -> Self {
        Self {
            completion_met: Some(H2_COMPLETION_MET_THRESHOLD),
            completion_unmet: Some(H2_COMPLETION_UNMET_THRESHOLD),
            permission_allow: Some(H2_PERMISSION_ALLOW_THRESHOLD),
            permission_deny: Some(H2_PERMISSION_DENY_THRESHOLD),
            distribution_tolerance: H2_DISTRIBUTION_TOLERANCE,
        }
    }

    /// Creates explicit thresholds.
    ///
    /// Values must be finite and within `0..=1`; the provider-shape check in
    /// [`AssessmentProfile::new`] decides whether probability thresholds are
    /// allowed. A threshold below the H2 default is a deliberate profile
    /// version change and must be confirmed by a human before use; it is not
    /// silently normalized.
    pub fn new(
        completion_met: Option<f64>,
        completion_unmet: Option<f64>,
        permission_allow: Option<f64>,
        permission_deny: Option<f64>,
        distribution_tolerance: f64,
    ) -> Result<Self, SupervisionError> {
        for (field, value) in [
            ("thresholds.completionMet", completion_met),
            ("thresholds.completionUnmet", completion_unmet),
            ("thresholds.permissionAllow", permission_allow),
            ("thresholds.permissionDeny", permission_deny),
        ] {
            if let Some(value) = value
                && (!value.is_finite() || !(0.0..=1.0).contains(&value))
            {
                return Err(SupervisionError::InvalidValue {
                    field: field.to_owned(),
                    detail: "threshold must be finite and between 0 and 1".to_owned(),
                });
            }
        }
        if !distribution_tolerance.is_finite()
            || !(0.0..=H2_DISTRIBUTION_TOLERANCE).contains(&distribution_tolerance)
        {
            return Err(SupervisionError::InvalidValue {
                field: "thresholds.distributionTolerance".to_owned(),
                detail: "tolerance must be finite, non-negative, and no larger than the H2 default"
                    .to_owned(),
            });
        }
        Ok(Self {
            completion_met,
            completion_unmet,
            permission_allow,
            permission_deny,
            distribution_tolerance,
        })
    }

    /// Default thresholds for a provider kind.
    pub const fn for_provider(provider: ProviderKind) -> Self {
        if provider.has_probabilities() {
            Self::decisions()
        } else {
            Self::normal_llm()
        }
    }

    /// Completion `met` threshold, when the provider reports probabilities.
    pub const fn completion_met(self) -> Option<f64> {
        self.completion_met
    }

    /// Completion `unmet` threshold, when the provider reports probabilities.
    pub const fn completion_unmet(self) -> Option<f64> {
        self.completion_unmet
    }

    /// Permission `allow` threshold, when the provider reports probabilities.
    pub const fn permission_allow(self) -> Option<f64> {
        self.permission_allow
    }

    /// Permission `deny` threshold, when the provider reports probabilities.
    pub const fn permission_deny(self) -> Option<f64> {
        self.permission_deny
    }

    /// Distribution-sum tolerance.
    pub const fn distribution_tolerance(self) -> f64 {
        self.distribution_tolerance
    }

    /// Whether a Decision threshold is below the conservative H2 default and
    /// therefore requires a new human-approved profile version before use.
    pub fn below_h2_defaults(self, provider: ProviderKind) -> bool {
        if !provider.has_probabilities() {
            return false;
        }
        [
            (self.completion_met, H2_COMPLETION_MET_THRESHOLD),
            (self.completion_unmet, H2_COMPLETION_UNMET_THRESHOLD),
            (self.permission_allow, H2_PERMISSION_ALLOW_THRESHOLD),
            (self.permission_deny, H2_PERMISSION_DENY_THRESHOLD),
        ]
        .into_iter()
        .any(|(value, default)| value.is_some_and(|value| value < default))
    }

    fn validate_for(self, provider: ProviderKind) -> Result<(), SupervisionError> {
        if provider.has_probabilities() {
            for (field, value) in [
                ("thresholds.completionMet", self.completion_met),
                ("thresholds.completionUnmet", self.completion_unmet),
                ("thresholds.permissionAllow", self.permission_allow),
                ("thresholds.permissionDeny", self.permission_deny),
            ] {
                let value = value.ok_or(SupervisionError::InvalidValue {
                    field: field.to_owned(),
                    detail: "a Decision profile requires an explicit threshold".to_owned(),
                })?;
                if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                    return Err(SupervisionError::InvalidValue {
                        field: field.to_owned(),
                        detail: "threshold must be finite and between 0 and 1".to_owned(),
                    });
                }
            }
        } else if self.completion_met.is_some()
            || self.completion_unmet.is_some()
            || self.permission_allow.is_some()
            || self.permission_deny.is_some()
        {
            return Err(SupervisionError::InvalidValue {
                field: "thresholds".to_owned(),
                detail: "a normal LLM has no calibrated probability threshold".to_owned(),
            });
        }
        if !self.distribution_tolerance.is_finite()
            || !(0.0..=H2_DISTRIBUTION_TOLERANCE).contains(&self.distribution_tolerance)
        {
            return Err(SupervisionError::InvalidValue {
                field: "thresholds.distributionTolerance".to_owned(),
                detail: "tolerance must be finite, non-negative, and no larger than the H2 default"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

/// One purpose-specific assessment profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProfile {
    id: ProfileId,
    version: ProfileVersion,
    purpose: ProfilePurpose,
    provider: ProviderKind,
    connection: ConnectionId,
    model: ModelId,
    adapter_version: AdapterVersion,
    rubric_version: RubricVersion,
    required_inputs: ProfileInputs,
    thresholds: ProfileThresholds,
}

impl AssessmentProfile {
    /// Creates a validated profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ProfileId,
        version: ProfileVersion,
        purpose: ProfilePurpose,
        provider: ProviderKind,
        connection: ConnectionId,
        model: ModelId,
        adapter_version: AdapterVersion,
        rubric_version: RubricVersion,
        required_inputs: ProfileInputs,
        thresholds: ProfileThresholds,
    ) -> Result<Self, SupervisionError> {
        thresholds.validate_for(provider)?;
        if !required_inputs.text {
            return Err(SupervisionError::InvalidValue {
                field: "profile.requiredInputs.text".to_owned(),
                detail: "every assessment profile requires text input".to_owned(),
            });
        }
        Ok(Self {
            id,
            version,
            purpose,
            provider,
            connection,
            model,
            adapter_version,
            rubric_version,
            required_inputs,
            thresholds,
        })
    }

    /// Profile identifier.
    pub const fn id(&self) -> ProfileId {
        self.id
    }

    /// Fixed profile version.
    pub const fn version(&self) -> ProfileVersion {
        self.version
    }

    /// Assessment purpose.
    pub const fn purpose(&self) -> ProfilePurpose {
        self.purpose
    }

    /// Provider kind.
    pub const fn provider(&self) -> ProviderKind {
        self.provider
    }

    /// Connection selected for assessment.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Selected model alias.
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

    /// Required input capabilities.
    pub const fn required_inputs(&self) -> ProfileInputs {
        self.required_inputs
    }

    /// Adoption thresholds.
    pub const fn thresholds(&self) -> ProfileThresholds {
        self.thresholds
    }

    /// Fixed binding stored in a supervision contract.
    pub fn binding(&self) -> ProfileBinding {
        ProfileBinding {
            profile_id: self.id,
            version: self.version,
            purpose: self.purpose,
        }
    }
}

/// Exact profile identity fixed at supervision start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileBinding {
    profile_id: ProfileId,
    version: ProfileVersion,
    purpose: ProfilePurpose,
}

impl ProfileBinding {
    /// Creates a binding.
    pub const fn new(
        profile_id: ProfileId,
        version: ProfileVersion,
        purpose: ProfilePurpose,
    ) -> Self {
        Self {
            profile_id,
            version,
            purpose,
        }
    }

    /// Profile identifier.
    pub const fn profile_id(self) -> ProfileId {
        self.profile_id
    }

    /// Fixed version.
    pub const fn version(self) -> ProfileVersion {
        self.version
    }

    /// Purpose.
    pub const fn purpose(self) -> ProfilePurpose {
        self.purpose
    }

    /// Ensures the binding belongs to `project`.
    pub fn ensure_project(self, project: ProjectId) -> Result<(), SupervisionError> {
        verify_scoped(&self.profile_id, project)
    }

    /// Whether `profile` is exactly the bound profile and version.
    pub fn matches(self, profile: &AssessmentProfile) -> bool {
        self.profile_id == profile.id
            && self.version == profile.version
            && self.purpose == profile.purpose
    }
}

/// Why a profile cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ProfileUnavailable {
    /// No profile is configured for this purpose.
    Unset {
        /// Requested purpose.
        purpose: ProfilePurpose,
    },
    /// The configured profile is a different version than the fixed binding.
    VersionMismatch {
        /// Fixed version.
        bound: u64,
        /// Configured version.
        configured: u64,
    },
    /// The configured profile is a different profile than the fixed binding.
    ProfileMismatch {
        /// Bound profile.
        bound: String,
        /// Configured profile.
        configured: String,
    },
    /// The configured profile has a different purpose.
    PurposeMismatch {
        /// Bound purpose.
        bound: ProfilePurpose,
        /// Configured purpose.
        configured: ProfilePurpose,
    },
    /// The profile requires an input the connection does not declare.
    MissingInput {
        /// Missing modality.
        modality: InputModality,
    },
    /// The profile requires structured output that is not available.
    MissingStructuredOutput,
    /// The connection is not currently available.
    ConnectionNotAvailable {
        /// Reported status.
        status: ConnectionStatus,
    },
    /// The connection does not exist in the profile registry.
    ConnectionMissing,
    /// The provider kind and endpoint class do not belong together.
    ProviderMismatch {
        /// Declared provider kind.
        provider: ProviderKind,
        /// Connection endpoint class.
        endpoint: EndpointClass,
    },
    /// The connection cannot carry assessment requests.
    AssessmentNotAllowed,
    /// A normal LLM profile cannot use probability thresholds, and a Decision
    /// profile cannot omit them.
    ConfidenceModelMismatch,
    /// The run model was offered as a silent substitute for the judge model.
    RunModelSubstitutionRejected,
}

/// One configured profile plus the connection facts needed to use it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileEntry {
    profile: AssessmentProfile,
    connection: ConnectionCapabilities,
    status: ConnectionStatus,
    structured_output: bool,
}

impl ProfileEntry {
    /// Creates a profile entry. Validation happens on resolution.
    pub fn new(
        profile: AssessmentProfile,
        connection: ConnectionCapabilities,
        status: ConnectionStatus,
        structured_output: bool,
    ) -> Self {
        Self {
            profile,
            connection,
            status,
            structured_output,
        }
    }

    /// Profile value.
    pub fn profile(&self) -> &AssessmentProfile {
        &self.profile
    }

    /// Connection capabilities.
    pub fn connection(&self) -> &ConnectionCapabilities {
        &self.connection
    }

    /// Current connection status.
    pub const fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// Whether structured output is available on the connection.
    pub const fn structured_output(&self) -> bool {
        self.structured_output
    }

    /// Validates the profile against its connection.
    pub fn validate(&self) -> Result<(), SupervisionError> {
        let unavailable = |reason| SupervisionError::ProfileUnavailable { reason };
        if self.profile.connection != self.connection.connection_id() {
            return Err(unavailable(ProfileUnavailable::ConnectionMissing));
        }
        if self.status != ConnectionStatus::Available {
            return Err(unavailable(ProfileUnavailable::ConnectionNotAvailable {
                status: self.status,
            }));
        }
        if !self.connection.allows_assessment() {
            return Err(unavailable(ProfileUnavailable::AssessmentNotAllowed));
        }
        let expected_provider = match self.profile.provider {
            ProviderKind::NormalLlm => !self.connection.endpoint_class().is_assessment_only(),
            ProviderKind::Jev => {
                self.connection.endpoint_class() == EndpointClass::TypeSafeSystemOne
            }
            ProviderKind::Decisions => {
                self.connection.endpoint_class() == EndpointClass::OpenAiDecisions
            }
        };
        if !expected_provider {
            return Err(unavailable(ProfileUnavailable::ProviderMismatch {
                provider: self.profile.provider,
                endpoint: self.connection.endpoint_class(),
            }));
        }
        let required = self.profile.required_inputs;
        if required.requires_text() && !self.connection.input().supports_text() {
            return Err(unavailable(ProfileUnavailable::MissingInput {
                modality: InputModality::Text,
            }));
        }
        if required.requires_image() && !self.connection.input().supports_image() {
            return Err(unavailable(ProfileUnavailable::MissingInput {
                modality: InputModality::Image,
            }));
        }
        if required.requires_structured_output() && !self.structured_output {
            return Err(unavailable(ProfileUnavailable::MissingStructuredOutput));
        }
        self.profile
            .thresholds
            .validate_for(self.profile.provider)
            .map_err(|_| unavailable(ProfileUnavailable::ConfidenceModelMismatch))?;
        Ok(())
    }
}

/// Profiles configured for one project.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileCatalog {
    project_id: Option<ProjectId>,
    entries: BTreeMap<ProfilePurpose, ProfileEntry>,
}

impl ProfileCatalog {
    /// Creates an empty catalog. An empty catalog makes every purpose unusable.
    pub const fn unset() -> Self {
        Self {
            project_id: None,
            entries: BTreeMap::new(),
        }
    }

    /// Creates an empty catalog bound to `project`.
    pub const fn for_project(project_id: ProjectId) -> Self {
        Self {
            project_id: Some(project_id),
            entries: BTreeMap::new(),
        }
    }

    /// Installs or replaces the profile for its purpose.
    pub fn insert(&mut self, entry: ProfileEntry) -> Result<(), SupervisionError> {
        let project = entry.profile.id.project_id();
        match self.project_id {
            Some(expected) if expected != project => {
                return Err(SupervisionError::CrossProjectReference {
                    id_kind: "profile".to_owned(),
                    expected,
                    found: project,
                });
            }
            None => self.project_id = Some(project),
            _ => {}
        }
        self.entries.insert(entry.profile.purpose, entry);
        Ok(())
    }

    /// Resolves the exact profile for `purpose`.
    ///
    /// There is no cross-purpose, cross-provider, or run-model fallback.
    pub fn resolve(&self, purpose: ProfilePurpose) -> Result<AssessmentProfile, SupervisionError> {
        let entry = self
            .entries
            .get(&purpose)
            .ok_or(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::Unset { purpose },
            })?;
        entry.validate()?;
        Ok(entry.profile.clone())
    }

    /// Resolves the exact profile fixed in a supervision contract.
    pub fn resolve_bound(
        &self,
        binding: ProfileBinding,
    ) -> Result<AssessmentProfile, SupervisionError> {
        let entry =
            self.entries
                .get(&binding.purpose)
                .ok_or(SupervisionError::ProfileUnavailable {
                    reason: ProfileUnavailable::Unset {
                        purpose: binding.purpose,
                    },
                })?;
        if entry.profile.id != binding.profile_id {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::ProfileMismatch {
                    bound: binding.profile_id.to_string(),
                    configured: entry.profile.id.to_string(),
                },
            });
        }
        if entry.profile.version != binding.version {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::VersionMismatch {
                    bound: binding.version.get(),
                    configured: entry.profile.version.get(),
                },
            });
        }
        if entry.profile.purpose != binding.purpose {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::PurposeMismatch {
                    bound: binding.purpose,
                    configured: entry.profile.purpose,
                },
            });
        }
        entry.validate()?;
        Ok(entry.profile.clone())
    }

    /// Whether any profile is configured for `purpose`.
    pub fn contains(&self, purpose: ProfilePurpose) -> bool {
        self.entries.contains_key(&purpose)
    }
}

/// Rejects a run model offered as the assessment model without a profile.
pub fn reject_run_model_substitution(
    run_model: &ModelId,
    profile: Option<&AssessmentProfile>,
) -> Result<(), SupervisionError> {
    match profile {
        Some(profile) if profile.model() == run_model => {
            Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::RunModelSubstitutionRejected,
            })
        }
        Some(_) => Ok(()),
        None => Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::Unset {
                purpose: ProfilePurpose::Completion,
            },
        }),
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
    if trimmed.chars().count() > 512 {
        return Err(SupervisionError::InvalidValue {
            field: field.to_owned(),
            detail: "must contain at most 512 characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}
