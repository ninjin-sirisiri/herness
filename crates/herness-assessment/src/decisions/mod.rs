//! OpenAI Decisions per-condition choice assessment adapter.
//!
//! The adapter turns one supervision [`AssessmentRequest`] and the exact
//! caller-supplied evidence documents into a tool-less `POST /v1/decisions`
//! request using the fixed `gpt-6-luna` model, then validates the returned
//! choice distribution.
//!
//! It owns no conversation, repository, store, budget, or credential access. It
//! never falls back to another provider/model/connection, never reuses a ChatGPT
//! login, never truncates evidence into a passing assessment, and never treats
//! the provider-native confidence as a calibrated probability.

mod request;
mod wire;

use std::collections::BTreeSet;
use std::sync::Arc;

use herness_core::contracts::{AuthMethod, ConnectionUsage, EndpointClass, ModelId, Provider};
use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult, ConditionVerdict,
    RationaleOrigin,
};
use herness_supervision::error::SupervisionError;
use herness_supervision::ids::EvidenceId;
use herness_supervision::ports::ClockPort;
use herness_supervision::profiles::{
    ProfileEntry, ProfilePurpose, ProfileThresholds, ProfileUnavailable, ProviderKind,
};

use crate::error::{AssessmentError, AssessmentErrorKind};
use crate::image::StillImageFormat;
use crate::llm::{EvidenceContent, EvidenceDocument};
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, ImageInput, TransportControl,
};

/// Fixed model requested in every OpenAI Decisions call.
///
/// The official Decisions API supports only this model. A response that reports
/// another ID (including an alias) is not a reusable evaluation.
pub const DECISIONS_REQUEST_MODEL: &str = "gpt-6-luna";

/// Provider-specific scale label for the Decisions `confidence` field.
///
/// This value is a derived statistic, not the probability of correctness, and is
/// never compared with the completion thresholds.
pub const DECISIONS_CONFIDENCE_SCALE: &str = "openai-decisions-choice-confidence";

const MAX_EVIDENCE_DOCUMENTS: usize = 64;
const MAX_EVIDENCE_TEXT_BYTES: usize = 1_000_000;
const MAX_REQUEST_TEXT_BYTES: usize = 1_200_000;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const INSTRUCTION_RESERVE_BYTES: usize = 8_192;
const PER_DOCUMENT_RESERVE_BYTES: usize = 256;
const MIN_IMAGE_DIMENSION: u32 = 1;
const MAX_IMAGE_DIMENSION: u32 = 8_192;
const MAX_IMAGE_PIXELS: u64 = 33_554_432;

const VALID_RATIONALE: &str = "Host note: the OpenAI Decisions choice response contains no model rationale; the returned distribution is recorded unchanged.";

/// Stable per-request question ID.
///
/// The decision/request identifier is project-scoped and idempotent, so a
/// retried request uses the same question name while a different assessment
/// uses a different one.
pub fn decisions_question_id(request: &AssessmentRequest) -> String {
    request.id().to_string()
}

/// Why a Decisions answer was not usable as a condition verdict.
///
/// Every reason maps to an `insufficient` result. The label never contains
/// provider text, evidence content, or a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionsRejection {
    /// The response body was not valid JSON.
    InvalidJson,
    /// The response did not match the expected Decisions answer envelope.
    SchemaViolation,
    /// The reported model was not the fixed requested model.
    ModelMismatch,
    /// The provider returned an error envelope instead of an answer.
    ProviderFailure,
    /// The provider refused the assessment.
    Refusal,
    /// The response contained no answer for the question.
    MissingAnswer,
    /// The response contained another question or several answers.
    UnknownAnswer,
    /// A question name appeared more than once in the response.
    DuplicateAnswer,
    /// The answer type was not `choice`.
    WrongAnswerType,
    /// The selected choice was missing or outside the three supplied values.
    InvalidChoice,
    /// The native confidence was missing, non-finite, or outside `0..=1`.
    InvalidConfidence,
    /// A required probability value was missing.
    MissingProbabilities,
    /// The distribution contained a value outside the three supplied choices.
    ExtraProbabilities,
    /// The same probability value appeared more than once.
    DuplicateProbability,
    /// The probability array was reordered relative to the supplied choices.
    ReorderedProbabilities,
    /// A probability was non-numeric, non-finite, or outside `0..=1`.
    InvalidProbability,
    /// The probabilities did not sum to one within the H2 tolerance.
    ProbabilitySum,
    /// The selected choice was not the maximum-probability choice.
    SelectionNotMaximum,
}

impl DecisionsRejection {
    /// Stable diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::SchemaViolation => "schema_violation",
            Self::ModelMismatch => "model_mismatch",
            Self::ProviderFailure => "provider_failure",
            Self::Refusal => "refusal",
            Self::MissingAnswer => "missing_answer",
            Self::UnknownAnswer => "unknown_answer",
            Self::DuplicateAnswer => "duplicate_answer",
            Self::WrongAnswerType => "wrong_answer_type",
            Self::InvalidChoice => "invalid_choice",
            Self::InvalidConfidence => "invalid_confidence",
            Self::MissingProbabilities => "missing_probabilities",
            Self::ExtraProbabilities => "extra_probabilities",
            Self::DuplicateProbability => "duplicate_probability",
            Self::ReorderedProbabilities => "reordered_probabilities",
            Self::InvalidProbability => "invalid_probability",
            Self::ProbabilitySum => "probability_sum",
            Self::SelectionNotMaximum => "selection_not_maximum",
        }
    }

    /// Clearly host-owned rationale stored with the inconclusive result.
    ///
    /// Decisions returns no rationale. These notes describe the host validation
    /// failure and must not be presented as model reasoning.
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::InvalidJson => {
                "Host note: the OpenAI Decisions response was not valid JSON; the condition cannot be decided."
            }
            Self::SchemaViolation => {
                "Host note: the OpenAI Decisions response did not match the expected choice envelope; the condition cannot be decided."
            }
            Self::ModelMismatch => {
                "Host note: the OpenAI Decisions response reported a model other than the fixed requested model; the evaluation is not reusable."
            }
            Self::ProviderFailure => {
                "Host note: the OpenAI Decisions provider returned an error instead of an answer; the condition cannot be decided."
            }
            Self::Refusal => {
                "Host note: the OpenAI Decisions provider refused the assessment; the condition cannot be decided."
            }
            Self::MissingAnswer => {
                "Host note: the OpenAI Decisions response omitted the requested answer; the condition cannot be decided."
            }
            Self::UnknownAnswer => {
                "Host note: the OpenAI Decisions response contained another question or several answers; the condition cannot be decided."
            }
            Self::DuplicateAnswer => {
                "Host note: the OpenAI Decisions response contained a duplicate question answer; the condition cannot be decided."
            }
            Self::WrongAnswerType => {
                "Host note: the OpenAI Decisions answer was not a choice answer; the condition cannot be decided."
            }
            Self::InvalidChoice => {
                "Host note: the OpenAI Decisions answer selected a choice outside the three supplied values; the condition cannot be decided."
            }
            Self::InvalidConfidence => {
                "Host note: the OpenAI Decisions native confidence was missing or invalid; the condition cannot be decided."
            }
            Self::MissingProbabilities => {
                "Host note: the OpenAI Decisions answer omitted a required probability; the condition cannot be decided."
            }
            Self::ExtraProbabilities => {
                "Host note: the OpenAI Decisions answer contained a probability value outside the three supplied choices; the condition cannot be decided."
            }
            Self::DuplicateProbability => {
                "Host note: the OpenAI Decisions answer contained a duplicate probability value; the condition cannot be decided."
            }
            Self::ReorderedProbabilities => {
                "Host note: the OpenAI Decisions probability array did not follow the supplied choice order; the condition cannot be decided."
            }
            Self::InvalidProbability => {
                "Host note: the OpenAI Decisions answer contained a probability that was non-finite or outside 0 to 1; the condition cannot be decided."
            }
            Self::ProbabilitySum => {
                "Host note: the OpenAI Decisions probabilities did not sum to one within the allowed tolerance; the condition cannot be decided."
            }
            Self::SelectionNotMaximum => {
                "Host note: the OpenAI Decisions selected choice was not the maximum-probability choice; the condition cannot be decided."
            }
        }
    }
}

/// Token usage reported by one Decisions response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionsUsage {
    input_tokens: u64,
    cached_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    output_tokens: u64,
}

impl DecisionsUsage {
    /// Creates a known usage value without cache details.
    pub const fn new(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            cached_tokens: None,
            cache_write_tokens: None,
            output_tokens,
        }
    }

    /// Attaches the optional cache detail counts.
    pub const fn with_cache_details(
        mut self,
        cached_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> Self {
        self.cached_tokens = cached_tokens;
        self.cache_write_tokens = cache_write_tokens;
        self
    }

    /// Billable input tokens reported by the provider.
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Cached input tokens included in `input_tokens`, when reported.
    pub const fn cached_tokens(self) -> Option<u64> {
        self.cached_tokens
    }

    /// Cache-write input tokens included in `input_tokens`, when reported.
    pub const fn cache_write_tokens(self) -> Option<u64> {
        self.cache_write_tokens
    }

    /// Output tokens reported by the provider.
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }
}

/// Result of one Decisions assessment.
///
/// `rejection()` is `None` only when the response matched the fixed model and
/// the complete choice contract. An unusable answer still produces an
/// `AssessmentResult` whose reported verdict is `insufficient`; it never
/// becomes `met` or `unmet`, and no distribution or model rationale is
/// fabricated.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionsAssessment {
    result: AssessmentResult,
    rejection: Option<DecisionsRejection>,
    usage: Option<DecisionsUsage>,
    attempts: u8,
}

impl DecisionsAssessment {
    /// The assessment result to store in supervision history.
    pub const fn result(&self) -> &AssessmentResult {
        &self.result
    }

    /// Validation/refusal reason, when the answer was unusable.
    pub const fn rejection(&self) -> Option<DecisionsRejection> {
        self.rejection
    }

    /// Provider-reported usage, when both counts were present and valid.
    ///
    /// Missing or malformed usage is `None`, never zero.
    pub const fn usage(&self) -> Option<DecisionsUsage> {
        self.usage
    }

    /// Number of HTTP attempts used for this assessment.
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Verdict adopted under the supplied profile thresholds.
    pub fn adopted_verdict(&self, thresholds: ProfileThresholds) -> Option<ConditionVerdict> {
        self.result.adopted_verdict(thresholds)
    }

    /// Consumes the wrapper and returns the result.
    pub fn into_result(self) -> AssessmentResult {
        self.result
    }
}

/// OpenAI Decisions assessment adapter over the tool-less transport.
pub struct DecisionsAssessmentAdapter {
    transport: AssessmentTransport,
    clock: Arc<dyn ClockPort + Send + Sync>,
}

impl DecisionsAssessmentAdapter {
    /// Creates an adapter that uses the exact connection selected by the
    /// profile and the injected host clock.
    pub fn new(transport: AssessmentTransport, clock: Arc<dyn ClockPort + Send + Sync>) -> Self {
        Self { transport, clock }
    }

    /// Assesses exactly one completion condition using exactly the supplied
    /// evidence.
    ///
    /// Capability, evidence-scope, and input-size deficiencies are returned as
    /// errors before any HTTP request. Transport failures keep their sanitized
    /// [`AssessmentError`]. A response that cannot be validated as a complete
    /// choice becomes an `insufficient` result with a rejection reason.
    pub fn assess(
        &self,
        request: &AssessmentRequest,
        entry: &ProfileEntry,
        evidence: &[EvidenceDocument],
        control: TransportControl,
    ) -> Result<DecisionsAssessment, AssessmentError> {
        let registered = self.transport.capabilities(entry.profile().connection())?;
        if &registered != entry.connection() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::ProfileBindingMismatch,
            ));
        }
        let preflight = Preflight::new(request, entry, evidence)?;
        let body = request::build(request, evidence, &preflight)?;
        let mut transport_request = TransportRequest::new(
            entry.profile().connection(),
            entry.profile().model().as_str(),
            body,
        )?;
        for image in &preflight.images {
            transport_request = transport_request.with_image(image.clone());
        }
        let response = self.transport.send(transport_request, control)?;
        let parsed = wire::parse_response(response.body(), &preflight.question_id);

        let mut provenance = AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::Decisions,
            entry.profile().model().clone(),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::InvalidResponse))?;
        if let Some(model) = parsed
            .reported_model
            .as_deref()
            .and_then(|model| ModelId::new(model).ok())
        {
            provenance = provenance.with_reported_model(model);
        }

        let wire::ParsedResponse {
            choice,
            confidence,
            usage,
            ..
        } = parsed;
        let (outcome, rationale, rejection) = match choice {
            Ok(choice) => (
                AssessmentOutcome::Decision {
                    selected: choice.selected,
                    probabilities: choice.probabilities,
                    confidence: confidence.clone(),
                },
                VALID_RATIONALE.to_owned(),
                None,
            ),
            Err(reason) => (
                AssessmentOutcome::NormalLlm {
                    verdict: ConditionVerdict::Insufficient,
                    confidence,
                },
                reason.rationale().to_owned(),
                Some(reason),
            ),
        };
        let result = AssessmentResult::new(
            request,
            request.evidence().to_vec(),
            rationale,
            None,
            outcome,
            provenance,
            self.clock.now(),
        )
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::InvalidResponse))?
        .with_rationale_origin(RationaleOrigin::Host);
        Ok(DecisionsAssessment {
            result,
            rejection,
            usage,
            attempts: response.attempts(),
        })
    }
}

/// Validated preflight state for one request.
pub(super) struct Preflight {
    pub(super) question_id: String,
    pub(super) images: Vec<ImageInput>,
}

impl Preflight {
    fn new(
        request: &AssessmentRequest,
        entry: &ProfileEntry,
        evidence: &[EvidenceDocument],
    ) -> Result<Self, AssessmentError> {
        entry.validate().map_err(|error| match error {
            SupervisionError::ProfileUnavailable { reason } => profile_error(reason),
            _ => AssessmentError::new(AssessmentErrorKind::CapabilityMismatch),
        })?;
        let project = request.project_id();
        if request.supervision_id().project_id() != project
            || request.condition_id().project_id() != project
            || request.profile().profile_id().project_id() != project
            || entry.profile().id().project_id() != project
            || request
                .evidence()
                .iter()
                .any(|evidence| evidence.project_id() != project)
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CrossProjectReference,
            ));
        }

        let profile = entry.profile();
        if request.purpose() != ProfilePurpose::Completion
            || profile.provider() != ProviderKind::Decisions
            || !request.profile().matches(profile)
            || request.adapter_version() != profile.adapter_version()
            || request.rubric_version() != profile.rubric_version()
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::ProfileBindingMismatch,
            ));
        }

        let connection = entry.connection();
        if connection.provider() != Provider::OpenAi
            || connection.endpoint_class() != EndpointClass::OpenAiDecisions
            || connection.auth_method() != AuthMethod::ApiKey
            || connection.usage() != ConnectionUsage::AssessmentOnly
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CapabilityMismatch,
            ));
        }
        if !connection.input().supports_text() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::UnsupportedModality,
            ));
        }
        if profile.required_inputs().requires_image() && !connection.input().supports_image() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::UnsupportedModality,
            ));
        }

        validate_evidence(request, evidence)?;

        let mut images = Vec::new();
        let mut text_bytes = 0_usize;
        let mut image_bytes = 0_usize;
        for document in evidence {
            match document.content() {
                EvidenceContent::Text(text) => {
                    text_bytes = text_bytes.saturating_add(text.len());
                }
                EvidenceContent::Image(image) => {
                    if !connection.input().supports_image() {
                        return Err(AssessmentError::new(
                            AssessmentErrorKind::UnsupportedModality,
                        ));
                    }
                    validate_image(image)?;
                    image_bytes = image_bytes.saturating_add(image.bytes().len());
                    images.push(image.clone());
                }
            }
        }
        if text_bytes > MAX_EVIDENCE_TEXT_BYTES || image_bytes > MAX_TOTAL_IMAGE_BYTES {
            return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
        }
        let request_text_bytes = text_bytes
            .saturating_add(request.rubric().len())
            .saturating_add(INSTRUCTION_RESERVE_BYTES)
            .saturating_add(evidence.len().saturating_mul(PER_DOCUMENT_RESERVE_BYTES));
        if request_text_bytes > MAX_REQUEST_TEXT_BYTES {
            return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
        }

        Ok(Self {
            question_id: decisions_question_id(request),
            images,
        })
    }
}

fn validate_evidence(
    request: &AssessmentRequest,
    evidence: &[EvidenceDocument],
) -> Result<(), AssessmentError> {
    if request.evidence().is_empty() || evidence.is_empty() {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    if evidence.len() > MAX_EVIDENCE_DOCUMENTS {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let project = request.project_id();
    let mut seen = BTreeSet::new();
    for document in evidence {
        if document.id().project_id() != project {
            return Err(AssessmentError::new(
                AssessmentErrorKind::CrossProjectReference,
            ));
        }
        if !seen.insert(document.id()) {
            return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
        }
    }
    let requested: BTreeSet<EvidenceId> = request.evidence().iter().copied().collect();
    if requested.len() != request.evidence().len()
        || requested.len() != evidence.len()
        || seen != requested
    {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    Ok(())
}

fn profile_error(reason: ProfileUnavailable) -> AssessmentError {
    match reason {
        ProfileUnavailable::MissingInput { .. } => {
            AssessmentError::new(AssessmentErrorKind::UnsupportedModality)
        }
        ProfileUnavailable::MissingStructuredOutput => {
            AssessmentError::new(AssessmentErrorKind::StructuredOutputUnavailable)
        }
        _ => AssessmentError::new(AssessmentErrorKind::CapabilityMismatch),
    }
}

fn validate_image(image: &ImageInput) -> Result<(), AssessmentError> {
    let format = StillImageFormat::from_media_type(image.media_type())
        .ok_or_else(|| AssessmentError::new(AssessmentErrorKind::InvalidEvidence))?;
    if image.bytes().len() > MAX_IMAGE_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let (width, height) = format
        .dimensions(image.bytes())
        .ok_or_else(|| AssessmentError::new(AssessmentErrorKind::InvalidEvidence))?;
    let pixels = u64::from(width) * u64::from(height);
    if !(MIN_IMAGE_DIMENSION..=MAX_IMAGE_DIMENSION).contains(&width)
        || !(MIN_IMAGE_DIMENSION..=MAX_IMAGE_DIMENSION).contains(&height)
        || pixels > MAX_IMAGE_PIXELS
    {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
            bytes.extend_from_slice(kind);
            bytes.extend_from_slice(data);
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        };
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &header);
        chunk(b"IDAT", &[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        chunk(b"IEND", &[]);
        bytes
    }

    #[test]
    fn image_limits_accept_small_still_images() {
        let png = ImageInput::new("image/png", png_fixture(1, 1)).expect("png");
        validate_image(&png).expect("1x1 png");
        let png = ImageInput::new("image/png", png_fixture(280, 280)).expect("png");
        validate_image(&png).expect("280x280 png");
    }

    #[test]
    fn image_limits_reject_dimensions_outside_the_decisions_range() {
        for (width, height) in [(0, 10), (8_193, 1), (8_192, 8_192)] {
            let image =
                ImageInput::new("image/png", png_fixture(width, height)).expect("png bytes");
            assert_eq!(
                validate_image(&image).unwrap_err().kind(),
                AssessmentErrorKind::InvalidEvidence,
                "{width}x{height}"
            );
        }
        let webp = ImageInput::new("image/webp", vec![1, 2, 3, 4]).expect("webp bytes");
        assert_eq!(
            validate_image(&webp).unwrap_err().kind(),
            AssessmentErrorKind::InvalidEvidence
        );
    }
}
