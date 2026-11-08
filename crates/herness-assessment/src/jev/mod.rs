//! Jev (TypeSafe System One) per-condition choice assessment adapter.
//!
//! The adapter turns one supervision [`AssessmentRequest`] and the exact
//! caller-supplied evidence documents into a tool-less `POST /v1/systemone`
//! request, then validates the returned choice distribution.
//!
//! It owns no conversation, repository, store, budget, or credential access.
//! It never falls back to another provider/model/connection, never truncates
//! evidence into a passing assessment, and never treats the provider-native
//! confidence as a calibrated probability.

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
use crate::llm::{EvidenceContent, EvidenceDocument};
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, ImageInput, TransportControl,
};

/// Fixed versioned Jev model requested in every System One call.
///
/// Aliases such as `jev-latest` and `jev-preview` move. The response must
/// report this fixed ID; an alias or another version is not a reusable
/// evaluation.
pub const JEV_REQUEST_MODEL: &str = "jev-1.14.0";

/// Provider-specific scale label for the Jev `confidence` field.
///
/// This value is a derived statistic, not the probability of correctness, and
/// is never compared with the completion thresholds.
pub const JEV_CONFIDENCE_SCALE: &str = "typesafe-jev-choice-confidence";

const MAX_EVIDENCE_DOCUMENTS: usize = 64;
const MAX_EVIDENCE_TEXT_BYTES: usize = 24_000;
const MAX_REQUEST_TEXT_BYTES: usize = 32_000;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const INSTRUCTION_RESERVE_BYTES: usize = 4_096;
const PER_DOCUMENT_RESERVE_BYTES: usize = 256;
const MIN_IMAGE_DIMENSION: u32 = 280;
const MAX_IMAGE_DIMENSION: u32 = 1_568;
const MIN_IMAGE_PIXELS: u64 = 78_400;
const MAX_IMAGE_PIXELS: u64 = 2_458_624;

const VALID_RATIONALE: &str = "Host note: the Jev System One choice response contains no model rationale; the returned distribution is recorded unchanged.";

/// Stable per-request question ID.
///
/// The decision/request identifier is project-scoped and idempotent, so a
/// retried request uses the same question name while a different assessment
/// uses a different one.
pub fn jev_question_id(request: &AssessmentRequest) -> String {
    request.id().to_string()
}

/// Why a Jev answer was not usable as a condition verdict.
///
/// Every reason maps to an `insufficient` result. The label never contains
/// provider text, evidence content, or a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JevRejection {
    /// The response body was not valid JSON.
    InvalidJson,
    /// The response did not match the expected answer envelope.
    SchemaViolation,
    /// The reported model was not the fixed requested version.
    ModelMismatch,
    /// The provider returned an error envelope instead of an answer.
    ProviderFailure,
    /// The provider refused the assessment.
    Refusal,
    /// The response contained no answer for the question.
    MissingAnswer,
    /// The response contained another question or several answers.
    UnknownAnswer,
    /// A question name appeared more than once in the raw response.
    DuplicateAnswer,
    /// The answer type was not `choice`.
    WrongAnswerType,
    /// The selected choice was missing or outside the three criteria.
    InvalidChoice,
    /// The native confidence was missing, non-finite, or outside `0..=1`.
    InvalidConfidence,
    /// A required probability key was missing.
    MissingProbabilities,
    /// The distribution contained a key outside the three criteria.
    ExtraProbabilities,
    /// A probability key appeared more than once in the raw response.
    DuplicateProbability,
    /// A probability was non-numeric, non-finite, or outside `0..=1`.
    InvalidProbability,
    /// The probabilities did not sum to one within the H2 tolerance.
    ProbabilitySum,
    /// The selected choice was not the maximum-probability choice.
    SelectionNotMaximum,
}

impl JevRejection {
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
            Self::InvalidProbability => "invalid_probability",
            Self::ProbabilitySum => "probability_sum",
            Self::SelectionNotMaximum => "selection_not_maximum",
        }
    }

    /// Clearly host-owned rationale stored with the inconclusive result.
    ///
    /// Jev returns no rationale. These notes describe the host validation
    /// failure and must not be presented as model reasoning.
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::InvalidJson => {
                "Host note: the Jev System One response was not valid JSON; the condition cannot be decided."
            }
            Self::SchemaViolation => {
                "Host note: the Jev System One response did not match the expected choice envelope; the condition cannot be decided."
            }
            Self::ModelMismatch => {
                "Host note: the Jev System One response reported a model other than the fixed requested version; the evaluation is not reusable."
            }
            Self::ProviderFailure => {
                "Host note: the Jev System One provider returned an error instead of an answer; the condition cannot be decided."
            }
            Self::Refusal => {
                "Host note: the Jev System One provider refused the assessment; the condition cannot be decided."
            }
            Self::MissingAnswer => {
                "Host note: the Jev System One response omitted the requested answer; the condition cannot be decided."
            }
            Self::UnknownAnswer => {
                "Host note: the Jev System One response contained another question or several answers; the condition cannot be decided."
            }
            Self::DuplicateAnswer => {
                "Host note: the Jev System One response contained a duplicate question answer; the condition cannot be decided."
            }
            Self::WrongAnswerType => {
                "Host note: the Jev System One answer was not a choice answer; the condition cannot be decided."
            }
            Self::InvalidChoice => {
                "Host note: the Jev System One answer selected a choice outside the three criteria; the condition cannot be decided."
            }
            Self::InvalidConfidence => {
                "Host note: the Jev System One native confidence was missing or invalid; the condition cannot be decided."
            }
            Self::MissingProbabilities => {
                "Host note: the Jev System One answer omitted a required probability; the condition cannot be decided."
            }
            Self::ExtraProbabilities => {
                "Host note: the Jev System One answer contained a probability key outside the three criteria; the condition cannot be decided."
            }
            Self::DuplicateProbability => {
                "Host note: the Jev System One answer contained a duplicate probability key; the condition cannot be decided."
            }
            Self::InvalidProbability => {
                "Host note: the Jev System One answer contained a probability that was non-finite or outside 0 to 1; the condition cannot be decided."
            }
            Self::ProbabilitySum => {
                "Host note: the Jev System One probabilities did not sum to one within the allowed tolerance; the condition cannot be decided."
            }
            Self::SelectionNotMaximum => {
                "Host note: the Jev System One selected choice was not the maximum-probability choice; the condition cannot be decided."
            }
        }
    }
}

/// Token usage reported by one System One response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JevUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl JevUsage {
    /// Creates a known usage value.
    pub const fn new(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
        }
    }

    /// Billable input tokens reported by the provider.
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Output tokens reported by the provider.
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }
}

/// Result of one Jev assessment.
///
/// `rejection()` is `None` only when the response matched the fixed model and
/// the complete choice contract. An unusable answer still produces an
/// `AssessmentResult` whose reported verdict is `insufficient`; it never
/// becomes `met` or `unmet`, and no distribution or model rationale is
/// fabricated.
#[derive(Debug, Clone, PartialEq)]
pub struct JevAssessment {
    result: AssessmentResult,
    rejection: Option<JevRejection>,
    usage: Option<JevUsage>,
    attempts: u8,
}

impl JevAssessment {
    /// The assessment result to store in supervision history.
    pub const fn result(&self) -> &AssessmentResult {
        &self.result
    }

    /// Validation/refusal reason, when the answer was unusable.
    pub const fn rejection(&self) -> Option<JevRejection> {
        self.rejection
    }

    /// Provider-reported usage, when both counts were present and valid.
    ///
    /// Missing or malformed usage is `None`, never zero.
    pub const fn usage(&self) -> Option<JevUsage> {
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

/// Jev System One assessment adapter over the tool-less transport.
pub struct JevAssessmentAdapter {
    transport: AssessmentTransport,
    clock: Arc<dyn ClockPort + Send + Sync>,
}

impl JevAssessmentAdapter {
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
    ) -> Result<JevAssessment, AssessmentError> {
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
            Provider::TypeSafe,
            ProviderKind::Jev,
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
        Ok(JevAssessment {
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
            || profile.provider() != ProviderKind::Jev
            || !request.profile().matches(profile)
            || request.adapter_version() != profile.adapter_version()
            || request.rubric_version() != profile.rubric_version()
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::ProfileBindingMismatch,
            ));
        }

        let connection = entry.connection();
        if connection.provider() != Provider::TypeSafe
            || connection.endpoint_class() != EndpointClass::TypeSafeSystemOne
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
            question_id: jev_question_id(request),
            images,
        })
    }
}

fn validate_evidence(
    request: &AssessmentRequest,
    evidence: &[EvidenceDocument],
) -> Result<(), AssessmentError> {
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

#[derive(Debug, Clone, Copy)]
enum ImageFormat {
    Png,
    Jpeg,
}

fn validate_image(image: &ImageInput) -> Result<(), AssessmentError> {
    let format = match image.media_type() {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        _ => return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence)),
    };
    if image.bytes().len() > MAX_IMAGE_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let (width, height) = match format {
        ImageFormat::Png => png_dimensions(image.bytes()),
        ImageFormat::Jpeg => jpeg_dimensions(image.bytes()),
    }
    .ok_or_else(|| AssessmentError::new(AssessmentErrorKind::InvalidEvidence))?;
    let pixels = u64::from(width) * u64::from(height);
    if !(MIN_IMAGE_DIMENSION..=MAX_IMAGE_DIMENSION).contains(&width)
        || !(MIN_IMAGE_DIMENSION..=MAX_IMAGE_DIMENSION).contains(&height)
        || !(MIN_IMAGE_PIXELS..=MAX_IMAGE_PIXELS).contains(&pixels)
    {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    Ok(())
}

/// Reads PNG dimensions and rejects animated PNGs, truncated files, and files
/// that do not contain both image data and an end marker.
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.get(..8)? != SIGNATURE.as_slice() {
        return None;
    }
    if bytes.get(8..12)? != 13_u32.to_be_bytes().as_slice() {
        return None;
    }
    if bytes.get(12..16)? != b"IHDR".as_slice() {
        return None;
    }
    let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
    let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);

    let mut offset = 8_usize;
    let mut saw_image_data = false;
    let mut saw_end = false;
    while offset.saturating_add(12) <= bytes.len() {
        let length = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
        let kind = bytes.get(offset + 4..offset + 8)?;
        if kind == b"acTL".as_slice() {
            // Animated PNGs are not still images.
            return None;
        }
        if kind == b"IDAT".as_slice() {
            saw_image_data = true;
        }
        if kind == b"IEND".as_slice() {
            saw_end = true;
            break;
        }
        offset = offset.checked_add(12)?.checked_add(length)?;
        if offset > bytes.len() {
            return None;
        }
    }
    if !saw_image_data || !saw_end {
        return None;
    }
    Some((width, height))
}

/// Reads JPEG dimensions from the first start-of-frame marker.
fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut offset = 2_usize;
    while offset.saturating_add(4) <= bytes.len() {
        if bytes[offset] != 0xFF {
            return None;
        }
        let mut marker = bytes[offset + 1];
        offset += 2;
        while marker == 0xFF {
            marker = *bytes.get(offset)?;
            offset += 1;
        }
        if marker == 0xD8 || marker == 0xD9 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if marker == 0xDA {
            break;
        }
        let length = u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]) as usize;
        if length < 2 || offset.saturating_add(length) > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        ) {
            if length < 7 {
                return None;
            }
            let height =
                u16::from_be_bytes([*bytes.get(offset + 3)?, *bytes.get(offset + 4)?]) as u32;
            let width =
                u16::from_be_bytes([*bytes.get(offset + 5)?, *bytes.get(offset + 6)?]) as u32;
            return Some((width, height));
        }
        offset = offset.saturating_add(length);
    }
    None
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

    fn jpeg_fixture(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        bytes.extend_from_slice(b"JFIF\0");
        bytes.extend_from_slice(&[1, 1, 0, 0, 1, 0, 1, 0, 0]);
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    #[test]
    fn image_limits_accept_supported_png_and_jpeg_dimensions() {
        let png = ImageInput::new("image/png", png_fixture(280, 280)).expect("png");
        validate_image(&png).expect("280x280 png");
        let jpeg = ImageInput::new("image/jpeg", jpeg_fixture(640, 480)).expect("jpeg");
        validate_image(&jpeg).expect("640x480 jpeg");
    }

    #[test]
    fn image_limits_reject_dimensions_outside_the_jev_range() {
        for (width, height) in [(100, 100), (2000, 300), (280, 2800)] {
            let image =
                ImageInput::new("image/png", png_fixture(width, height)).expect("png bytes");
            assert_eq!(
                validate_image(&image).unwrap_err().kind(),
                AssessmentErrorKind::InvalidEvidence,
                "{width}x{height}"
            );
        }
        let animated_png = {
            let mut bytes = png_fixture(280, 280);
            // Insert an acTL chunk immediately after IHDR.
            let mut animated = bytes.drain(..33).collect::<Vec<_>>();
            animated.extend_from_slice(&[0, 0, 0, 8]);
            animated.extend_from_slice(b"acTL");
            animated.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
            animated.extend_from_slice(&[0, 0, 0, 0]);
            animated.extend_from_slice(&bytes);
            animated
        };
        let image = ImageInput::new("image/png", animated_png).expect("png bytes");
        assert_eq!(
            validate_image(&image).unwrap_err().kind(),
            AssessmentErrorKind::InvalidEvidence
        );
    }
}
