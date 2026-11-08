//! Normal-LLM per-condition assessment adapter.
//!
//! The adapter turns one supervision [`AssessmentRequest`] and the exact
//! caller-supplied evidence documents into a provider-specific, tool-less
//! request, sends it through the [`AssessmentTransport`], and turns the answer
//! into one strict [`ConditionVerdict`].
//!
//! It deliberately owns no conversation, repository, store, budget, or
//! credential access. It never fetches evidence, never falls back to another
//! provider/model/connection, and never treats a self-reported confidence or
//! probability as a calibrated value.

mod request;
mod wire;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult, ConditionVerdict,
    RationaleOrigin,
};
use herness_supervision::error::SupervisionError;
use herness_supervision::ids::EvidenceId;
use herness_supervision::ports::ClockPort;
use herness_supervision::profiles::{
    ProfileEntry, ProfilePurpose, ProfileUnavailable, ProviderKind,
};

use crate::error::{AssessmentError, AssessmentErrorKind};
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, ImageInput, TransportControl,
};

use self::request::Route;
use self::wire::ParsedCondition;

const MAX_EVIDENCE_DOCUMENTS: usize = 64;
const MAX_EVIDENCE_TEXT_CHARS: usize = 100_000;
const MAX_EVIDENCE_TOTAL_CHARS: usize = 500_000;

/// One caller-supplied evidence document.
///
/// The document contains only the ID and the content the caller explicitly
/// decided to disclose. The adapter never reads a file, conversation, shell
/// output, or repository to complete it. Debug output reports the ID and size,
/// never the content.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceDocument {
    id: EvidenceId,
    content: EvidenceContent,
}

/// Content of one caller-supplied evidence document.
#[derive(Clone, PartialEq, Eq)]
pub enum EvidenceContent {
    /// UTF-8 text, source, diff, or log content.
    Text(String),
    /// Caller-provided image bytes.
    Image(ImageInput),
}

impl EvidenceDocument {
    /// Creates a text evidence document.
    pub fn text(id: EvidenceId, text: impl Into<String>) -> Result<Self, AssessmentError> {
        let text = text.into();
        if text.chars().count() > MAX_EVIDENCE_TEXT_CHARS {
            return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
        }
        Ok(Self {
            id,
            content: EvidenceContent::Text(text),
        })
    }

    /// Creates an image evidence document from caller-provided bytes.
    pub fn image(
        id: EvidenceId,
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, AssessmentError> {
        Ok(Self {
            id,
            content: EvidenceContent::Image(ImageInput::new(media_type, bytes)?),
        })
    }

    /// Evidence identifier.
    pub const fn id(&self) -> EvidenceId {
        self.id
    }

    /// Supplied content.
    pub const fn content(&self) -> &EvidenceContent {
        &self.content
    }

    fn image_input(&self) -> Option<&ImageInput> {
        match &self.content {
            EvidenceContent::Image(image) => Some(image),
            EvidenceContent::Text(_) => None,
        }
    }

    fn text_len(&self) -> usize {
        match &self.content {
            EvidenceContent::Text(text) => text.chars().count(),
            EvidenceContent::Image(_) => 0,
        }
    }
}

impl fmt::Debug for EvidenceDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, size) = match &self.content {
            EvidenceContent::Text(text) => ("text", text.chars().count()),
            EvidenceContent::Image(image) => ("image", image.bytes().len()),
        };
        f.debug_struct("EvidenceDocument")
            .field("id", &self.id)
            .field("kind", &kind)
            .field("size", &size)
            .finish()
    }
}

/// Why a provider answer was not usable as a condition verdict.
///
/// Every reason maps to an `insufficient` result. The value is a diagnostic
/// label only; it never contains provider text or evidence content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InconclusiveReason {
    /// The answer was not valid JSON.
    InvalidJson,
    /// The JSON did not match the strict condition schema.
    SchemaViolation,
    /// A required schema field was missing.
    MissingField,
    /// The answer named another condition.
    UnknownCondition,
    /// The answer contained more than one condition verdict.
    MultipleConditions,
    /// An evidence ID was malformed or outside the supplied set.
    UnknownEvidence,
    /// The same evidence ID appeared twice.
    DuplicateEvidence,
    /// A verdict was not supported by any cited evidence.
    MissingEvidence,
    /// The provider refused to answer.
    Refusal,
    /// The provider answer was truncated or incomplete.
    Truncated,
    /// The provider returned an empty answer.
    EmptyAnswer,
    /// The answer attempted tool use.
    ToolUse,
    /// The provider returned several competing answers.
    MultipleAnswers,
    /// The provider failed before producing an answer.
    ProviderFailure,
}

impl InconclusiveReason {
    /// Stable diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::SchemaViolation => "schema_violation",
            Self::MissingField => "missing_field",
            Self::UnknownCondition => "unknown_condition",
            Self::MultipleConditions => "multiple_conditions",
            Self::UnknownEvidence => "unknown_evidence",
            Self::DuplicateEvidence => "duplicate_evidence",
            Self::MissingEvidence => "missing_evidence",
            Self::Refusal => "refusal",
            Self::Truncated => "truncated",
            Self::EmptyAnswer => "empty_answer",
            Self::ToolUse => "tool_use",
            Self::MultipleAnswers => "multiple_answers",
            Self::ProviderFailure => "provider_failure",
        }
    }

    const fn rationale(self) -> &'static str {
        match self {
            Self::InvalidJson => {
                "The model answer was not valid JSON; the condition cannot be decided."
            }
            Self::SchemaViolation => {
                "The model answer did not match the required condition schema; the condition cannot be decided."
            }
            Self::MissingField => {
                "The model answer omitted a required field; the condition cannot be decided."
            }
            Self::UnknownCondition => {
                "The model answer named another condition; the condition cannot be decided."
            }
            Self::MultipleConditions => {
                "The model answer contained more than one condition verdict; the condition cannot be decided."
            }
            Self::UnknownEvidence => {
                "The model answer cited evidence outside the supplied set; the condition cannot be decided."
            }
            Self::DuplicateEvidence => {
                "The model answer cited the same evidence more than once; the condition cannot be decided."
            }
            Self::MissingEvidence => {
                "The model answer returned a verdict without citing evidence; the condition cannot be decided."
            }
            Self::Refusal => {
                "The model refused to assess the condition; the condition cannot be decided."
            }
            Self::Truncated => {
                "The model answer was incomplete or truncated; the condition cannot be decided."
            }
            Self::EmptyAnswer => {
                "The model returned an empty answer; the condition cannot be decided."
            }
            Self::ToolUse => {
                "The model attempted tool use during a tool-less assessment; the condition cannot be decided."
            }
            Self::MultipleAnswers => {
                "The model returned several competing answers; the condition cannot be decided."
            }
            Self::ProviderFailure => {
                "The provider failed to produce an assessment; the condition cannot be decided."
            }
        }
    }
}

/// Result of one normal-LLM assessment.
///
/// `rejection()` is `None` only when the answer matched the strict schema. An
/// unusable answer still produces an `AssessmentResult` whose reported verdict
/// is `insufficient`; it is never silently upgraded to `met`.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmAssessment {
    result: AssessmentResult,
    rejection: Option<InconclusiveReason>,
}

impl LlmAssessment {
    /// The assessment result to store in supervision history.
    pub const fn result(&self) -> &AssessmentResult {
        &self.result
    }

    /// Schema/refusal/truncation reason, when the answer was unusable.
    pub const fn rejection(&self) -> Option<InconclusiveReason> {
        self.rejection
    }

    /// Consumes the wrapper and returns the result.
    pub fn into_result(self) -> AssessmentResult {
        self.result
    }
}

/// Normal-LLM assessment adapter over the tool-less transport.
pub struct LlmAssessmentAdapter {
    transport: AssessmentTransport,
    clock: Arc<dyn ClockPort + Send + Sync>,
}

impl LlmAssessmentAdapter {
    /// Creates an adapter that uses the exact connection selected by the
    /// profile and the injected host clock.
    pub fn new(transport: AssessmentTransport, clock: Arc<dyn ClockPort + Send + Sync>) -> Self {
        Self { transport, clock }
    }

    /// Assesses exactly one condition using exactly the supplied evidence.
    ///
    /// A capability deficiency is returned as an error before any HTTP request.
    /// Transport failures keep their sanitized [`AssessmentError`]. A provider
    /// answer that cannot be used as a strict condition verdict returns an
    /// `insufficient` result with a rejection reason.
    pub fn assess(
        &self,
        request: &AssessmentRequest,
        entry: &ProfileEntry,
        evidence: &[EvidenceDocument],
        control: TransportControl,
    ) -> Result<LlmAssessment, AssessmentError> {
        let registered = self.transport.capabilities(entry.profile().connection())?;
        if &registered != entry.connection() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::ProfileBindingMismatch,
            ));
        }
        let preflight = Preflight::new(request, entry, evidence)?;
        let provenance = provenance(request, entry)?;
        let body = request::build(
            preflight.route,
            entry.profile(),
            request,
            evidence,
            preflight.native_structured_output,
        )?;
        let mut transport_request = TransportRequest::new(
            entry.profile().connection(),
            entry.profile().model().as_str(),
            body,
        )?;
        for image in &preflight.images {
            transport_request = transport_request.with_image(image.clone());
        }
        let response = self.transport.send(transport_request, control)?;
        let (verdict, cited, rationale, uncertainty, rejection) =
            match wire::extract_text(preflight.route, response.body()) {
                Ok(text) => match wire::parse_condition(&text, request, &preflight.requested) {
                    Ok(ParsedCondition {
                        verdict,
                        evidence,
                        rationale,
                        uncertainty,
                    }) => (verdict, evidence, rationale, uncertainty, None),
                    Err(reason) => (
                        ConditionVerdict::Insufficient,
                        request.evidence().to_vec(),
                        reason.rationale().to_owned(),
                        None,
                        Some(reason),
                    ),
                },
                Err(reason) => (
                    ConditionVerdict::Insufficient,
                    request.evidence().to_vec(),
                    reason.rationale().to_owned(),
                    None,
                    Some(reason),
                ),
            };
        let rationale_origin = if rejection.is_some() {
            RationaleOrigin::Host
        } else {
            RationaleOrigin::Model
        };
        let result = AssessmentResult::new(
            request,
            cited,
            rationale,
            uncertainty,
            AssessmentOutcome::NormalLlm {
                verdict,
                confidence: None,
            },
            provenance,
            self.clock.now(),
        )
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::InvalidResponse))?
        .with_rationale_origin(rationale_origin);
        Ok(LlmAssessment { result, rejection })
    }
}

struct Preflight {
    route: Route,
    images: Vec<ImageInput>,
    requested: BTreeSet<EvidenceId>,
    native_structured_output: bool,
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
            || !request.profile().matches(profile)
            || request.adapter_version() != profile.adapter_version()
            || request.rubric_version() != profile.rubric_version()
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::ProfileBindingMismatch,
            ));
        }
        let route = Route::for_capabilities(entry.connection())?;
        let required = profile.required_inputs();
        if required.requires_structured_output()
            && (!entry.structured_output() || !route.supports_native_structured_output())
        {
            return Err(AssessmentError::new(
                AssessmentErrorKind::StructuredOutputUnavailable,
            ));
        }
        if required.requires_image() && !entry.connection().input().supports_image() {
            return Err(AssessmentError::new(
                AssessmentErrorKind::UnsupportedModality,
            ));
        }
        let mut images = Vec::new();
        for document in evidence {
            if let Some(image) = document.image_input() {
                if !entry.connection().input().supports_image() {
                    return Err(AssessmentError::new(
                        AssessmentErrorKind::UnsupportedModality,
                    ));
                }
                images.push(image.clone());
            }
        }
        let requested = validate_evidence(request, evidence)?;
        Ok(Self {
            route,
            images,
            requested,
            native_structured_output: required.requires_structured_output(),
        })
    }
}

fn validate_evidence(
    request: &AssessmentRequest,
    evidence: &[EvidenceDocument],
) -> Result<BTreeSet<EvidenceId>, AssessmentError> {
    if evidence.len() > MAX_EVIDENCE_DOCUMENTS {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    let project = request.project_id();
    let mut total = 0_usize;
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
        total = total.saturating_add(document.text_len());
    }
    if total > MAX_EVIDENCE_TOTAL_CHARS {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    let requested: BTreeSet<EvidenceId> = request.evidence().iter().copied().collect();
    if requested.len() != evidence.len() {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    if seen != requested {
        return Err(AssessmentError::new(AssessmentErrorKind::InvalidEvidence));
    }
    Ok(requested)
}

fn profile_error(reason: ProfileUnavailable) -> AssessmentError {
    match reason {
        ProfileUnavailable::MissingStructuredOutput => {
            AssessmentError::new(AssessmentErrorKind::StructuredOutputUnavailable)
        }
        ProfileUnavailable::MissingInput { .. } => {
            AssessmentError::new(AssessmentErrorKind::UnsupportedModality)
        }
        _ => AssessmentError::new(AssessmentErrorKind::CapabilityMismatch),
    }
}

fn provenance(
    request: &AssessmentRequest,
    entry: &ProfileEntry,
) -> Result<AssessmentProvenance, AssessmentError> {
    AssessmentProvenance::new(
        entry.connection().provider(),
        ProviderKind::NormalLlm,
        entry.profile().model().clone(),
        request.adapter_version().clone(),
        request.rubric_version().clone(),
    )
    .map_err(|_| AssessmentError::new(AssessmentErrorKind::CapabilityMismatch))
}
