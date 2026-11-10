//! H3 conflict, adoption, history restore, and orphan operations.
//!
//! These are human-initiated state changes, not model tools. The crate owns the
//! verification of exact bytes, version checks, durable state, request
//! idempotency, history-before-restore ordering, and orphan accounting. It has
//! no Tauri, database, filesystem-write, or Git dependency; the host supplies
//! exact reads/writes, validation, assessment, and job control through ports.
//!
//! External HTML and invalid metadata are never overwritten silently. Adoption
//! requires a passing structural/semantic/SVG validation and a current,
//! completion-ready evaluation bound to the exact external bytes. Explicit
//! replacement and adoption go through the Task 19 [`PublicationOrchestrator`]
//! path, so final validation and old-version history still run. Restore saves
//! the current HTML/receipt to history before replacing them, never changes the
//! Markdown, and leaves the document unsynchronized with a human-wait latch.

use std::collections::BTreeSet;

use herness_core::ports::publish::PublicationArchivePort;
use herness_core::{
    ExpectedTargetVersion, NonEmptyText, OldVersionArchive, ProjectId, PublicationRequest,
    PublicationRequestId, Timestamp, hash_bytes,
};
use herness_supervision::ContentDigest;
use herness_supervision::evidence::TargetVersion;
use serde_json::Value;

use crate::document::{DocumentKey, FingerprintKind, FingerprintSet};
use crate::error::H3Error;
use crate::evidence::{AppliedEvaluation, EvidenceCheckResult, H3Condition, RequiredCheckKind};
use crate::ids::{GenerationId, PublicationId};
use crate::observer::{DependencyKind, dependency_fingerprint, html_evidence_path};
use crate::ports::{
    DocumentCommit, H3DocumentRecord, H3StorePort, HtmlSyncCommit, HtmlSyncCommitOutcome,
};
use crate::publish::{
    CandidatePublication, HostPublicationPort, PublicationFileInput, PublicationFileReadPort,
    PublicationOrchestrator, PublicationOutcome, PublicationPolicyIdentity, RECEIPT_CONTRACT,
    RECEIPT_SCHEMA, RECEIPT_VERSION,
};
use crate::request::{
    H3Operation, H3OperationOutcome, H3OperationRequest, H3OperationResult, RequestCommit,
    StoredRequestResult,
};
use crate::state::{
    Applicability, ApplicabilityReason, GenerationRecord, H3DocumentState, H3Reason, H3State,
    H3StateReasonKind, HumanWaitCause, PublicationFileJournal, PublicationFileRole,
    PublicationJournal, PublicationStatus, RequiredAction,
};

/// Result of validating the exact current companion against the current source.
///
/// A pass means the Common SDD structural stage accepted the semantic-v1
/// contract, the source-unit/semantic mapping was preserved, and SVG/figure
/// structure was accepted. It is deliberately not a publication pass: adoption
/// additionally requires a current completion-ready evaluation and the normal
/// final validation inside the publication path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentHtmlValidation {
    html_digest: ContentDigest,
    source_digest: ContentDigest,
    contract: String,
    structural: bool,
    semantic: bool,
    svg_figure: bool,
    violations: Vec<String>,
    verifier: String,
    operation: String,
    observed_at: Timestamp,
}

impl CurrentHtmlValidation {
    /// Creates a validation result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        html_digest: ContentDigest,
        source_digest: ContentDigest,
        contract: impl Into<String>,
        structural: bool,
        semantic: bool,
        svg_figure: bool,
        violations: Vec<String>,
        verifier: impl Into<String>,
        operation: impl Into<String>,
        observed_at: Timestamp,
    ) -> Result<Self, H3Error> {
        let contract = contract.into();
        if contract.trim().is_empty() {
            return Err(H3Error::empty("validationContract"));
        }
        let verifier = verifier.into();
        if verifier.trim().is_empty() {
            return Err(H3Error::empty("validationVerifier"));
        }
        let operation = operation.into();
        if operation.trim().is_empty() {
            return Err(H3Error::empty("validationOperation"));
        }
        Ok(Self {
            html_digest,
            source_digest,
            contract,
            structural,
            semantic,
            svg_figure,
            violations,
            verifier,
            operation,
            observed_at,
        })
    }

    /// Exact HTML digest validated.
    pub const fn html_digest(&self) -> &ContentDigest {
        &self.html_digest
    }

    /// Exact Markdown digest validated against.
    pub const fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    /// Declared HTML contract.
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Common structural stage accepted the document.
    pub const fn structural(&self) -> bool {
        self.structural
    }

    /// Semantic source-unit preservation passed.
    pub const fn semantic(&self) -> bool {
        self.semantic
    }

    /// SVG/figure policy structure passed.
    pub const fn svg_figure(&self) -> bool {
        self.svg_figure
    }

    /// Sanitized policy violations.
    pub fn violations(&self) -> &[String] {
        &self.violations
    }

    /// Verifier label.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Exact verification operation.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Observation time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Whether every validation layer passed without a violation.
    pub fn is_passing(&self) -> bool {
        self.structural
            && self.semantic
            && self.svg_figure
            && self.violations.is_empty()
            && self.contract == RECEIPT_CONTRACT
    }
}

/// One explicit human adoption of the current external HTML.
#[derive(Debug, Clone)]
pub struct CurrentHtmlAdoption {
    document_revision: u64,
    publication_id: PublicationId,
    generation: GenerationRecord,
    candidate_html: String,
    provenance: String,
    source_bytes: Vec<u8>,
    css: Vec<PublicationFileInput>,
    resources: Vec<PublicationFileInput>,
    policy: PublicationPolicyIdentity,
    applied: AppliedEvaluation,
    validation: CurrentHtmlValidation,
    expected_html: ExpectedTargetVersion,
    expected_receipt: ExpectedTargetVersion,
}

impl CurrentHtmlAdoption {
    /// Creates an adoption attempt. Exact byte and evaluation checks run before
    /// any file or durable state side effect.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_revision: u64,
        publication_id: PublicationId,
        generation: GenerationRecord,
        candidate_html: impl Into<String>,
        provenance: impl Into<String>,
        source_bytes: impl Into<Vec<u8>>,
        css: Vec<PublicationFileInput>,
        resources: Vec<PublicationFileInput>,
        policy: PublicationPolicyIdentity,
        applied: AppliedEvaluation,
        validation: CurrentHtmlValidation,
        expected_html: ExpectedTargetVersion,
        expected_receipt: ExpectedTargetVersion,
    ) -> Result<Self, H3Error> {
        if document_revision == 0 {
            return Err(H3Error::must_be_positive("expectedDocumentRevision"));
        }
        publication_id.validate_in(generation.document_key().project_id())?;
        if generation.candidate().is_none() {
            return Err(H3Error::invalid(
                "generation",
                "an adopted generation needs exact candidate metadata",
            ));
        }
        Ok(Self {
            document_revision,
            publication_id,
            generation,
            candidate_html: candidate_html.into(),
            provenance: provenance.into(),
            source_bytes: source_bytes.into(),
            css,
            resources,
            policy,
            applied,
            validation,
            expected_html,
            expected_receipt,
        })
    }

    /// Document being adopted.
    pub fn document(&self) -> &DocumentKey {
        self.generation.document_key()
    }

    /// Publication journal identifier.
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    /// Adopted generation.
    pub const fn generation(&self) -> &GenerationRecord {
        &self.generation
    }

    /// Exact current HTML.
    pub fn candidate_html(&self) -> &str {
        &self.candidate_html
    }

    /// Exact provenance mapping embedded in the HTML.
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// Exact source Markdown bytes.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    /// Exact CSS inputs.
    pub fn css(&self) -> &[PublicationFileInput] {
        &self.css
    }

    /// Exact resource inputs.
    pub fn resources(&self) -> &[PublicationFileInput] {
        &self.resources
    }

    /// Approved policy/pack identity.
    pub const fn policy(&self) -> &PublicationPolicyIdentity {
        &self.policy
    }

    /// Evaluation bound to the exact external HTML.
    pub const fn applied(&self) -> &AppliedEvaluation {
        &self.applied
    }

    /// Current HTML validation.
    pub const fn validation(&self) -> &CurrentHtmlValidation {
        &self.validation
    }

    /// Expected current formal HTML version.
    pub const fn expected_html(&self) -> &ExpectedTargetVersion {
        &self.expected_html
    }

    /// Expected current receipt version.
    pub const fn expected_receipt(&self) -> &ExpectedTargetVersion {
        &self.expected_receipt
    }

    /// Replaces the validation result with a host-recomputed result.
    ///
    /// The desktop composition uses this to require the real Common SDD
    /// structural/semantic/SVG validation of the exact supplied bytes instead
    /// of trusting a caller-supplied summary.
    pub fn with_validation(mut self, validation: CurrentHtmlValidation) -> Self {
        self.validation = validation;
        self
    }
}

/// Preparation outcome for one adoption.
#[derive(Debug, Clone)]
pub enum AdoptionPreparation {
    /// The exact adoption attempt may enter the publication path.
    Ready(Box<CandidatePublication>),
    /// The document or validation does not allow adoption. No side effect ran.
    WaitingHuman {
        /// Concrete human wait cause.
        cause: HumanWaitCause,
        /// Sanitized explanation.
        detail: String,
    },
    /// The document is not in an external HTML conflict.
    NotApplicable {
        /// Sanitized explanation.
        detail: String,
    },
    /// A current version or revision conflict was detected before any write.
    Conflict {
        /// Project-relative path in conflict.
        target: String,
        /// Sanitized explanation.
        detail: String,
    },
}

/// Result of an adoption operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptionOutcome {
    /// The adoption completed through the publication path.
    Adopted(PublicationOutcome),
    /// Validation/evaluation is missing or stale; the document keeps waiting.
    WaitingHuman {
        /// Concrete human wait cause.
        cause: HumanWaitCause,
        /// Sanitized explanation.
        detail: String,
    },
    /// The document was not in an external HTML conflict.
    NotApplicable {
        /// Sanitized explanation.
        detail: String,
    },
    /// A current version or revision conflict was detected before any write.
    Conflict {
        /// Project-relative path in conflict.
        target: String,
        /// Sanitized explanation.
        detail: String,
    },
}

/// One archived historical version selected by a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryVersion {
    generation: GenerationId,
    html: PublicationFileInput,
    receipt: PublicationFileInput,
}

impl HistoryVersion {
    /// Creates a selected history version for one document.
    pub fn new(
        document: &DocumentKey,
        generation: GenerationId,
        html: PublicationFileInput,
        receipt: PublicationFileInput,
    ) -> Result<Self, H3Error> {
        if html.path() != document.companion_path() {
            return Err(H3Error::invalid(
                "historyHtmlPath",
                "the history HTML path is not the document companion",
            ));
        }
        if receipt.path() != html_evidence_path(document) {
            return Err(H3Error::invalid(
                "historyReceiptPath",
                "the history receipt path is not the canonical document receipt",
            ));
        }
        Ok(Self {
            generation,
            html,
            receipt,
        })
    }

    /// Selected generation.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Exact historical HTML.
    pub const fn html(&self) -> &PublicationFileInput {
        &self.html
    }

    /// Exact historical receipt.
    pub const fn receipt(&self) -> &PublicationFileInput {
        &self.receipt
    }
}

/// Reads one exact historical version from the host's private archive.
pub trait HistoryReadPort {
    /// Returns `None` when that generation has no complete historical pair.
    fn load_version(
        &self,
        document: &DocumentKey,
        generation: GenerationId,
    ) -> Result<Option<HistoryVersion>, H3Error>;
}

/// Result of one source removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStop {
    /// No job was active for the document.
    NotRunning,
    /// The job stop was confirmed.
    Stopped,
    /// The stop could not be confirmed; do not claim orphaned yet.
    Unconfirmed,
}

/// Host boundary that stops the H1/H2 job for a removed source.
pub trait SourceJobControlPort {
    /// Stops the job for one document, if one exists.
    fn stop_source(&mut self, document: &DocumentKey) -> Result<SourceStop, H3Error>;
}

/// Result of one history restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryRestoreOutcome {
    /// The selected exact pair was restored. The document is unsynchronized.
    Restored {
        /// Restore journal identifier.
        publication: PublicationId,
        /// Selected generation.
        generation: GenerationId,
        /// Exact restored HTML digest.
        html_digest: ContentDigest,
        /// Exact restored receipt digest.
        receipt_digest: ContentDigest,
        /// Durable document revision after the restore.
        document_revision: u64,
        /// Whether this was an idempotent request replay.
        duplicate: bool,
    },
    /// The formal pair already equals the selected version; nothing changed.
    Unchanged {
        /// Selected generation.
        generation: GenerationId,
        /// Whether this was an idempotent request replay.
        duplicate: bool,
    },
    /// The current formal pair or document revision was not what was expected.
    Conflict {
        /// Project-relative path in conflict.
        target: String,
        /// Sanitized explanation.
        detail: String,
    },
    /// A stop, capacity, or permission condition requires a human.
    WaitingHuman {
        /// Concrete wait cause.
        cause: HumanWaitCause,
        /// Sanitized explanation.
        detail: String,
    },
    /// The restore is known not to have replaced the formal pair.
    NotRestored {
        /// Sanitized explanation.
        detail: String,
        /// Whether this was an idempotent request replay.
        duplicate: bool,
    },
    /// A side effect may have happened; reconciliation is required.
    ReconciliationRequired {
        /// Sanitized explanation.
        detail: String,
    },
}

/// Result of one source deletion/move ledger update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRemovalOutcome {
    /// Orphaned companion retained exactly.
    pub target: String,
    /// Remaining approved Target paths.
    pub remaining_paths: Vec<String>,
    /// New Target path for a move.
    pub new_target: Option<String>,
    /// Whether the new path is inside the approved Target scope.
    pub new_target_approved: bool,
    /// Durable document revision after the orphan commit.
    pub document_revision: u64,
    /// Whether this request replayed a stored result.
    pub duplicate: bool,
}

/// Records an external HTML or receipt change as a human-waiting conflict.
///
/// No file is written. The document keeps its source and artifacts, loses
/// current applicability, and gains a `ResolveHtmlConflict` action. Repeated
/// notifications with the same observed bytes are idempotent and add no event.
pub fn record_external_html_conflict(
    store: &mut dyn H3StorePort,
    document: &H3DocumentRecord,
    observed: Option<&ContentDigest>,
    now: Timestamp,
) -> Result<H3DocumentRecord, H3Error> {
    let state = document.state();
    let expected = state
        .fingerprints()
        .get(FingerprintKind::Candidate)
        .cloned();
    if let (Some(expected), Some(observed)) = (&expected, observed)
        && expected == observed
    {
        return Ok(document.clone());
    }
    if state.state() == H3State::WaitingHuman
        && matches!(
            state.reason().kind(),
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::ExternalHtmlConflict
            }
        )
    {
        return Ok(document.clone());
    }
    let reason = conflict_reason(state.document_key());
    let applicability = match (state.applicability().is_applicable(), expected, observed) {
        (true, Some(expected), Some(observed)) => {
            Applicability::not_applicable(ApplicabilityReason::HtmlChanged {
                expected: expected.clone(),
                observed: observed.clone(),
            })
        }
        _ => Applicability::not_applicable(ApplicabilityReason::NeverPublished),
    };
    let next = rebuild_document(state, reason, applicability, now)?;
    let event =
        crate::events::document_state_event(state.document_key(), Some(state.state()), &next, now)?;
    let mut commit = HtmlSyncCommit::new()
        .with_document(DocumentCommit::new(Some(document.revision()), next)?)
        .with_events(vec![event]);
    if let Some(cycle_id) = state.cycle_id()
        && let Some(cycle) = store.load_html_sync_cycle(state.project_id(), cycle_id)?
    {
        commit = commit.with_cycle(cycle.with_latch(crate::state::CycleLatch::WaitingHuman));
    }
    match store.commit_html_sync(commit)? {
        HtmlSyncCommitOutcome::Applied { document, .. } => {
            document.ok_or_else(|| H3Error::Storage {
                detail: "the external-conflict commit returned no document".to_owned(),
            })
        }
        HtmlSyncCommitOutcome::Duplicate { .. } => Ok(document.clone()),
    }
}

/// Prepares one adoption without any file or durable write.
///
/// The exact current bytes, current source, current CSS/resources, approval,
/// structural/semantic/SVG validation, render/structural checks, all four
/// condition results, consistency, and generation metadata must agree. A
/// structural-only validation or a stale/mismatched evaluation keeps the
/// document waiting for a human.
pub fn prepare_adoption(
    store: &mut dyn H3StorePort,
    files: &dyn PublicationFileReadPort,
    adoption: CurrentHtmlAdoption,
    now: Timestamp,
) -> Result<AdoptionPreparation, H3Error> {
    let document_key = adoption.generation.document_key().clone();
    let project = document_key.project_id();
    let settings = store
        .load_html_sync_settings(project)?
        .ok_or_else(|| H3Error::Unavailable {
            capability: "h3.adoption.settings".to_owned(),
            detail: "the project has no stored H3 settings".to_owned(),
        })?;
    let settings = settings.settings();
    let record = store
        .load_html_sync_document(project, &document_key)?
        .ok_or_else(|| H3Error::NotFound {
            record: "document state",
            id: document_key.target_path().to_owned(),
        })?;
    if !matches!(
        record.state().reason().kind(),
        H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::ExternalHtmlConflict
        }
    ) {
        return Ok(AdoptionPreparation::NotApplicable {
            detail: "the document is not waiting on an external HTML conflict".to_owned(),
        });
    }
    if record.revision() != adoption.document_revision {
        return Ok(AdoptionPreparation::Conflict {
            target: document_key.companion_path(),
            detail: format!(
                "the document revision changed: expected {}, found {}",
                adoption.document_revision,
                record.revision()
            ),
        });
    }
    if !settings.verify_fingerprint() {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the stored H3 settings no longer match their approved fingerprint".to_owned(),
        });
    }
    let Some(approval) = settings.approval() else {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the project settings carry no human configuration approval".to_owned(),
        });
    };
    if !approval.is_current_at(now) {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the human configuration approval is revoked, superseded, or expired"
                .to_owned(),
        });
    }

    let candidate_html_digest = ContentDigest::sha256(adoption.candidate_html.as_bytes());
    let source_digest = ContentDigest::sha256(&adoption.source_bytes);
    let provenance_digest = ContentDigest::sha256(adoption.provenance.as_bytes());
    let validation = &adoption.validation;
    if validation.html_digest() != &candidate_html_digest
        || validation.source_digest() != &source_digest
        || !validation.is_passing()
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the current HTML did not pass the exact structural, semantic, and SVG/figure validation"
                .to_owned(),
        });
    }

    let fingerprint = adoption.applied.binding().post_verification().clone();
    if !adoption.applied.completion_ready()
        || adoption.applied.test_only()
        || !adoption.applied.binding().is_current()
        || !adoption.applied.checks().all_pass()
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption evaluation is incomplete, stale, fake, or not all-met".to_owned(),
        });
    }
    let Some(render) = adoption.applied.checks().get(RequiredCheckKind::RealRender) else {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption evaluation has no real render check".to_owned(),
        });
    };
    if render.status() != EvidenceCheckResult::Pass || !render.origin().is_native_render() {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption real render check is not a native pass".to_owned(),
        });
    }
    for condition in H3Condition::ALL {
        if !adoption
            .applied
            .condition(condition)
            .is_some_and(|adoption| adoption.met())
        {
            return Ok(AdoptionPreparation::WaitingHuman {
                cause: HumanWaitCause::UndecidableAssessment,
                detail: format!("adoption condition {condition} is not met"),
            });
        }
    }
    if !adoption
        .applied
        .consistency()
        .is_some_and(|consistency| consistency.met())
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption whole-document consistency assessment is not met".to_owned(),
        });
    }
    if fingerprint.settings() != settings.fingerprint()
        || fingerprint.policy() != adoption.policy.digest()
        || fingerprint.pack() != adoption.policy.pack()
        || fingerprint.source() != &source_digest
        || fingerprint.candidate() != &candidate_html_digest
        || fingerprint.provenance() != &provenance_digest
        || fingerprint.profile() != approval.assessment().profile()
        || fingerprint.condition_version() != approval.owner_binding().condition_version()
        || fingerprint.condition_digest() != approval.owner_binding().conditions_digest()
        || !target_version_matches_html_range_consent(
            store,
            project,
            fingerprint.target_version(),
            approval,
        )
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption evaluation does not bind the exact current inputs and approval"
                .to_owned(),
        });
    }

    let generation = &adoption.generation;
    if !matches!(
        generation.status(),
        crate::state::GenerationStatus::Active | crate::state::GenerationStatus::Completed
    ) || generation.source().digest() != &source_digest
        || generation.candidate().is_none_or(|candidate| {
            candidate.html_digest() != &candidate_html_digest
                || candidate.provenance_digest() != &provenance_digest
                || candidate.generation_id() != generation.generation_id()
        })
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adopted generation does not describe the exact external HTML".to_owned(),
        });
    }
    if record.state().source().digest() != &source_digest {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::ExternalHtmlConflict,
            detail:
                "the Markdown source changed; adoption must be evaluated against the current source"
                    .to_owned(),
        });
    }

    let css = match collect_inputs(files, &adoption.css, DependencyKind::Css)? {
        Ok(fingerprint) => fingerprint,
        Err(detail) => {
            return Ok(AdoptionPreparation::WaitingHuman {
                cause: HumanWaitCause::UndecidableAssessment,
                detail,
            });
        }
    };
    let resources = match collect_inputs(files, &adoption.resources, DependencyKind::Resource)? {
        Ok(fingerprint) => fingerprint,
        Err(detail) => {
            return Ok(AdoptionPreparation::WaitingHuman {
                cause: HumanWaitCause::UndecidableAssessment,
                detail,
            });
        }
    };
    if &css != fingerprint.css() || &resources != fingerprint.resources() {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adoption CSS/resource fingerprints do not match the current inputs"
                .to_owned(),
        });
    }
    let derived = FingerprintSet::new(
        fingerprint.settings().clone(),
        fingerprint.policy().clone(),
        fingerprint.css().clone(),
        fingerprint.resources().clone(),
        Some(fingerprint.candidate().clone()),
        Some(fingerprint.provenance().clone()),
        Some(fingerprint.digest()),
    );
    if generation.fingerprints() != &derived {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::UndecidableAssessment,
            detail: "the adopted generation fingerprints differ from its evaluation".to_owned(),
        });
    }
    if adoption.policy.digest() != approval.versions().policy_fingerprint()
        || adoption.policy.pack() != approval.versions().pack_fingerprint()
        || adoption.policy.version() != approval.versions().policy_version()
    {
        return Ok(AdoptionPreparation::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the adoption policy/pack identity differs from the approval".to_owned(),
        });
    }

    match files.read(&document_key.companion_path())? {
        Some(bytes) if bytes == adoption.candidate_html.as_bytes() => {}
        Some(_) => {
            return Ok(AdoptionPreparation::Conflict {
                target: document_key.companion_path(),
                detail: "the current HTML changed after validation".to_owned(),
            });
        }
        None => {
            return Ok(AdoptionPreparation::Conflict {
                target: document_key.companion_path(),
                detail: "the current HTML disappeared after validation".to_owned(),
            });
        }
    }
    match files.read(document_key.target_path())? {
        Some(bytes) if bytes == adoption.source_bytes => {}
        Some(_) => {
            return Ok(AdoptionPreparation::WaitingHuman {
                cause: HumanWaitCause::ExternalHtmlConflict,
                detail: "the Markdown source changed after validation".to_owned(),
            });
        }
        None => {
            return Ok(AdoptionPreparation::NotApplicable {
                detail: "the Markdown source no longer exists".to_owned(),
            });
        }
    }
    let current_receipt = files.read(&html_evidence_path(&document_key))?;
    if let Some(detail) = expected_mismatch(
        &html_evidence_path(&document_key),
        &adoption.expected_receipt,
        current_receipt.as_deref(),
    ) {
        return Ok(AdoptionPreparation::Conflict {
            target: html_evidence_path(&document_key),
            detail,
        });
    }
    if let Some(detail) = expected_mismatch(
        &document_key.companion_path(),
        &adoption.expected_html,
        Some(adoption.candidate_html.as_bytes()),
    ) {
        return Ok(AdoptionPreparation::Conflict {
            target: document_key.companion_path(),
            detail,
        });
    }

    let attempt = CandidatePublication::new(
        adoption.publication_id,
        document_key,
        adoption.document_revision,
        settings.version(),
        adoption.generation,
        adoption.candidate_html,
        adoption.provenance,
        adoption.source_bytes,
        adoption.css,
        adoption.resources,
        adoption.policy,
        adoption.applied,
        adoption.expected_html,
        adoption.expected_receipt,
    )?
    .with_explicit_resolution();
    Ok(AdoptionPreparation::Ready(Box::new(attempt)))
}

/// Runs one adoption through the Task 19 publication path.
pub fn adopt_current_html(
    publisher: &mut PublicationOrchestrator<'_>,
    adoption: CurrentHtmlAdoption,
    now: Timestamp,
) -> Result<AdoptionOutcome, H3Error> {
    let prepared = prepare_adoption(publisher.store, publisher.files, adoption, now)?;
    match prepared {
        AdoptionPreparation::Ready(attempt) => publisher
            .publish(*attempt, now)
            .map(AdoptionOutcome::Adopted),
        AdoptionPreparation::WaitingHuman { cause, detail } => {
            Ok(AdoptionOutcome::WaitingHuman { cause, detail })
        }
        AdoptionPreparation::NotApplicable { detail } => {
            Ok(AdoptionOutcome::NotApplicable { detail })
        }
        AdoptionPreparation::Conflict { target, detail } => {
            Ok(AdoptionOutcome::Conflict { target, detail })
        }
    }
}

/// Runs an explicit regenerated-candidate replacement through the Task 19 path.
///
/// The attempt must already be marked explicit and carry the exact current
/// HTML/receipt expectations. The normal publication preflight, final
/// validation, history save, and journal still run.
pub fn replace_with_regenerated(
    publisher: &mut PublicationOrchestrator<'_>,
    attempt: CandidatePublication,
    now: Timestamp,
) -> Result<PublicationOutcome, H3Error> {
    if !attempt.is_explicit_resolution() {
        return Ok(PublicationOutcome::NotPublished {
            publication: attempt.publication_id(),
            detail: "a regenerated replacement must be an explicit human resolution".to_owned(),
            duplicate: false,
        });
    }
    // A stored attempt is resolved by the publication journal before any state
    // or file check, so an idempotent retry after success still returns the
    // original result instead of a new conflict.
    if publisher
        .store
        .load_html_sync_publication(attempt.document().project_id(), attempt.publication_id())?
        .is_some()
    {
        return publisher.publish(attempt, now);
    }
    let record = publisher
        .store
        .load_html_sync_document(attempt.document().project_id(), attempt.document())?
        .ok_or_else(|| H3Error::NotFound {
            record: "document state",
            id: attempt.document().target_path().to_owned(),
        })?;
    if !matches!(
        record.state().reason().kind(),
        H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::ExternalHtmlConflict
        }
    ) {
        return Ok(PublicationOutcome::NotPublished {
            publication: attempt.publication_id(),
            detail: "the document is not waiting on an external HTML conflict".to_owned(),
            duplicate: false,
        });
    }
    publisher.publish(attempt, now)
}

/// Restores one selected historical HTML/receipt pair.
///
/// The current exact pair is first saved to the private history archive. Only
/// then are the selected bytes replaced through the host H1 single-file writer.
/// Markdown is never changed. A successful restore commits `waiting_human` with
/// the `Restored` applicability and a reassessment action, never `synced`.
#[allow(clippy::too_many_arguments)]
pub fn restore_history(
    store: &mut dyn H3StorePort,
    files: &dyn PublicationFileReadPort,
    history: &dyn HistoryReadPort,
    archive: &mut dyn PublicationArchivePort,
    writer: &mut dyn HostPublicationPort,
    request: &H3OperationRequest,
    publication: PublicationId,
    expected_html: &ExpectedTargetVersion,
    expected_receipt: &ExpectedTargetVersion,
    now: Timestamp,
) -> Result<HistoryRestoreOutcome, H3Error> {
    let document = request
        .document()
        .ok_or_else(|| H3Error::empty("document"))?;
    let project = document.project_id();
    let H3Operation::RestoreHistory { generation } = request.operation() else {
        return Err(H3Error::invalid(
            "operation",
            "restore_history requires a RestoreHistory operation",
        ));
    };
    publication.validate_in(project)?;
    if let Some(stored) = store.html_sync_request_result(project, request.request_id())? {
        if stored.fingerprint() != request.fingerprint() {
            return Ok(HistoryRestoreOutcome::Conflict {
                target: document.companion_path(),
                detail: "the restore request id was reused with different inputs".to_owned(),
            });
        }
        return Ok(restore_outcome_from_stored(&stored, true));
    }
    let expected_revision = request
        .expected_revision()
        .ok_or_else(|| H3Error::empty("expectedRevision"))?;
    let settings = store
        .load_html_sync_settings(project)?
        .ok_or_else(|| H3Error::Unavailable {
            capability: "h3.restore.settings".to_owned(),
            detail: "the project has no stored H3 settings".to_owned(),
        })?;
    let settings = settings.settings();
    if !settings.verify_fingerprint() {
        return Ok(HistoryRestoreOutcome::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the stored H3 settings no longer match their approved fingerprint".to_owned(),
        });
    }
    if !settings
        .approval()
        .is_some_and(|approval| approval.is_current_at(now))
    {
        return Ok(HistoryRestoreOutcome::WaitingHuman {
            cause: HumanWaitCause::PermissionDenied,
            detail: "the human configuration approval is not current".to_owned(),
        });
    }
    let record = store
        .load_html_sync_document(project, document)?
        .ok_or_else(|| H3Error::NotFound {
            record: "document state",
            id: document.target_path().to_owned(),
        })?;
    if record.revision() != expected_revision {
        return Ok(HistoryRestoreOutcome::Conflict {
            target: document.target_path().to_owned(),
            detail: format!(
                "the document revision changed: expected {expected_revision}, found {}",
                record.revision()
            ),
        });
    }
    if let Some(expected_source) = request.expected_source_digest() {
        match files.read(document.target_path())? {
            Some(bytes) if ContentDigest::sha256(&bytes) == *expected_source => {}
            Some(_) => {
                return Ok(HistoryRestoreOutcome::Conflict {
                    target: document.target_path().to_owned(),
                    detail: "the Markdown source changed after the restore request".to_owned(),
                });
            }
            None => {
                return Ok(HistoryRestoreOutcome::Conflict {
                    target: document.target_path().to_owned(),
                    detail: "the Markdown source disappeared before the restore".to_owned(),
                });
            }
        }
    }
    let selected = store
        .html_sync_generations(project, document)?
        .into_iter()
        .find(|record| record.generation_id() == *generation)
        .ok_or_else(|| H3Error::NotFound {
            record: "generation",
            id: generation.to_string(),
        })?;
    let Some(version) = history.load_version(document, *generation)? else {
        return Ok(HistoryRestoreOutcome::NotRestored {
            detail: "the selected generation has no complete historical HTML/receipt pair"
                .to_owned(),
            duplicate: false,
        });
    };
    if version.generation() != *generation {
        return Ok(HistoryRestoreOutcome::NotRestored {
            detail: "the history reader returned another generation".to_owned(),
            duplicate: false,
        });
    }
    if let Some(detail) = verify_history_version(store, document, &selected, &version)? {
        return Ok(HistoryRestoreOutcome::Conflict {
            target: document.companion_path(),
            detail,
        });
    }
    let current_html = files.read(&document.companion_path())?;
    if let Some(detail) = expected_mismatch(
        &document.companion_path(),
        expected_html,
        current_html.as_deref(),
    ) {
        return Ok(HistoryRestoreOutcome::Conflict {
            target: document.companion_path(),
            detail,
        });
    }
    let receipt_path = html_evidence_path(document);
    let current_receipt = files.read(&receipt_path)?;
    if let Some(detail) =
        expected_mismatch(&receipt_path, expected_receipt, current_receipt.as_deref())
    {
        return Ok(HistoryRestoreOutcome::Conflict {
            target: receipt_path,
            detail,
        });
    }
    if let Some(journal) = store.load_html_sync_publication(project, publication)? {
        return Ok(restore_outcome_from_journal(journal, request));
    }
    if current_html.as_deref() == Some(version.html().bytes())
        && current_receipt.as_deref() == Some(version.receipt().bytes())
    {
        return persist_unchanged_restore(store, &record, request, &selected, now);
    }

    let candidate = selected.candidate().ok_or_else(|| {
        H3Error::invalid(
            "generation",
            "a restored generation needs exact candidate metadata",
        )
    })?;
    let request_fingerprint = ContentDigest::sha256(request.fingerprint().as_str().as_bytes());
    let html_request = request_id(format!("{publication}:html"))?;
    let receipt_request = request_id(format!("{publication}:receipt"))?;
    let mut journal = PublicationJournal::new(
        publication,
        document.clone(),
        selected.generation_id(),
        candidate.candidate_id(),
        html_request.clone(),
        expected_html.clone(),
        version.html().digest(),
        candidate.provenance_digest().clone(),
        selected.source().clone(),
        now,
    )?
    .with_request_fingerprint(request_fingerprint)
    .with_receipt(
        &receipt_path,
        expected_receipt.clone(),
        version.receipt().digest(),
        receipt_request.clone(),
        now,
    )?
    .with_files(vec![PublicationFileJournal::pending(
        PublicationFileRole::Html,
        document.companion_path(),
        expected_html.clone(),
        version.html().digest(),
        Some(html_request.clone()),
        now,
    )?]);

    // Persist the intent and make the document unsynchronized before any file
    // side effect. A crash can no longer leave a `synced` claim over old bytes.
    let restoring_reason = restoring_reason();
    let restoring_document = restore_document(
        record.state(),
        restoring_reason,
        Applicability::not_applicable(ApplicabilityReason::Restored {
            generation: *generation,
        }),
        now,
    )?;
    let restoring_event = crate::events::document_state_event(
        document,
        Some(record.state().state()),
        &restoring_document,
        now,
    )?;
    let prepared_event = crate::events::publication_event(&journal, now)?;
    let mut prepared_record = match store.commit_html_sync(
        HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(
                Some(record.revision()),
                restoring_document,
            )?)
            .with_publication(journal.clone())
            .with_events(vec![restoring_event, prepared_event]),
    )? {
        HtmlSyncCommitOutcome::Applied { document, .. } => {
            document.ok_or_else(|| H3Error::Storage {
                detail: "the restore intent commit returned no document".to_owned(),
            })?
        }
        HtmlSyncCommitOutcome::Duplicate { .. } => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: "the restore intent commit was reported as a duplicate".to_owned(),
            });
        }
    };

    // Save the exact current pair before replacing either formal file.
    let old_html = match save_current(
        archive,
        document,
        PublicationFileRole::Html,
        &document.companion_path(),
        &request_id(format!("{publication}:history-html"))?,
        current_html.as_deref(),
    ) {
        Ok(saved) => saved,
        Err(error) => {
            let detail = format!("the current HTML could not be saved to history: {error}");
            return persist_restore_failure(
                store,
                &prepared_record,
                journal,
                request,
                &selected,
                Refusal::waiting(HumanWaitCause::CapacityInsufficient, detail),
                now,
            );
        }
    };
    let old_receipt = match save_current(
        archive,
        document,
        PublicationFileRole::Receipt,
        &receipt_path,
        &request_id(format!("{publication}:history-receipt"))?,
        current_receipt.as_deref(),
    ) {
        Ok(saved) => saved,
        Err(error) => {
            let detail = format!("the current receipt could not be saved to history: {error}");
            return persist_restore_failure(
                store,
                &prepared_record,
                journal,
                request,
                &selected,
                Refusal::waiting(HumanWaitCause::CapacityInsufficient, detail),
                now,
            );
        }
    };
    journal = journal
        .old_versions_saved(old_html, old_receipt, now)?
        .with_file(PublicationFileJournal::pending(
            PublicationFileRole::Receipt,
            &receipt_path,
            expected_receipt.clone(),
            version.receipt().digest(),
            Some(receipt_request.clone()),
            now,
        )?)?;
    prepared_record = match persist_restore_journal(store, &prepared_record, journal.clone(), now)?
    {
        Some(record) => record,
        None => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: "the old-version-saved journal commit was reported as a duplicate"
                    .to_owned(),
            });
        }
    };

    journal = journal.replacing(now)?;
    prepared_record = match persist_restore_journal(store, &prepared_record, journal.clone(), now)?
    {
        Some(record) => record,
        None => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: "the replacing journal commit was reported as a duplicate".to_owned(),
            });
        }
    };

    let html_write = PublicationRequest::new(
        project,
        html_request.clone(),
        NonEmptyText::new(document.companion_path())
            .map_err(|error| H3Error::invalid("restoreTarget", error.to_string()))?,
        expected_html.clone(),
        file_text(version.html())?,
        herness_core::Purpose::new("restore the historical HTML companion")
            .map_err(|error| H3Error::invalid("restorePurpose", error.to_string()))?,
    )
    .map_err(|error| H3Error::invalid("restoreRequest", error.to_string()))?;
    let html_result = match writer.publish(html_write) {
        Ok(result) => result,
        Err(failure) => {
            let detail = failure.to_string();
            let journal = journal
                .with_file(
                    PublicationFileJournal::pending(
                        PublicationFileRole::Html,
                        document.companion_path(),
                        expected_html.clone(),
                        version.html().digest(),
                        Some(html_request.clone()),
                        now,
                    )?
                    .unverifiable(now),
                )?
                .unverifiable(detail.clone(), now);
            return persist_restore_failure(
                store,
                &prepared_record,
                journal,
                request,
                &selected,
                Refusal::reconciliation(detail),
                now,
            );
        }
    };
    let journal = journal.with_file(
        PublicationFileJournal::pending(
            PublicationFileRole::Html,
            document.companion_path(),
            expected_html.clone(),
            version.html().digest(),
            Some(html_request.clone()),
            now,
        )?
        .observed(
            published_digest(&html_result, &version.html().digest())?,
            now,
        ),
    )?;

    let receipt_write = PublicationRequest::new(
        project,
        receipt_request.clone(),
        NonEmptyText::new(&receipt_path)
            .map_err(|error| H3Error::invalid("restoreTarget", error.to_string()))?,
        expected_receipt.clone(),
        file_text(version.receipt())?,
        herness_core::Purpose::new("restore the historical evaluation receipt")
            .map_err(|error| H3Error::invalid("restorePurpose", error.to_string()))?,
    )
    .map_err(|error| H3Error::invalid("restoreRequest", error.to_string()))?;
    let receipt_result = match writer.publish(receipt_write) {
        Ok(result) => result,
        Err(failure) => {
            let detail = failure.to_string();
            let journal = journal
                .with_file(
                    PublicationFileJournal::pending(
                        PublicationFileRole::Receipt,
                        &receipt_path,
                        expected_receipt.clone(),
                        version.receipt().digest(),
                        Some(receipt_request.clone()),
                        now,
                    )?
                    .unverifiable(now),
                )?
                .unverifiable(
                    format!("the HTML was restored but the receipt was not: {detail}"),
                    now,
                );
            return persist_restore_failure(
                store,
                &prepared_record,
                journal,
                request,
                &selected,
                Refusal::reconciliation(format!(
                    "the HTML was restored but the receipt was not: {failure}"
                )),
                now,
            );
        }
    };
    let journal = journal.with_file(
        PublicationFileJournal::pending(
            PublicationFileRole::Receipt,
            &receipt_path,
            expected_receipt.clone(),
            version.receipt().digest(),
            Some(receipt_request),
            now,
        )?
        .observed(
            published_digest(&receipt_result, &version.receipt().digest())?,
            now,
        ),
    )?;

    let observed_html = files.read(&document.companion_path())?;
    let observed_receipt = files.read(&receipt_path)?;
    let postcondition =
        postcondition_mismatch("html", &version.html().digest(), observed_html.as_deref()).or_else(
            || {
                postcondition_mismatch(
                    "receipt",
                    &version.receipt().digest(),
                    observed_receipt.as_deref(),
                )
            },
        );
    if let Some(detail) = postcondition {
        let journal = journal.unverifiable(detail.clone(), now);
        return persist_restore_failure(
            store,
            &prepared_record,
            journal,
            request,
            &selected,
            Refusal::reconciliation(detail),
            now,
        );
    }
    if let Some(detail) = recheck_source(files, document, request)? {
        let journal = journal.unverifiable(detail.clone(), now);
        return persist_restore_failure(
            store,
            &prepared_record,
            journal,
            request,
            &selected,
            Refusal::reconciliation(detail),
            now,
        );
    }

    let journal = journal.published_pair(
        version.html().digest(),
        version.receipt().digest(),
        None,
        now,
    )?;
    let restored_document = restore_document(
        prepared_record.state(),
        restored_reason(),
        Applicability::not_applicable(ApplicabilityReason::Restored {
            generation: *generation,
        }),
        now,
    )?;
    let outcome = H3OperationOutcome::Restored {
        publication,
        generation: *generation,
        html_digest: version.html().digest(),
        receipt_digest: version.receipt().digest(),
        revision: prepared_record.revision().saturating_add(1),
    };
    let result = H3OperationResult::new(request, outcome, 0, now)?;
    let state_event = crate::events::document_state_event(
        document,
        Some(prepared_record.state().state()),
        &restored_document,
        now,
    )?;
    let publication_event = crate::events::publication_event(&journal, now)?;
    let mut commit = HtmlSyncCommit::new()
        .with_document(DocumentCommit::new(
            Some(prepared_record.revision()),
            restored_document,
        )?)
        .with_publication(journal.clone())
        .with_request(RequestCommit::new(request.clone(), result)?)
        .with_events(vec![state_event, publication_event]);
    if let Some(cycle_id) = prepared_record.state().cycle_id()
        && let Some(cycle) = store.load_html_sync_cycle(project, cycle_id)?
    {
        commit = commit.with_cycle(cycle.with_latch(crate::state::CycleLatch::WaitingHuman));
    }
    let document_revision = match store.commit_html_sync(commit) {
        Ok(HtmlSyncCommitOutcome::Applied {
            document,
            final_project_sequence,
            ..
        }) => {
            let revision = document
                .as_ref()
                .map_or(prepared_record.revision(), H3DocumentRecord::revision);
            let _ = store.update_html_sync_publication(
                journal.with_final_project_sequence(final_project_sequence),
            );
            revision
        }
        Ok(HtmlSyncCommitOutcome::Duplicate { .. }) => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: "the restored commit was reported as a duplicate".to_owned(),
            });
        }
        Err(error) => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: format!(
                    "the selected files were restored but the unsynced state could not be committed: {error}"
                ),
            });
        }
    };
    Ok(HistoryRestoreOutcome::Restored {
        publication,
        generation: *generation,
        html_digest: version.html().digest(),
        receipt_digest: version.receipt().digest(),
        document_revision,
        duplicate: false,
    })
}

/// Records a Markdown deletion or move without deleting or moving any artifact.
#[allow(clippy::too_many_arguments)]
pub fn record_source_removal(
    store: &mut dyn H3StorePort,
    controls: &mut dyn SourceJobControlPort,
    request: &H3OperationRequest,
    remaining_targets: &[String],
    now: Timestamp,
) -> Result<SourceRemovalOutcome, H3Error> {
    let document = request
        .document()
        .ok_or_else(|| H3Error::empty("document"))?;
    let project = document.project_id();
    let H3Operation::SourceRemoved { new_path } = request.operation() else {
        return Err(H3Error::invalid(
            "operation",
            "source removal requires a SourceRemoved operation",
        ));
    };
    if let Some(stored) = store.html_sync_request_result(project, request.request_id())? {
        if stored.fingerprint() != request.fingerprint() {
            return Err(H3Error::DuplicateRequestConflict {
                request: request.request_id().to_string(),
                recorded: stored.request().describe(),
                supplied: request.describe(),
            });
        }
        return match stored.result().outcome() {
            H3OperationOutcome::Orphaned { .. } => source_removal_from_stored(&stored),
            H3OperationOutcome::Rejected { reason }
                if matches!(
                    reason.kind(),
                    H3StateReasonKind::Stopped {
                        cause: crate::state::H3StopCause::StopUnconfirmed
                    }
                ) =>
            {
                Err(H3Error::Unavailable {
                    capability: "h3.source.stop".to_owned(),
                    detail: "the stored source-removal request stopped unconfirmed".to_owned(),
                })
            }
            _ => Err(H3Error::Storage {
                detail: "the stored request result is not a source-removal result".to_owned(),
            }),
        };
    }
    let expected_revision = request
        .expected_revision()
        .ok_or_else(|| H3Error::empty("expectedRevision"))?;
    let settings = store.load_html_sync_settings(project)?;
    let approved_targets = settings
        .as_ref()
        .map_or_else(Vec::new, |record| record.settings().target_paths().to_vec());
    let record = store
        .load_html_sync_document(project, document)?
        .ok_or_else(|| H3Error::NotFound {
            record: "document state",
            id: document.target_path().to_owned(),
        })?;
    if record.revision() != expected_revision {
        return Err(H3Error::StaleRevision {
            key: document.target_path().to_owned(),
            expected: Some(expected_revision),
            found: Some(record.revision()),
        });
    }
    let new_target = new_path.clone();
    let new_target_approved = new_target
        .as_ref()
        .is_some_and(|path| approved_targets.iter().any(|target| target == path));
    let remaining_paths: Vec<String> = remaining_targets
        .iter()
        .filter(|path| *path != document.target_path())
        .cloned()
        .collect();
    if record.state().state() == H3State::Orphaned {
        let result = H3OperationResult::new(
            request,
            H3OperationOutcome::Orphaned {
                target: document.companion_path(),
                remaining_paths: remaining_paths.clone(),
                new_target: new_target.clone(),
                new_target_approved,
                revision: record.revision().saturating_add(1),
            },
            0,
            now,
        )?;
        let stored = match store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(record.revision()),
                    record.state().clone(),
                )?)
                .with_request(RequestCommit::new(request.clone(), result)?),
        )? {
            HtmlSyncCommitOutcome::Applied {
                request: Some(stored),
                ..
            } => stored,
            HtmlSyncCommitOutcome::Applied { .. } => {
                return Err(H3Error::Storage {
                    detail: "the orphan request commit returned no stored result".to_owned(),
                });
            }
            HtmlSyncCommitOutcome::Duplicate { stored, .. } => stored,
        };
        return source_removal_from_stored(&stored);
    }
    match controls.stop_source(document)? {
        SourceStop::Unconfirmed => {
            let reason = H3Reason::new(
                H3StateReasonKind::Stopped {
                    cause: crate::state::H3StopCause::StopUnconfirmed,
                },
                vec![RequiredAction::ReconcileRecovery],
            )?;
            let next = rebuild_document(
                record.state(),
                reason.clone(),
                Applicability::not_applicable(ApplicabilityReason::NeverPublished),
                now,
            )?;
            let event = crate::events::document_state_event(
                document,
                Some(record.state().state()),
                &next,
                now,
            )?;
            let result =
                H3OperationResult::new(request, H3OperationOutcome::Rejected { reason }, 0, now)?;
            store.commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(Some(record.revision()), next)?)
                    .with_request(RequestCommit::new(request.clone(), result)?)
                    .with_events(vec![event]),
            )?;
            return Err(H3Error::Unavailable {
                capability: "h3.source.stop".to_owned(),
                detail: "the job stop was not confirmed; the source is not orphaned yet".to_owned(),
            });
        }
        SourceStop::Stopped | SourceStop::NotRunning => {}
    }

    let reason = H3Reason::new(
        H3StateReasonKind::Orphaned {
            last_companion: document.companion_path(),
        },
        Vec::new(),
    )?;
    let next = rebuild_document(
        record.state(),
        reason,
        Applicability::not_applicable(ApplicabilityReason::Orphaned),
        now,
    )?;
    let event =
        crate::events::document_state_event(document, Some(record.state().state()), &next, now)?;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::Orphaned {
            target: document.companion_path(),
            remaining_paths: remaining_paths.clone(),
            new_target: new_target.clone(),
            new_target_approved,
            revision: record.revision().saturating_add(1),
        },
        0,
        now,
    )?;
    let outcome = store.commit_html_sync(
        HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(record.revision()), next)?)
            .with_request(RequestCommit::new(request.clone(), result)?)
            .with_events(vec![event]),
    )?;
    let document = match outcome {
        HtmlSyncCommitOutcome::Applied { document, .. } => {
            document.ok_or_else(|| H3Error::Storage {
                detail: "the orphan commit returned no document".to_owned(),
            })?
        }
        HtmlSyncCommitOutcome::Duplicate { .. } => {
            return Err(H3Error::Storage {
                detail: "the orphan commit was reported as a duplicate".to_owned(),
            });
        }
    };
    Ok(SourceRemovalOutcome {
        target: document.state().document_key().companion_path(),
        remaining_paths,
        new_target,
        new_target_approved,
        document_revision: document.revision(),
        duplicate: false,
    })
}

fn conflict_reason(document: &DocumentKey) -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::ExternalHtmlConflict,
        },
        vec![RequiredAction::ResolveHtmlConflict {
            target: document.companion_path(),
        }],
    )
    .expect("an external conflict always has a required action")
}

fn restoring_reason() -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation,
        },
        vec![RequiredAction::ReconcileRecovery],
    )
    .expect("a restore intent always has a required action")
}

fn restored_reason() -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation,
        },
        vec![RequiredAction::ReassessCandidate],
    )
    .expect("a restored document always needs a human reassessment")
}

fn rebuild_document(
    document: &H3DocumentState,
    reason: H3Reason,
    applicability: Applicability,
    now: Timestamp,
) -> Result<H3DocumentState, H3Error> {
    H3DocumentState::new(
        document.document_key().clone(),
        document.settings_version(),
        document.job_id(),
        document.cycle_id(),
        document.generation(),
        document.source().clone(),
        document.fingerprints().clone(),
        reason,
        document.h2().cloned(),
        document.evidence().to_vec(),
        applicability,
        now,
    )
}

fn restore_document(
    document: &H3DocumentState,
    reason: H3Reason,
    applicability: Applicability,
    now: Timestamp,
) -> Result<H3DocumentState, H3Error> {
    H3DocumentState::new(
        document.document_key().clone(),
        document.settings_version(),
        document.job_id(),
        document.cycle_id(),
        None,
        document.source().clone(),
        document.fingerprints().clone(),
        reason,
        document.h2().cloned(),
        document.evidence().to_vec(),
        applicability,
        now,
    )
}

fn persist_unchanged_restore(
    store: &mut dyn H3StorePort,
    record: &H3DocumentRecord,
    request: &H3OperationRequest,
    selected: &GenerationRecord,
    now: Timestamp,
) -> Result<HistoryRestoreOutcome, H3Error> {
    let _ = record;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::HistoryUnchanged {
            generation: selected.generation_id(),
        },
        0,
        now,
    )?;
    match store.commit_html_sync(
        HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(
                Some(record.revision()),
                record.state().clone(),
            )?)
            .with_request(RequestCommit::new(request.clone(), result)?),
    )? {
        HtmlSyncCommitOutcome::Applied { .. } | HtmlSyncCommitOutcome::Duplicate { .. } => {}
    }
    Ok(HistoryRestoreOutcome::Unchanged {
        generation: selected.generation_id(),
        duplicate: false,
    })
}

fn persist_restore_journal(
    store: &mut dyn H3StorePort,
    record: &H3DocumentRecord,
    journal: PublicationJournal,
    now: Timestamp,
) -> Result<Option<H3DocumentRecord>, H3Error> {
    let state = record.state();
    let next = restore_document(
        state,
        restoring_reason(),
        Applicability::not_applicable(ApplicabilityReason::Restored {
            generation: journal.generation_id(),
        }),
        now,
    )?;
    let event =
        crate::events::document_state_event(state.document_key(), Some(state.state()), &next, now)?;
    let publication_event = crate::events::publication_event(&journal, now)?;
    match store.commit_html_sync(
        HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(record.revision()), next)?)
            .with_publication(journal)
            .with_events(vec![event, publication_event]),
    )? {
        HtmlSyncCommitOutcome::Applied { document, .. } => Ok(document),
        HtmlSyncCommitOutcome::Duplicate { .. } => Ok(None),
    }
}

fn persist_restore_failure(
    store: &mut dyn H3StorePort,
    record: &H3DocumentRecord,
    journal: PublicationJournal,
    request: &H3OperationRequest,
    selected: &GenerationRecord,
    refusal: Refusal,
    now: Timestamp,
) -> Result<HistoryRestoreOutcome, H3Error> {
    let journal = match (journal.status(), refusal.kind) {
        (PublicationStatus::Published, _) => journal,
        (PublicationStatus::Replacing, _) | (PublicationStatus::Unverifiable, _) => {
            journal.unverifiable(refusal.detail.clone(), now)
        }
        (_, RefusalKind::Reconciliation) => journal.unverifiable(refusal.detail.clone(), now),
        (_, RefusalKind::Waiting) => {
            journal.failed(PublicationStatus::NotPublished, refusal.detail.clone(), now)?
        }
    };
    let reason = refusal.reason();
    let next = restore_document(
        record.state(),
        reason.clone(),
        Applicability::not_applicable(ApplicabilityReason::Restored {
            generation: selected.generation_id(),
        }),
        now,
    )?;
    let event = crate::events::document_state_event(
        record.state().document_key(),
        Some(record.state().state()),
        &next,
        now,
    )?;
    let publication_event = crate::events::publication_event(&journal, now)?;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::Rejected {
            reason: reason.clone(),
        },
        0,
        now,
    )?;
    let journal_status = journal.status();
    match store.commit_html_sync(
        HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(record.revision()), next)?)
            .with_publication(journal)
            .with_request(RequestCommit::new(request.clone(), result)?)
            .with_events(vec![event, publication_event]),
    ) {
        Ok(HtmlSyncCommitOutcome::Applied { .. } | HtmlSyncCommitOutcome::Duplicate { .. }) => {}
        Err(error) => {
            return Ok(HistoryRestoreOutcome::ReconciliationRequired {
                detail: format!("the restore failure could not be committed consistently: {error}"),
            });
        }
    }
    Ok(refusal.outcome(journal_status))
}

fn restore_outcome_from_stored(
    stored: &StoredRequestResult,
    duplicate: bool,
) -> HistoryRestoreOutcome {
    match stored.result().outcome() {
        H3OperationOutcome::Restored {
            publication,
            generation,
            html_digest,
            receipt_digest,
            revision,
        } => HistoryRestoreOutcome::Restored {
            publication: *publication,
            generation: *generation,
            html_digest: html_digest.clone(),
            receipt_digest: receipt_digest.clone(),
            document_revision: *revision,
            duplicate,
        },
        H3OperationOutcome::HistoryUnchanged { generation } => HistoryRestoreOutcome::Unchanged {
            generation: *generation,
            duplicate,
        },
        H3OperationOutcome::Rejected { reason } => match reason.kind() {
            H3StateReasonKind::WaitingHuman { cause } => HistoryRestoreOutcome::WaitingHuman {
                cause: *cause,
                detail: "the stored restore result requires a human".to_owned(),
            },
            _ => HistoryRestoreOutcome::NotRestored {
                detail: "the stored restore result was rejected".to_owned(),
                duplicate,
            },
        },
        _ => HistoryRestoreOutcome::NotRestored {
            detail: "the stored request result is not a restore result".to_owned(),
            duplicate,
        },
    }
}

fn restore_outcome_from_journal(
    journal: PublicationJournal,
    request: &H3OperationRequest,
) -> HistoryRestoreOutcome {
    let fingerprint = ContentDigest::sha256(request.fingerprint().as_str().as_bytes());
    if journal.request_fingerprint() != Some(&fingerprint) {
        return HistoryRestoreOutcome::Conflict {
            target: journal.document_key().companion_path(),
            detail: "the restore request id was reused with different inputs".to_owned(),
        };
    }
    match journal.status() {
        PublicationStatus::Published => HistoryRestoreOutcome::ReconciliationRequired {
            detail: "the restore journal is published but its request result is missing".to_owned(),
        },
        PublicationStatus::NotPublished | PublicationStatus::Conflict => {
            HistoryRestoreOutcome::NotRestored {
                detail: journal
                    .detail()
                    .unwrap_or("the stored restore did not complete")
                    .to_owned(),
                duplicate: true,
            }
        }
        PublicationStatus::Prepared
        | PublicationStatus::OldVersionSaved
        | PublicationStatus::Replacing
        | PublicationStatus::Unverifiable => HistoryRestoreOutcome::ReconciliationRequired {
            detail: "the stored restore has no durable terminal result".to_owned(),
        },
    }
}

fn source_removal_from_stored(
    stored: &StoredRequestResult,
) -> Result<SourceRemovalOutcome, H3Error> {
    let H3OperationOutcome::Orphaned {
        target,
        remaining_paths,
        new_target,
        new_target_approved,
        revision,
    } = stored.result().outcome()
    else {
        return Err(H3Error::Storage {
            detail: "the stored request result is not an orphan result".to_owned(),
        });
    };
    Ok(SourceRemovalOutcome {
        target: target.clone(),
        remaining_paths: remaining_paths.clone(),
        new_target: new_target.clone(),
        new_target_approved: *new_target_approved,
        document_revision: *revision,
        duplicate: true,
    })
}

fn collect_inputs(
    files: &dyn PublicationFileReadPort,
    inputs: &[PublicationFileInput],
    kind: DependencyKind,
) -> Result<Result<ContentDigest, String>, H3Error> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !seen.insert(input.path().to_owned()) {
            return Ok(Err(format!(
                "duplicate {} input path {}",
                kind.as_str(),
                input.path()
            )));
        }
        match files.read(input.path())? {
            Some(bytes) if bytes == input.bytes() => {}
            Some(_) => {
                return Ok(Err(format!(
                    "the {} bytes for {} changed on disk",
                    kind.as_str(),
                    input.path()
                )));
            }
            None => {
                return Ok(Err(format!(
                    "the {} input {} is missing",
                    kind.as_str(),
                    input.path()
                )));
            }
        }
        entries.push((input.path(), input.digest()));
    }
    Ok(Ok(dependency_fingerprint(kind, entries)))
}

fn verify_history_version(
    store: &mut dyn H3StorePort,
    document: &DocumentKey,
    selected: &GenerationRecord,
    version: &HistoryVersion,
) -> Result<Option<String>, H3Error> {
    let version_digest = version.html().digest();
    let candidate = match selected.candidate() {
        Some(candidate) => candidate,
        None => {
            return Ok(Some(
                "the selected generation has no candidate metadata".to_owned(),
            ));
        }
    };
    if candidate.html_digest() != &version_digest {
        return Ok(Some(
            "the selected history HTML does not match the generation candidate".to_owned(),
        ));
    }
    let journal = match selected.publication() {
        Some(publication_id) => {
            store.load_html_sync_publication(document.project_id(), publication_id)?
        }
        None => store
            .list_html_sync_publications(document.project_id(), document)?
            .into_iter()
            .find(|journal| {
                journal.generation_id() == selected.generation_id()
                    && journal.status() == PublicationStatus::Published
            }),
    };
    let Some(journal) = journal else {
        return Ok(Some(
            "the selected generation has no published publication journal".to_owned(),
        ));
    };
    if journal.status() != PublicationStatus::Published
        || journal.approved_html_digest() != &version_digest
        || journal.receipt_digest() != Some(&version.receipt().digest())
    {
        return Ok(Some(
            "the selected history pair does not match its published journal".to_owned(),
        ));
    }
    if !receipt_matches(version.receipt().bytes(), document, &version_digest)? {
        return Ok(Some(
            "the selected history receipt does not bind the exact HTML".to_owned(),
        ));
    }
    Ok(None)
}

fn receipt_matches(
    bytes: &[u8],
    document: &DocumentKey,
    html_digest: &ContentDigest,
) -> Result<bool, H3Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| H3Error::invalid("historyReceipt", "the selected receipt is not UTF-8"))?;
    let value: Value = serde_json::from_str(text).map_err(|error| {
        H3Error::invalid(
            "historyReceipt",
            format!("the selected receipt is invalid: {error}"),
        )
    })?;
    Ok(
        value.get("schema").and_then(Value::as_str) == Some(RECEIPT_SCHEMA)
            && value.get("version").and_then(Value::as_u64) == Some(u64::from(RECEIPT_VERSION))
            && value.get("contract").and_then(Value::as_str) == Some(RECEIPT_CONTRACT)
            && value.pointer("/source/path").and_then(Value::as_str)
                == Some(document.target_path())
            && value.pointer("/html/path").and_then(Value::as_str)
                == Some(document.companion_path().as_str())
            && value.pointer("/html/digest").and_then(Value::as_str)
                == Some(format!("sha256:{}", html_digest.as_str()).as_str()),
    )
}

fn save_current(
    archive: &mut dyn PublicationArchivePort,
    document: &DocumentKey,
    role: PublicationFileRole,
    target: &str,
    request: &PublicationRequestId,
    content: Option<&[u8]>,
) -> Result<Option<crate::state::ArchivedVersionRef>, H3Error> {
    let Some(content) = content else {
        return Ok(None);
    };
    let version = hash_bytes(content);
    let text = std::str::from_utf8(content).map_err(|_| {
        H3Error::invalid(
            "history",
            format!("the current {} is not UTF-8", role.as_str()),
        )
    })?;
    let archive_request =
        OldVersionArchive::new(request, document.project_id(), target, &version, text);
    let archived = archive
        .save_old_version(&archive_request)
        .map_err(|error| H3Error::Storage {
            detail: format!(
                "the current {} could not be saved to history: {error}",
                role.as_str()
            ),
        })?;
    Ok(Some(crate::state::ArchivedVersionRef::new(
        archived.reference().as_str(),
        ContentDigest::parse(archived.version().as_str())
            .map_err(|error| H3Error::invalid("archiveVersion", error.to_string()))?,
    )?))
}

fn request_id(value: String) -> Result<PublicationRequestId, H3Error> {
    PublicationRequestId::new(value)
        .map_err(|error| H3Error::invalid("publicationRequestId", error.to_string()))
}

fn published_digest(
    result: &herness_core::PublicationResult,
    expected: &ContentDigest,
) -> Result<ContentDigest, H3Error> {
    if result.status() != herness_core::contracts::publication::PublicationStatus::Published {
        return Err(H3Error::Storage {
            detail: "the host writer returned a non-published restore result".to_owned(),
        });
    }
    let observed = result
        .observed_after_version()
        .ok_or_else(|| H3Error::Storage {
            detail: "the host writer returned no observed version".to_owned(),
        })?;
    let digest = ContentDigest::parse(observed.as_str())
        .map_err(|error| H3Error::invalid("fileVersion", error.to_string()))?;
    if digest != *expected {
        return Err(H3Error::Storage {
            detail: "the host writer observed another version than the restored bytes".to_owned(),
        });
    }
    Ok(digest)
}

fn recheck_source(
    files: &dyn PublicationFileReadPort,
    document: &DocumentKey,
    request: &H3OperationRequest,
) -> Result<Option<String>, H3Error> {
    match files.read(document.target_path())? {
        Some(bytes) => {
            if let Some(expected) = request.expected_source_digest()
                && ContentDigest::sha256(&bytes) != *expected
            {
                return Ok(Some(
                    "the Markdown source changed after the restore".to_owned(),
                ));
            }
            Ok(None)
        }
        None => Ok(Some(
            "the Markdown source disappeared during the restore".to_owned(),
        )),
    }
}

fn expected_mismatch(
    path: &str,
    expected: &ExpectedTargetVersion,
    observed: Option<&[u8]>,
) -> Option<String> {
    match (expected, observed) {
        (ExpectedTargetVersion::Absent, None) => None,
        (ExpectedTargetVersion::Absent, Some(bytes)) => Some(format!(
            "{path} exists with version {} but absence was expected",
            ContentDigest::sha256(bytes)
        )),
        (ExpectedTargetVersion::Present { version }, None) => {
            Some(format!("{path} is missing; expected version {version}"))
        }
        (ExpectedTargetVersion::Present { version }, Some(bytes)) => {
            let observed = ContentDigest::sha256(bytes);
            if observed.as_str() == version.as_str() {
                None
            } else {
                Some(format!("{path} has version {observed}; expected {version}"))
            }
        }
    }
}

fn postcondition_mismatch(
    role: &str,
    expected: &ContentDigest,
    observed: Option<&[u8]>,
) -> Option<String> {
    match observed {
        None => Some(format!("the {role} file was not found after the restore")),
        Some(bytes) if ContentDigest::sha256(bytes) == *expected => None,
        Some(bytes) => Some(format!(
            "the {role} bytes after the restore are {}, not the selected {}",
            ContentDigest::sha256(bytes),
            expected
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalKind {
    Waiting,
    Reconciliation,
}

#[derive(Debug, Clone)]
struct Refusal {
    kind: RefusalKind,
    cause: HumanWaitCause,
    detail: String,
}

impl Refusal {
    fn waiting(cause: HumanWaitCause, detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Waiting,
            cause,
            detail: detail.into(),
        }
    }

    fn reconciliation(detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Reconciliation,
            cause: HumanWaitCause::RecoveryReconciliation,
            detail: detail.into(),
        }
    }

    fn reason(&self) -> H3Reason {
        let actions = match self.kind {
            RefusalKind::Waiting => vec![RequiredAction::ReassessCandidate],
            RefusalKind::Reconciliation => vec![RequiredAction::ReconcileRecovery],
        };
        H3Reason::new(
            H3StateReasonKind::WaitingHuman { cause: self.cause },
            actions,
        )
        .expect("a restore refusal always has an action")
    }

    fn outcome(&self, status: PublicationStatus) -> HistoryRestoreOutcome {
        match self.kind {
            RefusalKind::Reconciliation => HistoryRestoreOutcome::ReconciliationRequired {
                detail: self.detail.clone(),
            },
            RefusalKind::Waiting => {
                if status == PublicationStatus::NotPublished {
                    HistoryRestoreOutcome::WaitingHuman {
                        cause: self.cause,
                        detail: self.detail.clone(),
                    }
                } else {
                    HistoryRestoreOutcome::ReconciliationRequired {
                        detail: self.detail.clone(),
                    }
                }
            }
        }
    }
}

fn file_text(input: &PublicationFileInput) -> Result<&str, H3Error> {
    std::str::from_utf8(input.bytes())
        .map_err(|_| H3Error::invalid("historyFile", "the selected history bytes are not UTF-8"))
}

/// Whether the evaluation target version matches the approved Html consent or
/// one recorded host-only reissue inside the exact approved Target set.
fn target_version_matches_html_range_consent(
    store: &dyn H3StorePort,
    project: ProjectId,
    version: TargetVersion,
    approval: &crate::config::H3ConfigurationApproval,
) -> bool {
    let assessment = approval.assessment();
    if assessment.consent().target_scope_version() == version {
        return true;
    }
    let key = format!("h3.consent.reissue:{}:html:{}", project, version.get());
    let Ok(Some(bytes)) = store.load_html_sync_host_state(&key) else {
        return false;
    };
    let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    record.get("schema").and_then(serde_json::Value::as_str) == Some("h3-range-consent-reissue-v1")
        && record.get("purpose").and_then(serde_json::Value::as_str) == Some("html")
        && record
            .get("targetVersion")
            .and_then(serde_json::Value::as_u64)
            == Some(version.get())
        && record
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|targets| {
                targets
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .eq(assessment.disclosure().targets().iter().map(String::as_str))
            })
        && record
            .get("dataKinds")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|kinds| {
                let recorded = kinds
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<BTreeSet<_>>();
                recorded
                    == assessment
                        .disclosure()
                        .data_kinds()
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<BTreeSet<_>>()
            })
        && record
            .get("origin")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|origin| origin == assessment.origin().to_string())
}
