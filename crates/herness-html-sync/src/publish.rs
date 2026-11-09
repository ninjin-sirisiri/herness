//! Versioned evaluation receipt building and journaled candidate publication.
//!
//! Publication is host-only. The host supplies exact source, candidate, CSS,
//! resource, and receipt bytes plus the H2 condition results. This module
//! re-checks every fingerprint and current file version, builds a version 1
//! `sdd-html-receipt`, runs the Common SDD policy's final `candidate-check`
//! through a host port, saves the old HTML and receipt, and only then asks the
//! H1 host-only single-file writer to replace each formal file.
//!
//! The HTML and receipt are two separate single-file replacements. The durable
//! [`PublicationJournal`] records per-file state and order; this module never
//! claims one atomic multi-file filesystem transaction. An external process can
//! still change a formal file between the final check and the rename. A detected
//! race is refused or left for reconciliation, never silently overwritten and
//! never rolled back automatically.

use std::collections::BTreeSet;

use herness_core::ports::publish::PublicationArchivePort;
use herness_core::{
    ArchivedVersion, ExpectedTargetVersion, FileVersion, NonEmptyText, OldVersionArchive,
    PublicationFailure, PublicationRequest, PublicationRequestId, PublicationResult, RunControl,
    Timestamp, hash_bytes,
};
use herness_supervision::ContentDigest;
use herness_supervision::evidence::TargetVersion;
use herness_supervision::profiles::ProfileBinding;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::document::{DocumentKey, FingerprintKind};
use crate::error::H3Error;
use crate::evidence::{
    AppliedEvaluation, EvidenceCheckResult, H3Condition, RequiredCheck, RequiredCheckKind,
};
use crate::ids::PublicationId;
use crate::observer::{DependencyKind, dependency_fingerprint, html_evidence_path};
use crate::ports::{
    DocumentCommit, H3DocumentRecord, H3StorePort, HtmlSyncCommit, HtmlSyncCommitOutcome,
};
use crate::state::{
    Applicability, GenerationRecord, H3DocumentState, H3FailureCause, H3Reason, H3Settings, H3State,
    H3StateReasonKind, H3StopCause, HumanWaitCause, PublicationFileJournal, PublicationFileRole,
    PublicationJournal, PublicationStatus, RequiredAction,
};

/// Receipt schema written by this build.
pub const RECEIPT_SCHEMA: &str = "sdd-html-receipt";
/// Receipt schema version.
pub const RECEIPT_VERSION: u32 = 1;
/// HTML contract required for a receipt.
pub const RECEIPT_CONTRACT: &str = "semantic-v1";
/// Canonical receipt directory.
pub const RECEIPT_DIRECTORY: &str = "docs/sdd/html-evidence";
/// Shared stylesheet every receipt must fingerprint.
pub const SHARED_STYLESHEET: &str = "docs/sdd/assets/sdd.css";

/// One exact project input supplied to final validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationFileInput {
    path: String,
    bytes: Vec<u8>,
}

impl PublicationFileInput {
    /// Creates a canonical project-relative input.
    pub fn new(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Result<Self, H3Error> {
        let path = path.into();
        validate_relative(&path, "publicationInput.path")?;
        Ok(Self {
            path,
            bytes: bytes.into(),
        })
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact digest.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }
}

/// Approved policy and pack identity for one publication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationPolicyIdentity {
    version: String,
    digest: ContentDigest,
    pack: ContentDigest,
}

impl PublicationPolicyIdentity {
    /// Creates the identity from already-approved values.
    pub fn new(
        version: impl Into<String>,
        digest: ContentDigest,
        pack: ContentDigest,
    ) -> Result<Self, H3Error> {
        let version = version.into();
        if version.trim().is_empty() {
            return Err(H3Error::empty("policyVersion"));
        }
        Ok(Self {
            version,
            digest,
            pack,
        })
    }

    /// Approved policy version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Approved policy fingerprint.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Approved pack integration fingerprint.
    pub const fn pack(&self) -> &ContentDigest {
        &self.pack
    }
}

/// One host publication attempt with exact frozen inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidatePublication {
    publication_id: PublicationId,
    document: DocumentKey,
    expected_document_revision: u64,
    settings_version: u64,
    generation: GenerationRecord,
    candidate_html: String,
    provenance: String,
    source_bytes: Vec<u8>,
    css: Vec<PublicationFileInput>,
    resources: Vec<PublicationFileInput>,
    policy: PublicationPolicyIdentity,
    applied: AppliedEvaluation,
    expected_html: ExpectedTargetVersion,
    expected_receipt: ExpectedTargetVersion,
}

impl CandidatePublication {
    /// Creates a publication attempt. Exact digest and fingerprint checks are
    /// performed by [`PublicationOrchestrator::publish`] before any side
    /// effect.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publication_id: PublicationId,
        document: DocumentKey,
        expected_document_revision: u64,
        settings_version: u64,
        generation: GenerationRecord,
        candidate_html: impl Into<String>,
        provenance: impl Into<String>,
        source_bytes: impl Into<Vec<u8>>,
        css: Vec<PublicationFileInput>,
        resources: Vec<PublicationFileInput>,
        policy: PublicationPolicyIdentity,
        applied: AppliedEvaluation,
        expected_html: ExpectedTargetVersion,
        expected_receipt: ExpectedTargetVersion,
    ) -> Result<Self, H3Error> {
        let project = document.project_id();
        if expected_document_revision == 0 {
            return Err(H3Error::must_be_positive("expectedDocumentRevision"));
        }
        if settings_version == 0 {
            return Err(H3Error::must_be_positive("settingsVersion"));
        }
        publication_id.validate_in(project)?;
        generation.generation_id().validate_in(project)?;
        if generation.document_key() != &document {
            return Err(H3Error::invalid(
                "generation",
                "the generation belongs to another document",
            ));
        }
        if generation.candidate().is_none() {
            return Err(H3Error::invalid(
                "candidate",
                "the generation has no authored candidate",
            ));
        }
        Ok(Self {
            publication_id,
            document,
            expected_document_revision,
            settings_version,
            generation,
            candidate_html: candidate_html.into(),
            provenance: provenance.into(),
            source_bytes: source_bytes.into(),
            css,
            resources,
            policy,
            applied,
            expected_html,
            expected_receipt,
        })
    }

    /// Publication journal identifier.
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    /// Document being published.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Generation being published.
    pub const fn generation(&self) -> &GenerationRecord {
        &self.generation
    }

    /// Exact candidate HTML.
    pub fn candidate_html(&self) -> &str {
        &self.candidate_html
    }

    /// Exact candidate provenance payload.
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

    /// Applied H2 evaluation.
    pub const fn applied(&self) -> &AppliedEvaluation {
        &self.applied
    }

    /// Expected current HTML version or explicit absence.
    pub const fn expected_html(&self) -> &ExpectedTargetVersion {
        &self.expected_html
    }

    /// Expected current receipt version or explicit absence.
    pub const fn expected_receipt(&self) -> &ExpectedTargetVersion {
        &self.expected_receipt
    }
}

/// A receipt built from current exact inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltReceipt {
    path: String,
    text: String,
    digest: ContentDigest,
}

impl BuiltReceipt {
    /// Canonical project-relative receipt path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact receipt JSON text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Exact receipt digest.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// Reads one project-relative formal file.
pub trait PublicationFileReadPort {
    /// Returns exact bytes, explicit absence, or a sanitized failure.
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, H3Error>;

    /// Ensures the canonical parent directory of a formal path exists.
    ///
    /// The default implementation does nothing. The desktop host creates the
    /// canonical receipt directory before the journal intent and refuses a
    /// parent that escapes the project root.
    fn ensure_parent(&self, _path: &str) -> Result<(), H3Error> {
        Ok(())
    }
}

/// Exact inputs for the Common SDD final `candidate-check`.
#[derive(Debug)]
pub struct FinalCandidateCheckRequest<'a> {
    /// Project-relative Markdown path.
    pub source_path: &'a str,
    /// Exact Markdown bytes.
    pub source: &'a [u8],
    /// Project-relative companion path.
    pub html_path: &'a str,
    /// Exact candidate HTML bytes.
    pub html: &'a [u8],
    /// Project-relative receipt path.
    pub receipt_path: &'a str,
    /// Exact receipt text.
    pub receipt: &'a str,
    /// Exact CSS inputs.
    pub css: &'a [PublicationFileInput],
    /// Exact resource inputs.
    pub resources: &'a [PublicationFileInput],
}

/// Final validation result. A structural-only pass is not enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalCandidateCheck {
    /// Policy decision was allow.
    pub allowed: bool,
    /// The pack reported the final stage.
    pub final_pass: bool,
    /// The pack bound the receipt and every supplied input.
    pub final_binding: bool,
    /// Declared HTML contract.
    pub contract: String,
    /// Sanitized violation codes/messages.
    pub violations: Vec<String>,
}

/// Host port running the Common SDD final validation stage.
pub trait FinalCandidateCheckPort {
    /// Runs final `candidate-check` on the exact supplied bytes.
    fn check(
        &self,
        request: &FinalCandidateCheckRequest<'_>,
    ) -> Result<FinalCandidateCheck, H3Error>;
}

/// Host-only single-file publication writer used by the H3 journal.
pub trait HostPublicationPort {
    /// Publishes one exact file or returns the stored duplicate result.
    fn publish(
        &mut self,
        request: PublicationRequest,
    ) -> Result<PublicationResult, PublicationFailure>;
}

impl<S, A, G> HostPublicationPort for herness_core::runtime::PublicationWriter<S, A, G>
where
    S: herness_core::ports::publish::PublicationRecordPort,
    A: PublicationArchivePort,
    G: herness_core::ports::publish::PublicationGatePort,
{
    fn publish(
        &mut self,
        request: PublicationRequest,
    ) -> Result<PublicationResult, PublicationFailure> {
        herness_core::runtime::PublicationWriter::publish(self, request)
    }
}

/// Read-only re-check of stop, consent, approval, and remaining budget.
#[derive(Debug)]
pub struct PublicationSafetyRequest<'a> {
    /// Document being published.
    pub document: &'a DocumentKey,
    /// Generation being published.
    pub generation: &'a GenerationRecord,
    /// Current approved settings.
    pub settings: &'a H3Settings,
    /// H2 target version bound to the approved consent.
    pub target_version: TargetVersion,
    /// Fixed Html assessment profile.
    pub profile: ProfileBinding,
    /// Time of the re-check.
    pub now: Timestamp,
}

/// Result of the host safety re-check. Every flag must be true to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationSafety {
    /// No host stop or deadline applies.
    pub stop_requested: bool,
    /// The approved Html consent still covers this exact scope.
    pub consent_current: bool,
    /// The approved configuration is current and unrevoked.
    pub approval_current: bool,
    /// The H2 budget still has remaining capacity.
    pub budget_remaining: bool,
}

impl PublicationSafety {
    /// All checks hold.
    pub const fn permits_publication(&self) -> bool {
        !self.stop_requested
            && self.consent_current
            && self.approval_current
            && self.budget_remaining
    }
}

/// Host port re-reading publication preconditions.
pub trait PublicationSafetyPort {
    /// Re-checks exactly what the current attempt requires.
    fn recheck(
        &self,
        request: &PublicationSafetyRequest<'_>,
    ) -> Result<PublicationSafety, H3Error>;
}

/// Registers and retires the observer's expected publication write.
pub trait PublicationWriteExpectationPort {
    /// Registers the exact HTML/receipt bytes before any side effect.
    fn expect(
        &mut self,
        write: crate::observer::ExpectedPublicationWrite,
    ) -> Result<(), H3Error>;

    /// Removes the expectation after the journal reaches a terminal state.
    fn retire(&mut self, publication: PublicationId);
}

/// Publication result returned to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationOutcome {
    /// Both formal files were replaced, re-read, and the synced state was
    /// committed. `duplicate` means the journal already stored this result.
    Synced {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Document.
        document: DocumentKey,
        /// Generation.
        generation: crate::ids::GenerationId,
        /// Exact HTML digest at the formal path.
        html_digest: ContentDigest,
        /// Exact receipt digest at the formal path.
        receipt_digest: ContentDigest,
        /// Final project sequence of the synced commit.
        final_project_sequence: u64,
        /// Whether this was an idempotent replay.
        duplicate: bool,
    },
    /// The attempt is known not to have replaced a formal file.
    NotPublished {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Sanitized explanation.
        detail: String,
        /// Whether this was an idempotent replay.
        duplicate: bool,
    },
    /// A current version, path, or metadata conflict was detected.
    Conflict {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Conflicting project-relative path.
        target: String,
        /// Sanitized explanation.
        detail: String,
    },
    /// A human must resolve a consent, permission, or conflict condition.
    WaitingHuman {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Concrete wait cause.
        cause: HumanWaitCause,
        /// Sanitized explanation.
        detail: String,
    },
    /// A stop, budget, or unconfirmed stop prevented publication.
    Stopped {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Concrete stop cause.
        cause: H3StopCause,
        /// Sanitized explanation.
        detail: String,
    },
    /// A side effect may have happened; reconciliation is required.
    ReconciliationRequired {
        /// Publication journal identifier.
        publication: PublicationId,
        /// Sanitized explanation.
        detail: String,
    },
}

/// Journaled H3 publication orchestration over host ports.
pub struct PublicationOrchestrator<'a> {
    /// Durable H3 store.
    pub store: &'a mut dyn H3StorePort,
    /// Exact project read boundary.
    pub files: &'a dyn PublicationFileReadPort,
    /// Private old-version archive (H3 history and H1 writer share one root).
    pub archive: &'a mut dyn PublicationArchivePort,
    /// H1 host-only single-file writer.
    pub host: &'a mut dyn HostPublicationPort,
    /// Common SDD final validation stage.
    pub final_check: &'a dyn FinalCandidateCheckPort,
    /// Host safety re-check.
    pub safety: &'a dyn PublicationSafetyPort,
    /// Observer expectation boundary for self-notification.
    pub expectations: &'a mut dyn PublicationWriteExpectationPort,
    /// Shared stop/deadline control.
    pub control: &'a RunControl,
}

impl PublicationOrchestrator<'_> {
    /// Runs one idempotent publication attempt.
    pub fn publish(
        &mut self,
        attempt: CandidatePublication,
        now: Timestamp,
    ) -> Result<PublicationOutcome, H3Error> {
        let project = attempt.document.project_id();
        let fingerprint = attempt_fingerprint(&attempt)?;

        // Duplicate handling happens before any read or side effect.
        if let Some(journal) = self
            .store
            .load_html_sync_publication(project, attempt.publication_id())?
        {
            return duplicate_outcome(journal, &fingerprint);
        }

        let settings_record = self
            .store
            .load_html_sync_settings(project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.publication.settings".to_owned(),
                detail: "the project has no stored H3 settings".to_owned(),
            })?;
        let settings = settings_record.settings();
        let document_record = self
            .store
            .load_html_sync_document(project, attempt.document())?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: attempt.document().target_path().to_owned(),
            })?;

        let receipt_path = html_evidence_path(attempt.document());
        let mut journal = attempt_journal(&attempt, fingerprint, now)?;

        // Preflight: exact frozen inputs, settings, fingerprints, and state.
        if let Some(refusal) = self.preflight(&attempt, settings, &document_record, now)? {
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }

        // The receipt parent directory is the only host-created directory. It is
        // prepared only after every frozen input and approval check passed and
        // before the journal intent/side effects.
        if let Err(error) = self.files.ensure_parent(&receipt_path) {
            let detail = format!("the receipt directory could not be prepared: {error}");
            let refusal = Refusal::waiting(
                HumanWaitCause::CapabilityMissing,
                detail,
                RequiredAction::ReviewFailure,
            );
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }

        // Current formal files and the previous receipt/generation chain.
        let current_html = self.files.read(&attempt.document().companion_path())?;
        if let Some(detail) = expected_mismatch(
            &attempt.document().companion_path(),
            attempt.expected_html(),
            current_html.as_deref(),
        ) {
            let refusal = Refusal::conflict(
                HumanWaitCause::ExternalHtmlConflict,
                detail,
                attempt.document().companion_path(),
            );
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }
        let current_receipt = self.files.read(&receipt_path)?;
        if let Some(detail) = expected_mismatch(
            &receipt_path,
            attempt.expected_receipt(),
            current_receipt.as_deref(),
        ) {
            let refusal = Refusal::conflict(
                HumanWaitCause::ExternalHtmlConflict,
                format!("receipt metadata conflict: {detail}"),
                receipt_path,
            );
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }
        let previous_receipt = match current_receipt.as_deref() {
            Some(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => Some(text),
                Err(_) => {
                    let refusal = Refusal::conflict(
                        HumanWaitCause::ExternalHtmlConflict,
                        "the existing receipt is not UTF-8",
                        receipt_path,
                    );
                    return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
                }
            },
            None => None,
        };

        let receipt = match build_publication_receipt(&attempt, settings, previous_receipt) {
            Ok(receipt) => receipt,
            Err(error) => {
                let refusal = Refusal::conflict(
                    HumanWaitCause::ExternalHtmlConflict,
                    error.to_string(),
                    receipt_path,
                );
                return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
            }
        };
        journal = journal
            .with_receipt(
                &receipt_path,
                attempt.expected_receipt().clone(),
                receipt.digest().clone(),
                receipt_request_id(attempt.publication_id()),
                now,
            )?
            .with_file(
                PublicationFileJournal::pending(
                    PublicationFileRole::Receipt,
                    &receipt_path,
                    attempt.expected_receipt().clone(),
                    receipt.digest().clone(),
                    Some(receipt_request_id(attempt.publication_id())),
                    now,
                )?,
            )?;

        // Final pre-side-effect stop/safety check.
        if !self.control.permits_side_effect() {
            let detail = "the host stop or deadline is set before publication".to_owned();
            let refusal = Refusal::stopped(H3StopCause::HumanRequest, detail);
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }
        let safety = self.safety.recheck(&PublicationSafetyRequest {
            document: attempt.document(),
            generation: &attempt.generation,
            settings,
            target_version: attempt
                .applied
                .binding()
                .post_verification()
                .target_version(),
            profile: attempt.applied.binding().post_verification().profile(),
            now,
        })?;
        if !safety.permits_publication() {
            let refusal = safety_refusal(&safety);
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }

        // The pack's final stage is required. A structural-only result is never
        // accepted as publication evidence.
        let final_result = self.final_check.check(&FinalCandidateCheckRequest {
            source_path: attempt.document().target_path(),
            source: &attempt.source_bytes,
            html_path: &attempt.document().companion_path(),
            html: attempt.candidate_html.as_bytes(),
            receipt_path: receipt.path(),
            receipt: receipt.text(),
            css: &attempt.css,
            resources: &attempt.resources,
        })?;
        if !(final_result.allowed
            && final_result.final_pass
            && final_result.final_binding
            && final_result.contract == RECEIPT_CONTRACT)
        {
            let detail = if final_result.violations.is_empty() {
                "the Common SDD final candidate-check denied publication".to_owned()
            } else {
                format!(
                    "the Common SDD final candidate-check denied publication: {}",
                    final_result.violations.join("; ")
                )
            };
            let refusal = Refusal::failed(H3FailureCause::CandidateRejected, detail);
            return self.persist_terminal(&attempt, &document_record, journal, refusal, now);
        }

        // Persist the intent before the first side effect.
        let ready_reason = H3Reason::new(
            H3StateReasonKind::ReadyToPublish {
                generation: attempt.generation.generation_id(),
                publication: attempt.publication_id(),
            },
            Vec::new(),
        )?;
        let ready_document = rebuild_document(&document_record.state(), ready_reason, now)?;
        let prepared_event = crate::events::publication_event(&journal, now)?;
        let ready_event = crate::events::document_state_event(
            attempt.document(),
            Some(document_record.state().state()),
            &ready_document,
            now,
        )?;
        let prepared_outcome = match self.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(document_record.revision()),
                    ready_document,
                )?)
                .with_publication(journal.clone())
                .with_events(vec![ready_event, prepared_event]),
        )? {
            HtmlSyncCommitOutcome::Applied { document, .. } => document,
            HtmlSyncCommitOutcome::Duplicate { .. } => {
                return Err(H3Error::Storage {
                    detail: "the publication intent commit was reported as a duplicate".to_owned(),
                });
            }
        };
        let mut current_document = prepared_outcome.ok_or_else(|| H3Error::Storage {
            detail: "the publication intent commit returned no document".to_owned(),
        })?;

        // Save the exact old HTML and receipt before replacing either file.
        let old_html = match self.archive_old(
            attempt.document(),
            PublicationFileRole::Html,
            &attempt.document().companion_path(),
            &html_request_id(attempt.publication_id()),
            current_html.as_deref(),
        ) {
            Ok(saved) => saved,
            Err(error) => {
                let detail = format!("the old HTML version could not be archived: {error}");
                let journal = journal
                    .clone()
                    .failed(PublicationStatus::NotPublished, detail.clone(), now)?;
                return self.persist_terminal(
                    &attempt,
                    &current_document,
                    journal,
                    Refusal::waiting(
                        HumanWaitCause::CapacityInsufficient,
                        detail,
                        RequiredAction::FreeCapacity,
                    ),
                    now,
                );
            }
        };
        let old_receipt = match self.archive_old(
            attempt.document(),
            PublicationFileRole::Receipt,
            &receipt_path,
            &receipt_request_id(attempt.publication_id()),
            current_receipt.as_deref(),
        ) {
            Ok(saved) => saved,
            Err(error) => {
                let detail = format!("the old receipt could not be archived: {error}");
                let journal = journal
                    .clone()
                    .failed(PublicationStatus::NotPublished, detail.clone(), now)?;
                return self.persist_terminal(
                    &attempt,
                    &current_document,
                    journal,
                    Refusal::waiting(
                        HumanWaitCause::CapacityInsufficient,
                        detail,
                        RequiredAction::FreeCapacity,
                    ),
                    now,
                );
            }
        };
        let old_saved = journal.old_versions_saved(old_html, old_receipt, now)?;
        let old_saved_event = crate::events::publication_event(&old_saved, now)?;
        let old_saved_document = rebuild_document(
            &current_document.state(),
            H3Reason::new(
                H3StateReasonKind::ReadyToPublish {
                    generation: attempt.generation.generation_id(),
                    publication: attempt.publication_id(),
                },
                Vec::new(),
            )?,
            now,
        )?;
        let old_saved_outcome = self.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(current_document.revision()),
                    old_saved_document,
                )?)
                .with_publication(old_saved.clone())
                .with_events(vec![old_saved_event]),
        )?;
        current_document = match old_saved_outcome {
            HtmlSyncCommitOutcome::Applied { document, .. } => {
                document.ok_or_else(|| H3Error::Storage {
                    detail: "the old-version-saved commit returned no document".to_owned(),
                })?
            }
            HtmlSyncCommitOutcome::Duplicate { .. } => {
                return Err(H3Error::Storage {
                    detail: "the old-version-saved commit was reported as a duplicate".to_owned(),
                });
            }
        };

        // Register the observer expectation before writing, then persist the
        // replacing state. Both files remain single-file H1 requests.
        self.expectations.expect(
            crate::observer::ExpectedPublicationWrite::new(
                attempt.publication_id(),
                html_request_id(attempt.publication_id()),
                attempt.document().clone(),
                ContentDigest::sha256(attempt.candidate_html.as_bytes()),
            )?
            .with_receipt(receipt.digest().clone()),
        )?;

        let replacing = old_saved.replacing(now)?;
        let publishing_reason = H3Reason::new(
            H3StateReasonKind::Publishing {
                generation: attempt.generation.generation_id(),
                publication: attempt.publication_id(),
            },
            Vec::new(),
        )?;
        let publishing_document =
            rebuild_document(&current_document.state(), publishing_reason, now)?;
        let publishing_event = crate::events::publication_event(&replacing, now)?;
        let publishing_state_event = crate::events::document_state_event(
            attempt.document(),
            Some(current_document.state().state()),
            &publishing_document,
            now,
        )?;
        let replacing_outcome = self.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(
                    Some(current_document.revision()),
                    publishing_document,
                )?)
                .with_publication(replacing.clone())
                .with_events(vec![publishing_state_event, publishing_event]),
        )?;
        current_document = match replacing_outcome {
            HtmlSyncCommitOutcome::Applied { document, .. } => {
                document.ok_or_else(|| H3Error::Storage {
                    detail: "the replacing commit returned no document".to_owned(),
                })?
            }
            HtmlSyncCommitOutcome::Duplicate { .. } => {
                return Err(H3Error::Storage {
                    detail: "the replacing commit was reported as a duplicate".to_owned(),
                });
            }
        };

        // Publish the HTML through the H1 host-only single-file writer.
        let html_request = h1_request(
            attempt.publication_id(),
            &attempt.document,
            &attempt.document().companion_path(),
            attempt.expected_html(),
            &attempt.candidate_html,
            "publish the approved HTML companion",
        )?;
        if !self.control.permits_side_effect() {
            let detail = "the host stop or deadline is set before the HTML replacement".to_owned();
            let journal = replacing
                .clone()
                .failed(PublicationStatus::NotPublished, detail.clone(), now)?;
            return self.persist_terminal(
                &attempt,
                &current_document,
                journal,
                Refusal::stopped(H3StopCause::HumanRequest, detail),
                now,
            );
        }
        let html_result = match self.host.publish(html_request) {
            Ok(result) => result,
            Err(failure) => {
                return self.publication_failure(
                    &attempt,
                    &current_document,
                    replacing.clone(),
                    PublicationFileRole::Html,
                    failure,
                    now,
                );
            }
        };
        let journal = replacing
            .clone()
            .with_file(
                PublicationFileJournal::pending(
                    PublicationFileRole::Html,
                    attempt.document().companion_path(),
                    attempt.expected_html().clone(),
                    ContentDigest::sha256(attempt.candidate_html.as_bytes()),
                    Some(html_request_id(attempt.publication_id())),
                    now,
                )?
                .observed(published_file_digest(&html_result)?, now),
            )?;

        // Publish the receipt as a second single-file request.
        let receipt_request = h1_request(
            attempt.publication_id(),
            &attempt.document,
            &receipt_path,
            attempt.expected_receipt(),
            receipt.text(),
            "publish the approved evaluation receipt",
        )?;
        if !self.control.permits_side_effect() {
            let detail = "the host stop or deadline is set before the receipt replacement".to_owned();
            let journal = journal
                .clone()
                .with_file(
                    PublicationFileJournal::pending(
                        PublicationFileRole::Receipt,
                        &receipt_path,
                        attempt.expected_receipt().clone(),
                        receipt.digest().clone(),
                        Some(receipt_request_id(attempt.publication_id())),
                        now,
                    )?
                    .not_published(now),
                )?
                .unverifiable(detail.clone(), now);
            return self.persist_terminal(
                &attempt,
                &current_document,
                journal,
                Refusal::reconciliation(detail),
                now,
            );
        }
        let receipt_result = match self.host.publish(receipt_request) {
            Ok(result) => result,
            Err(failure) => {
                let journal = journal
                    .clone()
                    .with_file(
                        PublicationFileJournal::pending(
                            PublicationFileRole::Receipt,
                            &receipt_path,
                            attempt.expected_receipt().clone(),
                            receipt.digest().clone(),
                            Some(receipt_request_id(attempt.publication_id())),
                            now,
                        )?
                        .unverifiable(now),
                    )?
                    .unverifiable(
                        format!("the receipt publication did not complete: {failure}"),
                        now,
                    );
                return self.persist_terminal(
                    &attempt,
                    &current_document,
                    journal,
                    Refusal::reconciliation(format!(
                        "the HTML was published but the receipt was not: {failure}"
                    )),
                    now,
                );
            }
        };
        let journal = journal
            .clone()
            .with_file(
                PublicationFileJournal::pending(
                    PublicationFileRole::Receipt,
                    &receipt_path,
                    attempt.expected_receipt().clone(),
                    receipt.digest().clone(),
                    Some(receipt_request_id(attempt.publication_id())),
                    now,
                )?
                .observed(published_file_digest(&receipt_result)?, now),
            )?;

        // Re-read both formal files and the source/dependency set.
        let observed_html = self.files.read(&attempt.document().companion_path())?;
        let observed_receipt = self.files.read(&receipt_path)?;
        let html_digest = ContentDigest::sha256(attempt.candidate_html.as_bytes());
        let postcondition = postcondition_mismatch("html", &html_digest, observed_html.as_deref())
            .or_else(|| {
                postcondition_mismatch("receipt", receipt.digest(), observed_receipt.as_deref())
            });
        if let Some(detail) = postcondition {
            let journal = journal.unverifiable(detail.clone(), now);
            return self.persist_terminal(
                &attempt,
                &current_document,
                journal,
                Refusal::reconciliation(detail),
                now,
            );
        }
        if let Some(detail) = self.recheck_source_and_dependencies(&attempt)? {
            let journal = journal.unverifiable(detail.clone(), now);
            return self.persist_terminal(
                &attempt,
                &current_document,
                journal,
                Refusal::reconciliation(detail),
                now,
            );
        }

        // Persist the exact result and the synced state with the project
        // sequence in one H3 transaction. The journal's own sequence field is
        // filled by a follow-up commit once the sequence is known.
        let synced_reason = H3Reason::new(
            H3StateReasonKind::Synced {
                generation: attempt.generation.generation_id(),
                source_revision: attempt.generation.source().revision().get(),
                source_digest: attempt.generation.source().digest().clone(),
            },
            Vec::new(),
        )?;
        let synced_document = rebuild_synced_document(
            &current_document.state(),
            synced_reason,
            Applicability::current_synced(),
            now,
        )?;
        let published = journal
            .clone()
            .published_pair(html_digest.clone(), receipt.digest().clone(), None, now)?;
        let synced_event = crate::events::document_state_event(
            attempt.document(),
            Some(current_document.state().state()),
            &synced_document,
            now,
        )?;
        let publication_event = crate::events::publication_event(&published, now)?;
        let commit = HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(
                Some(current_document.revision()),
                synced_document,
            )?)
            .with_publication(published.clone())
            .with_events(vec![synced_event, publication_event]);
        let outcome = match self.store.commit_html_sync(commit) {
            Ok(outcome) => outcome,
            Err(error) => {
                // Both writes may already be on disk; the journal still says
                // replacing. Never claim synced.
                return Ok(PublicationOutcome::ReconciliationRequired {
                    publication: attempt.publication_id(),
                    detail: format!(
                        "both formal files were replaced but the synced state could not be committed: {error}"
                    ),
                });
            }
        };
        let final_sequence = match outcome {
            HtmlSyncCommitOutcome::Applied {
                document,
                final_project_sequence,
                ..
            } => {
                document.ok_or_else(|| H3Error::Storage {
                    detail: "the synced commit returned no document".to_owned(),
                })?;
                final_project_sequence
            }
            HtmlSyncCommitOutcome::Duplicate { .. } => {
                return Ok(PublicationOutcome::ReconciliationRequired {
                    publication: attempt.publication_id(),
                    detail: "the synced commit was reported as a duplicate".to_owned(),
                });
            }
        };
        self.expectations.retire(attempt.publication_id());

        // Best-effort: record the assigned sequence on the durable journal
        // without adding a second project sequence or state event. The synced
        // state and its sequence are already committed, so a failure here does
        // not turn the publication into an unknown result.
        let updated = published.with_final_project_sequence(final_sequence);
        let _ = self.store.update_html_sync_publication(updated);
        Ok(PublicationOutcome::Synced {
            publication: attempt.publication_id(),
            document: attempt.document().clone(),
            generation: attempt.generation.generation_id(),
            html_digest,
            receipt_digest: receipt.digest().clone(),
            final_project_sequence: final_sequence,
            duplicate: false,
        })
    }

    fn preflight(
        &self,
        attempt: &CandidatePublication,
        settings: &H3Settings,
        document: &H3DocumentRecord,
        now: Timestamp,
    ) -> Result<Option<Refusal>, H3Error> {
        let project = attempt.document.project_id();
        if settings.project_id() != project || document.state().project_id() != project {
            return Err(H3Error::CrossProject {
                id_kind: "publication".to_owned(),
                expected: project,
                found: settings.project_id(),
            });
        }
        if document.revision() != attempt.expected_document_revision {
            return Ok(Some(Refusal::plain(format!(
                "the document revision changed: expected {}, found {}",
                attempt.expected_document_revision,
                document.revision()
            ))));
        }
        if !settings.verify_fingerprint() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the stored H3 settings no longer match their approved fingerprint",
                RequiredAction::ApproveSettings,
            )));
        }
        if settings.version() != attempt.settings_version
            || document.state().settings_version() != attempt.settings_version
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the publication attempt was prepared for another settings version",
                RequiredAction::ApproveSettings,
            )));
        }
        let Some(approval) = settings.approval() else {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the project settings carry no human configuration approval",
                RequiredAction::ApproveSettings,
            )));
        };
        if !approval.is_current_at(now) {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the human configuration approval is revoked, superseded, or expired",
                RequiredAction::ApproveSettings,
            )));
        }
        if !approval.auto_publish() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the approved configuration does not allow automatic publication",
                RequiredAction::ApproveSettings,
            )));
        }
        if document.state().generation() != Some(attempt.generation.generation_id())
            || document.state().source() != attempt.generation.source()
        {
            return Ok(Some(Refusal::plain(
                "the saved document no longer names this generation and source revision",
            )));
        }
        if !matches!(
            document.state().state(),
            H3State::Assessing | H3State::ReadyToPublish | H3State::Publishing
        ) {
            return Ok(Some(Refusal::plain(
                "the document is not in a state that allows publication",
            )));
        }

        let candidate = attempt
            .generation
            .candidate()
            .ok_or_else(|| H3Error::invalid("candidate", "the generation has no candidate"))?;
        if candidate.html_digest() != &ContentDigest::sha256(attempt.candidate_html.as_bytes()) {
            return Ok(Some(Refusal::plain(
                "the supplied candidate bytes do not match the stored candidate digest",
            )));
        }
        if candidate.provenance_digest() != &ContentDigest::sha256(attempt.provenance.as_bytes()) {
            return Ok(Some(Refusal::plain(
                "the supplied provenance does not match the stored candidate digest",
            )));
        }
        if attempt.generation.source().digest() != &ContentDigest::sha256(&attempt.source_bytes) {
            return Ok(Some(Refusal::plain(
                "the supplied source bytes do not match the generation source digest",
            )));
        }
        if document.state().source().digest() != &ContentDigest::sha256(&attempt.source_bytes) {
            return Ok(Some(Refusal::plain(
                "the document source changed after the candidate was verified",
            )));
        }

        // Exact project bytes: the supplied source and dependencies must equal
        // what is currently on disk.
        match self.files.read(attempt.document().target_path())? {
            Some(bytes) if bytes == attempt.source_bytes => {}
            Some(_) => {
                return Ok(Some(Refusal::plain(
                    "the Markdown source changed after the candidate was verified",
                )));
            }
            None => {
                return Ok(Some(Refusal::plain(
                    "the Markdown source is no longer present",
                )));
            }
        }
        match self.collect_inputs(&attempt.css, DependencyKind::Css)? {
            Ok(css) => {
                if Some(&css) != attempt.generation.fingerprints().get(FingerprintKind::Css) {
                    return Ok(Some(Refusal::plain(
                        "the supplied CSS bytes do not match the generation CSS fingerprint",
                    )));
                }
            }
            Err(detail) => return Ok(Some(Refusal::plain(detail))),
        }
        match self.collect_inputs(&attempt.resources, DependencyKind::Resource)? {
            Ok(resources) => {
                if Some(&resources)
                    != attempt
                        .generation
                        .fingerprints()
                        .get(FingerprintKind::Resources)
                {
                    return Ok(Some(Refusal::plain(
                        "the supplied resource bytes do not match the generation resource fingerprint",
                    )));
                }
            }
            Err(detail) => return Ok(Some(Refusal::plain(detail))),
        }

        // Approved policy, pack, and settings identity.
        let fingerprints = attempt.generation.fingerprints();
        if attempt.policy.digest() != approval.versions().policy_fingerprint()
            || fingerprints.get(FingerprintKind::Policy) != Some(attempt.policy.digest())
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::CapabilityMissing,
                "the policy fingerprint does not match the approved and generation policy",
                RequiredAction::ApproveSettings,
            )));
        }
        if attempt.policy.pack() != approval.versions().pack_fingerprint() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::CapabilityMissing,
                "the pack fingerprint does not match the approved integration",
                RequiredAction::ApproveSettings,
            )));
        }
        if attempt.policy.version() != approval.versions().policy_version() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::CapabilityMissing,
                "the policy version does not match the approved integration",
                RequiredAction::ApproveSettings,
            )));
        }
        if fingerprints.get(FingerprintKind::Settings) != Some(settings.fingerprint()) {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the generation settings fingerprint differs from the approved settings",
                RequiredAction::ApproveSettings,
            )));
        }

        // H2 results must be current, complete, and bound to this candidate.
        if !attempt.applied.completion_ready() || attempt.applied.test_only() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::UndecidableAssessment,
                "the applied H2 evaluation is not completion-ready",
                RequiredAction::ReassessCandidate,
            )));
        }
        if !attempt.applied.binding().is_current() {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::UndecidableAssessment,
                "the H2 evaluation binding became stale",
                RequiredAction::ReassessCandidate,
            )));
        }
        if !attempt.applied.checks().all_pass() {
            return Ok(Some(Refusal::plain(
                "a mandatory common or render check did not pass",
            )));
        }
        let Some(render) = attempt.applied.checks().get(RequiredCheckKind::RealRender) else {
            return Ok(Some(Refusal::plain(
                "the real render required check is missing",
            )));
        };
        if render.status() != EvidenceCheckResult::Pass || !render.origin().is_native_render() {
            return Ok(Some(Refusal::plain(
                "the real render required check is not a native pass",
            )));
        }
        for condition in H3Condition::ALL {
            match attempt.applied.condition(condition) {
                Some(adoption) if adoption.met() => {}
                _ => {
                    return Ok(Some(Refusal::waiting(
                        HumanWaitCause::UndecidableAssessment,
                        format!("condition {condition} is not met"),
                        RequiredAction::ReassessCandidate,
                    )));
                }
            }
        }
        if !attempt
            .applied
            .consistency()
            .is_some_and(|consistency| consistency.met())
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::UndecidableAssessment,
                "the whole-document consistency assessment is not met",
                RequiredAction::ReassessCandidate,
            )));
        }
        let applied = attempt.applied.binding().post_verification();
        if applied.settings() != settings.fingerprint()
            || applied.policy() != attempt.policy.digest()
            || applied.pack() != attempt.policy.pack()
            || applied.source() != attempt.generation.source().digest()
            || applied.candidate() != &ContentDigest::sha256(attempt.candidate_html.as_bytes())
            || applied.provenance() != &ContentDigest::sha256(attempt.provenance.as_bytes())
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::UndecidableAssessment,
                "the saved evaluation fingerprints differ from the current inputs",
                RequiredAction::ReassessCandidate,
            )));
        }
        if applied.profile() != approval.assessment().profile()
            || applied.condition_version() != approval.owner_binding().condition_version()
            || applied.condition_digest() != approval.owner_binding().conditions_digest()
            || applied.target_version() != approval.assessment().consent().target_scope_version()
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::PermissionDenied,
                "the evaluation profile, condition, or target version differs from the approval",
                RequiredAction::ApproveSettings,
            )));
        }
        if Some(applied.css()) != fingerprints.get(FingerprintKind::Css)
            || Some(applied.resources()) != fingerprints.get(FingerprintKind::Resources)
        {
            return Ok(Some(Refusal::waiting(
                HumanWaitCause::UndecidableAssessment,
                "the evaluation CSS or resource fingerprints differ from the generation",
                RequiredAction::ReassessCandidate,
            )));
        }
        Ok(None)
    }

    fn collect_inputs(
        &self,
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
            match self.files.read(input.path())? {
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

    fn recheck_source_and_dependencies(
        &self,
        attempt: &CandidatePublication,
    ) -> Result<Option<String>, H3Error> {
        match self.files.read(attempt.document().target_path())? {
            Some(bytes) if bytes == attempt.source_bytes => {}
            Some(_) => {
                return Ok(Some(
                    "the Markdown source changed after the formal files were replaced".to_owned(),
                ));
            }
            None => {
                return Ok(Some(
                    "the Markdown source disappeared after the formal files were replaced"
                        .to_owned(),
                ));
            }
        }
        match self.collect_inputs(&attempt.css, DependencyKind::Css)? {
            Ok(css) if Some(&css) == attempt.generation.fingerprints().get(FingerprintKind::Css) => {}
            Ok(_) => {
                return Ok(Some(
                    "the CSS fingerprint changed after the formal files were replaced".to_owned(),
                ));
            }
            Err(detail) => return Ok(Some(detail)),
        }
        match self.collect_inputs(&attempt.resources, DependencyKind::Resource)? {
            Ok(resources)
                if Some(&resources)
                    == attempt
                        .generation
                        .fingerprints()
                        .get(FingerprintKind::Resources) => {}
            Ok(_) => {
                return Ok(Some(
                    "the resource fingerprint changed after the formal files were replaced"
                        .to_owned(),
                ));
            }
            Err(detail) => return Ok(Some(detail)),
        }
        Ok(None)
    }

    fn archive_old(
        &mut self,
        document: &DocumentKey,
        role: PublicationFileRole,
        path: &str,
        request_id: &PublicationRequestId,
        content: Option<&[u8]>,
    ) -> Result<Option<crate::state::ArchivedVersionRef>, H3Error> {
        let Some(content) = content else {
            return Ok(None);
        };
        let version = hash_bytes(content);
        let text = std::str::from_utf8(content)
            .map_err(|_| H3Error::invalid("archive", "the old version is not UTF-8"))?;
        let archive = OldVersionArchive::new(request_id, document.project_id(), path, &version, text);
        let archived: ArchivedVersion =
            self.archive
                .save_old_version(&archive)
                .map_err(|error| H3Error::Storage {
                    detail: format!(
                        "the {} old version could not be archived: {error}",
                        role.as_str()
                    ),
                })?;
        Ok(Some(crate::state::ArchivedVersionRef::new(
            archived.reference().as_str(),
            ContentDigest::parse(archived.version().as_str())
                .map_err(|error| H3Error::invalid("archiveVersion", error.to_string()))?,
        )?))
    }

    fn persist_terminal(
        &mut self,
        attempt: &CandidatePublication,
        document: &H3DocumentRecord,
        journal: PublicationJournal,
        refusal: Refusal,
        now: Timestamp,
    ) -> Result<PublicationOutcome, H3Error> {
        let journal = match refusal.kind {
            RefusalKind::Conflict => {
                journal.failed(PublicationStatus::Conflict, refusal.detail.clone(), now)?
            }
            RefusalKind::Reconciliation => journal.unverifiable(refusal.detail.clone(), now),
            RefusalKind::Plain => {
                if journal.status() == PublicationStatus::Unverifiable {
                    journal
                } else {
                    journal.failed(PublicationStatus::NotPublished, refusal.detail.clone(), now)?
                }
            }
            RefusalKind::Waiting | RefusalKind::Stopped | RefusalKind::Failed => journal
                .failed(PublicationStatus::NotPublished, refusal.detail.clone(), now)?,
        };
        let reason = refusal.reason(document)?;
        let next = rebuild_document(&document.state(), reason, now)?;
        let document_event = crate::events::document_state_event(
            attempt.document(),
            Some(document.state().state()),
            &next,
            now,
        )?;
        let publication_event = crate::events::publication_event(&journal, now)?;
        let outcome = self.store.commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(document.revision()), next)?)
                .with_publication(journal.clone())
                .with_events(vec![document_event, publication_event]),
        )?;
        match outcome {
            HtmlSyncCommitOutcome::Applied { .. } | HtmlSyncCommitOutcome::Duplicate { .. } => {}
        }
        self.expectations.retire(attempt.publication_id());
        Ok(refusal.outcome(attempt.publication_id(), journal.status()))
    }

    fn publication_failure(
        &mut self,
        attempt: &CandidatePublication,
        document: &H3DocumentRecord,
        journal: PublicationJournal,
        role: PublicationFileRole,
        failure: PublicationFailure,
        now: Timestamp,
    ) -> Result<PublicationOutcome, H3Error> {
        let detail = failure.to_string();
        let (path, expected, digest, request_id) = match role {
            PublicationFileRole::Html => (
                attempt.document().companion_path(),
                attempt.expected_html().clone(),
                ContentDigest::sha256(attempt.candidate_html.as_bytes()),
                html_request_id(attempt.publication_id()),
            ),
            PublicationFileRole::Receipt => (
                html_evidence_path(attempt.document()),
                attempt.expected_receipt().clone(),
                journal
                    .receipt_digest()
                    .cloned()
                    .unwrap_or_else(|| ContentDigest::sha256(b"")),
                receipt_request_id(attempt.publication_id()),
            ),
        };
        let unknown = matches!(
            failure,
            PublicationFailure::Unverifiable { .. }
                | PublicationFailure::ReconciliationRequired { .. }
        );
        let file = PublicationFileJournal::pending(
            role,
            path,
            expected,
            digest,
            Some(request_id),
            now,
        )?;
        let file = if unknown {
            file.unverifiable(now)
        } else {
            file.not_published(now)
        };
        let journal = if unknown {
            journal.with_file(file)?.unverifiable(detail.clone(), now)
        } else {
            journal
                .with_file(file)?
                .failed(PublicationStatus::NotPublished, detail.clone(), now)?
        };
        let refusal = if unknown {
            Refusal::reconciliation(detail)
        } else {
            match &failure {
                PublicationFailure::Stopped { .. } => {
                    Refusal::stopped(H3StopCause::HumanRequest, detail)
                }
                PublicationFailure::PermissionDenied { .. } => Refusal::waiting(
                    HumanWaitCause::PermissionDenied,
                    detail,
                    RequiredAction::ApproveSettings,
                ),
                PublicationFailure::ArchiveUnavailable { .. }
                | PublicationFailure::OldVersionSaveFailed { .. } => Refusal::waiting(
                    HumanWaitCause::CapacityInsufficient,
                    detail,
                    RequiredAction::FreeCapacity,
                ),
                PublicationFailure::VersionConflict { .. }
                | PublicationFailure::ExpectedAbsentButPresent { .. }
                | PublicationFailure::ExpectedPresentButAbsent { .. }
                | PublicationFailure::RequestConflict { .. } => Refusal::conflict(
                    HumanWaitCause::ExternalHtmlConflict,
                    detail,
                    attempt.document().companion_path(),
                ),
                _ => Refusal::plain(detail),
            }
        };
        self.persist_terminal(attempt, document, journal, refusal, now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalKind {
    Plain,
    Conflict,
    Waiting,
    Stopped,
    Failed,
    Reconciliation,
}

#[derive(Debug, Clone)]
struct Refusal {
    kind: RefusalKind,
    detail: String,
    cause: Option<HumanWaitCause>,
    stop: Option<H3StopCause>,
    failure: Option<H3FailureCause>,
    action: Option<RequiredAction>,
}

impl Refusal {
    fn plain(detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Plain,
            detail: detail.into(),
            cause: None,
            stop: None,
            failure: None,
            action: None,
        }
    }

    fn conflict(cause: HumanWaitCause, detail: impl Into<String>, target: impl AsRef<str>) -> Self {
        Self {
            kind: RefusalKind::Conflict,
            detail: format!("{}: {}", target.as_ref(), detail.into()),
            cause: Some(cause),
            stop: None,
            failure: None,
            action: Some(RequiredAction::ResolveHtmlConflict {
                target: target.as_ref().to_owned(),
            }),
        }
    }

    fn waiting(cause: HumanWaitCause, detail: impl Into<String>, action: RequiredAction) -> Self {
        Self {
            kind: RefusalKind::Waiting,
            detail: detail.into(),
            cause: Some(cause),
            stop: None,
            failure: None,
            action: Some(action),
        }
    }

    fn stopped(cause: H3StopCause, detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Stopped,
            detail: detail.into(),
            cause: None,
            stop: Some(cause),
            failure: None,
            action: Some(RequiredAction::ResumeCycle),
        }
    }

    fn failed(cause: H3FailureCause, detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Failed,
            detail: detail.into(),
            cause: None,
            stop: None,
            failure: Some(cause),
            action: Some(RequiredAction::ReviewFailure),
        }
    }

    fn reconciliation(detail: impl Into<String>) -> Self {
        Self {
            kind: RefusalKind::Reconciliation,
            detail: detail.into(),
            cause: Some(HumanWaitCause::RecoveryReconciliation),
            stop: None,
            failure: None,
            action: Some(RequiredAction::ReconcileRecovery),
        }
    }

    fn reason(&self, document: &H3DocumentRecord) -> Result<H3Reason, H3Error> {
        match self.kind {
            RefusalKind::Conflict | RefusalKind::Waiting | RefusalKind::Reconciliation => {
                H3Reason::new(
                    H3StateReasonKind::WaitingHuman {
                        cause: self
                            .cause
                            .unwrap_or(HumanWaitCause::RecoveryReconciliation),
                    },
                    self.action.clone().into_iter().collect(),
                )
            }
            RefusalKind::Stopped => H3Reason::new(
                H3StateReasonKind::Stopped {
                    cause: self.stop.unwrap_or(H3StopCause::HumanRequest),
                },
                vec![RequiredAction::ResumeCycle],
            ),
            RefusalKind::Failed => H3Reason::new(
                H3StateReasonKind::Failed {
                    cause: self.failure.unwrap_or(H3FailureCause::CandidateRejected),
                },
                vec![RequiredAction::ReviewFailure],
            ),
            RefusalKind::Plain => H3Reason::new(
                H3StateReasonKind::Pending {
                    source_revision: document.state().source().revision().get(),
                },
                vec![RequiredAction::WaitForStableSource],
            ),
        }
    }

    fn outcome(&self, publication: PublicationId, status: PublicationStatus) -> PublicationOutcome {
        match self.kind {
            RefusalKind::Conflict => PublicationOutcome::Conflict {
                publication,
                target: self
                    .action
                    .as_ref()
                    .and_then(|action| match action {
                        RequiredAction::ResolveHtmlConflict { target } => Some(target.clone()),
                        _ => None,
                    })
                    .unwrap_or_default(),
                detail: self.detail.clone(),
            },
            RefusalKind::Waiting => PublicationOutcome::WaitingHuman {
                publication,
                cause: self
                    .cause
                    .unwrap_or(HumanWaitCause::RecoveryReconciliation),
                detail: self.detail.clone(),
            },
            RefusalKind::Reconciliation => PublicationOutcome::ReconciliationRequired {
                publication,
                detail: self.detail.clone(),
            },
            RefusalKind::Stopped => PublicationOutcome::Stopped {
                publication,
                cause: self.stop.unwrap_or(H3StopCause::HumanRequest),
                detail: self.detail.clone(),
            },
            RefusalKind::Failed => PublicationOutcome::NotPublished {
                publication,
                detail: self.detail.clone(),
                duplicate: false,
            },
            RefusalKind::Plain => {
                if status == PublicationStatus::Unverifiable {
                    PublicationOutcome::ReconciliationRequired {
                        publication,
                        detail: self.detail.clone(),
                    }
                } else {
                    PublicationOutcome::NotPublished {
                        publication,
                        detail: self.detail.clone(),
                        duplicate: false,
                    }
                }
            }
        }
    }
}

fn safety_refusal(safety: &PublicationSafety) -> Refusal {
    if safety.stop_requested {
        return Refusal::stopped(
            H3StopCause::HumanRequest,
            "the host stop or deadline is set",
        );
    }
    if !safety.approval_current {
        return Refusal::waiting(
            HumanWaitCause::PermissionDenied,
            "the approved configuration is no longer current",
            RequiredAction::ApproveSettings,
        );
    }
    if !safety.consent_current {
        return Refusal::waiting(
            HumanWaitCause::PermissionDenied,
            "the approved Html consent no longer covers this exact target and profile",
            RequiredAction::ApproveSettings,
        );
    }
    Refusal::stopped(
        H3StopCause::BudgetLimit,
        "the H2 budget has no remaining capacity",
    )
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
        (ExpectedTargetVersion::Present { version }, None) => Some(format!(
            "{path} is missing; expected version {version}"
        )),
        (ExpectedTargetVersion::Present { version }, Some(bytes)) => {
            let observed = ContentDigest::sha256(bytes);
            if observed.as_str() == version.as_str() {
                None
            } else {
                Some(format!(
                    "{path} has version {observed}; expected {version}"
                ))
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
        None => Some(format!("the {role} file was not found after publication")),
        Some(bytes) if ContentDigest::sha256(bytes) == *expected => None,
        Some(bytes) => Some(format!(
            "the {role} bytes after publication are {}, not the approved {}",
            ContentDigest::sha256(bytes),
            expected
        )),
    }
}

fn duplicate_outcome(
    journal: PublicationJournal,
    fingerprint: &ContentDigest,
) -> Result<PublicationOutcome, H3Error> {
    if journal.request_fingerprint() != Some(fingerprint) {
        return Ok(PublicationOutcome::Conflict {
            publication: journal.publication_id(),
            target: journal
                .files()
                .first()
                .map(|file| file.path().to_owned())
                .unwrap_or_else(|| journal.document_key().companion_path()),
            detail: "the publication request id was reused with different inputs".to_owned(),
        });
    }
    match journal.status() {
        PublicationStatus::Published => {
            let Some(html) = journal.observed_after_html().cloned() else {
                return Ok(PublicationOutcome::ReconciliationRequired {
                    publication: journal.publication_id(),
                    detail: "the stored publication has no observed HTML digest".to_owned(),
                });
            };
            let Some(receipt) = journal.observed_after_receipt().cloned() else {
                return Ok(PublicationOutcome::ReconciliationRequired {
                    publication: journal.publication_id(),
                    detail: "the stored publication has no observed receipt digest".to_owned(),
                });
            };
            let Some(sequence) = journal.final_project_sequence() else {
                return Ok(PublicationOutcome::ReconciliationRequired {
                    publication: journal.publication_id(),
                    detail: "the stored publication has no final project sequence".to_owned(),
                });
            };
            Ok(PublicationOutcome::Synced {
                publication: journal.publication_id(),
                document: journal.document_key().clone(),
                generation: journal.generation_id(),
                html_digest: html,
                receipt_digest: receipt,
                final_project_sequence: sequence,
                duplicate: true,
            })
        }
        PublicationStatus::NotPublished => Ok(PublicationOutcome::NotPublished {
            publication: journal.publication_id(),
            detail: journal
                .detail()
                .unwrap_or("the stored publication was not published")
                .to_owned(),
            duplicate: true,
        }),
        PublicationStatus::Conflict => Ok(PublicationOutcome::Conflict {
            publication: journal.publication_id(),
            target: journal
                .files()
                .first()
                .map(|file| file.path().to_owned())
                .unwrap_or_else(|| journal.document_key().companion_path()),
            detail: journal
                .detail()
                .unwrap_or("the stored publication is in conflict")
                .to_owned(),
        }),
        PublicationStatus::Prepared
        | PublicationStatus::OldVersionSaved
        | PublicationStatus::Replacing
        | PublicationStatus::Unverifiable => Ok(PublicationOutcome::ReconciliationRequired {
            publication: journal.publication_id(),
            detail: "the stored publication has no durable terminal result".to_owned(),
        }),
    }
}

fn attempt_fingerprint(attempt: &CandidatePublication) -> Result<ContentDigest, H3Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fingerprint<'a> {
        publication: PublicationId,
        document: &'a DocumentKey,
        generation: crate::ids::GenerationId,
        generation_number: u64,
        candidate: &'a ContentDigest,
        provenance: &'a ContentDigest,
        source: &'a ContentDigest,
        expected_html: &'a ExpectedTargetVersion,
        expected_receipt: &'a ExpectedTargetVersion,
        settings_version: u64,
        policy_version: &'a str,
        policy: &'a ContentDigest,
        pack: &'a ContentDigest,
        css: Vec<(&'a str, ContentDigest)>,
        resources: Vec<(&'a str, ContentDigest)>,
    }
    let candidate = ContentDigest::sha256(attempt.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(attempt.provenance.as_bytes());
    let source = ContentDigest::sha256(&attempt.source_bytes);
    let value = Fingerprint {
        publication: attempt.publication_id,
        document: &attempt.document,
        generation: attempt.generation.generation_id(),
        generation_number: attempt.generation.generation(),
        candidate: &candidate,
        provenance: &provenance,
        source: &source,
        expected_html: &attempt.expected_html,
        expected_receipt: &attempt.expected_receipt,
        settings_version: attempt.settings_version,
        policy_version: attempt.policy.version(),
        policy: attempt.policy.digest(),
        pack: attempt.policy.pack(),
        css: attempt
            .css
            .iter()
            .map(|input| (input.path(), input.digest()))
            .collect(),
        resources: attempt
            .resources
            .iter()
            .map(|input| (input.path(), input.digest()))
            .collect(),
    };
    let bytes = serde_json::to_vec(&value).map_err(|error| H3Error::Corrupt {
        record: "publication fingerprint",
        detail: error.to_string(),
    })?;
    Ok(ContentDigest::sha256(&bytes))
}

fn attempt_journal(
    attempt: &CandidatePublication,
    fingerprint: ContentDigest,
    now: Timestamp,
) -> Result<PublicationJournal, H3Error> {
    let candidate = attempt
        .generation
        .candidate()
        .ok_or_else(|| H3Error::invalid("candidate", "the generation has no candidate"))?;
    let html_path = attempt.document.companion_path();
    let files = vec![PublicationFileJournal::pending(
        PublicationFileRole::Html,
        html_path,
        attempt.expected_html.clone(),
        candidate.html_digest().clone(),
        Some(html_request_id(attempt.publication_id)),
        now,
    )?];
    PublicationJournal::new(
        attempt.publication_id,
        attempt.document.clone(),
        attempt.generation.generation_id(),
        candidate.candidate_id(),
        html_request_id(attempt.publication_id),
        attempt.expected_html.clone(),
        candidate.html_digest().clone(),
        candidate.provenance_digest().clone(),
        attempt.generation.source().clone(),
        now,
    )
    .map(|journal| {
        journal
            .with_request_fingerprint(fingerprint)
            .with_files(files)
    })
}

fn receipt_request_id(publication: PublicationId) -> PublicationRequestId {
    PublicationRequestId::new(format!("{publication}:receipt"))
        .expect("an H3 publication id plus a role suffix is a valid request id")
}

fn html_request_id(publication: PublicationId) -> PublicationRequestId {
    PublicationRequestId::new(format!("{publication}:html"))
        .expect("an H3 publication id plus a role suffix is a valid request id")
}

fn h1_request(
    publication: PublicationId,
    document: &DocumentKey,
    target: &str,
    expected: &ExpectedTargetVersion,
    content: &str,
    purpose: &str,
) -> Result<PublicationRequest, H3Error> {
    let request_id = if target == document.companion_path() {
        html_request_id(publication)
    } else {
        receipt_request_id(publication)
    };
    PublicationRequest::new(
        document.project_id(),
        request_id,
        NonEmptyText::new(target)
            .map_err(|error| H3Error::invalid("publicationTarget", error.to_string()))?,
        expected.clone(),
        content,
        herness_core::Purpose::new(purpose)
            .map_err(|error| H3Error::invalid("publicationPurpose", error.to_string()))?,
    )
    .map_err(|error| H3Error::invalid("publicationRequest", error.to_string()))
}

fn rebuild_document(
    document: &H3DocumentState,
    reason: H3Reason,
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
        document.applicability().clone(),
        now,
    )
}

fn rebuild_synced_document(
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

fn validate_relative(path: &str, field: &str) -> Result<(), H3Error> {
    if path.is_empty() {
        return Err(H3Error::empty(field));
    }
    if path.len() > 4_096 {
        return Err(H3Error::invalid(field, "the path exceeds the byte limit"));
    }
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(H3Error::invalid(field, "the path must be project-relative"));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(H3Error::invalid(field, "the path must be canonical"));
    }
    Ok(())
}

fn file_version_digest(version: &FileVersion) -> Result<ContentDigest, H3Error> {
    ContentDigest::parse(version.as_str())
        .map_err(|error| H3Error::invalid("fileVersion", error.to_string()))
}

fn published_file_digest(result: &PublicationResult) -> Result<ContentDigest, H3Error> {
    if result.status() != herness_core::contracts::publication::PublicationStatus::Published {
        return Err(H3Error::Storage {
            detail: "the host writer returned a non-published file result".to_owned(),
        });
    }
    let version = result.observed_after_version().ok_or_else(|| H3Error::Storage {
        detail: "the host writer returned no observed version".to_owned(),
    })?;
    file_version_digest(version)
}

/// Builds a version 1 `sdd-html-receipt` from the current exact H2 results.
///
/// The receipt is auxiliary evidence, not an approval and not a signature. It
/// contains only paths, digests, version identities, decisions, and evidence
/// references; no secret, credential, prompt, or raw provider error is copied.
pub fn build_publication_receipt(
    attempt: &CandidatePublication,
    settings: &H3Settings,
    previous_receipt: Option<&str>,
) -> Result<BuiltReceipt, H3Error> {
    let document = attempt.document();
    let generation = &attempt.generation;
    let candidate = generation
        .candidate()
        .ok_or_else(|| H3Error::invalid("candidate", "the generation has no candidate"))?;
    let approval = settings
        .approval()
        .ok_or_else(|| H3Error::invalid("approval", "the settings have no human approval"))?;
    let h2 = generation.h2().ok_or_else(|| {
        H3Error::invalid("h2", "the generation has no H2 reference for the receipt")
    })?;
    let checks = attempt.applied.checks();
    if !checks.all_pass() {
        return Err(H3Error::invalid(
            "verification",
            "the receipt cannot be built without every mandatory check passing",
        ));
    }
    if !attempt.applied.completion_ready() || attempt.applied.test_only() {
        return Err(H3Error::invalid(
            "conditions",
            "the receipt cannot be built from a non-completion-ready or test-only evaluation",
        ));
    }
    if !attempt.applied.binding().is_current() {
        return Err(H3Error::invalid(
            "binding",
            "the receipt cannot be built from a stale evaluation binding",
        ));
    }
    let applied = attempt.applied.binding().post_verification();
    if applied.settings() != settings.fingerprint()
        || applied.policy() != attempt.policy.digest()
        || applied.pack() != attempt.policy.pack()
        || applied.source() != generation.source().digest()
        || applied.candidate() != &ContentDigest::sha256(attempt.candidate_html.as_bytes())
        || applied.provenance() != &ContentDigest::sha256(attempt.provenance.as_bytes())
    {
        return Err(H3Error::invalid(
            "fingerprints",
            "the applied evaluation does not bind the current inputs",
        ));
    }
    if approval.versions().policy_fingerprint() != attempt.policy.digest()
        || approval.versions().pack_fingerprint() != attempt.policy.pack()
    {
        return Err(H3Error::invalid(
            "policy",
            "the approved policy or pack fingerprint differs from the attempt",
        ));
    }
    if applied.profile() != approval.assessment().profile()
        || applied.condition_version() != approval.owner_binding().condition_version()
        || applied.condition_digest() != approval.owner_binding().conditions_digest()
        || applied.target_version() != approval.assessment().consent().target_scope_version()
    {
        return Err(H3Error::invalid(
            "versions",
            "the evaluation profile, condition, or target version differs from the approval",
        ));
    }

    let mut condition_entries = Vec::new();
    for condition in H3Condition::ALL {
        let adoption = attempt
            .applied
            .condition(condition)
            .ok_or_else(|| H3Error::invalid("conditions", "a condition adoption is missing"))?;
        if !adoption.met() {
            return Err(H3Error::invalid(
                "conditions",
                format!("condition {condition} is not met"),
            ));
        }
        if adoption.evidence_ids().is_empty() {
            return Err(H3Error::invalid(
                "conditions",
                format!("condition {condition} cites no evidence"),
            ));
        }
        condition_entries.push(json!({
            "id": condition.as_str(),
            "decision": "met",
            "evidence": adoption
                .evidence_ids()
                .iter()
                .map(|id| format!("h2-evidence:{id}"))
                .collect::<Vec<_>>(),
        }));
    }
    if !attempt
        .applied
        .consistency()
        .is_some_and(|consistency| consistency.met())
    {
        return Err(H3Error::invalid(
            "conditions",
            "the whole-document consistency assessment is not met",
        ));
    }

    let previous = match previous_receipt {
        Some(text) => Some(parse_previous_receipt(text)?),
        None => None,
    };
    let settings_identity = format!("settings:{}", settings.version());
    let profile = profile_identity(approval.assessment().profile());
    if let Some(previous) = &previous {
        if previous.generation.revision >= generation.generation() {
            return Err(H3Error::invalid(
                "generation.revision",
                "the receipt generation does not advance beyond the current receipt",
            ));
        }
        if previous.versions.settings == settings_identity
            && (previous.versions.profile != profile
                || previous.versions.rubric != crate::rubric::H3_RUBRIC_VERSION)
        {
            return Err(H3Error::invalid(
                "versions",
                "the profile or rubric changed without a new settings version",
            ));
        }
    }

    let mut css_entries = attempt
        .css
        .iter()
        .map(|input| {
            json!({
                "path": input.path(),
                "digest": prefixed_digest(&input.digest()),
            })
        })
        .collect::<Vec<_>>();
    css_entries.sort_by(|left, right| {
        left.get("path")
            .and_then(serde_json::Value::as_str)
            .cmp(&right.get("path").and_then(serde_json::Value::as_str))
    });
    if !attempt
        .css
        .iter()
        .any(|input| input.path() == SHARED_STYLESHEET)
    {
        return Err(H3Error::invalid(
            "inputs.css",
            "the receipt must fingerprint the shared stylesheet",
        ));
    }
    let mut resource_entries = attempt
        .resources
        .iter()
        .map(|input| {
            json!({
                "path": input.path(),
                "digest": prefixed_digest(&input.digest()),
            })
        })
        .collect::<Vec<_>>();
    resource_entries.sort_by(|left, right| {
        left.get("path")
            .and_then(serde_json::Value::as_str)
            .cmp(&right.get("path").and_then(serde_json::Value::as_str))
    });

    let verification_checks = vec![
        check_entry(
            checks
                .get(RequiredCheckKind::CommonStructural)
                .ok_or_else(|| H3Error::invalid("verification", "the structural check is missing"))?,
        )?,
        check_entry(
            checks
                .get(RequiredCheckKind::RealRender)
                .ok_or_else(|| H3Error::invalid("verification", "the render check is missing"))?,
        )?,
    ];

    let receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "version": RECEIPT_VERSION,
        "contract": RECEIPT_CONTRACT,
        "source": {
            "path": document.target_path(),
            "digest": prefixed_digest(generation.source().digest()),
        },
        "html": {
            "path": document.companion_path(),
            "digest": prefixed_digest(candidate.html_digest()),
        },
        "inputs": {
            "css": css_entries,
            "resources": resource_entries,
            "policy": {
                "version": attempt.policy.version(),
                "digest": prefixed_digest(attempt.policy.digest()),
            },
        },
        "versions": {
            "settings": settings_identity,
            "rubric": crate::rubric::H3_RUBRIC_VERSION,
            "profile": profile,
        },
        "generation": {
            "id": generation.generation_id().to_string(),
            "revision": generation.generation(),
            "parent": previous.as_ref().map(|previous| previous.generation.id.clone()),
            "job": generation.job_id().to_string(),
            "cycle": generation.cycle_id().to_string(),
        },
        "h2": {
            "reference": h2.supervision_id().to_string(),
            "purpose": "Html",
        },
        "verification": {
            "result": "pass",
            "checks": verification_checks,
        },
        "conditions": condition_entries,
    });
    let mut text = serde_json::to_string_pretty(&receipt).map_err(|error| H3Error::Corrupt {
        record: "publication receipt",
        detail: error.to_string(),
    })?;
    text.push('\n');
    let path = html_evidence_path(document);
    let digest = ContentDigest::sha256(text.as_bytes());
    Ok(BuiltReceipt { path, text, digest })
}

fn check_entry(check: &RequiredCheck) -> Result<serde_json::Value, H3Error> {
    let evidence = match check.evidence_id() {
        Some(id) => format!("h2-evidence:{id}"),
        None => {
            let bytes = serde_json::to_vec(check).map_err(|error| H3Error::Corrupt {
                record: "required check",
                detail: error.to_string(),
            })?;
            format!(
                "h3-check:{}:{}",
                check.kind().as_str(),
                ContentDigest::sha256(&bytes)
            )
        }
    };
    Ok(json!({
        "name": check.kind().as_str(),
        "decision": if check.status() == EvidenceCheckResult::Pass { "pass" } else { "fail" },
        "evidence": [evidence],
    }))
}

fn profile_identity(profile: ProfileBinding) -> String {
    format!(
        "profile:{}:{}",
        profile.profile_id(),
        profile.version().get()
    )
}

fn prefixed_digest(digest: &ContentDigest) -> String {
    format!("sha256:{}", digest.as_str())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviousReceipt {
    schema: String,
    version: u32,
    contract: String,
    source: PreviousArtifact,
    html: PreviousArtifact,
    inputs: serde_json::Value,
    versions: PreviousVersions,
    generation: PreviousGeneration,
    h2: serde_json::Value,
    verification: serde_json::Value,
    conditions: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviousArtifact {
    path: String,
    digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviousVersions {
    settings: String,
    rubric: String,
    profile: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviousGeneration {
    id: String,
    revision: u64,
    parent: Option<String>,
    job: String,
    cycle: String,
}

fn parse_previous_receipt(text: &str) -> Result<PreviousReceipt, H3Error> {
    let receipt: PreviousReceipt = serde_json::from_str(text).map_err(|error| {
        H3Error::invalid("receipt", format!("the existing receipt is invalid: {error}"))
    })?;
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.version != RECEIPT_VERSION
        || receipt.contract != RECEIPT_CONTRACT
    {
        return Err(H3Error::invalid(
            "receipt",
            "the existing receipt is not a version 1 semantic receipt",
        ));
    }
    if !receipt.source.path.ends_with(".md") || !receipt.html.path.ends_with(".html") {
        return Err(H3Error::invalid(
            "receipt",
            "the existing receipt paths are invalid",
        ));
    }
    if !receipt.source.digest.starts_with("sha256:")
        || !receipt.html.digest.starts_with("sha256:")
        || receipt.generation.id.trim().is_empty()
        || receipt.generation.job.trim().is_empty()
        || receipt.generation.cycle.trim().is_empty()
        || receipt
            .generation
            .parent
            .as_ref()
            .is_some_and(|parent| parent.trim().is_empty())
    {
        return Err(H3Error::invalid(
            "receipt",
            "the existing receipt generation or digests are invalid",
        ));
    }
    let css = receipt
        .inputs
        .get("css")
        .and_then(serde_json::Value::as_array)
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| H3Error::invalid("receipt", "the existing receipt has no CSS fingerprints"))?;
    if !css.iter().all(|entry| {
        entry.get("path").and_then(serde_json::Value::as_str).is_some()
            && entry
                .get("digest")
                .and_then(serde_json::Value::as_str)
                .is_some()
    }) {
        return Err(H3Error::invalid("receipt", "the existing receipt CSS entries are invalid"));
    }
    if receipt.inputs.get("resources").and_then(serde_json::Value::as_array).is_none() {
        return Err(H3Error::invalid("receipt", "the existing receipt resources are invalid"));
    }
    let policy = receipt
        .inputs
        .get("policy")
        .ok_or_else(|| H3Error::invalid("receipt", "the existing receipt has no policy identity"))?;
    if policy.get("version").and_then(serde_json::Value::as_str).is_none()
        || policy.get("digest").and_then(serde_json::Value::as_str).is_none()
    {
        return Err(H3Error::invalid("receipt", "the existing receipt policy identity is invalid"));
    }
    if receipt.h2.get("purpose").and_then(serde_json::Value::as_str) != Some("Html") {
        return Err(H3Error::invalid("receipt", "the existing receipt purpose is not Html"));
    }
    if !matches!(
        receipt.verification.get("result").and_then(serde_json::Value::as_str),
        Some("pass" | "fail")
    ) || receipt
        .verification
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|checks| checks.is_empty())
    {
        return Err(H3Error::invalid("receipt", "the existing receipt verification is invalid"));
    }
    let mut conditions = std::collections::BTreeSet::new();
    let condition_entries = receipt
        .conditions
        .as_array()
        .ok_or_else(|| H3Error::invalid("receipt", "the existing receipt conditions are invalid"))?;
    for condition in condition_entries {
        let id = condition
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| H3Error::invalid("receipt", "the existing receipt condition id is missing"))?;
        let decision = condition
            .get("decision")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| H3Error::invalid("receipt", "the existing receipt condition decision is missing"))?;
        if !matches!(decision, "met" | "unmet" | "insufficient" | "not_run" | "unavailable") {
            return Err(H3Error::invalid("receipt", "the existing receipt condition decision is invalid"));
        }
        if !conditions.insert(id) {
            return Err(H3Error::invalid("receipt", "the existing receipt has duplicate conditions"));
        }
    }
    for expected in ["information", "support", "usability", "render"] {
        if !conditions.contains(expected) {
            return Err(H3Error::invalid(
                "receipt",
                "the existing receipt does not contain all four conditions",
            ));
        }
    }
    Ok(receipt)
}
