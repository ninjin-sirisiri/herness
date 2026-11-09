//! H3 quit/crash reconciliation and human resume preflight.
//!
//! Recovery is read-mostly. [`RecoveryService::recover_project`] classifies the
//! durable H3/H2 state and current files without writing; [`RecoveryService::reconcile_project`]
//! persists only explicit human/recovery latches. Neither method starts a run,
//! sends a model request, authors a candidate, retries a publication, publishes,
//! or rolls back a formal file. The side-effect counters stay zero.
//!
//! Each crash boundary is reported explicitly. A `Prepared`/`OldVersionSaved`/
//! `Replacing`/`Unverifiable` publication journal is never returned as success,
//! and an after-one-file replacement is identified by role rather than repaired.
//! Current external HTML/receipt changes are preserved and require a human; this
//! module never overwrites or deletes them.
//!
//! A human resume/reassess first calls [`RecoveryService::resume_preflight`].
//! The current source digest, settings approval, Html profile/consent,
//! policy/pack identity, H2 recovery facts, and remaining budget must all still
//! match. A stale or exhausted value blocks the resume; recovery never invents a
//! new approval or a fresh budget.

use std::collections::BTreeMap;

use herness_core::{ProjectId, Timestamp};
use herness_supervision::budget::BudgetUsage;
use herness_supervision::{ClockPort, ContentDigest, SupervisionId, SupervisionState};
use serde::Serialize;

use crate::candidate::CandidateVerification;
use crate::coordinator::AuthoringJob;
use crate::document::{DocumentKey, FingerprintKind, SourceSnapshot};
use crate::error::H3Error;
use crate::events::document_state_event;
use crate::ids::{GenerationId, PublicationId};
use crate::observer::{DependencyKind, DependencyPath, html_evidence_path};
use crate::ports::{
    DocumentCommit, H3DocumentRecord, H3SettingsRecord, H3StorePort, HtmlSyncCommit,
};
use crate::state::{
    Applicability, ApplicabilityReason, CandidateRecord, CycleLatch, CycleState, H2Reference,
    H3DocumentState, H3Reason, H3State, H3StateReasonKind, H3StopCause, HumanWaitCause,
    PublicationFileRole, PublicationFileStatus, PublicationJournal, PublicationStatus,
    RequiredAction, SyncCycle,
};

/// One exact current candidate-byte check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateBytes {
    /// Both candidate slots hold exactly the recorded bytes.
    Present,
    /// The private namespace or a candidate slot is missing.
    Missing,
    /// The stored bytes differ from the candidate record.
    Mismatch {
        /// Candidate HTML bytes differ.
        html: bool,
        /// Provenance bytes differ.
        provenance: bool,
    },
    /// The private store could not be read.
    Unavailable {
        /// Sanitized failure detail.
        detail: String,
    },
}

/// Injected exact read boundary for recovery.
///
/// The desktop implementation reads through the observer's canonical
/// [`crate::observer::FilesystemSourceReader`]. Tests supply deterministic
/// values. No method writes a formal file.
pub trait RecoveryReadPort {
    /// Reads the current Markdown bytes, or `None` when absent.
    fn read_source(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error>;

    /// Reads the current formal HTML companion, or `None` when absent.
    fn read_companion(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error>;

    /// Reads the current receipt, or `None` when absent.
    fn read_receipt(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error>;

    /// Verifies the private candidate bytes referenced by the record.
    fn candidate_bytes(&self, candidate: &CandidateRecord) -> Result<CandidateBytes, H3Error>;

    /// Computes the current dependency fingerprint for one kind.
    ///
    /// `None` means a declared dependency could not be read. The caller supplies
    /// the host-owned dependency list; recovery never discovers paths itself.
    fn dependency_digest(
        &self,
        document: &DocumentKey,
        kind: DependencyKind,
        paths: &[DependencyPath],
    ) -> Result<Option<ContentDigest>, H3Error>;
}

/// One unresolved H2 model-request attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct H2RequestUnknown {
    attempt_id: String,
    kind: String,
    purpose: String,
}

impl H2RequestUnknown {
    /// Creates one unresolved request label.
    pub fn new(
        attempt_id: impl Into<String>,
        kind: impl Into<String>,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            kind: kind.into(),
            purpose: purpose.into(),
        }
    }

    /// Durable attempt identifier.
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// H2 classification label.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Host-owned purpose label.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

/// Durable H2 facts surfaced to H3 recovery.
///
/// This is a read-only snapshot. H3 never charges, resets, or reserves budget;
/// it carries the exact usage so a later human operation can decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct H2RecoveryFacts {
    supervision_id: SupervisionId,
    revision: u64,
    state: SupervisionState,
    resumable: bool,
    unresolved_requests: Vec<H2RequestUnknown>,
    stop_unconfirmed: bool,
    recovery_pending: bool,
    budget: BudgetUsage,
    remaining_active_seconds: u64,
    money_cap_micros: Option<u64>,
    budget_exhausted: bool,
    permissions_current: bool,
    profile_current: bool,
    consent_current: bool,
    approval_current: bool,
    block_labels: Vec<String>,
}

impl H2RecoveryFacts {
    /// Creates one read-only H2 recovery snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        supervision_id: SupervisionId,
        revision: u64,
        state: SupervisionState,
        resumable: bool,
        unresolved_requests: Vec<H2RequestUnknown>,
        stop_unconfirmed: bool,
        recovery_pending: bool,
        budget: BudgetUsage,
        remaining_active_seconds: u64,
        money_cap_micros: Option<u64>,
        budget_exhausted: bool,
        permissions_current: bool,
        profile_current: bool,
        consent_current: bool,
        approval_current: bool,
        block_labels: Vec<String>,
    ) -> Result<Self, H3Error> {
        if revision == 0 {
            return Err(H3Error::must_be_positive("h2RecoveryRevision"));
        }
        Ok(Self {
            supervision_id,
            revision,
            state,
            resumable,
            unresolved_requests,
            stop_unconfirmed,
            recovery_pending,
            budget,
            remaining_active_seconds,
            money_cap_micros,
            budget_exhausted,
            permissions_current,
            profile_current,
            consent_current,
            approval_current,
            block_labels,
        })
    }

    /// H2 target identifier.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Stored H2 revision observed by recovery.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Stored H2 state.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Whether H2's read-only recovery found no blocker.
    pub const fn resumable(&self) -> bool {
        self.resumable
    }

    /// Unresolved model-request attempts.
    pub fn unresolved_requests(&self) -> &[H2RequestUnknown] {
        &self.unresolved_requests
    }

    /// Whether H1 did not confirm a stop.
    pub const fn stop_unconfirmed(&self) -> bool {
        self.stop_unconfirmed
    }

    /// Whether H2 still requires recovery reconciliation.
    pub const fn recovery_pending(&self) -> bool {
        self.recovery_pending
    }

    /// Exact consumed/reserved budget, preserved across restart.
    pub const fn budget(&self) -> BudgetUsage {
        self.budget
    }

    /// Remaining active seconds under the stored policy.
    pub const fn remaining_active_seconds(&self) -> u64 {
        self.remaining_active_seconds
    }

    /// Configured money cap in micro-dollars, when any.
    pub const fn money_cap_micros(&self) -> Option<u64> {
        self.money_cap_micros
    }

    /// Whether the finite budget already blocks another run.
    pub const fn budget_exhausted(&self) -> bool {
        self.budget_exhausted
    }

    /// Whether the H1 permission context still authorizes the work.
    pub const fn permissions_current(&self) -> bool {
        self.permissions_current
    }

    /// Whether the approved profile binding still matches.
    pub const fn profile_current(&self) -> bool {
        self.profile_current
    }

    /// Whether the Html disclosure consent still matches.
    pub const fn consent_current(&self) -> bool {
        self.consent_current
    }

    /// Whether the condition approval is still valid.
    pub const fn approval_current(&self) -> bool {
        self.approval_current
    }

    /// Sanitized H2 block labels.
    pub fn block_labels(&self) -> &[String] {
        &self.block_labels
    }
}

/// One cooperative stop result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStop {
    /// No run existed for the document.
    NotRunning,
    /// H1 confirmed the stop.
    Confirmed,
    /// H1 did not confirm the stop; never claim it.
    Unconfirmed,
}

/// Host runtime facts used by recovery.
pub trait RecoveryRuntimePort {
    /// Loads H2 facts for the stored supervision target, when one exists.
    fn h2_facts(
        &mut self,
        document: &DocumentKey,
        h2: Option<&H2Reference>,
        cycle: Option<&SyncCycle>,
    ) -> Result<Option<H2RecoveryFacts>, H3Error>;

    /// Requests one cooperative stop for the document's active job, if any.
    fn request_stop(&mut self, document: &DocumentKey) -> Result<RecoveryStop, H3Error>;
}

/// One explicit recovery boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBoundary {
    /// No unresolved crash boundary was found.
    Clean,
    /// An active generation was restored and cannot be resumed automatically.
    ActiveWorkRestored,
    /// An open cycle was restored with no active generation.
    PendingCycleRestored,
    /// A publication intent exists but no old-version save is recorded.
    PendingPublicationIntent,
    /// Old versions were saved but replacement did not start.
    PublicationOldVersionSaved,
    /// Replacement was in progress.
    PublicationReplacing,
    /// Exactly one formal file was replaced.
    PublicationAfterOneFile,
    /// The publication result is unknown.
    PublicationUnverifiable,
    /// Both files were replaced but the synced sequence is missing.
    PublicationPublishedWithoutSequence,
    /// A synced document has no publication journal.
    PublicationJournalMissing,
    /// The recorded candidate bytes are missing.
    CandidateMissing,
    /// The recorded candidate bytes differ.
    CandidateMismatch,
    /// The current source differs from the stored source.
    StaleSource,
    /// The current source is absent.
    SourceMissing,
    /// The formal HTML differs from the recorded version.
    ExternalHtmlChange,
    /// The receipt differs from the recorded version or is absent.
    ReceiptChange,
    /// A CSS/resource fingerprint changed.
    DependencyChange,
    /// A declared dependency could not be read.
    DependencyUnavailable,
    /// H1 did not confirm a stop.
    StopUnconfirmed,
    /// An H2 model request remains unresolved.
    RequestUnknown,
    /// H2 recovery still has blockers.
    H2RecoveryPending,
    /// A restored document is deliberately unsynchronized.
    RestoredUnsynced,
}

impl RecoveryBoundary {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::ActiveWorkRestored => "active_work_restored",
            Self::PendingCycleRestored => "pending_cycle_restored",
            Self::PendingPublicationIntent => "pending_publication_intent",
            Self::PublicationOldVersionSaved => "publication_old_version_saved",
            Self::PublicationReplacing => "publication_replacing",
            Self::PublicationAfterOneFile => "publication_after_one_file",
            Self::PublicationUnverifiable => "publication_unverifiable",
            Self::PublicationPublishedWithoutSequence => "publication_published_without_sequence",
            Self::PublicationJournalMissing => "publication_journal_missing",
            Self::CandidateMissing => "candidate_missing",
            Self::CandidateMismatch => "candidate_mismatch",
            Self::StaleSource => "stale_source",
            Self::SourceMissing => "source_missing",
            Self::ExternalHtmlChange => "external_html_change",
            Self::ReceiptChange => "receipt_change",
            Self::DependencyChange => "dependency_change",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::StopUnconfirmed => "stop_unconfirmed",
            Self::RequestUnknown => "request_unknown",
            Self::H2RecoveryPending => "h2_recovery_pending",
            Self::RestoredUnsynced => "restored_unsynced",
        }
    }
}

/// One explicit recovery finding. The detail is for display only and carries no
/// raw candidate bytes, credentials, or provider error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryFinding {
    boundary: RecoveryBoundary,
    fingerprint: Option<FingerprintKind>,
    detail: String,
}

impl RecoveryFinding {
    /// Creates one finding.
    pub fn new(boundary: RecoveryBoundary, detail: impl Into<String>) -> Self {
        Self {
            boundary,
            fingerprint: None,
            detail: detail.into(),
        }
    }

    /// Creates one dependency finding with its exact changed kind.
    pub fn dependency(
        boundary: RecoveryBoundary,
        fingerprint: FingerprintKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            boundary,
            fingerprint: Some(fingerprint),
            detail: detail.into(),
        }
    }

    /// Structured boundary.
    pub const fn boundary(&self) -> RecoveryBoundary {
        self.boundary
    }

    /// Changed dependency kind, when this is a dependency finding.
    pub const fn fingerprint(&self) -> Option<FingerprintKind> {
        self.fingerprint
    }

    /// Sanitized display detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Recovery view of one publication journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationRecovery {
    publication: PublicationId,
    generation: GenerationId,
    status: PublicationStatus,
    boundary: RecoveryBoundary,
    html_status: PublicationFileStatus,
    receipt_status: Option<PublicationFileStatus>,
    expected_html: ContentDigest,
    expected_receipt: Option<ContentDigest>,
    observed_html: Option<ContentDigest>,
    observed_receipt: Option<ContentDigest>,
    current_html: Option<ContentDigest>,
    current_receipt: Option<ContentDigest>,
    final_project_sequence: Option<u64>,
}

impl PublicationRecovery {
    /// Publication identifier.
    pub const fn publication(&self) -> PublicationId {
        self.publication
    }

    /// Generation linked to the journal.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Stored journal status. Recovery never rewrites it to success.
    pub const fn status(&self) -> PublicationStatus {
        self.status
    }

    /// Explicit crash boundary for this journal.
    pub const fn boundary(&self) -> RecoveryBoundary {
        self.boundary
    }

    /// Per-file HTML state.
    pub const fn html_status(&self) -> PublicationFileStatus {
        self.html_status
    }

    /// Per-file receipt state, when the journal recorded one.
    pub const fn receipt_status(&self) -> Option<PublicationFileStatus> {
        self.receipt_status
    }

    /// Exact observed HTML digest stored after the attempt.
    pub const fn observed_html(&self) -> Option<&ContentDigest> {
        self.observed_html.as_ref()
    }

    /// Exact observed receipt digest stored after the attempt.
    pub const fn observed_receipt(&self) -> Option<&ContentDigest> {
        self.observed_receipt.as_ref()
    }

    /// Recorded expected HTML digest for this attempt.
    pub const fn expected_html(&self) -> &ContentDigest {
        &self.expected_html
    }

    /// Recorded expected receipt digest, when any.
    pub const fn expected_receipt(&self) -> Option<&ContentDigest> {
        self.expected_receipt.as_ref()
    }

    /// Current formal HTML digest observed during recovery.
    pub const fn current_html(&self) -> Option<&ContentDigest> {
        self.current_html.as_ref()
    }

    /// Current receipt digest observed during recovery.
    pub const fn current_receipt(&self) -> Option<&ContentDigest> {
        self.current_receipt.as_ref()
    }

    /// Final sequence, when the journal reached a complete sync.
    pub const fn final_project_sequence(&self) -> Option<u64> {
        self.final_project_sequence
    }
}

/// Recovery view of one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateRecovery {
    candidate: crate::ids::CandidateId,
    generation: GenerationId,
    bytes: CandidateBytes,
}

impl CandidateRecovery {
    /// Candidate identifier.
    pub const fn candidate(&self) -> crate::ids::CandidateId {
        self.candidate
    }

    /// Generation owning the candidate.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Exact private byte check.
    pub const fn bytes(&self) -> &CandidateBytes {
        &self.bytes
    }
}

/// Recovery result for one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentRecovery {
    document: DocumentKey,
    revision: u64,
    stored_state: H3State,
    next_state: H3State,
    boundaries: Vec<RecoveryBoundary>,
    findings: Vec<RecoveryFinding>,
    publications: Vec<PublicationRecovery>,
    candidate: Option<CandidateRecovery>,
    h2: Option<H2RecoveryFacts>,
    required_actions: Vec<RequiredAction>,
    latch: Option<CycleLatch>,
    state_changed: bool,
}

impl DocumentRecovery {
    /// Document.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Durable document CAS revision observed.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// State before reconciliation.
    pub const fn stored_state(&self) -> H3State {
        self.stored_state
    }

    /// State after reconciliation.
    pub const fn next_state(&self) -> H3State {
        self.next_state
    }

    /// Every explicit boundary found in canonical order.
    pub fn boundaries(&self) -> &[RecoveryBoundary] {
        &self.boundaries
    }

    /// Whether a boundary other than `Clean` was found.
    pub fn requires_human(&self) -> bool {
        self.boundaries
            .iter()
            .any(|boundary| *boundary != RecoveryBoundary::Clean)
    }

    /// Full findings.
    pub fn findings(&self) -> &[RecoveryFinding] {
        &self.findings
    }

    /// Publication journals considered for this document.
    pub fn publications(&self) -> &[PublicationRecovery] {
        &self.publications
    }

    /// Candidate byte check, when a candidate exists.
    pub const fn candidate(&self) -> Option<&CandidateRecovery> {
        self.candidate.as_ref()
    }

    /// H2 facts, when the document has a supervision target.
    pub const fn h2(&self) -> Option<&H2RecoveryFacts> {
        self.h2.as_ref()
    }

    /// Actions a human may take.
    pub fn required_actions(&self) -> &[RequiredAction] {
        &self.required_actions
    }

    /// Persisted latch after reconciliation.
    pub const fn latch(&self) -> Option<CycleLatch> {
        self.latch
    }

    /// Whether the next state differs from the stored state/reason.
    pub const fn state_changed(&self) -> bool {
        self.state_changed
    }
}

/// Counters proving recovery did no external work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySideEffects {
    /// Model requests sent. Always zero.
    pub model_requests: u32,
    /// H1 runs started. Always zero.
    pub runs_started: u32,
    /// Candidates authored. Always zero.
    pub candidates_authored: u32,
    /// Publication attempts executed. Always zero.
    pub publications: u32,
    /// Automatic resumes. Always zero.
    pub auto_resumes: u32,
    /// Tool executions. Always zero.
    pub tool_executions: u32,
}

impl RecoverySideEffects {
    /// Zero counters.
    pub const fn zero() -> Self {
        Self {
            model_requests: 0,
            runs_started: 0,
            candidates_authored: 0,
            publications: 0,
            auto_resumes: 0,
            tool_executions: 0,
        }
    }

    /// Whether every counter is zero.
    pub const fn is_zero(self) -> bool {
        self.model_requests == 0
            && self.runs_started == 0
            && self.candidates_authored == 0
            && self.publications == 0
            && self.auto_resumes == 0
            && self.tool_executions == 0
    }
}

/// One project's startup reconciliation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRecoveryReport {
    project_id: ProjectId,
    observed_at: Timestamp,
    settings: Option<H3SettingsRecord>,
    documents: Vec<DocumentRecovery>,
    request_results: usize,
    last_request_sequence: Option<u64>,
    committed: bool,
    side_effects: RecoverySideEffects,
}

impl ProjectRecoveryReport {
    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Observation time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Stored settings, when present.
    pub const fn settings(&self) -> Option<&H3SettingsRecord> {
        self.settings.as_ref()
    }

    /// Per-document recovery results.
    pub fn documents(&self) -> &[DocumentRecovery] {
        &self.documents
    }

    /// Number of stored idempotent H3 request results loaded.
    pub const fn request_results(&self) -> usize {
        self.request_results
    }

    /// Highest final project sequence among the loaded request results.
    pub const fn last_request_sequence(&self) -> Option<u64> {
        self.last_request_sequence
    }

    /// Whether reconciliation committed a local latch.
    pub const fn committed(&self) -> bool {
        self.committed
    }

    /// Proof that no request, run, candidate, or publication was started.
    pub const fn side_effects(&self) -> RecoverySideEffects {
        self.side_effects
    }

    /// Number of model requests sent during recovery. Always zero.
    pub const fn request_count(&self) -> u32 {
        self.side_effects.model_requests
    }
}

/// One human resume/reassess preflight block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeBlock {
    /// The caller observed an outdated document CAS revision.
    StaleRevision,
    /// The current source digest differs from the stored source.
    StaleSource,
    /// The current source is absent.
    SourceMissing,
    /// Settings or their human approval changed.
    SettingsChanged,
    /// The condition approval is expired, revoked, or superseded.
    ApprovalChanged,
    /// The Html profile binding changed.
    ProfileChanged,
    /// The Html disclosure consent changed or was revoked.
    ConsentChanged,
    /// The common SDD policy identity changed.
    PolicyChanged,
    /// The pack integration fingerprint changed.
    PackChanged,
    /// The finite budget is exhausted or a reservation is unresolved.
    BudgetExhausted,
    /// An H2 model request remains unresolved.
    RequestUnknown,
    /// H2 still has a recovery/stop/permission blocker.
    H2RecoveryPending,
    /// H1 did not confirm a stop.
    StopUnconfirmed,
    /// The current H1 permission context changed.
    PermissionsChanged,
    /// The stored document is not in a resumable state.
    StateNotResumable,
    /// A CSS/resource dependency changed while the process was stopped.
    DependencyChanged,
    /// The source is gone while the old companion remains.
    Orphaned,
}

/// One read-only human resume/reassess preflight request.
#[derive(Debug)]
pub struct ResumePreflightRequest<'a> {
    /// Document observed by the human operation.
    pub document: &'a DocumentKey,
    /// Durable revision the caller observed.
    pub expected_revision: u64,
    /// Current approved job context.
    pub job: &'a AuthoringJob,
    /// Current stored settings plus approval.
    pub settings: &'a H3SettingsRecord,
    /// Current exact source snapshot from the host rescan.
    pub observed_source: &'a SourceSnapshot,
    /// Current common SDD policy version.
    pub policy_version: &'a str,
    /// Current common SDD policy fingerprint.
    pub policy_digest: &'a ContentDigest,
    /// Current pack integration fingerprint.
    pub pack_digest: &'a ContentDigest,
    /// Current H2 recovery facts, when a supervision target exists.
    pub h2: Option<&'a H2RecoveryFacts>,
    /// Current host-selected authoring profile, when available.
    pub current_authoring_profile: Option<&'a herness_supervision::profiles::ProfileBinding>,
    /// Current host-selected authoring consent, when available.
    pub current_authoring_consent: Option<&'a herness_supervision::ConsentBinding>,
    /// Current host-selected Html profile, when available.
    pub current_html_profile: Option<&'a herness_supervision::profiles::ProfileBinding>,
    /// Current host-selected Html consent, when available.
    pub current_html_consent: Option<&'a herness_supervision::ConsentBinding>,
    /// Current time.
    pub now: Timestamp,
}

/// One read-only resume/reassess preflight result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumePreflight {
    document: DocumentKey,
    revision: u64,
    state: H3State,
    allowed: bool,
    blocks: Vec<ResumeBlock>,
    required_actions: Vec<RequiredAction>,
    budget: Option<BudgetUsage>,
    remaining_active_seconds: Option<u64>,
    side_effects: RecoverySideEffects,
}

impl ResumePreflight {
    /// Document.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Durable revision observed.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Current stored H3 state.
    pub const fn state(&self) -> H3State {
        self.state
    }

    /// Whether the human operation may proceed.
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    /// Structured blockers. Empty exactly when `allowed` is true.
    pub fn blocks(&self) -> &[ResumeBlock] {
        &self.blocks
    }

    /// Actions the human operation should perform after the preflight.
    pub fn required_actions(&self) -> &[RequiredAction] {
        &self.required_actions
    }

    /// Preserved H2 budget usage.
    pub const fn budget(&self) -> Option<BudgetUsage> {
        self.budget
    }

    /// Preserved remaining active seconds.
    pub const fn remaining_active_seconds(&self) -> Option<u64> {
        self.remaining_active_seconds
    }

    /// Proof that the preflight sent, started, or published nothing.
    pub const fn side_effects(&self) -> RecoverySideEffects {
        self.side_effects
    }
}

/// One document's quit result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuitDocument {
    document: DocumentKey,
    stop: RecoveryStop,
    state: H3State,
    committed: bool,
}

impl QuitDocument {
    /// Document.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Cooperative stop result.
    pub const fn stop(&self) -> RecoveryStop {
        self.stop
    }

    /// Saved H3 state after the quit hook.
    pub const fn state(&self) -> H3State {
        self.state
    }

    /// Whether a state/latch commit was written.
    pub const fn committed(&self) -> bool {
        self.committed
    }
}

/// One project's quit result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuitProjectReport {
    project_id: ProjectId,
    observed_at: Timestamp,
    documents: Vec<QuitDocument>,
    unconfirmed: Vec<DocumentKey>,
    stop_requests: u32,
    model_requests: u32,
    publications: u32,
    committed: bool,
}

impl QuitProjectReport {
    /// Project.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Observation time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Per-document quit results.
    pub fn documents(&self) -> &[QuitDocument] {
        &self.documents
    }

    /// Documents whose stop H1 did not confirm.
    pub fn unconfirmed(&self) -> &[DocumentKey] {
        &self.unconfirmed
    }

    /// Number of cooperative stop requests issued.
    pub const fn stop_requests(&self) -> u32 {
        self.stop_requests
    }

    /// Model requests sent during quit. Always zero.
    pub const fn model_requests(&self) -> u32 {
        self.model_requests
    }

    /// Publications executed during quit. Always zero.
    pub const fn publications(&self) -> u32 {
        self.publications
    }

    /// Whether any state/latch was committed.
    pub const fn committed(&self) -> bool {
        self.committed
    }
}

/// Recovery service over the durable H3 store and injected read/runtime ports.
pub struct RecoveryService<'a> {
    store: &'a mut dyn H3StorePort,
    reads: &'a dyn RecoveryReadPort,
    runtime: &'a mut dyn RecoveryRuntimePort,
    clock: &'a dyn ClockPort,
    dependencies: &'a BTreeMap<ProjectId, Vec<DependencyPath>>,
}

impl<'a> RecoveryService<'a> {
    /// Creates one read-mostly recovery service.
    pub fn new(
        store: &'a mut dyn H3StorePort,
        reads: &'a dyn RecoveryReadPort,
        runtime: &'a mut dyn RecoveryRuntimePort,
        clock: &'a dyn ClockPort,
        dependencies: &'a BTreeMap<ProjectId, Vec<DependencyPath>>,
    ) -> Self {
        Self {
            store,
            reads,
            runtime,
            clock,
            dependencies,
        }
    }

    /// Classifies every stored H3 document without writing any state.
    pub fn recover_project(
        &mut self,
        project: ProjectId,
    ) -> Result<ProjectRecoveryReport, H3Error> {
        self.project_report(project, false)
    }

    /// Classifies and persists only explicit recovery latches.
    ///
    /// Publication journals, generations, candidate metadata, formal files, and
    /// H2 budget rows are never changed. A clean synced document is left
    /// byte-for-byte unchanged.
    pub fn reconcile_project(
        &mut self,
        project: ProjectId,
    ) -> Result<ProjectRecoveryReport, H3Error> {
        self.project_report(project, true)
    }

    /// Runs one human resume/reassess preflight. It performs no write.
    pub fn resume_preflight(
        &mut self,
        request: ResumePreflightRequest<'_>,
    ) -> Result<ResumePreflight, H3Error> {
        let project = request.document.project_id();
        let record = self
            .store
            .load_html_sync_document(project, request.document)?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: request.document.target_path().to_owned(),
            })?;
        let state = record.state();
        let mut blocks = Vec::new();
        if request.expected_revision != record.revision() {
            blocks.push(ResumeBlock::StaleRevision);
        }
        if !matches!(
            state.state(),
            H3State::WaitingHuman | H3State::Stopped | H3State::Pending
        ) {
            blocks.push(ResumeBlock::StateNotResumable);
        }
        if state.state() == H3State::Orphaned {
            blocks.push(ResumeBlock::Orphaned);
        }
        if state.source().digest() != request.observed_source.digest() {
            blocks.push(ResumeBlock::StaleSource);
        }
        if state.settings_version() != request.settings.settings().version()
            || request.job.settings_version() != request.settings.settings().version()
            || state.fingerprints().get(FingerprintKind::Settings)
                != Some(request.job.settings_fingerprint())
        {
            blocks.push(ResumeBlock::SettingsChanged);
        }
        if request
            .job
            .verify_against(request.settings.settings(), request.now)
            .is_err()
        {
            blocks.push(ResumeBlock::SettingsChanged);
        }
        if request.job.policy_version() != request.policy_version
            || request.job.policy_fingerprint() != request.policy_digest
            || state.fingerprints().get(FingerprintKind::Policy) != Some(request.policy_digest)
        {
            blocks.push(ResumeBlock::PolicyChanged);
        }
        if request.job.pack_fingerprint() != request.pack_digest {
            blocks.push(ResumeBlock::PackChanged);
        }
        if let Some(approval) = request.settings.settings().approval() {
            if request
                .current_authoring_profile
                .is_some_and(|profile| profile != &approval.authoring().profile())
                || request
                    .current_authoring_consent
                    .is_some_and(|consent| consent != &approval.authoring().consent())
            {
                blocks.push(ResumeBlock::ProfileChanged);
                blocks.push(ResumeBlock::ConsentChanged);
            }
            if request
                .current_html_profile
                .is_some_and(|profile| profile != &approval.assessment().profile())
            {
                blocks.push(ResumeBlock::ProfileChanged);
            }
            if request
                .current_html_consent
                .is_some_and(|consent| consent != &approval.assessment().consent())
            {
                blocks.push(ResumeBlock::ConsentChanged);
            }
        }
        let mut budget = None;
        let mut remaining = None;
        if state.h2().is_some() && request.h2.is_none() {
            blocks.push(ResumeBlock::H2RecoveryPending);
        }
        if let Some(h2) = request.h2 {
            budget = Some(h2.budget());
            remaining = Some(h2.remaining_active_seconds());
            if !h2.unresolved_requests().is_empty() {
                blocks.push(ResumeBlock::RequestUnknown);
            }
            if h2.stop_unconfirmed() {
                blocks.push(ResumeBlock::StopUnconfirmed);
            }
            if !h2.permissions_current() {
                blocks.push(ResumeBlock::PermissionsChanged);
            }
            if !h2.profile_current() {
                blocks.push(ResumeBlock::ProfileChanged);
            }
            if !h2.consent_current() {
                blocks.push(ResumeBlock::ConsentChanged);
            }
            if !h2.approval_current() {
                blocks.push(ResumeBlock::ApprovalChanged);
            }
            if h2.budget_exhausted()
                || h2.remaining_active_seconds() == 0
                || !h2.budget().permits_run_start(request.job.budget())
                || !h2.budget().within_money_cap(request.job.budget())
            {
                blocks.push(ResumeBlock::BudgetExhausted);
            }
            if !h2.resumable()
                || h2.recovery_pending()
                || !matches!(
                    h2.state(),
                    SupervisionState::Ready
                        | SupervisionState::WaitingHuman
                        | SupervisionState::Stopped
                        | SupervisionState::Cancelled
                )
            {
                blocks.push(ResumeBlock::H2RecoveryPending);
            }
        }
        if !self.dependencies_current(state)? {
            blocks.push(ResumeBlock::DependencyChanged);
        }
        blocks.sort_by_key(|block| format!("{block:?}"));
        blocks.dedup();
        let allowed = blocks.is_empty();
        let required_actions = if allowed {
            vec![RequiredAction::ReassessCandidate]
        } else {
            state.reason().required_actions().to_vec()
        };
        Ok(ResumePreflight {
            document: request.document.clone(),
            revision: record.revision(),
            state: state.state(),
            allowed,
            blocks,
            required_actions,
            budget,
            remaining_active_seconds: remaining,
            side_effects: RecoverySideEffects::zero(),
        })
    }

    /// Requests cooperative stops and persists the quit/recovery latch.
    ///
    /// `confirmed_stops` maps a document to an H1-confirmed stop fact already
    /// observed by the quit flow. An absent fact requests one stop through the
    /// runtime port. A missing or unconfirmed fact is never reported as a stop.
    pub fn quit_project(
        &mut self,
        project: ProjectId,
        confirmed_stops: &BTreeMap<DocumentKey, bool>,
    ) -> Result<QuitProjectReport, H3Error> {
        let now = self.clock.now();
        let documents = self.store.list_html_sync_documents(project)?;
        let mut results = Vec::new();
        let mut unconfirmed = Vec::new();
        let mut stop_requests = 0_u32;
        let mut committed = false;
        for record in documents {
            let state = record.state();
            let active = matches!(
                state.state(),
                H3State::Pending
                    | H3State::Authoring
                    | H3State::Verifying
                    | H3State::Assessing
                    | H3State::ReadyToPublish
                    | H3State::Publishing
            );
            if !active {
                results.push(QuitDocument {
                    document: state.document_key().clone(),
                    stop: RecoveryStop::NotRunning,
                    state: state.state(),
                    committed: false,
                });
                continue;
            }
            let stop = match confirmed_stops.get(state.document_key()) {
                Some(true) => RecoveryStop::Confirmed,
                Some(false) => RecoveryStop::Unconfirmed,
                None => {
                    stop_requests = stop_requests.saturating_add(1);
                    self.runtime.request_stop(state.document_key())?
                }
            };
            let confirmed = matches!(stop, RecoveryStop::Confirmed | RecoveryStop::NotRunning);
            if !confirmed {
                unconfirmed.push(state.document_key().clone());
            }
            let reason = if confirmed {
                H3Reason::new(
                    H3StateReasonKind::Stopped {
                        cause: H3StopCause::RecoveryReconciliation,
                    },
                    vec![RequiredAction::ReconcileRecovery],
                )?
            } else {
                H3Reason::new(
                    H3StateReasonKind::Stopped {
                        cause: H3StopCause::StopUnconfirmed,
                    },
                    vec![RequiredAction::ReconcileRecovery],
                )?
            };
            let next = rebuild_document(
                &state,
                reason,
                Applicability::not_applicable(ApplicabilityReason::NeverPublished),
                now,
            )?;
            let cycle = self.load_cycle(project, &state)?;
            self.commit_document(
                &record,
                &next,
                cycle,
                Some(CycleLatch::RecoveryReconciliation),
                now,
            )?;
            committed = true;
            results.push(QuitDocument {
                document: state.document_key().clone(),
                stop,
                state: next.state(),
                committed: true,
            });
        }
        Ok(QuitProjectReport {
            project_id: project,
            observed_at: now,
            documents: results,
            unconfirmed,
            stop_requests,
            model_requests: 0,
            publications: 0,
            committed,
        })
    }

    fn project_report(
        &mut self,
        project: ProjectId,
        persist: bool,
    ) -> Result<ProjectRecoveryReport, H3Error> {
        let now = self.clock.now();
        let settings = self.store.load_html_sync_settings(project)?;
        let documents = self.store.list_html_sync_documents(project)?;
        let request_results = self.store.list_html_sync_request_results(project)?;
        let last_request_sequence = request_results
            .iter()
            .map(|stored| stored.result().final_project_sequence())
            .max();
        let empty_dependencies = Vec::new();
        let deps = self
            .dependencies
            .get(&project)
            .unwrap_or(&empty_dependencies);
        let mut results = Vec::new();
        let mut committed = false;
        for record in documents {
            let recovery = self.analyze_document(project, &record, deps)?;
            if persist && recovery.state_changed {
                let state = record.state();
                let next = next_document_state(&state, &recovery, now)?;
                let cycle = self.load_cycle(project, &state)?;
                self.commit_document(&record, &next, cycle, recovery.latch, now)?;
                committed = true;
            }
            results.push(recovery);
        }
        Ok(ProjectRecoveryReport {
            project_id: project,
            observed_at: now,
            settings,
            documents: results,
            request_results: request_results.len(),
            last_request_sequence,
            committed,
            side_effects: RecoverySideEffects::zero(),
        })
    }

    fn analyze_document(
        &mut self,
        project: ProjectId,
        record: &H3DocumentRecord,
        dependencies: &[DependencyPath],
    ) -> Result<DocumentRecovery, H3Error> {
        let document = record.state().document_key().clone();
        let state = record.state();
        let generations = self.store.html_sync_generations(project, &document)?;
        let current_generation = state.generation().and_then(|id| {
            generations
                .iter()
                .find(|generation| generation.generation_id() == id)
        });
        let publications = self.store.list_html_sync_publications(project, &document)?;
        let cycle = self.load_cycle(project, &state)?;
        let h2 = self
            .runtime
            .h2_facts(&document, state.h2(), cycle.as_ref())?;
        let mut findings = Vec::new();

        let source = self.reads.read_source(&document)?;
        match &source {
            None => findings.push(RecoveryFinding::new(
                RecoveryBoundary::SourceMissing,
                "the Markdown source is absent",
            )),
            Some(bytes) => {
                let observed = ContentDigest::sha256(bytes);
                if &observed != state.source().digest() {
                    findings.push(RecoveryFinding::new(
                        RecoveryBoundary::StaleSource,
                        format!(
                            "the current source digest {observed} differs from the stored {}",
                            state.source().digest()
                        ),
                    ));
                }
            }
        }

        for (kind, fingerprint_kind) in [
            (DependencyKind::Css, FingerprintKind::Css),
            (DependencyKind::Resource, FingerprintKind::Resources),
        ] {
            let paths = dependencies
                .iter()
                .filter(|dependency| dependency.kind() == kind)
                .cloned()
                .collect::<Vec<_>>();
            if paths.is_empty() {
                // The host did not supply the dependency path set. Recovery
                // does not invent a fingerprint or call the stored value stale.
                continue;
            }
            let observed = self.reads.dependency_digest(&document, kind, &paths)?;
            match observed {
                Some(observed) => {
                    if state.fingerprints().get(fingerprint_kind) != Some(&observed) {
                        findings.push(RecoveryFinding::dependency(
                            RecoveryBoundary::DependencyChange,
                            fingerprint_kind,
                            format!("the current {fingerprint_kind:?} fingerprint differs"),
                        ));
                    }
                }
                None => findings.push(RecoveryFinding::dependency(
                    RecoveryBoundary::DependencyUnavailable,
                    fingerprint_kind,
                    format!("a declared {fingerprint_kind:?} dependency could not be read"),
                )),
            }
        }

        let mut candidate_recovery = None;
        if let Some(generation) = current_generation
            && let Some(candidate) = generation.candidate()
        {
            let bytes = match self.reads.candidate_bytes(candidate) {
                Ok(bytes) => bytes,
                Err(error) => CandidateBytes::Unavailable {
                    detail: error.to_string(),
                },
            };
            match &bytes {
                CandidateBytes::Missing => findings.push(RecoveryFinding::new(
                    RecoveryBoundary::CandidateMissing,
                    "the recorded candidate bytes are missing from private storage",
                )),
                CandidateBytes::Mismatch { html, provenance } => {
                    findings.push(RecoveryFinding::new(
                        RecoveryBoundary::CandidateMismatch,
                        format!(
                            "the recorded candidate bytes differ (html={html}, provenance={provenance})"
                        ),
                    ))
                }
                CandidateBytes::Unavailable { detail } => findings.push(RecoveryFinding::new(
                    RecoveryBoundary::CandidateMissing,
                    format!("the candidate store is unavailable: {detail}"),
                )),
                CandidateBytes::Present => {}
            }
            candidate_recovery = Some(CandidateRecovery {
                candidate: candidate.candidate_id(),
                generation: generation.generation_id(),
                bytes,
            });
        }

        let mut publication_recoveries = Vec::new();
        let current_publication = current_generation
            .and_then(|generation| generation.publication())
            .and_then(|publication| {
                publications
                    .iter()
                    .find(|journal| journal.publication_id() == publication)
            })
            .or_else(|| {
                state.generation().and_then(|id| {
                    publications
                        .iter()
                        .find(|journal| journal.generation_id() == id)
                })
            });
        for journal in &publications {
            let considered = matches!(
                journal.status(),
                PublicationStatus::Prepared
                    | PublicationStatus::OldVersionSaved
                    | PublicationStatus::Replacing
                    | PublicationStatus::Unverifiable
            ) || (journal.status() == PublicationStatus::Published
                && journal.final_project_sequence().is_none())
                || current_publication == Some(journal);
            if !considered {
                continue;
            }
            let recovery = analyze_publication(&document, journal, self.reads)?;
            if recovery.boundary != RecoveryBoundary::Clean {
                findings.push(RecoveryFinding::new(
                    recovery.boundary,
                    match recovery.boundary {
                        RecoveryBoundary::ExternalHtmlChange => {
                            "the formal HTML differs from the recorded publication".to_owned()
                        }
                        RecoveryBoundary::ReceiptChange => {
                            "the formal receipt differs from the recorded publication".to_owned()
                        }
                        _ => format!(
                            "publication {} is {:?}",
                            recovery.publication, recovery.status
                        ),
                    },
                ));
            }
            publication_recoveries.push(recovery);
        }

        if state.state() == H3State::Synced && current_publication.is_none() {
            findings.push(RecoveryFinding::new(
                RecoveryBoundary::PublicationJournalMissing,
                "a synced document has no publication journal",
            ));
        }

        if matches!(
            state.applicability().reason(),
            ApplicabilityReason::Restored { .. }
        ) && state.state() == H3State::WaitingHuman
        {
            findings.push(RecoveryFinding::new(
                RecoveryBoundary::RestoredUnsynced,
                "the document was restored from history and stays unsynchronized",
            ));
        }

        if (state.h2().is_some()
            || cycle
                .as_ref()
                .is_some_and(|cycle| cycle.supervision_id().is_some()))
            && h2.is_none()
        {
            findings.push(RecoveryFinding::new(
                RecoveryBoundary::H2RecoveryPending,
                "the stored H2 target could not be loaded for recovery",
            ));
        }
        if let Some(h2) = &h2 {
            if h2.stop_unconfirmed() {
                findings.push(RecoveryFinding::new(
                    RecoveryBoundary::StopUnconfirmed,
                    "H1 did not confirm the previous stop",
                ));
            }
            if !h2.unresolved_requests().is_empty() {
                findings.push(RecoveryFinding::new(
                    RecoveryBoundary::RequestUnknown,
                    format!(
                        "{} H2 model request(s) remain unresolved",
                        h2.unresolved_requests().len()
                    ),
                ));
            }
            if !h2.resumable()
                || h2.recovery_pending()
                || h2.budget_exhausted()
                || !h2.permissions_current()
                || !h2.profile_current()
                || !h2.consent_current()
                || !h2.approval_current()
            {
                findings.push(RecoveryFinding::new(
                    RecoveryBoundary::H2RecoveryPending,
                    "the H2 target still has recovery blockers",
                ));
            }
        }

        if findings.is_empty() {
            let active = matches!(
                state.state(),
                H3State::Authoring
                    | H3State::Verifying
                    | H3State::Assessing
                    | H3State::ReadyToPublish
                    | H3State::Publishing
            );
            if active {
                findings.push(RecoveryFinding::new(
                    RecoveryBoundary::ActiveWorkRestored,
                    "active work cannot resume without a human decision",
                ));
            } else if state.state() == H3State::Pending && state.cycle_id().is_some() {
                findings.push(RecoveryFinding::new(
                    RecoveryBoundary::PendingCycleRestored,
                    "the process restarted with an unfinished cycle",
                ));
            }
        }
        findings.sort_by(|left, right| {
            (left.boundary.as_str(), left.detail.as_str())
                .cmp(&(right.boundary.as_str(), right.detail.as_str()))
        });
        findings.dedup();
        let boundaries = if findings.is_empty() {
            vec![RecoveryBoundary::Clean]
        } else {
            let mut boundaries = findings
                .iter()
                .map(|finding| finding.boundary)
                .collect::<Vec<_>>();
            boundaries.sort_by_key(|boundary| boundary.as_str());
            boundaries.dedup();
            boundaries
        };
        let plan = recovery_plan(&state, &findings, &publication_recoveries);
        let next_state = plan.next_state;
        let latch_changed = plan.latch.is_some_and(|latch| {
            cycle.as_ref().is_some_and(|cycle| {
                cycle.state() == CycleState::Open && cycle.latch() != Some(latch)
            })
        });
        let state_changed = next_state != state.state()
            || &plan.reason != state.reason()
            || plan.applicability != *state.applicability()
            || latch_changed;
        Ok(DocumentRecovery {
            document,
            revision: record.revision(),
            stored_state: state.state(),
            next_state,
            boundaries,
            findings,
            publications: publication_recoveries,
            candidate: candidate_recovery,
            h2,
            required_actions: plan.actions,
            latch: plan.latch,
            state_changed,
        })
    }

    fn dependencies_current(&self, state: &H3DocumentState) -> Result<bool, H3Error> {
        let project = state.project_id();
        let Some(dependencies) = self.dependencies.get(&project) else {
            return Ok(true);
        };
        for (kind, fingerprint_kind) in [
            (DependencyKind::Css, FingerprintKind::Css),
            (DependencyKind::Resource, FingerprintKind::Resources),
        ] {
            let paths = dependencies
                .iter()
                .filter(|dependency| dependency.kind() == kind)
                .cloned()
                .collect::<Vec<_>>();
            if paths.is_empty() {
                continue;
            }
            match self
                .reads
                .dependency_digest(state.document_key(), kind, &paths)?
            {
                Some(observed) if state.fingerprints().get(fingerprint_kind) == Some(&observed) => {
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn load_cycle(
        &self,
        project: ProjectId,
        state: &H3DocumentState,
    ) -> Result<Option<SyncCycle>, H3Error> {
        match state.cycle_id() {
            Some(cycle) => self.store.load_html_sync_cycle(project, cycle),
            None => Ok(None),
        }
    }

    fn commit_document(
        &mut self,
        record: &H3DocumentRecord,
        next: &H3DocumentState,
        cycle: Option<SyncCycle>,
        latch: Option<CycleLatch>,
        now: Timestamp,
    ) -> Result<(), H3Error> {
        let mut commit = HtmlSyncCommit::new()
            .with_document(DocumentCommit::new(Some(record.revision()), next.clone())?);
        if let Some(cycle) = cycle
            && cycle.state() == CycleState::Open
            && let Some(latch) = latch
            && cycle.latch() != Some(latch)
        {
            commit = commit.with_cycle(cycle.with_latch(latch));
        }
        let event =
            document_state_event(next.document_key(), Some(record.state().state()), next, now)?;
        commit = commit.with_events(vec![event]);
        self.store.commit_html_sync(commit)?;
        Ok(())
    }
}

#[derive(Debug)]
struct StatePlan {
    next_state: H3State,
    reason: H3Reason,
    applicability: Applicability,
    actions: Vec<RequiredAction>,
    latch: Option<CycleLatch>,
}

fn recovery_plan(
    state: &H3DocumentState,
    findings: &[RecoveryFinding],
    publications: &[PublicationRecovery],
) -> StatePlan {
    if matches!(
        state.state(),
        H3State::Failed | H3State::Cancelled | H3State::Orphaned | H3State::Disabled
    ) {
        return StatePlan {
            next_state: state.state(),
            reason: state.reason().clone(),
            applicability: state.applicability().clone(),
            actions: state.reason().required_actions().to_vec(),
            latch: None,
        };
    }
    let has =
        |boundary: RecoveryBoundary| findings.iter().any(|finding| finding.boundary == boundary);
    let has_stop = has(RecoveryBoundary::StopUnconfirmed);
    let has_external =
        has(RecoveryBoundary::ExternalHtmlChange) || has(RecoveryBoundary::ReceiptChange);
    let has_candidate =
        has(RecoveryBoundary::CandidateMissing) || has(RecoveryBoundary::CandidateMismatch);
    let has_source = has(RecoveryBoundary::StaleSource) || has(RecoveryBoundary::SourceMissing);
    let has_dependency =
        has(RecoveryBoundary::DependencyChange) || has(RecoveryBoundary::DependencyUnavailable);
    let has_restored = has(RecoveryBoundary::RestoredUnsynced);
    let has_active =
        has(RecoveryBoundary::ActiveWorkRestored) || has(RecoveryBoundary::PendingCycleRestored);
    let has_h2 = has(RecoveryBoundary::RequestUnknown) || has(RecoveryBoundary::H2RecoveryPending);
    let has_publication = has(RecoveryBoundary::PendingPublicationIntent)
        || has(RecoveryBoundary::PublicationOldVersionSaved)
        || has(RecoveryBoundary::PublicationReplacing)
        || has(RecoveryBoundary::PublicationAfterOneFile)
        || has(RecoveryBoundary::PublicationUnverifiable)
        || has(RecoveryBoundary::PublicationPublishedWithoutSequence)
        || has(RecoveryBoundary::PublicationJournalMissing);
    let actionable = findings
        .iter()
        .any(|finding| finding.boundary != RecoveryBoundary::Clean);
    if !actionable
        && !matches!(
            state.state(),
            H3State::Failed | H3State::Cancelled | H3State::Orphaned | H3State::Disabled
        )
    {
        let latch = match state.state() {
            H3State::WaitingHuman => Some(CycleLatch::WaitingHuman),
            H3State::Stopped => Some(CycleLatch::RecoveryReconciliation),
            _ => None,
        };
        return StatePlan {
            next_state: state.state(),
            reason: state.reason().clone(),
            applicability: state.applicability().clone(),
            actions: state.reason().required_actions().to_vec(),
            latch,
        };
    }
    if has_stop {
        return plan(
            H3StateReasonKind::Stopped {
                cause: H3StopCause::StopUnconfirmed,
            },
            vec![RequiredAction::ReconcileRecovery],
            Applicability::not_applicable(applicability_reason(state, findings, publications)),
            Some(CycleLatch::RecoveryReconciliation),
        );
    }
    if has_external {
        let target = state.document_key().companion_path();
        return plan(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::ExternalHtmlConflict,
            },
            vec![RequiredAction::ResolveHtmlConflict { target }],
            Applicability::not_applicable(applicability_reason(state, findings, publications)),
            Some(CycleLatch::WaitingHuman),
        );
    }
    if has_restored {
        return plan(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::RecoveryReconciliation,
            },
            vec![RequiredAction::ReassessCandidate],
            state.applicability().clone(),
            Some(CycleLatch::WaitingHuman),
        );
    }
    if has_candidate {
        return plan(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::RecoveryReconciliation,
            },
            vec![RequiredAction::RegenerateCandidate],
            Applicability::not_applicable(applicability_reason(state, findings, publications)),
            Some(CycleLatch::RecoveryReconciliation),
        );
    }
    if has_source || has_dependency {
        return plan(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::RecoveryReconciliation,
            },
            vec![RequiredAction::ReassessCandidate],
            Applicability::not_applicable(applicability_reason(state, findings, publications)),
            Some(CycleLatch::RecoveryReconciliation),
        );
    }
    if has_publication || has_h2 || has_active {
        return plan(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::RecoveryReconciliation,
            },
            vec![RequiredAction::ReconcileRecovery],
            Applicability::not_applicable(applicability_reason(state, findings, publications)),
            Some(CycleLatch::RecoveryReconciliation),
        );
    }
    StatePlan {
        next_state: state.state(),
        reason: state.reason().clone(),
        applicability: state.applicability().clone(),
        actions: state.reason().required_actions().to_vec(),
        latch: None,
    }
}

fn plan(
    kind: H3StateReasonKind,
    actions: Vec<RequiredAction>,
    applicability: Applicability,
    latch: Option<CycleLatch>,
) -> StatePlan {
    let next_state = kind.state();
    StatePlan {
        next_state,
        reason: H3Reason::new(kind, actions.clone()).expect("recovery reasons have actions"),
        applicability,
        actions,
        latch,
    }
}

fn applicability_reason(
    state: &H3DocumentState,
    findings: &[RecoveryFinding],
    publications: &[PublicationRecovery],
) -> ApplicabilityReason {
    if let Some(fingerprint) = findings.iter().find_map(RecoveryFinding::fingerprint) {
        return ApplicabilityReason::DependencyChanged { fingerprint };
    }
    if let Some(publication) = publications
        .iter()
        .find(|publication| publication.boundary == RecoveryBoundary::ExternalHtmlChange)
        && let Some(observed) = publication.current_html()
    {
        return ApplicabilityReason::HtmlChanged {
            expected: publication.expected_html().clone(),
            observed: observed.clone(),
        };
    }
    if findings
        .iter()
        .any(|finding| finding.boundary == RecoveryBoundary::StaleSource)
        && let Some(generation) = state.generation()
    {
        return ApplicabilityReason::Superseded {
            generation,
            source_revision: state.source().revision().get(),
        };
    }
    ApplicabilityReason::NeverPublished
}

fn next_document_state(
    state: &H3DocumentState,
    recovery: &DocumentRecovery,
    now: Timestamp,
) -> Result<H3DocumentState, H3Error> {
    let plan = recovery_plan(state, &recovery.findings, &recovery.publications);
    rebuild_document(state, plan.reason, plan.applicability, now)
}

fn rebuild_document(
    state: &H3DocumentState,
    reason: H3Reason,
    applicability: Applicability,
    now: Timestamp,
) -> Result<H3DocumentState, H3Error> {
    H3DocumentState::new(
        state.document_key().clone(),
        state.settings_version(),
        state.job_id(),
        state.cycle_id(),
        state.generation(),
        state.source().clone(),
        state.fingerprints().clone(),
        reason,
        state.h2().cloned(),
        state.evidence().to_vec(),
        applicability,
        now,
    )
}

fn analyze_publication(
    document: &DocumentKey,
    journal: &PublicationJournal,
    reads: &dyn RecoveryReadPort,
) -> Result<PublicationRecovery, H3Error> {
    let html_status = journal.file(PublicationFileRole::Html).map_or_else(
        || match journal.status() {
            PublicationStatus::Published => PublicationFileStatus::Published,
            PublicationStatus::Unverifiable | PublicationStatus::Replacing => {
                PublicationFileStatus::Unverifiable
            }
            _ => PublicationFileStatus::Pending,
        },
        |file| file.status(),
    );
    let receipt_status = journal
        .file(PublicationFileRole::Receipt)
        .map(|file| file.status());
    let expected_html = journal
        .observed_after_html()
        .unwrap_or_else(|| journal.approved_html_digest())
        .clone();
    let expected_receipt = journal
        .observed_after_receipt()
        .or_else(|| journal.receipt_digest())
        .cloned();
    let current_html = reads
        .read_companion(document)?
        .as_deref()
        .map(ContentDigest::sha256);
    let current_receipt = if expected_receipt.is_some() || journal.receipt_path().is_some() {
        reads
            .read_receipt(document)?
            .as_deref()
            .map(ContentDigest::sha256)
    } else {
        None
    };
    let mut boundary = match journal.status() {
        PublicationStatus::Prepared => RecoveryBoundary::PendingPublicationIntent,
        PublicationStatus::OldVersionSaved => RecoveryBoundary::PublicationOldVersionSaved,
        PublicationStatus::Replacing => RecoveryBoundary::PublicationReplacing,
        PublicationStatus::Unverifiable => RecoveryBoundary::PublicationUnverifiable,
        PublicationStatus::Published if journal.final_project_sequence().is_none() => {
            RecoveryBoundary::PublicationPublishedWithoutSequence
        }
        PublicationStatus::Published => RecoveryBoundary::Clean,
        PublicationStatus::NotPublished | PublicationStatus::Conflict => RecoveryBoundary::Clean,
    };
    if journal.status() == PublicationStatus::Replacing {
        let html_done = html_status == PublicationFileStatus::Published;
        let receipt_done = receipt_status == Some(PublicationFileStatus::Published);
        if html_done != receipt_done {
            boundary = RecoveryBoundary::PublicationAfterOneFile;
        }
    }
    if journal.status() == PublicationStatus::Published
        && journal.final_project_sequence().is_some()
    {
        if current_html.as_ref() != Some(&expected_html) {
            boundary = RecoveryBoundary::ExternalHtmlChange;
        } else if let Some(expected_receipt) = &expected_receipt
            && current_receipt.as_ref() != Some(expected_receipt)
        {
            boundary = RecoveryBoundary::ReceiptChange;
        }
    }
    Ok(PublicationRecovery {
        publication: journal.publication_id(),
        generation: journal.generation_id(),
        status: journal.status(),
        boundary,
        html_status,
        receipt_status,
        expected_html,
        expected_receipt,
        observed_html: journal.observed_after_html().cloned(),
        observed_receipt: journal.observed_after_receipt().cloned(),
        current_html,
        current_receipt,
        final_project_sequence: journal.final_project_sequence(),
    })
}

/// Maps a private-store verification into the recovery read value.
pub fn candidate_bytes(verification: CandidateVerification) -> CandidateBytes {
    match verification {
        CandidateVerification::Present => CandidateBytes::Present,
        CandidateVerification::Missing => CandidateBytes::Missing,
        CandidateVerification::Mismatch { html, provenance } => {
            CandidateBytes::Mismatch { html, provenance }
        }
    }
}

/// Returns the canonical receipt path used by recovery reads.
pub fn receipt_path(document: &DocumentKey) -> String {
    html_evidence_path(document)
}
