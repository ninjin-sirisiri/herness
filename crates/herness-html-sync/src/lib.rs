//! H3 HTML sync contracts, durable state ports, and private candidate storage.
//!
//! This crate owns versioned H3 document identity, states, reasons, cycles,
//! generations, candidates, publication journal entries, idempotent operation
//! records, and the persistence port implemented by `herness-store`. It has no
//! Tauri, engine, rusqlite, or desktop dependency; the store and desktop compose
//! the implementation.
//!
//! H3 state and events never replace H1 run state or the H1 project sequence.
//! State events use the existing host-activity envelope, and candidate/host
//! publication audit remains in the H1 `artifact.change*` and `artifact.publish*`
//! events.

#![doc = "H3 numeric defaults remain the approved spec values; this crate does not weaken them."]

pub mod barrier;
pub mod candidate;
pub mod config;
pub mod coordinator;
pub mod document;
pub mod error;
pub mod events;
pub mod evidence;
pub mod ids;
pub mod observer;
pub mod operations;
pub mod ports;
pub mod publish;
pub mod recovery;
pub mod request;
pub mod rubric;
pub mod state;
pub mod version;
pub mod workspace;

pub use barrier::{
    BarrierDependency, BarrierMismatch, BarrierMismatchKind, BarrierOutcome, BarrierRequest,
    H4Barrier,
};
pub use candidate::{
    CandidateArtifactStore, CandidateGenerationRequest, CandidateVerification, MAX_CANDIDATE_BYTES,
    MAX_SOURCE_MARKDOWN_BYTES, OpenedCandidateGeneration,
};
pub use config::{
    APPROVED_AUTHORING_CONCURRENCY, APPROVED_DOCUMENT_PUBLICATION_CONCURRENCY, H3ApprovalLimits,
    H3ApprovalState, H3Approver, H3ConfigurationApproval, H3ConfigurationDraft,
    H3ConnectionApproval, H3OwnerBinding, H3PackBinding, H3ScopeChange, H3ScopeChangeKind,
    H3VersionBinding, HOST_API_PROTOCOL, HOST_API_VERSION, MAX_APPROVED_ADDITIONAL_RUNS,
    MAX_APPROVED_CANDIDATE_BYTES, MAX_APPROVED_CONSECUTIVE_STALLS,
    MAX_APPROVED_CYCLE_ACTIVE_SECONDS, MAX_APPROVED_RECONCILE_INTERVAL_MS,
    MAX_APPROVED_RENDER_TIMEOUT_MS, MAX_APPROVED_SETTLE_MS, MAX_APPROVED_SOURCE_BYTES,
    MAX_APPROVED_SVG_ELEMENTS, PACK_INTEGRATION_HOST, PACK_INTEGRATION_SCHEMA, PACK_POLICY_VERSION,
    StoreBackedOwnerApprovalRegistry,
};
pub use coordinator::{
    APP_WIDE_AUTHORING_CONCURRENCY, ActiveOwner, AuthoringBrief, AuthoringControlPort,
    AuthoringGate, AuthoringJob, CandidateAuthored, CandidateIntake, CoordinatorPorts,
    CoordinatorTick, DOCUMENT_PUBLICATION_CONCURRENCY, GenerationStarted, HeldAuthoring,
    OfferOutcome, OwnerGateRequest, OwnerProgress, OwnerStartRequest, OwnerStarted,
    OwnerSupersedeRequest, StaleCandidate, StopOutcome, SupersessionOutcome, SyncCoordinator,
};
pub use document::{
    DocumentKey, FingerprintKind, FingerprintSet, MAX_DOCUMENT_PATH_BYTES, SourceRevision,
    SourceSnapshot,
};
pub use error::H3Error;
pub use events::{
    H3_DOCUMENT_ACTIVITY_KIND, H3_PROJECT_ACTIVITY_KIND, H3_PUBLICATION_EVENT_KIND,
    H3_SETTINGS_EVENT_KIND, H3_STATE_EVENT_KIND, document_state_event, publication_event,
    publication_status_label, settings_event,
};
pub use evidence::{
    AppliedEvaluation, AssessmentPlan, AssessmentSlice, CheckSet, ConditionAdoption,
    ConditionBinding, ConditionEvidenceRef, ConditionEvidenceSummary, CoverageReport,
    EvaluationBinding, EvaluationDisposition, EvaluationDispositionState, EvaluationSplit,
    EvidenceBuildInput, EvidenceCheckResult, EvidenceContentKind, EvidenceContentSource,
    EvidenceContentStore, EvidenceDocumentContent, EvidenceFingerprints, EvidenceImage,
    EvidenceOrigin, EvidencePack, EvidenceValidationError, H3_EVIDENCE_CONTENT_SCHEMA,
    H3_EVIDENCE_SCHEMA, H3_RENDER_MANIFEST_VERSION, H3Condition, HOST_JS_ACCESSIBILITY_SOURCE,
    MAX_DEFAULT_SLICE_BYTES, MAX_DEFAULT_SLICE_UNITS, NATIVE_RENDER_SOURCE, Provenance,
    RenderCandidateFingerprints, RenderConfigurationEvidence, RenderEvidence, RenderPngEvidence,
    RenderSignalEvidence, RequiredCheck, RequiredCheckKind, ScannedHtml, SliceAssessment,
    SourceUnitDefinition, SourceUnits, StrictRequirement, SupplementaryEvidence, SupportEvidence,
    UnitEvidence, UsabilityEvidence,
};
pub use ids::{
    CandidateId, CycleId, GenerationId, H3KeyKind, H3RequestId, H3ScopedId, JobId, PublicationId,
};
pub use observer::{
    ChangeSignal, ChangeSource, CompanionChange, CompanionFileKind, CompanionObservation,
    DependencyInvalidation, DependencyKind, DependencyPath, ExpectedPublicationWrite, FileRead,
    FilesystemSourceReader, HTML_EVIDENCE_DIR, IneligibleReason, ObservationClock,
    ObservationEligibility, ObservationTargets, ObservationTrigger, ObservationUncertainty,
    ObserverHealth, ObserverTick, ProjectObserver, RecoveryReconciliation, SourceChange,
    SourceObservation, SourceReadError, SourceReadPort, SystemObservationClock, WatcherStatus,
    dependency_fingerprint, html_evidence_path,
};
pub use operations::{
    AdoptionOutcome, AdoptionPreparation, CurrentHtmlAdoption, CurrentHtmlValidation,
    HistoryReadPort, HistoryRestoreOutcome, HistoryVersion, SourceJobControlPort,
    SourceRemovalOutcome, SourceStop, adopt_current_html, prepare_adoption,
    record_external_html_conflict, record_source_removal, replace_with_regenerated,
    restore_history,
};
pub use ports::{
    DocumentCommit, H3DocumentRecord, H3SettingsRecord, H3StorePort, HtmlSyncCommit,
    HtmlSyncCommitOutcome, SettingsCommit, decode_candidate, decode_cycle, decode_generation,
    decode_operation_result, decode_publication, decode_settings, decode_stored_request,
    verify_bytes_digest,
};
pub use publish::{
    BuiltReceipt, CandidatePublication, FinalCandidateCheck, FinalCandidateCheckPort,
    FinalCandidateCheckRequest, HostPublicationPort, PublicationFileInput, PublicationFileReadPort,
    PublicationOrchestrator, PublicationOutcome, PublicationPolicyIdentity, PublicationSafety,
    PublicationSafetyPort, PublicationSafetyRequest, PublicationWriteExpectationPort,
    RECEIPT_CONTRACT, RECEIPT_DIRECTORY, RECEIPT_SCHEMA, RECEIPT_VERSION, SHARED_STYLESHEET,
    build_publication_receipt,
};
pub use recovery::{
    CandidateBytes, CandidateRecovery, DocumentRecovery, H2RecoveryFacts, H2RequestUnknown,
    ProjectRecoveryReport, PublicationRecovery, QuitDocument, QuitProjectReport, RecoveryBoundary,
    RecoveryFinding, RecoveryReadPort, RecoveryRuntimePort, RecoveryService, RecoverySideEffects,
    RecoveryStop, ResumeBlock, ResumePreflight, ResumePreflightRequest, candidate_bytes,
    receipt_path,
};
pub use request::{
    ConflictResolution, H3Operation, H3OperationOutcome, H3OperationRequest, H3OperationResult,
    H3RequestFingerprint, RequestCommit, StoredRequestResult, decode_stored_request_result,
};
pub use rubric::{
    ConditionRubric, H3_RUBRIC_SCHEMA, H3_RUBRIC_VERSION, RubricSet, condition_rubric,
};
pub use state::{
    Applicability, ApplicabilityReason, ArchivedVersionRef, CandidateRecord, CandidateStorageRef,
    CycleLatch, CycleState, EvidenceKind, EvidenceRef, GenerationRecord, GenerationStatus,
    H2Reference, H3CancelCause, H3DocumentState, H3DocumentStatus, H3FailureCause, H3Reason,
    H3Settings, H3State, H3StateReasonKind, H3StopCause, HumanWaitCause, PublicationFileJournal,
    PublicationFileRole, PublicationFileStatus, PublicationJournal, PublicationStatus,
    RequiredAction, SyncCycle, project_activity_id,
};
pub use version::{H3_FORMAT_VERSION, H3Record, decode_record, encode_record, ensure_format};
pub use workspace::{
    AuthoringPolicy, AuthoringSnapshot, AuthoringWorkspace, CapturedInput, CapturedResource,
    DocumentKind, MAX_RESOURCE_BYTES, MAX_SHARED_CSS_BYTES, WorkspaceCaptureRequest,
    WorkspaceReader,
};
