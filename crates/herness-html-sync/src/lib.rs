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

pub mod candidate;
pub mod document;
pub mod error;
pub mod events;
pub mod ids;
pub mod ports;
pub mod request;
pub mod state;
pub mod version;

pub use candidate::{
    CandidateArtifactStore, CandidateGenerationRequest, MAX_CANDIDATE_BYTES,
    MAX_SOURCE_MARKDOWN_BYTES, OpenedCandidateGeneration,
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
pub use ids::{
    CandidateId, CycleId, GenerationId, H3KeyKind, H3RequestId, H3ScopedId, JobId, PublicationId,
};
pub use ports::{
    DocumentCommit, H3DocumentRecord, H3SettingsRecord, H3StorePort, HtmlSyncCommit,
    HtmlSyncCommitOutcome, SettingsCommit, decode_candidate, decode_cycle, decode_generation,
    decode_operation_result, decode_publication, decode_settings, decode_stored_request,
    verify_bytes_digest,
};
pub use request::{
    ConflictResolution, H3Operation, H3OperationOutcome, H3OperationRequest, H3OperationResult,
    H3RequestFingerprint, RequestCommit, StoredRequestResult, decode_stored_request_result,
};
pub use state::{
    Applicability, ApplicabilityReason, ArchivedVersionRef, CandidateRecord, CandidateStorageRef,
    CycleLatch, CycleState, EvidenceKind, EvidenceRef, GenerationRecord, GenerationStatus,
    H2Reference, H3CancelCause, H3DocumentState, H3DocumentStatus, H3FailureCause, H3Reason,
    H3Settings, H3State, H3StateReasonKind, H3StopCause, HumanWaitCause, PublicationJournal,
    PublicationStatus, RequiredAction, SyncCycle, project_activity_id,
};
pub use version::{H3_FORMAT_VERSION, H3Record, decode_record, encode_record, ensure_format};
