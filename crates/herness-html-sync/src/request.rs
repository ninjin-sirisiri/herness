//! Versioned H3 operations, request idempotency, and public results.
//!
//! Every request carries a host-issued identifier and a canonical fingerprint.
//! Repeating the same identifier with the same request returns the stored
//! result; reusing it with a different request conflicts before any side
//! effect. A document-mutating request also carries the document revision the
//! caller observed, so a stale update conflicts before authorization, sending,
//! or publication.

use herness_core::ProjectId;
use herness_supervision::ContentDigest;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::document::DocumentKey;
use crate::error::H3Error;
use crate::ids::{GenerationId, H3RequestId};
use crate::state::{GenerationRecord, H3DocumentState, H3Reason, H3State};
use crate::version::{H3_FORMAT_VERSION, H3Record, ensure_format};

/// Fingerprint of one canonical operation request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct H3RequestFingerprint(String);

impl H3RequestFingerprint {
    /// Wraps a 64-character lowercase SHA-256 hex fingerprint.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, H3Error> {
        let value = value.as_ref().trim().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(H3Error::invalid(
                "requestFingerprint",
                "expected a 64-character SHA-256 hex fingerprint",
            ));
        }
        Ok(Self(value))
    }

    /// Hex fingerprint.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for H3RequestFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for H3RequestFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for H3RequestFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// How a human resolves an external HTML conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// Adopt the current external HTML after verifying and assessing it.
    AdoptCurrent,
    /// Replace the external HTML with a newly verified candidate.
    ReplaceWithCandidate,
    /// Keep waiting without changing the formal file.
    KeepWaiting,
}

/// One supported H3 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum H3Operation {
    /// Approve or re-enable project settings.
    EnableSettings,
    /// List current document states.
    ListDocuments,
    /// Read one document state.
    GetDocument,
    /// Subscribe to committed events after an optional sequence.
    Subscribe {
        /// Last project sequence already observed.
        after_sequence: Option<u64>,
    },
    /// Pause automatic work without discarding state.
    Pause,
    /// Cancel the current cycle. Published files are not rolled back.
    Cancel,
    /// Resume after an explicit human stop or cancellation.
    Resume,
    /// Reassess the current candidate against current evidence.
    Reassess,
    /// Regenerate the candidate for the current source.
    Regenerate,
    /// Resolve an external HTML conflict.
    ResolveConflict {
        /// Human-selected resolution.
        resolution: ConflictResolution,
    },
    /// Read generation history for one document.
    GetHistory {
        /// Maximum entries to return.
        limit: u32,
    },
    /// Restore one historical generation through the normal publication path.
    RestoreHistory {
        /// Generation to restore.
        generation: GenerationId,
    },
    /// The source Markdown disappeared or moved outside H3.
    SourceRemoved {
        /// New Target-relative path for a move, or `None` for a deletion.
        new_path: Option<String>,
    },
}

impl H3Operation {
    /// Stable operation label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EnableSettings => "enable_settings",
            Self::ListDocuments => "list_documents",
            Self::GetDocument => "get_document",
            Self::Subscribe { .. } => "subscribe",
            Self::Pause => "pause",
            Self::Cancel => "cancel",
            Self::Resume => "resume",
            Self::Reassess => "reassess",
            Self::Regenerate => "regenerate",
            Self::ResolveConflict { .. } => "resolve_conflict",
            Self::GetHistory { .. } => "get_history",
            Self::RestoreHistory { .. } => "restore_history",
            Self::SourceRemoved { .. } => "source_removed",
        }
    }

    /// Whether the operation addresses one document.
    pub const fn requires_document(&self) -> bool {
        matches!(
            self,
            Self::GetDocument
                | Self::Pause
                | Self::Cancel
                | Self::Resume
                | Self::Reassess
                | Self::Regenerate
                | Self::ResolveConflict { .. }
                | Self::GetHistory { .. }
                | Self::RestoreHistory { .. }
                | Self::SourceRemoved { .. }
        )
    }

    /// Whether the operation mutates durable state.
    pub const fn mutates(&self) -> bool {
        matches!(
            self,
            Self::EnableSettings
                | Self::Pause
                | Self::Cancel
                | Self::Resume
                | Self::Reassess
                | Self::Regenerate
                | Self::ResolveConflict { .. }
                | Self::RestoreHistory { .. }
                | Self::SourceRemoved { .. }
        )
    }

    /// Whether a document-mutating request must carry an observed revision.
    pub const fn requires_expected_revision(&self) -> bool {
        matches!(
            self,
            Self::Pause
                | Self::Cancel
                | Self::Resume
                | Self::Reassess
                | Self::Regenerate
                | Self::ResolveConflict { .. }
                | Self::RestoreHistory { .. }
                | Self::SourceRemoved { .. }
        )
    }
}

/// A versioned request for one H3 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3OperationRequest {
    format_version: u32,
    request_id: H3RequestId,
    project_id: ProjectId,
    document: Option<DocumentKey>,
    expected_revision: Option<u64>,
    expected_source_digest: Option<ContentDigest>,
    operation: H3Operation,
    requested_at: herness_core::Timestamp,
}

impl H3OperationRequest {
    /// Creates a validated request.
    pub fn new(
        request_id: H3RequestId,
        project_id: ProjectId,
        document: Option<DocumentKey>,
        expected_revision: Option<u64>,
        expected_source_digest: Option<ContentDigest>,
        operation: H3Operation,
        requested_at: herness_core::Timestamp,
    ) -> Result<Self, H3Error> {
        request_id.validate_in(project_id)?;
        match (&operation, &document) {
            (operation, None) if operation.requires_document() => {
                return Err(H3Error::empty("document"));
            }
            (operation, Some(_)) if !operation.requires_document() => {
                return Err(H3Error::invalid(
                    "document",
                    "this operation does not address one document",
                ));
            }
            _ => {}
        }
        if let Some(document) = &document {
            document.validate_in(project_id)?;
        } else if expected_source_digest.is_some() {
            return Err(H3Error::invalid(
                "expectedSourceDigest",
                "a project-scoped operation cannot carry a source digest",
            ));
        }
        if operation.requires_expected_revision() && expected_revision.is_none() {
            return Err(H3Error::empty("expectedRevision"));
        }
        if expected_revision == Some(0) {
            return Err(H3Error::must_be_positive("expectedRevision"));
        }
        if let H3Operation::GetHistory { limit } = operation
            && limit == 0
        {
            return Err(H3Error::must_be_positive("historyLimit"));
        }
        if let H3Operation::SourceRemoved { new_path: Some(path) } = &operation {
            let new_document = DocumentKey::new(project_id, path.clone())?;
            if document
                .as_ref()
                .is_some_and(|document| document.target_path() == new_document.target_path())
            {
                return Err(H3Error::invalid(
                    "newPath",
                    "a moved Target must have a different canonical path",
                ));
            }
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            request_id,
            project_id,
            document,
            expected_revision,
            expected_source_digest,
            operation,
            requested_at,
        })
    }

    /// Request identifier.
    pub const fn request_id(&self) -> H3RequestId {
        self.request_id
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document the request addresses, when any.
    pub const fn document(&self) -> Option<&DocumentKey> {
        self.document.as_ref()
    }

    /// Document or settings revision the caller observed.
    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }

    /// Source digest the caller observed.
    pub const fn expected_source_digest(&self) -> Option<&ContentDigest> {
        self.expected_source_digest.as_ref()
    }

    /// Requested operation.
    pub const fn operation(&self) -> &H3Operation {
        &self.operation
    }

    /// When the request was created.
    pub const fn requested_at(&self) -> herness_core::Timestamp {
        self.requested_at
    }

    /// Canonical SHA-256 fingerprint over the request semantics.
    ///
    /// The creation timestamp is excluded so a retry of the same request at a
    /// later time still matches its stored result. The request ID and every
    /// operation argument are included.
    pub fn fingerprint(&self) -> H3RequestFingerprint {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FingerprintInput<'a> {
            format_version: u32,
            request_id: H3RequestId,
            project_id: ProjectId,
            document: &'a Option<DocumentKey>,
            expected_revision: Option<u64>,
            expected_source_digest: &'a Option<ContentDigest>,
            operation: &'a H3Operation,
        }
        let input = FingerprintInput {
            format_version: self.format_version,
            request_id: self.request_id,
            project_id: self.project_id,
            document: &self.document,
            expected_revision: self.expected_revision,
            expected_source_digest: &self.expected_source_digest,
            operation: &self.operation,
        };
        let bytes = serde_json::to_vec(&input).expect("request serialization cannot fail");
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        H3RequestFingerprint(hex)
    }

    /// Short stable description used in duplicate-request errors.
    pub fn describe(&self) -> String {
        format!(
            "{} document={} expectedRevision={:?}",
            self.operation.as_str(),
            self.document
                .as_ref()
                .map_or_else(|| "<project>".to_owned(), |key| key.target_path().to_owned()),
            self.expected_revision
        )
    }
}

impl H3Record for H3OperationRequest {
    const RECORD: &'static str = "operation request";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Result of one H3 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[allow(clippy::large_enum_variant)]
pub enum H3OperationOutcome {
    /// Settings were approved or enabled.
    SettingsEnabled {
        /// Approved settings version.
        settings_version: u64,
    },
    /// A mutating operation was accepted.
    Accepted {
        /// Resulting state.
        state: H3State,
        /// Resulting document revision.
        revision: u64,
    },
    /// One document state.
    Document {
        /// State value.
        state: H3DocumentState,
    },
    /// Project document states.
    Documents {
        /// State values in stable path order.
        states: Vec<H3DocumentState>,
    },
    /// One document's generation history.
    History {
        /// History entries in generation order.
        generations: Vec<GenerationRecord>,
    },
    /// A historical version was restored. The document stays unsynchronized
    /// and waits for a human reassessment; this is not a synced result.
    Restored {
        /// Restore journal identifier.
        publication: crate::ids::PublicationId,
        /// Generation whose exact bytes were restored.
        generation: GenerationId,
        /// Exact restored HTML digest.
        html_digest: ContentDigest,
        /// Exact restored receipt digest.
        receipt_digest: ContentDigest,
        /// Durable document revision after the restore commit.
        revision: u64,
    },
    /// The selected history pair already equals the formal pair.
    HistoryUnchanged {
        /// Selected generation.
        generation: GenerationId,
    },
    /// The Markdown source disappeared or moved. Old artifacts were retained.
    Orphaned {
        /// Project-relative companion path that was retained.
        target: String,
        /// Remaining approved Target paths after the removal.
        remaining_paths: Vec<String>,
        /// New Target path for a move, when one was supplied.
        new_target: Option<String>,
        /// Whether the new path is already inside the approved Target scope.
        new_target_approved: bool,
        /// Durable document revision after the orphan commit.
        revision: u64,
    },
    /// A subscription cursor acknowledgement.
    Subscription {
        /// Last sequence already acknowledged by the caller.
        after_sequence: Option<u64>,
    },
    /// The operation was rejected with a versioned reason.
    Rejected {
        /// Reason and required actions.
        reason: H3Reason,
    },
}

/// Public result of one H3 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3OperationResult {
    format_version: u32,
    request_id: H3RequestId,
    project_id: ProjectId,
    document: Option<DocumentKey>,
    duplicate: bool,
    outcome: H3OperationOutcome,
    final_project_sequence: u64,
    recorded_at: herness_core::Timestamp,
}

impl H3OperationResult {
    /// Creates a result for `request`.
    ///
    /// A sequence of `0` is a template; the durable store replaces it with the
    /// final sequence assigned by the project commit before saving.
    pub fn new(
        request: &H3OperationRequest,
        outcome: H3OperationOutcome,
        final_project_sequence: u64,
        recorded_at: herness_core::Timestamp,
    ) -> Result<Self, H3Error> {
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            request_id: request.request_id(),
            project_id: request.project_id(),
            document: request.document().cloned(),
            duplicate: false,
            outcome,
            final_project_sequence,
            recorded_at,
        })
    }

    /// Request identifier this result answers.
    pub const fn request_id(&self) -> H3RequestId {
        self.request_id
    }

    /// Project that owns the result.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Document addressed by the request, when any.
    pub const fn document(&self) -> Option<&DocumentKey> {
        self.document.as_ref()
    }

    /// Whether this result replays an already stored request.
    pub const fn duplicate(&self) -> bool {
        self.duplicate
    }

    /// Operation outcome.
    pub const fn outcome(&self) -> &H3OperationOutcome {
        &self.outcome
    }

    /// Final project sequence observed by the operation.
    pub const fn final_project_sequence(&self) -> u64 {
        self.final_project_sequence
    }

    /// When the result was recorded.
    pub const fn recorded_at(&self) -> herness_core::Timestamp {
        self.recorded_at
    }

    /// Replaces the template sequence with the committed project sequence.
    pub fn with_final_project_sequence(mut self, sequence: u64) -> Self {
        self.final_project_sequence = sequence;
        self
    }

    /// Returns a replay marker for a stored result.
    pub fn into_duplicate(mut self) -> Self {
        self.duplicate = true;
        self
    }

    /// Verifies this result answers the same request scope.
    pub fn matches_request(&self, request: &H3OperationRequest) -> bool {
        self.request_id == request.request_id()
            && self.project_id == request.project_id()
            && self.document.as_ref() == request.document()
    }
}

impl H3Record for H3OperationResult {
    const RECORD: &'static str = "operation result";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// One stored request and its already recorded result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredRequestResult {
    format_version: u32,
    request: H3OperationRequest,
    result: H3OperationResult,
    recorded_at: herness_core::Timestamp,
}

impl StoredRequestResult {
    /// Creates a stored request result from a matching request and result.
    pub fn new(
        request: H3OperationRequest,
        result: H3OperationResult,
        recorded_at: herness_core::Timestamp,
    ) -> Result<Self, H3Error> {
        if !result.matches_request(&request) {
            return Err(H3Error::invalid(
                "operationResult",
                "the stored result does not answer the stored request",
            ));
        }
        Ok(Self {
            format_version: H3_FORMAT_VERSION,
            request,
            result,
            recorded_at,
        })
    }

    /// Stored request.
    pub const fn request(&self) -> &H3OperationRequest {
        &self.request
    }

    /// Stored result.
    pub const fn result(&self) -> &H3OperationResult {
        &self.result
    }

    /// Canonical fingerprint of the stored request.
    pub fn fingerprint(&self) -> H3RequestFingerprint {
        self.request.fingerprint()
    }

    /// When the result was first recorded.
    pub const fn recorded_at(&self) -> herness_core::Timestamp {
        self.recorded_at
    }

    /// Returns the stored result marked as a duplicate replay.
    pub fn replay(&self) -> H3OperationResult {
        self.result.clone().into_duplicate()
    }
}

impl H3Record for StoredRequestResult {
    const RECORD: &'static str = "stored request result";
    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// One atomic request plus its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestCommit {
    request: H3OperationRequest,
    result: H3OperationResult,
}

impl RequestCommit {
    /// Creates a commit after checking that the result answers the request.
    pub fn new(
        request: H3OperationRequest,
        result: H3OperationResult,
    ) -> Result<Self, H3Error> {
        if !result.matches_request(&request) {
            return Err(H3Error::invalid(
                "operationResult",
                "the result does not answer the request",
            ));
        }
        if result.duplicate() {
            return Err(H3Error::invalid(
                "operationResult",
                "a newly committed result cannot already be a duplicate replay",
            ));
        }
        Ok(Self { request, result })
    }

    /// Request being recorded.
    pub const fn request(&self) -> &H3OperationRequest {
        &self.request
    }

    /// Stored result.
    pub const fn result(&self) -> &H3OperationResult {
        &self.result
    }

    /// Stored form of this request/result pair.
    pub fn stored(&self) -> Result<StoredRequestResult, H3Error> {
        StoredRequestResult::new(
            self.request.clone(),
            self.result.clone(),
            self.result.recorded_at(),
        )
    }
}

/// Decodes a stored request result after checking its format.
pub fn decode_stored_request_result(bytes: &[u8]) -> Result<StoredRequestResult, H3Error> {
    let value = crate::version::decode_record::<StoredRequestResult>(bytes)?;
    ensure_format(value.format_version, "stored request result")?;
    Ok(value)
}
