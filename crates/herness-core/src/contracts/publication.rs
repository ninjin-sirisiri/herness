//! Host-only publication request, record, and result values.
//!
//! A publication request names exactly one formal companion file and the
//! expected current version (or explicit absence). The boundary that consumes
//! it is not a model tool, is not part of [`crate::tools::ToolArguments`], and
//! has no run or operation identifier. Audit uses a real host-activity subject.
//!
//! This module intentionally knows nothing about H3 job state, receipts, or the
//! H3 publication journal. Those remain owned by the H3 layer. Publishing one
//! file is a single-file replacement; publishing several files is a sequence
//! coordinated by a journal, never one atomic filesystem transaction.

use std::fmt;
use std::path::Path;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError, PublicationFailure};
use crate::contracts::events::{Event, EventKind};
use crate::contracts::ids::{HostActivityId, ProjectId};
use crate::contracts::time::Timestamp;
use crate::tools::{hash_bytes, FileVersion, NonEmptyText, Purpose};

/// Maximum Unicode scalar values in a publication request identifier.
pub const MAX_PUBLICATION_REQUEST_ID_SCALARS: usize = 200;
/// Maximum UTF-8 bytes in a project-relative publication target.
pub const MAX_PUBLICATION_TARGET_BYTES: usize = 4_096;
/// Maximum UTF-8 bytes of one approved publication body.
///
/// This is the same candidate HTML ceiling H3 uses. An over-limit request is
/// rejected, never truncated.
pub const MAX_PUBLICATION_CONTENT_BYTES: usize = 8 * 1024 * 1024;
/// Stable host-activity kind for publication audit events.
pub const PUBLICATION_ACTIVITY_KIND: &str = "artifact.publication";
/// Audit event kind committed before the filesystem side effect.
pub const PUBLICATION_INTENDED_EVENT_KIND: &str = "artifact.publish.intended";
/// Audit event kind committed with the durable publication result.
pub const PUBLICATION_EVENT_KIND: &str = "artifact.publish";
/// Stable label for a single-file replacement.
pub const PUBLICATION_UNIT_SINGLE_FILE: &str = "single_file";
/// Current persisted publication-record format.
pub const PUBLICATION_RECORD_FORMAT: u32 = 1;

/// Stable, host-issued identifier for one publication request.
///
/// The value is opaque to H1. It is validated so it can safely become part of a
/// private host-state key and an audit payload. Reusing the same identifier with
/// different request data conflicts rather than publishing twice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicationRequestId(NonEmptyText);

impl PublicationRequestId {
    /// Validates a non-empty, bounded request identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "publicationRequestId".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        let actual = trimmed.chars().count();
        if actual > MAX_PUBLICATION_REQUEST_ID_SCALARS {
            return Err(CoreError::InvalidValue {
                field: "publicationRequestId".to_owned(),
                violation: ArgumentViolation::TooLong {
                    actual,
                    max: MAX_PUBLICATION_REQUEST_ID_SCALARS,
                },
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(CoreError::InvalidValue {
                field: "publicationRequestId".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "control characters are not allowed".to_owned(),
                },
            });
        }
        Ok(Self(NonEmptyText::new(trimmed)?))
    }

    /// Borrows the identifier text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PublicationRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for PublicationRequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PublicationRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// The current state expected at the formal companion path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ExpectedTargetVersion {
    /// The target must not exist.
    Absent,
    /// The target must exist with exactly this version.
    Present {
        /// Expected content version.
        version: FileVersion,
    },
}

impl ExpectedTargetVersion {
    /// Explicit absence.
    pub const fn absent() -> Self {
        Self::Absent
    }

    /// A required current version.
    pub const fn present(version: FileVersion) -> Self {
        Self::Present { version }
    }

    /// Expected version when the target must already exist.
    pub const fn version(&self) -> Option<&FileVersion> {
        match self {
            Self::Absent => None,
            Self::Present { version } => Some(version),
        }
    }

    /// Whether this expectation requires the target to be absent.
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// One host-approved publication of exactly one formal companion file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRequest {
    project_id: ProjectId,
    request_id: PublicationRequestId,
    target: NonEmptyText,
    expected_version: ExpectedTargetVersion,
    content: String,
    approved_version: FileVersion,
    purpose: Purpose,
}

impl PublicationRequest {
    /// Creates a validated publication request.
    ///
    /// `purpose` is the host's reason for publishing. There is deliberately no
    /// agent rationale field: an agent's candidate-change explanation must not
    /// be relabeled as the host's publication purpose.
    pub fn new(
        project_id: ProjectId,
        request_id: PublicationRequestId,
        target: NonEmptyText,
        expected_version: ExpectedTargetVersion,
        content: impl Into<String>,
        purpose: Purpose,
    ) -> Result<Self, CoreError> {
        let content = content.into();
        let target_text = target.as_str();
        if target_text.len() > MAX_PUBLICATION_TARGET_BYTES {
            return Err(CoreError::InvalidValue {
                field: "publicationTarget".to_owned(),
                violation: ArgumentViolation::TooLongBytes {
                    actual: target_text.len(),
                    max: MAX_PUBLICATION_TARGET_BYTES,
                },
            });
        }
        if target_text.contains('\0') {
            return Err(CoreError::InvalidValue {
                field: "publicationTarget".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "NUL bytes are not allowed".to_owned(),
                },
            });
        }
        if Path::new(target_text).is_absolute() {
            return Err(CoreError::InvalidValue {
                field: "publicationTarget".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "the publication target must be project-relative".to_owned(),
                },
            });
        }
        if content.len() > MAX_PUBLICATION_CONTENT_BYTES {
            return Err(CoreError::InvalidValue {
                field: "publicationContent".to_owned(),
                violation: ArgumentViolation::TooLongBytes {
                    actual: content.len(),
                    max: MAX_PUBLICATION_CONTENT_BYTES,
                },
            });
        }
        let approved_version = hash_bytes(content.as_bytes());
        Ok(Self {
            project_id,
            request_id,
            target,
            expected_version,
            content,
            approved_version,
            purpose,
        })
    }

    /// Project that owns the formal companion.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Stable host-issued request identifier.
    pub const fn request_id(&self) -> &PublicationRequestId {
        &self.request_id
    }

    /// Project-relative formal companion path.
    pub fn target(&self) -> &NonEmptyText {
        &self.target
    }

    /// Expected current version or explicit absence.
    pub const fn expected_version(&self) -> &ExpectedTargetVersion {
        &self.expected_version
    }

    /// Exact approved bytes as text.
    pub fn content(&self) -> &str {
        &self.content
    }

    /// SHA-256 of the exact approved content bytes.
    pub const fn approved_version(&self) -> &FileVersion {
        &self.approved_version
    }

    /// Host purpose for this publication.
    pub const fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    /// Stable digest binding the request id to its exact payload.
    ///
    /// A repeated request id with a different digest is a conflict and must not
    /// reach the filesystem boundary.
    pub fn fingerprint(&self) -> FileVersion {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Fingerprint<'a> {
            project_id: ProjectId,
            request_id: &'a str,
            target: &'a str,
            expected_version: &'a ExpectedTargetVersion,
            approved_version: &'a FileVersion,
            purpose: &'a str,
        }

        let bytes = serde_json::to_vec(&Fingerprint {
            project_id: self.project_id,
            request_id: self.request_id.as_str(),
            target: self.target.as_str(),
            expected_version: &self.expected_version,
            approved_version: &self.approved_version,
            purpose: self.purpose.as_str(),
        })
        .expect("a publication fingerprint contains only serializable values");
        hash_bytes(&bytes)
    }
}

/// Durable state of one publication request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    /// Intent persisted; the result is not durable yet.
    Pending,
    /// The formal file was observed with the approved content and the result
    /// was persisted.
    Published,
    /// The formal file was not replaced; a known failure was persisted.
    NotPublished,
    /// The side effect may or may not have happened; reconciliation is needed.
    Unverifiable,
}

impl PublicationStatus {
    /// Stable wire and storage label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::NotPublished => "not_published",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// Result of saving the old formal version into the private app area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum OldVersionSave {
    /// The intent exists but saving the old version was not attempted yet.
    NotAttempted,
    /// The target was absent, so there was no old version.
    NotApplicable,
    /// The exact old version is durably saved in the private app area.
    Saved {
        /// SHA-256 of the saved content.
        version: FileVersion,
        /// Opaque, non-secret reference inside the private archive.
        reference: NonEmptyText,
    },
    /// The old version could not be saved; the target was not replaced.
    Failed {
        /// Sanitized explanation.
        detail: String,
    },
    /// The archive could not confirm whether the old version was saved.
    Unknown {
        /// Sanitized explanation.
        detail: String,
    },
}

impl OldVersionSave {
    /// Whether the save operation positively completed.
    pub const fn is_saved(&self) -> bool {
        matches!(self, Self::Saved { .. })
    }

    /// Saved version, when known.
    pub const fn version(&self) -> Option<&FileVersion> {
        match self {
            Self::Saved { version, .. } => Some(version),
            _ => None,
        }
    }

    /// Opaque archive reference, when the save completed.
    pub const fn reference(&self) -> Option<&NonEmptyText> {
        match self {
            Self::Saved { reference, .. } => Some(reference),
            _ => None,
        }
    }

    /// Sanitized failure detail, when one exists.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Failed { detail } | Self::Unknown { detail } => Some(detail),
            _ => None,
        }
    }
}

/// Exact old bytes a host archive must save before a replacement.
#[derive(Debug)]
pub struct OldVersionArchive<'a> {
    request_id: &'a PublicationRequestId,
    project_id: ProjectId,
    target: &'a str,
    version: &'a FileVersion,
    content: &'a str,
}

impl<'a> OldVersionArchive<'a> {
    /// Creates an archive request for one exact old version.
    pub const fn new(
        request_id: &'a PublicationRequestId,
        project_id: ProjectId,
        target: &'a str,
        version: &'a FileVersion,
        content: &'a str,
    ) -> Self {
        Self {
            request_id,
            project_id,
            target,
            version,
            content,
        }
    }

    /// Publication request that requires the archive.
    pub const fn request_id(&self) -> &'a PublicationRequestId {
        self.request_id
    }

    /// Project that owns the formal companion.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Project-relative formal companion.
    pub const fn target(&self) -> &'a str {
        self.target
    }

    /// SHA-256 of the exact old bytes.
    pub const fn version(&self) -> &'a FileVersion {
        self.version
    }

    /// Exact old text bytes.
    pub const fn content(&self) -> &'a str {
        self.content
    }
}

/// A positively completed old-version save returned by a host archive port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchivedVersion {
    version: FileVersion,
    reference: NonEmptyText,
}

impl ArchivedVersion {
    /// Creates a save receipt for the exact version and opaque reference.
    pub fn new(version: FileVersion, reference: impl AsRef<str>) -> Result<Self, CoreError> {
        Ok(Self {
            version,
            reference: NonEmptyText::new(reference)?,
        })
    }

    /// Saved content version.
    pub const fn version(&self) -> &FileVersion {
        &self.version
    }

    /// Opaque, non-secret archive reference.
    pub const fn reference(&self) -> &NonEmptyText {
        &self.reference
    }
}

impl From<ArchivedVersion> for OldVersionSave {
    fn from(value: ArchivedVersion) -> Self {
        Self::Saved {
            version: value.version,
            reference: value.reference,
        }
    }
}

/// One durable publication record stored in the private host state.
///
/// The record binds the request id to its exact payload fingerprint and stores
/// the expected, before, and approved digests plus the old-version save result.
/// It contains no H3 job state, approval receipt, or H3 journal fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationRecord {
    format: u32,
    project_id: ProjectId,
    request_id: PublicationRequestId,
    request_fingerprint: FileVersion,
    target: NonEmptyText,
    expected_version: ExpectedTargetVersion,
    approved_version: FileVersion,
    before_version: Option<FileVersion>,
    observed_after_version: Option<FileVersion>,
    purpose: Purpose,
    activity_kind: EventKind,
    activity_id: HostActivityId,
    status: PublicationStatus,
    old_version_save: OldVersionSave,
    detail: Option<String>,
    recorded_at: Timestamp,
    updated_at: Timestamp,
}

impl PublicationRecord {
    /// Builds a pending intent record.
    pub(crate) fn pending(
        request: &PublicationRequest,
        before_version: Option<FileVersion>,
        activity_kind: EventKind,
        activity_id: HostActivityId,
        now: Timestamp,
    ) -> Self {
        Self {
            format: PUBLICATION_RECORD_FORMAT,
            project_id: request.project_id,
            request_id: request.request_id.clone(),
            request_fingerprint: request.fingerprint(),
            target: request.target.clone(),
            expected_version: request.expected_version.clone(),
            approved_version: request.approved_version.clone(),
            before_version,
            observed_after_version: None,
            purpose: request.purpose.clone(),
            activity_kind,
            activity_id,
            status: PublicationStatus::Pending,
            old_version_save: OldVersionSave::NotAttempted,
            detail: None,
            recorded_at: now,
            updated_at: now,
        }
    }

    /// Builds a known, pre-intent rejection record.
    pub(crate) fn rejected(
        request: &PublicationRequest,
        activity_kind: EventKind,
        activity_id: HostActivityId,
        detail: String,
        now: Timestamp,
    ) -> Self {
        Self {
            format: PUBLICATION_RECORD_FORMAT,
            project_id: request.project_id,
            request_id: request.request_id.clone(),
            request_fingerprint: request.fingerprint(),
            target: request.target.clone(),
            expected_version: request.expected_version.clone(),
            approved_version: request.approved_version.clone(),
            before_version: None,
            observed_after_version: None,
            purpose: request.purpose.clone(),
            activity_kind,
            activity_id,
            status: PublicationStatus::NotPublished,
            old_version_save: OldVersionSave::NotAttempted,
            detail: Some(detail),
            recorded_at: now,
            updated_at: now,
        }
    }

    /// Returns a copy with a durable result.
    pub(crate) fn with_result(
        &self,
        status: PublicationStatus,
        observed_after_version: Option<FileVersion>,
        old_version_save: OldVersionSave,
        detail: Option<String>,
        now: Timestamp,
    ) -> Self {
        Self {
            format: PUBLICATION_RECORD_FORMAT,
            project_id: self.project_id,
            request_id: self.request_id.clone(),
            request_fingerprint: self.request_fingerprint.clone(),
            target: self.target.clone(),
            expected_version: self.expected_version.clone(),
            approved_version: self.approved_version.clone(),
            before_version: self.before_version.clone(),
            observed_after_version,
            purpose: self.purpose.clone(),
            activity_kind: self.activity_kind.clone(),
            activity_id: self.activity_id,
            status,
            old_version_save,
            detail,
            recorded_at: self.recorded_at,
            updated_at: now,
        }
    }

    /// Serializes the record for host-state persistence.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, PublicationFailure> {
        let mut current = self.clone();
        current.format = PUBLICATION_RECORD_FORMAT;
        serde_json::to_vec(&current).map_err(|error| PublicationFailure::RecordCorrupt {
            detail: format!("publication record JSON: {error}"),
        })
    }

    /// Parses a host-state record, rejecting unknown formats and fields.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, PublicationFailure> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| PublicationFailure::RecordCorrupt {
                detail: format!("publication record JSON: {error}"),
            })?;
        let format = value
            .get("format")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| PublicationFailure::RecordCorrupt {
                detail: "publication record has no numeric format".to_owned(),
            })?;
        let format = u32::try_from(format).map_err(|_| PublicationFailure::RecordCorrupt {
            detail: format!("unsupported publication record format {format}"),
        })?;
        if format != PUBLICATION_RECORD_FORMAT {
            return Err(PublicationFailure::UnsupportedRecordFormat { found: format });
        }
        serde_json::from_value(value).map_err(|error| PublicationFailure::RecordCorrupt {
            detail: format!("publication record JSON: {error}"),
        })
    }

    /// Persisted format version.
    pub const fn format(&self) -> u32 {
        self.format
    }

    /// Project that owns the record.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Request identifier.
    pub const fn request_id(&self) -> &PublicationRequestId {
        &self.request_id
    }

    /// Fingerprint of the exact request payload.
    pub const fn request_fingerprint(&self) -> &FileVersion {
        &self.request_fingerprint
    }

    /// Project-relative formal companion.
    pub fn target(&self) -> &NonEmptyText {
        &self.target
    }

    /// Expected current version or explicit absence.
    pub const fn expected_version(&self) -> &ExpectedTargetVersion {
        &self.expected_version
    }

    /// Approved content digest.
    pub const fn approved_version(&self) -> &FileVersion {
        &self.approved_version
    }

    /// Version observed before the intent, when one existed.
    pub const fn before_version(&self) -> Option<&FileVersion> {
        self.before_version.as_ref()
    }

    /// Version observed after the side effect, when it was readable.
    pub const fn observed_after_version(&self) -> Option<&FileVersion> {
        self.observed_after_version.as_ref()
    }

    /// Host purpose for the publication.
    pub const fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    /// Stable host-activity kind.
    pub const fn activity_kind(&self) -> &EventKind {
        &self.activity_kind
    }

    /// Stable host-activity identifier shared by the intent and result events.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity_id
    }

    /// Current record status.
    pub const fn status(&self) -> PublicationStatus {
        self.status
    }

    /// Old-version save result.
    pub const fn old_version_save(&self) -> &OldVersionSave {
        &self.old_version_save
    }

    /// Sanitized detail for a failure or unknown result.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Time the request intent was first recorded.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// Time the record last changed.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

/// Whether a publication is one file replacement or part of a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationUnit {
    /// Exactly one formal file is replaced by this request.
    SingleFile,
}

impl PublicationUnit {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFile => PUBLICATION_UNIT_SINGLE_FILE,
        }
    }
}

impl fmt::Display for PublicationUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Positive, durable publication outcome returned to the host.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationResult {
    request_id: PublicationRequestId,
    project_id: ProjectId,
    target: NonEmptyText,
    status: PublicationStatus,
    duplicate: bool,
    unit: PublicationUnit,
    before_version: Option<FileVersion>,
    approved_version: FileVersion,
    observed_after_version: Option<FileVersion>,
    old_version_save: OldVersionSave,
    activity_id: HostActivityId,
    notification: Option<Event>,
}

impl PublicationResult {
    pub(crate) fn from_record(
        record: &PublicationRecord,
        duplicate: bool,
        notification: Option<Event>,
    ) -> Self {
        Self {
            request_id: record.request_id.clone(),
            project_id: record.project_id,
            target: record.target.clone(),
            status: record.status,
            duplicate,
            unit: PublicationUnit::SingleFile,
            before_version: record.before_version.clone(),
            approved_version: record.approved_version.clone(),
            observed_after_version: record.observed_after_version.clone(),
            old_version_save: record.old_version_save.clone(),
            activity_id: record.activity_id,
            notification,
        }
    }

    /// Request that produced this result.
    pub const fn request_id(&self) -> &PublicationRequestId {
        &self.request_id
    }

    /// Project that owns the formal companion.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Project-relative formal companion.
    pub fn target(&self) -> &NonEmptyText {
        &self.target
    }

    /// `Published` or `NotPublished`.
    pub const fn status(&self) -> PublicationStatus {
        self.status
    }

    /// Whether this result came from an already recorded request.
    pub const fn duplicate(&self) -> bool {
        self.duplicate
    }

    /// This boundary only performs single-file replacements.
    pub const fn unit(&self) -> PublicationUnit {
        self.unit
    }

    /// Version observed before the request, when the target existed.
    pub const fn before_version(&self) -> Option<&FileVersion> {
        self.before_version.as_ref()
    }

    /// Approved content digest.
    pub const fn approved_version(&self) -> &FileVersion {
        &self.approved_version
    }

    /// Version observed after the side effect, when it was readable.
    pub const fn observed_after_version(&self) -> Option<&FileVersion> {
        self.observed_after_version.as_ref()
    }

    /// Old-version save result.
    pub const fn old_version_save(&self) -> &OldVersionSave {
        &self.old_version_save
    }

    /// Host-activity identifier used by the audit events.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity_id
    }

    /// Newly committed notification for this call, absent on duplicates.
    pub const fn notification(&self) -> Option<&Event> {
        self.notification.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::events::EventKind;
    use crate::contracts::ids::HostActivityId;

    fn request_for(project: ProjectId, content: &str, purpose: &str) -> PublicationRequest {
        PublicationRequest::new(
            project,
            PublicationRequestId::new("request-1").expect("request id"),
            NonEmptyText::new("docs/sdd/specs/page.html").expect("target"),
            ExpectedTargetVersion::absent(),
            content,
            Purpose::new(purpose).expect("purpose"),
        )
        .expect("request")
    }

    fn request(content: &str, purpose: &str) -> PublicationRequest {
        request_for(ProjectId::new(), content, purpose)
    }

    #[test]
    fn request_rejects_empty_bounded_and_absolute_fields() {
        let project = ProjectId::new();
        let id = PublicationRequestId::new("request").expect("id");
        let target = NonEmptyText::new("page.html").expect("target");
        let purpose = Purpose::new("publish").expect("purpose");
        assert!(
            PublicationRequest::new(project, id.clone(), target.clone(), ExpectedTargetVersion::absent(), "x", purpose.clone())
                .is_ok()
        );
        assert!(PublicationRequestId::new(" ").is_err());
        assert!(PublicationRequestId::new("x\ny").is_err());
        assert!(
            PublicationRequestId::new("x".repeat(MAX_PUBLICATION_REQUEST_ID_SCALARS + 1)).is_err()
        );
        let absolute = NonEmptyText::new("/tmp/page.html").expect("target");
        assert!(
            PublicationRequest::new(project, id, absolute, ExpectedTargetVersion::absent(), "x", purpose)
                .is_err()
        );
    }

    #[test]
    fn fingerprints_bind_the_exact_payload() {
        let project = ProjectId::new();
        let first = request_for(project, "<html>one</html>", "publish the approved companion");
        let second = request_for(project, "<html>one</html>", "publish the approved companion");
        let changed_content = request_for(
            project,
            "<html>two</html>",
            "publish the approved companion",
        );
        let changed_purpose = request_for(
            project,
            "<html>one</html>",
            "publish a different companion",
        );
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_ne!(first.fingerprint(), changed_content.fingerprint());
        assert_ne!(first.fingerprint(), changed_purpose.fingerprint());
    }

    #[test]
    fn publication_records_reject_unknown_formats_and_roundtrip() {
        let request = request("<html>one</html>", "publish the approved companion");
        let record = PublicationRecord::pending(
            &request,
            None,
            EventKind::new(PUBLICATION_ACTIVITY_KIND).expect("kind"),
            HostActivityId::new(request.project_id()),
            Timestamp::from_unix_millis(100),
        );
        let encoded = record.to_bytes().expect("encode");
        let decoded = PublicationRecord::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(decoded.status(), PublicationStatus::Pending);
        assert_eq!(decoded.old_version_save(), &OldVersionSave::NotAttempted);

        let unknown = br#"{"format":999,"projectId":"x"}"#;
        assert!(matches!(
            PublicationRecord::from_bytes(unknown),
            Err(PublicationFailure::UnsupportedRecordFormat { found: 999 })
        ));
        assert!(matches!(
            PublicationRecord::from_bytes(b"{not json"),
            Err(PublicationFailure::RecordCorrupt { .. })
        ));
    }
}
