//! Structured errors produced by the host-owned store.
//!
//! The store keeps failure detail internal and maps every error crossing the
//! [`herness_core::StorePort`] boundary to a sanitized [`CoreError`]. Database
//! rows, checkpoint bytes, credentials, and provider responses are never
//! included in these values.

use std::fmt;

use herness_core::{
    ArgumentViolation, AttemptId, CONTRACT_VERSION, CoreError, IdKind, OperationId, ProjectId,
    StoreFailureKind,
};

/// Why a [`StoreConfig`](crate::StoreConfig) was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigViolation {
    /// No application-data root was supplied.
    EmptyPath,
    /// The application-data root was relative, which would resolve against a
    /// process or project directory.
    NotAbsolute,
    /// The application-data root contained a `..` component.
    ParentComponent,
    /// The application-data root was the project directory or inside it.
    InsideProject,
}

impl fmt::Display for ConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("application-data root must not be empty"),
            Self::NotAbsolute => f.write_str("application-data root must be an absolute path"),
            Self::ParentComponent => {
                f.write_str("application-data root must not contain a parent component")
            }
            Self::InsideProject => {
                f.write_str("application-data root must be outside the project directory")
            }
        }
    }
}

/// A store failure with host-internal detail.
///
/// This type never carries checkpoint bodies, credentials, or provider
/// responses. Convert it with `Into<CoreError>` before crossing a public port.
#[derive(Debug)]
pub enum StoreError {
    /// The application-data root or project boundary is not acceptable.
    InvalidConfig {
        /// Rejected configuration rule.
        violation: ConfigViolation,
    },
    /// The database schema is newer than this build supports.
    UnsupportedSchemaVersion {
        /// Schema version stored in the database.
        found: u32,
        /// Newest schema version this build can migrate to.
        supported: u32,
    },
    /// The database has user tables but no herness schema marker.
    ForeignDatabase,
    /// A migration failed; its transaction was rolled back.
    MigrationFailed {
        /// Migration version being applied.
        version: u32,
        /// Sanitized description of the failure.
        detail: String,
    },
    /// A stored checkpoint declares a format version this build does not accept.
    UnsupportedCheckpointFormat {
        /// Format version found in the checkpoint row.
        found: u32,
    },
    /// A stored event declares an unknown public contract version.
    UnsupportedContractVersion {
        /// Contract version found in the event row.
        found: u32,
    },
    /// A host-activity event was offered to a run-only storage path.
    ///
    /// A checkpoint or operation result belongs to one run. The event must not
    /// be dropped or given a fabricated run identifier.
    UnsupportedHostActivityEvent,
    /// A checkpoint commit repeats an operation id that is already recorded.
    DuplicateOperation {
        /// Operation id already present in the store.
        operation: OperationId,
    },
    /// A result was supplied for an operation with no recorded intent.
    UnknownOperation {
        /// Operation id that has no intent row.
        operation: OperationId,
    },
    /// A history cursor was minted for a different project.
    CrossProjectReference {
        /// Project the query addresses.
        expected: ProjectId,
        /// Project that minted the cursor.
        found: ProjectId,
    },
    /// A live replay cursor was not a positive sequence.
    InvalidLiveCursor,
    /// A different result is already recorded for the operation.
    OperationResultConflict {
        /// Operation id whose stored result differs.
        operation: OperationId,
    },
    /// A request attempt is already recorded with a different intent.
    RequestIntentConflict {
        /// Attempt whose stored intent differs.
        attempt: AttemptId,
    },
    /// A terminal observation is already recorded, or the transition is not
    /// allowed.
    RequestObservationConflict {
        /// Attempt whose stored observation differs.
        attempt: AttemptId,
    },
    /// An observation was supplied for an attempt that was never persisted.
    UnknownRequestAttempt {
        /// Attempt with no intent row.
        attempt: AttemptId,
    },
    /// A supervised-state update used an outdated or missing revision.
    StaleRevision {
        /// Host-owned state key.
        key: String,
        /// Revision the caller expected.
        expected: Option<u64>,
        /// Revision currently stored.
        found: Option<u64>,
    },
    /// A supervised-state key was empty.
    InvalidStateKey,
    /// A different evidence value is already stored for the same ID.
    EvidenceRecordConflict {
        /// Evidence identifier whose stored value differs.
        evidence: String,
    },
    /// A different command result is already stored for the same request ID.
    CommandResultConflict {
        /// Request identifier whose stored result differs.
        request: String,
    },
    /// A different budget reservation is already stored for the same attempt.
    BudgetReservationConflict {
        /// Reservation attempt identifier whose stored value differs.
        attempt: String,
    },
    /// A different immutable H3 record is already stored for the same ID.
    HtmlSyncRecordConflict {
        /// H3 record kind.
        record: &'static str,
        /// Record identifier.
        id: String,
    },
    /// The same H3 request identifier was recorded with another request.
    HtmlSyncRequestConflict {
        /// Request identifier.
        request: String,
        /// Recorded request description.
        recorded: String,
        /// Newly supplied request description.
        supplied: String,
    },
    /// A saved H3 record declares an unknown format version.
    HtmlSyncFormat {
        /// H3 record kind.
        record: &'static str,
        /// Version found in the row.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// An H3 value belongs to another project.
    HtmlSyncCrossProject {
        /// Project the operation is bound to.
        expected: ProjectId,
        /// Project found on the value.
        found: ProjectId,
    },
    /// An H3 commit is structurally invalid before any write.
    HtmlSyncInvalidCommit {
        /// Sanitized validation detail.
        detail: String,
    },
    /// Stored data failed an integrity check.
    CorruptData {
        /// Sanitized description of the failed check.
        detail: String,
    },
    /// SQLite reported an error.
    Database {
        /// Sanitized SQLite failure description.
        detail: String,
    },
    /// The filesystem could not prepare the store location.
    Io {
        /// Sanitized I/O failure description.
        detail: String,
    },
    /// JSON stored in a row could not be interpreted.
    Codec {
        /// Sanitized codec failure description.
        detail: String,
    },
    /// A test-only fault was injected.
    InjectedFault {
        /// Fault injection point that fired.
        point: &'static str,
    },
}

impl StoreError {
    pub(crate) fn database(error: rusqlite::Error) -> Self {
        Self::Database {
            detail: error.to_string(),
        }
    }

    pub(crate) fn io(error: std::io::Error) -> Self {
        Self::Io {
            detail: error.to_string(),
        }
    }

    pub(crate) fn codec(error: serde_json::Error) -> Self {
        Self::Codec {
            detail: error.to_string(),
        }
    }

    pub(crate) fn corrupt(detail: impl Into<String>) -> Self {
        Self::CorruptData {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { violation } => write!(f, "invalid store config: {violation}"),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "database schema version {found} is newer than supported version {supported}"
            ),
            Self::ForeignDatabase => {
                f.write_str("database contains tables but no herness schema marker")
            }
            Self::MigrationFailed { version, detail } => {
                write!(f, "schema migration {version} failed: {detail}")
            }
            Self::UnsupportedCheckpointFormat { found } => {
                write!(f, "checkpoint format version {found} is not supported")
            }
            Self::UnsupportedContractVersion { found } => write!(
                f,
                "stored event contract version {found} is not supported by contract version {CONTRACT_VERSION}"
            ),
            Self::UnsupportedHostActivityEvent => {
                f.write_str("host activity events are not allowed on this run-only path")
            }
            Self::DuplicateOperation { operation } => {
                write!(f, "operation {operation} is already recorded")
            }
            Self::UnknownOperation { operation } => {
                write!(f, "operation {operation} has no recorded intent")
            }
            Self::RequestIntentConflict { attempt } => {
                write!(
                    f,
                    "request attempt {attempt} is already recorded with another intent"
                )
            }
            Self::RequestObservationConflict { attempt } => {
                write!(
                    f,
                    "request attempt {attempt} already has a conflicting observation"
                )
            }
            Self::UnknownRequestAttempt { attempt } => {
                write!(f, "request attempt {attempt} has no recorded intent")
            }
            Self::StaleRevision {
                key,
                expected,
                found,
            } => write!(
                f,
                "supervised state {key:?} revision is stale: expected {expected:?}, found {found:?}"
            ),
            Self::InvalidStateKey => f.write_str("supervised state key must not be empty"),
            Self::EvidenceRecordConflict { evidence } => {
                write!(
                    f,
                    "evidence {evidence} is already recorded with another value"
                )
            }
            Self::CommandResultConflict { request } => {
                write!(
                    f,
                    "request {request} is already recorded with another result"
                )
            }
            Self::BudgetReservationConflict { attempt } => {
                write!(
                    f,
                    "attempt {attempt} is already recorded with another budget reservation"
                )
            }
            Self::HtmlSyncRecordConflict { record, id } => {
                write!(f, "{record} {id} is already stored with another value")
            }
            Self::HtmlSyncRequestConflict {
                request,
                recorded,
                supplied,
            } => write!(
                f,
                "H3 request {request} was already recorded as {recorded}, not {supplied}"
            ),
            Self::HtmlSyncFormat {
                record,
                found,
                expected,
            } => write!(
                f,
                "stored {record} format version {found} is not supported (expected {expected})"
            ),
            Self::HtmlSyncCrossProject { expected, found } => write!(
                f,
                "H3 value belongs to project {found}, not the expected project {expected}"
            ),
            Self::HtmlSyncInvalidCommit { detail } => {
                write!(f, "invalid H3 commit: {detail}")
            }
            Self::CrossProjectReference { expected, found } => write!(
                f,
                "history cursor belongs to project {found}, not the expected project {expected}"
            ),
            Self::InvalidLiveCursor => {
                f.write_str("live replay cursor must be a positive sequence")
            }
            Self::OperationResultConflict { operation } => {
                write!(f, "operation {operation} already has a different result")
            }
            Self::CorruptData { detail } => write!(f, "stored data is corrupt: {detail}"),
            Self::Database { detail } => write!(f, "sqlite failure: {detail}"),
            Self::Io { detail } => write!(f, "store location failure: {detail}"),
            Self::Codec { detail } => write!(f, "stored JSON is invalid: {detail}"),
            Self::InjectedFault { point } => write!(f, "injected fault at {point}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::database(error)
    }
}

impl From<StoreError> for herness_supervision::SupervisionError {
    fn from(error: StoreError) -> Self {
        use herness_supervision::SupervisionError;

        match error {
            StoreError::CrossProjectReference { expected, found } => {
                SupervisionError::CrossProjectReference {
                    id_kind: "project".to_owned(),
                    expected,
                    found,
                }
            }
            StoreError::StaleRevision {
                expected, found, ..
            } => match (expected, found) {
                (Some(expected), Some(found)) => {
                    SupervisionError::RevisionConflict { expected, found }
                }
                (_, None) => SupervisionError::UnknownSupervision,
                (None, Some(found)) => SupervisionError::RevisionConflict { expected: 0, found },
            },
            StoreError::EvidenceRecordConflict { evidence } => {
                SupervisionError::EvidenceContractViolation {
                    field: "evidence.id".to_owned(),
                    detail: format!("a different evidence record is already stored for {evidence}"),
                }
            }
            StoreError::CommandResultConflict { request } => {
                SupervisionError::DuplicateResultConflict { request }
            }
            StoreError::BudgetReservationConflict { attempt } => {
                SupervisionError::BudgetReservationConflict { attempt }
            }
            other => SupervisionError::StorageFailure {
                detail: other.to_string(),
            },
        }
    }
}

impl From<StoreError> for CoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::DuplicateOperation { operation } => {
                CoreError::DuplicateOperation { operation }
            }
            StoreError::CrossProjectReference { expected, found } => {
                CoreError::CrossProjectReference {
                    id_kind: IdKind::Project,
                    expected,
                    found,
                }
            }
            StoreError::InvalidLiveCursor => CoreError::InvalidValue {
                field: "afterSequence".to_owned(),
                violation: ArgumentViolation::MustBePositive,
            },
            StoreError::UnsupportedContractVersion { found } => CoreError::UnknownContractVersion {
                found,
                expected: CONTRACT_VERSION,
            },
            StoreError::UnsupportedHostActivityEvent => CoreError::UnsupportedPortFeature {
                feature: herness_core::PortFeature::HostActivityEvents,
            },
            StoreError::UnsupportedSchemaVersion { .. }
            | StoreError::UnsupportedCheckpointFormat { .. } => CoreError::StoreUnavailable {
                failure: StoreFailureKind::UnsupportedVersion,
            },
            StoreError::OperationResultConflict { .. }
            | StoreError::RequestIntentConflict { .. }
            | StoreError::RequestObservationConflict { .. }
            | StoreError::StaleRevision { .. }
            | StoreError::EvidenceRecordConflict { .. }
            | StoreError::CommandResultConflict { .. }
            | StoreError::BudgetReservationConflict { .. }
            | StoreError::HtmlSyncRecordConflict { .. }
            | StoreError::HtmlSyncRequestConflict { .. } => CoreError::StoreUnavailable {
                failure: StoreFailureKind::Conflict,
            },
            StoreError::CorruptData { .. }
            | StoreError::Codec { .. }
            | StoreError::ForeignDatabase
            | StoreError::HtmlSyncFormat { .. }
            | StoreError::HtmlSyncCrossProject { .. } => CoreError::StoreUnavailable {
                failure: StoreFailureKind::CorruptData,
            },
            StoreError::InvalidConfig { .. }
            | StoreError::MigrationFailed { .. }
            | StoreError::UnknownOperation { .. }
            | StoreError::UnknownRequestAttempt { .. }
            | StoreError::InvalidStateKey
            | StoreError::HtmlSyncInvalidCommit { .. }
            | StoreError::Database { .. }
            | StoreError::Io { .. }
            | StoreError::InjectedFault { .. } => CoreError::StoreUnavailable {
                failure: StoreFailureKind::Unavailable,
            },
        }
    }
}
