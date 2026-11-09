//! Structured, non-secret H3 failures.
//!
//! These values cross contract and port boundaries. They never carry raw
//! candidate bytes, credentials, provider bodies, or model-chosen paths.

use std::fmt;

use herness_core::{ArgumentViolation, ProjectId};
use herness_supervision::SupervisionError;

/// A structured H3 contract or persistence failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Error {
    /// A contract value failed schema validation.
    InvalidValue {
        /// Rejected field.
        field: String,
        /// Structured validation failure.
        violation: ArgumentViolation,
    },
    /// A value belonging to another project reached a project-scoped API.
    CrossProject {
        /// Identifier or record kind.
        id_kind: String,
        /// Project the API is bound to.
        expected: ProjectId,
        /// Project found on the value.
        found: ProjectId,
    },
    /// A saved record declares an unknown format version.
    UnsupportedFormat {
        /// Record kind.
        record: &'static str,
        /// Version found on the record.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// A compare-and-swap write used an outdated or missing revision.
    StaleRevision {
        /// Host-owned record key.
        key: String,
        /// Revision the caller expected.
        expected: Option<u64>,
        /// Revision currently stored.
        found: Option<u64>,
    },
    /// The same request identifier was already recorded with another request.
    DuplicateRequestConflict {
        /// Request identifier.
        request: String,
        /// Recorded request description.
        recorded: String,
        /// Newly supplied request description.
        supplied: String,
    },
    /// A different immutable value is already stored for the same identifier.
    RecordConflict {
        /// Record kind.
        record: &'static str,
        /// Record identifier.
        id: String,
    },
    /// A required record does not exist.
    NotFound {
        /// Record kind.
        record: &'static str,
        /// Record identifier.
        id: String,
    },
    /// Stored bytes could not be decoded as the expected record.
    Corrupt {
        /// Record kind.
        record: &'static str,
        /// Sanitized decode detail.
        detail: String,
    },
    /// The host persistence layer is unavailable.
    Storage {
        /// Sanitized storage detail.
        detail: String,
    },
    /// A required capability is not implemented or not currently available.
    Unavailable {
        /// Stable capability label.
        capability: String,
        /// Sanitized explanation. It never contains candidate bytes or secrets.
        detail: String,
    },
}

impl H3Error {
    /// Creates an empty-value validation failure.
    pub fn empty(field: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            violation: ArgumentViolation::Empty,
        }
    }

    /// Creates a positive-integer validation failure.
    pub fn must_be_positive(field: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            violation: ArgumentViolation::MustBePositive,
        }
    }

    /// Creates a generic validation failure.
    pub fn invalid(field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            violation: ArgumentViolation::Invalid {
                detail: detail.into(),
            },
        }
    }
}

impl fmt::Display for H3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue { field, violation } => {
                write!(f, "invalid {field}: {violation:?}")
            }
            Self::CrossProject {
                id_kind,
                expected,
                found,
            } => write!(
                f,
                "{id_kind} belongs to project {found}, not the expected project {expected}"
            ),
            Self::UnsupportedFormat {
                record,
                found,
                expected,
            } => write!(
                f,
                "{record} format version {found} is not supported (expected {expected})"
            ),
            Self::StaleRevision {
                key,
                expected,
                found,
            } => write!(
                f,
                "record {key:?} revision is stale: expected {expected:?}, found {found:?}"
            ),
            Self::DuplicateRequestConflict {
                request,
                recorded,
                supplied,
            } => write!(
                f,
                "request {request} was already recorded as {recorded}, not {supplied}"
            ),
            Self::RecordConflict { record, id } => {
                write!(f, "{record} {id} is already stored with another value")
            }
            Self::NotFound { record, id } => write!(f, "{record} {id} was not found"),
            Self::Corrupt { record, detail } => {
                write!(f, "stored {record} is invalid: {detail}")
            }
            Self::Storage { detail } => write!(f, "H3 storage failure: {detail}"),
            Self::Unavailable { capability, detail } => {
                write!(f, "H3 capability {capability} is unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for H3Error {}

impl From<SupervisionError> for H3Error {
    fn from(error: SupervisionError) -> Self {
        match error {
            SupervisionError::CrossProjectReference {
                id_kind,
                expected,
                found,
            } => Self::CrossProject {
                id_kind,
                expected,
                found,
            },
            other => Self::InvalidValue {
                field: "supervision".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: other.to_string(),
                },
            },
        }
    }
}
