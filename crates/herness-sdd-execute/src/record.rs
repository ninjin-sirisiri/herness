//! Versioned store envelopes for H4 durable rows.
//!
//! Every persisted H4 value is written as
//! `{"formatVersion": 1, "body": <value>}`. The envelope gives each row an
//! explicit format version even where the H4 value itself carries no version
//! (journals, control records, reservations), so an unknown or future payload
//! is rejected before any field is interpreted with current rules.
//!
//! The H4 crate owns this format. `herness-store` only stores and forwards the
//! bytes; it never redefines or rewrites the H4 payload structure.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{FailureDetails, SddExecutionError};
use crate::state::RecoveryReason;

/// Format version written for every H4 persisted row by this build.
pub const STORE_RECORD_FORMAT_VERSION: u32 = 1;

/// Why one persisted H4 value could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordDecodeError {
    /// The envelope declares a format version this build does not implement.
    UnsupportedFormat {
        /// Row kind that was read.
        record: &'static str,
        /// Version found in the row.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// The bytes are not a valid envelope or body.
    Corrupt {
        /// Row kind that was read.
        record: &'static str,
        /// Non-secret decode detail.
        detail: String,
    },
}

impl RecordDecodeError {
    /// The stored record kind.
    pub const fn record(&self) -> &'static str {
        match self {
            Self::UnsupportedFormat { record, .. } | Self::Corrupt { record, .. } => record,
        }
    }
}

impl std::fmt::Display for RecordDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat {
                record,
                found,
                expected,
            } => write!(
                f,
                "stored {record} format version {found} is not supported (expected {expected})"
            ),
            Self::Corrupt { record, detail } => {
                write!(f, "stored {record} is corrupt: {detail}")
            }
        }
    }
}

impl std::error::Error for RecordDecodeError {}

impl From<RecordDecodeError> for SddExecutionError {
    fn from(error: RecordDecodeError) -> Self {
        match error {
            RecordDecodeError::UnsupportedFormat { .. } => SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::VersionMismatch,
                details: FailureDetails::none().boxed(),
            },
            RecordDecodeError::Corrupt { record, detail } => SddExecutionError::InvalidValue {
                field: format!("stored.{record}"),
                detail,
            },
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeProbe {
    format_version: u32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    format_version: u32,
    body: serde_json::Value,
}

/// Encodes one H4 value in the current envelope.
pub fn encode_record<T: Serialize>(body: &T) -> Result<Vec<u8>, RecordDecodeError> {
    let record = "H4 record";
    let body = serde_json::to_value(body).map_err(|error| RecordDecodeError::Corrupt {
        record,
        detail: error.to_string(),
    })?;
    serde_json::to_vec(&serde_json::json!({
        "formatVersion": STORE_RECORD_FORMAT_VERSION,
        "body": body,
    }))
    .map_err(|error| RecordDecodeError::Corrupt {
        record,
        detail: error.to_string(),
    })
}

/// Decodes one H4 value after checking the envelope format version.
///
/// The version probe runs before the body is decoded, so a future envelope is
/// never interpreted with current rules.
pub fn decode_record<T: DeserializeOwned>(
    bytes: &[u8],
    record: &'static str,
) -> Result<T, RecordDecodeError> {
    let probe: EnvelopeProbe =
        serde_json::from_slice(bytes).map_err(|error| RecordDecodeError::Corrupt {
            record,
            detail: error.to_string(),
        })?;
    if probe.format_version != STORE_RECORD_FORMAT_VERSION {
        return Err(RecordDecodeError::UnsupportedFormat {
            record,
            found: probe.format_version,
            expected: STORE_RECORD_FORMAT_VERSION,
        });
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|error| RecordDecodeError::Corrupt {
            record,
            detail: error.to_string(),
        })?;
    if envelope.format_version != STORE_RECORD_FORMAT_VERSION {
        return Err(RecordDecodeError::UnsupportedFormat {
            record,
            found: envelope.format_version,
            expected: STORE_RECORD_FORMAT_VERSION,
        });
    }
    serde_json::from_value(envelope.body).map_err(|error| RecordDecodeError::Corrupt {
        record,
        detail: error.to_string(),
    })
}
