//! H3 contract and persisted-record format versions.
//!
//! Every saved H3 value carries an explicit `formatVersion`. A decoder checks
//! the version before it interprets any other field, and an unknown version is
//! rejected instead of being read with current rules.

use crate::error::H3Error;

/// Format version written for every H3 record by this build.
pub const H3_FORMAT_VERSION: u32 = 1;

/// Rejects a record that is not the current H3 format.
pub fn ensure_format(found: u32, record: &'static str) -> Result<(), H3Error> {
    if found == H3_FORMAT_VERSION {
        Ok(())
    } else {
        Err(H3Error::UnsupportedFormat {
            record,
            found,
            expected: H3_FORMAT_VERSION,
        })
    }
}

/// A persisted H3 record with an explicit format version.
pub trait H3Record: serde::de::DeserializeOwned {
    /// Stable record label used in structured errors.
    const RECORD: &'static str;
    /// Format version expected by this build.
    const FORMAT_VERSION: u32 = H3_FORMAT_VERSION;

    /// Format version carried by the decoded value.
    fn format_version(&self) -> u32;
}

/// Decodes a saved H3 record after checking its format version.
///
/// The probe happens before the full decode so a future or unknown format is
/// not interpreted with current rules. Unknown fields are rejected by the
/// record's own `deny_unknown_fields` attribute.
pub fn decode_record<T: H3Record>(bytes: &[u8]) -> Result<T, H3Error> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Probe {
        format_version: u32,
    }

    let probe: Probe = serde_json::from_slice(bytes).map_err(|error| H3Error::Corrupt {
        record: T::RECORD,
        detail: error.to_string(),
    })?;
    ensure_format(probe.format_version, T::RECORD)?;
    let value: T = serde_json::from_slice(bytes).map_err(|error| H3Error::Corrupt {
        record: T::RECORD,
        detail: error.to_string(),
    })?;
    ensure_format(value.format_version(), T::RECORD)?;
    Ok(value)
}

/// Serializes a current-format H3 record, rejecting a foreign format before
/// any bytes are written.
pub fn encode_record<T: H3Record + serde::Serialize>(value: &T) -> Result<Vec<u8>, H3Error> {
    ensure_format(value.format_version(), T::RECORD)?;
    serde_json::to_vec(value).map_err(|error| H3Error::Corrupt {
        record: T::RECORD,
        detail: error.to_string(),
    })
}
