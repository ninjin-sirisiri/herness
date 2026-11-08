//! Versioned opaque engine checkpoint carried across the store port.
//!
//! Core never interprets checkpoint internals. The engine adapter owns the
//! format; the store persists and returns the same versioned opaque bytes.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;
use crate::contracts::ids::RunId;

/// Format version of an engine-owned checkpoint body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointFormatVersion(u32);

impl CheckpointFormatVersion {
    /// Creates a non-zero checkpoint format version.
    pub fn new(value: u32) -> Result<Self, CoreError> {
        if value == 0 {
            Err(CoreError::InvalidCheckpointVersion { found: value })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Serialize for CheckpointFormatVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for CheckpointFormatVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Opaque engine checkpoint bytes.
///
/// The bytes are redacted from `Debug` output. Only engine adapters and the
/// store should ever inspect them.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckpointPayload(Vec<u8>);

impl CheckpointPayload {
    /// Wraps opaque checkpoint bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the opaque bytes. Intended for engine adapters and the store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the value and returns the opaque bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for CheckpointPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheckpointPayload([REDACTED; {} bytes])", self.0.len())
    }
}

impl From<Vec<u8>> for CheckpointPayload {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl Serialize for CheckpointPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for CheckpointPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        decode_hex(&value).map(Self).map_err(de::Error::custom)
    }
}

/// A checkpoint body plus its adapter-owned format version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkpoint {
    run_id: RunId,
    format_version: CheckpointFormatVersion,
    payload: CheckpointPayload,
}

impl Checkpoint {
    /// Creates a versioned opaque checkpoint for `run_id`.
    pub fn new(
        run_id: RunId,
        format_version: CheckpointFormatVersion,
        payload: CheckpointPayload,
    ) -> Self {
        Self {
            run_id,
            format_version,
            payload,
        }
    }

    /// Run this checkpoint belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Adapter-owned checkpoint format version.
    pub const fn format_version(&self) -> CheckpointFormatVersion {
        self.format_version
    }

    /// Opaque checkpoint body.
    pub fn payload(&self) -> &CheckpointPayload {
        &self.payload
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("checkpoint payload hex must have an even number of digits");
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or("checkpoint payload contains a non-hex digit")?;
        let low = hex_nibble(pair[1]).ok_or("checkpoint payload contains a non-hex digit")?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
