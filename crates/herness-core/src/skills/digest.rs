//! SHA-256 digests used by skill fingerprints.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::contracts::errors::{ArgumentViolation, CoreError};

/// Lowercase SHA-256 hex digest of skill source bytes.
///
/// The digest is always computed over the original bytes read from the pack.
/// It is not computed over normalized text, a rendered view, or host overlay
/// content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkillDigest(String);

impl SkillDigest {
    /// Hashes `bytes` with SHA-256.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self::from_sha256(Sha256::digest(bytes))
    }

    /// Builds a digest from an existing SHA-256 output.
    pub(crate) fn from_sha256(digest: impl Into<[u8; 32]>) -> Self {
        let mut hex = String::with_capacity(64);
        for byte in digest.into() {
            use fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(hex)
    }

    /// Validates a 64-character SHA-256 hex digest and normalizes it to
    /// lowercase.
    pub fn from_hex(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidValue {
                field: "skillDigest".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "expected a 64-character SHA-256 hex digest".to_owned(),
                },
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Borrows the lowercase hex representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SkillDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SkillDigest {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl Serialize for SkillDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SkillDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_lowercase_sha256_hex() {
        let digest = SkillDigest::of_bytes(b"abc");
        assert_eq!(
            digest.as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest.to_string(), digest.as_str());
    }

    #[test]
    fn digest_rejects_invalid_hex() {
        assert!(SkillDigest::from_hex("abc").is_err());
        assert!(SkillDigest::from_hex("z".repeat(64)).is_err());
        assert_eq!(
            SkillDigest::from_hex("A".repeat(64))
                .expect("uppercase hex is accepted")
                .as_str(),
            "a".repeat(64)
        );
    }
}
