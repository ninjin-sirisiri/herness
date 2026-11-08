//! Rationale and purpose values with the shared Unicode-scalar limit.
//!
//! Both values are trimmed, must be non-empty after trimming, and may contain
//! at most 1,000 Unicode scalar values. The count is deliberately neither the
//! UTF-8 byte length nor the UTF-16 code-unit length.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;

/// Maximum number of Unicode scalar values in a rationale or purpose.
pub const MAX_REASON_SCALARS: usize = 1_000;

/// Which reason field is being validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonField {
    /// The file-level reason for write/edit.
    Rationale,
    /// The command-level reason for bash.
    Purpose,
}

/// Reason validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ReasonViolation {
    /// The trimmed value was empty.
    Empty,
    /// The trimmed value exceeded [`MAX_REASON_SCALARS`].
    TooLong {
        /// Counted Unicode scalar values.
        actual: usize,
        /// Maximum permitted count.
        max: usize,
    },
}

fn validate_reason(field: ReasonField, raw: &str) -> Result<String, CoreError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::Empty,
        });
    }

    let actual = trimmed.chars().count();
    if actual > MAX_REASON_SCALARS {
        return Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::TooLong {
                actual,
                max: MAX_REASON_SCALARS,
            },
        });
    }

    Ok(trimmed.to_owned())
}

/// File-level explanation supplied by the model for a write or edit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rationale(String);

impl Rationale {
    /// Validates and stores a rationale.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        validate_reason(ReasonField::Rationale, value.as_ref()).map(Self)
    }

    /// Borrows the trimmed rationale.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value and returns the trimmed string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Rationale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Rationale {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Rationale {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Rationale {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for Rationale {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Rationale {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Command-level explanation supplied by the model for bash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Purpose(String);

impl Purpose {
    /// Validates and stores a purpose.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        validate_reason(ReasonField::Purpose, value.as_ref()).map(Self)
    }

    /// Borrows the trimmed purpose.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value and returns the trimmed string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Purpose {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Purpose {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Purpose {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for Purpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Purpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}
