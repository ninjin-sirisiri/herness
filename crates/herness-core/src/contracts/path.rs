//! Absolute working-directory values frozen into an operation.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{CoreError, PathViolation};

/// An absolute, UTF-8 working directory captured when an operation is frozen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsolutePath(String);

impl AbsolutePath {
    /// Validates and stores an absolute path.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CoreError::InvalidPath {
                path: value,
                violation: PathViolation::Empty,
            });
        }
        if value.contains('\0') {
            return Err(CoreError::InvalidPath {
                path: value,
                violation: PathViolation::ContainsNul,
            });
        }
        if !Path::new(&value).is_absolute() {
            return Err(CoreError::InvalidPath {
                path: value,
                violation: PathViolation::NotAbsolute,
            });
        }
        Ok(Self(value))
    }

    /// Borrows the path.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Borrows the path as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AbsolutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AbsolutePath {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for AbsolutePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AbsolutePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}
