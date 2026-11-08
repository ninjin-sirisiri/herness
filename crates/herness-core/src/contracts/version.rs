//! Public contract versioning.
//!
//! Version 1 is the only contract this build can interpret. Unknown versions
//! are rejected with [`CoreError::UnknownContractVersion`] instead of being
//! read with version-1 rules.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;

/// The public contract version implemented by this build.
pub const CONTRACT_VERSION: u32 = 1;

/// Version of the host-owned public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractVersion(u32);

impl ContractVersion {
    /// The contract version implemented by this build.
    pub const CURRENT: Self = Self(CONTRACT_VERSION);

    /// Returns the numeric version.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for ContractVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl TryFrom<u32> for ContractVersion {
    type Error = CoreError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == CONTRACT_VERSION {
            Ok(Self(value))
        } else {
            Err(CoreError::UnknownContractVersion {
                found: value,
                expected: CONTRACT_VERSION,
            })
        }
    }
}

impl FromStr for ContractVersion {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = value
            .parse::<u32>()
            .map_err(|_| CoreError::InvalidContractVersion {
                value: value.to_owned(),
            })?;
        Self::try_from(parsed)
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ContractVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for ContractVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::try_from(value).map_err(de::Error::custom)
    }
}
