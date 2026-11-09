//! Public contract versioning.
//!
//! Version 2 is the only version written for new public events. Both version 1
//! and version 2 are known read versions: version 1 events are decoded by an
//! explicit compatibility decoder as run-subject events. Unknown versions are
//! rejected with [`CoreError::UnknownContractVersion`] instead of being read
//! with version-2 rules.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::CoreError;

/// The version written for new public events.
pub const CONTRACT_VERSION: u32 = 2;

/// Oldest public contract version this build can read.
pub const OLDEST_READABLE_CONTRACT_VERSION: u32 = 1;

/// Version of the host-owned public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractVersion(u32);

impl ContractVersion {
    /// Version 1, readable through the explicit compatibility decoder.
    pub const V1: Self = Self(1);

    /// Version 2, the only version written for new events.
    pub const V2: Self = Self(2);

    /// The contract version implemented by this build for new writes.
    pub const CURRENT: Self = Self(CONTRACT_VERSION);

    /// Every event contract version this build can read.
    pub const READABLE: [Self; 2] = [Self::V1, Self::V2];

    /// Returns the numeric version.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether this build knows how to read the version.
    pub const fn is_readable(self) -> bool {
        matches!(self.0, 1 | 2)
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
        match value {
            1 => Ok(Self::V1),
            CONTRACT_VERSION => Ok(Self::CURRENT),
            _ => Err(CoreError::UnknownContractVersion {
                found: value,
                expected: CONTRACT_VERSION,
            }),
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
