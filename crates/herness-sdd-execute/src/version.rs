//! Version, digest, and numeric-default identities for the H4 contract.
//!
//! The H4 public contract is version 1. A value that carries any other version
//! fails to decode instead of being read with version 1 rules. Plan schema and
//! inspector protocol versions are separate values so a plan defect is never
//! reported as an H4 contract defect.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SddExecutionError;

/// Version written for every H4 contract value, snapshot, and public response.
pub const SDD_EXECUTION_CONTRACT_VERSION: u32 = 1;

/// Pack-side host execution contract schema name.
pub const EXECUTION_CONTRACT_SCHEMA: &str = "herness-sdd-execution-contract";

/// Pack-side host execution contract version bound by this build.
pub const EXECUTION_CONTRACT_VERSION: u32 = 1;

/// Only approval source H4 accepts: the host-owned approval registry.
pub const APPROVAL_SOURCE_REGISTRY: &str = "h4-approval-registry";

/// Approval kind recorded for one H4 execution approval revision.
pub const APPROVAL_KIND: &str = "h4-execution-approval";

/// Only approval actor H4 accepts.
pub const APPROVAL_APPROVER: &str = "human";

/// Execution plan schema name owned by the pack.
pub const PLAN_SCHEMA_NAME: &str = "sdd-execution-plan";

/// Execution plan schema version owned by the pack.
pub const PLAN_SCHEMA_VERSION: u32 = 1;

/// Fenced block info string that carries the structured execution plan.
pub const PLAN_EXECUTION_BLOCK_INFO: &str = "sdd-execution-v1";

/// Plan inspector protocol name.
pub const PLAN_INSPECTOR_PROTOCOL: &str = "sdd-plan-inspect";

/// Plan inspector protocol version.
pub const PLAN_INSPECTOR_PROTOCOL_VERSION: u32 = 1;

/// Project-relative directory that may contain an execution plan.
pub const PLAN_PATH_PREFIX: &str = "docs/sdd/plans/";

/// Exact plan input limit in UTF-8 bytes. Larger input is rejected, never
/// truncated.
pub const MAX_PLAN_BYTES: u64 = 2 * 1024 * 1024;

/// Host-enforced inspector timeout in seconds.
pub const INSPECTOR_TIMEOUT_SECONDS: u64 = 30;

/// Periodic plan reconciliation interval in milliseconds.
pub const PLAN_RECONCILE_INTERVAL_MILLIS: u64 = 1_000;

/// Host commit budget in seconds (stage, hooks, and commit together).
pub const HOST_COMMIT_TIMEOUT_SECONDS: u64 = 30;

/// Application-wide concurrent Task executions. H3's authoring slot is
/// separate and may proceed at the same time.
pub const MAX_CONCURRENT_TASK_EXECUTIONS: u32 = 1;

/// Cumulative H2 supervision seconds for one Task. Resuming or re-approving a
/// plan never restores consumed time.
pub const H4_MAX_SUPERVISION_SECONDS: u64 = 7_200;

/// Additional child runs allowed by H2 for one Task.
pub const H4_MAX_ADDITIONAL_RUNS: u32 = 30;

/// Consecutive stalls that stop a Task without consuming another run.
pub const H4_MAX_CONSECUTIVE_STALLS: u32 = 3;

/// H4 contract version written and read by this build.
///
/// The value cannot hold an unknown version: decoding any other number fails
/// with [`SddExecutionError::UnsupportedContractVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionContractVersion(u32);

impl ExecutionContractVersion {
    /// The only version this build writes and reads.
    pub const CURRENT: Self = Self(SDD_EXECUTION_CONTRACT_VERSION);

    /// Numeric version.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for ExecutionContractVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl TryFrom<u32> for ExecutionContractVersion {
    type Error = SddExecutionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == SDD_EXECUTION_CONTRACT_VERSION {
            Ok(Self::CURRENT)
        } else {
            Err(SddExecutionError::UnsupportedContractVersion {
                found: value,
                expected: SDD_EXECUTION_CONTRACT_VERSION,
            })
        }
    }
}

impl Serialize for ExecutionContractVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for ExecutionContractVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::try_from(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for ExecutionContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Rejects a version number that this build does not implement.
pub fn ensure_supported_version(found: u32) -> Result<ExecutionContractVersion, SddExecutionError> {
    ExecutionContractVersion::try_from(found)
}

/// The H4 contract version written by this build.
pub const fn current_contract_version() -> ExecutionContractVersion {
    ExecutionContractVersion::CURRENT
}

/// Rejects a decoded contract value that is not the current version.
pub fn ensure_current_version(version: ExecutionContractVersion) -> Result<(), SddExecutionError> {
    if version == ExecutionContractVersion::CURRENT {
        Ok(())
    } else {
        Err(SddExecutionError::UnsupportedContractVersion {
            found: version.get(),
            expected: SDD_EXECUTION_CONTRACT_VERSION,
        })
    }
}

/// A SHA-256 digest in the pack's `sha256:<hex>` wire form.
///
/// The pack writes plan digests and execution-contract fingerprints in this
/// form. The digest is an identity, not a signature or an approval.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Computes the digest of exact bytes.
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(format!("sha256:{:x}", hasher.finalize()))
    }

    /// Parses a `sha256:<64 hex>` value.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, SddExecutionError> {
        let value = value.as_ref().trim();
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid_digest("a digest must start with 'sha256:'"))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_digest(
                "a digest must carry 64 hexadecimal characters",
            ));
        }
        Ok(Self(format!("sha256:{}", hex.to_ascii_lowercase())))
    }

    /// Full `sha256:<hex>` form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Bare hexadecimal part.
    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }
}

fn invalid_digest(detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: "digest".to_owned(),
        detail: detail.to_owned(),
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

macro_rules! digest_role {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Digest that identifies ", $label, ".")]
        ///
        /// A distinct type keeps a plan digest, an approved plan revision's
        /// pack fingerprint, and a request fingerprint from being compared by
        /// accident.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Computes the digest of exact bytes.
            pub fn sha256(bytes: &[u8]) -> Self {
                Self(Sha256Digest::sha256(bytes))
            }

            /// Parses a `sha256:<64 hex>` value.
            pub fn parse(value: impl AsRef<str>) -> Result<Self, SddExecutionError> {
                Sha256Digest::parse(value).map(Self)
            }

            /// Full `sha256:<hex>` form.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0.as_str())
            }
        }
    };
}

digest_role!(PlanDigest, "the exact plan bytes");
digest_role!(PackFingerprint, "the pack execution contract");
digest_role!(RequestFingerprint, "one update request's content");
