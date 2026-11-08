//! Version marker for the public supervision contract.
//!
//! The supervision contract is part of the same public contract family as H1
//! events. New supervision records written by this build carry version 2;
//! version 1 supervision records do not exist and are not guessed at.

use herness_core::contracts::ContractVersion;

use crate::error::SupervisionError;

/// Version written for new supervision contract, record, consent, and profile
/// values.
pub const SUPERVISION_CONTRACT_VERSION: u32 = 2;

/// The only supervision contract version written by this build.
pub const fn current_contract_version() -> ContractVersion {
    ContractVersion::V2
}

/// Rejects any supervision value that is not the current contract version.
pub fn ensure_current_version(version: ContractVersion) -> Result<(), SupervisionError> {
    if version == ContractVersion::V2 {
        Ok(())
    } else {
        Err(SupervisionError::UnsupportedContractVersion {
            found: version.get(),
            expected: SUPERVISION_CONTRACT_VERSION,
        })
    }
}
