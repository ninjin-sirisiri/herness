//! macOS Keychain adapter for the herness credential vault.
//!
//! The adapter maps every operating-system result to a structured
//! [`herness_core::VaultFailure`]. There is deliberately no plaintext-file
//! fallback: if the Keychain denies, locks, or fails an update, the credential
//! save or read fails and the caller must show an error.
//!
//! Real Keychain access is not exercised by normal tests. The test suite uses
//! [`KeychainBackend`] fakes; Task 13 performs the allowed real-Keychain
//! verification with separately approved items.

mod keychain;

pub use keychain::{KeychainBackend, KeychainError, MacKeychainVault, SystemKeychain};
