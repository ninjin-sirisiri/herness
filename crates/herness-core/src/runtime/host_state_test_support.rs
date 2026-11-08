//! Test-only host-state compatibility helpers.
//!
//! The runtime reads host state through `HostState::from_bytes` and writes it
//! through `HostState::to_bytes`. Integration tests use this module to exercise
//! the same compatibility path without exposing the private document types as
//! production API.

use super::state::HostState;

/// Reads a stored host-state document and re-serializes it in the current
/// write format.
///
/// Returns the same sanitized message the runtime uses for corrupt documents.
pub fn migrate(bytes: &[u8]) -> Result<Vec<u8>, String> {
    HostState::from_bytes(bytes)
        .and_then(|state| state.to_bytes())
        .map_err(|error| error.to_string())
}
