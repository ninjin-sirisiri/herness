//! Host-owned SQLite store for checkpoint, audit, operation, and history data.
//!
//! The store depends on `herness-core` for public contract values; core never
//! depends on the store. Checkpoint bodies stay opaque. The database lives in
//! an explicit private application-data root, never inside a project.
//!
//! Recovery APIs are read-only: loading a checkpoint or listing unresolved
//! operations never re-executes anything.

mod config;
mod error;
mod fault;
mod migrations;
mod store;

#[cfg(feature = "test-support")]
pub mod test_support;

pub use config::{DATABASE_FILE_NAME, StoreConfig};
pub use error::{ConfigViolation, StoreError};
pub use herness_core::{
    FileObservation, OperationEvidence, OperationOutcome, OperationRecord, OperationResult,
};
pub use store::{CheckpointRecord, Store};
