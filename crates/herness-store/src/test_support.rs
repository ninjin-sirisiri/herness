//! Test-only helpers for fault injection and schema-version setup.
//!
//! This module is compiled only with the `test-support` feature. Production
//! hosts must never enable that feature.

use crate::config::StoreConfig;
use crate::error::StoreError;
use crate::fault::{CommitPoint, MigrationPoint, ResultPoint};
use crate::store::Store;

/// Commit failure point for a store test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFault {
    /// Fail after opening the write transaction but before writing rows.
    BeforeRows,
    /// Fail after writing rows but before `COMMIT`.
    BeforeCommit,
}

impl From<CommitFault> for CommitPoint {
    fn from(value: CommitFault) -> Self {
        match value {
            CommitFault::BeforeRows => Self::BeforeRows,
            CommitFault::BeforeCommit => Self::BeforeCommit,
        }
    }
}

/// Operation-result recording failure point for a store test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFault {
    /// Fail after opening the write transaction but before updating the result.
    BeforeUpdate,
}

impl From<ResultFault> for ResultPoint {
    fn from(value: ResultFault) -> Self {
        match value {
            ResultFault::BeforeUpdate => Self::BeforeUpdate,
        }
    }
}

/// Migration failure point for a store test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationFault {
    /// Fail after applying the given number of statements of a migration.
    AfterStatements {
        /// Migration version to interrupt.
        version: u32,
        /// Number of statements to apply before failing.
        statements: usize,
    },
}

/// Opens a store migrated only to `version`.
///
/// Used to build a pre-existing database at an older schema version before
/// testing a failing migration.
pub fn open_at_schema_version(config: StoreConfig, version: u32) -> Result<Store, StoreError> {
    Store::open_at_version(config, version, None)
}

/// Opens a store while injecting a migration failure.
pub fn open_with_migration_fault(
    config: StoreConfig,
    fault: MigrationFault,
) -> Result<Store, StoreError> {
    let point = match fault {
        MigrationFault::AfterStatements {
            version,
            statements,
        } => MigrationPoint {
            version,
            after_statements: statements,
        },
    };
    Store::open_at_version(
        config,
        crate::migrations::latest_schema_version(),
        Some(point),
    )
}
