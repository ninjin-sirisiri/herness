//! Test-only fault injection points.
//!
//! The plan is stored inside [`Store`](crate::Store) but only test-support
//! builds can set it. Production code paths never create a non-empty plan.

/// Commit failure point used by store tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitPoint {
    /// Fail after opening the write transaction but before writing rows.
    BeforeRows,
    /// Fail after writing rows but before `COMMIT`.
    BeforeCommit,
}

impl CommitPoint {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeRows => "commit-before-rows",
            Self::BeforeCommit => "commit-before-commit",
        }
    }
}

/// Migration failure point used by store tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MigrationPoint {
    pub(crate) version: u32,
    pub(crate) after_statements: usize,
}

/// Fault plan attached to an open store.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FaultPlan {
    pub(crate) commit: Option<CommitPoint>,
}
