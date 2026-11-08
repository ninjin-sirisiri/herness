//! Store operations owned by the host runtime rather than a tool or engine.
//!
//! The runtime needs three things beyond [`StorePort`]: ascending committed
//! event replay for UI subscriptions, unresolved-operation reads for restart
//! reconciliation, and a private, non-secret host-state row for run/agent/
//! approval metadata. Host state is versioned JSON and never contains
//! credentials, checkpoints, or provider output.
//!
//! These methods are deliberately a separate trait so engine/test implementations
//! of [`StorePort`] do not have to grow runtime-only behavior.

use crate::contracts::errors::CoreError;
use crate::contracts::events::{Event, EventDraft};
use crate::contracts::history::HistoryLimit;
use crate::contracts::ids::{OperationId, ProjectId};
use crate::contracts::operation::{OperationRecord, OperationResult};
use crate::ports::store::{CheckpointCommit, CommitReceipt, StorePort};

/// Store capability required by the host runtime.
pub trait RuntimeStore: StorePort {
    /// Reads committed events in ascending sequence order after a cursor.
    ///
    /// Only committed rows are visible. Redelivering an event is never an
    /// instruction to execute the operation it refers to.
    fn events_after(
        &self,
        project: &ProjectId,
        after_sequence: Option<u64>,
        limit: HistoryLimit,
    ) -> Result<Vec<Event>, CoreError>;

    /// Returns pending or unverifiable operations for restart reconciliation.
    ///
    /// This is a read-only recovery query; it never re-executes an operation.
    fn unresolved_operations(&self, project: &ProjectId)
    -> Result<Vec<OperationRecord>, CoreError>;

    /// Loads one private host-state value.
    fn load_host_state(&self, key: &str) -> Result<Option<Vec<u8>>, CoreError>;

    /// Persists one private host-state value.
    fn save_host_state(&mut self, key: &str, value: &[u8]) -> Result<(), CoreError>;

    /// Persists host state and appends audit events in one transaction.
    fn save_host_state_and_events(
        &mut self,
        key: &str,
        value: &[u8],
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError>;

    /// Persists host state and a checkpoint commit in one transaction.
    fn save_host_state_and_checkpoint(
        &mut self,
        key: &str,
        value: &[u8],
        commit: CheckpointCommit,
    ) -> Result<CommitReceipt, CoreError>;

    /// Records an operation result, events, and host state in one transaction.
    fn record_operation_result_with_state(
        &mut self,
        key: &str,
        value: &[u8],
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError>;
}
