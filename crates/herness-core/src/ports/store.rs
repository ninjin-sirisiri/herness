//! Transactional store port.
//!
//! The store persists a checkpoint and its related audit events/operation intent
//! atomically. Checkpoint bodies remain versioned opaque data; the store must
//! not interpret SDK internals.

use crate::contracts::checkpoint::Checkpoint;
use crate::contracts::errors::CoreError;
use crate::contracts::events::{Event, EventDraft};
use crate::contracts::history::{HistoryPage, HistoryQuery};
use crate::contracts::ids::{ProjectId, RunId};
use crate::contracts::operation::OperationIntent;

/// One atomic checkpoint commit.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointCommit {
    checkpoint: Checkpoint,
    operation: Option<OperationIntent>,
    events: Vec<EventDraft>,
}

impl CheckpointCommit {
    /// Creates a commit whose operation and events all belong to the checkpoint
    /// run.
    pub fn new(
        checkpoint: Checkpoint,
        operation: Option<OperationIntent>,
        events: Vec<EventDraft>,
    ) -> Result<Self, CoreError> {
        let expected = checkpoint.run_id();
        if let Some(operation) = &operation {
            let found = operation.operation().run_id();
            if found != expected {
                return Err(CoreError::MismatchedRun { expected, found });
            }
        }
        for event in &events {
            let found = event.run_id();
            if found != expected {
                return Err(CoreError::MismatchedRun { expected, found });
            }
        }

        Ok(Self {
            checkpoint,
            operation,
            events,
        })
    }

    /// Checkpoint to persist.
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Optional operation intent persisted in the same transaction.
    pub const fn operation(&self) -> Option<&OperationIntent> {
        self.operation.as_ref()
    }

    /// Events persisted in the same transaction.
    pub fn events(&self) -> &[EventDraft] {
        &self.events
    }
}

/// Result of a committed checkpoint transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitReceipt {
    events: Vec<Event>,
    max_sequence: u64,
}

impl CommitReceipt {
    /// Creates a receipt for committed events.
    pub const fn new(events: Vec<Event>, max_sequence: u64) -> Self {
        Self {
            events,
            max_sequence,
        }
    }

    /// Committed events carrying store-assigned sequences.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Highest sequence committed in the transaction.
    pub const fn max_sequence(&self) -> u64 {
        self.max_sequence
    }
}

/// Port implemented by the SQLite-backed transactional store.
pub trait StorePort {
    /// Atomically commits a checkpoint, optional operation intent, and events.
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError>;

    /// Loads the latest checkpoint for a run. Unknown versions are errors, not
    /// discarded data.
    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError>;

    /// Returns one project's history page in descending sequence order.
    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError>;

    /// Returns operation intents that have no durable result yet.
    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError>;
}
