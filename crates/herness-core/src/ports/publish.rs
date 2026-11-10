//! Host-only publication ports.
//!
//! These ports are composed by the trusted host. They are not reachable from a
//! model tool, a tool argument payload, or an IPC command. H3 owns the job,
//! approval, receipt, and multi-file journal; these ports only provide the H1
//! reflection primitive's old-version archive, host permission re-check, and
//! durable per-request record.

use crate::contracts::errors::PublicationFailure;
use crate::contracts::events::EventDraft;
use crate::contracts::publication::{
    ArchivedVersion, OldVersionArchive, PublicationRecord, PublicationRequest,
};
use crate::ports::runtime_store::RuntimeStore;
use crate::ports::store::CommitReceipt;

/// Saves the exact old formal version into the host's private app area.
///
/// The implementation must write the exact bytes durably before returning
/// success. Returning an error means the caller must not replace the target.
/// A reference returned here is opaque and must not contain secrets or a
/// project path.
pub trait PublicationArchivePort {
    /// Saves one exact old version.
    fn save_old_version(
        &mut self,
        archive: &OldVersionArchive<'_>,
    ) -> Result<ArchivedVersion, PublicationFailure>;
}

/// Re-checks host permission immediately before a publication side effect.
///
/// This is the host's grant/authorization check, not an H3 approval or receipt
/// decision. H3 owns those. A host without a usable check returns an error and
/// no write occurs.
pub trait PublicationGatePort {
    /// Returns `Ok(())` only when this exact request is authorized now.
    fn authorize_publication(&self, request: &PublicationRequest)
    -> Result<(), PublicationFailure>;
}

/// Loads and persists one publication request record.
///
/// `key` is an opaque host-state key derived from the request id. Saving a
/// record and its audit events is one atomic host-state transaction. Loading a
/// missing record returns `Ok(None)`; an unreadable or unknown-format record is
/// an error, never an empty result.
pub trait PublicationRecordPort {
    /// Loads the durable record for `key`.
    fn load_publication(&self, key: &str) -> Result<Option<PublicationRecord>, PublicationFailure>;

    /// Persists the record and appends its audit events atomically.
    fn save_publication(
        &mut self,
        key: &str,
        record: &PublicationRecord,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, PublicationFailure>;
}

/// Publication records persisted in the private host-state table.
///
/// H1 does not interpret H3 job state or receipts. This type only stores the
/// opaque publication record and its host-activity audit events.
#[derive(Debug)]
pub struct StorePublicationRecords<S> {
    store: S,
}

impl<S> StorePublicationRecords<S> {
    /// Wraps a runtime store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrows the underlying store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Mutably borrows the underlying store.
    pub const fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Returns the underlying store.
    pub fn into_inner(self) -> S {
        self.store
    }
}

impl<S: RuntimeStore> PublicationRecordPort for StorePublicationRecords<S> {
    fn load_publication(&self, key: &str) -> Result<Option<PublicationRecord>, PublicationFailure> {
        let bytes = self.store.load_host_state(key).map_err(|error| {
            PublicationFailure::RecordUnavailable {
                detail: error.to_string(),
            }
        })?;
        match bytes {
            Some(bytes) => PublicationRecord::from_bytes(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn save_publication(
        &mut self,
        key: &str,
        record: &PublicationRecord,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, PublicationFailure> {
        let bytes = record.to_bytes()?;
        self.store
            .save_host_state_and_events(key, &bytes, events)
            .map_err(|error| PublicationFailure::RecordUnavailable {
                detail: error.to_string(),
            })
    }
}
