//! Shared durable-store handles used by the H2 supervision composition.
//!
//! The handle wraps the single `Store` owned by `DesktopHost`. Clones share the
//! same SQLite connection and therefore the same supervision records, evidence,
//! budget rows, command journal, and recovery facts. No second store or ledger
//! is opened.

use std::sync::{Arc, Mutex};

use herness_core::contracts::{ModelRequestObservation, ProjectId, RequestGateIntent, Timestamp};
use herness_core::{
    Checkpoint, CheckpointCommit, CoreError, EventDraft, HistoryPage, HistoryQuery, OperationId,
    OperationIntent, OperationRecord, OperationResult, RunId, StorePort,
};
use herness_store::Store;
use herness_supervision::budget::ledger::{BudgetClockPort, ClockReading};
use herness_supervision::ports::{
    BudgetStorePort, ClockPort, EvidenceStorePort, StoredBudgetRecord, SupervisionStorePort,
};
use herness_supervision::recovery::{RecoveryFactsPort, RecoverySnapshot};
use herness_supervision::{
    CommandResult, EvidenceId, EvidenceRecord, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId,
};

/// Cloneable handle to the one process-wide supervision store.
#[derive(Clone)]
pub struct StoreHandle(Arc<Mutex<Store>>);

impl StoreHandle {
    /// Creates a handle over an existing store.
    pub const fn new(store: Arc<Mutex<Store>>) -> Self {
        Self(store)
    }

    /// Access the underlying handle for host-only store operations.
    pub const fn shared(&self) -> &Arc<Mutex<Store>> {
        &self.0
    }

    /// Locks the store, recovering a poisoned guard.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StorePort for StoreHandle {
    fn commit_checkpoint(
        &mut self,
        commit: CheckpointCommit,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        self.lock().commit(commit).map_err(Into::into)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        <Store as StorePort>::load_checkpoint(&self.lock(), run)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        <Store as StorePort>::history(&self.lock(), query)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        <Store as StorePort>::pending_operations(&self.lock(), project)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        <Store as StorePort>::operation(&self.lock(), operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_operation_result(&mut self.lock(), operation, result)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        <Store as StorePort>::record_operation_result_with_events(
            &mut self.lock(),
            operation,
            result,
            events,
        )
    }

    fn record_model_request(
        &mut self,
        intent: RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_model_request(&mut self.lock(), intent, recorded_at)
    }

    fn record_model_request_observation(
        &mut self,
        observation: ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_model_request_observation(
            &mut self.lock(),
            observation,
            observed_at,
        )
    }
}

impl EvidenceStorePort for StoreHandle {
    fn append(&mut self, evidence: EvidenceRecord) -> Result<EvidenceRecord, SupervisionError> {
        self.lock().append_evidence(&evidence).map_err(Into::into)
    }

    fn get(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceRecord>, SupervisionError> {
        self.lock()
            .evidence_record(project_id, evidence_id)
            .map_err(Into::into)
    }

    fn list_for_supervision(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Vec<EvidenceRecord>, SupervisionError> {
        self.lock()
            .evidence_for_supervision(project_id, supervision_id)
            .map_err(Into::into)
    }
}

impl SupervisionStorePort for StoreHandle {
    fn load(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<SupervisionRecord>, SupervisionError> {
        self.lock()
            .load_supervision_record(project_id, supervision_id)
            .map_err(Into::into)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
    ) -> Result<u64, SupervisionError> {
        self.lock()
            .compare_and_swap_supervision(project_id, supervision_id, expected_revision, next)
            .map_err(Into::into)
    }

    fn command_result(
        &self,
        request_id: SupervisionRequestId,
    ) -> Result<Option<CommandResult>, SupervisionError> {
        self.lock()
            .supervision_command_result(request_id)
            .map_err(Into::into)
    }

    fn record_command_result(
        &mut self,
        result: &CommandResult,
    ) -> Result<CommandResult, SupervisionError> {
        self.lock()
            .record_supervision_command_result(result)
            .map_err(Into::into)
    }

    fn commit_command(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
        result: &CommandResult,
    ) -> Result<u64, SupervisionError> {
        self.lock()
            .commit_supervision_command(project_id, supervision_id, expected_revision, next, result)
            .map_err(Into::into)
    }
}

impl RecoveryFactsPort for StoreHandle {
    fn recovery_snapshot(
        &self,
        project_id: ProjectId,
    ) -> Result<RecoverySnapshot, SupervisionError> {
        self.lock()
            .recovery_snapshot(&project_id)
            .map(|snapshot| snapshot.into_recovery_snapshot())
            .map_err(Into::into)
    }
}

impl BudgetStorePort for StoreHandle {
    fn load_budget(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError> {
        self.lock()
            .load_budget_record(project_id, supervision_id)
            .map_err(Into::into)
    }

    fn compare_and_swap_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
    ) -> Result<u64, SupervisionError> {
        self.lock()
            .compare_and_swap_budget(project_id, supervision_id, expected_revision, next)
    }

    fn commit_budget_admission(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
        intent: &RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        self.lock()
            .commit_budget_admission(
                project_id,
                supervision_id,
                expected_revision,
                next,
                intent,
                recorded_at,
            )
            .map_err(Into::into)
    }

    fn commit_budget_observation(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
        observation: &ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        self.lock()
            .commit_budget_observation(
                project_id,
                supervision_id,
                expected_revision,
                next,
                observation,
                observed_at,
            )
            .map_err(Into::into)
    }
}

/// Production wall+monotonic clock for the durable budget ledger.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostBudgetClock {
    origin: Option<std::time::Instant>,
}

impl HostBudgetClock {
    /// Creates a clock whose monotonic origin is this process's start.
    pub fn new() -> Self {
        Self {
            origin: Some(std::time::Instant::now()),
        }
    }
}

impl BudgetClockPort for HostBudgetClock {
    fn read(&self) -> ClockReading {
        let monotonic = self
            .origin
            .map_or(0, |origin| origin.elapsed().as_millis() as u64);
        ClockReading::new(Timestamp::now(), monotonic)
    }
}

/// Wall-clock port used by the supervisor and recovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostClock;

impl ClockPort for HostClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Reads the latest H1 run state through the runtime boundary.
pub fn project_runs(store: &StoreHandle, project: ProjectId) -> Vec<herness_core::RunId> {
    let records = store
        .lock()
        .supervision_records_for_project(&project)
        .unwrap_or_default();
    records
        .into_iter()
        .flat_map(|record| record.run_group().runs().to_vec())
        .collect()
}
