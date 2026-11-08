//! SQLite-backed checkpoint, audit, operation, and history store.
//!
//! `Store` is a single-threaded host-owned connection. `StorePort` commits a
//! checkpoint, an optional operation intent, and audit events in one immediate
//! transaction; committed rows are the only rows any reader can observe.
//! Readers use separate connections when the host needs to re-open the
//! database.
//!
//! Restoring state is read-only. Nothing in this crate starts tool execution.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use herness_core::{
    AbsolutePath, AttemptId, Checkpoint, CheckpointCommit, CheckpointFormatVersion,
    CheckpointPayload, CommitReceipt, ConnectionId, ContractVersion, CoreError, Event, EventDraft,
    EventKind, EventPayload, EventSubject, FrozenOperation, HistoryCursor, HistoryLimit,
    HistoryPage, HistoryQuery, HostActivitySubject, ModelRequestObservation, OperationEvidence,
    OperationId, OperationIntent, OperationOutcome, OperationRecord, OperationResult,
    PermissionMode, PolicyVersion, ProjectId, RequestGateIntent, RequestId, RequestOutcome,
    RequestPurpose, RunId, RunSubject, RuntimeStore, StopDeadlineControl, StorePort, Timestamp,
    ToolArguments, ToolName,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::config::StoreConfig;
use crate::error::StoreError;
use crate::fault::{CommitPoint, FaultPlan, ResultPoint};
use crate::migrations;

const EVENT_COLUMNS: &str = "contract_version, subject_type, agent_id, session_id, run_id, \
                              activity_kind, activity_id, operation_id, sequence, kind, \
                              occurred_at, payload";

const OPERATION_COLUMNS: &str = "operation_id, project_id, run_id, tool, arguments, cwd, \
                                 policy_version, permission_mode, recorded_at, outcome, evidence, \
                                 resolved_at";

const REQUEST_COLUMNS: &str = "attempt_id, request_id, project_id, subject_type, agent_id, \
                               session_id, run_id, activity_kind, activity_id, connection_id, \
                               purpose, control, recorded_at, observation, observed_at";

/// A loaded checkpoint plus the project sequence observed at commit time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    checkpoint: Checkpoint,
    last_sequence: u64,
}

impl CheckpointRecord {
    /// The versioned opaque checkpoint.
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Highest project sequence committed in the checkpoint transaction.
    ///
    /// This is `0` when the checkpoint commit carried no events and the project
    /// had no earlier events.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Consumes the record and returns the checkpoint.
    pub fn into_checkpoint(self) -> Checkpoint {
        self.checkpoint
    }
}

/// A persisted model-request intent with its optional observation.
///
/// The intent row is durable before a request may be sent. A repeated identical
/// record returns this value again instead of inserting or sending twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRequestRecord {
    intent: RequestGateIntent,
    recorded_at: Timestamp,
    observation: Option<ModelRequestObservation>,
    observed_at: Option<Timestamp>,
}

impl ModelRequestRecord {
    /// Recorded request intent.
    pub const fn intent(&self) -> &RequestGateIntent {
        &self.intent
    }

    /// When the intent was first persisted.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// Send-started or terminal observation, when one exists.
    pub const fn observation(&self) -> Option<&ModelRequestObservation> {
        self.observation.as_ref()
    }

    /// When the current observation was first persisted.
    pub const fn observed_at(&self) -> Option<Timestamp> {
        self.observed_at
    }
}

/// One generic revision-checked state value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedStateRecord {
    revision: u64,
    value: Vec<u8>,
}

impl SupervisedStateRecord {
    /// Revision the value was committed at. Revisions start at one.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Opaque state bytes owned by the caller.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Host-owned SQLite store.
pub struct Store {
    conn: Connection,
    config: StoreConfig,
    fault: FaultPlan,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("database_path", &self.config.database_path())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens (or creates and migrates) the database under the configured
    /// application-data root.
    ///
    /// A database whose schema is newer than this build is rejected before any
    /// write. A failing migration rolls back completely.
    pub fn open(config: StoreConfig) -> Result<Self, StoreError> {
        Self::open_at_version(config, migrations::latest_schema_version(), None)
    }

    pub(crate) fn open_at_version(
        config: StoreConfig,
        target_version: u32,
        migration_fault: Option<crate::fault::MigrationPoint>,
    ) -> Result<Self, StoreError> {
        prepare_location(&config)?;
        let database_path = config.database_path();
        let mut conn = Connection::open(&database_path).map_err(StoreError::database)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(StoreError::database)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(StoreError::database)?;

        migrations::apply(&mut conn, target_version, migration_fault)?;

        // Only after a successfully migrated (or already current) database do
        // we switch journal modes. An unknown newer database therefore stays
        // byte-for-byte untouched.
        conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(StoreError::database)?;
        conn.execute_batch("PRAGMA synchronous = FULL;")
            .map_err(StoreError::database)?;

        Ok(Self {
            conn,
            config,
            fault: FaultPlan::default(),
        })
    }

    /// Schema version currently stored in the database.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        migrations::read_schema_version(&self.conn)?.ok_or_else(|| {
            StoreError::corrupt("schema_version table is missing from an open store")
        })
    }

    /// Commits a checkpoint, optional operation intent, and events atomically.
    ///
    /// This is the inherent form of [`StorePort::commit_checkpoint`] with the
    /// full store error detail.
    pub fn commit(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, StoreError> {
        self.commit_with_state(None, commit)
    }

    fn commit_with_state(
        &mut self,
        state: Option<(&str, &[u8])>,
        commit: CheckpointCommit,
    ) -> Result<CommitReceipt, StoreError> {
        let checkpoint = commit.checkpoint();
        let run = checkpoint.run_id();
        let project = run.project_id();
        let format_version = checkpoint.format_version();
        if !self.config.accepts_checkpoint_format(format_version) {
            return Err(StoreError::UnsupportedCheckpointFormat {
                found: format_version.get(),
            });
        }

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }

        if let Some(operation) = commit.operation() {
            let operation_id = operation.operation().operation_id();
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id = ?1)",
                [operation_id.to_string()],
                |row| row.get(0),
            )?;
            if exists {
                return Err(StoreError::DuplicateOperation {
                    operation: operation_id,
                });
            }
        }

        let (events, next_sequence) = append_event_drafts(&transaction, &project, commit.events())?;

        let max_sequence = events.last().map_or(0, Event::sequence);
        let last_sequence = if events.is_empty() {
            next_sequence.saturating_sub(1)
        } else {
            max_sequence
        };

        transaction.execute(
            "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(run_id) DO UPDATE SET
                 project_id = excluded.project_id,
                 format_version = excluded.format_version,
                 payload = excluded.payload,
                 last_sequence = excluded.last_sequence",
            params![
                run.to_string(),
                project.to_string(),
                i64::from(format_version.get()),
                checkpoint.payload().as_bytes(),
                sequence_to_sql(last_sequence)?,
            ],
        )?;

        if let Some(intent) = commit.operation() {
            insert_operation(&transaction, intent)?;
        }

        if let Some((key, value)) = state {
            write_host_state(&transaction, key, value)?;
        }

        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }

        transaction.commit().map_err(StoreError::database)?;
        Ok(CommitReceipt::new(events, max_sequence))
    }

    /// Loads the latest checkpoint for a run, including the sequence observed at
    /// checkpoint commit.
    pub fn load_checkpoint_record(
        &self,
        run: &RunId,
    ) -> Result<Option<CheckpointRecord>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT project_id, format_version, payload, last_sequence
                 FROM checkpoints WHERE run_id = ?1",
                [run.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((project_text, format_version, payload, last_sequence)) = row else {
            return Ok(None);
        };

        let project: ProjectId = parse_core(&project_text, "checkpoint project id")?;
        if project != run.project_id() {
            return Err(StoreError::corrupt(
                "checkpoint project does not match its run id",
            ));
        }

        let found = u32::try_from(format_version)
            .map_err(|_| StoreError::corrupt("checkpoint format version is out of range"))?;
        let version = CheckpointFormatVersion::new(found)
            .map_err(|_| StoreError::UnsupportedCheckpointFormat { found })?;
        if !self.config.accepts_checkpoint_format(version) {
            return Err(StoreError::UnsupportedCheckpointFormat { found });
        }

        let last_sequence = u64::try_from(last_sequence)
            .map_err(|_| StoreError::corrupt("checkpoint sequence is negative"))?;

        Ok(Some(CheckpointRecord {
            checkpoint: Checkpoint::new(*run, version, CheckpointPayload::new(payload)),
            last_sequence,
        }))
    }

    /// Reads one operation record, including evidence when a result exists.
    pub fn operation(
        &self,
        operation: &OperationId,
    ) -> Result<Option<OperationRecord>, StoreError> {
        load_operation_record(&self.conn, &operation.to_string())
    }

    /// Records the durable result of an operation.
    ///
    /// Re-recording the same result is idempotent. A different result for the
    /// same operation is rejected. The store never executes anything here.
    pub fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<OperationRecord, StoreError> {
        self.record_result(operation, result, Vec::new(), None)
            .map(|(record, _)| record)
    }

    /// Records the durable result and appends events in one transaction.
    ///
    /// This is how a file tool persists "the result happened and here is its
    /// notification" without a window where one exists without the other.
    /// Re-recording an identical result appends no events and returns an empty
    /// receipt. A different result conflicts.
    pub fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, StoreError> {
        self.record_result(operation, result, events, None)
            .map(|(_, receipt)| receipt)
    }

    /// Records an operation result, its events, and private host state in one
    /// transaction.
    pub fn record_operation_result_with_state(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
        state_key: &str,
        state_value: &[u8],
    ) -> Result<CommitReceipt, StoreError> {
        self.record_result(operation, result, events, Some((state_key, state_value)))
            .map(|(_, receipt)| receipt)
    }

    fn record_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
        state: Option<(&str, &[u8])>,
    ) -> Result<(OperationRecord, CommitReceipt), StoreError> {
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if self.fault.result == Some(ResultPoint::BeforeUpdate) {
            return Err(StoreError::InjectedFault {
                point: ResultPoint::BeforeUpdate.as_str(),
            });
        }

        let Some(record) = load_operation_record(&transaction, &operation.to_string())? else {
            return Err(StoreError::UnknownOperation {
                operation: *operation,
            });
        };

        let intent = record.intent().operation();
        for event in &events {
            if event.project_id() != intent.project_id() {
                return Err(StoreError::CrossProjectReference {
                    expected: intent.project_id(),
                    found: event.project_id(),
                });
            }
            let Some(event_run) = event.run_id() else {
                return Err(StoreError::UnsupportedHostActivityEvent);
            };
            if event_run != intent.run_id() {
                return Err(StoreError::corrupt(
                    "operation result event belongs to another run",
                ));
            }
            if event.operation_id().is_some_and(|id| id != *operation) {
                return Err(StoreError::corrupt(
                    "operation result event belongs to another operation",
                ));
            }
        }

        if let Some(existing) = record.result() {
            if existing == &result {
                return Ok((record, CommitReceipt::new(Vec::new(), 0)));
            }
            return Err(StoreError::OperationResultConflict {
                operation: *operation,
            });
        }

        let changed = transaction.execute(
            "UPDATE operations SET outcome = ?2, evidence = ?3, resolved_at = ?4
             WHERE operation_id = ?1 AND outcome IS NULL",
            params![
                operation.to_string(),
                result.outcome().as_str(),
                serde_json::to_string(result.evidence()).map_err(StoreError::codec)?,
                i64::try_from(result.recorded_at().as_unix_millis())
                    .map_err(|_| StoreError::corrupt("result timestamp does not fit in sqlite"))?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::OperationResultConflict {
                operation: *operation,
            });
        }

        let (events, _) = append_event_drafts(&transaction, &intent.project_id(), &events)?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        if let Some((key, value)) = state {
            write_host_state(&transaction, key, value)?;
        }
        transaction.commit().map_err(StoreError::database)?;
        let record = OperationRecord::new(record.intent().clone(), Some(result));
        Ok((record, CommitReceipt::new(events, max_sequence)))
    }

    /// Returns operations whose outcome is still pending or unverifiable.
    ///
    /// This is a read-only recovery query. The returned evidence supports
    /// deciding between applied, not applied, and needing reconciliation; the
    /// store never resumes or replays an operation.
    pub fn unresolved_operations(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        let sql = format!(
            "SELECT {OPERATION_COLUMNS} FROM operations
             WHERE project_id = ?1 AND (outcome IS NULL OR outcome = 'unverifiable')
             ORDER BY recorded_at ASC, operation_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query([project.to_string()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let record = operation_record_from_row(row)?;
            if record.is_unresolved() {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Reads committed events in ascending sequence order after `after_sequence`.
    ///
    /// This is a read-only live/re-subscription replay. Redelivering an event
    /// is never an instruction to re-execute the operation it refers to, and
    /// this method has no execution path. Only committed rows are visible.
    pub fn events_after(
        &self,
        project: &ProjectId,
        after_sequence: Option<u64>,
        limit: HistoryLimit,
    ) -> Result<Vec<Event>, StoreError> {
        if after_sequence == Some(0) {
            return Err(StoreError::InvalidLiveCursor);
        }
        let after = after_sequence.map(sequence_to_sql).transpose()?;
        let limit = i64::from(limit.get());

        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM events
             WHERE project_id = ?1 AND (?2 IS NULL OR sequence > ?2)
             ORDER BY sequence ASC LIMIT ?3"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query(params![project.to_string(), after, limit])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(event_from_row(row, *project)?);
        }
        Ok(events)
    }

    /// Loads one private host-state value. Values are opaque to the store.
    pub fn load_host_state(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .query_row(
                "SELECT value FROM host_state WHERE key = ?1",
                [key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(StoreError::database)
    }

    /// Persists one private host-state value.
    pub fn save_host_state(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        write_host_state(&transaction, key, value)?;
        transaction.commit().map_err(StoreError::database)
    }

    /// Persists host state and appends committed events atomically.
    ///
    /// All events must belong to one project; an empty list persists only the
    /// state value.
    pub fn save_host_state_and_events(
        &mut self,
        key: &str,
        value: &[u8],
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, StoreError> {
        let project = events.first().map(EventDraft::project_id);
        if events
            .iter()
            .any(|event| Some(event.project_id()) != project)
        {
            return Err(StoreError::corrupt(
                "host-state events must belong to one project",
            ));
        }

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        write_host_state(&transaction, key, value)?;
        let (events, _) = match project {
            Some(project) => append_event_drafts(&transaction, &project, &events)?,
            None => (Vec::new(), 0),
        };
        let max_sequence = events.last().map_or(0, Event::sequence);
        transaction.commit().map_err(StoreError::database)?;
        Ok(CommitReceipt::new(events, max_sequence))
    }

    /// Persists host state and a checkpoint commit atomically.
    pub fn save_host_state_and_checkpoint(
        &mut self,
        key: &str,
        value: &[u8],
        commit: CheckpointCommit,
    ) -> Result<CommitReceipt, StoreError> {
        self.commit_with_state(Some((key, value)), commit)
    }

    /// Appends events without a checkpoint or host-state write.
    ///
    /// Run and host-activity events share one project sequence. An empty list is
    /// a no-op. The returned receipt contains only committed rows.
    pub fn append_events(&mut self, events: Vec<EventDraft>) -> Result<CommitReceipt, StoreError> {
        let Some(project) = events.first().map(EventDraft::project_id) else {
            return Ok(CommitReceipt::new(Vec::new(), 0));
        };
        ensure_same_project(&events, project)?;

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (events, _) = append_event_drafts(&transaction, &project, &events)?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        transaction.commit().map_err(StoreError::database)?;
        Ok(CommitReceipt::new(events, max_sequence))
    }

    /// Loads one persisted model-request attempt.
    pub fn model_request(
        &self,
        attempt: &AttemptId,
    ) -> Result<Option<ModelRequestRecord>, StoreError> {
        load_model_request_record(&self.conn, &attempt.to_string())
    }

    /// Loads every recorded attempt of one request in stable order.
    pub fn model_request_attempts(
        &self,
        request: &RequestId,
    ) -> Result<Vec<ModelRequestRecord>, StoreError> {
        let sql = format!(
            "SELECT {REQUEST_COLUMNS} FROM model_requests
             WHERE request_id = ?1
             ORDER BY recorded_at ASC, attempt_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query([request.to_string()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(model_request_record_from_row(row)?);
        }
        Ok(records)
    }

    /// Persists one request intent before any bytes may be sent.
    ///
    /// Repeating an identical attempt is idempotent and returns the stored
    /// record. A different intent for an existing attempt is rejected, so a
    /// duplicate request cannot cause a second send.
    pub fn record_model_request(
        &mut self,
        intent: RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<ModelRequestRecord, StoreError> {
        self.record_model_request_with_events(intent, recorded_at, Vec::new())
            .map(|(record, _)| record)
    }

    /// Persists a request intent and notification events in one transaction.
    pub fn record_model_request_with_events(
        &mut self,
        intent: RequestGateIntent,
        recorded_at: Timestamp,
        events: Vec<EventDraft>,
    ) -> Result<(ModelRequestRecord, CommitReceipt), StoreError> {
        let project = intent.subject().project_id();
        ensure_same_project(&events, project)?;

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempt = intent.attempt_id();
        if let Some(existing) = load_model_request_record(&transaction, &attempt.to_string())? {
            if existing.intent == intent {
                return Ok((existing, CommitReceipt::new(Vec::new(), 0)));
            }
            return Err(StoreError::RequestIntentConflict { attempt });
        }

        insert_model_request(&transaction, &intent, recorded_at)?;
        let (events, _) = append_event_drafts(&transaction, &project, &events)?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        transaction.commit().map_err(StoreError::database)?;

        Ok((
            ModelRequestRecord {
                intent,
                recorded_at,
                observation: None,
                observed_at: None,
            },
            CommitReceipt::new(events, max_sequence),
        ))
    }

    /// Records a send-started or terminal observation for a persisted intent.
    ///
    /// The intent must already exist. Repeating the identical observation is
    /// idempotent. A send-started observation may advance once to a terminal
    /// outcome; a terminal result is never overwritten.
    pub fn record_model_request_observation(
        &mut self,
        observation: ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<ModelRequestRecord, StoreError> {
        self.record_model_request_observation_with_events(observation, observed_at, Vec::new())
            .map(|(record, _)| record)
    }

    /// Records a request observation and notification events atomically.
    pub fn record_model_request_observation_with_events(
        &mut self,
        observation: ModelRequestObservation,
        observed_at: Timestamp,
        events: Vec<EventDraft>,
    ) -> Result<(ModelRequestRecord, CommitReceipt), StoreError> {
        let attempt = observation.attempt_id();
        let project = attempt.project_id();
        ensure_same_project(&events, project)?;

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(mut record) = load_model_request_record(&transaction, &attempt.to_string())?
        else {
            return Err(StoreError::UnknownRequestAttempt { attempt });
        };
        if observation.request_id() != record.intent.request_id() {
            return Err(StoreError::RequestObservationConflict { attempt });
        }
        if let Some(existing) = &record.observation {
            if existing == &observation {
                return Ok((record, CommitReceipt::new(Vec::new(), 0)));
            }
            let may_advance = existing.outcome() == RequestOutcome::SendStarted
                && matches!(
                    observation.outcome(),
                    RequestOutcome::Completed
                        | RequestOutcome::Cancelled
                        | RequestOutcome::SendResultUnknown
                );
            if !may_advance {
                return Err(StoreError::RequestObservationConflict { attempt });
            }
        }

        let changed = transaction.execute(
            "UPDATE model_requests SET observation = ?2, observed_at = ?3
             WHERE attempt_id = ?1",
            params![
                attempt.to_string(),
                serde_json::to_string(&observation).map_err(StoreError::codec)?,
                i64::try_from(observed_at.as_unix_millis()).map_err(|_| StoreError::corrupt(
                    "observation timestamp does not fit in sqlite"
                ))?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::RequestObservationConflict { attempt });
        }

        let (events, _) = append_event_drafts(&transaction, &project, &events)?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        transaction.commit().map_err(StoreError::database)?;

        record.observation = Some(observation);
        record.observed_at = Some(observed_at);
        Ok((record, CommitReceipt::new(events, max_sequence)))
    }

    /// Loads one generic supervised-state value.
    pub fn supervised_state(
        &self,
        project: &ProjectId,
        key: &str,
    ) -> Result<Option<SupervisedStateRecord>, StoreError> {
        validate_state_key(key)?;
        load_supervised_state(&self.conn, project, key)
    }

    /// Compares the stored revision and writes the new value atomically.
    ///
    /// `expected_revision` is `None` for creation and `Some(revision)` for an
    /// update. A missing or stale revision is rejected; the state and any
    /// events stay unchanged. Events share the project sequence and are only
    /// returned after the transaction commits.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_and_swap_supervised_state(
        &mut self,
        project: &ProjectId,
        key: &str,
        expected_revision: Option<u64>,
        value: &[u8],
        updated_at: Timestamp,
        events: Vec<EventDraft>,
    ) -> Result<(SupervisedStateRecord, CommitReceipt), StoreError> {
        validate_state_key(key)?;
        ensure_same_project(&events, *project)?;

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_supervised_state_revision(&transaction, project, key)?;

        let matches = match (expected_revision, current) {
            (None, None) => true,
            (Some(expected), Some(found)) => expected == found,
            _ => false,
        };
        if !matches {
            return Err(StoreError::StaleRevision {
                key: key.to_owned(),
                expected: expected_revision,
                found: current,
            });
        }

        let revision = current
            .map(|found| {
                found
                    .checked_add(1)
                    .ok_or_else(|| StoreError::corrupt("supervised state revision overflow"))
            })
            .transpose()?
            .unwrap_or(1);

        let changed = match current {
            None => transaction.execute(
                "INSERT INTO supervised_state (project_id, state_key, revision, payload, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    project.to_string(),
                    key,
                    sequence_to_sql(revision)?,
                    value,
                    i64::try_from(updated_at.as_unix_millis()).map_err(|_| {
                        StoreError::corrupt("supervised state timestamp does not fit in sqlite")
                    })?,
                ],
            )?,
            Some(expected) => transaction.execute(
                "UPDATE supervised_state
                 SET revision = ?3, payload = ?4, updated_at = ?5
                 WHERE project_id = ?1 AND state_key = ?2 AND revision = ?6",
                params![
                    project.to_string(),
                    key,
                    sequence_to_sql(revision)?,
                    value,
                    i64::try_from(updated_at.as_unix_millis()).map_err(|_| {
                        StoreError::corrupt("supervised state timestamp does not fit in sqlite")
                    })?,
                    sequence_to_sql(expected)?,
                ],
            )?,
        };
        if changed != 1 {
            return Err(StoreError::StaleRevision {
                key: key.to_owned(),
                expected: expected_revision,
                found: current,
            });
        }

        let (events, _) = append_event_drafts(&transaction, project, &events)?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        transaction.commit().map_err(StoreError::database)?;

        Ok((
            SupervisedStateRecord {
                revision,
                value: value.to_vec(),
            },
            CommitReceipt::new(events, max_sequence),
        ))
    }

    fn history_page(&self, query: HistoryQuery) -> Result<HistoryPage, StoreError> {
        if let Some(cursor) = query.cursor()
            && cursor.project_id() != query.project_id()
        {
            return Err(StoreError::CrossProjectReference {
                expected: query.project_id(),
                found: cursor.project_id(),
            });
        }

        let project = query.project_id();
        let before = query.before_sequence().map(sequence_to_sql).transpose()?;
        let fetch_limit = i64::from(query.limit().get()) + 1;

        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM events
             WHERE project_id = ?1 AND (?2 IS NULL OR sequence < ?2)
             ORDER BY sequence DESC LIMIT ?3"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query(params![project.to_string(), before, fetch_limit])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(event_from_row(row, project)?);
        }

        let has_more = events.len() > usize::from(query.limit().get());
        if has_more {
            events.truncate(usize::from(query.limit().get()));
        }
        let next_cursor = if has_more {
            let sequence = events
                .last()
                .map(Event::sequence)
                .ok_or_else(|| StoreError::corrupt("history page lost its events"))?;
            Some(
                HistoryCursor::new(project, sequence)
                    .map_err(|error| StoreError::corrupt(format!("history cursor: {error}")))?,
            )
        } else {
            None
        };

        HistoryPage::new(events, next_cursor)
            .map_err(|error| StoreError::corrupt(format!("history page: {error}")))
    }

    fn pending_intents(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, StoreError> {
        let sql = format!(
            "SELECT {OPERATION_COLUMNS} FROM operations
             WHERE project_id = ?1 AND outcome IS NULL
             ORDER BY recorded_at ASC, operation_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query([project.to_string()])?;
        let mut intents = Vec::new();
        while let Some(row) = rows.next()? {
            let record = operation_record_from_row(row)?;
            if record.result().is_none() {
                intents.push(record.intent().clone());
            }
        }
        Ok(intents)
    }

    /// Test-support fault injection for the next commit.
    #[cfg(feature = "test-support")]
    pub fn set_commit_fault(&mut self, fault: Option<crate::test_support::CommitFault>) {
        self.fault.commit = fault.map(Into::into);
    }

    /// Test-support fault injection for the next operation-result recording.
    #[cfg(feature = "test-support")]
    pub fn set_result_fault(&mut self, fault: Option<crate::test_support::ResultFault>) {
        self.fault.result = fault.map(Into::into);
    }
}

impl StorePort for Store {
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
        self.commit(commit).map_err(Into::into)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        self.load_checkpoint_record(run)
            .map(|record| record.map(CheckpointRecord::into_checkpoint))
            .map_err(Into::into)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        self.history_page(query).map_err(Into::into)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        self.pending_intents(project).map_err(Into::into)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        Store::operation(self, operation).map_err(Into::into)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        Store::record_operation_result(self, operation, result)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        Store::record_operation_result_with_events(self, operation, result, events)
            .map_err(Into::into)
    }
}

impl RuntimeStore for Store {
    fn events_after(
        &self,
        project: &ProjectId,
        after_sequence: Option<u64>,
        limit: HistoryLimit,
    ) -> Result<Vec<Event>, CoreError> {
        Store::events_after(self, project, after_sequence, limit).map_err(Into::into)
    }

    fn unresolved_operations(
        &self,
        project: &ProjectId,
    ) -> Result<Vec<OperationRecord>, CoreError> {
        Store::unresolved_operations(self, project).map_err(Into::into)
    }

    fn load_host_state(&self, key: &str) -> Result<Option<Vec<u8>>, CoreError> {
        Store::load_host_state(self, key).map_err(Into::into)
    }

    fn save_host_state(&mut self, key: &str, value: &[u8]) -> Result<(), CoreError> {
        Store::save_host_state(self, key, value).map_err(Into::into)
    }

    fn save_host_state_and_events(
        &mut self,
        key: &str,
        value: &[u8],
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        Store::save_host_state_and_events(self, key, value, events).map_err(Into::into)
    }

    fn save_host_state_and_checkpoint(
        &mut self,
        key: &str,
        value: &[u8],
        commit: CheckpointCommit,
    ) -> Result<CommitReceipt, CoreError> {
        Store::save_host_state_and_checkpoint(self, key, value, commit).map_err(Into::into)
    }

    fn record_operation_result_with_state(
        &mut self,
        key: &str,
        value: &[u8],
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<CommitReceipt, CoreError> {
        Store::record_operation_result_with_state(self, operation, result, events, key, value)
            .map_err(Into::into)
    }
}

fn write_host_state(
    transaction: &Transaction<'_>,
    key: &str,
    value: &[u8],
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO host_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn prepare_location(config: &StoreConfig) -> Result<(), StoreError> {
    let root = config.app_data_root();
    std::fs::create_dir_all(root).map_err(StoreError::io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .map_err(StoreError::io)?;
    }

    let database_path = config.database_path();
    if !database_path.exists() {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&database_path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(StoreError::io(error)),
        }
    }
    Ok(())
}

fn next_sequence(transaction: &Transaction<'_>, project: &ProjectId) -> Result<u64, StoreError> {
    let current: Option<i64> = transaction
        .query_row(
            "SELECT next_sequence FROM project_sequences WHERE project_id = ?1",
            [project.to_string()],
            |row| row.get(0),
        )
        .optional()?;

    match current {
        None => Ok(1),
        Some(value) => {
            let value = u64::try_from(value)
                .map_err(|_| StoreError::corrupt("project sequence is negative"))?;
            if value == 0 {
                return Err(StoreError::corrupt("project sequence must be positive"));
            }
            Ok(value)
        }
    }
}

fn sequence_to_sql(sequence: u64) -> Result<i64, StoreError> {
    i64::try_from(sequence)
        .map_err(|_| StoreError::corrupt("sequence does not fit in sqlite integer"))
}

/// Assigns project sequences to drafts, inserts them, and advances the project
/// sequence counter. Returns the committed events and the sequence observed
/// before the first draft.
fn append_event_drafts(
    transaction: &Transaction<'_>,
    project: &ProjectId,
    drafts: &[EventDraft],
) -> Result<(Vec<Event>, u64), StoreError> {
    let next_sequence = next_sequence(transaction, project)?;
    let mut events = Vec::with_capacity(drafts.len());
    for (index, draft) in drafts.iter().enumerate() {
        let offset =
            u64::try_from(index).map_err(|_| StoreError::corrupt("event index overflow"))?;
        let sequence = next_sequence
            .checked_add(offset)
            .ok_or_else(|| StoreError::corrupt("project sequence overflow"))?;
        let event = draft
            .clone()
            .into_event(sequence)
            .map_err(|error| StoreError::corrupt(format!("event draft: {error}")))?;
        events.push(event);
    }

    if !events.is_empty() {
        let mut statement = transaction.prepare(
            "INSERT INTO events (project_id, sequence, contract_version, subject_type, agent_id,
                                 session_id, run_id, activity_kind, activity_id, operation_id,
                                 kind, occurred_at, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for event in &events {
            let subject = SubjectColumns::from_subject(event.subject());
            statement.execute(params![
                event.project_id().to_string(),
                sequence_to_sql(event.sequence())?,
                i64::from(event.contract_version().get()),
                subject.subject_type,
                subject.agent_id,
                subject.session_id,
                subject.run_id,
                subject.activity_kind,
                subject.activity_id,
                event.operation_id().map(|operation| operation.to_string()),
                event.kind().as_str(),
                i64::try_from(event.occurred_at().as_unix_millis())
                    .map_err(|_| StoreError::corrupt("event timestamp does not fit in sqlite"))?,
                serde_json::to_string(event.payload()).map_err(StoreError::codec)?,
            ])?;
        }
        drop(statement);

        transaction.execute(
            "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, ?2)
             ON CONFLICT(project_id) DO UPDATE SET next_sequence = excluded.next_sequence",
            params![
                project.to_string(),
                sequence_to_sql(
                    next_sequence
                        .checked_add(events.len() as u64)
                        .ok_or_else(|| StoreError::corrupt("project sequence overflow"))?,
                )?,
            ],
        )?;
    }

    Ok((events, next_sequence))
}

fn insert_operation(
    transaction: &Transaction<'_>,
    intent: &OperationIntent,
) -> Result<(), StoreError> {
    let operation = intent.operation();
    transaction.execute(
        "INSERT INTO operations (operation_id, project_id, run_id, tool, arguments, cwd,
                                 policy_version, permission_mode, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            operation.operation_id().to_string(),
            operation.project_id().to_string(),
            operation.run_id().to_string(),
            operation.tool().as_str(),
            serde_json::to_string(operation.arguments()).map_err(StoreError::codec)?,
            operation.cwd().as_str(),
            i64::try_from(operation.policy_version().get())
                .map_err(|_| StoreError::corrupt("policy version does not fit in sqlite"))?,
            operation.permission_mode().to_string(),
            i64::try_from(intent.recorded_at().as_unix_millis())
                .map_err(|_| StoreError::corrupt("intent timestamp does not fit in sqlite"))?,
        ],
    )?;
    Ok(())
}

fn load_operation_record(
    conn: &Connection,
    operation_id: &str,
) -> Result<Option<OperationRecord>, StoreError> {
    let sql = format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE operation_id = ?1");
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query([operation_id])?;
    match rows.next()? {
        Some(row) => Ok(Some(operation_record_from_row(row)?)),
        None => Ok(None),
    }
}

fn operation_record_from_row(row: &rusqlite::Row<'_>) -> Result<OperationRecord, StoreError> {
    let operation_text: String = row.get(0)?;
    let project_text: String = row.get(1)?;
    let run_text: String = row.get(2)?;
    let tool_text: String = row.get(3)?;
    let arguments_text: String = row.get(4)?;
    let cwd_text: String = row.get(5)?;
    let policy_version: i64 = row.get(6)?;
    let permission_mode: String = row.get(7)?;
    let recorded_at: i64 = row.get(8)?;
    let outcome: Option<String> = row.get(9)?;
    let evidence: Option<String> = row.get(10)?;
    let resolved_at: Option<i64> = row.get(11)?;

    let operation: OperationId = parse_core(&operation_text, "operation id")?;
    let project: ProjectId = parse_core(&project_text, "operation project id")?;
    if operation.project_id() != project {
        return Err(StoreError::corrupt(
            "operation id project does not match its stored project",
        ));
    }
    let run: RunId = parse_core(&run_text, "operation run id")?;
    if run.project_id() != project {
        return Err(StoreError::corrupt(
            "operation run project does not match its stored project",
        ));
    }

    let tool = parse_tool(&tool_text)
        .ok_or_else(|| StoreError::corrupt(format!("unknown stored tool {tool_text:?}")))?;
    let arguments: ToolArguments =
        serde_json::from_str(&arguments_text).map_err(StoreError::codec)?;
    let cwd = AbsolutePath::new(cwd_text)
        .map_err(|error| StoreError::corrupt(format!("stored cwd: {error}")))?;
    let policy_version = u64::try_from(policy_version)
        .map_err(|_| StoreError::corrupt("stored policy version is negative"))?;
    let policy_version = PolicyVersion::new(policy_version)
        .map_err(|error| StoreError::corrupt(format!("stored policy version: {error}")))?;
    let permission_mode = parse_permission_mode(&permission_mode).ok_or_else(|| {
        StoreError::corrupt(format!(
            "unknown stored permission mode {permission_mode:?}"
        ))
    })?;
    let recorded_at = timestamp_from_sql(recorded_at, "operation intent timestamp")?;

    let frozen = FrozenOperation::new(
        operation,
        run,
        tool,
        arguments,
        cwd,
        policy_version,
        permission_mode,
    )
    .map_err(|error| StoreError::corrupt(format!("stored operation: {error}")))?;
    let intent = OperationIntent::new(frozen, recorded_at);

    let result = match outcome {
        None => {
            if evidence.is_some() || resolved_at.is_some() {
                return Err(StoreError::corrupt("pending operation has result evidence"));
            }
            None
        }
        Some(outcome_text) => {
            let outcome = OperationOutcome::parse(&outcome_text).ok_or_else(|| {
                StoreError::corrupt(format!("unknown stored outcome {outcome_text:?}"))
            })?;
            let evidence_text = evidence
                .ok_or_else(|| StoreError::corrupt("resolved operation has no evidence row"))?;
            let evidence: OperationEvidence =
                serde_json::from_str(&evidence_text).map_err(StoreError::codec)?;
            let resolved_at = resolved_at
                .ok_or_else(|| StoreError::corrupt("resolved operation has no timestamp"))?;
            let resolved_at = timestamp_from_sql(resolved_at, "operation result timestamp")?;
            Some(OperationResult::new(outcome, evidence, resolved_at))
        }
    };

    Ok(OperationRecord::new(intent, result))
}

fn event_from_row(row: &rusqlite::Row<'_>, project: ProjectId) -> Result<Event, StoreError> {
    let contract_version: i64 = row.get(0)?;
    let subject_type: String = row.get(1)?;
    let subject = subject_from_columns(
        project,
        &subject_type,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    )?;
    let operation_text: Option<String> = row.get(7)?;
    let sequence: i64 = row.get(8)?;
    let kind_text: String = row.get(9)?;
    let occurred_at: i64 = row.get(10)?;
    let payload_text: String = row.get(11)?;

    let found = u32::try_from(contract_version)
        .map_err(|_| StoreError::corrupt("event contract version is out of range"))?;
    let contract_version = ContractVersion::try_from(found)
        .map_err(|_| StoreError::UnsupportedContractVersion { found })?;
    let operation = match operation_text {
        Some(text) => Some(parse_core(&text, "event operation id")?),
        None => None,
    };
    let sequence =
        u64::try_from(sequence).map_err(|_| StoreError::corrupt("event sequence is negative"))?;
    let kind = EventKind::new(&kind_text)
        .map_err(|error| StoreError::corrupt(format!("event kind: {error}")))?;
    let occurred_at = timestamp_from_sql(occurred_at, "event timestamp")?;
    let payload: EventPayload = serde_json::from_str(&payload_text).map_err(StoreError::codec)?;

    if contract_version == ContractVersion::V1 {
        let Some(run) = subject.run() else {
            return Err(StoreError::corrupt(
                "version 1 event row carries a host activity subject",
            ));
        };
        Event::from_v1(
            run.project_id(),
            run.agent_id(),
            run.session_id(),
            run.run_id(),
            operation,
            sequence,
            kind,
            occurred_at,
            payload,
        )
        .map_err(|error| StoreError::corrupt(format!("event row: {error}")))
    } else {
        Event::new(subject, operation, sequence, kind, occurred_at, payload)
            .map_err(|error| StoreError::corrupt(format!("event row: {error}")))
    }
}

/// Normalized subject columns shared by events and request intents.
struct SubjectColumns {
    subject_type: &'static str,
    agent_id: Option<String>,
    session_id: Option<String>,
    run_id: Option<String>,
    activity_kind: Option<String>,
    activity_id: Option<String>,
}

impl SubjectColumns {
    fn from_subject(subject: &EventSubject) -> Self {
        match subject {
            EventSubject::Run(run) => Self {
                subject_type: "run",
                agent_id: Some(run.agent_id().to_string()),
                session_id: Some(run.session_id().to_string()),
                run_id: Some(run.run_id().to_string()),
                activity_kind: None,
                activity_id: None,
            },
            EventSubject::HostActivity(activity) => Self {
                subject_type: "host_activity",
                agent_id: None,
                session_id: None,
                run_id: None,
                activity_kind: Some(activity.activity_kind().to_string()),
                activity_id: Some(activity.activity_id().to_string()),
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn subject_from_columns(
    project: ProjectId,
    subject_type: &str,
    agent_id: Option<String>,
    session_id: Option<String>,
    run_id: Option<String>,
    activity_kind: Option<String>,
    activity_id: Option<String>,
) -> Result<EventSubject, StoreError> {
    match subject_type {
        "run" => {
            if activity_kind.is_some() || activity_id.is_some() {
                return Err(StoreError::corrupt(
                    "run subject row carries host activity columns",
                ));
            }
            let agent_text =
                agent_id.ok_or_else(|| StoreError::corrupt("run subject row has no agent id"))?;
            let session_text = session_id
                .ok_or_else(|| StoreError::corrupt("run subject row has no session id"))?;
            let run_text =
                run_id.ok_or_else(|| StoreError::corrupt("run subject row has no run id"))?;
            let agent = parse_core(&agent_text, "run subject agent id")?;
            let session = parse_core(&session_text, "run subject session id")?;
            let run = parse_core(&run_text, "run subject run id")?;
            let subject = RunSubject::new(project, agent, session, run)
                .map_err(|error| StoreError::corrupt(format!("run subject row: {error}")))?;
            Ok(EventSubject::Run(subject))
        }
        "host_activity" => {
            if agent_id.is_some() || session_id.is_some() || run_id.is_some() {
                return Err(StoreError::corrupt(
                    "host activity subject row carries run identifier columns",
                ));
            }
            let kind_text = activity_kind
                .ok_or_else(|| StoreError::corrupt("host activity row has no activity kind"))?;
            let id_text = activity_id
                .ok_or_else(|| StoreError::corrupt("host activity row has no activity id"))?;
            let kind = EventKind::new(&kind_text)
                .map_err(|error| StoreError::corrupt(format!("activity kind: {error}")))?;
            let id = parse_core(&id_text, "host activity id")?;
            let subject = HostActivitySubject::new(project, kind, id).map_err(|error| {
                StoreError::corrupt(format!("host activity subject row: {error}"))
            })?;
            Ok(EventSubject::HostActivity(subject))
        }
        other => Err(StoreError::corrupt(format!(
            "unknown subject type {other:?}"
        ))),
    }
}

fn ensure_same_project(events: &[EventDraft], project: ProjectId) -> Result<(), StoreError> {
    if let Some(event) = events.iter().find(|event| event.project_id() != project) {
        return Err(StoreError::CrossProjectReference {
            expected: project,
            found: event.project_id(),
        });
    }
    Ok(())
}

fn insert_model_request(
    transaction: &Transaction<'_>,
    intent: &RequestGateIntent,
    recorded_at: Timestamp,
) -> Result<(), StoreError> {
    let subject = SubjectColumns::from_subject(intent.subject());
    transaction.execute(
        "INSERT INTO model_requests (attempt_id, request_id, project_id, subject_type, agent_id,
                                     session_id, run_id, activity_kind, activity_id, connection_id,
                                     purpose, control, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            intent.attempt_id().to_string(),
            intent.request_id().to_string(),
            intent.subject().project_id().to_string(),
            subject.subject_type,
            subject.agent_id,
            subject.session_id,
            subject.run_id,
            subject.activity_kind,
            subject.activity_id,
            intent.connection().to_string(),
            intent.purpose().as_str(),
            serde_json::to_string(&intent.control()).map_err(StoreError::codec)?,
            i64::try_from(recorded_at.as_unix_millis())
                .map_err(|_| StoreError::corrupt("request timestamp does not fit in sqlite"))?,
        ],
    )?;
    Ok(())
}

fn load_model_request_record(
    conn: &Connection,
    attempt_id: &str,
) -> Result<Option<ModelRequestRecord>, StoreError> {
    let sql = format!("SELECT {REQUEST_COLUMNS} FROM model_requests WHERE attempt_id = ?1");
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query([attempt_id])?;
    match rows.next()? {
        Some(row) => Ok(Some(model_request_record_from_row(row)?)),
        None => Ok(None),
    }
}

fn model_request_record_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<ModelRequestRecord, StoreError> {
    let attempt_text: String = row.get(0)?;
    let request_text: String = row.get(1)?;
    let project_text: String = row.get(2)?;
    let subject_type: String = row.get(3)?;
    let connection_text: String = row.get(9)?;
    let purpose_text: String = row.get(10)?;
    let control_text: String = row.get(11)?;
    let recorded_at: i64 = row.get(12)?;
    let observation_text: Option<String> = row.get(13)?;
    let observed_at: Option<i64> = row.get(14)?;

    let attempt: AttemptId = parse_core(&attempt_text, "request attempt id")?;
    let request: RequestId = parse_core(&request_text, "request id")?;
    let project: ProjectId = parse_core(&project_text, "request project id")?;
    if attempt.project_id() != project {
        return Err(StoreError::corrupt(
            "request attempt project does not match its stored project",
        ));
    }
    if request.project_id() != project {
        return Err(StoreError::corrupt(
            "request id project does not match its stored project",
        ));
    }
    let subject = subject_from_columns(
        project,
        &subject_type,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    )?;
    let connection: ConnectionId = parse_core(&connection_text, "request connection id")?;
    let purpose = RequestPurpose::new(&purpose_text)
        .map_err(|error| StoreError::corrupt(format!("request purpose: {error}")))?;
    let control: StopDeadlineControl =
        serde_json::from_str(&control_text).map_err(StoreError::codec)?;
    let recorded_at = timestamp_from_sql(recorded_at, "request intent timestamp")?;
    let intent = RequestGateIntent::new(request, attempt, connection, purpose, subject, control)
        .map_err(|error| StoreError::corrupt(format!("request intent row: {error}")))?;

    let (observation, observed_at) = match observation_text {
        None => {
            if observed_at.is_some() {
                return Err(StoreError::corrupt(
                    "request without an observation has an observation timestamp",
                ));
            }
            (None, None)
        }
        Some(text) => {
            let observation: ModelRequestObservation =
                serde_json::from_str(&text).map_err(StoreError::codec)?;
            if observation.request_id() != request || observation.attempt_id() != attempt {
                return Err(StoreError::corrupt(
                    "request observation identifiers do not match its intent",
                ));
            }
            let observed_at = observed_at
                .ok_or_else(|| StoreError::corrupt("request observation has no timestamp"))?;
            (
                Some(observation),
                Some(timestamp_from_sql(
                    observed_at,
                    "request observation timestamp",
                )?),
            )
        }
    };

    Ok(ModelRequestRecord {
        intent,
        recorded_at,
        observation,
        observed_at,
    })
}

fn validate_state_key(key: &str) -> Result<(), StoreError> {
    if key.trim().is_empty() {
        return Err(StoreError::InvalidStateKey);
    }
    Ok(())
}

fn load_supervised_state_revision(
    conn: &Connection,
    project: &ProjectId,
    key: &str,
) -> Result<Option<u64>, StoreError> {
    let revision: Option<i64> = conn
        .query_row(
            "SELECT revision FROM supervised_state WHERE project_id = ?1 AND state_key = ?2",
            params![project.to_string(), key],
            |row| row.get(0),
        )
        .optional()?;
    revision
        .map(|value| {
            let value = u64::try_from(value)
                .map_err(|_| StoreError::corrupt("supervised state revision must be positive"))?;
            if value == 0 {
                return Err(StoreError::corrupt(
                    "supervised state revision must be positive",
                ));
            }
            Ok(value)
        })
        .transpose()
}

fn load_supervised_state(
    conn: &Connection,
    project: &ProjectId,
    key: &str,
) -> Result<Option<SupervisedStateRecord>, StoreError> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT revision, payload FROM supervised_state
             WHERE project_id = ?1 AND state_key = ?2",
            params![project.to_string(), key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((revision, value)) = row else {
        return Ok(None);
    };
    let revision = u64::try_from(revision)
        .map_err(|_| StoreError::corrupt("supervised state revision must be positive"))?;
    if revision == 0 {
        return Err(StoreError::corrupt(
            "supervised state revision must be positive",
        ));
    }
    Ok(Some(SupervisedStateRecord { revision, value }))
}

fn timestamp_from_sql(value: i64, field: &str) -> Result<Timestamp, StoreError> {
    let value =
        u64::try_from(value).map_err(|_| StoreError::corrupt(format!("{field} is negative")))?;
    Ok(Timestamp::from_unix_millis(value))
}

fn parse_core<T>(value: &str, field: &str) -> Result<T, StoreError>
where
    T: FromStr<Err = CoreError>,
{
    value
        .parse()
        .map_err(|error| StoreError::corrupt(format!("{field}: {error}")))
}

fn parse_tool(value: &str) -> Option<ToolName> {
    match value {
        "read" => Some(ToolName::Read),
        "search" => Some(ToolName::Search),
        "write" => Some(ToolName::Write),
        "edit" => Some(ToolName::Edit),
        "bash" => Some(ToolName::Bash),
        _ => None,
    }
}

fn parse_permission_mode(value: &str) -> Option<PermissionMode> {
    match value {
        "configured" => Some(PermissionMode::Configured),
        "automatic" => Some(PermissionMode::Automatic),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_roundtrip() {
        for tool in [
            ToolName::Read,
            ToolName::Search,
            ToolName::Write,
            ToolName::Edit,
            ToolName::Bash,
        ] {
            assert_eq!(parse_tool(tool.as_str()), Some(tool));
        }
        assert_eq!(parse_tool("unknown"), None);
    }

    #[test]
    fn permission_modes_roundtrip() {
        for mode in [PermissionMode::Configured, PermissionMode::Automatic] {
            assert_eq!(parse_permission_mode(&mode.to_string()), Some(mode));
        }
        assert_eq!(parse_permission_mode("unknown"), None);
    }

    #[test]
    fn sequence_conversion_rejects_overflow() {
        assert_eq!(sequence_to_sql(1).unwrap(), 1);
        assert!(sequence_to_sql(u64::MAX).is_err());
    }
}
