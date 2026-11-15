//! SQLite implementation of the H4 execution persistence ports.
//!
//! H4 state lives in dedicated rows whose payloads are opaque versioned JSON
//! owned by `herness-sdd-execute`. A compare-and-swap revision, its control
//! operation result, and its project event commit in one immediate transaction.
//! Journal records commit with the event that describes them. Events use the
//! existing H1 `events` table and project sequence; there is no second H4
//! sequence and no H4 event table.
//!
//! `commit_operation` is overridden: a revision advance can never commit
//! without the operation result row and the events that describe it, so a crash
//! at any point either keeps the old revision with no result or publishes both.
//!
//! Test-only fault injection uses the existing [`CommitPoint`] hooks
//! (`commit-before-rows`, `commit-before-commit`) on every write path.

use herness_core::{Event, ProjectId, Timestamp};
use herness_sdd_execute::{
    ApprovalId, ApprovalRevisionStorePort, BudgetIncrement, CommitRequestId, ControlRecord,
    ControlRequestId, DispatchJournalEntry, DispatchManifest, DispatchRequestId,
    DurableExecutionStorePort, ExecutionApproval, ExecutionId, ExecutionOperationResult,
    ExecutionRevision, ExecutionSnapshot, ExecutionStorePort, GitCommitOutcome, GitJournalEntry,
    GitJournalState, JournalEntryState, PlanChangeLatch, PlanChangeLatchStorePort,
    ProgressJournalEntry, ProgressJournalId, ProgressJournalState, RecordDecodeError,
    RecoveryEnumerationPort, SddExecutionError, StartRecord, StartRecordStorePort, StoredExecution,
    TaskReservation, decode_record, dispatch_event, encode_record, git_event, operation_event,
    progress_event, snapshot_event,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::StoreError;
use crate::fault::CommitPoint;
use crate::store::{Store, append_event_drafts, sequence_to_sql};

const SNAPSHOT_RECORD: &str = "execution snapshot";
const APPROVAL_RECORD: &str = "execution approval";
const RESERVATION_RECORD: &str = "task reservation";
const MANIFEST_RECORD: &str = "dispatch manifest";
const DISPATCH_RECORD: &str = "dispatch journal";
const GIT_RECORD: &str = "git journal";
const PROGRESS_RECORD: &str = "progress journal";
const CONTROL_RECORD: &str = "control record";
const BUDGET_RECORD: &str = "budget increment";
const PLAN_CHANGE_LATCH_RECORD: &str = "plan change latch";

fn positive(value: i64, field: &str) -> Result<u64, StoreError> {
    if value <= 0 {
        return Err(StoreError::corrupt(format!("{field} must be positive")));
    }
    u64::try_from(value).map_err(|_| StoreError::corrupt(format!("{field} does not fit in u64")))
}

fn to_sql_value(value: u64, field: &str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::corrupt(format!("{field} does not fit in sqlite")))
}

fn now_sql() -> Result<i64, StoreError> {
    to_sql_value(Timestamp::now().as_unix_millis(), "timestamp")
}

fn decode_row<T: DeserializeOwned>(bytes: &[u8], record: &'static str) -> Result<T, StoreError> {
    decode_record(bytes, record).map_err(|error| match error {
        RecordDecodeError::UnsupportedFormat {
            record,
            found,
            expected,
        } => StoreError::SddExecutionFormat {
            record,
            found,
            expected,
        },
        RecordDecodeError::Corrupt { detail, .. } => {
            StoreError::corrupt(format!("stored {record} is invalid: {detail}"))
        }
    })
}

fn encode_row<T: Serialize>(value: &T, record: &'static str) -> Result<Vec<u8>, StoreError> {
    encode_record(value).map_err(|error| StoreError::SddExecutionInvalidCommit {
        detail: format!("could not encode {record}: {error}"),
    })
}

fn cross_project(project: ProjectId, execution: ExecutionId) -> StoreError {
    StoreError::SddExecutionCrossProject {
        expected: project,
        found: execution.project_id(),
    }
}

fn ensure_execution(project: ProjectId, execution: ExecutionId) -> Result<(), StoreError> {
    execution
        .validate_in(project)
        .map_err(|_| cross_project(project, execution))
}

fn next_revision(expected: Option<ExecutionRevision>) -> Result<ExecutionRevision, StoreError> {
    match expected {
        None => Ok(ExecutionRevision::INITIAL),
        Some(expected) => {
            let value = expected
                .get()
                .checked_add(1)
                .ok_or_else(|| StoreError::corrupt("execution revision overflow"))?;
            ExecutionRevision::new(value).map_err(|error| {
                StoreError::corrupt(format!("execution revision is invalid: {error}"))
            })
        }
    }
}

fn check_expected_revision(
    expected: Option<ExecutionRevision>,
    found: Option<ExecutionRevision>,
) -> Result<(), StoreError> {
    let matches = match (expected, found) {
        (None, None) => true,
        (Some(expected), Some(found)) => expected == found,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::StaleRevision {
            key: "execution snapshot".to_owned(),
            expected: expected.map(ExecutionRevision::get),
            found: found.map(ExecutionRevision::get),
        })
    }
}

const fn journal_state_label(state: JournalEntryState) -> &'static str {
    match state {
        JournalEntryState::Intent => "intent",
        JournalEntryState::Recorded => "recorded",
    }
}

const fn git_state_label(state: GitJournalState) -> &'static str {
    match state {
        GitJournalState::Intent => "intent",
        GitJournalState::Committed => "committed",
        GitJournalState::Rejected => "rejected",
        GitJournalState::ResultUnknown => "result_unknown",
    }
}

const fn progress_state_label(state: ProgressJournalState) -> &'static str {
    match state {
        ProgressJournalState::Intent => "intent",
        ProgressJournalState::Recorded => "recorded",
        ProgressJournalState::ResultUnknown => "result_unknown",
    }
}

fn dispatch_transition(from: &str, to: &str) -> bool {
    from == "intent" && to == "recorded"
}

fn git_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("intent", "committed" | "rejected" | "result_unknown")
            | ("result_unknown", "committed" | "rejected")
    )
}

fn progress_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("intent", "recorded" | "result_unknown") | ("result_unknown", "recorded")
    )
}

fn control_transition(from: &str, to: &str) -> bool {
    from == "intent" && to == "recorded"
}

fn git_commit_sha(entry: &GitJournalEntry) -> Option<String> {
    match entry.outcome() {
        Some(GitCommitOutcome::Committed { commit, .. }) => Some(commit.to_string()),
        _ => None,
    }
}

fn progress_digest(entry: &ProgressJournalEntry) -> Option<String> {
    match entry.outcome() {
        Some(herness_sdd_execute::ProgressWriteOutcome::Written { digest }) => {
            Some(digest.to_string())
        }
        _ => None,
    }
}

fn load_snapshot(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
) -> Result<Option<StoredExecution>, StoreError> {
    ensure_execution(project, execution)?;
    let row = conn
        .query_row(
            "SELECT revision, payload FROM sdd_execution_snapshots
             WHERE project_id = ?1 AND execution_id = ?2",
            params![project.to_string(), execution.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((revision, payload)) = row else {
        return Ok(None);
    };
    let revision = positive(revision, "execution revision")?;
    let snapshot: ExecutionSnapshot = decode_row(&payload, SNAPSHOT_RECORD)?;
    if snapshot.project_id() != project {
        return Err(StoreError::SddExecutionCrossProject {
            expected: project,
            found: snapshot.project_id(),
        });
    }
    if snapshot.execution_id() != execution || snapshot.revision().get() != revision {
        return Err(StoreError::corrupt(
            "execution snapshot row does not match its recorded identifiers",
        ));
    }
    let revision = ExecutionRevision::new(revision)
        .map_err(|error| StoreError::corrupt(format!("stored revision: {error}")))?;
    StoredExecution::new(revision, snapshot)
        .map(Some)
        .map_err(|error| StoreError::corrupt(format!("stored snapshot: {error}")))
}

fn write_snapshot(
    transaction: &Transaction<'_>,
    snapshot: &ExecutionSnapshot,
    updated_at: i64,
    last_sequence: Option<u64>,
) -> Result<(), StoreError> {
    let payload = encode_row(snapshot, SNAPSHOT_RECORD)?;
    transaction.execute(
        "INSERT INTO sdd_execution_snapshots
             (project_id, execution_id, revision, state, plan_revision,
              last_sequence, payload, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(project_id, execution_id) DO UPDATE SET
             revision = excluded.revision,
             state = excluded.state,
             plan_revision = excluded.plan_revision,
             last_sequence = excluded.last_sequence,
             payload = excluded.payload,
             updated_at = excluded.updated_at",
        params![
            snapshot.project_id().to_string(),
            snapshot.execution_id().to_string(),
            sequence_to_sql(snapshot.revision().get())?,
            snapshot.state().as_str(),
            sequence_to_sql(snapshot.plan().approved_revision().get())?,
            last_sequence.map(sequence_to_sql).transpose()?,
            payload,
            updated_at,
        ],
    )?;
    Ok(())
}

fn load_dispatch(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: DispatchRequestId,
) -> Result<Option<DispatchJournalEntry>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let row = conn
        .query_row(
            "SELECT state, fingerprint, payload FROM sdd_dispatch_journal
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((state, fingerprint, payload)) = row else {
        return Ok(None);
    };
    let entry: DispatchJournalEntry = decode_row(&payload, DISPATCH_RECORD)?;
    let identity = entry.identity();
    if identity.project_id() != project
        || identity.execution_id() != execution
        || identity.request_id() != request
        || entry.fingerprint().as_str() != fingerprint
        || journal_state_label(entry.state()) != state
    {
        return Err(StoreError::corrupt(
            "dispatch journal row does not match its payload",
        ));
    }
    Ok(Some(entry))
}

fn load_git(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: CommitRequestId,
) -> Result<Option<GitJournalEntry>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let row = conn
        .query_row(
            "SELECT state, fingerprint, payload FROM sdd_git_journal
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((state, fingerprint, payload)) = row else {
        return Ok(None);
    };
    let entry: GitJournalEntry = decode_row(&payload, GIT_RECORD)?;
    let identity = entry.identity();
    if identity.project_id() != project
        || identity.execution_id() != execution
        || identity.request_id() != request
        || entry.fingerprint().as_str() != fingerprint
        || git_state_label(entry.state()) != state
    {
        return Err(StoreError::corrupt(
            "git journal row does not match its payload",
        ));
    }
    Ok(Some(entry))
}

fn load_progress(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: ProgressJournalId,
) -> Result<Option<ProgressJournalEntry>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let row = conn
        .query_row(
            "SELECT state, fingerprint, payload FROM sdd_progress_journal
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((state, fingerprint, payload)) = row else {
        return Ok(None);
    };
    let entry: ProgressJournalEntry = decode_row(&payload, PROGRESS_RECORD)?;
    let identity = entry.identity();
    if identity.project_id() != project
        || identity.execution_id() != execution
        || identity.request_id() != request
        || entry.fingerprint().as_str() != fingerprint
        || progress_state_label(entry.state()) != state
    {
        return Err(StoreError::corrupt(
            "progress journal row does not match its payload",
        ));
    }
    Ok(Some(entry))
}

fn load_control(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: ControlRequestId,
) -> Result<Option<ControlRecord>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let row = conn
        .query_row(
            "SELECT state, fingerprint, payload FROM sdd_control_records
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((state, fingerprint, payload)) = row else {
        return Ok(None);
    };
    let record: ControlRecord = decode_row(&payload, CONTROL_RECORD)?;
    let identity = record.identity();
    if identity.project_id() != project
        || identity.execution_id() != execution
        || identity.request_id() != request
        || record.fingerprint().as_str() != fingerprint
        || journal_state_label(record.state()) != state
    {
        return Err(StoreError::corrupt(
            "control record row does not match its payload",
        ));
    }
    Ok(Some(record))
}

fn write_control(
    transaction: &Transaction<'_>,
    record: &ControlRecord,
    now: i64,
) -> Result<(), StoreError> {
    let identity = record.identity();
    let payload = encode_row(record, CONTROL_RECORD)?;
    let outcome = record.outcome();
    transaction.execute(
        "INSERT INTO sdd_control_records
             (project_id, execution_id, request_id, operation, state, fingerprint,
              expected_revision, resulting_revision, payload, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
         ON CONFLICT(project_id, execution_id, request_id) DO UPDATE SET
             operation = excluded.operation,
             state = excluded.state,
             resulting_revision = excluded.resulting_revision,
             payload = excluded.payload,
             updated_at = excluded.updated_at",
        params![
            identity.project_id().to_string(),
            identity.execution_id().to_string(),
            identity.request_id().to_string(),
            outcome.map(|result| result.operation().as_str()),
            journal_state_label(record.state()),
            record.fingerprint().as_str(),
            sequence_to_sql(identity.expected_revision().get())?,
            outcome
                .map(|result| sequence_to_sql(result.resulting_revision().get()))
                .transpose()?,
            payload,
            now,
        ],
    )?;
    Ok(())
}

impl Store {
    /// Loads the stored execution snapshot.
    pub fn load_sdd_execution(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, StoreError> {
        load_snapshot(&self.conn, project_id, execution_id)
    }

    /// Creates or updates the execution snapshot with a revision check.
    ///
    /// The snapshot revision must be the initial revision on creation and
    /// exactly one greater than the expected revision on update. The snapshot
    /// and its project event commit in one immediate transaction.
    pub fn compare_and_swap_execution(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, StoreError> {
        ensure_execution(project_id, execution_id)?;
        if next.project_id() != project_id || next.execution_id() != execution_id {
            return Err(cross_project(project_id, next.execution_id()));
        }
        next.validate()
            .map_err(|error| StoreError::SddExecutionInvalidCommit {
                detail: error.to_string(),
            })?;
        if next.revision() != next_revision(expected_revision)? {
            return Err(StoreError::SddExecutionInvalidCommit {
                detail: "the written revision must advance by exactly one".to_owned(),
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
        let current = load_snapshot(&transaction, project_id, execution_id)?;
        check_expected_revision(
            expected_revision,
            current.as_ref().map(StoredExecution::revision),
        )?;
        let draft = snapshot_event(next, Timestamp::now()).map_err(StoreError::from)?;
        let (events, _) = append_event_drafts(&transaction, &project_id, &[draft])?;
        let last_sequence = events.last().map(Event::sequence);
        write_snapshot(&transaction, next, now_sql()?, last_sequence)?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(next.revision())
    }

    /// Returns the recorded dispatch entry for one request.
    pub fn sdd_dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, StoreError> {
        load_dispatch(&self.conn, project_id, execution_id, request_id)
    }

    /// Returns the recorded Git entry for one request.
    pub fn sdd_git_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, StoreError> {
        load_git(&self.conn, project_id, execution_id, request_id)
    }

    /// Returns the recorded progress entry for one request.
    pub fn sdd_progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, StoreError> {
        load_progress(&self.conn, project_id, execution_id, request_id)
    }

    /// Returns the recorded control record for one request.
    pub fn sdd_control_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<ControlRecord>, StoreError> {
        load_control(&self.conn, project_id, execution_id, request_id)
    }

    /// Writes one dispatch intent or result exactly once.
    pub fn record_dispatch_entry(
        &mut self,
        entry: &DispatchJournalEntry,
    ) -> Result<(), StoreError> {
        let identity = *entry.identity();
        identity
            .ensure_project(identity.project_id())
            .map_err(StoreError::from)?;
        let state = journal_state_label(entry.state());
        let fingerprint = entry.fingerprint().as_str();

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        let existing = load_dispatch(
            &transaction,
            identity.project_id(),
            identity.execution_id(),
            identity.request_id(),
        )?;
        if let Some(ref stored) = existing {
            if stored.fingerprint().as_str() != fingerprint {
                return Err(StoreError::SddExecutionRequestConflict {
                    request: identity.request_id().to_string(),
                    recorded: stored.fingerprint().to_string(),
                    supplied: fingerprint.to_owned(),
                });
            }
            if stored == entry {
                return Ok(());
            }
            let from = journal_state_label(stored.state());
            if !dispatch_transition(from, state) {
                return Err(StoreError::SddExecutionRecordConflict {
                    record: DISPATCH_RECORD,
                    id: identity.request_id().to_string(),
                });
            }
        }
        let payload = encode_row(entry, DISPATCH_RECORD)?;
        let now = now_sql()?;
        transaction.execute(
            "INSERT INTO sdd_dispatch_journal
                 (project_id, execution_id, request_id, state, fingerprint,
                  expected_revision, payload, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(project_id, execution_id, request_id) DO UPDATE SET
                 state = excluded.state,
                 payload = excluded.payload,
                 updated_at = excluded.updated_at",
            params![
                identity.project_id().to_string(),
                identity.execution_id().to_string(),
                identity.request_id().to_string(),
                state,
                fingerprint,
                sequence_to_sql(identity.expected_revision().get())?,
                payload,
                now,
            ],
        )?;
        let draft = dispatch_event(entry, Timestamp::now()).map_err(StoreError::from)?;
        append_event_drafts(&transaction, &identity.project_id(), &[draft])?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Writes one Git intent or result exactly once.
    ///
    /// An `intent` becomes `committed`, `rejected`, or `result_unknown`; an
    /// unknown result may later be bound to an observed commit or rejection. A
    /// recorded commit is never rewritten.
    pub fn record_git_entry(&mut self, entry: &GitJournalEntry) -> Result<(), StoreError> {
        let identity = *entry.identity();
        identity
            .ensure_project(identity.project_id())
            .map_err(StoreError::from)?;
        let state = git_state_label(entry.state());
        let fingerprint = entry.fingerprint().as_str();

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        let existing = load_git(
            &transaction,
            identity.project_id(),
            identity.execution_id(),
            identity.request_id(),
        )?;
        if let Some(ref stored) = existing {
            if stored.fingerprint().as_str() != fingerprint {
                return Err(StoreError::SddExecutionRequestConflict {
                    request: identity.request_id().to_string(),
                    recorded: stored.fingerprint().to_string(),
                    supplied: fingerprint.to_owned(),
                });
            }
            if stored == entry {
                return Ok(());
            }
            if !git_transition(git_state_label(stored.state()), state) {
                return Err(StoreError::SddExecutionRecordConflict {
                    record: GIT_RECORD,
                    id: identity.request_id().to_string(),
                });
            }
        }
        let payload = encode_row(entry, GIT_RECORD)?;
        let now = now_sql()?;
        transaction.execute(
            "INSERT INTO sdd_git_journal
                 (project_id, execution_id, request_id, state, fingerprint,
                  expected_revision, commit_sha, payload, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(project_id, execution_id, request_id) DO UPDATE SET
                 state = excluded.state,
                 commit_sha = excluded.commit_sha,
                 payload = excluded.payload,
                 updated_at = excluded.updated_at",
            params![
                identity.project_id().to_string(),
                identity.execution_id().to_string(),
                identity.request_id().to_string(),
                state,
                fingerprint,
                sequence_to_sql(identity.expected_revision().get())?,
                git_commit_sha(entry),
                payload,
                now,
            ],
        )?;
        let draft = git_event(entry, Timestamp::now()).map_err(StoreError::from)?;
        append_event_drafts(&transaction, &identity.project_id(), &[draft])?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Writes one progress intent or result exactly once.
    pub fn record_progress_entry(
        &mut self,
        entry: &ProgressJournalEntry,
    ) -> Result<(), StoreError> {
        let identity = *entry.identity();
        identity
            .ensure_project(identity.project_id())
            .map_err(StoreError::from)?;
        let state = progress_state_label(entry.state());
        let fingerprint = entry.fingerprint().as_str();

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        let existing = load_progress(
            &transaction,
            identity.project_id(),
            identity.execution_id(),
            identity.request_id(),
        )?;
        if let Some(ref stored) = existing {
            if stored.fingerprint().as_str() != fingerprint {
                return Err(StoreError::SddExecutionRequestConflict {
                    request: identity.request_id().to_string(),
                    recorded: stored.fingerprint().to_string(),
                    supplied: fingerprint.to_owned(),
                });
            }
            if stored == entry {
                return Ok(());
            }
            if !progress_transition(progress_state_label(stored.state()), state) {
                return Err(StoreError::SddExecutionRecordConflict {
                    record: PROGRESS_RECORD,
                    id: identity.request_id().to_string(),
                });
            }
        }
        let payload = encode_row(entry, PROGRESS_RECORD)?;
        let now = now_sql()?;
        transaction.execute(
            "INSERT INTO sdd_progress_journal
                 (project_id, execution_id, request_id, state, fingerprint,
                  expected_revision, document_digest, payload, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(project_id, execution_id, request_id) DO UPDATE SET
                 state = excluded.state,
                 document_digest = excluded.document_digest,
                 payload = excluded.payload,
                 updated_at = excluded.updated_at",
            params![
                identity.project_id().to_string(),
                identity.execution_id().to_string(),
                identity.request_id().to_string(),
                state,
                fingerprint,
                sequence_to_sql(identity.expected_revision().get())?,
                progress_digest(entry),
                payload,
                now,
            ],
        )?;
        let draft = progress_event(entry, Timestamp::now()).map_err(StoreError::from)?;
        append_event_drafts(&transaction, &identity.project_id(), &[draft])?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Writes one control-operation record exactly once.
    ///
    /// This records the result without changing the execution snapshot. Use
    /// [`Store::commit_execution_operation`] to bind a result to a revision
    /// advance in one transaction.
    pub fn record_control_record(&mut self, record: &ControlRecord) -> Result<(), StoreError> {
        let identity = *record.identity();
        identity
            .ensure_project(identity.project_id())
            .map_err(StoreError::from)?;
        if let Some(result) = record.outcome()
            && (result.project_id() != identity.project_id()
                || result.execution_id() != identity.execution_id())
        {
            return Err(StoreError::SddExecutionCrossProject {
                expected: identity.project_id(),
                found: result.project_id(),
            });
        }
        let state = journal_state_label(record.state());
        let fingerprint = record.fingerprint().as_str();

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        if let Some(stored) = load_control(
            &transaction,
            identity.project_id(),
            identity.execution_id(),
            identity.request_id(),
        )? {
            if stored.fingerprint().as_str() != fingerprint {
                return Err(StoreError::SddExecutionRequestConflict {
                    request: identity.request_id().to_string(),
                    recorded: stored.fingerprint().to_string(),
                    supplied: fingerprint.to_owned(),
                });
            }
            if stored == *record {
                return Ok(());
            }
            if !control_transition(journal_state_label(stored.state()), state) {
                return Err(StoreError::SddExecutionRecordConflict {
                    record: CONTROL_RECORD,
                    id: identity.request_id().to_string(),
                });
            }
        }
        write_control(&transaction, record, now_sql()?)?;
        let draft = operation_event(record, Timestamp::now()).map_err(StoreError::from)?;
        append_event_drafts(&transaction, &identity.project_id(), &[draft])?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Atomically checks the revision, writes the next snapshot, records the
    /// operation result, and appends both events.
    ///
    /// The decision order is fixed so a re-delivered request never writes twice
    /// and never creates a second side effect:
    ///
    /// 1. Project and execution bindings are checked.
    /// 2. A stored record for the same request ID is looked up **before** any
    ///    revision check. Same fingerprint with a recorded result returns that
    ///    stored revision without a write or an event; a different fingerprint
    ///    is refused. This is what makes a re-delivered start or commit request
    ///    idempotent even after the revision advanced.
    /// 3. Only for a new (or intent-only) request does the expected revision
    ///    have to be current; a stale revision is refused before any side
    ///    effect.
    /// 4. The written revision must be exactly one greater than the expected
    ///    revision, and the record's result must describe the written snapshot.
    /// 5. The snapshot, the control record, and the two events commit in one
    ///    immediate transaction.
    pub fn commit_execution_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &ControlRecord,
    ) -> Result<ExecutionRevision, StoreError> {
        ensure_execution(project_id, execution_id)?;
        if next.project_id() != project_id || next.execution_id() != execution_id {
            return Err(cross_project(project_id, next.execution_id()));
        }
        let identity = *record.identity();
        if identity.project_id() != project_id || identity.execution_id() != execution_id {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project_id,
                found: identity.project_id(),
            });
        }
        if let Some(result) = record.outcome()
            && (result.project_id() != project_id || result.execution_id() != execution_id)
        {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project_id,
                found: result.project_id(),
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

        // Duplicate detection precedes the stale-revision check.
        if let Some(stored) = load_control(
            &transaction,
            project_id,
            execution_id,
            identity.request_id(),
        )? {
            if stored.fingerprint() != record.fingerprint() {
                return Err(StoreError::SddExecutionRequestConflict {
                    request: identity.request_id().to_string(),
                    recorded: stored.fingerprint().to_string(),
                    supplied: record.fingerprint().to_string(),
                });
            }
            if let Some(stored_result) = stored.outcome() {
                return Ok(stored_result.resulting_revision());
            }
            // A recorded intent without a result is completed below.
        }

        let result: &ExecutionOperationResult =
            record
                .outcome()
                .ok_or_else(|| StoreError::SddExecutionInvalidCommit {
                    detail: "commit_operation requires a recorded operation result".to_owned(),
                })?;
        if result.resulting_revision() != next.revision() || result.snapshot() != next {
            return Err(StoreError::SddExecutionInvalidCommit {
                detail: "the operation result must describe the written snapshot".to_owned(),
            });
        }

        // The stale-revision check runs before the structural advance check so
        // a new request against an outdated revision is refused as a revision
        // conflict, before any row or event is written.
        let current = load_snapshot(&transaction, project_id, execution_id)?;
        check_expected_revision(
            expected_revision,
            current.as_ref().map(StoredExecution::revision),
        )?;
        if next.revision() != next_revision(expected_revision)? {
            return Err(StoreError::SddExecutionInvalidCommit {
                detail: "the written revision must advance by exactly one".to_owned(),
            });
        }
        let drafts = vec![
            snapshot_event(next, Timestamp::now()).map_err(StoreError::from)?,
            operation_event(record, Timestamp::now()).map_err(StoreError::from)?,
        ];
        let (events, _) = append_event_drafts(&transaction, &project_id, &drafts)?;
        let last_sequence = events.last().map(Event::sequence);
        write_snapshot(&transaction, next, now_sql()?, last_sequence)?;
        write_control(&transaction, record, now_sql()?)?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(next.revision())
    }

    /// Records one immutable approval revision.
    ///
    /// The revision must strictly increase for the approval identity; the same
    /// stored revision is a no-op and a different value for the same key is
    /// refused.
    pub fn record_sdd_approval(&mut self, approval: &ExecutionApproval) -> Result<(), StoreError> {
        let project = approval.project_id();
        if approval.approval_id().project_id() != project {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project,
                found: approval.approval_id().project_id(),
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
        let existing = load_approval(
            &transaction,
            project,
            approval.approval_id(),
            approval.revision(),
        )?;
        if let Some(stored) = existing {
            if stored == *approval {
                return Ok(());
            }
            return Err(StoreError::SddExecutionRecordConflict {
                record: APPROVAL_RECORD,
                id: format!(
                    "{} revision {}",
                    approval.approval_id(),
                    approval.revision()
                ),
            });
        }
        let latest = latest_approval_revision(&transaction, project, approval.approval_id())?;
        if latest.is_some_and(|latest| approval.revision() <= latest) {
            return Err(StoreError::SddExecutionRecordConflict {
                record: APPROVAL_RECORD,
                id: format!(
                    "{} revision {}",
                    approval.approval_id(),
                    approval.revision()
                ),
            });
        }
        let payload = encode_row(approval, APPROVAL_RECORD)?;
        transaction.execute(
            "INSERT INTO sdd_execution_approvals
                 (project_id, approval_id, revision, plan_revision, payload,
                  approved_at, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                project.to_string(),
                approval.approval_id().to_string(),
                sequence_to_sql(approval.revision())?,
                sequence_to_sql(approval.plan().plan_revision().get())?,
                payload,
                to_sql_value(approval.approved_at().as_unix_millis(), "approved_at")?,
                now_sql()?,
            ],
        )?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Loads one approval revision.
    pub fn sdd_approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, StoreError> {
        load_approval(&self.conn, project_id, approval_id, revision)
    }

    /// Loads the newest recorded approval revision.
    pub fn latest_sdd_approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, StoreError> {
        let Some(revision) = latest_approval_revision(&self.conn, project_id, approval_id)? else {
            return Ok(None);
        };
        load_approval(&self.conn, project_id, approval_id, revision)
    }

    /// Loads every recorded approval revision in ascending order.
    pub fn sdd_approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, StoreError> {
        approval_id
            .validate_in(project_id)
            .map_err(|_| StoreError::SddExecutionCrossProject {
                expected: project_id,
                found: approval_id.project_id(),
            })?;
        let mut statement = self.conn.prepare(
            "SELECT revision FROM sdd_execution_approvals
             WHERE project_id = ?1 AND approval_id = ?2
             ORDER BY revision ASC",
        )?;
        let revisions = statement
            .query_map(
                params![project_id.to_string(), approval_id.to_string()],
                |row| row.get::<_, i64>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let mut approvals = Vec::with_capacity(revisions.len());
        for revision in revisions {
            let revision = positive(revision, "approval revision")?;
            let approval = load_approval(&self.conn, project_id, approval_id, revision)?
                .ok_or_else(|| {
                    StoreError::corrupt("approval row disappeared during the listing")
                })?;
            approvals.push(approval);
        }
        Ok(approvals)
    }

    /// Every distinct approval identity recorded for one project.
    ///
    /// The recovery binding needs it because a snapshot records the plan identity
    /// (path, digest, plan revision) rather than the approval identity.
    pub fn sdd_approval_ids(&self, project_id: ProjectId) -> Result<Vec<ApprovalId>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT approval_id FROM sdd_execution_approvals
             WHERE project_id = ?1 ORDER BY approval_id ASC",
        )?;
        let ids = statement
            .query_map(params![project_id.to_string()], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut approvals = Vec::with_capacity(ids.len());
        for id in ids {
            let approval_id: ApprovalId = id
                .parse()
                .map_err(|_| StoreError::corrupt("stored approval id is invalid"))?;
            approval_id.validate_in(project_id).map_err(|_| {
                StoreError::SddExecutionCrossProject {
                    expected: project_id,
                    found: approval_id.project_id(),
                }
            })?;
            approvals.push(approval_id);
        }
        Ok(approvals)
    }

    /// Loads the start record for one request.
    pub fn sdd_start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, StoreError> {
        ensure_execution(project_id, execution_id)?;
        request_id
            .validate_in(project_id)
            .map_err(|_| StoreError::SddExecutionCrossProject {
                expected: project_id,
                found: request_id.project_id(),
            })?;
        let key = start_record_key(project_id, execution_id, request_id);
        let Some(bytes) = Store::load_host_state(self, &key)? else {
            return Ok(None);
        };
        let record: StartRecord = serde_json::from_slice(&bytes).map_err(|error| {
            StoreError::corrupt(format!("stored H4 start record is invalid: {error}"))
        })?;
        if record.project_id() != project_id
            || record.execution_id() != execution_id
            || record.request_id() != request_id
        {
            return Err(StoreError::corrupt(
                "H4 start record does not match its recorded identifiers",
            ));
        }
        Ok(Some(record))
    }

    /// Loads the one start record written for one Task, if any.
    ///
    /// The start-record host-state key ends with the request identity, so the
    /// SQLite port cannot index by Task directly. It reads every start-record key
    /// of the execution and returns the record whose Task matches. An
    /// unreadable row is an error, never `None`.
    pub fn sdd_start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: herness_sdd_execute::TaskRef,
    ) -> Result<Option<StartRecord>, StoreError> {
        ensure_execution(project_id, execution_id)?;
        task.ensure_project(project_id)
            .map_err(|_| StoreError::SddExecutionCrossProject {
                expected: project_id,
                found: task.project_id(),
            })?;
        let prefix = start_record_prefix(project_id, execution_id);
        let mut statement = self
            .conn
            .prepare("SELECT key FROM host_state WHERE key LIKE ?1 ORDER BY key ASC")?;
        let keys = statement
            .query_map(params![format!("{prefix}%")], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            let Some(bytes) = Store::load_host_state(self, &key)? else {
                continue;
            };
            let record: StartRecord = serde_json::from_slice(&bytes).map_err(|error| {
                StoreError::corrupt(format!("stored H4 start record is invalid: {error}"))
            })?;
            if record.project_id() != project_id || record.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "H4 start record does not match its recorded identifiers",
                ));
            }
            if record.task() == task {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Writes the start record for one request.
    ///
    /// A record that would move the phase backwards or replace the stored start
    /// result is refused before any write.
    pub fn record_sdd_start_record(&mut self, record: &StartRecord) -> Result<(), StoreError> {
        let project = record.project_id();
        let execution = record.execution_id();
        let request = record.request_id();
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        if let Some(stored) = load_start_record(&transaction, project, execution, request)? {
            stored.ensure_advance(record).map_err(StoreError::from)?;
            if stored == *record {
                return Ok(());
            }
        }
        let key = start_record_key(project, execution, request);
        let bytes: Vec<u8> = serde_json::to_vec(record).map_err(|error| StoreError::Codec {
            detail: format!("could not encode the H4 start record: {error}"),
        })?;
        crate::store::write_host_state(&transaction, &key, &bytes)?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)
    }

    /// Records the one reservation for a dispatch request.
    ///
    /// A re-delivered identical reservation returns the stored value without a
    /// write. A different request for the same Task, or a different reservation
    /// for the same request, is refused before any write.
    pub fn reserve_sdd_task(
        &mut self,
        reservation: &TaskReservation,
    ) -> Result<TaskReservation, StoreError> {
        let project = reservation.project_id();
        let execution = reservation.execution_id();
        if execution.project_id() != project || reservation.task().project_id() != project {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project,
                found: execution.project_id(),
            });
        }
        if reservation.supervision_id().project_id() != project {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project,
                found: reservation.supervision_id().project_id(),
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
        if let Some(stored) =
            load_reservation_by_request(&transaction, project, execution, reservation.request_id())?
        {
            if stored == *reservation {
                return Ok(stored);
            }
            return Err(StoreError::SddExecutionRecordConflict {
                record: RESERVATION_RECORD,
                id: reservation.request_id().to_string(),
            });
        }
        if let Some(stored) =
            load_reservation_by_task(&transaction, project, execution, reservation.task())?
        {
            return Err(StoreError::SddExecutionRecordConflict {
                record: RESERVATION_RECORD,
                id: format!(
                    "task {} is already reserved by request {}",
                    stored.task(),
                    stored.request_id()
                ),
            });
        }
        let payload = encode_row(reservation, RESERVATION_RECORD)?;
        transaction.execute(
            "INSERT INTO sdd_task_reservations
                 (project_id, execution_id, task_stable_id, task_number, request_id,
                  supervision_id, child_agent_id, child_session_id, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                project.to_string(),
                execution.to_string(),
                reservation.task().stable_id().to_string(),
                sequence_to_sql(u64::from(reservation.task().number().get()))?,
                reservation.request_id().to_string(),
                reservation.supervision_id().to_string(),
                reservation.child().agent_id().to_string(),
                reservation.child().session_id().to_string(),
                payload,
                now_sql()?,
            ],
        )?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(*reservation)
    }

    /// Loads the reservation created by one dispatch request.
    pub fn sdd_task_reservation(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<TaskReservation>, StoreError> {
        load_reservation_by_request(&self.conn, project_id, execution_id, request_id)
    }

    /// Records the immutable manifest for one dispatch request.
    pub fn record_sdd_manifest(&mut self, manifest: &DispatchManifest) -> Result<(), StoreError> {
        let project = manifest.project_id();
        if manifest.execution_id().project_id() != project {
            return Err(StoreError::SddExecutionCrossProject {
                expected: project,
                found: manifest.execution_id().project_id(),
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
        if let Some(stored) = load_manifest(
            &transaction,
            project,
            manifest.execution_id(),
            manifest.request_id(),
        )? {
            if stored == *manifest {
                return Ok(());
            }
            return Err(StoreError::SddExecutionRecordConflict {
                record: MANIFEST_RECORD,
                id: manifest.request_id().to_string(),
            });
        }
        let payload = encode_row(manifest, MANIFEST_RECORD)?;
        transaction.execute(
            "INSERT INTO sdd_dispatch_manifests
                 (project_id, execution_id, request_id, task_stable_id, task_number,
                  plan_revision, baseline, manifest_digest, packet_digest, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                project.to_string(),
                manifest.execution_id().to_string(),
                manifest.request_id().to_string(),
                manifest.task().stable_id().to_string(),
                sequence_to_sql(u64::from(manifest.task().number().get()))?,
                sequence_to_sql(manifest.approved_plan_revision().get())?,
                manifest.baseline().as_str(),
                manifest.manifest_digest().as_str(),
                manifest.packet_digest().as_str(),
                payload,
                now_sql()?,
            ],
        )?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Loads the manifest for one dispatch request.
    pub fn sdd_manifest(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchManifest>, StoreError> {
        load_manifest(&self.conn, project_id, execution_id, request_id)
    }

    /// Records one budget increment for an execution revision.
    ///
    /// Increments are append-only: the amounts may only grow, and this record
    /// cannot express a decrease. The same revision with the same value is a
    /// no-op; the same revision with another value is refused.
    pub fn record_sdd_budget_increment(
        &mut self,
        increment: &BudgetIncrement,
    ) -> Result<(), StoreError> {
        increment.validate().map_err(StoreError::from)?;
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        if let Some(stored) = load_budget_increment(
            &transaction,
            increment.project_id(),
            increment.execution_id(),
            increment.revision(),
        )? {
            if stored == *increment {
                return Ok(());
            }
            return Err(StoreError::SddExecutionRecordConflict {
                record: BUDGET_RECORD,
                id: format!("revision {}", increment.revision().get()),
            });
        }
        let payload = encode_row(increment, BUDGET_RECORD)?;
        transaction.execute(
            "INSERT INTO sdd_execution_budget_increments
                 (project_id, execution_id, revision, consumed_seconds_delta,
                  additional_runs_delta, micros_delta, payload, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                increment.project_id().to_string(),
                increment.execution_id().to_string(),
                sequence_to_sql(increment.revision().get())?,
                to_sql_value(increment.consumed_seconds_delta(), "consumed_seconds_delta")?,
                i64::from(increment.additional_runs_delta()),
                increment
                    .money_delta()
                    .map(|money| to_sql_value(money.micros(), "micros_delta"))
                    .transpose()?,
                payload,
                now_sql()?,
            ],
        )?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }

    /// Lists budget increments in revision order.
    pub fn sdd_budget_increments(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<BudgetIncrement>, StoreError> {
        ensure_execution(project_id, execution_id)?;
        let mut statement = self.conn.prepare(
            "SELECT payload FROM sdd_execution_budget_increments
             WHERE project_id = ?1 AND execution_id = ?2 ORDER BY revision ASC",
        )?;
        let rows = statement.query_map(
            params![project_id.to_string(), execution_id.to_string()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut increments = Vec::new();
        for row in rows {
            let payload = row?;
            let increment: BudgetIncrement = decode_row(&payload, BUDGET_RECORD)?;
            if increment.project_id() != project_id || increment.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "budget increment row does not match its recorded identifiers",
                ));
            }
            increments.push(increment);
        }
        Ok(increments)
    }

    /// Loads the plan-change latch of one execution, when one exists.
    pub fn sdd_plan_change_latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, StoreError> {
        load_plan_change_latch(&self.conn, project_id, execution_id)
    }

    /// Records one plan-change latch state.
    ///
    /// The first open latch of an execution is the history of the stop, so an
    /// existing open row is only rewritten when it is identical or when a
    /// human-approved plan revision clears it. A cleared row never moves back to
    /// a different clearance.
    pub fn record_sdd_plan_change_latch(
        &mut self,
        latch: &PlanChangeLatch,
    ) -> Result<(), StoreError> {
        latch.validate().map_err(StoreError::from)?;
        let project = latch.project_id();
        let execution = latch.execution_id();
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }
        let stored = load_plan_change_latch(&transaction, project, execution)?;
        if let Some(stored) = &stored {
            PlanChangeLatch::ensure_advance(stored, latch).map_err(StoreError::from)?;
            if stored == latch {
                return Ok(());
            }
        }
        let payload = encode_row(latch, PLAN_CHANGE_LATCH_RECORD)?;
        let state = match latch.state() {
            herness_sdd_execute::LatchState::Open => "open",
            herness_sdd_execute::LatchState::Cleared { .. } => "cleared",
        };
        let approval_revision = match latch.state() {
            herness_sdd_execute::LatchState::Open => None,
            herness_sdd_execute::LatchState::Cleared {
                approval_revision, ..
            } => Some(sequence_to_sql(approval_revision)?),
        };
        transaction.execute(
            "INSERT INTO sdd_plan_change_latches
                 (project_id, execution_id, approval_id, state, approval_revision,
                  plan_revision, observed_digest, payload, opened_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(project_id, execution_id) DO UPDATE SET
                 approval_id = excluded.approval_id,
                 state = excluded.state,
                 approval_revision = excluded.approval_revision,
                 plan_revision = excluded.plan_revision,
                 observed_digest = excluded.observed_digest,
                 payload = excluded.payload,
                 updated_at = excluded.updated_at",
            params![
                project.to_string(),
                execution.to_string(),
                latch.approval_id().to_string(),
                state,
                approval_revision,
                sequence_to_sql(latch.expectation().plan_revision().get())?,
                latch
                    .change()
                    .observed_digest()
                    .map(|digest| digest.as_str().to_owned()),
                payload,
                now_sql()?,
            ],
        )?;
        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }
        transaction.commit().map_err(StoreError::database)?;
        Ok(())
    }
}

fn load_plan_change_latch(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
) -> Result<Option<PlanChangeLatch>, StoreError> {
    ensure_execution(project, execution)?;
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_plan_change_latches
             WHERE project_id = ?1 AND execution_id = ?2",
            params![project.to_string(), execution.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let latch: PlanChangeLatch = decode_row(&payload, PLAN_CHANGE_LATCH_RECORD)?;
    latch.validate().map_err(StoreError::from)?;
    if latch.project_id() != project || latch.execution_id() != execution {
        return Err(StoreError::corrupt(
            "plan change latch row does not match its recorded identifiers",
        ));
    }
    Ok(Some(latch))
}

fn load_start_record(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: ControlRequestId,
) -> Result<Option<StartRecord>, StoreError> {
    let key = start_record_key(project, execution, request);
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM host_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let record: StartRecord = serde_json::from_slice(&bytes).map_err(|error| {
        StoreError::corrupt(format!("stored H4 start record is invalid: {error}"))
    })?;
    if record.project_id() != project
        || record.execution_id() != execution
        || record.request_id() != request
    {
        return Err(StoreError::corrupt(
            "H4 start record does not match its recorded identifiers",
        ));
    }
    Ok(Some(record))
}

fn start_record_key(
    project: ProjectId,
    execution: ExecutionId,
    request: ControlRequestId,
) -> String {
    format!("{}{request}", start_record_prefix(project, execution))
}

fn start_record_prefix(project: ProjectId, execution: ExecutionId) -> String {
    format!("h4.start.record:{project}:{execution}:")
}

fn load_approval(
    conn: &Connection,
    project: ProjectId,
    approval_id: ApprovalId,
    revision: u64,
) -> Result<Option<ExecutionApproval>, StoreError> {
    approval_id
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: approval_id.project_id(),
        })?;
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_execution_approvals
             WHERE project_id = ?1 AND approval_id = ?2 AND revision = ?3",
            params![
                project.to_string(),
                approval_id.to_string(),
                sequence_to_sql(revision)?
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let approval: ExecutionApproval = decode_row(&payload, APPROVAL_RECORD)?;
    if approval.project_id() != project
        || approval.approval_id() != approval_id
        || approval.revision() != revision
    {
        return Err(StoreError::corrupt(
            "approval row does not match its recorded identifiers",
        ));
    }
    Ok(Some(approval))
}

fn latest_approval_revision(
    conn: &Connection,
    project: ProjectId,
    approval_id: ApprovalId,
) -> Result<Option<u64>, StoreError> {
    approval_id
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: approval_id.project_id(),
        })?;
    let value: Option<i64> = conn
        .query_row(
            "SELECT MAX(revision) FROM sdd_execution_approvals
             WHERE project_id = ?1 AND approval_id = ?2",
            params![project.to_string(), approval_id.to_string()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .map(Option::flatten)?;
    value
        .map(|value| positive(value, "approval revision"))
        .transpose()
}

fn load_reservation_by_request(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: DispatchRequestId,
) -> Result<Option<TaskReservation>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_task_reservations
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let reservation: TaskReservation = decode_row(&payload, RESERVATION_RECORD)?;
    if reservation.project_id() != project
        || reservation.execution_id() != execution
        || reservation.request_id() != request
    {
        return Err(StoreError::corrupt(
            "task reservation row does not match its recorded identifiers",
        ));
    }
    Ok(Some(reservation))
}

fn load_reservation_by_task(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    task: herness_sdd_execute::TaskRef,
) -> Result<Option<TaskReservation>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_task_reservations
             WHERE project_id = ?1 AND execution_id = ?2 AND task_stable_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                task.stable_id().to_string()
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let reservation: TaskReservation = decode_row(&payload, RESERVATION_RECORD)?;
    if reservation.project_id() != project
        || reservation.execution_id() != execution
        || reservation.task() != task
    {
        return Err(StoreError::corrupt(
            "task reservation row does not match its recorded identifiers",
        ));
    }
    Ok(Some(reservation))
}

fn load_manifest(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    request: DispatchRequestId,
) -> Result<Option<DispatchManifest>, StoreError> {
    ensure_execution(project, execution)?;
    request
        .validate_in(project)
        .map_err(|_| StoreError::SddExecutionCrossProject {
            expected: project,
            found: request.project_id(),
        })?;
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_dispatch_manifests
             WHERE project_id = ?1 AND execution_id = ?2 AND request_id = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                request.to_string()
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let manifest: DispatchManifest = decode_row(&payload, MANIFEST_RECORD)?;
    if manifest.project_id() != project
        || manifest.execution_id() != execution
        || manifest.request_id() != request
    {
        return Err(StoreError::corrupt(
            "dispatch manifest row does not match its recorded identifiers",
        ));
    }
    Ok(Some(manifest))
}

fn load_budget_increment(
    conn: &Connection,
    project: ProjectId,
    execution: ExecutionId,
    revision: ExecutionRevision,
) -> Result<Option<BudgetIncrement>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM sdd_execution_budget_increments
             WHERE project_id = ?1 AND execution_id = ?2 AND revision = ?3",
            params![
                project.to_string(),
                execution.to_string(),
                sequence_to_sql(revision.get())?
            ],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let increment: BudgetIncrement = decode_row(&payload, BUDGET_RECORD)?;
    if increment.project_id() != project
        || increment.execution_id() != execution
        || increment.revision() != revision
    {
        return Err(StoreError::corrupt(
            "budget increment row does not match its recorded identifiers",
        ));
    }
    Ok(Some(increment))
}

impl From<StoreError> for SddExecutionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::StaleRevision {
                expected: Some(expected),
                found: Some(found),
                ..
            } => match (
                ExecutionRevision::new(expected),
                ExecutionRevision::new(found),
            ) {
                (Ok(expected), Ok(found)) => Self::RevisionConflict { expected, found },
                _ => Self::RecoveryRequired {
                    reason: herness_sdd_execute::RecoveryReason::StateUnreadable,
                    details: herness_sdd_execute::FailureDetails::none().boxed(),
                },
            },
            StoreError::StaleRevision { .. } => Self::Conflict {
                reason: herness_sdd_execute::ConflictReason::StaleRevision,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            StoreError::SddExecutionCrossProject { expected, found }
            | StoreError::CrossProjectReference { expected, found } => {
                Self::CrossProjectReference {
                    id_kind: "H4 record".to_owned(),
                    expected,
                    found,
                }
            }
            StoreError::SddExecutionRequestConflict {
                recorded, supplied, ..
            }
            | StoreError::HtmlSyncRequestConflict {
                recorded, supplied, ..
            } => Self::DuplicateRequestConflict { recorded, supplied },
            StoreError::SddExecutionRecordConflict { record, id } => {
                Self::DuplicateResultConflict {
                    request: format!("{record} {id}"),
                }
            }
            StoreError::SddExecutionFormat { .. } => Self::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::VersionMismatch,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            StoreError::UnsupportedSchemaVersion { .. } => Self::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::VersionMismatch,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            StoreError::SddExecutionInvalidCommit { detail } => Self::InvalidValue {
                field: "executionStore".to_owned(),
                detail,
            },
            StoreError::CorruptData { detail } | StoreError::Codec { detail } => {
                Self::InvalidValue {
                    field: "stored.execution".to_owned(),
                    detail,
                }
            }
            _other => Self::Unavailable {
                feature: "execution store".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
        }
    }
}

impl From<SddExecutionError> for StoreError {
    fn from(error: SddExecutionError) -> Self {
        match error {
            SddExecutionError::CrossProjectReference {
                id_kind,
                expected,
                found,
            } => {
                let _ = id_kind;
                Self::SddExecutionCrossProject { expected, found }
            }
            SddExecutionError::RevisionConflict { expected, found } => Self::StaleRevision {
                key: "execution snapshot".to_owned(),
                expected: Some(expected.get()),
                found: Some(found.get()),
            },
            SddExecutionError::DuplicateRequestConflict { recorded, supplied } => {
                Self::SddExecutionRequestConflict {
                    request: "request".to_owned(),
                    recorded,
                    supplied,
                }
            }
            SddExecutionError::DuplicateResultConflict { request } => {
                Self::SddExecutionRecordConflict {
                    record: "request",
                    id: request,
                }
            }
            SddExecutionError::UnsupportedContractVersion { found, expected } => {
                Self::SddExecutionFormat {
                    record: SNAPSHOT_RECORD,
                    found,
                    expected,
                }
            }
            SddExecutionError::InvalidSnapshot { field, detail } => {
                Self::SddExecutionInvalidCommit {
                    detail: format!("{field}: {detail}"),
                }
            }
            SddExecutionError::InvalidValue { field, detail } => Self::SddExecutionInvalidCommit {
                detail: format!("{field}: {detail}"),
            },
            other => Self::SddExecutionInvalidCommit {
                detail: other.to_string(),
            },
        }
    }
}

impl ExecutionStorePort for Store {
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, SddExecutionError> {
        Store::load_sdd_execution(self, project_id, execution_id).map_err(SddExecutionError::from)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        Store::compare_and_swap_execution(self, project_id, execution_id, expected_revision, next)
            .map_err(SddExecutionError::from)
    }

    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, SddExecutionError> {
        Store::sdd_dispatch_entry(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, SddExecutionError> {
        Store::sdd_git_entry(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, SddExecutionError> {
        Store::sdd_progress_entry(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<ControlRecord>, SddExecutionError> {
        Store::sdd_control_record(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn record_dispatch(&mut self, entry: &DispatchJournalEntry) -> Result<(), SddExecutionError> {
        Store::record_dispatch_entry(self, entry).map_err(SddExecutionError::from)
    }

    fn record_git(&mut self, entry: &GitJournalEntry) -> Result<(), SddExecutionError> {
        Store::record_git_entry(self, entry).map_err(SddExecutionError::from)
    }

    fn record_progress(&mut self, entry: &ProgressJournalEntry) -> Result<(), SddExecutionError> {
        Store::record_progress_entry(self, entry).map_err(SddExecutionError::from)
    }

    fn record_operation(&mut self, record: &ControlRecord) -> Result<(), SddExecutionError> {
        Store::record_control_record(self, record).map_err(SddExecutionError::from)
    }

    /// Durable override: one transaction writes the revision, the operation
    /// result, and the events, or nothing changes.
    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        Store::commit_execution_operation(
            self,
            project_id,
            execution_id,
            expected_revision,
            next,
            record,
        )
        .map_err(SddExecutionError::from)
    }
}

impl DurableExecutionStorePort for Store {
    fn record_approval(&mut self, approval: &ExecutionApproval) -> Result<(), SddExecutionError> {
        Store::record_sdd_approval(self, approval).map_err(SddExecutionError::from)
    }

    fn approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Store::sdd_approval(self, project_id, approval_id, revision)
            .map_err(SddExecutionError::from)
    }

    fn latest_approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Store::latest_sdd_approval(self, project_id, approval_id).map_err(SddExecutionError::from)
    }

    fn reserve_task(
        &mut self,
        reservation: &TaskReservation,
    ) -> Result<TaskReservation, SddExecutionError> {
        Store::reserve_sdd_task(self, reservation).map_err(SddExecutionError::from)
    }

    fn task_reservation(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<TaskReservation>, SddExecutionError> {
        Store::sdd_task_reservation(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn record_manifest(&mut self, manifest: &DispatchManifest) -> Result<(), SddExecutionError> {
        Store::record_sdd_manifest(self, manifest).map_err(SddExecutionError::from)
    }

    fn manifest(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchManifest>, SddExecutionError> {
        Store::sdd_manifest(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn record_budget_increment(
        &mut self,
        increment: &BudgetIncrement,
    ) -> Result<(), SddExecutionError> {
        Store::record_sdd_budget_increment(self, increment).map_err(SddExecutionError::from)
    }

    fn budget_increments(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<BudgetIncrement>, SddExecutionError> {
        Store::sdd_budget_increments(self, project_id, execution_id)
            .map_err(SddExecutionError::from)
    }
}

impl PlanChangeLatchStorePort for Store {
    fn plan_change_latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError> {
        Store::sdd_plan_change_latch(self, project_id, execution_id)
            .map_err(SddExecutionError::from)
    }

    fn record_plan_change_latch(
        &mut self,
        latch: &PlanChangeLatch,
    ) -> Result<(), SddExecutionError> {
        Store::record_sdd_plan_change_latch(self, latch).map_err(SddExecutionError::from)
    }
}

impl ApprovalRevisionStorePort for Store {
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        Store::record_sdd_approval(self, approval).map_err(SddExecutionError::from)
    }

    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Store::sdd_approval(self, project_id, approval_id, revision)
            .map_err(SddExecutionError::from)
    }

    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        Store::latest_sdd_approval(self, project_id, approval_id).map_err(SddExecutionError::from)
    }

    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        Store::sdd_approval_revisions(self, project_id, approval_id)
            .map_err(SddExecutionError::from)
    }
}

impl StartRecordStorePort for Store {
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        Store::sdd_start_record(self, project_id, execution_id, request_id)
            .map_err(SddExecutionError::from)
    }

    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: herness_sdd_execute::TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        Store::sdd_start_record_for_task(self, project_id, execution_id, task)
            .map_err(SddExecutionError::from)
    }

    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError> {
        Store::record_sdd_start_record(self, record).map_err(SddExecutionError::from)
    }
}

// ---------------------------------------------------------------------------
// Crash-recovery enumeration
// ---------------------------------------------------------------------------

/// Every row of one journal table of one execution, decoded and checked exactly
/// like the single-request loaders.
fn payloads(
    conn: &Connection,
    table: &str,
    project: ProjectId,
    execution: ExecutionId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    ensure_execution(project, execution)?;
    let sql = format!(
        "SELECT payload FROM {table} WHERE project_id = ?1 AND execution_id = ?2 ORDER BY created_at ASC, request_id ASC"
    );
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(params![project.to_string(), execution.to_string()])?;
    let mut payloads = Vec::new();
    while let Some(row) = rows.next()? {
        payloads.push(row.get::<_, Vec<u8>>(0)?);
    }
    Ok(payloads)
}

impl Store {
    /// Every stored execution snapshot, in project and execution order.
    pub fn sdd_stored_executions(&self) -> Result<Vec<StoredExecution>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT project_id, execution_id FROM sdd_execution_snapshots
             ORDER BY project_id ASC, execution_id ASC",
        )?;
        let mut rows = statement.query([])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            keys.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
        }
        let mut executions = Vec::with_capacity(keys.len());
        for (project, execution) in keys {
            let project: ProjectId = project
                .parse()
                .map_err(|_| StoreError::corrupt("stored execution project id is invalid"))?;
            let execution: ExecutionId = execution
                .parse()
                .map_err(|_| StoreError::corrupt("stored execution id is invalid"))?;
            if let Some(stored) = load_snapshot(&self.conn, project, execution)? {
                executions.push(stored);
            }
        }
        Ok(executions)
    }

    /// Every saved dispatch journal row of one execution.
    pub fn sdd_dispatch_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<DispatchJournalEntry>, StoreError> {
        let mut entries = Vec::new();
        for payload in payloads(&self.conn, "sdd_dispatch_journal", project_id, execution_id)? {
            let entry: DispatchJournalEntry = decode_row(&payload, DISPATCH_RECORD)?;
            let identity = entry.identity();
            if identity.project_id() != project_id || identity.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "dispatch journal row does not match its recorded identifiers",
                ));
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Every saved Git journal row of one execution.
    pub fn sdd_git_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<GitJournalEntry>, StoreError> {
        let mut entries = Vec::new();
        for payload in payloads(&self.conn, "sdd_git_journal", project_id, execution_id)? {
            let entry: GitJournalEntry = decode_row(&payload, GIT_RECORD)?;
            let identity = entry.identity();
            if identity.project_id() != project_id || identity.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "git journal row does not match its recorded identifiers",
                ));
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Every saved progress journal row of one execution.
    pub fn sdd_progress_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ProgressJournalEntry>, StoreError> {
        let mut entries = Vec::new();
        for payload in payloads(&self.conn, "sdd_progress_journal", project_id, execution_id)? {
            let entry: ProgressJournalEntry = decode_row(&payload, PROGRESS_RECORD)?;
            let identity = entry.identity();
            if identity.project_id() != project_id || identity.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "progress journal row does not match its recorded identifiers",
                ));
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Every saved control-operation row of one execution.
    pub fn sdd_control_records(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ControlRecord>, StoreError> {
        let mut records = Vec::new();
        for payload in payloads(&self.conn, "sdd_control_records", project_id, execution_id)? {
            let record: ControlRecord = decode_row(&payload, CONTROL_RECORD)?;
            let identity = record.identity();
            if identity.project_id() != project_id || identity.execution_id() != execution_id {
                return Err(StoreError::corrupt(
                    "control record row does not match its recorded identifiers",
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Every saved Task reservation of one execution.
    pub fn sdd_task_reservations(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<TaskReservation>, StoreError> {
        let mut reservations = Vec::new();
        for payload in payloads(
            &self.conn,
            "sdd_task_reservations",
            project_id,
            execution_id,
        )? {
            let reservation: TaskReservation = decode_row(&payload, RESERVATION_RECORD)?;
            if reservation.project_id() != project_id || reservation.execution_id() != execution_id
            {
                return Err(StoreError::corrupt(
                    "task reservation row does not match its recorded identifiers",
                ));
            }
            reservations.push(reservation);
        }
        Ok(reservations)
    }
}

impl RecoveryEnumerationPort for Store {
    fn stored_executions(&self) -> Result<Vec<StoredExecution>, SddExecutionError> {
        Store::sdd_stored_executions(self).map_err(SddExecutionError::from)
    }

    fn dispatch_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<DispatchJournalEntry>, SddExecutionError> {
        Store::sdd_dispatch_entries(self, project_id, execution_id).map_err(SddExecutionError::from)
    }

    fn git_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<GitJournalEntry>, SddExecutionError> {
        Store::sdd_git_entries(self, project_id, execution_id).map_err(SddExecutionError::from)
    }

    fn progress_entries(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ProgressJournalEntry>, SddExecutionError> {
        Store::sdd_progress_entries(self, project_id, execution_id).map_err(SddExecutionError::from)
    }

    fn control_records(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<ControlRecord>, SddExecutionError> {
        Store::sdd_control_records(self, project_id, execution_id).map_err(SddExecutionError::from)
    }

    fn task_reservations(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<TaskReservation>, SddExecutionError> {
        Store::sdd_task_reservations(self, project_id, execution_id)
            .map_err(SddExecutionError::from)
    }
}
