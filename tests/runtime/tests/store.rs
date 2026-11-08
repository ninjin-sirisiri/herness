//! Black-box tests for the host-owned SQLite store.
//!
//! These tests use temporary project and application-data directories only.
//! They exercise the public `StorePort` and the store's recovery-facing read
//! APIs; no engine, Tauri, or real credentials are involved.

use std::fs;
use std::path::{Path, PathBuf};

use herness_core::runtime::host_state_test_support;
use herness_core::*;
use herness_runtime_tests::fixtures::{ProjectFixture, second_project};
use herness_store::test_support::{
    CommitFault, MigrationFault, open_at_schema_version, open_with_migration_fault,
};
use herness_store::{
    FileObservation, OperationEvidence, OperationOutcome, OperationResult, Store, StoreConfig,
    StoreError,
};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

struct Harness {
    _temp: TempDir,
    project_root: PathBuf,
    config: StoreConfig,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let project_root = temp.path().join("project");
        fs::create_dir_all(&project_root).expect("project directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("app data root");
        config
            .ensure_outside_project(&project_root)
            .expect("app data root is outside the project");
        Self {
            _temp: temp,
            project_root,
            config,
        }
    }

    fn open(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }

    fn database_path(&self) -> PathBuf {
        self.config.database_path()
    }
}

fn checkpoint(fixture: &ProjectFixture, format_version: u32, payload: &[u8]) -> Checkpoint {
    Checkpoint::new(
        fixture.run_id,
        CheckpointFormatVersion::new(format_version).expect("non-zero checkpoint version"),
        CheckpointPayload::new(payload.to_vec()),
    )
}

fn draft(fixture: &ProjectFixture, kind: &str, occurred_at: u64) -> EventDraft {
    EventDraft::new(
        fixture.project_id,
        fixture.agent_id,
        fixture.session_id,
        fixture.run_id,
        None,
        EventKind::new(kind).expect("event kind"),
        Timestamp::from_unix_millis(occurred_at),
        EventPayload::new(json!({ "kind": kind })),
    )
    .expect("event draft")
}

fn write_arguments() -> ToolArguments {
    ToolArguments::Write(WriteArgs {
        path: NonEmptyText::new("notes.txt").expect("path"),
        content: "hello".to_owned(),
        rationale: Rationale::new("record the note").expect("rationale"),
    })
}

fn frozen_write(fixture: &ProjectFixture, operation: OperationId) -> FrozenOperation {
    FrozenOperation::new(
        operation,
        fixture.run_id,
        ToolName::Write,
        write_arguments(),
        fixture.cwd(),
        PolicyVersion::new(7).expect("policy version"),
        PermissionMode::Configured,
    )
    .expect("frozen operation")
}

fn intent(fixture: &ProjectFixture, operation: OperationId, recorded_at: u64) -> OperationIntent {
    OperationIntent::new(
        frozen_write(fixture, operation),
        Timestamp::from_unix_millis(recorded_at),
    )
}

fn commit(
    store: &mut Store,
    checkpoint: Checkpoint,
    operation: Option<OperationIntent>,
    events: Vec<EventDraft>,
) -> Result<CommitReceipt, CoreError> {
    store.commit_checkpoint(
        CheckpointCommit::new(checkpoint, operation, events).expect("valid checkpoint commit"),
    )
}

fn sequences(page: &HistoryPage) -> Vec<u64> {
    page.events().iter().map(Event::sequence).collect()
}

fn raw(path: &Path) -> Connection {
    Connection::open(path).expect("raw sqlite connection")
}

/// Writes one event in the schema-1/2/3 shape, before subject columns exist.
#[allow(clippy::too_many_arguments)]
fn insert_legacy_event(
    conn: &Connection,
    fixture: &ProjectFixture,
    sequence: u64,
    contract_version: u32,
    operation: Option<OperationId>,
    kind: &str,
    occurred_at: u64,
    payload: &str,
) {
    conn.execute(
        "INSERT INTO events (project_id, sequence, contract_version, agent_id, session_id,
                             run_id, operation_id, kind, occurred_at, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            fixture.project_id.to_string(),
            i64::try_from(sequence).unwrap(),
            i64::from(contract_version),
            fixture.agent_id.to_string(),
            fixture.session_id.to_string(),
            fixture.run_id.to_string(),
            operation.map(|operation| operation.to_string()),
            kind,
            i64::try_from(occurred_at).unwrap(),
            payload,
        ],
    )
    .expect("legacy event row");
}

type LegacyEventRow = (
    String,
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
);

fn legacy_event_rows(conn: &Connection) -> Vec<LegacyEventRow> {
    let mut statement = conn
        .prepare(
            "SELECT project_id, sequence, contract_version, agent_id, session_id, run_id,
                    operation_id, kind, occurred_at, payload
             FROM events ORDER BY sequence ASC",
        )
        .expect("legacy event query");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        })
        .expect("legacy event rows");
    rows.map(Result::unwrap).collect()
}

#[test]
fn checkpoint_operation_and_events_commit_atomically_and_reload_from_another_connection() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let operation = fixture.frozen_operation(ToolName::Write, write_arguments());
    let operation_id = operation.operation_id();
    let operation_intent =
        OperationIntent::new(operation, Timestamp::from_unix_millis(1_700_000_000_000));
    let checkpoint = checkpoint(&fixture, 1, b"alpha");
    let events = vec![
        draft(&fixture, "operation.requested", 1_700_000_000_001),
        draft(&fixture, "run.state_changed", 1_700_000_000_002),
    ];

    let mut store = harness.open();
    let receipt = commit(
        &mut store,
        checkpoint.clone(),
        Some(operation_intent.clone()),
        events,
    )
    .expect("commit");

    assert_eq!(receipt.max_sequence(), 2);
    assert_eq!(
        receipt
            .events()
            .iter()
            .map(Event::sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(receipt.events()[0].kind().as_str(), "operation.requested");
    assert_eq!(
        receipt.events()[1].payload().as_value(),
        &json!({ "kind": "run.state_changed" })
    );
    assert_eq!(
        store.load_checkpoint(&fixture.run_id).unwrap(),
        Some(checkpoint)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );
    assert_eq!(
        store.pending_operations(&fixture.project_id).unwrap(),
        vec![operation_intent.clone()]
    );
    assert_eq!(
        store.operation(&operation_id).unwrap().unwrap().intent(),
        &operation_intent
    );

    // A second connection sees only committed rows.
    let other = harness.open();
    assert_eq!(
        other.load_checkpoint(&fixture.run_id).unwrap(),
        store.load_checkpoint(&fixture.run_id).unwrap()
    );
    assert_eq!(
        sequences(
            &other
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );
    assert_eq!(
        other.pending_operations(&fixture.project_id).unwrap(),
        vec![operation_intent]
    );
    drop(other);
    drop(store);

    let reopened = harness.open();
    assert_eq!(
        sequences(
            &reopened
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );
}

#[test]
fn failed_commit_before_rows_and_before_commit_leaves_no_partial_rows() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let first_checkpoint = checkpoint(&fixture, 1, b"first");
    let first_intent = intent(&fixture, OperationId::new(fixture.project_id), 100);

    let mut store = harness.open();
    commit(
        &mut store,
        first_checkpoint.clone(),
        Some(first_intent.clone()),
        vec![draft(&fixture, "first", 1)],
    )
    .expect("first commit");

    let before_rows_checkpoint = checkpoint(&fixture, 1, b"before-rows");
    store.set_commit_fault(Some(CommitFault::BeforeRows));
    let error = commit(
        &mut store,
        before_rows_checkpoint,
        Some(intent(&fixture, OperationId::new(fixture.project_id), 200)),
        vec![draft(&fixture, "before-rows", 2)],
    )
    .expect_err("injected failure before rows");
    assert_eq!(
        error,
        CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable
        }
    );

    let before_commit_checkpoint = checkpoint(&fixture, 1, b"before-commit");
    store.set_commit_fault(Some(CommitFault::BeforeCommit));
    let error = commit(
        &mut store,
        before_commit_checkpoint,
        Some(intent(&fixture, OperationId::new(fixture.project_id), 300)),
        vec![draft(&fixture, "before-commit", 3)],
    )
    .expect_err("injected failure before commit");
    assert_eq!(
        error,
        CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable
        }
    );
    store.set_commit_fault(None);

    // No partial checkpoint, operation, event, or sequence row survived.
    assert_eq!(
        store.load_checkpoint(&fixture.run_id).unwrap(),
        Some(first_checkpoint)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );
    assert_eq!(
        store.pending_operations(&fixture.project_id).unwrap(),
        vec![first_intent]
    );

    // The failed attempts consumed no sequence numbers.
    let receipt = commit(
        &mut store,
        checkpoint(&fixture, 1, b"after-faults"),
        None,
        vec![draft(&fixture, "after-faults", 4)],
    )
    .expect("commit after clearing faults");
    assert_eq!(receipt.max_sequence(), 2);
    assert_eq!(receipt.events()[0].sequence(), 2);

    let other = harness.open();
    assert_eq!(
        sequences(
            &other
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );
    assert_eq!(
        other.pending_operations(&fixture.project_id).unwrap().len(),
        1
    );
}

#[test]
fn duplicate_operation_is_rejected_and_its_stored_result_is_readable() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let operation_id = OperationId::new(fixture.project_id);
    let operation_intent = intent(&fixture, operation_id, 100);
    let original_checkpoint = checkpoint(&fixture, 1, b"original");

    let mut store = harness.open();
    commit(
        &mut store,
        original_checkpoint.clone(),
        Some(operation_intent.clone()),
        vec![draft(&fixture, "operation.requested", 1)],
    )
    .expect("first commit");

    for _ in 0..2 {
        let error = commit(
            &mut store,
            checkpoint(&fixture, 1, b"duplicate"),
            Some(operation_intent.clone()),
            vec![draft(&fixture, "duplicate", 2)],
        )
        .expect_err("duplicate operation");
        assert_eq!(
            error,
            CoreError::DuplicateOperation {
                operation: operation_id
            }
        );
    }

    assert_eq!(
        store.load_checkpoint(&fixture.run_id).unwrap(),
        Some(original_checkpoint)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );
    assert_eq!(
        store.pending_operations(&fixture.project_id).unwrap(),
        vec![operation_intent]
    );

    let result = OperationResult::new(
        OperationOutcome::Applied,
        OperationEvidence::new(
            vec![FileObservation::new(
                fixture.cwd(),
                Some(FileVersion::new("before-hash").unwrap()),
                Some(FileVersion::new("after-hash").unwrap()),
            )],
            false,
        ),
        Timestamp::from_unix_millis(500),
    );
    store
        .record_operation_result(&operation_id, result.clone())
        .expect("record result");
    assert_eq!(
        store.operation(&operation_id).unwrap().unwrap().result(),
        Some(&result)
    );
    assert!(
        store
            .pending_operations(&fixture.project_id)
            .unwrap()
            .is_empty()
    );

    // A recorded operation is still a duplicate: it is not a new execution.
    let error = commit(
        &mut store,
        checkpoint(&fixture, 1, b"duplicate-after-result"),
        Some(OperationIntent::new(
            frozen_write(&fixture, operation_id),
            Timestamp::from_unix_millis(100),
        )),
        vec![draft(&fixture, "duplicate-after-result", 3)],
    )
    .expect_err("duplicate after result");
    assert_eq!(
        error,
        CoreError::DuplicateOperation {
            operation: operation_id
        }
    );
    assert_eq!(
        store.operation(&operation_id).unwrap().unwrap().result(),
        Some(&result)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );
}

#[test]
fn newer_schema_version_is_rejected_and_the_database_is_untouched() {
    let harness = Harness::new();
    let database = harness.database_path();
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    {
        let conn = raw(&database);
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             INSERT INTO schema_version (version) VALUES (999);
             CREATE TABLE canary (value TEXT NOT NULL);
             INSERT INTO canary (value) VALUES ('unchanged');",
        )
        .unwrap();
    }
    let before = fs::read(&database).unwrap();

    let error = Store::open(harness.config.clone()).expect_err("newer schema is rejected");
    assert!(matches!(
        error,
        StoreError::UnsupportedSchemaVersion {
            found: 999,
            supported: 7
        }
    ));
    assert_eq!(fs::read(&database).unwrap(), before);
    assert_eq!(
        raw(&database)
            .query_row("SELECT value FROM canary", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "unchanged"
    );
}

#[test]
fn foreign_database_without_a_schema_marker_is_rejected() {
    let harness = Harness::new();
    let database = harness.database_path();
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    {
        let conn = raw(&database);
        conn.execute_batch("CREATE TABLE unrelated (value TEXT NOT NULL);")
            .unwrap();
    }
    let before = fs::read(&database).unwrap();

    let error = Store::open(harness.config.clone()).expect_err("foreign database");
    assert!(matches!(error, StoreError::ForeignDatabase));
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[test]
fn unknown_checkpoint_and_event_versions_are_errors_not_dropped_rows() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let checkpoint = checkpoint(&fixture, 1, b"stored");

    {
        let mut store = harness.open();
        commit(
            &mut store,
            checkpoint.clone(),
            Some(intent(&fixture, OperationId::new(fixture.project_id), 100)),
            vec![draft(&fixture, "run.state_changed", 1)],
        )
        .expect("commit");
    }

    {
        let conn = raw(&harness.database_path());
        conn.execute("UPDATE checkpoints SET format_version = 99", [])
            .unwrap();
    }
    {
        let store = harness.open();
        let error = store.load_checkpoint(&fixture.run_id).unwrap_err();
        assert_eq!(
            error,
            CoreError::StoreUnavailable {
                failure: StoreFailureKind::UnsupportedVersion
            }
        );
    }
    assert_eq!(
        raw(&harness.database_path())
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );

    {
        let conn = raw(&harness.database_path());
        conn.execute("UPDATE events SET contract_version = 3", [])
            .unwrap();
    }
    {
        let store = harness.open();
        let error = store
            .history(HistoryQuery::first(fixture.project_id))
            .unwrap_err();
        assert_eq!(
            error,
            CoreError::UnknownContractVersion {
                found: 3,
                expected: 2
            }
        );
    }
    assert_eq!(
        raw(&harness.database_path())
            .query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn commit_with_an_unaccepted_checkpoint_format_writes_nothing() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let mut store = harness.open();

    let error = commit(
        &mut store,
        checkpoint(&fixture, 2, b"unsupported"),
        None,
        vec![draft(&fixture, "unsupported", 1)],
    )
    .expect_err("unsupported checkpoint format");
    assert_eq!(
        error,
        CoreError::StoreUnavailable {
            failure: StoreFailureKind::UnsupportedVersion
        }
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        Vec::<u64>::new()
    );
    assert_eq!(store.load_checkpoint(&fixture.run_id).unwrap(), None);
}

#[test]
fn failing_migration_rolls_back_and_preserves_the_existing_database() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let stored_checkpoint = checkpoint(&fixture, 1, b"before-migration-failure");

    {
        let store =
            open_at_schema_version(harness.config.clone(), 1).expect("open schema version 1");
        assert_eq!(store.schema_version().unwrap(), 1);
    }
    {
        let conn = raw(&harness.database_path());
        conn.execute(
            "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                fixture.run_id.to_string(),
                fixture.project_id.to_string(),
                1_i64,
                stored_checkpoint.payload().as_bytes(),
                1_i64,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, ?2)",
            rusqlite::params![fixture.project_id.to_string(), 2_i64],
        )
        .unwrap();
        insert_legacy_event(
            &conn,
            &fixture,
            1,
            1,
            None,
            "before-migration",
            1,
            r#"{"legacy":true}"#,
        );
    }

    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 2,
            statements: 1,
        },
    )
    .expect_err("migration failure");
    assert!(matches!(
        error,
        StoreError::InjectedFault {
            point: "migration-after-statement"
        }
    ));

    {
        let conn = raw(&harness.database_path());
        let version: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let indexes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index'
                 AND name IN ('checkpoints_by_project', 'events_by_run')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 0);
        let events: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events, 1);
    }

    let mut reopened = harness.open();
    assert_eq!(reopened.schema_version().unwrap(), 7);
    assert_eq!(
        reopened.load_checkpoint(&fixture.run_id).unwrap(),
        Some(stored_checkpoint)
    );
    assert_eq!(
        sequences(
            &reopened
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );
    let receipt = commit(
        &mut reopened,
        checkpoint(&fixture, 1, b"after-migration"),
        None,
        vec![draft(&fixture, "after-migration", 2)],
    )
    .expect("commit after migration");
    assert_eq!(receipt.events()[0].sequence(), 2);
}

#[test]
fn failing_first_migration_on_a_fresh_database_leaves_no_partial_schema() {
    let harness = Harness::new();
    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 1,
            statements: 2,
        },
    )
    .expect_err("fresh migration failure");
    assert!(matches!(
        error,
        StoreError::InjectedFault {
            point: "migration-after-statement"
        }
    ));

    {
        let conn = raw(&harness.database_path());
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

    let store = harness.open();
    assert_eq!(store.schema_version().unwrap(), 7);
}

#[test]
fn history_pages_fix_the_first_cursor_and_reject_foreign_project_cursors() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let other = second_project();
    let mut store = harness.open();

    commit(
        &mut store,
        checkpoint(&fixture, 1, b"history"),
        None,
        (1..=5)
            .map(|at| draft(&fixture, "initial", at))
            .collect::<Vec<_>>(),
    )
    .expect("initial history commit");

    let limit = HistoryLimit::new(2).unwrap();
    let first = store
        .history(HistoryQuery::new(fixture.project_id, None, limit).unwrap())
        .expect("first page");
    assert_eq!(sequences(&first), vec![5, 4]);
    let cursor = first.next_cursor().expect("next cursor");
    assert_eq!(cursor.project_id(), fixture.project_id);
    assert_eq!(cursor.before_sequence(), 4);

    // Events added between pages must not enter a page already in progress.
    commit(
        &mut store,
        checkpoint(&fixture, 1, b"history-new"),
        None,
        (6..=7)
            .map(|at| draft(&fixture, "added-between-pages", at))
            .collect::<Vec<_>>(),
    )
    .expect("append between pages");

    let second = store
        .history(HistoryQuery::new(fixture.project_id, Some(cursor), limit).unwrap())
        .expect("second page");
    assert_eq!(sequences(&second), vec![3, 2]);
    assert_eq!(second.next_cursor().unwrap().before_sequence(), 2);

    let third = store
        .history(HistoryQuery::new(fixture.project_id, second.next_cursor(), limit).unwrap())
        .expect("third page");
    assert_eq!(sequences(&third), vec![1]);
    assert_eq!(third.next_cursor(), None);

    // Re-reading the same page is stable; the new events only appear in live
    // replay or a fresh first page.
    let second_again = store
        .history(HistoryQuery::new(fixture.project_id, Some(cursor), limit).unwrap())
        .unwrap();
    assert_eq!(sequences(&second_again), vec![3, 2]);
    let fresh = store
        .history(HistoryQuery::new(fixture.project_id, None, limit).unwrap())
        .unwrap();
    assert_eq!(sequences(&fresh), vec![7, 6]);

    // A cursor minted for another project is rejected, including on the wire.
    let error = HistoryQuery::new(other.project_id, Some(cursor), limit).unwrap_err();
    assert!(matches!(
        error,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Project,
            expected,
            found,
        } if expected == other.project_id && found == fixture.project_id
    ));
    let mismatched = json!({
        "projectId": other.project_id.to_string(),
        "cursor": {
            "projectId": fixture.project_id.to_string(),
            "beforeSequence": 4
        },
        "limit": 100
    });
    assert!(serde_json::from_value::<HistoryQuery>(mismatched).is_err());

    // Live replay is ascending after a sequence and is independent of paging.
    let replay = store
        .events_after(&fixture.project_id, None, HistoryLimit::new(10).unwrap())
        .unwrap();
    assert_eq!(
        replay.iter().map(Event::sequence).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7]
    );
    let replay_after = store
        .events_after(&fixture.project_id, Some(4), HistoryLimit::new(10).unwrap())
        .unwrap();
    assert_eq!(
        replay_after.iter().map(Event::sequence).collect::<Vec<_>>(),
        vec![5, 6, 7]
    );
    let replay_again = store
        .events_after(&fixture.project_id, Some(4), HistoryLimit::new(10).unwrap())
        .unwrap();
    assert_eq!(replay_after, replay_again);
    assert!(matches!(
        store.events_after(&fixture.project_id, Some(0), HistoryLimit::new(10).unwrap()),
        Err(StoreError::InvalidLiveCursor)
    ));
}

#[test]
fn unresolved_operations_distinguish_applied_not_applied_and_unverifiable() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let operations = (0..4)
        .map(|_| OperationId::new(fixture.project_id))
        .collect::<Vec<_>>();

    let mut store = harness.open();
    for (index, operation) in operations.iter().enumerate() {
        let at = 1_000 + index as u64 * 1_000;
        commit(
            &mut store,
            checkpoint(&fixture, 1, format!("intent-{index}").as_bytes()),
            Some(OperationIntent::new(
                frozen_write(&fixture, *operation),
                Timestamp::from_unix_millis(at),
            )),
            vec![draft(&fixture, "operation.requested", at + 1)],
        )
        .expect("intent commit");
    }

    let applied = OperationResult::new(
        OperationOutcome::Applied,
        OperationEvidence::new(
            vec![FileObservation::new(
                fixture.cwd(),
                Some(FileVersion::new("before").unwrap()),
                Some(FileVersion::new("after").unwrap()),
            )],
            false,
        ),
        Timestamp::from_unix_millis(5_000),
    );
    let not_applied = OperationResult::new(
        OperationOutcome::NotApplied,
        OperationEvidence::new(
            vec![FileObservation::new(
                fixture.cwd(),
                Some(FileVersion::new("before").unwrap()),
                None,
            )],
            false,
        ),
        Timestamp::from_unix_millis(6_000),
    );
    let unverifiable = OperationResult::new(
        OperationOutcome::Unverifiable,
        OperationEvidence::new(Vec::new(), true),
        Timestamp::from_unix_millis(7_000),
    );

    store
        .record_operation_result(&operations[0], applied.clone())
        .expect("applied result");
    store
        .record_operation_result(&operations[1], not_applied.clone())
        .expect("not applied result");
    store
        .record_operation_result(&operations[3], unverifiable.clone())
        .expect("unverifiable result");

    // The port returns only intents without any result.
    let pending = store.pending_operations(&fixture.project_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation().operation_id(), operations[2]);

    let unresolved = store.unresolved_operations(&fixture.project_id).unwrap();
    assert_eq!(
        unresolved
            .iter()
            .map(|record| record.intent().operation().operation_id())
            .collect::<Vec<_>>(),
        vec![operations[2], operations[3]]
    );
    assert!(unresolved[0].is_pending());
    assert!(unresolved[1].is_unresolved());
    assert_eq!(
        unresolved[1].result().unwrap().outcome(),
        OperationOutcome::Unverifiable
    );
    assert!(
        unresolved[1]
            .result()
            .unwrap()
            .evidence()
            .shell_outcome_unknown()
    );

    let applied_record = store.operation(&operations[0]).unwrap().unwrap();
    assert_eq!(applied_record.result(), Some(&applied));
    assert_eq!(
        applied_record.result().unwrap().evidence().files()[0]
            .before_version()
            .unwrap()
            .as_str(),
        "before"
    );
    assert_eq!(
        applied_record.result().unwrap().evidence().files()[0]
            .after_version()
            .unwrap()
            .as_str(),
        "after"
    );
    assert_eq!(
        store.operation(&operations[1]).unwrap().unwrap().result(),
        Some(&not_applied)
    );

    // Re-recording the same result is idempotent; a different result conflicts.
    assert_eq!(
        store
            .record_operation_result(&operations[0], applied.clone())
            .unwrap()
            .result(),
        Some(&applied)
    );
    let conflicting = OperationResult::new(
        OperationOutcome::NotApplied,
        OperationEvidence::empty(),
        Timestamp::from_unix_millis(8_000),
    );
    assert!(matches!(
        store.record_operation_result(&operations[0], conflicting),
        Err(StoreError::OperationResultConflict { .. })
    ));
    assert!(matches!(
        store.record_operation_result(&OperationId::new(fixture.project_id), applied),
        Err(StoreError::UnknownOperation { .. })
    ));

    // Recovery reads are repeatable and have no execution side effects.
    let first_read = store.unresolved_operations(&fixture.project_id).unwrap();
    let second_read = store.unresolved_operations(&fixture.project_id).unwrap();
    assert_eq!(first_read, second_read);
    assert_eq!(
        store.pending_operations(&fixture.project_id).unwrap().len(),
        1
    );
}

#[test]
fn opening_and_migrating_touches_only_the_configured_database_file() {
    let harness = Harness::new();
    fs::create_dir_all(harness.config.app_data_root()).unwrap();
    let sibling = harness.config.app_data_root().join("unrelated.sqlite3");
    {
        let conn = raw(&sibling);
        conn.execute_batch(
            "CREATE TABLE canary (value TEXT NOT NULL);
             INSERT INTO canary (value) VALUES ('unchanged');",
        )
        .unwrap();
    }
    let before = fs::read(&sibling).unwrap();

    let store = harness.open();
    assert_eq!(store.schema_version().unwrap(), 7);
    drop(store);

    assert_eq!(fs::read(&sibling).unwrap(), before);
    assert_eq!(
        raw(&sibling)
            .query_row("SELECT value FROM canary", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "unchanged"
    );
}

#[test]
fn store_location_is_outside_the_project_and_private() {
    let harness = Harness::new();

    assert!(matches!(
        StoreConfig::new("app-data"),
        Err(StoreError::InvalidConfig {
            violation: herness_store::ConfigViolation::NotAbsolute
        })
    ));
    assert!(matches!(
        StoreConfig::new(harness.project_root.join("app-data"))
            .unwrap()
            .ensure_outside_project(&harness.project_root),
        Err(StoreError::InvalidConfig {
            violation: herness_store::ConfigViolation::InsideProject
        })
    ));

    let resolved = harness.config.database_path();
    assert!(resolved.starts_with(harness.config.app_data_root()));
    assert!(!resolved.starts_with(&harness.project_root));
    assert_ne!(resolved, harness.project_root);
    assert_ne!(resolved, harness.project_root.join("herness.sqlite3"));

    let store = harness.open();
    assert!(store.schema_version().unwrap() >= 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let database_mode = fs::metadata(&resolved).unwrap().permissions().mode() & 0o777;
        assert_eq!(database_mode, 0o600);
        let root_mode = fs::metadata(harness.config.app_data_root())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
    }
}

#[test]
fn sequences_are_monotonic_per_project_and_independent_of_other_projects() {
    let harness = Harness::new();
    let first = ProjectFixture::new();
    let second = second_project();
    let mut store = harness.open();

    let receipt = commit(
        &mut store,
        checkpoint(&first, 1, b"a1"),
        None,
        vec![draft(&first, "first", 1), draft(&first, "second", 2)],
    )
    .expect("first project commit");
    assert_eq!(
        receipt
            .events()
            .iter()
            .map(Event::sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    let receipt = commit(
        &mut store,
        checkpoint(&second, 1, b"b1"),
        None,
        vec![draft(&second, "other-project", 1)],
    )
    .expect("second project commit");
    assert_eq!(receipt.events()[0].sequence(), 1);

    let receipt = commit(
        &mut store,
        checkpoint(&first, 1, b"a2"),
        None,
        vec![draft(&first, "third", 3)],
    )
    .expect("first project second commit");
    assert_eq!(receipt.events()[0].sequence(), 3);

    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(first.project_id))
                .unwrap()
        ),
        vec![3, 2, 1]
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(second.project_id))
                .unwrap()
        ),
        vec![1]
    );

    // A second run in the same project continues the project sequence.
    let second_run = RunId::new(first.project_id);
    let second_checkpoint = Checkpoint::new(
        second_run,
        CheckpointFormatVersion::new(1).unwrap(),
        CheckpointPayload::new(b"second-run".to_vec()),
    );
    let receipt = commit(
        &mut store,
        second_checkpoint.clone(),
        None,
        vec![
            EventDraft::new(
                first.project_id,
                first.agent_id,
                first.session_id,
                second_run,
                None,
                EventKind::new("second-run").unwrap(),
                Timestamp::from_unix_millis(4),
                EventPayload::new(json!({})),
            )
            .unwrap(),
        ],
    )
    .expect("second run commit");
    assert_eq!(receipt.events()[0].sequence(), 4);
    assert_eq!(
        store
            .load_checkpoint_record(&second_run)
            .unwrap()
            .unwrap()
            .last_sequence(),
        4
    );
    assert_eq!(
        store
            .load_checkpoint_record(&first.run_id)
            .unwrap()
            .unwrap()
            .last_sequence(),
        3
    );
}

#[test]
fn operation_policy_version_and_permission_mode_survive_the_transaction() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let operation_id = OperationId::new(fixture.project_id);
    let frozen = FrozenOperation::new(
        operation_id,
        fixture.run_id,
        ToolName::Write,
        write_arguments(),
        fixture.cwd(),
        PolicyVersion::new(11).unwrap(),
        PermissionMode::Automatic,
    )
    .unwrap();
    let recorded = OperationIntent::new(frozen.clone(), Timestamp::from_unix_millis(42));

    let mut store = harness.open();
    commit(
        &mut store,
        checkpoint(&fixture, 1, b"policy"),
        Some(recorded.clone()),
        Vec::new(),
    )
    .expect("commit intent");

    let pending = store.pending_operations(&fixture.project_id).unwrap();
    assert_eq!(pending, vec![recorded]);
    assert_eq!(pending[0].operation().policy_version().get(), 11);
    assert_eq!(
        pending[0].operation().permission_mode(),
        PermissionMode::Automatic
    );
    assert_eq!(pending[0].operation(), &frozen);
}

#[test]
fn checkpoint_only_commits_keep_the_last_project_sequence() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let mut store = harness.open();

    let first_checkpoint = checkpoint(&fixture, 1, b"empty");
    let receipt = commit(&mut store, first_checkpoint.clone(), None, Vec::new())
        .expect("checkpoint-only commit");
    assert!(receipt.events().is_empty());
    assert_eq!(receipt.max_sequence(), 0);
    assert_eq!(
        store
            .load_checkpoint_record(&fixture.run_id)
            .unwrap()
            .unwrap()
            .last_sequence(),
        0
    );

    commit(
        &mut store,
        checkpoint(&fixture, 1, b"with-event"),
        None,
        vec![draft(&fixture, "event", 1)],
    )
    .expect("event commit");

    let second_checkpoint = checkpoint(&fixture, 1, b"updated");
    let receipt = commit(&mut store, second_checkpoint.clone(), None, Vec::new())
        .expect("checkpoint-only update");
    assert_eq!(receipt.max_sequence(), 0);
    let loaded = store
        .load_checkpoint_record(&fixture.run_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.checkpoint(), &second_checkpoint);
    assert_eq!(loaded.last_sequence(), 1);
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );
}

#[test]
fn schema_three_v1_history_is_preserved_exactly_with_its_ids_sequence_and_payload() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let operation = OperationId::new(fixture.project_id);
    let stored_checkpoint = checkpoint(&fixture, 1, b"legacy-checkpoint");

    {
        let store =
            open_at_schema_version(harness.config.clone(), 3).expect("open schema version 3");
        assert_eq!(store.schema_version().unwrap(), 3);
    }
    let before = {
        let conn = raw(&harness.database_path());
        conn.execute(
            "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                fixture.run_id.to_string(),
                fixture.project_id.to_string(),
                1_i64,
                stored_checkpoint.payload().as_bytes(),
                2_i64,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, ?2)",
            rusqlite::params![fixture.project_id.to_string(), 3_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO operations (operation_id, project_id, run_id, tool, arguments, cwd,
                                     policy_version, permission_mode, recorded_at)
             VALUES (?1, ?2, ?3, 'write', ?4, ?5, 7, 'configured', 10)",
            rusqlite::params![
                operation.to_string(),
                fixture.project_id.to_string(),
                fixture.run_id.to_string(),
                serde_json::to_string(&write_arguments()).unwrap(),
                fixture.cwd().as_str(),
            ],
        )
        .unwrap();
        insert_legacy_event(
            &conn,
            &fixture,
            1,
            1,
            None,
            "run.state_changed",
            1_000,
            r#"{"legacy":1}"#,
        );
        insert_legacy_event(
            &conn,
            &fixture,
            2,
            2,
            Some(operation),
            "operation.requested",
            2_000,
            r#"{"legacy":2}"#,
        );
        conn.execute(
            "INSERT INTO host_state (key, value) VALUES (?1, ?2)",
            rusqlite::params!["herness.runtime.host-state", b"opaque-state".as_slice()],
        )
        .unwrap();
        legacy_event_rows(&conn)
    };

    let mut store = harness.open();
    assert_eq!(store.schema_version().unwrap(), 7);

    {
        let conn = raw(&harness.database_path());
        assert_eq!(legacy_event_rows(&conn), before);
        assert_eq!(before.len(), 2);

        let subjects: Vec<(String, Option<String>, Option<String>)> = conn
            .prepare(
                "SELECT subject_type, activity_kind, activity_id
                 FROM events ORDER BY sequence ASC",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            subjects,
            vec![
                ("run".to_owned(), None, None),
                ("run".to_owned(), None, None)
            ]
        );

        let indexes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index'
                 AND name IN ('checkpoints_by_project', 'events_by_run', 'events_by_activity')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 3);
        let next_sequence: i64 = conn
            .query_row(
                "SELECT next_sequence FROM project_sequences WHERE project_id = ?1",
                [fixture.project_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(next_sequence, 3);
        let host_state: Vec<u8> = conn
            .query_row(
                "SELECT value FROM host_state WHERE key = 'herness.runtime.host-state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(host_state, b"opaque-state");
    }

    let page = store
        .history(HistoryQuery::first(fixture.project_id))
        .expect("history after migration");
    assert_eq!(sequences(&page), vec![2, 1]);

    let legacy = &page.events()[1];
    assert_eq!(legacy.contract_version(), ContractVersion::V1);
    let run = legacy
        .run_subject()
        .expect("v1 event keeps its run subject");
    assert_eq!(run.project_id(), fixture.project_id);
    assert_eq!(run.agent_id(), fixture.agent_id);
    assert_eq!(run.session_id(), fixture.session_id);
    assert_eq!(run.run_id(), fixture.run_id);
    assert_eq!(legacy.sequence(), 1);
    assert_eq!(legacy.kind().as_str(), "run.state_changed");
    assert_eq!(legacy.occurred_at().as_unix_millis(), 1_000);
    assert_eq!(legacy.payload().as_value(), &json!({ "legacy": 1 }));
    let legacy_wire = serde_json::to_value(legacy).unwrap();
    assert_eq!(legacy_wire["contractVersion"], 1);
    assert_eq!(legacy_wire["runId"], fixture.run_id.to_string());
    assert_eq!(legacy_wire["sequence"], 1);
    assert!(legacy_wire.get("subject").is_none());

    let current = &page.events()[0];
    assert_eq!(current.contract_version(), ContractVersion::V2);
    assert_eq!(current.operation_id(), Some(operation));
    assert_eq!(current.payload().as_value(), &json!({ "legacy": 2 }));

    assert_eq!(
        store.load_checkpoint(&fixture.run_id).unwrap(),
        Some(stored_checkpoint)
    );
    assert_eq!(
        store
            .load_checkpoint_record(&fixture.run_id)
            .unwrap()
            .unwrap()
            .last_sequence(),
        2
    );
    let expected_intent = OperationIntent::new(
        frozen_write(&fixture, operation),
        Timestamp::from_unix_millis(10),
    );
    assert_eq!(
        store.operation(&operation).unwrap().unwrap().intent(),
        &expected_intent
    );

    // The migrated sequence space continues without reuse or gaps.
    let receipt = store
        .append_events(vec![draft(&fixture, "after-migration", 3_000)])
        .expect("append after migration");
    assert_eq!(receipt.events()[0].sequence(), 3);
}

#[test]
fn host_activity_events_share_the_project_sequence_and_store_no_fake_run_ids() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let activity = HostActivityId::new(fixture.project_id);
    let activity_kind = EventKind::new("supervision").expect("activity kind");

    let mut store = harness.open();
    let receipt = commit(
        &mut store,
        checkpoint(&fixture, 1, b"run-started"),
        None,
        vec![draft(&fixture, "run.started", 1)],
    )
    .expect("run event commit");
    assert_eq!(receipt.events()[0].sequence(), 1);

    let started = EventDraft::for_host_activity(
        fixture.project_id,
        activity_kind.clone(),
        activity,
        EventKind::new("supervision.started").expect("event kind"),
        Timestamp::from_unix_millis(2),
        EventPayload::new(json!({ "phase": "started" })),
    )
    .expect("host activity draft");
    let receipt = store
        .append_events(vec![started])
        .expect("host activity append");
    assert_eq!(receipt.events()[0].sequence(), 2);
    let subject = receipt.events()[0]
        .subject()
        .host_activity()
        .expect("activity subject");
    assert_eq!(subject.project_id(), fixture.project_id);
    assert_eq!(subject.activity_kind().as_str(), "supervision");
    assert_eq!(subject.activity_id(), activity);
    assert_eq!(receipt.events()[0].run_id(), None);
    assert_eq!(receipt.events()[0].operation_id(), None);

    // Run and activity events in one transaction consume one shared sequence.
    let assessing = EventDraft::for_host_activity(
        fixture.project_id,
        activity_kind,
        activity,
        EventKind::new("supervision.assessing").expect("event kind"),
        Timestamp::from_unix_millis(3),
        EventPayload::new(json!({ "phase": "assessing" })),
    )
    .expect("host activity draft");
    let receipt = store
        .append_events(vec![assessing, draft(&fixture, "run.idle", 4)])
        .expect("mixed append");
    assert_eq!(
        receipt
            .events()
            .iter()
            .map(Event::sequence)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );

    {
        let conn = raw(&harness.database_path());
        let row: (
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT agent_id, session_id, run_id, activity_kind, activity_id
                 FROM events WHERE project_id = ?1 AND sequence = 2",
                [fixture.project_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, None);
        assert_eq!(row.1, None);
        assert_eq!(row.2, None);
        assert_eq!(row.3, "supervision");
        assert_eq!(row.4, activity.to_string());
    }

    // Another connection sees only committed rows, including both subjects.
    let other = harness.open();
    let replay = other
        .events_after(
            &fixture.project_id,
            None,
            HistoryLimit::new(10).expect("limit"),
        )
        .expect("replay");
    assert_eq!(
        replay.iter().map(Event::sequence).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(replay[0].run_subject().is_some());
    assert!(replay[1].subject().host_activity().is_some());
    assert!(replay[2].subject().host_activity().is_some());
    assert!(replay[3].run_subject().is_some());

    drop(other);
    drop(store);
    let mut reopened = harness.open();
    let receipt = reopened
        .append_events(vec![draft(&fixture, "after-reopen", 5)])
        .expect("append after reopen");
    assert_eq!(receipt.events()[0].sequence(), 5);
}

#[test]
fn failed_event_subject_and_request_migrations_roll_back_to_schema_three() {
    for (version, statements) in [(4_u32, 1_usize), (4, 4), (5, 1)] {
        let harness = Harness::new();
        let fixture = ProjectFixture::new();
        let stored_checkpoint = checkpoint(&fixture, 1, b"before-fault");

        {
            let store =
                open_at_schema_version(harness.config.clone(), 3).expect("open schema version 3");
            assert_eq!(store.schema_version().unwrap(), 3);
        }
        let before = {
            let conn = raw(&harness.database_path());
            conn.execute(
                "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
                 VALUES (?1, ?2, 1, ?3, 1)",
                rusqlite::params![
                    fixture.run_id.to_string(),
                    fixture.project_id.to_string(),
                    stored_checkpoint.payload().as_bytes(),
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, 2)",
                [fixture.project_id.to_string()],
            )
            .unwrap();
            insert_legacy_event(
                &conn,
                &fixture,
                1,
                2,
                None,
                "operation.requested",
                777,
                r#"{"fault":true}"#,
            );
            legacy_event_rows(&conn)
        };

        let error = open_with_migration_fault(
            harness.config.clone(),
            MigrationFault::AfterStatements {
                version,
                statements,
            },
        )
        .expect_err("injected migration failure");
        assert!(matches!(
            error,
            StoreError::InjectedFault {
                point: "migration-after-statement"
            }
        ));

        {
            let conn = raw(&harness.database_path());
            let stored_version: i64 = conn
                .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored_version, 3, "fault version {version}");
            assert_eq!(legacy_event_rows(&conn), before);
            let subject_columns: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('events')
                     WHERE name IN ('subject_type', 'activity_kind', 'activity_id')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(subject_columns, 0);
            let new_tables: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
                     AND name IN ('model_requests', 'supervised_state')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(new_tables, 0);
            let event_index: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index'
                     AND name = 'events_by_run'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(event_index, 1);
        }

        let mut reopened = harness.open();
        assert_eq!(reopened.schema_version().unwrap(), 7);
        assert_eq!(
            reopened.load_checkpoint(&fixture.run_id).unwrap(),
            Some(stored_checkpoint)
        );
        assert_eq!(
            sequences(
                &reopened
                    .history(HistoryQuery::first(fixture.project_id))
                    .unwrap()
            ),
            vec![1]
        );
        let receipt = reopened
            .append_events(vec![draft(&fixture, "after-recovery", 2)])
            .expect("append after recovery");
        assert_eq!(receipt.events()[0].sequence(), 2);
    }
}

#[test]
fn older_build_target_cannot_migrate_a_newer_database_down() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    {
        let mut store = harness.open();
        assert_eq!(store.schema_version().unwrap(), 7);
        store
            .append_events(vec![draft(&fixture, "run.started", 11)])
            .expect("event before downgrade attempt");
    }

    let error = open_at_schema_version(harness.config.clone(), 3)
        .expect_err("an older schema target must not rewrite a newer database");
    assert!(matches!(
        error,
        StoreError::MigrationFailed { version: 7, .. }
    ));

    let conn = raw(&harness.database_path());
    let version: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 7);
    assert_eq!(legacy_event_rows(&conn).len(), 1);
    assert_eq!(
        conn.query_row(
            "SELECT payload FROM events WHERE project_id = ?1 AND sequence = 1",
            [fixture.project_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        r#"{"kind":"run.started"}"#
    );
}

#[test]
fn supervised_state_compare_and_swap_rejects_stale_revisions() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let other = second_project();
    let key = "supervision/one";

    let mut store = harness.open();
    assert_eq!(
        store.supervised_state(&fixture.project_id, key).unwrap(),
        None
    );

    let (record, receipt) = store
        .compare_and_swap_supervised_state(
            &fixture.project_id,
            key,
            None,
            b"version-1",
            Timestamp::from_unix_millis(10),
            vec![draft(&fixture, "state.created", 1)],
        )
        .expect("create state");
    assert_eq!(record.revision(), 1);
    assert_eq!(record.value(), b"version-1");
    assert_eq!(receipt.events()[0].sequence(), 1);

    let error = store
        .compare_and_swap_supervised_state(
            &fixture.project_id,
            key,
            None,
            b"duplicate-create",
            Timestamp::from_unix_millis(11),
            vec![draft(&fixture, "state.duplicate", 2)],
        )
        .expect_err("creation over an existing row is stale");
    assert!(matches!(
        error,
        StoreError::StaleRevision {
            expected: None,
            found: Some(1),
            ..
        }
    ));
    assert_eq!(
        store.supervised_state(&fixture.project_id, key).unwrap(),
        Some(record.clone())
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );

    let (record, receipt) = store
        .compare_and_swap_supervised_state(
            &fixture.project_id,
            key,
            Some(1),
            b"version-2",
            Timestamp::from_unix_millis(12),
            vec![draft(&fixture, "state.updated", 3)],
        )
        .expect("update state");
    assert_eq!(record.revision(), 2);
    assert_eq!(receipt.events()[0].sequence(), 2);

    let error = store
        .compare_and_swap_supervised_state(
            &fixture.project_id,
            key,
            Some(1),
            b"stale-write",
            Timestamp::from_unix_millis(13),
            vec![draft(&fixture, "state.stale", 4)],
        )
        .expect_err("stale revision is rejected");
    assert!(matches!(
        error,
        StoreError::StaleRevision {
            expected: Some(1),
            found: Some(2),
            ..
        }
    ));
    assert_eq!(
        store.supervised_state(&fixture.project_id, key).unwrap(),
        Some(record)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );

    let error = store
        .compare_and_swap_supervised_state(
            &fixture.project_id,
            key,
            Some(2),
            b"wrong-project-event",
            Timestamp::from_unix_millis(14),
            vec![draft(&other, "state.cross-project", 5)],
        )
        .expect_err("cross-project events are rejected");
    assert!(matches!(error, StoreError::CrossProjectReference { .. }));
    assert!(matches!(
        store.compare_and_swap_supervised_state(
            &fixture.project_id,
            " ",
            Some(2),
            b"empty-key",
            Timestamp::from_unix_millis(15),
            Vec::new(),
        ),
        Err(StoreError::InvalidStateKey)
    ));

    let other_connection = harness.open();
    let loaded = other_connection
        .supervised_state(&fixture.project_id, key)
        .unwrap()
        .expect("committed state");
    assert_eq!(loaded.revision(), 2);
    assert_eq!(loaded.value(), b"version-2");
    assert_eq!(
        other_connection
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(10).expect("limit"),
            )
            .unwrap()
            .iter()
            .map(Event::sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn model_request_intent_and_observation_survive_reopen_without_duplicate_sends() {
    let harness = Harness::new();
    let fixture = ProjectFixture::new();
    let request = RequestId::new(fixture.project_id);
    let attempt = AttemptId::new(fixture.project_id);
    let connection = ConnectionId::new();
    let subject = EventSubject::Run(
        RunSubject::new(
            fixture.project_id,
            fixture.agent_id,
            fixture.session_id,
            fixture.run_id,
        )
        .unwrap(),
    );
    let intent = RequestGateIntent::new(
        request,
        attempt,
        connection,
        RequestPurpose::new("completion-assessment").unwrap(),
        subject,
        StopDeadlineControl::stopped(StopReason::UserRequest),
    )
    .expect("request intent");

    let mut store = harness.open();
    let (record, receipt) = store
        .record_model_request_with_events(
            intent.clone(),
            Timestamp::from_unix_millis(20),
            vec![draft(&fixture, "request.intent", 1)],
        )
        .expect("record intent");
    assert_eq!(record.intent(), &intent);
    assert_eq!(record.recorded_at(), Timestamp::from_unix_millis(20));
    assert!(record.observation().is_none());
    assert_eq!(receipt.events()[0].sequence(), 1);

    // An identical duplicate returns the original row and appends nothing.
    let (duplicate, duplicate_receipt) = store
        .record_model_request_with_events(
            intent.clone(),
            Timestamp::from_unix_millis(21),
            vec![draft(&fixture, "request.duplicate", 2)],
        )
        .expect("duplicate intent");
    assert_eq!(duplicate, record);
    assert!(duplicate_receipt.events().is_empty());
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );

    // A conflicting intent for the same attempt is rejected.
    let conflicting = RequestGateIntent::new(
        request,
        attempt,
        ConnectionId::new(),
        RequestPurpose::new("different-purpose").unwrap(),
        EventSubject::Run(
            RunSubject::new(
                fixture.project_id,
                fixture.agent_id,
                fixture.session_id,
                fixture.run_id,
            )
            .unwrap(),
        ),
        StopDeadlineControl::proceed(),
    )
    .unwrap();
    assert!(matches!(
        store.record_model_request_with_events(
            conflicting,
            Timestamp::from_unix_millis(21),
            vec![draft(&fixture, "request.conflict", 2)],
        ),
        Err(StoreError::RequestIntentConflict { attempt: found }) if found == attempt
    ));
    assert_eq!(
        store.model_request(&attempt).unwrap().unwrap().intent(),
        &intent
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![1]
    );

    let started = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::SendStarted,
        None,
        None,
        TokenUsage::unknown(),
    )
    .unwrap();
    let started_record = store
        .record_model_request_observation(started.clone(), Timestamp::from_unix_millis(22))
        .expect("send started");
    assert_eq!(started_record.observation(), Some(&started));
    assert_eq!(
        started_record.observed_at(),
        Some(Timestamp::from_unix_millis(22))
    );

    // Repeating the identical observation does not overwrite or re-notify.
    let repeated = store
        .record_model_request_observation_with_events(
            started,
            Timestamp::from_unix_millis(23),
            vec![draft(&fixture, "request.send_started_again", 2)],
        )
        .expect("repeat send started");
    assert!(repeated.1.events().is_empty());
    assert_eq!(
        repeated.0.observed_at(),
        Some(Timestamp::from_unix_millis(22))
    );

    let usage = TokenUsage::new(
        TokenCount::known(0),
        TokenCount::unknown(),
        TokenCount::known(12),
        TokenCount::unknown(),
    );
    let completed = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::Completed,
        None,
        Some(ModelId::new("gpt-real-2026").unwrap()),
        usage,
    )
    .unwrap();
    let (completed_record, receipt) = store
        .record_model_request_observation_with_events(
            completed.clone(),
            Timestamp::from_unix_millis(24),
            vec![draft(&fixture, "request.completed", 3)],
        )
        .expect("terminal observation");
    assert_eq!(completed_record.observation(), Some(&completed));
    assert_eq!(receipt.events()[0].sequence(), 2);
    assert_eq!(
        completed_record.observation().unwrap().usage(),
        TokenUsage::new(
            TokenCount::known(0),
            TokenCount::unknown(),
            TokenCount::known(12),
            TokenCount::unknown(),
        )
    );
    assert_eq!(
        completed_record
            .observation()
            .unwrap()
            .model_id()
            .unwrap()
            .as_str(),
        "gpt-real-2026"
    );

    // A conflicting terminal result is rejected and keeps the first result.
    let conflicting_terminal = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::Cancelled,
        Some(ProviderFailureKind::Network),
        None,
        TokenUsage::unknown(),
    )
    .unwrap();
    assert!(matches!(
        store.record_model_request_observation_with_events(
            conflicting_terminal,
            Timestamp::from_unix_millis(25),
            vec![draft(&fixture, "request.conflict", 4)],
        ),
        Err(StoreError::RequestObservationConflict { attempt: found }) if found == attempt
    ));
    assert_eq!(
        store
            .model_request(&attempt)
            .unwrap()
            .unwrap()
            .observation(),
        Some(&completed)
    );
    assert_eq!(
        sequences(
            &store
                .history(HistoryQuery::first(fixture.project_id))
                .unwrap()
        ),
        vec![2, 1]
    );

    // An observation cannot be attached to a different request id.
    let mismatched_request = ModelRequestObservation::new(
        RequestId::new(fixture.project_id),
        attempt,
        RequestOutcome::Cancelled,
        None,
        None,
        TokenUsage::unknown(),
    )
    .unwrap();
    assert!(matches!(
        store.record_model_request_observation(
            mismatched_request,
            Timestamp::from_unix_millis(25),
        ),
        Err(StoreError::RequestObservationConflict { attempt: found }) if found == attempt
    ));

    let unknown_attempt = AttemptId::new(fixture.project_id);
    let unknown_observation = ModelRequestObservation::new(
        request,
        unknown_attempt,
        RequestOutcome::SendResultUnknown,
        None,
        None,
        TokenUsage::unknown(),
    )
    .unwrap();
    assert!(matches!(
        store.record_model_request_observation(unknown_observation, Timestamp::from_unix_millis(26)),
        Err(StoreError::UnknownRequestAttempt { attempt: found }) if found == unknown_attempt
    ));

    // A host-activity subject is a valid request subject and keeps its deadline.
    let activity = HostActivityId::new(fixture.project_id);
    let activity_request = RequestId::new(fixture.project_id);
    let activity_attempt = AttemptId::new(fixture.project_id);
    let activity_intent = RequestGateIntent::new(
        activity_request,
        activity_attempt,
        connection,
        RequestPurpose::new("supervision-planning").unwrap(),
        EventSubject::HostActivity(
            HostActivitySubject::new(
                fixture.project_id,
                EventKind::new("supervision").unwrap(),
                activity,
            )
            .unwrap(),
        ),
        StopDeadlineControl::deadline(),
    )
    .unwrap();
    store
        .record_model_request(activity_intent.clone(), Timestamp::from_unix_millis(30))
        .expect("activity request intent");

    // A retry is a new attempt under the same request id, not a duplicate
    // request or a second attempt with the same id.
    let retry_attempt = AttemptId::new(fixture.project_id);
    let retry_intent = RequestGateIntent::new(
        request,
        retry_attempt,
        connection,
        RequestPurpose::new("completion-assessment").unwrap(),
        EventSubject::Run(
            RunSubject::new(
                fixture.project_id,
                fixture.agent_id,
                fixture.session_id,
                fixture.run_id,
            )
            .unwrap(),
        ),
        StopDeadlineControl::proceed(),
    )
    .unwrap();
    store
        .record_model_request(retry_intent, Timestamp::from_unix_millis(31))
        .expect("retry attempt under the same request");

    let other_connection = harness.open();
    let reloaded = other_connection
        .model_request(&attempt)
        .unwrap()
        .expect("reloaded request");
    assert_eq!(reloaded, completed_record);
    let usage = reloaded.observation().unwrap().usage();
    assert_eq!(usage.input_tokens(), TokenCount::Known(0));
    assert_eq!(usage.output_tokens(), TokenCount::Unknown);
    assert_eq!(usage.cache_read_tokens(), TokenCount::Known(12));
    assert_eq!(usage.cache_write_tokens(), TokenCount::Unknown);
    assert_eq!(
        reloaded.intent().control().stop_reason(),
        Some(StopReason::UserRequest)
    );

    let activity_record = other_connection
        .model_request(&activity_attempt)
        .unwrap()
        .expect("activity request");
    assert!(activity_record.intent().subject().host_activity().is_some());
    assert!(activity_record.intent().control().is_deadline_reached());

    let attempts = other_connection.model_request_attempts(&request).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].intent().attempt_id(), attempt);
    assert_eq!(attempts[1].intent().attempt_id(), retry_attempt);
    assert!(attempts[1].observation().is_none());
}

#[test]
fn host_state_formats_one_and_two_migrate_to_format_three_without_losing_records() {
    let project = ProjectId::new();
    let agent = AgentId::new(project);
    let session = SessionId::new(project);
    let run = RunId::new(project);
    let connection = ConnectionId::new();
    let operation = OperationId::new(project);
    let path = "/tmp/herness-host-state-fixture";
    let state = json!({
        "format": 2,
        "projects": {
            project.to_string(): {
                "path": path,
                "agents": {
                    agent.to_string(): {
                        "sessionId": session.to_string(),
                        "name": "supervised child",
                        "role": "worker",
                        "connection": connection.to_string(),
                        "requiredCapabilities": [],
                        "createdAt": 100
                    }
                },
                "runs": {
                    run.to_string(): {
                        "agentId": agent.to_string(),
                        "sessionId": session.to_string(),
                        "connection": connection.to_string(),
                        "state": "idle",
                        "instructions": "do the work",
                        "grant": {
                            "grants": [],
                            "mode": "configured",
                            "policyVersion": 1
                        },
                        "mode": "configured",
                        "policyVersion": 1,
                        "createdAt": 101,
                        "updatedAt": 102
                    }
                },
                "approvals": {
                    operation.to_string(): {
                        "runId": run.to_string(),
                        "agentId": agent.to_string(),
                        "sessionId": session.to_string(),
                        "operation": {
                            "operationId": operation.to_string(),
                            "runId": run.to_string(),
                            "tool": "write",
                            "arguments": {
                                "tool": "write",
                                "arguments": {
                                    "path": "notes.txt",
                                    "content": "hello",
                                    "rationale": "record the note"
                                }
                            },
                            "cwd": path,
                            "policyVersion": 7,
                            "permissionMode": "configured"
                        },
                        "reason": "needs approval",
                        "requestedAt": 103,
                        "restored": true
                    }
                }
            }
        },
        "connections": {
            connection.to_string(): {
                "connectionId": connection.to_string(),
                "provider": "openai",
                "model": "gpt-test",
                "authMethod": "api_key",
                "credentialRef": format!("connection/{connection}/api_key")
            }
        },
        "shutdown": {
            "outcome": "completed",
            "startedAt": 500,
            "finishedAt": 900,
            "stoppedRuns": [],
            "unconfirmedRuns": [],
            "remainingRuns": [],
            "discardedDeferredMessages": 2,
            "saveFailures": 0
        }
    });

    let migrated =
        host_state_test_support::migrate(&serde_json::to_vec(&state).expect("format 2 fixture"))
            .expect("format 2 is readable");
    let migrated: serde_json::Value = serde_json::from_slice(&migrated).expect("migrated JSON");
    assert_eq!(migrated["format"], 3);

    // Every project, agent, run, approval, connection, and shutdown field is
    // preserved byte-for-byte at the JSON value level.
    let mut expected = state.as_object().unwrap().clone();
    expected.remove("format");
    let mut actual = migrated.as_object().unwrap().clone();
    actual.remove("format");
    assert_eq!(actual, expected);

    // The format-3 write is itself readable and stable.
    let rewritten =
        host_state_test_support::migrate(&serde_json::to_vec(&migrated).expect("format 3 fixture"))
            .expect("format 3 is readable");
    let rewritten: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
    assert_eq!(rewritten, migrated);

    let format_one = host_state_test_support::migrate(br#"{"format":1,"projects":{}}"#)
        .expect("format 1 is readable");
    let format_one: serde_json::Value = serde_json::from_slice(&format_one).unwrap();
    assert_eq!(format_one["format"], 3);
    assert_eq!(format_one["projects"], json!({}));

    let mut invalid_format_one = state.clone();
    invalid_format_one["format"] = json!(1);
    let error = host_state_test_support::migrate(
        &serde_json::to_vec(&invalid_format_one).expect("format 1 fixture"),
    )
    .expect_err("format 1 must not carry format 2 fields");
    assert!(error.contains("format 1 must not contain format 2 fields"));

    // A format-3 run field in an older document is rejected before the run is
    // reinterpreted. The raw check runs before typed deserialization.
    for field in ["inputs", "continuationOf"] {
        let document = json!({
            "format": 2,
            "projects": {
                "placeholder": {
                    "path": "/tmp",
                    "agents": {},
                    "runs": {"placeholder": {(field): []}},
                    "approvals": {}
                }
            }
        });
        let error = host_state_test_support::migrate(
            &serde_json::to_vec(&document).expect("format 2 fixture"),
        )
        .expect_err("format 2 must not carry format 3 fields");
        assert!(error.contains("format 2 must not contain format 3 fields"));
    }

    let error = host_state_test_support::migrate(br#"{"format":2,"projects":{},"sections":{}}"#)
        .expect_err("unknown format fields are rejected");
    assert!(error.contains("host-state JSON"));

    let error = host_state_test_support::migrate(br#"{"format":4,"projects":{}}"#)
        .expect_err("unknown newer format is rejected");
    assert!(error.contains("unsupported host-state format"));
}
