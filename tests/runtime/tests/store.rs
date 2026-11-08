//! Black-box tests for the host-owned SQLite store.
//!
//! These tests use temporary project and application-data directories only.
//! They exercise the public `StorePort` and the store's recovery-facing read
//! APIs; no engine, Tauri, or real credentials are involved.

use std::fs;
use std::path::{Path, PathBuf};

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
            supported: 2
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
        conn.execute("UPDATE events SET contract_version = 2", [])
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
                found: 2,
                expected: 1
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
        let mut store =
            open_at_schema_version(harness.config.clone(), 1).expect("open schema version 1");
        assert_eq!(store.schema_version().unwrap(), 1);
        commit(
            &mut store,
            stored_checkpoint.clone(),
            None,
            vec![draft(&fixture, "before-migration", 1)],
        )
        .expect("pre-migration commit");
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
    assert_eq!(reopened.schema_version().unwrap(), 2);
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
    assert_eq!(store.schema_version().unwrap(), 2);
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
