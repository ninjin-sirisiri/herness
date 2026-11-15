//! Black-box H4 durable state and journal tests.
//!
//! Every case uses a temporary SQLite database under a temporary app-data root,
//! synthetic projects, and synthetic plan/commit values. No real checkout,
//! provider, credential, Tauri host, or model request is involved.
//!
//! The cases cover:
//!
//! - migrating a populated schema-9 database without losing history or H2/H3
//!   state, and reading H2/H3 through their own APIs afterwards;
//! - a failing 0010 migration leaving the old database intact, including a
//!   0010-specific [`MigrationPoint`](herness_store::test_support::MigrationFault)
//!   case;
//! - rejecting an unknown newer schema before any write;
//! - compare-and-swap revisions with a stale revision refused before any side
//!   effect;
//! - `commit_operation` binding a revision, its operation result, and its
//!   events in one transaction, with a crash boundary that keeps neither alone;
//! - duplicate request IDs returning the stored result and different content
//!   being refused;
//! - cross-project and cross-execution references refused before writing;
//! - re-reading everything from a second `Store::open` on the same root.

mod support;

use std::collections::BTreeMap;

use herness_core::{HistoryLimit, ProjectId};
use herness_html_sync::{
    H3Settings, HtmlSyncCommit, HtmlSyncCommitOutcome, SettingsCommit, settings_event,
};
use herness_sdd_execute::{
    ControlRecord, DurableExecutionStorePort, ExecutionOperation, ExecutionRevision,
    ExecutionStorePort,
};
use herness_store::StoreError;
use herness_store::test_support::{
    CommitFault, MigrationFault, open_at_schema_version, open_with_migration_fault,
};
use rusqlite::Connection;
use support::{
    Harness, approval, approval_at, baseline, child, commit_request_id, control_request_id,
    control_request_id_second, digest, dispatch_intent, dispatch_recorded, dispatch_request_id,
    execution, git_intent, head, increment, manifest, operation_request, operation_request_with_id,
    operation_result, other_execution, other_project, progress_intent, progress_request_id,
    project, running_snapshot, snapshot, supervision, task_ref, task_reservation,
};

fn raw(path: &std::path::Path) -> Connection {
    Connection::open(path).expect("raw sqlite connection")
}

/// Progress content whose document digest differs from the fixture content.
fn progress_content_other() -> herness_sdd_execute::ProgressContent {
    herness_sdd_execute::ProgressContent::new(
        ".sdd/progress.md",
        support::CHECKOUT,
        "h4-store",
        baseline(),
        Vec::new(),
        vec!["another ruling".to_owned()],
        None,
        digest("other document"),
    )
    .expect("other progress content")
}

fn relation(conn: &Connection, sql: &str) -> Vec<String> {
    let mut statement = conn.prepare(sql).expect("prepare relation");
    let mut rows = statement.query([]).expect("query relation");
    let mut values = Vec::new();
    while let Some(row) = rows.next().expect("next row") {
        values.push(row.get::<_, String>(0).expect("text value"));
    }
    values
}

/// Every table that exists before the H4 migration, with the IDs this test
/// compares before and after the migration. `schema_version` is checked
/// separately because the migration is expected to advance it.
const LEGACY_TABLES: &[(&str, &str)] = &[
    ("checkpoints", "run_id"),
    ("project_sequences", "project_id || ':' || next_sequence"),
    ("events", "project_id || ':' || sequence || ':' || kind"),
    ("operations", "operation_id"),
    ("host_state", "key"),
    ("model_requests", "attempt_id"),
    (
        "supervised_state",
        "project_id || ':' || state_key || ':' || revision",
    ),
    ("supervision_records", "project_id || ':' || supervision_id"),
    ("evidence_records", "project_id || ':' || evidence_id"),
    ("supervision_command_results", "request_id"),
    ("budget_ledgers", "project_id || ':' || supervision_id"),
    (
        "budget_reservations",
        "project_id || ':' || attempt_id || ':' || state",
    ),
    ("html_sync_settings", "project_id || ':' || revision"),
    ("html_sync_documents", "project_id || ':' || target_path"),
    ("html_sync_cycles", "project_id || ':' || cycle_id"),
    (
        "html_sync_generations",
        "project_id || ':' || generation_id",
    ),
    ("html_sync_candidates", "project_id || ':' || candidate_id"),
    (
        "html_sync_publications",
        "project_id || ':' || publication_id",
    ),
    ("html_sync_requests", "project_id || ':' || request_id"),
];

/// Every table the H4 migration adds.
const H4_TABLES: &[&str] = &[
    "sdd_execution_snapshots",
    "sdd_execution_approvals",
    "sdd_task_reservations",
    "sdd_dispatch_manifests",
    "sdd_dispatch_journal",
    "sdd_git_journal",
    "sdd_progress_journal",
    "sdd_control_records",
    "sdd_execution_budget_increments",
    "sdd_plan_change_latches",
];

fn legacy_snapshot(conn: &Connection) -> BTreeMap<&'static str, Vec<String>> {
    LEGACY_TABLES
        .iter()
        .map(|(table, order)| {
            (
                *table,
                relation(conn, &format!("SELECT {order} FROM {table} ORDER BY 1")),
            )
        })
        .collect()
}

fn schema_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("schema version")
}

fn h4_table_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'sdd_%'",
        [],
        |row| row.get(0),
    )
    .expect("H4 table count")
}

fn table_count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("table count")
}

fn event_count(store: &herness_store::Store, project: ProjectId) -> usize {
    store
        .events_after(&project, None, HistoryLimit::new(100).expect("limit"))
        .expect("events")
        .len()
}

/// Asserts the durable store is reachable through the H4 ports themselves, so
/// later Tasks can depend on the trait objects rather than the inherent API.
#[test]
fn the_store_implements_the_h4_execution_ports() {
    let harness = Harness::new();
    let project = project();
    let execution = execution(project);
    let mut store = harness.open();

    let execution_port: &mut dyn ExecutionStorePort = &mut store;
    assert!(
        execution_port
            .load(project, execution)
            .expect("port load")
            .is_none()
    );
    execution_port
        .compare_and_swap(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("port create");
    assert_eq!(
        execution_port
            .load(project, execution)
            .expect("port load")
            .expect("stored")
            .revision(),
        ExecutionRevision::INITIAL
    );

    let durable_port: &mut dyn DurableExecutionStorePort = &mut store;
    let approval = approval(project);
    durable_port
        .record_approval(&approval)
        .expect("port approval");
    assert_eq!(
        durable_port
            .latest_approval(project, approval.approval_id())
            .expect("port approval read")
            .expect("stored"),
        approval
    );
    // The port error type is the H4 error, not a store error, and a read under
    // the wrong project is refused.
    let foreign = approval_at(other_project(), 1);
    assert!(matches!(
        durable_port.latest_approval(project, foreign.approval_id()),
        Err(herness_sdd_execute::SddExecutionError::CrossProjectReference { .. })
    ));
}

/// Seeds a schema-9 database with H1 history, H2 state, and H3 state.
fn seed_schema_nine(config: &herness_store::StoreConfig) -> BTreeMap<&'static str, Vec<String>> {
    {
        let mut store = open_at_schema_version(config.clone(), 9).expect("schema 9 store");
        assert_eq!(store.schema_version().expect("version"), 9);

        // H2-owned generic state plus a project event.
        let event = herness_core::EventDraft::for_host_activity(
            project(),
            herness_core::EventKind::new("h2.fixture").expect("kind"),
            herness_core::HostActivityId::new(project()),
            herness_core::EventKind::new("h2.state").expect("kind"),
            herness_core::Timestamp::from_unix_millis(10),
            herness_core::EventPayload::new(serde_json::json!({"fixture": 1})),
        )
        .expect("draft");
        store
            .compare_and_swap_supervised_state(
                &project(),
                "h2.fixture",
                None,
                b"{\"state\":\"ready\"}",
                herness_core::Timestamp::from_unix_millis(11),
                vec![event],
            )
            .expect("H2 state");

        // H3 settings and a document state, through H3's own commit path.
        let settings = H3Settings::new(
            project(),
            1,
            true,
            vec!["docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md".to_owned()],
            true,
            true,
            herness_core::Timestamp::from_unix_millis(12),
        )
        .expect("H3 settings");
        let outcome = store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(SettingsCommit::new(None, settings.clone()).expect("commit"))
                    .with_events(vec![
                        settings_event(&settings, herness_core::Timestamp::from_unix_millis(12))
                            .expect("settings event"),
                    ]),
            )
            .expect("H3 settings commit");
        assert!(matches!(outcome, HtmlSyncCommitOutcome::Applied { .. }));
    }

    // Fixture rows for the remaining pre-H4 tables, inserted directly so the
    // comparison covers every table without depending on an encoder.
    let conn = raw(&config.database_path());
    let project = project();
    conn.execute(
        "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
         VALUES ('run-legacy', ?1, 1, ?2, 2)",
        rusqlite::params![project.to_string(), b"legacy-checkpoint".as_slice()],
    )
    .expect("checkpoint");
    conn.execute(
        "INSERT INTO operations (operation_id, project_id, run_id, tool, arguments, cwd,
                                 policy_version, permission_mode, recorded_at)
         VALUES ('operation-legacy', ?1, 'run-legacy', 'write', '{}', '/tmp', 7, 'configured', 13)",
        [project.to_string()],
    )
    .expect("operation");
    conn.execute(
        "INSERT INTO host_state (key, value) VALUES ('herness.fixture', ?1)",
        [b"opaque".as_slice()],
    )
    .expect("host state");
    conn.execute(
        "INSERT INTO supervision_records (project_id, supervision_id, revision, payload)
         VALUES (?1, 'supervision-legacy', 2, ?2)",
        rusqlite::params![project.to_string(), b"{\"fixture\":true}".as_slice()],
    )
    .expect("supervision record");
    conn.execute(
        "INSERT INTO evidence_records (project_id, supervision_id, evidence_id, sequence, payload)
         VALUES (?1, 'supervision-legacy', 'evidence-legacy', 1, ?2)",
        rusqlite::params![project.to_string(), b"{\"evidence\":true}".as_slice()],
    )
    .expect("evidence");
    conn.execute(
        "INSERT INTO supervision_command_results
             (request_id, project_id, supervision_id, revision, payload)
         VALUES ('command-legacy', ?1, 'supervision-legacy', 2, ?2)",
        rusqlite::params![project.to_string(), b"{\"command\":true}".as_slice()],
    )
    .expect("command result");
    conn.execute(
        "INSERT INTO budget_ledgers (project_id, supervision_id, revision, payload)
         VALUES (?1, 'supervision-legacy', 1, ?2)",
        rusqlite::params![project.to_string(), b"{\"budget\":true}".as_slice()],
    )
    .expect("budget ledger");
    conn.execute(
        "INSERT INTO budget_reservations
             (project_id, supervision_id, attempt_id, request_id, estimate_micros,
              price_version, state, settled_micros)
         VALUES (?1, 'supervision-legacy', 'attempt-legacy', 'request-legacy', 10,
                 'fixture-price-1', 'reserved', NULL)",
        [project.to_string()],
    )
    .expect("budget reservation");
    legacy_snapshot(&conn)
}

#[test]
fn schema_nine_history_and_h2_h3_state_survive_the_migration_to_ten() {
    let harness = Harness::new();
    let before = seed_schema_nine(&harness.config);

    let store = harness.open();
    assert_eq!(store.schema_version().expect("version"), 11);
    // H2 and H3 keep working through their own store APIs after the migration.
    let state = store
        .supervised_state(&project(), "h2.fixture")
        .expect("H2 read")
        .expect("stored H2 state");
    assert_eq!(state.revision(), 1);
    assert_eq!(state.value(), b"{\"state\":\"ready\"}");
    assert!(
        store
            .load_html_sync_settings(project())
            .expect("H3 read")
            .expect("stored H3 settings")
            .settings()
            .enabled()
    );
    assert!(
        store
            .events_after(&project(), None, HistoryLimit::new(10).expect("limit"))
            .expect("events")
            .len()
            >= 2
    );
    drop(store);

    let conn = raw(&harness.database_path());
    assert_eq!(schema_version(&conn), 11);
    assert_eq!(legacy_snapshot(&conn), before);
    assert_eq!(h4_table_count(&conn), 10);
    for table in H4_TABLES {
        assert_eq!(table_count(&conn, table), 0, "{table} must start empty");
    }
}

#[test]
fn migration_fault_leaves_the_schema_nine_database_intact() {
    let harness = Harness::new();
    let before = seed_schema_nine(&harness.config);

    // Fail after the first statement of the 0010 migration, which is a
    // 0010-specific migration point.
    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 10,
            statements: 1,
        },
    )
    .expect_err("migration fault");
    assert!(matches!(
        error,
        StoreError::InjectedFault {
            point: "migration-after-statement"
        }
    ));

    let conn = raw(&harness.database_path());
    assert_eq!(schema_version(&conn), 9);
    assert_eq!(legacy_snapshot(&conn), before);
    assert_eq!(h4_table_count(&conn), 0);
    drop(conn);

    // A later open with no fault completes the migration without repairing
    // anything by restoring.
    let store = harness.open();
    assert_eq!(store.schema_version().expect("version"), 11);
    drop(store);
    let conn = raw(&harness.database_path());
    assert_eq!(legacy_snapshot(&conn), before);
    assert_eq!(h4_table_count(&conn), 10);
}

#[test]
fn an_unknown_newer_schema_is_rejected_before_any_write() {
    let harness = Harness::new();
    let before = seed_schema_nine(&harness.config);
    {
        let conn = raw(&harness.database_path());
        conn.execute("UPDATE schema_version SET version = 12", [])
            .expect("bump schema");
    }

    let error = herness_store::Store::open(harness.config.clone()).expect_err("newer schema");
    assert!(matches!(
        error,
        StoreError::UnsupportedSchemaVersion {
            found: 12,
            supported: 11
        }
    ));

    let conn = raw(&harness.database_path());
    assert_eq!(schema_version(&conn), 12);
    assert_eq!(h4_table_count(&conn), 0);
    // Every pre-H4 row is untouched.
    assert_eq!(legacy_snapshot(&conn), before);
}

#[test]
fn snapshot_cas_persists_and_a_stale_revision_is_refused_before_any_event() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    let first = snapshot(project, execution, ExecutionRevision::INITIAL);
    assert_eq!(
        store
            .compare_and_swap_execution(project, execution, None, &first)
            .expect("create"),
        ExecutionRevision::INITIAL
    );
    assert_eq!(event_count(&store, project), 1);

    let second = snapshot(project, execution, ExecutionRevision::INITIAL.next());
    assert_eq!(
        store
            .compare_and_swap_execution(
                project,
                execution,
                Some(ExecutionRevision::INITIAL),
                &second
            )
            .expect("update"),
        ExecutionRevision::INITIAL.next()
    );
    assert_eq!(event_count(&store, project), 2);

    // A stale revision is refused before any row or event changes.
    let stale = snapshot(project, execution, ExecutionRevision::INITIAL.next());
    let error = store
        .compare_and_swap_execution(project, execution, Some(ExecutionRevision::INITIAL), &stale)
        .expect_err("stale revision");
    assert!(matches!(
        error,
        StoreError::StaleRevision {
            expected: Some(1),
            found: Some(2),
            ..
        }
    ));
    assert_eq!(event_count(&store, project), 2);

    let loaded = store
        .load_sdd_execution(project, execution)
        .expect("load")
        .expect("stored snapshot");
    assert_eq!(loaded.revision(), ExecutionRevision::INITIAL.next());
    assert_eq!(loaded.snapshot(), &second);

    // A non-advancing revision cannot replace the stored snapshot.
    let non_advancing = snapshot(project, execution, ExecutionRevision::INITIAL.next());
    assert!(matches!(
        store.compare_and_swap_execution(
            project,
            execution,
            Some(ExecutionRevision::INITIAL.next()),
            &non_advancing
        ),
        Err(StoreError::SddExecutionInvalidCommit { .. })
    ));
    assert_eq!(event_count(&store, project), 2);
}

#[test]
fn commit_operation_binds_revision_result_and_events_in_one_transaction() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    assert_eq!(event_count(&store, project), 1);

    let next = running_snapshot(
        project,
        execution,
        ExecutionRevision::INITIAL.next(),
        supervision(project),
        child(project),
    );
    let request = operation_request(
        project,
        execution,
        ExecutionRevision::INITIAL,
        ExecutionOperation::ApproveAndStart,
    );
    let record = request
        .recorded(operation_result(ExecutionOperation::ApproveAndStart, &next))
        .expect("record");

    assert_eq!(
        store
            .commit_execution_operation(
                project,
                execution,
                Some(ExecutionRevision::INITIAL),
                &next,
                &record
            )
            .expect("commit operation"),
        ExecutionRevision::INITIAL.next()
    );
    assert_eq!(
        event_count(&store, project),
        3,
        "snapshot and operation events"
    );
    let stored = store
        .sdd_control_record(project, execution, control_request_id(project))
        .expect("operation record")
        .expect("recorded");
    assert_eq!(stored, record);
    assert_eq!(
        store
            .load_sdd_execution(project, execution)
            .expect("load")
            .expect("snapshot")
            .revision(),
        ExecutionRevision::INITIAL.next()
    );

    // A duplicate delivery returns the stored result and publishes no event.
    assert_eq!(
        store
            .commit_execution_operation(
                project,
                execution,
                Some(ExecutionRevision::INITIAL),
                &next,
                &record
            )
            .expect("duplicate"),
        ExecutionRevision::INITIAL.next()
    );
    assert_eq!(event_count(&store, project), 3);

    // The same request ID with different content is refused before any write.
    let conflicting = operation_request(
        project,
        execution,
        ExecutionRevision::INITIAL,
        ExecutionOperation::Pause,
    )
    .recorded(operation_result(ExecutionOperation::Pause, &next))
    .expect("conflicting record");
    assert!(matches!(
        store.commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &next,
            &conflicting
        ),
        Err(StoreError::SddExecutionRequestConflict { .. })
    ));
    assert_eq!(event_count(&store, project), 3);

    // A new request whose expected revision is stale is refused before any
    // side effect.
    let stale_next = running_snapshot(
        project,
        execution,
        ExecutionRevision::INITIAL.next().next(),
        supervision(project),
        child(project),
    );
    let stale_record = operation_request_with_id(
        project,
        execution,
        control_request_id_second(project),
        ExecutionRevision::INITIAL,
        ExecutionOperation::Pause,
    )
    .recorded(operation_result(ExecutionOperation::Pause, &stale_next))
    .expect("stale record");
    assert!(matches!(
        store.commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &stale_next,
            &stale_record
        ),
        Err(StoreError::StaleRevision { .. })
    ));
    assert_eq!(event_count(&store, project), 3);
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id_second(project))
            .expect("operation record")
            .is_none()
    );
}

#[test]
fn a_crash_boundary_never_leaves_a_revision_without_its_result_or_event() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    let next = running_snapshot(
        project,
        execution,
        ExecutionRevision::INITIAL.next(),
        supervision(project),
        child(project),
    );
    let record = operation_request(
        project,
        execution,
        ExecutionRevision::INITIAL,
        ExecutionOperation::ApproveAndStart,
    )
    .recorded(operation_result(ExecutionOperation::ApproveAndStart, &next))
    .expect("record");

    for fault in [CommitFault::BeforeRows, CommitFault::BeforeCommit] {
        store.set_commit_fault(Some(fault));
        let error = store
            .commit_execution_operation(
                project,
                execution,
                Some(ExecutionRevision::INITIAL),
                &next,
                &record,
            )
            .expect_err("injected fault");
        assert!(matches!(error, StoreError::InjectedFault { .. }));
        store.set_commit_fault(None);

        // The old revision, no operation result, and no new event survive. The
        // revision never advances without the result that describes it.
        assert_eq!(
            store
                .load_sdd_execution(project, execution)
                .expect("load")
                .expect("snapshot")
                .revision(),
            ExecutionRevision::INITIAL
        );
        assert!(
            store
                .sdd_control_record(project, execution, control_request_id(project))
                .expect("operation record")
                .is_none()
        );
        assert_eq!(event_count(&store, project), 1);
    }

    // The retry after the faults commits revision, result, and events together.
    store
        .commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &next,
            &record,
        )
        .expect("retry");
    assert_eq!(event_count(&store, project), 3);
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id(project))
            .expect("operation record")
            .is_some()
    );
}

#[test]
fn a_stale_revision_is_refused_before_any_side_effect() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    let second = snapshot(project, execution, ExecutionRevision::INITIAL.next());
    store
        .compare_and_swap_execution(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &second,
        )
        .expect("update");
    assert_eq!(event_count(&store, project), 2);

    let third = snapshot(project, execution, ExecutionRevision::INITIAL.next().next());
    let record = operation_request_with_id(
        project,
        execution,
        control_request_id_second(project),
        ExecutionRevision::INITIAL,
        ExecutionOperation::Pause,
    )
    .recorded(operation_result(ExecutionOperation::Pause, &third))
    .expect("record");
    assert!(matches!(
        store.commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &third,
            &record
        ),
        Err(StoreError::StaleRevision { .. })
    ));
    assert_eq!(event_count(&store, project), 2);
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id_second(project))
            .expect("operation record")
            .is_none()
    );
}

#[test]
fn journals_persist_intents_and_results_and_refuse_conflicting_content() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    // Dispatch: intent, then result.
    let intent = dispatch_intent(project, execution, ExecutionRevision::INITIAL);
    store
        .record_dispatch_entry(&intent)
        .expect("dispatch intent");
    let recorded = dispatch_recorded(project, execution, ExecutionRevision::INITIAL);
    store
        .record_dispatch_entry(&recorded)
        .expect("dispatch result");
    assert_eq!(
        store
            .sdd_dispatch_entry(project, execution, dispatch_request_id(project))
            .expect("dispatch entry")
            .expect("stored"),
        recorded
    );
    store
        .record_dispatch_entry(&recorded)
        .expect("duplicate dispatch is a no-op");

    // Git: intent, then a committed result.
    let git = git_intent(project, execution, ExecutionRevision::INITIAL);
    store.record_git_entry(&git).expect("git intent");
    let committed = git
        .clone()
        .record(herness_sdd_execute::GitCommitOutcome::Committed {
            commit: head(),
            tree: herness_sdd_execute::TreeSha::parse("c".repeat(40)).expect("tree"),
            parent: head(),
        });
    store.record_git_entry(&committed).expect("git result");
    let stored_git = store
        .sdd_git_entry(project, execution, commit_request_id(project))
        .expect("git entry")
        .expect("stored");
    assert_eq!(
        stored_git.state(),
        herness_sdd_execute::GitJournalState::Committed
    );
    assert_eq!(stored_git, committed);

    // Progress: intent, then a written result.
    let progress = progress_intent(project, execution, ExecutionRevision::INITIAL);
    store
        .record_progress_entry(&progress)
        .expect("progress intent");
    let written = progress
        .clone()
        .record(herness_sdd_execute::ProgressWriteOutcome::Written {
            digest: digest("written"),
        });
    store
        .record_progress_entry(&written)
        .expect("progress result");
    assert_eq!(
        store
            .sdd_progress_entry(project, execution, progress_request_id(project))
            .expect("progress entry")
            .expect("stored"),
        written
    );

    // One event per dispatch/git/progress write.
    assert_eq!(event_count(&store, project), 6);

    // The same request ID with different content is refused before any write.
    let conflicting_progress = {
        let identity = *progress.identity();
        herness_sdd_execute::ProgressJournalEntry::new(identity, progress_content_other())
            .expect("other entry")
    };
    assert!(matches!(
        store.record_progress_entry(&conflicting_progress),
        Err(StoreError::SddExecutionRequestConflict { .. })
    ));
    assert_eq!(event_count(&store, project), 6);

    // A recorded result cannot be rewritten by a second result.
    let rewritten = git
        .clone()
        .record(herness_sdd_execute::GitCommitOutcome::Rejected {
            reason: herness_sdd_execute::GitRejection::HookFailed,
        });
    assert!(matches!(
        store.record_git_entry(&rewritten),
        Err(StoreError::SddExecutionRecordConflict { .. })
    ));
    assert_eq!(event_count(&store, project), 6);
}

#[test]
fn approvals_reservations_manifest_and_budget_increments_are_durable() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    // Approval revisions are immutable and monotonic.
    let first = approval(project);
    store.record_sdd_approval(&first).expect("approval v1");
    store
        .record_sdd_approval(&first)
        .expect("approval v1 again");
    let second = approval_at(project, 2);
    store.record_sdd_approval(&second).expect("approval v2");
    assert_eq!(
        store
            .latest_sdd_approval(project, first.approval_id())
            .expect("latest")
            .expect("stored"),
        second
    );
    assert_eq!(
        store
            .sdd_approval(project, first.approval_id(), 1)
            .expect("approval v1")
            .expect("stored"),
        first
    );

    // The Task reservation is created once per request and Task.
    let reservation = task_reservation(project, execution);
    assert_eq!(
        store.reserve_sdd_task(&reservation).expect("reserve"),
        reservation
    );
    assert_eq!(
        store.reserve_sdd_task(&reservation).expect("reserve again"),
        reservation
    );
    assert_eq!(
        store
            .sdd_task_reservation(project, execution, dispatch_request_id(project))
            .expect("reservation")
            .expect("stored"),
        reservation
    );

    // The manifest is immutable.
    let manifest = manifest(project, execution);
    store.record_sdd_manifest(&manifest).expect("manifest");
    store
        .record_sdd_manifest(&manifest)
        .expect("manifest again");
    assert_eq!(
        store
            .sdd_manifest(project, execution, dispatch_request_id(project))
            .expect("manifest")
            .expect("stored"),
        manifest
    );

    // Budget increments are append-only and listed in revision order.
    store
        .record_sdd_budget_increment(&increment(project, execution, ExecutionRevision::INITIAL))
        .expect("increment 1");
    store
        .record_sdd_budget_increment(&increment(
            project,
            execution,
            ExecutionRevision::INITIAL.next(),
        ))
        .expect("increment 2");
    let increments = store
        .sdd_budget_increments(project, execution)
        .expect("increments");
    assert_eq!(increments.len(), 2);
    assert_eq!(increments[0].revision(), ExecutionRevision::INITIAL);
    assert_eq!(increments[0].consumed_seconds_delta(), 42);
    assert_eq!(increments[0].reserved_seconds_delta(), 60);
    assert_eq!(increments[1].revision(), ExecutionRevision::INITIAL.next());

    // Repeating an identical increment is a no-op; changing it is refused.
    store
        .record_sdd_budget_increment(&increment(project, execution, ExecutionRevision::INITIAL))
        .expect("duplicate increment");
    let different = herness_sdd_execute::BudgetIncrement::new(
        project,
        execution,
        ExecutionRevision::INITIAL,
        43,
        1,
        None,
    );
    assert!(matches!(
        store.record_sdd_budget_increment(&different),
        Err(StoreError::SddExecutionRecordConflict { .. })
    ));
    assert_eq!(
        store
            .sdd_budget_increments(project, execution)
            .expect("increments")
            .len(),
        2
    );
}

#[test]
fn cross_project_and_cross_execution_references_are_rejected_before_writing() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);
    let other = other_project();

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");

    // A snapshot from another project cannot be written under this project.
    let foreign = snapshot(other, other_execution(other), ExecutionRevision::INITIAL);
    assert!(matches!(
        store.compare_and_swap_execution(project, execution, None, &foreign),
        Err(StoreError::SddExecutionCrossProject { .. })
    ));
    // A foreign execution identifier is refused even for a read.
    assert!(matches!(
        store.load_sdd_execution(project, other_execution(other)),
        Err(StoreError::SddExecutionCrossProject { .. })
    ));
    // A control record for another execution is refused before writing.
    let record = operation_request(
        other,
        other_execution(other),
        ExecutionRevision::INITIAL,
        ExecutionOperation::Pause,
    )
    .recorded(operation_result(
        ExecutionOperation::Pause,
        &snapshot(other, other_execution(other), ExecutionRevision::INITIAL),
    ))
    .expect("foreign record");
    assert!(matches!(
        store.commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &snapshot(project, execution, ExecutionRevision::INITIAL.next()),
            &record
        ),
        Err(StoreError::SddExecutionCrossProject { .. })
    ));
    // A reservation whose child belongs to another project is refused.
    let foreign_child = herness_sdd_execute::TaskReservation::new(
        execution,
        task_ref(project, 1),
        dispatch_request_id(project),
        supervision(project),
        child(other),
    );
    assert!(foreign_child.is_err());
    // An approval from another project cannot be read under this one.
    store
        .record_sdd_approval(&approval(project))
        .expect("approval");
    assert!(matches!(
        store.sdd_approval(other, approval(project).approval_id(), 1),
        Err(StoreError::SddExecutionCrossProject { .. })
    ));
    // Nothing foreign was written and the only H4 row is the project's.
    assert_eq!(event_count(&store, project), 1);
    assert_eq!(
        store
            .load_sdd_execution(project, execution)
            .expect("load")
            .expect("snapshot")
            .revision(),
        ExecutionRevision::INITIAL
    );
}

#[test]
fn saved_state_is_re_read_from_a_second_connection() {
    let harness = Harness::new();
    let project = project();
    let execution = execution(project);
    let approval = approval(project);
    let reservation = task_reservation(project, execution);
    let manifest = manifest(project, execution);
    let increment = increment(project, execution, ExecutionRevision::INITIAL);

    let committed;
    {
        let mut store = harness.open();
        store
            .compare_and_swap_execution(
                project,
                execution,
                None,
                &snapshot(project, execution, ExecutionRevision::INITIAL),
            )
            .expect("create");
        store.record_sdd_approval(&approval).expect("approval");
        store.reserve_sdd_task(&reservation).expect("reservation");
        store.record_sdd_manifest(&manifest).expect("manifest");
        store
            .record_sdd_budget_increment(&increment)
            .expect("increment");
        store
            .record_dispatch_entry(&dispatch_recorded(
                project,
                execution,
                ExecutionRevision::INITIAL,
            ))
            .expect("dispatch");
        committed = store
            .commit_execution_operation(
                project,
                execution,
                Some(ExecutionRevision::INITIAL),
                &running_snapshot(
                    project,
                    execution,
                    ExecutionRevision::INITIAL.next(),
                    supervision(project),
                    child(project),
                ),
                &operation_request(
                    project,
                    execution,
                    ExecutionRevision::INITIAL,
                    ExecutionOperation::ApproveAndStart,
                )
                .recorded(operation_result(
                    ExecutionOperation::ApproveAndStart,
                    &running_snapshot(
                        project,
                        execution,
                        ExecutionRevision::INITIAL.next(),
                        supervision(project),
                        child(project),
                    ),
                ))
                .expect("record"),
            )
            .expect("commit operation");
    }
    assert_eq!(committed, ExecutionRevision::INITIAL.next());

    // A second open on the same app-data root reads everything back.
    let store = harness.open();
    assert_eq!(
        store
            .load_sdd_execution(project, execution)
            .expect("load")
            .expect("snapshot")
            .revision(),
        ExecutionRevision::INITIAL.next()
    );
    assert_eq!(
        store
            .latest_sdd_approval(project, approval.approval_id())
            .expect("approval")
            .expect("stored"),
        approval
    );
    assert_eq!(
        store
            .sdd_task_reservation(project, execution, dispatch_request_id(project))
            .expect("reservation")
            .expect("stored"),
        reservation
    );
    assert_eq!(
        store
            .sdd_manifest(project, execution, dispatch_request_id(project))
            .expect("manifest")
            .expect("stored"),
        manifest
    );
    assert_eq!(
        store
            .sdd_budget_increments(project, execution)
            .expect("increments"),
        vec![increment]
    );
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id(project))
            .expect("operation record")
            .is_some()
    );
    assert!(
        store
            .sdd_dispatch_entry(project, execution, dispatch_request_id(project))
            .expect("dispatch entry")
            .is_some()
    );
}

#[test]
fn no_h4_write_reuses_or_mutates_h2_h3_rows() {
    let harness = Harness::new();
    let before = seed_schema_nine(&harness.config);

    let mut store = harness.open();
    let project = project();
    let execution = execution(project);
    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    store
        .record_sdd_approval(&approval(project))
        .expect("approval");
    store
        .reserve_sdd_task(&task_reservation(project, execution))
        .expect("reservation");
    store
        .record_dispatch_entry(&dispatch_recorded(
            project,
            execution,
            ExecutionRevision::INITIAL,
        ))
        .expect("dispatch");
    drop(store);

    let conn = raw(&harness.database_path());
    // The H4 writes appended H1 events but did not touch any H2/H3 row.
    let after = legacy_snapshot(&conn);
    for (table, values) in &before {
        if *table == "events" {
            // H4 shares the H1 event stream by design: it may only append.
            assert!(after[table].len() >= values.len(), "{table} must only grow");
            assert!(
                after[table].starts_with(values),
                "{table} keeps every earlier row and ID in order"
            );
            continue;
        }
        if *table == "project_sequences" {
            // H4 shares the single H1 project sequence: only the counter moves.
            assert_eq!(after[table].len(), values.len());
            assert!(
                after[table][0].starts_with(&project.to_string()),
                "the same project row is advanced in place"
            );
            continue;
        }
        assert_eq!(&after[table], values, "{table} must not change");
    }
    // No H4 event table exists: H4 uses the existing H1 events table.
    let h4_event_tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
             AND name LIKE 'sdd_%event%'",
            [],
            |row| row.get(0),
        )
        .expect("event table count");
    assert_eq!(h4_event_tables, 0);
    // The H4 rows are in their own tables, not merged into H2/H3 ones.
    assert_eq!(table_count(&conn, "sdd_execution_snapshots"), 1);
    assert_eq!(table_count(&conn, "sdd_execution_approvals"), 1);
    assert_eq!(table_count(&conn, "sdd_task_reservations"), 1);
    assert_eq!(table_count(&conn, "sdd_dispatch_journal"), 1);
}

#[test]
fn an_unknown_stored_payload_version_is_refused_on_read() {
    let harness = Harness::new();
    let project = project();
    let execution = execution(project);
    {
        let mut store = harness.open();
        store
            .compare_and_swap_execution(
                project,
                execution,
                None,
                &snapshot(project, execution, ExecutionRevision::INITIAL),
            )
            .expect("create");
    }
    {
        let conn = raw(&harness.database_path());
        conn.execute(
            "UPDATE sdd_execution_snapshots SET payload = ?1",
            [
                serde_json::to_vec(&serde_json::json!({"formatVersion": 99, "body": {}}))
                    .expect("payload"),
            ],
        )
        .expect("seed future format");
    }

    let store = harness.open();
    assert!(matches!(
        store.load_sdd_execution(project, execution),
        Err(StoreError::SddExecutionFormat {
            record: "execution snapshot",
            found: 99,
            ..
        })
    ));
}

#[test]
fn committed_events_are_reported_in_project_sequence_order_only_after_commit() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    let next = running_snapshot(
        project,
        execution,
        ExecutionRevision::INITIAL.next(),
        supervision(project),
        child(project),
    );
    let record = operation_request(
        project,
        execution,
        ExecutionRevision::INITIAL,
        ExecutionOperation::ApproveAndStart,
    )
    .recorded(operation_result(ExecutionOperation::ApproveAndStart, &next))
    .expect("record");

    // A failed commit reports no event at all.
    store.set_commit_fault(Some(CommitFault::BeforeCommit));
    store
        .commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &next,
            &record,
        )
        .expect_err("fault");
    store.set_commit_fault(None);
    let after_failure = store
        .events_after(&project, None, HistoryLimit::new(100).expect("limit"))
        .expect("events");
    assert_eq!(after_failure.len(), 1);
    assert_eq!(after_failure[0].sequence(), 1);
    assert_eq!(after_failure[0].kind().as_str(), "sdd_execution.snapshot");

    store
        .commit_execution_operation(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &next,
            &record,
        )
        .expect("commit");
    let events = store
        .events_after(&project, None, HistoryLimit::new(100).expect("limit"))
        .expect("events");
    assert_eq!(events.len(), 3);
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // The snapshot event is published before its operation result event, so a
    // reader never sees a result before the revision it describes.
    assert_eq!(events[2].kind().as_str(), "sdd_execution.operation");
    let payload = events[2].payload().as_value();
    assert_eq!(payload["resultingRevision"], serde_json::json!(2));
    assert_eq!(
        payload["requestId"],
        serde_json::json!(control_request_id(project).to_string())
    );
    // A subscriber paging after the first event sees only the new ones.
    let later = store
        .events_after(&project, Some(1), HistoryLimit::new(100).expect("limit"))
        .expect("events");
    assert_eq!(later.len(), 2);
    assert_eq!(later[0].sequence(), 2);
}

#[test]
fn a_plain_revision_write_does_not_record_a_control_result() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let execution = execution(project);

    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &snapshot(project, execution, ExecutionRevision::INITIAL),
        )
        .expect("create");
    let second = snapshot(project, execution, ExecutionRevision::INITIAL.next());
    store
        .compare_and_swap_execution(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &second,
        )
        .expect("update");
    // Only the two snapshot events exist, and no control record was invented.
    assert_eq!(event_count(&store, project), 2);
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id(project))
            .expect("operation record")
            .is_none()
    );

    // `record_operation` alone writes the record but not the revision.
    let record: ControlRecord = operation_request(
        project,
        execution,
        ExecutionRevision::INITIAL.next(),
        ExecutionOperation::Pause,
    )
    .intent()
    .expect("intent");
    store.record_control_record(&record).expect("intent record");
    assert!(
        store
            .sdd_control_record(project, execution, control_request_id(project))
            .expect("operation record")
            .is_some()
    );
    assert_eq!(
        store
            .load_sdd_execution(project, execution)
            .expect("load")
            .expect("snapshot")
            .revision(),
        ExecutionRevision::INITIAL.next()
    );
}
