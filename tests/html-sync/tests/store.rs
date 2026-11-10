//! Black-box H3 persistence and private candidate storage tests.
//!
//! These tests use temporary databases, synthetic projects, and synthetic
//! documents only. No provider, credential, Tauri host, or real project is
//! involved.

use std::collections::BTreeMap;
use std::path::PathBuf;

use herness_core::{
    ArtifactFailure, ArtifactHandle, ArtifactPort, ArtifactSlot, AttemptId, ConnectionId,
    HistoryLimit, HostActivityId, ProjectId, RequestId, RunId, Timestamp,
};
use herness_html_sync::{
    CandidateArtifactStore, CandidateGenerationRequest, DocumentCommit, H3Error, H3State,
    H3StorePort, HtmlSyncCommit, HtmlSyncCommitOutcome, MAX_CANDIDATE_BYTES, SettingsCommit,
    document_state_event, settings_event,
};
use herness_html_sync_tests::fixtures::{
    TARGET_PATH, authored_fingerprints, candidate, cycle, digest, document_commit, document_key,
    fingerprints, generation, h2_reference, ids, now, other_document_key, other_project,
    pending_document, pending_document_with, project, publication, request_commit, settings,
    settings_commit, source, source_at, synced_document,
};
use herness_store::test_support::{
    CommitFault, MigrationFault, open_at_schema_version, open_with_migration_fault,
};
use herness_store::{Store, StoreConfig, StoreError};
use rusqlite::Connection;
use tempfile::TempDir;
use uuid::Uuid;

struct Harness {
    _temp: TempDir,
    config: StoreConfig,
    candidate_root: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("app data root");
        let candidate_root = temp_path_for(&config).join("html-sync-candidates");
        Self {
            _temp: temp,
            config,
            candidate_root,
        }
    }

    fn open(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }

    fn database_path(&self) -> PathBuf {
        self.config.database_path()
    }
}

fn temp_path_for(config: &StoreConfig) -> PathBuf {
    config
        .app_data_root()
        .parent()
        .expect("app data has a parent")
        .to_path_buf()
}

fn raw(path: &PathBuf) -> Connection {
    Connection::open(path).expect("raw sqlite connection")
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

#[derive(Debug, PartialEq)]
struct LegacySnapshot {
    schema_version: i64,
    values: BTreeMap<&'static str, Vec<String>>,
}

fn legacy_snapshot(conn: &Connection) -> LegacySnapshot {
    let mut values = BTreeMap::new();
    values.insert(
        "checkpoints",
        relation(conn, "SELECT run_id FROM checkpoints ORDER BY run_id"),
    );
    values.insert(
        "project_sequences",
        relation(
            conn,
            "SELECT project_id || ':' || next_sequence FROM project_sequences ORDER BY project_id",
        ),
    );
    values.insert(
        "events",
        relation(
            conn,
            "SELECT project_id || ':' || sequence || ':' || kind || ':' || payload
             FROM events ORDER BY project_id, sequence",
        ),
    );
    values.insert(
        "operations",
        relation(
            conn,
            "SELECT operation_id || ':' || project_id || ':' || run_id || ':' || tool
             FROM operations ORDER BY operation_id",
        ),
    );
    values.insert(
        "host_state",
        relation(conn, "SELECT key FROM host_state ORDER BY key"),
    );
    values.insert(
        "model_requests",
        relation(
            conn,
            "SELECT attempt_id FROM model_requests ORDER BY attempt_id",
        ),
    );
    values.insert(
        "supervised_state",
        relation(
            conn,
            "SELECT project_id || ':' || state_key || ':' || revision
             FROM supervised_state ORDER BY project_id, state_key",
        ),
    );
    values.insert(
        "supervision_records",
        relation(
            conn,
            "SELECT project_id || ':' || supervision_id FROM supervision_records
             ORDER BY project_id, supervision_id",
        ),
    );
    values.insert(
        "evidence_records",
        relation(
            conn,
            "SELECT project_id || ':' || evidence_id FROM evidence_records
             ORDER BY project_id, evidence_id",
        ),
    );
    values.insert(
        "supervision_command_results",
        relation(
            conn,
            "SELECT request_id FROM supervision_command_results ORDER BY request_id",
        ),
    );
    values.insert(
        "budget_ledgers",
        relation(
            conn,
            "SELECT project_id || ':' || supervision_id FROM budget_ledgers
             ORDER BY project_id, supervision_id",
        ),
    );
    values.insert(
        "budget_reservations",
        relation(
            conn,
            "SELECT project_id || ':' || attempt_id || ':' || state FROM budget_reservations
             ORDER BY project_id, attempt_id",
        ),
    );
    let schema_version = conn
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("schema version");
    LegacySnapshot {
        schema_version,
        values,
    }
}

fn seed_schema_eight(config: &StoreConfig) -> LegacySnapshot {
    {
        let store = open_at_schema_version(config.clone(), 8).expect("schema 8 store");
        assert_eq!(store.schema_version().expect("version"), 8);
    }
    let conn = raw(&config.database_path());
    let project = project();
    let run = RunId::new(project);
    let operation = herness_core::OperationId::new(project);
    let supervision = herness_supervision::SupervisionId::from_parts(
        project,
        Uuid::parse_str("60000000-0000-4000-8000-000000000001").unwrap(),
    );
    let evidence = herness_supervision::EvidenceId::from_parts(
        project,
        Uuid::parse_str("60000000-0000-4000-8000-000000000002").unwrap(),
    );
    let request = herness_supervision::SupervisionRequestId::from_parts(
        project,
        Uuid::parse_str("60000000-0000-4000-8000-000000000003").unwrap(),
    );
    let attempt = AttemptId::new(project);
    let model_request = RequestId::new(project);
    let host_activity = HostActivityId::new(project);

    conn.execute(
        "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
         VALUES (?1, ?2, 1, ?3, 4)",
        rusqlite::params![
            run.to_string(),
            project.to_string(),
            b"legacy-checkpoint".as_slice(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, 5)",
        [project.to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO events (project_id, sequence, contract_version, subject_type, agent_id,
                             session_id, run_id, activity_kind, activity_id, operation_id,
                             kind, occurred_at, payload)
         VALUES (?1, 1, 1, 'run', 'agent-1', 'session-1', 'run-1', NULL, NULL, NULL,
                 'run.started', 10, '{\"legacy\":1}')",
        [project.to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO operations (operation_id, project_id, run_id, tool, arguments, cwd,
                                 policy_version, permission_mode, recorded_at)
         VALUES (?1, ?2, ?3, 'write', '{\"path\":\"notes.txt\"}', '/tmp', 7, 'configured', 11)",
        rusqlite::params![operation.to_string(), project.to_string(), run.to_string(),],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO host_state (key, value) VALUES ('herness.runtime.fixture', ?1)",
        [b"opaque".as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO model_requests (attempt_id, request_id, project_id, subject_type,
                                     agent_id, session_id, run_id, activity_kind, activity_id,
                                     connection_id, purpose, control, recorded_at)
         VALUES (?1, ?2, ?3, 'host_activity', NULL, NULL, NULL, 'fixture',
                 ?4, ?5, 'completion', '{\"deadline\":null}', 12)",
        rusqlite::params![
            attempt.to_string(),
            model_request.to_string(),
            project.to_string(),
            host_activity.to_string(),
            ConnectionId::new().to_string(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO supervised_state (project_id, state_key, revision, payload, updated_at)
         VALUES (?1, 'fixture-state', 3, ?2, 13)",
        rusqlite::params![project.to_string(), b"state".as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO supervision_records (project_id, supervision_id, revision, payload)
         VALUES (?1, ?2, 2, ?3)",
        rusqlite::params![
            project.to_string(),
            supervision.to_string(),
            b"{\"fixture\":true}".as_slice(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO evidence_records
             (project_id, supervision_id, evidence_id, sequence, payload)
         VALUES (?1, ?2, ?3, 2, ?4)",
        rusqlite::params![
            project.to_string(),
            supervision.to_string(),
            evidence.to_string(),
            b"{\"evidence\":true}".as_slice(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO supervision_command_results
             (request_id, project_id, supervision_id, revision, payload)
         VALUES (?1, ?2, ?3, 2, ?4)",
        rusqlite::params![
            request.to_string(),
            project.to_string(),
            supervision.to_string(),
            b"{\"command\":true}".as_slice(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO budget_ledgers (project_id, supervision_id, revision, payload)
         VALUES (?1, ?2, 1, ?3)",
        rusqlite::params![
            project.to_string(),
            supervision.to_string(),
            b"{\"budget\":true}".as_slice(),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO budget_reservations
             (project_id, supervision_id, attempt_id, request_id, estimate_micros,
              price_version, state, settled_micros)
         VALUES (?1, ?2, ?3, ?4, 10, 'fixture-price-1', 'reserved', NULL)",
        rusqlite::params![
            project.to_string(),
            supervision.to_string(),
            attempt.to_string(),
            model_request.to_string(),
        ],
    )
    .unwrap();
    legacy_snapshot(&conn)
}

fn h3_tables(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'html_sync_%'",
        [],
        |row| row.get(0),
    )
    .expect("H3 table count")
}

fn event_count(store: &Store, project: ProjectId) -> usize {
    store
        .events_after(&project, None, HistoryLimit::new(100).expect("limit"))
        .expect("events")
        .len()
}

fn create_settings(store: &mut Store) {
    let settings = settings(true);
    let event = settings_event(&settings, now()).expect("settings event");
    let outcome = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(settings_commit(settings))
                .with_events(vec![event]),
        )
        .expect("settings commit");
    assert!(matches!(outcome, HtmlSyncCommitOutcome::Applied { .. }));
}

fn create_document(store: &mut Store) {
    let document = pending_document(source("source v1"));
    let event = document_state_event(&document_key(), None, &document, now()).expect("event");
    let outcome = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(document_commit(document))
                .with_events(vec![event]),
        )
        .expect("document commit");
    assert!(matches!(outcome, HtmlSyncCommitOutcome::Applied { .. }));
}

#[test]
fn schema_eight_rows_and_ids_survive_the_ordered_migration_to_nine() {
    let harness = Harness::new();
    let before = seed_schema_eight(&harness.config);

    let store = harness.open();
    assert_eq!(store.schema_version().expect("version"), 9);
    drop(store);

    let conn = raw(&harness.database_path());
    let after = legacy_snapshot(&conn);
    assert_eq!(after.schema_version, 9);
    assert_eq!(after.values, before.values);
    assert_eq!(h3_tables(&conn), 7);
    for table in [
        "html_sync_settings",
        "html_sync_documents",
        "html_sync_cycles",
        "html_sync_generations",
        "html_sync_candidates",
        "html_sync_publications",
        "html_sync_requests",
    ] {
        let rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("table count");
        assert_eq!(rows, 0, "{table} must start empty");
    }
}

#[test]
fn migration_fault_from_schema_eight_rolls_back_to_the_exact_previous_rows() {
    let harness = Harness::new();
    let before = seed_schema_eight(&harness.config);

    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 9,
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
    let after = legacy_snapshot(&conn);
    assert_eq!(after.schema_version, 8);
    assert_eq!(after.values, before.values);
    assert_eq!(h3_tables(&conn), 0);
    drop(conn);

    let store = harness.open();
    assert_eq!(store.schema_version().expect("version"), 9);
    drop(store);
    let conn = raw(&harness.database_path());
    assert_eq!(legacy_snapshot(&conn).values, before.values);
}

#[test]
fn settings_and_documents_use_revision_cas_and_reject_foreign_projects() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();

    create_settings(&mut store);
    create_document(&mut store);
    assert_eq!(event_count(&store, project), 2);

    let settings_record = store
        .load_html_sync_settings(project)
        .expect("load settings")
        .expect("settings exist");
    assert_eq!(settings_record.revision(), 1);
    assert!(settings_record.settings().enabled());
    let document_record = store
        .load_html_sync_document(project, &key)
        .expect("load document")
        .expect("document exists");
    assert_eq!(document_record.revision(), 1);
    assert_eq!(document_record.last_sequence(), 2);
    assert_eq!(document_record.state().state(), H3State::Pending);

    let stale_settings = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(SettingsCommit::new(Some(2), settings(true)).expect("commit"))
                .with_events(vec![settings_event(&settings(true), now()).expect("event")]),
        )
        .expect_err("stale settings revision");
    assert!(matches!(
        stale_settings,
        StoreError::StaleRevision {
            expected: Some(2),
            found: Some(1),
            ..
        }
    ));
    let stale_document = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(
                    DocumentCommit::new(Some(2), pending_document(source("source v2")))
                        .expect("commit"),
                )
                .with_events(vec![
                    document_state_event(
                        &key,
                        Some(H3State::Pending),
                        &pending_document(source("source v2")),
                        now(),
                    )
                    .expect("event"),
                ]),
        )
        .expect_err("stale document revision");
    assert!(matches!(
        stale_document,
        StoreError::StaleRevision {
            expected: Some(2),
            found: Some(1),
            ..
        }
    ));
    assert_eq!(event_count(&store, project), 2);

    assert!(matches!(
        store.load_html_sync_document(other_project(), &key),
        Err(StoreError::HtmlSyncCrossProject { .. })
    ));
    assert!(matches!(
        store.load_html_sync_candidate(
            other_project(),
            ids(herness_html_sync_tests::fixtures::project()).candidate_one,
        ),
        Err(StoreError::HtmlSyncCrossProject { .. })
    ));
    let foreign_document = pending_document(source("foreign"));
    let other_cycle = {
        let foreign_key = other_document_key();
        herness_html_sync::SyncCycle::new(
            ids(other_project()).cycle,
            foreign_key,
            1,
            now(),
            source("foreign"),
            None,
        )
        .expect("foreign cycle")
    };
    let mixed = HtmlSyncCommit::new()
        .with_document(document_commit(foreign_document))
        .with_cycle(other_cycle)
        .with_events(vec![
            document_state_event(&key, None, &pending_document(source("foreign")), now())
                .expect("event"),
        ]);
    assert!(matches!(
        store.commit_html_sync(mixed),
        Err(StoreError::HtmlSyncCrossProject { .. })
    ));

    let listed = store.list_html_sync_documents(project).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state().document_key(), &key);

    let port: &mut dyn H3StorePort = &mut store;
    let through_port = port
        .load_html_sync_document(project, &key)
        .expect("port load")
        .expect("document");
    assert_eq!(through_port.revision(), 1);
    assert_eq!(
        through_port.status().final_project_sequence(),
        document_record.last_sequence()
    );
}

#[test]
fn duplicate_request_returns_the_stored_result_without_another_write_or_event() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);
    create_document(&mut store);
    let before_events = event_count(&store, project);

    let request = herness_html_sync_tests::fixtures::pause_request(ids.request_one, 1);
    let updated = pending_document_with(source("source v1"), None);
    let event = document_state_event(&key, Some(H3State::Pending), &updated, now()).expect("event");
    let commit = HtmlSyncCommit::new()
        .with_document(DocumentCommit::new(Some(1), updated.clone()).expect("commit"))
        .with_request(request_commit(request.clone(), 2))
        .with_events(vec![event]);
    let outcome = store.commit_html_sync(commit).expect("first request");
    let HtmlSyncCommitOutcome::Applied {
        request: Some(stored),
        final_project_sequence,
        ..
    } = outcome
    else {
        panic!("expected an applied request");
    };
    assert_eq!(final_project_sequence, 3);
    assert_eq!(stored.result().final_project_sequence(), 3);
    assert_eq!(event_count(&store, project), before_events + 1);
    let after_first = store
        .load_html_sync_document(project, &key)
        .expect("load")
        .expect("document");
    assert_eq!(after_first.revision(), 2);

    let duplicate = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), updated).expect("stale commit"))
                .with_request(request_commit(request.clone(), 2))
                .with_events(vec![]),
        )
        .expect("duplicate request");
    let HtmlSyncCommitOutcome::Duplicate {
        stored: replayed,
        final_project_sequence,
    } = duplicate
    else {
        panic!("expected a duplicate outcome");
    };
    assert_eq!(final_project_sequence, 3);
    assert_eq!(replayed.fingerprint(), request.fingerprint());
    assert_eq!(event_count(&store, project), before_events + 1);
    let after_duplicate = store
        .load_html_sync_document(project, &key)
        .expect("load")
        .expect("document");
    assert_eq!(after_duplicate.revision(), 2);
    assert!(
        store
            .html_sync_request_result(project, ids.request_one)
            .expect("request result")
            .expect("stored")
            .replay()
            .duplicate()
    );

    let conflicting = herness_html_sync_tests::fixtures::pause_request(ids.request_one, 2);
    let error = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(
                    DocumentCommit::new(Some(2), pending_document(source("v2"))).expect("commit"),
                )
                .with_request(request_commit(conflicting, 3))
                .with_events(vec![]),
        )
        .expect_err("same request id with another request");
    assert!(matches!(error, StoreError::HtmlSyncRequestConflict { .. }));
    assert_eq!(event_count(&store, project), before_events + 1);
}

#[test]
fn competing_writers_fail_cas_before_history_or_events_change() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);
    create_document(&mut store);
    let before_events = event_count(&store, project);

    let first_generation = generation(ids.generation_one, 1, source("source v1"), fingerprints());
    let first_state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let first_event =
        document_state_event(&key, Some(H3State::Pending), &first_state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), first_state).expect("commit"))
                .with_generation(first_generation)
                .with_events(vec![first_event]),
        )
        .expect("first writer");

    let second_generation = generation(ids.generation_two, 2, source("source v2"), fingerprints());
    let second_state = pending_document_with(source("source v2"), Some(ids.generation_two));
    let second_event =
        document_state_event(&key, Some(H3State::Pending), &second_state, now()).expect("event");
    let error = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), second_state).expect("commit"))
                .with_generation(second_generation)
                .with_events(vec![second_event]),
        )
        .expect_err("stale writer");
    assert!(matches!(
        error,
        StoreError::StaleRevision {
            expected: Some(1),
            found: Some(2),
            ..
        }
    ));
    assert_eq!(event_count(&store, project), before_events + 1);
    let history = store.html_sync_generations(project, &key).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].generation_id(), ids.generation_one);
    assert_eq!(
        store
            .load_html_sync_document(project, &key)
            .expect("load")
            .expect("document")
            .revision(),
        2
    );
}

#[test]
fn failed_commit_publishes_no_event_and_success_publishes_after_the_commit() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);
    create_document(&mut store);
    assert_eq!(event_count(&store, project), 2);

    let updated = pending_document_with(source("source v2"), Some(ids.generation_one));
    let event = document_state_event(&key, Some(H3State::Pending), &updated, now()).expect("event");
    store.set_commit_fault(Some(CommitFault::BeforeCommit));
    let error = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), updated.clone()).expect("commit"))
                .with_generation(generation(
                    ids.generation_one,
                    1,
                    source("source v2"),
                    fingerprints(),
                ))
                .with_events(vec![event]),
        )
        .expect_err("injected commit fault");
    assert!(matches!(
        error,
        StoreError::InjectedFault {
            point: "commit-before-commit"
        }
    ));
    store.set_commit_fault(None);
    let after_failure = store
        .load_html_sync_document(project, &key)
        .expect("load")
        .expect("document");
    assert_eq!(after_failure.revision(), 1);
    assert_eq!(event_count(&store, project), 2);
    assert!(
        store
            .html_sync_generations(project, &key)
            .expect("history")
            .is_empty()
    );

    let event = document_state_event(&key, Some(H3State::Pending), &updated, now()).expect("event");
    let outcome = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), updated).expect("commit"))
                .with_generation(generation(
                    ids.generation_one,
                    1,
                    source("source v2"),
                    fingerprints(),
                ))
                .with_events(vec![event]),
        )
        .expect("retry after fault");
    let HtmlSyncCommitOutcome::Applied {
        final_project_sequence,
        receipt,
        ..
    } = outcome
    else {
        panic!("expected applied");
    };
    assert_eq!(final_project_sequence, 3);
    assert_eq!(receipt.events().len(), 1);
    assert_eq!(receipt.events()[0].sequence(), 3);
    assert_eq!(
        receipt.events()[0]
            .subject()
            .host_activity()
            .expect("host activity")
            .activity_kind()
            .as_str(),
        "html_sync.document"
    );
    let events = store
        .events_after(&project, None, HistoryLimit::new(10).expect("limit"))
        .expect("events");
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].sequence(), 3);
    assert_eq!(events[2].kind().as_str(), "html_sync.state");
    let after_success = store
        .load_html_sync_document(project, &key)
        .expect("load")
        .expect("document");
    assert_eq!(after_success.revision(), 2);
    assert_eq!(after_success.last_sequence(), 3);
    let conn = raw(&harness.database_path());
    let h3_event_tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
             AND name LIKE 'html_sync%event%'",
            [],
            |row| row.get(0),
        )
        .expect("event table count");
    assert_eq!(h3_event_tables, 0, "H3 uses the existing H1 event table");
}

#[test]
fn cycles_generations_candidates_publication_and_history_are_persisted() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);

    let first_source = source("source v1");
    let first_fingerprints = fingerprints()
        .with_candidate(digest("<html>one</html>"))
        .with_provenance(digest("{\"unit\":1}"));
    let candidate_one = candidate(
        ids.candidate_one,
        ids.generation_one,
        "<html>one</html>",
        "{\"unit\":1}",
    );
    let first_generation = generation(
        ids.generation_one,
        1,
        first_source.clone(),
        first_fingerprints.clone(),
    )
    .with_candidate(candidate_one.clone())
    .expect("candidate")
    .with_h2(h2_reference())
    .with_publication(ids.publication)
    .complete(now())
    .expect("complete");
    let publication_one = publication(
        ids.generation_one,
        ids.candidate_one,
        "<html>one</html>",
        "{\"unit\":1}",
    )
    .replacing(now())
    .expect("replacing")
    .published(digest("<html>one</html>"), now())
    .expect("published");
    let synced_one = synced_document(
        ids.generation_one,
        first_source.clone(),
        first_fingerprints.clone(),
    );
    let event = document_state_event(&key, None, &synced_one, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(document_commit(synced_one))
                .with_cycle(cycle())
                .with_generation(first_generation.clone())
                .with_candidate(candidate_one.clone())
                .with_publication(publication_one)
                .with_events(vec![event]),
        )
        .expect("first sync commit");

    let history = store.html_sync_generations(project, &key).expect("history");
    assert_eq!(history.len(), 1);
    assert!(history[0].completed());
    assert_eq!(history[0].candidate(), Some(&candidate_one));
    assert_eq!(
        store
            .load_html_sync_candidate(project, ids.candidate_one)
            .expect("candidate")
            .expect("stored"),
        candidate_one
    );
    let publication = store
        .load_html_sync_publication(project, ids.publication)
        .expect("publication")
        .expect("stored");
    assert_eq!(
        publication.status(),
        herness_html_sync::PublicationStatus::Published
    );
    assert_eq!(publication.h1_request_id().as_str(), "h1-publication-1");
    assert_eq!(
        store
            .load_html_sync_cycle(project, ids.cycle)
            .expect("cycle")
            .expect("stored")
            .state(),
        herness_html_sync::CycleState::Open
    );

    let second_source = source_at(2, "source v2");
    let second_fingerprints = fingerprints()
        .with_candidate(digest("<html>two</html>"))
        .with_provenance(digest("{\"unit\":2}"));
    let second_generation = generation(
        ids.generation_two,
        2,
        second_source.clone(),
        second_fingerprints.clone(),
    )
    .complete(Timestamp::from_unix_millis(now().as_unix_millis() + 10))
    .expect("complete");
    let superseded_first = first_generation
        .clone()
        .supersede(Timestamp::from_unix_millis(now().as_unix_millis() + 10))
        .expect("supersede");
    let synced_two = synced_document(
        ids.generation_two,
        second_source.clone(),
        second_fingerprints,
    );
    let event =
        document_state_event(&key, Some(H3State::Synced), &synced_two, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), synced_two).expect("commit"))
                .with_generation(superseded_first)
                .with_generation(second_generation)
                .with_events(vec![event]),
        )
        .expect("second sync commit");

    let history = store.html_sync_generations(project, &key).expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].generation_id(), ids.generation_one);
    assert_eq!(
        history[0].status(),
        herness_html_sync::GenerationStatus::Superseded
    );
    assert!(history[0].completed(), "past success survives supersession");
    assert!(history[1].completed());
    let document = store
        .load_html_sync_document(project, &key)
        .expect("load")
        .expect("document");
    assert_eq!(document.state().state(), H3State::Synced);
    assert!(document.state().applicability().is_applicable());
    assert_eq!(document.state().generation(), Some(ids.generation_two));
}

#[test]
fn unknown_saved_formats_and_fields_are_rejected_on_read() {
    let harness = Harness::new();
    let mut store = harness.open();
    create_settings(&mut store);
    create_document(&mut store);
    drop(store);

    let conn = raw(&harness.database_path());
    let payload = serde_json::to_vec(&pending_document(source("source v1"))).expect("payload");
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("value");
    value["formatVersion"] = serde_json::json!(999);
    conn.execute(
        "UPDATE html_sync_documents SET payload = ?1 WHERE project_id = ?2 AND target_path = ?3",
        rusqlite::params![
            serde_json::to_vec(&value).unwrap(),
            project().to_string(),
            TARGET_PATH,
        ],
    )
    .expect("seed future format");

    let store = harness.open();
    let error = store
        .load_html_sync_document(project(), &document_key())
        .expect_err("unknown format");
    assert!(matches!(
        error,
        StoreError::HtmlSyncFormat {
            record: "document state",
            found: 999,
            ..
        }
    ));
    drop(store);

    let conn = raw(&harness.database_path());
    let mut value: serde_json::Value = serde_json::from_slice(&payload).expect("value");
    value["unknownModelField"] = serde_json::json!("ignored?");
    conn.execute(
        "UPDATE html_sync_documents SET payload = ?1 WHERE project_id = ?2 AND target_path = ?3",
        rusqlite::params![
            serde_json::to_vec(&value).unwrap(),
            project().to_string(),
            TARGET_PATH,
        ],
    )
    .expect("seed unknown field");
    let store = harness.open();
    let error = store
        .load_html_sync_document(project(), &document_key())
        .expect_err("unknown field");
    assert!(matches!(error, StoreError::CorruptData { .. }));
}

#[test]
fn generation_status_can_progress_but_immutable_source_or_evidence_cannot_shrink() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);

    let active = generation(ids.generation_one, 1, source("source v1"), fingerprints());
    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, None, &state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(document_commit(state))
                .with_generation(active.clone())
                .with_events(vec![event]),
        )
        .expect("active generation");

    let completed = active.clone().complete(now()).expect("complete");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_generation(completed.clone())
                .with_events(vec![]),
        )
        .expect_err("a generation update needs a document commit");

    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, Some(H3State::Pending), &state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), state).expect("commit"))
                .with_generation(completed.clone())
                .with_events(vec![event]),
        )
        .expect("completion update");

    let different_source = generation(ids.generation_one, 1, source("different"), fingerprints());
    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, Some(H3State::Pending), &state, now()).expect("event");
    let error = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(2), state).expect("commit"))
                .with_generation(different_source)
                .with_events(vec![event]),
        )
        .expect_err("immutable source change");
    assert!(matches!(error, StoreError::HtmlSyncRecordConflict { .. }));
}

#[test]
fn active_generation_accepts_its_candidate_and_rejects_a_fingerprint_rewrite() {
    let harness = Harness::new();
    let mut store = harness.open();
    let project = project();
    let key = document_key();
    let ids = ids(project);
    create_settings(&mut store);

    let active = generation(ids.generation_one, 1, source("source v1"), fingerprints());
    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, None, &state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(document_commit(state))
                .with_generation(active.clone())
                .with_events(vec![event]),
        )
        .expect("active generation");

    let authored = candidate(
        ids.candidate_one,
        ids.generation_one,
        "<html>candidate</html>",
        "{\"units\":[]}",
    );
    let with_candidate = active
        .clone()
        .with_candidate(authored.clone())
        .expect("attach candidate");
    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, Some(H3State::Pending), &state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(1), state).expect("commit"))
                .with_generation(with_candidate)
                .with_candidate(authored.clone())
                .with_events(vec![event]),
        )
        .expect("active generation candidate attach");

    let loaded = store
        .load_html_sync_candidate(project, ids.candidate_one)
        .expect("load candidate")
        .expect("candidate");
    assert_eq!(loaded.generation_id(), ids.generation_one);
    let stored = store
        .html_sync_generations(project, &key)
        .expect("generations")
        .into_iter()
        .find(|record| record.generation_id() == ids.generation_one)
        .expect("generation");
    assert!(stored.candidate().is_some());
    assert_eq!(stored.status(), herness_html_sync::GenerationStatus::Active);

    let rewritten = generation(
        ids.generation_one,
        1,
        source("source v1"),
        authored_fingerprints("<html>candidate</html>", "{\"units\":[]}"),
    )
    .with_candidate(authored)
    .expect("candidate");
    let state = pending_document_with(source("source v1"), Some(ids.generation_one));
    let event = document_state_event(&key, Some(H3State::Pending), &state, now()).expect("event");
    let error = store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(Some(2), state).expect("commit"))
                .with_generation(rewritten)
                .with_events(vec![event]),
        )
        .expect_err("fingerprint rewrite");
    assert!(matches!(error, StoreError::HtmlSyncRecordConflict { .. }));
}

#[test]
fn candidate_store_is_private_generation_scoped_and_enforces_the_limits() {
    let harness = Harness::new();
    let store = CandidateArtifactStore::new(&harness.candidate_root).expect("candidate store");
    let request = CandidateGenerationRequest::new(
        document_key(),
        "job-1",
        1,
        Some("token-1".to_owned()),
        "# Source\n",
        Some("<html>old</html>".to_owned()),
        Some("body{}".to_owned()),
    )
    .expect("generation request");
    let opened = store
        .open_generation(request.clone())
        .expect("open generation");
    let handle = opened.handle().clone();
    assert_eq!(handle.project_id(), project());
    assert_eq!(handle.job_id(), "job-1");
    assert_eq!(handle.generation(), 1);
    assert_eq!(opened.storage().namespace().len(), 64);
    assert!(
        opened
            .storage()
            .namespace()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert_eq!(opened.document().target_path(), TARGET_PATH);

    let mut port = store.clone();
    let source_snapshot = port
        .read_artifact(&handle, ArtifactSlot::SourceMarkdown)
        .expect("read source")
        .expect("source exists");
    assert_eq!(source_snapshot.content(), "# Source\n");
    assert_eq!(
        source_snapshot.version().as_str(),
        herness_supervision::ContentDigest::sha256(b"# Source\n").as_str()
    );
    assert_eq!(
        port.read_artifact(&handle, ArtifactSlot::ExistingHtml)
            .expect("read existing")
            .expect("existing exists")
            .content(),
        "<html>old</html>"
    );
    assert_eq!(
        port.read_artifact(&handle, ArtifactSlot::SharedCss)
            .expect("read css")
            .expect("css exists")
            .content(),
        "body{}"
    );
    assert!(
        port.read_artifact(&handle, ArtifactSlot::CandidateHtml)
            .expect("read candidate")
            .is_none()
    );

    let written = port
        .write_artifact(
            &handle,
            ArtifactSlot::CandidateHtml,
            "<html>new</html>",
            None,
        )
        .expect("write candidate");
    assert_eq!(written.content(), "<html>new</html>");
    let conflict = port
        .write_artifact(
            &handle,
            ArtifactSlot::CandidateHtml,
            "<html>third</html>",
            None,
        )
        .expect_err("missing expected version conflicts with an existing candidate");
    assert!(matches!(
        conflict,
        ArtifactFailure::VersionConflict {
            artifact: ArtifactSlot::CandidateHtml,
            ..
        }
    ));
    port.write_artifact(
        &handle,
        ArtifactSlot::CandidateHtml,
        "<html>third</html>",
        Some(written.version()),
    )
    .expect("compare-and-swap candidate");

    assert!(matches!(
        port.write_artifact(&handle, ArtifactSlot::SourceMarkdown, "changed", None),
        Err(ArtifactFailure::NotCandidateTarget {
            artifact: ArtifactSlot::SourceMarkdown
        })
    ));

    let before_over_limit = port
        .read_artifact(&handle, ArtifactSlot::CandidateHtml)
        .expect("read")
        .expect("candidate");
    let over_limit = "x".repeat(MAX_CANDIDATE_BYTES + 1);
    assert!(matches!(
        port.write_artifact(
            &handle,
            ArtifactSlot::CandidateHtml,
            &over_limit,
            Some(before_over_limit.version())
        ),
        Err(ArtifactFailure::NotExecutable { .. })
    ));
    assert_eq!(
        port.read_artifact(&handle, ArtifactSlot::CandidateHtml)
            .expect("read")
            .expect("candidate")
            .content(),
        "<html>third</html>"
    );

    let foreign_project =
        ArtifactHandle::new(other_project(), "job-1", 1, "token-1").expect("handle");
    assert!(
        port.read_artifact(&foreign_project, ArtifactSlot::CandidateHtml)
            .is_err()
    );
    let foreign_job = ArtifactHandle::new(project(), "job-2", 1, "token-1").expect("handle");
    assert!(
        port.read_artifact(&foreign_job, ArtifactSlot::CandidateHtml)
            .is_err()
    );
    let foreign_generation = ArtifactHandle::new(project(), "job-1", 2, "token-1").expect("handle");
    assert!(
        port.read_artifact(&foreign_generation, ArtifactSlot::CandidateHtml)
            .is_err()
    );
    let foreign_token = ArtifactHandle::new(project(), "job-1", 1, "token-2").expect("handle");
    assert!(
        port.read_artifact(&foreign_token, ArtifactSlot::CandidateHtml)
            .is_err()
    );

    let reopened = store
        .open_generation(request.clone())
        .expect("idempotent reopen");
    assert_eq!(reopened.handle(), &handle);
    let different = CandidateGenerationRequest::new(
        document_key(),
        "job-1",
        1,
        Some("token-1".to_owned()),
        "# Different\n",
        None,
        None,
    )
    .expect("different request");
    assert!(matches!(
        store.open_generation(different),
        Err(H3Error::RecordConflict { .. })
    ));

    let mut roots = std::fs::read_dir(&harness.candidate_root)
        .expect("candidate root")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    roots.sort();
    assert_eq!(roots.len(), 1, "one generation directory");
    assert_eq!(roots[0].to_string_lossy().len(), 64);
    let manifest = std::fs::read(harness.candidate_root.join(&roots[0]).join("manifest.json"))
        .expect("manifest");
    assert!(
        !String::from_utf8_lossy(&manifest).contains("token-1"),
        "the raw capability token is not persisted"
    );
}

#[test]
fn candidate_storage_requires_an_absolute_private_root() {
    assert!(CandidateArtifactStore::new("relative/path").is_err());
    assert!(CandidateArtifactStore::new("/tmp/../escape").is_err());
    let harness = Harness::new();
    assert!(CandidateArtifactStore::new(&harness.candidate_root).is_ok());
}
