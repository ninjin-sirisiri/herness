-- H4 host-owned SDD execution state: approval revisions, Task reservations,
-- control/request records, the dispatch manifest, budget increments, the Git
-- and progress journals, and the execution snapshot with a compare-and-set
-- revision.
--
-- Payloads are opaque versioned JSON owned by herness-sdd-execute. A row's
-- payload is a store envelope with a format version and the H4 body, so an
-- unknown payload format is rejected before the record is interpreted. The
-- store also decodes the H4 contract version and checks every project and
-- execution binding before writing.
--
-- H4 state events use the existing events table and project sequence. There is
-- no second sequence and no H4 event table. One immediate transaction writes a
-- revision advance, its operation result row, and its event together, so a
-- crash cannot keep a new revision without the result that describes it.

CREATE TABLE sdd_execution_snapshots (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision > 0),
    last_sequence INTEGER CHECK (last_sequence IS NULL OR last_sequence >= 0),
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id)
);

CREATE TABLE sdd_execution_approvals (
    project_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    plan_revision INTEGER NOT NULL CHECK (plan_revision > 0),
    payload BLOB NOT NULL,
    approved_at INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, approval_id, revision)
);

CREATE INDEX sdd_execution_approvals_by_plan
    ON sdd_execution_approvals (project_id, plan_revision);

CREATE TABLE sdd_task_reservations (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    task_stable_id TEXT NOT NULL,
    task_number INTEGER NOT NULL CHECK (task_number > 0),
    request_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    child_agent_id TEXT NOT NULL,
    child_session_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, task_stable_id),
    UNIQUE (project_id, execution_id, request_id),
    UNIQUE (project_id, supervision_id)
);

CREATE INDEX sdd_task_reservations_by_request
    ON sdd_task_reservations (project_id, execution_id, request_id);

CREATE TABLE sdd_dispatch_manifests (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    task_stable_id TEXT NOT NULL,
    task_number INTEGER NOT NULL CHECK (task_number > 0),
    plan_revision INTEGER NOT NULL CHECK (plan_revision > 0),
    baseline TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, request_id)
);

CREATE TABLE sdd_dispatch_journal (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('intent', 'recorded')),
    fingerprint TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, request_id)
);

CREATE TABLE sdd_git_journal (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('intent', 'committed', 'rejected', 'result_unknown')),
    fingerprint TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    commit_sha TEXT,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, request_id),
    CHECK ((state = 'committed') = (commit_sha IS NOT NULL))
);

CREATE TABLE sdd_progress_journal (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('intent', 'recorded', 'result_unknown')),
    fingerprint TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    document_digest TEXT,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, request_id)
);

CREATE TABLE sdd_control_records (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation TEXT,
    state TEXT NOT NULL CHECK (state IN ('intent', 'recorded')),
    fingerprint TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    resulting_revision INTEGER CHECK (resulting_revision IS NULL OR resulting_revision > 0),
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, request_id),
    CHECK ((state = 'recorded') = (resulting_revision IS NOT NULL)),
    CHECK ((state = 'recorded') = (operation IS NOT NULL))
);

CREATE TABLE sdd_execution_budget_increments (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    consumed_seconds_delta INTEGER NOT NULL CHECK (consumed_seconds_delta >= 0),
    additional_runs_delta INTEGER NOT NULL CHECK (additional_runs_delta >= 0),
    micros_delta INTEGER CHECK (micros_delta IS NULL OR micros_delta >= 0),
    payload BLOB NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id, revision)
);
