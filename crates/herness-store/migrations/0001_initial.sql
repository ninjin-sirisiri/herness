-- Host-owned initial schema for checkpoint, audit, and operation records.
-- Statements are applied one at a time inside the migration transaction.

CREATE TABLE checkpoints (
    run_id TEXT PRIMARY KEY NOT NULL,
    project_id TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    payload BLOB NOT NULL,
    last_sequence INTEGER NOT NULL
);

CREATE TABLE project_sequences (
    project_id TEXT PRIMARY KEY NOT NULL,
    next_sequence INTEGER NOT NULL
);

CREATE TABLE events (
    project_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    contract_version INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    operation_id TEXT,
    kind TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (project_id, sequence)
);

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    arguments TEXT NOT NULL,
    cwd TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    permission_mode TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    outcome TEXT,
    evidence TEXT,
    resolved_at INTEGER
);
