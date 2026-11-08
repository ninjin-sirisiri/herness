-- Versioned event subjects: a run or a host activity that has no run.
--
-- Schema 3 required agent_id, session_id, and run_id for every event. A host
-- activity event must not invent those identifiers, so the rebuilt table keeps
-- the run columns nullable and adds explicit activity columns. Every existing
-- row is copied unchanged and keeps its contract version, identifiers,
-- sequence, kind, timestamp, and payload. The project sequence space stays
-- shared by both subject kinds.

CREATE TABLE events_v4 (
    project_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    contract_version INTEGER NOT NULL,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('run', 'host_activity')),
    agent_id TEXT,
    session_id TEXT,
    run_id TEXT,
    activity_kind TEXT,
    activity_id TEXT,
    operation_id TEXT,
    kind TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (project_id, sequence),
    CHECK (
        (
            subject_type = 'run'
            AND agent_id IS NOT NULL
            AND session_id IS NOT NULL
            AND run_id IS NOT NULL
            AND activity_kind IS NULL
            AND activity_id IS NULL
        )
        OR (
            subject_type = 'host_activity'
            AND agent_id IS NULL
            AND session_id IS NULL
            AND run_id IS NULL
            AND activity_kind IS NOT NULL
            AND activity_id IS NOT NULL
            AND operation_id IS NULL
        )
    )
);

INSERT INTO events_v4 (
    project_id,
    sequence,
    contract_version,
    subject_type,
    agent_id,
    session_id,
    run_id,
    activity_kind,
    activity_id,
    operation_id,
    kind,
    occurred_at,
    payload
)
SELECT
    project_id,
    sequence,
    contract_version,
    'run',
    agent_id,
    session_id,
    run_id,
    NULL,
    NULL,
    operation_id,
    kind,
    occurred_at,
    payload
FROM events;

DROP TABLE events;

ALTER TABLE events_v4 RENAME TO events;

CREATE INDEX events_by_run ON events (run_id);

CREATE INDEX events_by_activity ON events (activity_kind, activity_id);
