-- Durable model-request intents and observations.
--
-- An intent is persisted before any bytes are sent. The attempt ID uniquely
-- identifies one send attempt. A request may have several attempts. The
-- observation column stores the validated terminal (or send-started) value as
-- JSON so known and unknown token counts round-trip without being rewritten to
-- zero. Provider bodies, credentials, and SDK checkpoints are never stored
-- here.

CREATE TABLE model_requests (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('run', 'host_activity')),
    agent_id TEXT,
    session_id TEXT,
    run_id TEXT,
    activity_kind TEXT,
    activity_id TEXT,
    connection_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    control TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    observation TEXT,
    observed_at INTEGER,
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
        )
    )
);

CREATE INDEX model_requests_by_request ON model_requests (request_id);

CREATE INDEX model_requests_by_project ON model_requests (project_id);
