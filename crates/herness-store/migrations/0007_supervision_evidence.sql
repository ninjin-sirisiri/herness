-- H2 supervision records, verification evidence, and idempotent command results.
--
-- Payloads are opaque JSON owned by herness-supervision. No credential,
-- provider body, or raw request content belongs in these rows.

CREATE TABLE supervision_records (
    project_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    PRIMARY KEY (project_id, supervision_id)
);

CREATE TABLE evidence_records (
    project_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    payload BLOB NOT NULL,
    PRIMARY KEY (project_id, evidence_id),
    UNIQUE (project_id, supervision_id, sequence)
);

CREATE TABLE supervision_command_results (
    request_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    PRIMARY KEY (request_id)
);
