-- H3 HTML sync settings, document state, cycles, generations, candidates,
-- publication journal, and idempotent operation results.
--
-- Payloads are opaque JSON owned by herness-html-sync. The store checks
-- format versions and cross-project identifiers before writing. Candidate
-- bytes live in the private H3 app area, not in these rows. H3 state events use
-- the existing events table and project sequence. There is no second sequence.

CREATE TABLE html_sync_settings (
    project_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE html_sync_documents (
    project_id TEXT NOT NULL,
    target_path TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    PRIMARY KEY (project_id, target_path)
);

CREATE TABLE html_sync_cycles (
    project_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    target_path TEXT NOT NULL,
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, cycle_id)
);

CREATE INDEX html_sync_cycles_by_document
    ON html_sync_cycles (project_id, target_path);

CREATE TABLE html_sync_generations (
    project_id TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    target_path TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    cycle_id TEXT NOT NULL,
    completed INTEGER NOT NULL CHECK (completed IN (0, 1)),
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, generation_id),
    UNIQUE (project_id, target_path, generation)
);

CREATE INDEX html_sync_generations_by_document
    ON html_sync_generations (project_id, target_path, generation);

CREATE TABLE html_sync_candidates (
    project_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    target_path TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (project_id, candidate_id)
);

CREATE INDEX html_sync_candidates_by_document
    ON html_sync_candidates (project_id, target_path, generation_id);

CREATE TABLE html_sync_publications (
    project_id TEXT NOT NULL,
    publication_id TEXT NOT NULL,
    target_path TEXT NOT NULL,
    h1_request_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, publication_id)
);

CREATE INDEX html_sync_publications_by_document
    ON html_sync_publications (project_id, target_path);

CREATE TABLE html_sync_requests (
    project_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload BLOB NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, request_id)
);
