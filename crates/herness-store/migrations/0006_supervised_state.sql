-- Generic revision-checked state slots for supervision-owned documents.
--
-- The store does not interpret the payload or add H2 state-machine values to
-- core. Writers compare the revision they read before overwriting. A stale
-- revision is rejected instead of silently replacing newer state.

CREATE TABLE supervised_state (
    project_id TEXT NOT NULL,
    state_key TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, state_key)
);
