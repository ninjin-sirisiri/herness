-- Lookup indexes added after the initial schema.

CREATE INDEX checkpoints_by_project ON checkpoints (project_id);

CREATE INDEX events_by_run ON events (run_id);
