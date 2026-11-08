-- Private, non-secret host runtime state.
--
-- Values are versioned JSON owned by the runtime. This table never stores
-- credentials, provider tokens, checkpoints, or raw provider output.

CREATE TABLE host_state (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);
