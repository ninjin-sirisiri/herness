-- Durable H2 budget ledgers and money reservations.
--
-- The ledger payload is opaque JSON owned by herness-supervision. The
-- reservation table mirrors the payload for recovery and audit. Both are
-- written in the same immediate transaction as a model request intent or
-- observation, so a crash cannot separate an admitted request from its
-- reservation.

CREATE TABLE budget_ledgers (
    project_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload BLOB NOT NULL,
    PRIMARY KEY (project_id, supervision_id)
);

CREATE TABLE budget_reservations (
    project_id TEXT NOT NULL,
    supervision_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    estimate_micros INTEGER NOT NULL CHECK (estimate_micros >= 0),
    price_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'settled', 'unresolved', 'released')),
    settled_micros INTEGER,
    PRIMARY KEY (project_id, attempt_id),
    CHECK ((state = 'settled') = (settled_micros IS NOT NULL))
);

CREATE INDEX budget_reservations_by_supervision
    ON budget_reservations (project_id, supervision_id);

CREATE INDEX budget_reservations_by_state
    ON budget_reservations (project_id, state);
