-- H4 plan-change safety latch and limited re-approval state.
--
-- One row per execution holds the plan change that stopped new dispatch and
-- commit. The row is the history of the stop: an open latch keeps the first
-- observed change, and only a human-approved plan revision moves it to
-- `cleared`. Returning to the previously approved plan bytes never deletes or
-- rewrites this row, so a restart cannot lose the stop.
--
-- The payload is an opaque versioned JSON owned by herness-sdd-execute. The
-- store decodes it and refuses an unknown format or a row whose identifiers do
-- not match its body.

CREATE TABLE sdd_plan_change_latches (
    project_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'cleared')),
    approval_revision INTEGER CHECK (approval_revision IS NULL OR approval_revision > 0),
    plan_revision INTEGER NOT NULL CHECK (plan_revision > 0),
    observed_digest TEXT,
    payload BLOB NOT NULL,
    opened_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, execution_id),
    CHECK ((state = 'cleared') = (approval_revision IS NOT NULL))
);
