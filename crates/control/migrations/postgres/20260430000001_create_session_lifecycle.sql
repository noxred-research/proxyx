CREATE TABLE IF NOT EXISTS session_lifecycle (
    session_id      UUID PRIMARY KEY,
    org_id          TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_id       TEXT,
    state           TEXT NOT NULL CHECK (state IN ('active', 'consuming', 'closed')),
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    closing_at      TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS session_lifecycle_org_state_idx
    ON session_lifecycle (org_id, state);

CREATE INDEX IF NOT EXISTS session_lifecycle_source_idx
    ON session_lifecycle (source, source_id);
