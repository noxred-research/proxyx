-- Created in its final shape: see 20250425000001_create_orgs.sql.
CREATE TABLE IF NOT EXISTS session_lifecycle (
    session_id BLOB PRIMARY KEY,
    org_id     TEXT NOT NULL,
    source     TEXT NOT NULL,
    source_id  TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('active', 'consuming', 'closed')),
    opened_at  INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    closing_at INTEGER,
    closed_at  INTEGER,
    expires_at INTEGER NOT NULL,
    ref_count  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS session_lifecycle_org_state_idx ON session_lifecycle (org_id, state);
CREATE INDEX IF NOT EXISTS session_lifecycle_source_idx ON session_lifecycle (source, source_id);
