-- Async Parquet export jobs. view_id is a deterministic UUID v5 over the
-- canonical (org_id, branches) query, so identical queries map to the same row.
-- Created with the progress and completion columns of 20260516000001 and
-- 20261017000001 (SQLite adds columns one at a time; a fresh table is simpler).
CREATE TABLE traffic_view_jobs (
    view_id         BLOB PRIMARY KEY,
    org_id          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    s3_key          TEXT,
    error           TEXT,
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    updated_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    query_id        TEXT,
    read_rows       INTEGER,
    written_rows    INTEGER,
    total_rows      INTEGER,
    last_checked_at INTEGER,
    completed_at    INTEGER
);

CREATE INDEX ix_traffic_view_jobs_org_id ON traffic_view_jobs (org_id);
