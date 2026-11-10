-- Async Parquet export jobs. view_id is a deterministic UUID v5 over the
-- canonical (org_id, branches) query, so identical queries map to the same row.
CREATE TABLE traffic_view_jobs (
    view_id    UUID PRIMARY KEY,
    org_id     TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    s3_key     TEXT,
    error      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_traffic_view_jobs_org_id ON traffic_view_jobs (org_id);
