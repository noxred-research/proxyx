-- Async Parquet export jobs. view_id is a deterministic UUID v5 over the
-- canonical (org_id, branches) query, so identical queries map to the same row.
CREATE TABLE traffic_view_jobs (
    view_id    BINARY(16) NOT NULL PRIMARY KEY,
    org_id     VARCHAR(255) NOT NULL,
    status     VARCHAR(16) NOT NULL DEFAULT 'pending',
    s3_key     TEXT NULL,
    error      TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    updated_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    CONSTRAINT traffic_view_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE INDEX ix_traffic_view_jobs_org_id ON traffic_view_jobs (org_id);
