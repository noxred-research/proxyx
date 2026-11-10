-- Range-partitioned http_captures table.
-- Matches the backend's final schema after reindex + compression migrations.
-- Partition management is handled by pg_partman (configured separately).

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS http_captures (
    id                  UUID NOT NULL,
    org_id              TEXT NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL,
    method              TEXT NOT NULL,
    path                TEXT NOT NULL,
    host                TEXT NOT NULL,
    scheme              TEXT NOT NULL,
    session_id          TEXT NOT NULL,
    proxy_id            TEXT NOT NULL,
    num_request         INTEGER NOT NULL DEFAULT 0,
    request_headers     JSONB NOT NULL DEFAULT '{}',
    request_body        TEXT,
    request_size        INTEGER NOT NULL DEFAULT 0,
    status_code         INTEGER NOT NULL DEFAULT 0,
    response_headers    JSONB NOT NULL DEFAULT '{}',
    response_body       TEXT,
    response_size       INTEGER NOT NULL DEFAULT 0,
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    ratelimit_wait_ms   INTEGER NOT NULL DEFAULT 0,
    source              TEXT NOT NULL DEFAULT '',
    source_id           TEXT,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Body compression (inherited by future partitions)
ALTER TABLE http_captures
    ALTER COLUMN request_body SET COMPRESSION pglz,
    ALTER COLUMN response_body SET COMPRESSION pglz;

-- Org-scoped browsing with source filter + time sort.
-- Also covers org-only queries via leading prefix.
CREATE INDEX ix_http_captures_org_source_ts
    ON http_captures (org_id, source, timestamp DESC);

-- Unscoped: recon domain scoping + per-run drill-down with sequence range.
CREATE INDEX ix_http_captures_source_sid_seq
    ON http_captures (source, source_id, num_request);

-- Unscoped: admin drill-down by source_id with sequence range.
CREATE INDEX ix_http_captures_sid_seq
    ON http_captures (source_id, num_request);

-- Unscoped: time-sorted browsing with no filters.
CREATE INDEX ix_http_captures_ts
    ON http_captures (timestamp DESC);

-- Substring search on request path (ILIKE '%/api/v2%').
CREATE INDEX ix_http_captures_path_trgm
    ON http_captures USING gin (path gin_trgm_ops);

-- Substring search on host/subdomain (ILIKE '%staging.example%').
CREATE INDEX ix_http_captures_host_trgm
    ON http_captures USING gin (host gin_trgm_ops);
