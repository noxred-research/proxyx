-- Drop the source-leading index (unused; queries always scope by org_id + source_id).
DROP INDEX IF EXISTS ix_http_captures_source_sid_seq;

-- Composite index for org-scoped source_id queries sorted by timestamp.
-- NOTE: on staging/prod this was applied manually per-partition using
-- CREATE INDEX CONCURRENTLY to avoid write locks. This non-concurrent
-- form exists for fresh deploys and test databases.
CREATE INDEX IF NOT EXISTS ix_http_captures_org_sid_ts
    ON http_captures (org_id, source_id, timestamp DESC);
