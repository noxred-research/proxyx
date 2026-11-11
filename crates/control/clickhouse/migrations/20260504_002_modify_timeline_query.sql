-- Recreate http_captures_timeline MV with `ratelimit_wait_ms` in the
-- SELECT projection. Mirrors the definition in indexes.sql so fresh
-- installs and existing clusters converge.
--
-- The backfill INSERT repopulates the MV from the base table so
-- historical rows are not lost after the DROP in migration 001.

CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_timeline
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, timestamp, id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, session_offset, source, source_id, correlation_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures;

INSERT INTO http_captures_timeline
SELECT
    id, org_id, timestamp, session_offset, source, source_id, correlation_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures
