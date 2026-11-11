-- Recreate http_captures_timeline MV with session_offset in the ORDER BY key.
--
-- The query sorts by (timestamp, session_offset, id) but the MV's ORDER BY
-- was (org_id, timestamp, id), forcing ClickHouse to scan all matching rows
-- and re-sort. Adding session_offset lets the engine serve DESC pagination
-- directly from the index.
--
-- DROP + CREATE is required; ClickHouse does not allow ALTER on MV sort keys.
-- Backfill repopulates from the base table so no data is lost.

DROP TABLE IF EXISTS http_captures_timeline;

CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_timeline
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, timestamp, session_offset, id)
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
