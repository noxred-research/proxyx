ALTER TABLE http_captures
    ADD COLUMN IF NOT EXISTS parent_correlation_id Nullable(String) AFTER correlation_id;

ALTER TABLE http_captures
    ADD INDEX IF NOT EXISTS ix_parent_correlation_id parent_correlation_id
    TYPE bloom_filter(0.01) GRANULARITY 4;

DROP TABLE IF EXISTS http_captures_timeline;

CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_timeline
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, timestamp, session_offset, id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, session_offset, source, source_id, correlation_id, parent_correlation_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures;

INSERT INTO http_captures_timeline
SELECT
    id, org_id, timestamp, session_offset, source, source_id, correlation_id, parent_correlation_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures;
