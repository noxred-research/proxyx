-- Switch http_captures_timeline from ReplicatedReplacingMergeTree to
-- ReplicatedMergeTree.
--
-- ReplacingMergeTree adds per-read dedup overhead (~40x slower for
-- ORDER BY ... DESC LIMIT N) even without FINAL. The timeline MV is a
-- read-only projection — dedup is unnecessary here; the base table
-- handles it.

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
