CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_by_agent_hierarchy
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, parent_correlation_id, correlation_id, tool_call_id, timestamp, session_offset, id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    allow_nullable_key = 1,
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, session_offset, source, source_id,
    correlation_id, parent_correlation_id, account_id, tool_call_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures;

INSERT INTO http_captures_by_agent_hierarchy
SELECT
    id, org_id, timestamp, session_offset, source, source_id,
    correlation_id, parent_correlation_id, account_id, tool_call_id,
    method, path, host, scheme, session_id, proxy_id,
    status_code, duration_ms, ratelimit_wait_ms, request_size, response_size,
    inserted_at
FROM http_captures;
