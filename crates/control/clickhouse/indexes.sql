-- Skip indexes on http_captures.
--
-- Notes on choices:
-- * `set(N)` for low-cardinality categorical columns (status_code, method) —
--   prunes any granule whose set of distinct values doesn't include the
--   predicate. Far more selective than minmax for these.
-- * `lower(col)` ngrambf for case-insensitive substring search on host/path.
--   ILIKE pruning via raw ngrambf is unreliable across CH versions; routing
--   `IContains` through `lower(col) LIKE lower(pattern)` keeps pruning predictable.
-- * `lower(body)` tokenbf for case-insensitive token search on bodies. Body
--   columns are non-nullable in init.sql for this reason — Nullable(String)
--   tokenbf was rejected by CH 24.x and `coalesce()`-wrapped expressions
--   stop the planner from seeing the index (CH issues #73870, #94689).
-- * `bloom_filter` on `correlation_id` for fast exact-match scoped to a
--   known org. Map-key access (the previous attempt against
--   `request_headers['X-ProxyX-Agent']`) couldn't be indexed reliably,
--   so the value is hoisted to its own nullable column.
-- * `minmax` on `length(body)` for cheap pruning of `Length` filters in the
--   new query API.

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_status (status_code)
    TYPE set(64) GRANULARITY 4;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_method (method)
    TYPE set(16) GRANULARITY 4;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_host_lower lower(host)
    TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 4;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_path_lower lower(path)
    TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 4;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_response_body_lower lower(response_body)
    TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 2;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_request_body_lower lower(request_body)
    TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 2;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_response_body_length length(response_body)
    TYPE minmax GRANULARITY 4;

ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_request_body_length length(request_body)
    TYPE minmax GRANULARITY 4;

-- Correlation id lookup. Bloom filter supports exact-match (`=`) and
-- `IN (...)` predicates with NULL-safe semantics in CH.
ALTER TABLE http_captures ADD INDEX IF NOT EXISTS ix_correlation_id correlation_id
    TYPE bloom_filter(0.01) GRANULARITY 4;


-- Materialized view for single-row lookups by ID.
-- Sort key (id) enables a cheap locator lookup: given a UUID we resolve
-- (source_id, timestamp) and then seek the full row (with bodies) from
-- the base table via its sort key (org_id, source_id, timestamp, id).
-- Body and header columns are intentionally excluded — they bloat the
-- MV without benefit since the two-step get_by_id never reads them here.
CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_by_id
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, source_id,
    inserted_at
FROM http_captures;

-- Materialized view for paginated timeline queries across all sources.
-- Sort key (org_id, timestamp, session_offset, id) enables direct seek for
-- WHERE org_id = 'X' ORDER BY timestamp DESC, session_offset DESC, id DESC LIMIT N.
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


-- Org-scoped per-minute request counts for request-rate charts.
CREATE MATERIALIZED VIEW IF NOT EXISTS http_request_counts_per_minute
ENGINE = SummingMergeTree
PARTITION BY toStartOfWeek(minute)
ORDER BY (org_id, minute)
TTL
    toDateTime(minute) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    org_id,
    toStartOfMinute(timestamp) AS minute,
    count() AS requests
FROM http_captures
GROUP BY org_id, minute;
