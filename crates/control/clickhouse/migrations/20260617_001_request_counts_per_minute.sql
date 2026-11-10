-- Add an org-scoped per-minute request-count projection for request-rate charts.
-- The query path groups by one-minute buckets, so storing the minute rollup avoids
-- scanning raw captures for every dashboard refresh.

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

INSERT INTO http_request_counts_per_minute
SELECT
    org_id,
    toStartOfMinute(timestamp) AS minute,
    count() AS requests
FROM http_captures
GROUP BY org_id, minute;
