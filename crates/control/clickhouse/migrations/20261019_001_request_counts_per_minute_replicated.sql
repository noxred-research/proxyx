-- Recreate http_request_counts_per_minute on ReplicatedSummingMergeTree.
-- 20260617_001 created it on plain SummingMergeTree, so its inner table is
-- local to each replica: an http_captures insert fires the MV only on the
-- replica that received it, and on multi-replica clusters (prod today) the
-- per-minute counts drift apart and request-rate charts depend on which
-- replica answers. Every other proxyx table and MV is already Replicated*.
-- The chart is empty until the backfill below finishes.
-- The backfill rebuilds history from http_captures, which deletes rows after
-- 12 months while the old view never expires, so this must run before 2027-06
-- or counts older than the capture TTL would be lost (staging 2026-10-19:
-- oldest count 2026-06-23 21:42, oldest capture 2026-06-23 21:42:36). For
-- prod, run `SELECT min(minute) FROM http_request_counts_per_minute` and
-- `SELECT min(timestamp) FROM http_captures` first and record them in .
-- Run against one fixed replica (not a load-balanced Service) so SYNC REPLICA
-- and the backfill INSERT hit the same host: captures not yet replicated there
-- would otherwise be missed, and a later replica fetch does not fire the MV.

DROP TABLE IF EXISTS http_request_counts_per_minute;

CREATE MATERIALIZED VIEW IF NOT EXISTS http_request_counts_per_minute
ENGINE = ReplicatedSummingMergeTree
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

SYSTEM SYNC REPLICA http_captures;

INSERT INTO http_request_counts_per_minute
SELECT
    org_id,
    toStartOfMinute(timestamp) AS minute,
    count() AS requests
FROM http_captures
GROUP BY org_id, minute;
