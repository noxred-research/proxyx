-- keep 3 days (was 7) of http_captures on the local hot disk.
-- A 7-day hot window plus large merges can fill the local disk.
--
-- Recalculate-only first: MODIFY TTL starts a MATERIALIZE TTL mutation, and
-- with the default it rewrites every part (2.3 TiB on the cold tier in prod).
-- With this setting it only reads `timestamp` and rewrites the TTL info, so
-- existing hot parts older than 3 days move to cold. Rows are unchanged.
ALTER TABLE http_captures MODIFY SETTING materialize_ttl_recalculate_only = 1;

-- `TTL` on its own line so the single-node local rewrite drops the
-- TO VOLUME entry (local ClickHouse has no cold volume).
ALTER TABLE http_captures MODIFY
TTL
    toDateTime(timestamp) + INTERVAL 3 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 12 MONTH DELETE;
