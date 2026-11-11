-- Recreate http_captures_by_id MV without body/header columns.
--
-- The two-step get_by_id lookup only reads (id, org_id, timestamp,
-- source_id) from this MV, then fetches the full row from the base
-- table. Dropping bodies shrinks the MV from ~1 TiB to ~4 GiB and
-- eliminates the slow granule reads that caused 4-5s lookup times.
--
-- The DROP uses max_table_size_to_drop = 0 because the old MV with
-- bodies can exceed the default 50 GB safety limit.

DROP TABLE IF EXISTS http_captures_by_id
SETTINGS max_table_size_to_drop = 0;

CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_by_id
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
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

INSERT INTO http_captures_by_id
SELECT id, org_id, timestamp, source_id, inserted_at
FROM http_captures
