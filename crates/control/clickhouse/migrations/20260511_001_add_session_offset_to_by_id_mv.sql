-- Add session_offset to http_captures_by_id MV so the step-2 get_by_id
-- query can bind the full sort key (org_id, source_id, timestamp,
-- session_offset, id), reducing each per-part scan to a single granule.

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
    id, org_id, timestamp, session_offset, source_id,
    inserted_at
FROM http_captures;

INSERT INTO http_captures_by_id
SELECT id, org_id, timestamp, session_offset, source_id, inserted_at
FROM http_captures
