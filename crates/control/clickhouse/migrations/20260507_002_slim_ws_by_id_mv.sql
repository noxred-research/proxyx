-- Recreate ws_messages_by_id MV without payload and non-locator columns.
--
-- The two-step get_ws_by_id lookup only reads (id, org_id, timestamp,
-- source_id, session_offset) from this MV, then fetches the full row
-- from the base table. Dropping payload and ancillary columns shrinks
-- the MV and eliminates slow granule reads at scale.

DROP TABLE IF EXISTS ws_messages_by_id;

CREATE MATERIALIZED VIEW IF NOT EXISTS ws_messages_by_id
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, source_id, session_offset,
    inserted_at
FROM ws_messages;

INSERT INTO ws_messages_by_id
SELECT id, org_id, timestamp, source_id, session_offset, inserted_at
FROM ws_messages
