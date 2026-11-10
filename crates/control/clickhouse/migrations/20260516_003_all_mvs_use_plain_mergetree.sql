-- Switch all remaining MVs from ReplicatedReplacingMergeTree to
-- ReplicatedMergeTree. MVs are read-only projections — dedup belongs
-- on the base table, not on projections. ReplacingMergeTree adds
-- significant per-read overhead even without FINAL.

-- http_captures_by_id
DROP TABLE IF EXISTS http_captures_by_id;

CREATE MATERIALIZED VIEW IF NOT EXISTS http_captures_by_id
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, session_offset, source_id, inserted_at
FROM http_captures;

INSERT INTO http_captures_by_id
SELECT id, org_id, timestamp, session_offset, source_id, inserted_at
FROM http_captures;

-- ws_messages_by_id
DROP TABLE IF EXISTS ws_messages_by_id;

CREATE MATERIALIZED VIEW IF NOT EXISTS ws_messages_by_id
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, org_id, timestamp, source_id, session_offset, inserted_at
FROM ws_messages;

INSERT INTO ws_messages_by_id
SELECT id, org_id, timestamp, source_id, session_offset, inserted_at
FROM ws_messages;

-- ws_messages_by_parent
DROP TABLE IF EXISTS ws_messages_by_parent;

CREATE MATERIALIZED VIEW IF NOT EXISTS ws_messages_by_parent
ENGINE = ReplicatedMergeTree
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (parent_event_id, timestamp, session_offset, id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY TO VOLUME 'cold'
SETTINGS
    storage_policy = 'tiered'
AS SELECT
    id, parent_event_id, org_id, timestamp, session_offset,
    direction, opcode, session_id, proxy_id, source, source_id, host,
    payload, payload_size, payload_truncated, payload_is_text,
    was_compressed, close_code, close_reason, inserted_at
FROM ws_messages;

INSERT INTO ws_messages_by_parent
SELECT
    id, parent_event_id, org_id, timestamp, session_offset,
    direction, opcode, session_id, proxy_id, source, source_id, host,
    payload, payload_size, payload_truncated, payload_is_text,
    was_compressed, close_code, close_reason, inserted_at
FROM ws_messages
