-- WebSocket message storage. Schema, engine, partitioning, and TTL tiers
-- mirror `http_captures` so the two tables share operational behavior
-- (merges, backups, cold-tier moves).
--
-- One row per logical WebSocket message — fragments reassembled, RSV1
-- (permessage-deflate) inflated by the proxy. Linked back to the parent
-- `101 Switching Protocols` row in `http_captures` via `parent_event_id`.

CREATE TABLE IF NOT EXISTS ws_messages (
    -- Identity
    id                  UUID,
    parent_event_id     UUID,

    -- Tenancy + scoping (matches http_captures)
    org_id              LowCardinality(String),
    source              LowCardinality(String),
    source_id           String,
    session_id          String,
    proxy_id            LowCardinality(String),
    -- Hoisted from the parent 101 row for query convenience without a JOIN.
    host                LowCardinality(String),

    -- Time + ordering
    timestamp           DateTime64(3, 'UTC'),
    -- Broker-assigned per-key monotonic offset. Sub-millisecond tiebreaker
    -- so multiple messages emitted in the same millisecond keep wire order.
    session_offset      UInt64 DEFAULT 0,

    -- Message classification
    direction           Enum8('c2s' = 1, 's2c' = 2),
    opcode              Enum8('text' = 1, 'binary' = 2, 'close' = 8, 'ping' = 9, 'pong' = 10),

    -- Decompressed payload. String typed for tokenbf_v1 compatibility (matches
    -- http_captures pattern). Binary frames are stored byte-faithfully; the
    -- payload_is_text flag tells consumers whether to UTF-8-decode for display.
    payload             String DEFAULT '' CODEC(ZSTD(3)),
    -- Pre-truncation size. length(payload) == min(payload_size, cap) when
    -- payload_truncated == 1.
    payload_size        UInt32,
    payload_truncated   UInt8,
    payload_is_text     UInt8,
    -- RSV1 was set on the leading wire frame. Indicates the wire bytes were
    -- compressed; the stored payload is already inflated.
    was_compressed      UInt8,

    -- Only meaningful when opcode = 'close'. Per RFC 6455 §5.5.1.
    close_code          UInt16 DEFAULT 0,
    close_reason        String DEFAULT '',

    -- Engine version key. Wall-clock nanoseconds at insert time. When the
    -- proxy retries replay the same logical message and collide on the
    -- sort-key tuple, the latest write wins at merge time.
    inserted_at         DateTime64(9, 'UTC') DEFAULT now64(9)
)
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, source_id, timestamp, session_offset, id)
TTL
    toDateTime(timestamp) + INTERVAL 7 DAY  TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 12 MONTH DELETE
SETTINGS
    index_granularity = 8192,
    storage_policy = 'tiered',
    -- Mirror http_captures graceful merge/backpressure settings (see init.sql).
    max_bytes_to_merge_at_max_space_in_pool = 21474836480,
    vertical_merge_algorithm_min_rows_to_activate = 8192,
    parts_to_delay_insert = 300,
    max_delay_to_insert = 10,
    remote_fs_execute_merges_on_single_replica_time_threshold = 0;

-- Per-conversation playback. Direct seek on parent_event_id; sort key IS
-- the index. Used by every "show this WS conversation" query.
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
    payload, payload_size, payload_truncated, payload_is_text, was_compressed,
    close_code, close_reason, inserted_at
FROM ws_messages;

-- Lightweight single-row lookup by id for GET /orgs/{org}/ws_messages/{id}.
-- Only locator columns needed for the two-step pattern: look up sort-key
-- fields here, then fetch the full row from the base table.
CREATE MATERIALIZED VIEW IF NOT EXISTS ws_messages_by_id
ENGINE = ReplicatedMergeTree
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
