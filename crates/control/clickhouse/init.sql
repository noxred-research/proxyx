CREATE TABLE IF NOT EXISTS http_captures (
    id                  UUID,
    org_id              LowCardinality(String),
    timestamp           DateTime64(3, 'UTC'),
    session_offset      UInt64 DEFAULT 0,
    method              LowCardinality(String),
    path                String,
    host                String,
    scheme              LowCardinality(String),
    session_id          String,
    proxy_id            LowCardinality(String),
    request_headers     Map(String, String),
    -- Bodies are non-nullable so tokenbf_v1 / ngrambf_v1 indexes apply.
    -- Empty body = empty string (API-side normalization). The size
    -- columns carry the "was there a wire body" signal independently.
    request_body        String DEFAULT '' CODEC(ZSTD(1)),
    request_size        UInt32,
    status_code         UInt16,
    response_headers    Map(String, String),
    response_body       String DEFAULT '' CODEC(ZSTD(1)),
    response_size       UInt32,
    duration_ms         UInt32,
    ratelimit_wait_ms   UInt32,
    source              LowCardinality(String),
    source_id           String,
    correlation_id      Nullable(String),
    parent_correlation_id Nullable(String),
    account_id      Nullable(String),
    tool_call_id     Nullable(String),
    -- Server-set wall-clock at insert time. Used as the ReplacingMergeTree
    -- version: when proxy retries replay the same logical capture and
    -- collide on the sort-key tuple, the latest write wins at merge time.
    inserted_at         DateTime64(9, 'UTC') DEFAULT now64(9)
)
ENGINE = ReplicatedReplacingMergeTree(inserted_at)
PARTITION BY toStartOfWeek(timestamp)
ORDER BY (org_id, source_id, timestamp, session_offset, id)
-- 3 days on the local hot disk: a 7-day window plus large merges
-- filled the local disk of a production node.
TTL
    toDateTime(timestamp) + INTERVAL 3 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 12 MONTH DELETE
SETTINGS
    index_granularity = 8192,
    storage_policy = 'tiered',
    -- A TTL change only recalculates part TTL info instead of rewriting
    -- every part (2.3 TiB on the cold tier in prod).
    materialize_ttl_recalculate_only = 1,
    -- Graceful degradation under heavy write/merge load (wide body columns on
    -- the Azure Blob cold tier are memory-heavy to merge). Cap per-merge size,
    -- prefer vertical (column-by-column) merges, and apply insert backpressure
    -- (delay inserts as parts accumulate) instead of letting merges OOM.
    max_bytes_to_merge_at_max_space_in_pool = 21474836480,
    vertical_merge_algorithm_min_rows_to_activate = 8192,
    parts_to_delay_insert = 300,
    max_delay_to_insert = 10,
    -- Each replica merges its own cold (Azure Blob) parts. The default
    -- (10800s) designates ONE replica per cold merge and lets the others
    -- fetch the result; if that replica dies mid-merge, the fetch entries
    -- reference a part that never existed and wedge the replication queue
    -- (NO_REPLICA_HAS_PART).
    remote_fs_execute_merges_on_single_replica_time_threshold = 0;

-- Migration tracking. Records which ClickHouse migrations have been
-- applied so they are not re-run on subsequent API restarts.
-- ReplacingMergeTree deduplicates by name; the applied_at version
-- column means a re-insert is harmless (latest wins, same row).
CREATE TABLE IF NOT EXISTS _ch_migrations (
    name        String,
    applied_at  DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplicatedReplacingMergeTree(applied_at)
ORDER BY (name)
SETTINGS
    index_granularity = 64;
