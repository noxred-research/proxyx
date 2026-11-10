-- Skip indexes on ws_messages.
--
-- Same indexing philosophy as http_captures.indexes.sql:
-- * `set(N)` for low-cardinality categorical columns — exact pruning.
-- * `lower(col)` ngrambf for case-insensitive substring on host.
-- * `lower(payload)` tokenbf for token search across message bodies.
-- * `minmax` for length / size predicates.
-- * `bloom_filter` for cross-table joins on parent_event_id.

ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_direction (direction)
    TYPE set(2) GRANULARITY 4;

ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_opcode (opcode)
    TYPE set(8) GRANULARITY 4;

ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_host_lower lower(host)
    TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 4;

-- Token search on payload. Primary value-add for GraphQL — find by
-- operationName, subscription id, error string, etc. Denser granularity
-- than host because payloads are bigger and pruning matters more.
ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_payload_lower lower(payload)
    TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 2;

-- Pre-truncation size — what queries actually want when filtering on
-- "messages over X bytes".
ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_payload_size (payload_size)
    TYPE minmax GRANULARITY 4;

-- Stored bytes — symmetric with http_captures' length(body) minmax.
ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_payload_length length(payload)
    TYPE minmax GRANULARITY 4;

-- Cross-table joins:
--   WHERE parent_event_id IN (SELECT id FROM http_captures WHERE ...)
-- The MV ws_messages_by_parent is the primary path for direct seeks; this
-- accelerates the join path against the base table when callers arrive
-- with org_id + time already constrained.
ALTER TABLE ws_messages ADD INDEX IF NOT EXISTS ix_ws_parent (parent_event_id)
    TYPE bloom_filter(0.01) GRANULARITY 4;
