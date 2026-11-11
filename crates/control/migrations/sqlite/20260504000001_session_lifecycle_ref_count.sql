-- `ref_count` exists since 20260430000001_create_session_lifecycle.sql.
-- At most one active session per (org_id, source, source_id): the dedup invariant.
CREATE UNIQUE INDEX IF NOT EXISTS session_lifecycle_active_source_uidx
    ON session_lifecycle (org_id, source, source_id)
    WHERE state = 'active';
