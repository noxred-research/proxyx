-- Add reference counting to session_lifecycle so multiple callers sharing
-- the same (org_id, source, source_id) reuse a single session. The session
-- is only torn down when the last reference is released (ref_count → 0).

ALTER TABLE session_lifecycle ADD COLUMN IF NOT EXISTS ref_count INTEGER NOT NULL DEFAULT 1;

-- At most one active session per (org_id, source, source_id). This is the
-- dedup invariant: a second POST with the same triple attaches to the
-- existing session instead of creating a new one.
CREATE UNIQUE INDEX IF NOT EXISTS session_lifecycle_active_source_uidx
    ON session_lifecycle (org_id, source, source_id)
    WHERE state = 'active';
