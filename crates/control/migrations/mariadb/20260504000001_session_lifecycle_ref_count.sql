-- Reference counting so multiple callers sharing the same (org_id, source,
-- source_id) reuse one session; torn down when the last reference is released.
ALTER TABLE session_lifecycle ADD COLUMN IF NOT EXISTS ref_count INT NOT NULL DEFAULT 1;

-- At most one active session per (org_id, source, source_id). MariaDB has no partial
-- unique index: `active_key` is 1 for an active row and NULL for the others, and
-- NULLs never collide in a unique index.
ALTER TABLE session_lifecycle
    ADD COLUMN IF NOT EXISTS active_key TINYINT AS (IF(state = 'active', 1, NULL)) STORED,
    ADD UNIQUE KEY session_lifecycle_active_source_uidx (org_id, source, source_id, active_key);
