-- `expires_at` exists since 20260430000001_create_session_lifecycle.sql.
-- Partial index on the reaper's hot path: only active rows, ordered by expiry.
CREATE INDEX IF NOT EXISTS session_lifecycle_active_expires_idx
    ON session_lifecycle (expires_at)
    WHERE state = 'active';
