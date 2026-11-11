-- Add `expires_at` to session_lifecycle so an API-side reaper can close sessions whose
-- Redis TTL elapsed without an explicit DELETE.
ALTER TABLE session_lifecycle ADD COLUMN IF NOT EXISTS expires_at DATETIME(6) NULL;

-- Backfill existing rows with a sensible historic default (1h after open).
UPDATE session_lifecycle SET expires_at = opened_at + INTERVAL 1 HOUR WHERE expires_at IS NULL;

ALTER TABLE session_lifecycle MODIFY expires_at DATETIME(6) NOT NULL;

-- The reaper's hot path: active rows ordered by expiry. MariaDB has no partial
-- index; leading with `state` makes the active rows one contiguous range.
CREATE INDEX IF NOT EXISTS session_lifecycle_active_expires_idx
    ON session_lifecycle (state, expires_at);
