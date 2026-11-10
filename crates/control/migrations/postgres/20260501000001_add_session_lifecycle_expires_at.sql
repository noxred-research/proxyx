-- Add `expires_at` to session_lifecycle so a API-side reaper can
-- close sessions whose Redis TTL elapsed without an explicit DELETE.
-- Without this column, sessions whose clients never call DELETE leak
-- as state='active' rows forever and pollute the (org_id, state) index.

ALTER TABLE session_lifecycle ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Backfill existing rows with a sensible historic default (1h after open).
-- After the reaper runs once, all such rows transition to 'closed'.
UPDATE session_lifecycle
   SET expires_at = opened_at + interval '1 hour'
 WHERE expires_at IS NULL;

ALTER TABLE session_lifecycle ALTER COLUMN expires_at SET NOT NULL;

-- Partial index on the reaper's hot path: only active rows, ordered by
-- expiry. Tiny relative to the full table because closed rows dominate.
CREATE INDEX IF NOT EXISTS session_lifecycle_active_expires_idx
    ON session_lifecycle (expires_at)
    WHERE state = 'active';
