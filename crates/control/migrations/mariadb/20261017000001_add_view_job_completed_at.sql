-- Expiry clock for traffic view exports. updated_at moves on every
-- create_view upsert, so it cannot measure age since completion.
ALTER TABLE traffic_view_jobs ADD COLUMN IF NOT EXISTS completed_at DATETIME(6) NULL;

-- Existing completed exports start their TTL from their last update.
UPDATE traffic_view_jobs SET completed_at = updated_at
WHERE status = 'completed' AND completed_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_traffic_view_jobs_completed_at
    ON traffic_view_jobs (status, completed_at);
