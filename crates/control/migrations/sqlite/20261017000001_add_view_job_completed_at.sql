-- `completed_at` exists since 20260515000001_create_traffic_view_jobs.sql.
CREATE INDEX IF NOT EXISTS ix_traffic_view_jobs_completed_at
    ON traffic_view_jobs (completed_at)
    WHERE status = 'completed';
