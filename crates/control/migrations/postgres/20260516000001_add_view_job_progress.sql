-- Add progress tracking and debouncing columns to traffic_view_jobs.
-- query_id is the ClickHouse query identifier used to track export progress
-- via system.processes / system.query_log.
ALTER TABLE traffic_view_jobs
    ADD COLUMN IF NOT EXISTS query_id     TEXT,
    ADD COLUMN IF NOT EXISTS read_rows    BIGINT,
    ADD COLUMN IF NOT EXISTS written_rows BIGINT,
    ADD COLUMN IF NOT EXISTS total_rows   BIGINT,
    ADD COLUMN IF NOT EXISTS last_checked_at TIMESTAMPTZ;
