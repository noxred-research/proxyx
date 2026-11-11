-- Progress tracking and debouncing columns of traffic_view_jobs.
-- query_id is the capture store's query identifier used to track export progress.
ALTER TABLE traffic_view_jobs
    ADD COLUMN IF NOT EXISTS query_id        VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS read_rows       BIGINT NULL,
    ADD COLUMN IF NOT EXISTS written_rows    BIGINT NULL,
    ADD COLUMN IF NOT EXISTS total_rows      BIGINT NULL,
    ADD COLUMN IF NOT EXISTS last_checked_at DATETIME(6) NULL;
