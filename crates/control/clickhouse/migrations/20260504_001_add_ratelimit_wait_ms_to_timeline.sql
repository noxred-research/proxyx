-- Recreate http_captures_timeline MV to include `ratelimit_wait_ms`.
--
-- ClickHouse does not allow ADD COLUMN on a MaterializedView; the only
-- way to change the projection is DROP + CREATE. The inner table is
-- dropped along with the MV, but the source `http_captures` retains all
-- rows, so the new MV will be backfilled from future inserts.
--
-- This migration is acceptable on staging where the timeline rows are
-- redundant with `http_captures` (we just lose the timeline-friendly
-- sort key for already-inserted rows; new rows immediately get it).
-- For production use, drain captures before running.

DROP TABLE IF EXISTS http_captures_timeline
