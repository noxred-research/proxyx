-- http_captures partition bootstrap. NO LONGER USES pg_partman / pg_cron.
--
-- History: this migration originally ran `CREATE EXTENSION pg_partman` +
-- `pg_cron` to auto-partition http_captures. Those extensions are not bundled
-- in the stock cloudnative-pg image (only AWS's image had them), so a fresh
-- database on Azure/dev could never apply it. http_captures is vestigial anyway
-- -- it was dropped from Postgres in 20260701000001 (captures live in
-- ClickHouse) and partman was torn down in 20260703000001 -- so the extension
-- dependency serves no purpose.
--
-- The parent table (20250425000002) is PARTITION BY RANGE, which rejects every
-- insert until at least one partition exists. Attach a single catch-all DEFAULT
-- partition so the table is functional without partman. No automatic monthly
-- rollover / retention, which is irrelevant for a table that is dropped a few
-- migrations later.
--
-- CHECKSUM NOTE: rewriting this already-applied migration changes its sqlx
-- checksum. Fresh databases apply the new content cleanly. EXISTING deployments
-- (staging/prod) recorded the old checksum and will fail `sqlx migrate run` with
-- VersionMismatch(20250425000003). When that happens, update the stored checksum
-- by hand once, e.g.:
--   UPDATE _sqlx_migrations
--   SET checksum = <new sha384 of this file>
--   WHERE version = 20250425000003;
-- (or delete the row -- the DEFAULT partition create is idempotent). No
-- automatic repair is wired in on purpose.

CREATE TABLE IF NOT EXISTS http_captures_default
    PARTITION OF http_captures DEFAULT;
