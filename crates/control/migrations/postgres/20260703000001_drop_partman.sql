-- pg_partman and pg_cron are no longer used by ProxyX.
-- http_captures was dropped from Postgres in 20260701000001; partitioning is
-- vestigial. This migration may only touch objects ProxyX owns: a database is
-- shared with other products and tenants, and extensions, the `partman` and
-- `cron` schemas and cron jobs exist once per database.
--
-- CHECKSUM NOTE: this file was rewritten after release 0.1.0. The released text
-- ran `DROP EXTENSION pg_partman CASCADE`, `DROP EXTENSION pg_cron CASCADE`,
-- `DROP SCHEMA partman` and `cron.unschedule('partman-maintenance')`, which
-- destroyed the extensions and jobs of every neighbour in the database.
-- Databases that applied the old text keep their checksum row repaired by
-- `Pool::migrate` (the old checksum is pinned in `migrators!(rewritten = ...)`
-- in crates/control/src/db); any other checksum still fails with
-- VersionMismatch.
--
-- ProxyX no longer installs pg_partman or pg_cron (see 20250425000003), so it
-- leaves the extensions, the `partman` schema and the cron jobs alone. An
-- operator who installed them for an old ProxyX can remove them by hand.

-- Remove the partman configuration row of this schema's own http_captures
-- table, if an old deployment registered one and this role may change it.
-- Rows of other schemas stay.
DO $$
BEGIN
    IF to_regclass('partman.part_config') IS NOT NULL
       AND has_table_privilege(current_user, 'partman.part_config', 'SELECT')
       AND has_table_privilege(current_user, 'partman.part_config', 'DELETE')
    THEN
        DELETE FROM partman.part_config
        WHERE parent_table = current_schema() || '.http_captures';
    END IF;
END$$;
