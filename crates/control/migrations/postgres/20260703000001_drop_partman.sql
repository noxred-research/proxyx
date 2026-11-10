-- pg_partman and pg_cron are no longer used.
-- http_captures was dropped from Postgres in 20260701000001; partitioning
-- is vestigial. Remove the scheduled job, partman config, and extensions.

-- Unschedules the hourly maintenance job if it exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        IF EXISTS (
            SELECT 1 FROM cron.job WHERE jobname = 'partman-maintenance'
        ) THEN
            PERFORM cron.unschedule('partman-maintenance');
        END IF;
    END IF;
END$$;

-- Drop partman config for the (already-dropped) http_captures table if present.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'partman' AND table_name = 'part_config'
    ) THEN
        DELETE FROM partman.part_config WHERE parent_table = 'public.http_captures';
    END IF;
END$$;

DROP EXTENSION IF EXISTS pg_partman CASCADE;
DROP EXTENSION IF EXISTS pg_cron CASCADE;
DROP SCHEMA IF EXISTS partman;
