-- Nothing to do on this backend: the Postgres migration of the same version only
-- touches the vestigial http_captures table (created, then dropped again by
-- 20260701000001; captures live in the capture store). The no-op keeps the
-- version numbers equal on every backend.
SELECT 1;
