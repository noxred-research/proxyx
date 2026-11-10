-- Version of an org-owned upstream: every set, rotate and clear of it takes a new
-- value from one sequence, so a version names one state of one row. A check through
-- the upstream (validate, rotate-secret) records its result only when the version is
-- still the one read before the check, so a result about an old proxy never marks a
-- replacement available or overwrites its login.
CREATE SEQUENCE IF NOT EXISTS inventory_upstream_version_seq;
ALTER TABLE inventory ADD COLUMN IF NOT EXISTS upstream_version BIGINT NOT NULL
    DEFAULT (NEXTVAL(inventory_upstream_version_seq));
