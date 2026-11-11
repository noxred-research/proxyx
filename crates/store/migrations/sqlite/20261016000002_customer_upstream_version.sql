-- Version of an org-owned upstream: every set, rotate and clear of it takes a new
-- value from one counter, so a version names one state of one row. A check through
-- the upstream (validate, rotate-secret) records its result only when the version is
-- still the one read before the check, so a result about an old proxy never marks a
-- replacement available or overwrites its login.
--
-- SQLite has no sequences: the counter is one row, advanced inside the writing
-- transaction (the only writer there is) by `UPDATE ... RETURNING`.
CREATE TABLE IF NOT EXISTS inventory_upstream_version_seq (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO inventory_upstream_version_seq (id, value) VALUES (1, 0);
ALTER TABLE inventory ADD COLUMN upstream_version INTEGER NOT NULL DEFAULT 0;
