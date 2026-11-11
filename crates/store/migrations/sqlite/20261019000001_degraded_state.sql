-- A degraded IP is leasable but slow: clean answers over the TTFB or load limit.
-- The gateway leases it only when no normal IP is left.
--
-- SQLite cannot change a CHECK constraint: the table is rebuilt with the wider
-- list of states and its indexes are created again.
CREATE TABLE inventory_rebuilt (
    ip              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    region          TEXT NOT NULL,
    subtype         TEXT NOT NULL,
    entry           TEXT NOT NULL CHECK (json_valid(entry)),
    state           TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN (
        'candidate', 'available', 'leased', 'degraded', 'cooldown', 'quarantined',
        'rotating', 'offline', 'replace_requested', 'retired')),
    state_since     INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    cooldown_until  INTEGER,
    quarantined_at  INTEGER,
    retest_at       INTEGER,
    offline_since   INTEGER,
    last_check_at   INTEGER,
    exit_ip         TEXT,
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    updated_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    owner_org       TEXT
        CHECK (owner_org IS NULL OR (length(owner_org) BETWEEN 1 AND 64 AND owner_org NOT GLOB '*[^a-z0-9_-]*')),
    upstream_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO inventory_rebuilt (
    ip, provider, region, subtype, entry, state, state_since, cooldown_until, quarantined_at,
    retest_at, offline_since, last_check_at, exit_ip, created_at, updated_at, owner_org,
    upstream_version)
SELECT ip, provider, region, subtype, entry, state, state_since, cooldown_until, quarantined_at,
       retest_at, offline_since, last_check_at, exit_ip, created_at, updated_at, owner_org,
       upstream_version
FROM inventory;
DROP TABLE inventory;
ALTER TABLE inventory_rebuilt RENAME TO inventory;
CREATE INDEX IF NOT EXISTS inventory_provider ON inventory (provider);
CREATE INDEX IF NOT EXISTS inventory_state ON inventory (state);
CREATE UNIQUE INDEX IF NOT EXISTS inventory_one_live_unit_per_owner
    ON inventory (owner_org) WHERE owner_org IS NOT NULL AND state <> 'retired';
