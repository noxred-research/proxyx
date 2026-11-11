-- Org-owned static units: a customer upstream (plan section 7) belongs to one org
-- and is leasable only by it. Git-synced and operator-listed inventory has no owner.
ALTER TABLE inventory ADD COLUMN owner_org TEXT
    CHECK (owner_org IS NULL OR (length(owner_org) BETWEEN 1 AND 64 AND owner_org NOT GLOB '*[^a-z0-9_-]*'));

-- One live upstream per org. A retired row keeps its owner for the audit trail.
CREATE UNIQUE INDEX IF NOT EXISTS inventory_one_live_unit_per_owner
    ON inventory (owner_org) WHERE owner_org IS NOT NULL AND state <> 'retired';

-- Login of each customer upstream, in clear text like the session proxy's orgs.proxy_password
-- (Vault writes are not available to the service). The database is private to ProxyX.
-- No route returns these columns; the gateway and warmer read them with the snapshot.
CREATE TABLE IF NOT EXISTS customer_credentials (
    org        TEXT PRIMARY KEY CHECK (length(org) BETWEEN 1 AND 64 AND org NOT GLOB '*[^a-z0-9_-]*'),
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    rotated_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)
);
