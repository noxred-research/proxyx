-- Org-owned static units: a customer upstream (plan section 7) belongs to one org
-- and is leasable only by it. Git-synced and operator-listed inventory has no owner.
ALTER TABLE inventory ADD COLUMN IF NOT EXISTS owner_org TEXT
    CHECK (owner_org ~ '^[a-z0-9_-]{1,64}$');

-- One live upstream per org. A retired row keeps its owner for the audit trail.
CREATE UNIQUE INDEX IF NOT EXISTS inventory_one_live_unit_per_owner
    ON inventory (owner_org) WHERE owner_org IS NOT NULL AND state <> 'retired';

-- Login of each customer upstream, in clear text like the session proxy's orgs.proxy_password
-- (Vault writes are not available to the service). Postgres is private to ProxyX.
-- No route returns these columns; the gateway and warmer read them with the snapshot.
CREATE TABLE IF NOT EXISTS customer_credentials (
    org        TEXT PRIMARY KEY CHECK (org ~ '^[a-z0-9_-]{1,64}$'),
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
