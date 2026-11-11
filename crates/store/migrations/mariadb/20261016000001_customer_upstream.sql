-- Org-owned static units: a customer upstream (plan section 7) belongs to one org
-- and is leasable only by it. Git-synced and operator-listed inventory has no owner.
ALTER TABLE inventory
    ADD COLUMN IF NOT EXISTS owner_org VARCHAR(64) NULL,
    ADD CONSTRAINT inventory_owner_org_format CHECK (owner_org REGEXP '(?-i)^[a-z0-9_-]{1,64}$'),
    -- One live upstream per org. A retired row keeps its owner for the audit trail.
    -- NULL for a shared unit and for a retired one: only live owned rows collide.
    ADD COLUMN IF NOT EXISTS live_owner VARCHAR(64) AS (IF(state <> 'retired', owner_org, NULL)) STORED,
    ADD UNIQUE KEY inventory_one_live_unit_per_owner (live_owner);

-- Login of each customer upstream, in clear text like the session proxy's orgs.proxy_password
-- (Vault writes are not available to the service). The database is private to ProxyX.
-- No route returns these columns; the gateway and warmer read them with the snapshot.
CREATE TABLE IF NOT EXISTS customer_credentials (
    org        VARCHAR(64) NOT NULL PRIMARY KEY,
    username   VARCHAR(255) NOT NULL,
    password   TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    rotated_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    CONSTRAINT customer_credentials_org_format CHECK (org REGEXP '(?-i)^[a-z0-9_-]{1,64}$')
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
