-- ProxyX durable state (MariaDB 10.6+). Redis holds only what can be rebuilt from here.
--
-- Same logical schema as migrations/postgres. Differences are in the
-- dialect, not in meaning: every table is InnoDB with utf8mb4_general_ci (a
-- binary collation would make the client driver read every text column as
-- bytes, so text compares without regard to case here: see docs/databases.md;
-- the format checks switch case sensitivity back on with `(?-i)`); timestamps are
-- DATETIME(6) in UTC; JSON is the JSON alias; a partial unique index is a
-- unique index on a generated column that is NULL outside the predicate.

-- Org keys: only the sha256 of the key is stored (never the key).
CREATE TABLE IF NOT EXISTS org_keys (
    key_hash    VARBINARY(32) NOT NULL PRIMARY KEY,
    org         VARCHAR(64) NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    disabled_at DATETIME(6) NULL,
    CONSTRAINT org_keys_key_hash_len CHECK (OCTET_LENGTH(key_hash) = 32),
    CONSTRAINT org_keys_org_format CHECK (org REGEXP '(?-i)^[a-z0-9_-]{1,64}$')
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS org_keys_org ON org_keys (org);

-- Versioned policy documents. One row per version; at most one current.
-- `current_one` is 1 for the current row and NULL for the others, so the
-- unique index lets any number of old versions exist and exactly one current.
CREATE TABLE IF NOT EXISTS policies (
    id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scope       VARCHAR(16) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    target      TEXT NULL,
    version     INT NOT NULL,
    doc         JSON NOT NULL,
    `current`   BOOLEAN NOT NULL DEFAULT TRUE,
    actor       VARCHAR(255) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    current_one TINYINT AS (IF(`current`, 1, NULL)) STORED,
    CONSTRAINT policies_scope_check CHECK (scope IN ('global', 'route_class', 'org')),
    CONSTRAINT policies_name_check CHECK (name <> ''),
    CONSTRAINT policies_version_check CHECK (version > 0),
    UNIQUE KEY policies_scope_name_version (scope, name, version),
    UNIQUE KEY policies_one_current (scope, name, current_one)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- Static IP inventory with state and deadlines.
CREATE TABLE IF NOT EXISTS inventory (
    ip              VARCHAR(45) NOT NULL PRIMARY KEY,
    provider        VARCHAR(64) NOT NULL,
    region          VARCHAR(64) NOT NULL,
    subtype         VARCHAR(32) NOT NULL,
    entry           JSON NOT NULL,
    state           VARCHAR(24) NOT NULL DEFAULT 'candidate',
    state_since     DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    cooldown_until  DATETIME(6) NULL,
    quarantined_at  DATETIME(6) NULL,
    retest_at       DATETIME(6) NULL,
    offline_since   DATETIME(6) NULL,
    last_check_at   DATETIME(6) NULL,
    exit_ip         VARCHAR(45) NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    updated_at      DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    CONSTRAINT inventory_state_check CHECK (state IN (
        'candidate', 'available', 'leased', 'cooldown', 'quarantined',
        'rotating', 'offline', 'replace_requested', 'retired'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS inventory_provider ON inventory (provider);
CREATE INDEX IF NOT EXISTS inventory_state ON inventory (state);

-- Reputation scores, one row per check, so the replacement rule can look at
-- consecutive checks from several services.
CREATE TABLE IF NOT EXISTS ip_scores (
    id         BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip         VARCHAR(45) NOT NULL,
    source     VARCHAR(64) NOT NULL,
    risk       SMALLINT NOT NULL,
    flags      JSON NOT NULL DEFAULT '[]',
    checked_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    CONSTRAINT ip_scores_risk_check CHECK (risk BETWEEN 0 AND 100)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS ip_scores_ip ON ip_scores (ip, source, checked_at DESC);

-- Block history for quarantine and replacement. A target block has a target
-- and an expiry (it is re-seeded into Redis after a loss); an IP-wide block
-- has no target. MariaDB has no partial index: `ip_blocks_active` covers all rows.
CREATE TABLE IF NOT EXISTS ip_blocks (
    id           BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip           VARCHAR(45) NOT NULL,
    target       VARCHAR(255) NULL,
    source       VARCHAR(64) NOT NULL,
    signal_type  VARCHAR(64) NOT NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    expires_at   DATETIME(6) NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS ip_blocks_ip ON ip_blocks (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ip_blocks_active ON ip_blocks (expires_at);

-- Operator org blocks.
CREATE TABLE IF NOT EXISTS org_blocks (
    id          BINARY(16) NOT NULL PRIMARY KEY,
    org         VARCHAR(64) NOT NULL,
    scope       VARCHAR(16) NOT NULL,
    scope_value VARCHAR(255) NOT NULL,
    reason      TEXT NOT NULL,
    operator    VARCHAR(255) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    expires_at  DATETIME(6) NULL,
    revoked_at  DATETIME(6) NULL,
    CONSTRAINT org_blocks_org_format CHECK (org REGEXP '(?-i)^[a-z0-9_-]{1,64}$'),
    CONSTRAINT org_blocks_scope_check CHECK (scope IN ('ip', 'provider', 'route_class', 'pool'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS org_blocks_org ON org_blocks (org);

-- Content hash of each git data source that was synced into the database.
CREATE TABLE IF NOT EXISTS data_sources (
    name       VARCHAR(255) NOT NULL PRIMARY KEY,
    sha256     VARCHAR(64) NOT NULL,
    applied_at DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- Append-only audit trail. Holds actor, action and subject, never a secret.
CREATE TABLE IF NOT EXISTS audit (
    id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    at      DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    actor   VARCHAR(255) NOT NULL,
    action  VARCHAR(64) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    detail  JSON NOT NULL DEFAULT '{}'
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
CREATE INDEX IF NOT EXISTS audit_subject ON audit (subject, at DESC);

-- MariaDB runs no trigger for TRUNCATE (it is DDL): the application user must not hold
-- the DROP privilege on this table, see docs/databases.md.
DROP TRIGGER IF EXISTS audit_no_update;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit rows are append-only';
END;
DROP TRIGGER IF EXISTS audit_no_delete;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit rows are append-only';
END;

-- Transaction-scoped named locks (the role of pg_advisory_xact_lock): a
-- transaction that updates the row of a name holds the lock until it ends.
CREATE TABLE IF NOT EXISTS advisory_locks (
    name VARCHAR(255) NOT NULL PRIMARY KEY
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

-- One row per lock name the code takes, so a lock is always a row that exists:
-- two first users never race to insert it. `org_block:N` are the 64 buckets an org
-- hashes to.
INSERT IGNORE INTO advisory_locks (name) VALUES ('inventory'), ('policies');
INSERT IGNORE INTO advisory_locks (name)
WITH RECURSIVE n (i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 63)
SELECT CONCAT('org_block:', i) FROM n;
