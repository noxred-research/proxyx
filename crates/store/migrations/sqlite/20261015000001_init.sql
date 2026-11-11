-- ProxyX durable state (SQLite 3.40+, one node). Redis holds only what can be rebuilt from here.
--
-- Same logical schema as migrations/postgres. Differences are in the
-- dialect, not in meaning: a timestamp is INTEGER microseconds since the Unix
-- epoch (UTC; the column default is the current time, to the millisecond), JSON is TEXT
-- checked with json_valid(), a UUID is a 16 byte BLOB and an org id is checked
-- with GLOB because SQLite has no built-in regular expressions.

-- Org keys: only the sha256 of the key is stored (never the key).
CREATE TABLE IF NOT EXISTS org_keys (
    key_hash    BLOB PRIMARY KEY CHECK (length(key_hash) = 32),
    org         TEXT NOT NULL CHECK (length(org) BETWEEN 1 AND 64 AND org NOT GLOB '*[^a-z0-9_-]*'),
    label       TEXT NOT NULL DEFAULT '',
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    disabled_at INTEGER
);
CREATE INDEX IF NOT EXISTS org_keys_org ON org_keys (org);

-- Versioned policy documents. One row per version; at most one current.
CREATE TABLE IF NOT EXISTS policies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL CHECK (scope IN ('global', 'route_class', 'org')),
    name       TEXT NOT NULL CHECK (name <> ''),
    target     TEXT,
    version    INTEGER NOT NULL CHECK (version > 0),
    doc        TEXT NOT NULL CHECK (json_valid(doc)),
    "current"  BOOLEAN NOT NULL DEFAULT TRUE,
    actor      TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    UNIQUE (scope, name, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_current ON policies (scope, name) WHERE "current";

-- Static IP inventory with state and deadlines.
CREATE TABLE IF NOT EXISTS inventory (
    ip              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    region          TEXT NOT NULL,
    subtype         TEXT NOT NULL,
    entry           TEXT NOT NULL CHECK (json_valid(entry)),
    state           TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN (
        'candidate', 'available', 'leased', 'cooldown', 'quarantined',
        'rotating', 'offline', 'replace_requested', 'retired')),
    state_since     INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    cooldown_until  INTEGER,
    quarantined_at  INTEGER,
    retest_at       INTEGER,
    offline_since   INTEGER,
    last_check_at   INTEGER,
    exit_ip         TEXT,
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    updated_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)
);
CREATE INDEX IF NOT EXISTS inventory_provider ON inventory (provider);
CREATE INDEX IF NOT EXISTS inventory_state ON inventory (state);

-- Reputation scores, one row per check, so the replacement rule can look at
-- consecutive checks from several services.
CREATE TABLE IF NOT EXISTS ip_scores (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    source     TEXT NOT NULL,
    risk       SMALLINT NOT NULL CHECK (risk BETWEEN 0 AND 100),
    flags      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(flags)),
    checked_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)
);
CREATE INDEX IF NOT EXISTS ip_scores_ip ON ip_scores (ip, source, checked_at DESC);

-- Block history for quarantine and replacement. A target block has a target
-- and an expiry (it is re-seeded into Redis after a loss); an IP-wide block
-- has no target.
CREATE TABLE IF NOT EXISTS ip_blocks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    target       TEXT,
    source       TEXT NOT NULL,
    signal_type  TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    expires_at   INTEGER
);
CREATE INDEX IF NOT EXISTS ip_blocks_ip ON ip_blocks (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ip_blocks_active ON ip_blocks (expires_at) WHERE target IS NOT NULL;

-- Operator org blocks.
CREATE TABLE IF NOT EXISTS org_blocks (
    id          BLOB PRIMARY KEY,
    org         TEXT NOT NULL CHECK (length(org) BETWEEN 1 AND 64 AND org NOT GLOB '*[^a-z0-9_-]*'),
    scope       TEXT NOT NULL CHECK (scope IN ('ip', 'provider', 'route_class', 'pool')),
    scope_value TEXT NOT NULL,
    reason      TEXT NOT NULL,
    operator    TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    expires_at  INTEGER,
    revoked_at  INTEGER
);
CREATE INDEX IF NOT EXISTS org_blocks_org ON org_blocks (org);

-- Content hash of each git data source that was synced into the database.
CREATE TABLE IF NOT EXISTS data_sources (
    name       TEXT PRIMARY KEY,
    sha256     TEXT NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)
);

-- Append-only audit trail. Holds actor, action and subject, never a secret.
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
);
CREATE INDEX IF NOT EXISTS audit_subject ON audit (subject, at DESC);

DROP TRIGGER IF EXISTS audit_no_update;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;
DROP TRIGGER IF EXISTS audit_no_delete;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;
