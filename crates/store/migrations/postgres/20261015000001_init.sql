-- ProxyX durable state. Redis holds only what can be rebuilt from here.

-- Org keys: only the sha256 of the key is stored (never the key).
CREATE TABLE IF NOT EXISTS org_keys (
    key_hash    BYTEA PRIMARY KEY CHECK (octet_length(key_hash) = 32),
    org         TEXT NOT NULL CHECK (org ~ '^[a-z0-9_-]{1,64}$'),
    label       TEXT NOT NULL DEFAULT '',
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS org_keys_org ON org_keys (org);

-- Versioned policy documents. One row per version; at most one current.
CREATE TABLE IF NOT EXISTS policies (
    id         BIGSERIAL PRIMARY KEY,
    scope      TEXT NOT NULL CHECK (scope IN ('global', 'route_class', 'org')),
    name       TEXT NOT NULL CHECK (name <> ''),
    target     TEXT,
    version    INTEGER NOT NULL CHECK (version > 0),
    doc        JSONB NOT NULL,
    current    BOOLEAN NOT NULL DEFAULT TRUE,
    actor      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope, name, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_current ON policies (scope, name) WHERE current;

-- Static IP inventory with state and deadlines.
CREATE TABLE IF NOT EXISTS inventory (
    ip              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    region          TEXT NOT NULL,
    subtype         TEXT NOT NULL,
    entry           JSONB NOT NULL,
    state           TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN (
        'candidate', 'available', 'leased', 'cooldown', 'quarantined',
        'rotating', 'offline', 'replace_requested', 'retired')),
    state_since     TIMESTAMPTZ NOT NULL DEFAULT now(),
    cooldown_until  TIMESTAMPTZ,
    quarantined_at  TIMESTAMPTZ,
    retest_at       TIMESTAMPTZ,
    offline_since   TIMESTAMPTZ,
    last_check_at   TIMESTAMPTZ,
    exit_ip         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inventory_provider ON inventory (provider);
CREATE INDEX IF NOT EXISTS inventory_state ON inventory (state);

-- Reputation scores, one row per check, so the replacement rule can look at
-- consecutive checks from several services.
CREATE TABLE IF NOT EXISTS ip_scores (
    id         BIGSERIAL PRIMARY KEY,
    ip         TEXT NOT NULL,
    source     TEXT NOT NULL,
    risk       SMALLINT NOT NULL CHECK (risk BETWEEN 0 AND 100),
    flags      JSONB NOT NULL DEFAULT '[]',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ip_scores_ip ON ip_scores (ip, source, checked_at DESC);

-- Block history for quarantine and replacement. A target block has a target
-- and an expiry (it is re-seeded into Redis after a loss); an IP-wide block
-- has no target.
CREATE TABLE IF NOT EXISTS ip_blocks (
    id           BIGSERIAL PRIMARY KEY,
    ip           TEXT NOT NULL,
    target       TEXT,
    source       TEXT NOT NULL,
    signal_type  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ip_blocks_ip ON ip_blocks (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ip_blocks_active ON ip_blocks (expires_at) WHERE target IS NOT NULL;

-- Operator org blocks.
CREATE TABLE IF NOT EXISTS org_blocks (
    id          UUID PRIMARY KEY,
    org         TEXT NOT NULL CHECK (org ~ '^[a-z0-9_-]{1,64}$'),
    scope       TEXT NOT NULL CHECK (scope IN ('ip', 'provider', 'route_class', 'pool')),
    scope_value TEXT NOT NULL,
    reason      TEXT NOT NULL,
    operator    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS org_blocks_org ON org_blocks (org);

-- Content hash of each git data source that was synced into Postgres.
CREATE TABLE IF NOT EXISTS data_sources (
    name       TEXT PRIMARY KEY,
    sha256     TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only audit trail. Holds actor, action and subject, never a secret.
CREATE TABLE IF NOT EXISTS audit (
    id      BIGSERIAL PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail  JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_subject ON audit (subject, at DESC);

CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit rows are append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
