-- Native API keys of the control plane (`auth_mode = "keys"`).
-- Only the SHA-256 of a key is stored; the key itself is shown once, at creation.
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    BYTEA PRIMARY KEY CHECK (octet_length(key_hash) = 32),
    kind        TEXT NOT NULL CHECK (kind IN ('service', 'user', 'admin')),
    org_id      TEXT,
    name        TEXT NOT NULL CHECK (name ~ '^[A-Za-z0-9._@-]{1,64}$'),
    disabled    BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ,
    -- Service and user keys act inside one org; admin keys act across orgs.
    CHECK ((kind = 'admin') = (org_id IS NULL))
);

CREATE INDEX IF NOT EXISTS api_keys_org_idx ON api_keys (org_id);
