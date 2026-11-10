-- Native API keys of the control plane (`auth_mode = "keys"`).
-- Only the SHA-256 of a key is stored; the key itself is shown once, at creation.
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    BLOB PRIMARY KEY CHECK (length(key_hash) = 32),
    kind        TEXT NOT NULL CHECK (kind IN ('service', 'user', 'admin')),
    org_id      TEXT,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64 AND name NOT GLOB '*[^A-Za-z0-9._@-]*'),
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    disabled_at INTEGER,
    -- Service and user keys act inside one org; admin keys act across orgs.
    CHECK ((kind = 'admin') = (org_id IS NULL))
);

CREATE INDEX IF NOT EXISTS api_keys_org_idx ON api_keys (org_id);
