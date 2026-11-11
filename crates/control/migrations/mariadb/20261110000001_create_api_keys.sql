-- Native API keys of the control plane (`auth_mode = "keys"`).
-- Only the SHA-256 of a key is stored; the key itself is shown once, at creation.
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    VARBINARY(32) NOT NULL PRIMARY KEY,
    kind        VARCHAR(16) NOT NULL,
    org_id      VARCHAR(255) NULL,
    name        VARCHAR(64) NOT NULL,
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    disabled_at DATETIME(6) NULL,
    CONSTRAINT api_keys_key_hash_len CHECK (OCTET_LENGTH(key_hash) = 32),
    CONSTRAINT api_keys_kind_check CHECK (kind IN ('service', 'user', 'admin')),
    CONSTRAINT api_keys_name_format CHECK (name REGEXP '(?-i)^[A-Za-z0-9._@-]{1,64}$'),
    -- Service and user keys act inside one org; admin keys act across orgs.
    CONSTRAINT api_keys_org_by_kind CHECK ((kind = 'admin') = (org_id IS NULL))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE INDEX IF NOT EXISTS api_keys_org_idx ON api_keys (org_id);
