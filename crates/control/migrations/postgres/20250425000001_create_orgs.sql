CREATE TABLE IF NOT EXISTS orgs (
    id              TEXT PRIMARY KEY,
    rate_limit_rpm  INTEGER NOT NULL DEFAULT 0,
    rate_limit_burst INTEGER NOT NULL DEFAULT 0,
    proxy_type      TEXT,
    proxy_address   TEXT,
    proxy_username  TEXT,
    proxy_password  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
