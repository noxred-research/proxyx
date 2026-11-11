-- Control plane schema (MariaDB 10.6+). Same logical schema as migrations/postgres.
-- InnoDB, utf8mb4_general_ci (see docs/databases.md for what that means for text
-- comparison), timestamps are DATETIME(6) in UTC, UUIDs are BINARY(16).
CREATE TABLE IF NOT EXISTS orgs (
    id               VARCHAR(255) NOT NULL PRIMARY KEY,
    rate_limit_rpm   INT NOT NULL DEFAULT 0,
    rate_limit_burst INT NOT NULL DEFAULT 0,
    proxy_type       VARCHAR(16) NULL,
    proxy_address    TEXT NULL,
    proxy_username   TEXT NULL,
    proxy_password   TEXT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    updated_at       DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
