CREATE TABLE IF NOT EXISTS session_lifecycle (
    session_id BINARY(16) NOT NULL PRIMARY KEY,
    org_id     VARCHAR(255) NOT NULL,
    source     VARCHAR(255) NOT NULL,
    source_id  VARCHAR(255) NULL,
    state      VARCHAR(16) NOT NULL,
    opened_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6)),
    closing_at DATETIME(6) NULL,
    closed_at  DATETIME(6) NULL,
    CONSTRAINT session_lifecycle_state_check CHECK (state IN ('active', 'consuming', 'closed'))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE INDEX IF NOT EXISTS session_lifecycle_org_state_idx ON session_lifecycle (org_id, state);
CREATE INDEX IF NOT EXISTS session_lifecycle_source_idx ON session_lifecycle (source, source_id);
