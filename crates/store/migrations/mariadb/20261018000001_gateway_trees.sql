-- The policy tree (content hash of `policies/`) each running gateway holds, and when it
-- last said so. A gateway that restarts with an older tree than the stored one must not
-- overwrite it while a gateway that runs the stored tree is alive.
CREATE TABLE IF NOT EXISTS gateway_trees (
    instance VARCHAR(255) NOT NULL PRIMARY KEY,
    sha256   VARCHAR(64) NOT NULL,
    seen_at  DATETIME(6) NOT NULL DEFAULT (UTC_TIMESTAMP(6))
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;
