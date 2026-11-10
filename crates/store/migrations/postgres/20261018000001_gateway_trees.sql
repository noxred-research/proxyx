-- The policy tree (content hash of `policies/`) each running gateway holds, and when it
-- last said so. A gateway that restarts with an older tree than the stored one must not
-- overwrite it while a gateway that runs the stored tree is alive.
CREATE TABLE IF NOT EXISTS gateway_trees (
    instance TEXT PRIMARY KEY,
    sha256   TEXT NOT NULL,
    seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
