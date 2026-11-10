-- Control plane schema (SQLite 3.40+, one node). Same logical schema as
-- migrations/postgres. Timestamps are INTEGER microseconds since the Unix epoch
-- (UTC), UUIDs are 16 byte BLOBs.
--
-- SQLite cannot drop a NOT NULL or add one to a column, so a table is created in
-- the shape the later migrations of this directory give the other backends: the
-- rate limits of orgs are nullable from the start and session_lifecycle has
-- expires_at, source_id NOT NULL and ref_count from the start. The later
-- migrations of those changes only add what SQLite can add (indexes).
CREATE TABLE IF NOT EXISTS orgs (
    id               TEXT PRIMARY KEY,
    rate_limit_rpm   INTEGER,
    rate_limit_burst INTEGER,
    proxy_type       TEXT,
    proxy_address    TEXT,
    proxy_username   TEXT,
    proxy_password   TEXT,
    created_at       INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000),
    updated_at       INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)
);
