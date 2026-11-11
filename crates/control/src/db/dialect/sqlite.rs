//! SQLite dialect (3.40 or newer, one node).
//!
//! SQLite has one writer at a time. Every write transaction begins with
//! `BEGIN IMMEDIATE`, so it takes the write lock at once and waits for it (busy
//! timeout), which makes row locks (`FOR UPDATE`, `SKIP LOCKED`) unnecessary.

use sqlx::Sqlite;

use crate::db::DbResult;

pub(in crate::db) type Conn = sqlx::SqliteConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, Sqlite>;
pub(in crate::db) type Pool = sqlx::SqlitePool;

macro_rules! sql {
    ($sql:expr) => {
        $sql
    };
}
/// Microseconds since the Unix epoch, to the millisecond.
macro_rules! now {
    () => {
        "(CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
macro_rules! for_update {
    () => {
        ""
    };
}
macro_rules! for_update_skip_locked {
    () => {
        ""
    };
}
macro_rules! key_id {
    () => {
        "lower(hex(substr(key_hash, 1, 8)))"
    };
}
macro_rules! in_json_array {
    () => {
        "(SELECT value FROM json_each(?))"
    };
}
macro_rules! org_rate_limit_upsert {
    () => {
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst) VALUES (?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET rate_limit_rpm = EXCLUDED.rate_limit_rpm,
             rate_limit_burst = EXCLUDED.rate_limit_burst,
             updated_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
macro_rules! org_proxy_upsert {
    () => {
        "INSERT INTO orgs (id, proxy_type, proxy_address, proxy_username, proxy_password)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET proxy_type = EXCLUDED.proxy_type,
             proxy_address = EXCLUDED.proxy_address, proxy_username = EXCLUDED.proxy_username,
             proxy_password = EXCLUDED.proxy_password,
             updated_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
macro_rules! org_settings_upsert {
    () => {
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst, proxy_type, proxy_address,
                           proxy_username, proxy_password)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET rate_limit_rpm = EXCLUDED.rate_limit_rpm,
             rate_limit_burst = EXCLUDED.rate_limit_burst, proxy_type = EXCLUDED.proxy_type,
             proxy_address = EXCLUDED.proxy_address, proxy_username = EXCLUDED.proxy_username,
             proxy_password = EXCLUDED.proxy_password,
             updated_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
/// Create a view job, or reclaim a failed one. The query id of a pending,
/// running or completed job is kept; a failed job (or a legacy row without
/// one) takes the new attempt's id.
macro_rules! view_job_upsert {
    () => {
        "INSERT INTO traffic_view_jobs (view_id, org_id, query_id) VALUES (?, ?, ?)
         ON CONFLICT (view_id) DO UPDATE
             SET status     = CASE WHEN traffic_view_jobs.status = 'failed'
                                   THEN 'pending' ELSE traffic_view_jobs.status END,
                 error      = CASE WHEN traffic_view_jobs.status = 'failed'
                                   THEN NULL ELSE traffic_view_jobs.error END,
                 s3_key     = CASE WHEN traffic_view_jobs.status = 'failed'
                                   THEN NULL ELSE traffic_view_jobs.s3_key END,
                 query_id   = CASE WHEN traffic_view_jobs.status = 'failed'
                                        OR traffic_view_jobs.query_id IS NULL
                                        OR traffic_view_jobs.query_id = ''
                                   THEN EXCLUDED.query_id ELSE traffic_view_jobs.query_id END,
                 updated_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
pub(in crate::db) use {
    for_update, for_update_skip_locked, in_json_array, key_id, now, org_proxy_upsert,
    org_rate_limit_upsert, org_settings_upsert, sql, view_job_upsert,
};

/// A transaction that writes: takes the write lock now.
pub(in crate::db) async fn begin_write(pool: &Pool) -> DbResult<Tx> {
    pool.begin_with("BEGIN IMMEDIATE").await
}
