//! PostgreSQL dialect.

use sqlx::Postgres;

use crate::db::DbResult;

pub(in crate::db) type Conn = sqlx::PgConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, Postgres>;
pub(in crate::db) type Pool = sqlx::PgPool;

macro_rules! sql {
    ($sql:expr) => {
        proxyx_db::pg_sql!($sql)
    };
}
macro_rules! now {
    () => {
        "now()"
    };
}
macro_rules! for_update {
    () => {
        " FOR UPDATE"
    };
}
macro_rules! for_update_skip_locked {
    () => {
        " FOR UPDATE SKIP LOCKED"
    };
}
/// `key_hash` of an API key as the lowercase hex of its first 8 bytes.
macro_rules! key_id {
    () => {
        "encode(substring(key_hash FROM 1 FOR 8), 'hex')"
    };
}
/// `source_id IN <this>`, bound to one JSON array of strings.
macro_rules! in_json_array {
    () => {
        "(SELECT jsonb_array_elements_text(?))"
    };
}
macro_rules! org_rate_limit_upsert {
    () => {
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst) VALUES (?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET rate_limit_rpm = EXCLUDED.rate_limit_rpm,
             rate_limit_burst = EXCLUDED.rate_limit_burst, updated_at = now()"
    };
}
macro_rules! org_proxy_upsert {
    () => {
        "INSERT INTO orgs (id, proxy_type, proxy_address, proxy_username, proxy_password)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET proxy_type = EXCLUDED.proxy_type,
             proxy_address = EXCLUDED.proxy_address, proxy_username = EXCLUDED.proxy_username,
             proxy_password = EXCLUDED.proxy_password, updated_at = now()"
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
             proxy_password = EXCLUDED.proxy_password, updated_at = now()"
    };
}
/// Create a view job, or reclaim a failed one. `?` order: view id, org id, query id.
/// The status of the old row is read before any column is assigned. The
/// query id of a pending, running or completed job is kept; a failed job (or
/// a legacy row without one) takes the new attempt's id.
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
                 updated_at = now()"
    };
}
pub(in crate::db) use {
    for_update, for_update_skip_locked, in_json_array, key_id, now, org_proxy_upsert,
    org_rate_limit_upsert, org_settings_upsert, sql, view_job_upsert,
};

/// A transaction that writes.
pub(in crate::db) async fn begin_write(pool: &Pool) -> DbResult<Tx> {
    pool.begin().await
}
