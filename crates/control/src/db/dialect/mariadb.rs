//! MariaDB dialect (10.6 or newer: `SKIP LOCKED`, `JSON_TABLE`).
//!
//! MariaDB evaluates the assignments of an UPDATE and of ON DUPLICATE KEY UPDATE
//! left to right, and a later one sees the columns an earlier one set: where a
//! statement reads a column it also sets, it reads it first.

use sqlx::MySql;

use crate::db::DbResult;

pub(in crate::db) type Conn = sqlx::MySqlConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, MySql>;
pub(in crate::db) type Pool = sqlx::MySqlPool;

macro_rules! sql {
    ($sql:expr) => {
        $sql
    };
}
macro_rules! now {
    () => {
        "UTC_TIMESTAMP(6)"
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
macro_rules! key_id {
    () => {
        "LOWER(HEX(SUBSTRING(key_hash, 1, 8)))"
    };
}
macro_rules! in_json_array {
    () => {
        "(SELECT jt.v FROM JSON_TABLE(?, '$[*]' COLUMNS (v VARCHAR(255) PATH '$')) jt)"
    };
}
macro_rules! org_rate_limit_upsert {
    () => {
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE rate_limit_rpm = VALUES(rate_limit_rpm),
             rate_limit_burst = VALUES(rate_limit_burst), updated_at = UTC_TIMESTAMP(6)"
    };
}
macro_rules! org_proxy_upsert {
    () => {
        "INSERT INTO orgs (id, proxy_type, proxy_address, proxy_username, proxy_password)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE proxy_type = VALUES(proxy_type),
             proxy_address = VALUES(proxy_address), proxy_username = VALUES(proxy_username),
             proxy_password = VALUES(proxy_password), updated_at = UTC_TIMESTAMP(6)"
    };
}
macro_rules! org_settings_upsert {
    () => {
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst, proxy_type, proxy_address,
                           proxy_username, proxy_password)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE rate_limit_rpm = VALUES(rate_limit_rpm),
             rate_limit_burst = VALUES(rate_limit_burst), proxy_type = VALUES(proxy_type),
             proxy_address = VALUES(proxy_address), proxy_username = VALUES(proxy_username),
             proxy_password = VALUES(proxy_password), updated_at = UTC_TIMESTAMP(6)"
    };
}
/// Create a view job, or reclaim a failed one. Assignments run left to right
/// and see the columns already assigned, so `status` is assigned last:
/// `query_id`, `error` and `s3_key` read the old status. The query id of a
/// pending, running or completed job is kept; a failed job (or a legacy row
/// without one) takes the new attempt's id.
macro_rules! view_job_upsert {
    () => {
        "INSERT INTO traffic_view_jobs (view_id, org_id, query_id) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
             query_id   = CASE WHEN status = 'failed' OR query_id IS NULL OR query_id = ''
                               THEN VALUES(query_id) ELSE query_id END,
             error      = CASE WHEN status = 'failed' THEN NULL ELSE error END,
             s3_key     = CASE WHEN status = 'failed' THEN NULL ELSE s3_key END,
             status     = CASE WHEN status = 'failed' THEN 'pending' ELSE status END,
             updated_at = UTC_TIMESTAMP(6)"
    };
}
pub(in crate::db) use {
    for_update, for_update_skip_locked, in_json_array, key_id, now, org_proxy_upsert,
    org_rate_limit_upsert, org_settings_upsert, sql, view_job_upsert,
};

/// A transaction that writes. The session runs at READ COMMITTED (see
/// `proxyx_db::Pool::connect`).
pub(in crate::db) async fn begin_write(pool: &Pool) -> DbResult<Tx> {
    pool.begin().await
}
