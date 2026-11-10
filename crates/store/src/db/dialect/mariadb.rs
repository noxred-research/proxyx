//! MariaDB dialect (10.6 or newer).
//!
//! Locks by name are rows of `advisory_locks`, taken `FOR UPDATE` and held to
//! the end of the transaction. The rows are seeded by the migration, so two
//! first users never race to insert one.

use sqlx::MySql;

use super::ORG_LOCK_BUCKETS;
use crate::error::{Result, StoreError};

pub(in crate::db) type Conn = sqlx::MySqlConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, MySql>;
pub(in crate::db) use crate::db::audit::mariadb::append_audit;
#[allow(unused_imports)]
pub(in crate::db) use crate::db::{
    blocks::mariadb as blocks, customer::mariadb as customer, inventory::mariadb as inventory,
    org_blocks::mariadb as org_blocks, policies::mariadb as policies,
};
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
macro_rules! now_minus_secs {
    () => {
        "(UTC_TIMESTAMP(6) - INTERVAL ? SECOND)"
    };
}
macro_rules! json_text {
    ($col:literal, $key:literal) => {
        concat!("JSON_VALUE(", $col, ", '$.", $key, "')")
    };
}
macro_rules! next_version {
    () => {
        "NEXTVAL(inventory_upstream_version_seq)"
    };
}
macro_rules! returning_id {
    () => {
        ""
    };
}
/// The row of the org's live upstream: one `?`, the org.
macro_rules! live_unit {
    () => {
        "live_owner = ?"
    };
}
macro_rules! for_update {
    () => {
        " FOR UPDATE"
    };
}
macro_rules! login_upsert {
    () => {
        "INSERT INTO customer_credentials (org, username, password) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
         username = VALUES(username), password = VALUES(password), rotated_at = UTC_TIMESTAMP(6)"
    };
}
macro_rules! source_upsert {
    () => {
        "INSERT INTO data_sources (name, sha256) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), applied_at = UTC_TIMESTAMP(6)"
    };
}
macro_rules! tree_upsert {
    () => {
        "INSERT INTO gateway_trees (instance, sha256) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), seen_at = UTC_TIMESTAMP(6)"
    };
}
pub(in crate::db) use {
    for_update, json_text, live_unit, login_upsert, next_version, now, now_minus_secs,
    returning_id, source_upsert, sql, tree_upsert,
};

/// A transaction that writes. The session runs at READ COMMITTED (see
/// `proxyx_db::Pool::connect`), so a statement sees what committed before it.
pub(in crate::db) async fn begin_write(pool: &Pool) -> Result<Tx> {
    Ok(pool.begin().await?)
}

/// A transaction whose reads all see one snapshot and that writes nothing.
pub(in crate::db) async fn begin_snapshot(pool: &Pool) -> Result<Tx> {
    Ok(pool
        .begin_with("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; START TRANSACTION")
        .await?)
}

async fn lock_row(conn: &mut Conn, name: &str) -> Result<()> {
    let row: Option<String> =
        sqlx::query_scalar("SELECT name FROM advisory_locks WHERE name = ? FOR UPDATE")
            .bind(name)
            .fetch_optional(conn)
            .await?;
    match row {
        Some(_) => Ok(()),
        None => Err(StoreError::Invalid(format!(
            "advisory lock {name:?} is missing: run `proxyx migrate pool`"
        ))),
    }
}

/// Serialise transactions that read-modify-write one table: a row lock,
/// released at commit or rollback.
pub(in crate::db) async fn lock_table(conn: &mut Conn, name: &str) -> Result<()> {
    lock_row(conn, name).await
}

/// The same for the changes of one org's blocks: one of
/// [`ORG_LOCK_BUCKETS`] rows, so two orgs may share a lock and none waits long.
pub(in crate::db) async fn lock_org(conn: &mut Conn, org: &str) -> Result<()> {
    lock_row(conn, &super::org_lock_name(org)).await
}

/// MariaDB takes the next sequence value inside the statement.
pub(in crate::db) async fn bump_version(_conn: &mut Conn) -> Result<()> {
    Ok(())
}

const _: () = assert!(ORG_LOCK_BUCKETS == 64);

/// Run an INSERT of an auto-numbered row and return its id. MariaDB does not
/// describe the columns of `INSERT ... RETURNING` when the statement is
/// prepared, so the id comes from the OK packet.
pub(in crate::db) async fn insert_id(
    conn: &mut Conn,
    query: sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments>,
) -> Result<i64> {
    let done = query.execute(conn).await?;
    i64::try_from(done.last_insert_id())
        .map_err(|e| crate::error::StoreError::decode("inserted id", e))
}
