//! SQLite dialect (3.40 or newer, one node).
//!
//! SQLite has one writer at a time. Every write transaction begins with
//! `BEGIN IMMEDIATE`, so it takes the write lock at once and waits for it
//! (busy timeout) instead of failing halfway when a read upgrades to a write.
//! That serialises writers like the advisory locks of the other backends,
//! which makes `lock_table` and `lock_org` no-ops.

use sqlx::Sqlite;

use crate::error::Result;

pub(in crate::db) type Conn = sqlx::SqliteConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, Sqlite>;
pub(in crate::db) use crate::db::audit::sqlite::append_audit;
#[allow(unused_imports)]
pub(in crate::db) use crate::db::{
    blocks::sqlite as blocks, customer::sqlite as customer, inventory::sqlite as inventory,
    org_blocks::sqlite as org_blocks, policies::sqlite as policies,
};
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
macro_rules! now_minus_secs {
    () => {
        "((CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000) - CAST(? * 1000000 AS INTEGER))"
    };
}
macro_rules! json_text {
    ($col:literal, $key:literal) => {
        concat!("json_extract(", $col, ", '$.", $key, "')")
    };
}
macro_rules! next_version {
    () => {
        "(SELECT value FROM inventory_upstream_version_seq WHERE id = 1)"
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
        "owner_org = ? AND state <> 'retired'"
    };
}
macro_rules! for_update {
    () => {
        ""
    };
}
macro_rules! login_upsert {
    () => {
        "INSERT INTO customer_credentials (org, username, password) VALUES (?, ?, ?)
         ON CONFLICT (org) DO UPDATE
         SET username = EXCLUDED.username, password = EXCLUDED.password,
             rotated_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
macro_rules! source_upsert {
    () => {
        "INSERT INTO data_sources (name, sha256) VALUES (?, ?)
         ON CONFLICT (name) DO UPDATE SET sha256 = EXCLUDED.sha256,
             applied_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
macro_rules! tree_upsert {
    () => {
        "INSERT INTO gateway_trees (instance, sha256) VALUES (?, ?)
         ON CONFLICT (instance) DO UPDATE SET sha256 = EXCLUDED.sha256,
             seen_at = (CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + (CAST(ROUND(strftime('%f', 'now') * 1000) AS INTEGER) % 1000) * 1000)"
    };
}
pub(in crate::db) use {
    for_update, json_text, live_unit, login_upsert, next_version, now, now_minus_secs,
    returning_id, source_upsert, sql, tree_upsert,
};

/// A transaction that writes: takes the write lock now.
pub(in crate::db) async fn begin_write(pool: &Pool) -> Result<Tx> {
    Ok(pool.begin_with("BEGIN IMMEDIATE").await?)
}

/// A transaction whose reads all see one snapshot (WAL) and that writes
/// nothing.
pub(in crate::db) async fn begin_snapshot(pool: &Pool) -> Result<Tx> {
    Ok(pool.begin().await?)
}

/// Writers are serialised by `BEGIN IMMEDIATE`.
pub(in crate::db) async fn lock_table(_conn: &mut Conn, _name: &str) -> Result<()> {
    Ok(())
}

/// Writers are serialised by `BEGIN IMMEDIATE`.
pub(in crate::db) async fn lock_org(_conn: &mut Conn, _org: &str) -> Result<()> {
    Ok(())
}

/// Advance the upstream version counter, so the statement that follows reads
/// a new value from [`next_version!`]. SQLite has no sequences: the counter is
/// one row, advanced inside the write transaction.
pub(in crate::db) async fn bump_version(conn: &mut Conn) -> Result<()> {
    sqlx::query("UPDATE inventory_upstream_version_seq SET value = value + 1 WHERE id = 1")
        .execute(conn)
        .await?;
    Ok(())
}

/// Run an INSERT of an auto-numbered row and return its id (`rowid`).
pub(in crate::db) async fn insert_id<'q>(
    conn: &mut Conn,
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments>,
) -> Result<i64> {
    Ok(query.execute(conn).await?.last_insert_rowid())
}
