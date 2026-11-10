//! PostgreSQL dialect.

use sqlx::Postgres;

use crate::error::Result;

pub(in crate::db) type Conn = sqlx::PgConnection;
pub(in crate::db) type Tx = sqlx::Transaction<'static, Postgres>;
pub(in crate::db) use crate::db::audit::postgres::append_audit;
#[allow(unused_imports)]
pub(in crate::db) use crate::db::{
    blocks::postgres as blocks, customer::postgres as customer, inventory::postgres as inventory,
    org_blocks::postgres as org_blocks, policies::postgres as policies,
};
pub(in crate::db) type Pool = sqlx::PgPool;

macro_rules! sql {
    ($sql:expr) => {
        proxyx_db::pg_sql!($sql)
    };
}
/// The database clock.
macro_rules! now {
    () => {
        "now()"
    };
}
/// The database clock minus a number of seconds (one `?`, a double).
macro_rules! now_minus_secs {
    () => {
        "(now() - make_interval(secs => ?))"
    };
}
macro_rules! json_text {
    ($col:literal, $key:literal) => {
        concat!($col, "->>'", $key, "'")
    };
}
macro_rules! next_version {
    () => {
        "nextval('inventory_upstream_version_seq')"
    };
}
/// The clause that makes an INSERT answer with the new row id, where the
/// backend needs it (see `insert_id`).
macro_rules! returning_id {
    () => {
        " RETURNING id"
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
        " FOR UPDATE"
    };
}
macro_rules! login_upsert {
    () => {
        "INSERT INTO customer_credentials (org, username, password) VALUES (?, ?, ?)
         ON CONFLICT (org) DO UPDATE
         SET username = EXCLUDED.username, password = EXCLUDED.password, rotated_at = now()"
    };
}
macro_rules! source_upsert {
    () => {
        "INSERT INTO data_sources (name, sha256) VALUES (?, ?)
         ON CONFLICT (name) DO UPDATE SET sha256 = EXCLUDED.sha256, applied_at = now()"
    };
}
macro_rules! tree_upsert {
    () => {
        "INSERT INTO gateway_trees (instance, sha256) VALUES (?, ?)
         ON CONFLICT (instance) DO UPDATE SET sha256 = EXCLUDED.sha256, seen_at = now()"
    };
}
pub(in crate::db) use {
    for_update, json_text, live_unit, login_upsert, next_version, now, now_minus_secs,
    returning_id, source_upsert, sql, tree_upsert,
};

/// A transaction that writes.
pub(in crate::db) async fn begin_write(pool: &Pool) -> Result<Tx> {
    Ok(pool.begin().await?)
}

/// A transaction whose reads all see one snapshot and that writes nothing.
pub(in crate::db) async fn begin_snapshot(pool: &Pool) -> Result<Tx> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Serialise transactions that read-modify-write one table: a transaction
/// advisory lock, released at commit or rollback.
pub(in crate::db) async fn lock_table(conn: &mut Conn, name: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(name)
        .execute(conn)
        .await?;
    Ok(())
}

/// The same for the changes of one org's blocks.
pub(in crate::db) async fn lock_org(conn: &mut Conn, org: &str) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org_block:' || $1::text, 0))")
        .bind(org)
        .execute(conn)
        .await?;
    Ok(())
}

/// Take the next value of the upstream version sequence, for the statement
/// that follows: PostgreSQL does it inside the statement.
pub(in crate::db) async fn bump_version(_conn: &mut Conn) -> Result<()> {
    Ok(())
}

/// Run an INSERT of an auto-numbered row and return its id (`RETURNING id`).
pub(in crate::db) async fn insert_id(
    conn: &mut Conn,
    query: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>,
) -> Result<i64> {
    use sqlx::Row as _;
    Ok(query.fetch_one(conn).await?.try_get(0)?)
}
