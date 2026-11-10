// API keys: the queries of one backend. See `db/keys.rs`.

use super::KeyRow;
use crate::db::DbResult;

pub(crate) async fn insert_key(
    pool: &d::Pool,
    key_hash: &[u8],
    kind: &str,
    org_id: Option<&str>,
    name: &str,
) -> DbResult<()> {
    sqlx::query(d::sql!(
        "INSERT INTO api_keys (key_hash, kind, org_id, name) VALUES (?, ?, ?, ?)"
    ))
    .bind(key_hash)
    .bind(kind)
    .bind(org_id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn list_keys(pool: &d::Pool, org_id: Option<&str>) -> DbResult<Vec<KeyRow>> {
    match org_id {
        Some(org_id) => {
            sqlx::query_as(d::sql!(
                "SELECT key_hash, kind, org_id, name, disabled, created_at FROM api_keys
                 WHERE org_id = ? ORDER BY created_at DESC"
            ))
            .bind(org_id)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as(
                "SELECT key_hash, kind, org_id, name, disabled, created_at FROM api_keys
                 ORDER BY created_at DESC",
            )
            .fetch_all(pool)
            .await
        }
    }
}

pub(crate) async fn disable_key(pool: &d::Pool, id: &str) -> DbResult<bool> {
    let done = sqlx::query(d::sql!(concat!(
        "UPDATE api_keys SET disabled = TRUE, disabled_at = ",
        d::now!(),
        " WHERE ",
        d::key_id!(),
        " = ? AND NOT disabled"
    )))
    .bind(id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

pub(crate) async fn enabled_key(
    pool: &d::Pool,
    key_hash: &[u8],
) -> DbResult<Option<(String, Option<String>, String)>> {
    sqlx::query_as(d::sql!(
        "SELECT kind, org_id, name FROM api_keys WHERE key_hash = ? AND NOT disabled"
    ))
    .bind(key_hash)
    .fetch_optional(pool)
    .await
}
