// Data source hashes and gateway trees: the queries of one backend. See
// `db/sources.rs`.

use std::time::Duration;

use serde_json::json;

use crate::error::Result;

pub(crate) async fn source_hash(pool: &d::Pool, name: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar(d::sql!("SELECT sha256 FROM data_sources WHERE name = ?"))
            .bind(name)
            .fetch_optional(pool)
            .await?,
    )
}

pub(crate) async fn set_source_hash(
    pool: &d::Pool,
    name: &str,
    sha256: &str,
    actor: &str,
) -> Result<()> {
    let mut tx = d::begin_write(pool).await?;
    sqlx::query(d::sql!(d::source_upsert!()))
        .bind(name)
        .bind(sha256)
        .execute(&mut *tx)
        .await?;
    d::append_audit(
        &mut tx,
        actor,
        "data_source.applied",
        name,
        json!({ "sha256": sha256 }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn beat_gateway_tree(pool: &d::Pool, instance: &str, hash: &str) -> Result<()> {
    let mut tx = d::begin_write(pool).await?;
    sqlx::query(d::sql!(d::tree_upsert!()))
        .bind(instance)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query(d::sql!(concat!(
        "DELETE FROM gateway_trees WHERE seen_at < ",
        d::now_minus_secs!()
    )))
    .bind(86_400.0_f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn forget_gateway_tree(pool: &d::Pool, instance: &str) -> Result<()> {
    sqlx::query(d::sql!("DELETE FROM gateway_trees WHERE instance = ?"))
        .bind(instance)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn gateway_tree_is_live(
    pool: &d::Pool,
    instance: &str,
    hash: &str,
    live_for: Duration,
) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(d::sql!(concat!(
        "SELECT count(*) FROM (SELECT 1 FROM gateway_trees
                        WHERE instance <> ? AND sha256 = ? AND seen_at > ",
        d::now_minus_secs!(),
        " LIMIT 1) live"
    )))
    .bind(instance)
    .bind(hash)
    .bind(live_for.as_secs_f64())
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub(crate) async fn policy_tree_was_applied(pool: &d::Pool, hash: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(d::sql!(concat!(
        "SELECT count(*) FROM (SELECT 1 FROM audit
                        WHERE subject = 'policies' AND action = 'data_source.applied'
                          AND ",
        d::json_text!("detail", "sha256"),
        " = ? LIMIT 1) applied"
    )))
    .bind(hash)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}
