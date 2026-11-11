// Org keys: the queries of one backend. See `db/org_keys.rs`.

use common::Secret;
use common::types::OrgId;
use serde_json::json;

use crate::db::org_keys::{KeyStatus, hash_org_key};
use crate::error::{Result, StoreError, ensure};

pub(crate) async fn add_org_key(
    pool: &d::Pool,
    org: &OrgId,
    key: &Secret,
    label: &str,
    actor: &str,
) -> Result<()> {
    ensure(!key.is_empty(), "empty org key")?;
    let hash = hash_org_key(key.expose());
    let mut tx = d::begin_write(pool).await?;
    let inserted = sqlx::query(d::sql!(
        "INSERT INTO org_keys (key_hash, org, label) VALUES (?, ?, ?)"
    ))
    .bind(&hash[..])
    .bind(org.as_str())
    .bind(label)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(StoreError::Conflict { what: "org key" });
        }
        Err(e) => return Err(e.into()),
    }
    d::append_audit(
        &mut tx,
        actor,
        "org_key.add",
        org.as_str(),
        json!({ "label": label }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn verify_org_key(pool: &d::Pool, key: &str) -> Result<KeyStatus> {
    let hash = hash_org_key(key);
    let row: Option<(String, bool)> = sqlx::query_as(d::sql!(
        "SELECT org, disabled FROM org_keys WHERE key_hash = ?"
    ))
    .bind(&hash[..])
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(KeyStatus::Unknown),
        Some((_, true)) => Ok(KeyStatus::Disabled),
        Some((org, false)) => OrgId::try_from(org)
            .map(KeyStatus::Enabled)
            .map_err(|e| StoreError::decode("org id", e)),
    }
}

pub(crate) async fn disable_org_keys(pool: &d::Pool, org: &OrgId, actor: &str) -> Result<u64> {
    let mut tx = d::begin_write(pool).await?;
    let n = sqlx::query(d::sql!(concat!(
        "UPDATE org_keys SET disabled = TRUE, disabled_at = ",
        d::now!(),
        " WHERE org = ? AND NOT disabled"
    )))
    .bind(org.as_str())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    d::append_audit(
        &mut tx,
        actor,
        "org_key.disable",
        org.as_str(),
        json!({ "keys": n }),
    )
    .await?;
    tx.commit().await?;
    Ok(n)
}
