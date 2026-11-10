// Org blocks: the queries of one backend. See `db/org_blocks.rs`.

use common::types::OrgId;
use proxyx_db::Ts;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::org_blocks::{BlockScope, OrgBlock, RawOrgBlock, org_block_columns};
use crate::error::{Result, ensure};
use crate::hot::Hot;

pub(crate) async fn active_org_blocks_in(
    conn: &mut d::Conn,
    now: OffsetDateTime,
) -> Result<Vec<OrgBlock>> {
    let raw: Vec<RawOrgBlock> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        org_block_columns!(),
        " FROM org_blocks
         WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at, id"
    )))
    .bind(Ts(now))
    .fetch_all(conn)
    .await?;
    raw.into_iter().map(OrgBlock::try_from).collect()
}

/// Write the cache field of `org` and `scope` from the active blocks the
/// locked transaction `conn` sees.
///
/// Every change of an org's blocks takes the org's block lock before it
/// writes, and the Redis cache is brought up to date while it is held, so
/// processes cannot write the cache from states that are no longer current
/// (the last writer would be a stale one). The lock wait is bounded by the
/// lock timeout.
async fn sync_cache_in(
    conn: &mut d::Conn,
    hot: &Hot,
    org: &OrgId,
    scope: &BlockScope,
) -> Result<()> {
    let active = active_org_blocks_in(conn, OffsetDateTime::now_utc()).await?;
    hot.org_block_sync(org, scope, &active).await
}

pub(crate) async fn create_org_block(
    pool: &d::Pool,
    hot: &Hot,
    org: &OrgId,
    scope: &BlockScope,
    reason: &str,
    operator: &str,
    expires_at: Option<OffsetDateTime>,
) -> Result<OrgBlock> {
    ensure(!reason.trim().is_empty(), "an org block needs a reason")?;
    ensure(
        expires_at.is_none_or(|t| t > OffsetDateTime::now_utc()),
        "org block expires in the past",
    )?;
    let (kind, value) = scope.parts();
    let mut tx = d::begin_write(pool).await?;
    d::lock_org(&mut tx, org.as_str()).await?;
    let id = Uuid::new_v4();
    sqlx::query(d::sql!(
        "INSERT INTO org_blocks (id, org, scope, scope_value, reason, operator, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    ))
    .bind(id)
    .bind(org.as_str())
    .bind(kind)
    .bind(&value)
    .bind(reason)
    .bind(operator)
    .bind(expires_at.map(Ts))
    .execute(&mut *tx)
    .await?;
    let raw: RawOrgBlock = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        org_block_columns!(),
        " FROM org_blocks WHERE id = ?"
    )))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    d::append_audit(
        &mut tx,
        operator,
        "org_block.create",
        org.as_str(),
        json!({ "id": raw.id(), "scope": kind, "value": value, "reason": reason }),
    )
    .await?;
    sync_cache_in(&mut tx, hot, org, scope).await?;
    tx.commit().await?;
    raw.try_into()
}

async fn org_block(pool: &d::Pool, id: Uuid) -> Result<Option<OrgBlock>> {
    let raw: Option<RawOrgBlock> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        org_block_columns!(),
        " FROM org_blocks WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    raw.map(OrgBlock::try_from).transpose()
}

pub(crate) async fn revoke_org_block(
    pool: &d::Pool,
    hot: &Hot,
    id: Uuid,
    operator: &str,
) -> Result<Option<OrgBlock>> {
    let Some(block) = org_block(pool, id).await? else {
        return Ok(None);
    };
    let mut tx = d::begin_write(pool).await?;
    d::lock_org(&mut tx, block.org.as_str()).await?;
    // The org lock serialises every change of the org's blocks, so the row
    // read here is the row the update changes.
    let open: Option<RawOrgBlock> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        org_block_columns!(),
        " FROM org_blocks WHERE id = ? AND revoked_at IS NULL",
        d::for_update!()
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let raw = match open {
        Some(_) => {
            sqlx::query(d::sql!(concat!(
                "UPDATE org_blocks SET revoked_at = ",
                d::now!(),
                " WHERE id = ?"
            )))
            .bind(id)
            .execute(&mut *tx)
            .await?;
            let revoked: RawOrgBlock = sqlx::query_as(d::sql!(concat!(
                "SELECT ",
                org_block_columns!(),
                " FROM org_blocks WHERE id = ?"
            )))
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            Some(revoked)
        }
        None => None,
    };
    if let Some(raw) = &raw {
        d::append_audit(
            &mut tx,
            operator,
            "org_block.revoke",
            raw.org(),
            json!({ "id": raw.id() }),
        )
        .await?;
    }
    sync_cache_in(&mut tx, hot, &block.org, &block.scope).await?;
    tx.commit().await?;
    raw.map(OrgBlock::try_from).transpose()
}

pub(crate) async fn active_org_blocks(
    pool: &d::Pool,
    now: OffsetDateTime,
) -> Result<Vec<OrgBlock>> {
    let mut conn = pool.acquire().await?;
    active_org_blocks_in(&mut conn, now).await
}

pub(crate) async fn resync_org_block(
    pool: &d::Pool,
    hot: &Hot,
    org: &OrgId,
    scope: &BlockScope,
) -> Result<()> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_org(&mut tx, org.as_str()).await?;
    sync_cache_in(&mut tx, hot, org, scope).await?;
    tx.commit().await?;
    Ok(())
}
