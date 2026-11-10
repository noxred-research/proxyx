// Block signals: the queries of one backend. See `db/blocks.rs`.

use std::net::IpAddr;

use common::types::{SignalSource, SignalType};
use proxyx_db::Ts;
use serde_json::json;
use time::OffsetDateTime;

use crate::db::blocks::{IpBlock, RawBlock, block_columns};
use crate::db::enum_text;
use crate::error::{Result, ensure};

pub(crate) async fn active_target_blocks_in(
    conn: &mut d::Conn,
    now: OffsetDateTime,
) -> Result<Vec<IpBlock>> {
    let raw: Vec<RawBlock> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        block_columns!(),
        " FROM ip_blocks WHERE target IS NOT NULL AND expires_at > ? ORDER BY id"
    )))
    .bind(Ts(now))
    .fetch_all(conn)
    .await?;
    raw.into_iter().map(IpBlock::try_from).collect()
}

pub(crate) async fn record_block(
    pool: &d::Pool,
    ip: IpAddr,
    target: Option<&str>,
    source: SignalSource,
    signal_type: SignalType,
    expires_at: Option<OffsetDateTime>,
) -> Result<IpBlock> {
    ensure(
        target.is_some() == expires_at.is_some(),
        "a target block needs expires_at and an IP-wide block must not have it",
    )?;
    let source_text = enum_text(&source)?;
    let mut tx = d::begin_write(pool).await?;
    let id = d::insert_id(
        &mut tx,
        sqlx::query(d::sql!(concat!(
            "INSERT INTO ip_blocks (ip, target, source, signal_type, expires_at)
             VALUES (?, ?, ?, ?, ?)",
            d::returning_id!()
        )))
        .bind(ip.to_string())
        .bind(target.map(str::to_ascii_lowercase))
        .bind(&source_text)
        .bind(enum_text(&signal_type)?)
        .bind(expires_at.map(Ts)),
    )
    .await?;
    let raw: RawBlock = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        block_columns!(),
        " FROM ip_blocks WHERE id = ?"
    )))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    d::append_audit(
        &mut tx,
        &format!("signal:{source_text}"),
        "ip_block.record",
        &ip.to_string(),
        json!({ "target": raw.target(), "type": raw.signal_type() }),
    )
    .await?;
    tx.commit().await?;
    raw.try_into()
}

pub(crate) async fn blocks_since(
    pool: &d::Pool,
    ip: IpAddr,
    since: OffsetDateTime,
) -> Result<Vec<IpBlock>> {
    let raw: Vec<RawBlock> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        block_columns!(),
        " FROM ip_blocks WHERE ip = ? AND created_at >= ? ORDER BY id DESC"
    )))
    .bind(ip.to_string())
    .bind(Ts(since))
    .fetch_all(pool)
    .await?;
    raw.into_iter().map(IpBlock::try_from).collect()
}

pub(crate) async fn ip_wide_blocks_since(
    pool: &d::Pool,
    ip: IpAddr,
    since: OffsetDateTime,
) -> Result<i64> {
    Ok(sqlx::query_scalar(d::sql!(
        "SELECT count(*) FROM ip_blocks WHERE ip = ? AND target IS NULL AND created_at >= ?"
    ))
    .bind(ip.to_string())
    .bind(Ts(since))
    .fetch_one(pool)
    .await?)
}

pub(crate) async fn blocked_targets_since(
    pool: &d::Pool,
    ip: IpAddr,
    since: OffsetDateTime,
) -> Result<i64> {
    Ok(sqlx::query_scalar(d::sql!(
        "SELECT count(DISTINCT target) FROM ip_blocks
         WHERE ip = ? AND target IS NOT NULL AND created_at >= ?"
    ))
    .bind(ip.to_string())
    .bind(Ts(since))
    .fetch_one(pool)
    .await?)
}
