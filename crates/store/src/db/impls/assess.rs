// Read-only pool summaries: the queries of one backend. See `db/assess.rs`.

use std::net::IpAddr;

use proxyx_db::Ts;
use time::OffsetDateTime;

use crate::db::assess::{BlockSummary, TypeCount};
use crate::error::{Result, StoreError};

pub(crate) async fn latest_risks(pool: &d::Pool) -> Result<Vec<(IpAddr, u8)>> {
    let rows: Vec<(String, i16)> = sqlx::query_as(d::sql!(
        "SELECT ip, max(risk) FROM (
             SELECT ip, risk, row_number() OVER (
                 PARTITION BY ip, source ORDER BY checked_at DESC, id DESC) AS n
             FROM ip_scores
         ) latest WHERE n = 1 GROUP BY ip ORDER BY ip"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(ip, risk)| {
            Ok((
                ip.parse().map_err(|e| StoreError::decode("ip", e))?,
                u8::try_from(risk).map_err(|e| StoreError::decode("risk", e))?,
            ))
        })
        .collect()
}

pub(crate) async fn block_summary_since(
    pool: &d::Pool,
    since: OffsetDateTime,
) -> Result<BlockSummary> {
    let by_type: Vec<TypeCount> = sqlx::query_as(d::sql!(
        "SELECT signal_type, count(*) AS n FROM ip_blocks
         WHERE created_at >= ? GROUP BY signal_type ORDER BY signal_type"
    ))
    .bind(Ts(since))
    .fetch_all(pool)
    .await?;
    let ips: i64 = sqlx::query_scalar(d::sql!(
        "SELECT count(DISTINCT ip) FROM ip_blocks WHERE created_at >= ?"
    ))
    .bind(Ts(since))
    .fetch_one(pool)
    .await?;
    Ok(BlockSummary {
        signals: by_type.iter().map(|t| t.n).sum(),
        ips,
        by_type: by_type.into_iter().map(|t| (t.signal_type, t.n)).collect(),
    })
}
