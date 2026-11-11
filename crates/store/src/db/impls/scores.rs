// Reputation scores: the queries of one backend. See `db/scores.rs`.

use std::net::IpAddr;

use proxyx_db::Ts;
use sqlx::types::Json;

use crate::db::scores::{RawScore, ScoreRow};
use crate::db::to_json;
use crate::error::{Result, StoreError};

pub(crate) async fn record_score(pool: &d::Pool, score: &ScoreRow) -> Result<()> {
    if score.risk > 100 {
        return Err(StoreError::Invalid(format!(
            "risk {} above 100",
            score.risk
        )));
    }
    let flags = to_json(&score.flags)?;
    sqlx::query(d::sql!(
        "INSERT INTO ip_scores (ip, source, risk, flags, checked_at) VALUES (?, ?, ?, ?, ?)"
    ))
    .bind(score.ip.to_string())
    .bind(&score.source)
    .bind(i16::from(score.risk))
    .bind(Json(flags))
    .bind(Ts(score.checked_at))
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn recent_scores(
    pool: &d::Pool,
    ip: IpAddr,
    per_source: i64,
) -> Result<Vec<ScoreRow>> {
    let raw: Vec<RawScore> = sqlx::query_as(d::sql!(
        "SELECT ip, source, risk, flags, checked_at FROM (
             SELECT ip, source, risk, flags, checked_at,
                    row_number() OVER (PARTITION BY source ORDER BY checked_at DESC, id DESC) AS n
             FROM ip_scores WHERE ip = ?
         ) s WHERE n <= ? ORDER BY source, checked_at DESC"
    ))
    .bind(ip.to_string())
    .bind(per_source)
    .fetch_all(pool)
    .await?;
    raw.into_iter().map(ScoreRow::try_from).collect()
}
