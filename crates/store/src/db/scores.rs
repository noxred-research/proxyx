//! Reputation scores (`ip_scores`): the history of checks of an IP by each
//! service, so the replacement rule can look at consecutive checks.

use std::net::IpAddr;

use proxyx_db::Ts;
use serde_json::Value;
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::error::{Result, StoreError};

instances!("impls/scores.rs");

/// One reputation check of an IP by one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreRow {
    pub ip: IpAddr,
    pub source: String,
    /// 0 to 100, higher is worse.
    pub risk: u8,
    pub flags: Vec<String>,
    pub checked_at: OffsetDateTime,
}

#[derive(FromRow)]
pub(super) struct RawScore {
    ip: String,
    source: String,
    risk: i16,
    flags: Json<Value>,
    checked_at: Ts,
}

impl TryFrom<RawScore> for ScoreRow {
    type Error = StoreError;

    fn try_from(r: RawScore) -> Result<Self> {
        Ok(Self {
            ip: r.ip.parse().map_err(|e| StoreError::decode("ip", e))?,
            source: r.source,
            risk: u8::try_from(r.risk).map_err(|e| StoreError::decode("risk", e))?,
            flags: serde_json::from_value(r.flags.0).map_err(|e| StoreError::decode("flags", e))?,
            checked_at: r.checked_at.0,
        })
    }
}

delegate! {
    /// Append one check result (no audit row: a measurement).
    ///
    /// Fails with [`StoreError::Invalid`] when `risk` is above 100.
    pub async fn record_score(&self, score: &ScoreRow) -> Result<()>;

    /// The newest `per_source` checks of each service, newest first within a
    /// service. The replacement rule reads consecutive checks from this.
    pub async fn recent_scores(&self, ip: IpAddr, per_source: i64) -> Result<Vec<ScoreRow>>;
}
