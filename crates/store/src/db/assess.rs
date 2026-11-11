//! Read-only summaries for `proxyx assess pool`: the reputation and block
//! history of the whole pool in one query each, instead of one per IP.

use std::net::IpAddr;

use sqlx::FromRow;
use time::OffsetDateTime;

use crate::error::Result;

instances!("impls/assess.rs");

/// Block signals recorded since some moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockSummary {
    /// Signals in all.
    pub signals: i64,
    /// Distinct IPs that got at least one.
    pub ips: i64,
    /// Signals by signal type (`rate_limited`, `challenge`, ...), by name.
    pub by_type: Vec<(String, i64)>,
}

#[derive(FromRow)]
pub(super) struct TypeCount {
    pub(super) signal_type: String,
    pub(super) n: i64,
}

delegate! {
    /// The highest risk (0 to 100, higher is worse) of each scored IP, taking
    /// the newest check of every reputation service.
    pub async fn latest_risks(&self) -> Result<Vec<(IpAddr, u8)>>;

    /// The block signals recorded at or after `since`.
    pub async fn block_summary_since(&self, since: OffsetDateTime) -> Result<BlockSummary>;
}
