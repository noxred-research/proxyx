//! Block signals per IP (`ip_blocks`): the history that decides quarantine and
//! replacement, and the per-target cooldowns the gateway reads.

use std::net::IpAddr;

use common::types::{SignalSource, SignalType};
use proxyx_db::Ts;
use sqlx::FromRow;
use time::OffsetDateTime;

use super::parse_enum;
use crate::error::{Result, StoreError};

instances!("impls/blocks.rs");

/// One block signal in the history of an IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBlock {
    pub id: i64,
    pub ip: IpAddr,
    /// Lowercase target host; `None` for an IP-wide block.
    pub target: Option<String>,
    pub source: SignalSource,
    pub signal_type: SignalType,
    pub created_at: OffsetDateTime,
    /// Target blocks: end of the per-target cooldown.
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
pub(super) struct RawBlock {
    id: i64,
    ip: String,
    target: Option<String>,
    source: String,
    signal_type: String,
    created_at: Ts,
    expires_at: Option<Ts>,
}

impl RawBlock {
    pub(super) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    pub(super) fn signal_type(&self) -> &str {
        &self.signal_type
    }
}

impl TryFrom<RawBlock> for IpBlock {
    type Error = StoreError;

    fn try_from(r: RawBlock) -> Result<Self> {
        Ok(Self {
            id: r.id,
            ip: r.ip.parse().map_err(|e| StoreError::decode("ip", e))?,
            target: r.target,
            source: parse_enum("signal source", &r.source)?,
            signal_type: parse_enum("signal type", &r.signal_type)?,
            created_at: r.created_at.0,
            expires_at: r.expires_at.map(|t| t.0),
        })
    }
}

macro_rules! block_columns {
    () => {
        "id, ip, target, source, signal_type, created_at, expires_at"
    };
}
pub(super) use block_columns;

delegate! {
    /// Record a block signal. A target block needs `expires_at` (its
    /// cooldown end); an IP-wide block (`target` None) must not have one.
    ///
    /// Fails with [`StoreError::Invalid`] for a target without expiry or the
    /// reverse.
    pub async fn record_block(
        &self,
        ip: IpAddr,
        target: Option<&str>,
        source: SignalSource,
        signal_type: SignalType,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<IpBlock>;

    /// Blocks of an IP since `since`, newest first.
    pub async fn blocks_since(&self, ip: IpAddr, since: OffsetDateTime) -> Result<Vec<IpBlock>>;

    /// IP-wide blocks of an IP since `since` (the `quarantine_after` rule).
    pub async fn ip_wide_blocks_since(&self, ip: IpAddr, since: OffsetDateTime) -> Result<i64>;

    /// Distinct targets that blocked an IP since `since` (the
    /// `escalate_targets` rule).
    pub async fn blocked_targets_since(&self, ip: IpAddr, since: OffsetDateTime) -> Result<i64>;
}
