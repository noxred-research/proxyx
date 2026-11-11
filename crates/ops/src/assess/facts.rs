//! What `proxyx assess pool` reads from the pool, as plain data. [`collect`]
//! fills it from Postgres, Redis and the gateway; [`evaluate`] judges it. The
//! split keeps every threshold testable without a service.
//!
//! [`collect`]: super::collect
//! [`evaluate`]: super::evaluate

use std::net::IpAddr;
use std::time::Duration;

use common::types::IpState;
use store::BlockSummary;
use time::{Date, OffsetDateTime};

/// Rotating sessions or static IPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rotating,
    Static,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rotating => "rotating",
            Self::Static => "static",
        }
    }
}

/// State of a provider's circuit breaker (worst over its partitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Breaker {
    Closed,
    HalfOpen,
    Open,
}

/// The tunnels of the most loaded static unit of a partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyUnit {
    pub ip: IpAddr,
    pub tunnels: u64,
    /// Tunnels per IP the policy allows (`max_conns_per_ip`, else 80% of the
    /// provider's limit).
    pub limit: u32,
}

/// One partition (a provider in a region and kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionFacts {
    pub provider: String,
    pub region: String,
    pub kind: Kind,
    /// Leasable units that are free. Rotating: the free ready sessions. Static:
    /// every IP in a leasable state (available, degraded, leased), the same
    /// figure the pool's cache gauges and low-watermark alert use.
    pub ready: u64,
    /// Units with a lease or an open tunnel.
    pub leased: u64,
    /// Free units of the degraded tier.
    pub degraded_free: u64,
    /// Creates started and not ready yet.
    pub creating: u64,
    pub min_ready: u32,
    pub low_watermark: u32,
    /// A failed canary paused warming of the partition.
    pub paused: bool,
    pub busiest: Option<BusyUnit>,
}

/// Spend of a provider against its cost policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostFacts {
    pub bytes_today: u64,
    pub creates_this_hour: u64,
    pub max_gb_per_day: f64,
    pub max_creates_per_hour: u32,
}

/// Per provider: the breaker, the budget and the policy values the findings use.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderFacts {
    pub provider: String,
    pub breaker: Breaker,
    /// Only providers with a rotating partition meter a budget.
    pub cost: Option<CostFacts>,
    /// How often the warmer re-checks a static IP (`static.recheck_every`).
    pub recheck_every: Duration,
    /// Risk above which a reputation score disqualifies an IP (`criteria.max_risk`).
    pub max_risk: u8,
}

/// One static IP of the shared pool (customer upstreams and retired IPs are left out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFacts {
    pub provider: String,
    pub ip: IpAddr,
    pub state: IpState,
    pub state_since: OffsetDateTime,
    pub last_check_at: Option<OffsetDateTime>,
    pub rental_end: Option<Date>,
    /// Highest risk of the IP's latest reputation checks.
    pub risk: Option<u8>,
}

/// Gauges read from the gateway's `/metrics`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayGauges {
    pub postgres_down: Option<f64>,
    pub redis_down: Option<f64>,
    /// Sources whose last reload was rejected.
    pub reload_failed: Vec<String>,
    pub snapshot_age_seconds: Option<f64>,
}

/// What the gateway's ops server said.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayFacts {
    pub url: String,
    /// `/readyz`: status and body, or why it could not be asked.
    pub ready: Result<(u16, String), String>,
    pub gauges: Option<GatewayGauges>,
    /// The configured reload interval, for judging the snapshot age.
    pub reload_every: Duration,
}

/// Everything one assessment reads.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolFacts {
    pub now: OffsetDateTime,
    /// How far back block signals are counted.
    pub window: Duration,
    pub partitions: Vec<PartitionFacts>,
    pub providers: Vec<ProviderFacts>,
    pub statics: Vec<StaticFacts>,
    /// The highest latest risk of every scored IP (rotating exits included).
    pub risks: Vec<u8>,
    pub blocks: BlockSummary,
    pub gateway: Option<GatewayFacts>,
}
