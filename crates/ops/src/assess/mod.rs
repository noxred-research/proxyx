//! `proxyx assess pool`: a health assessment of a running pool.
//!
//! It reads Postgres and Redis through the store (read calls only) and the
//! gateway's ops server, and prints findings by section, each `OK`, `WARN` or
//! `CRIT`. Nothing is written, and no lease or session is touched.

mod collect;
mod evaluate;
mod facts;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Subcommand};
use common::config::Settings;
use common::metrics::Metrics;

pub use collect::{collect, probe_gateway};
pub use evaluate::{
    Assessment, EXIT_CRIT, EXIT_OK, EXIT_WARN, Finding, Level, SCHEMA_VERSION, Section, Thresholds,
    evaluate,
};
pub use facts::{
    Breaker, BusyUnit, CostFacts, GatewayFacts, GatewayGauges, Kind, PartitionFacts, PoolFacts,
    ProviderFacts, StaticFacts,
};

/// `proxyx assess`.
#[derive(Debug, Clone, Args)]
pub struct AssessArgs {
    #[command(subcommand)]
    pub target: AssessTarget,
}

#[derive(Debug, Clone, Subcommand)]
pub enum AssessTarget {
    /// Assess the pool: capacity, leases, breakers, checks, reputation, block
    /// signals, rentals and budget.
    Pool(PoolAssessArgs),
}

/// `proxyx assess pool`.
#[derive(Debug, Clone, Args)]
pub struct PoolAssessArgs {
    /// Pool configuration file; overrides the environment (`PROXYX_POOL_*`),
    /// as for `proxyx gateway`.
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// Print the assessment as JSON.
    #[arg(long)]
    pub json: bool,
    /// Treat warnings as critical (exit 1 instead of 2).
    #[arg(long)]
    pub strict: bool,
    /// How far back block signals are counted (`30m`, `1h`, `1d`).
    #[arg(long, default_value = "1h", value_parser = parse_window, value_name = "DURATION")]
    pub window: Duration,
    /// Ops server of a gateway (`/readyz`, `/metrics`). Default: the
    /// configured `ops_listen` on this host.
    #[arg(long, value_name = "URL")]
    pub ops_url: Option<String>,
    /// Do not ask the gateway.
    #[arg(long)]
    pub no_gateway: bool,
    /// Bound on every HTTP request to the gateway.
    #[arg(long, default_value = "5s", value_parser = parse_window, value_name = "DURATION")]
    pub timeout: Duration,
}

fn parse_window(text: &str) -> Result<Duration, String> {
    let d = common::config::humantime_secs::parse(text)?;
    if d.is_zero() {
        return Err("must be above zero".to_owned());
    }
    Ok(d)
}

/// `http://host:port` of a gateway's ops listener as reached from this host:
/// a wildcard address means loopback.
pub fn ops_url(listen: std::net::SocketAddr) -> String {
    let ip = if listen.ip().is_unspecified() {
        if listen.is_ipv4() { "127.0.0.1" } else { "::1" }
            .parse()
            .unwrap_or(listen.ip())
    } else {
        listen.ip()
    };
    match ip {
        std::net::IpAddr::V4(_) => format!("http://{ip}:{}", listen.port()),
        std::net::IpAddr::V6(_) => format!("http://[{ip}]:{}", listen.port()),
    }
}

/// Connect and load the pool as the roles do (no git sync), read it, and judge it.
///
/// The load runs once, with no reload loop behind it, and the Postgres pool is
/// closed before the gateway is asked: nothing of this call keeps a session
/// (or anything it could lock) on the database after it returns.
pub async fn assess_pool(settings: &Settings, args: &PoolAssessArgs) -> anyhow::Result<Assessment> {
    let db = store::Db::connect(settings.database_url.expose())
        .await
        .context("cannot connect to Postgres")?;
    let facts = read_pool(&db, settings, args).await;
    db.close().await;
    let mut facts = facts?;
    if !args.no_gateway {
        let url = args
            .ops_url
            .clone()
            .unwrap_or_else(|| ops_url(settings.ops_listen));
        facts.gateway = Some(probe_gateway(&url, args.timeout, settings.reload_every).await);
    }
    Ok(evaluate(&facts, &Thresholds::default()))
}

async fn read_pool(
    db: &store::Db,
    settings: &Settings,
    args: &PoolAssessArgs,
) -> anyhow::Result<PoolFacts> {
    let hot = store::Hot::connect(settings.redis_url.expose())
        .await
        .context("cannot connect to Redis")?;
    let metrics = Metrics::new("proxyx-assess");
    let loaded = store::loaded::load(db, settings, &metrics, false)
        .await
        .context("cannot load the pool configuration (policies, adapters, inventory)")?;
    collect(
        db,
        &hot,
        &loaded,
        time::OffsetDateTime::now_utc(),
        args.window,
    )
    .await
    .context("cannot read the pool state")
}

/// `proxyx assess`: print the assessment and return its exit code: 0 all OK,
/// 1 a CRIT (or a WARN with `--strict`), 2 only WARNs.
pub async fn run_assess(args: AssessArgs) -> anyhow::Result<i32> {
    let AssessTarget::Pool(args) = args.target;
    let settings = Settings::load(args.config.as_deref())?;
    let assessment = assess_pool(&settings, &args).await?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&assessment.to_json(args.strict))?
        );
    } else {
        print!("{}", assessment.render(args.strict));
    }
    Ok(assessment.exit_code(args.strict))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_listener_is_asked_on_loopback() {
        assert_eq!(
            ops_url("0.0.0.0:8888".parse().expect("addr")),
            "http://127.0.0.1:8888"
        );
        assert_eq!(
            ops_url("[::]:8888".parse().expect("addr")),
            "http://[::1]:8888"
        );
        assert_eq!(
            ops_url("10.0.0.5:9".parse().expect("addr")),
            "http://10.0.0.5:9"
        );
    }
}
