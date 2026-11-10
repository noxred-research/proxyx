//! Reading the pool: Postgres through the store, Redis through the store's
//! read calls, the gateway through its ops server. Nothing is written.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::Context as _;
use common::retry::{BreakerConfig, BreakerState};
use common::types::{IpState, Kind as UnitKind, Partition};
use diag::net::http_get;
use store::loaded::Loaded;
use store::{Db, Hot, InventoryRow};
use time::{Date, Month, OffsetDateTime};

use super::facts::{
    Breaker, BusyUnit, CostFacts, GatewayFacts, GatewayGauges, Kind, PartitionFacts, PoolFacts,
    ProviderFacts, StaticFacts,
};

/// The org the warmer's policy lookups use: the policy of the pool itself,
/// not of a customer.
const POLICY_ORG: &str = "proxyx-warmer";
/// Static units whose load is read per partition (the busiest is kept).
const MAX_UNIT_LOADS: usize = 500;

fn policy_for<'a>(
    loaded: &'a Loaded,
    org: &common::types::OrgId,
    provider: &common::types::ProviderId,
) -> &'a policy::EffectivePolicy {
    loaded.policies.effective(org, Some(provider))
}

/// Read the pool as of `now`: `window` back for block signals.
pub async fn collect(
    db: &Db,
    hot: &Hot,
    loaded: &Loaded,
    now: OffsetDateTime,
    window: Duration,
) -> anyhow::Result<PoolFacts> {
    let org = POLICY_ORG.parse().context("the policy org name")?;
    let policy_of = |provider: &common::types::ProviderId| policy_for(loaded, &org, provider);
    let inventory: Vec<&InventoryRow> = loaded
        .snapshot
        .inventory
        .iter()
        .filter(|r| r.owner.is_none() && r.state != IpState::Retired)
        .collect();

    // Partitions: one per policy region of a rotating adapter, one per
    // (provider, region) that holds a static IP.
    let mut partitions = Vec::new();
    let mut breaker_partitions: BTreeMap<String, Vec<Partition>> = BTreeMap::new();
    let mut rotating_providers = BTreeSet::new();
    for adapter in loaded
        .adapters
        .iter()
        .filter(|a| a.kind() == UnitKind::Rotating)
    {
        let policy = policy_of(adapter.id());
        let listed = policy.providers.is_empty() || policy.providers.contains(adapter.id());
        if !policy.kinds.contains(&UnitKind::Rotating) || !listed {
            continue;
        }
        rotating_providers.insert(adapter.id().to_string());
        for region in &policy.regions {
            let p = Partition {
                provider: adapter.id().clone(),
                region: region.clone(),
            };
            let counts = hot
                .counts(&p)
                .await
                .with_context(|| format!("counts of {p}"))?;
            let target = policy.capacity.target(region);
            partitions.push(PartitionFacts {
                provider: p.provider.to_string(),
                region: region.to_string(),
                kind: Kind::Rotating,
                ready: counts.ready_free,
                leased: counts.leased,
                degraded_free: counts.degraded_free,
                creating: counts.creating,
                min_ready: target.min_ready,
                low_watermark: target.low_watermark,
                paused: hot.warm_paused(&p).await?,
                busiest: None,
            });
            breaker_partitions
                .entry(p.provider.to_string())
                .or_default()
                .push(p);
        }
    }
    let static_partitions: BTreeSet<Partition> = inventory.iter().map(|r| r.partition()).collect();
    for p in static_partitions {
        let policy = policy_of(&p.provider);
        let counts = hot
            .counts(&p)
            .await
            .with_context(|| format!("counts of {p}"))?;
        let rows: Vec<&&InventoryRow> = inventory.iter().filter(|r| r.partition() == p).collect();
        let leasable = rows.iter().filter(|r| r.state.is_leasable()).count();
        let target = policy.capacity.target(&p.region);
        let limit = match loaded
            .adapters
            .get(&p.provider)
            .and_then(|a| a.max_conns_per_ip())
        {
            Some(provider_limit) => Some(policy.conns_per_ip(provider_limit)),
            None => policy.max_conns_per_ip,
        }
        .filter(|l| *l > 0);
        let mut busiest = None;
        if let Some(limit) = limit {
            let mut best: Option<(u64, IpAddr)> = None;
            for row in rows
                .iter()
                .filter(|r| r.state.is_leasable())
                .take(MAX_UNIT_LOADS)
            {
                let ip = row.unit_ip();
                let load = hot.unit_load(&p, &ip.to_string()).await?;
                if best.is_none_or(|(tunnels, _)| load.tunnels > tunnels) {
                    best = Some((load.tunnels, ip));
                }
            }
            busiest = best
                .filter(|(tunnels, _)| *tunnels > 0)
                .map(|(tunnels, ip)| BusyUnit { ip, tunnels, limit });
        }
        partitions.push(PartitionFacts {
            provider: p.provider.to_string(),
            region: p.region.to_string(),
            kind: Kind::Static,
            ready: u64::try_from(leasable).unwrap_or(u64::MAX),
            leased: counts.leased,
            degraded_free: counts.degraded_free,
            creating: counts.creating,
            min_ready: target.min_ready,
            low_watermark: target.low_watermark,
            paused: hot.warm_paused(&p).await?,
            busiest,
        });
        breaker_partitions
            .entry(p.provider.to_string())
            .or_default()
            .push(p);
    }
    partitions.sort_by(|a, b| {
        (&a.provider, &a.region, a.kind.name()).cmp(&(&b.provider, &b.region, b.kind.name()))
    });

    // Providers: breaker, budget, policy values.
    let cfg = BreakerConfig::default();
    let mut providers = Vec::new();
    for (provider, parts) in &breaker_partitions {
        let mut worst = Breaker::Closed;
        for p in parts {
            let (state, _) = hot.breaker_peek(p, &cfg).await?;
            worst = worst.max(match state {
                BreakerState::Closed => Breaker::Closed,
                BreakerState::HalfOpen => Breaker::HalfOpen,
                BreakerState::Open => Breaker::Open,
            });
        }
        let id = parts[0].provider.clone();
        let policy = policy_of(&id);
        let cost = if rotating_providers.contains(provider) {
            let used = hot.cost_used(&id, now).await?;
            Some(CostFacts {
                bytes_today: used.bytes_today,
                creates_this_hour: used.creates_this_hour,
                max_gb_per_day: policy.cost.max_gb_per_day,
                max_creates_per_hour: policy.cost.max_creates_per_hour,
            })
        } else {
            None
        };
        providers.push(ProviderFacts {
            provider: provider.clone(),
            breaker: worst,
            cost,
            recheck_every: policy.static_ips.recheck_every,
            max_risk: policy.criteria.max_risk,
        });
    }

    // Static IPs, with the risk of their latest checks.
    let risks = db.latest_risks().await?;
    let risk_of: HashMap<IpAddr, u8> = risks.iter().copied().collect();
    let statics = inventory
        .iter()
        .map(|r| StaticFacts {
            provider: r.entry.provider.to_string(),
            ip: r.unit_ip(),
            state: r.state,
            state_since: r.state_since,
            last_check_at: r.last_check_at,
            rental_end: r.entry.rental_end.as_deref().and_then(parse_date),
            risk: risk_of
                .get(&r.unit_ip())
                .or_else(|| risk_of.get(&r.entry.ip))
                .copied(),
        })
        .collect();
    let blocks = db.block_summary_since(now - window).await?;
    Ok(PoolFacts {
        now,
        window,
        partitions,
        providers,
        statics,
        risks: risks.iter().map(|(_, risk)| *risk).collect(),
        blocks,
        gateway: None,
    })
}

/// `YYYY-MM-DD`; anything else is no date.
pub(crate) fn parse_date(text: &str) -> Option<Date> {
    let mut parts = text.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

/// Ask the gateway's ops server (`/readyz`, `/metrics`).
pub async fn probe_gateway(url: &str, timeout: Duration, reload_every: Duration) -> GatewayFacts {
    let base = url.trim_end_matches('/');
    let ready = http_get(&format!("{base}/readyz"), timeout).await;
    let gauges = match http_get(&format!("{base}/metrics"), timeout).await {
        Ok((200, text)) => Some(parse_gauges(&text)),
        _ => None,
    };
    GatewayFacts {
        url: base.to_owned(),
        ready,
        gauges,
        reload_every,
    }
}

/// The gauges the assessment reads out of a Prometheus text exposition.
pub(crate) fn parse_gauges(text: &str) -> GatewayGauges {
    let mut g = GatewayGauges::default();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        let (name, labels) = series.split_once('{').map_or((series, ""), |(n, l)| (n, l));
        match name {
            "proxyx_pool_postgres_down" => g.postgres_down = Some(value),
            "proxyx_pool_redis_down" => g.redis_down = Some(value),
            "proxyx_pool_snapshot_age_seconds" => g.snapshot_age_seconds = Some(value),
            "proxyx_pool_config_reload_failed" if value > 0.0 => {
                let source = labels
                    .split(',')
                    .find_map(|l| l.trim().strip_prefix("source=\""))
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("unknown");
                g.reload_failed.push(source.to_owned());
            }
            _ => {}
        }
    }
    g.reload_failed.sort();
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_parse_strictly() {
        assert!(parse_date("2026-12-31").is_some());
        assert!(parse_date("2026-13-01").is_none());
        assert!(parse_date("2026-12").is_none());
        assert!(parse_date("2026-12-31-1").is_none());
        assert!(parse_date("soon").is_none());
    }

    #[test]
    fn gauges_come_out_of_the_exposition() {
        let text = "# HELP proxyx_pool_redis_down x\n\
                    proxyx_pool_redis_down{service=\"proxyx-gateway\"} 1\n\
                    proxyx_pool_postgres_down{service=\"proxyx-gateway\"} 0\n\
                    proxyx_pool_snapshot_age_seconds{service=\"proxyx-gateway\"} 12.5\n\
                    proxyx_pool_config_reload_failed{service=\"proxyx-gateway\",source=\"inventory\"} 1\n\
                    proxyx_pool_config_reload_failed{service=\"proxyx-gateway\",source=\"policies\"} 0\n";
        let g = parse_gauges(text);
        assert_eq!(g.redis_down, Some(1.0));
        assert_eq!(g.postgres_down, Some(0.0));
        assert_eq!(g.snapshot_age_seconds, Some(12.5));
        assert_eq!(g.reload_failed, ["inventory"]);
    }
}
