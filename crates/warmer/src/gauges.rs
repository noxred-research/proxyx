//! State gauges: `cache_ready`, `cache_min_ready`,
//! `cache_low_watermark`, `cache_low`, `cache_sessions`, `inventory_ips`,
//! `provider_breaker_state` and `cost_used_ratio`. The low-watermark alert
//! reads `cache_low{tier="all"}`: 1 once the leasable units of both tiers have
//! been below `cache_low_watermark` for the policy's `low_for`;
//! `cache_low{tier="normal"}` is the same for the normal tier alone, so a
//! cache that serves on degraded units shows. Rotating units are the free
//! ready sessions, static units the IPs that are healthy (available,
//! degraded or leased).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use common::types::{IpState, Kind};
use store::InventoryRow;
use store::loaded::Loaded;
use time::OffsetDateTime;

use crate::budget;
use crate::state::{Warmer, all_partitions, policy_for, rotating_partitions};

impl Warmer {
    pub(crate) async fn gauges_tick(&self) {
        self.gauges_tick_at(Instant::now()).await;
    }

    /// One tick with `now` as the clock of `cache_low`, so tests can move it.
    pub(crate) async fn gauges_tick_at(&self, now: Instant) {
        let loaded = self.loaded();
        if let Err(error) = self.rotating_gauges(&loaded, now).await {
            self.metrics.redis_down.set(1);
            tracing::warn!(%error, "failed to read rotating gauges");
        }
        if let Err(error) = self.breaker_gauges(&loaded).await {
            self.metrics.redis_down.set(1);
            tracing::warn!(%error, "failed to read breaker states");
        }
        match self.db.list_inventory(None, None).await {
            Ok(rows) => {
                self.metrics.postgres_down.set(0);
                if let Err(error) = self.static_gauges(&loaded, &rows, now).await {
                    self.metrics.redis_down.set(1);
                    tracing::warn!(%error, "failed to read static leases for gauges");
                }
            }
            Err(error) => {
                self.metrics.postgres_down.set(1);
                tracing::warn!(%error, "failed to read the inventory for gauges");
            }
        }
        // A provider that left the policy or the inventory keeps no series
        // of its own: its last breaker state or budget would keep alerting.
        let breakers = all_partitions(&loaded)
            .into_iter()
            .map(|p| p.provider.to_string())
            .collect();
        let costs = rotating_partitions(&loaded)
            .into_iter()
            .map(|(p, _)| p.provider.to_string())
            .collect();
        self.metrics.forget_providers(&breakers, &costs);
    }

    /// The breaker of each provider: the worst state of its route classes,
    /// rotating and static, as the gateway and the warmers wrote it.
    async fn breaker_gauges(&self, loaded: &Loaded) -> store::Result<()> {
        let providers: BTreeSet<_> = all_partitions(loaded)
            .into_iter()
            .map(|p| p.provider)
            .collect();
        for provider in providers {
            self.publish_breaker(&provider).await?;
        }
        Ok(())
    }

    async fn rotating_gauges(&self, loaded: &Loaded, now: Instant) -> store::Result<()> {
        let kind = Kind::Rotating.as_str();
        let mut by_provider: BTreeMap<String, CacheLevels> = BTreeMap::new();
        let (mut creating, mut ready, mut leased) = (0i64, 0i64, 0i64);
        for (p, policy) in rotating_partitions(loaded) {
            let counts = self.hot.counts(&p).await?;
            let free = gauge(counts.ready_free);
            let target = policy.capacity.target(&p.region);
            let levels = by_provider.entry(p.provider.to_string()).or_default();
            levels.ready += free;
            levels.degraded += gauge(counts.degraded_free);
            levels.min_ready += i64::from(target.min_ready);
            levels.low_watermark += i64::from(target.low_watermark);
            // The partitions of a provider share one policy (`policy_for`),
            // so this is that policy's `low_for`; the longest wins should
            // they ever differ, so no policy is alerted sooner than it asked.
            levels.low_for = levels.low_for.max(policy.capacity.low_for);
            ready += free;
            leased += gauge(counts.leased);
            creating += gauge(counts.creating);

            let used = self
                .hot
                .cost_used(&p.provider, OffsetDateTime::now_utc())
                .await?;
            self.metrics.set_cost_used_ratio(
                p.provider.as_str(),
                budget::assess(&policy.cost, used).ratio,
            );
        }
        self.publish_levels(now, kind, &by_provider);
        // `verifying` has no state of its own (the checks run inside the
        // create, which counts as `creating`) and `expired` ends in the drain
        // at once, so neither can be counted.
        let draining = gauge(self.hot.draining_sessions().await?);
        for (state, n) in [
            ("creating", creating),
            ("ready", ready),
            ("leased", leased),
            ("draining", draining),
        ] {
            self.metrics
                .cache_sessions
                .with_label_values(&[kind, state])
                .set(n);
        }
        Ok(())
    }

    /// `inventory_ips`: the state of each row, except that a unit with a lease
    /// or a tunnel counts as `leased` and not in its row's state (`available`
    /// or `degraded`): the lease lives in Redis, the row keeps its state.
    /// Customer upstreams (rows with an owner) are left out of every figure:
    /// they are no part of the pool the cache and pool alerts measure, and a
    /// customer with one upstream would otherwise leave `cache_ready` at 1,
    /// under the low watermark.
    async fn static_gauges(
        &self,
        loaded: &Loaded,
        all_rows: &[InventoryRow],
        now: Instant,
    ) -> store::Result<()> {
        let rows: Vec<&InventoryRow> = all_rows.iter().filter(|r| r.owner.is_none()).collect();
        let kind = Kind::Static.as_str();
        // Per provider: units with a lease or a tunnel, and free degraded units.
        let mut leased: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        let partitions: BTreeSet<_> = rows
            .iter()
            .filter(|r| r.state != IpState::Retired)
            .map(|r| r.partition())
            .collect();
        for p in &partitions {
            let counts = self.hot.counts(p).await?;
            let (in_use, degraded_free) = leased.entry(p.provider.as_str()).or_default();
            *in_use += usize::try_from(counts.leased).unwrap_or(usize::MAX);
            *degraded_free += usize::try_from(counts.degraded_free).unwrap_or(usize::MAX);
        }
        // A provider that left the inventory must not keep its last counts.
        self.metrics.inventory_ips.reset();
        let providers: BTreeSet<&str> = rows.iter().map(|r| r.entry.provider.as_str()).collect();
        let mut published = BTreeMap::new();
        for provider in providers {
            let mine = || {
                rows.iter()
                    .filter(|r| r.entry.provider.as_str() == provider)
            };
            let (in_use, degraded_free) = leased.get(provider).copied().unwrap_or_default();
            // A unit in use is a row in `available` or `degraded`; the degraded
            // rows that are not free are the ones in use.
            let degraded_rows = mine().filter(|r| r.state == IpState::Degraded).count();
            let degraded_in_use = degraded_rows.saturating_sub(degraded_free).min(in_use);
            for state in IpState::ALL {
                let n = mine().filter(|r| r.state == state).count();
                let n = match state {
                    IpState::Available => n.saturating_sub(in_use - degraded_in_use),
                    IpState::Degraded => n.saturating_sub(degraded_in_use),
                    IpState::Leased => n + in_use,
                    _ => n,
                };
                self.metrics
                    .inventory_ips
                    .with_label_values(&[provider, state.as_str()])
                    .set(gauge(n));
            }
            let healthy = mine().filter(|r| r.state.is_leasable()).count();
            let regions: BTreeSet<_> = mine()
                .filter(|r| r.state != IpState::Retired)
                .map(|r| r.entry.region.clone())
                .collect();
            let Some(first) = mine().next() else { continue };
            let policy = policy_for(loaded, &first.entry.provider);
            let (min_ready, low_watermark) = regions
                .iter()
                .map(|region| policy.capacity.target(region))
                .fold((0, 0), |(min, low), t| {
                    (
                        min + i64::from(t.min_ready),
                        low + i64::from(t.low_watermark),
                    )
                });
            let healthy = gauge(healthy);
            published.insert(
                provider.to_owned(),
                CacheLevels {
                    ready: healthy,
                    degraded: gauge(mine().filter(|r| r.state == IpState::Degraded).count()),
                    min_ready,
                    low_watermark,
                    // Static partitions of a provider share its one policy.
                    low_for: policy.capacity.low_for,
                },
            );
        }
        self.publish_levels(now, kind, &published);
        Ok(())
    }

    /// Publish the levels of one (kind, provider), and `cache_low` per tier:
    /// 1 once the units of the tier have been below the low watermark for
    /// `low_for` without a break, measured on `now`. `all` counts both tiers,
    /// `normal` the normal tier alone.
    fn set_cache_gauges(&self, now: Instant, kind: &str, provider: &str, levels: &CacheLevels) {
        let normal = levels.ready - levels.degraded;
        for (tier, n) in [("normal", normal), ("degraded", levels.degraded)] {
            self.metrics
                .cache_ready
                .with_label_values(&[kind, provider, tier])
                .set(n);
        }
        let labels = [kind, provider];
        self.metrics
            .cache_min_ready
            .with_label_values(&labels)
            .set(levels.min_ready);
        self.metrics
            .cache_low_watermark
            .with_label_values(&labels)
            .set(levels.low_watermark);
        for (tier, n) in [("all", levels.ready), ("normal", normal)] {
            let low = track_low(
                &mut self.low_since.lock(),
                now,
                (kind, provider, tier),
                n < levels.low_watermark,
                levels.low_for,
            );
            self.metrics
                .cache_low
                .with_label_values(&[kind, provider, tier])
                .set(i64::from(low));
        }
    }

    /// Publish the levels of every provider of `kind`. A provider that left
    /// them must not keep its clocks or the series of its last levels (a
    /// stale `cache_low` of 1, or a level under the watermark, would keep
    /// alerting).
    fn publish_levels(&self, now: Instant, kind: &str, levels: &BTreeMap<String, CacheLevels>) {
        for (provider, l) in levels {
            self.set_cache_gauges(now, kind, provider, l);
        }
        let published = levels.keys().cloned().collect();
        let gone = drop_vanished(&mut self.low_since.lock(), kind, &published);
        let mut vanished = BTreeSet::new();
        for (provider, tier) in &gone {
            // The series exists: it was created with the clock entry.
            let _ = self.metrics.cache_low.remove_label_values(&[
                kind,
                provider.as_str(),
                tier.as_str(),
            ]);
            vanished.insert(provider.as_str());
        }
        for provider in vanished {
            for tier in ["normal", "degraded"] {
                let _ = self
                    .metrics
                    .cache_ready
                    .remove_label_values(&[kind, provider, tier]);
            }
            let _ = self
                .metrics
                .cache_min_ready
                .remove_label_values(&[kind, provider]);
            let _ = self
                .metrics
                .cache_low_watermark
                .remove_label_values(&[kind, provider]);
        }
    }
}

/// What the cache gauges of one (kind, provider) publish.
#[derive(Default)]
struct CacheLevels {
    /// Leasable units of both tiers.
    ready: i64,
    /// Of `ready`, the units of the degraded tier.
    degraded: i64,
    min_ready: i64,
    low_watermark: i64,
    /// How long the units must stay below `low_watermark` before `cache_low`
    /// is 1.
    low_for: Duration,
}

/// Per (kind, provider, tier): since when the units of the tier have been
/// below the low watermark without a break (`None`: they are not below).
pub(crate) type LowSince = HashMap<(String, String, String), Option<Instant>>;

/// A count as a gauge value.
fn gauge(n: impl TryInto<i64>) -> i64 {
    n.try_into().unwrap_or(i64::MAX)
}

/// Record one reading of `(kind, provider, tier)` and say whether it has been
/// low for at least `low_for`. A reading that is not `below` stops the clock;
/// the next low reading starts it again.
fn track_low(
    since: &mut LowSince,
    now: Instant,
    (kind, provider, tier): (&str, &str, &str),
    below: bool,
    low_for: Duration,
) -> bool {
    let slot = since
        .entry((kind.to_owned(), provider.to_owned(), tier.to_owned()))
        .or_default();
    if !below {
        *slot = None;
        return false;
    }
    let from = *slot.get_or_insert(now);
    now.saturating_duration_since(from) >= low_for
}

/// Drop the clocks of `kind` whose provider is not in `published`; returns
/// their (provider, tier).
fn drop_vanished(
    since: &mut LowSince,
    kind: &str,
    published: &BTreeSet<String>,
) -> Vec<(String, String)> {
    let mut gone = Vec::new();
    since.retain(|(k, provider, tier), _| {
        let keep = k != kind || published.contains(provider);
        if !keep {
            gone.push((provider.clone(), tier.clone()));
        }
        keep
    });
    gone
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW_FOR: Duration = Duration::from_secs(120);

    fn low(since: &mut LowSince, now: Instant, provider: &str, below: bool) -> bool {
        track_low(since, now, ("rotating", provider, "all"), below, LOW_FOR)
    }

    #[test]
    fn low_for_counts_from_the_first_low_reading_and_a_recovery_restarts_it() {
        let (mut since, t0) = (LowSince::new(), Instant::now());
        let at = |s| t0 + Duration::from_secs(s);
        assert!(!low(&mut since, at(0), "p", true), "the clock starts");
        assert!(!low(&mut since, at(119), "p", true));
        assert!(low(&mut since, at(120), "p", true), "exactly low_for");
        assert!(low(&mut since, at(500), "p", true));
        assert!(!low(&mut since, at(501), "p", false), "recovered");
        assert!(!low(&mut since, at(502), "p", true), "the clock restarts");
        assert!(!low(&mut since, at(621), "p", true));
        assert!(low(&mut since, at(622), "p", true));
    }

    #[test]
    fn a_zero_low_for_is_low_at_once_and_providers_do_not_share_a_clock() {
        let (mut since, t0) = (LowSince::new(), Instant::now());
        assert!(track_low(
            &mut since,
            t0,
            ("static", "a", "all"),
            true,
            Duration::ZERO
        ));
        assert!(!low(&mut since, t0, "b", true));
        let later = t0 + LOW_FOR;
        assert!(low(&mut since, later, "b", true));
        assert!(!low(&mut since, later, "c", true), "c starts only now");
    }

    #[test]
    fn a_vanished_provider_loses_its_clock_but_other_kinds_keep_theirs() {
        let (mut since, t0) = (LowSince::new(), Instant::now());
        for (kind, provider) in [("rotating", "a"), ("rotating", "b"), ("static", "a")] {
            track_low(&mut since, t0, (kind, provider, "all"), true, LOW_FOR);
        }
        let published = BTreeSet::from(["a".to_owned()]);
        assert_eq!(
            drop_vanished(&mut since, "rotating", &published),
            [("b".to_owned(), "all".to_owned())]
        );
        assert_eq!(since.len(), 2);
        assert!(since.contains_key(&("static".to_owned(), "a".to_owned(), "all".to_owned())));
        assert!(drop_vanished(&mut since, "rotating", &published).is_empty());
    }
}
