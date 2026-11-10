//! Limits: token buckets for bandwidth and request rate, connection counters
//! and the compiled `[[limit]]` rules.
//!
//! Every matching `[[limit]]` applies: each has its own bucket per scope key,
//! so the strictest one is the one a client feels. Buckets restart on a
//! configuration reload; open tunnels keep the budgets they were admitted with.

use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use moka::sync::Cache;
use parking_lot::Mutex;

use crate::acl::{Known, Match, Req};
use crate::config::{LimitConfig, LimitScope};

/// A token bucket. `reserve` always takes the tokens and says how long the
/// caller has to wait for them (the bucket may go into debt), which keeps
/// the long-run rate exact however the callers interleave.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate: rate_per_sec,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    pub fn burst(&self) -> f64 {
        self.burst
    }

    fn refill(&self, st: &mut (f64, Instant)) {
        let now = Instant::now();
        let gained = now.duration_since(st.1).as_secs_f64() * self.rate;
        st.0 = (st.0 + gained).min(self.burst);
        st.1 = now;
    }

    /// Take `n` tokens; the returned delay is how long to wait before using them.
    pub fn reserve(&self, n: f64) -> Duration {
        let mut st = self.state.lock();
        self.refill(&mut st);
        st.0 -= n;
        if st.0 >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-st.0 / self.rate)
        }
    }

    /// Take `n` tokens only when they are all there.
    pub fn try_take(&self, n: f64) -> bool {
        let mut st = self.state.lock();
        self.refill(&mut st);
        if st.0 >= n {
            st.0 -= n;
            true
        } else {
            false
        }
    }
}

/// Counts of something open, per key, released by dropping the guard.
pub struct Counters<K: Hash + Eq + Clone + Send + Sync + 'static> {
    map: Arc<DashMap<K, usize>>,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> Default for Counters<K> {
    fn default() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }
}

pub struct CountGuard<K: Hash + Eq + Clone + Send + Sync + 'static> {
    map: Arc<DashMap<K, usize>>,
    key: K,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> Drop for CountGuard<K> {
    fn drop(&mut self) {
        self.map.remove_if_mut(&self.key, |_, n| {
            *n = n.saturating_sub(1);
            *n == 0
        });
    }
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> Counters<K> {
    /// Count one more for `key`; `None` when that would pass `max` (0 is no limit).
    pub fn acquire(&self, key: K, max: usize) -> Option<CountGuard<K>> {
        let mut over = false;
        self.map
            .entry(key.clone())
            .and_modify(|n| {
                if max != 0 && *n >= max {
                    over = true;
                } else {
                    *n += 1;
                }
            })
            .or_insert(1);
        if over {
            return None;
        }
        Some(CountGuard {
            map: Arc::clone(&self.map),
            key,
        })
    }

    pub fn current(&self, key: &K) -> usize {
        self.map.get(key).map_or(0, |n| *n)
    }
}

/// Process-wide connection counters; they survive a reload.
#[derive(Default)]
pub struct ConnCounters {
    pub total: AtomicUsize,
    pub per_src: Counters<IpAddr>,
    pub per_user: Counters<String>,
    pub per_listener: Counters<String>,
}

pub struct TotalGuard(Arc<ConnCounters>);

impl Drop for TotalGuard {
    fn drop(&mut self) {
        self.0.total.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConnCounters {
    pub fn acquire_total(self: &Arc<Self>, max: usize) -> Option<TotalGuard> {
        let prev = self.total.fetch_add(1, Ordering::Relaxed);
        if max != 0 && prev >= max {
            self.total.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(TotalGuard(Arc::clone(self)))
    }
}

/// Which way the bytes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Client to target.
    Up,
    /// Target to client.
    Down,
}

/// One scope key's limits of one `[[limit]]`.
#[derive(Debug)]
pub struct Budget {
    down: Option<TokenBucket>,
    up: Option<TokenBucket>,
    rate: Option<TokenBucket>,
    max_conn: Option<usize>,
    open: AtomicUsize,
}

pub struct BudgetGuard(Arc<Budget>);

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

fn bandwidth_bucket(bytes_per_sec: u64) -> TokenBucket {
    let rate = bytes_per_sec as f64;
    TokenBucket::new(rate, (rate / 10.0).max(2048.0))
}

#[derive(Debug)]
struct CompiledLimit {
    m: Match,
    scope: LimitScope,
    down: Option<u64>,
    up: Option<u64>,
    max_conn: Option<usize>,
    rate: Option<(u32, Duration)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Connections,
    Rate,
}

/// The compiled `[[limit]]` rules and their live budgets.
pub struct LimitSet {
    limits: Vec<CompiledLimit>,
    budgets: Cache<(usize, String), Arc<Budget>>,
}

impl LimitSet {
    pub fn compile(cfg: &[LimitConfig], known: &Known<'_>) -> Result<Self, String> {
        let mut limits = Vec::with_capacity(cfg.len());
        for (i, l) in cfg.iter().enumerate() {
            if l.bandwidth_down.is_none()
                && l.bandwidth_up.is_none()
                && l.max_connections.is_none()
                && l.request_rate.is_none()
            {
                return Err(format!("limit #{}: sets no limit", i + 1));
            }
            if l.max_connections == Some(0) {
                return Err(format!(
                    "limit #{}: max_connections must be above zero",
                    i + 1
                ));
            }
            limits.push(CompiledLimit {
                m: Match::compile(&l.when, known).map_err(|e| format!("limit #{}: {e}", i + 1))?,
                scope: l.scope,
                down: l.bandwidth_down.map(|b| b.0),
                up: l.bandwidth_up.map(|b| b.0),
                max_conn: l.max_connections,
                rate: l.request_rate.map(|r| (r.count, r.per)),
            });
        }
        Ok(Self {
            limits,
            // Idle budgets go away; a budget in use is held by its connections.
            budgets: Cache::builder()
                .max_capacity(200_000)
                .time_to_idle(Duration::from_secs(900))
                .build(),
        })
    }

    pub fn uses_dst(&self) -> bool {
        self.limits.iter().any(|l| l.m.uses_dst())
    }

    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    fn budget(&self, idx: usize, key: String) -> Arc<Budget> {
        let l = &self.limits[idx];
        self.budgets.get_with((idx, key), || {
            Arc::new(Budget {
                down: l.down.map(bandwidth_bucket),
                up: l.up.map(bandwidth_bucket),
                rate: l.rate.map(|(count, per)| {
                    TokenBucket::new(f64::from(count) / per.as_secs_f64(), f64::from(count))
                }),
                max_conn: l.max_conn,
                open: AtomicUsize::new(0),
            })
        })
    }

    /// Admit one request or tunnel against every limit that matches it.
    pub fn admit(&self, req: &Req<'_>) -> Result<Admission, Reject> {
        let mut adm = Admission::default();
        for (i, l) in self.limits.iter().enumerate() {
            if !l.m.matches(req) {
                continue;
            }
            let key = match l.scope {
                LimitScope::Rule => String::new(),
                LimitScope::Src => req.src.to_string(),
                LimitScope::User => req
                    .user
                    .map_or_else(|| format!("ip:{}", req.src), |u| format!("user:{u}")),
            };
            let b = self.budget(i, key);
            if let Some(rate) = &b.rate
                && !rate.try_take(1.0)
            {
                return Err(Reject::Rate);
            }
            if let Some(max) = b.max_conn {
                let prev = b.open.fetch_add(1, Ordering::Relaxed);
                if prev >= max {
                    b.open.fetch_sub(1, Ordering::Relaxed);
                    return Err(Reject::Connections);
                }
                adm.guards.push(BudgetGuard(Arc::clone(&b)));
            }
            if b.up.is_some() || b.down.is_some() {
                adm.budgets.push(b);
            }
        }
        Ok(adm)
    }
}

/// What a request was admitted with: connection slots held and buckets to charge.
#[derive(Default)]
pub struct Admission {
    guards: Vec<BudgetGuard>,
    budgets: Vec<Arc<Budget>>,
}

impl Admission {
    pub fn shaper(&self, dir: Dir) -> Shaper {
        Shaper {
            buckets: self.budgets.to_vec(),
            dir,
        }
    }

    pub fn holds(&self) -> usize {
        self.guards.len()
    }
}

/// Paces one direction of a transfer to the buckets of its budgets.
#[derive(Clone)]
pub struct Shaper {
    buckets: Vec<Arc<Budget>>,
    dir: Dir,
}

impl Shaper {
    pub fn none() -> Self {
        Self {
            buckets: Vec::new(),
            dir: Dir::Up,
        }
    }

    fn bucket<'a>(&self, b: &'a Budget) -> Option<&'a TokenBucket> {
        match self.dir {
            Dir::Up => b.up.as_ref(),
            Dir::Down => b.down.as_ref(),
        }
    }

    pub fn is_limited(&self) -> bool {
        self.buckets.iter().any(|b| self.bucket(b).is_some())
    }

    /// Largest piece worth reading at once: one bucket burst at most.
    pub fn chunk(&self, max: usize) -> usize {
        self.buckets
            .iter()
            .filter_map(|b| self.bucket(b))
            .map(|t| t.burst() as usize)
            .fold(max, usize::min)
            .max(1)
    }

    /// Charge `n` bytes and wait as long as the strictest bucket says.
    pub async fn pace(&self, n: usize) {
        let wait = self
            .buckets
            .iter()
            .filter_map(|b| self.bucket(b))
            .map(|t| t.reserve(n as f64))
            .max()
            .unwrap_or(Duration::ZERO);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{Clock, Proto};
    use crate::config::Config;

    fn known() -> Known<'static> {
        Known {
            listeners: vec!["main"],
            users: vec!["alice", "bob"],
            groups: vec!["staff"],
        }
    }

    fn set(toml: &str) -> LimitSet {
        LimitSet::compile(&Config::parse(toml).expect("parse").limits, &known()).expect("compile")
    }

    fn req<'a>(user: Option<&'a str>, src: &str) -> Req<'a> {
        Req {
            src: src.parse().expect("ip"),
            listener: "main",
            proto: Proto::Http,
            method: "GET",
            host: "a.test",
            port: 80,
            dst_ips: &[],
            user,
            groups: &[],
            clock: Clock {
                weekday: 0,
                minute: 0,
            },
        }
    }

    #[test]
    fn a_token_bucket_paces_to_its_rate() {
        let b = TokenBucket::new(1000.0, 100.0);
        assert_eq!(b.reserve(100.0), Duration::ZERO, "the burst is free");
        let wait = b.reserve(500.0);
        assert!(
            wait >= Duration::from_millis(480) && wait <= Duration::from_millis(520),
            "{wait:?}"
        );
        assert!(b.reserve(500.0) > wait, "debt accumulates");
    }

    #[test]
    fn try_take_is_all_or_nothing() {
        let b = TokenBucket::new(1.0, 2.0);
        assert!(b.try_take(1.0));
        assert!(b.try_take(1.0));
        assert!(!b.try_take(1.0));
    }

    #[test]
    fn counters_enforce_max_and_release_on_drop() {
        let c: Counters<String> = Counters::default();
        let a = c.acquire("k".into(), 2).expect("1");
        let b = c.acquire("k".into(), 2).expect("2");
        assert!(c.acquire("k".into(), 2).is_none());
        assert_eq!(c.current(&"k".to_owned()), 2);
        drop(a);
        let _again = c.acquire("k".into(), 2).expect("slot freed");
        drop(b);
        assert!(c.acquire("other".into(), 0).is_some(), "0 is unlimited");
    }

    #[test]
    fn total_guard_counts_connections() {
        let c = Arc::new(ConnCounters::default());
        let g1 = c.acquire_total(2).expect("1");
        let _g2 = c.acquire_total(2).expect("2");
        assert!(c.acquire_total(2).is_none());
        drop(g1);
        assert!(c.acquire_total(2).is_some());
    }

    #[test]
    fn limits_apply_per_scope_key() {
        let s = set(r#"
            [[limit]]
            when = { group = ["staff"] }
            max_connections = 1
        "#);
        let groups = vec!["staff".to_owned()];
        let mut a = req(Some("alice"), "10.0.0.1");
        a.groups = &groups;
        let mut b = req(Some("bob"), "10.0.0.2");
        b.groups = &groups;
        let a1 = s.admit(&a).expect("alice 1");
        assert_eq!(s.admit(&a).err(), Some(Reject::Connections));
        let _b1 = s.admit(&b).expect("bob has his own budget");
        drop(a1);
        assert!(s.admit(&a).is_ok());
        // no match: no limit at all
        assert_eq!(
            s.admit(&req(Some("alice"), "10.0.0.1"))
                .expect("unmatched")
                .holds(),
            0
        );
    }

    #[test]
    fn rule_scope_shares_one_budget() {
        let s = set("[[limit]]\nscope = \"rule\"\nmax_connections = 2\n");
        let a = s.admit(&req(Some("alice"), "10.0.0.1")).expect("1");
        let b = s.admit(&req(Some("bob"), "10.0.0.2")).expect("2");
        assert_eq!(
            s.admit(&req(None, "10.0.0.3")).err(),
            Some(Reject::Connections)
        );
        drop((a, b));
    }

    #[test]
    fn request_rate_rejects_past_the_bucket() {
        let s = set("[[limit]]\nscope = \"src\"\nrequest_rate = \"3/min\"\n");
        let r = req(None, "10.0.0.1");
        for _ in 0..3 {
            assert!(s.admit(&r).is_ok());
        }
        assert_eq!(s.admit(&r).err(), Some(Reject::Rate));
        assert!(s.admit(&req(None, "10.0.0.2")).is_ok(), "another source");
    }

    #[tokio::test(start_paused = true)]
    async fn the_shaper_waits_for_the_strictest_bucket() {
        let s = set(r#"
            [[limit]]
            bandwidth_down = "10000"
            [[limit]]
            bandwidth_down = "1000"
        "#);
        let adm = s.admit(&req(None, "10.0.0.1")).expect("admit");
        let down = adm.shaper(Dir::Down);
        assert!(down.is_limited());
        assert!(!adm.shaper(Dir::Up).is_limited());
        assert_eq!(down.chunk(16_384), 2048, "one burst of the smallest bucket");
        let start = tokio::time::Instant::now();
        down.pace(2048).await; // free burst
        down.pace(2000).await; // ~2 s at 1000 B/s
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(1800) && took <= Duration::from_millis(2300),
            "{took:?}"
        );
    }

    #[test]
    fn compile_refuses_empty_and_zero_limits() {
        for bad in [
            "[[limit]]\nname = \"x\"\n",
            "[[limit]]\nmax_connections = 0\n",
            "[[limit]]\nmax_connections = 1\nwhen = { user = [\"ghost\"] }\n",
        ] {
            let c = Config::parse(bad).expect("parse");
            assert!(LimitSet::compile(&c.limits, &known()).is_err(), "{bad}");
        }
    }
}
