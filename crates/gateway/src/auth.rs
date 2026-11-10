//! Org key lookup with a memory cache, so a tunnel never waits on Postgres
//! When it is down.
//!
//! A key checked less than [`FRESH_FOR`] ago is trusted without asking
//! Postgres. An older entry is checked again; when Postgres fails or is slow,
//! the stale entry still answers for up to [`STALE_FOR`]. After a failure
//! Postgres is not asked again for [`DB_BACKOFF`], so the next tunnels do not
//! each wait for the lookup timeout. An unknown key while Postgres is down gets
//! `503 cache_unavailable`; a key that Postgres says is unknown gets `407`, a
//! disabled one `403 org_disabled`, and either leaves the cache at once.
//!
//! Concurrent lookups of one key share one Postgres query, and a key that
//! Postgres says is unknown is refused from memory for [`UNKNOWN_FOR`], so a
//! flood of wrong keys costs one query per key and window, not one per
//! request. At most [`LOOKUP_SLOTS`] lookups run at once, so
//! the flood cannot take the whole pool, and a lookup that found no slot or
//! no pooled connection says nothing about Postgres: it never starts the
//! backoff that would refuse every uncached key.
//!
//! Distinct wrong keys defeat that memory, so each source (an IPv4 address,
//! an IPv6 /64) may cause [`FAILURES_PER_WINDOW`] lookups that end "unknown"
//! per [`FAILURE_WINDOW`], in each of [`BUCKETS`]
//! buckets chosen by the first bits of the key's hash. Past that, until the
//! window ends, a key of that bucket this pod holds no verified entry for
//! (fresh or stale) is refused with the same `407` without a lookup. A key
//! with a verified entry is never refused by the limit: a fresh one returns
//! before the limit is read, a stale one still gets its lookup. Only the
//! caller that ran a lookup is charged, and only for an "unknown" answer, so
//! valid keys, a disabled org, a wrong key repeated within [`UNKNOWN_FOR`]
//! and callers that joined another's lookup cost their source nothing.
//!
//! The buckets keep one tenant from locking the others out: every
//! gateway client is a session proxy pod that serves many orgs, and an org that
//! saves wrong keys as its proxy password makes its pod fail lookups. Whoever
//! does not hold a key cannot tell which bucket it falls in, so using up the
//! limit for the first verification of another org's key takes failures in
//! every bucket: [`BUCKETS`] times as many, and a bucket that was used up
//! leaves the keys of the others alone.
//!
//! A key is not known to be wrong before it is looked up, so the lookups of
//! unverified keys of one source take turns, one at a time, and the limit is
//! read when a lookup's turn comes: a burst of wrong keys gets exactly
//! [`FAILURES_PER_WINDOW`] lookups per bucket, and a burst of valid new keys
//! (a session proxy pod restarting with many orgs) waits its turn instead of being
//! refused, at most [`TURN_TIMEOUT`].

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::Cause;
use common::metrics::Metrics;
use common::types::OrgId;
use moka::future::Cache;
use parking_lot::Mutex;
use store::{KeyStatus, StoreError};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};

/// A verified key is trusted this long without a lookup.
const FRESH_FOR: Duration = Duration::from_secs(30);
/// A verified key may answer this long while Postgres is down.
const STALE_FOR: Duration = Duration::from_secs(3600);
/// A key Postgres does not know is refused from memory this long.
const UNKNOWN_FOR: Duration = Duration::from_secs(5);
/// One Postgres lookup on the tunnel path, from waiting for a slot to the answer.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
/// After a failed lookup, Postgres is skipped this long.
const DB_BACKOFF: Duration = Duration::from_secs(5);
/// Lookups in flight at once. The store pool has 10 connections, shared with
/// the other users of the pod's `Db`.
const LOOKUP_SLOTS: usize = 6;
/// How long a lookup of an unverified key waits for its source's turn; past
/// it the answer is `cache_unavailable`: the queue only builds behind a slow
/// Postgres.
const TURN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KEYS: u64 = 10_000;
/// Lookups ending "unknown" that one source may cause per window and bucket.
/// A source that cycles wrong keys is held to `FAILURES_PER_WINDOW * BUCKETS
/// / FAILURE_WINDOW`, about five lookups a second, far below what
/// high-entropy keys need and far above what a mistyped config causes (one
/// lookup per [`UNKNOWN_FOR`]).
pub(crate) const FAILURES_PER_WINDOW: u32 = 20;
/// Buckets of the per-source count, by the first bits of the key hash.
pub(crate) const BUCKETS: usize = 16;
/// Fixed window of the per-source count, from the first charge. A source is
/// limited at most this long.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Sources counted at once: the memory bound of the limiter. A full table
/// evicts, so a very wide scan leaves some sources uncounted rather than
/// grow.
const MAX_SOURCES: u64 = 10_000;

/// Failures of one source in its current window.
struct Window {
    start: Instant,
    count: u32,
}

impl Window {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            count: 0,
        }
    }
}

/// The bucket of a key by its hash.
pub(crate) fn bucket(hash: &[u8; 32]) -> usize {
    usize::from(hash[0]) % BUCKETS
}

/// `n` distinct keys that fall in `bucket`, for tests.
#[cfg(test)]
pub(crate) fn keys_in_bucket(bucket_of: usize, tag: &str, n: usize) -> Vec<String> {
    (0u32..)
        .map(|i| format!("{tag}{i}"))
        .filter(|key| bucket(&store::hash_org_key(key)) == bucket_of)
        .take(n)
        .collect()
}
/// What the limiter keeps of one source.
struct Source {
    windows: Mutex<[Window; BUCKETS]>,
    /// Held by the one lookup of an unverified key the source has running.
    turn: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
struct Verified {
    org: OrgId,
    at: Instant,
}

/// Why a lookup gave no answer.
#[derive(Debug)]
enum Unanswered {
    /// The source used up its unknown-key lookups while this one waited for
    /// its turn: no lookup was made.
    SourceLimited,
    /// No free lookup slot in time: this pod is asking too much at once.
    Busy,
    /// The pool had no connection to give in time.
    PoolFull,
    /// Postgres failed or did not answer in time.
    Down(String),
}

pub(crate) struct KeyCache {
    /// Keyed by the sha256 of the org key, so the key itself is never kept.
    verified: Cache<[u8; 32], Verified>,
    /// When Postgres last said the key is unknown. The entry is only used
    /// while younger than [`UNKNOWN_FOR`] on the tokio clock.
    unknown: Cache<[u8; 32], Instant>,
    /// The lookup in flight per key. An entry lives only until its lookup
    /// ends, so it joins callers and never answers a later one.
    flights: Cache<[u8; 32], KeyStatus>,
    slots: Semaphore,
    skip_db_until: Mutex<Option<Instant>>,
    /// Per source ([`FAILURES_PER_WINDOW`], the turn). Timing is read from the
    /// `Window`, on the tokio clock; the cache only bounds the table and
    /// drops sources idle for a window.
    sources: Cache<IpAddr, Arc<Source>>,
    metrics: Arc<Metrics>,
}

impl KeyCache {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            verified: Cache::builder()
                .max_capacity(MAX_KEYS)
                .time_to_live(STALE_FOR)
                .build(),
            unknown: Cache::builder()
                .max_capacity(MAX_KEYS)
                .time_to_live(UNKNOWN_FOR)
                .build(),
            flights: Cache::builder().max_capacity(MAX_KEYS).build(),
            slots: Semaphore::new(LOOKUP_SLOTS),
            skip_db_until: Mutex::new(None),
            sources: Cache::builder()
                .max_capacity(MAX_SOURCES)
                .time_to_idle(FAILURE_WINDOW)
                .build(),
            metrics,
        }
    }

    /// Count a refusal of a login and give the cause it is answered with.
    fn refused(&self, reason: &str) -> Cause {
        self.metrics
            .auth_failures_total
            .with_label_values(&[reason])
            .inc();
        Cause::AuthRequired
    }

    /// What the limiter keeps of `source`, created at its first use.
    async fn source(&self, source: IpAddr) -> Arc<Source> {
        self.sources
            .get_with(source, async {
                Arc::new(Source {
                    windows: Mutex::new(std::array::from_fn(|_| Window::new())),
                    turn: tokio::sync::Mutex::new(()),
                })
            })
            .await
    }

    /// True when `source` caused [`FAILURES_PER_WINDOW`] unknown-key lookups
    /// in the current window of the bucket of `hash`.
    async fn source_limited(&self, source: IpAddr, hash: &[u8; 32]) -> bool {
        let Some(source) = self.sources.get(&source).await else {
            return false;
        };
        let windows = source.windows.lock();
        let window = &windows[bucket(hash)];
        window.count >= FAILURES_PER_WINDOW && window.start.elapsed() < FAILURE_WINDOW
    }

    /// Charge `source` one lookup that ended "unknown" in the bucket of
    /// `hash`, starting a new window when the last one ended.
    async fn charge(&self, source: IpAddr, hash: &[u8; 32]) {
        let source = self.source(source).await;
        let mut windows = source.windows.lock();
        let window = &mut windows[bucket(hash)];
        if window.start.elapsed() >= FAILURE_WINDOW {
            *window = Window::new();
        }
        window.count += 1;
    }

    fn db_backing_off(&self) -> bool {
        matches!(*self.skip_db_until.lock(), Some(until) if Instant::now() < until)
    }

    /// The org of `key`, tried by `source`. `lookup` asks Postgres; it is
    /// called at most once, and not at all when another caller already asks
    /// about the same key or `source` is limited and the key unverified.
    pub(crate) async fn resolve<F, Fut>(
        &self,
        source: IpAddr,
        key: &str,
        lookup: F,
    ) -> Result<OrgId, Cause>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = store::Result<KeyStatus>>,
    {
        let hash = store::hash_org_key(key);
        let cached = self.verified.get(&hash).await;
        if let Some(v) = &cached
            && v.at.elapsed() < FRESH_FOR
        {
            return Ok(v.org.clone());
        }
        if let Some(at) = self.unknown.get(&hash).await
            && at.elapsed() < UNKNOWN_FOR
        {
            return Err(self.refused("unknown_key"));
        }
        if cached.is_none() && self.source_limited(source, &hash).await {
            return Err(self.refused("source_limited"));
        }
        let stale = || cached.as_ref().map(|v| v.org.clone());
        if self.db_backing_off() {
            return stale().ok_or(Cause::CacheUnavailable);
        }
        let answer = self
            .flights
            .try_get_with(hash, self.ask(source, hash, cached.is_none(), lookup))
            .await;
        self.flights.invalidate(&hash).await;
        match answer {
            Ok(KeyStatus::Enabled(org)) => Ok(org),
            Ok(KeyStatus::Disabled) => Err(Cause::OrgDisabled),
            Ok(KeyStatus::Unknown) => Err(self.refused("unknown_key")),
            Err(e) if matches!(*e, Unanswered::SourceLimited) => {
                Err(self.refused("source_limited"))
            }
            Err(_) => stale().ok_or(Cause::CacheUnavailable),
        }
    }

    /// Run the lookup of one flight and record what it found. Only the caller
    /// that leads the flight gets here. With `queue` (the key is not
    /// verified) it first waits for its source's turn and reads the limit
    /// then, so a burst cannot get more than [`FAILURES_PER_WINDOW`] lookups
    /// through however slow they are, and a valid key waits
    /// instead of being refused. Only an "unknown" answer charges
    /// the source; a key that was verified once is not limited.
    async fn ask<F, Fut>(
        &self,
        source: IpAddr,
        hash: [u8; 32],
        queue: bool,
        lookup: F,
    ) -> Result<KeyStatus, Unanswered>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = store::Result<KeyStatus>>,
    {
        let state = self.source(source).await;
        let _turn = if queue {
            let Ok(turn) = timeout(TURN_TIMEOUT, state.turn.lock()).await else {
                return Err(Unanswered::Busy);
            };
            if self.source_limited(source, &hash).await {
                return Err(Unanswered::SourceLimited);
            }
            Some(turn)
        } else {
            None
        };
        let started = AtomicBool::new(false);
        let work = async {
            let _slot = self.slots.acquire().await;
            started.store(true, Ordering::Relaxed);
            lookup().await
        };
        let failure = match timeout(LOOKUP_TIMEOUT, work).await {
            Ok(Ok(status)) => {
                self.remember(hash, &status).await;
                if matches!(status, KeyStatus::Unknown) {
                    self.charge(source, &hash).await;
                }
                return Ok(status);
            }
            Ok(Err(StoreError::Database(sqlx::Error::PoolTimedOut))) => Unanswered::PoolFull,
            Ok(Err(e)) => Unanswered::Down(e.to_string()),
            Err(_) if started.load(Ordering::Relaxed) => Unanswered::Down("timed out".to_owned()),
            Err(_) => Unanswered::Busy,
        };
        match &failure {
            Unanswered::SourceLimited => {}
            Unanswered::Busy | Unanswered::PoolFull => {
                tracing::warn!(?failure, "org key lookup found Postgres saturated");
            }
            Unanswered::Down(error) => {
                tracing::warn!(%error, "org key lookup failed");
                *self.skip_db_until.lock() = Some(Instant::now() + DB_BACKOFF);
            }
        }
        Err(failure)
    }

    /// Postgres answered: end any backoff and update what is known of the key.
    async fn remember(&self, hash: [u8; 32], status: &KeyStatus) {
        *self.skip_db_until.lock() = None;
        match status {
            KeyStatus::Enabled(org) => {
                self.unknown.invalidate(&hash).await;
                self.verified
                    .insert(
                        hash,
                        Verified {
                            org: org.clone(),
                            at: Instant::now(),
                        },
                    )
                    .await;
            }
            KeyStatus::Disabled => self.verified.invalidate(&hash).await,
            KeyStatus::Unknown => {
                self.verified.invalidate(&hash).await;
                self.unknown.insert(hash, Instant::now()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use store::StoreError;
    use tokio::task::JoinSet;

    use super::*;

    type Answer = Result<OrgId, Cause>;
    /// What a lookup finds in Postgres.
    type Found = fn() -> store::Result<KeyStatus>;

    fn org(s: &str) -> OrgId {
        s.parse().expect("org id")
    }

    const SRC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

    /// The `i`th other source.
    fn source(i: u32) -> IpAddr {
        IpAddr::from([10, 1, (i >> 8) as u8, i as u8])
    }

    fn cache() -> KeyCache {
        KeyCache::new(Arc::new(Metrics::new("test")))
    }

    /// A lookup that counts its calls and answers with `answer`.
    fn lookup(
        calls: &AtomicUsize,
        answer: Found,
    ) -> impl FnOnce() -> std::future::Ready<store::Result<KeyStatus>> + '_ {
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(answer())
        }
    }

    /// Resolve `key` from [`SRC`] with a counting lookup.
    async fn ask(cache: &KeyCache, calls: &AtomicUsize, key: &str, answer: Found) -> Answer {
        cache.resolve(SRC, key, lookup(calls, answer)).await
    }

    fn enabled() -> store::Result<KeyStatus> {
        Ok(KeyStatus::Enabled(org("acme")))
    }

    fn disabled() -> store::Result<KeyStatus> {
        Ok(KeyStatus::Disabled)
    }

    fn unknown() -> store::Result<KeyStatus> {
        Ok(KeyStatus::Unknown)
    }

    fn down() -> store::Result<KeyStatus> {
        Err(StoreError::Invalid("postgres is down".into()))
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_key_skips_postgres_and_stale_key_is_checked_again() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        assert_eq!(ask(&cache, &calls, "k1", enabled).await, Ok(org("acme")));
        assert_eq!(ask(&cache, &calls, "k1", enabled).await, Ok(org("acme")));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call is served from memory"
        );

        tokio::time::advance(FRESH_FOR + Duration::from_secs(1)).await;
        assert_eq!(ask(&cache, &calls, "k1", enabled).await, Ok(org("acme")));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn postgres_outage_serves_the_stale_key_and_refuses_an_unknown_one() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        ask(&cache, &calls, "known", enabled)
            .await
            .expect("verified");
        tokio::time::advance(FRESH_FOR + Duration::from_secs(1)).await;

        assert_eq!(ask(&cache, &calls, "known", down).await, Ok(org("acme")));
        assert_eq!(
            ask(&cache, &calls, "unknown", down).await,
            Err(Cause::CacheUnavailable)
        );
        // Postgres is skipped while it backs off: no new lookups.
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(ask(&cache, &calls, "known", down).await, Ok(org("acme")));
        assert_eq!(calls.load(Ordering::SeqCst), before);

        tokio::time::advance(DB_BACKOFF + Duration::from_secs(1)).await;
        assert_eq!(ask(&cache, &calls, "known", down).await, Ok(org("acme")));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "asked again after the backoff"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_key_is_refused_at_once_even_when_it_was_cached() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        ask(&cache, &calls, "k", enabled).await.expect("verified");
        tokio::time::advance(FRESH_FOR + Duration::from_secs(1)).await;
        assert_eq!(
            ask(&cache, &calls, "k", disabled).await,
            Err(Cause::OrgDisabled)
        );
        // and a later outage does not bring the key back from the stale entry
        assert_eq!(
            ask(&cache, &calls, "k", down).await,
            Err(Cause::CacheUnavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_postgres_is_cut_off_at_the_lookup_timeout() {
        let cache = cache();
        let slow = || async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            enabled()
        };
        assert_eq!(
            cache.resolve(SRC, "k", slow).await,
            Err(Cause::CacheUnavailable)
        );
    }

    /// Resolve `key` on its own task with a lookup that takes `took`, counts
    /// its calls and answers with `answer`.
    fn spawn_resolve(
        set: &mut JoinSet<Answer>,
        cache: &Arc<KeyCache>,
        calls: &Arc<AtomicUsize>,
        source: IpAddr,
        key: String,
        took: Duration,
        answer: Found,
    ) {
        let (cache, calls) = (Arc::clone(cache), Arc::clone(calls));
        set.spawn(async move {
            cache
                .resolve(source, &key, || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(took).await;
                    answer()
                })
                .await
        });
    }

    /// Wait for every task of `set`; each must have answered `expected`.
    async fn drain(set: &mut JoinSet<Answer>, expected: Answer) {
        while let Some(answer) = set.join_next().await {
            assert_eq!(answer.expect("task"), expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_lookups_of_one_key_share_one_postgres_query() {
        let cache = Arc::new(cache());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        let burst = |set: &mut JoinSet<Answer>| {
            for _ in 0..500 {
                let took = Duration::from_millis(50);
                spawn_resolve(set, &cache, &calls, SRC, "k".to_owned(), took, enabled);
            }
        };
        burst(&mut set);
        drain(&mut set, Ok(org("acme"))).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // a stale entry is refreshed once as well, not once per caller
        tokio::time::advance(FRESH_FOR + Duration::from_secs(1)).await;
        burst(&mut set);
        drain(&mut set, Ok(org("acme"))).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_key_costs_one_postgres_query_per_window() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        for _ in 0..20 {
            assert_eq!(
                ask(&cache, &calls, "bad", unknown).await,
                Err(Cause::AuthRequired)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(UNKNOWN_FOR + Duration::from_secs(1)).await;
        assert_eq!(
            ask(&cache, &calls, "bad", unknown).await,
            Err(Cause::AuthRequired)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "asked again after the window"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_registered_after_it_was_refused_works_once_the_window_ends() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        assert_eq!(
            ask(&cache, &calls, "new", unknown).await,
            Err(Cause::AuthRequired)
        );
        tokio::time::advance(UNKNOWN_FOR + Duration::from_secs(1)).await;
        assert_eq!(ask(&cache, &calls, "new", enabled).await, Ok(org("acme")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_valid_new_key_authenticates_during_a_wrong_key_flood() {
        let cache = Arc::new(cache());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut flood = JoinSet::new();
        let wrong_keys = |flood: &mut JoinSet<Answer>| {
            for i in 0..1000 {
                let took = Duration::from_millis(1);
                let key = format!("bad{i}");
                spawn_resolve(flood, &cache, &calls, source(i), key, took, unknown);
            }
        };
        wrong_keys(&mut flood);
        let mut valid = JoinSet::new();
        let valid_calls = Arc::new(AtomicUsize::new(0));
        spawn_resolve(
            &mut valid,
            &cache,
            &valid_calls,
            SRC,
            "good".to_owned(),
            Duration::from_millis(1),
            enabled,
        );
        drain(&mut valid, Ok(org("acme"))).await;
        drain(&mut flood, Err(Cause::AuthRequired)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1000);

        // the same wrong keys again are refused from memory
        wrong_keys(&mut flood);
        drain(&mut flood, Err(Cause::AuthRequired)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1000);
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_pool_does_not_make_uncached_keys_unavailable() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        let pool_full = || Err(StoreError::Database(sqlx::Error::PoolTimedOut));
        assert_eq!(
            ask(&cache, &calls, "bad", pool_full).await,
            Err(Cause::CacheUnavailable)
        );
        // Postgres was never slow or down, so the next key is looked up
        assert_eq!(ask(&cache, &calls, "good", enabled).await, Ok(org("acme")));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_finds_no_free_slot_starts_no_backoff() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        let held = cache
            .slots
            .acquire_many(LOOKUP_SLOTS as u32)
            .await
            .expect("slots");
        assert_eq!(
            ask(&cache, &calls, "late", enabled).await,
            Err(Cause::CacheUnavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "Postgres was not asked");
        assert!(
            !cache.db_backing_off(),
            "the wait says nothing about Postgres"
        );

        drop(held);
        assert_eq!(ask(&cache, &calls, "good", enabled).await, Ok(org("acme")));
    }

    /// Resolve `n` distinct wrong keys of bucket 0 from `from`, each refused
    /// with `407`.
    async fn scan(cache: &KeyCache, from: IpAddr, calls: &AtomicUsize, tag: &str, n: u32) {
        scan_in(cache, from, calls, 0, tag, n).await;
    }

    async fn scan_in(
        cache: &KeyCache,
        from: IpAddr,
        calls: &AtomicUsize,
        bucket: usize,
        tag: &str,
        n: u32,
    ) {
        for key in keys_in_bucket(bucket, tag, n as usize) {
            let answer = cache.resolve(from, &key, lookup(calls, unknown)).await;
            assert_eq!(answer, Err(Cause::AuthRequired));
        }
    }

    fn failures(cache: &KeyCache, reason: &str) -> u64 {
        cache
            .metrics
            .auth_failures_total
            .with_label_values(&[reason])
            .get()
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_cycling_wrong_keys_is_cut_off_from_postgres() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        scan(&cache, SRC, &calls, "bad", FAILURES_PER_WINDOW).await;
        assert_eq!(calls.load(Ordering::SeqCst), FAILURES_PER_WINDOW as usize);
        assert_eq!(
            failures(&cache, "unknown_key"),
            u64::from(FAILURES_PER_WINDOW)
        );

        // 1000 more distinct keys: refused without a single lookup
        scan(&cache, SRC, &calls, "more", 1000).await;
        assert_eq!(calls.load(Ordering::SeqCst), FAILURES_PER_WINDOW as usize);
        assert_eq!(failures(&cache, "source_limited"), 1000);

        // another source is not touched
        scan(&cache, source(7), &calls, "other", 1).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            FAILURES_PER_WINDOW as usize + 1
        );

        // the window ends and the source may look up again
        tokio::time::advance(FAILURE_WINDOW + Duration::from_secs(1)).await;
        scan(&cache, SRC, &calls, "after", 1).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            FAILURES_PER_WINDOW as usize + 2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_limited_source_keeps_every_key_with_a_verified_entry() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        ask(&cache, &calls, "good", enabled)
            .await
            .expect("verified");
        scan(&cache, SRC, &calls, "bad", FAILURES_PER_WINDOW + 5).await;
        let before = calls.load(Ordering::SeqCst);
        assert!(
            failures(&cache, "source_limited") > 0,
            "the source is limited"
        );

        // fresh: answered from memory, no lookup, limit not read
        assert_eq!(ask(&cache, &calls, "good", enabled).await, Ok(org("acme")));
        // stale: looked up again although the source is limited
        tokio::time::advance(FRESH_FOR + Duration::from_secs(1)).await;
        assert_eq!(ask(&cache, &calls, "good", enabled).await, Ok(org("acme")));
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);
        // and the valid lookups did not charge the source: still limited, but
        // no worse than the window it started
        assert_eq!(
            failures(&cache, "unknown_key"),
            u64::from(FAILURES_PER_WINDOW)
        );
    }

    /// The wrong keys one org saves make its the session proxy pod fail
    /// lookups in some buckets. The source is limited for the keys of those
    /// buckets only: the first verification of a key of another bucket still
    /// goes through, and so does every key once the window ends.
    #[tokio::test(start_paused = true)]
    async fn wrong_keys_of_one_bucket_do_not_stop_the_first_verification_of_other_keys() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        scan(&cache, SRC, &calls, "bad", FAILURES_PER_WINDOW).await;
        scan(&cache, SRC, &calls, "more", 5).await;
        assert_eq!(failures(&cache, "source_limited"), 5, "bucket 0 is limited");

        // a valid key of another bucket is looked up and authenticates
        let other = keys_in_bucket(1, "good", 1).remove(0);
        assert_eq!(ask(&cache, &calls, &other, enabled).await, Ok(org("acme")));
        // while a new key of the limited bucket is refused without a lookup
        let before = calls.load(Ordering::SeqCst);
        let same = keys_in_bucket(0, "late", 1).remove(0);
        assert_eq!(
            ask(&cache, &calls, &same, enabled).await,
            Err(Cause::AuthRequired)
        );
        assert_eq!(calls.load(Ordering::SeqCst), before);

        // using up every other bucket as well limits the source for all keys
        for b in 1..BUCKETS {
            scan_in(&cache, SRC, &calls, b, "fill", FAILURES_PER_WINDOW).await;
        }
        let fresh = keys_in_bucket(2, "fresh", 1).remove(0);
        assert_eq!(
            ask(&cache, &calls, &fresh, enabled).await,
            Err(Cause::AuthRequired)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_unknown_answers_to_the_caller_that_ran_the_lookup_are_charged() {
        let cache = Arc::new(cache());
        let calls = Arc::new(AtomicUsize::new(0));

        // a disabled org costs the source nothing
        for i in 0..FAILURES_PER_WINDOW * 2 {
            let key = format!("disabled{i}");
            assert_eq!(
                cache.resolve(SRC, &key, || async { disabled() }).await,
                Err(Cause::OrgDisabled)
            );
        }
        for b in 0..BUCKETS {
            let probe = keys_in_bucket(b, "probe", 1).remove(0);
            assert!(
                !cache
                    .source_limited(SRC, &store::hash_org_key(&probe))
                    .await
            );
        }

        // 100 sources ask about the same wrong key at once: one lookup, one
        // charge, to the source that led it
        let mut set = JoinSet::new();
        for i in 0..100 {
            let took = Duration::from_millis(50);
            spawn_resolve(
                &mut set,
                &cache,
                &calls,
                source(i),
                "shared".to_owned(),
                took,
                unknown,
            );
        }
        drain(&mut set, Err(Cause::AuthRequired)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut charged = 0;
        for i in 0..100 {
            charged += usize::from(cache.sources.get(&source(i)).await.is_some());
        }
        assert_eq!(charged, 1, "only the leader is charged");
    }

    /// N.7: the limit is taken before the lookup, so a burst of
    /// concurrent wrong keys from one source gets no more lookups than the
    /// window allows, however slow the lookups are.
    #[tokio::test(start_paused = true)]
    async fn a_concurrent_burst_from_one_source_gets_only_its_lookups() {
        let cache = Arc::new(cache());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        for key in keys_in_bucket(0, "burst", 1000) {
            let took = Duration::from_millis(50);
            spawn_resolve(&mut set, &cache, &calls, SRC, key, took, unknown);
        }
        drain(&mut set, Err(Cause::AuthRequired)).await;
        assert_eq!(calls.load(Ordering::SeqCst), FAILURES_PER_WINDOW as usize);
        assert_eq!(
            failures(&cache, "unknown_key"),
            u64::from(FAILURES_PER_WINDOW)
        );
        assert_eq!(
            failures(&cache, "source_limited"),
            1000 - u64::from(FAILURES_PER_WINDOW)
        );
    }

    /// Valid keys are never refused by the per-source limit,
    /// however many of them one source tries at once (a session proxy pod restarting
    /// with many orgs): they wait for their turn.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_valid_unseen_keys_from_one_source_is_all_served() {
        let cache = Arc::new(cache());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        for i in 0..100 {
            let (key, took) = (format!("fresh{i}"), Duration::from_millis(5));
            spawn_resolve(&mut set, &cache, &calls, SRC, key, took, enabled);
        }
        drain(&mut set, Ok(org("acme"))).await;
        assert_eq!(calls.load(Ordering::SeqCst), 100);
        assert_eq!(failures(&cache, "source_limited"), 0);
    }

    /// Only wrong keys use up the source's lookups: a key that exists (or no
    /// answer) is not charged.
    #[tokio::test(start_paused = true)]
    async fn lookups_of_real_keys_do_not_use_up_the_failure_budget() {
        let cache = cache();
        let calls = AtomicUsize::new(0);
        for i in 0..FAILURES_PER_WINDOW * 3 {
            let key = format!("real{i}");
            assert_eq!(ask(&cache, &calls, &key, enabled).await, Ok(org("acme")));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            FAILURES_PER_WINDOW as usize * 3
        );
        assert_eq!(failures(&cache, "source_limited"), 0);
    }

    #[tokio::test]
    async fn the_table_of_sources_stays_within_its_bound() {
        let cache = cache();
        for i in 0..MAX_SOURCES as u32 * 2 {
            cache.charge(IpAddr::from(i.to_be_bytes()), &[0; 32]).await;
        }
        cache.sources.run_pending_tasks().await;
        assert!(cache.sources.entry_count() <= MAX_SOURCES);
    }
}
