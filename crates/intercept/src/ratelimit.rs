//! Rate limiting for proxied exchanges. Two backends behind the `RateLimiter`
//! trait: a Redis Lua token bucket and the limiter rate-limit service.
use common::types::RateLimitSettings;

use anyhow::Result;
use moka::sync::Cache;
use redis::Script;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Counter incremented every time a Redis-backed refill fails.
/// Exposed for observability — read with `redis_error_count()`.
static REDIS_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
/// Returns the cumulative count of Redis errors during rate-limit refills.
pub fn redis_error_count() -> u64 {
    REDIS_ERROR_COUNT.load(Ordering::Relaxed)
}

const ACQUIRE_SCRIPT: &str = r#"
-- KEYS[1] = {prefix}:ratelimit:{org_id}       (token-state, volatile)
-- KEYS[2] = {prefix}:ratelimit:{org_id}:config (burst/rpm, persistent)
-- ARGV[1] = default_burst (fallback if config key absent)
-- ARGV[2] = default_rpm   (fallback if config key absent)
-- ARGV[3] = now_ms
-- ARGV[4] = requested
-- Returns: {granted, wait_ms, burst}

local state_key  = KEYS[1]
local config_key = KEYS[2]
local default_burst = tonumber(ARGV[1])
local default_rpm   = tonumber(ARGV[2])
local now_ms    = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

-- Read burst/rpm from the persistent config key (fallback to ARGV defaults).
local cfg = redis.call('HMGET', config_key, 'burst', 'rpm')
local burst = tonumber(cfg[1]) or default_burst
local rpm   = tonumber(cfg[2]) or default_rpm
local refill_rate = rpm / 60.0

-- Read token state from the volatile key.
local state = redis.call('HMGET', state_key, 'tokens', 'last_ms')
local tokens  = tonumber(state[1]) or burst
local last_ms = tonumber(state[2]) or now_ms

-- Refill based on elapsed time
local elapsed_ms = math.max(now_ms - last_ms, 0)
local refilled = elapsed_ms * refill_rate / 1000.0
tokens = math.min(tokens + refilled, burst)

-- Consume
local granted = math.min(requested, math.floor(tokens))
tokens = tokens - granted

redis.call('HMSET', state_key, 'tokens', tostring(tokens), 'last_ms', tostring(now_ms))
redis.call('EXPIRE', state_key, 3600)

local wait_ms = 0
if granted < requested and refill_rate > 0 then
    wait_ms = math.ceil((1.0 / refill_rate) * 1000)
end

return {granted, wait_ms, burst}
"#;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Default burst size when org has no custom settings
    #[serde(default = "default_burst")]
    pub default_burst: u32,
    /// Default requests per minute when org has no custom settings
    #[serde(default = "default_rpm")]
    pub default_rpm: u32,
    /// Local buffer threshold: refill from Redis when local tokens < this % of max
    #[serde(default = "default_refill_threshold")]
    pub refill_threshold_pct: f32,
    /// Maximum time to wait for a token before returning a rate-limit error.
    #[serde(default = "default_rate_limit_max_wait_ms")]
    pub rate_limit_max_wait_ms: u64,
    /// Behavior when Redis is unreachable. Default `GrantTokens(default_burst)`
    /// fails open permanently for the local org bucket after the first Redis
    /// error; `Deny` preserves fail-closed behavior.
    #[serde(default)]
    pub failopen_policy: FailOpenPolicy,
    /// Which rate-limit backend to use. Defaults to `Redis` (the historical
    /// behavior); set to `Limiter` to enforce against the limiter service.
    #[serde(default)]
    pub backend: RateLimitBackend,
    /// Address of the limiter rate-limit service (used only when
    /// `backend = Limiter`).
    #[serde(default = "default_limiter_addr")]
    pub limiter_addr: String,
    /// Connect budget of one limiter connection, in ms (`backend = Limiter`).
    #[serde(default = "default_limiter_connect_timeout_ms")]
    pub limiter_connect_timeout_ms: u64,
    /// Budget of one limiter request/response exchange, in ms.
    #[serde(default = "default_limiter_io_timeout_ms")]
    pub limiter_io_timeout_ms: u64,
    /// Idle seconds before the first TCP keepalive probe on limiter
    /// connections. 0 turns keepalive off.
    #[serde(default = "default_limiter_keepalive_secs")]
    pub limiter_keepalive_secs: u64,
    /// Consecutive limiter transport failures that open the client's
    /// breaker. 0 turns the breaker off.
    #[serde(default = "default_limiter_breaker_failures")]
    pub limiter_breaker_failures: u32,
    /// How long the limiter client's breaker stays open, in ms.
    #[serde(default = "default_limiter_breaker_open_ms")]
    pub limiter_breaker_open_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_burst: default_burst(),
            default_rpm: default_rpm(),
            refill_threshold_pct: default_refill_threshold(),
            rate_limit_max_wait_ms: default_rate_limit_max_wait_ms(),
            failopen_policy: FailOpenPolicy::default(),
            backend: RateLimitBackend::default(),
            limiter_addr: default_limiter_addr(),
            limiter_connect_timeout_ms: default_limiter_connect_timeout_ms(),
            limiter_io_timeout_ms: default_limiter_io_timeout_ms(),
            limiter_keepalive_secs: default_limiter_keepalive_secs(),
            limiter_breaker_failures: default_limiter_breaker_failures(),
            limiter_breaker_open_ms: default_limiter_breaker_open_ms(),
        }
    }
}

impl RateLimitConfig {
    /// Reject limiter transport settings that cannot work.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.limiter_connect_timeout_ms > 0,
            "ratelimit.limiter_connect_timeout_ms must be greater than 0"
        );
        anyhow::ensure!(
            self.limiter_io_timeout_ms > 0,
            "ratelimit.limiter_io_timeout_ms must be greater than 0"
        );
        anyhow::ensure!(
            self.limiter_breaker_failures == 0 || self.limiter_breaker_open_ms > 0,
            "ratelimit.limiter_breaker_open_ms must be greater than 0 while the breaker is on"
        );
        Ok(())
    }

    fn limiter_resilience(&self) -> limiter_client::ResilienceConfig {
        limiter_client::ResilienceConfig {
            connect_timeout: Duration::from_millis(self.limiter_connect_timeout_ms),
            io_timeout: Duration::from_millis(self.limiter_io_timeout_ms),
            keepalive: (self.limiter_keepalive_secs > 0)
                .then(|| Duration::from_secs(self.limiter_keepalive_secs)),
            breaker: (self.limiter_breaker_failures > 0).then(|| limiter_client::BreakerConfig {
                failure_threshold: self.limiter_breaker_failures,
                open_duration: Duration::from_millis(self.limiter_breaker_open_ms),
            }),
        }
    }
}

fn default_limiter_connect_timeout_ms() -> u64 {
    1000
}

fn default_limiter_io_timeout_ms() -> u64 {
    1000
}

fn default_limiter_keepalive_secs() -> u64 {
    30
}

fn default_limiter_breaker_failures() -> u32 {
    5
}

fn default_limiter_breaker_open_ms() -> u64 {
    2000
}

/// Policy applied when the Redis refill request fails.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum FailOpenPolicy {
    /// Reject the request, surfacing the outage to callers (429).
    Deny,
    /// Enter fail-open mode for this org after a Redis error. The value is
    /// retained for config compatibility but fail-open is no longer metered.
    GrantTokens(u32),
}

impl Default for FailOpenPolicy {
    /// Fail OPEN on a Redis outage: when the rate-limit backend is
    /// unreachable, keep serving traffic rather than rejecting it. Operators
    /// can opt back into `Deny` explicitly.
    fn default() -> Self {
        FailOpenPolicy::GrantTokens(default_burst())
    }
}

/// Selects which rate-limit backend the proxy enforces against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    /// Redis Lua token bucket (the historical default).
    #[default]
    Redis,
    /// The limiter rate-limit service.
    Limiter,
}

fn default_limiter_addr() -> String {
    "127.0.0.1:39091".to_string()
}

fn default_burst() -> u32 {
    1000
}

fn default_rpm() -> u32 {
    6000
}

fn default_refill_threshold() -> f32 {
    0.25
}
fn default_rate_limit_max_wait_ms() -> u64 {
    1000
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("timeout waiting for tokens after {0:?}")]
    Timeout(Duration),
    #[error("rejected: {reason}")]
    Rejected { reason: String },
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

pub struct RedisRateLimiter {
    redis: redis::aio::ConnectionManager,
    config: RateLimitConfig,
    buckets: Cache<String, Arc<LocalBucket>>,
    acquire_script: Script,
    redis_key_prefix: String,
}

struct LocalBucket {
    tokens: AtomicU32,
    max_tokens: AtomicU32,
    requesting: AtomicBool,
    fail_open: AtomicBool,
}

impl LocalBucket {
    /// Starts empty. A fresh bucket must earn its allowance from the Redis
    /// refill before granting anything; seeding it full would hand every
    /// proxy pod `max_tokens` unearned grants per org (and again after each
    /// idle eviction), multiplying the fleet-wide limit by the pod count.
    fn new(max_tokens: u32) -> Self {
        Self {
            tokens: AtomicU32::new(0),
            max_tokens: AtomicU32::new(max_tokens),
            requesting: AtomicBool::new(false),
            fail_open: AtomicBool::new(false),
        }
    }

    fn try_consume(&self, requested: u32) -> Option<u32> {
        let mut current = self.tokens.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return None;
            }
            let granted = requested.min(current);
            let new_value = current - granted;

            match self.tokens.compare_exchange_weak(
                current,
                new_value,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(granted),
                Err(actual) => current = actual,
            }
        }
    }

    fn add_tokens(&self, count: u32) {
        let max = self.max_tokens.load(Ordering::Relaxed);
        let mut current = self.tokens.load(Ordering::Acquire);
        loop {
            let new_value = current.saturating_add(count).min(max);
            match self.tokens.compare_exchange_weak(
                current,
                new_value,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    fn below_threshold(&self, threshold_pct: f32) -> bool {
        let current = self.tokens.load(Ordering::Relaxed);
        let max = self.max_tokens.load(Ordering::Relaxed);
        let threshold = (max as f32 * threshold_pct) as u32;
        current < threshold
    }

    fn update_max(&self, new_max: u32) {
        self.max_tokens.store(new_max, Ordering::Release);
    }

    fn is_fail_open(&self) -> bool {
        self.fail_open.load(Ordering::Acquire)
    }

    fn open(&self) {
        self.fail_open.store(true, Ordering::Release);
    }
}

impl RedisRateLimiter {
    pub fn from_conn(
        redis: redis::aio::ConnectionManager,
        config: RateLimitConfig,
        redis_key_prefix: String,
    ) -> Self {
        let acquire_script = Script::new(ACQUIRE_SCRIPT);
        Self {
            redis,
            config,
            buckets: Cache::builder()
                .max_capacity(50_000)
                .time_to_idle(Duration::from_secs(1800))
                .build(),
            acquire_script,
            redis_key_prefix,
        }
    }

    pub async fn acquire(&self, org_id: &str) -> Result<Duration, RateLimitError> {
        let bucket = self.get_or_create_bucket(org_id, self.config.default_burst);

        let timeout = Duration::from_millis(self.config.rate_limit_max_wait_ms);
        let start = Instant::now();

        loop {
            if bucket.is_fail_open() {
                debug!(org_id, "rate limiter is fail-open");
                common::metrics::PROXY_RATELIMIT_FAILOPEN_TOTAL
                    .with_label_values(&["redis"])
                    .inc();
                return Ok(Duration::ZERO);
            }
            // Try local consumption first
            if let Some(granted) = bucket.try_consume(1)
                && granted > 0
            {
                debug!(org_id, "acquired token from local bucket");
                return Ok(Duration::ZERO);
            }

            // Check timeout
            if start.elapsed() >= timeout {
                return Err(RateLimitError::Timeout(timeout));
            }

            // Check if we should refill from Redis
            if bucket.below_threshold(self.config.refill_threshold_pct)
                || bucket.tokens.load(Ordering::Relaxed) == 0
            {
                // Try to acquire the refill lock
                if bucket
                    .requesting
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    // We got the lock, do the refill
                    let refill_result = self.refill_from_redis(org_id, &bucket).await;
                    bucket.requesting.store(false, Ordering::Release);

                    match refill_result {
                        Ok(wait_ms) => {
                            debug!(org_id, wait_ms, "refilled from redis");
                            if wait_ms > 0 {
                                // Sleep for the time the Lua script says tokens
                                // will next be available, clamped to [1ms, remaining budget].
                                let remaining = timeout.saturating_sub(start.elapsed());
                                let sleep_dur = Duration::from_millis(wait_ms as u64)
                                    .max(Duration::from_millis(1))
                                    .min(remaining);
                                tokio::time::sleep(sleep_dur).await;
                            }
                            continue;
                        }
                        Err(e) => {
                            REDIS_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                            common::metrics::PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL
                                .with_label_values(&["redis"])
                                .inc();
                            warn!(
                                org_id,
                                error = %e,
                                policy = ?self.config.failopen_policy,
                                "redis error during rate limit check"
                            );
                            match self.config.failopen_policy {
                                FailOpenPolicy::Deny => {
                                    return Err(RateLimitError::Rejected {
                                        reason: "rate limit backend unreachable".to_string(),
                                    });
                                }
                                FailOpenPolicy::GrantTokens(_) => {
                                    bucket.open();
                                    common::metrics::PROXY_RATELIMIT_FAILOPEN_TOTAL
                                        .with_label_values(&["redis"])
                                        .inc();
                                    return Ok(Duration::ZERO);
                                }
                            }
                        }
                    }
                }
            }

            // Sleep a small amount before retry (fallback when not refilling).
            let remaining = timeout.saturating_sub(start.elapsed());
            let wait = Duration::from_millis(1).min(remaining);
            tokio::time::sleep(wait).await;

            // Check timeout again
            if start.elapsed() >= timeout {
                return Err(RateLimitError::Timeout(timeout));
            }
        }
    }

    fn get_or_create_bucket(&self, org_id: &str, max: u32) -> Arc<LocalBucket> {
        self.buckets.get_with(org_id.to_string(), || {
            debug!(org_id, max, "creating new local bucket");
            Arc::new(LocalBucket::new(max))
        })
    }

    async fn refill_from_redis(
        &self,
        org_id: &str,
        bucket: &LocalBucket,
    ) -> Result<u32, RateLimitError> {
        let state_key = format!("{}:ratelimit:{}", self.redis_key_prefix, org_id);
        let config_key = format!("{}:ratelimit:{}:config", self.redis_key_prefix, org_id);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Batch size follows the bucket's current cap: it starts at the default
        // burst and, once the first refill learns the org's real burst, scales
        // to half of it. Half keeps round-trips infrequent without letting one
        // pod drain the whole distributed allowance in a single call.
        let request_count = (bucket.max_tokens.load(Ordering::Relaxed) / 2).max(1);

        // ConnectionManager reconnects in the background, so a broken pipe on an
        // idle-reaped connection clears on the next call. Retry once before
        // surfacing the error (which would otherwise trip the fail-open policy).
        let mut last_err: Option<redis::RedisError> = None;
        for _ in 0..2 {
            let mut conn = self.redis.clone();
            let result: Result<(i64, i64, i64), redis::RedisError> = self
                .acquire_script
                .key(&state_key)
                .key(&config_key)
                .arg(self.config.default_burst)
                .arg(self.config.default_rpm)
                .arg(now_ms)
                .arg(request_count)
                .invoke_async(&mut conn)
                .await;

            match result {
                Ok((granted, wait_ms, burst)) => {
                    // Size the local cap to the org's effective burst (clamped to
                    // u32) so a high configured limit isn't throttled down to the
                    // default. Fall back to the default when no config is present.
                    let effective_burst = if burst > 0 {
                        burst.min(u32::MAX as i64) as u32
                    } else {
                        self.config.default_burst
                    };
                    bucket.update_max(effective_burst);
                    if granted > 0 {
                        bucket.add_tokens(granted as u32);
                    }
                    return Ok(wait_ms as u32);
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err
            .expect("loop sets last_err on every failed attempt")
            .into())
    }
}

/// Micro-token scale: one logical request costs `TOKEN_SCALE` tokens, so an
/// integer per-second refill (`rpm * SCALE / 60`) preserves sub-1-rps rates.
const TOKEN_SCALE: u64 = 1000;
/// limiter client connection pool size.
const PROXYX_LIMITER_POOL_SIZE: usize = 16;
/// Idle TTL for a per-org limiter bucket. The server reaps a bucket this long
/// after its last access; the proxy refreshes it on every `consume`.
// ponytail: fixed 1h idle TTL; promote to a config knob if org churn warrants.
const PROXYX_LIMITER_BUCKET_TTL_NS: u64 = 3600 * 1_000_000_000;

/// Backend trait for org-keyed rate limiting. Implemented by the Redis and
/// limiter limiters; selected at startup via `RateLimitBackend`.
pub trait RateLimiter: Send + Sync {
    /// Acquire one token for `org_id`, waiting up to the configured budget and
    /// returning the time spent waiting. `limits` carries the session's
    /// resolved per-org settings: the limiter backend sizes the bucket from
    /// them (falling back to proxy defaults when `None`, matching the Redis
    /// Lua's "config key absent" path); the Redis backend reads its own config
    /// from Redis and ignores them.
    fn acquire<'a>(
        &'a self,
        org_id: &'a str,
        limits: Option<&'a RateLimitSettings>,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + 'a>>;
}

impl RateLimiter for RedisRateLimiter {
    fn acquire<'a>(
        &'a self,
        org_id: &'a str,
        _limits: Option<&'a RateLimitSettings>,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + 'a>> {
        // One arg disambiguates to the inherent `acquire`, not this trait method.
        Box::pin(async move { self.acquire(org_id).await })
    }
}

/// Single-tier limiter enforcing directly against the limiter service: every
/// exchange is a `consume` against a per-org server-side bucket (no local
/// pre-grant, so the fleet-wide limit is exact). Per-org buckets are cached so
/// the hot path skips the create round-trip.
pub struct ServiceRateLimiter {
    client: limiter_client::AsyncClient,
    buckets: Cache<String, CachedBucket>,
    config: RateLimitConfig,
}

/// A cached per-org limiter bucket plus the effective (scaled) limits it was
/// created with, so a settings change is detected and re-applied.
#[derive(Clone)]
struct CachedBucket {
    bucket: Arc<limiter_client::AsyncBucket>,
    capacity: u64,
    refill_rate: u64,
}

impl ServiceRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let fail_mode = match config.failopen_policy {
            FailOpenPolicy::Deny => limiter_client::FailMode::Closed,
            FailOpenPolicy::GrantTokens(_) => limiter_client::FailMode::Open,
        };
        let client = limiter_client::AsyncClient::connect_with(
            config.limiter_addr.clone(),
            limiter_client::ClientConfig {
                pool_size: PROXYX_LIMITER_POOL_SIZE,
                fail_mode,
            },
            config.limiter_resilience(),
        );
        Self {
            client,
            buckets: Cache::builder()
                .max_capacity(50_000)
                .time_to_idle(Duration::from_secs(1800))
                .build(),
            config,
        }
    }

    async fn bucket_for(
        &self,
        org_id: &str,
        limits: Option<&RateLimitSettings>,
    ) -> std::io::Result<Arc<limiter_client::AsyncBucket>> {
        // None == no per-org config (Redis "config key absent"): fall back to
        // proxy defaults. Zero fields within Some are preserved as-is (burst 0
        // denies, rpm 0 never refills), matching the Lua.
        let (burst, rpm) = match limits {
            Some(s) => (s.burst as u64, s.requests_per_minute as u64),
            None => (
                self.config.default_burst as u64,
                self.config.default_rpm as u64,
            ),
        };
        let capacity = burst.saturating_mul(TOKEN_SCALE);
        let refill_rate = rpm.saturating_mul(TOKEN_SCALE) / 60;
        // Reuse the cached bucket only when its effective limits still match;
        // a config change re-creates (create-or-update) so it takes effect
        // immediately rather than at TTI, matching the Redis config-on-refill.
        if let Some(cached) = self.buckets.get(org_id)
            && cached.capacity == capacity
            && cached.refill_rate == refill_rate
        {
            return Ok(cached.bucket);
        }
        let bucket = Arc::new(
            self.client
                .create(
                    org_id.as_bytes(),
                    limiter_client::Limits {
                        capacity,
                        refill_rate,
                        ttl_ns: PROXYX_LIMITER_BUCKET_TTL_NS,
                    },
                )
                .await?,
        );
        self.buckets.insert(
            org_id.to_string(),
            CachedBucket {
                bucket: bucket.clone(),
                capacity,
                refill_rate,
            },
        );
        Ok(bucket)
    }
}

impl RateLimiter for ServiceRateLimiter {
    fn acquire<'a>(
        &'a self,
        org_id: &'a str,
        limits: Option<&'a RateLimitSettings>,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + 'a>> {
        Box::pin(async move {
            let bucket = match self.bucket_for(org_id, limits).await {
                Ok(bucket) => bucket,
                Err(e) => {
                    // Control-plane create failed (limiter unreachable): apply
                    // the configured fail policy.
                    warn!(
                        org_id,
                        error = %e,
                        policy = ?self.config.failopen_policy,
                        "limiter bucket create failed"
                    );
                    common::metrics::PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL
                        .with_label_values(&["limiter"])
                        .inc();
                    return match self.config.failopen_policy {
                        FailOpenPolicy::Deny => Err(RateLimitError::Rejected {
                            reason: "rate limit backend unreachable".to_string(),
                        }),
                        FailOpenPolicy::GrantTokens(_) => {
                            common::metrics::PROXY_RATELIMIT_FAILOPEN_TOTAL
                                .with_label_values(&["limiter"])
                                .inc();
                            Ok(Duration::ZERO)
                        }
                    };
                }
            };

            let timeout = Duration::from_millis(self.config.rate_limit_max_wait_ms);
            let start = Instant::now();
            loop {
                let outcome = bucket.consume(TOKEN_SCALE).await;
                if outcome.degraded {
                    // Transport failure: the client answered with its fail
                    // mode instead of a verdict from the limiter.
                    common::metrics::PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL
                        .with_label_values(&["limiter"])
                        .inc();
                    if outcome.allowed {
                        common::metrics::PROXY_RATELIMIT_FAILOPEN_TOTAL
                            .with_label_values(&["limiter"])
                            .inc();
                        return Ok(start.elapsed());
                    }
                    return Err(RateLimitError::Rejected {
                        reason: "rate limit backend unreachable".to_string(),
                    });
                }
                if outcome.allowed {
                    return Ok(start.elapsed());
                }
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(RateLimitError::Timeout(timeout));
                }
                let wait = Duration::from_nanos(outcome.retry_after_ns)
                    .max(Duration::from_millis(1))
                    .min(remaining);
                tokio::time::sleep(wait).await;
            }
        })
    }
}

/// Rate limiter for individual HTTP exchanges within a MITM tunnel.
/// Trait-object safe so the MITM module doesn't depend on transport generics.
pub trait ExchangeRateLimit: Send + Sync {
    fn acquire(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + '_>>;
}

/// Binds a `RateLimiter` backend to a specific org (and its resolved limits)
/// for the duration of a tunnel.
pub struct OrgRateLimit {
    limiter: Arc<dyn RateLimiter>,
    org_id: String,
    limits: Option<RateLimitSettings>,
}

impl OrgRateLimit {
    pub fn new(
        limiter: Arc<dyn RateLimiter>,
        org_id: String,
        limits: Option<RateLimitSettings>,
    ) -> Self {
        Self {
            limiter,
            org_id,
            limits,
        }
    }
}

impl ExchangeRateLimit for OrgRateLimit {
    fn acquire(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + '_>> {
        Box::pin(async move {
            self.limiter
                .acquire(&self.org_id, self.limits.as_ref())
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_bucket_starts_empty() {
        let bucket = LocalBucket::new(100);
        assert_eq!(bucket.try_consume(1), None);
    }

    #[test]
    fn test_local_bucket_consume() {
        let bucket = LocalBucket::new(100);
        bucket.add_tokens(100);
        assert_eq!(bucket.try_consume(10), Some(10));
        assert_eq!(bucket.tokens.load(Ordering::Relaxed), 90);
    }

    #[test]
    fn test_below_threshold() {
        let bucket = LocalBucket::new(100);
        bucket.add_tokens(100);
        bucket.try_consume(80);
        assert!(bucket.below_threshold(0.25));
        assert!(!bucket.below_threshold(0.1));
    }

    #[test]
    fn test_update_max_lifts_default_cap() {
        // A bucket created at the default cap must honor a higher cap once the
        // refill learns the org's real burst — otherwise a high configured
        // limit stays throttled to the default.
        let bucket = LocalBucket::new(1000);
        bucket.update_max(50_000);
        bucket.add_tokens(40_000);
        assert_eq!(bucket.tokens.load(Ordering::Relaxed), 40_000);
    }

    #[test]
    fn test_fail_open_persists_without_tokens() {
        let bucket = LocalBucket::new(100);
        bucket.open();

        assert!(bucket.is_fail_open());
        assert_eq!(bucket.try_consume(1), None);
        assert!(bucket.is_fail_open());
    }
}
