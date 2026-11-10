//! Bounded recovery primitives: full-jitter backoff, a token bucket
//! and the breaker tuning. The breaker itself lives in Redis (`store`), so
//! every replica shares it. The bucket takes the current time as an argument,
//! so tests drive it without sleeping.

use std::time::{Duration, Instant};

use rand::Rng;

/// Exponential backoff with full jitter: a random wait in `[0, min(cap, base * 2^attempt)]`.
pub fn full_jitter(base: Duration, cap: Duration, attempt: u32) -> Duration {
    let ceiling = base
        .checked_mul(1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX))
        .unwrap_or(cap)
        .min(cap);
    let millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::thread_rng().gen_range(0..=millis))
}

/// Add up to `share` (0.0 to 1.0) random extra time to an interval.
pub fn jittered(interval: Duration, share: f64) -> Duration {
    let extra = interval.mul_f64(share.clamp(0.0, 1.0) * rand::thread_rng().r#gen::<f64>());
    interval + extra
}

/// A token bucket: `capacity` tokens, refilled at `per_minute`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, per_minute: u32, now: Instant) -> Self {
        Self {
            capacity: f64::from(capacity),
            per_sec: f64::from(per_minute) / 60.0,
            tokens: f64::from(capacity),
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.per_sec).min(self.capacity);
        self.last = now;
    }

    /// Whole tokens available now.
    pub fn available(&mut self, now: Instant) -> u32 {
        self.refill(now);
        // tokens is clamped to [0, capacity] and capacity came from a u32.
        self.tokens.floor() as u32
    }

    /// Take `n` tokens if available.
    pub fn try_take(&mut self, n: u32, now: Instant) -> bool {
        self.refill(now);
        let n = f64::from(n);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// Breaker state; the gauge value is the discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed = 0,
    HalfOpen = 1,
    Open = 2,
}

/// Tuning of the shared breaker (`store::Hot::breaker_*`). Defaults follow the
/// Policy: 5 failures in 60 s open it; the first
/// probe comes 5 s later and each failed probe doubles the wait up to 5 min
/// (5, 10, 20, 40, 80, 160, 300 s), so a provider that is back is found within
/// seconds, not after a 30 s first wait; 3 passes close it.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub failures_to_open: u32,
    pub window: Duration,
    pub first_probe_after: Duration,
    pub max_probe_after: Duration,
    pub passes_to_close: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failures_to_open: 5,
            window: Duration::from_secs(60),
            first_probe_after: Duration::from_secs(5),
            max_probe_after: Duration::from_secs(300),
            passes_to_close: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills_at_rate_and_caps() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(2, 60, t0);
        assert!(tb.try_take(2, t0));
        assert!(!tb.try_take(1, t0));
        assert!(tb.try_take(1, t0 + Duration::from_secs(1)));
        assert_eq!(tb.available(t0 + Duration::from_secs(100)), 2);
    }

    #[test]
    fn full_jitter_stays_under_cap() {
        for attempt in 0..40 {
            let d = full_jitter(Duration::from_secs(5), Duration::from_secs(300), attempt);
            assert!(d <= Duration::from_secs(300));
        }
    }

    #[test]
    fn the_first_probe_comes_five_seconds_after_opening_and_doubles_to_five_minutes() {
        let cfg = BreakerConfig::default();
        assert_eq!(cfg.first_probe_after, Duration::from_secs(5));
        let waits: Vec<u64> = std::iter::successors(Some(cfg.first_probe_after), |wait| {
            (*wait < cfg.max_probe_after).then(|| (*wait * 2).min(cfg.max_probe_after))
        })
        .map(|wait| wait.as_secs())
        .collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300]);
    }
}
