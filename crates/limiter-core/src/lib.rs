use std::cell::UnsafeCell;
use std::hint::spin_loop;
use std::sync::atomic::{AtomicBool, Ordering};

const NANOS_PER_SECOND_U64: u64 = 1_000_000_000;
const NANOS_PER_SECOND: u128 = NANOS_PER_SECOND_U64 as u128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketResult {
    pub ok: bool,
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketSnapshot {
    pub capacity: u64,
    pub refill_rate: u64,
    pub tokens: u64,
    pub last_refill_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BucketState {
    capacity: u64,
    refill_rate: u64,
    tokens: u64,
    last_refill_ns: u64,
}

/// In-process token bucket with a compact per-bucket spin lock.
///
/// All quantities are integer microtokens except timestamps, which are integer
/// nanoseconds. Refill is intentionally floor-rounded to match the reference
/// contract exactly.
pub struct TokenBucket {
    locked: AtomicBool,
    state: UnsafeCell<BucketState>,
}

// SAFETY: every access to `state` is serialized by `locked`.
unsafe impl Send for TokenBucket {}
unsafe impl Sync for TokenBucket {}

impl TokenBucket {
    #[inline]
    pub fn new(capacity: u64, refill_rate: u64, tokens: u64, now_ns: u64) -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(BucketState {
                capacity,
                refill_rate,
                tokens: tokens.min(capacity),
                last_refill_ns: now_ns,
            }),
        }
    }

    #[inline]
    pub fn consume(&self, amount: u64, now_ns: u64) -> BucketResult {
        self.lock();
        // SAFETY: the spin lock is held until `unlock` below.
        let state = unsafe { &mut *self.state.get() };
        state.refill(now_ns);

        let result = if state.tokens >= amount {
            state.tokens -= amount;
            BucketResult {
                ok: true,
                allowed: true,
                remaining: state.tokens,
                retry_after_ns: 0,
            }
        } else {
            let retry_after_ns = retry_after_ns(amount - state.tokens, state.refill_rate);
            BucketResult {
                ok: true,
                allowed: false,
                remaining: state.tokens,
                retry_after_ns,
            }
        };

        self.unlock();
        result
    }

    #[inline]
    pub fn update(
        &self,
        now_ns: u64,
        capacity: Option<u64>,
        refill_rate: Option<u64>,
    ) -> BucketResult {
        self.lock();
        // SAFETY: the spin lock is held until `unlock` below.
        let state = unsafe { &mut *self.state.get() };
        state.refill(now_ns);

        if let Some(capacity) = capacity {
            state.capacity = capacity;
            state.tokens = state.tokens.min(capacity);
        }
        if let Some(refill_rate) = refill_rate {
            state.refill_rate = refill_rate;
        }

        let result = BucketResult {
            ok: true,
            allowed: true,
            remaining: state.tokens,
            retry_after_ns: 0,
        };

        self.unlock();
        result
    }

    #[inline]
    pub fn snapshot(&self) -> BucketSnapshot {
        self.lock();
        // SAFETY: the spin lock is held until `unlock` below.
        let state = unsafe { &*self.state.get() };
        let snapshot = BucketSnapshot {
            capacity: state.capacity,
            refill_rate: state.refill_rate,
            tokens: state.tokens,
            last_refill_ns: state.last_refill_ns,
        };

        self.unlock();
        snapshot
    }

    #[inline]
    pub fn reset(&self, capacity: u64, refill_rate: u64, tokens: u64, now_ns: u64) {
        self.lock();
        // SAFETY: the spin lock is held until `unlock` below.
        let state = unsafe { &mut *self.state.get() };
        *state = BucketState {
            capacity,
            refill_rate,
            tokens: tokens.min(capacity),
            last_refill_ns: now_ns,
        };
        self.unlock();
    }

    /// Debit up to `amount` tokens (after refill), never failing: drains
    /// `min(amount, tokens)` and returns how much was actually removed. Used for
    /// post-hoc accounting (e.g. charging variable output cost) where the caller
    /// must always record what budget remained, not gate on it.
    #[inline]
    pub fn drain(&self, amount: u64, now_ns: u64) -> u64 {
        self.lock();
        // SAFETY: the spin lock is held until `unlock` below.
        let state = unsafe { &mut *self.state.get() };
        state.refill(now_ns);
        let drained = amount.min(state.tokens);
        state.tokens -= drained;
        self.unlock();
        drained
    }

    #[inline]
    fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    #[inline]
    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl BucketState {
    #[inline]
    fn refill(&mut self, now_ns: u64) {
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);

        if self.tokens >= self.capacity {
            self.tokens = self.capacity;
        } else if elapsed_ns != 0 && self.refill_rate != 0 {
            if let Some(refill_numer) = self.refill_rate.checked_mul(elapsed_ns) {
                if refill_numer >= NANOS_PER_SECOND_U64 {
                    let missing_tokens = self.capacity - self.tokens;
                    if let Some(refill_needed) = missing_tokens.checked_mul(NANOS_PER_SECOND_U64) {
                        if refill_numer >= refill_needed {
                            self.tokens = self.capacity;
                        } else {
                            self.tokens += refill_numer / NANOS_PER_SECOND_U64;
                        }
                    } else {
                        self.tokens += refill_numer / NANOS_PER_SECOND_U64;
                    }
                }
            } else {
                let refill_numer = self.refill_rate as u128 * elapsed_ns as u128;
                let missing_tokens = self.capacity - self.tokens;
                let refill_needed = missing_tokens as u128 * NANOS_PER_SECOND;
                if refill_numer >= refill_needed {
                    self.tokens = self.capacity;
                } else {
                    self.tokens += (refill_numer / NANOS_PER_SECOND) as u64;
                }
            }
        }

        self.last_refill_ns = now_ns;
    }
}

#[inline]
fn retry_after_ns(missing_tokens: u64, refill_rate: u64) -> u64 {
    if missing_tokens == 0 {
        return 0;
    }
    if refill_rate == 0 {
        return u64::MAX;
    }
    let nanos = (missing_tokens as u128 * NANOS_PER_SECOND) / refill_rate as u128;
    nanos.min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_initial_tokens_to_capacity() {
        let bucket = TokenBucket::new(10, 1, 50, 0);
        assert_eq!(bucket.snapshot().tokens, 10);
    }

    #[test]
    fn denied_zero_refill_rate_reports_unbounded_retry() {
        let bucket = TokenBucket::new(10, 0, 3, 0);
        assert_eq!(
            bucket.consume(4, 10),
            BucketResult {
                ok: true,
                allowed: false,
                remaining: 3,
                retry_after_ns: u64::MAX,
            }
        );
    }

    #[test]
    fn drain_debits_up_to_available_and_reports_actual() {
        let bucket = TokenBucket::new(100, 0, 30, 0);
        // Drains only what's there, never below zero.
        assert_eq!(bucket.drain(50, 0), 30);
        assert_eq!(bucket.snapshot().tokens, 0);
        assert_eq!(bucket.drain(10, 0), 0);
        // Partial drain within budget.
        let bucket = TokenBucket::new(100, 0, 100, 0);
        assert_eq!(bucket.drain(40, 0), 40);
        assert_eq!(bucket.snapshot().tokens, 60);
    }
}
