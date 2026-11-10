use limiter_core::{BucketResult, TokenBucket};

#[derive(Clone, Copy)]
struct ReferenceBucket {
    capacity: u64,
    refill_rate: u64,
    tokens: u64,
    last_refill_ns: u64,
}

impl ReferenceBucket {
    fn new(capacity: u64, refill_rate: u64, tokens: u64, now_ns: u64) -> Self {
        Self {
            capacity,
            refill_rate,
            tokens: tokens.min(capacity),
            last_refill_ns: now_ns,
        }
    }

    fn refill(&mut self, now_ns: u64) {
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
        let added = (self.refill_rate as u128 * elapsed_ns as u128) / 1_000_000_000_u128;
        self.tokens = (self.tokens as u128 + added)
            .min(self.capacity as u128)
            .min(u64::MAX as u128) as u64;
        self.last_refill_ns = now_ns;
    }

    fn consume(&mut self, amount: u64, now_ns: u64) -> BucketResult {
        self.refill(now_ns);
        if self.tokens >= amount {
            self.tokens -= amount;
            BucketResult {
                ok: true,
                allowed: true,
                remaining: self.tokens,
                retry_after_ns: 0,
            }
        } else {
            let missing = amount - self.tokens;
            let retry_after_ns = if self.refill_rate == 0 {
                u64::MAX
            } else {
                ((missing as u128 * 1_000_000_000_u128) / self.refill_rate as u128)
                    .min(u64::MAX as u128) as u64
            };
            BucketResult {
                ok: true,
                allowed: false,
                remaining: self.tokens,
                retry_after_ns,
            }
        }
    }

    fn update(
        &mut self,
        now_ns: u64,
        capacity: Option<u64>,
        refill_rate: Option<u64>,
    ) -> BucketResult {
        self.refill(now_ns);
        if let Some(capacity) = capacity {
            self.capacity = capacity;
            self.tokens = self.tokens.min(capacity);
        }
        if let Some(refill_rate) = refill_rate {
            self.refill_rate = refill_rate;
        }
        BucketResult {
            ok: true,
            allowed: true,
            remaining: self.tokens,
            retry_after_ns: 0,
        }
    }
}

enum Op {
    Consume {
        amount: u64,
        now_ns: u64,
    },
    Update {
        now_ns: u64,
        capacity: Option<u64>,
        refill_rate: Option<u64>,
    },
}

#[test]
fn deterministic_trace_matches_reference() {
    let bucket = TokenBucket::new(1_000_000, 100_000, 250_000, 1_000_000_000);
    let mut reference = ReferenceBucket::new(1_000_000, 100_000, 250_000, 1_000_000_000);
    let trace = [
        Op::Consume {
            amount: 40_000,
            now_ns: 1_000_000_000,
        },
        Op::Consume {
            amount: 250_000,
            now_ns: 1_500_000_000,
        },
        Op::Consume {
            amount: 20_000,
            now_ns: 1_400_000_000,
        },
        Op::Update {
            now_ns: 2_000_000_000,
            capacity: Some(100_000),
            refill_rate: None,
        },
        Op::Consume {
            amount: 120_000,
            now_ns: 2_100_000_000,
        },
        Op::Update {
            now_ns: 2_500_000_000,
            capacity: Some(900_000),
            refill_rate: Some(300_000),
        },
        Op::Consume {
            amount: 175_000,
            now_ns: 3_500_000_000,
        },
        Op::Update {
            now_ns: 3_600_000_000,
            capacity: None,
            refill_rate: Some(0),
        },
        Op::Consume {
            amount: 1_000_000,
            now_ns: 3_700_000_000,
        },
    ];

    for op in trace {
        let actual = match op {
            Op::Consume { amount, now_ns } => bucket.consume(amount, now_ns),
            Op::Update {
                now_ns,
                capacity,
                refill_rate,
            } => bucket.update(now_ns, capacity, refill_rate),
        };
        let expected = match op {
            Op::Consume { amount, now_ns } => reference.consume(amount, now_ns),
            Op::Update {
                now_ns,
                capacity,
                refill_rate,
            } => reference.update(now_ns, capacity, refill_rate),
        };
        assert_eq!(actual, expected);
    }

    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.capacity, reference.capacity);
    assert_eq!(snapshot.refill_rate, reference.refill_rate);
    assert_eq!(snapshot.tokens, reference.tokens);
    assert_eq!(snapshot.last_refill_ns, reference.last_refill_ns);
}

#[test]
fn generated_trace_matches_reference() {
    let bucket = TokenBucket::new(3_000_000, 777_777, 1_234_567, 123);
    let mut reference = ReferenceBucket::new(3_000_000, 777_777, 1_234_567, 123);
    let mut seed = 0x0123_4567_89ab_cdef_u64;
    let mut now_ns = 123_u64;

    for step in 0..2_000 {
        seed = seed
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        now_ns = if step % 37 == 0 {
            now_ns.saturating_sub(seed % 10_000)
        } else {
            now_ns.wrapping_add(seed % 2_000_000)
        };

        let actual;
        let expected;
        if step % 29 == 0 {
            let capacity = if step % 58 == 0 {
                Some(500_000 + (seed % 4_000_000))
            } else {
                None
            };
            let refill_rate = if step % 87 == 0 {
                Some(seed % 2_000_000)
            } else {
                None
            };
            actual = bucket.update(now_ns, capacity, refill_rate);
            expected = reference.update(now_ns, capacity, refill_rate);
        } else {
            let amount = 1 + (seed % 25_000);
            actual = bucket.consume(amount, now_ns);
            expected = reference.consume(amount, now_ns);
        }
        assert_eq!(actual, expected, "step {step}");
    }
}
