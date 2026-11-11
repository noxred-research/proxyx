use limiter_core::{BucketResult, TokenBucket};

#[test]
fn edge_case_trace_matrix() {
    let bucket = TokenBucket::new(10_000, 3, 0, 0);
    assert_eq!(
        bucket.consume(1, 333_333_333),
        BucketResult {
            ok: true,
            allowed: false,
            remaining: 0,
            retry_after_ns: 333_333_333
        }
    );
    assert_eq!(
        bucket.consume(1, 666_666_666),
        BucketResult {
            ok: true,
            allowed: false,
            remaining: 0,
            retry_after_ns: 333_333_333
        }
    );
    assert_eq!(
        bucket.consume(1, 1_000_000_000),
        BucketResult {
            ok: true,
            allowed: true,
            remaining: 0,
            retry_after_ns: 0
        }
    );

    let bucket = TokenBucket::new(1_000, 100, 500, 1_000_000_000);
    assert!(bucket.consume(100, 2_000_000_000).allowed);
    assert!(bucket.consume(100, 1_500_000_000).allowed);
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.last_refill_ns, 1_500_000_000);
    assert_eq!(snapshot.tokens, 400);
    assert!(bucket.consume(100, 2_500_000_000).allowed);
    assert_eq!(bucket.snapshot().tokens, 400);

    let bucket = TokenBucket::new(10_000, 1_000, 8_000, 0);
    assert_eq!(bucket.update(0, Some(5_000), None).remaining, 5_000);
    assert_eq!(bucket.consume(5_000, 0).remaining, 0);
    assert!(!bucket.consume(1, 0).allowed);

    let bucket = TokenBucket::new(100, 3, 0, 0);
    assert_eq!(bucket.consume(2, 0).retry_after_ns, 666_666_666);
}

#[test]
fn exact_balance_zero_amount_and_idle_burst() {
    let bucket = TokenBucket::new(10_000, 1_000, 5_000, 0);
    assert!(bucket.consume(0, 0).allowed);
    assert_eq!(bucket.snapshot().tokens, 5_000);
    assert!(bucket.consume(5_000, 0).allowed);
    assert_eq!(bucket.snapshot().tokens, 0);
    assert!(!bucket.consume(1, 0).allowed);

    let bucket = TokenBucket::new(10_000, 1_000, 0, 0);
    assert!(bucket.consume(1, 20_000_000_000).allowed);
    assert_eq!(bucket.snapshot().tokens, 9_999);
    for _ in 0..9 {
        assert!(bucket.consume(1_000, 20_000_000_000).allowed);
    }
    assert!(!bucket.consume(1_000, 20_000_000_000).allowed);
}
