use limiter_core::TokenBucket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn concurrent_consumers_do_not_over_admit() {
    const PERMITS: u64 = 37;
    const WORKERS: usize = 128;

    let bucket = Arc::new(TokenBucket::new(PERMITS, 0, PERMITS, 0));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let admitted = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let bucket = Arc::clone(&bucket);
        let barrier = Arc::clone(&barrier);
        let admitted = Arc::clone(&admitted);
        handles.push(thread::spawn(move || {
            barrier.wait();
            if bucket.consume(1, 0).allowed {
                admitted.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker panicked");
    }

    assert_eq!(admitted.load(Ordering::Relaxed), PERMITS);
    assert_eq!(bucket.snapshot().tokens, 0);
}
