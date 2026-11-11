//! Throughput/latency probe for the async client. Each task owns a bucket
//! (no contention) and hammers `consume(1)` for a fixed window; reports
//! aggregate ops/sec and per-op p50/p99.
//!
//! Usage: async_bench [addr] [concurrency] [seconds]

use limiter_client::{AsyncClient, ClientConfig, FailMode, Limits};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:39091".to_string());
    let concurrency: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let seconds: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    let client = AsyncClient::connect(
        addr,
        ClientConfig {
            pool_size: concurrency,
            fail_mode: FailMode::Open,
        },
    );
    let count = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();

    let mut handles = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let client = client.clone();
        let count = Arc::clone(&count);
        let stop = Arc::clone(&stop);
        handles.push(tokio::spawn(async move {
            // Effectively unlimited bucket so every consume is allowed.
            let bucket = client
                .create(
                    format!("bench:{i}").as_bytes(),
                    Limits {
                        capacity: u64::MAX,
                        refill_rate: 0,
                        ttl_ns: 0,
                    },
                )
                .await
                .expect("create");
            let mut lats: Vec<u64> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                let _ = bucket.consume(1).await;
                lats.push(t.elapsed().as_nanos() as u64);
                count.fetch_add(1, Ordering::Relaxed);
            }
            lats
        }));
    }

    tokio::time::sleep(Duration::from_secs(seconds)).await;
    stop.store(true, Ordering::Relaxed);

    let mut lats: Vec<u64> = Vec::new();
    for h in handles {
        lats.extend(h.await.expect("task"));
    }
    let elapsed = started.elapsed().as_secs_f64();
    let total = count.load(Ordering::Relaxed);
    lats.sort_unstable();
    let pct = |q: f64| -> f64 {
        if lats.is_empty() {
            return 0.0;
        }
        let idx = ((lats.len() as f64 * q) as usize).min(lats.len() - 1);
        lats[idx] as f64 / 1000.0
    };
    println!(
        "async_rust concurrency={concurrency} ops={total} ops_per_sec={:.0} p50_us={:.1} p99_us={:.1}",
        total as f64 / elapsed,
        pct(0.50),
        pct(0.99),
    );
}
