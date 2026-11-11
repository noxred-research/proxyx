use limiter_core::TokenBucket;
use std::env;
use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

struct Row {
    workload: &'static str,
    operations: usize,
    allowed: usize,
    denied: usize,
    elapsed_ns: u128,
    ops_per_sec: f64,
}

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn summarize(
    workload: &'static str,
    operations: usize,
    allowed: usize,
    denied: usize,
    elapsed_ns: u128,
) -> Row {
    Row {
        workload,
        operations,
        allowed,
        denied,
        elapsed_ns,
        ops_per_sec: operations as f64 * 1_000_000_000.0 / elapsed_ns.max(1) as f64,
    }
}

fn hot_bucket(ops: usize) -> Row {
    let bucket = TokenBucket::new(10_000_000_000, 1_000_000, 10_000_000_000, 0);
    let mut allowed = 0;
    let started = Instant::now();
    for i in 0..ops {
        let result = black_box(bucket.consume(1, i as u64));
        if result.allowed {
            allowed += 1;
        }
    }
    summarize(
        "hot_bucket",
        ops,
        allowed,
        ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn many_buckets_uniform(ops: usize) -> Row {
    const BUCKETS: usize = 16_384;
    let buckets: Vec<TokenBucket> = (0..BUCKETS)
        .map(|_| TokenBucket::new(10_000_000, 1_000_000, 10_000_000, 0))
        .collect();
    let mut allowed = 0;
    let started = Instant::now();
    for i in 0..ops {
        let result = black_box(buckets[i & (BUCKETS - 1)].consume(1_000, i as u64 * 1_000_000));
        if result.allowed {
            allowed += 1;
        }
    }
    summarize(
        "many_buckets_uniform",
        ops,
        allowed,
        ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn many_buckets_zipfian(ops: usize) -> Row {
    const BUCKETS: usize = 4_096;
    const HOT_SET: u64 = 64;
    let buckets: Vec<TokenBucket> = (0..BUCKETS)
        .map(|_| TokenBucket::new(10_000_000, 1_000_000, 10_000_000, 0))
        .collect();
    let mut rng = Lcg::new(872_341);
    let mut allowed = 0;
    let started = Instant::now();
    for i in 0..ops {
        let index = if rng.next() % 10 < 9 {
            (rng.next() % HOT_SET) as usize
        } else {
            (rng.next() as usize) & (BUCKETS - 1)
        };
        let result = black_box(buckets[index].consume(1_000, i as u64 * 1_000_000));
        if result.allowed {
            allowed += 1;
        }
    }
    summarize(
        "many_buckets_zipfian",
        ops,
        allowed,
        ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn mostly_allowed(ops: usize) -> Row {
    let bucket = TokenBucket::new((ops * 2) as u64, 1, (ops * 2) as u64, 0);
    let mut allowed = 0;
    let started = Instant::now();
    for i in 0..ops {
        let result = black_box(bucket.consume(1, i as u64));
        if result.allowed {
            allowed += 1;
        }
    }
    summarize(
        "mostly_allowed",
        ops,
        allowed,
        ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn mostly_denied(ops: usize) -> Row {
    let bucket = TokenBucket::new(1_000, 1, 0, 0);
    let mut allowed = 0;
    let started = Instant::now();
    for i in 0..ops {
        let result = black_box(bucket.consume(1_000, i as u64));
        if result.allowed {
            allowed += 1;
        }
    }
    summarize(
        "mostly_denied",
        ops,
        allowed,
        ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn mixed_update_consume(ops: usize) -> Row {
    const BUCKETS: usize = 1_024;
    let buckets: Vec<TokenBucket> = (0..BUCKETS)
        .map(|_| TokenBucket::new(10_000_000, 1_000_000, 5_000_000, 0))
        .collect();
    let mut rng = Lcg::new(1_138);
    let mut allowed = 0;
    let mut denied = 0;
    let started = Instant::now();
    for i in 0..ops {
        let bucket = &buckets[(rng.next() as usize) & (BUCKETS - 1)];
        let now_ns = i as u64 * 500_000;
        if i % 100 == 0 {
            let rate = 1 + (rng.next() % 2_000_000);
            black_box(bucket.update(now_ns, None, Some(rate)));
        } else if i % 250 == 0 {
            let capacity = 1 + (rng.next() % 20_000_000);
            black_box(bucket.update(now_ns, Some(capacity), None));
        } else {
            let result = black_box(bucket.consume(1 + (rng.next() % 20_000), now_ns));
            if result.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
        }
    }
    summarize(
        "mixed_update_consume",
        ops,
        allowed,
        denied,
        started.elapsed().as_nanos(),
    )
}

fn concurrent_hot_bucket(ops: usize) -> Row {
    let bucket = Arc::new(TokenBucket::new(ops as u64, 1, ops as u64, 0));
    const WORKERS: usize = 8;
    let per_worker = (ops / WORKERS).max(1);
    let started = Instant::now();
    let mut handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let bucket = Arc::clone(&bucket);
        handles.push(thread::spawn(move || {
            let mut allowed = 0;
            for i in 0..per_worker {
                let result = black_box(bucket.consume(1, i as u64));
                if result.allowed {
                    allowed += 1;
                }
            }
            allowed
        }));
    }
    let mut allowed = 0;
    for handle in handles {
        allowed += handle.join().expect("worker panicked");
    }
    let actual_ops = per_worker * WORKERS;
    summarize(
        "concurrent_hot_bucket",
        actual_ops,
        allowed,
        actual_ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn concurrent_many_buckets(ops: usize) -> Row {
    const BUCKETS: usize = 4_096;
    const WORKERS: usize = 8;
    let buckets: Arc<Vec<TokenBucket>> = Arc::new(
        (0..BUCKETS)
            .map(|_| TokenBucket::new(10_000_000, 1_000_000, 10_000_000, 0))
            .collect(),
    );
    let per_worker = (ops / WORKERS).max(1);
    let started = Instant::now();
    let mut handles = Vec::with_capacity(WORKERS);
    for worker in 0..WORKERS {
        let buckets = Arc::clone(&buckets);
        handles.push(thread::spawn(move || {
            let mut rng = Lcg::new(10_000 + worker as u64);
            let mut allowed = 0;
            for i in 0..per_worker {
                let bucket = &buckets[(rng.next() as usize) & (BUCKETS - 1)];
                let result = black_box(bucket.consume(1_000, i as u64 * 1_000_000));
                if result.allowed {
                    allowed += 1;
                }
            }
            allowed
        }));
    }
    let mut allowed = 0;
    for handle in handles {
        allowed += handle.join().expect("worker panicked");
    }
    let actual_ops = per_worker * WORKERS;
    summarize(
        "concurrent_many_buckets",
        actual_ops,
        allowed,
        actual_ops - allowed,
        started.elapsed().as_nanos(),
    )
}

fn many_bucket_score(rows: &[Row]) -> f64 {
    let mut count = 0.0;
    let mut inverse_sum = 0.0;
    for row in rows {
        if matches!(
            row.workload,
            "many_buckets_uniform" | "many_buckets_zipfian" | "concurrent_many_buckets"
        ) {
            count += 1.0;
            inverse_sum += 1.0 / row.ops_per_sec;
        }
    }
    count / inverse_sum
}

fn main() {
    let ops = env_usize("BENCH_OPS", 200_000);
    let rows = vec![
        hot_bucket(ops),
        many_buckets_uniform(ops),
        many_buckets_zipfian(ops),
        mostly_allowed(ops),
        mostly_denied(ops),
        mixed_update_consume(ops),
        concurrent_hot_bucket(ops),
        concurrent_many_buckets(ops),
    ];
    println!("METRIC score={:.6}", many_bucket_score(&rows));
    println!("ASI score_basis=many_buckets_uniform,many_buckets_zipfian,concurrent_many_buckets");
    for row in rows {
        println!("METRIC {}_ops_per_sec={:.6}", row.workload, row.ops_per_sec);
        println!("ASI {}_allowed={}", row.workload, row.allowed);
        println!("ASI {}_denied={}", row.workload, row.denied);
        println!("ASI {}_elapsed_ns={}", row.workload, row.elapsed_ns);
        println!("ASI {}_operations={}", row.workload, row.operations);
    }
    println!("ASI benchmark_language=rust");
    println!("ASI operations={ops}");
}
