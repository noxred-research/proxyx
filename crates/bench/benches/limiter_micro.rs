//! Microbenchmarks of rate limiting: the in-process token bucket, and the
//! limiter client against a real `proxyx-limiter-server` on loopback.
//!
//! For sustained multi-client throughput of the service use `limiter-bench`;
//! this file measures the cost of one operation.

use std::hint::black_box;
use std::net::TcpListener;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use limiter_client::{Client, ClientConfig, Connection, ConsumeReq, CreateReq, FailMode, Limits};
use limiter_core::TokenBucket;

const BUCKET_CAPACITY: u64 = u64::MAX / 4;
const BUCKET_REFILL: u64 = 1_000_000_000;

fn token_bucket(c: &mut Criterion) {
    let mut g = c.benchmark_group("token_bucket");
    g.throughput(Throughput::Elements(1));
    let bucket = TokenBucket::new(BUCKET_CAPACITY, BUCKET_REFILL, BUCKET_CAPACITY, 0);
    let mut now = 0u64;
    g.bench_function("consume_allowed", |b| {
        b.iter(|| {
            now += 1_000;
            black_box(bucket.consume(black_box(1), now))
        });
    });
    // a drained bucket answers "denied" with the retry hint
    let empty = TokenBucket::new(1_000, 1, 0, 0);
    g.bench_function("consume_denied", |b| {
        b.iter(|| black_box(empty.consume(black_box(1_000_000), 0)));
    });
    g.finish();
}

/// Start the limiter server in this process and wait until it accepts.
fn start_server() -> String {
    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").expect("find a port");
        probe.local_addr().expect("addr").to_string()
    };
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        // runs until the process exits
        let _ = limiter_server::run(&serve_addr);
    });
    for _ in 0..100 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            return addr;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the limiter server did not start on {addr}");
}

fn over_loopback(c: &mut Criterion) {
    let addr = start_server();

    let mut g = c.benchmark_group("limiter_loopback");

    // One consume per round trip, through the pooled client.
    let client = Client::connect(
        addr.clone(),
        ClientConfig {
            pool_size: 4,
            fail_mode: FailMode::Closed,
        },
    );
    let bucket = client
        .create(
            b"bench:single",
            Limits {
                capacity: BUCKET_CAPACITY,
                refill_rate: BUCKET_REFILL,
                ttl_ns: 0,
            },
        )
        .expect("create the bucket");
    g.throughput(Throughput::Elements(1));
    g.bench_function("client_consume_round_trip", |b| {
        b.iter(|| black_box(bucket.consume(black_box(1))));
    });

    // Batches of consumes by handle on one connection: what a busy proxy does.
    let mut conn = Connection::connect(&addr).expect("connect");
    let keys: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("bench:batch:{i}").into_bytes())
        .collect();
    let creates: Vec<CreateReq> = keys
        .iter()
        .map(|k| CreateReq {
            capacity: BUCKET_CAPACITY,
            refill_rate: BUCKET_REFILL,
            ttl_ns: 0,
            key: k,
        })
        .collect();
    let handles: Vec<u64> = conn
        .create(&creates)
        .expect("create the working set")
        .iter()
        .map(|r| r.handle)
        .collect();
    for batch in [1usize, 32, 256] {
        let reqs: Vec<ConsumeReq> = handles
            .iter()
            .take(batch)
            .map(|&handle| ConsumeReq { handle, amount: 1 })
            .collect();
        g.throughput(Throughput::Elements(batch as u64));
        g.bench_function(format!("connection_consume_batch_{batch}"), |b| {
            b.iter(|| black_box(conn.consume(black_box(&reqs)).expect("consume")));
        });
    }
    g.finish();
}

criterion_group!(benches, token_bucket, over_loopback);
criterion_main!(benches);
