//! Product-protocol load generator for limiter-server. Each client thread holds
//! a persistent `Connection`, creates its working-set buckets once (outside the
//! timed window), caches the returned handles, then runs a measured pipelined
//! CONSUME-by-handle loop. Emits the same `METRIC`/`ASI` lines the autoresearch
//! harness consumes; `network_score` is the harmonic mean of the selected
//! workloads' ops/sec.

use limiter_client::{Connection, ConsumeReq, CreateReq};
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const DEFAULT_ADDR: &str = "127.0.0.1:39091";
const DEFAULT_OPS: usize = 1_000_000;
const DEFAULT_CLIENTS: usize = 32;
const DEFAULT_BATCH: usize = 32;
/// Most connections (one thread each).
const MAX_CLIENTS: usize = 4096;
/// Most consumes in one frame: `MAX_BATCH` of the limiter protocol, above which the server
/// refuses the frame.
const MAX_BATCH: usize = 4096;
const MAX_PIPELINE_DEPTH: usize = 1024;
const MAX_OPS: usize = 1 << 40;

// One shared working set of named buckets, addressed by handle. Power of two so
// the pick masks are cheap.
const WORKING_SET: usize = 1 << 15;
const ZIPF_HOT_BUCKETS: usize = 256;
const CREATE_BATCH: usize = 4096;
const BUCKET_CAPACITY: u64 = 10_000_000;
const BUCKET_REFILL: u64 = 1_000_000;
const DEFAULT_AMOUNT: u64 = 1_000;
const RATE_LIMITED_AMOUNT: u64 = 10_000_000;

#[derive(Clone, Copy)]
struct Row {
    workload: &'static str,
    operations: usize,
    allowed: usize,
    denied: usize,
    elapsed_ns: u128,
    ops_per_sec: f64,
    p99_latency_ns: u128,
}

struct ClientResult {
    allowed: usize,
    denied: usize,
    latencies: Vec<(u128, usize)>,
}

/// Maps (client, op, rng, per_client) -> an index into the shared handle set.
type PickFn = fn(usize, usize, &mut Lcg, usize) -> usize;
/// (metric name, selection aliases, consume amount, pick fn).
type Workload = (&'static str, &'static [&'static str], u64, PickFn);

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

const USAGE: &str =
    "usage: limiter-bench [ADDR [OPS [CLIENTS [BATCH [WORKLOAD [PIPELINE_DEPTH]]]]]]\n\
  ADDR            limiter host:port (default 127.0.0.1:39091)\n\
  OPS             total consumes per workload, CLIENTS to 2^40 (default 1000000)\n\
  CLIENTS         connections, 1 to 4096 (default 32)\n\
  BATCH           consumes per frame, 1 to 4096 (default 32)\n\
  WORKLOAD        all, uniform, zipfian, concurrent or openloop_rate_limited (default all)\n\
  PIPELINE_DEPTH  frames in flight per connection, 1 to 1024 (default 1)";

/// A command-line error: say what was wrong and how to call the tool, exit 2.
fn usage_error(message: &str) -> ! {
    eprintln!("limiter-bench: {message}\n{USAGE}");
    std::process::exit(2);
}

fn arg_string(index: usize, default: &str) -> String {
    env::args()
        .nth(index)
        .unwrap_or_else(|| default.to_string())
}

/// A positive integer argument within `1..=max`; a missing one is `default`.
fn arg_usize(index: usize, name: &str, default: usize, max: usize) -> usize {
    let Some(text) = env::args().nth(index) else {
        return default;
    };
    match text.parse::<usize>() {
        Ok(value) if (1..=max).contains(&value) => value,
        _ => usage_error(&format!(
            "{name} must be an integer from 1 to {max}, got {text:?}"
        )),
    }
}

fn p99(latencies: &mut [(u128, usize)], operations: usize) -> u128 {
    if latencies.is_empty() || operations == 0 {
        return 0;
    }
    latencies.sort_unstable_by_key(|sample| sample.0);
    let target = operations.saturating_sub(1) * 99 / 100;
    let mut seen = 0_usize;
    for &(latency, count) in latencies.iter() {
        seen += count;
        if seen > target {
            return latency;
        }
    }
    latencies.last().map(|sample| sample.0).unwrap_or(0)
}

fn summarize(
    workload: &'static str,
    operations: usize,
    allowed: usize,
    denied: usize,
    elapsed_ns: u128,
    mut latencies: Vec<(u128, usize)>,
) -> Row {
    Row {
        workload,
        operations,
        allowed,
        denied,
        elapsed_ns,
        ops_per_sec: operations as f64 * 1_000_000_000.0 / elapsed_ns.max(1) as f64,
        p99_latency_ns: p99(&mut latencies, operations),
    }
}

fn uniform_pick(client: usize, op: usize, _rng: &mut Lcg, per_client: usize) -> usize {
    (client * per_client + op) & (WORKING_SET - 1)
}

fn zipf_pick(_client: usize, _op: usize, rng: &mut Lcg, _per_client: usize) -> usize {
    if rng.next() & 1023 < 922 {
        (rng.next() as usize) & (ZIPF_HOT_BUCKETS - 1)
    } else {
        (rng.next() as usize) & (WORKING_SET - 1)
    }
}

fn concurrent_pick(_client: usize, _op: usize, rng: &mut Lcg, _per_client: usize) -> usize {
    (rng.next() as usize) & (WORKING_SET - 1)
}

fn rate_limited_pick(client: usize, op: usize, _rng: &mut Lcg, per_client: usize) -> usize {
    (client * per_client + op) & (WORKING_SET - 1)
}

fn network_score(rows: &[Row]) -> f64 {
    rows.len() as f64 / rows.iter().map(|row| 1.0 / row.ops_per_sec).sum::<f64>()
}

/// Create the shared working set on one connection before any timing.
fn create_working_set(conn: &mut Connection) -> Vec<u64> {
    let mut handles = Vec::with_capacity(WORKING_SET);
    let mut i = 0;
    while i < WORKING_SET {
        let count = (WORKING_SET - i).min(CREATE_BATCH);
        let keys: Vec<Vec<u8>> = (i..i + count)
            .map(|k| format!("b{k}").into_bytes())
            .collect();
        let reqs: Vec<CreateReq> = keys
            .iter()
            .map(|k| CreateReq {
                capacity: BUCKET_CAPACITY,
                refill_rate: BUCKET_REFILL,
                ttl_ns: 0,
                key: k,
            })
            .collect();
        let results = conn.create(&reqs).expect("create working set");
        for r in &results {
            handles.push(r.handle);
        }
        i += count;
    }
    handles
}

#[allow(clippy::too_many_arguments)]
fn run_workload(
    workload: &'static str,
    ops: usize,
    clients: usize,
    batch: usize,
    pipeline_depth: usize,
    amount: u64,
    handles: Arc<Vec<u64>>,
    conns: Vec<Connection>,
    pick: PickFn,
) -> (Row, Vec<Connection>) {
    let per_client = ops / clients;
    let actual_ops = per_client * clients;
    let batch = batch.max(1).min(per_client.max(1));
    let pipeline_depth = pipeline_depth.max(1);
    let started = Instant::now();
    let mut workers = Vec::with_capacity(clients);

    for (client_index, mut conn) in conns.into_iter().enumerate() {
        let handles = Arc::clone(&handles);
        workers.push(thread::spawn(move || {
            let mut rng = Lcg::new(10_000 + client_index as u64);
            let mut latencies: Vec<(u128, usize)> = Vec::new();
            let mut allowed = 0usize;
            let mut denied = 0usize;
            let mut op_index = 0usize;
            let mut counts: Vec<usize> = Vec::with_capacity(pipeline_depth);
            let mut reqs: Vec<ConsumeReq> = Vec::with_capacity(batch);
            let mut dead = false;

            while op_index < per_client && !dead {
                let before = Instant::now();
                let mut window_ops = 0usize;
                counts.clear();
                while counts.len() < pipeline_depth && op_index < per_client {
                    let count = batch.min(per_client - op_index);
                    reqs.clear();
                    for b in 0..count {
                        let idx = pick(client_index, op_index + b, &mut rng, per_client);
                        reqs.push(ConsumeReq {
                            handle: handles[idx],
                            amount,
                        });
                    }
                    if conn.send_consume(&reqs).is_err() {
                        denied += count;
                        dead = true;
                        break;
                    }
                    counts.push(count);
                    op_index += count;
                    window_ops += count;
                }
                for &count in &counts {
                    match conn.recv_consume(count) {
                        Ok(results) => {
                            for r in results {
                                if r.allowed {
                                    allowed += 1;
                                } else {
                                    denied += 1;
                                }
                            }
                        }
                        Err(_) => {
                            denied += count;
                            dead = true;
                        }
                    }
                }
                if window_ops != 0 {
                    let per_operation_latency = before.elapsed().as_nanos() / window_ops as u128;
                    latencies.push((per_operation_latency, window_ops));
                }
            }

            (
                client_index,
                ClientResult {
                    allowed,
                    denied,
                    latencies,
                },
                conn,
            )
        }));
    }

    let mut allowed = 0;
    let mut denied = 0;
    let mut latencies = Vec::new();
    let mut slots: Vec<Option<Connection>> = (0..clients).map(|_| None).collect();
    for worker in workers {
        let (client_index, mut result, conn) = worker.join().expect("client panicked");
        allowed += result.allowed;
        denied += result.denied;
        latencies.append(&mut result.latencies);
        slots[client_index] = Some(conn);
    }
    let conns = slots
        .into_iter()
        .map(|slot| slot.expect("client connection"))
        .collect();

    let row = summarize(
        workload,
        actual_ops,
        allowed,
        denied,
        started.elapsed().as_nanos(),
        latencies,
    );
    (row, conns)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    if args.len() > 6 {
        usage_error(&format!("expected at most 6 arguments, got {}", args.len()));
    }
    let addr = arg_string(1, DEFAULT_ADDR);
    let ops = arg_usize(2, "OPS", DEFAULT_OPS, MAX_OPS);
    let clients = arg_usize(3, "CLIENTS", DEFAULT_CLIENTS, MAX_CLIENTS);
    let batch = arg_usize(4, "BATCH", DEFAULT_BATCH, MAX_BATCH);
    let selection = arg_string(5, "all");
    let pipeline_depth = arg_usize(6, "PIPELINE_DEPTH", 1, MAX_PIPELINE_DEPTH);
    if ops < clients {
        usage_error(&format!(
            "OPS ({ops}) must be at least CLIENTS ({clients}): each client runs OPS / CLIENTS consumes"
        ));
    }

    let workloads: &[Workload] = &[
        (
            "network_many_buckets_uniform",
            &["all", "uniform"],
            DEFAULT_AMOUNT,
            uniform_pick,
        ),
        (
            "network_many_buckets_zipfian",
            &["all", "zipfian"],
            DEFAULT_AMOUNT,
            zipf_pick,
        ),
        (
            "network_concurrent_many_buckets",
            &["all", "concurrent"],
            DEFAULT_AMOUNT,
            concurrent_pick,
        ),
        (
            "network_openloop_rate_limited",
            &["openloop_rate_limited"],
            RATE_LIMITED_AMOUNT,
            rate_limited_pick,
        ),
    ];
    let selected = |(name, aliases, _, _): &&Workload| {
        selection == *name || aliases.contains(&selection.as_str())
    };
    if !workloads.iter().any(|w| selected(&w)) {
        usage_error(&format!("unknown workload {selection:?}"));
    }

    // Persistent connection pool, established once before timing and reused
    // across every selected workload (connect/handshake never lands in a
    // measured window).
    let mut conns: Vec<Connection> = (0..clients)
        .map(|_| {
            Connection::connect(&addr).unwrap_or_else(|error| {
                eprintln!("limiter-bench: cannot connect to {addr}: {error}");
                std::process::exit(1);
            })
        })
        .collect();

    // Working set created once on the first connection.
    let handles = Arc::new(create_working_set(&mut conns[0]));

    let mut rows = Vec::new();
    for (name, _, amount, pick) in workloads.iter().filter(selected) {
        let (row, next) = run_workload(
            name,
            ops,
            clients,
            batch,
            pipeline_depth,
            *amount,
            Arc::clone(&handles),
            conns,
            *pick,
        );
        rows.push(row);
        conns = next;
    }
    drop(conns);

    let basis = rows
        .iter()
        .map(|row| row.workload)
        .collect::<Vec<_>>()
        .join(",");

    println!("METRIC network_score={}", network_score(&rows));
    println!("ASI network_score_basis={basis}");
    for row in &rows {
        println!("METRIC {}_ops_per_sec={}", row.workload, row.ops_per_sec);
        println!(
            "METRIC {}_p99_latency_ns={}",
            row.workload, row.p99_latency_ns
        );
        println!("ASI {}_allowed={}", row.workload, row.allowed);
        println!("ASI {}_denied={}", row.workload, row.denied);
        println!("ASI {}_elapsed_ns={}", row.workload, row.elapsed_ns);
        println!("ASI {}_operations={}", row.workload, row.operations);
    }
    println!("ASI protocol=tcp-handle-framed-pipeline{pipeline_depth}");
    println!("ASI clients={clients}");
    println!("ASI batch={batch}");
    println!("ASI pipeline_depth={pipeline_depth}");
    println!("ASI operations={ops}");
}
