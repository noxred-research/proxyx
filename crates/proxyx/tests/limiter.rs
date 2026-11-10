// Test harness of the rate-limit service: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

//! End-to-end tests: spawn the real `proxyx limiter` role on an ephemeral port
//! (parsing its `READY` line) and drive it through `limiter-client` plus raw
//! sockets for protocol-level checks.

use limiter_client::{Client, ClientConfig, Connection, ConsumeReq, FailMode, Limits};
use limiter_proto::{MAGIC, ST_OK, ST_STALE, VERSION};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

struct Server {
    child: Child,
    addr: String,
}

impl Server {
    fn start(env: &[(&str, &str)]) -> Server {
        Server::start_on("127.0.0.1:0", env)
    }

    fn start_on(bind: &str, env: &[(&str, &str)]) -> Server {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_proxyx"));
        cmd.args(["limiter", bind]).stdout(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn server");
        let stdout = child.stdout.take().expect("server stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read READY line");
        assert!(line.starts_with("READY "), "unexpected line: {line:?}");
        let addr = line.split_whitespace().nth(1).expect("addr").to_string();
        Server { child, addr }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn client(&self) -> Client {
        Client::connect(self.addr.clone(), ClientConfig::default())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn limits(capacity: u64, refill_rate: u64, ttl_ns: u64) -> Limits {
    Limits {
        capacity,
        refill_rate,
        ttl_ns,
    }
}

#[test]
fn create_consume_snapshot_happy_path() {
    let server = Server::start(&[]);
    let client = server.client();
    let bucket = client.create(b"user:1", limits(10, 0, 0)).unwrap();

    // 10 allowed, then denied with a positive retry (zero refill -> unbounded).
    for _ in 0..10 {
        assert!(bucket.consume(1).allowed);
    }
    let denied = bucket.consume(1);
    assert!(!denied.allowed);
    assert!(!denied.degraded);
    assert_eq!(denied.retry_after_ns, u64::MAX);

    let snap = bucket.snapshot().unwrap();
    assert_eq!(snap.capacity, 10);
    assert_eq!(snap.tokens, 0);
}

#[test]
fn recreate_same_key_returns_same_handle_and_updates_capacity() {
    let server = Server::start(&[]);
    let client = server.client();
    let b1 = client.create(b"k", limits(3, 0, 0)).unwrap();
    let h1 = b1.handle();
    let b2 = client.create(b"k", limits(20, 0, 0)).unwrap();
    assert_eq!(h1, b2.handle());
    assert_eq!(b2.snapshot().unwrap().capacity, 20);
}

#[test]
fn nonzero_refill_denied_has_finite_retry() {
    let server = Server::start(&[]);
    let client = server.client();
    let bucket = client.create(b"r", limits(2, 1, 0)).unwrap();
    assert!(bucket.consume(2).allowed);
    let denied = bucket.consume(5);
    assert!(!denied.allowed);
    assert!(denied.retry_after_ns > 0 && denied.retry_after_ns < u64::MAX);
}

#[test]
fn slab_full_is_rejected() {
    let server = Server::start(&[("PROXYX_LIMITER_MAX_BUCKETS", "2")]);
    let client = server.client();
    client.create(b"a", limits(1, 0, 0)).unwrap();
    client.create(b"b", limits(1, 0, 0)).unwrap();
    assert!(client.create(b"c", limits(1, 0, 0)).is_err());
}

#[test]
fn evicted_handle_reports_stale_then_client_recovers() {
    let server = Server::start(&[("PROXYX_LIMITER_REAPER_MS", "20")]);
    // Raw connection to observe the protocol-level STALE before the client hides it.
    let mut raw = Connection::connect(&server.addr).unwrap();
    let ttl_ns = 15_000_000; // 15 ms idle TTL
    let created = raw
        .create(&[limiter_client::CreateReq {
            capacity: 5,
            refill_rate: 0,
            ttl_ns,
            key: b"ephemeral",
        }])
        .unwrap();
    let handle = created[0].handle;
    std::thread::sleep(Duration::from_millis(150));
    let res = raw.consume(&[ConsumeReq { handle, amount: 1 }]).unwrap();
    assert_eq!(res[0].status, ST_STALE);

    // The high-level client transparently re-creates on STALE and succeeds.
    let client = server.client();
    let bucket = client.create(b"ephemeral", limits(5, 0, ttl_ns)).unwrap();
    std::thread::sleep(Duration::from_millis(150)); // let it be evicted again
    let outcome = bucket.consume(1);
    assert!(outcome.allowed);
    assert!(!outcome.degraded);
}

#[test]
fn no_over_admission_across_wire() {
    const K: u64 = 37;
    const WORKERS: usize = 64;
    let server = Server::start(&[]);
    let client = server.client();
    let bucket = client.create(b"shared", limits(K, 0, 0)).unwrap();
    let admitted = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                if bucket.consume(1).allowed {
                    admitted.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(admitted.load(Ordering::Relaxed), K);
    assert_eq!(bucket.snapshot().unwrap().tokens, 0);
}

#[test]
fn malformed_frame_drops_conn_but_server_keeps_serving() {
    let server = Server::start(&[]);
    // Open a raw socket, handshake, then send a frame claiming an oversized length.
    let mut sock = TcpStream::connect(&server.addr).unwrap();
    let mut hello = [0u8; 5];
    hello[..4].copy_from_slice(&MAGIC);
    hello[4] = VERSION;
    sock.write_all(&hello).unwrap();
    let mut reply = [0u8; 1];
    sock.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], VERSION);
    // frame_len = 0xFFFFFFFF > MAX_FRAME_BYTES -> server rejects and closes.
    sock.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    let mut buf = [0u8; 1];
    // Server closes the connection: read returns 0 (EOF) or an error.
    let _ = sock.read(&mut buf);
    drop(sock);

    // A fresh connection is still served.
    let client = server.client();
    let bucket = client.create(b"after", limits(2, 0, 0)).unwrap();
    assert!(bucket.consume(1).allowed);
    assert!(bucket.consume(1).allowed);
    assert!(!bucket.consume(1).allowed);
}

#[test]
fn client_fail_open_degrades_then_recovers_after_restart() {
    let mut server = Server::start(&[]);
    let addr = server.addr.clone();
    let client = Client::connect(
        addr.clone(),
        ClientConfig {
            pool_size: 4,
            fail_mode: FailMode::Open,
        },
    );
    let bucket = client.create(b"fo", limits(5, 0, 0)).unwrap();
    assert!(bucket.consume(1).allowed);

    // Server gone: consume must degrade open (allowed despite no server).
    server.kill();
    let degraded = bucket.consume(1);
    assert!(degraded.allowed);
    assert!(degraded.degraded);

    // Restart on the same port; the client recovers to real allow/deny within a
    // few attempts (a dead pooled connection may degrade once before it is
    // dropped and reconnected). The handle is stale post-restart, so the client
    // re-creates transparently.
    let _server2 = Server::start_on(&addr, &[]);
    let mut recovered = false;
    for _ in 0..10 {
        let o = bucket.consume(1);
        if !o.degraded {
            recovered = true;
            break;
        }
    }
    assert!(recovered, "client never recovered after restart");
}

#[test]
fn drain_debits_up_to_available_over_wire() {
    let server = Server::start(&[]);
    let client = server.client();
    // Create a bucket and consume some, then drain via a raw connection.
    let bucket = client.create(b"tpm", limits(100, 0, 0)).unwrap();
    assert!(bucket.consume(60).allowed); // 40 left
    let handle = bucket.handle();

    let mut conn = Connection::connect(&server.addr).unwrap();
    // Drain 50 but only 40 remain -> drained == 40, never denies.
    let r = conn.drain(&[ConsumeReq { handle, amount: 50 }]).unwrap();
    assert_eq!(r[0].status, ST_OK);
    assert_eq!(r[0].drained, 40);
    // Bucket now empty; a second drain returns 0.
    let r2 = conn.drain(&[ConsumeReq { handle, amount: 10 }]).unwrap();
    assert_eq!(r2[0].drained, 0);
    assert_eq!(bucket.snapshot().unwrap().tokens, 0);
}
