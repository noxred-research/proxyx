//! Pooled client for the limiter rate-limit service.
//!
//! `Client` holds a small pool of [`Connection`]s and an address for lazy
//! reconnects. `create` returns a [`Bucket`] addressed by an opaque key; the
//! bucket caches the server handle and transparently re-`create`s once on a
//! `STALE` reply (the slot was evicted and recycled). On a transport failure the
//! data-plane `consume` degrades per [`FailMode`]; control-plane `create`/
//! `snapshot` propagate the error (a create cannot be silently faked).
//!
//! Transport behaviour is set by [`ResilienceConfig`]: bounded connect and
//! per-exchange timeouts, TCP keepalive, idle pool expiry and a circuit breaker
//! that stops dialing a dead service after repeated failures. EOF or timeout
//! after a write is ambiguous: the server may have applied the request even if
//! no response byte arrived. Exchanges are never reconnected and replayed.
//! Failed connections are dropped; later operations can open fresh connections.
//! `consume` returns a degraded result per [`FailMode`], not a server success;
//! `create`, `drain` and `snapshot` propagate transport errors.
//! [`Client::connect`] uses the defaults; [`Client::connect_with`] takes an
//! explicit config.

mod conn;
mod resilience;

#[cfg(feature = "async")]
mod async_client;

pub use conn::Connection;
pub use limiter_proto::{ConsumeReq, CreateReq, PingResult};
pub use resilience::{BreakerConfig, CircuitState, ClientStats, ResilienceConfig};

#[cfg(feature = "async")]
pub use async_client::{AsyncBucket, AsyncClient, AsyncConnection};

use limiter_proto::{ST_OK, ST_STALE};
use parking_lot::Mutex;
use resilience::Health;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// On transport failure, allow the request (degraded).
    Open,
    /// On transport failure, deny the request (degraded).
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientConfig {
    pub pool_size: usize,
    pub fail_mode: FailMode,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            pool_size: 8,
            fail_mode: FailMode::Open,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub capacity: u64,
    pub refill_rate: u64,
    pub ttl_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ns: u64,
    /// True when the result came from the fail-mode fallback, not the server.
    pub degraded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub capacity: u64,
    pub refill_rate: u64,
    pub tokens: u64,
    pub last_refill_ns: u64,
}

struct ClientInner {
    addr: String,
    pool_size: usize,
    fail_mode: FailMode,
    pool: Mutex<Vec<Connection>>,
    health: Arc<Health>,
}

impl ClientInner {
    /// Check out an unexpired pooled connection, or open a fresh one.
    /// Failed operations drop their connection instead of returning it.
    fn take(&self) -> io::Result<Connection> {
        self.health.allow()?;
        while let Some(conn) = self.pool.lock().pop() {
            if conn.last_used.elapsed() < self.health.config.max_idle {
                return Ok(conn);
            }
        }
        let conn = Connection::connect_with(&self.addr, Arc::clone(&self.health));
        if conn.is_err() {
            self.health.failure();
        }
        conn
    }

    fn give(&self, mut conn: Connection) {
        let mut pool = self.pool.lock();
        if pool.len() < self.pool_size {
            conn.last_used = Instant::now();
            pool.push(conn);
        }
    }
}

pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Construct a client. Lazy: connections open on first use, so this never
    /// blocks on or fails because of an unreachable server (fail-open clients
    /// must still construct).
    pub fn connect(addr: impl Into<String>, config: ClientConfig) -> Self {
        Self::connect_with(addr, config, ResilienceConfig::default())
    }

    /// Like [`Client::connect`] with explicit timeouts, keepalive, idle expiry and breaker.
    pub fn connect_with(
        addr: impl Into<String>,
        config: ClientConfig,
        resilience: ResilienceConfig,
    ) -> Self {
        Client {
            inner: Arc::new(ClientInner {
                addr: addr.into(),
                pool_size: config.pool_size,
                fail_mode: config.fail_mode,
                pool: Mutex::new(Vec::new()),
                health: Arc::new(Health::new(resilience)),
            }),
        }
    }

    /// Round-trip a liveness probe to the service. Honors the breaker and
    /// counts toward it like any other operation.
    pub fn ping(&self) -> io::Result<PingResult> {
        let mut conn = self.inner.take()?;
        let result = conn.ping(0x5058_4c49_4d49_5445)?;
        self.inner.give(conn);
        Ok(result)
    }

    /// Current circuit state.
    pub fn circuit_state(&self) -> CircuitState {
        self.inner.health.state()
    }

    /// Cumulative transport counters.
    pub fn stats(&self) -> ClientStats {
        self.inner.health.stats()
    }

    /// Create-or-update a bucket for `key`, returning a handle wrapper. Propagates
    /// transport errors and a server rejection (e.g. slab full).
    pub fn create(&self, key: &[u8], limits: Limits) -> io::Result<Bucket> {
        let mut conn = self.inner.take()?;
        let handle = create_on(&mut conn, key, limits)?;
        self.inner.give(conn);
        Ok(Bucket {
            inner: Arc::clone(&self.inner),
            key: key.into(),
            limits,
            handle: AtomicU64::new(handle),
        })
    }
}

/// One CREATE round-trip on a borrowed connection.
fn create_on(conn: &mut Connection, key: &[u8], limits: Limits) -> io::Result<u64> {
    let req = [CreateReq {
        capacity: limits.capacity,
        refill_rate: limits.refill_rate,
        ttl_ns: limits.ttl_ns,
        key,
    }];
    let results = conn.create(&req)?;
    let res = results[0];
    if res.status != ST_OK {
        return Err(io::Error::other("server rejected create (slab full?)"));
    }
    Ok(res.handle)
}

pub struct Bucket {
    inner: Arc<ClientInner>,
    key: Box<[u8]>,
    limits: Limits,
    handle: AtomicU64,
}

impl Bucket {
    pub fn handle(&self) -> u64 {
        self.handle.load(Ordering::Relaxed)
    }

    /// Consume `amount` tokens. Transparent re-create + single retry on `STALE`.
    /// On transport failure, returns the fail-mode fallback with `degraded=true`.
    pub fn consume(&self, amount: u64) -> Outcome {
        match self.try_consume(amount) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.inner.health.degraded();
                Outcome {
                    allowed: matches!(self.inner.fail_mode, FailMode::Open),
                    remaining: 0,
                    retry_after_ns: 0,
                    degraded: true,
                }
            }
        }
    }

    fn try_consume(&self, amount: u64) -> io::Result<Outcome> {
        let mut conn = self.inner.take()?;
        let handle = self.handle.load(Ordering::Relaxed);
        let r = conn.consume(&[ConsumeReq { handle, amount }])?[0];
        if r.status != ST_STALE {
            self.inner.give(conn);
            return Ok(outcome(r.allowed, r.remaining, r.retry_after_ns));
        }
        // Slot was evicted and recycled: re-create once and retry the consume.
        let new_handle = create_on(&mut conn, &self.key, self.limits)?;
        self.handle.store(new_handle, Ordering::Relaxed);
        let r2 = conn.consume(&[ConsumeReq {
            handle: new_handle,
            amount,
        }])?[0];
        self.inner.give(conn);
        if r2.status == ST_STALE {
            return Err(io::Error::other("persistent stale handle"));
        }
        Ok(outcome(r2.allowed, r2.remaining, r2.retry_after_ns))
    }

    /// Debit up to `amount` tokens for post-hoc accounting; returns how many
    /// were actually drained (never denies). Re-creates once on `STALE`.
    /// Propagates transport errors (the caller decides best-effort handling).
    pub fn drain(&self, amount: u64) -> io::Result<u64> {
        let mut conn = self.inner.take()?;
        let handle = self.handle.load(Ordering::Relaxed);
        let r = conn.drain(&[ConsumeReq { handle, amount }])?[0];
        if r.status != ST_STALE {
            self.inner.give(conn);
            return Ok(r.drained);
        }
        let new_handle = create_on(&mut conn, &self.key, self.limits)?;
        self.handle.store(new_handle, Ordering::Relaxed);
        let r2 = conn.drain(&[ConsumeReq {
            handle: new_handle,
            amount,
        }])?[0];
        self.inner.give(conn);
        Ok(r2.drained)
    }

    /// Read the bucket's current state. Re-creates once on `STALE`. Propagates
    /// transport errors (read plane is not faked).
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        let mut conn = self.inner.take()?;
        let handle = self.handle.load(Ordering::Relaxed);
        let s = conn.snapshot(&[handle])?[0];
        let s = if s.status == ST_STALE {
            let new_handle = create_on(&mut conn, &self.key, self.limits)?;
            self.handle.store(new_handle, Ordering::Relaxed);
            conn.snapshot(&[new_handle])?[0]
        } else {
            s
        };
        self.inner.give(conn);
        Ok(Snapshot {
            capacity: s.capacity,
            refill_rate: s.refill_rate,
            tokens: s.tokens,
            last_refill_ns: s.last_refill_ns,
        })
    }
}

fn outcome(allowed: bool, remaining: u64, retry_after_ns: u64) -> Outcome {
    Outcome {
        allowed,
        remaining,
        retry_after_ns,
        degraded: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use limiter_proto::{
        decode_consume_reqs, decode_create_reqs, decode_snapshot_reqs, encode_consume_results,
        encode_create_results, encode_drain_results, encode_snapshot_results, parse_frame,
        ConsumeResult, CreateResult, DrainResult, SnapshotResult, MAGIC, MAX_FRAME_BYTES,
        OP_CONSUME, OP_CREATE, OP_DRAIN, OP_SNAPSHOT, VERSION,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const LIMITS: Limits = Limits {
        capacity: 10,
        refill_rate: 0,
        ttl_ns: 60_000_000_000,
    };
    const UPDATED_LIMITS: Limits = Limits {
        capacity: 8,
        ..LIMITS
    };

    fn resilience() -> ResilienceConfig {
        ResilienceConfig {
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            breaker: None,
            ..ResilienceConfig::default()
        }
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        let length = u32::from_be_bytes(header) as usize;
        assert!((5..=MAX_FRAME_BYTES).contains(&length));
        let mut bytes = header.to_vec();
        bytes.resize(4 + length, 0);
        stream.read_exact(&mut bytes[4..]).unwrap();
        bytes
    }

    /// A non-refilling, single-bucket wire server. It applies one mutation on
    /// the warmed connection, drops its entire response, then serves recovery.
    /// Replayed requests are applied again, so duplicate debits remain visible.
    fn lost_response_server(listener: &TcpListener, dropped_op: u8) -> JoinHandle<[usize; 3]> {
        let listener = listener.try_clone().unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut calls = [0; 3];
            let mut capacity = 0;
            let mut tokens = 0;
            let mut lost = false;
            loop {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing recovery connection");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut hello = [0; 5];
                stream.read_exact(&mut hello).unwrap();
                assert_eq!(&hello[..4], &MAGIC);
                assert_eq!(hello[4], VERSION);
                stream.write_all(&[VERSION]).unwrap();
                loop {
                    let bytes = read_request(&mut stream);
                    let frame = parse_frame(&bytes).unwrap().unwrap();
                    assert_eq!(frame.count, 1);
                    let mut reply = Vec::new();
                    match frame.op {
                        OP_CREATE => {
                            let request = decode_create_reqs(frame.payload, 1).unwrap()[0];
                            assert_eq!(request.key, b"lost-response");
                            assert_eq!(request.refill_rate, 0);
                            capacity = request.capacity;
                            tokens = if calls[0] == 0 {
                                capacity
                            } else {
                                tokens.min(capacity)
                            };
                            calls[0] += 1;
                            encode_create_results(
                                &mut reply,
                                &[CreateResult {
                                    status: ST_OK,
                                    handle: 1,
                                }],
                            );
                        }
                        OP_CONSUME | OP_DRAIN => {
                            let request = decode_consume_reqs(frame.payload, 1)
                                .unwrap()
                                .next()
                                .unwrap();
                            assert_eq!(request.handle, 1);
                            if frame.op == OP_CONSUME {
                                calls[1] += 1;
                                let allowed = tokens >= request.amount;
                                if allowed {
                                    tokens -= request.amount;
                                }
                                encode_consume_results(
                                    &mut reply,
                                    &[ConsumeResult {
                                        status: ST_OK,
                                        allowed,
                                        remaining: tokens,
                                        retry_after_ns: 0,
                                    }],
                                );
                            } else {
                                calls[2] += 1;
                                let drained = tokens.min(request.amount);
                                tokens -= drained;
                                encode_drain_results(
                                    &mut reply,
                                    &[DrainResult {
                                        status: ST_OK,
                                        drained,
                                    }],
                                );
                            }
                        }
                        OP_SNAPSHOT => {
                            assert!(lost, "snapshot must follow the lost response");
                            let handle = decode_snapshot_reqs(frame.payload, 1)
                                .unwrap()
                                .next()
                                .unwrap();
                            assert_eq!(handle, 1);
                            encode_snapshot_results(
                                &mut reply,
                                &[SnapshotResult {
                                    status: ST_OK,
                                    capacity,
                                    refill_rate: 0,
                                    tokens,
                                    last_refill_ns: 0,
                                }],
                            );
                        }
                        op => panic!("unexpected operation {op}"),
                    }
                    if !lost
                        && frame.op == dropped_op
                        && calls[0] > 0
                        && (dropped_op != OP_CREATE || calls[0] == 2)
                    {
                        lost = true;
                        // Close only after applying the request, without writing
                        // even the first response byte.
                        drop(stream);
                        break;
                    }
                    stream.write_all(&reply).unwrap();
                    if frame.op == OP_SNAPSHOT {
                        return calls;
                    }
                }
            }
        })
    }

    fn assert_recovery(
        op: u8,
        fail_mode: FailMode,
        failed: bool,
        consumed: Option<Outcome>,
        snapshot: Snapshot,
        calls: [usize; 3],
        stats: ClientStats,
    ) {
        assert!(failed, "mutation transport failure must not become success");
        let expected_calls = match op {
            OP_CREATE => [2, 0, 0],
            OP_CONSUME => [1, 1, 0],
            OP_DRAIN => [1, 0, 1],
            _ => unreachable!(),
        };
        assert_eq!(calls, expected_calls, "mutation must apply exactly once");
        assert_eq!(snapshot.tokens, if op == OP_CREATE { 8 } else { 7 });
        assert_eq!(snapshot.capacity, if op == OP_CREATE { 8 } else { 10 });
        assert_eq!(stats.transport_errors, 1);
        assert_eq!(stats.degraded, u64::from(op == OP_CONSUME));
        if let Some(result) = consumed {
            assert_eq!(
                result,
                Outcome {
                    allowed: fail_mode == FailMode::Open,
                    remaining: 0,
                    retry_after_ns: 0,
                    degraded: true,
                }
            );
        }
    }

    #[test]
    fn lost_mutation_responses_are_not_replayed_and_consume_degrades() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        for fail_mode in [FailMode::Open, FailMode::Closed] {
            for op in [OP_CONSUME, OP_CREATE, OP_DRAIN] {
                let server = lost_response_server(&listener, op);
                let client = Client::connect_with(
                    &addr,
                    ClientConfig {
                        pool_size: 1,
                        fail_mode,
                    },
                    resilience(),
                );
                let bucket = client.create(b"lost-response", LIMITS).unwrap();
                let mut consumed = None;
                let failed = match op {
                    OP_CREATE => client.create(b"lost-response", UPDATED_LIMITS).is_err(),
                    OP_CONSUME => {
                        consumed = Some(bucket.consume(3));
                        true
                    }
                    OP_DRAIN => bucket.drain(3).is_err(),
                    _ => unreachable!(),
                };
                // A separate operation recovers on a new connection and reads
                // authoritative state; it must not repeat the lost mutation.
                let snapshot = bucket.snapshot().unwrap();
                let calls = server.join().unwrap();
                assert_recovery(
                    op,
                    fail_mode,
                    failed,
                    consumed,
                    snapshot,
                    calls,
                    client.stats(),
                );
            }
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_lost_mutation_responses_are_not_replayed_and_consume_degrades() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        for fail_mode in [FailMode::Open, FailMode::Closed] {
            for op in [OP_CONSUME, OP_CREATE, OP_DRAIN] {
                let server = lost_response_server(&listener, op);
                let client = AsyncClient::connect_with(
                    &addr,
                    ClientConfig {
                        pool_size: 1,
                        fail_mode,
                    },
                    resilience(),
                );
                let bucket = client.create(b"lost-response", LIMITS).await.unwrap();
                let mut consumed = None;
                let failed = match op {
                    OP_CREATE => client
                        .create(b"lost-response", UPDATED_LIMITS)
                        .await
                        .is_err(),
                    OP_CONSUME => {
                        consumed = Some(bucket.consume(3).await);
                        true
                    }
                    OP_DRAIN => bucket.drain(3).await.is_err(),
                    _ => unreachable!(),
                };
                let snapshot = bucket.snapshot().await.unwrap();
                let calls = server.join().unwrap();
                assert_recovery(
                    op,
                    fail_mode,
                    failed,
                    consumed,
                    snapshot,
                    calls,
                    client.stats(),
                );
            }
        }
    }
}
