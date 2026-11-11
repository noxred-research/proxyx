//! Tokio-based async client, mirroring the synchronous `Client`/`Bucket`/
//! `Connection` API. Shares the plain value types (`FailMode`, `ClientConfig`,
//! `Limits`, `Outcome`, `Snapshot`) with the sync client. Gated behind the
//! `async` feature.

use crate::resilience::{retryable_disconnect, set_keepalive, Health};
use crate::{
    CircuitState, ClientConfig, ClientStats, FailMode, Limits, Outcome, ResilienceConfig, Snapshot,
};
use limiter_proto::{
    decode_consume_results, decode_create_results, decode_drain_results, decode_snapshot_results,
    encode_consume_reqs, encode_create_reqs, encode_drain_reqs, encode_snapshot_reqs, parse_frame,
    ConsumeReq, ConsumeResult, CreateReq, CreateResult, DrainResult, Frame, SnapshotResult, MAGIC,
    MAX_FRAME_BYTES, OP_CONSUME, OP_CREATE, OP_DRAIN, OP_SNAPSHOT, ST_OK, ST_STALE, VERSION,
};
use limiter_proto::{decode_ping_results, encode_ping_reqs, PingResult, OP_PING};
use parking_lot::Mutex;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A single async connection: owns a tokio `TcpStream`, performs the handshake on
/// connect, and frames requests/responses through `limiter-proto`.
pub struct AsyncConnection {
    stream: TcpStream,
    peer: std::net::SocketAddr,
    req: Vec<u8>,
    resp: Vec<u8>,
    /// Set for connections the pooled client opens: exchanges are bounded by
    /// the I/O timeout and report their outcome to the circuit breaker.
    health: Option<Arc<Health>>,
    last_used: Instant,
    reused: bool,
    response_started: bool,
}

/// Run one exchange under the connection's I/O timeout and report the outcome.
/// A timed-out exchange leaves the stream mid-frame, so callers drop the
/// connection on any error (they already do).
async fn observed<T>(
    health: Option<Arc<Health>>,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let Some(health) = health else {
        return fut.await;
    };
    let result = match tokio::time::timeout(health.config.io_timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "limiter exchange timed out",
        )),
    };
    health.observe(&result);
    result
}

impl AsyncConnection {
    /// Connect without timeouts or a breaker. The pooled [`AsyncClient`] uses
    /// the resilient path instead.
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let stream = Self::handshake(TcpStream::connect(addr).await?).await?;
        Self::from_stream(stream, None)
    }

    /// Connect and handshake within the connect timeout, with keepalive.
    async fn connect_with(addr: &str, health: Arc<Health>) -> io::Result<Self> {
        let stream = Self::connect_stream(addr, &health).await?;
        Self::from_stream(stream, Some(health))
    }

    async fn connect_stream(
        addr: impl tokio::net::ToSocketAddrs,
        health: &Health,
    ) -> io::Result<TcpStream> {
        let config = health.config;
        let connected = async {
            let stream = TcpStream::connect(addr).await?;
            if let Some(idle) = config.keepalive {
                set_keepalive(socket2::SockRef::from(&stream), idle)?;
            }
            Self::handshake(stream).await
        };
        match tokio::time::timeout(config.connect_timeout, connected).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "limiter connect timed out",
            )),
        }
    }

    async fn handshake(mut stream: TcpStream) -> io::Result<TcpStream> {
        stream.set_nodelay(true)?;
        let mut hello = [0u8; 5];
        hello[..4].copy_from_slice(&MAGIC);
        hello[4] = VERSION;
        stream.write_all(&hello).await?;
        let mut reply = [0u8; 1];
        stream.read_exact(&mut reply).await?;
        if reply[0] != VERSION {
            return Err(invalid("server rejected handshake"));
        }
        Ok(stream)
    }

    fn from_stream(stream: TcpStream, health: Option<Arc<Health>>) -> io::Result<Self> {
        let peer = stream.peer_addr()?;
        Ok(Self {
            stream,
            peer,
            req: Vec::with_capacity(4096),
            resp: Vec::with_capacity(4096),
            health,
            last_used: Instant::now(),
            reused: false,
            response_started: false,
        })
    }

    async fn read_frame_bytes(&mut self) -> io::Result<()> {
        self.resp.resize(4, 0);
        let mut received = 0;
        while received < 4 {
            let count = self.stream.read(&mut self.resp[received..4]).await?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.response_started = true;
            received += count;
        }
        let frame_len =
            u32::from_be_bytes([self.resp[0], self.resp[1], self.resp[2], self.resp[3]]) as usize;
        if !(5..=MAX_FRAME_BYTES).contains(&frame_len) {
            return Err(invalid("bad response frame length"));
        }
        let total = 4 + frame_len;
        self.resp.resize(total, 0);
        self.stream.read_exact(&mut self.resp[4..total]).await?;
        Ok(())
    }

    async fn exchange_once(&mut self) -> io::Result<()> {
        self.response_started = false;
        self.stream.write_all(&self.req).await?;
        self.read_frame_bytes().await
    }

    async fn exchange(&mut self) -> io::Result<Frame<'_>> {
        let reused = std::mem::take(&mut self.reused);
        let result = self.exchange_once().await;
        if reused && !self.response_started && result.as_ref().is_err_and(retryable_disconnect) {
            let health = self
                .health
                .as_ref()
                .ok_or_else(|| invalid("pooled connection has no health state"))?;
            self.stream = Self::connect_stream(self.peer, health).await?;
            self.exchange_once().await?;
        } else {
            result?;
        }
        parse_frame(&self.resp)?.ok_or_else(|| invalid("incomplete response frame"))
    }

    pub async fn create(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        let health = self.health.clone();
        observed(health, self.create_inner(reqs)).await
    }

    async fn create_inner(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        self.req.clear();
        encode_create_reqs(&mut self.req, reqs);
        let frame = self.exchange().await?;
        if frame.op != OP_CREATE || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_create_results(frame.payload, frame.count)?)
    }

    pub async fn snapshot(&mut self, handles: &[u64]) -> io::Result<Vec<SnapshotResult>> {
        let health = self.health.clone();
        observed(health, self.snapshot_inner(handles)).await
    }

    async fn snapshot_inner(&mut self, handles: &[u64]) -> io::Result<Vec<SnapshotResult>> {
        self.req.clear();
        encode_snapshot_reqs(&mut self.req, handles);
        let frame = self.exchange().await?;
        if frame.op != OP_SNAPSHOT || frame.count != handles.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_snapshot_results(frame.payload, frame.count)?)
    }

    pub async fn consume(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<ConsumeResult>> {
        let health = self.health.clone();
        observed(health, self.consume_inner(reqs)).await
    }

    async fn consume_inner(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<ConsumeResult>> {
        self.req.clear();
        encode_consume_reqs(&mut self.req, reqs);
        let frame = self.exchange().await?;
        if frame.op != OP_CONSUME || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_consume_results(frame.payload, frame.count)?)
    }

    pub async fn drain(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<DrainResult>> {
        let health = self.health.clone();
        observed(health, self.drain_inner(reqs)).await
    }

    async fn drain_inner(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<DrainResult>> {
        self.req.clear();
        encode_drain_reqs(&mut self.req, reqs);
        let frame = self.exchange().await?;
        if frame.op != OP_DRAIN || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_drain_results(frame.payload, frame.count)?)
    }
}

impl AsyncConnection {
    /// Liveness probe: send `token`, expect it echoed with the server's uptime.
    pub async fn ping(&mut self, token: u64) -> io::Result<PingResult> {
        let health = self.health.clone();
        observed(health, self.ping_inner(token)).await
    }

    async fn ping_inner(&mut self, token: u64) -> io::Result<PingResult> {
        self.req.clear();
        encode_ping_reqs(&mut self.req, &[token]);
        let frame = self.exchange().await?;
        if frame.op != OP_PING || frame.count != 1 {
            return Err(invalid("response op/count mismatch"));
        }
        let result = decode_ping_results(frame.payload, frame.count)?[0];
        if result.token != token {
            return Err(invalid("ping token mismatch"));
        }
        Ok(result)
    }
}

struct AsyncInner {
    addr: String,
    pool_size: usize,
    fail_mode: FailMode,
    pool: Mutex<Vec<AsyncConnection>>,
    health: Arc<Health>,
}

impl AsyncInner {
    /// Check out a pooled connection or open a new one. The pool lock is only
    /// held to pop/push, never across the network await.
    async fn take(&self) -> io::Result<AsyncConnection> {
        self.health.allow()?;
        {
            let mut pool = self.pool.lock();
            while let Some(mut conn) = pool.pop() {
                if conn.last_used.elapsed() < self.health.config.max_idle {
                    conn.reused = true;
                    return Ok(conn);
                }
            }
        }
        let conn = AsyncConnection::connect_with(&self.addr, Arc::clone(&self.health)).await;
        if conn.is_err() {
            self.health.failure();
        }
        conn
    }

    fn give(&self, mut conn: AsyncConnection) {
        conn.last_used = Instant::now();
        let mut pool = self.pool.lock();
        if pool.len() < self.pool_size {
            pool.push(conn);
        }
    }
}

/// Pooled async client. Lazy: connections open on first use, so construction
/// never blocks on or fails because of an unreachable server.
#[derive(Clone)]
pub struct AsyncClient {
    inner: Arc<AsyncInner>,
}

impl AsyncClient {
    pub fn connect(addr: impl Into<String>, config: ClientConfig) -> Self {
        Self::connect_with(addr, config, ResilienceConfig::default())
    }

    /// Like [`AsyncClient::connect`] with explicit timeouts, keepalive and breaker.
    pub fn connect_with(
        addr: impl Into<String>,
        config: ClientConfig,
        resilience: ResilienceConfig,
    ) -> Self {
        AsyncClient {
            inner: Arc::new(AsyncInner {
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
    pub async fn ping(&self) -> io::Result<PingResult> {
        let mut conn = self.inner.take().await?;
        let result = conn.ping(0x5058_4c49_4d49_5445).await?;
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

    /// Create-or-update a bucket for `key`. Propagates transport errors and a
    /// server rejection (e.g. slab full).
    pub async fn create(&self, key: &[u8], limits: Limits) -> io::Result<AsyncBucket> {
        let mut conn = self.inner.take().await?;
        let handle = create_on(&mut conn, key, limits).await?;
        self.inner.give(conn);
        Ok(AsyncBucket {
            inner: Arc::clone(&self.inner),
            key: key.into(),
            limits,
            handle: AtomicU64::new(handle),
        })
    }
}

async fn create_on(conn: &mut AsyncConnection, key: &[u8], limits: Limits) -> io::Result<u64> {
    let req = [CreateReq {
        capacity: limits.capacity,
        refill_rate: limits.refill_rate,
        ttl_ns: limits.ttl_ns,
        key,
    }];
    let results = conn.create(&req).await?;
    let res = results[0];
    if res.status != ST_OK {
        return Err(io::Error::other("server rejected create (slab full?)"));
    }
    Ok(res.handle)
}

pub struct AsyncBucket {
    inner: Arc<AsyncInner>,
    key: Box<[u8]>,
    limits: Limits,
    handle: AtomicU64,
}

impl AsyncBucket {
    pub fn handle(&self) -> u64 {
        self.handle.load(Ordering::Relaxed)
    }

    /// Consume `amount` tokens. Transparent re-create + single retry on `STALE`.
    /// On transport failure, returns the fail-mode fallback with `degraded=true`.
    pub async fn consume(&self, amount: u64) -> Outcome {
        match self.try_consume(amount).await {
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

    async fn try_consume(&self, amount: u64) -> io::Result<Outcome> {
        let mut conn = self.inner.take().await?;
        let handle = self.handle.load(Ordering::Relaxed);
        let r = conn.consume(&[ConsumeReq { handle, amount }]).await?[0];
        if r.status != ST_STALE {
            self.inner.give(conn);
            return Ok(outcome(r.allowed, r.remaining, r.retry_after_ns));
        }
        let new_handle = create_on(&mut conn, &self.key, self.limits).await?;
        self.handle.store(new_handle, Ordering::Relaxed);
        let r2 = conn
            .consume(&[ConsumeReq {
                handle: new_handle,
                amount,
            }])
            .await?[0];
        self.inner.give(conn);
        if r2.status == ST_STALE {
            return Err(io::Error::other("persistent stale handle"));
        }
        Ok(outcome(r2.allowed, r2.remaining, r2.retry_after_ns))
    }

    /// Debit up to `amount` tokens for post-hoc accounting; returns how many
    /// were actually drained (never denies). Re-creates once on `STALE`.
    /// Propagates transport errors (the caller decides best-effort handling).
    pub async fn drain(&self, amount: u64) -> io::Result<u64> {
        let mut conn = self.inner.take().await?;
        let handle = self.handle.load(Ordering::Relaxed);
        let r = conn.drain(&[ConsumeReq { handle, amount }]).await?[0];
        if r.status != ST_STALE {
            self.inner.give(conn);
            return Ok(r.drained);
        }
        let new_handle = create_on(&mut conn, &self.key, self.limits).await?;
        self.handle.store(new_handle, Ordering::Relaxed);
        let r2 = conn
            .drain(&[ConsumeReq {
                handle: new_handle,
                amount,
            }])
            .await?[0];
        self.inner.give(conn);
        Ok(r2.drained)
    }

    /// Read the bucket's current state. Re-creates once on `STALE`. Propagates
    /// transport errors (read plane is not faked).
    pub async fn snapshot(&self) -> io::Result<Snapshot> {
        let mut conn = self.inner.take().await?;
        let handle = self.handle.load(Ordering::Relaxed);
        let s = conn.snapshot(&[handle]).await?[0];
        let s = if s.status == ST_STALE {
            let new_handle = create_on(&mut conn, &self.key, self.limits).await?;
            self.handle.store(new_handle, Ordering::Relaxed);
            conn.snapshot(&[new_handle]).await?[0]
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
    use crate::resilience::ResilienceConfig;
    use socket2::SockRef;

    #[tokio::test]
    async fn async_connections_carry_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 5];
            stream.read_exact(&mut hello).await.unwrap();
            stream.write_all(&[VERSION]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        });
        let health = Arc::new(Health::new(ResilienceConfig {
            keepalive: Some(std::time::Duration::from_secs(42)),
            ..ResilienceConfig::default()
        }));
        let conn = AsyncConnection::connect_with(&addr.to_string(), health)
            .await
            .unwrap();
        let sock = SockRef::from(&conn.stream);
        assert!(sock.keepalive().unwrap());
        assert_eq!(
            sock.tcp_keepalive_time().unwrap(),
            std::time::Duration::from_secs(42)
        );
        assert_eq!(
            sock.tcp_keepalive_interval().unwrap(),
            std::time::Duration::from_secs(7)
        );
        assert_eq!(sock.tcp_keepalive_retries().unwrap(), 3);
    }
}
