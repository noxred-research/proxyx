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
//! that stops dialing a dead service after repeated failures. A reused socket
//! gets one fresh connection and replay only if it disconnects before any
//! response byte. Fresh sockets, partial responses and timeouts are not retried.
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
        while let Some(mut conn) = self.pool.lock().pop() {
            if conn.last_used.elapsed() < self.health.config.max_idle {
                conn.reused = true;
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
