//! Timeouts, TCP keepalive and a circuit breaker for the client's transport.
//!
//! The breaker counts transport failures only (connect, write, read, timeout,
//! malformed frames). A server that answers `FULL` or `STALE` is alive, so
//! those replies count as successes. While open, no connection is attempted:
//! callers see an immediate error and the data plane falls back per
//! `FailMode` without waiting on a dead or blackholed service.

use parking_lot::Mutex;
use socket2::{SockRef, TcpKeepalive};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Circuit breaker thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Consecutive transport failures that open the circuit.
    pub failure_threshold: u32,
    /// How long the circuit stays open before one probe is let through.
    pub open_duration: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(2),
        }
    }
}

/// Transport behaviour of a client. The defaults suit a limiter on the same
/// host or the same network segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResilienceConfig {
    /// TCP connect plus handshake budget.
    pub connect_timeout: Duration,
    /// Budget for one request/response exchange on an open connection.
    pub io_timeout: Duration,
    /// Drop pooled connections idle this long before checkout (default 30 seconds).
    pub max_idle: Duration,
    /// Idle time before the first TCP keepalive probe; `None` leaves keepalive off.
    pub keepalive: Option<Duration>,
    /// `None` disables the breaker: every operation tries the network.
    pub breaker: Option<BreakerConfig>,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(1),
            max_idle: Duration::from_secs(30),
            keepalive: Some(Duration::from_secs(30)),
            breaker: Some(BreakerConfig::default()),
        }
    }
}

/// Only clean disconnects before a response starts permit replay on a reused socket.
pub(crate) fn retryable_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

/// Circuit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    /// One probe operation is in flight; the rest still fail fast.
    HalfOpen,
}

/// Cumulative counters since the client was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Operations that failed on the transport (including timeouts).
    pub transport_errors: u64,
    /// Operations refused without a network attempt because the circuit was open.
    pub circuit_rejections: u64,
    /// `consume` calls answered by the fail-mode fallback.
    pub degraded: u64,
    /// Times the circuit opened.
    pub circuit_opens: u64,
}

enum Phase {
    Closed { failures: u32 },
    Open { since: Instant },
    HalfOpen { probe_started: Instant },
}

/// Shared by every connection and bucket of one client.
pub(crate) struct Health {
    pub(crate) config: ResilienceConfig,
    phase: Mutex<Phase>,
    transport_errors: AtomicU64,
    circuit_rejections: AtomicU64,
    degraded: AtomicU64,
    circuit_opens: AtomicU64,
}

impl Health {
    pub(crate) fn new(config: ResilienceConfig) -> Self {
        Self {
            config,
            phase: Mutex::new(Phase::Closed { failures: 0 }),
            transport_errors: AtomicU64::new(0),
            circuit_rejections: AtomicU64::new(0),
            degraded: AtomicU64::new(0),
            circuit_opens: AtomicU64::new(0),
        }
    }

    /// Ask to start a network operation. `Err` means the circuit is open.
    pub(crate) fn allow(&self) -> io::Result<()> {
        let Some(breaker) = self.config.breaker else {
            return Ok(());
        };
        let mut phase = self.phase.lock();
        let now = Instant::now();
        match *phase {
            Phase::Closed { .. } => Ok(()),
            Phase::Open { since } if now.duration_since(since) >= breaker.open_duration => {
                *phase = Phase::HalfOpen { probe_started: now };
                Ok(())
            }
            // A probe whose future was dropped never reports back; after one
            // open period let another through rather than stay half-open forever.
            Phase::HalfOpen { probe_started }
                if now.duration_since(probe_started) >= breaker.open_duration =>
            {
                *phase = Phase::HalfOpen { probe_started: now };
                Ok(())
            }
            Phase::Open { .. } | Phase::HalfOpen { .. } => {
                self.circuit_rejections.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "limiter circuit open",
                ))
            }
        }
    }

    pub(crate) fn success(&self) {
        if self.config.breaker.is_none() {
            return;
        }
        *self.phase.lock() = Phase::Closed { failures: 0 };
    }

    pub(crate) fn failure(&self) {
        self.transport_errors.fetch_add(1, Ordering::Relaxed);
        let Some(breaker) = self.config.breaker else {
            return;
        };
        let mut phase = self.phase.lock();
        let opens = match *phase {
            Phase::Closed { failures } => failures + 1 >= breaker.failure_threshold.max(1),
            Phase::HalfOpen { .. } => true,
            Phase::Open { .. } => false,
        };
        if opens {
            *phase = Phase::Open {
                since: Instant::now(),
            };
            self.circuit_opens.fetch_add(1, Ordering::Relaxed);
        } else if let Phase::Closed { failures } = &mut *phase {
            *failures += 1;
        }
    }

    /// Record the outcome of one exchange.
    pub(crate) fn observe<T>(&self, result: &io::Result<T>) {
        match result {
            Ok(_) => self.success(),
            Err(_) => self.failure(),
        }
    }

    pub(crate) fn degraded(&self) {
        self.degraded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn state(&self) -> CircuitState {
        match *self.phase.lock() {
            Phase::Closed { .. } => CircuitState::Closed,
            Phase::Open { .. } => CircuitState::Open,
            Phase::HalfOpen { .. } => CircuitState::HalfOpen,
        }
    }

    pub(crate) fn stats(&self) -> ClientStats {
        ClientStats {
            transport_errors: self.transport_errors.load(Ordering::Relaxed),
            circuit_rejections: self.circuit_rejections.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
            circuit_opens: self.circuit_opens.load(Ordering::Relaxed),
        }
    }
}

/// Turn on TCP keepalive: first probe after `idle`, then every `idle / 6`
/// (at least 1 s), dropping the peer after 3 unanswered probes.
pub(crate) fn set_keepalive(sock: SockRef<'_>, idle: Duration) -> io::Result<()> {
    let interval = (idle / 6).max(Duration::from_secs(1));
    sock.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(idle)
            .with_interval(interval)
            .with_retries(3),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(threshold: u32, open_ms: u64) -> Health {
        Health::new(ResilienceConfig {
            breaker: Some(BreakerConfig {
                failure_threshold: threshold,
                open_duration: Duration::from_millis(open_ms),
            }),
            ..ResilienceConfig::default()
        })
    }

    #[test]
    fn opens_after_consecutive_failures_and_rejects() {
        let h = health(3, 10_000);
        for _ in 0..2 {
            h.failure();
        }
        assert_eq!(h.state(), CircuitState::Closed);
        h.failure();
        assert_eq!(h.state(), CircuitState::Open);
        assert!(h.allow().is_err());
        assert_eq!(h.stats().circuit_rejections, 1);
        assert_eq!(h.stats().circuit_opens, 1);
    }

    #[test]
    fn a_success_resets_the_failure_run() {
        let h = health(3, 10_000);
        h.failure();
        h.failure();
        h.success();
        h.failure();
        h.failure();
        assert_eq!(h.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_lets_one_probe_through_then_closes_or_reopens() {
        let h = health(1, 30);
        h.failure();
        assert!(h.allow().is_err());
        std::thread::sleep(Duration::from_millis(40));
        assert!(h.allow().is_ok());
        assert_eq!(h.state(), CircuitState::HalfOpen);
        assert!(h.allow().is_err(), "only one probe at a time");
        h.failure();
        assert_eq!(h.state(), CircuitState::Open);
        assert_eq!(h.stats().circuit_opens, 2);

        std::thread::sleep(Duration::from_millis(40));
        assert!(h.allow().is_ok());
        h.success();
        assert_eq!(h.state(), CircuitState::Closed);
        assert!(h.allow().is_ok());
    }

    #[test]
    fn a_lost_probe_does_not_wedge_half_open() {
        let h = health(1, 30);
        h.failure();
        std::thread::sleep(Duration::from_millis(40));
        assert!(h.allow().is_ok());
        std::thread::sleep(Duration::from_millis(40));
        assert!(h.allow().is_ok());
    }

    #[test]
    fn disabled_breaker_never_rejects() {
        let h = Health::new(ResilienceConfig {
            breaker: None,
            ..ResilienceConfig::default()
        });
        for _ in 0..100 {
            h.failure();
        }
        assert!(h.allow().is_ok());
        assert_eq!(h.state(), CircuitState::Closed);
        assert_eq!(h.stats().transport_errors, 100);
    }
}
