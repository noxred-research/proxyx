//! The rate-limit service (`proxyx limiter`): a single-process, in-memory rate-limit daemon. Thread per
//! connection; a lock-free generational slab of token buckets keyed by an opaque
//! name on `create`, addressed by u64 handle on the hot path; a background TTL
//! reaper. State is intentionally not durable: restart resets every bucket.
//!
//! Operations surface: an optional plain-HTTP port (`PROXYX_LIMITER_METRICS_ADDR`)
//! with `/healthz`, `/readyz` and `/metrics`, a `PING` op on the data protocol,
//! a connection cap and TCP keepalive on accepted sockets.

mod conn;
mod http;
mod reaper;
mod state;
mod stats;

use socket2::{SockRef, TcpKeepalive};
use state::Registry;
use stats::{ConnGuard, Stats};
use std::env;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_ADDR: &str = "127.0.0.1:39091";
const DEFAULT_MAX_BUCKETS: usize = 1 << 20;
const DEFAULT_SHARDS: usize = 256;
const DEFAULT_REAPER_MS: u64 = 1000;
const DEFAULT_MAX_CONNECTIONS: usize = 4096;
const DEFAULT_KEEPALIVE_SECS: u64 = 60;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn _exit(code: i32) -> !;
}

// In-memory state is intentionally discarded on shutdown; exit cleanly so a
// SIGTERM from an orchestrator yields status 0 rather than 143.
extern "C" fn on_term(_sig: i32) {
    unsafe { _exit(0) }
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// Default listen address of `proxyx limiter`.
pub const DEFAULT_LISTEN: &str = DEFAULT_ADDR;

/// Service tuning. [`Config::from_env`] reads the `PROXYX_LIMITER_*` variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Capacity of the bucket slab (rounded up to a power of two).
    pub max_buckets: usize,
    /// Shards of the name index.
    pub shards: usize,
    /// TTL reaper interval.
    pub reaper_interval: Duration,
    /// Open connections above this are accepted and dropped at once (one OS
    /// thread per connection, so the cap bounds threads and memory).
    pub max_connections: usize,
    /// Absolute budget to complete the handshake, measured from acceptance.
    pub handshake_timeout: Duration,
    /// Maximum time without read progress on an established connection.
    pub idle_timeout: Duration,
    /// Idle time before the first TCP keepalive probe on accepted sockets;
    /// probes then repeat every `keepalive / 6` (at least 1 s) and the peer is
    /// dropped after 3 unanswered probes. `None` leaves keepalive off.
    pub keepalive: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_buckets: DEFAULT_MAX_BUCKETS,
            shards: DEFAULT_SHARDS,
            reaper_interval: Duration::from_millis(DEFAULT_REAPER_MS),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS),
            keepalive: Some(Duration::from_secs(DEFAULT_KEEPALIVE_SECS)),
        }
    }
}

impl Config {
    /// `PROXYX_LIMITER_MAX_BUCKETS`, `_SHARDS`, `_REAPER_MS`, `_MAX_CONNECTIONS`,
    /// `_IDLE_TIMEOUT_MS` and `_TCP_KEEPALIVE_SECS` (`0` turns keepalive off).
    /// Unset, unparsable or zero values (except keepalive) use the defaults.
    pub fn from_env() -> Self {
        let keepalive = match env::var("PROXYX_LIMITER_TCP_KEEPALIVE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            Some(0) => None,
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Some(Duration::from_secs(DEFAULT_KEEPALIVE_SECS)),
        };
        Self {
            max_buckets: env_usize("PROXYX_LIMITER_MAX_BUCKETS", DEFAULT_MAX_BUCKETS),
            shards: env_usize("PROXYX_LIMITER_SHARDS", DEFAULT_SHARDS),
            reaper_interval: Duration::from_millis(env_u64(
                "PROXYX_LIMITER_REAPER_MS",
                DEFAULT_REAPER_MS,
            )),
            max_connections: env_usize("PROXYX_LIMITER_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: Duration::from_millis(env_u64(
                "PROXYX_LIMITER_IDLE_TIMEOUT_MS",
                DEFAULT_IDLE_TIMEOUT_MS,
            )),
            keepalive,
        }
    }
}

/// A running service: bound addresses and the accept thread.
pub struct Running {
    /// Where the data protocol listens.
    pub addr: SocketAddr,
    /// Where `/healthz`, `/readyz` and `/metrics` listen, when enabled.
    pub metrics_addr: Option<SocketAddr>,
    /// Bucket capacity of the slab.
    pub capacity: usize,
    accept: thread::JoinHandle<()>,
}

impl Running {
    /// Block for the life of the service. The accept loop only ends if the
    /// listener fails.
    pub fn wait(self) {
        let _ = self.accept.join();
    }
}

/// Bind and start serving without installing signal handlers: the accept loop,
/// the TTL reaper and, when `metrics_addr` is given, the operations endpoint
/// all run on background threads. Returns once the listeners are bound.
pub fn spawn(addr: &str, metrics_addr: Option<&str>, config: &Config) -> std::io::Result<Running> {
    let registry = Arc::new(Registry::new(config.max_buckets, config.shards));
    let stats = Arc::new(Stats::default());
    reaper::spawn(Arc::clone(&registry), config.reaper_interval);

    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    let metrics_listener = metrics_addr.map(TcpListener::bind).transpose()?;
    let metrics_addr = metrics_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    if let Some(metrics_listener) = metrics_listener {
        let (registry, stats) = (Arc::clone(&registry), Arc::clone(&stats));
        thread::spawn(move || http::serve(metrics_listener, registry, stats));
    }

    let capacity = registry.capacity();
    let (max_connections, keepalive) = (config.max_connections as u64, config.keepalive);
    let (handshake_timeout, idle_timeout) = (config.handshake_timeout, config.idle_timeout);
    let accept = thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handshake_deadline = Instant::now() + handshake_timeout;
            if stats.connections.load(Ordering::Relaxed) >= max_connections {
                Stats::add(&stats.connections_refused, 1);
                continue;
            }
            // Best effort: a socket that refuses an option is still served.
            let _ = stream.set_nodelay(true);
            if let Some(idle) = keepalive {
                let _ = set_keepalive(&stream, idle);
            }
            stats.connections.fetch_add(1, Ordering::Relaxed);
            let guard = ConnGuard(Arc::clone(&stats));
            let (registry, stats) = (Arc::clone(&registry), Arc::clone(&stats));
            thread::spawn(move || {
                let _guard = guard;
                let _ =
                    conn::handle_client(stream, registry, stats, handshake_deadline, idle_timeout);
            });
        }
    });
    Ok(Running {
        addr,
        metrics_addr,
        capacity,
        accept,
    })
}

fn set_keepalive(stream: &TcpStream, idle: Duration) -> std::io::Result<()> {
    let interval = (idle / 6).max(Duration::from_secs(1));
    SockRef::from(stream).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(idle)
            .with_interval(interval)
            .with_retries(3),
    )
}

/// Serve the rate-limit protocol on `addr` until SIGTERM or SIGINT, which exit
/// the process with status 0 (state is intentionally not durable). Prints
/// `READY <addr> max_buckets=<n>` on stdout once listening, then
/// `METRICS <addr>` when `PROXYX_LIMITER_METRICS_ADDR` enables the operations
/// endpoint.
pub fn run(addr: &str) -> std::io::Result<()> {
    let config = Config::from_env();
    let metrics_addr = env::var("PROXYX_LIMITER_METRICS_ADDR")
        .ok()
        .filter(|v| !v.trim().is_empty());

    // SAFETY: installing async-signal-safe handlers (`_exit`) before serving.
    unsafe {
        signal(SIGTERM, on_term);
        signal(SIGINT, on_term);
    }

    let running = spawn(addr, metrics_addr.as_deref(), &config)?;
    println!("READY {} max_buckets={}", running.addr, running.capacity);
    if let Some(metrics_addr) = running.metrics_addr {
        println!("METRICS {metrics_addr}");
    }
    running.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_is_applied_to_accepted_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        set_keepalive(&accepted, Duration::from_secs(60)).unwrap();
        let sock = SockRef::from(&accepted);
        assert!(sock.keepalive().unwrap());
        assert_eq!(sock.tcp_keepalive_time().unwrap(), Duration::from_secs(60));
        assert_eq!(
            sock.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(sock.tcp_keepalive_retries().unwrap(), 3);
    }

    #[test]
    fn default_config_matches_documented_values() {
        let config = Config::default();
        assert_eq!(config.max_buckets, 1 << 20);
        assert_eq!(config.shards, 256);
        assert_eq!(config.reaper_interval, Duration::from_millis(1000));
        assert_eq!(config.max_connections, 4096);
        assert_eq!(config.keepalive, Some(Duration::from_secs(60)));
    }
}
