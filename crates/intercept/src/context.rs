use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::breaker::BreakerConfig;
use crate::config::{Config, NetworkConfig, TlsConfig, TuningConfig};
use crate::egress::Egress;
use crate::mitm::{CertificateAuthority, MitmHandler};
use crate::pipeline::RequestLogWriter;
use crate::ratelimit::RateLimiter;
use crate::state::ProxyState;

/// The settings the data plane reads: capture limits, network options and the
/// upstream breaker. `ProxySettings::from(&config)` takes them from the
/// loaded configuration.
#[derive(Debug, Clone, Default)]
pub struct ProxySettings {
    pub tuning: TuningConfig,
    pub network: NetworkConfig,
    pub breaker: BreakerConfig,
    pub tls: TlsConfig,
}

impl From<&Config> for ProxySettings {
    fn from(config: &Config) -> Self {
        Self {
            tuning: config.tuning.clone(),
            network: config.network.clone(),
            breaker: config.breaker.clone(),
            tls: config.tls.clone(),
        }
    }
}

pub struct ProxyContext {
    pub state: ProxyState,
    pub ratelimit: Arc<dyn RateLimiter>,
    pub egress: Egress,
    pub mitm: MitmHandler,
    pub pipeline: Arc<RequestLogWriter>,
    pub exchange_channel_capacity: usize,
    /// Per-message WebSocket payload capture cap. Defaults to `max_body_capture`.
    pub max_ws_payload_capture: usize,
    pub max_ws_compressed_message_bytes: usize,
    /// Capture PING/PONG too. CLOSE is always captured. Default false.
    pub capture_ws_control_frames: bool,
    /// Global connection semaphore — limits concurrent connection tasks.
    pub conn_semaphore: Arc<Semaphore>,
    /// Timeouts and socket options of the data plane.
    pub network: NetworkConfig,
    max_connections: usize,
}

/// Why [`ProxyContext::admit`] did not let a connection in.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `tuning.max_connections` connections are already open.
    LimitReached,
    /// The semaphore was closed: the proxy is shutting down.
    Closed,
}

/// An admitted client connection. Holds one connection permit and counts the
/// connection in `proxyx_intercept_connections_active` until dropped.
pub struct ConnSlot {
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        common::metrics::PROXY_CONNECTIONS_ACTIVE.dec();
    }
}

impl ProxyContext {
    pub fn new(
        state: ProxyState,
        ca: CertificateAuthority,
        ratelimit: Arc<dyn RateLimiter>,
        pipeline: Arc<RequestLogWriter>,
        settings: ProxySettings,
    ) -> anyhow::Result<Self> {
        let ProxySettings {
            tuning,
            network,
            breaker,
            tls,
        } = settings;
        // For now WS payload cap mirrors HTTP body cap. A separate knob can
        // be plumbed through TuningConfig if WS volume requires it.
        let max_ws_payload_capture = tuning.max_body_capture;
        let capture_ws_control_frames = false;
        // One shared Egress: the MITM fallback dialer reuses the same DNS
        // cache, breakers and egress-proxy routing as the primary path.
        let egress = Egress::new(&network, &breaker);
        Ok(Self {
            ratelimit,
            mitm: MitmHandler::new(
                Arc::new(ca),
                tuning.max_body_capture,
                tuning.max_header_capture,
                egress.clone(),
                &network,
                &tls,
            )?,
            egress,
            state,
            pipeline,
            exchange_channel_capacity: tuning.exchange_channel_capacity,
            max_ws_payload_capture,
            max_ws_compressed_message_bytes: tuning.max_ws_compressed_message_bytes,
            capture_ws_control_frames,
            conn_semaphore: Arc::new(Semaphore::new(tuning.max_connections)),
            network,
            max_connections: tuning.max_connections,
        })
    }

    /// Connections currently holding a permit.
    pub fn active_connections(&self) -> usize {
        self.max_connections
            .saturating_sub(self.conn_semaphore.available_permits())
    }

    /// Take a connection slot for an accepted client socket and apply the
    /// client socket options. Never waits: at the limit the connection is
    /// refused (and counted in
    /// `proxyx_intercept_connection_limit_refusals_total`), so a flood cannot
    /// queue accepted sockets without bound.
    pub fn admit(&self, stream: &TcpStream) -> Result<ConnSlot, Refusal> {
        match self.conn_semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                common::metrics::PROXY_CONNECTIONS_ACTIVE.inc();
                crate::net::configure(stream, &self.network.client_keepalive, "client");
                Ok(ConnSlot { _permit: permit })
            }
            Err(TryAcquireError::NoPermits) => {
                common::metrics::PROXY_CONNECTION_LIMIT_REFUSALS_TOTAL.inc();
                Err(Refusal::LimitReached)
            }
            Err(TryAcquireError::Closed) => Err(Refusal::Closed),
        }
    }
}
