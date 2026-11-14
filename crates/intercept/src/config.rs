use serde::Deserializer;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Which broker backs the captures log: `redis_stream` (default, needs
/// `redis_url` and `request_log.*`), `kafka` (needs `[kafka]`; `redpanda` is a
/// deprecated alias) or `rabbitmq` (needs `[rabbitmq]`).
pub use common::log::BrokerKind;

/// Runtime tuning parameters for proxy operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningConfig {
    /// Maximum body capture size in bytes (default: 512KB).
    #[serde(default = "default_max_body_capture")]
    pub max_body_capture: usize,
    /// Maximum individual header value size in bytes (default: 512).
    /// Values exceeding this are truncated before writing to the Redis stream.
    #[serde(default = "default_max_header_capture")]
    pub max_header_capture: usize,
    /// Maximum compressed WebSocket frame and fragmented-message size.
    #[serde(default = "default_max_ws_compressed_message_bytes")]
    pub max_ws_compressed_message_bytes: usize,
    /// Per-tunnel exchange channel capacity (default: 8).
    /// Controls backpressure from the pipeline to the MITM tunnel.
    #[serde(default = "default_exchange_channel_capacity")]
    pub exchange_channel_capacity: usize,
    /// Maximum concurrent connections across all listeners (default: 10000).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Seconds to wait for in-flight tunnels to drain on shutdown before
    /// forcing exit (default: 300). Keep below the pod's
    /// terminationGracePeriodSeconds minus preStop minus the pipeline flush.
    #[serde(default = "default_shutdown_drain_timeout_secs")]
    pub shutdown_drain_timeout_secs: u64,
}

fn default_max_body_capture() -> usize {
    512 * 1024
}
fn default_max_header_capture() -> usize {
    512
}
fn default_max_ws_compressed_message_bytes() -> usize {
    16 * 1024 * 1024
}
fn default_exchange_channel_capacity() -> usize {
    8
}
fn default_max_connections() -> usize {
    10_000
}
fn default_shutdown_drain_timeout_secs() -> u64 {
    300
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            max_body_capture: default_max_body_capture(),
            max_header_capture: default_max_header_capture(),
            max_ws_compressed_message_bytes: default_max_ws_compressed_message_bytes(),
            exchange_channel_capacity: default_exchange_channel_capacity(),
            max_connections: default_max_connections(),
            shutdown_drain_timeout_secs: default_shutdown_drain_timeout_secs(),
        }
    }
}

/// TCP keepalive settings for one side of the proxy (accepted client sockets
/// or sockets dialed upstream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpKeepaliveConfig {
    /// Turn `SO_KEEPALIVE` on. When false the option is switched off.
    pub enabled: bool,
    /// Idle seconds before the first probe (`TCP_KEEPIDLE`).
    pub time_secs: u64,
    /// Seconds between probes (`TCP_KEEPINTVL`).
    pub interval_secs: u64,
    /// Unanswered probes before the connection is dropped (`TCP_KEEPCNT`).
    pub retries: u32,
}

impl Default for TcpKeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            time_secs: 60,
            interval_secs: 20,
            retries: 3,
        }
    }
}

impl TcpKeepaliveConfig {
    fn validate(&self, section: &str) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(
            self.time_secs > 0,
            "{section}.time_secs must be greater than 0"
        );
        anyhow::ensure!(
            self.interval_secs > 0,
            "{section}.interval_secs must be greater than 0"
        );
        anyhow::ensure!(self.retries > 0, "{section}.retries must be greater than 0");
        // The kernel stores these as C ints.
        anyhow::ensure!(
            self.time_secs <= i32::MAX as u64 && self.interval_secs <= i32::MAX as u64,
            "{section}.time_secs and {section}.interval_secs must fit in 31 bits"
        );
        Ok(())
    }
}

/// Network options of the data plane: timeouts, HTTP keep-alive, DNS cache,
/// egress retries and TCP keepalive. The defaults are the values that were
/// hardcoded before these keys existed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Time a client has to send a complete CONNECT or HTTP request head.
    pub client_header_timeout_ms: u64,
    /// Time for the SOCKS5 greeting, authentication and request.
    pub socks_handshake_timeout_ms: u64,
    /// Time for one upstream connect, all retries included.
    pub upstream_connect_timeout_ms: u64,
    /// Time for one TLS handshake, client side or upstream side.
    pub tls_handshake_timeout_ms: u64,
    /// Time the upstream has to send response headers.
    pub upstream_response_header_timeout_ms: u64,
    /// Longest wait for the next bytes of a message body.
    pub body_idle_timeout_ms: u64,
    /// Idle time between two requests on an intercepted client connection.
    pub http_keepalive_idle_timeout_ms: u64,
    /// Requests served on one intercepted client connection before the proxy
    /// closes it. 0 means no limit.
    pub http_keepalive_max_requests: u32,
    /// Wait for the upstream's reply to the HTTP/2 SETTINGS round trip that
    /// precedes a WebSocket upgrade.
    pub h2_settings_timeout_ms: u64,
    /// Lifetime of a cached DNS answer.
    pub dns_cache_ttl_secs: u64,
    /// Attempts for one upstream connect (first try included).
    pub egress_retries: u32,
    /// Waits between attempts; the last value repeats when there are more
    /// attempts than values.
    pub egress_backoffs_ms: Vec<u64>,
    /// Keepalive of accepted client sockets.
    pub client_keepalive: TcpKeepaliveConfig,
    /// Keepalive of upstream sockets: direct dials, egress proxy dials and
    /// private override dials.
    pub upstream_keepalive: TcpKeepaliveConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            client_header_timeout_ms: 5_000,
            socks_handshake_timeout_ms: 5_000,
            upstream_connect_timeout_ms: 10_000,
            tls_handshake_timeout_ms: 10_000,
            upstream_response_header_timeout_ms: 30_000,
            body_idle_timeout_ms: 30_000,
            http_keepalive_idle_timeout_ms: 30_000,
            http_keepalive_max_requests: 0,
            h2_settings_timeout_ms: 2_000,
            dns_cache_ttl_secs: 60,
            egress_retries: 3,
            egress_backoffs_ms: vec![100, 200, 400],
            client_keepalive: TcpKeepaliveConfig::default(),
            upstream_keepalive: TcpKeepaliveConfig::default(),
        }
    }
}

impl NetworkConfig {
    pub fn client_header_timeout(&self) -> Duration {
        Duration::from_millis(self.client_header_timeout_ms)
    }

    pub fn socks_handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.socks_handshake_timeout_ms)
    }

    pub fn upstream_connect_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_connect_timeout_ms)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let timeouts = [
            ("client_header_timeout_ms", self.client_header_timeout_ms),
            (
                "socks_handshake_timeout_ms",
                self.socks_handshake_timeout_ms,
            ),
            (
                "upstream_connect_timeout_ms",
                self.upstream_connect_timeout_ms,
            ),
            ("tls_handshake_timeout_ms", self.tls_handshake_timeout_ms),
            (
                "upstream_response_header_timeout_ms",
                self.upstream_response_header_timeout_ms,
            ),
            ("body_idle_timeout_ms", self.body_idle_timeout_ms),
            (
                "http_keepalive_idle_timeout_ms",
                self.http_keepalive_idle_timeout_ms,
            ),
            ("h2_settings_timeout_ms", self.h2_settings_timeout_ms),
            ("dns_cache_ttl_secs", self.dns_cache_ttl_secs),
        ];
        for (name, value) in timeouts {
            anyhow::ensure!(value > 0, "network.{name} must be greater than 0");
        }
        anyhow::ensure!(
            self.egress_retries > 0,
            "network.egress_retries must be at least 1 (the first attempt counts)"
        );
        anyhow::ensure!(
            !self.egress_backoffs_ms.is_empty(),
            "network.egress_backoffs_ms must list at least one backoff"
        );
        anyhow::ensure!(
            self.egress_backoffs_ms.iter().all(|ms| *ms > 0),
            "network.egress_backoffs_ms values must be greater than 0"
        );
        self.client_keepalive.validate("network.client_keepalive")?;
        self.upstream_keepalive
            .validate("network.upstream_keepalive")?;
        Ok(())
    }
}

/// Settings of the readiness checks behind `/health/ready`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthConfig {
    /// Period of the Redis ping and of the capture pipeline sample.
    pub check_interval_ms: u64,
    /// Time one Redis `PING` may take.
    pub redis_timeout_ms: u64,
    /// Consecutive failed pings that make `redis` fail.
    pub redis_failure_threshold: u32,
    /// The capture queue counts as full at this share of its capacity.
    pub capture_stall_fraction: f64,
    /// How long the queue has to stay full before `capture_pipeline` fails.
    pub capture_stall_window_ms: u64,
    /// Work is queued or being published but nothing was published for this
    /// long: `capture_pipeline` fails.
    pub capture_publish_stale_ms: u64,
    /// Pause between going not-ready and closing the listeners on shutdown,
    /// so a load balancer notices before connections are refused.
    pub drain_notice_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: 2_000,
            redis_timeout_ms: 1_000,
            redis_failure_threshold: 3,
            capture_stall_fraction: 0.9,
            capture_stall_window_ms: 30_000,
            capture_publish_stale_ms: 60_000,
            drain_notice_ms: 0,
        }
    }
}

impl HealthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        let positive = [
            ("check_interval_ms", self.check_interval_ms),
            ("redis_timeout_ms", self.redis_timeout_ms),
            ("capture_stall_window_ms", self.capture_stall_window_ms),
            ("capture_publish_stale_ms", self.capture_publish_stale_ms),
        ];
        for (name, value) in positive {
            anyhow::ensure!(value > 0, "health.{name} must be greater than 0");
        }
        anyhow::ensure!(
            self.redis_failure_threshold > 0,
            "health.redis_failure_threshold must be at least 1"
        );
        anyhow::ensure!(
            self.capture_stall_fraction > 0.0 && self.capture_stall_fraction <= 1.0,
            "health.capture_stall_fraction must be in (0, 1]"
        );
        Ok(())
    }
}

/// CA certificate configuration for MITM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CaConfig {
    /// Load from PROXYX_INTERCEPT_CA_CERT / PROXYX_INTERCEPT_CA_KEY env vars (base64 DER)
    Env,
    /// Load from file paths
    File {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// Generate or load from data directory
    Generate { data_dir: PathBuf },
}

impl Default for CaConfig {
    fn default() -> Self {
        CaConfig::Generate {
            data_dir: PathBuf::from("data"),
        }
    }
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_redis_key_prefix() -> String {
    "proxyx".to_string()
}

fn default_socks_addr() -> SocketAddr {
    "0.0.0.0:1080".parse().unwrap()
}

fn default_api_addr() -> SocketAddr {
    "0.0.0.0:8888".parse().unwrap()
}
fn default_request_log() -> crate::pipeline::RequestLogConfig {
    crate::pipeline::RequestLogConfig::default()
}

fn default_ratelimit() -> crate::ratelimit::RateLimitConfig {
    crate::ratelimit::RateLimitConfig::default()
}

/// Trust policy for TLS connections from the session proxy to origins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Verify certificate chains and hostnames unless an explicit exception applies.
    pub verify_upstream: bool,
    /// Additional PEM CA bundle. System roots remain trusted.
    pub ca_bundle: Option<PathBuf>,
    /// Exact hostnames allowed to use unverified upstream TLS.
    pub insecure_upstream_hosts: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_upstream: true,
            ca_bundle: None,
            insecure_upstream_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Proxy ID (set by PROXYX_INTERCEPT_ID env var, or auto-generated)
    pub id: Option<String>,

    /// CONNECT proxy address (for HTTPS tunneling)
    pub connect_addr: SocketAddr,

    /// HTTP forward proxy address (optional)
    pub http_addr: Option<SocketAddr>,

    /// SOCKS5 proxy address
    #[serde(default = "default_socks_addr")]
    pub socks_addr: SocketAddr,

    /// HTTP admin/session API address
    #[serde(default = "default_api_addr")]
    pub api_addr: SocketAddr,

    /// Redis connection URL
    #[serde(default = "default_redis_url")]
    pub redis_url: String,

    /// Prefix for all Redis keys and pubsub channels.
    /// Default `"proxyx"` produces the legacy key scheme (`proxyx:session:…`).
    /// Set per-instance to isolate dev deployments on a shared Valkey.
    /// Env: `PROXYX_INTERCEPT_REDIS_KEY_PREFIX`.
    #[serde(default = "default_redis_key_prefix")]
    pub redis_key_prefix: String,

    /// Rate limiting configuration
    #[serde(default = "default_ratelimit")]
    pub ratelimit: crate::ratelimit::RateLimitConfig,

    /// Request log writer configuration
    #[serde(default = "default_request_log")]
    pub request_log: crate::pipeline::RequestLogConfig,

    /// CA certificate configuration
    #[serde(default)]
    pub ca: CaConfig,

    /// Upstream certificate verification policy.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Runtime tuning parameters
    #[serde(default)]
    pub tuning: TuningConfig,

    /// Timeouts, HTTP keep-alive, DNS cache, egress retries and TCP keepalive.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Per-upstream circuit breaker.
    #[serde(default)]
    pub breaker: crate::breaker::BreakerConfig,

    /// Readiness checks and drain behavior.
    #[serde(default)]
    pub health: HealthConfig,

    /// Host patterns that are never captured, even when a session includes them.
    /// Accepts a comma-separated env var or a sequence in file config.
    #[serde(default, deserialize_with = "deserialize_host_patterns")]
    pub no_capture_hosts: Vec<String>,

    /// Sentry error tracking configuration
    #[serde(default)]
    pub sentry: common::sentry::SentryConfig,

    /// Broker implementation for the captures log.
    /// `redis_stream` (default), `kafka` or `rabbitmq`.
    #[serde(default)]
    pub broker_kind: BrokerKind,

    /// Kafka broker configuration (required when `broker_kind = "kafka"`).
    #[serde(default, deserialize_with = "common::config::optional_section")]
    pub kafka: Option<common::log::kafka::KafkaConfig>,

    /// Deprecated name of `[kafka]`, accepted for one release.
    #[serde(default, deserialize_with = "common::config::optional_section")]
    pub redpanda: Option<common::log::kafka::KafkaConfig>,

    /// RabbitMQ configuration (required when `broker_kind = "rabbitmq"`).
    #[serde(default, deserialize_with = "common::config::optional_section")]
    pub rabbitmq: Option<common::log::rabbitmq::RabbitMqConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: None,
            connect_addr: "0.0.0.0:8443".parse().unwrap(),
            http_addr: Some("0.0.0.0:8080".parse().unwrap()),
            socks_addr: default_socks_addr(),
            api_addr: default_api_addr(),
            redis_url: default_redis_url(),
            redis_key_prefix: default_redis_key_prefix(),
            ratelimit: default_ratelimit(),
            request_log: default_request_log(),
            ca: CaConfig::default(),
            tls: TlsConfig::default(),
            tuning: TuningConfig::default(),
            network: NetworkConfig::default(),
            breaker: crate::breaker::BreakerConfig::default(),
            health: HealthConfig::default(),
            no_capture_hosts: Vec::new(),
            sentry: common::sentry::SentryConfig::default(),
            broker_kind: BrokerKind::default(),
            kafka: None,
            redpanda: None,
            rabbitmq: None,
        }
    }
}

impl Config {
    /// The capture stream: `request_log.stream_name`, or
    /// `<redis_key_prefix>:request_log`.
    pub fn request_log_stream(&self) -> String {
        self.request_log
            .stream_name
            .clone()
            .unwrap_or_else(|| format!("{}:request_log", self.redis_key_prefix))
    }

    /// The `[kafka]` section, or the deprecated `[redpanda]` one.
    pub fn kafka_config(&self) -> anyhow::Result<Option<&common::log::kafka::KafkaConfig>> {
        common::log::resolve_kafka_section(self.kafka.as_ref(), self.redpanda.as_ref())
    }

    pub fn load(config_path: Option<&str>) -> anyhow::Result<Self> {
        let config: Self = common::config::load("intercept", config_path)?;
        config.validate()?;
        Ok(config)
    }

    /// Reject values that would make the proxy misbehave (zero timeouts and
    /// the like) with an error that names the key.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.network.validate()?;
        self.breaker.validate()?;
        self.health.validate()?;
        self.ratelimit.validate()?;
        if let Some(kafka) = self.kafka_config()? {
            kafka.validate()?;
        }
        if let Some(rabbitmq) = &self.rabbitmq {
            rabbitmq.validate()?;
        }
        Ok(())
    }

    pub fn id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }
}

fn deserialize_host_patterns<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HostPatterns {
        List(Vec<String>),
        Csv(String),
    }

    match HostPatterns::deserialize(deserializer)? {
        HostPatterns::List(patterns) => Ok(patterns),
        HostPatterns::Csv(patterns) => Ok(patterns
            .split(',')
            .map(str::trim)
            .filter(|pattern| !pattern.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> Result<Config, serde_json::Error> {
        let mut value = value;
        value["connect_addr"] = "127.0.0.1:8443".into();
        serde_json::from_value(value)
    }

    /// The capture stream follows `redis_key_prefix` unless it is named.
    #[test]
    fn the_capture_stream_is_under_the_key_prefix_by_default() {
        let stream = |value| parse(value).unwrap().request_log_stream();
        assert_eq!(stream(serde_json::json!({})), "proxyx:request_log");
        assert_eq!(
            stream(serde_json::json!({ "redis_key_prefix": "proxyxb" })),
            "proxyxb:request_log"
        );
        assert_eq!(
            stream(serde_json::json!({
                "redis_key_prefix": "proxyxb",
                "request_log": { "stream_name": "legacy:log" }
            })),
            "legacy:log"
        );
    }

    /// The credentials of a broker this process does not use do not fail the
    /// load; any other incomplete section still does.
    #[test]
    fn credentials_of_an_unselected_broker_are_ignored() {
        let config = parse(serde_json::json!({
            "rabbitmq": { "username": "u", "password": "p" },
            "kafka": { "sasl": { "username": "u", "password": "p" } }
        }))
        .unwrap();
        assert!(config.rabbitmq.is_none() && config.kafka.is_none());
        assert!(parse(serde_json::json!({ "rabbitmq": { "username": "u", "typo": 1 } })).is_err());
    }

    #[test]
    fn upstream_tls_and_compressed_websocket_limits_default_secure() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "connect_addr": "127.0.0.1:8443"
        }))
        .unwrap();
        assert!(config.tls.verify_upstream);
        assert!(config.tls.ca_bundle.is_none());
        assert!(config.tls.insecure_upstream_hosts.is_empty());
        assert_eq!(
            config.tuning.max_ws_compressed_message_bytes,
            16 * 1024 * 1024
        );
    }

    #[test]
    fn upstream_tls_trust_policy_deserializes_explicit_exceptions() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "connect_addr": "127.0.0.1:8443",
            "tls": {
                "verify_upstream": true,
                "ca_bundle": "/etc/proxyx/test-roots.pem",
                "insecure_upstream_hosts": ["test.example"]
            },
            "tuning": { "max_ws_compressed_message_bytes": 1024 }
        }))
        .unwrap();
        assert!(config.tls.verify_upstream);
        assert_eq!(
            config.tls.ca_bundle.unwrap(),
            PathBuf::from("/etc/proxyx/test-roots.pem")
        );
        assert_eq!(config.tls.insecure_upstream_hosts, ["test.example"]);
        assert_eq!(config.tuning.max_ws_compressed_message_bytes, 1024);
    }

    #[test]
    fn no_capture_hosts_accepts_csv_string() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "connect_addr": "0.0.0.0:8443",
            "no_capture_hosts": "pypi.org, *.npmjs.org,, crates.io "
        }))
        .unwrap();

        assert_eq!(
            config.no_capture_hosts,
            vec!["pypi.org", "*.npmjs.org", "crates.io"]
        );
    }

    #[test]
    fn no_capture_hosts_accepts_list() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "connect_addr": "0.0.0.0:8443",
            "no_capture_hosts": ["pypi.org", "*.npmjs.org"]
        }))
        .unwrap();

        assert_eq!(config.no_capture_hosts, vec!["pypi.org", "*.npmjs.org"]);
    }

    #[test]
    fn ratelimit_max_wait_defaults_to_one_second() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "connect_addr": "0.0.0.0:8443"
        }))
        .unwrap();

        assert_eq!(config.ratelimit.rate_limit_max_wait_ms, 1000);
    }

    /// Write `toml` next to a required `connect_addr` and load it the way
    /// the binary does.
    fn load_toml(toml: &str) -> anyhow::Result<Config> {
        let path = std::env::temp_dir().join(format!(
            "proxyx-intercept-config-{}.toml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, format!("connect_addr = \"0.0.0.0:8443\"\n{toml}")).unwrap();
        let loaded = Config::load(path.to_str());
        let _ = std::fs::remove_file(&path);
        loaded
    }

    #[test]
    fn defaults_load_and_validate() {
        let config = load_toml("").unwrap();
        assert_eq!(config.network, NetworkConfig::default());
        assert_eq!(config.breaker, crate::breaker::BreakerConfig::default());
        assert_eq!(config.health, HealthConfig::default());
        assert!(config.breaker.enabled);
        assert!(config.network.client_keepalive.enabled);
        assert!(config.network.upstream_keepalive.enabled);
        assert_eq!(config.ratelimit.limiter_connect_timeout_ms, 1000);
        assert_eq!(config.ratelimit.limiter_io_timeout_ms, 1000);
        assert_eq!(config.ratelimit.limiter_keepalive_secs, 30);
        assert_eq!(config.ratelimit.limiter_breaker_failures, 5);
        assert_eq!(config.ratelimit.limiter_breaker_open_ms, 2000);
    }

    #[test]
    fn network_values_load_from_a_file() {
        let config = load_toml(
            r#"
            [network]
            upstream_connect_timeout_ms = 2500
            http_keepalive_max_requests = 100
            egress_retries = 2
            egress_backoffs_ms = [50]

            [network.upstream_keepalive]
            enabled = false

            [network.client_keepalive]
            time_secs = 30

            [breaker]
            enabled = false

            [health]
            redis_failure_threshold = 5
            "#,
        )
        .unwrap();
        assert_eq!(config.network.upstream_connect_timeout_ms, 2500);
        assert_eq!(config.network.http_keepalive_max_requests, 100);
        assert_eq!(config.network.egress_backoffs_ms, vec![50]);
        assert!(!config.network.upstream_keepalive.enabled);
        assert_eq!(config.network.client_keepalive.time_secs, 30);
        assert_eq!(
            config.network.client_keepalive.interval_secs, 20,
            "unset keys keep defaults"
        );
        assert!(!config.breaker.enabled);
        assert_eq!(config.health.redis_failure_threshold, 5);
    }

    #[test]
    fn invalid_values_are_rejected_with_the_key_named() {
        let cases = [
            (
                "[network]\nupstream_connect_timeout_ms = 0",
                "network.upstream_connect_timeout_ms",
            ),
            (
                "[network]\nclient_header_timeout_ms = 0",
                "network.client_header_timeout_ms",
            ),
            (
                "[network]\nsocks_handshake_timeout_ms = 0",
                "network.socks_handshake_timeout_ms",
            ),
            (
                "[network]\ntls_handshake_timeout_ms = 0",
                "network.tls_handshake_timeout_ms",
            ),
            (
                "[network]\nupstream_response_header_timeout_ms = 0",
                "network.upstream_response_header_timeout_ms",
            ),
            (
                "[network]\nbody_idle_timeout_ms = 0",
                "network.body_idle_timeout_ms",
            ),
            (
                "[network]\nhttp_keepalive_idle_timeout_ms = 0",
                "network.http_keepalive_idle_timeout_ms",
            ),
            (
                "[network]\nh2_settings_timeout_ms = 0",
                "network.h2_settings_timeout_ms",
            ),
            (
                "[network]\ndns_cache_ttl_secs = 0",
                "network.dns_cache_ttl_secs",
            ),
            ("[network]\negress_retries = 0", "network.egress_retries"),
            (
                "[network]\negress_backoffs_ms = []",
                "network.egress_backoffs_ms",
            ),
            (
                "[network]\negress_backoffs_ms = [100, 0]",
                "network.egress_backoffs_ms",
            ),
            (
                "[network.client_keepalive]\ntime_secs = 0",
                "network.client_keepalive.time_secs",
            ),
            (
                "[network.upstream_keepalive]\ninterval_secs = 0",
                "network.upstream_keepalive.interval_secs",
            ),
            (
                "[network.upstream_keepalive]\nretries = 0",
                "network.upstream_keepalive.retries",
            ),
            (
                "[breaker]\nconsecutive_failures = 0",
                "breaker.consecutive_failures",
            ),
            (
                "[breaker]\nopen_duration_ms = 0",
                "breaker.open_duration_ms",
            ),
            (
                "[health]\ncheck_interval_ms = 0",
                "health.check_interval_ms",
            ),
            ("[health]\nredis_timeout_ms = 0", "health.redis_timeout_ms"),
            (
                "[health]\nredis_failure_threshold = 0",
                "health.redis_failure_threshold",
            ),
            (
                "[health]\ncapture_stall_fraction = 0.0",
                "health.capture_stall_fraction",
            ),
            (
                "[health]\ncapture_stall_fraction = 1.5",
                "health.capture_stall_fraction",
            ),
            (
                "[health]\ncapture_stall_window_ms = 0",
                "health.capture_stall_window_ms",
            ),
            (
                "[health]\ncapture_publish_stale_ms = 0",
                "health.capture_publish_stale_ms",
            ),
            (
                "[ratelimit]\nlimiter_connect_timeout_ms = 0",
                "ratelimit.limiter_connect_timeout_ms",
            ),
            (
                "[ratelimit]\nlimiter_io_timeout_ms = 0",
                "ratelimit.limiter_io_timeout_ms",
            ),
            (
                "[ratelimit]\nlimiter_breaker_open_ms = 0",
                "ratelimit.limiter_breaker_open_ms",
            ),
        ];
        for (toml, key) in cases {
            let err = load_toml(toml).expect_err(toml);
            assert!(
                format!("{err:#}").contains(key),
                "{toml:?} was rejected with {err:#}, which does not name {key}"
            );
        }
    }

    #[test]
    fn disabled_features_skip_their_validation() {
        let config = load_toml(
            r#"
            [network.client_keepalive]
            enabled = false
            time_secs = 0

            [breaker]
            enabled = false
            consecutive_failures = 0

            [ratelimit]
            limiter_breaker_failures = 0
            limiter_breaker_open_ms = 0
            limiter_keepalive_secs = 0
            "#,
        )
        .unwrap();
        assert!(!config.network.client_keepalive.enabled);
    }
}
