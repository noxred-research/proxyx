use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

fn default_traffic_views_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_traffic_views_ttl_secs() -> u64 {
    86_400 // 24 h
}

// Tuned for tables with wide body columns (multi-MB response_body values).
// preferred_block_size_bytes=32MB prevents the MergeTree reader from
// allocating GiB-scale blocks when decompressing wide string columns.
fn default_export_preferred_block_size_bytes() -> u64 {
    33_554_432 // 32 MiB
}
fn default_export_max_block_size() -> u64 {
    5_000
}
fn default_export_row_group_size_bytes() -> u64 {
    134_217_728 // 128 MiB
}
fn default_export_row_group_size() -> u64 {
    10_000
}

fn default_cloudfront_domain() -> String {
    String::new()
}
fn default_correlation_id_header() -> Option<String> {
    Some("X-ProxyX-Agent".to_string())
}

fn default_parent_correlation_id_header() -> Option<String> {
    Some("X-ProxyX-Parent-Agent".to_string())
}
fn default_account_id_header() -> Option<String> {
    Some("X-ProxyX-Account".to_string())
}

fn default_tool_call_id_header() -> Option<String> {
    Some("X-ProxyX-Tool".to_string())
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

/// Which broker backs the captures log: `redis_stream` (default), `kafka`
/// (needs `[kafka]`; `redpanda` is a deprecated alias) or `rabbitmq` (needs
/// `[rabbitmq]`).
pub use common::log::BrokerKind;

/// Object store that receives traffic view Parquet exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficViewsBackend {
    /// AWS S3 (default). ClickHouse writes via `s3()`; downloads are
    /// CloudFront-signed URLs.
    #[default]
    S3,
    /// Azure Blob Storage. ClickHouse writes via `azureBlobStorage()` using
    /// its own workload identity; downloads are user-delegation SAS URLs.
    Azure,
}

/// How control-plane API callers authenticate; see [`ControlConfig::auth_mode`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Bearer API keys stored hashed in Postgres.
    #[default]
    Keys,
    /// Principal headers set by a trusted, authenticating gateway.
    TrustedHeaders,
}

fn default_env() -> String {
    "dev".to_string()
}
/// CA certificate configuration for session responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CaConfig {
    /// Load from PROXYX_CONTROL_CA_CERT env var (PEM string)
    Env,
    /// Load from file path
    File { cert_path: PathBuf },
    /// Generate or load from data directory (dev only)
    Generate { data_dir: PathBuf },
}

impl Default for CaConfig {
    fn default() -> Self {
        CaConfig::Generate {
            data_dir: PathBuf::from("data"),
        }
    }
}

fn default_api_addr() -> SocketAddr {
    "0.0.0.0:9000".parse().unwrap()
}

fn default_ingester_health_addr() -> SocketAddr {
    "0.0.0.0:9001".parse().unwrap()
}

fn default_request_log_stream() -> String {
    "proxyx:request_log".to_string()
}

fn default_request_log_max_stream_len() -> u64 {
    1_000_000
}

fn default_consumer_group() -> String {
    "proxyx_control".to_string()
}

fn default_session_default_ttl_secs() -> u32 {
    600
}

fn default_proxy_public_host() -> String {
    "localhost:8443".to_string()
}

fn default_redis_key_prefix() -> String {
    "proxyx".to_string()
}

fn default_proxy_public_host_socks5() -> String {
    "localhost:1080".to_string()
}

fn default_session_lifecycle_writes() -> bool {
    true
}

/// Request limits of the control API.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpLimits {
    /// A request still running after this long is answered `504`; `0` disables.
    pub request_timeout_secs: u64,
    /// Requests served at once; one more is answered `503` with `Retry-After: 1`.
    /// `0` disables.
    pub max_in_flight: usize,
    /// Sustained requests per second in independent source-address and credential
    /// buckets; either limit answers `429`. Source addresses use the transport
    /// peer IP, not forwarded headers. Credentials use normalized bearer tokens
    /// or trusted-header organization and principal identities. `0` disables both.
    pub per_key_rps: f64,
    /// Burst allowance of each source-address and credential bucket.
    pub per_key_burst: f64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            request_timeout_secs: 60,
            max_in_flight: 1024,
            per_key_rps: 100.0,
            per_key_burst: 200.0,
        }
    }
}

/// API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Current environment (`dev`, `staging`, `prod`).
    #[serde(default = "default_env")]
    pub env: String,

    /// Enable development conveniences only when explicitly configured.
    #[serde(default)]
    pub debug: bool,

    /// How API callers authenticate (`PROXYX_CONTROL_AUTH_MODE`):
    /// `keys` (default) checks `Authorization: Bearer pxk_...` against the
    /// `api_keys` table; `trusted_headers` trusts `x-proxyx-*` principal
    /// headers set by an authenticating gateway in front of the API, and then
    /// also requires the `X-Forwarded-For` client to be in
    /// `internal_allowed_cidrs` outside `env = "dev"`.
    #[serde(default)]
    pub auth_mode: AuthMode,

    /// Request limits of the control API (`[http]`, `PROXYX_CONTROL_HTTP__*`).
    #[serde(default)]
    pub http: HttpLimits,

    /// Comma-separated CIDR allowlist for `/rpc/*` in `trusted_headers` mode;
    /// enforced outside dev.
    #[serde(default)]
    pub internal_allowed_cidrs: String,

    /// PostgreSQL connection URL for org data and migrations.
    #[serde(default)]
    pub database_url: String,

    /// API server bind address
    #[serde(default = "default_api_addr")]
    pub api_addr: SocketAddr,

    /// Ingester health server bind address.
    #[serde(default = "default_ingester_health_addr")]
    pub ingester_health_addr: SocketAddr,

    /// Redis connection URL. Required for the API and session manager.
    /// Optional for the ingester when `broker_kind = "redpanda"`.
    #[serde(default = "default_redis_url")]
    pub redis_url: String,

    /// Prefix for all Redis keys, streams, and pubsub channels.
    /// Default `"proxyx"` produces the legacy key scheme (`proxyx:session:…`).
    /// Set per-instance to isolate dev deployments on a shared Valkey.
    /// Env: `PROXYX_CONTROL_REDIS_KEY_PREFIX`.
    #[serde(default = "default_redis_key_prefix")]
    pub redis_key_prefix: String,

    /// ClickHouse connection and ingest settings. Required when
    /// `capture_store.backend = "clickhouse"` (the default); see
    /// [`ControlConfig::clickhouse_config`].
    #[serde(default)]
    pub clickhouse: Option<crate::pipeline::clickhouse::ClickHouseConfig>,

    /// Which store holds captures: `clickhouse` (default) or `opensearch`
    /// (also Elasticsearch 8). Env: `PROXYX_CONTROL_CAPTURE_STORE__BACKEND`.
    #[serde(default)]
    pub capture_store: crate::capture_store::CaptureStoreConfig,

    /// Redis stream name for request logs
    #[serde(default = "default_request_log_stream")]
    pub request_log_stream: String,

    /// Approximate cap on the Redis stream length (`XADD ... MAXLEN ~ N`).
    /// 0 disables trimming. Default: 1_000_000. Should match the proxy's
    /// `request_log.max_stream_len`.
    #[serde(default = "default_request_log_max_stream_len")]
    pub request_log_max_stream_len: u64,

    /// Consumer group name for request log stream
    #[serde(default = "default_consumer_group")]
    pub consumer_group: String,

    /// Default session TTL in seconds
    #[serde(default = "default_session_default_ttl_secs")]
    pub session_default_ttl_secs: u32,

    /// Whether the ingester marks `session_lifecycle` rows `closed` after
    /// its ClickHouse flush. Turn off on an ingester whose cluster does not
    /// serve reads, so only the serving side closes sessions.
    /// Env: `PROXYX_CONTROL_SESSION_LIFECYCLE_WRITES`.
    #[serde(default = "default_session_lifecycle_writes")]
    pub session_lifecycle_writes: bool,

    /// Default rate limit RPM for sessions with unknown orgs (0 = unlimited).
    #[serde(default)]
    pub default_rate_limit_rpm: u32,

    /// Default rate limit burst for sessions with unknown orgs (0 = unlimited).
    #[serde(default)]
    pub default_rate_limit_burst: u32,

    /// CA certificate configuration
    #[serde(default)]
    pub ca: CaConfig,

    /// Public `host:port` of the proxy CONNECT endpoint.
    /// Used to build authenticated proxy URLs in `CreateSessionResponse`.
    #[serde(default = "default_proxy_public_host")]
    pub proxy_public_host: String,

    /// Public `host:port` of the proxy SOCKS5 endpoint.
    #[serde(default = "default_proxy_public_host_socks5")]
    pub proxy_public_host_socks5: String,

    /// HTTP header name to extract as `correlation_id` for stored captures.
    /// `None` disables extraction — `correlation_id` stays NULL in CH.
    /// Lookup is case-insensitive against `request_headers`.
    /// Env: `PROXYX_CONTROL_CORRELATION_ID_HEADER`.
    #[serde(default = "default_correlation_id_header")]
    pub correlation_id_header: Option<String>,

    /// HTTP header name to extract as `parent_correlation_id` for stored captures.
    /// `None` disables extraction — `parent_correlation_id` stays NULL in CH.
    /// Lookup is case-insensitive against `request_headers`.
    /// Env: `PROXYX_CONTROL_PARENT_CORRELATION_ID_HEADER`.
    #[serde(default = "default_parent_correlation_id_header")]
    pub parent_correlation_id_header: Option<String>,

    /// HTTP header name to extract as `account_id` for stored captures.
    /// `None` disables extraction — `account_id` stays NULL in CH.
    /// Lookup is case-insensitive against `request_headers`.
    /// Env: `PROXYX_CONTROL_ACCOUNT_ID_HEADER`.
    #[serde(default = "default_account_id_header")]
    pub account_id_header: Option<String>,

    /// HTTP header name to extract as `tool_call_id` for stored captures.
    /// `None` disables extraction — `tool_call_id` stays NULL in CH.
    /// Lookup is case-insensitive against `request_headers`.
    /// Env: `PROXYX_CONTROL_TOOL_CALL_ID_HEADER`.
    #[serde(default = "default_tool_call_id_header")]
    pub tool_call_id_header: Option<String>,

    /// Sentry error tracking configuration
    #[serde(default)]
    pub sentry: common::sentry::SentryConfig,

    /// Broker implementation for the captures log.
    /// `redis_stream` (default), `kafka` or `rabbitmq`.
    #[serde(default)]
    pub broker_kind: BrokerKind,

    /// Kafka configuration (required when `broker_kind = "kafka"`).
    pub kafka: Option<common::log::kafka::KafkaConfig>,

    /// Deprecated name of `[kafka]`, accepted for one release.
    pub redpanda: Option<common::log::kafka::KafkaConfig>,

    /// RabbitMQ configuration (required when `broker_kind = "rabbitmq"`).
    pub rabbitmq: Option<common::log::rabbitmq::RabbitMqConfig>,

    /// Object store for traffic view Parquet exports.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_BACKEND` (`s3` | `azure`).
    #[serde(default)]
    pub traffic_views_backend: TrafficViewsBackend,

    /// S3 bucket (backend `s3`) or blob container (backend `azure`) for
    /// traffic view Parquet exports.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_BUCKET`.
    #[serde(default)]
    pub traffic_views_bucket: String,

    /// Azure storage account name holding `traffic_views_bucket`.
    /// Required when the backend is `azure`.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_AZURE_ACCOUNT`.
    #[serde(default)]
    pub traffic_views_azure_account: String,

    /// Seconds a completed export is kept before the reaper deletes the
    /// object and its job row. Measured from completion, not last access.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_TTL_SECS`.
    #[serde(default = "default_traffic_views_ttl_secs")]
    pub traffic_views_ttl_secs: u64,

    /// AWS region for the traffic views S3 bucket.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_S3_REGION`.
    #[serde(default = "default_traffic_views_s3_region")]
    pub traffic_views_s3_region: String,

    /// Optional HTTP(S) S3-compatible endpoint for traffic view exports.
    /// Uses path-style bucket addressing for both ClickHouse and the S3 client.
    /// Unset keeps the AWS virtual-hosted endpoint.
    /// Env: `PROXYX_CONTROL_TRAFFIC_VIEWS_S3_ENDPOINT`.
    #[serde(default)]
    pub traffic_views_s3_endpoint: Option<String>,

    // ── Parquet export query settings ─────────────────────────────────────
    // These control ClickHouse memory usage during INSERT INTO s3() exports.
    // Defaults are tuned for tables with wide body columns (multi-MB rows).
    /// MergeTree reader target block size in bytes. Shrinks read blocks when
    /// columns are wide to avoid multi-GiB allocations.
    /// Env: `PROXYX_CONTROL_EXPORT_PREFERRED_BLOCK_SIZE_BYTES`.
    #[serde(default = "default_export_preferred_block_size_bytes")]
    pub export_preferred_block_size_bytes: u64,

    /// Maximum rows per block during export reads.
    /// Env: `PROXYX_CONTROL_EXPORT_MAX_BLOCK_SIZE`.
    #[serde(default = "default_export_max_block_size")]
    pub export_max_block_size: u64,

    /// Target Parquet row group size in bytes.
    /// Env: `PROXYX_CONTROL_EXPORT_ROW_GROUP_SIZE_BYTES`.
    #[serde(default = "default_export_row_group_size_bytes")]
    pub export_row_group_size_bytes: u64,

    /// Target Parquet row group size in rows.
    /// Env: `PROXYX_CONTROL_EXPORT_ROW_GROUP_SIZE`.
    #[serde(default = "default_export_row_group_size")]
    pub export_row_group_size: u64,

    /// CloudFront distribution domain for signed view download URLs.
    /// Env: `PROXYX_CONTROL_CLOUDFRONT_DOMAIN`.
    /// Empty in dev/local; required for signed-URL generation in production.
    #[serde(default = "default_cloudfront_domain")]
    pub cloudfront_domain: String,

    /// CloudFront key pair ID for URL signing.
    /// Env: `PROXYX_CONTROL_CLOUDFRONT_KEY_PAIR_ID`.
    #[serde(default)]
    pub cloudfront_key_pair_id: String,

    /// RSA private key (PEM, PKCS#1 or PKCS#8) for CloudFront URL signing.
    /// Env: `PROXYX_CONTROL_CLOUDFRONT_PRIVATE_KEY`.
    #[serde(default)]
    pub cloudfront_private_key: String,
}

impl ControlConfig {
    /// The `[kafka]` section, or the deprecated `[redpanda]` one.
    pub fn kafka_config(&self) -> anyhow::Result<Option<&common::log::kafka::KafkaConfig>> {
        common::log::resolve_kafka_section(self.kafka.as_ref(), self.redpanda.as_ref())
    }

    /// Check the broker section the selected `broker_kind` needs.
    pub fn validate_broker(&self) -> anyhow::Result<()> {
        match self.broker_kind {
            BrokerKind::RedisStream => Ok(()),
            BrokerKind::Kafka => self
                .kafka_config()?
                .ok_or_else(|| {
                    anyhow::anyhow!("broker_kind = \"kafka\" but the [kafka] section is missing")
                })?
                .validate(),
            BrokerKind::Rabbitmq => self
                .rabbitmq
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "broker_kind = \"rabbitmq\" but the [rabbitmq] section is missing"
                    )
                })?
                .validate(),
        }
    }

    /// The `[clickhouse]` section, which the ClickHouse backend and
    /// `migrate --target clickhouse` need.
    pub fn clickhouse_config(
        &self,
    ) -> anyhow::Result<&crate::pipeline::clickhouse::ClickHouseConfig> {
        self.clickhouse.as_ref().ok_or_else(|| {
            anyhow::anyhow!("the [clickhouse] config section (clickhouse.url) is required")
        })
    }

    /// The `[capture_store.opensearch]` section, which the OpenSearch
    /// backend and `migrate --target opensearch` need.
    pub fn opensearch_config(&self) -> anyhow::Result<&crate::capture_store::OpenSearchConfig> {
        self.capture_store.opensearch.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "the [capture_store.opensearch] config section (capture_store.opensearch.url) is required"
            )
        })
    }

    pub fn load(config_path: Option<&str>) -> anyhow::Result<Self> {
        common::config::load("control", config_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_store::{CaptureBackend, Rollover};
    use figment::{Figment, providers::Format as _, providers::Toml};

    fn load(toml: &str) -> ControlConfig {
        Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("config parses")
    }

    #[test]
    fn shipped_example_selects_clickhouse() {
        let config = load(include_str!("../../../examples/control.toml"));
        assert_eq!(config.capture_store.backend, CaptureBackend::ClickHouse);
        assert_eq!(
            config.clickhouse_config().expect("[clickhouse] is set").url,
            "http://localhost:8123"
        );
        assert!(config.opensearch_config().is_err());
    }

    #[test]
    fn a_config_without_capture_store_keeps_the_clickhouse_default() {
        let config = load("[clickhouse]\nurl = \"http://ch:8123\"\n");
        assert_eq!(config.capture_store.backend, CaptureBackend::ClickHouse);
    }

    #[test]
    fn opensearch_needs_no_clickhouse_section() {
        let config = load(
            r#"
            [capture_store]
            backend = "opensearch"

            [capture_store.opensearch]
            url = "https://os:9200"
            username = "proxyx"
            password = "secret"
            rollover = "weekly"
            number_of_replicas = 2

            [capture_store.opensearch.index_settings]
            "index.lifecycle.name" = "keep-90d"
            "index.mapping.total_fields.limit" = 2000
            "#,
        );
        assert_eq!(config.capture_store.backend, CaptureBackend::OpenSearch);
        assert!(config.clickhouse.is_none());
        assert!(config.clickhouse_config().is_err());
        let os = config.opensearch_config().expect("opensearch section");
        assert_eq!(os.rollover, Rollover::Weekly);
        assert_eq!(os.number_of_replicas, 2);
        assert_eq!(os.index_settings["index.lifecycle.name"], "keep-90d");
        assert_eq!(os.index_settings["index.mapping.total_fields.limit"], 2000);
    }

    const KAFKA_SECTION: &str = r#"
        brokers = "k:9092"
        topic = "proxyx.captures"
    "#;

    #[test]
    fn kafka_is_the_broker_name_and_redpanda_still_works() {
        let config = load(&format!(
            "broker_kind = \"kafka\"\n[kafka]\n{KAFKA_SECTION}[clickhouse]\nurl = \"http://ch:8123\"\n"
        ));
        assert_eq!(config.broker_kind, BrokerKind::Kafka);
        assert_eq!(
            config.kafka_config().unwrap().unwrap().topic,
            "proxyx.captures"
        );
        config.validate_broker().unwrap();

        // The deprecated spelling resolves to the same thing.
        let legacy = load(&format!(
            "broker_kind = \"redpanda\"\n[redpanda]\n{KAFKA_SECTION}[clickhouse]\nurl = \"http://ch:8123\"\n"
        ));
        assert_eq!(legacy.broker_kind, BrokerKind::Kafka);
        assert_eq!(legacy.kafka_config().unwrap().unwrap().brokers, "k:9092");
        legacy.validate_broker().unwrap();
    }

    #[test]
    fn both_kafka_and_redpanda_sections_are_refused() {
        let config = load(&format!(
            "broker_kind = \"kafka\"\n[kafka]\n{KAFKA_SECTION}[redpanda]\n{KAFKA_SECTION}"
        ));
        assert!(config.kafka_config().is_err());
        assert!(config.validate_broker().is_err());
    }

    #[test]
    fn the_selected_broker_needs_its_section() {
        let no_section = load("broker_kind = \"kafka\"\n[clickhouse]\nurl = \"http://ch:8123\"\n");
        assert!(no_section.validate_broker().is_err());
        let rabbit = load("broker_kind = \"rabbitmq\"\n");
        assert!(rabbit.validate_broker().is_err());
        let rabbit = load(
            "broker_kind = \"rabbitmq\"\n[rabbitmq]\nurl = \"amqp://u:p@r:5672/%2f\"\npartitions = 4\n",
        );
        rabbit.validate_broker().unwrap();
        assert_eq!(rabbit.rabbitmq.as_ref().unwrap().partitions, 4);
        // Redis Streams needs no section.
        assert!(load("").validate_broker().is_ok());
    }

    #[test]
    fn traffic_views_s3_endpoint_defaults_to_none() {
        let config = load("");
        assert!(config.traffic_views_s3_endpoint.is_none());
        assert_eq!(config.traffic_views_s3_region, "us-east-1");
    }

    #[test]
    fn traffic_views_s3_endpoint_accepts_custom_endpoint() {
        let config = load(
            "traffic_views_s3_endpoint = \"http://minio:9000/storage/\"\n\
             traffic_views_s3_region = \"eu-west-1\"\n",
        );
        assert_eq!(
            config.traffic_views_s3_endpoint.as_deref(),
            Some("http://minio:9000/storage/")
        );
        assert_eq!(config.traffic_views_s3_region, "eu-west-1");
    }

    #[test]
    fn unknown_broker_and_unsupported_acks_are_refused() {
        let bad: Result<ControlConfig, _> = Figment::new()
            .merge(Toml::string("broker_kind = \"nats\"\n"))
            .extract();
        assert!(bad.is_err());
        let acks = load(&format!(
            "broker_kind = \"kafka\"\n[kafka]\n{KAFKA_SECTION}acks = \"1\"\n"
        ));
        assert!(acks.validate_broker().is_err());
    }
}
