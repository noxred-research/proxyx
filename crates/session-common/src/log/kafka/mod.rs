//! Apache Kafka implementation of the captures-log abstraction. It speaks the
//! Kafka protocol only, so it works unchanged against Kafka-compatible brokers
//! such as Redpanda.
//!
//! Built on [rskafka](https://crates.io/crates/rskafka), a pure-Rust Kafka
//! client that uses `rustls` for TLS. This avoids the OpenSSL / BoringSSL
//! symbol conflict that prevents `rdkafka` (librdkafka, C) from coexisting
//! with the `boring` crate used by the proxy for upstream TLS.
//!
//! # Producer
//! One `PartitionClient` per partition. `publish_batch` groups records by
//! partition (FNV hash of the key) and sends each partition's records as
//! produce requests of at most 1 MiB, all partitions at the same time. Within
//! a partition, requests go one after another and stop at the first failure,
//! so per-key order holds and a retry of the failed records cannot reorder
//! them. The proxy's capture drain hands over everything it has queued in one
//! call, so a busy proxy sends many captures per request instead of one.
//!
//! # Consumer
//! One async task per partition calls `fetch_records` in a loop and forwards
//! messages over a bounded `mpsc::channel`. Per-partition committed offsets
//! are persisted via an injected [`OffsetStore`] (`KafkaOffsetStore` in
//! production, backed by Kafka's native `__consumer_offsets`); on restart the
//! consumer resumes from `committed + 1`. Partitions without a committed
//! offset fall back to the latest offset (first-boot behaviour). If retention
//! has trimmed past a committed offset, the reader resets to the earliest
//! retained offset instead of wedging (see `partition_reader`).
//! ClickHouse `ReplacingMergeTree` deduplicates the up-to-flush-interval
//! window of records that may be replayed after a crash.
//!
//! # session_offset
//! Set to the Kafka partition offset (u64). Per-source routing via the message
//! key guarantees that all traffic for a given source lands on the same
//! partition, so partition offsets are monotonic within a source — sufficient
//! for the ClickHouse sort-key tiebreaker role.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use rskafka::client::partition::{Compression, OffsetAt, UnknownTopicHandling};
use rskafka::client::producer::ProducerClient;
use rskafka::client::{Client, ClientBuilder};
use rskafka::record::Record;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use super::{
    AckHandle, AckInner, CaptureLogConsumer, CaptureLogProducer, ConnState, LogMessage,
    PublishOutcome,
};

/// Durable per-partition offset commit store.
///
/// The production implementation (`KafkaOffsetStore` in `proxyx-api`) persists
/// offsets in Kafka's native `__consumer_offsets` topic via a separate
/// `rdkafka` `BaseConsumer`, so they are visible via `rpk group describe`.
/// rskafka 0.6 itself does not expose the `OffsetCommit` / `OffsetFetch` wire
/// protocol, which is why the commit path uses `rdkafka` rather than the same
/// client that does the fetching.
#[async_trait]
pub trait OffsetStore: Send + Sync {
    /// Load all committed offsets for `topic`. Partitions with no committed
    /// offset are absent from the map.
    async fn load(&self, topic: &str) -> Result<HashMap<i32, i64>>;

    /// Persist committed offsets for `topic`. Idempotent; safe to call with
    /// an offset equal to or older than the stored value.
    async fn commit(&self, topic: &str, offsets: &[(i32, i64)]) -> Result<()>;
}

/// Default interval between periodic offset flushes from tracker to store.
const OFFSET_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// TLS settings for broker connections (rustls-based).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to CA certificate PEM file.
    /// If omitted, the connection uses rustls defaults (no custom CA).
    pub ca_cert: Option<String>,
    /// Path to client certificate PEM file (mutual TLS).
    pub client_cert: Option<String>,
    /// Path to client private-key PEM file (mutual TLS).
    pub client_key: Option<String>,
}

/// SASL authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaslConfig {
    /// SASL mechanism: `PLAIN`, `SCRAM-SHA-256`, or `SCRAM-SHA-512`.
    pub mechanism: String,
    pub username: String,
    pub password: String,
}

fn default_partitions() -> i32 {
    12
}
fn default_replication_factor() -> i32 {
    3
}
fn default_retention_ms() -> i64 {
    604_800_000 // 7 days
}
fn default_client_id_prefix() -> String {
    "proxyx".to_string()
}
fn default_acks() -> String {
    "all".to_string()
}
fn default_batch_bytes() -> usize {
    MAX_REQUEST_BYTES
}

/// Produce-side compression of a record batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KafkaCompression {
    /// No compression (default).
    #[default]
    None,
    Gzip,
    Lz4,
    Snappy,
    Zstd,
}

impl KafkaCompression {
    fn to_rskafka(self) -> Compression {
        match self {
            Self::None => Compression::NoCompression,
            Self::Gzip => Compression::Gzip,
            Self::Lz4 => Compression::Lz4,
            Self::Snappy => Compression::Snappy,
            Self::Zstd => Compression::Zstd,
        }
    }
}

/// Configuration for the Kafka broker connection. Used for Apache Kafka and
/// for Kafka-compatible brokers (Redpanda).
///
/// TOML example:
/// ```toml
/// broker_kind = "kafka"
/// [kafka]
/// brokers = "kafka-0:9092,kafka-1:9092,kafka-2:9092"
/// topic   = "proxyx.captures"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Bootstrap broker list, comma-separated (`host:port`).
    pub brokers: String,
    /// Captures log topic name.
    pub topic: String,
    /// Number of topic partitions — **permanent**. Topic creation fails loudly
    /// if the topic already exists with a different partition count.
    #[serde(default = "default_partitions")]
    pub partitions: i32,
    /// Replication factor for topic creation. Default 3 (production).
    /// Set to 1 for single-node development clusters.
    #[serde(default = "default_replication_factor")]
    pub replication_factor: i32,
    /// Topic `retention.ms`, set when `proxyx migrate control` creates the
    /// topic (an existing topic keeps its setting; a different value is
    /// reported). Default 7 days.
    #[serde(default = "default_retention_ms")]
    pub retention_ms: i64,
    /// Prefix for the Kafka `client.id` (`<prefix>-<component>`).
    #[serde(default = "default_client_id_prefix")]
    pub client_id_prefix: String,
    /// Optional TLS configuration (rustls).
    pub tls: Option<TlsConfig>,
    /// Optional SASL authentication.
    pub sasl: Option<SaslConfig>,
    /// Producer compression: `none` (default), `gzip`, `lz4`, `snappy`, `zstd`.
    #[serde(default)]
    pub compression: KafkaCompression,
    /// Producer acknowledgement level. Only `"all"` is accepted: the pure-Rust
    /// producer always waits for all in-sync replicas, which is what the
    /// durable-publish contract needs.
    #[serde(default = "default_acks")]
    pub acks: String,
    /// How long the producer waits to coalesce concurrent publish calls into
    /// one produce request. `0` (default) sends what is queued at once. Only
    /// callers that publish concurrently benefit (the control API); the
    /// session proxy's single writer already sends everything it has queued
    /// in one call.
    #[serde(default)]
    pub linger_ms: u64,
    /// Largest produce request in bytes. Default 1 MiB; raise it together with
    /// the broker's `message.max.bytes`.
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: usize,
}

impl KafkaConfig {
    /// Check settings that cannot be expressed in the types.
    pub fn validate(&self) -> Result<()> {
        if self.brokers.trim().is_empty() {
            anyhow::bail!("kafka.brokers must not be empty");
        }
        if self.topic.trim().is_empty() {
            anyhow::bail!("kafka.topic must not be empty");
        }
        if self.partitions < 1 || self.replication_factor < 1 {
            anyhow::bail!("kafka.partitions and kafka.replication_factor must be at least 1");
        }
        if !self.acks.eq_ignore_ascii_case("all") && self.acks != "-1" {
            anyhow::bail!(
                "kafka.acks = {:?} is not supported: the producer always uses acks=all, which \
                 the durable publish contract requires",
                self.acks
            );
        }
        if self.batch_bytes < 16 * 1024 || self.batch_bytes > 100 * 1024 * 1024 {
            anyhow::bail!("kafka.batch_bytes must be between 16 KiB and 100 MiB");
        }
        if let Some(sasl) = &self.sasl {
            to_rskafka_sasl(sasl)?;
        }
        Ok(())
    }
}

/// Build an rskafka [`Client`] from config.
async fn build_client(config: &KafkaConfig, component: &str) -> Result<Client> {
    let brokers: Vec<String> = config
        .brokers
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let mut builder =
        ClientBuilder::new(brokers).client_id(format!("{}-{}", config.client_id_prefix, component));

    if let Some(sasl) = &config.sasl {
        builder = builder.sasl_config(to_rskafka_sasl(sasl)?);
    }

    if let Some(tls) = &config.tls {
        let tls_cfg = build_rustls_config(tls)?;
        builder = builder.tls_config(tls_cfg);
    }

    builder.build().await.context("failed to connect to Kafka")
}

fn to_rskafka_sasl(sasl: &SaslConfig) -> Result<rskafka::client::SaslConfig> {
    let creds = rskafka::client::Credentials {
        username: sasl.username.clone(),
        password: sasl.password.clone(),
    };
    match sasl.mechanism.to_uppercase().as_str() {
        "PLAIN" => Ok(rskafka::client::SaslConfig::Plain(creds)),
        "SCRAM-SHA-256" => Ok(rskafka::client::SaslConfig::ScramSha256(creds)),
        "SCRAM-SHA-512" => Ok(rskafka::client::SaslConfig::ScramSha512(creds)),
        other => Err(anyhow!("unsupported SASL mechanism: {other}")),
    }
}

fn build_rustls_config(tls: &TlsConfig) -> Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::BufReader;

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &tls.ca_cert {
        let ca_pem =
            std::fs::read(ca_path).with_context(|| format!("reading CA cert from {ca_path}"))?;
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(&ca_pem[..]))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("parsing CA PEM")?;
        for cert in certs {
            root_store
                .add(cert)
                .context("adding CA cert to root store")?;
        }
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let config = match (&tls.client_cert, &tls.client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("reading client cert from {cert_path}"))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("reading client key from {key_path}"))?;
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("parsing client cert PEM")?;
            let key: PrivateKeyDer<'static> =
                rustls_pemfile::private_key(&mut BufReader::new(&key_pem[..]))
                    .context("parsing client key PEM")?
                    .context("no private key found in PEM file")?;
            builder
                .with_client_auth_cert(certs, key)
                .context("building rustls client config with mTLS")?
        }
        _ => builder.with_no_client_auth(),
    };

    Ok(Arc::new(config))
}

/// Broker batches have a 1 MiB limit. `Record::approximate_size` omits Kafka
/// framing, so reserve space for the v2 batch header and each record's fields.
/// Captured records have no Kafka headers.
const MAX_REQUEST_BYTES: usize = 1_048_576;
/// How long producer start-up waits for the brokers.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const BATCH_SIZE_RESERVE: usize = 128;
const RECORD_SIZE_RESERVE: usize = 64;

/// rskafka-based producer over a Kafka topic, with one client per
/// partition (index = partition ID order).
pub struct KafkaProducer {
    inner: Arc<ProducerInner>,
    /// Present when `linger_ms > 0`: publish calls go through it so
    /// concurrent callers share produce requests.
    coalescer: Option<tokio::sync::mpsc::Sender<CoalesceRequest>>,
    _coalescer_task: Option<tokio::task::JoinHandle<()>>,
}

struct ProducerInner {
    partitions: Vec<Arc<dyn ProducerClient>>,
    max_request_bytes: usize,
    compression: Compression,
    state: Arc<ConnState>,
}

/// One caller's records waiting to be coalesced.
struct CoalesceRequest {
    records: Vec<(Bytes, Bytes)>,
    reply: tokio::sync::oneshot::Sender<Vec<PublishOutcome>>,
}

impl KafkaProducer {
    /// Connect to Kafka, discover the topic's partitions, and create a
    /// per-partition client.
    pub async fn new(config: &KafkaConfig, component: &str) -> Result<Self> {
        config.validate()?;
        // The client retries a refused connection or login for ever; a
        // process that cannot reach its broker should fail at start instead.
        tokio::time::timeout(CONNECT_TIMEOUT, Self::connect(config, component))
            .await
            .map_err(|_| {
                anyhow!(
                    "connecting the Kafka producer to {} timed out after {}s (unreachable \
                     brokers, bad credentials or TLS settings?)",
                    config.brokers,
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
    }

    async fn connect(config: &KafkaConfig, component: &str) -> Result<Self> {
        let client = build_client(config, component).await?;
        let topics = client.list_topics().await.context("listing topics")?;
        let topic_info = topics
            .iter()
            .find(|t| t.name == config.topic)
            .ok_or_else(|| {
                anyhow!(
                    "topic '{}' not found — run `proxyx migrate` first",
                    config.topic
                )
            })?;

        let mut partition_ids: Vec<i32> = topic_info.partitions.iter().copied().collect();
        partition_ids.sort_unstable();

        let mut partitions: Vec<Arc<dyn ProducerClient>> = Vec::with_capacity(partition_ids.len());
        for &pid in &partition_ids {
            let pc = client
                .partition_client(config.topic.clone(), pid, UnknownTopicHandling::Retry)
                .await
                .with_context(|| format!("creating partition client for partition {pid}"))?;
            partitions.push(Arc::new(pc));
        }

        tracing::info!(
            topic = %config.topic,
            partitions = partitions.len(),
            compression = ?config.compression,
            linger_ms = config.linger_ms,
            "Kafka producer connected"
        );
        let producer = Self::from_parts(
            partitions,
            config.batch_bytes,
            config.compression.to_rskafka(),
            config.linger_ms,
        );
        producer.inner.state.set(true);
        Ok(producer)
    }

    fn from_parts(
        partitions: Vec<Arc<dyn ProducerClient>>,
        max_request_bytes: usize,
        compression: Compression,
        linger_ms: u64,
    ) -> Self {
        let inner = Arc::new(ProducerInner {
            partitions,
            max_request_bytes,
            compression,
            state: ConnState::new("kafka", "producer"),
        });
        if linger_ms == 0 {
            return Self {
                inner,
                coalescer: None,
                _coalescer_task: None,
            };
        }
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let task = tokio::spawn(coalesce(
            Arc::clone(&inner),
            rx,
            Duration::from_millis(linger_ms),
        ));
        Self {
            inner,
            coalescer: Some(tx),
            _coalescer_task: Some(task),
        }
    }
}

impl Drop for KafkaProducer {
    fn drop(&mut self) {
        if let Some(task) = &self._coalescer_task {
            task.abort();
        }
    }
}

/// Collects the records of concurrent `publish_batch` calls for up to
/// `linger` (or until `max_request_bytes` are waiting) and publishes them as
/// one batch, in arrival order. Records of different callers that share a
/// partition keep their arrival order, and a failed request blocks the later
/// records of its partition for every caller, exactly like within one call.
async fn coalesce(
    inner: Arc<ProducerInner>,
    mut rx: tokio::sync::mpsc::Receiver<CoalesceRequest>,
    linger: Duration,
) {
    while let Some(first) = rx.recv().await {
        let mut bytes: usize = first.records.iter().map(|(k, v)| k.len() + v.len()).sum();
        let mut group = vec![first];
        let deadline = tokio::time::Instant::now() + linger;
        while bytes < inner.max_request_bytes {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(next)) => {
                    bytes += next
                        .records
                        .iter()
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>();
                    group.push(next);
                }
                Ok(None) | Err(_) => break,
            }
        }
        let all: Vec<(Bytes, Bytes)> = group
            .iter()
            .flat_map(|g| g.records.iter().cloned())
            .collect();
        let mut outcomes = inner.publish_direct(&all).await.into_iter();
        for request in group {
            let own: Vec<PublishOutcome> = outcomes.by_ref().take(request.records.len()).collect();
            // A caller that gave up (dropped its future) is not told.
            let _ = request.reply.send(own);
        }
    }
}

/// Deterministic key → partition mapping. Uses FNV-1a for speed; the exact
/// hash doesn't matter as long as it's consistent across restarts.
pub(crate) fn partition_for_key(key: &[u8], num_partitions: usize) -> usize {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut h = FNV_OFFSET;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    (h % num_partitions as u64) as usize
}

/// Sends one partition's records in input order, in produce requests of at
/// most `MAX_REQUEST_BYTES`, and returns one outcome per record. After a
/// failed request, later records return `NotSent` without using retry attempts.
/// A record larger than `MAX_REQUEST_BYTES` can never be
/// sent, so it fails alone without stopping the records after it.
async fn produce_in_order(
    client: &dyn ProducerClient,
    records: Vec<Record>,
    max_request_bytes: usize,
    compression: Compression,
) -> Vec<PublishOutcome> {
    let mut results = Vec::with_capacity(records.len());
    let mut request = Vec::new();
    let mut request_bytes = 0;
    let mut blocked = false;
    for record in records {
        let size = record.approximate_size();
        // Send what is collected first, so results stay in input order. A
        // large but valid record can still be sent on its own.
        if !request.is_empty()
            && request_bytes + size + RECORD_SIZE_RESERVE + BATCH_SIZE_RESERVE > max_request_bytes
        {
            send_request(
                client,
                &mut request,
                compression,
                &mut blocked,
                &mut results,
            )
            .await;
            request_bytes = 0;
        }
        if blocked {
            results.push(PublishOutcome::NotSent);
        } else if size > max_request_bytes {
            results.push(PublishOutcome::Failed(anyhow!(
                "record of {size} bytes exceeds the {max_request_bytes}-byte request limit"
            )));
        } else {
            request.push(record);
            request_bytes += size + RECORD_SIZE_RESERVE;
        }
    }
    send_request(
        client,
        &mut request,
        compression,
        &mut blocked,
        &mut results,
    )
    .await;
    results
}

/// Sends the collected records as one produce request (if any) and pushes
/// one outcome per record. On failure, sets `blocked` so the caller stops
/// sending this partition's later records.
async fn send_request(
    client: &dyn ProducerClient,
    request: &mut Vec<Record>,
    compression: Compression,
    blocked: &mut bool,
    results: &mut Vec<PublishOutcome>,
) {
    if request.is_empty() {
        return;
    }
    let count = request.len();
    match client.produce(std::mem::take(request), compression).await {
        Ok(_) => results.extend((0..count).map(|_| PublishOutcome::Published)),
        Err(e) => {
            let error = format!("Kafka publish failed: {e}");
            results.extend((0..count).map(|_| PublishOutcome::Failed(anyhow!("{error}"))));
            *blocked = true;
        }
    }
}

impl ProducerInner {
    /// Publish `records` now: one task per partition, each sending its
    /// records in input order and stopping at the first failed request.
    async fn publish_direct(&self, records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
        // Record indices per partition, in input order.
        let mut by_partition = vec![Vec::new(); self.partitions.len()];
        for (index, (key, _)) in records.iter().enumerate() {
            by_partition[partition_for_key(key, self.partitions.len())].push(index);
        }

        // One task per partition, so partitions send at the same time.
        let mut tasks = JoinSet::new();
        for (partition, indices) in by_partition.into_iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let client = Arc::clone(&self.partitions[partition]);
            let (max_request_bytes, compression) = (self.max_request_bytes, self.compression);
            let batch = indices
                .iter()
                .map(|&index| {
                    let (key, payload) = &records[index];
                    Record {
                        key: Some(key.to_vec()),
                        value: Some(payload.to_vec()),
                        headers: BTreeMap::new(),
                        timestamp: Utc::now(),
                    }
                })
                .collect();
            tasks.spawn(async move {
                (
                    indices,
                    produce_in_order(client.as_ref(), batch, max_request_bytes, compression).await,
                )
            });
        }

        // Every record belongs to exactly one partition, so each placeholder
        // is overwritten below.
        let mut results: Vec<PublishOutcome> = Vec::with_capacity(records.len());
        results.resize_with(records.len(), || PublishOutcome::NotSent);
        while let Some(joined) = tasks.join_next().await {
            let (indices, partition_results) = joined.expect("Kafka produce task panicked");
            for (index, result) in indices.into_iter().zip(partition_results) {
                results[index] = result;
            }
        }
        // Connected means the last request that reached a broker succeeded.
        if results
            .iter()
            .any(|r| matches!(r, PublishOutcome::Failed(_)))
        {
            self.state.set(false);
        } else if results
            .iter()
            .any(|r| matches!(r, PublishOutcome::Published))
        {
            self.state.set(true);
        }
        results
    }
}

#[async_trait]
impl CaptureLogProducer for KafkaProducer {
    async fn publish(&self, key: &[u8], payload: Bytes) -> Result<()> {
        match self
            .publish_batch(&[(Bytes::copy_from_slice(key), payload)])
            .await
            .pop()
            .expect("publish_batch returns one outcome per record")
        {
            PublishOutcome::Published => Ok(()),
            PublishOutcome::Failed(error) => Err(error),
            PublishOutcome::NotSent => {
                unreachable!("a single record has no earlier failed request")
            }
        }
    }

    async fn publish_batch(&self, records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
        let Some(coalescer) = &self.coalescer else {
            return self.inner.publish_direct(records).await;
        };
        let (reply, answer) = tokio::sync::oneshot::channel();
        let request = CoalesceRequest {
            records: records.to_vec(),
            reply,
        };
        if coalescer.send(request).await.is_err() {
            return fail_all(records.len(), "Kafka producer is closed");
        }
        answer
            .await
            .unwrap_or_else(|_| fail_all(records.len(), "Kafka producer is closed"))
    }

    async fn flush_and_close(&self, _timeout: Duration) {
        // Nothing is buffered: every publish call waits for its requests.
    }

    fn healthy(&self) -> bool {
        self.inner.state.is_up()
    }
}

fn fail_all(count: usize, why: &str) -> Vec<PublishOutcome> {
    (0..count)
        .map(|_| PublishOutcome::Failed(anyhow!("{why}")))
        .collect()
}

struct PartitionState {
    /// Offsets that have been acked but not yet part of the contiguous run.
    acked: BTreeSet<i64>,
    /// Highest contiguous acked offset. -1 = nothing committed yet.
    watermark: i64,
}

/// High-water-mark of the total out-of-order ack backlog across all partitions.
/// A large value signals a stalled watermark — some [`AckHandle`] was dropped
/// without being acked, blocking the contiguous commit run and letting the
/// `acked` set grow unboundedly behind the gap.
static MAX_ACK_GAP: AtomicU64 = AtomicU64::new(0);

/// Threshold above which the ack gap is logged as an error.
const ACK_GAP_ERROR_THRESHOLD: usize = 100_000;

/// Whether the ack-gap error has already been logged (rate-limit to once).
static ACK_GAP_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Returns the current maximum aggregate ack gap across all tracked partitions.
#[allow(dead_code)]
pub fn max_ack_gap() -> u64 {
    MAX_ACK_GAP.load(Ordering::Relaxed)
}

/// Tracks per-partition ack state and computes the contiguous commit watermark.
///
/// `snapshot` exposes the per-partition watermarks for periodic durable commit
/// via [`OffsetStore`].
pub(crate) struct OffsetTracker {
    partitions: HashMap<i32, PartitionState>,
}

impl OffsetTracker {
    pub(crate) fn new() -> Self {
        Self {
            partitions: HashMap::new(),
        }
    }

    /// Record the first-seen offset for a partition (called during `poll`).
    /// No-op if the partition is already tracked.
    pub(crate) fn observe(&mut self, partition: i32, first_offset: i64) {
        self.partitions
            .entry(partition)
            .or_insert_with(|| PartitionState {
                acked: BTreeSet::new(),
                watermark: first_offset - 1,
            });
    }

    /// Record an ack for `(partition, offset)`.
    ///
    /// Returns `Some(next_offset)` when the contiguous watermark advanced.
    /// Returns `None` when the watermark did not advance or partition unknown.
    pub(crate) fn ack(&mut self, partition: i32, offset: i64) -> Option<i64> {
        let result = {
            let state = self.partitions.get_mut(&partition)?;
            state.acked.insert(offset);
            let mut wm = state.watermark;
            loop {
                if state.acked.remove(&(wm + 1)) {
                    wm += 1;
                } else {
                    break;
                }
            }
            if wm != state.watermark {
                state.watermark = wm;
                Some(wm + 1)
            } else {
                None
            }
        };

        // Update the ack-gap gauge once the per-partition borrow has ended:
        // total out-of-order acks waiting behind gaps.
        self.update_ack_gap();

        result
    }

    /// Aggregate `acked.len()` across all partitions, update the global gauge,
    /// and log an error (once) if the gap exceeds the threshold.
    fn update_ack_gap(&self) {
        let total: usize = self.partitions.values().map(|s| s.acked.len()).sum();
        MAX_ACK_GAP.store(total as u64, Ordering::Relaxed);
        if total >= ACK_GAP_ERROR_THRESHOLD && !ACK_GAP_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::error!(
                gap = total,
                "ack gap exceeded threshold ({ACK_GAP_ERROR_THRESHOLD}); \
                 a dropped AckHandle is likely stalling the commit watermark"
            );
        }
    }

    /// Snapshot per-partition committed watermarks. Only partitions whose
    /// watermark is >= 0 are returned — a freshly-observed partition starts
    /// with `watermark = first_offset - 1` which is negative when the
    /// partition starts at offset 0, preventing over-commit back to its
    /// start before any ack has actually advanced the watermark.
    pub(crate) fn snapshot(&self) -> Vec<(i32, i64)> {
        // Refresh the gap gauge on every snapshot (called by the flush loop).
        self.update_ack_gap();

        self.partitions
            .iter()
            .filter_map(|(p, s)| (s.watermark >= 0).then_some((*p, s.watermark)))
            .collect()
    }
}

/// Owned message data forwarded from per-partition reader tasks.
struct PendingMessage {
    partition: i32,
    offset: i64,
    key: Bytes,
    payload: Bytes,
}

/// rskafka-based consumer for a Kafka topic.
///
/// Spawns one async task per partition. Each task calls `fetch_records` in a
/// loop, forwarding messages over a bounded `mpsc::channel`. `poll` drains
/// from that channel.
///
/// Per-partition committed offsets are persisted via an injected
/// [`OffsetStore`]. On startup the consumer resumes from `committed + 1` for
/// each partition that has a committed offset, and falls back to the latest
/// offset for partitions with no committed offset (first-boot behaviour).
/// When `offset_store` is `None`, offsets are tracked in memory only and the
/// consumer always starts from latest — the legacy behaviour, kept for tests
/// and for the producer-only proxy crate.
pub struct KafkaConsumer {
    rx: tokio::sync::mpsc::Receiver<PendingMessage>,
    tracker: Arc<parking_lot::Mutex<OffsetTracker>>,
    /// Spawned reader tasks and the optional offset-flush task. `JoinSet`
    /// aborts all contained tasks on drop, ensuring the flush loop and
    /// partition readers are terminated when the consumer is dropped.
    _tasks: tokio::task::JoinSet<()>,
}

impl KafkaConsumer {
    /// Connect to Kafka, discover partitions, and start per-partition
    /// reader tasks.
    pub async fn new(
        config: &KafkaConfig,
        component: &str,
        offset_store: Option<Arc<dyn OffsetStore>>,
    ) -> Result<Self> {
        let client = build_client(config, component).await?;
        let topics = client.list_topics().await.context("listing topics")?;
        let topic_info = topics
            .iter()
            .find(|t| t.name == config.topic)
            .ok_or_else(|| {
                anyhow!(
                    "topic '{}' not found — run `proxyx migrate` first",
                    config.topic
                )
            })?;

        // Load any previously-committed offsets so we can resume after restart
        // instead of skipping ahead to `Latest`.
        let committed: HashMap<i32, i64> = match offset_store.as_ref() {
            Some(store) => store
                .load(&config.topic)
                .await
                .context("loading committed offsets")?,
            None => HashMap::new(),
        };

        let tracker = Arc::new(parking_lot::Mutex::new(OffsetTracker::new()));
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let mut tasks = tokio::task::JoinSet::new();

        for &partition in &topic_info.partitions {
            let pc = client
                .partition_client(config.topic.clone(), partition, UnknownTopicHandling::Retry)
                .await
                .with_context(|| format!("creating consumer partition client {partition}"))?;

            // Resume from the last committed offset (committed + 1) if we have
            // one; otherwise jump to the latest offset so we don't replay
            // history on first boot. A transient metadata error here must NOT
            // silently fall back to 0 — that would replay the entire retention
            // window into ClickHouse. Retry, then fail startup.
            let start_offset = match committed.get(&partition) {
                Some(c) => c + 1,
                None => offset_with_retry(&pc, partition, OffsetAt::Latest).await?,
            };

            let tx = tx.clone();
            tasks.spawn(partition_reader(pc, partition, tx, start_offset));
        }
        // Drop the original sender; clones live in the tasks.
        drop(tx);

        if let Some(store) = offset_store {
            tasks.spawn(offset_flush_loop(
                Arc::clone(&tracker),
                store,
                config.topic.clone(),
            ));
        }

        tracing::info!(
            topic = %config.topic,
            partitions = tasks.len(),
            "Kafka consumer started"
        );
        Ok(Self {
            rx,
            tracker,
            _tasks: tasks,
        })
    }

    fn push_message(&self, messages: &mut Vec<LogMessage>, pending: PendingMessage) {
        {
            let mut tracker = self.tracker.lock();
            tracker.observe(pending.partition, pending.offset);
        }

        let ack = AckHandle::new(KafkaAck {
            partition: pending.partition,
            offset: pending.offset,
            tracker: Arc::clone(&self.tracker),
        });

        messages.push(LogMessage {
            key: pending.key,
            payload: pending.payload,
            session_offset: pending.offset.max(0) as u64,
            ack,
        });
    }
}

/// Fetch a partition's offset at `at`, retrying transient errors with a short
/// backoff. Used for first-boot (no committed offset → `Latest`, so a flaky
/// metadata call can't silently resolve to 0 and replay the whole retention
/// window) and for out-of-range recovery (→ `Earliest`). An empty partition
/// legitimately reports 0 here.
async fn offset_with_retry(
    client: &rskafka::client::partition::PartitionClient,
    partition: i32,
    at: OffsetAt,
) -> Result<i64> {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match client.get_offset(at).await {
            Ok(offset) => return Ok(offset),
            Err(e) => {
                tracing::warn!(
                    partition,
                    attempt,
                    error = %e,
                    "fetching latest offset failed, retrying"
                );
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }
        }
    }
    Err(anyhow!(last_err.expect("loop ran at least once")))
        .with_context(|| format!("fetching latest offset for partition {partition} after retries"))
}

/// Per-partition reader loop.
async fn partition_reader(
    client: rskafka::client::partition::PartitionClient,
    partition: i32,
    tx: tokio::sync::mpsc::Sender<PendingMessage>,
    mut offset: i64,
) {
    loop {
        match client.fetch_records(offset, 1..1_048_576, 500).await {
            Ok((records, _high_watermark)) => {
                for rao in records {
                    let pending = PendingMessage {
                        partition,
                        offset: rao.offset,
                        key: rao.record.key.map(Bytes::from).unwrap_or_default(),
                        payload: rao.record.value.map(Bytes::from).unwrap_or_default(),
                    };
                    offset = rao.offset + 1;
                    if tx.send(pending).await.is_err() {
                        // Consumer dropped — shut down this reader.
                        return;
                    }
                }
            }
            Err(e) => {
                // Retention deleted records at our resume offset: the committed
                // offset fell below the partition's start (e.g. brokers hit the
                // retention target and trimmed segments the consumer had not yet
                // read). rskafka surfaces this as a fatal OffsetOutOfRange and
                // does NOT auto-reset, so without this arm the reader retries the
                // same dead offset forever and ingestion wedges. Reset to the
                // earliest still-retained offset; the replayed window is
                // deduplicated by ClickHouse ReplacingMergeTree.
                if matches!(
                    &e,
                    rskafka::client::error::Error::ServerError {
                        protocol_error: rskafka::client::error::ProtocolError::OffsetOutOfRange,
                        ..
                    }
                ) {
                    match offset_with_retry(&client, partition, OffsetAt::Earliest).await {
                        Ok(earliest) => {
                            tracing::warn!(
                                partition,
                                stale_offset = offset,
                                earliest,
                                "offset out of range; resetting to earliest retained offset"
                            );
                            offset = earliest;
                        }
                        Err(e) => {
                            tracing::error!(
                                partition,
                                error = %e,
                                "failed to resolve earliest offset after out-of-range; retrying"
                            );
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                } else {
                    tracing::warn!(partition, error = %e, "Kafka fetch error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

/// Periodically snapshot per-partition watermarks from `tracker` and commit
/// them to `store`. Runs until aborted by the owning `JoinSet` when the
/// `KafkaConsumer` is dropped. Commit failures are logged and the loop
/// continues — durability is best-effort and any unflushed offsets are
/// replayed safely on restart thanks to ClickHouse `ReplacingMergeTree` dedup.
async fn offset_flush_loop(
    tracker: Arc<parking_lot::Mutex<OffsetTracker>>,
    store: Arc<dyn OffsetStore>,
    topic: String,
) {
    let mut interval = tokio::time::interval(OFFSET_FLUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick — wait one interval before the first flush.
    interval.tick().await;
    loop {
        interval.tick().await;
        let offsets = tracker.lock().snapshot();
        if offsets.is_empty() {
            continue;
        }
        if let Err(e) = store.commit(&topic, &offsets).await {
            tracing::warn!(error = %e, topic = %topic, "offset commit failed");
        }
    }
}

#[async_trait]
impl CaptureLogConsumer for KafkaConsumer {
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        let mut messages = Vec::with_capacity(max.min(64));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);

        // Wait for at least one message (up to the deadline).
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, self.rx.recv()).await {
            Ok(Some(pending)) => self.push_message(&mut messages, pending),
            Ok(None) => {
                return Err(anyhow!("Kafka consumer channel closed unexpectedly"));
            }
            Err(_elapsed) => return Ok(messages), // deadline — no messages
        }

        // Drain any additional buffered messages without further waiting.
        while messages.len() < max {
            match self.rx.try_recv() {
                Ok(pending) => self.push_message(&mut messages, pending),
                Err(_) => break,
            }
        }

        Ok(messages)
    }
}

struct KafkaAck {
    partition: i32,
    offset: i64,
    tracker: Arc<parking_lot::Mutex<OffsetTracker>>,
}

#[async_trait]
impl AckInner for KafkaAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        // Advance the contiguous watermark. With rskafka there is no broker
        // offset commit — the tracker is bookkeeping only.
        self.tracker.lock().ack(self.partition, self.offset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rskafka::client::error::Error as ClientError;
    use std::pin::Pin;

    /// Partition client that records the values of each produce request and
    /// fails the requests whose 0-based number is in `fail_requests`.
    #[derive(Debug, Default)]
    struct FakePartition {
        requests: parking_lot::Mutex<Vec<Vec<Vec<u8>>>>,
        fail_requests: Vec<usize>,
        max_wire_batch_bytes: Option<usize>,
    }

    impl ProducerClient for FakePartition {
        fn produce(
            &self,
            records: Vec<Record>,
            _compression: Compression,
        ) -> Pin<Box<dyn Future<Output = std::result::Result<Vec<i64>, ClientError>> + Send + '_>>
        {
            // A v2 record batch has framing beyond Record::approximate_size().
            let too_large = self.max_wire_batch_bytes.is_some_and(|limit| {
                61 + records
                    .iter()
                    .map(|r| r.approximate_size() + 16)
                    .sum::<usize>()
                    > limit
            });
            let result = {
                let mut requests = self.requests.lock();
                let number = requests.len();
                requests.push(
                    records
                        .iter()
                        .map(|r| r.value.clone().unwrap_or_default())
                        .collect(),
                );
                if self.fail_requests.contains(&number) || too_large {
                    Err(ClientError::Timeout)
                } else {
                    Ok((0..records.len() as i64).collect())
                }
            };
            Box::pin(async move { result })
        }
    }

    fn producer_over(partitions: &[Arc<FakePartition>]) -> KafkaProducer {
        KafkaProducer::from_parts(
            partitions
                .iter()
                .map(|p| Arc::clone(p) as Arc<dyn ProducerClient>)
                .collect(),
            MAX_REQUEST_BYTES,
            Compression::NoCompression,
            0,
        )
    }

    /// First key `k0`, `k1`, ... that maps to `partition` out of 2.
    fn key_for(partition: usize) -> Bytes {
        (0..)
            .map(|i| Bytes::from(format!("k{i}")))
            .find(|k| partition_for_key(k, 2) == partition)
            .unwrap()
    }

    #[tokio::test]
    async fn publish_batch_sends_each_partition_as_one_request_in_input_order() {
        let fakes = [
            Arc::new(FakePartition::default()),
            Arc::new(FakePartition::default()),
        ];
        let (a, b) = (key_for(0), key_for(1));
        let records = [
            (a.clone(), Bytes::from("a1")),
            (b.clone(), Bytes::from("b1")),
            (a.clone(), Bytes::from("a2")),
            (b.clone(), Bytes::from("b2")),
        ];

        let results = producer_over(&fakes).publish_batch(&records).await;

        assert!(
            results
                .iter()
                .all(|r| matches!(r, PublishOutcome::Published)),
            "{results:?}"
        );
        assert_eq!(
            *fakes[0].requests.lock(),
            vec![vec![b"a1".to_vec(), b"a2".to_vec()]]
        );
        assert_eq!(
            *fakes[1].requests.lock(),
            vec![vec![b"b1".to_vec(), b"b2".to_vec()]]
        );
    }

    #[tokio::test]
    async fn batch_near_broker_limit_preserves_both_captures() {
        let fake = Arc::new(FakePartition {
            max_wire_batch_bytes: Some(MAX_REQUEST_BYTES),
            ..Default::default()
        });
        let key = Bytes::from("k");
        let payload = Bytes::from(vec![b'x'; (MAX_REQUEST_BYTES - 18) / 2]);
        let records = [(key.clone(), payload.clone()), (key, payload)];

        let results = producer_over(&[fake]).publish_batch(&records).await;

        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|r| matches!(r, PublishOutcome::Published))
        );
    }

    #[tokio::test]
    async fn valid_large_capture_is_sent_alone_after_a_small_one() {
        let fake = Arc::new(FakePartition {
            max_wire_batch_bytes: Some(MAX_REQUEST_BYTES),
            ..Default::default()
        });
        let key = Bytes::from("k");
        let large = Bytes::from(vec![b'x'; MAX_REQUEST_BYTES - 80 - key.len()]);
        let records = [(key.clone(), Bytes::from_static(b"small")), (key, large)];

        let results = producer_over(&[fake]).publish_batch(&records).await;

        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|r| matches!(r, PublishOutcome::Published))
        );
    }

    #[tokio::test]
    async fn failed_request_stops_only_the_rest_of_its_partition() {
        let fakes = [
            Arc::new(FakePartition {
                fail_requests: vec![0],
                ..Default::default()
            }),
            Arc::new(FakePartition::default()),
        ];
        let (a, b) = (key_for(0), key_for(1));
        // Two of these do not fit in one request, so partition 0 needs two.
        let big = Bytes::from(vec![b'x'; MAX_REQUEST_BYTES / 2 + 1]);
        let records = [
            (a.clone(), big.clone()),
            (a.clone(), big.clone()),
            (b.clone(), Bytes::from("b1")),
        ];

        let results = producer_over(&fakes).publish_batch(&records).await;

        assert!(matches!(results[0], PublishOutcome::Failed(_)));
        assert!(
            matches!(results[1], PublishOutcome::NotSent),
            "must not land after the failed record"
        );
        assert!(
            matches!(results[2], PublishOutcome::Published),
            "other partitions are not affected"
        );
        assert_eq!(
            fakes[0].requests.lock().len(),
            1,
            "second request must not be sent after the first one failed"
        );
        assert_eq!(*fakes[1].requests.lock(), vec![vec![b"b1".to_vec()]]);
    }

    #[tokio::test]
    async fn oversized_record_fails_alone() {
        let fakes = [Arc::new(FakePartition::default())];
        let key = Bytes::from("k");
        let records = [
            (key.clone(), Bytes::from("s1")),
            (key.clone(), Bytes::from(vec![b'x'; MAX_REQUEST_BYTES + 1])),
            (key.clone(), Bytes::from("s2")),
        ];

        let results = producer_over(&fakes).publish_batch(&records).await;

        assert!(matches!(results[0], PublishOutcome::Published));
        assert!(matches!(results[1], PublishOutcome::Failed(_)));
        assert!(matches!(results[2], PublishOutcome::Published));
        assert_eq!(
            *fakes[0].requests.lock(),
            vec![vec![b"s1".to_vec()], vec![b"s2".to_vec()]]
        );
    }

    fn tracker_at(first_offset: i64) -> OffsetTracker {
        let mut t = OffsetTracker::new();
        t.observe(0, first_offset);
        t
    }

    #[test]
    fn snapshot_excludes_partitions_with_no_acks() {
        let mut t = OffsetTracker::new();
        t.observe(0, 0); // watermark = -1, not yet advanced
        t.observe(1, 100);
        t.ack(1, 100); // watermark for p1 = 100
        let snap: std::collections::HashMap<i32, i64> = t.snapshot().into_iter().collect();
        assert_eq!(snap.get(&1), Some(&100));
        assert!(
            !snap.contains_key(&0),
            "partition with no acks must not be committed: {snap:?}"
        );
    }

    #[test]
    fn snapshot_returns_latest_watermark_per_partition() {
        let mut t = OffsetTracker::new();
        t.observe(0, 0);
        t.observe(1, 0);
        t.ack(0, 0);
        t.ack(0, 1);
        t.ack(1, 0);
        let snap: std::collections::HashMap<i32, i64> = t.snapshot().into_iter().collect();
        assert_eq!(snap.get(&0), Some(&1));
        assert_eq!(snap.get(&1), Some(&0));
    }

    #[test]
    fn in_order_acks_advance_watermark_one_by_one() {
        let mut t = tracker_at(0);
        assert_eq!(t.ack(0, 0), Some(1));
        assert_eq!(t.ack(0, 1), Some(2));
        assert_eq!(t.ack(0, 2), Some(3));
    }

    #[test]
    fn out_of_order_acks_batch_advance() {
        let mut t = OffsetTracker::new();
        t.observe(0, 3); // partition starts at offset 3
        assert_eq!(t.ack(0, 5), None); // gap: 3,4 not yet acked
        assert_eq!(t.ack(0, 4), None); // gap: 3 not yet acked
        assert_eq!(t.ack(0, 3), Some(6)); // fills run [3,4,5]; commit=6
    }

    #[test]
    fn gap_in_middle_does_not_over_commit() {
        let mut t = tracker_at(0);
        assert_eq!(t.ack(0, 0), Some(1));
        assert_eq!(t.ack(0, 2), None); // gap at 1
        assert_eq!(t.ack(0, 1), Some(3)); // fills gap; jumps over 2
    }

    #[test]
    fn ack_unknown_partition_returns_none() {
        let mut t = tracker_at(0);
        assert_eq!(t.ack(99, 0), None); // partition 99 never observed
    }

    #[test]
    fn multiple_partitions_are_independent() {
        let mut t = OffsetTracker::new();
        t.observe(0, 0);
        t.observe(1, 0);
        assert_eq!(t.ack(0, 0), Some(1));
        assert_eq!(t.ack(1, 0), Some(1));
        assert_eq!(t.ack(0, 1), Some(2));
        assert_eq!(t.ack(1, 2), None); // gap at partition 1 offset 1
    }

    #[test]
    fn non_zero_start_offset_initialises_correctly() {
        let mut t = tracker_at(1000);
        assert_eq!(t.ack(0, 1000), Some(1001));
        assert_eq!(t.ack(0, 1002), None);
        assert_eq!(t.ack(0, 1001), Some(1003));
    }

    #[test]
    fn partition_for_key_is_deterministic() {
        let n = 12;
        let p1 = partition_for_key(b"session-abc", n);
        let p2 = partition_for_key(b"session-abc", n);
        assert_eq!(p1, p2);
        assert!(p1 < n);
    }

    #[test]
    fn partition_for_key_distributes() {
        let n = 12;
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let key = format!("key-{i}");
            seen.insert(partition_for_key(key.as_bytes(), n));
        }
        // With 100 keys across 12 partitions, we should hit at least half.
        assert!(
            seen.len() >= 6,
            "poor distribution: only {} partitions hit",
            seen.len()
        );
    }

    #[tokio::test]
    async fn linger_coalesces_concurrent_callers_into_one_request() {
        let partition = Arc::new(FakePartition::default());
        let producer = Arc::new(KafkaProducer::from_parts(
            vec![Arc::clone(&partition) as Arc<dyn ProducerClient>],
            MAX_REQUEST_BYTES,
            Compression::NoCompression,
            200,
        ));
        let key = Bytes::from_static(b"k");
        let mut calls = Vec::new();
        for n in 0..3u8 {
            let producer = Arc::clone(&producer);
            let key = key.clone();
            calls.push(tokio::spawn(async move {
                producer.publish_batch(&[(key, Bytes::from(vec![n]))]).await
            }));
        }
        for call in calls {
            let outcomes = call.await.unwrap();
            assert_eq!(outcomes.len(), 1);
            assert!(matches!(outcomes[0], PublishOutcome::Published));
        }
        let requests = partition.requests.lock();
        assert_eq!(requests.len(), 1, "one produce request for three callers");
        assert_eq!(requests[0].len(), 3);
    }

    #[tokio::test]
    async fn linger_failure_blocks_later_callers_of_the_same_partition() {
        let partition = Arc::new(FakePartition {
            fail_requests: vec![0],
            ..Default::default()
        });
        let producer = Arc::new(KafkaProducer::from_parts(
            vec![Arc::clone(&partition) as Arc<dyn ProducerClient>],
            MAX_REQUEST_BYTES,
            Compression::NoCompression,
            100,
        ));
        let key = Bytes::from_static(b"k");
        let first = {
            let (producer, key) = (Arc::clone(&producer), key.clone());
            tokio::spawn(async move {
                producer
                    .publish_batch(&[(key, Bytes::from_static(b"a"))])
                    .await
            })
        };
        let second = {
            let (producer, key) = (Arc::clone(&producer), key.clone());
            tokio::spawn(async move {
                producer
                    .publish_batch(&[(key, Bytes::from_static(b"b"))])
                    .await
            })
        };
        let (first, second) = (first.await.unwrap(), second.await.unwrap());
        assert!(matches!(first[0], PublishOutcome::Failed(_)));
        assert!(matches!(second[0], PublishOutcome::Failed(_)));
        assert!(!producer.healthy());
    }

    fn config(extra: &str) -> KafkaConfig {
        toml_like(&format!(
            "{{\"brokers\":\"b:9092\",\"topic\":\"t\"{extra}}}"
        ))
    }

    fn toml_like(json: &str) -> KafkaConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn config_defaults_and_validation() {
        let c = config("");
        assert_eq!(c.compression, KafkaCompression::None);
        assert_eq!(c.acks, "all");
        assert_eq!(c.linger_ms, 0);
        assert_eq!(c.batch_bytes, MAX_REQUEST_BYTES);
        c.validate().unwrap();

        let c = config(",\"compression\":\"zstd\",\"linger_ms\":5,\"acks\":\"ALL\"");
        assert_eq!(c.compression, KafkaCompression::Zstd);
        c.validate().unwrap();

        assert!(config(",\"acks\":\"1\"").validate().is_err());
        assert!(config(",\"batch_bytes\":10").validate().is_err());
        assert!(config(",\"partitions\":0").validate().is_err());
        assert!(
            config(",\"sasl\":{\"mechanism\":\"GSSAPI\",\"username\":\"u\",\"password\":\"p\"}")
                .validate()
                .is_err()
        );
        assert!(
            serde_json::from_str::<KafkaConfig>(
                "{\"brokers\":\"b\",\"topic\":\"t\",\"compression\":\"brotli\"}"
            )
            .is_err()
        );
    }
}
