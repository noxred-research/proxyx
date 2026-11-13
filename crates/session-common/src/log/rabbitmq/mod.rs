//! RabbitMQ implementation of the captures-log abstraction, on
//! [lapin](https://crates.io/crates/lapin) with rustls.
//!
//! # Topology
//!
//! `proxyx migrate control` declares (all durable):
//!
//! - a direct exchange `<exchange>` (default `proxyx.captures`);
//! - `partitions` **quorum queues** `<queue_prefix>.p00`, `.p01`, ... bound to
//!   it with routing key `p00`, `p01`, ..., each with `x-single-active-consumer`,
//!   a delivery limit and a dead-letter exchange;
//! - a dead-letter exchange `<exchange>.dlx` and a quorum queue
//!   `<queue_prefix>.dead` holding poison messages.
//!
//! The partition of a record is `FNV-1a(key) mod partitions`, the same mapping
//! as the Kafka backend, so every message of one `source_id` (its captures and
//! its `SessionEnd`) goes to one queue. A queue delivers in publish order and
//! single active consumer gives it one consumer at a time, so per-key order
//! holds across ingester replicas and restarts. Streams were not used: the
//! maintained Rust stream client has no consumer-side acknowledgement, which
//! the ack-after-flush contract needs.
//!
//! # Producer
//! One connection and one confirm-mode channel. A batch is split per
//! partition; each partition's records are published in order in chunks, and
//! the chunk's publisher confirms are awaited before the next chunk. A nack,
//! a returned (unroutable) message, a confirm timeout or a channel error fails
//! the record, and the records after it in the partition are `NotSent`, as for
//! Kafka. (Records after a failed one inside the same chunk were already sent
//! and are reported as published.) A lost connection is re-established with
//! exponential backoff on the next publish.
//!
//! # Consumer
//! One connection, one channel with `basic.qos(prefetch)`, one consumer per
//! queue. Messages are acked manually, after the ingester flushed them to
//! the capture store; unacked messages of a lost connection are redelivered
//! (with the `redelivered` flag). Malformed envelopes are rejected without
//! requeue and land in the dead-letter queue, as do messages redelivered more
//! than `delivery_limit` times. A lost connection is re-established with
//! exponential backoff inside `poll`.
//!
//! # session_offset
//! RabbitMQ has no per-queue offset. The producer stamps each message with
//! the header `px-seq` = `(unix_ms << 20) | counter`, strictly increasing per
//! producer process (a counter in the low 20 bits, never below the clock) like
//! a Redis stream id, and the consumer uses it as `session_offset`. It is
//! monotonic per key as long as one producer process (or one wall clock)
//! publishes the key, which holds because a source's captures come from the
//! session proxy that owns the session.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::stream::SelectAll;
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions, BasicQosOptions,
    ConfirmSelectOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};
use lapin::tcp::{OwnedIdentity, OwnedTLSConfig};
use lapin::types::{AMQPValue, FieldTable, ShortString};
use lapin::uri::AMQPUri;
use lapin::{
    BasicProperties, Channel, Confirmation, Connection, ConnectionProperties, Consumer,
    ExchangeKind,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

pub use super::kafka::TlsConfig;
use super::kafka::partition_for_key;
use super::{
    AckHandle, AckInner, CaptureLogConsumer, CaptureLogProducer, ConnState, LogMessage,
    PublishOutcome,
};

/// Header carrying the record key.
const KEY_HEADER: &str = "px-key";
/// Header carrying `session_offset`.
const SEQ_HEADER: &str = "px-seq";
/// Records published before their confirms are awaited.
const CONFIRM_CHUNK: usize = 256;

fn default_exchange() -> String {
    "proxyx.captures".to_string()
}
fn default_partitions() -> u32 {
    12
}
fn default_quorum_group_size() -> u32 {
    3
}
fn default_delivery_limit() -> u32 {
    20
}
fn default_message_ttl_ms() -> u64 {
    604_800_000 // 7 days
}
fn default_prefetch() -> u16 {
    500
}
fn default_heartbeat_secs() -> u16 {
    30
}
fn default_connect_timeout_secs() -> u64 {
    10
}
fn default_confirm_timeout_secs() -> u64 {
    30
}
fn default_reconnect_initial_backoff_ms() -> u64 {
    500
}
fn default_reconnect_max_backoff_ms() -> u64 {
    30_000
}
fn default_client_name_prefix() -> String {
    "proxyx".to_string()
}

/// `[rabbitmq]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqConfig {
    /// `amqp://host:5672/%2f` or `amqps://host:5671/vhost` (TLS). Credentials
    /// may be part of the URL or set with `username` and `password`.
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Direct exchange the producers publish to.
    #[serde(default = "default_exchange")]
    pub exchange: String,
    /// Prefix of the partition queues; defaults to the exchange name.
    #[serde(default)]
    pub queue_prefix: Option<String>,
    /// Number of partition queues, **permanent** like a Kafka partition count:
    /// it decides which queue a key goes to. Changing it needs a drained log.
    #[serde(default = "default_partitions")]
    pub partitions: u32,
    /// Replicas of each quorum queue at declaration (`x-quorum-initial-group-size`);
    /// use 1 on a single node.
    #[serde(default = "default_quorum_group_size")]
    pub quorum_group_size: u32,
    /// Redeliveries of one message before it is dead-lettered
    /// (`x-delivery-limit`). Protects the pipeline from a message that keeps
    /// failing its consumer.
    #[serde(default = "default_delivery_limit")]
    pub delivery_limit: u32,
    /// Queue message TTL in milliseconds (the retention analogue); expired
    /// messages are dead-lettered. `0` keeps messages until consumed.
    #[serde(default = "default_message_ttl_ms")]
    pub message_ttl_ms: u64,
    /// Unacked messages the broker lets each queue's consumer hold. Keep it
    /// at least the ingester's `bulk_size`: acks follow the flush.
    #[serde(default = "default_prefetch")]
    pub prefetch: u16,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u16,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// How long the producer waits for the confirms of one chunk.
    #[serde(default = "default_confirm_timeout_secs")]
    pub confirm_timeout_secs: u64,
    #[serde(default = "default_reconnect_initial_backoff_ms")]
    pub reconnect_initial_backoff_ms: u64,
    #[serde(default = "default_reconnect_max_backoff_ms")]
    pub reconnect_max_backoff_ms: u64,
    /// Prefix of the connection name (`<prefix>-<component>`).
    #[serde(default = "default_client_name_prefix")]
    pub client_name_prefix: String,
    /// TLS settings for `amqps://`: a CA file and an optional client
    /// certificate and key (PEM, PKCS#8).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

impl crate::config::PartialSection for RabbitMqConfig {
    const STANDALONE: &'static [&'static str] = &["username", "password"];
}

impl RabbitMqConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
            exchange: default_exchange(),
            queue_prefix: None,
            partitions: default_partitions(),
            quorum_group_size: default_quorum_group_size(),
            delivery_limit: default_delivery_limit(),
            message_ttl_ms: default_message_ttl_ms(),
            prefetch: default_prefetch(),
            heartbeat_secs: default_heartbeat_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            confirm_timeout_secs: default_confirm_timeout_secs(),
            reconnect_initial_backoff_ms: default_reconnect_initial_backoff_ms(),
            reconnect_max_backoff_ms: default_reconnect_max_backoff_ms(),
            client_name_prefix: default_client_name_prefix(),
            tls: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let scheme_ok = self.url.starts_with("amqp://") || self.url.starts_with("amqps://");
        if !scheme_ok {
            bail!("rabbitmq.url must start with amqp:// or amqps://");
        }
        if self.tls.is_some() && !self.url.starts_with("amqps://") {
            bail!("rabbitmq.tls is set but rabbitmq.url is not amqps://");
        }
        if self.partitions == 0 || self.partitions > 1000 {
            bail!("rabbitmq.partitions must be between 1 and 1000");
        }
        if self.quorum_group_size == 0 || self.delivery_limit == 0 || self.prefetch == 0 {
            bail!("rabbitmq.quorum_group_size, delivery_limit and prefetch must be positive");
        }
        if self.exchange.is_empty() || self.exchange.len() > 200 {
            bail!("rabbitmq.exchange must be 1 to 200 characters");
        }
        if self.reconnect_initial_backoff_ms > self.reconnect_max_backoff_ms {
            bail!("rabbitmq.reconnect_initial_backoff_ms must not exceed reconnect_max_backoff_ms");
        }
        if self.connect_timeout_secs == 0 || self.confirm_timeout_secs == 0 {
            bail!("rabbitmq.connect_timeout_secs and confirm_timeout_secs must be positive");
        }
        self.uri().map(|_| ())
    }

    fn prefix(&self) -> &str {
        self.queue_prefix.as_deref().unwrap_or(&self.exchange)
    }

    /// Name of partition queue `partition`.
    pub fn queue_name(&self, partition: u32) -> String {
        format!("{}.p{partition:02}", self.prefix())
    }

    fn routing_key(partition: u32) -> String {
        format!("p{partition:02}")
    }

    fn dlx_name(&self) -> String {
        format!("{}.dlx", self.exchange)
    }

    /// Name of the dead-letter queue.
    pub fn dead_queue_name(&self) -> String {
        format!("{}.dead", self.prefix())
    }

    fn uri(&self) -> Result<AMQPUri> {
        let mut uri: AMQPUri = self
            .url
            .parse()
            .map_err(|e: String| anyhow!("invalid rabbitmq.url: {e}"))?;
        if let Some(user) = &self.username {
            uri.authority.userinfo.username = user.clone();
        }
        if let Some(password) = &self.password {
            uri.authority.userinfo.password = password.clone();
        }
        uri.query.heartbeat = Some(self.heartbeat_secs);
        Ok(uri)
    }

    fn tls_config(&self) -> Result<OwnedTLSConfig> {
        let Some(tls) = &self.tls else {
            return Ok(OwnedTLSConfig::default());
        };
        let cert_chain = tls
            .ca_cert
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading rabbitmq.tls.ca_cert {path}"))
            })
            .transpose()?;
        let identity = match (&tls.client_cert, &tls.client_key) {
            (Some(cert), Some(key)) => {
                let pem = std::fs::read(cert)
                    .with_context(|| format!("reading rabbitmq.tls.client_cert {cert}"))?;
                let key_pem = std::fs::read(key)
                    .with_context(|| format!("reading rabbitmq.tls.client_key {key}"))?;
                // The identity wants the PEM bytes (the TLS backend parses
                // them itself); parse once here so a bad key names its file.
                {
                    use rustls::pki_types::pem::PemObject as _;
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
                        .context("parsing rabbitmq.tls.client_key")?;
                }
                Some(OwnedIdentity::PKCS8 { pem, key: key_pem })
            }
            (None, None) => None,
            _ => bail!("rabbitmq.tls.client_cert and client_key must be set together"),
        };
        Ok(OwnedTLSConfig {
            identity,
            cert_chain,
        })
    }
}

/// Open a connection with the configured credentials, TLS and timeouts.
async fn connect(config: &RabbitMqConfig, component: &str) -> Result<Connection> {
    let properties = ConnectionProperties::default()
        .with_connection_name(format!("{}-{component}", config.client_name_prefix).into());
    let runtime = lapin::runtime::default_runtime().context("lapin runtime")?;
    let connecting = Connection::connect_uri_with_config(
        config.uri()?,
        properties,
        config.tls_config()?,
        runtime,
    );
    tokio::time::timeout(Duration::from_secs(config.connect_timeout_secs), connecting)
        .await
        .map_err(|_| anyhow!("connecting to RabbitMQ timed out"))?
        .context("connecting to RabbitMQ")
}

fn table(entries: Vec<(&str, AMQPValue)>) -> FieldTable {
    let mut table = FieldTable::default();
    for (key, value) in entries {
        table.insert(ShortString::from(key), value);
    }
    table
}

fn durable_queue() -> QueueDeclareOptions {
    QueueDeclareOptions {
        durable: true,
        ..QueueDeclareOptions::default()
    }
}

fn long(value: u32) -> AMQPValue {
    AMQPValue::LongLongInt(i64::from(value))
}

/// Arguments of partition queue `partition`.
fn partition_queue_arguments(config: &RabbitMqConfig) -> FieldTable {
    let mut entries = vec![
        ("x-queue-type", AMQPValue::LongString("quorum".into())),
        ("x-single-active-consumer", AMQPValue::Boolean(true)),
        (
            "x-dead-letter-exchange",
            AMQPValue::LongString(config.dlx_name().into()),
        ),
        (
            "x-dead-letter-routing-key",
            AMQPValue::LongString("dead".into()),
        ),
        ("x-delivery-limit", long(config.delivery_limit)),
        (
            "x-quorum-initial-group-size",
            long(config.quorum_group_size),
        ),
    ];
    if config.message_ttl_ms > 0 {
        entries.push((
            "x-message-ttl",
            AMQPValue::LongLongInt(i64::try_from(config.message_ttl_ms).unwrap_or(i64::MAX)),
        ));
    }
    table(entries)
}

fn dead_queue_arguments(config: &RabbitMqConfig) -> FieldTable {
    let mut entries = vec![
        ("x-queue-type", AMQPValue::LongString("quorum".into())),
        (
            "x-quorum-initial-group-size",
            long(config.quorum_group_size),
        ),
    ];
    if config.message_ttl_ms > 0 {
        entries.push((
            "x-message-ttl",
            AMQPValue::LongLongInt(i64::try_from(config.message_ttl_ms).unwrap_or(i64::MAX)),
        ));
    }
    table(entries)
}

/// Declare the exchanges, queues and bindings (idempotent). A queue that
/// already exists with different arguments makes the broker refuse the
/// declaration; the error says so.
pub async fn declare_topology(config: &RabbitMqConfig) -> Result<()> {
    config.validate()?;
    let connection = connect(config, "migrate").await?;
    let channel = connection.create_channel().await?;
    let durable = ExchangeDeclareOptions {
        durable: true,
        ..ExchangeDeclareOptions::default()
    };

    channel
        .exchange_declare(
            config.exchange.clone().into(),
            ExchangeKind::Direct,
            durable,
            FieldTable::default(),
        )
        .await
        .with_context(|| format!("declaring exchange {}", config.exchange))?;
    channel
        .exchange_declare(
            config.dlx_name().into(),
            ExchangeKind::Direct,
            durable,
            FieldTable::default(),
        )
        .await
        .context("declaring the dead-letter exchange")?;

    let dead = config.dead_queue_name();
    channel
        .queue_declare(
            dead.clone().into(),
            durable_queue(),
            dead_queue_arguments(config),
        )
        .await
        .with_context(|| declare_hint(&dead))?;
    channel
        .queue_bind(
            dead.clone().into(),
            config.dlx_name().into(),
            "dead".into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    for partition in 0..config.partitions {
        let queue = config.queue_name(partition);
        channel
            .queue_declare(
                queue.clone().into(),
                durable_queue(),
                partition_queue_arguments(config),
            )
            .await
            .with_context(|| declare_hint(&queue))?;
        channel
            .queue_bind(
                queue.into(),
                config.exchange.clone().into(),
                RabbitMqConfig::routing_key(partition).into(),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
    }
    tracing::info!(
        exchange = %config.exchange,
        partitions = config.partitions,
        "RabbitMQ topology declared"
    );
    let _ = connection.close(200, "done".into()).await;
    Ok(())
}

fn declare_hint(queue: &str) -> String {
    format!(
        "declaring queue {queue}; if it exists with different arguments (queue type, delivery \
         limit, TTL, group size), delete it once drained or restore the old settings"
    )
}

/// Fail unless every queue of the topology exists.
pub async fn verify_topology(config: &RabbitMqConfig) -> Result<()> {
    config.validate()?;
    let connection = connect(config, "migrate").await?;
    let mut names: Vec<String> = (0..config.partitions)
        .map(|p| config.queue_name(p))
        .collect();
    names.push(config.dead_queue_name());
    for name in names {
        // A passive declare of a missing queue closes its channel, so each
        // gets its own.
        let channel = connection.create_channel().await?;
        channel
            .queue_declare(
                name.clone().into(),
                QueueDeclareOptions {
                    passive: true,
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .with_context(|| {
                format!("queue {name} does not exist (run `proxyx migrate control`)")
            })?;
    }
    tracing::info!("RabbitMQ topology present");
    let _ = connection.close(200, "done".into()).await;
    Ok(())
}

/// Strictly increasing `(unix_ms << 20) | counter` values.
#[derive(Default)]
struct SeqGen {
    last: AtomicU64,
}

impl SeqGen {
    fn next(&self) -> u64 {
        let clock = (u64::try_from(unix_ms()).unwrap_or(0)) << 20;
        let mut last = self.last.load(Ordering::Relaxed);
        loop {
            let next = clock.max(last + 1);
            match self
                .last
                .compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(seen) => last = seen,
            }
        }
    }
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Exponential reconnect backoff.
struct Backoff {
    initial: Duration,
    max: Duration,
    current: Duration,
    not_before: Option<Instant>,
}

impl Backoff {
    fn new(config: &RabbitMqConfig) -> Self {
        let initial = Duration::from_millis(config.reconnect_initial_backoff_ms);
        Self {
            initial,
            max: Duration::from_millis(config.reconnect_max_backoff_ms),
            current: initial,
            not_before: None,
        }
    }

    /// Time left before the next attempt is allowed.
    fn wait(&self) -> Option<Duration> {
        self.not_before
            .and_then(|t| t.checked_duration_since(Instant::now()))
    }

    fn failed(&mut self) {
        self.not_before = Some(Instant::now() + self.current);
        self.current = (self.current * 2).min(self.max);
    }

    fn succeeded(&mut self) {
        self.current = self.initial;
        self.not_before = None;
    }
}

struct ProducerSession {
    connection: Connection,
    channel: Channel,
}

/// RabbitMQ producer: publisher confirms, reconnect with backoff.
pub struct RabbitMqProducer {
    config: RabbitMqConfig,
    component: String,
    session: tokio::sync::Mutex<Option<ProducerSession>>,
    backoff: parking_lot::Mutex<Backoff>,
    seq: SeqGen,
    state: Arc<ConnState>,
}

impl RabbitMqProducer {
    /// Connect and check that the exchange exists.
    pub async fn new(config: &RabbitMqConfig, component: &str) -> Result<Self> {
        config.validate()?;
        let producer = Self {
            config: config.clone(),
            component: component.to_string(),
            session: tokio::sync::Mutex::new(None),
            backoff: parking_lot::Mutex::new(Backoff::new(config)),
            seq: SeqGen::default(),
            state: ConnState::new("rabbitmq", "producer"),
        };
        producer
            .channel()
            .await
            .context("connecting the RabbitMQ producer (is the topology declared? run `proxyx migrate control`)")?;
        tracing::info!(exchange = %config.exchange, partitions = config.partitions, "RabbitMQ producer connected");
        Ok(producer)
    }

    /// The confirm-mode channel, reconnecting when the old one is gone.
    async fn channel(&self) -> Result<Channel> {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            if session.channel.status().connected() && session.connection.status().connected() {
                return Ok(session.channel.clone());
            }
            *guard = None;
            self.state.set(false);
        }
        if let Some(wait) = self.backoff.lock().wait() {
            bail!("RabbitMQ connection is backing off for another {wait:?}");
        }
        let connected = async {
            let connection = connect(&self.config, &self.component).await?;
            let channel = connection.create_channel().await?;
            channel
                .confirm_select(ConfirmSelectOptions::default())
                .await?;
            Ok::<_, anyhow::Error>(ProducerSession {
                connection,
                channel,
            })
        }
        .await;
        match connected {
            Ok(session) => {
                self.backoff.lock().succeeded();
                self.state.set(true);
                let channel = session.channel.clone();
                *guard = Some(session);
                Ok(channel)
            }
            Err(error) => {
                self.backoff.lock().failed();
                self.state.set(false);
                Err(error)
            }
        }
    }

    async fn drop_session(&self) {
        *self.session.lock().await = None;
        self.state.set(false);
    }
}

/// Publish one partition's records in order. Returns `(index, outcome)`.
async fn publish_partition(
    channel: Channel,
    config: RabbitMqConfig,
    partition: u32,
    records: Vec<(usize, Bytes, Bytes, u64)>,
) -> Vec<(usize, PublishOutcome)> {
    let mut results = Vec::with_capacity(records.len());
    let mut blocked = false;
    let confirm_timeout = Duration::from_secs(config.confirm_timeout_secs);
    let routing_key = RabbitMqConfig::routing_key(partition);
    for chunk in records.chunks(CONFIRM_CHUNK) {
        if blocked {
            results.extend(chunk.iter().map(|(i, ..)| (*i, PublishOutcome::NotSent)));
            continue;
        }
        let mut pending = Vec::with_capacity(chunk.len());
        for (index, key, payload, seq) in chunk {
            let properties = BasicProperties::default()
                .with_delivery_mode(2)
                .with_content_type("application/x-protobuf".into())
                .with_headers(table(vec![
                    (KEY_HEADER, AMQPValue::ByteArray(key.to_vec().into())),
                    (SEQ_HEADER, AMQPValue::LongLongInt(*seq as i64)),
                ]));
            let published = channel
                .basic_publish(
                    config.exchange.clone().into(),
                    routing_key.clone().into(),
                    BasicPublishOptions {
                        mandatory: true,
                        ..BasicPublishOptions::default()
                    },
                    payload,
                    properties,
                )
                .await;
            pending.push((*index, published));
        }
        for (index, published) in pending {
            let outcome = match published {
                Err(error) => PublishOutcome::Failed(anyhow!("RabbitMQ publish failed: {error}")),
                Ok(confirm) => match tokio::time::timeout(confirm_timeout, confirm).await {
                    Err(_) => {
                        PublishOutcome::Failed(anyhow!("RabbitMQ publisher confirm timed out"))
                    }
                    Ok(Err(error)) => PublishOutcome::Failed(anyhow!(
                        "RabbitMQ publisher confirm failed: {error}"
                    )),
                    Ok(Ok(Confirmation::Ack(None))) | Ok(Ok(Confirmation::NotRequested)) => {
                        PublishOutcome::Published
                    }
                    Ok(Ok(Confirmation::Ack(Some(_)))) => PublishOutcome::Failed(anyhow!(
                        "RabbitMQ returned the message as unroutable: queue p{partition:02} is \
                         missing (run `proxyx migrate control`)"
                    )),
                    Ok(Ok(Confirmation::Nack(_))) => {
                        PublishOutcome::Failed(anyhow!("RabbitMQ nacked the message"))
                    }
                },
            };
            if matches!(outcome, PublishOutcome::Failed(_)) {
                blocked = true;
            }
            results.push((index, outcome));
        }
    }
    results
}

#[async_trait]
impl CaptureLogProducer for RabbitMqProducer {
    async fn publish(&self, key: &[u8], payload: Bytes) -> Result<()> {
        match self
            .publish_batch(&[(Bytes::copy_from_slice(key), payload)])
            .await
            .pop()
            .expect("publish_batch returns one outcome per record")
        {
            PublishOutcome::Published => Ok(()),
            PublishOutcome::Failed(error) => Err(error),
            PublishOutcome::NotSent => unreachable!("a single record has no earlier failure"),
        }
    }

    async fn publish_batch(&self, records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
        let channel = match self.channel().await {
            Ok(channel) => channel,
            Err(error) => {
                let message = format!("{error:#}");
                return records
                    .iter()
                    .map(|_| PublishOutcome::Failed(anyhow!("{message}")))
                    .collect();
            }
        };

        let partitions = self.config.partitions as usize;
        let mut by_partition: Vec<Vec<(usize, Bytes, Bytes, u64)>> = vec![Vec::new(); partitions];
        for (index, (key, payload)) in records.iter().enumerate() {
            by_partition[partition_for_key(key, partitions)].push((
                index,
                key.clone(),
                payload.clone(),
                self.seq.next(),
            ));
        }

        let mut tasks = JoinSet::new();
        for (partition, batch) in by_partition.into_iter().enumerate() {
            if batch.is_empty() {
                continue;
            }
            tasks.spawn(publish_partition(
                channel.clone(),
                self.config.clone(),
                partition as u32,
                batch,
            ));
        }
        let mut results: Vec<PublishOutcome> = Vec::with_capacity(records.len());
        results.resize_with(records.len(), || PublishOutcome::NotSent);
        while let Some(joined) = tasks.join_next().await {
            for (index, outcome) in joined.expect("RabbitMQ publish task panicked") {
                results[index] = outcome;
            }
        }

        let failed = results
            .iter()
            .any(|r| matches!(r, PublishOutcome::Failed(_)));
        if failed && !(channel.status().connected()) {
            // The channel died under us: reconnect on the next publish.
            self.drop_session().await;
        }
        results
    }

    async fn flush_and_close(&self, _timeout: Duration) {
        // Nothing is buffered: every publish call waits for its confirms.
        if let Some(session) = self.session.lock().await.take() {
            let _ = session.connection.close(200, "shutdown".into()).await;
        }
        self.state.set(false);
    }

    fn healthy(&self) -> bool {
        self.state.is_up()
    }

    /// Reconnect if needed, then passively declare every partition queue:
    /// a round trip that fails while the broker is down, frozen or missing a
    /// queue (which would make every publish come back unroutable).
    async fn probe(&self) -> Result<()> {
        self.channel().await?;
        let guard = self.session.lock().await;
        let Some(session) = guard.as_ref() else {
            bail!("RabbitMQ connection was lost");
        };
        let timeout = Duration::from_secs(self.config.confirm_timeout_secs);
        let checked = tokio::time::timeout(timeout, async {
            for partition in 0..self.config.partitions {
                let queue = self.config.queue_name(partition);
                // A passive declare of a missing queue closes its channel,
                // so each gets its own.
                let channel = session.connection.create_channel().await?;
                channel
                    .queue_declare(
                        queue.clone().into(),
                        QueueDeclareOptions {
                            passive: true,
                            durable: true,
                            ..QueueDeclareOptions::default()
                        },
                        FieldTable::default(),
                    )
                    .await
                    .with_context(|| {
                        format!("queue {queue} is missing (run `proxyx migrate control`)")
                    })?;
                let _ = channel.close(200, "probe".into()).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        match checked {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => {
                drop(guard);
                self.drop_session().await;
                Err(anyhow!("RabbitMQ did not answer within {timeout:?}"))
            }
        }
    }
}

struct ConsumerSession {
    connection: Connection,
    deliveries: SelectAll<Consumer>,
}

/// RabbitMQ consumer over all partition queues.
pub struct RabbitMqConsumer {
    config: RabbitMqConfig,
    component: String,
    session: Option<ConsumerSession>,
    backoff: Backoff,
    state: Arc<ConnState>,
}

impl RabbitMqConsumer {
    /// Connect and start consuming every partition queue. Fails if the
    /// broker is unreachable or a queue is missing.
    pub async fn new(config: &RabbitMqConfig, component: &str) -> Result<Self> {
        config.validate()?;
        let mut consumer = Self {
            config: config.clone(),
            component: component.to_string(),
            session: None,
            backoff: Backoff::new(config),
            state: ConnState::new("rabbitmq", "consumer"),
        };
        consumer.open().await?;
        Ok(consumer)
    }

    async fn open(&mut self) -> Result<()> {
        let session = self.connect_session().await;
        match session {
            Ok(session) => {
                self.session = Some(session);
                self.backoff.succeeded();
                self.state.set(true);
                Ok(())
            }
            Err(error) => {
                self.backoff.failed();
                self.state.set(false);
                Err(error)
            }
        }
    }

    async fn connect_session(&self) -> Result<ConsumerSession> {
        let connection = connect(&self.config, &self.component).await?;
        let channel = connection.create_channel().await?;
        channel
            .basic_qos(self.config.prefetch, BasicQosOptions::default())
            .await?;
        // Single active consumer picks the first consumer to register on a
        // queue, so replicas register in different orders to spread queues.
        let partitions = self.config.partitions;
        let rotation = (uuid::Uuid::new_v4().as_u128() % u128::from(partitions)) as u32;
        let mut deliveries = SelectAll::new();
        for step in 0..partitions {
            let partition = (step + rotation) % partitions;
            let queue = self.config.queue_name(partition);
            let consumer = channel
                .basic_consume(
                    queue.clone().into(),
                    format!(
                        "{}-{}-p{partition:02}",
                        self.config.client_name_prefix, self.component
                    )
                    .into(),
                    BasicConsumeOptions::default(),
                    FieldTable::default(),
                )
                .await
                .with_context(|| {
                    format!("consuming queue {queue} (run `proxyx migrate control` first)")
                })?;
            deliveries.push(consumer);
        }
        tracing::info!(
            partitions,
            prefetch = self.config.prefetch,
            "RabbitMQ consumer started"
        );
        Ok(ConsumerSession {
            connection,
            deliveries,
        })
    }

    fn lose_session(&mut self, why: &str) {
        tracing::warn!(reason = why, "RabbitMQ consumer connection lost");
        self.session = None;
        self.state.set(false);
        self.backoff.failed();
    }
}

fn header_u64(delivery: &Delivery, name: &str) -> Option<u64> {
    match delivery.properties.headers().as_ref()?.inner().get(name)? {
        AMQPValue::LongLongInt(v) => u64::try_from(*v).ok(),
        _ => None,
    }
}

fn header_bytes(delivery: &Delivery, name: &str) -> Option<Bytes> {
    match delivery.properties.headers().as_ref()?.inner().get(name)? {
        AMQPValue::ByteArray(v) => Some(Bytes::copy_from_slice(v.as_slice())),
        AMQPValue::LongString(v) => Some(Bytes::copy_from_slice(v.as_bytes())),
        _ => None,
    }
}

struct RabbitAck {
    acker: lapin::Acker,
}

#[async_trait]
impl AckInner for RabbitAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        // `Ok(false)` means the acker's channel is gone and nothing was sent:
        // the broker will redeliver the message.
        let sent = self
            .acker
            .ack(BasicAckOptions::default())
            .await
            .context("RabbitMQ ack")?;
        if !sent {
            bail!(
                "RabbitMQ ack not sent: the channel of this delivery is closed, the message will be redelivered"
            );
        }
        Ok(())
    }

    async fn reject_boxed(self: Box<Self>) -> Result<()> {
        let sent = self
            .acker
            .nack(BasicNackOptions {
                requeue: false,
                ..BasicNackOptions::default()
            })
            .await
            .context("RabbitMQ nack")?;
        if !sent {
            bail!(
                "RabbitMQ nack not sent: the channel of this delivery is closed, the message will be redelivered"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl CaptureLogConsumer for RabbitMqConsumer {
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        if self.session.is_none() {
            if let Some(wait) = self.backoff.wait() {
                tokio::time::sleep(wait.min(Duration::from_secs(1))).await;
                return Ok(Vec::new());
            }
            self.open()
                .await
                .context("reconnecting the RabbitMQ consumer")?;
        }

        let mut messages = Vec::with_capacity(max);
        let mut lost: Option<String> = None;
        while messages.len() < max {
            let wait = if messages.is_empty() {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(1)
            };
            let Some(session) = self.session.as_mut() else {
                break;
            };
            let next = match tokio::time::timeout(wait, session.deliveries.next()).await {
                Ok(next) => next,
                Err(_) => break,
            };
            match next {
                Some(Ok(delivery)) => {
                    let session_offset = header_u64(&delivery, SEQ_HEADER).unwrap_or_else(|| {
                        // A message not published by ProxyX: use arrival time.
                        (u64::try_from(unix_ms()).unwrap_or(0)) << 20
                    });
                    messages.push(LogMessage {
                        key: header_bytes(&delivery, KEY_HEADER).unwrap_or_default(),
                        payload: Bytes::from(delivery.data),
                        session_offset,
                        ack: AckHandle::new(RabbitAck {
                            acker: delivery.acker,
                        }),
                    });
                }
                Some(Err(error)) => {
                    lost = Some(error.to_string());
                    break;
                }
                None => {
                    lost = Some("all consumers were cancelled".to_string());
                    break;
                }
            }
        }
        if let Some(why) = lost {
            if let Some(session) = self.session.take() {
                let _ = session.connection.close(200, "reconnect".into()).await;
            }
            self.lose_session(&why);
        }
        Ok(messages)
    }

    fn connection(&self) -> Option<Arc<ConnState>> {
        Some(Arc::clone(&self.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RabbitMqConfig {
        RabbitMqConfig::new("amqp://guest:guest@localhost:5672/%2f")
    }

    #[test]
    fn names_follow_the_exchange_unless_a_prefix_is_set() {
        let mut c = config();
        assert_eq!(c.queue_name(3), "proxyx.captures.p03");
        assert_eq!(c.dead_queue_name(), "proxyx.captures.dead");
        assert_eq!(c.dlx_name(), "proxyx.captures.dlx");
        c.queue_prefix = Some("cap".into());
        assert_eq!(c.queue_name(11), "cap.p11");
        assert_eq!(c.dead_queue_name(), "cap.dead");
        assert_eq!(RabbitMqConfig::routing_key(7), "p07");
    }

    /// lapin's rustls backend parses the identity key itself and wants the
    /// PEM text; handing it DER failed every mutual-TLS connection.
    #[test]
    fn a_client_key_reaches_the_tls_backend_as_pem() {
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
        };

        let rcgen::CertifiedKey {
            cert: certificate,
            key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("proxyx-rabbit-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("client.pem"), dir.join("client.key"));
        std::fs::write(&cert, certificate.pem()).unwrap();
        std::fs::write(&key, key_pair.serialize_pem()).unwrap();
        let mut c = RabbitMqConfig::new("amqps://localhost/%2f");
        c.tls = Some(TlsConfig {
            ca_cert: None,
            client_cert: Some(cert.to_string_lossy().into_owned()),
            client_key: Some(key.to_string_lossy().into_owned()),
        });
        let Some(OwnedIdentity::PKCS8 { pem, key }) = c.tls_config().unwrap().identity else {
            panic!("a client identity was configured");
        };
        let certificate = CertificateDer::from_pem_slice(&pem).unwrap();
        let private_key = PrivatePkcs8KeyDer::from_pem_slice(&key).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_client_auth_cert(vec![certificate], PrivateKeyDer::Pkcs8(private_key))
        .unwrap();
        assert!(client.client_auth_cert_resolver.has_certs());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_catches_bad_settings() {
        config().validate().unwrap();
        let mut c = config();
        c.url = "http://x".into();
        assert!(c.validate().is_err());
        let mut c = config();
        c.partitions = 0;
        assert!(c.validate().is_err());
        let mut c = config();
        c.tls = Some(TlsConfig {
            ca_cert: None,
            client_cert: None,
            client_key: None,
        });
        assert!(c.validate().is_err(), "tls needs amqps://");
        c.url = "amqps://localhost/%2f".into();
        c.validate().unwrap();
        let mut c = config();
        c.reconnect_initial_backoff_ms = 10_000;
        c.reconnect_max_backoff_ms = 100;
        assert!(c.validate().is_err());
    }

    #[test]
    fn credentials_override_the_url() {
        let mut c = config();
        c.username = Some("px".into());
        c.password = Some("secret".into());
        let uri = c.uri().unwrap();
        assert_eq!(uri.authority.userinfo.username, "px");
        assert_eq!(uri.authority.userinfo.password, "secret");
        assert_eq!(uri.query.heartbeat, Some(30));
    }

    #[test]
    fn queue_arguments_carry_the_ordering_and_poison_settings() {
        let args = partition_queue_arguments(&config());
        let inner = args.inner();
        assert!(matches!(
            inner.get("x-single-active-consumer"),
            Some(AMQPValue::Boolean(true))
        ));
        assert!(matches!(
            inner.get("x-delivery-limit"),
            Some(AMQPValue::LongLongInt(20))
        ));
        assert!(matches!(
            inner.get("x-message-ttl"),
            Some(AMQPValue::LongLongInt(604_800_000))
        ));
        let mut c = config();
        c.message_ttl_ms = 0;
        assert!(
            !partition_queue_arguments(&c)
                .inner()
                .contains_key("x-message-ttl")
        );
    }

    #[test]
    fn seq_is_strictly_increasing_even_within_one_millisecond() {
        let seq = SeqGen::default();
        let mut last = 0;
        for _ in 0..5_000 {
            let next = seq.next();
            assert!(next > last);
            last = next;
        }
    }

    #[test]
    fn backoff_doubles_to_its_cap_and_resets() {
        let mut c = config();
        c.reconnect_initial_backoff_ms = 100;
        c.reconnect_max_backoff_ms = 300;
        let mut backoff = Backoff::new(&c);
        assert!(backoff.wait().is_none());
        backoff.failed();
        assert!(backoff.wait().is_some());
        backoff.failed();
        backoff.failed();
        assert_eq!(backoff.current, Duration::from_millis(300));
        backoff.succeeded();
        assert!(backoff.wait().is_none());
        assert_eq!(backoff.current, Duration::from_millis(100));
    }
}
