//! PostgreSQL handler for storing captured request events.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tokio::sync::mpsc;
use tokio::time::interval;

use common::types::CapturedRequest;

use super::normalize::{NormalizedCapturedRequest, clamp_u64_to_i32, headers_to_map};
fn default_max_connections() -> u32 {
    5
}

fn default_bulk_size() -> usize {
    100
}

fn default_flush_interval() -> u64 {
    5
}

fn default_max_buffer() -> usize {
    10000
}

fn default_circuit_threshold() -> u32 {
    5
}

fn default_circuit_reset() -> u64 {
    60
}

/// PostgreSQL handler configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PostgresConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_bulk_size")]
    pub bulk_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_max_buffer")]
    pub max_buffer_size: usize,
    #[serde(default = "default_circuit_threshold")]
    pub circuit_breaker_threshold: u32,
    #[serde(default = "default_circuit_reset")]
    pub circuit_breaker_reset_secs: u64,
}

/// Document prepared for PostgreSQL insertion from a captured request.
struct HttpRequestDocument {
    org_id: String,
    timestamp: time::OffsetDateTime,
    method: String,
    path: String,
    host: String,
    scheme: String,
    request_headers: Vec<(String, String)>,
    request_body: Option<String>,
    request_size: u64,
    status_code: u32,
    response_headers: Vec<(String, String)>,
    response_body: Option<String>,
    response_size: u64,
    duration_ms: u64,
    ratelimit_wait_ms: u64,
    source: String,
    source_id: Option<String>,
    session_id: common::types::SessionId,
    proxy_id: String,
    num_request: u64,
}

impl HttpRequestDocument {
    fn from_captured(req: &CapturedRequest) -> Self {
        let normalized = NormalizedCapturedRequest::from_captured(req);
        Self {
            org_id: normalized.org_id,
            timestamp: normalized.timestamp,
            method: normalized.method,
            path: normalized.path,
            host: normalized.host,
            scheme: normalized.scheme,
            request_headers: normalized.request_headers,
            request_body: normalized.request_body,
            request_size: normalized.request_size,
            status_code: normalized.status_code,
            response_headers: normalized.response_headers,
            response_body: normalized.response_body,
            response_size: normalized.response_size,
            duration_ms: normalized.duration_ms,
            ratelimit_wait_ms: normalized.ratelimit_wait_ms,
            source: normalized.source,
            source_id: normalized.source_id,
            session_id: normalized.session_id,
            proxy_id: normalized.proxy_id,
            num_request: normalized.num_request,
        }
    }
}

/// PostgreSQL event handler that batches and flushes captured requests.
pub struct PostgresHandler {
    sender: mpsc::Sender<HttpRequestDocument>,
}

impl PostgresHandler {
    /// Create a new PostgreSQL handler. Spawns a background flusher task.
    pub async fn new(config: PostgresConfig) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.url)
            .await?;

        tracing::info!(
            url = %config.url,
            max_connections = config.max_connections,
            "PostgreSQL connection pool created"
        );

        let (sender, receiver) = mpsc::channel(config.bulk_size * 2);

        let flusher = Flusher {
            pool,
            config: config.clone(),
            buffer: Arc::new(Mutex::new(Vec::with_capacity(config.bulk_size))),
            receiver,
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            circuit_open_until: Arc::new(AtomicU64::new(0)),
        };
        tokio::spawn(flusher.run());

        Ok(Self { sender })
    }

    /// Send a captured request to the handler. Applies backpressure via channel.
    pub async fn send(&self, captured: &CapturedRequest) -> Result<()> {
        let doc = HttpRequestDocument::from_captured(captured);
        self.sender
            .send(doc)
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL flusher dropped — channel closed"))?;
        Ok(())
    }
}

/// Background task that batches and flushes events to PostgreSQL.
struct Flusher {
    pool: PgPool,
    config: PostgresConfig,
    buffer: Arc<Mutex<Vec<HttpRequestDocument>>>,
    receiver: mpsc::Receiver<HttpRequestDocument>,
    consecutive_failures: Arc<AtomicU32>,
    circuit_open_until: Arc<AtomicU64>,
}

impl Flusher {
    async fn run(mut self) {
        let mut flush_interval = interval(Duration::from_secs(self.config.flush_interval_secs));

        loop {
            tokio::select! {
                result = self.receiver.recv() => {
                    match result {
                        Some(doc) => {
                            let should_flush = {
                                let mut buffer = self.buffer.lock();
                                if buffer.len() >= self.config.max_buffer_size {
                                    let dropped = buffer.len() - self.config.max_buffer_size + 1;
                                    buffer.drain(0..dropped);
                                    tracing::warn!(
                                        dropped,
                                        max_size = self.config.max_buffer_size,
                                        "PostgreSQL buffer overflow, dropped oldest events"
                                    );
                                }
                                buffer.push(doc);
                                buffer.len() >= self.config.bulk_size
                            };
                            if should_flush {
                                self.flush().await;
                            }
                        }
                        None => {
                            tracing::info!("PostgreSQL handler channel closed, flushing remaining");
                            self.flush().await;
                            break;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    self.flush().await;
                }
            }
        }
    }

    fn is_circuit_open(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.circuit_open_until.load(Ordering::Relaxed)
    }

    fn open_circuit(&self) {
        let reset_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.config.circuit_breaker_reset_secs;

        self.circuit_open_until.store(reset_at, Ordering::Relaxed);
        tracing::error!(
            reset_secs = self.config.circuit_breaker_reset_secs,
            "PostgreSQL circuit breaker opened"
        );
    }

    fn record_success(&self) {
        let prev = self.consecutive_failures.swap(0, Ordering::Relaxed);
        if prev > 0 {
            tracing::info!("PostgreSQL connection recovered after {} failures", prev);
        }
    }

    fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.config.circuit_breaker_threshold {
            self.open_circuit();
        }
    }

    async fn flush(&self) {
        if self.is_circuit_open() {
            tracing::debug!("PostgreSQL circuit breaker open, skipping flush");
            return;
        }

        let docs: Vec<HttpRequestDocument> = {
            let mut buffer = self.buffer.lock();
            if buffer.is_empty() {
                return;
            }
            std::mem::take(&mut *buffer)
        };

        let count = docs.len();

        let mut ids = Vec::with_capacity(count);
        let mut org_ids = Vec::with_capacity(count);
        let mut timestamps = Vec::with_capacity(count);
        let mut methods = Vec::with_capacity(count);
        let mut paths = Vec::with_capacity(count);
        let mut hosts = Vec::with_capacity(count);
        let mut schemes = Vec::with_capacity(count);
        let mut session_ids = Vec::with_capacity(count);
        let mut proxy_ids = Vec::with_capacity(count);
        let mut num_requests = Vec::with_capacity(count);
        let mut request_headers = Vec::with_capacity(count);
        let mut request_bodies = Vec::with_capacity(count);
        let mut request_sizes = Vec::with_capacity(count);
        let mut status_codes = Vec::with_capacity(count);
        let mut response_headers = Vec::with_capacity(count);
        let mut response_bodies = Vec::with_capacity(count);
        let mut response_sizes = Vec::with_capacity(count);
        let mut duration_ms_vec = Vec::with_capacity(count);
        let mut ratelimit_wait_ms_vec = Vec::with_capacity(count);
        let mut sources = Vec::with_capacity(count);
        let mut source_ids = Vec::with_capacity(count);

        for doc in docs {
            ids.push(uuid::Uuid::new_v4());
            org_ids.push(doc.org_id);
            timestamps.push(doc.timestamp);
            methods.push(doc.method);
            paths.push(doc.path);
            hosts.push(doc.host);
            schemes.push(doc.scheme);
            session_ids.push(doc.session_id.to_string());
            proxy_ids.push(doc.proxy_id);
            num_requests.push(clamp_u64_to_i32(doc.num_request));

            let req_headers_json = headers_to_map(&doc.request_headers);
            request_headers.push(req_headers_json);

            request_bodies.push(doc.request_body);
            request_sizes.push(clamp_u64_to_i32(doc.request_size));
            status_codes.push(doc.status_code as i32);

            let resp_headers_json = headers_to_map(&doc.response_headers);
            response_headers.push(resp_headers_json);

            response_bodies.push(doc.response_body);
            response_sizes.push(clamp_u64_to_i32(doc.response_size));
            duration_ms_vec.push(clamp_u64_to_i32(doc.duration_ms));
            ratelimit_wait_ms_vec.push(clamp_u64_to_i32(doc.ratelimit_wait_ms));
            sources.push(doc.source);
            source_ids.push(doc.source_id);
        }

        let result = sqlx::query(
            r#"
            INSERT INTO http_captures (
                id, org_id, timestamp, method, path, host, scheme,
                session_id, proxy_id, num_request,
                request_headers, request_body, request_size,
                status_code, response_headers, response_body, response_size,
                duration_ms, ratelimit_wait_ms, source, source_id
            ) SELECT * FROM UNNEST(
                $1::uuid[], $2::text[], $3::timestamptz[], $4::text[], $5::text[],
                $6::text[], $7::text[], $8::text[], $9::text[], $10::int4[],
                $11::jsonb[], $12::text[], $13::int4[],
                $14::int4[], $15::jsonb[], $16::text[], $17::int4[],
                $18::int4[], $19::int4[], $20::text[], $21::text[]
            )
            "#,
        )
        .bind(&ids)
        .bind(&org_ids)
        .bind(&timestamps)
        .bind(&methods)
        .bind(&paths)
        .bind(&hosts)
        .bind(&schemes)
        .bind(&session_ids)
        .bind(&proxy_ids)
        .bind(&num_requests)
        .bind(&request_headers)
        .bind(&request_bodies)
        .bind(&request_sizes)
        .bind(&status_codes)
        .bind(&response_headers)
        .bind(&response_bodies)
        .bind(&response_sizes)
        .bind(&duration_ms_vec)
        .bind(&ratelimit_wait_ms_vec)
        .bind(&sources)
        .bind(&source_ids)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {
                tracing::debug!(count, "flushed events to PostgreSQL");
                self.record_success();
            }
            Err(e) => {
                tracing::error!(error = %e, count, "PostgreSQL bulk insert failed");
                self.record_failure();
            }
        }
    }
}
