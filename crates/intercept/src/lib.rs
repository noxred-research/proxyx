//! Session proxy data plane: CONNECT, HTTP and SOCKS5 listeners, optional TLS
//! interception with capture, header injection, upstream overrides, per-org
//! rate limiting and egress chaining. Entry point: [`run`].

mod api;
#[doc(hidden)]
pub mod bench_support;
mod breaker;
mod ca;
mod config;
mod context;
pub mod doctor;
mod egress;
mod health;
mod listener;
mod mitm;
mod net;
mod pipeline;
mod profiling;
mod ratelimit;
mod state;

use anyhow::{Context as _, Result};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub use config::Config;
pub use context::{ProxyContext, ProxySettings};
pub use state::ProxyState;

/// Run the session proxy until SIGTERM or ctrl-c, then drain in-flight
/// tunnels and buffered captures. `config_path` overrides the environment
/// (`PROXYX_INTERCEPT_*`).
pub async fn run(config_path: Option<&str>) -> Result<()> {
    let config = Config::load(config_path)?;
    anyhow::ensure!(
        config.tuning.max_connections > 0,
        "tuning.max_connections must be greater than 0"
    );
    let _sentry_guard = common::sentry::init(&config.sentry, "proxyx-intercept");
    let _otel_guard = common::telemetry::init("proxyx-intercept");
    // Release builds abort on panic, so this ERROR line is the only structured
    // record of the crash. The default hook still prints the plain-text message.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "proxy panicked");
        default_panic_hook(info);
    }));
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider already installed; continuing");
    }

    let proxy_id = config.id();
    let shutdown = CancellationToken::new();
    // The admin API outlives the listeners: it keeps answering `/health/live`,
    // `/health/ready` (not ready while draining) and `/metrics` until the
    // drain and the capture flush are over.
    let api_shutdown = CancellationToken::new();
    let readiness = Arc::new(health::Readiness::new());

    // --- Infrastructure ---

    // Redis connection (fatal on failure)
    let (redis_client, redis_conn) =
        common::redis_connect::connect(config.redis_url.as_str()).await?;
    tracing::info!(redis_url = %config.redis_url, "connected to Redis");

    // State with Redis fallback
    let state = ProxyState::new(
        proxy_id.clone(),
        redis_conn.clone(),
        config.no_capture_hosts.clone(),
        config.redis_key_prefix.clone(),
    );
    state.spawn_invalidation_subscriber(redis_client.clone(), shutdown.clone());

    // Rate limiter: Redis Lua token bucket or the limiter service.
    let ratelimit: Arc<dyn crate::ratelimit::RateLimiter> = match config.ratelimit.backend {
        crate::ratelimit::RateLimitBackend::Redis => {
            Arc::new(crate::ratelimit::RedisRateLimiter::from_conn(
                redis_conn.clone(),
                config.ratelimit.clone(),
                config.redis_key_prefix.clone(),
            ))
        }
        crate::ratelimit::RateLimitBackend::Limiter => {
            tracing::info!(addr = %config.ratelimit.limiter_addr, "rate limiting via limiter");
            Arc::new(crate::ratelimit::ServiceRateLimiter::new(
                config.ratelimit.clone(),
            ))
        }
    };

    // Captures-log producer + request log writer
    common::log::warn_deprecated_broker_names();
    let log_producer: Box<dyn common::log::CaptureLogProducer> = match config.broker_kind {
        config::BrokerKind::RedisStream => {
            Box::new(common::log::redis_stream::RedisStreamProducer::new(
                redis_conn.clone(),
                config.request_log.stream_name.clone(),
                config.request_log.max_stream_len,
            ))
        }
        config::BrokerKind::Kafka => Box::new(
            common::log::kafka::KafkaProducer::new(
                config
                    .kafka_config()?
                    .context("broker_kind=kafka but the [kafka] config section is missing")?,
                "proxy",
            )
            .await?,
        ),
        config::BrokerKind::Rabbitmq => Box::new(
            common::log::rabbitmq::RabbitMqProducer::new(
                config
                    .rabbitmq
                    .as_ref()
                    .context("broker_kind=rabbitmq but the [rabbitmq] config section is missing")?,
                "proxy",
            )
            .await?,
        ),
    };
    let log_producer = common::log::instrument_producer(config.broker_kind.as_str(), log_producer);
    let pipeline = Arc::new(pipeline::RequestLogWriter::new(
        config.request_log.clone(),
        log_producer,
    ));

    // Proxy context (shared across proxy listeners)
    let ctx = Arc::new(ProxyContext::new(
        state.clone(),
        ca::load(&config.ca)?,
        ratelimit.clone(),
        pipeline.clone(),
        ProxySettings::from(&config),
    )?);

    // --- Background tasks ---

    // Readiness checks: Redis reachability and the capture pipeline.
    let monitor = health::spawn_monitor(
        readiness.clone(),
        redis_conn.clone(),
        pipeline.clone(),
        config.health.clone(),
        shutdown.clone(),
    );

    // CONNECT proxy listener (HTTPS tunneling)
    let connect_ctx = ctx.clone();
    let connect_addr = config.connect_addr;
    let connect_up = readiness.register_listener("connect");
    let connect_shutdown = shutdown.clone();
    tokio::spawn(async move {
        tracing::info!(%connect_addr, "starting CONNECT proxy");
        if let Err(e) =
            listener::connect::serve(connect_addr, connect_ctx, connect_up, connect_shutdown).await
        {
            tracing::error!(error = %e, "CONNECT proxy failed");
        }
    });

    // HTTP proxy listener (optional)
    if let Some(http_addr) = config.http_addr {
        let http_ctx = ctx.clone();
        let http_up = readiness.register_listener("http");
        let http_shutdown = shutdown.clone();
        tokio::spawn(async move {
            tracing::info!(%http_addr, "starting HTTP proxy");
            if let Err(e) = listener::http::serve(http_addr, http_ctx, http_up, http_shutdown).await
            {
                tracing::error!(error = %e, "HTTP proxy failed");
            }
        });
    }

    // SOCKS5 proxy listener
    {
        let socks_addr = config.socks_addr;
        let socks_ctx = ctx.clone();
        let socks_up = readiness.register_listener("socks5");
        let socks_shutdown = shutdown.clone();
        tokio::spawn(async move {
            tracing::info!(%socks_addr, "starting SOCKS5 proxy");
            if let Err(e) =
                listener::socks::serve(socks_addr, socks_ctx, socks_up, socks_shutdown).await
            {
                tracing::error!(error = %e, "SOCKS5 proxy failed");
            }
        });
    }

    // API server (+ opt-in profiling routes)
    let profiler = profiling::enabled().then(|| {
        tracing::info!("proxy profiling enabled");
        profiling::Profiler::start(shutdown.clone())
    });
    let api_cancel = api_shutdown.clone();
    let api_addr = config.api_addr;
    let api_readiness = readiness.clone();
    let api_task = tokio::spawn(async move {
        if let Err(e) = api::serve(api_addr, api_cancel, api_readiness, profiler).await {
            tracing::error!(error = %e, "API server failed");
        }
    });

    // Session cache reaper — evicts entries past their explicit expires_at_ms.
    let reaper_state = state.clone();
    let reaper_cancel = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    let expired: Vec<uuid::Uuid> = reaper_state
                        .sessions
                        .iter()
                        .filter_map(|(k, v)| {
                            if v.expires_at_ms.load(std::sync::atomic::Ordering::Relaxed)
                                <= now_ms
                            {
                                Some(*k)
                            } else {
                                None
                            }
                        })
                        .collect();
                    for id in expired {
                        reaper_state.sessions.invalidate(&id);
                    }
                }
                _ = reaper_cancel.cancelled() => break,
            }
        }
    });

    tracing::info!(
        %proxy_id,
        connect_addr = %config.connect_addr,
        api_addr = %config.api_addr,
        "proxy started"
    );

    // Wait for shutdown signal
    let shutdown_signal = async {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
        Ok::<_, std::io::Error>(())
    };
    shutdown_signal.await?;

    let stop = Shutdown {
        readiness: &readiness,
        listeners: &shutdown,
        api: &api_shutdown,
        pipeline: &pipeline,
        health: &config.health,
        drain_timeout: std::time::Duration::from_secs(config.tuning.shutdown_drain_timeout_secs),
        drain_poll: std::time::Duration::from_secs(2),
        flush_timeout: std::time::Duration::from_secs(30),
    };
    stop.run(|| ctx.active_connections(), monitor, api_task)
        .await;
    tracing::info!("proxy stopped");

    Ok(())
}

/// The stop sequence after the shutdown signal.
struct Shutdown<'a> {
    readiness: &'a health::Readiness,
    /// Cancels the accept loops and background tasks.
    listeners: &'a CancellationToken,
    /// Cancels the admin API, last.
    api: &'a CancellationToken,
    pipeline: &'a pipeline::RequestLogWriter,
    health: &'a config::HealthConfig,
    drain_timeout: std::time::Duration,
    drain_poll: std::time::Duration,
    flush_timeout: std::time::Duration,
}

impl Shutdown<'_> {
    /// Stop the proxy after the shutdown signal, in this order:
    ///
    /// 1. Report not ready.
    /// 2. Close the listeners (after `health.drain_notice_ms`).
    /// 3. Wait for in-flight connections.
    /// 4. Flush buffered captures.
    /// 5. Stop the admin API.
    ///
    /// The API serves `/health/live`, `/health/ready` and `/metrics` through
    /// steps 1 to 4.
    async fn run(
        &self,
        active_connections: impl Fn() -> usize,
        monitor: tokio::task::JoinHandle<()>,
        api_task: tokio::task::JoinHandle<()>,
    ) {
        // Report not ready first, so the balancer stops sending before any
        // listener closes.
        self.readiness.set_draining();
        tracing::info!("shutdown signal received: reporting not ready");
        if self.health.drain_notice_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                self.health.drain_notice_ms,
            ))
            .await;
        }
        tracing::info!("shutting down: cancelling background tasks");
        self.listeners.cancel();
        let _ = monitor.await;

        // Drain in-flight tunnels before tearing down the runtime. The accept
        // loops stop on the cancelled token above, so no new connections
        // arrive; we then wait for active connection tasks (tracked by the
        // conn semaphore permits) to finish on their own. Without this, a
        // rolling deploy or KEDA scale-down aborts live proxy tunnels
        // mid-exchange when the runtime is dropped.
        let drain_deadline = std::time::Instant::now() + self.drain_timeout;
        loop {
            let active = active_connections();
            if active == 0 {
                tracing::info!("all tunnels drained");
                break;
            }
            if std::time::Instant::now() >= drain_deadline {
                tracing::warn!(
                    active,
                    "tunnel drain timeout reached; aborting remaining tunnels"
                );
                break;
            }
            tracing::info!(active, "draining in-flight tunnels");
            tokio::time::sleep(self.drain_poll).await;
        }

        // Drain captured exchanges that are already buffered between the MITM
        // path and the Redis writer. Bounded so SIGTERM cannot hang
        // indefinitely.
        self.pipeline.flush_and_close(self.flush_timeout).await;

        // Last: the admin API, so probes and scrapes work for the whole drain.
        self.api.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), api_task).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn get(addr: std::net::SocketAddr, path: &str) -> std::io::Result<(u16, String)> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        let text = String::from_utf8_lossy(&raw).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap();
        Ok((status, text))
    }

    /// During the drain the admin API keeps answering: live `200`, ready
    /// `503` with `draining`, metrics. It stops only after the drain.
    #[tokio::test]
    async fn api_outlives_the_listener_drain() {
        let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = free.local_addr().unwrap();
        drop(free);

        let readiness = Arc::new(health::Readiness::new());
        readiness
            .register_listener("connect")
            .store(true, std::sync::atomic::Ordering::Release);
        let listeners = CancellationToken::new();
        let api_cancel = CancellationToken::new();
        let api_task = tokio::spawn({
            let readiness = readiness.clone();
            let api_cancel = api_cancel.clone();
            async move {
                api::serve(addr, api_cancel, readiness, None).await.unwrap();
            }
        });
        let monitor = tokio::spawn(async {});
        let (producer, _gate) = health::testkit::GatedProducer::new(true);
        let pipeline = pipeline::RequestLogWriter::new(
            pipeline::RequestLogConfig::default(),
            Box::new(producer),
        );

        for _ in 0..100 {
            if get(addr, "/health/live").await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(get(addr, "/health/ready").await.unwrap().0, 200);

        let active = Arc::new(AtomicUsize::new(1));
        let health_cfg = config::HealthConfig::default();
        let stop_listeners = listeners.clone();
        let stop = tokio::spawn({
            let readiness = readiness.clone();
            let active = active.clone();
            let api_cancel = api_cancel.clone();
            async move {
                let pipeline = pipeline;
                Shutdown {
                    readiness: &readiness,
                    listeners: &stop_listeners,
                    api: &api_cancel,
                    pipeline: &pipeline,
                    health: &health_cfg,
                    drain_timeout: std::time::Duration::from_secs(30),
                    drain_poll: std::time::Duration::from_millis(50),
                    flush_timeout: std::time::Duration::from_secs(1),
                }
                .run(|| active.load(Ordering::SeqCst), monitor, api_task)
                .await;
            }
        });

        // One connection is still open, so the drain is waiting.
        for _ in 0..100 {
            if listeners.is_cancelled() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(listeners.is_cancelled(), "the listeners were told to stop");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !stop.is_finished(),
            "the drain waits for the open connection"
        );

        let (live, _) = get(addr, "/health/live").await.unwrap();
        assert_eq!(live, 200, "liveness holds during the drain");
        let (ready, body) = get(addr, "/health/ready").await.unwrap();
        assert_eq!(ready, 503);
        assert!(body.contains("\"draining\":true"), "{body}");
        let (metrics, body) = get(addr, "/metrics").await.unwrap();
        assert_eq!(metrics, 200);
        assert!(
            body.contains("proxyx_intercept_draining"),
            "metrics served while draining"
        );

        active.store(0, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(10), stop)
            .await
            .expect("shutdown finished")
            .unwrap();
        assert!(
            get(addr, "/health/live").await.is_err(),
            "the API is gone after the drain"
        );
    }
}
