//! `proxyx control`: the session control plane (sessions API, ingester,
//! migrations, GraphQL schema tooling).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    broker_admin, ca,
    capture_store::{self, CaptureBackend},
    config::{BrokerKind, ControlConfig},
    consumer, group_consumer, migrations, pipeline, runtime, server, session,
};
use anyhow::{Context as _, Result};
use clap::{Args, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;

const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Arguments of `proxyx control`.
#[derive(Args)]
pub struct ControlArgs {
    /// Configuration file; overrides the environment (`PROXYX_CONTROL_*`).
    #[arg(short, long, global = true)]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// A control-plane role.
#[derive(Subcommand)]
pub enum Command {
    /// Start the API server
    Api,
    /// Start the ingester (consume request logs, write to the capture store)
    Ingester,
    /// Manage API keys of `auth_mode = "keys"` (needs Postgres only)
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// GraphQL schema operations
    Schema {
        #[command(subcommand)]
        action: SchemaAction,
    },
}

/// API key administration.
#[derive(Subcommand)]
pub enum KeysAction {
    /// Create a key and print it once on stdout.
    Create {
        /// What the key may do.
        #[arg(long, value_enum)]
        kind: crate::keys::KeyKind,
        /// Org the key acts in (required for service and user keys, refused for admin keys).
        #[arg(long)]
        org: Option<String>,
        /// Name of the holder, e.g. `crawler` or `ops@example.com` (1-64 of [A-Za-z0-9._@-]).
        #[arg(long)]
        name: String,
    },
    /// List keys (without secrets) as JSON lines.
    List {
        /// Only the keys of this org.
        #[arg(long)]
        org: Option<String>,
    },
    /// Disable a key by the id `list` shows.
    Disable { id: String },
}

/// GraphQL schema tooling; needs no infrastructure.
#[derive(Subcommand)]
pub enum SchemaAction {
    /// Export the federation SDL to stdout or a file
    Export {
        /// Write SDL to this path instead of stdout
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Validate the federation SDL
    Validate,
    /// Write the federation subgraph manifest JSON locally (no S3).
    Manifest {
        /// Directory to write proxyx.json into
        #[arg(short, long)]
        out: String,
        /// Git SHA / release tag identifying this SDL (or PROVENANCE_ID env)
        #[arg(long)]
        version: Option<String>,
    },
}

/// Which stores `migrate` touches.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum MigrateTarget {
    /// The relational database, the schema of the configured capture store and
    /// the captures log of the configured broker.
    All,
    /// The relational database `database_url` names (PostgreSQL, MariaDB or
    /// SQLite).
    #[value(alias = "postgres")]
    Database,
    Clickhouse,
    /// OpenSearch / Elasticsearch index templates.
    Opensearch,
    /// The captures log of the configured broker (Kafka topic or RabbitMQ
    /// queues); Redis Streams needs none.
    Broker,
}

/// Run one control-plane role until it finishes or the process is signalled.
pub async fn run(cli: ControlArgs) -> Result<()> {
    match cli.command {
        Command::Schema { action } => run_schema(action).await,
        _ => run_service(cli).await,
    }
}

/// Schema subcommands don't need any infrastructure connections.
async fn run_schema(action: SchemaAction) -> Result<()> {
    use crate::server::traffic_graphql;

    let sdl = traffic_graphql::federation_sdl();

    match action {
        SchemaAction::Export { output } => {
            if let Some(path) = output {
                std::fs::create_dir_all(
                    std::path::Path::new(&path)
                        .parent()
                        .unwrap_or(std::path::Path::new(".")),
                )?;
                std::fs::write(&path, &sdl)?;
                eprintln!("GraphQL SDL written to {path}");
            } else {
                print!("{sdl}");
            }
        }
        SchemaAction::Validate => {
            // If we got here, the schema built successfully and SDL was generated.
            // async-graphql validates the schema at build time.
            eprintln!("GraphQL federation schema is valid ({} bytes)", sdl.len());
        }
        SchemaAction::Manifest { out, version } => {
            write_manifest(&out, &sdl, version)?;
        }
    }
    Ok(())
}

/// Write a deterministic subgraph manifest matching the Python `_build_manifest`
/// shape to `{out}/proxyx.json` (no timestamp — `version` identifies the SDL —
/// so the file is a reproducible build artifact). The supergraph composition
/// (Nix) consumes it; there is no S3 publish.
fn write_manifest(out: &str, sdl: &str, version: Option<String>) -> Result<()> {
    let version = version
        .or_else(|| std::env::var("PROVENANCE_ID").ok())
        .filter(|v| !v.trim().is_empty())
        .context("--version is required (or set PROVENANCE_ID)")?;
    let routing_url = std::env::var("PROXYX_SCHEMA_ROUTING_URL")
        .unwrap_or_else(|_| "http://localhost:9000/graphql".to_string());

    let manifest = serde_json::json!({
        "subgraph": "proxyx",
        "routing_url": routing_url,
        "schema": sdl,
        "version": version.trim(),
    });

    std::fs::create_dir_all(out)?;
    let path = std::path::Path::new(out).join("proxyx.json");
    std::fs::write(&path, serde_json::to_vec(&manifest)?)?;
    eprintln!("Wrote proxyx manifest to {}", path.display());
    Ok(())
}

async fn run_service(cli: ControlArgs) -> Result<()> {
    let config = ControlConfig::load(cli.config.as_deref())?;

    match cli.command {
        Command::Api => run_api(config).await,
        Command::Ingester => run_ingester(config).await,
        Command::Keys { action } => run_keys(config, action).await,
        Command::Schema { .. } => unreachable!(),
    }
}

async fn run_api(config: ControlConfig) -> Result<()> {
    let _guard = runtime::init_process(&config, "api");
    common::log::warn_deprecated_broker_names();
    config.validate_broker()?;

    let db = crate::db::Db::connect(&config.database_url, 10).await?;
    tracing::info!(backend = %db.backend(), "connected to the database");

    let capture_store = capture_store::build_store(&config).await?;

    let view_store = Arc::new(crate::view_store::ViewStore::from_config(&config).await?);
    tracing::info!(backend = ?config.traffic_views_backend, "traffic view store ready");

    let shutdown = CancellationToken::new();

    let (_, redis_conn) = common::redis_connect::connect(config.redis_url.as_str()).await?;
    tracing::info!(redis_url = %config.redis_url, "connected to Redis");

    let ca_cert_pem = ca::load_ca_cert_pem(&config.ca)?;

    let log_producer: Box<dyn common::log::CaptureLogProducer> = match config.broker_kind {
        BrokerKind::RedisStream => Box::new(common::log::redis_stream::RedisStreamProducer::new(
            redis_conn.clone(),
            config.request_log_stream.clone(),
            config.request_log_max_stream_len,
        )),
        BrokerKind::Kafka => Box::new(
            common::log::kafka::KafkaProducer::new(
                config
                    .kafka_config()?
                    .context("broker_kind=kafka but the [kafka] config section is missing")?,
                "api",
            )
            .await?,
        ),
        BrokerKind::Rabbitmq => Box::new(
            common::log::rabbitmq::RabbitMqProducer::new(
                config
                    .rabbitmq
                    .as_ref()
                    .context("broker_kind=rabbitmq but the [rabbitmq] config section is missing")?,
                "api",
            )
            .await?,
        ),
    };
    let log_producer: Arc<dyn common::log::CaptureLogProducer> = Arc::from(
        common::log::instrument_producer(config.broker_kind.as_str(), log_producer),
    );
    let broker_producer = Arc::clone(&log_producer);

    let session_manager = Arc::new(session::SessionManager::new(
        redis_conn.clone(),
        db.clone(),
        ca_cert_pem.clone(),
        config.session_default_ttl_secs,
        config.default_rate_limit_rpm,
        config.default_rate_limit_burst,
        log_producer,
        config.proxy_public_host.clone(),
        config.proxy_public_host_socks5.clone(),
        config.redis_key_prefix.clone(),
    ));

    let reaper_manager = session_manager.clone();
    let reaper_shutdown = shutdown.clone();
    let reaper_view_store = view_store.clone();
    let reaper_db = db.clone();
    let view_ttl = std::time::Duration::from_secs(config.traffic_views_ttl_secs);
    let mut reaper_handle = tokio::spawn(async move {
        const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        const REAP_GRACE: std::time::Duration = std::time::Duration::from_secs(300);
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = reaper_manager.reap_expired_sessions(REAP_GRACE).await {
                        tracing::warn!(error = %e, "session reaper pass failed");
                    }
                    // Re-drive sessions stranded in `consuming` by a failed
                    // SessionEnd publish / Redis-expired attach. A healthy
                    // teardown closes within seconds; the 5-minute grace is
                    // deliberately generous so we do not republish while the
                    // consumer is still draining its current batch.
                    const CONSUMING_GRACE: std::time::Duration =
                        std::time::Duration::from_secs(300);
                    if let Err(e) = reaper_manager.reap_stuck_consuming(CONSUMING_GRACE).await {
                        tracing::warn!(error = %e, "stuck-consuming reaper pass failed");
                    }
                    if let Err(e) = crate::views::expire_completed_views(
                        &reaper_view_store,
                        &reaper_db,
                        view_ttl,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "traffic view expiry pass failed");
                    }
                }
                _ = reaper_shutdown.cancelled() => break,
            }
        }
    });

    let api_state = Arc::new(server::AppState {
        config: config.clone(),
        session_manager: session_manager.clone(),
        redis: redis_conn.clone(),
        ca_cert_pem,
        db: db.clone(),
        capture_store,
        broker_producer,
        default_rate_limit_rpm: config.default_rate_limit_rpm,
        default_rate_limit_burst: config.default_rate_limit_burst,
        view_store,
        keys: crate::keys::KeyStore::new(db.clone()),
    });
    let api_cancel = shutdown.clone();
    let api_addr = config.api_addr;
    let api_handle =
        tokio::spawn(async move { server::serve(api_addr, api_state, api_cancel).await });
    let result = supervise_server(api_handle, shutdown, "API server", wait_for_shutdown()).await;
    let reaper_result = drain_task(&mut reaper_handle, "session reaper", DRAIN_TIMEOUT).await;
    result?;
    reaper_result?;
    tracing::info!("api stopped");
    Ok(())
}

async fn run_ingester(config: ControlConfig) -> Result<()> {
    let _guard = runtime::init_process(&config, "ingester");
    common::log::warn_deprecated_broker_names();
    config.validate_broker()?;

    let db = crate::db::Db::connect(&config.database_url, 10).await?;
    tracing::info!(backend = %db.backend(), "connected to the database");
    // ClickHouse schema is managed out-of-band (Replicated database + manual
    // DDL during the 2026-07 recovery); the boot-time migration gate is removed
    // so the ingester starts against a hand-provisioned schema. The OpenSearch
    // sink only checks that its index templates exist.

    let shutdown = CancellationToken::new();

    let log_consumer: Box<dyn common::log::CaptureLogConsumer> = match config.broker_kind {
        BrokerKind::RedisStream => {
            let (redis_client, redis_conn) =
                common::redis_connect::connect(config.redis_url.as_str()).await?;
            tracing::info!(redis_url = %config.redis_url, "connected to Redis (stream consumer)");
            let consumer_id = format!(
                "ingester-{}",
                uuid::Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("0")
            );
            Box::new(
                common::log::redis_stream::RedisStreamConsumer::new(
                    redis_client,
                    redis_conn,
                    config.request_log_stream.clone(),
                    config.consumer_group.clone(),
                    consumer_id,
                )
                .await?,
            )
        }
        BrokerKind::Kafka => {
            let kafka = config
                .kafka_config()?
                .context("broker_kind=kafka but the [kafka] config section is missing")?;
            Box::new(group_consumer::KafkaGroupConsumer::new(
                kafka,
                &config.consumer_group,
                &format!("{}-{}", kafka.client_id_prefix, uuid::Uuid::new_v4()),
            )?)
        }
        BrokerKind::Rabbitmq => {
            let rabbitmq = config
                .rabbitmq
                .as_ref()
                .context("broker_kind=rabbitmq but the [rabbitmq] config section is missing")?;
            Box::new(common::log::rabbitmq::RabbitMqConsumer::new(rabbitmq, "ingester").await?)
        }
    };
    let log_consumer = common::log::instrument_consumer(config.broker_kind.as_str(), log_consumer);
    // Finish fallible setup before starting the pipeline's background drain.
    let sink = capture_store::build_sink(&config).await?;
    let pipeline = pipeline::RequestPipeline::new(sink, 256);
    let pipeline_sender = pipeline.sender();
    let broker_connection = log_consumer.connection();
    let log_consumer = consumer::RequestLogConsumer::new(
        log_consumer,
        config.session_lifecycle_writes.then(|| db.clone()),
        pipeline_sender,
    );
    let consumer_shutdown = shutdown.clone();
    let ingest_healthy = Arc::new(AtomicBool::new(true));
    let ingest_healthy_flag = Arc::clone(&ingest_healthy);
    let mut consumer_handle = tokio::spawn(async move {
        log_consumer.run(consumer_shutdown).await;
    });

    let health_shutdown = shutdown.clone();
    let health_addr = config.ingester_health_addr;
    let health_sink = pipeline.sink();
    let health_handle = tokio::spawn(serve_health(
        health_addr,
        health_shutdown,
        ingest_healthy,
        health_sink,
        broker_connection,
    ));

    tracing::info!(
        stream = %config.request_log_stream,
        group = %config.consumer_group,
        health_addr = %config.ingester_health_addr,
        "ingester started"
    );

    let mut consumer_finished = false;
    let stop = async {
        tokio::select! {
            result = wait_for_shutdown() => result,
            result = &mut consumer_handle => {
                consumer_finished = true;
                ingest_healthy_flag.store(false, Ordering::Relaxed);
                result.context("ingester consumer task failed")?;
                anyhow::bail!("ingester consumer exited unexpectedly");
            }
        }
    };
    let result = supervise_server(health_handle, shutdown, "ingester health server", stop).await;
    tracing::info!("draining ingester...");
    let consumer_result = if consumer_finished {
        Ok(())
    } else {
        drain_task(&mut consumer_handle, "ingester consumer", DRAIN_TIMEOUT).await
    };
    // Always close the pipeline, including health bind, signal and task errors.
    pipeline.flush_and_close(DRAIN_TIMEOUT).await;
    result?;
    consumer_result?;
    tracing::info!("ingester stopped");
    Ok(())
}

async fn run_keys(config: ControlConfig, action: KeysAction) -> Result<()> {
    let db = crate::db::Db::connect(&config.database_url, 1)
        .await
        .context("connect to the database (database_url)")?;
    let keys = crate::keys::KeyStore::new(db);
    match action {
        KeysAction::Create { kind, org, name } => {
            let key = keys.create(kind, org.as_deref(), &name).await?;
            println!("{key}");
        }
        KeysAction::List { org } => {
            for info in keys.list(org.as_deref()).await? {
                println!("{}", serde_json::to_string(&info)?);
            }
        }
        KeysAction::Disable { id } => {
            if !keys.disable(&id).await? {
                anyhow::bail!("no live key has id {id}");
            }
            eprintln!("disabled {id}");
        }
    }
    Ok(())
}

/// Apply (or with `check`, verify) the control-plane migrations of `target`;
/// `config` overrides the environment (`PROXYX_CONTROL_*`).
pub async fn migrate(config: Option<&str>, target: MigrateTarget, check: bool) -> Result<()> {
    let config = ControlConfig::load(config)?;
    let _guard = runtime::init_process(&config, "migrate");
    migrate_stores(&config, target, check).await
}

async fn migrate_stores(config: &ControlConfig, target: MigrateTarget, check: bool) -> Result<()> {
    let store_schema = match target {
        MigrateTarget::All => Some(config.capture_store.backend),
        MigrateTarget::Clickhouse => Some(CaptureBackend::ClickHouse),
        MigrateTarget::Opensearch => Some(CaptureBackend::OpenSearch),
        MigrateTarget::Database | MigrateTarget::Broker => None,
    };
    if matches!(target, MigrateTarget::All | MigrateTarget::Database) {
        let db = crate::db::Db::connect(&config.database_url, 2).await?;
        if check {
            migrations::verify_database(&db).await?;
        } else {
            migrations::run_database(&db).await?;
        }
    }
    let broker = matches!(target, MigrateTarget::All | MigrateTarget::Broker);
    common::log::warn_deprecated_broker_names();
    if broker {
        config.validate_broker()?;
    }

    if check {
        match store_schema {
            Some(CaptureBackend::ClickHouse) => {
                let ch = runtime::clickhouse_client(config.clickhouse_config()?);
                migrations::verify_clickhouse(&ch).await?;
            }
            Some(CaptureBackend::OpenSearch) => {
                capture_store::migrate_opensearch(config, true).await?;
            }
            None => {}
        }
        if broker {
            broker_admin::verify_broker(config).await?;
        }
    } else {
        match store_schema {
            Some(CaptureBackend::ClickHouse) => {
                runtime::ensure_clickhouse_database(config.clickhouse_config()?).await?;
                let ch = runtime::clickhouse_client(config.clickhouse_config()?);
                migrations::run_clickhouse(&ch).await?;
            }
            Some(CaptureBackend::OpenSearch) => {
                capture_store::migrate_opensearch(config, false).await?;
            }
            None => {}
        }
        if broker {
            broker_admin::ensure_broker(config).await?;
        }
    }

    Ok(())
}

/// `/health` is `200` while the consumer runs, the capture store's circuit
/// breaker is closed and the broker connection is up, otherwise `503` with
/// the reason.
async fn serve_health(
    addr: std::net::SocketAddr,
    cancel: CancellationToken,
    healthy: Arc<AtomicBool>,
    sink: Arc<dyn pipeline::CaptureSink>,
    broker: Option<Arc<common::log::ConnState>>,
) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route(
            "/health",
            axum::routing::get(move || {
                let healthy = Arc::clone(&healthy);
                let sink = Arc::clone(&sink);
                let broker = broker.clone();
                async move {
                    ingester_health(
                        healthy.load(Ordering::Relaxed),
                        sink.circuit_open(),
                        broker.as_ref().is_none_or(|b| b.is_up()),
                    )
                }
            }),
        )
        .route(
            "/metrics",
            axum::routing::get(|| async {
                (
                    [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                    common::metrics::render(),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "ingester health server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    Ok(())
}

fn ingester_health(
    consumer_running: bool,
    store_circuit_open: bool,
    broker_connected: bool,
) -> (axum::http::StatusCode, &'static str) {
    use axum::http::StatusCode;
    if !consumer_running {
        (StatusCode::SERVICE_UNAVAILABLE, "consumer stopped")
    } else if !broker_connected {
        (StatusCode::SERVICE_UNAVAILABLE, "broker connection down")
    } else if store_circuit_open {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "capture store circuit breaker open",
        )
    } else {
        (StatusCode::OK, "ok")
    }
}

async fn drain_task<T>(
    task: &mut tokio::task::JoinHandle<T>,
    name: &str,
    timeout: std::time::Duration,
) -> Result<T> {
    match tokio::time::timeout(timeout, &mut *task).await {
        Ok(result) => result.with_context(|| format!("{name} task failed")),
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("{name} did not drain within {timeout:?}");
        }
    }
}

async fn supervise_server(
    mut task: tokio::task::JoinHandle<Result<()>>,
    shutdown: CancellationToken,
    name: &str,
    signal: impl Future<Output = Result<()>>,
) -> Result<()> {
    let signal_result = tokio::select! {
        result = &mut task => {
            shutdown.cancel();
            result.with_context(|| format!("{name} task failed"))?
                .with_context(|| format!("{name} failed"))?;
            anyhow::bail!("{name} exited unexpectedly");
        }
        result = signal => result,
    };
    shutdown.cancel();
    let drain_result = drain_task(&mut task, name, DRAIN_TIMEOUT)
        .await
        .and_then(|result| result.with_context(|| format!("{name} failed during shutdown")));
    signal_result?;
    drain_result
}

async fn wait_for_shutdown() -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = sigterm.recv() => {},
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use figment::{Figment, providers::Format as _, providers::Toml};

    fn empty_config() -> ControlConfig {
        Figment::new()
            .merge(Toml::string(""))
            .extract()
            .expect("default control config")
    }

    #[tokio::test]
    async fn standalone_redis_broker_migration_needs_no_database_or_store() {
        let mut config = empty_config();
        assert!(config.database_url.is_empty());
        config.redis_url = "not a Redis URL".to_owned();
        for check in [false, true] {
            migrate_stores(&config, MigrateTarget::Broker, check)
                .await
                .expect("Redis broker migration needs no connections");
        }
    }

    #[tokio::test]
    async fn standalone_store_migrations_require_only_the_selected_store_config() {
        let mut config = empty_config();
        // An unconfigured broker must not gate either standalone store.
        config.broker_kind = BrokerKind::Kafka;
        for check in [false, true] {
            for (target, section) in [
                (MigrateTarget::Clickhouse, "[clickhouse]"),
                (MigrateTarget::Opensearch, "[capture_store.opensearch]"),
            ] {
                let error = migrate_stores(&config, target, check)
                    .await
                    .expect_err("selected store config is required");
                assert!(error.to_string().contains(section), "{error:#}");
            }
        }
    }

    #[tokio::test]
    async fn database_targets_still_require_a_database() {
        let config = empty_config();
        for check in [false, true] {
            for target in [MigrateTarget::All, MigrateTarget::Database] {
                assert!(migrate_stores(&config, target, check).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn server_bind_failure_stops_supervision_without_a_signal() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve loopback port");
        let addr = occupied.local_addr().expect("reserved address");
        let task = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, axum::Router::new()).await?;
            Ok(())
        });
        let shutdown = CancellationToken::new();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            supervise_server(task, shutdown.clone(), "API server", std::future::pending()),
        )
        .await
        .expect("bind failure must not wait for a signal")
        .expect_err("occupied bind must fail");
        assert!(error.to_string().contains("API server failed"), "{error:#}");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("bind error retains its source")
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn unexpected_successful_server_exit_is_an_error() {
        let shutdown = CancellationToken::new();
        let error = supervise_server(
            tokio::spawn(async { Ok(()) }),
            shutdown.clone(),
            "API server",
            std::future::pending(),
        )
        .await
        .expect_err("server must not stop before shutdown");
        assert!(error.to_string().contains("exited unexpectedly"));
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_waits_for_an_active_http_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("server address");
        let started = Arc::new(tokio::sync::Notify::new());
        let handler_started = Arc::clone(&started);
        let release = CancellationToken::new();
        let handler_release = release.clone();
        let app = axum::Router::new().route(
            "/slow",
            axum::routing::get(move || {
                let started = Arc::clone(&handler_started);
                let release = handler_release.clone();
                async move {
                    started.notify_one();
                    release.cancelled().await;
                    "drained"
                }
            }),
        );
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let observed_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(server_shutdown.cancelled_owned())
                .await?;
            Ok(())
        });
        let signal = CancellationToken::new();
        let stop = signal.clone();
        let supervisor = tokio::spawn(async move {
            supervise_server(task, shutdown, "API server", async move {
                stop.cancelled().await;
                Ok(())
            })
            .await
        });
        let request = tokio::spawn(async move {
            reqwest::get(format!("http://{addr}/slow"))
                .await?
                .text()
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .expect("request enters handler");
        signal.cancel();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            observed_shutdown.cancelled(),
        )
        .await
        .expect("supervisor requests graceful shutdown");
        assert!(!supervisor.is_finished());
        release.cancel();
        let body = tokio::time::timeout(std::time::Duration::from_secs(2), request)
            .await
            .expect("request drains")
            .expect("request task joins")
            .expect("request succeeds");
        assert_eq!(body, "drained");
        tokio::time::timeout(std::time::Duration::from_secs(2), supervisor)
            .await
            .expect("server drains")
            .expect("supervisor task joins")
            .expect("shutdown succeeds");
    }

    #[tokio::test]
    async fn signal_failure_still_cancels_and_joins_server() {
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let drained = Arc::new(AtomicBool::new(false));
        let server_drained = Arc::clone(&drained);
        let task = tokio::spawn(async move {
            server_shutdown.cancelled().await;
            server_drained.store(true, Ordering::Relaxed);
            Ok(())
        });
        let error = supervise_server(task, shutdown, "API server", async {
            anyhow::bail!("signal registration failed");
        })
        .await
        .expect_err("signal failure must propagate");
        assert!(error.to_string().contains("signal registration failed"));
        assert!(drained.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn server_panic_stops_supervision() {
        async fn panic_server() -> Result<()> {
            panic!("test server panic");
        }
        let shutdown = CancellationToken::new();
        let error = supervise_server(
            tokio::spawn(panic_server()),
            shutdown.clone(),
            "API server",
            std::future::pending(),
        )
        .await
        .expect_err("panic must stop supervision");
        assert!(error.to_string().contains("API server task failed"));
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn drain_timeout_aborts_and_joins_the_task() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(Arc::clone(&dropped));
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut task = tokio::spawn(async move {
            let _flag = flag;
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.expect("task starts before timeout");
        let error = drain_task(&mut task, "test server", std::time::Duration::ZERO)
            .await
            .expect_err("unresponsive task times out");
        assert!(error.to_string().contains("did not drain"));
        assert!(dropped.load(Ordering::Relaxed), "task must not detach");
        assert!(task.is_finished());
    }

    #[test]
    fn ingester_health_reflects_consumer_and_store_breaker() {
        assert_eq!(ingester_health(true, false, true).0, StatusCode::OK);
        assert_eq!(
            ingester_health(true, false, false),
            (StatusCode::SERVICE_UNAVAILABLE, "broker connection down")
        );
        assert_eq!(
            ingester_health(true, true, true),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "capture store circuit breaker open"
            )
        );
        assert_eq!(
            ingester_health(false, false, true),
            (StatusCode::SERVICE_UNAVAILABLE, "consumer stopped")
        );
        assert_eq!(
            ingester_health(false, true, true).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
