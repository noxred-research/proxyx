//! `proxyx`: one binary, one role per process.
//!
//! | Command | Role |
//! |---|---|
//! | `proxyx gateway` | Pool gateway: CONNECT and SOCKS5 ingress, leasing, control API |
//! | `proxyx warmer` | Pool maintenance: warming, keepalive, checks, sweeper |
//! | `proxyx control api\|ingester\|schema` | Session control plane |
//! | `proxyx edge --config FILE [--check]` | Self-hosted multi-IP forward proxy (HTTP, CONNECT, SOCKS4/5); no database |
//! | `proxyx mcp` | AI/LLM agent control: MCP server (stdio or HTTP) over the ProxyX APIs |
//! | `proxyx limiter [ADDR]` | Rate-limit service |
//! | `proxyx doctor` | Self-check of role configuration, dependencies, files and ports |
//! | `proxyx assess pool` | Health assessment of a running pool |
//! | `proxyx migrate pool\|control` | Database migrations |
//!
//! The session proxy is the separate `proxyx-intercept` binary: its BoringSSL
//! upstream TLS stack cannot share a process with the OpenSSL of the Kafka
//! consumer.
//!
//! The pool, session and limiter roles read their own configuration file and
//! environment prefix (`PROXYX_POOL_*`, `PROXYX_INTERCEPT_*`,
//! `PROXYX_CONTROL_*`, `PROXYX_LIMITER_*`); `edge` reads one TOML file only.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use proxyx_control::cli::{ControlArgs, MigrateTarget};
use proxyx_pool::cli::Role;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(
    name = "proxyx",
    version,
    about = "Next-generation AI/LLM-native proxy for authorized security research: pool gateway, edge proxy, session control plane, MCP server and rate-limit service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pool gateway: serve tunnels (CONNECT, SOCKS5, probe) and the pool control API.
    Gateway(PoolConfig),
    /// Pool warmer: keep ready pools, static inventory and quality checks healthy.
    Warmer(PoolConfig),
    /// Session control plane: sessions API, capture ingester, GraphQL schema tooling.
    Control(ControlArgs),
    /// AI/LLM agent control: MCP server (stdio or HTTP) over the ProxyX APIs.
    Mcp(proxyx_mcp::McpArgs),
    /// Self-hosted forward proxy over this machine's IP addresses: HTTP, CONNECT,
    /// SOCKS4/5, ACLs, limits and parent proxies from one TOML file; no database.
    Edge(EdgeArgs),
    /// Self-check: validate role configuration and probe dependencies, files and
    /// ports without starting any role. Exits non-zero when a check fails.
    Doctor(proxyx_ops::DoctorArgs),
    /// Assess a running deployment from its datastores and ops endpoints.
    Assess(proxyx_ops::AssessArgs),
    /// Rate-limit service (in-memory token buckets over a binary TCP protocol).
    Limiter {
        /// Listen address.
        #[arg(default_value = proxyx_limiter_server::DEFAULT_LISTEN)]
        addr: String,
    },
    /// Apply or check database migrations.
    Migrate {
        #[command(subcommand)]
        target: Migrate,
    },
}

#[derive(clap::Args)]
struct PoolConfig {
    /// Configuration file; overrides the environment (`PROXYX_POOL_*`).
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
struct EdgeArgs {
    /// Configuration file (TOML). SIGHUP reloads it and reopens the access log.
    #[arg(short, long)]
    config: PathBuf,
    /// Validate the configuration (references, local addresses, hashes) and exit.
    #[arg(long)]
    check: bool,
}

#[derive(Subcommand)]
enum Migrate {
    /// Pool gateway Postgres schema.
    Pool {
        #[command(flatten)]
        config: PoolConfig,
        /// Report pending migrations and exit non-zero instead of applying them.
        #[arg(long)]
        check: bool,
    },
    /// Control plane Postgres and ClickHouse schema (and the Kafka topic when
    /// the broker is Kafka-compatible).
    Control {
        /// Configuration file; overrides the environment (`PROXYX_CONTROL_*`).
        #[arg(short, long)]
        config: Option<String>,
        /// Stores to migrate.
        #[arg(long, value_enum, default_value_t = MigrateTarget::All)]
        target: MigrateTarget,
        /// Check migration state without applying changes.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    if let Command::Limiter { addr } = &cli.command {
        // Thread per connection; no async runtime.
        proxyx_limiter_server::run(addr).with_context(|| format!("limiter on {addr}"))?;
        return Ok(ExitCode::SUCCESS);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start the async runtime")?
        .block_on(run(cli.command))
}

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

async fn run(command: Command) -> anyhow::Result<ExitCode> {
    match command {
        Command::Gateway(c) => proxyx_pool::cli::run(c.config.as_deref(), Role::Gateway).await,
        Command::Warmer(c) => proxyx_pool::cli::run(c.config.as_deref(), Role::Warmer).await,
        Command::Migrate {
            target: Migrate::Pool { config, check },
        } => proxyx_pool::cli::run(config.config.as_deref(), Role::Migrate { check }).await,
        Command::Migrate {
            target:
                Migrate::Control {
                    config,
                    target,
                    check,
                },
        } => {
            proxyx_control::cli::migrate(config.as_deref(), target, check).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Control(args) => {
            proxyx_control::cli::run(args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Edge(args) if args.check => {
            let report = proxyx_edge::check(&args.config)?;
            println!(
                "ok: {} listener(s), {} user(s), {} rule(s), {} parent(s)",
                report.listeners, report.users, report.rules, report.parents
            );
            for (pool, addrs) in &report.pools {
                let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                println!("pool {pool}: {}", list.join(", "));
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Edge(args) => {
            proxyx_edge::run(&args.config).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Mcp(args) => {
            proxyx_mcp::init_logging();
            proxyx_mcp::run(args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor(args) => Ok(exit_code(proxyx_ops::run_doctor(args).await?)),
        Command::Assess(args) => Ok(exit_code(proxyx_ops::run_assess(args).await?)),
        Command::Limiter { .. } => unreachable!("handled before the runtime starts"),
    }
}
