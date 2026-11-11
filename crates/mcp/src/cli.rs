//! `proxyx mcp`: serve the MCP server, and the operator commands around it.
//!
//! ```text
//! proxyx mcp [--config mcp.toml] [--transport stdio|http] [--bind ADDR]   serve (stdio default)
//! proxyx mcp pending                      list changes waiting for approval
//! proxyx mcp approve <change_id> [--yes]  approve a change (review shown first)
//! proxyx mcp reject <change_id>           reject a change
//! proxyx mcp check                        load the configuration and probe the backends
//! proxyx mcp tools                        list every tool and why it is listed or not
//! proxyx mcp audit [--verify] [--tail N]  show or verify the audit log
//! ```

use std::io::{BufRead as _, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, read_secret};
use crate::server::Server;
use crate::store::{Status, Store, change_view};
use crate::tools::{self, CallInfo, Ctx};
use crate::{audit, http, stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportKind {
    /// Newline-delimited JSON-RPC on stdin and stdout.
    Stdio,
    /// Streamable HTTP with a bearer token.
    Http,
}

/// Arguments of `proxyx mcp`.
#[derive(Args, Debug, Clone)]
pub struct McpArgs {
    /// Configuration file (TOML). Default: $PROXYX_MCP_CONFIG, then ./mcp.toml, then
    /// /etc/proxyx/mcp.toml, then built-in defaults (read-only, no backends).
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Transport to serve.
    #[arg(long, value_enum, default_value_t = TransportKind::Stdio)]
    pub transport: TransportKind,
    /// Address of the HTTP transport (overrides http.bind). Loopback unless you know why not.
    #[arg(long, value_name = "ADDR")]
    pub bind: Option<SocketAddr>,
    #[command(subcommand)]
    pub command: Option<McpCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum McpCommand {
    /// List configuration changes that are proposed, approved or recently applied.
    Pending,
    /// Approve a change after reviewing its diff.
    Approve {
        /// The change id (chg_...).
        id: String,
        /// Skip the confirmation question.
        #[arg(long)]
        yes: bool,
        /// Who is approving (default: $USER).
        #[arg(long)]
        by: Option<String>,
        /// A note stored with the approval.
        #[arg(long)]
        note: Option<String>,
    },
    /// Reject a change.
    Reject {
        id: String,
        #[arg(long)]
        by: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Load the configuration and probe every configured backend.
    Check,
    /// List every tool, whether it is listed for this configuration, and why not.
    Tools,
    /// Show or verify the audit log.
    Audit {
        /// Recompute the hash chain and fail when a line was edited or removed.
        #[arg(long)]
        verify: bool,
        /// Show the last N entries.
        #[arg(long, default_value_t = 0)]
        tail: usize,
    },
}

fn operator(by: Option<String>) -> String {
    by.or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "operator".to_owned())
}

fn print_json(value: &Value) {
    let mut value = value.clone();
    crate::redact::redact_value(&mut value);
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_default()
    );
}

/// Install a logger that writes to stderr (stdout is the stdio protocol channel). `RUST_LOG`
/// selects the level, default `info`. Does nothing when a logger is already installed.
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Run `proxyx mcp`.
///
/// For the stdio transport the process's stdout is the protocol channel: nothing else may write
/// to it, so any logger the caller installs must write to stderr.
///
/// # Errors
/// When the configuration is invalid, a credential file is unreadable, or the transport fails.
pub async fn run(args: McpArgs) -> anyhow::Result<()> {
    let (config, path) = Config::load(args.config.as_deref())?;
    match &args.command {
        None => serve(config, path, &args).await,
        Some(McpCommand::Pending) => pending(&config),
        Some(McpCommand::Approve { id, yes, by, note }) => {
            approve(&config, id, *yes, by.clone(), note.as_deref())
        }
        Some(McpCommand::Reject { id, by, note }) => {
            reject(&config, id, by.clone(), note.as_deref())
        }
        Some(McpCommand::Check) => check(config, path).await,
        Some(McpCommand::Tools) => list_tools(config),
        Some(McpCommand::Audit { verify, tail }) => audit_command(&config, *verify, *tail),
    }
}

async fn serve(config: Config, path: Option<PathBuf>, args: &McpArgs) -> anyhow::Result<()> {
    let http_settings = config.http.clone();
    let ctx = Ctx::new(config)?;
    let server = Arc::new(Server::new(Arc::clone(&ctx)));
    let cancel = CancellationToken::new();
    tools::spawn_sampler(&ctx, cancel.clone());
    let listed = ctx.tools.iter().filter(|def| ctx.visible(def)).count();
    let enabled: Vec<&str> = ctx
        .gate
        .enabled()
        .iter()
        .map(|capability| capability.as_str())
        .collect();
    tracing::info!(
        config = ?path,
        tools = listed,
        capabilities = ?enabled,
        audit = %ctx.audit.path().display(),
        "proxyx mcp ready"
    );
    match args.transport {
        TransportKind::Stdio => {
            stdio::serve(
                BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
                server,
            )
            .await
            .context("the stdio transport failed")?;
            cancel.cancel();
            Ok(())
        }
        TransportKind::Http => {
            let token_file = http_settings.token_file.as_deref().context(
                "the HTTP transport needs http.token_file: it always requires a bearer token",
            )?;
            let token = read_secret(token_file)?;
            let bind: SocketAddr = match args.bind {
                Some(bind) => bind,
                None => http_settings.bind.parse().context("http.bind")?,
            };
            let loopback = bind.ip().is_loopback();
            if !loopback {
                eprintln!(
                    "proxyx mcp: binding {bind}, which is not loopback; the bearer token travels in clear text unless a TLS proxy fronts this endpoint"
                );
            }
            let options = http::HttpOptions {
                path: http_settings.path.clone(),
                token,
                allowed_origins: http_settings.allowed_origins.clone(),
                loopback_bind: loopback,
                max_body_bytes: http_settings.max_body_bytes,
                shutdown: cancel.clone(),
            };
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("cannot bind {bind}"))?;
            eprintln!(
                "proxyx mcp: streamable HTTP on http://{}{}",
                listener.local_addr()?,
                http_settings.path
            );
            let router = http::router(server, options);
            let stop = cancel.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                stop.cancel();
            });
            http::serve(listener, router, cancel)
                .await
                .context("the HTTP transport failed")
        }
    }
}

fn open_store(config: &Config) -> anyhow::Result<Store> {
    Store::open(config.state_dir()).with_context(|| {
        format!(
            "cannot open the state directory {}",
            config.state_dir().display()
        )
    })
}

fn pending(config: &Config) -> anyhow::Result<()> {
    let store = open_store(config)?;
    let rows: Vec<Value> = store
        .list()
        .into_iter()
        .map(|(change, status)| change_view(&change, &status))
        .collect();
    print_json(&json!({"changes": rows}));
    Ok(())
}

fn approve(
    config: &Config,
    id: &str,
    yes: bool,
    by: Option<String>,
    note: Option<&str>,
) -> anyhow::Result<()> {
    let store = open_store(config)?;
    let change = store.load(id)?;
    let status = store.status(&change);
    print_json(&json!({
        "change": change_view(&change, &status),
        "diff": change.diff,
        "warnings": change.warnings,
        "engagement": change.engagement,
    }));
    if !matches!(status, Status::Proposed) {
        bail!("change {id} is {}: nothing to approve", status.name());
    }
    if !yes {
        eprint!("Approve this change? [y/N] ");
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            bail!("not approved");
        }
    }
    let by = operator(by);
    store.approve(id, &by, note)?;
    println!("approved {id} as {by}; the agent can now call apply_config_change");
    Ok(())
}

fn reject(config: &Config, id: &str, by: Option<String>, note: Option<&str>) -> anyhow::Result<()> {
    let store = open_store(config)?;
    let by = operator(by);
    store.reject(id, &by, note)?;
    println!("rejected {id} as {by}");
    Ok(())
}

async fn check(config: Config, path: Option<PathBuf>) -> anyhow::Result<()> {
    let ctx = Ctx::new(config)?;
    let mut report = serde_json::Map::new();
    report.insert(
        "config".into(),
        json!(path.map(|p| p.display().to_string())),
    );
    report.insert(
        "state_dir".into(),
        json!(ctx.store.root().display().to_string()),
    );
    report.insert(
        "audit_log".into(),
        json!(ctx.audit.path().display().to_string()),
    );
    report.insert(
        "enabled_capabilities".into(),
        json!(
            ctx.gate
                .enabled()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
        ),
    );
    report.insert(
        "listed_tools".into(),
        json!(ctx.tools.iter().filter(|def| ctx.visible(def)).count()),
    );
    let outcome = |result: Result<Value, crate::backend::ApiError>| match result {
        Ok(_) => json!({"ok": true}),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    };
    if let Some(pool) = &ctx.backends.pool {
        report.insert(
            "pool_api".into(),
            outcome(pool.api.get(&["v1", "org-blocks"], &[]).await),
        );
    }
    if let Some(control) = &ctx.backends.control {
        report.insert(
            "control_api".into(),
            outcome(
                control
                    .api
                    .get(&["rpc", "orgs", &control.org, "rate-limit"], &[])
                    .await,
            ),
        );
    }
    if !ctx.backends.roles.is_empty() {
        let info = CallInfo {
            caller: audit::Caller {
                transport: "cli",
                ..audit::Caller::default()
            },
        };
        if let Ok(done) = tools::run(&ctx, "health", json!({}), &info).await {
            report.insert(
                "roles".into(),
                done.result.unwrap_or_else(|error| error.to_value()),
            );
        }
    }
    print_json(&Value::Object(report));
    Ok(())
}

fn list_tools(config: Config) -> anyhow::Result<()> {
    let ctx = Ctx::new(config)?;
    let rows: Vec<Value> = ctx
        .tools
        .iter()
        .map(|def| {
            json!({
                "tool": def.name,
                "access": match def.access {
                    tools::Access::Read => "read".to_owned(),
                    tools::Access::Write(capability) => format!("write:{}", capability.as_str()),
                    tools::Access::Change => "change".to_owned(),
                },
                "listed": ctx.visible(def),
            })
        })
        .collect();
    print_json(&json!({"tools": rows}));
    Ok(())
}

fn audit_command(config: &Config, verify: bool, tail: usize) -> anyhow::Result<()> {
    let path = config.audit_path();
    if verify {
        let report =
            audit::verify(&path).with_context(|| format!("cannot read {}", path.display()))?;
        print_json(&serde_json::to_value(&report)?);
        if let Some((line, reason)) = report.broken {
            bail!("the audit log is broken at line {line}: {reason}");
        }
    }
    if tail > 0 {
        let log = audit::Audit::open(&path, None)?;
        print_json(&json!({"entries": log.tail(tail)}));
    }
    if !verify && tail == 0 {
        println!("{}", path.display());
    }
    Ok(())
}
