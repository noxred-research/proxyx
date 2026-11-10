//! The tool catalogue and its dispatcher.
//!
//! A tool is listed when it passes the allow and deny lists, its capability is enabled (for a
//! mutating tool) and the backend it needs is configured. Calls go through one path: allow
//! list, rate budget, argument validation against the advertised schema, the tool, then one
//! audit entry. Mutating tools run detached from the request, so a client that disconnects
//! cannot leave a half-applied change without its audit entry.

mod assess;
mod catalog;
mod explain_tools;
mod llm_tools;
mod manage;
mod monitor;
mod policy_tools;
mod read;
mod traffic;
pub mod util;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxyx_client::Secret;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::audit::{Audit, Caller, Entry, Phase, sha256_hex};
use crate::backend::{Backends, ControlApi, PoolApi};
use crate::config::{Capability, Config, read_secret};
use crate::llm::Llm;
use crate::metrics::{self, Sampler};
use crate::safety::Gate;
use crate::schema;
use crate::store::Store;
pub use catalog::build as build_catalog;
use util::{Args, FailKind, ToolError, ToolResult};

/// What a tool does to ProxyX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reads or computes only.
    Read,
    /// Changes ProxyX. Needs its capability.
    Write(Capability),
    /// Handles proposals and approvals: writes local state, and applies through the gate.
    Change,
}

/// A backend or feature a tool needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Pool,
    Control,
    Roles,
    Llm,
    ConfirmToken,
}

/// MCP tool annotations. Hints only: a client must not trust them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hints {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

impl Hints {
    pub const READ: Hints = Hints {
        read_only: true,
        destructive: false,
        idempotent: true,
        open_world: false,
    };
    pub const WRITE: Hints = Hints {
        read_only: false,
        destructive: false,
        idempotent: false,
        open_world: false,
    };
    pub const IDEMPOTENT_WRITE: Hints = Hints {
        read_only: false,
        destructive: false,
        idempotent: true,
        open_world: false,
    };
    pub const DESTRUCTIVE: Hints = Hints {
        read_only: false,
        destructive: true,
        idempotent: false,
        open_world: false,
    };
}

/// One tool.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: &'static str,
    pub title: &'static str,
    pub description: String,
    pub input_schema: Value,
    pub access: Access,
    pub needs: &'static [Need],
    pub hints: Hints,
}

impl ToolDef {
    /// The `tools/list` entry.
    pub fn descriptor(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.hints.read_only,
                "destructiveHint": self.hints.destructive,
                "idempotentHint": self.hints.idempotent,
                "openWorldHint": self.hints.open_world,
            },
        })
    }
}

/// A resolved named credential.
#[derive(Clone)]
pub struct Credential {
    pub username: Option<String>,
    pub password: Secret,
}

/// Everything a tool call can use.
pub struct Ctx {
    pub cfg: Arc<Config>,
    pub backends: Backends,
    pub gate: Gate,
    pub audit: Audit,
    pub store: Store,
    pub sampler: Sampler,
    pub llm: Option<Llm>,
    /// SHA-256 of the confirm token, when `confirm_change` is enabled.
    pub confirm_token: Option<String>,
    pub credentials: BTreeMap<String, Credential>,
    pub tools: Vec<ToolDef>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("tools", &self.tools.len())
            .finish_non_exhaustive()
    }
}

impl Ctx {
    /// Build the context: read credential files, open the audit log and the state directory.
    ///
    /// # Errors
    /// When a credential file, the audit log or the state directory cannot be used.
    pub fn new(cfg: Config) -> anyhow::Result<Arc<Self>> {
        let backends = Backends::connect(&cfg)?;
        let store = Store::open(cfg.state_dir())?;
        let audit = Audit::open(&cfg.audit_path(), cfg.scope.engagement.clone())?;
        let llm = cfg.llm.as_ref().map(Llm::new).transpose()?;
        let confirm_token = cfg
            .safety
            .confirm_token_file
            .as_deref()
            .map(read_secret)
            .transpose()?
            .map(|token| sha256_hex(token.expose()));
        let mut credentials = BTreeMap::new();
        for (name, files) in &cfg.credentials {
            credentials.insert(
                name.clone(),
                Credential {
                    username: files.username.clone(),
                    password: read_secret(&files.password_file)?,
                },
            );
        }
        let tools = build_catalog(&cfg);
        Ok(Arc::new(Self {
            gate: Gate::new(&cfg),
            sampler: Sampler::new(cfg.metrics.history),
            cfg: Arc::new(cfg),
            backends,
            audit,
            store,
            llm,
            confirm_token,
            credentials,
            tools,
        }))
    }

    /// Names of configured backends that did not answer a cheap request: `pool`, `control` and
    /// the configured role names. A credential the backend rejects counts as unreachable.
    pub async fn unreachable_backends(&self) -> Vec<String> {
        let mut down = Vec::new();
        if let Some(pool) = &self.backends.pool {
            let answer = pool
                .api
                .get(
                    &["v1", "org-blocks"],
                    &[("org", "readiness-probe".to_owned())],
                )
                .await;
            if answer.is_err() {
                down.push("pool".to_owned());
            }
        }
        if let Some(control) = &self.backends.control {
            let answer = control
                .api
                .get(&["rpc", "orgs", &control.org, "rate-limit"], &[])
                .await;
            if answer.is_err() {
                down.push("control".to_owned());
            }
        }
        for role in &self.backends.roles {
            if role
                .api
                .get_raw(role.paths.live, 4096)
                .await
                .map_or(true, |reply| reply.status != 200)
            {
                down.push(role.name.clone());
            }
        }
        down
    }

    pub fn def(&self, name: &str) -> Option<&ToolDef> {
        self.tools.iter().find(|def| def.name == name)
    }

    fn satisfied(&self, need: Need) -> bool {
        match need {
            Need::Pool => self.backends.pool.is_some(),
            Need::Control => self.backends.control.is_some(),
            Need::Roles => !self.backends.roles.is_empty(),
            Need::Llm => self.llm.is_some(),
            Need::ConfirmToken => self.confirm_token.is_some(),
        }
    }

    /// Whether `def` is listed for this server.
    pub fn visible(&self, def: &ToolDef) -> bool {
        self.gate.tool_allowed(def.name)
            && match def.access {
                Access::Write(capability) => self.gate.has(capability),
                Access::Read | Access::Change => true,
            }
            && def.needs.iter().all(|need| self.satisfied(*need))
    }

    /// The `tools/list` descriptors, in catalogue order.
    pub fn descriptors(&self) -> Vec<Value> {
        self.tools
            .iter()
            .filter(|def| self.visible(def))
            .map(ToolDef::descriptor)
            .collect()
    }

    pub fn pool(&self) -> Result<&PoolApi, ToolError> {
        self.backends.pool.as_ref().ok_or_else(|| {
            ToolError::not_configured(
                "the pool gateway control API is not configured (endpoints.pool in the server configuration)",
            )
        })
    }

    pub fn control(&self) -> Result<&ControlApi, ToolError> {
        self.backends.control.as_ref().ok_or_else(|| {
            ToolError::not_configured(
                "the session control plane is not configured (endpoints.control in the server configuration)",
            )
        })
    }

    /// The org an org-scoped tool acts on: the argument, else the control key's org.
    ///
    /// # Errors
    /// When neither is available, the id is malformed or the org is outside the allowed scope.
    pub fn org(&self, args: &Args) -> Result<String, ToolError> {
        let org = match args.str("org") {
            Some(org) => org.to_owned(),
            None => self
                .backends
                .control
                .as_ref()
                .map(|control| control.org.clone())
                .ok_or_else(|| ToolError::invalid("`org` is required"))?,
        };
        if !crate::config::is_org_id(&org) {
            return Err(ToolError::invalid(format!(
                "{org:?} is not an org id ([a-z0-9_-], 1 to 64)"
            )));
        }
        self.gate.check_org(&org)?;
        Ok(org)
    }

    /// A policy for the number of rows a list tool returns.
    pub fn rows(&self, requested: Option<u64>) -> usize {
        let cap = self.cfg.limits.max_rows;
        requested.map_or(cap, |n| usize::try_from(n).unwrap_or(cap).clamp(1, cap))
    }
}

/// The caller of one tool call.
#[derive(Debug, Clone)]
pub struct CallInfo {
    pub caller: Caller,
}

/// How a call ended, for the audit entry and the response.
pub struct Completed {
    pub result: ToolResult,
    pub outcome: &'static str,
    pub change_id: Option<String>,
}

/// The reason a call named a tool this server does not have.
#[derive(Debug)]
pub struct UnknownTool;

fn outcome_of(result: &ToolResult) -> (&'static str, Option<String>) {
    match result {
        Ok(value) => {
            let outcome = match value.get("status").and_then(Value::as_str) {
                Some("dry_run") => "dry_run",
                Some("pending_approval") => "pending_approval",
                Some("applied") | Some("ok") | None => "ok",
                Some(_) => "ok",
            };
            let change = value
                .get("change_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            (outcome, change)
        }
        Err(error) if error.kind == FailKind::Refused => ("refused", None),
        Err(_) => ("error", None),
    }
}

/// Run one tool call end to end.
///
/// Mutating tools run in a task of their own, so a client that disconnects or cancels cannot
/// leave a half-applied change without its audit entry.
///
/// # Errors
/// [`UnknownTool`] when no tool of that name exists in the catalogue at all.
pub async fn run(
    ctx: &Arc<Ctx>,
    name: &str,
    arguments: Value,
    info: &CallInfo,
) -> Result<Completed, UnknownTool> {
    let Some(def) = ctx.def(name) else {
        return Err(UnknownTool);
    };
    if def.access == Access::Read {
        return Ok(run_inner(ctx, def, arguments, info).await);
    }
    let name = def.name;
    let task_ctx = Arc::clone(ctx);
    let task_info = info.clone();
    let joined = tokio::spawn(async move {
        let def = task_ctx.def(name)?;
        Some(run_inner(&task_ctx, def, arguments, &task_info).await)
    })
    .await;
    Ok(match joined {
        Ok(Some(completed)) => completed,
        _ => Completed {
            result: Err(ToolError::internal("the tool task failed")),
            outcome: "error",
            change_id: None,
        },
    })
}

async fn run_inner(ctx: &Arc<Ctx>, def: &ToolDef, arguments: Value, info: &CallInfo) -> Completed {
    let started = Instant::now();
    let result = execute(ctx, def, arguments.clone(), info).await;
    let (outcome, change_id) = outcome_of(&result);
    let detail = result.as_ref().err().map(|error| error.message.clone());
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Err(error) = ctx.audit.record(&Entry {
        phase: Phase::Result,
        caller: &info.caller,
        tool: def.name,
        arguments: &arguments,
        outcome,
        detail: detail.as_deref(),
        change_id: change_id.as_deref(),
        duration_ms: Some(elapsed),
    }) {
        tracing::warn!(%error, tool = def.name, "the audit entry could not be written");
    }
    Completed {
        result,
        outcome,
        change_id,
    }
}

async fn execute(ctx: &Arc<Ctx>, def: &ToolDef, arguments: Value, info: &CallInfo) -> ToolResult {
    if !ctx.gate.tool_allowed(def.name) {
        return Err(ToolError::new(
            FailKind::Refused,
            format!(
                "tool `{}` is disabled by this server's allow or deny list (safety.allow_tools, safety.deny_tools)",
                def.name
            ),
        ));
    }
    if let Access::Write(capability) = def.access {
        ctx.gate.check_applicable(capability, None)?;
    }
    for need in def.needs {
        if !ctx.satisfied(*need) {
            return Err(ToolError::not_configured(format!(
                "tool `{}` needs {} which this server does not have configured",
                def.name,
                match need {
                    Need::Pool => "the pool gateway control API (endpoints.pool)",
                    Need::Control => "the session control plane (endpoints.control)",
                    Need::Roles => "at least one role endpoint (endpoints.roles)",
                    Need::Llm => "an LLM endpoint ([llm])",
                    Need::ConfirmToken => "a confirm token (safety.confirm_token_file)",
                }
            )));
        }
    }
    ctx.gate.admit_call()?;
    let checked = schema::check(&def.input_schema, arguments).map_err(|issues| {
        ToolError::invalid(format!(
            "invalid arguments for {}: {}",
            def.name,
            issues.join("; ")
        ))
        .with_detail(json!({"issues": issues}))
    })?;
    dispatch(ctx, def.name, Args::from_value(checked), info).await
}

async fn dispatch(ctx: &Arc<Ctx>, name: &'static str, args: Args, info: &CallInfo) -> ToolResult {
    match name {
        // monitoring
        "health" => monitor::health(ctx, &args).await,
        "metrics_snapshot" => monitor::metrics_snapshot(ctx, &args).await,
        "pool_capacity" => monitor::pool_capacity(ctx, &args).await,
        "breaker_states" => monitor::breaker_states(ctx, &args).await,
        "block_signal_rates" => monitor::block_signal_rates(ctx, &args).await,
        "recent_refusals" => monitor::recent_refusals(ctx, &args).await,
        "diagnose" => monitor::diagnose(ctx, &args).await,
        "assess" => assess::assess(ctx, &args).await,
        "effective_config" => assess::effective_config(ctx, &args).await,
        // reads
        "capabilities" => read::capabilities(ctx),
        "list_inventory" => read::list_inventory(ctx, &args).await,
        "inventory_replacements" => read::inventory_replacements(ctx, &args).await,
        "list_policies" => read::list_policies(ctx, &args).await,
        "list_org_blocks" => read::list_org_blocks(ctx, &args).await,
        "get_customer_upstream" => read::get_customer_upstream(ctx, &args).await,
        "get_org" => read::get_org(ctx, &args).await,
        "list_sessions" => read::list_sessions(ctx, &args).await,
        "session_status" => read::session_status(ctx, &args).await,
        "list_changes" => read::list_changes(ctx, &args),
        // traffic
        "search_traffic" => traffic::search_traffic(ctx, &args).await,
        "count_traffic" => traffic::count_traffic(ctx, &args).await,
        "get_capture" => traffic::get_capture(ctx, &args).await,
        "search_ws" => traffic::search_ws(ctx, &args).await,
        "get_ws_conversation" => traffic::get_ws_conversation(ctx, &args).await,
        "summarize_traffic" => llm_tools::summarize_traffic(ctx, &args).await,
        "classify_block_page" => llm_tools::classify_block_page(ctx, &args, info).await,
        "suggest_policy" => llm_tools::suggest_policy(ctx, &args).await,
        // offline explanations
        "explain_refusal" => explain_tools::explain_refusal(&args),
        "explain_selector" => explain_tools::explain_selector(ctx, &args).await,
        "validate_policy" => explain_tools::validate_policy(ctx, &args).await,
        // changes
        "propose_config_change" => manage::propose_config_change(ctx, &args, info).await,
        "apply_config_change" => manage::apply_config_change(ctx, &args, info).await,
        "confirm_change" => manage::confirm_change(ctx, &args, info),
        // mutations
        other => match manage::Action::from_name(other) {
            Some(action) => manage::run_direct(ctx, action, args, info).await,
            None => Err(ToolError::internal(format!(
                "tool `{other}` has no implementation"
            ))),
        },
    }
}

/// Start the background scraper that feeds rate calculations. Returns immediately.
pub fn spawn_sampler(ctx: &Arc<Ctx>, cancel: CancellationToken) {
    let interval = ctx.cfg.metrics.sample_interval_secs;
    if interval == 0 || ctx.backends.roles.is_empty() {
        return;
    }
    let ctx = Arc::clone(ctx);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let (scrapes, _) = metrics::scrape(&ctx.backends, None).await;
            for scrape in &scrapes {
                ctx.sampler.record(scrape);
            }
        }
    });
}
