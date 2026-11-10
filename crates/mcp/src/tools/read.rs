//! Read tools over the pool gateway's control API and the session control plane, and the
//! server's own state (capabilities, sessions it created, changes it holds).

use serde_json::{Value, json};

use super::Ctx;
use super::util::{Args, FailKind, ToolError, ToolResult, now};
use crate::backend::ErrorKind;
use crate::config::Capability;
use crate::store::{Status, change_view};

fn cap_items(body: &Value, key: &str, limit: usize) -> (Vec<Value>, bool, usize) {
    let items = body[key].as_array().cloned().unwrap_or_default();
    let total = items.len();
    let truncated = total > limit;
    (items.into_iter().take(limit).collect(), truncated, total)
}

pub fn capabilities(ctx: &Ctx) -> ToolResult {
    let cfg = &ctx.cfg;
    let enabled: Vec<&str> = ctx.gate.enabled().iter().map(|c| c.as_str()).collect();
    let disabled: Vec<&str> = Capability::ALL
        .iter()
        .filter(|c| !ctx.gate.has(**c))
        .map(|c| c.as_str())
        .collect();
    let listed: Vec<&str> = ctx
        .tools
        .iter()
        .filter(|def| ctx.visible(def))
        .map(|def| def.name)
        .collect();
    let hidden: Vec<Value> = ctx
        .tools
        .iter()
        .filter(|def| !ctx.visible(def))
        .map(|def| json!({"tool": def.name, "why": why_hidden(ctx, def)}))
        .collect();
    Ok(json!({
        "profile": cfg.safety.profile,
        "enabled_capabilities": enabled,
        "disabled_capabilities": disabled,
        "read_only": enabled.is_empty(),
        "approval": {
            "mode": cfg.safety.approval,
            "tools": cfg.safety.approval_tools,
            "ttl_secs": cfg.safety.approval_ttl_secs,
            "operator_command": "proxyx mcp approve <change_id>",
            "confirm_tool": ctx.confirm_token.is_some(),
        },
        "force_dry_run": cfg.safety.force_dry_run,
        "reveal_secrets_once": cfg.safety.reveal_secrets_once,
        "scope": {
            "engagement": cfg.scope.engagement,
            "expires": cfg.scope.expires,
            "require_engagement": cfg.scope.require_engagement,
            "allowed_orgs": cfg.scope.allowed_orgs,
        },
        "limits": {
            "max_rows": cfg.limits.max_rows,
            "max_body_bytes": cfg.limits.max_body_bytes,
            "max_result_bytes": cfg.limits.max_result_bytes,
            "max_calls_per_minute": cfg.limits.max_calls_per_minute,
            "max_mutations_per_hour": cfg.limits.max_mutations_per_hour,
            "max_session_ttl_secs": cfg.limits.max_session_ttl_secs,
            "allow_inline_secrets": cfg.limits.allow_inline_secrets,
        },
        "backends": {
            "pool_api": ctx.backends.pool.is_some(),
            "pool_org_key_route": ctx.backends.pool.as_ref().is_some_and(|p| p.org_key.is_some()),
            "control_api": ctx.backends.control.is_some(),
            "roles": ctx.backends.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            "llm": ctx.llm.is_some(),
            "credential_refs": ctx.credentials.keys().collect::<Vec<_>>(),
        },
        "audit_log": ctx.audit.path().display().to_string(),
        "listed_tools": listed,
        "unlisted_tools": hidden,
    }))
}

fn why_hidden(ctx: &Ctx, def: &super::ToolDef) -> String {
    if !ctx.gate.tool_allowed(def.name) {
        return "disabled by safety.allow_tools or safety.deny_tools".into();
    }
    if let super::Access::Write(capability) = def.access
        && !ctx.gate.has(capability)
    {
        return format!("capability `{}` is not enabled", capability.as_str());
    }
    "its backend is not configured".into()
}

pub async fn list_inventory(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let mut query = Vec::new();
    if let Some(provider) = args.str("provider") {
        query.push(("provider", provider.to_owned()));
    }
    if let Some(state) = args.str("state") {
        query.push(("state", state.to_owned()));
    }
    let body = pool.api.get(&["v1", "inventory"], &query).await?;
    let (items, truncated, total) = cap_items(&body, "items", ctx.rows(args.u64("limit")));
    Ok(json!({"items": items, "total": total, "truncated": truncated}))
}

pub async fn inventory_replacements(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let body = pool
        .api
        .get(&["v1", "inventory", "replacements"], &[])
        .await?;
    let (items, truncated, total) = cap_items(&body, "items", ctx.rows(args.u64("limit")));
    Ok(json!({"items": items, "total": total, "truncated": truncated}))
}

pub async fn list_policies(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let body = pool.api.get(&["v1", "policies"], &[]).await?;
    let include_all = args.bool("include_docs").unwrap_or(false);
    let name = args.str("name");
    let scope = args.str("scope");
    let items: Vec<Value> = body["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| scope.is_none_or(|s| item["scope"] == s))
        .filter(|item| name.is_none_or(|n| item["name"] == n))
        .map(|mut item| {
            if !(include_all || name.is_some())
                && let Some(map) = item.as_object_mut()
            {
                map.remove("doc");
            }
            item
        })
        .collect();
    let total = items.len();
    let limit = ctx.rows(None);
    Ok(json!({
        "items": items.into_iter().take(limit).collect::<Vec<_>>(),
        "total": total,
        "note": "actor `gitops` means the policy was written from the git policy data; the API can override it only as an emergency change that git overrides again when it changes that policy",
    }))
}

pub async fn list_org_blocks(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let mut query = Vec::new();
    if let Some(org) = args.str("org") {
        ctx.gate.check_org(org)?;
        query.push(("org", org.to_owned()));
    }
    let body = pool.api.get(&["v1", "org-blocks"], &query).await?;
    let (items, truncated, total) = cap_items(&body, "items", ctx.rows(None));
    Ok(json!({"items": items, "total": total, "truncated": truncated}))
}

pub async fn get_customer_upstream(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let org = ctx.org(args)?;
    match pool.api.get(&["v1", "orgs", &org, "upstream"], &[]).await {
        Ok(body) => Ok(body),
        Err(error) if error.kind == ErrorKind::NotFound => {
            Ok(json!({"org": org, "upstream": null}))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn get_org(ctx: &Ctx, args: &Args) -> ToolResult {
    let control = ctx.control()?;
    let org = ctx.org(args)?;
    let mut problems = Vec::new();
    let mut part = |name: &str, result: Result<Value, crate::backend::ApiError>| match result {
        Ok(value) => value,
        Err(error) if error.kind == ErrorKind::NotFound => Value::Null,
        Err(error) => {
            problems.push(json!({"part": name, "error": error.to_value()}));
            Value::Null
        }
    };
    let settings = part("org", control.api.get(&["rpc", "orgs", &org], &[]).await);
    let rate_limit = part(
        "rate_limit",
        control
            .api
            .get(&["rpc", "orgs", &org, "rate-limit"], &[])
            .await,
    );
    let state = part(
        "rate_limit_state",
        control
            .api
            .get(&["rpc", "orgs", &org, "rate-limit-state"], &[])
            .await,
    );
    let egress = part(
        "egress_proxy",
        control.api.get(&["rpc", "orgs", &org, "proxy"], &[]).await,
    );
    if problems.len() == 4 {
        return Err(ToolError::new(
            FailKind::Backend,
            "the control plane answered none of the org requests",
        )
        .with_detail(json!({"problems": problems})));
    }
    Ok(json!({
        "org": org,
        "settings": settings,
        "rate_limit": rate_limit,
        "rate_limit_state": state,
        "egress_proxy": egress,
        "problems": problems,
    }))
}

pub async fn list_sessions(ctx: &Ctx, args: &Args) -> ToolResult {
    let limit = ctx.rows(args.u64("limit"));
    let mut sessions = ctx.store.recent_sessions(limit);
    if args.bool("refresh").unwrap_or(false) {
        let control = ctx.control()?;
        for record in sessions.iter_mut().take(20) {
            let Some(id) = record["session_id"].as_str().map(str::to_owned) else {
                continue;
            };
            record["lifecycle"] = match control
                .api
                .get(&["rpc", "sessions", &id, "status"], &[])
                .await
            {
                Ok(status) => status,
                Err(error) => json!({"error": error.message}),
            };
        }
    }
    let now_ms = now() * 1000;
    for record in &mut sessions {
        if let Some(expires) = record["expires_at_ms"].as_i64() {
            record["expired"] = json!(expires <= now_ms);
        }
    }
    Ok(json!({
        "sessions": sessions,
        "note": "The control plane has no session list endpoint: these are the sessions this MCP server created. Use session_status for one session.",
    }))
}

pub async fn session_status(ctx: &Ctx, args: &Args) -> ToolResult {
    let control = ctx.control()?;
    let id = args.require_str("session_id")?;
    let config = control.api.get(&["rpc", "sessions", id], &[]).await;
    let status = control
        .api
        .get(&["rpc", "sessions", id, "status"], &[])
        .await;
    let (config, status) = match (config, status) {
        (Err(a), Err(_)) => return Err(a.into()),
        (config, status) => (config.ok(), status.ok()),
    };
    let mut out = json!({"session_id": id, "lifecycle": status});
    if let Some(config) = config {
        let expires = config["expires_at_ms"].as_i64();
        out["org_id"] = config["org_id"].clone();
        out["source"] = config["source"].clone();
        out["source_id"] = config["source_id"].clone();
        out["captured_hosts"] = config["captured_hosts"].clone();
        out["excluded_hosts"] = config["excluded_hosts"].clone();
        out["serialize"] = config["serialize"].clone();
        out["agent"] = config["agent"].clone();
        out["expires_at_ms"] = json!(expires);
        out["expires_in_secs"] = json!(expires.map(|ms| (ms / 1000 - now()).max(0)));
        out["rate_limit"] = config["rate_limit"].clone();
        // Header values can carry credentials: names only.
        out["inject_header_names"] = json!(
            config["inject_headers"]
                .as_array()
                .map(|headers| headers
                    .iter()
                    .filter_map(|pair| pair[0].as_str().map(str::to_owned))
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );
        out["egress_proxy"] = match config["egress_proxy"].as_object() {
            Some(proxy) => json!({
                "proxy_type": proxy.get("proxy_type"),
                "address": proxy.get("address"),
                "has_credentials": proxy.get("username").is_some_and(|u| !u.is_null()),
            }),
            None => Value::Null,
        };
        out["upstream_overrides"] = json!(
            config["upstream_overrides"]
                .as_object()
                .map_or(0, serde_json::Map::len)
        );
    }
    Ok(out)
}

pub fn list_changes(ctx: &Ctx, args: &Args) -> ToolResult {
    let wanted = args.str("status");
    let limit = ctx.rows(args.u64("limit"));
    let rows: Vec<Value> = ctx
        .store
        .list()
        .into_iter()
        .filter(|(_, status)| wanted.is_none_or(|w| status.name() == w))
        .take(limit)
        .map(|(change, status)| {
            let mut view = change_view(&change, &status);
            if matches!(status, Status::Proposed | Status::Approved { .. }) {
                view["diff"] = change.diff.clone();
                view["warnings"] = json!(change.warnings);
                view["approval_required"] = json!(ctx.gate.approval_required(&change.action));
            }
            view
        })
        .collect();
    Ok(json!({"changes": rows}))
}
