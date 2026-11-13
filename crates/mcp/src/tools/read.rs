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

fn scope_inventory(ctx: &Ctx, body: &mut Value) {
    if !ctx.gate.unscoped()
        && let Some(items) = body["items"].as_array_mut()
    {
        items.retain(|item| {
            item.get("owner").is_some_and(Value::is_null)
                || item["owner"]
                    .as_str()
                    .is_some_and(|org| ctx.gate.check_org(org).is_ok())
        });
    }
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
        "analysis": {
            "enabled": cfg.analysis.enabled,
            "allow_external_llm": cfg.analysis.allow_external_llm,
            "sources": cfg.analysis.allowed_source_ids.len(),
            "origins": cfg.analysis.allowed_origins.len(),
            "details": "call analysis_capabilities",
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
    def.needs
        .iter()
        .find(|need| !ctx.satisfied(**need))
        .map_or_else(
            || "its backend is not configured".to_owned(),
            |need| format!("it needs {}", super::need_text(*need)),
        )
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
    let mut body = pool.api.get(&["v1", "inventory"], &query).await?;
    scope_inventory(ctx, &mut body);
    let (items, truncated, total) = cap_items(&body, "items", ctx.rows(args.u64("limit")));
    Ok(json!({"items": items, "total": total, "truncated": truncated}))
}

pub async fn inventory_replacements(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let mut body = pool
        .api
        .get(&["v1", "inventory", "replacements"], &[])
        .await?;
    scope_inventory(ctx, &mut body);
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
        .filter(|item| {
            item["scope"] != "org"
                || item["match"]
                    .as_str()
                    .or_else(|| item["doc"]["match"].as_str())
                    .is_some_and(|org| ctx.gate.check_org(org).is_ok())
        })
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
    if !ctx.gate.unscoped() && args.str("org").is_none() {
        return Err(ToolError::invalid(
            "`org` is required when scope.allowed_orgs is configured",
        ));
    }
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
    // Scope before truncation: unauthorized rows must not displace authorized sessions.
    let mut sessions: Vec<Value> = ctx
        .store
        .recent_sessions(usize::MAX)
        .into_iter()
        .filter(|record| {
            ctx.gate.unscoped()
                || record["org"]
                    .as_str()
                    .is_some_and(|org| ctx.gate.check_org(org).is_ok())
        })
        .take(limit)
        .collect();
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
        if let Some(id) = record["session_id"].as_str() {
            record["session_id"] = json!(ctx.session_alias(id)?);
        }
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
    let real_id = ctx.resolve_session(id)?;
    let config = control.api.get(&["rpc", "sessions", &real_id], &[]).await?;
    let org = config["org_id"]
        .as_str()
        .ok_or_else(|| ToolError::internal("session configuration has no org"))?;
    ctx.gate.check_org(org)?;
    let status = control
        .api
        .get(&["rpc", "sessions", &real_id, "status"], &[])
        .await?;
    let alias = ctx.session_alias(&real_id)?;
    let mut out = json!({"session_id": alias, "lifecycle": status});
    {
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
        .filter(|(change, _)| {
            ctx.gate.unscoped()
                || change.arguments["org"]
                    .as_str()
                    .is_some_and(|org| ctx.gate.check_org(org).is_ok())
        })
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

pub async fn list_pool_sessions(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let org = ctx.org(args)?;
    let body = pool.api.get(&["v1", "orgs", &org, "sessions"], &[]).await?;
    let (sessions, truncated, total) = cap_items(&body, "sessions", ctx.rows(args.u64("limit")));
    Ok(json!({
        "org": org,
        "sessions": sessions,
        "total": total,
        "truncated": truncated,
        "affinity": body["affinity"],
        "note": "Use rotate_pool_session (capability pool_sessions) to move a sid to a new unit.",
    }))
}

/// The gateway proxy username for the options of `generate_pool_endpoints`, without a sticky
/// key (the gateway adds one per endpoint).
pub fn endpoint_username(args: &Args) -> String {
    let mut name = String::from("px");
    for (key, field) in [
        ("kind", "kind"),
        ("cc", "country"),
        ("city", "city"),
        ("prov", "provider"),
    ] {
        if let Some(value) = args.str(field) {
            name.push_str(&format!("-{key}-{value}"));
        }
    }
    if let Some(ttl) = args.str("ttl") {
        name.push_str(&format!("-ttl-{ttl}"));
    }
    if args.str("rotation") == Some("each") {
        name.push_str("-rot-each");
    }
    name
}

/// True when `text` carries a password in URL userinfo, or an org key.
fn carries_credential(text: &str) -> bool {
    let userinfo_password = text.split("://").skip(1).any(|rest| {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        authority.rsplit_once('@').is_some_and(|(info, _)| {
            info.split_once(':')
                .is_some_and(|(_, pass)| !pass.is_empty())
        })
    });
    userinfo_password || text.contains("ak_")
}

fn strings_carry_credential(value: &Value) -> bool {
    match value {
        Value::String(text) => carries_credential(text),
        Value::Array(items) => items.iter().any(strings_carry_credential),
        Value::Object(map) => map.values().any(strings_carry_credential),
        _ => false,
    }
}

pub async fn generate_pool_endpoints(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let org = ctx.org(args)?;
    let host = args.require_str("gateway_host")?;
    if !super::manage::plain_host(host) {
        return Err(ToolError::invalid(
            "gateway_host must be a plain DNS name or IP literal, without scheme, port, path or login",
        ));
    }
    let style = args.str("style").unwrap_or("http");
    let port_field = if style == "socks5" {
        "socks5_port"
    } else {
        "http_port"
    };
    if args.u64(port_field).is_none() {
        return Err(ToolError::invalid(format!(
            "style {style} needs the matching explicit port `{port_field}`: the gateway does not guess the port clients reach it on"
        )));
    }
    let count = args.u64("count").unwrap_or(10);
    let cap = ctx.cfg.limits.max_rows as u64;
    if count == 0 || count > cap.min(10_000) {
        return Err(ToolError::invalid(format!(
            "count {count} is above this server's limit of {cap} (limits.max_rows); ask for fewer or page by calling again"
        )));
    }
    // Check the options with the gateway's own username grammar before asking.
    let username = endpoint_username(args);
    if policy::InboundOptions::parse(&username).is_err() {
        let mut verdict = crate::explain::explain_username(&username);
        verdict["note"] = json!(
            "the options would build this username, which the gateway grammar refuses; fix the options listed in issues"
        );
        return Err(ToolError::invalid(format!(
            "these options do not form a valid proxy username ({username}): {}",
            verdict["issues"]
        ))
        .with_detail(verdict));
    }
    let mut body = json!({
        "gateway_host": host,
        "style": style,
        "format": "json",
        "count": count,
        "rotation": args.str("rotation").unwrap_or("sticky"),
        "strict": args.bool("strict").unwrap_or(false),
    });
    for key in ["http_port", "socks5_port"] {
        if let Some(port) = args.u64(key) {
            body[key] = json!(port);
        }
    }
    for key in ["kind", "country", "city", "provider", "ttl"] {
        if let Some(value) = args.str(key) {
            body[key] = json!(value);
        }
    }
    // The org key is deliberately never part of this request: URLs are username-only.
    let reply = pool
        .api
        .post(&["v1", "orgs", &org, "endpoints"], &body)
        .await?;
    let key = if reply["endpoints"].is_array() {
        "endpoints"
    } else {
        "items"
    };
    let (endpoints, truncated, total) = cap_items(&reply, key, ctx.rows(Some(count)));
    if strings_carry_credential(&Value::Array(endpoints.clone())) {
        return Err(ToolError::internal(
            "the gateway returned an endpoint that carries a credential; refusing to pass it on",
        ));
    }
    Ok(json!({
        "org": org,
        "style": body["style"],
        "username_pattern": username,
        "total": total,
        "truncated": truncated,
        crate::redact::ENDPOINTS: endpoints,
        "credential_note": "These endpoints carry the proxy username only. Add the org key as the proxy password in your client or secret store; do not paste it into this conversation.",
    }))
}
