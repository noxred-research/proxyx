//! Mutating tools and the configuration-change workflow.
//!
//! Every mutation, whether called directly or through `propose_config_change` and
//! `apply_config_change`, follows one path:
//!
//! 1. the gate: capability, engagement, org scope;
//! 2. `prepare`: validate the arguments and compute a diff against the current state, with the
//!    gateway's own policy crate for policy documents;
//! 3. dry run: return the preview and stop;
//! 4. approval: when the server requires it, store the change and stop;
//! 5. the mutation budget, an `intent` audit entry (the call is refused when it cannot be
//!    written), then the backend call.
//!
//! A change never stores a secret: credentials are named references into the server's
//! `[credentials]` table. A secret the call creates (an org key, a session's proxy URL) is shown
//! once under `revealed_once` when the server allows it, and is otherwise written to a `0600`
//! file whose path is returned.

use std::collections::BTreeSet;
use std::net::IpAddr;

use proxyx_client::Secret;
use proxyx_client::gateway::ConnectInfo;
use proxyx_client::signals::{BlockSignal, PoolControlClient, SignalType};
use serde_json::{Value, json};

use super::policy_tools::{
    diff_docs, doc_json, doc_label, parse_input, scope_name, stored_policies, validate_merged,
};
use super::util::{Args, FailKind, ToolError, ToolResult, now};
use super::{CallInfo, Ctx};
use crate::audit::{Entry, Phase, sha256_hex};
use crate::backend::ErrorKind;
use crate::config::{Capability, is_org_id, is_provider_id};
use crate::redact::REVEALED;
use crate::schema;
use crate::store::{Change, Status, change_digest, change_view, new_change_id, now_secs};

/// A mutating tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    CreateSession,
    ExtendSession,
    EndSession,
    CreateOrgKey,
    DisableOrgKeys,
    SetOrgRateLimit,
    SetOrgEgressProxy,
    ClearOrgEgressProxy,
    SetCustomerUpstream,
    ClearCustomerUpstream,
    ValidateCustomerUpstream,
    CreateOrgBlock,
    LiftOrgBlock,
    ReportBlockSignal,
    PutPolicy,
    PutOrgPolicy,
    DeletePolicy,
    PutInventory,
}

impl Action {
    pub const ALL: [Action; 18] = [
        Action::CreateSession,
        Action::ExtendSession,
        Action::EndSession,
        Action::CreateOrgKey,
        Action::DisableOrgKeys,
        Action::SetOrgRateLimit,
        Action::SetOrgEgressProxy,
        Action::ClearOrgEgressProxy,
        Action::SetCustomerUpstream,
        Action::ClearCustomerUpstream,
        Action::ValidateCustomerUpstream,
        Action::CreateOrgBlock,
        Action::LiftOrgBlock,
        Action::ReportBlockSignal,
        Action::PutPolicy,
        Action::PutOrgPolicy,
        Action::DeletePolicy,
        Action::PutInventory,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Action::CreateSession => "create_session",
            Action::ExtendSession => "extend_session",
            Action::EndSession => "end_session",
            Action::CreateOrgKey => "create_org_key",
            Action::DisableOrgKeys => "disable_org_keys",
            Action::SetOrgRateLimit => "set_org_rate_limit",
            Action::SetOrgEgressProxy => "set_org_egress_proxy",
            Action::ClearOrgEgressProxy => "clear_org_egress_proxy",
            Action::SetCustomerUpstream => "set_customer_upstream",
            Action::ClearCustomerUpstream => "clear_customer_upstream",
            Action::ValidateCustomerUpstream => "validate_customer_upstream",
            Action::CreateOrgBlock => "create_org_block",
            Action::LiftOrgBlock => "lift_org_block",
            Action::ReportBlockSignal => "report_block_signal",
            Action::PutPolicy => "put_policy",
            Action::PutOrgPolicy => "put_org_policy",
            Action::DeletePolicy => "delete_policy",
            Action::PutInventory => "put_inventory",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.name() == name)
    }

    pub const fn capability(self) -> Capability {
        match self {
            Action::CreateSession | Action::ExtendSession | Action::EndSession => {
                Capability::Sessions
            }
            Action::CreateOrgKey | Action::DisableOrgKeys => Capability::OrgKeys,
            Action::SetOrgRateLimit => Capability::OrgLimits,
            Action::SetOrgEgressProxy
            | Action::ClearOrgEgressProxy
            | Action::SetCustomerUpstream
            | Action::ClearCustomerUpstream
            | Action::ValidateCustomerUpstream => Capability::Egress,
            Action::CreateOrgBlock | Action::LiftOrgBlock => Capability::OrgBlocks,
            Action::ReportBlockSignal => Capability::Signals,
            Action::PutPolicy | Action::PutOrgPolicy | Action::DeletePolicy => Capability::Policy,
            Action::PutInventory => Capability::Inventory,
        }
    }

    /// Whether `propose_config_change` takes it: configuration, not runtime operations or
    /// calls that return a secret.
    pub const fn proposable(self) -> bool {
        !matches!(
            self,
            Action::CreateSession
                | Action::ExtendSession
                | Action::EndSession
                | Action::CreateOrgKey
                | Action::ValidateCustomerUpstream
                | Action::ReportBlockSignal
        )
    }
}

/// A validated mutation, ready to preview, store or run.
pub struct Prepared {
    /// Normalized arguments. Never holds a secret.
    pub args: Value,
    pub org: Option<String>,
    pub summary: String,
    pub diff: Value,
    pub warnings: Vec<String>,
    /// The credential a call carries, resolved from a reference or given inline.
    credential: Option<Credential>,
    /// The call was given a secret inline: it cannot be stored.
    pub inline_secret: bool,
    pub would_call: Vec<String>,
}

struct Credential {
    username: Option<String>,
    password: Option<Secret>,
}

fn prepared(args: Value, summary: impl Into<String>, would_call: &[&str]) -> Prepared {
    Prepared {
        org: args.get("org").and_then(Value::as_str).map(str::to_owned),
        args,
        summary: summary.into(),
        diff: Value::Null,
        warnings: Vec::new(),
        credential: None,
        inline_secret: false,
        would_call: would_call.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::invalid(message)
}

// --- credentials ---------------------------------------------------------------------------------

/// Resolve `credential_ref`, or inline `username` and `password` when the server allows them.
fn resolve_credential(
    ctx: &Ctx,
    args: &Args,
) -> Result<(Option<Credential>, Option<String>, bool), ToolError> {
    let reference = args.str("credential_ref");
    let inline = args.str("username").is_some() || args.str("password").is_some();
    match (reference, inline) {
        (Some(_), true) => Err(invalid(
            "give `credential_ref` or inline `username` and `password`, not both",
        )),
        (Some(name), false) => {
            let found = ctx.credentials.get(name).ok_or_else(|| {
                invalid(format!(
                    "no credential named {name:?} in the server's [credentials] table (available: {:?})",
                    ctx.credentials.keys().collect::<Vec<_>>()
                ))
            })?;
            Ok((
                Some(Credential {
                    username: found.username.clone(),
                    password: Some(found.password.clone()),
                }),
                Some(name.to_owned()),
                false,
            ))
        }
        (None, true) => {
            if !ctx.cfg.limits.allow_inline_secrets {
                return Err(invalid(
                    "inline secrets are disabled on this server (limits.allow_inline_secrets); use `credential_ref` with a credential the operator configured",
                ));
            }
            Ok((
                Some(Credential {
                    username: args.string("username"),
                    password: args.str("password").map(Secret::new),
                }),
                None,
                true,
            ))
        }
        (None, false) => Ok((None, None, false)),
    }
}

// --- validation helpers --------------------------------------------------------------------------

fn plain_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'))
}

fn valid_port_pair(address: &str) -> Result<(), String> {
    let (host, port) = address.rsplit_once(':').ok_or("expected host:port")?;
    let port: u32 = port.parse().map_err(|_| "the port is not a number")?;
    if !(1..=65_535).contains(&port) {
        return Err("the port must be 1 to 65535".into());
    }
    if !plain_host(host.trim_start_matches('[').trim_end_matches(']')) {
        return Err("the host must be a plain DNS name or IP".into());
    }
    Ok(())
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn ttl_seconds(text: &str) -> Option<u64> {
    let (digits, unit) = text.split_at(text.len().checked_sub(1)?);
    let n: u64 = digits.parse().ok()?;
    let secs = n.checked_mul(match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    })?;
    (secs > 0 && secs <= 366 * 86_400).then_some(secs)
}

fn require_unscoped(ctx: &Ctx, what: &str) -> Result<(), ToolError> {
    if ctx.gate.unscoped() {
        Ok(())
    } else {
        Err(ToolError::new(
            FailKind::Refused,
            format!(
                "{what} affects every org, and this server is scoped to specific orgs (scope.allowed_orgs)"
            ),
        ))
    }
}

// --- prepare ---------------------------------------------------------------------------------------

/// Validate `args` for `action` and describe the change.
///
/// # Errors
/// [`ToolError`] with a message the model can act on.
pub async fn prepare(ctx: &Ctx, action: Action, args: &Args) -> Result<Prepared, ToolError> {
    match action {
        Action::CreateSession => prepare_create_session(ctx, args),
        Action::ExtendSession => prepare_extend_session(ctx, args).await,
        Action::EndSession => prepare_end_session(ctx, args).await,
        Action::CreateOrgKey => {
            let org = org_required(ctx, args)?;
            let label = args.str("label").map(str::to_owned);
            if label
                .as_deref()
                .is_some_and(|l| l.chars().any(char::is_control))
            {
                return Err(invalid("`label` must not contain control characters"));
            }
            ctx.pool()?;
            let mut p = prepared(
                json!({"org": org, "label": label}),
                format!("create an org key for {org}"),
                &["POST /v1/orgs/{org}/keys"],
            );
            p.warnings
                .push("the key can be read only in the result of this call".into());
            Ok(p)
        }
        Action::DisableOrgKeys => {
            let org = org_required(ctx, args)?;
            ctx.pool()?;
            let mut p = prepared(
                json!({"org": org}),
                format!("disable every key of org {org}"),
                &["DELETE /v1/orgs/{org}/keys"],
            );
            p.warnings
                .push("every client of the org gets org_disabled within 30 seconds".into());
            Ok(p)
        }
        Action::SetOrgRateLimit => prepare_rate_limit(ctx, args).await,
        Action::SetOrgEgressProxy => prepare_egress(ctx, args).await,
        Action::ClearOrgEgressProxy => {
            let org = ctx.org(args)?;
            let control = ctx.control()?;
            let mut p = prepared(
                json!({"org": org}),
                format!("clear the egress proxy of org {org}"),
                &["DELETE /rpc/orgs/{org}/proxy"],
            );
            match control.api.get(&["rpc", "orgs", &org, "proxy"], &[]).await {
                Ok(current) => {
                    p.diff = json!({"removes": {"proxy_type": current["proxy_type"], "address": current["address"]}})
                }
                Err(error) if error.kind == ErrorKind::NotFound => p
                    .warnings
                    .push("the org has no egress proxy; nothing to clear".into()),
                Err(error) => return Err(error.into()),
            }
            Ok(p)
        }
        Action::SetCustomerUpstream => prepare_upstream(ctx, args).await,
        Action::ClearCustomerUpstream => {
            let org = org_required(ctx, args)?;
            let pool = ctx.pool()?;
            let mut p = prepared(
                json!({"org": org}),
                format!("retire the customer upstream of org {org}"),
                &["DELETE /v1/orgs/{org}/upstream"],
            );
            match pool.api.get(&["v1", "orgs", &org, "upstream"], &[]).await {
                Ok(current) => {
                    p.diff = json!({"retires": {"host": current["host"], "port": current["port"], "state": current["state"]}})
                }
                Err(error) if error.kind == ErrorKind::NotFound => {
                    p.warnings.push("the org has no customer upstream".into())
                }
                Err(error) => return Err(error.into()),
            }
            Ok(p)
        }
        Action::ValidateCustomerUpstream => {
            let org = org_required(ctx, args)?;
            ctx.pool()?;
            let mut p = prepared(
                json!({"org": org}),
                format!("validate the customer upstream of org {org} by dialing through it"),
                &["POST /v1/orgs/{org}/upstream/validate"],
            );
            p.warnings.push("the gateway dials the upstream and an exit-IP check service; a pass makes the upstream leasable".into());
            Ok(p)
        }
        Action::CreateOrgBlock => prepare_block(ctx, args).await,
        Action::LiftOrgBlock => prepare_lift(ctx, args).await,
        Action::ReportBlockSignal => prepare_signal(ctx, args),
        Action::PutPolicy | Action::PutOrgPolicy => prepare_put_policy(ctx, action, args).await,
        Action::DeletePolicy => prepare_delete_policy(ctx, args).await,
        Action::PutInventory => prepare_inventory(ctx, args).await,
    }
}

fn org_required(ctx: &Ctx, args: &Args) -> Result<String, ToolError> {
    let org = args.require_str("org")?.to_owned();
    if !is_org_id(&org) {
        return Err(invalid(format!(
            "{org:?} is not an org id ([a-z0-9_-], 1 to 64)"
        )));
    }
    ctx.gate.check_org(&org)?;
    Ok(org)
}

fn prepare_create_session(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    ctx.control()?;
    let org = ctx.org(args)?;
    let cap = ctx.cfg.limits.max_session_ttl_secs;
    let ttl = args.u64("ttl_secs").unwrap_or(900);
    if ttl > u64::from(cap) {
        return Err(invalid(format!(
            "ttl_secs {ttl} is above this server's limit of {cap} (limits.max_session_ttl_secs); ask for less and extend_session later"
        )));
    }
    let hosts = |key: &str| -> Result<Vec<String>, ToolError> {
        args.get(key)
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| {
                        let host = v.as_str().unwrap_or("");
                        if host.is_empty()
                            || host
                                .chars()
                                .any(|c| c.is_whitespace() || c.is_control() || c == '/')
                        {
                            Err(invalid(format!(
                                "{key}: {host:?} is not a host pattern (no spaces, no slashes)"
                            )))
                        } else {
                            Ok(host.to_owned())
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    };
    let captured = hosts("captured_hosts")?;
    let excluded = hosts("excluded_hosts")?;
    let mut headers = Vec::new();
    for header in args
        .get("inject_headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = header["name"].as_str().unwrap_or("");
        let value = header["value"].as_str().unwrap_or("");
        let token = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !token {
            return Err(invalid(format!(
                "inject_headers: {name:?} is not a header name"
            )));
        }
        if value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(invalid(
                "inject_headers: a value must not contain line breaks",
            ));
        }
        headers.push(json!({"name": name, "value": value}));
    }
    let source = args.string("source").unwrap_or_else(|| "mcp".to_owned());
    let source_id = args
        .string("source_id")
        .unwrap_or_else(|| format!("mcp-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]));
    let normalized = json!({
        "org": org, "source": source, "source_id": source_id,
        "captured_hosts": captured, "excluded_hosts": excluded,
        "ttl_secs": ttl, "inject_headers": headers,
        "serialize": args.bool("serialize").unwrap_or(false),
        "agent": args.str("agent"),
    });
    let mut p = prepared(
        normalized.clone(),
        format!(
            "create a session for org {org} (source_id {source_id}) capturing {} host pattern(s) for {ttl}s",
            captured.len()
        ),
        &["POST /rpc/sessions"],
    );
    p.diff = json!({"creates": {"captured_hosts": captured, "excluded_hosts": excluded, "ttl_secs": ttl}});
    if captured.is_empty() {
        p.warnings
            .push("captured_hosts is empty: the session captures nothing".into());
    }
    if captured.iter().any(|h| h == "*") {
        p.warnings.push("`*` intercepts and stores every host the client reaches; make sure that is within the authorization".into());
    }
    if !headers.is_empty() {
        p.warnings.push(
            "injected header values are stored in the session; they are not shown again".into(),
        );
    }
    Ok(p)
}

async fn prepare_extend_session(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let control = ctx.control()?;
    let id = args.require_str("session_id")?;
    let (additional, new_ttl) = (args.u64("additional_secs"), args.u64("new_ttl_secs"));
    let secs = match (additional, new_ttl) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                "give `additional_secs` or `new_ttl_secs`, not both",
            ));
        }
        (None, None) => return Err(invalid("give `additional_secs` or `new_ttl_secs`")),
        (Some(n), None) | (None, Some(n)) => n,
    };
    let cap = u64::from(ctx.cfg.limits.max_session_ttl_secs);
    if secs > cap {
        return Err(invalid(format!(
            "{secs} seconds is above this server's limit of {cap} (limits.max_session_ttl_secs)"
        )));
    }
    let current = control.api.get(&["rpc", "sessions", id], &[]).await?;
    let expires = current["expires_at_ms"].as_i64().unwrap_or(0);
    let new_expires = match (additional, new_ttl) {
        (Some(add), _) => expires + i64::try_from(add).unwrap_or(0) * 1000,
        (None, Some(ttl)) => now() * 1000 + i64::try_from(ttl).unwrap_or(0) * 1000,
        _ => expires,
    };
    let mut p = prepared(
        json!({"session_id": id, "additional_secs": additional, "new_ttl_secs": new_ttl}),
        format!("extend session {id}"),
        &["PATCH /rpc/sessions/{id}"],
    );
    p.org = current["org_id"].as_str().map(str::to_owned);
    if let Some(org) = &p.org {
        ctx.gate.check_org(org)?;
    }
    p.diff = json!({"expires_at_ms": {"from": expires, "to": new_expires}});
    Ok(p)
}

async fn prepare_end_session(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let control = ctx.control()?;
    let id = args.require_str("session_id")?;
    let current = control.api.get(&["rpc", "sessions", id], &[]).await?;
    let mut p = prepared(
        json!({"session_id": id}),
        format!("release session {id}"),
        &["DELETE /rpc/sessions/{id}"],
    );
    p.org = current["org_id"].as_str().map(str::to_owned);
    if let Some(org) = &p.org {
        ctx.gate.check_org(org)?;
    }
    p.diff = json!({"releases": {"source_id": current["source_id"], "org_id": current["org_id"]}});
    p.warnings.push(
        "the last holder's release starts teardown; captures drain to storage afterwards".into(),
    );
    Ok(p)
}

async fn prepare_rate_limit(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let control = ctx.control()?;
    let org = ctx.org(args)?;
    let (rpm, burst) = (args.u64("requests_per_minute"), args.u64("burst"));
    if rpm.is_none() && burst.is_none() {
        return Err(invalid("give `requests_per_minute` and `burst`"));
    }
    let mut p = prepared(
        json!({"org": org, "requests_per_minute": rpm, "burst": burst}),
        format!("set the rate limit of org {org}"),
        &["PUT /rpc/orgs/{org}/rate-limit"],
    );
    if rpm.is_none() || burst.is_none() {
        p.warnings.push("an omitted field is stored as null, which inherits the control plane default; it is not left unchanged".into());
    }
    match control
        .api
        .get(&["rpc", "orgs", &org, "rate-limit"], &[])
        .await
    {
        Ok(current) => {
            p.diff = json!({
                "requests_per_minute": {"from": current["requests_per_minute"], "to": rpm},
                "burst": {"from": current["burst"], "to": burst},
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => p
            .warnings
            .push("the org has no row yet: this creates it".into()),
        Err(error) => return Err(error.into()),
    }
    Ok(p)
}

async fn prepare_egress(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let control = ctx.control()?;
    let org = ctx.org(args)?;
    let proxy_type = args.require_str("proxy_type")?;
    let address = args.require_str("address")?;
    valid_port_pair(address).map_err(|reason| invalid(format!("address {address:?}: {reason}")))?;
    let (credential, reference, inline) = resolve_credential(ctx, args)?;
    let mut p = prepared(
        json!({"org": org, "proxy_type": proxy_type, "address": address, "credential_ref": reference}),
        format!("chain the session traffic of org {org} through {proxy_type} proxy {address}"),
        &["PUT /rpc/orgs/{org}/proxy"],
    );
    p.credential = credential;
    p.inline_secret = inline;
    let has_login = p.credential.is_some();
    match control.api.get(&["rpc", "orgs", &org, "proxy"], &[]).await {
        Ok(current) => {
            p.diff = json!({
                "proxy_type": {"from": current["proxy_type"], "to": proxy_type},
                "address": {"from": current["address"], "to": address},
                "has_credentials": {"from": !current["username"].is_null(), "to": has_login},
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => {
            p.diff = json!({"creates": {"proxy_type": proxy_type, "address": address, "has_credentials": has_login}})
        }
        Err(error) => return Err(error.into()),
    }
    p.warnings.push(
        "sessions copy the egress proxy when they are created: existing sessions keep the old one"
            .into(),
    );
    Ok(p)
}

async fn prepare_upstream(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let org = org_required(ctx, args)?;
    let host = args.require_str("host")?;
    if !plain_host(host) {
        return Err(invalid(
            "host must be a plain DNS name or IP literal, without scheme, port, path or login",
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && !public_ip(ip)
    {
        return Err(invalid(
            "the upstream host must be public routable; the gateway refuses private, loopback and link-local addresses",
        ));
    }
    let (scheme, port, region) = (
        args.require_str("scheme")?,
        args.u64("port").unwrap_or(0),
        args.require_str("region")?,
    );
    let (credential, reference, inline) = resolve_credential(ctx, args)?;
    let mut p = prepared(
        json!({"org": org, "scheme": scheme, "host": host, "port": port, "region": region, "credential_ref": reference}),
        format!("set the customer upstream of org {org} to {scheme}://{host}:{port} ({region})"),
        &["PUT /v1/orgs/{org}/upstream"],
    );
    p.credential = credential;
    p.inline_secret = inline;
    match pool.api.get(&["v1", "orgs", &org, "upstream"], &[]).await {
        Ok(current) => {
            p.diff = json!({
                "scheme": {"from": current["scheme"], "to": scheme},
                "host": {"from": current["host"], "to": host},
                "port": {"from": current["port"], "to": port},
                "region": {"from": current["region"], "to": region},
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => {
            p.diff =
                json!({"creates": {"scheme": scheme, "host": host, "port": port, "region": region}})
        }
        Err(error) => return Err(error.into()),
    }
    p.warnings.push("the upstream starts as a candidate: nothing leases it until validate_customer_upstream passes".into());
    p.warnings.push("the gateway reloads its snapshot every 30 seconds, so this reaches each pod after its next reload".into());
    Ok(p)
}

async fn prepare_block(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let org = org_required(ctx, args)?;
    let (scope, value) = (args.require_str("scope")?, args.require_str("value")?);
    let reason = args.require_str("reason")?.trim().to_owned();
    if reason.is_empty() || reason.len() > 1000 {
        return Err(invalid("reason must be 1 to 1000 bytes"));
    }
    let value_ok = match scope {
        "ip" => value.parse::<IpAddr>().is_ok(),
        "provider" => is_provider_id(value),
        "route_class" => value
            .split_once(':')
            .is_some_and(|(provider, region)| is_provider_id(provider) && region_ok(region)),
        "pool" => matches!(value, "shared" | "private"),
        _ => false,
    };
    if !value_ok {
        return Err(invalid(format!(
            "value {value:?} does not fit scope {scope}: an address for ip, a provider id, `provider:region` for route_class, `shared` or `private` for pool"
        )));
    }
    let ttl = args.str("ttl");
    if let Some(ttl) = ttl
        && ttl_seconds(ttl).is_none()
    {
        return Err(invalid(
            "ttl must be like `30m`, `2h` or `7d`, above zero and at most 366d",
        ));
    }
    let mut p = prepared(
        json!({"org": org, "scope": scope, "value": value, "reason": reason, "ttl": ttl}),
        format!(
            "block org {org} from {scope} {value}{}",
            ttl.map(|t| format!(" for {t}")).unwrap_or_default()
        ),
        &["POST /v1/org-blocks"],
    );
    let existing = pool
        .api
        .get(&["v1", "org-blocks"], &[("org", org.clone())])
        .await?;
    let duplicates: Vec<&Value> = existing["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["scope"] == scope && b["value"] == value)
        .collect();
    p.diff = json!({"creates": {"org": org, "scope": scope, "value": value, "ttl": ttl}, "already_active": duplicates});
    if ttl.is_none() {
        p.warnings
            .push("no ttl: the block stays until someone lifts it".into());
    }
    if !duplicates.is_empty() {
        p.warnings
            .push("an identical block is already active".into());
    }
    p.warnings
        .push("open tunnels of the org inside the scope are asked to close".into());
    Ok(p)
}

fn region_ok(region: &str) -> bool {
    let (country, city) = region
        .split_once('/')
        .map_or((region, None), |(c, t)| (c, Some(t)));
    country.len() == 2
        && country.bytes().all(|b| b.is_ascii_lowercase())
        && city.is_none_or(|t| {
            !t.is_empty()
                && t.len() <= 48
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

async fn prepare_lift(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let id = args.require_str("id")?;
    let listing = pool.api.get(&["v1", "org-blocks"], &[]).await?;
    let block = listing["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|b| b["id"] == id)
        .cloned()
        .ok_or_else(|| {
            ToolError::invalid(format!(
                "no active block {id}; list_org_blocks shows the active ones"
            ))
        })?;
    let org = block["org"].as_str().unwrap_or("").to_owned();
    ctx.gate.check_org(&org)?;
    let mut p = prepared(
        json!({"id": id}),
        format!(
            "lift block {id} of org {org} ({} {})",
            block["scope"], block["value"]
        ),
        &["DELETE /v1/org-blocks/{id}"],
    );
    p.org = Some(org);
    p.diff = json!({"lifts": block});
    Ok(p)
}

fn prepare_signal(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let ip = args.require_str("exit_ip")?;
    ip.parse::<IpAddr>()
        .map_err(|_| invalid("exit_ip is not an IP address"))?;
    let target = args.require_str("target")?;
    if target
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/')
        || target.is_empty()
    {
        return Err(invalid("target is host, host:port or [v6]:port"));
    }
    let kind = args.require_str("type")?;
    let session = args.str("session");
    let via = args.str("via").unwrap_or("auto");
    let org_key_possible = pool.org_key.is_some() && session.is_some();
    let route = match via {
        "org_key" if !org_key_possible => {
            return Err(invalid(
                "via org_key needs `session` and an org key configured (endpoints.pool.org_key_file)",
            ));
        }
        "org_key" => "org_key",
        "operator" => "operator",
        _ if org_key_possible => "org_key",
        _ => "operator",
    };
    if route == "operator" {
        require_unscoped(
            ctx,
            "an operator block signal changes the state of a shared exit IP and",
        )?;
    }
    let mut p = prepared(
        json!({"exit_ip": ip, "target": target, "type": kind, "session": session, "via": route}),
        format!("report a {kind} signal for exit IP {ip} at {target} via the {route} route"),
        &[if route == "org_key" {
            "POST /v1/block-signals"
        } else {
            "POST /v1/ips/{ip}/block"
        }],
    );
    p.warnings.push("the pool cools the IP for this target and may escalate to the whole IP by the policy's block rules; a wrong report costs a healthy IP".into());
    Ok(p)
}

async fn prepare_put_policy(ctx: &Ctx, action: Action, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let mut docs = parse_input(args)?;
    if docs.len() > 200 {
        return Err(invalid("at most 200 policies per write"));
    }
    let mut org_arg: Option<String> = None;
    if action == Action::PutOrgPolicy {
        let org = org_required(ctx, args)?;
        if docs.len() != 1 {
            return Err(invalid("put_org_policy takes exactly one policy"));
        }
        let doc = &mut docs[0];
        if doc.target.as_deref().is_some_and(|m| m != org) {
            return Err(invalid(format!(
                "the policy's match must be {org:?} (or omitted)"
            )));
        }
        if doc.scope != policy::Scope::Org && doc.scope != policy::Scope::default() {
            return Err(invalid("an org policy has scope org"));
        }
        doc.scope = policy::Scope::Org;
        doc.target = Some(org.clone());
        if doc.name.is_empty() {
            doc.name = format!("org-{org}");
        }
        org_arg = Some(org);
    } else {
        for doc in &docs {
            match doc.scope {
                policy::Scope::Org => {
                    if let Some(org) = doc.target.as_deref() {
                        ctx.gate.check_org(org)?;
                    }
                }
                _ => require_unscoped(
                    ctx,
                    &format!("the {} policy {:?}", scope_name(doc.scope), doc.name),
                )?,
            }
        }
    }
    let listing = pool.api.get(&["v1", "policies"], &[]).await?;
    let stored = stored_policies(&listing).map_err(ToolError::internal)?;
    validate_merged(&stored, &docs).map_err(|error| {
        invalid(format!("the policy set would be invalid: {error}"))
            .with_detail(json!({"validation_error": error}))
    })?;
    let mut diff = Vec::new();
    let mut warnings = Vec::new();
    for doc in &docs {
        let new = doc_json(doc);
        let current = stored
            .iter()
            .find(|s| s.scope == scope_name(doc.scope) && s.name == doc.name);
        let changes = diff_docs(current.map(|s| &s.raw), &new);
        if let Some(current) = current
            && current.actor == "gitops"
            && matches!(doc.scope, policy::Scope::Global | policy::Scope::RouteClass)
        {
            warnings.push(format!(
                    "{} is written by git: this is an emergency override that git replaces when it changes that policy",
                    doc_label(doc)
                ));
        }
        diff.push(json!({
            "policy": doc_label(doc),
            "new": current.is_none(),
            "unchanged": current.is_some() && changes.is_empty(),
            "changes": changes,
        }));
    }
    warnings.push("the gateway also checks that a loaded provider adapter serves each region and fits each rotating provider's session life".into());
    let normalized = match &org_arg {
        Some(org) => json!({"org": org, "policies": docs.iter().map(doc_json).collect::<Vec<_>>()}),
        None => json!({"policies": docs.iter().map(doc_json).collect::<Vec<_>>()}),
    };
    let labels: Vec<String> = docs.iter().map(doc_label).collect();
    let mut p = prepared(
        normalized,
        format!("store {}", labels.join(", ")),
        &[if action == Action::PutOrgPolicy {
            "PUT /v1/orgs/{org}/cache-policy"
        } else {
            "PUT /v1/policies"
        }],
    );
    p.diff = json!(diff);
    p.warnings = warnings;
    Ok(p)
}

async fn prepare_delete_policy(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    let (scope, name) = (args.require_str("scope")?, args.require_str("name")?);
    let listing = pool.api.get(&["v1", "policies"], &[]).await?;
    let stored = stored_policies(&listing).map_err(ToolError::internal)?;
    let target = stored
        .iter()
        .find(|s| s.scope == scope && s.name == name)
        .ok_or_else(|| {
            invalid(format!(
                "no current policy {scope}/{name}; list_policies shows them"
            ))
        })?;
    if target.actor == "gitops" {
        return Err(ToolError::new(
            FailKind::Invalid,
            "git wrote this policy: delete its file from the git policy data instead; the API cannot remove it",
        ));
    }
    match target.doc.scope {
        policy::Scope::Org => {
            if let Some(org) = target.doc.target.as_deref() {
                ctx.gate.check_org(org)?;
            }
        }
        _ => require_unscoped(ctx, &format!("deleting the {scope} policy {name:?}"))?,
    }
    let rest: Vec<policy::PolicyDoc> = stored
        .iter()
        .filter(|s| !(s.scope == scope && s.name == name))
        .map(|s| s.doc.clone())
        .collect();
    policy::PolicySet::from_docs(rest).map_err(|error| {
        invalid(format!(
            "deleting it would leave an invalid policy set: {error}"
        ))
    })?;
    let mut p = prepared(
        json!({"scope": scope, "name": name}),
        format!("delete policy {scope}/{name}"),
        &["DELETE /v1/policies/{scope}/{name}"],
    );
    p.diff = json!({"removes": target.raw});
    p.warnings.push(
        "if git defines a policy of this name, the next reload writes git's version back".into(),
    );
    Ok(p)
}

async fn prepare_inventory(ctx: &Ctx, args: &Args) -> Result<Prepared, ToolError> {
    let pool = ctx.pool()?;
    require_unscoped(
        ctx,
        "a provider's static inventory is shared by every org and",
    )?;
    let provider = args.require_str("provider")?;
    if !is_provider_id(provider) {
        return Err(invalid("provider is [a-z0-9_-], 1 to 48"));
    }
    let entries = args
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        return Err(invalid(
            "entries must not be empty: an empty list would retire the whole provider; retire IPs explicitly by leaving them out of a non-empty list",
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let here = |field: &str| format!("entries[{index}].{field}");
        let Some(map) = entry.as_object() else {
            return Err(invalid(format!("entries[{index}] must be an object")));
        };
        let ip = map
            .get("ip")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .ok_or_else(|| invalid(format!("{} must be an IP address", here("ip"))))?;
        if !public_ip(ip) {
            return Err(invalid(format!(
                "{ip}: not a public address (private, loopback, link-local, multicast and unspecified are refused)"
            )));
        }
        if !seen.insert(ip) {
            return Err(invalid(format!("{ip} appears twice")));
        }
        if map.get("provider").and_then(Value::as_str) != Some(provider) {
            return Err(invalid(format!(
                "{} must equal {provider:?}",
                here("provider")
            )));
        }
        let host_ok = map
            .get("host")
            .and_then(Value::as_str)
            .is_some_and(plain_host);
        if !host_ok {
            return Err(invalid(format!(
                "{} must be a plain DNS name or IP",
                here("host")
            )));
        }
        if map
            .get("port")
            .and_then(Value::as_u64)
            .is_none_or(|port| port == 0 || port > 65_535)
        {
            return Err(invalid(format!("{} must be 1 to 65535", here("port"))));
        }
        if let Some(credentials) = map.get("credentials").and_then(Value::as_str)
            && (credentials.contains(['/', '\\', '\0']) || credentials.contains(".."))
        {
            return Err(invalid(format!(
                "{} must be a plain file name, not a path or a secret",
                here("credentials")
            )));
        }
    }
    let current = pool
        .api
        .get(&["v1", "inventory"], &[("provider", provider.to_owned())])
        .await?;
    let current_rows: Vec<&Value> = current["items"].as_array().into_iter().flatten().collect();
    let current_ips: BTreeSet<IpAddr> = current_rows
        .iter()
        .filter_map(|r| r["ip"].as_str()?.parse().ok())
        .collect();
    let added: Vec<String> = seen
        .iter()
        .filter(|ip| !current_ips.contains(ip))
        .map(ToString::to_string)
        .collect();
    let revived: Vec<String> = current_rows
        .iter()
        .filter(|r| r["state"] == "retired")
        .filter_map(|r| r["ip"].as_str())
        .filter(|ip| ip.parse::<IpAddr>().is_ok_and(|ip| seen.contains(&ip)))
        .map(str::to_owned)
        .collect();
    let retired: Vec<String> = current_rows
        .iter()
        .filter(|r| r["state"] != "retired" && r["owner"].is_null())
        .filter_map(|r| r["ip"].as_str())
        .filter(|ip| ip.parse::<IpAddr>().is_ok_and(|ip| !seen.contains(&ip)))
        .map(str::to_owned)
        .collect();
    let live = current_rows
        .iter()
        .filter(|r| r["state"] != "retired")
        .count();
    let mut p = prepared(
        json!({"provider": provider, "entries": entries}),
        format!(
            "make the inventory of {provider} equal to {} entries",
            entries.len()
        ),
        &["PUT /v1/inventory/{provider}"],
    );
    p.diff = json!({
        "added": added,
        "revived": revived,
        "retired": retired.iter().take(50).collect::<Vec<_>>(),
        "retired_count": retired.len(),
        "unchanged": seen.len() - added.len() - revived.len(),
    });
    if !retired.is_empty() && live > 0 && retired.len() * 2 > live {
        p.warnings.push(format!(
            "this retires {} of {live} live IPs of {provider}",
            retired.len()
        ));
    }
    Ok(p)
}

// --- execute ----------------------------------------------------------------------------------------

/// Reveal a secret once, or put it in a private file.
fn deliver(
    ctx: &Ctx,
    label: &str,
    fields: &[(&str, &str)],
    out: &mut Value,
) -> Result<(), ToolError> {
    if ctx.cfg.safety.reveal_secrets_once {
        let mut revealed = serde_json::Map::new();
        for (name, value) in fields {
            revealed.insert((*name).to_owned(), json!(value));
        }
        out[REVEALED] = Value::Object(revealed);
        out["secret_delivery"] = json!("shown once in `revealed_once`; it cannot be read again");
        return Ok(());
    }
    let content: String = fields
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    let path = ctx
        .store
        .write_secret(label, &content)
        .map_err(|error| ToolError::internal(format!("cannot write the secret file: {error}")))?;
    out["secret_delivery"] = json!("written to a private file (0600); the value is not shown here");
    out["secret_file"] = json!(path.display().to_string());
    Ok(())
}

async fn execute(ctx: &Ctx, action: Action, p: &Prepared, info: &CallInfo) -> ToolResult {
    let args = Args::from_value(p.args.clone());
    match action {
        Action::CreateSession => {
            let control = ctx.control()?;
            let headers: Vec<Value> = p.args["inject_headers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|h| json!([h["name"], h["value"]]))
                .collect();
            let mut body = json!({
                "org_id": p.args["org"], "source": p.args["source"], "source_id": p.args["source_id"],
                "captured_hosts": p.args["captured_hosts"], "excluded_hosts": p.args["excluded_hosts"],
                "inject_headers": headers, "serialize": p.args["serialize"], "ttl_secs": p.args["ttl_secs"],
            });
            if let Some(agent) = p.args["agent"].as_str() {
                body["agent"] = json!(agent);
            }
            let reply = control.api.post(&["rpc", "sessions"], &body).await?;
            let id = reply["session_id"].as_str().unwrap_or("").to_owned();
            let expires = reply["expires_at_ms"].as_i64().unwrap_or(0);
            let mut out = json!({
                "session_id": id,
                "org": p.args["org"],
                "source": p.args["source"],
                "source_id": p.args["source_id"],
                "expires_at_ms": expires,
                "expires_in_secs": (expires / 1000 - now()).max(0),
                "attached": reply["attached"].as_bool().unwrap_or(false),
                "warning": reply["warning"],
                "ca_cert_pem_sha256": reply["ca_cert_pem"].as_str().map(sha256_hex),
                "ca_cert_resource": "proxyx://control/certificate",
            });
            let url = reply["proxy_url"].as_str().unwrap_or("");
            let socks = reply["proxy_url_socks5"].as_str().unwrap_or("");
            let compact_id: String = id.chars().filter(|c| *c != '-').take(12).collect();
            deliver(
                ctx,
                &format!("session-{compact_id}"),
                &[
                    ("HTTP_PROXY", url),
                    ("HTTPS_PROXY", url),
                    ("ALL_PROXY", socks),
                ],
                &mut out,
            )?;
            let _ = ctx.store.register_session(&json!({
                "session_id": id, "org": p.args["org"], "source": p.args["source"], "source_id": p.args["source_id"],
                "created_at": now(), "expires_at_ms": expires,
                "captured_hosts": p.args["captured_hosts"].as_array().map_or(0, Vec::len),
                "created_by": info.caller.client_name,
            }));
            Ok(out)
        }
        Action::ExtendSession => {
            let control = ctx.control()?;
            let id = args.require_str("session_id")?;
            let body = match (args.u64("additional_secs"), args.u64("new_ttl_secs")) {
                (Some(add), _) => json!({"additional_secs": add}),
                (None, Some(ttl)) => json!({"new_ttl_secs": ttl}),
                _ => return Err(invalid("nothing to extend by")),
            };
            let reply = control.api.patch(&["rpc", "sessions", id], &body).await?;
            let expires = reply["expires_at_ms"].as_i64().unwrap_or(0);
            Ok(
                json!({"session_id": id, "expires_at_ms": expires, "expires_in_secs": (expires / 1000 - now()).max(0)}),
            )
        }
        Action::EndSession => {
            let control = ctx.control()?;
            let id = args.require_str("session_id")?;
            control.api.delete(&["rpc", "sessions", id]).await?;
            Ok(json!({"session_id": id, "released": true}))
        }
        Action::CreateOrgKey => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            let mut body = json!({});
            if let Some(label) = args.str("label") {
                body["label"] = json!(label);
            }
            let reply = pool.api.post(&["v1", "orgs", org, "keys"], &body).await?;
            let key = reply["key"]
                .as_str()
                .ok_or_else(|| ToolError::internal("the gateway returned no key"))?;
            let mut out = json!({"org": org, "key_fingerprint": &sha256_hex(key)[..12], "label": args.str("label")});
            deliver(ctx, &format!("org-key-{org}"), &[("key", key)], &mut out)?;
            Ok(out)
        }
        Action::DisableOrgKeys => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            let reply = pool.api.delete(&["v1", "orgs", org, "keys"]).await?;
            Ok(json!({"org": org, "disabled": reply["disabled"]}))
        }
        Action::SetOrgRateLimit => {
            let control = ctx.control()?;
            let org = args.require_str("org")?;
            let mut body = json!({});
            if let Some(rpm) = args.u64("requests_per_minute") {
                body["requests_per_minute"] = json!(rpm);
            }
            if let Some(burst) = args.u64("burst") {
                body["burst"] = json!(burst);
            }
            let reply = control
                .api
                .put(&["rpc", "orgs", org, "rate-limit"], &body)
                .await?;
            Ok(json!({"org": org, "applied": body, "server": reply}))
        }
        Action::SetOrgEgressProxy => {
            let control = ctx.control()?;
            let org = args.require_str("org")?;
            let mut body =
                json!({"proxy_type": args.str("proxy_type"), "address": args.str("address")});
            if let Some(credential) = &p.credential {
                if let Some(username) = &credential.username {
                    body["username"] = json!(username);
                }
                if let Some(password) = &credential.password {
                    body["password"] = json!(password.expose());
                }
            }
            control
                .api
                .put(&["rpc", "orgs", org, "proxy"], &body)
                .await?;
            Ok(
                json!({"org": org, "proxy_type": args.str("proxy_type"), "address": args.str("address"), "has_credentials": p.credential.is_some()}),
            )
        }
        Action::ClearOrgEgressProxy => {
            let control = ctx.control()?;
            let org = args.require_str("org")?;
            match control.api.delete(&["rpc", "orgs", org, "proxy"]).await {
                Ok(_) => Ok(json!({"org": org, "cleared": true})),
                Err(error) if error.kind == ErrorKind::NotFound => {
                    Ok(json!({"org": org, "cleared": false, "note": "there was no egress proxy"}))
                }
                Err(error) => Err(error.into()),
            }
        }
        Action::SetCustomerUpstream => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            let mut body = json!({
                "scheme": args.str("scheme"), "host": args.str("host"),
                "port": args.u64("port"), "region": args.str("region"),
            });
            if let Some(credential) = &p.credential {
                if let Some(username) = &credential.username {
                    body["username"] = json!(username);
                }
                if let Some(password) = &credential.password {
                    body["password"] = json!(password.expose());
                }
            }
            let reply = pool
                .api
                .put(&["v1", "orgs", org, "upstream"], &body)
                .await?;
            Ok(
                json!({"org": org, "upstream": reply, "next": "validate_customer_upstream makes it leasable"}),
            )
        }
        Action::ClearCustomerUpstream => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            let reply = pool.api.delete(&["v1", "orgs", org, "upstream"]).await?;
            Ok(json!({"org": org, "result": reply}))
        }
        Action::ValidateCustomerUpstream => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            match pool
                .api
                .post(&["v1", "orgs", org, "upstream", "validate"], &json!({}))
                .await
            {
                Ok(reply) => Ok(json!({"org": org, "valid": true, "result": reply})),
                Err(error) if error.status == Some(422) => Ok(json!({
                    "org": org,
                    "valid": false,
                    "reason": error.body.as_ref().map(|b| b["reason"].clone()),
                    "error": error.message,
                })),
                Err(error) => Err(error.into()),
            }
        }
        Action::CreateOrgBlock => {
            let pool = ctx.pool()?;
            let mut body = json!({
                "org": args.str("org"), "scope": args.str("scope"),
                "value": args.str("value"), "reason": args.str("reason"),
            });
            if let Some(ttl) = args.str("ttl") {
                body["ttl"] = json!(ttl);
            }
            let reply = pool.api.post(&["v1", "org-blocks"], &body).await?;
            Ok(json!({"block": reply}))
        }
        Action::LiftOrgBlock => {
            let pool = ctx.pool()?;
            let id = args.require_str("id")?;
            let reply = pool.api.delete(&["v1", "org-blocks", id]).await?;
            Ok(json!({"block": reply}))
        }
        Action::ReportBlockSignal => execute_signal(ctx, &args).await,
        Action::PutPolicy => {
            let pool = ctx.pool()?;
            let reply = pool
                .api
                .put(
                    &["v1", "policies"],
                    &json!({"policies": p.args["policies"]}),
                )
                .await?;
            Ok(json!({"result": reply}))
        }
        Action::PutOrgPolicy => {
            let pool = ctx.pool()?;
            let org = args.require_str("org")?;
            let doc = p.args["policies"][0].clone();
            let reply = pool
                .api
                .put(&["v1", "orgs", org, "cache-policy"], &doc)
                .await?;
            Ok(json!({"result": reply}))
        }
        Action::DeletePolicy => {
            let pool = ctx.pool()?;
            let reply = pool
                .api
                .delete(&[
                    "v1",
                    "policies",
                    args.require_str("scope")?,
                    args.require_str("name")?,
                ])
                .await?;
            Ok(json!({"result": reply}))
        }
        Action::PutInventory => {
            let pool = ctx.pool()?;
            let provider = args.require_str("provider")?;
            let reply = pool
                .api
                .put(
                    &["v1", "inventory", provider],
                    &json!({"entries": p.args["entries"]}),
                )
                .await?;
            Ok(json!({"result": reply}))
        }
    }
}

async fn execute_signal(ctx: &Ctx, args: &Args) -> ToolResult {
    let pool = ctx.pool()?;
    let (ip, target, kind) = (
        args.require_str("exit_ip")?,
        args.require_str("target")?,
        args.require_str("type")?,
    );
    let session = args.str("session");
    if args.str("via") == Some("org_key") {
        let (Some(key), Some(session)) = (pool.org_key.clone(), session) else {
            return Err(invalid("the org-key route needs an org key and a session"));
        };
        let client = PoolControlClient::new(&pool.base_url, key)
            .map_err(|error| ToolError::new(FailKind::Backend, error.to_string()))?;
        let exit_ip: IpAddr = ip
            .parse()
            .map_err(|_| invalid("exit_ip is not an IP address"))?;
        let kind = match kind {
            "rate_limited" => SignalType::RateLimited,
            "challenge" => SignalType::Challenge,
            "forbidden" => SignalType::Forbidden,
            _ => SignalType::Reset,
        };
        let (host, port) = split_target(target);
        let info = ConnectInfo {
            session: session.to_owned(),
            exit_ip,
        };
        let signal = BlockSignal::for_tunnel(&info, host, port, kind);
        let outcome = client
            .report(&[signal])
            .await
            .map_err(|error| ToolError::new(FailKind::Backend, error.to_string()))?;
        return Ok(
            json!({"route": "org_key", "accepted": outcome.accepted, "ignored": outcome.ignored,
            "reading": "ignored means the event was stale, for an unknown session, another org, or a different exit IP than the one recorded for the session"}),
        );
    }
    let host = target
        .rsplit_once(':')
        .filter(|(h, _)| !h.contains(':') || h.ends_with(']'))
        .map_or(target, |(h, _)| h);
    let mut body = json!({"target": host.trim_matches(['[', ']']), "type": kind});
    if let Some(session) = session {
        body["session"] = json!(session);
    }
    let reply = pool.api.post(&["v1", "ips", ip, "block"], &body).await?;
    Ok(json!({"route": "operator", "scope": reply["scope"],
        "reading": "scope target cooled the IP for that host; ip took it out of leasing for every target; pool_guard means escalation stopped because the cooled share of the partition was reached"}))
}

fn split_target(target: &str) -> (&str, u16) {
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host, port.parse().unwrap_or(443));
        }
        return (rest.trim_end_matches(']'), 443);
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse().unwrap_or(443)),
        _ => (target, 443),
    }
}

// --- the shared path -----------------------------------------------------------------------------------

fn preview(action: Action, p: &Prepared, status: &str, forced: bool) -> Value {
    json!({
        "status": status,
        "action": action.name(),
        "summary": p.summary,
        "diff": p.diff,
        "warnings": p.warnings,
        "would_call": p.would_call,
        "forced_by_server": forced,
    })
}

fn expiry(ctx: &Ctx) -> i64 {
    now_secs() + i64::try_from(ctx.cfg.safety.approval_ttl_secs).unwrap_or(86_400)
}

fn store_change(
    ctx: &Ctx,
    action: Action,
    p: &Prepared,
    info: &CallInfo,
) -> Result<Change, ToolError> {
    if p.inline_secret {
        return Err(invalid(
            "a change that waits for approval cannot carry an inline secret; use `credential_ref` so the secret is never stored",
        ));
    }
    let change = Change {
        id: new_change_id(),
        action: action.name().to_owned(),
        digest: change_digest(action.name(), &p.args),
        arguments: p.args.clone(),
        summary: p.summary.clone(),
        diff: p.diff.clone(),
        warnings: p.warnings.clone(),
        created_at: now_secs(),
        expires_at: expiry(ctx),
        requested_by: serde_json::to_value(&info.caller).unwrap_or(Value::Null),
        engagement: ctx.gate.engagement().map(str::to_owned),
    };
    ctx.store
        .create(&change)
        .map_err(|error| ToolError::internal(format!("cannot store the change: {error}")))?;
    Ok(change)
}

/// Audit the intent, run the mutation, and wrap the result.
async fn commit(
    ctx: &Ctx,
    action: Action,
    p: &Prepared,
    info: &CallInfo,
    change_id: Option<&str>,
) -> ToolResult {
    ctx.gate.admit_mutation()?;
    ctx.audit
        .record(&Entry {
            phase: Phase::Intent,
            caller: &info.caller,
            tool: action.name(),
            arguments: &p.args,
            outcome: "intent",
            detail: Some(&p.summary),
            change_id,
            duration_ms: None,
        })
        .map_err(|error| {
            ToolError::internal(format!(
                "the audit log cannot be written ({error}); refusing to change anything without a record"
            ))
        })?;
    let result = execute(ctx, action, p, info).await?;
    Ok(json!({
        "status": "applied",
        "action": action.name(),
        "change_id": change_id,
        "summary": p.summary,
        "result": result,
    }))
}

/// A mutating tool called directly.
pub async fn run_direct(ctx: &Ctx, action: Action, args: Args, info: &CallInfo) -> ToolResult {
    ctx.gate.check_applicable(action.capability(), None)?;
    let p = prepare(ctx, action, &args).await?;
    if let Some(org) = &p.org {
        ctx.gate.check_applicable(action.capability(), Some(org))?;
    }
    let forced = ctx.gate.force_dry_run();
    if args.dry_run() || forced {
        return Ok(preview(action, &p, "dry_run", forced && !args.dry_run()));
    }
    if ctx.gate.approval_required(action.name()) {
        let change = store_change(ctx, action, &p, info)?;
        let mut out = preview(action, &p, "pending_approval", false);
        out["change_id"] = json!(change.id);
        out["expires_at"] = json!(change.expires_at);
        out["approve_with"] = json!(format!("proxyx mcp approve {}", change.id));
        out["next"] = json!(format!(
            "An operator must approve this change. After approval call apply_config_change with change_id {}.",
            change.id
        ));
        return Ok(out);
    }
    commit(ctx, action, &p, info, None).await
}

pub async fn propose_config_change(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let name = args.require_str("action")?;
    let action = Action::from_name(name)
        .filter(|action| action.proposable())
        .ok_or_else(|| invalid(format!("{name:?} is not a configuration change")))?;
    if !ctx.gate.tool_allowed(name) {
        return Err(ToolError::new(
            FailKind::Refused,
            format!("tool `{name}` is disabled by this server's allow or deny list"),
        ));
    }
    let def = ctx
        .def(name)
        .ok_or_else(|| ToolError::internal("missing tool definition"))?;
    let mut arguments = args.get("arguments").cloned().unwrap_or(Value::Null);
    if let Some(map) = arguments.as_object_mut() {
        map.remove("dry_run");
    }
    let checked = schema::check(&def.input_schema, arguments).map_err(|issues| {
        invalid(format!(
            "invalid arguments for {name}: {}",
            issues.join("; ")
        ))
    })?;
    let p = prepare(ctx, action, &Args::from_value(checked)).await?;
    if let Some(org) = &p.org {
        ctx.gate.check_org(org)?;
    }
    let change = store_change(ctx, action, &p, info)?;
    let approval = ctx.gate.approval_required(name);
    Ok(json!({
        "status": "proposed",
        "change_id": change.id,
        "action": name,
        "summary": p.summary,
        "diff": p.diff,
        "warnings": p.warnings,
        "expires_at": change.expires_at,
        "approval_required": approval,
        "can_apply_here": ctx.gate.has(action.capability()),
        "next": if approval {
            format!("An operator approves with `proxyx mcp approve {}`; then call apply_config_change.", change.id)
        } else if ctx.gate.has(action.capability()) {
            format!("Review the diff, then call apply_config_change with change_id {}.", change.id)
        } else {
            format!("This server may not apply `{name}` (capability {} is not enabled); hand the change_id to an operator.", action.capability().as_str())
        },
    }))
}

pub async fn apply_config_change(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let id = args.require_str("change_id")?;
    let change = ctx
        .store
        .load(id)
        .map_err(|error| invalid(error.to_string()))?;
    let action = Action::from_name(&change.action)
        .ok_or_else(|| ToolError::internal("the change names an unknown action"))?;
    ctx.gate.check_applicable(action.capability(), None)?;
    match ctx.store.status(&change) {
        Status::Applied { .. } => return Err(invalid(format!("change {id} was already applied"))),
        Status::Rejected { by, .. } => {
            return Err(ToolError::new(
                FailKind::Refused,
                format!("change {id} was rejected by {by}"),
            ));
        }
        Status::Expired => return Err(invalid(format!("change {id} expired; propose it again"))),
        Status::Proposed if ctx.gate.approval_required(action.name()) => {
            return Err(ToolError::new(
                FailKind::Refused,
                format!("change {id} needs an operator's approval: run `proxyx mcp approve {id}`"),
            ));
        }
        Status::Proposed | Status::Approved { .. } => {}
    }
    // Validate again against the state as it is now: the diff shown at proposal time may be stale.
    let p = prepare(ctx, action, &Args::from_value(change.arguments.clone())).await?;
    if let Some(org) = &p.org {
        ctx.gate.check_applicable(action.capability(), Some(org))?;
    }
    let forced = ctx.gate.force_dry_run();
    if args.dry_run() || forced {
        let mut out = preview(action, &p, "dry_run", forced && !args.dry_run());
        out["change_id"] = json!(change.id);
        return Ok(out);
    }
    ctx.store
        .consume(&change)
        .map_err(|error| invalid(error.to_string()))?;
    commit(ctx, action, &p, info, Some(&change.id))
        .await
        .map_err(|mut error| {
            error.message = format!(
                "{} (change {id} is consumed: propose it again to retry)",
                error.message
            );
            error
        })
}

pub fn confirm_change(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let id = args.require_str("change_id")?;
    let token = args.require_str("token")?;
    let expected = ctx
        .confirm_token
        .as_deref()
        .ok_or_else(|| ToolError::not_configured("confirm_change is not enabled"))?;
    let given = sha256_hex(token);
    // Both are SHA-256 hex digests: compare in constant time over the whole length.
    let equal = given.len() == expected.len()
        && given
            .bytes()
            .zip(expected.bytes())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !equal {
        return Err(ToolError::new(
            FailKind::Refused,
            "the confirmation token is wrong",
        ));
    }
    let by = format!(
        "confirm-token:{}",
        info.caller
            .client_name
            .as_deref()
            .unwrap_or("unknown-client")
    );
    let change = ctx
        .store
        .approve(id, &by, None)
        .map_err(|error| invalid(error.to_string()))?;
    let status = ctx.store.status(&change);
    Ok(json!({"status": "approved", "change": change_view(&change, &status)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_round_trip_and_match_capabilities() {
        for action in Action::ALL {
            assert_eq!(Action::from_name(action.name()), Some(action));
        }
        assert_eq!(Action::PutPolicy.capability(), Capability::Policy);
        assert!(Action::PutPolicy.proposable());
        assert!(!Action::CreateOrgKey.proposable());
    }

    #[test]
    fn validators_match_the_gateway_rules() {
        assert!(valid_port_pair("proxy.example.net:3128").is_ok());
        assert!(valid_port_pair("[::1]:80").is_ok());
        assert!(valid_port_pair("nohost").is_err());
        assert!(valid_port_pair("h:0").is_err());
        assert!(valid_port_pair("h:99999").is_err());
        assert!(valid_port_pair("ho st:1").is_err());
        assert!(public_ip("203.0.113.5".parse().expect("ip")));
        for private in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(!public_ip(private.parse().expect("ip")), "{private}");
        }
        assert_eq!(ttl_seconds("30m"), Some(1800));
        assert_eq!(ttl_seconds("367d"), None);
        assert_eq!(ttl_seconds("0s"), None);
        assert_eq!(ttl_seconds("5x"), None);
        assert!(region_ok("fr") && region_ok("fr/paris") && !region_ok("FR") && !region_ok("fra"));
        assert_eq!(split_target("example.com:8443"), ("example.com", 8443));
        assert_eq!(split_target("example.com"), ("example.com", 443));
        assert_eq!(split_target("[::1]:80"), ("::1", 80));
    }
}
