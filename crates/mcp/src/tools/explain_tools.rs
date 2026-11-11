//! `explain_refusal`, `explain_selector` and `validate_policy`: answers computed with the
//! gateway's own grammar and policy crates. The first and last need no backend at all.

use policy::{InboundOptions, PolicySet, StickyKeySource};
use proxyx_client::sessions::ProxyErrorCause;
use serde_json::json;

use super::Ctx;
use super::policy_tools::{
    check_policy_scope, doc_json, doc_label, effective_summary, parse_input,
    scoped_stored_policies, validate_merged,
};
use super::util::{Args, ToolError, ToolResult};
use crate::explain::{self, CodeSource};

pub fn explain_refusal(args: &Args) -> ToolResult {
    let source = if let Some(code) = args.str("code") {
        let code = code.trim();
        common::Cause::from_code(code)
            .map(CodeSource::Gateway)
            .or_else(|| ProxyErrorCause::from_code(code).map(CodeSource::SessionProxy))
    } else if let Some(text) = args.str("text") {
        explain::find_code(text)
    } else {
        return Err(ToolError::invalid("give `code` or `text`"));
    };
    match source {
        Some(source) => Ok(explain::explain(source)),
        None => Err(
            ToolError::invalid("no known cause code found").with_detail(json!({
                "gateway_codes": explain::all_gateway_codes(),
                "session_proxy_codes": explain::all_proxy_codes(),
            })),
        ),
    }
}

pub async fn explain_selector(ctx: &Ctx, args: &Args) -> ToolResult {
    let username = args.require_str("username")?;
    if username.contains(':') {
        return Err(ToolError::invalid(
            "the username must not contain `:`; pass only the username part (never the org key)",
        ));
    }
    let mut out = explain::explain_username(username);
    let Ok(options) = InboundOptions::parse(username) else {
        return Ok(out);
    };
    if args.str("org").is_none() {
        return Ok(out);
    }
    let org = ctx.org(args)?;
    let Some(pool) = ctx.backends.pool.as_ref() else {
        out["policy_check"] = json!({"checked": false, "reason": "endpoints.pool is not configured, so the org's policy is unknown"});
        return Ok(out);
    };
    let listing = pool.api.get(&["v1", "policies"], &[]).await?;
    let stored = scoped_stored_policies(ctx, &listing).map_err(ToolError::internal)?;
    let set =
        PolicySet::from_docs(stored.into_iter().map(|s| s.doc).collect()).map_err(|error| {
            ToolError::internal(format!(
                "the stored policies do not form a valid set: {error}"
            ))
        })?;
    let org_id = org
        .parse::<common::types::OrgId>()
        .map_err(|error| ToolError::invalid(error.to_string()))?;
    let effective = set.effective(&org_id, None);
    match effective.narrow(&options) {
        Ok(request) => {
            out["policy_check"] = json!({
                "checked": true,
                "allowed": true,
                "lease_request": {
                    "kinds": request.kinds.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "providers": request.providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "regions": request.regions.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "ttl_secs": request.ttl.as_secs(),
                    "sticky": match &request.sticky {
                        StickyKeySource::Sid(sid) => json!({"sid": sid}),
                        StickyKeySource::Scope(scope) => json!({"scope": format!("{scope:?}").to_lowercase()}),
                    },
                    "rotation": format!("{:?}", request.rotation).to_lowercase(),
                },
            });
        }
        Err(cause) => {
            out["ok"] = json!(false);
            out["policy_check"] = json!({
                "checked": true,
                "allowed": false,
                "refusal": explain::explain(CodeSource::Gateway(cause)),
                "issues": explain::narrow_issues(&options, effective),
                "effective_policy": effective_summary(&set, Some(&org)),
            });
        }
    }
    Ok(out)
}

pub async fn validate_policy(ctx: &Ctx, args: &Args) -> ToolResult {
    let org = args.str("org").map(|_| ctx.org(args)).transpose()?;
    let docs = parse_input(args)?;
    check_policy_scope(ctx, &docs)?;
    let mut notes: Vec<String> = Vec::new();
    let stored = match ctx.backends.pool.as_ref() {
        Some(pool) => match pool.api.get(&["v1", "policies"], &[]).await {
            Ok(listing) => scoped_stored_policies(ctx, &listing).map_err(|error| {
                notes.push(format!("the stored policies were not usable: {error}"));
            }),
            Err(error) => {
                notes.push(format!("the stored policies could not be read ({error}); validated the documents on their own"));
                Err(())
            }
        },
        None => {
            notes.push("endpoints.pool is not configured: validated the documents on their own, without the stored policies".into());
            Err(())
        }
    };
    let merged_with_stored = stored.is_ok();
    let stored_list = stored.unwrap_or_default();
    let verdict = validate_merged(&stored_list, &docs);
    let (valid, error, effective) = match &verdict {
        Ok(set) => (true, None, Some(effective_summary(set, org.as_deref()))),
        Err(error) => (false, Some(error.clone()), None),
    };
    if !valid && !merged_with_stored {
        notes.push("a document that only fills fields (an org policy, a route-class policy) cannot be validated without the global policy it overlays; the strict parse above succeeded".into());
    }
    notes.push("the gateway additionally checks that a loaded provider adapter serves each region and fits each rotating provider's session life; only the gateway can do that".into());
    Ok(json!({
        "parsed": true,
        "valid": valid,
        "merged_with_stored_policies": merged_with_stored,
        "error": error,
        "documents": docs.iter().map(|doc| json!({"label": doc_label(doc), "document": doc_json(doc)})).collect::<Vec<_>>(),
        "effective_preview": effective,
        "notes": notes,
    }))
}
