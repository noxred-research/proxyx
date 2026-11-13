//! The AI-assisted tools: `summarize_traffic`, `classify_block_page` and `suggest_policy`.
//!
//! Each works without an LLM where that makes sense (statistics, rules) and calls the
//! configured model only when asked to and only for the part a model adds. A model never
//! applies anything: its answer is parsed against a strict schema, validated with the
//! gateway's own crates, and returned as a draft or a suggestion. Every model call shares one
//! absolute deadline, one total prompt budget and one audit record of its sizes and timing.

use std::collections::BTreeMap;

use policy::PolicyFile;
use serde_json::{Value, json};

use super::policy_tools::{
    check_policy_scope, doc_json, effective_summary, scoped_stored_policies, validate_merged,
};
use super::traffic::{clean_capture, validate_branches};
use super::util::{Args, FailKind, ToolError, ToolResult};
use super::{CallInfo, Ctx};
use crate::analysis::blocks::{self, Classification, Input};
use crate::analysis::{self, Evidence, Side};
use crate::audit::Phase;
use crate::llm::{Llm, LlmError, PromptBudget, Request, SYSTEM_RULES};
use crate::redact::{redact_body, redact_headers, redact_prompt_value};

fn llm_error(error: LlmError) -> ToolError {
    ToolError::new(FailKind::Llm, error.to_string())
}

fn need_llm(ctx: &Ctx) -> Result<&Llm, ToolError> {
    ctx.llm.as_ref().ok_or_else(|| {
        ToolError::not_configured("no LLM is configured ([llm] in the server configuration)")
    })
}

/// One model call with the shared contract: the configured timeout as an absolute deadline over
/// every attempt, and an audit record of the call's sizes and timing (never its content).
async fn ask(
    ctx: &Ctx,
    info: &CallInfo,
    tool: &str,
    schema_name: &str,
    prompt_version: &str,
    user: &str,
    schema: &Value,
) -> Result<Value, ToolError> {
    let llm = need_llm(ctx)?;
    if ctx.cfg.analysis.enabled {
        if !ctx.cfg.analysis.allow_external_llm {
            return Err(ToolError::new(
                FailKind::Refused,
                "sending content to the model is not allowed: with [analysis] enabled an operator must set analysis.allow_external_llm",
            ));
        }
        ctx.gate.check_engagement()?;
    }
    // like a mutation, a disclosure is recorded before it happens
    if !analysis::audit(
        ctx,
        info,
        Phase::Model,
        tool,
        "intent",
        &json!({
            "endpoint_alias": llm.alias(),
            "model": llm.model(),
            "prompt_version": prompt_version,
            "schema": schema_name,
            "evidence_ids": [],
        }),
    ) {
        return Err(ToolError::new(
            FailKind::Refused,
            "the audit log could not be written: nothing was sent to the model",
        ));
    }
    let (result, stats) = llm
        .complete_json(&Request {
            name: schema_name,
            system: SYSTEM_RULES,
            user,
            schema,
            deadline: None,
        })
        .await;
    analysis::audit(
        ctx,
        info,
        Phase::Model,
        tool,
        if result.is_ok() { "ok" } else { "error" },
        &json!({
            "endpoint_alias": llm.alias(),
            "model": llm.model(),
            "prompt_version": prompt_version,
            "schema": schema_name,
            "input_bytes": stats.input_bytes,
            "output_bytes": stats.output_bytes,
            "duration_ms": stats.duration_ms,
            "attempts": stats.attempts,
            "evidence_ids": [],
        }),
    );
    result.map_err(llm_error)
}

// --- summarize_traffic ------------------------------------------------------------------------------

fn top(counts: BTreeMap<String, u64>, n: usize) -> Vec<Value> {
    let mut rows: Vec<(String, u64)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.into_iter()
        .take(n)
        .map(|(name, count)| json!({"value": name, "count": count}))
        .collect()
}

/// Statistics over capture summaries. No bodies, no LLM.
pub fn traffic_stats(items: &[Value]) -> Value {
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut codes: BTreeMap<String, u64> = BTreeMap::new();
    let mut block_hosts: BTreeMap<String, u64> = BTreeMap::new();
    let (mut errors, mut rate_limited, mut maybe_blocks) = (0_u64, 0_u64, 0_u64);
    let mut durations: Vec<u64> = Vec::new();
    let mut sized: Vec<(u64, String)> = Vec::new();
    let mut slow: Vec<(u64, String)> = Vec::new();
    for item in items {
        let host = item["host"].as_str().unwrap_or("?").to_owned();
        let status = item["status_code"].as_u64().unwrap_or(0);
        *hosts.entry(host.clone()).or_insert(0) += 1;
        *methods
            .entry(item["method"].as_str().unwrap_or("?").to_owned())
            .or_insert(0) += 1;
        *classes
            .entry(if status == 0 {
                "none".to_owned()
            } else {
                format!("{}xx", status / 100)
            })
            .or_insert(0) += 1;
        *codes.entry(status.to_string()).or_insert(0) += 1;
        if status == 0 || status >= 400 {
            errors += 1;
        }
        if status == 429 {
            rate_limited += 1;
        }
        if matches!(status, 403 | 429 | 503) {
            maybe_blocks += 1;
            *block_hosts.entry(host.clone()).or_insert(0) += 1;
        }
        let path = format!("{host}{}", item["path"].as_str().unwrap_or(""));
        if let Some(duration) = item["duration_ms"].as_u64() {
            durations.push(duration);
            slow.push((duration, path.clone()));
        }
        if let Some(size) = item["response_size"].as_u64() {
            sized.push((size, path));
        }
    }
    durations.sort_unstable();
    let percentile = |p: f64| -> Option<u64> {
        (!durations.is_empty())
            .then(|| durations[((durations.len() as f64 - 1.0) * p).round() as usize])
    };
    slow.sort_by_key(|row| std::cmp::Reverse(row.0));
    sized.sort_by_key(|row| std::cmp::Reverse(row.0));
    let n = items.len() as u64;
    let share = |count: u64| {
        if n == 0 {
            0.0
        } else {
            (count as f64 / n as f64 * 1000.0).round() / 10.0
        }
    };
    json!({
        "captures_analysed": n,
        "hosts": top(hosts, 10),
        "methods": top(methods, 5),
        "status_classes": top(classes, 6),
        "status_codes": top(codes, 8),
        "error_share_percent": share(errors),
        "rate_limited_share_percent": share(rate_limited),
        "block_suspect_statuses_share_percent": share(maybe_blocks),
        "block_suspect_hosts": top(block_hosts, 5),
        "duration_ms": {"median": percentile(0.5), "p95": percentile(0.95), "max": durations.last()},
        "slowest": slow.iter().take(5).map(|(ms, path)| json!({"path": path, "duration_ms": ms})).collect::<Vec<_>>(),
        "largest_responses": sized.iter().take(5).map(|(size, path)| json!({"path": path, "bytes": size})).collect::<Vec<_>>(),
    })
}

pub async fn summarize_traffic(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let control = ctx.control()?;
    let mut branches = args.get("branches").cloned().unwrap_or(Value::Null);
    validate_branches(&branches, false)?;
    // what goes to a model stays inside an analysis scope once analysis is enabled
    let scope = if ctx.cfg.analysis.enabled && args.bool("use_llm").unwrap_or(false) {
        let Some(scope_id) = args.str("scope_id") else {
            return Err(ToolError::invalid(
                "capture analysis is enabled: give `scope_id` (from open_analysis_scope) to summarize with a model",
            ));
        };
        let scope = analysis::resolve_scope(ctx, scope_id)?;
        analysis::scope_org(&scope, args.str("org"))?;
        branches = scope.constrain(&branches, false, ctx.cfg.analysis.query.max_branches)?;
        Some(scope)
    } else {
        None
    };
    let org = match &scope {
        Some(scope) => scope.org.clone(),
        None => ctx.org(args)?,
    };
    // without a model the statistics stay inside the operator's ceiling instead
    let scope = match scope {
        Some(scope) => Some(scope),
        None => {
            let ceiling = analysis::ceiling(ctx, &org)?;
            if let Some(ceiling) = &ceiling {
                branches =
                    ceiling.constrain(&branches, false, ctx.cfg.analysis.query.max_branches)?;
            }
            ceiling
        }
    };
    let sample = args.u64("sample").unwrap_or(500).clamp(1, 5000);
    let body = json!({"org_id": org, "branches": branches, "limit": sample, "order": "desc"});
    let reply = control
        .api
        .post(&["rpc", "requests", "search"], &body)
        .await?;
    let mut items: Vec<Value> = reply["items"].as_array().cloned().unwrap_or_default();
    if let Some(scope) = &scope {
        items.retain(|item| scope.admits(item));
    }
    items.iter_mut().for_each(redact_prompt_value);
    let stats = traffic_stats(&items);
    let mut out = json!({
        "statistics": stats,
        "sampled": items.len(),
        "more_available": reply["next_cursor"].is_string(),
        "narrative": null,
        "untrusted_content": true,
    });
    if args.bool("use_llm").unwrap_or(false) {
        let llm = need_llm(ctx)?;
        let schema = json!({
            "type": "object",
            "properties": {
                "narrative": {"type": "string", "maxLength": 1500},
                "notable": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 6},
                "suggested_next_tools": {"type": "array", "items": {"type": "string", "enum": [
                    "search_traffic", "get_capture", "classify_block_page", "recent_refusals",
                    "block_signal_rates", "pool_capacity", "explain_refusal"
                ]}, "maxItems": 4}
            },
            "required": ["narrative", "notable", "suggested_next_tools"],
            "additionalProperties": false
        });
        let mut budget = PromptBudget::new(llm.max_input_chars);
        let user = format!(
            "Summarize what these traffic statistics show for a security researcher: what the traffic is, whether targets are blocking or rate limiting, and what to look at next.\n{}",
            budget.untrusted(
                "traffic_statistics",
                &stats.to_string(),
                llm.max_input_chars
            )
        );
        let answer = ask(
            ctx,
            info,
            "summarize_traffic",
            "traffic_summary",
            "traffic-summary-1",
            &user,
            &schema,
        )
        .await?;
        out["narrative"] = answer;
    }
    Ok(out)
}

// --- classify_block_page -----------------------------------------------------------------------------

/// One response to classify.
struct Observation {
    capture_id: Option<String>,
    status: u64,
    headers: Vec<(String, String)>,
    body: String,
    host: Option<String>,
}

const SEVERITY: [&str; 4] = ["challenge", "rate_limited", "forbidden", "none"];

fn severity_rank(class: &str) -> usize {
    SEVERITY
        .iter()
        .position(|c| *c == class)
        .unwrap_or(SEVERITY.len())
}

/// Whether the rules' verdict is weak enough for a model to be worth asking.
fn needs_model(verdict: &Classification) -> bool {
    verdict.abstained || (verdict.classification != "none" && verdict.strength < 0.9)
}

fn evidence_refs(
    ctx: &Ctx,
    org: &str,
    observation: &Observation,
    verdict: &Classification,
) -> Vec<Value> {
    let fp = ctx
        .analysis
        .fingerprinter(org, ctx.cfg.scope.engagement.as_deref());
    let mut evidence = Evidence::default();
    let capture = observation.capture_id.as_deref().unwrap_or("pasted");
    for signal in &verdict.signals {
        evidence.add(
            &fp,
            capture,
            Side::Response,
            &signal.location,
            &signal.detail,
        );
    }
    evidence.to_json()["refs"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

pub async fn classify_block_page(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let analysis_on = ctx.cfg.analysis.enabled;
    let mut ids: Vec<String> = args
        .get("capture_ids")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if let Some(id) = args.str("capture_id") {
        ids.insert(0, id.to_owned());
    }
    let mut unique = std::collections::BTreeSet::new();
    ids.retain(|id| unique.insert(id.clone()));
    let mut org = None;
    let mut observations: Vec<Observation> = Vec::new();
    if ids.is_empty() {
        let Some(status) = args.u64("status") else {
            return Err(ToolError::invalid(
                "give `capture_id` (or `capture_ids`), or `status` with optional `headers` and `body`",
            ));
        };
        let mut headers = args.get("headers").cloned().unwrap_or(Value::Null);
        redact_headers(&mut headers);
        observations.push(Observation {
            capture_id: None,
            status,
            headers: analysis::headers_of(&headers),
            body: redact_body(args.str("body").unwrap_or("")),
            host: args.string("host"),
        });
    } else {
        let control = ctx.control()?;
        let scope = if analysis_on {
            let Some(scope_id) = args.str("scope_id") else {
                return Err(ToolError::invalid(
                    "capture analysis is enabled: give `scope_id` (from open_analysis_scope) with capture ids",
                ));
            };
            Some(analysis::resolve_scope(ctx, scope_id)?)
        } else {
            None
        };
        let org_name = match &scope {
            Some(scope) => {
                analysis::scope_org(scope, args.str("org"))?;
                scope.org.clone()
            }
            None => ctx.org(args)?,
        };
        for id in &ids {
            let capture = control
                .api
                .get(&["rpc", "orgs", &org_name, "requests", id], &[])
                .await?;
            if let Some(scope) = &scope
                && !scope.admits(&capture)
            {
                return Err(ToolError::new(
                    FailKind::Refused,
                    "a capture is outside the analysis scope (source or origin)",
                ));
            }
            let cleaned = clean_capture(&capture, 16 * 1024);
            observations.push(Observation {
                capture_id: Some(id.clone()),
                status: capture["status_code"].as_u64().unwrap_or(0),
                headers: analysis::headers_of(&cleaned["response_headers"]),
                body: cleaned["response_body"]["text"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                host: capture["host"].as_str().map(str::to_owned),
            });
        }
        org = Some(org_name);
    }
    let rule_verdicts: Vec<Classification> = observations
        .iter()
        .map(|o| {
            blocks::classify(&Input {
                status: o.status,
                headers: &o.headers,
                body: &o.body,
            })
        })
        .collect();
    // the class most observations agree on; ties go to the more severe class
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for verdict in &rule_verdicts {
        if !verdict.abstained {
            *tally.entry(verdict.classification).or_insert(0) += 1;
        }
    }
    let chosen = tally
        .iter()
        .filter(|(class, _)| **class != "none")
        .max_by(|a, b| {
            a.1.cmp(b.1)
                .then(severity_rank(b.0).cmp(&severity_rank(a.0)))
        })
        .map_or("none", |(class, _)| *class);
    let primary_index = rule_verdicts
        .iter()
        .enumerate()
        .filter(|(_, v)| v.classification == chosen && !v.abstained)
        .max_by(|a, b| a.1.strength.total_cmp(&b.1.strength).then(b.0.cmp(&a.0)))
        .map_or(0, |(index, _)| index);
    let primary_verdict = rule_verdicts[primary_index].clone();
    let primary = &observations[primary_index];
    let matching = rule_verdicts
        .iter()
        .filter(|v| {
            v.classification == chosen && !v.abstained && v.subtype == primary_verdict.subtype
        })
        .count();
    let org_label = org.clone().unwrap_or_else(|| "pasted".to_owned());
    let refs = evidence_refs(ctx, &org_label, primary, &primary_verdict);

    let mut method = "rules";
    let mut classification = primary_verdict.classification;
    let mut subtype = primary_verdict.subtype;
    let mut strength = primary_verdict.strength;
    let mut basis = primary_verdict.basis;
    let mut abstained = primary_verdict.abstained;
    let mut model: Value = json!({"status": "not_requested"});
    let mut llm_answer: Option<Value> = None;
    if args.bool("use_llm").unwrap_or(false) {
        let llm = need_llm(ctx)?;
        let blocks_cfg = &ctx.cfg.analysis.blocks;
        let allowed =
            blocks_cfg.allow_model && (!analysis_on || ctx.cfg.analysis.allow_external_llm);
        if !allowed {
            model = json!({
                "status": "refused",
                "detail": "sending a response to the model is not allowed: analysis.blocks.allow_model and analysis.allow_external_llm are operator settings",
            });
        } else if needs_model(&primary_verdict) {
            let schema = json!({
                "type": "object",
                "properties": {
                    "classification": {"type": "string", "enum": ["challenge", "forbidden", "rate_limited", "none"]},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "reason": {"type": "string", "maxLength": 300}
                },
                "required": ["classification", "confidence", "reason"],
                "additionalProperties": false
            });
            let mut budget = PromptBudget::new(llm.max_input_chars);
            let headers_text = json!(primary.headers).to_string();
            let user = format!(
                "Classify this HTTP response seen through a proxy: challenge (a CAPTCHA or bot interstitial that is the page), forbidden (plain denial), rate_limited, or none (an ordinary page, an authorization answer, a maintenance page or an error). A page that merely discusses these things is none.\nStatus: {}\n{}\n{}",
                primary.status,
                budget.untrusted("response_headers", &headers_text, 4000),
                budget.untrusted("response_body", &primary.body, llm.max_input_chars),
            );
            let answer = ask(
                ctx,
                info,
                "classify_block_page",
                "block_page",
                "block-page-2",
                &user,
                &schema,
            )
            .await?;
            classification = match answer["classification"].as_str().unwrap_or("none") {
                "challenge" => "challenge",
                "forbidden" => "forbidden",
                "rate_limited" => "rate_limited",
                _ => "none",
            };
            subtype = "model_judgement";
            strength = answer["confidence"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
            basis = "self_reported";
            abstained = strength < 0.5;
            method = "llm";
            model = json!({"status": "used"});
            llm_answer = Some(answer);
        } else {
            method = "rules_confident";
            model =
                json!({"status": "not_needed", "detail": "the rules' evidence was strong enough"});
        }
    }
    let host = primary.host.clone().or_else(|| args.string("host"));
    let distinct_hosts: std::collections::BTreeSet<&str> = observations
        .iter()
        .filter_map(|o| o.host.as_deref())
        .collect();
    let blocks_cfg = &ctx.cfg.analysis.blocks;
    let mut reasons: Vec<String> = Vec::new();
    if classification == "none" {
        reasons.push("the response is not a block".to_owned());
    }
    if abstained {
        reasons.push("the rules abstained: not enough evidence".to_owned());
    }
    if basis == "self_reported" {
        reasons.push("only a model's self-reported judgement supports this: a model's answer never makes a classification reportable".to_owned());
    }
    if method != "llm" && matching < blocks_cfg.min_observations {
        reasons.push(format!(
            "{matching} equivalent observation(s); analysis.blocks.min_observations is {}. Classify more captures of this target first.",
            blocks_cfg.min_observations
        ));
    }
    if distinct_hosts.len() > 1 {
        reasons.push("the observations come from more than one target host".to_owned());
    }
    if let Some(minimum) = blocks_cfg.min_calibrated_precision {
        match blocks::measured_precision(subtype) {
            Some(precision) if precision >= minimum => {}
            _ => reasons.push(format!(
                "no measured precision of at least {minimum} exists for subtype {subtype}"
            )),
        }
    }
    let reportable = reasons.is_empty();
    let mut missing: Vec<&str> = Vec::new();
    if args.str("exit_ip").is_none() {
        missing.push("exit_ip");
    }
    if host.is_none() {
        missing.push("target");
    }
    let signal = (classification != "none").then(|| {
        json!({
            "type": classification,
            "target": host,
            "exit_ip": args.str("exit_ip"),
            "session": args.str("session"),
        })
    });
    let mut reporting_args = json!({"type": classification, "target": host});
    if let Some(ip) = args.str("exit_ip") {
        reporting_args["exit_ip"] = json!(ip);
    }
    if let Some(session) = args.str("session") {
        reporting_args["session"] = json!(session);
    }
    let requires_approval = ctx.gate.approval_required("report_block_signal");
    Ok(json!({
        "classification": classification,
        "subtype": subtype,
        "confidence": strength,
        "confidence_kind": basis,
        "confidence_scale": if basis == "self_reported" { "the model's own number: not calibrated" } else { "ordinal rule strength, not a probability" },
        "abstained": abstained,
        "detector_version": blocks::DETECTOR_VERSION,
        "fixture_version": blocks_cfg.fixture_version,
        "method": method,
        "http_status": primary.status,
        "evidence": primary_verdict.signals.iter().map(|s| format!("{}: {}", s.location, s.detail)).collect::<Vec<_>>(),
        "evidence_refs": refs,
        "recommendation": primary_verdict.recommendation,
        "rule_assessment": blocks::describe(&primary_verdict),
        "model": model,
        "llm_answer": llm_answer,
        "observations": {
            "total": observations.len(),
            "matching": matching,
            "hosts": distinct_hosts,
            "classes": tally,
        },
        "per_observation": rule_verdicts.iter().zip(&observations).map(|(v, o)| json!({
            "capture_id": o.capture_id, "classification": v.classification, "subtype": v.subtype, "abstained": v.abstained,
        })).collect::<Vec<_>>(),
        "suggested_signal": signal,
        "reporting": {
            "reportable": reportable,
            "why_not": reasons,
            "tool": "report_block_signal",
            "arguments": reporting_args,
            "missing": missing,
            "requires_approval": requires_approval,
            "note": "Classification never writes. Reporting is a separate call that needs the `signals` capability and, when required, an operator's approval. A wrong report cools a healthy IP for that target.",
        },
        "untrusted_content": true,
    }))
}

// --- suggest_policy ---------------------------------------------------------------------------------

/// The policy format, as given to the model.
const POLICY_REFERENCE: &str = r#"A policy file is a list of [[policy]] tables. Unknown fields are errors. Durations are integers (seconds) or strings like "30s", "5m", "2h", "1d" (at most 366d).
Fields: name (required, unique), scope = "global" | "route_class" | "org", match (provider id for route_class, org id for org; absent for global),
kinds = ["static","rotating"], providers = [provider ids], regions = ["fr","fr/paris"], min_ready, max_ready, low_watermark, low_for,
lease_ttl, lease_wait, create_deadline, orgs_hard, max_conns_per_ip, rest_after_release, max_tunnels_per_org, sticky_scope = "org"|"target"|"connection",
on_score_unavailable = "allow"|"deny", [policy.on_empty] static = "wait"|"fail", rotating = "create"|"wait"|"fail",
[policy.criteria] max_risk, max_ttfb_ms, max_load_ms, min_success, browser_sample, verdict_max_age,
[policy.block] target_cooldown, escalate_targets, escalate_signals, signal_window, max_cooldown_share,
[policy.static] cooldown, quarantine_after, retest_every, recheck_every, replace_after_checks, replace_min_sources, replace_blocked_share, replace_quarantine_for,
[policy.rotating] ready_ttl, max_age, min_remaining, refill_concurrency, refill_rate, headroom, headroom_auto, keepalive, recheck_every,
[policy.cost] max_gb_per_day, max_creates_per_hour, fair_use_gb_per_ip_month, [policy.limits] max_gb_per_day, max_creates_per_hour, fair_use_gb_per_ip_month, org_max_gb_per_day.
Precedence global < route_class < org, field by field; limits are ceilings that only tighten. Change as little as possible and set only the fields the request needs."#;

pub async fn suggest_policy(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let llm = need_llm(ctx)?;
    let request = args.require_str("request")?;
    let org = match args.str("org") {
        Some(_) => Some(ctx.org(args)?),
        None => None,
    };
    let scope = args
        .str("scope")
        .unwrap_or(if org.is_some() { "org" } else { "global" });
    if scope == "org" && org.is_none() {
        return Err(ToolError::invalid("scope org needs `org`"));
    }
    // current state, for context and validation
    let stored = match ctx.backends.pool.as_ref() {
        Some(pool) => pool
            .api
            .get(&["v1", "policies"], &[])
            .await
            .ok()
            .and_then(|body| scoped_stored_policies(ctx, &body).ok()),
        None => None,
    };
    let current = stored
        .as_ref()
        .map(|list| {
            list.iter()
                .filter(|s| {
                    s.scope == "global"
                        || org
                            .as_deref()
                            .is_some_and(|org| s.doc.target.as_deref() == Some(org))
                })
                .map(|s| s.raw.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let schema = json!({
        "type": "object",
        "properties": {
            "toml": {"type": "string", "minLength": 1, "maxLength": 8000},
            "rationale": {"type": "string", "maxLength": 600},
            "assumptions": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 5}
        },
        "required": ["toml", "rationale", "assumptions"],
        "additionalProperties": false
    });
    // the request and the format come first: the stored policies take what is left of the budget
    let mut budget = PromptBudget::new(llm.max_input_chars);
    let request_block = budget.untrusted("request", request, 2000);
    let scope_block = budget.untrusted(
        "requested_scope",
        &json!({"scope": scope, "org": org}).to_string(),
        2000,
    );
    let format_block = budget.untrusted("policy_format", POLICY_REFERENCE, 6000);
    let current_block = budget.untrusted(
        "current_policies",
        &Value::Array(current).to_string(),
        llm.max_input_chars,
    );
    let user = format!(
        "Write the smallest policy change that satisfies the request.\n{scope_block}\n{format_block}\n{current_block}\n{request_block}"
    );
    let answer = ask(
        ctx,
        info,
        "suggest_policy",
        "policy_draft",
        "policy-draft-1",
        &user,
        &schema,
    )
    .await?;
    let draft = answer["toml"].as_str().unwrap_or("");
    let file = PolicyFile::parse(draft).map_err(|error| {
        ToolError::new(
            FailKind::Llm,
            format!("the model's draft does not parse as a policy file: {error}"),
        )
        .with_detail(json!({"draft": draft}))
    })?;
    if file.policies.is_empty() {
        return Err(ToolError::new(
            FailKind::Llm,
            "the model's draft contains no policy",
        ));
    }
    check_policy_scope(ctx, &file.policies)?;
    let verdict = validate_merged(stored.as_deref().unwrap_or(&[]), &file.policies);
    let (valid, error, effective) = match &verdict {
        Ok(set) => (true, None, Some(effective_summary(set, org.as_deref()))),
        Err(error) => (false, Some(error.clone()), None),
    };
    Ok(json!({
        "draft_toml": draft,
        "documents": file.policies.iter().map(doc_json).collect::<Vec<_>>(),
        "valid": valid,
        "validation_error": error,
        "merged_with_stored_policies": stored.is_some(),
        "effective_preview": effective,
        "rationale": answer["rationale"],
        "assumptions": answer["assumptions"],
        "applied": false,
        "next": "Review it, then propose_config_change with action put_policy (or put_org_policy) and {\"toml\": <draft_toml>} to see the diff and have it approved. The model only drafted; nothing was written.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics_count_blocks_and_errors() {
        let items: Vec<Value> = [
            ("a.example", "GET", 200, 10, 100),
            ("a.example", "GET", 429, 20, 10),
            ("b.example", "POST", 403, 300, 10),
            ("b.example", "GET", 500, 5, 10),
        ]
        .into_iter()
        .map(|(host, method, status, duration, size)| {
            json!({"host": host, "method": method, "status_code": status, "duration_ms": duration, "response_size": size, "path": "/x"})
        })
        .collect();
        let stats = traffic_stats(&items);
        assert_eq!(stats["captures_analysed"], 4);
        assert_eq!(stats["error_share_percent"], 75.0);
        assert_eq!(stats["rate_limited_share_percent"], 25.0);
        assert_eq!(stats["block_suspect_hosts"][0]["count"], 1);
        assert_eq!(stats["duration_ms"]["max"], 300);
        assert_eq!(stats["hosts"][0]["count"], 2);
    }
}
