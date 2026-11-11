//! The AI-assisted tools: `summarize_traffic`, `classify_block_page` and `suggest_policy`.
//!
//! Each works without an LLM where that makes sense (statistics, rules) and calls the
//! configured model only when asked to and only for the part a model adds. A model never
//! applies anything: its answer is parsed against a strict schema, validated with the
//! gateway's own crates, and returned as a draft or a suggestion.

use std::collections::BTreeMap;

use policy::PolicyFile;
use serde_json::{Value, json};

use super::manage::Action;
use super::policy_tools::{
    check_policy_scope, doc_json, effective_summary, scoped_stored_policies, validate_merged,
};
use super::traffic::{clean_capture, validate_branches};
use super::util::{Args, FailKind, ToolError, ToolResult};
use super::{CallInfo, Ctx};
use crate::llm::{Llm, LlmError, SYSTEM_RULES, untrusted};
use crate::redact::{redact_body, redact_headers, redact_prompt_value};

fn llm_error(error: LlmError) -> ToolError {
    ToolError::new(FailKind::Llm, error.to_string())
}

fn need_llm(ctx: &Ctx) -> Result<&Llm, ToolError> {
    ctx.llm.as_ref().ok_or_else(|| {
        ToolError::not_configured("no LLM is configured ([llm] in the server configuration)")
    })
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

pub async fn summarize_traffic(ctx: &Ctx, args: &Args) -> ToolResult {
    let control = ctx.control()?;
    let branches = args.get("branches").cloned().unwrap_or(Value::Null);
    validate_branches(&branches, false)?;
    let org = ctx.org(args)?;
    let sample = args.u64("sample").unwrap_or(500).clamp(1, 5000);
    let body = json!({"org_id": org, "branches": branches, "limit": sample, "order": "desc"});
    let reply = control
        .api
        .post(&["rpc", "requests", "search"], &body)
        .await?;
    let mut items: Vec<Value> = reply["items"].as_array().cloned().unwrap_or_default();
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
        let user = format!(
            "Summarize what these traffic statistics show for a security researcher: what the traffic is, whether targets are blocking or rate limiting, and what to look at next.\n{}",
            untrusted(
                "traffic_statistics",
                &stats.to_string(),
                llm.max_input_chars
            )
        );
        let answer = llm
            .complete_json("traffic_summary", SYSTEM_RULES, &user, &schema)
            .await
            .map_err(llm_error)?;
        out["narrative"] = answer;
    }
    Ok(out)
}

// --- classify_block_page -----------------------------------------------------------------------------

const CHALLENGE_MARKERS: [&str; 15] = [
    "cf-chl", // detection-data
    "challenge-platform",
    "just a moment",
    "attention required",
    "captcha",
    "recaptcha",  // detection-data
    "hcaptcha",   // detection-data
    "px-captcha", // detection-data
    "datadome",   // detection-data
    "/sorry/",
    "unusual traffic",
    "verify you are human",
    "are you a robot",
    "request unsuccessful. incapsula", // detection-data
    "access denied - sucuri",          // detection-data
];

/// A rule-based classification of a response.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// `challenge`, `forbidden`, `rate_limited` or `none`.
    pub classification: &'static str,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Classify by status, headers and the start of the body. Conservative: a lone 403 is only
/// `forbidden` at moderate confidence, and a 200 with a challenge marker is a possible
/// challenge.
pub fn classify_rules(status: u64, headers: &Value, body: &str) -> Verdict {
    let lower = body.to_lowercase();
    let mut evidence = Vec::new();
    let header_text: String = match headers {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Array(pairs) => pairs
            .iter()
            .map(|p| {
                format!(
                    "{}: {}",
                    p[0].as_str().unwrap_or(""),
                    p[1].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
    .to_lowercase();
    let markers: Vec<&str> = CHALLENGE_MARKERS
        .iter()
        .copied()
        .filter(|marker| lower.contains(marker) || header_text.contains(marker))
        .collect();
    // detection-data: the challenge header of a CDN
    let challenge_header = header_text.contains("cf-mitigated: challenge");
    let sorry_redirect = (300..400).contains(&status) && header_text.contains("/sorry/");
    if status == 429 {
        evidence.push("HTTP 429".to_owned());
        if !markers.is_empty() {
            evidence.push(format!("markers: {markers:?}"));
        }
        return Verdict {
            classification: "rate_limited",
            confidence: 0.95,
            evidence,
        };
    }
    if challenge_header || sorry_redirect || (!markers.is_empty() && matches!(status, 403 | 503)) {
        evidence.push(format!("HTTP {status}"));
        if challenge_header {
            // detection-data: the challenge header of a CDN
            evidence.push("cf-mitigated: challenge header".to_owned());
        }
        if sorry_redirect {
            evidence.push("redirect to /sorry/".to_owned());
        }
        if !markers.is_empty() {
            evidence.push(format!("markers: {markers:?}"));
        }
        return Verdict {
            classification: "challenge",
            confidence: 0.9,
            evidence,
        };
    }
    if !markers.is_empty() && (200..300).contains(&status) {
        return Verdict {
            classification: "challenge",
            confidence: 0.55,
            evidence: vec![format!(
                "HTTP {status} but the page carries challenge markers: {markers:?}"
            )],
        };
    }
    if status == 403 {
        return Verdict {
            classification: "forbidden",
            confidence: 0.6,
            evidence: vec!["HTTP 403 without a challenge marker; one 403 can be an ordinary authorization answer, repeated ones from one exit IP are a block".to_owned()],
        };
    }
    Verdict {
        classification: "none",
        confidence: 0.7,
        evidence: vec![format!("HTTP {status} with no block marker")],
    }
}

pub async fn classify_block_page(ctx: &Ctx, args: &Args, info: &CallInfo) -> ToolResult {
    let (status, headers, body, host) = if let Some(id) = args.str("capture_id") {
        let control = ctx.control()?;
        let org = ctx.org(args)?;
        let mut capture = control
            .api
            .get(&["rpc", "orgs", &org, "requests", id], &[])
            .await?;
        redact_prompt_value(&mut capture);
        let cleaned = clean_capture(&capture, 16 * 1024);
        (
            capture["status_code"].as_u64().unwrap_or(0),
            cleaned["response_headers"].clone(),
            cleaned["response_body"]["text"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            capture["host"].as_str().map(str::to_owned),
        )
    } else {
        let Some(status) = args.u64("status") else {
            return Err(ToolError::invalid(
                "give `capture_id`, or `status` with optional `headers` and `body`",
            ));
        };
        let mut headers = args.get("headers").cloned().unwrap_or(Value::Null);
        redact_headers(&mut headers);
        (
            status,
            headers,
            redact_body(args.str("body").unwrap_or("")),
            args.string("host"),
        )
    };
    let mut verdict = classify_rules(status, &headers, &body);
    let mut method = "rules";
    let mut llm_answer: Option<Value> = None;
    let ambiguous =
        verdict.confidence < 0.9 && (!body.is_empty() || verdict.classification != "none");
    if args.bool("use_llm").unwrap_or(false) {
        let llm = need_llm(ctx)?;
        if ambiguous {
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
            let user = format!(
                "Classify this HTTP response seen through a proxy: challenge (captcha or bot interstitial), forbidden (plain denial), rate_limited, or none (an ordinary page or error).\nStatus: {status}\n{}\n{}",
                untrusted("response_headers", &headers.to_string(), 4000),
                untrusted("response_body", &body, llm.max_input_chars),
            );
            let answer = llm
                .complete_json("block_page", SYSTEM_RULES, &user, &schema)
                .await
                .map_err(llm_error)?;
            let label = answer["classification"].as_str().unwrap_or("none");
            let classification = match label {
                "challenge" => "challenge",
                "forbidden" => "forbidden",
                "rate_limited" => "rate_limited",
                _ => "none",
            };
            verdict = Verdict {
                classification,
                confidence: answer["confidence"].as_f64().unwrap_or(0.0),
                evidence: verdict
                    .evidence
                    .into_iter()
                    .chain([format!(
                        "model: {}",
                        answer["reason"].as_str().unwrap_or("")
                    )])
                    .collect(),
            };
            method = "llm";
            llm_answer = Some(answer);
        } else {
            method = "rules_confident";
        }
    }
    let signal = (verdict.classification != "none").then(|| {
        json!({
            "type": verdict.classification,
            "target": host.clone().or_else(|| args.string("host")),
            "exit_ip": args.str("exit_ip"),
            "session": args.str("session"),
        })
    });
    let mut out = json!({
        "classification": verdict.classification,
        "confidence": verdict.confidence,
        "method": method,
        "evidence": verdict.evidence,
        "http_status": status,
        "llm_answer": llm_answer,
        "suggested_signal": signal,
        "reported": null,
        "note": "A classification is a suggestion. A wrong block signal cools a healthy IP for that target, so confirm repeated evidence before reporting.",
    });
    if args.bool("report").unwrap_or(false) {
        let Some(signal) = out["suggested_signal"].as_object().cloned() else {
            out["reported"] = json!({"status": "skipped", "reason": "the response is not a block"});
            return Ok(out);
        };
        let (Some(exit_ip), Some(target)) = (
            args.str("exit_ip"),
            signal.get("target").and_then(Value::as_str),
        ) else {
            return Err(ToolError::invalid(
                "`report` needs `exit_ip` and a target host (`host`, or a capture with a host)",
            ));
        };
        let mut report =
            json!({"exit_ip": exit_ip, "target": target, "type": verdict.classification});
        if let Some(session) = args.str("session") {
            report["session"] = json!(session);
        }
        if args.bool("dry_run").unwrap_or(false) {
            report["dry_run"] = json!(true);
        }
        let reported = super::manage::run_direct(
            ctx,
            Action::ReportBlockSignal,
            Args::from_value(report),
            info,
        )
        .await;
        out["reported"] = match reported {
            Ok(value) => value,
            Err(error) => error.to_value(),
        };
    }
    Ok(out)
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

pub async fn suggest_policy(ctx: &Ctx, args: &Args) -> ToolResult {
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
    let user = format!(
        "Write the smallest policy change that satisfies the request.\n{}\n{}\n{}\n{}",
        untrusted(
            "requested_scope",
            &json!({"scope": scope, "org": org}).to_string(),
            2000
        ),
        untrusted("policy_format", POLICY_REFERENCE, 6000),
        untrusted(
            "current_policies",
            &Value::Array(current).to_string(),
            llm.max_input_chars
        ),
        untrusted("request", request, 2000),
    );
    let answer = llm
        .complete_json("policy_draft", SYSTEM_RULES, &user, &schema)
        .await
        .map_err(llm_error)?;
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
    fn rules_classify_the_documented_block_shapes() {
        let none = json!(null);
        assert_eq!(
            classify_rules(429, &none, "").classification,
            "rate_limited"
        );
        let challenge = classify_rules(
            403,
            // detection-data: the challenge header of a CDN
            &json!({"cf-mitigated": "challenge"}),
            "<title>Just a moment...</title>",
        );
        assert_eq!(
            (challenge.classification, challenge.confidence >= 0.9),
            ("challenge", true)
        );
        let captcha = classify_rules(503, &none, "<div class=\"captcha-widget\">");
        assert_eq!(captcha.classification, "challenge");
        let sorry = classify_rules(
            302,
            &json!([["Location", "https://search.example.test/sorry/index"]]),
            "",
        );
        assert_eq!(sorry.classification, "challenge");
        let plain = classify_rules(403, &none, "<h1>Forbidden</h1>");
        assert_eq!(
            (plain.classification, plain.confidence < 0.9),
            ("forbidden", true)
        );
        let page = classify_rules(200, &none, "<html>welcome</html>");
        assert_eq!(page.classification, "none");
        let soft = classify_rules(200, &none, "please verify you are human");
        assert_eq!(
            (soft.classification, soft.confidence < 0.9),
            ("challenge", true)
        );
    }

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
