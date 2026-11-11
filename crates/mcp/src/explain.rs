//! Offline explanations: refusal cause codes, session proxy error codes and block signal types,
//! and why a proxy username was refused. No backend is needed: the text comes from the
//! documented behaviour, the status and SOCKS codes come from `proxyx-pool-common`, and the
//! username is parsed with the gateway's own grammar (`proxyx-policy`).

use common::Cause;
use policy::{EffectivePolicy, InboundOptions, MAX_USERNAME_LEN};
use proxyx_client::sessions::ProxyErrorCause;
use serde_json::{Value, json};

/// Where an explained code comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSource {
    /// A gateway refusal (`HTTP/1.1 503 cache_empty`).
    Gateway(Cause),
    /// An `X-ProxyX-Error` value of the session proxy.
    SessionProxy(ProxyErrorCause),
}

/// Find a known code in free text: a status line, a log line, a header value.
pub fn find_code(text: &str) -> Option<CodeSource> {
    text.split(|c: char| !(c.is_ascii_lowercase() || c == '_'))
        .filter(|word| word.len() >= 7)
        .find_map(|word| {
            Cause::from_code(word).map(CodeSource::Gateway).or_else(|| {
                ProxyErrorCause::from_code(word)
                    .filter(|cause| cause.code() == word)
                    .map(CodeSource::SessionProxy)
            })
        })
}

struct Advice {
    meaning: &'static str,
    likely: &'static [&'static str],
    next: &'static [&'static str],
    metrics: &'static [&'static str],
}

fn gateway_advice(cause: Cause) -> Advice {
    match cause {
        Cause::AuthRequired => Advice {
            meaning: "The org key is missing, unknown or rate-limited, a probe-org key was used on a public listener, or a probe token is bad.",
            likely: &[
                "the client sent no Proxy-Authorization or the wrong password",
                "the key was never created or belongs to another deployment",
                "the source address made 20 unknown-key lookups in a minute (source_limited)",
            ],
            next: &[
                "check the password is the org key (ak_...), the username is only options",
                "create a key with create_org_key if the org has none",
                "wait for the one-minute window when auth_failures_total shows source_limited",
            ],
            metrics: &[
                "proxyx_pool_auth_failures_total",
                "proxyx_pool_connections_total",
            ],
        },
        Cause::OrgDisabled => Advice {
            meaning: "The org key exists but an operator disabled it.",
            likely: &["disable_org_keys ran for the org", "the org was offboarded"],
            next: &[
                "create a new key with create_org_key (capability org_keys) if the org should work again",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
        Cause::OptionDenied => Advice {
            meaning: "The proxy username is malformed or asks for more than the org's policy allows.",
            likely: &[
                "a value contains '-' or an uppercase letter",
                "a key is repeated or unknown, or city is given without cc",
                "kind, provider, region or ttl is outside the effective policy",
            ],
            next: &[
                "run explain_selector with the username (and the org) to see which rule fails",
                "widen the org policy with propose_config_change if the request is legitimate",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
        Cause::OrgBlocked => Advice {
            meaning: "An operator block stops this org in the requested scope (ip, provider, route_class or pool).",
            likely: &[
                "create_org_block or POST /v1/org-blocks was used, possibly after an abuse report",
                "the block has a ttl that has not expired",
            ],
            next: &[
                "list_org_blocks shows the scope, reason, operator and expiry",
                "lift_org_block (capability org_blocks) when the reason is resolved",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
        Cause::PortNotAllowed => Advice {
            meaning: "Every candidate provider restricts target ports and refuses this one.",
            likely: &["the provider adapter lists allowed_ports without the target port"],
            next: &[
                "use an allowed port, or a provider whose adapter allows it (see the adapter in data/adapters)",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
        Cause::DestinationDenied => Advice {
            meaning: "The target is a private, loopback, link-local, metadata or cluster address or name; on the probe listener, it is not a probe target.",
            likely: &[
                "the target resolves by name to an internal range the gateway recognizes",
                "the host is localhost, has no dot, or ends in .internal, .local, .svc, .lan",
            ],
            next: &[
                "the gateway never relays to internal networks; reach internal targets with a session upstream override instead",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
        Cause::OrgCapacity => Advice {
            meaning: "The org reached max_tunnels_per_org (in total, or on one provider for a route-class policy).",
            likely: &[
                "a crawl or scan opened more parallel tunnels than the policy allows",
                "tunnels leak because clients do not close them",
            ],
            next: &[
                "lower client concurrency or raise max_tunnels_per_org with propose_config_change (org policy)",
                "check proxyx_pool_tunnels_open for a steady climb",
            ],
            metrics: &[
                "proxyx_pool_org_capacity_refusals_total",
                "proxyx_pool_tunnels_open",
            ],
        },
        Cause::OrgBudget => Advice {
            meaning: "The org used its limits.org_max_gb_per_day for the UTC day. Open tunnels are not cut.",
            likely: &["large downloads or a long-running scan consumed the daily byte budget"],
            next: &[
                "wait for the next UTC day, or raise limits.org_max_gb_per_day in the org policy",
            ],
            metrics: &["proxyx_pool_org_budget_refusals_total"],
        },
        Cause::CacheEmpty => Advice {
            meaning: "No session or IP could be leased and on_empty is create or fail, or a create failed.",
            likely: &[
                "the ready pool is below min_ready: warmer down, provider breaker open, or cost budget spent",
                "the region or provider in the request has no ready units",
            ],
            next: &[
                "pool_capacity shows ready versus min_ready per provider",
                "breaker_states shows open breakers",
                "health shows whether the warmer is running",
            ],
            metrics: &[
                "proxyx_pool_cache_ready",
                "proxyx_pool_cache_low",
                "proxyx_pool_provider_breaker_state",
                "proxyx_pool_cost_used_ratio",
                "proxyx_pool_warm_creates_total",
            ],
        },
        Cause::NoHealthyIp => Advice {
            meaning: "A static partition has no healthy IP.",
            likely: &[
                "every IP of the region is leased, cooling down, quarantined or offline",
                "inventory is empty for the provider and region",
            ],
            next: &[
                "list_inventory with state filters shows where the IPs are",
                "inventory_replacements lists IPs waiting for replacement",
                "put_inventory when new IPs were rented",
            ],
            metrics: &["proxyx_pool_inventory_ips", "proxyx_pool_cache_ready"],
        },
        Cause::CacheUnavailable => Advice {
            meaning: "Redis is unreachable, or Postgres is down and the key is not cached. New leases are refused; open tunnels go on.",
            likely: &["Redis or Postgres outage or network partition"],
            next: &[
                "health on the gateway and warmer; readyz reports 503 redis unavailable after three failed checks",
            ],
            metrics: &["proxyx_pool_redis_down", "proxyx_pool_postgres_down"],
        },
        Cause::LeaseTimeout => Advice {
            meaning: "on_empty = wait ran out of lease_wait, or Redis was too slow for the lease script.",
            likely: &[
                "every static IP is busy and none became free within lease_wait",
                "Redis latency",
            ],
            next: &[
                "pool_capacity for free units; raise lease_wait or add IPs; check Redis latency",
            ],
            metrics: &["proxyx_pool_cache_leases_total", "proxyx_pool_cache_ready"],
        },
        Cause::ProviderUnavailable => Advice {
            meaning: "The provider refused the connection or could not be reached, its breaker is open, or the adapter could not render the credential.",
            likely: &[
                "the provider has an outage or rate-limits the account",
                "the route-class breaker opened after repeated failures",
            ],
            next: &[
                "breaker_states and proxyx_pool_breaker_skips_total show which provider",
                "wait for the half-open probe, or switch the org's policy providers order",
            ],
            metrics: &[
                "proxyx_pool_provider_breaker_state",
                "proxyx_pool_breaker_skips_total",
                "proxyx_pool_dial_duration_seconds",
            ],
        },
        Cause::ProviderAuth => Advice {
            meaning: "The provider rejected the rendered credential.",
            likely: &[
                "expired or rotated provider credentials",
                "an adapter template renders the username wrongly",
            ],
            next: &[
                "verify the provider account in the provider panel and the credential file the adapter names",
                "for a customer upstream use validate_customer_upstream after fixing the login",
            ],
            metrics: &[
                "proxyx_pool_connections_total",
                "proxyx_pool_warm_creates_total",
            ],
        },
        Cause::ProviderTimeout => Advice {
            meaning: "The provider did not answer in time, or the 8 s open budget ran out. It says nothing about provider health on its own.",
            likely: &[
                "a slow provider handshake",
                "the target is slow and the budget ran out in retries",
            ],
            next: &[
                "compare dial_duration_seconds by stage: a slow handshake points at the provider, first_byte at the target",
            ],
            metrics: &["proxyx_pool_dial_duration_seconds"],
        },
        Cause::UpstreamError => Advice {
            meaning: "The provider answered the CONNECT with an unexpected status or SOCKS5 reply.",
            likely: &[
                "the provider returns an error page for the requested options",
                "an account limit or a banned target on the provider side",
            ],
            next: &[
                "inspect the provider's dashboard; try another provider or region through the username",
            ],
            metrics: &["proxyx_pool_connections_total"],
        },
    }
}

fn proxy_error_advice(cause: ProxyErrorCause) -> Advice {
    match cause {
        ProxyErrorCause::SessionNotFound => Advice {
            meaning: "The session proxy does not know the session id in the proxy username: it expired, was never created, or the proxy reads another Redis.",
            likely: &[
                "the session ttl ran out",
                "the proxy and the control plane use different redis_key_prefix values",
            ],
            next: &[
                "session_status to see the lifecycle state",
                "create_session again (sessions are cheap), or extend_session before the ttl",
            ],
            metrics: &["proxyx_intercept_connections_total"],
        },
        ProxyErrorCause::SessionBackendUnavailable => Advice {
            meaning: "The session store (Redis) is unreachable from the session proxy.",
            likely: &["Redis outage"],
            next: &["health on the session proxy and control API; retry after Redis recovers"],
            metrics: &["proxyx_intercept_connections_total"],
        },
        ProxyErrorCause::UpstreamRefused => Advice {
            meaning: "The target (or the org's egress proxy) refused the connection.",
            likely: &[
                "nothing listens on the target port",
                "the egress proxy is down or rejects the login",
            ],
            next: &["check the org egress proxy with get_org; verify the target is up"],
            metrics: &["proxyx_intercept_connections_total"],
        },
        ProxyErrorCause::UpstreamDns => Advice {
            meaning: "The target name did not resolve.",
            likely: &[
                "a typo in the host",
                "the name exists only inside a network the proxy cannot reach (use an upstream override)",
            ],
            next: &["fix the host name"],
            metrics: &["proxyx_intercept_connections_total"],
        },
        ProxyErrorCause::UpstreamError => Advice {
            meaning: "Any other upstream failure: TLS handshake failure, reset, protocol error.",
            likely: &[
                "the target resets the connection or serves invalid TLS",
                "the egress chain rejects the request",
            ],
            next: &[
                "search_traffic for the host with status_code 0 or the response body to see the failure",
                "classify_block_page if the target answers with a block page",
            ],
            metrics: &[
                "proxyx_intercept_connections_total",
                "proxyx_intercept_upstream_duration_seconds",
            ],
        },
        ProxyErrorCause::UpstreamTimeout => Advice {
            meaning: "The target did not answer in time.",
            likely: &["a slow or silent target", "the egress path drops packets"],
            next: &["retry; compare upstream_duration_seconds with a direct request"],
            metrics: &["proxyx_intercept_upstream_duration_seconds"],
        },
        ProxyErrorCause::UpstreamUnavailable => Advice {
            meaning: "The proxy's circuit breaker for the target (or the org egress proxy, or a private override) is open: no dial was made. Honour the Retry-After header.",
            likely: &[
                "recent connection failures to the same target or egress proxy opened the breaker",
                "the org's egress proxy is down",
            ],
            next: &[
                "wait for Retry-After; the breaker probes by itself and closes after successful probes",
                "check the target or the org's egress proxy directly",
            ],
            metrics: &[
                "proxyx_intercept_upstream_breaker_state",
                "proxyx_intercept_upstream_breaker_rejected_total",
            ],
        },
        ProxyErrorCause::UpstreamTls => Advice {
            meaning: "The proxy's own TLS handshake with the target failed, or the target certificate did not verify (upstream verification is on by default).",
            likely: &[
                "the target serves a certificate from a private or unknown CA",
                "an expired, self-signed or mismatched certificate",
            ],
            next: &[
                "add the target's CA to the session proxy's [tls] ca_bundle",
                "for authorized tests only, set insecure_upstream_tls on the session",
            ],
            metrics: &["proxyx_intercept_tls_handshake_seconds"],
        },
        ProxyErrorCause::ConnectionLimit => Advice {
            meaning: "The session proxy is at tuning.max_connections and refused the connection.",
            likely: &[
                "a traffic burst or a client that leaks connections",
                "tuning.max_connections is low for the load",
            ],
            next: &[
                "retry after a short wait; raise tuning.max_connections or add session proxy replicas",
            ],
            metrics: &[
                "proxyx_intercept_connection_limit_refusals_total",
                "proxyx_intercept_connections_active",
            ],
        },
    }
}

/// The explanation of a code.
pub fn explain(source: CodeSource) -> Value {
    match source {
        CodeSource::Gateway(cause) => {
            let advice = gateway_advice(cause);
            json!({
                "source": "gateway",
                "code": cause.code(),
                "http_status": cause.status(),
                "socks5_reply": format!("0x{:02x}", cause.socks5_reply()),
                "status_line": cause.to_string(),
                "retryable": matches!(
                    cause,
                    Cause::OrgCapacity | Cause::CacheEmpty | Cause::NoHealthyIp
                        | Cause::CacheUnavailable | Cause::LeaseTimeout
                        | Cause::ProviderUnavailable | Cause::ProviderTimeout
                        | Cause::UpstreamError
                ),
                "meaning": advice.meaning,
                "likely_causes": advice.likely,
                "next_steps": advice.next,
                "metrics": advice.metrics,
            })
        }
        CodeSource::SessionProxy(cause) => {
            let advice = proxy_error_advice(cause);
            json!({
                "source": "session_proxy",
                "code": cause.code(),
                "header": "X-ProxyX-Error",
                "retryable": cause.is_retryable(),
                "meaning": advice.meaning,
                "likely_causes": advice.likely,
                "next_steps": advice.next,
                "metrics": advice.metrics,
            })
        }
    }
}

/// Every gateway cause code with its one-line meaning, for the reference resource.
pub fn all_gateway_codes() -> Vec<Value> {
    Cause::ALL
        .iter()
        .map(|cause| {
            let advice = gateway_advice(*cause);
            json!({
                "code": cause.code(),
                "http_status": cause.status(),
                "socks5_reply": format!("0x{:02x}", cause.socks5_reply()),
                "meaning": advice.meaning,
            })
        })
        .collect()
}

/// Every session proxy error code with its one-line meaning.
pub fn all_proxy_codes() -> Vec<Value> {
    [
        ProxyErrorCause::SessionNotFound,
        ProxyErrorCause::SessionBackendUnavailable,
        ProxyErrorCause::UpstreamRefused,
        ProxyErrorCause::UpstreamDns,
        ProxyErrorCause::UpstreamError,
        ProxyErrorCause::UpstreamTimeout,
        ProxyErrorCause::UpstreamUnavailable,
        ProxyErrorCause::UpstreamTls,
        ProxyErrorCause::ConnectionLimit,
    ]
    .into_iter()
    .map(|cause| {
        json!({
            "code": cause.code(),
            "retryable": cause.is_retryable(),
            "meaning": proxy_error_advice(cause).meaning,
        })
    })
    .collect()
}

/// The four block signal types a client can report.
pub fn signal_types() -> Value {
    json!([
        {"type": "rate_limited", "evidence": "HTTP 429"},
        {"type": "challenge", "evidence": "403 or 503 with a challenge or captcha marker, or a /sorry/ redirect"},
        {"type": "forbidden", "evidence": "repeated plain 403 on one target"},
        {"type": "reset", "evidence": "reset or TLS failure after a successful tunnel"},
    ])
}

/// One reason a username is refused.
fn issue(rule: &str, detail: impl Into<String>) -> Value {
    json!({"rule": rule, "detail": detail.into()})
}

const KEYS: [&str; 7] = ["kind", "cc", "city", "prov", "ttl", "sid", "rot"];

/// Why `username` is refused, rule by rule. The verdict (`ok`) is the gateway's own parser;
/// the issues are the documented rules, so an empty list for a refused username cannot happen:
/// a generic issue is added in that case.
pub fn explain_username(username: &str) -> Value {
    let parsed = InboundOptions::parse(username);
    let mut issues: Vec<Value> = Vec::new();
    if username.len() > MAX_USERNAME_LEN {
        issues.push(issue(
            "length",
            format!(
                "the username is {} bytes; the limit is {MAX_USERNAME_LEN}",
                username.len()
            ),
        ));
    }
    let mut parts = username.split('-');
    let first = parts.next().unwrap_or("");
    if first != "px" {
        let hint = if first.eq_ignore_ascii_case("px") {
            " (the prefix is lowercase)"
        } else {
            ""
        };
        issues.push(issue(
            "prefix",
            format!("the username must start with `px`, it starts with {first:?}{hint}"),
        ));
    }
    let rest: Vec<&str> = parts.collect();
    if first == "px" && rest.len() % 2 == 1 {
        issues.push(issue(
            "pairs",
            format!(
                "after `px` the parts must be `key-value` pairs, but there are {} parts; a value never contains `-` (a provider id with `-` cannot be selected with `prov`, use the policy's providers list)",
                rest.len()
            ),
        ));
    }
    let mut seen: Vec<&str> = Vec::new();
    for pair in rest.chunks_exact(2) {
        let (key, value) = (pair[0], pair[1]);
        if !KEYS.contains(&key) {
            issues.push(issue(
                "unknown_key",
                format!("`{key}` is not an option; the keys are {KEYS:?}"),
            ));
        } else if seen.contains(&key) {
            issues.push(issue("repeated_key", format!("`{key}` appears twice")));
        } else {
            seen.push(key);
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            issues.push(issue(
                "value_characters",
                format!("the value {value:?} of `{key}` must be 1 or more of a-z, 0-9, _ (lowercase, no `-`)"),
            ));
        }
        match key {
            "kind" if !matches!(value, "static" | "rotating") => {
                issues.push(issue(
                    "kind",
                    format!("kind is `static` or `rotating`, not {value:?}"),
                ));
            }
            "rot" if !matches!(value, "sticky" | "each") => {
                issues.push(issue(
                    "rot",
                    format!("rot is `sticky` or `each`, not {value:?}"),
                ));
            }
            "cc" if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_lowercase()) => {
                issues.push(issue(
                    "cc",
                    format!("cc is two lowercase letters (ISO 3166-1), not {value:?}"),
                ));
            }
            "ttl" if value == "0" || value.starts_with("0s") => {
                issues.push(issue(
                    "ttl",
                    "ttl must be above zero (`30`, `30s`, `10m`, `2h`, `1d`)",
                ));
            }
            _ => {}
        }
    }
    if seen.contains(&"city") && !seen.contains(&"cc") {
        issues.push(issue("city_needs_cc", "`city` requires `cc`"));
    }
    if seen.contains(&"sid") && rest.chunks_exact(2).any(|p| p == ["rot", "each"]) {
        issues.push(issue(
            "sid_with_rot_each",
            "`sid` cannot be combined with `rot-each`",
        ));
    }
    match parsed {
        Ok(options) => json!({
            "ok": true,
            "username": username,
            "options": {
                "kind": options.kind.map(|kind| kind.to_string()),
                "region": options.region.as_ref().map(ToString::to_string),
                "provider": options.provider.as_ref().map(ToString::to_string),
                "ttl_secs": options.ttl.map(|ttl| ttl.as_secs()),
                "sid": options.sid,
                "rotation": options.rotation.map(|rotation| format!("{rotation:?}").to_lowercase()),
            },
            "issues": [],
        }),
        Err(cause) => {
            if issues.is_empty() {
                issues.push(issue(
                    "grammar",
                    "the gateway's parser refuses this username; compare it with the grammar in proxyx://docs/username-grammar",
                ));
            }
            json!({
                "ok": false,
                "username": username,
                "refusal": explain(CodeSource::Gateway(cause)),
                "issues": issues,
            })
        }
    }
}

/// Which option of a parsed username the org's effective policy refuses.
pub fn narrow_issues(options: &InboundOptions, effective: &EffectivePolicy) -> Vec<Value> {
    let mut issues = Vec::new();
    if let Some(kind) = options.kind
        && !effective.kinds.contains(&kind)
    {
        issues.push(issue(
            "policy_kind",
            format!(
                "kind {kind} is not in the policy's kinds {:?}",
                effective
                    .kinds
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ),
        ));
    }
    if let Some(provider) = &options.provider
        && !effective.providers.is_empty()
        && !effective.providers.contains(provider)
    {
        issues.push(issue(
            "policy_provider",
            format!(
                "provider {provider} is not in the policy's providers {:?}",
                effective
                    .providers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ),
        ));
    }
    if let Some(region) = &options.region
        && !effective
            .regions
            .iter()
            .any(|allowed| region.satisfies(allowed))
    {
        issues.push(issue(
            "policy_region",
            format!(
                "region {region} is not covered by the policy's regions {:?}",
                effective
                    .regions
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ),
        ));
    }
    if let Some(ttl) = options.ttl
        && ttl > effective.lease_ttl
    {
        issues.push(issue(
            "policy_ttl",
            format!(
                "ttl {}s is above the policy's lease_ttl {}s",
                ttl.as_secs(),
                effective.lease_ttl.as_secs()
            ),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gateway_cause_has_advice_and_matching_codes() {
        for cause in Cause::ALL {
            let value = explain(CodeSource::Gateway(cause));
            assert_eq!(value["code"], cause.code());
            assert_eq!(value["http_status"], cause.status());
            assert!(!value["next_steps"].as_array().expect("steps").is_empty());
            assert_eq!(
                find_code(&format!("HTTP/1.1 {} {}", cause.status(), cause.code())),
                Some(CodeSource::Gateway(cause))
            );
        }
    }

    #[test]
    fn finds_codes_in_free_text() {
        assert!(matches!(
            find_code("proxy answered 'HTTP/1.1 503 cache_empty' for example.com"),
            Some(CodeSource::Gateway(Cause::CacheEmpty))
        ));
        assert!(matches!(
            find_code("x-proxyx-error: upstream_dns"),
            Some(CodeSource::SessionProxy(ProxyErrorCause::UpstreamDns))
        ));
        assert_eq!(find_code("all fine"), None);
    }

    #[test]
    fn username_verdict_is_the_gateways_parser() {
        // The verdict must agree with the real grammar for every example the docs give.
        for ok in [
            "px",
            "px-kind-rotating-cc-fr",
            "px-kind-rotating-cc-fr-city-paris-sid-scan42-ttl-30m",
            "px-rot-each",
            "px-sid-job_17-ttl-1h",
        ] {
            let value = explain_username(ok);
            assert_eq!(value["ok"], true, "{ok}");
            assert!(value["issues"].as_array().expect("issues").is_empty());
        }
        for (bad, rule) in [
            ("px-kind-rotating-sid", "pairs"),
            ("px-cc-fr-cc-de", "repeated_key"),
            ("px-city-paris", "city_needs_cc"),
            ("px-sid-a-rot-each", "sid_with_rot_each"),
            ("px-sid-my-id", "pairs"),
            ("px-cc-FR", "value_characters"),
            ("PX-kind-static", "prefix"),
            ("px-ttl-0", "ttl"),
            ("px-bogus-1", "unknown_key"),
        ] {
            let value = explain_username(bad);
            assert_eq!(value["ok"], false, "{bad}");
            let rules: Vec<&str> = value["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .filter_map(|issue| issue["rule"].as_str())
                .collect();
            assert!(rules.contains(&rule), "{bad}: {rules:?} lacks {rule}");
            assert_eq!(value["refusal"]["code"], "option_denied");
        }
        let long = format!("px-sid-{}", "a".repeat(200));
        assert_eq!(explain_username(&long)["issues"][0]["rule"], "length");
    }
}
