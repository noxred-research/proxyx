//! Evidence-calibrated block-page classification.
//!
//! The rules read structure, not keywords alone: the status, challenge-specific headers, a
//! redirect target, the page title, forms and challenge widgets. A page that only talks about a
//! CAPTCHA is not an interstitial, a login 403 is an authorization answer and not a block, a
//! maintenance 503 is not a block, and a refusal the proxy itself produced is never a block by the
//! target. The coarse class stays `challenge`, `forbidden`, `rate_limited` or `none`; the subtype
//! says why. Confidence here is a rule strength on an ordinal scale, not a probability: the
//! published fixtures measure precision per subtype, and a model's self-reported number is labelled
//! as such. Classification advises; reporting a block signal is a separate, gated tool call.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

/// The version of the rules, reported with every result.
pub const DETECTOR_VERSION: &str = "block-rules-2";

/// What the rules look at.
#[derive(Debug, Clone)]
pub struct Input<'a> {
    pub status: u64,
    /// Lowercase header names.
    pub headers: &'a [(String, String)],
    /// The response body, already redacted and clipped.
    pub body: &'a str,
}

/// One thing the rules saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub id: &'static str,
    /// `status`, `header:<name>`, `body:title`, `body:structure` or `body:text`.
    pub location: String,
    pub detail: String,
}

/// The rules' verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    /// `challenge`, `forbidden`, `rate_limited` or `none`.
    pub classification: &'static str,
    pub subtype: &'static str,
    /// Rule strength, ordinal and not a probability.
    pub strength: f64,
    /// `rule_deterministic`, `rule_structural` or `rule_heuristic`.
    pub basis: &'static str,
    /// The rules saw some evidence but not enough to call it either way.
    pub abstained: bool,
    pub signals: Vec<Signal>,
    /// What an operator may do. Never an evasion step.
    pub recommendation: &'static str,
}

// detection-data: strings that challenge interstitials carry in their title
const CHALLENGE_TITLES: &[&str] = &[
    "just a moment",         // detection-data
    "attention required",    // detection-data
    "verify you are human",  // detection-data
    "are you a robot",       // detection-data
    "one more step",         // detection-data
    "checking your browser", // detection-data
    "un instant",            // detection-data
    "einen moment",          // detection-data
    "un momento",            // detection-data
    "bir dakika",            // detection-data
    "один момент",           // detection-data
    "请稍候",                // detection-data
];

// detection-data: elements a challenge page embeds
const WIDGET_MARKERS: &[&str] = &[
    "data-sitekey",       // detection-data
    "g-recaptcha",        // detection-data
    "h-captcha",          // detection-data
    "cf-turnstile",       // detection-data
    "px-captcha",         // detection-data
    "challenge-platform", // detection-data
    "/cdn-cgi/challenge", // detection-data
    "captcha-delivery",   // detection-data
    "datadome",           // detection-data
];

// detection-data: sentences of block pages
const TEXT_MARKERS: &[&str] = &[
    "unusual traffic",                 // detection-data
    "verify you are human",            // detection-data
    "are you a robot",                 // detection-data
    "request unsuccessful. incapsula", // detection-data
    "access denied - sucuri",          // detection-data
    "captcha",                         // detection-data
    "checking your browser",           // detection-data
    "just a moment",                   // detection-data
    "attention required",              // detection-data
];

const MAINTENANCE_WORDS: &[&str] = &[
    "maintenance",
    "scheduled downtime",
    "be right back",
    "temporarily unavailable",
    "back soon",
    "upgrading",
    "bakım",
    "wartung",
];

/// Words of an authorization error in a JSON body.
const AUTH_ERROR_WORDS: &[&str] = &[
    "unauthorized",
    "unauthorised",
    "not authorized",
    "invalid token",
    "token expired",
    "insufficient_scope",
    "insufficient scope",
    "permission",
    "access_denied",
    "invalid_token",
];

/// Words in the title of a login page.
const LOGIN_TITLE_WORDS: &[&str] = &[
    "sign in",
    "log in",
    "login",
    "giriş",
    "anmelden",
    "connexion",
];

static TITLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<title[^>]*>(.{0,200}?)</title>").expect("title pattern is valid")
});

/// The structure of a page, from a bounded prefix.
#[derive(Debug, Default)]
struct Page {
    title: String,
    text_len: usize,
    widget: Option<&'static str>,
    text_marker: Option<&'static str>,
    form: bool,
    password_input: bool,
    json: bool,
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn inspect(body: &str) -> Page {
    // a bounded prefix: parse cost does not depend on the size of the page
    let mut end = body.len().min(65_536);
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let lower = body[..end].to_lowercase();
    let trimmed = lower.trim_start();
    Page {
        title: TITLE
            .captures(&lower)
            .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default(),
        text_len: body.len(),
        widget: WIDGET_MARKERS.iter().copied().find(|m| lower.contains(m)),
        text_marker: TEXT_MARKERS.iter().copied().find(|m| lower.contains(m)),
        form: lower.contains("<form"),
        password_input: lower.contains("type=\"password\"") || lower.contains("type='password'"),
        json: trimmed.starts_with('{') || trimmed.starts_with('['),
    }
}

fn signal(id: &'static str, location: &str, detail: impl Into<String>) -> Signal {
    Signal {
        id,
        location: location.to_owned(),
        detail: detail.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn verdict(
    classification: &'static str,
    subtype: &'static str,
    strength: f64,
    basis: &'static str,
    abstained: bool,
    signals: Vec<Signal>,
    recommendation: &'static str,
) -> Classification {
    Classification {
        classification,
        subtype,
        strength,
        basis,
        abstained,
        signals,
        recommendation,
    }
}

const PAUSE: &str = "Pause or slow the work against this target and confirm you are authorized to access it. Do not try to solve the challenge or change identity to get around it.";
const SLOW: &str = "Reduce the request rate for this target and honor Retry-After. Do not rotate identities to get around the limit.";
const VERIFY_AUTH: &str = "This is an authorization answer, not a block. Check the credentials and permissions the authorized test uses.";
const PROXY_SIDE: &str = "The proxy produced this refusal, not the target. Use explain_refusal; do not report a block signal.";
const NOTHING: &str = "No block evidence. Nothing to report.";

/// Classify one response.
pub fn classify(input: &Input<'_>) -> Classification {
    let status = input.status;
    let headers = input.headers;
    let page = inspect(input.body);
    let title_challenge = CHALLENGE_TITLES.iter().find(|t| page.title.contains(**t));

    // a refusal the proxy itself made says nothing about the target
    if let Some(code) = header_value(headers, "x-proxyx-error") {
        let code = code.trim().to_ascii_lowercase();
        let known = crate::explain::all_proxy_codes()
            .iter()
            .any(|row| row["code"].as_str() == Some(code.as_str()));
        if known {
            return verdict(
                "none",
                "proxy_refusal",
                0.95,
                "rule_deterministic",
                false,
                vec![signal("proxy_error_header", "header:x-proxyx-error", code)],
                PROXY_SIDE,
            );
        }
    }
    if status == 429 {
        let mut signals = vec![signal("http_429", "status", "HTTP 429")];
        if let Some(wait) = header_value(headers, "retry-after") {
            signals.push(signal("retry_after", "header:retry-after", wait));
        }
        return verdict(
            "rate_limited",
            "http_429",
            0.95,
            "rule_deterministic",
            false,
            signals,
            SLOW,
        );
    }
    // detection-data: the challenge header of a CDN
    if header_value(headers, "cf-mitigated")
        .is_some_and(|v| v.to_ascii_lowercase().contains("challenge"))
    {
        return verdict(
            "challenge",
            "challenge_header",
            0.95,
            "rule_deterministic",
            false,
            vec![
                signal("status", "status", format!("HTTP {status}")),
                signal("challenge_header", "header:cf-mitigated", "challenge"), // detection-data
            ],
            PAUSE,
        );
    }
    if (300..400).contains(&status)
        && let Some(target) = header_value(headers, "location")
    {
        let lower = target.to_ascii_lowercase();
        if lower.contains("/sorry/") {
            return verdict(
                "challenge",
                "search_redirect",
                0.9,
                "rule_deterministic",
                false,
                vec![signal(
                    "sorry_redirect",
                    "header:location",
                    "redirect to /sorry/",
                )],
                PAUSE,
            );
        }
        if lower.contains("captcha") || lower.contains("/challenge") {
            return verdict(
                "challenge",
                "redirect_to_challenge",
                0.7,
                "rule_heuristic",
                false,
                vec![signal(
                    "challenge_redirect",
                    "header:location",
                    "redirect to a challenge path",
                )],
                PAUSE,
            );
        }
    }
    if status == 401 {
        let mut signals = vec![signal("http_401", "status", "HTTP 401")];
        if let Some(scheme) =
            header_value(headers, "www-authenticate").and_then(|v| v.split_whitespace().next())
        {
            signals.push(signal(
                "www_authenticate",
                "header:www-authenticate",
                scheme.to_ascii_lowercase(),
            ));
        }
        return verdict(
            "none",
            "auth_required",
            0.9,
            "rule_deterministic",
            false,
            signals,
            VERIFY_AUTH,
        );
    }
    let error_status = matches!(status, 403 | 503 | 202 | 406);
    if error_status {
        if let (Some(title), Some(widget)) = (title_challenge, page.widget) {
            return verdict(
                "challenge",
                "interstitial",
                0.9,
                "rule_structural",
                false,
                vec![
                    signal("status", "status", format!("HTTP {status}")),
                    signal("challenge_title", "body:title", (*title).to_owned()),
                    signal("challenge_widget", "body:structure", widget),
                ],
                PAUSE,
            );
        }
        if let Some(widget) = page.widget {
            return verdict(
                "challenge",
                "challenge_widget",
                0.8,
                "rule_structural",
                false,
                vec![
                    signal("status", "status", format!("HTTP {status}")),
                    signal("challenge_widget", "body:structure", widget),
                ],
                PAUSE,
            );
        }
        if let Some(title) = title_challenge {
            return verdict(
                "challenge",
                "challenge_title",
                0.75,
                "rule_structural",
                false,
                vec![
                    signal("status", "status", format!("HTTP {status}")),
                    signal("challenge_title", "body:title", (*title).to_owned()),
                ],
                PAUSE,
            );
        }
        if let Some(marker) = page.text_marker {
            return verdict(
                "challenge",
                "marker_on_error_status",
                0.7,
                "rule_heuristic",
                false,
                vec![
                    signal("status", "status", format!("HTTP {status}")),
                    signal("challenge_text", "body:text", marker),
                ],
                PAUSE,
            );
        }
    }
    if (200..300).contains(&status) {
        let interstitial_shape = page.widget.is_some()
            && page.text_len < 20_000
            && (title_challenge.is_some() || page.form);
        if interstitial_shape {
            return verdict(
                "challenge",
                "soft_interstitial",
                0.6,
                "rule_heuristic",
                false,
                vec![
                    signal("status", "status", format!("HTTP {status}")),
                    signal(
                        "challenge_widget",
                        "body:structure",
                        page.widget.unwrap_or(""),
                    ),
                ],
                PAUSE,
            );
        }
        if page.widget.is_some() || page.text_marker.is_some() || title_challenge.is_some() {
            return verdict(
                "none",
                "marker_without_interstitial_structure",
                0.5,
                "rule_heuristic",
                true,
                vec![signal(
                    "marker_only",
                    "body:text",
                    "the page mentions challenge-related terms without an interstitial's structure",
                )],
                "Not enough evidence to call this a block. A page that talks about a CAPTCHA is not one.",
            );
        }
    }
    match status {
        403 => {
            let json_error = page.json
                && AUTH_ERROR_WORDS
                    .iter()
                    .any(|w| input.body.to_ascii_lowercase().contains(w));
            let login_page = page.password_input
                || (page.form && LOGIN_TITLE_WORDS.iter().any(|w| page.title.contains(w)));
            if header_value(headers, "www-authenticate").is_some() || json_error || login_page {
                return verdict(
                    "none",
                    "authorization_denied",
                    0.75,
                    "rule_structural",
                    false,
                    vec![signal(
                        "http_403",
                        "status",
                        "HTTP 403 with an authorization answer",
                    )],
                    VERIFY_AUTH,
                );
            }
            verdict(
                "forbidden",
                "plain_denial",
                0.6,
                "rule_heuristic",
                false,
                vec![signal(
                    "http_403",
                    "status",
                    "HTTP 403 without challenge structure or an authorization answer; one 403 can be ordinary, repeated ones from one exit are a block",
                )],
                "One 403 proves little. Look for the same answer on repeated requests before drawing a conclusion.",
            )
        }
        500..=599 => {
            let lower = input.body.to_lowercase();
            let maintenance = header_value(headers, "retry-after").is_some()
                || MAINTENANCE_WORDS.iter().any(|w| lower.contains(w))
                || page.title.contains("maintenance");
            if status == 503 && maintenance {
                verdict(
                    "none",
                    "maintenance",
                    0.8,
                    "rule_structural",
                    false,
                    vec![signal(
                        "http_503",
                        "status",
                        "HTTP 503 with a maintenance or Retry-After signal",
                    )],
                    "The target reports it is unavailable. Wait; this is not a block.",
                )
            } else {
                verdict(
                    "none",
                    "server_error",
                    0.7,
                    "rule_heuristic",
                    false,
                    vec![signal("http_5xx", "status", format!("HTTP {status}"))],
                    "A server error. Not evidence of a block on its own.",
                )
            }
        }
        _ => verdict(
            "none",
            "no_block_evidence",
            0.7,
            "rule_heuristic",
            false,
            vec![signal(
                "status",
                "status",
                format!("HTTP {status} with no block evidence"),
            )],
            NOTHING,
        ),
    }
}

/// The precision of a subtype measured on the published fixtures (`tests/fixtures/block_pages.json`),
/// or `None` for a subtype with no such measurement. A test recomputes these from the fixtures and
/// fails when a rule change lowers one, so the table cannot drift from the evidence.
pub fn measured_precision(subtype: &str) -> Option<f64> {
    match subtype {
        "http_429"
        | "challenge_header"
        | "search_redirect"
        | "interstitial"
        | "challenge_widget"
        | "challenge_title"
        | "marker_on_error_status"
        | "soft_interstitial"
        | "plain_denial"
        | "redirect_to_challenge" => Some(1.0),
        _ => None,
    }
}

/// Everything about a classification a result shows.
pub fn describe(classification: &Classification) -> Value {
    json!({
        "classification": classification.classification,
        "subtype": classification.subtype,
        "confidence": classification.strength,
        "confidence_kind": classification.basis,
        "confidence_scale": "ordinal rule strength, not a probability",
        "abstained": classification.abstained,
        "detector_version": DETECTOR_VERSION,
        "recommendation": classification.recommendation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(status: u64, headers: &[(&str, &str)], body: &str) -> Classification {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        classify(&Input {
            status,
            headers: &headers,
            body,
        })
    }

    #[test]
    fn strong_rules_name_their_subtype() {
        assert_eq!(run(429, &[("retry-after", "30")], "").subtype, "http_429");
        // detection-data: the challenge header of a CDN
        let challenge = run(403, &[("cf-mitigated", "challenge")], "");
        assert_eq!(
            (challenge.classification, challenge.subtype),
            ("challenge", "challenge_header")
        );
        let sorry = run(
            302,
            &[("location", "https://search.example.test/sorry/index")],
            "",
        );
        assert_eq!(sorry.subtype, "search_redirect");
        let proxy = run(502, &[("x-proxyx-error", "upstream_dns")], "");
        assert_eq!(
            (proxy.classification, proxy.subtype),
            ("none", "proxy_refusal")
        );
    }

    #[test]
    fn talking_about_a_captcha_is_not_a_challenge() {
        let article = run(
            200,
            &[],
            "<html><title>How CAPTCHA systems work</title><article>A captcha asks you to verify you are human. Long essay.</article></html>",
        );
        assert_eq!((article.classification, article.abstained), ("none", true));
    }

    #[test]
    fn authorization_answers_and_maintenance_are_not_blocks() {
        assert_eq!(
            run(401, &[("www-authenticate", "Bearer")], "").subtype,
            "auth_required"
        );
        let login = run(403, &[], "<form><input type=\"password\"></form>");
        assert_eq!(
            (login.classification, login.subtype),
            ("none", "authorization_denied")
        );
        let json = run(403, &[], "{\"error\":\"insufficient_scope\"}");
        assert_eq!(json.subtype, "authorization_denied");
        let down = run(503, &[("retry-after", "120")], "Down for maintenance");
        assert_eq!((down.classification, down.subtype), ("none", "maintenance"));
        let plain = run(403, &[], "<h1>Forbidden</h1>");
        assert_eq!(
            (plain.classification, plain.subtype),
            ("forbidden", "plain_denial")
        );
    }

    #[test]
    fn interstitials_need_structure() {
        // detection-data: the markup of a challenge page
        let page = "<html><title>Just a moment...</title><div class=\"cf-turnstile\" data-sitekey=\"x\"></div></html>";
        let interstitial = run(403, &[], page);
        assert_eq!(interstitial.subtype, "interstitial");
        let localized = run(
            503,
            &[],
            "<title>Un instant…</title><div data-sitekey=\"k\"></div>",
        );
        assert_eq!(localized.classification, "challenge");
    }
}
