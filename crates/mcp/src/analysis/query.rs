//! Natural-language traffic questions compiled to the capture query language.
//!
//! The compiler is deterministic: it recognizes a fixed set of phrases (status classes, methods,
//! hosts, paths, cookies, durations, sizes, content types, headers, body text) and turns each into
//! the typed filter the control plane already validates. A phrase it does not recognize is not
//! guessed at and not dropped: it is listed as unsupported and the draft stays non-executable. An
//! optional model may propose branches for what the templates cannot express, but its output goes
//! through the same validator and the same scope intersection as everything else, and the scope
//! constraints are applied after generation, to every OR branch.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::audit::{canonical_json, sha256_hex};
use crate::config::QueryAnalysisConfig;

/// What the compiler produced.
#[derive(Debug, Default)]
pub struct Draft {
    /// Branches before the scope is applied.
    pub branches: Vec<Map<String, Value>>,
    pub explanation: Vec<String>,
    pub assumptions: Vec<String>,
    pub unsupported: Vec<String>,
}

/// How expensive running the query is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cost {
    /// `cheap`, `moderate` or `expensive`.
    pub level: &'static str,
    pub body_scan: bool,
    pub regex: bool,
    pub reasons: Vec<String>,
}

impl Cost {
    pub fn to_json(&self) -> Value {
        json!({
            "level": self.level,
            "body_scan": self.body_scan,
            "regex": self.regex,
            "reasons": self.reasons,
        })
    }
}

/// Why a time range cannot be compiled.
pub const TIME_UNSUPPORTED: &str = "the capture query language has no time field, so a time range cannot be compiled; narrow by source_id (one run) or by another field instead";

static TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:(?:in\s+)?the\s+)?(?:last|past|previous)\s+(?:\d+\s*)?(?:second|minute|min|hour|day|week|month|year)s?\b|\byesterday\b|\btoday\b|\btonight\b|\b\d+\s*(?:seconds?|minutes?|mins?|hours?|days?|weeks?)\s+ago\b|\bsince\s+\S+|\bbetween\s+\S+\s+and\s+\S+|\brecent(?:ly)?\b|\bthis\s+(?:morning|week|hour|month)\b|\blatest\b|\bnewest\b|\boldest\b",
    )
    .expect("time pattern is valid")
});

static STATUS_CODES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:status(?:\s+codes?)?|http|codes?)\s+((?:[1-5]\d\d|[1-5]xx)(?:\s*(?:,|or|and)\s*(?:[1-5]\d\d|[1-5]xx))*)|\b((?:[1-5]\d\d|[1-5]xx)(?:\s*(?:,|or|and)\s*(?:[1-5]\d\d|[1-5]xx))*)\s+(?:status(?:es)?|responses?|errors?)",
    )
    .expect("status pattern is valid")
});

static STATUS_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(client\s+errors?|server\s+errors?|errors?|failed|failures?|failing|rate[\s-]?limited|throttled|unauthori[sz]ed|forbidden|not\s+found|redirects?|redirected|successful|successes)\b",
    )
    .expect("status word pattern is valid")
});

static METHODS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?:\s*(?:,|or|and)\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS))*)\b|(?i:\b(get|post|put|patch|delete|head|options)\s+(?:requests?|calls?)\b)",
    )
    .expect("method pattern is valid")
});

static COOKIES_SET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:that\s+)?set(?:s|ting)?\s+cookies?\b").expect("cookie pattern is valid")
});
static COOKIES_SENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:that\s+)?(?:send|sends|sent|sending|carry|carrying|with|using)\s+cookies?\b",
    )
    .expect("cookie pattern is valid")
});
static DURATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(slower|longer|more|faster|shorter|less|under|over)\s+than\s+(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?)\b")
        .expect("duration pattern is valid")
});
static SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(larger|bigger|greater|smaller|less)\s+than\s+(\d+(?:\.\d+)?)\s*(bytes?|b|kib|kb|k|mib|mb|m|gib|gb)\b(?:\s+(?:responses?|bodies|body))?")
        .expect("size pattern is valid")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:(?:host|hostname|domain)\s+(?:is\s+|=\s*|contains\s+)?|(?:to|from|on|at)\s+)(\*?\.?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}|localhost)\b")
        .expect("host pattern is valid")
});
static PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bpaths?\s+(?:contains?|containing|including|starts?\s+with|starting\s+with|begins?\s+with|is|=)\s*"?(/[^\s"',;]*)"?|\b(?:to|on|at|under|for)\s+(/[^\s"',;]+)"#)
        .expect("path pattern is valid")
});
static MIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(json|html|xml|javascript|css|image|pdf|plain\s+text)\s+(?:responses?|content|bod(?:y|ies))\b")
        .expect("mime pattern is valid")
});
static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(request|response)?\s*header\s+([a-z][a-z0-9-]*)\s*(?:=|:|is|equals|of)\s*"?([^\s",;]+)"?"#)
        .expect("header pattern is valid")
});
static SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bsource[\s_-]?id\s*(?:=|:|is)?\s*"?([A-Za-z0-9._:-]+)"?"#)
        .expect("source pattern is valid")
});
static CORRELATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(correlation|account|tool[\s_-]?call)[\s_-]?id\s*(?:=|:|is)?\s*"?([\w.:-]+)"?"#,
    )
    .expect("correlation pattern is valid")
});
static BODY_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(request|response)?\s*(?:bod(?:y|ies)|payloads?)\s+(?:contains?|containing|mentions?|mentioning|includes?|including|with)\s+"([^"]{1,200})""#)
        .expect("body pattern is valid")
});
static BODY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(request|response)?\s*(?:bod(?:y|ies)|payloads?)\s+(?:matches|matching)\s+(?:regex\s+)?"([^"]{1,1000})""#)
        .expect("body regex pattern is valid")
});
static DIRECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(incoming|outgoing|server[\s-]to[\s-]client|client[\s-]to[\s-]server|s2c|c2s)\b",
    )
    .expect("direction pattern is valid")
});
static CLOSE_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bclose\s+code\s+(\d{3,4})\b").expect("close code pattern is valid")
});
static SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\s+or\s+|;").expect("split pattern is valid"));

const STOP_WORDS: &[&str] = &[
    "a",
    "an",
    "the",
    "all",
    "any",
    "every",
    "show",
    "me",
    "list",
    "find",
    "get",
    "give",
    "display",
    "requests",
    "request",
    "traffic",
    "captures",
    "capture",
    "exchanges",
    "exchange",
    "calls",
    "call",
    "responses",
    "response",
    "messages",
    "message",
    "websocket",
    "ws",
    "http",
    "that",
    "which",
    "were",
    "was",
    "are",
    "is",
    "with",
    "of",
    "to",
    "from",
    "on",
    "in",
    "for",
    "and",
    "by",
    "have",
    "has",
    "had",
    "returned",
    "returning",
    "return",
    "got",
    "gets",
    "please",
    "whose",
    "where",
    "when",
    "made",
    "sent",
    "seen",
    "my",
    "our",
    "their",
    "it",
    "its",
    "this",
    "these",
    "those",
    "only",
    "also",
    "then",
    "host",
    "hosts",
    "domain",
    "status",
    "code",
    "codes",
    "path",
    "paths",
    "than",
];

fn text_filter(op: &str, value: &str) -> Value {
    json!({"op": op, "value": value})
}

fn int_filter(op: &str, value: i64) -> Value {
    json!({"op": op, "value": value})
}

/// Merge `filter` into `branch[field]`: a second filter on one field is ANDed with the first.
fn add(branch: &mut Map<String, Value>, field: &str, filter: Value) {
    match branch.remove(field) {
        Some(existing) if existing != filter => {
            branch.insert(
                field.to_owned(),
                json!({"op": "all", "filters": [existing, filter]}),
            );
        }
        Some(existing) => {
            branch.insert(field.to_owned(), existing);
        }
        None => {
            branch.insert(field.to_owned(), filter);
        }
    }
}

/// Remove every match of `re` from `text` (replaced by a space) and return the captures.
fn take(re: &Regex, text: &mut String) -> Vec<Vec<String>> {
    let found: Vec<Vec<String>> = re
        .captures_iter(text)
        .map(|c| {
            c.iter()
                .map(|m| m.map_or_else(String::new, |m| m.as_str().to_owned()))
                .collect()
        })
        .collect();
    if !found.is_empty() {
        *text = re.replace_all(text, " ").into_owned();
    }
    found
}

fn status_filter(token: &str) -> Option<Value> {
    let token = token.trim().to_ascii_lowercase();
    if let Some(class) = token.strip_suffix("xx") {
        let base = class.parse::<i64>().ok()? * 100;
        return Some(
            json!({"op": "all", "filters": [int_filter("gte", base), int_filter("lt", base + 100)]}),
        );
    }
    Some(int_filter("exact", token.parse().ok()?))
}

fn any_of(filters: Vec<Value>) -> Value {
    if filters.len() == 1 {
        filters.into_iter().next().unwrap_or(Value::Null)
    } else {
        json!({"op": "any", "filters": filters})
    }
}

fn status_phrase(words: &str) -> Option<(Value, &'static str)> {
    let normalized: String = words
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some(match normalized.as_str() {
        "client error" | "client errors" => (
            json!({"op": "all", "filters": [int_filter("gte", 400), int_filter("lt", 500)]}),
            "status 400 to 499",
        ),
        "server error" | "server errors" => (int_filter("gte", 500), "status 500 and above"),
        "error" | "errors" | "failed" | "failure" | "failures" | "failing" => (
            int_filter("gte", 400),
            "status 400 and above (errors and failures)",
        ),
        "rate limited" | "rate-limited" | "ratelimited" | "throttled" => {
            (int_filter("exact", 429), "status 429")
        }
        "unauthorized" | "unauthorised" => (int_filter("exact", 401), "status 401"),
        "forbidden" => (int_filter("exact", 403), "status 403"),
        "not found" => (int_filter("exact", 404), "status 404"),
        "redirect" | "redirects" | "redirected" => (
            json!({"op": "all", "filters": [int_filter("gte", 300), int_filter("lt", 400)]}),
            "status 300 to 399",
        ),
        "successful" | "successes" => (
            json!({"op": "all", "filters": [int_filter("gte", 200), int_filter("lt", 300)]}),
            "status 200 to 299",
        ),
        _ => return None,
    })
}

fn to_ms(value: f64, unit: &str) -> i64 {
    let unit = unit.to_ascii_lowercase();
    let factor = if unit.starts_with("ms") || unit.starts_with("milli") {
        1.0
    } else if unit.starts_with('m') {
        60_000.0
    } else {
        1000.0
    };
    (value * factor).round() as i64
}

fn to_bytes(value: f64, unit: &str) -> i64 {
    let unit = unit.to_ascii_lowercase();
    let factor = match unit.as_str() {
        "kib" | "kb" | "k" => 1024.0,
        "mib" | "mb" | "m" => 1024.0 * 1024.0,
        "gib" | "gb" => 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (value * factor).round() as i64
}

/// Compile `request` for HTTP or WebSocket captures.
pub fn compile(request: &str, ws: bool) -> Draft {
    let mut draft = Draft::default();
    let mut text = request.trim().to_owned();
    for found in take(&TIME, &mut text) {
        draft
            .unsupported
            .push(format!("“{}”: {TIME_UNSUPPORTED}", found[0].trim()));
    }
    compile_segments(&mut draft, text, ws);
    draft
}

/// A recognized phrase: the field it filters, the filter and how it reads in the explanation.
type Built = Option<(&'static str, Value, String)>;

#[derive(Default)]
struct Segment {
    filters: Map<String, Value>,
    says: Vec<String>,
}

fn compile_segments(draft: &mut Draft, mut text: String, ws: bool) {
    // statuses and methods carry their own `or`: pull them out as tokens before splitting
    let mut tokens: Vec<(String, &'static str, Value, String)> = Vec::new();
    let mut unsupported_ws: Vec<String> = Vec::new();
    let mut next = 0;
    let mut tokenize =
        |re: &Regex, text: &mut String, build: &mut dyn FnMut(&[String]) -> Built| {
            let captures: Vec<(std::ops::Range<usize>, Vec<String>)> = re
                .captures_iter(text)
                .filter_map(|c| {
                    let range = c.get(0)?.range();
                    let groups: Vec<String> = c
                        .iter()
                        .map(|m| m.map_or_else(String::new, |m| m.as_str().to_owned()))
                        .collect();
                    Some((range, groups))
                })
                .collect();
            let mut rebuilt = String::new();
            let mut last = 0;
            for (range, groups) in captures {
                rebuilt.push_str(&text[last..range.start]);
                last = range.end;
                match build(&groups) {
                    Some((field, filter, says)) => {
                        let token = format!(" §{next}§ ");
                        next += 1;
                        tokens.push((token.clone(), field, filter, says));
                        rebuilt.push_str(&token);
                    }
                    None => rebuilt.push(' '),
                }
            }
            rebuilt.push_str(&text[last..]);
            *text = rebuilt;
        };
    // body text and regexes first: their quoted content must not be read as other phrases
    tokenize(&BODY_REGEX, &mut text, &mut |g| {
        let field = body_field(&g[1], ws);
        Some((
            field,
            text_filter("regex_match", &g[2]),
            format!("{field} matches the regular expression “{}”", g[2]),
        ))
    });
    tokenize(&BODY_TEXT, &mut text, &mut |g| {
        let field = body_field(&g[1], ws);
        Some((
            field,
            text_filter("contains", &g[2]),
            format!("{field} contains “{}”", g[2]),
        ))
    });
    tokenize(&STATUS_CODES, &mut text, &mut |g| {
        if ws {
            unsupported_ws.push("status codes do not exist on WebSocket messages".to_owned());
            return None;
        }
        let list = if g[1].is_empty() { &g[2] } else { &g[1] };
        let filters: Vec<Value> = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| {
                !t.is_empty() && !t.eq_ignore_ascii_case("or") && !t.eq_ignore_ascii_case("and")
            })
            .filter_map(status_filter)
            .collect();
        (!filters.is_empty()).then(|| {
            (
                "status_code",
                any_of(filters),
                format!(
                    "status {}",
                    list.split_whitespace().collect::<Vec<_>>().join(" ")
                ),
            )
        })
    });
    tokenize(&METHODS, &mut text, &mut |g| {
        if ws {
            unsupported_ws.push("HTTP methods do not exist on WebSocket messages".to_owned());
            return None;
        }
        let list = if g[1].is_empty() { &g[2] } else { &g[1] };
        let filters: Vec<Value> = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| {
                !t.is_empty() && !t.eq_ignore_ascii_case("or") && !t.eq_ignore_ascii_case("and")
            })
            .map(|t| text_filter("exact", &t.to_ascii_uppercase()))
            .collect();
        (!filters.is_empty()).then(|| {
            (
                "method",
                any_of(filters),
                format!("method {}", list.to_ascii_uppercase()),
            )
        })
    });
    draft.unsupported.append(&mut unsupported_ws);
    let mut segments: Vec<String> = SPLIT.split(&text).map(str::to_owned).collect();
    if segments.len() > 1 {
        draft
            .assumptions
            .push("`or` and `;` start a new alternative: each alternative is a separate query branch, and conditions are not shared between them".to_owned());
    }
    let mut leftovers: Vec<String> = Vec::new();
    for raw in segments.drain(..) {
        let mut segment = Segment::default();
        let mut part = raw;
        for (token, field, filter, says) in &tokens {
            if part.contains(token.trim()) {
                part = part.replace(token.trim(), " ");
                add(&mut segment.filters, field, filter.clone());
                segment.says.push(says.clone());
            }
        }
        if !ws {
            for found in take(&STATUS_WORDS, &mut part) {
                if let Some((filter, says)) = status_phrase(&found[1]) {
                    add(&mut segment.filters, "status_code", filter);
                    segment.says.push(says.to_owned());
                }
            }
            if !take(&COOKIES_SET, &mut part).is_empty() {
                segment
                    .filters
                    .insert("response_sets_cookies".to_owned(), json!(true));
                segment.says.push("the response sets cookies".to_owned());
            }
            if !take(&COOKIES_SENT, &mut part).is_empty() {
                segment
                    .filters
                    .insert("request_sends_cookies".to_owned(), json!(true));
                segment.says.push("the request sends cookies".to_owned());
            }
            for found in take(&DURATION, &mut part) {
                let value: f64 = found[2].parse().unwrap_or(0.0);
                let ms = to_ms(value, &found[3]);
                let slower = matches!(
                    found[1].to_ascii_lowercase().as_str(),
                    "slower" | "longer" | "more" | "over"
                );
                add(
                    &mut segment.filters,
                    "duration_ms",
                    int_filter(if slower { "gt" } else { "lt" }, ms),
                );
                segment.says.push(format!(
                    "duration {} {ms} ms",
                    if slower { "over" } else { "under" }
                ));
            }
            for found in take(&SIZE, &mut part) {
                let value: f64 = found[2].parse().unwrap_or(0.0);
                let bytes = to_bytes(value, &found[3]);
                let larger = matches!(
                    found[1].to_ascii_lowercase().as_str(),
                    "larger" | "bigger" | "greater"
                );
                add(
                    &mut segment.filters,
                    "response_size",
                    int_filter(if larger { "gt" } else { "lt" }, bytes),
                );
                segment.says.push(format!(
                    "response size {} {bytes} bytes",
                    if larger { "over" } else { "under" }
                ));
                draft
                    .assumptions
                    .push("KB and MB are taken as 1024 and 1048576 bytes".to_owned());
            }
            for found in take(&MIME, &mut part) {
                let kind = found[1].to_ascii_lowercase();
                let value = if kind.starts_with("plain") {
                    "text/plain".to_owned()
                } else {
                    kind
                };
                add(
                    &mut segment.filters,
                    "mime_type",
                    text_filter("contains", &value),
                );
                segment
                    .says
                    .push(format!("content type contains “{value}”"));
            }
            for found in take(&HEADER, &mut part) {
                let field = if found[1].eq_ignore_ascii_case("request") {
                    "request_header"
                } else {
                    "response_header"
                };
                segment.filters.insert(
                    field.to_owned(),
                    json!({"key": found[2].to_ascii_lowercase(), "value": found[3]}),
                );
                segment
                    .says
                    .push(format!("{field} {} is “{}”", found[2], found[3]));
                if found[1].is_empty() {
                    draft.assumptions.push(
                        "a header with no side named is read as a response header".to_owned(),
                    );
                }
            }
            for found in take(&CORRELATION, &mut part) {
                let field = match found[1].to_ascii_lowercase().chars().next() {
                    Some('c') => "correlation_id",
                    Some('a') => "account_id",
                    _ => "tool_call_id",
                };
                add(&mut segment.filters, field, text_filter("exact", &found[2]));
                segment.says.push(format!("{field} is “{}”", found[2]));
            }
        } else {
            for found in take(&DIRECTION, &mut part) {
                let incoming = matches!(
                    found[1].to_ascii_lowercase().as_str(),
                    "incoming" | "server-to-client" | "server to client" | "s2c"
                );
                add(
                    &mut segment.filters,
                    "direction",
                    text_filter("exact", if incoming { "s2c" } else { "c2s" }),
                );
                segment.says.push(format!(
                    "direction {}",
                    if incoming { "s2c" } else { "c2s" }
                ));
            }
            for found in take(&CLOSE_CODE, &mut part) {
                add(
                    &mut segment.filters,
                    "close_code",
                    int_filter("exact", found[1].parse().unwrap_or(0)),
                );
                segment.says.push(format!("close code {}", found[1]));
            }
        }
        for found in take(&SOURCE, &mut part) {
            let value = json!(found[1]);
            segment.filters.insert(
                "source_id".to_owned(),
                if ws { value } else { json!([found[1]]) },
            );
            segment.says.push(format!("source_id is “{}”", found[1]));
        }
        for found in take(&PATH, &mut part) {
            if ws {
                draft.unsupported.push(format!(
                    "a path filter (“{}”) does not apply to WebSocket messages",
                    found[0].trim()
                ));
                continue;
            }
            let value = if found[1].is_empty() {
                &found[2]
            } else {
                &found[1]
            };
            add(&mut segment.filters, "path", text_filter("contains", value));
            segment.says.push(format!("path contains “{value}”"));
            draft.assumptions.push(
                "a path is matched as a substring: the query language has no prefix operator"
                    .to_owned(),
            );
        }
        for found in take(&HOST, &mut part) {
            let host = found[1]
                .trim_start_matches('*')
                .trim_start_matches('.')
                .to_ascii_lowercase();
            add(&mut segment.filters, "host", text_filter("contains", &host));
            segment.says.push(format!("host contains “{host}”"));
            draft
                .assumptions
                .push("a host is matched as a case-insensitive substring".to_owned());
        }
        let leftover: Vec<String> = part
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-' || c == '§'))
            .filter(|word| !word.is_empty() && !word.starts_with('§'))
            .filter(|word| !STOP_WORDS.contains(&word.to_ascii_lowercase().as_str()))
            .map(str::to_owned)
            .collect();
        leftovers.extend(leftover);
        if !segment.filters.is_empty() || !segment.says.is_empty() {
            draft.explanation.push(format!(
                "Branch {}: {}",
                draft.branches.len() + 1,
                segment.says.join("; ")
            ));
            draft.branches.push(segment.filters);
        }
    }
    if !leftovers.is_empty() {
        let shown: String = leftovers.join(" ").chars().take(120).collect();
        draft
            .unsupported
            .push(format!("not understood: “{shown}”; it was not applied"));
    }
    if draft.branches.is_empty() {
        draft.branches.push(Map::new());
        draft.assumptions.push(
            "no filter was recognized: the branch matches every capture in the scope".to_owned(),
        );
    }
    draft.assumptions.sort();
    draft.assumptions.dedup();
}

fn body_field(side: &str, ws: bool) -> &'static str {
    if ws {
        "payload"
    } else if side.eq_ignore_ascii_case("request") {
        "request_body"
    } else {
        "response_body"
    }
}

fn walk(value: &Value, in_body: bool, cost: &mut Cost, regexes: &mut Vec<usize>) {
    match value {
        Value::Object(map) => {
            if let (Some("regex_match"), Some(pattern)) = (
                map.get("op").and_then(Value::as_str),
                map.get("value").and_then(Value::as_str),
            ) {
                cost.regex = true;
                regexes.push(pattern.len());
            }
            if map.get("op").is_some() && in_body {
                cost.body_scan = true;
            }
            for (key, member) in map {
                let body =
                    in_body || matches!(key.as_str(), "request_body" | "response_body" | "payload");
                walk(member, body, cost, regexes);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| walk(item, in_body, cost, regexes)),
        _ => {}
    }
}

/// Estimate what running `branches` costs. A body scan reads the wide columns; a regex adds work.
pub fn cost(branches: &Value) -> (Cost, Vec<usize>) {
    let mut cost = Cost {
        level: "cheap",
        body_scan: false,
        regex: false,
        reasons: Vec::new(),
    };
    let mut regexes = Vec::new();
    walk(branches, false, &mut cost, &mut regexes);
    if cost.body_scan {
        cost.level = "expensive";
        cost.reasons.push(
            "filters on a body or payload read the wide body columns: the slowest queries"
                .to_owned(),
        );
    }
    if cost.regex {
        if cost.level == "cheap" {
            cost.level = "moderate";
        }
        cost.reasons
            .push("a regular expression is evaluated for every candidate row".to_owned());
    }
    if cost.reasons.is_empty() {
        cost.reasons
            .push("filters on indexed or small columns only".to_owned());
    }
    (cost, regexes)
}

/// What the operator's settings forbid for a query of this cost.
pub fn blocked_by(
    cost: &Cost,
    regex_lengths: &[usize],
    config: &QueryAnalysisConfig,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if cost.body_scan && !config.allow_body_scan {
        blockers.push(
            "body and payload filters are off: an operator sets analysis.query.allow_body_scan"
                .to_owned(),
        );
    }
    if cost.regex && !config.allow_regex {
        blockers.push(
            "regular expressions are off: an operator sets analysis.query.allow_regex".to_owned(),
        );
    }
    if regex_lengths
        .iter()
        .any(|len| *len > config.max_regex_bytes)
    {
        blockers.push(format!(
            "a regular expression is longer than analysis.query.max_regex_bytes ({})",
            config.max_regex_bytes
        ));
    }
    blockers
}

/// The digest that names a draft: the org, the protocol and the scope-constrained branches.
pub fn digest(org: &str, ws: bool, branches: &Value) -> String {
    sha256_hex(&canonical_json(&json!({
        "org": org,
        "protocol": if ws { "ws" } else { "http" },
        "branches": branches,
    })))
}

/// The JSON schema a model must answer with for a query draft.
pub fn model_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "branches": {"type": "array", "maxItems": 8, "items": {"type": "object"}},
            "explanation": {"type": "string", "maxLength": 600},
            "assumptions": {"type": "array", "maxItems": 6, "items": {"type": "string", "maxLength": 200}},
            "unsupported_clauses": {"type": "array", "maxItems": 6, "items": {"type": "string", "maxLength": 200}}
        },
        "required": ["branches", "explanation", "assumptions", "unsupported_clauses"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branches(request: &str, ws: bool) -> (Value, Draft) {
        let draft = compile(request, ws);
        (
            Value::Array(draft.branches.iter().cloned().map(Value::Object).collect()),
            draft,
        )
    }

    #[test]
    fn golden_questions_map_to_exact_filters() {
        let (b, d) = branches(
            "show me POST requests to api.example.com with status 401 or 403",
            false,
        );
        assert!(d.unsupported.is_empty(), "{:?}", d.unsupported);
        assert_eq!(
            b,
            json!([{
                "method": {"op": "exact", "value": "POST"},
                "status_code": {"op": "any", "filters": [{"op": "exact", "value": 401}, {"op": "exact", "value": 403}]},
                "host": {"op": "contains", "value": "api.example.com"}
            }])
        );
        let (b, _) = branches("server errors slower than 2 seconds", false);
        assert_eq!(
            b,
            json!([{"status_code": {"op": "gte", "value": 500}, "duration_ms": {"op": "gt", "value": 2000}}])
        );
        let (b, _) = branches("responses that set cookies; rate limited requests", false);
        assert_eq!(
            b,
            json!([{"response_sets_cookies": true}, {"status_code": {"op": "exact", "value": 429}}])
        );
        let (b, _) = branches("5xx responses with path containing /api/login", false);
        assert_eq!(
            b,
            json!([{"status_code": {"op": "all", "filters": [{"op": "gte", "value": 500}, {"op": "lt", "value": 600}]}, "path": {"op": "contains", "value": "/api/login"}}])
        );
        let (b, _) = branches("response header server is nginx", false);
        assert_eq!(
            b,
            json!([{"response_header": {"key": "server", "value": "nginx"}}])
        );
    }

    #[test]
    fn time_and_unknown_phrases_make_the_draft_non_executable() {
        let (_, d) = branches("errors in the last hour", false);
        assert!(
            d.unsupported.iter().any(|u| u.contains("no time field")),
            "{:?}",
            d.unsupported
        );
        let (_, d) = branches("requests that look suspicious", false);
        assert!(
            d.unsupported.iter().any(|u| u.contains("suspicious")),
            "{:?}",
            d.unsupported
        );
    }

    #[test]
    fn websocket_questions_use_websocket_fields() {
        let (b, d) = branches(
            "incoming messages with payload containing \"ping\" on echo.example.com",
            true,
        );
        assert!(d.unsupported.is_empty(), "{:?}", d.unsupported);
        assert_eq!(
            b,
            json!([{
                "direction": {"op": "exact", "value": "s2c"},
                "payload": {"op": "contains", "value": "ping"},
                "host": {"op": "contains", "value": "echo.example.com"}
            }])
        );
        let (_, d) = branches("status 500", true);
        assert!(!d.unsupported.is_empty());
    }

    #[test]
    fn cost_names_body_scans_and_regexes() {
        let (c, _) = cost(&json!([{"host": {"op": "contains", "value": "a"}}]));
        assert_eq!(c.level, "cheap");
        let (c, lengths) = cost(&json!([{"response_body": {"op": "regex_match", "value": "ab+"}}]));
        assert_eq!(
            (c.level, c.body_scan, c.regex, lengths),
            ("expensive", true, true, vec![3])
        );
        let (c, _) = cost(&json!([{"path": {"op": "regex_match", "value": "ab+"}}]));
        assert_eq!((c.level, c.body_scan), ("moderate", false));
    }
}
