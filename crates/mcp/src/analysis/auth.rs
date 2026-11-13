//! Authentication and session-flow discovery over captured exchanges.
//!
//! The extractor reads how requests authenticate (the `Authorization` scheme, cookies, API-key and
//! CSRF headers, token members in JSON and form bodies, credentials in a URL), how sessions are
//! issued (`Set-Cookie`, token members in responses) and how they end (cookie deletion,
//! replacement by a newer value). Every credential value becomes an engagement-local keyed
//! fingerprint at once; no value is kept, returned, audited or sent to a model. Decoding a token
//! structure never verifies it: a decoded claim is not an identity.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    Body, Evidence, Fingerprinter, Side, body_of, header, headers_of, media_type, safe_name,
};

/// The version of the extraction rules, reported with every result.
pub const DETECTOR_VERSION: &str = "auth-flows-1";

/// Most edges listed in a result.
const MAX_EDGES: usize = 200;

/// Settings of one analysis.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub max_candidates: usize,
    pub include_claim_names: bool,
}

/// What the extractor found.
#[derive(Debug, Default)]
pub struct Report {
    pub mechanisms: Vec<Value>,
    pub cookie_findings: Vec<Value>,
    pub flow_edges: Vec<Value>,
    pub hypotheses: Vec<Value>,
    pub incomplete: Vec<String>,
}

impl Report {
    pub fn to_json(&self) -> Value {
        json!({
            "mechanisms": self.mechanisms,
            "cookie_findings": self.cookie_findings,
            "flow_edges": self.flow_edges,
            "hypotheses": self.hypotheses,
            "completeness": {
                "complete": self.incomplete.is_empty(),
                "reasons": self.incomplete,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Slot(String);

#[derive(Debug)]
struct Token {
    label: String,
    kind: &'static str,
    name: String,
    jwt: Option<Value>,
    issued: Vec<(usize, String, String)>,
    sent: Vec<(usize, String, String)>,
    origins: BTreeSet<String>,
    /// Every `carrier:name` this value was seen in.
    carriers: BTreeSet<String>,
    replaced_by: Option<String>,
    cleared_by: Option<String>,
}

#[derive(Debug, Default)]
struct CookieSeen {
    name: String,
    domain: String,
    path: String,
    host_only: bool,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    persistent: bool,
    https: bool,
    observations: usize,
    deleted: bool,
    evidence: Vec<String>,
}

/// Where one value was seen.
struct Sighting<'a> {
    capture: usize,
    id: &'a str,
    origin: &'a str,
}

#[derive(Debug, Default)]
struct MechanismSeen {
    names: BTreeSet<String>,
    origins: BTreeSet<String>,
    captures: BTreeSet<usize>,
    evidence: Vec<String>,
    notes: BTreeSet<String>,
}

/// A name that holds a credential or session value.
fn credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let compact: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if compact.contains("password") || compact.ends_with("passwd") || compact == "pwd" {
        return false;
    }
    compact.ends_with("token")
        || compact.contains("apikey")
        || compact.contains("sessionid")
        || matches!(
            compact.as_str(),
            "sid" | "jwt" | "auth" | "session" | "bearer" | "idtoken" | "sessiontoken"
        )
}

fn csrf_name(name: &str) -> bool {
    let compact: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    compact.contains("csrf") || compact.contains("xsrf") || compact == "authenticitytoken"
}

fn password_name(name: &str) -> bool {
    let compact: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    compact.contains("password") || compact.ends_with("passwd") || compact == "pwd"
}

fn session_like_cookie(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    credential_name(name)
        || csrf_name(name)
        || ["sess", "auth", "login", "user", "jwt", "sid"]
            .iter()
            .any(|needle| lower.contains(needle))
}

fn origin_of(item: &Value) -> String {
    format!(
        "{}://{}",
        item["scheme"].as_str().unwrap_or("https"),
        item["host"].as_str().unwrap_or("").to_ascii_lowercase()
    )
}

/// The structure of a JWT-shaped value, decoded locally and not verified.
fn jwt_shape(value: &str, include_claims: bool) -> Option<Value> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 || parts.iter().take(2).any(|part| part.len() < 4) {
        return None;
    }
    let decode = |part: &str| -> Option<Value> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part.trim_end_matches('='))
            .ok()?;
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .filter(Value::is_object)
    };
    let header = decode(parts[0])?;
    let claims = decode(parts[1])?;
    let alg = header["alg"]
        .as_str()
        .filter(|alg| {
            (2..=16).contains(&alg.len())
                && alg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or("other");
    let numeric = |name: &str| claims.get(name).and_then(Value::as_i64);
    let lifetime = match (numeric("iat"), numeric("exp")) {
        (Some(issued), Some(expires)) if expires > issued => Some(match expires - issued {
            0..=3_600 => "up_to_1h",
            3_601..=86_400 => "up_to_1d",
            _ => "over_1d",
        }),
        _ => None,
    };
    let mut shape = json!({
        "format": "jwt",
        "alg": alg,
        "has_signature_part": !parts[2].is_empty(),
        "has_exp": claims.get("exp").is_some(),
        "has_iat": claims.get("iat").is_some(),
        "has_nbf": claims.get("nbf").is_some(),
        "lifetime_class": lifetime,
        "verified": false,
        "note": "Decoded locally without verifying the signature. Claims are attacker-controlled input, not an identity.",
    });
    if include_claims {
        let mut names: Vec<String> = claims
            .as_object()
            .map(|map| {
                map.keys()
                    .filter(|name| {
                        name.len() <= 40
                            && name.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')
                            })
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names.truncate(30);
        shape["claim_names"] = json!(names);
    }
    Some(shape)
}

/// The members of a JSON document that look like credentials: `(pointer, name, value)`.
fn walk_members(value: &Value, path: &str, depth: usize, out: &mut Vec<(String, String, String)>) {
    if depth > 8 || out.len() > 200 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (name, member) in map {
                let here = format!("{path}/{}", safe_name(name));
                match member {
                    Value::String(text) => out.push((here, name.clone(), text.clone())),
                    other => walk_members(other, &here, depth + 1, out),
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(20) {
                walk_members(item, &format!("{path}/*"), depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Members of a request or response body: JSON members or form fields.
fn body_members(text: &str, content_type: &str) -> (Vec<(String, String, String)>, bool) {
    let trimmed = text.trim_start();
    let mut out = Vec::new();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return match serde_json::from_str::<Value>(text) {
            Ok(value) => {
                walk_members(&value, "", 0, &mut out);
                (out, false)
            }
            Err(_) => (out, true),
        };
    }
    if content_type.contains("x-www-form-urlencoded")
        && let Ok(url) = reqwest::Url::parse(&format!("http://form.invalid/?{text}"))
    {
        for (name, value) in url.query_pairs() {
            out.push((
                format!("/{}", safe_name(&name)),
                name.into_owned(),
                value.into_owned(),
            ));
        }
    }
    (out, false)
}

fn query_pairs(path: &str) -> Vec<(String, String)> {
    match path.split_once('?') {
        Some((_, query)) => reqwest::Url::parse(&format!("http://query.invalid/?{query}"))
            .map(|url| {
                url.query_pairs()
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect()
            })
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

/// The default cookie path of a request path.
fn default_cookie_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("/");
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(end) => path[..end].to_owned(),
    }
}

struct SetCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    persistent: bool,
    deletes: bool,
}

fn parse_set_cookie(line: &str) -> Option<SetCookie> {
    let mut parts = line.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = SetCookie {
        name: name.to_owned(),
        value: value.trim().to_owned(),
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: None,
        persistent: false,
        deletes: false,
    };
    for attribute in parts {
        let (key, value) = attribute
            .split_once('=')
            .map_or((attribute.trim(), ""), |(k, v)| (k.trim(), v.trim()));
        match key.to_ascii_lowercase().as_str() {
            "domain" => {
                cookie.domain = Some(value.trim_start_matches('.').to_ascii_lowercase());
            }
            "path" => cookie.path = Some(value.to_owned()),
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(value.to_ascii_lowercase()),
            "max-age" => {
                cookie.persistent = true;
                if value.parse::<i64>().is_ok_and(|age| age <= 0) {
                    cookie.deletes = true;
                }
            }
            "expires" => {
                cookie.persistent = true;
                let old = value
                    .split(|c: char| !c.is_ascii_digit())
                    .filter(|part| part.len() == 4)
                    .filter_map(|part| part.parse::<u32>().ok())
                    .any(|year| year <= 1999);
                if old {
                    cookie.deletes = true;
                }
            }
            _ => {}
        }
    }
    if cookie.value.is_empty() {
        cookie.deletes = true;
    }
    Some(cookie)
}

struct Tracker<'a> {
    fp: &'a Fingerprinter,
    options: Options,
    tokens: BTreeMap<String, Token>,
    slots: BTreeMap<Slot, String>,
    cookies: BTreeMap<(String, String, String), CookieSeen>,
    mechanisms: BTreeMap<(String, String), MechanismSeen>,
    report: Report,
    capped: bool,
}

impl Tracker<'_> {
    fn mechanism(
        &mut self,
        kind: &str,
        side: &str,
        name: &str,
        at: &Sighting<'_>,
        evidence: &str,
        note: Option<&str>,
    ) {
        let (origin, capture) = (at.origin, at.capture);
        let seen = self
            .mechanisms
            .entry((kind.to_owned(), side.to_owned()))
            .or_default();
        seen.names.insert(safe_name(name).to_owned());
        seen.origins.insert(origin.to_owned());
        seen.captures.insert(capture);
        if seen.evidence.len() < 5 && !seen.evidence.iter().any(|id| id == evidence) {
            seen.evidence.push(evidence.to_owned());
        }
        if let Some(note) = note {
            seen.notes.insert(note.to_owned());
        }
    }

    fn token(&mut self, kind: &'static str, name: &str, value: &str) -> Option<String> {
        let label = self.fp.label(value);
        if !self.tokens.contains_key(&label) {
            if self.tokens.len() >= self.options.max_candidates {
                if !self.capped {
                    self.capped = true;
                    self.report.incomplete.push(
                        "the token candidate limit was reached; later values were not tracked"
                            .to_owned(),
                    );
                }
                return None;
            }
            self.tokens.insert(
                label.clone(),
                Token {
                    label: label.clone(),
                    kind,
                    name: safe_name(name).to_owned(),
                    jwt: jwt_shape(
                        value.strip_prefix("Bearer ").unwrap_or(value),
                        self.options.include_claim_names,
                    ),
                    issued: Vec::new(),
                    sent: Vec::new(),
                    origins: BTreeSet::new(),
                    carriers: BTreeSet::new(),
                    replaced_by: None,
                    cleared_by: None,
                },
            );
        }
        Some(label)
    }

    fn sent(
        &mut self,
        kind: &'static str,
        name: &str,
        value: &str,
        at: &Sighting<'_>,
        evidence: &str,
    ) {
        if let Some(label) = self.token(kind, name, value)
            && let Some(token) = self.tokens.get_mut(&label)
        {
            token
                .sent
                .push((at.capture, at.id.to_owned(), evidence.to_owned()));
            token.origins.insert(at.origin.to_owned());
            token.carriers.insert(format!("{kind}:{name}"));
        }
    }

    fn issued(
        &mut self,
        kind: &'static str,
        name: &str,
        value: &str,
        slot: Slot,
        at: &Sighting<'_>,
        evidence: &str,
    ) -> Option<String> {
        let label = self.token(kind, name, value)?;
        if let Some(token) = self.tokens.get_mut(&label) {
            token
                .issued
                .push((at.capture, at.id.to_owned(), evidence.to_owned()));
            token.carriers.insert(format!("{kind}:{name}"));
        }
        match self.slots.insert(slot, label.clone()) {
            Some(previous) if previous != label => {
                if let Some(old) = self.tokens.get_mut(&previous)
                    && old.replaced_by.is_none()
                {
                    old.replaced_by = Some(label.clone());
                }
            }
            _ => {}
        }
        Some(label)
    }
}

/// Analyse captures, oldest first.
pub fn analyze(
    items: &[Value],
    fp: &Fingerprinter,
    evidence: &mut Evidence,
    options: Options,
) -> Report {
    let mut tracker = Tracker {
        fp,
        options,
        tokens: BTreeMap::new(),
        slots: BTreeMap::new(),
        cookies: BTreeMap::new(),
        mechanisms: BTreeMap::new(),
        report: Report::default(),
        capped: false,
    };
    let mut truncated_bodies = 0_usize;
    let mut unreadable_json = 0_usize;
    for (index, item) in items.iter().enumerate() {
        let id = item["id"].as_str().unwrap_or("");
        let origin = origin_of(item);
        let at = Sighting {
            capture: index,
            id,
            origin: &origin,
        };
        let https = item["scheme"].as_str().unwrap_or("https") == "https";
        let host = item["host"].as_str().unwrap_or("").to_ascii_lowercase();
        let host = host.split(':').next().unwrap_or("").to_owned();
        let path = item["path"].as_str().unwrap_or("/");
        let request_headers = headers_of(&item["request_headers"]);
        let response_headers = headers_of(&item["response_headers"]);

        // --- request side
        for (name, value) in query_pairs(path) {
            if credential_name(&name) || csrf_name(&name) {
                let location = format!("query:{}", safe_name(&name));
                let ev = evidence.add(fp, id, Side::Request, &location, &value);
                tracker.mechanism(
                    "token_in_url",
                    "request",
                    &name,
                    &at,
                    &ev,
                    Some("a credential in a URL is logged by proxies and servers"),
                );
                tracker.sent("query_param", &name, &value, &at, &ev);
            }
        }
        if let Some(value) = header(&request_headers, "authorization") {
            let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
            let scheme = scheme.to_ascii_lowercase();
            let location = "header:authorization";
            let ev = evidence.add(fp, id, Side::Request, location, value);
            let kind = match scheme.as_str() {
                "bearer" => "bearer",
                "basic" => "basic",
                "digest" => "digest",
                _ => "authorization_other",
            };
            let shape = (kind == "bearer")
                .then(|| jwt_shape(rest, options.include_claim_names))
                .flatten();
            let note = shape.as_ref().map(|_| "bearer value is JWT-shaped");
            tracker.mechanism(kind, "request", "authorization", &at, &ev, note);
            if scheme != "digest" {
                tracker.sent("authorization", "authorization", rest, &at, &ev);
            }
        }
        if let Some(value) = header(&request_headers, "cookie") {
            for pair in value.split(';') {
                let Some((name, cookie_value)) = pair.split_once('=') else {
                    continue;
                };
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                let location = format!("header:cookie:{}", safe_name(name));
                let cookie_value = cookie_value.trim();
                let known = tracker.tokens.contains_key(&fp.label(cookie_value));
                if !session_like_cookie(name) && !known {
                    continue;
                }
                let ev = evidence.add(fp, id, Side::Request, &location, cookie_value);
                tracker.mechanism("cookie", "request", name, &at, &ev, None);
                tracker.sent("cookie", name, cookie_value, &at, &ev);
            }
        }
        for (name, value) in &request_headers {
            if name == "authorization" || name == "cookie" || name.starts_with("proxy-") {
                continue;
            }
            let csrf = csrf_name(name);
            if csrf || credential_name(name) || name == "x-api-key" {
                let location = format!("header:{}", safe_name(name));
                let ev = evidence.add(fp, id, Side::Request, &location, value);
                let kind = if csrf {
                    "csrf_header"
                } else {
                    "api_key_header"
                };
                tracker.mechanism(kind, "request", name, &at, &ev, None);
                tracker.sent("header", name, value, &at, &ev);
            }
        }
        match body_of(&item["request_body"]) {
            Body::Text(text) => {
                let (members, broken) = body_members(&text, &media_type(&request_headers));
                if broken {
                    unreadable_json += 1;
                }
                for (pointer, name, value) in members {
                    if password_name(&name) {
                        let ev =
                            evidence.add(fp, id, Side::Request, &format!("body:{pointer}"), "");
                        tracker.mechanism(
                            "password_login",
                            "request",
                            &name,
                            &at,
                            &ev,
                            Some("a password field is present; its value is never read"),
                        );
                    } else if csrf_name(&name) {
                        let ev =
                            evidence.add(fp, id, Side::Request, &format!("body:{pointer}"), &value);
                        tracker.mechanism("csrf_body_field", "request", &name, &at, &ev, None);
                        tracker.sent("body_member", &name, &value, &at, &ev);
                    } else if credential_name(&name) {
                        let ev =
                            evidence.add(fp, id, Side::Request, &format!("body:{pointer}"), &value);
                        tracker.mechanism("token_in_body", "request", &name, &at, &ev, None);
                        tracker.sent("body_member", &name, &value, &at, &ev);
                    }
                }
            }
            Body::TooLarge => truncated_bodies += 1,
            Body::Absent => {}
        }

        // --- response side
        if let Some(value) = header(&response_headers, "www-authenticate") {
            let scheme = value
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !scheme.is_empty()
            {
                let ev = evidence.add(fp, id, Side::Response, "header:www-authenticate", &scheme);
                tracker.mechanism("www_authenticate", "response", &scheme, &at, &ev, None);
            }
        }
        for (name, line) in &response_headers {
            if name != "set-cookie" {
                if (credential_name(name) || csrf_name(name)) && name != "www-authenticate" {
                    let location = format!("header:{}", safe_name(name));
                    let ev = evidence.add(fp, id, Side::Response, &location, line);
                    let slot = Slot(format!("header:{name}:{origin}"));
                    tracker.mechanism("token_in_response_header", "response", name, &at, &ev, None);
                    tracker.issued("header", name, line, slot, &at, &ev);
                }
                continue;
            }
            let Some(cookie) = parse_set_cookie(line) else {
                continue;
            };
            let domain = cookie.domain.clone().unwrap_or_else(|| host.clone());
            let cookie_path = cookie
                .path
                .clone()
                .unwrap_or_else(|| default_cookie_path(path));
            let location = format!("header:set-cookie:{}", safe_name(&cookie.name));
            let ev = evidence.add(fp, id, Side::Response, &location, &cookie.value);
            let key = (cookie.name.clone(), domain.clone(), cookie_path.clone());
            let seen = tracker.cookies.entry(key.clone()).or_default();
            seen.name = safe_name(&cookie.name).to_owned();
            seen.domain = domain.clone();
            seen.path = cookie_path.clone();
            seen.host_only = cookie.domain.is_none();
            seen.secure = cookie.secure;
            seen.http_only = cookie.http_only;
            seen.same_site = cookie.same_site.clone();
            seen.persistent = cookie.persistent;
            seen.https = https;
            seen.observations += 1;
            seen.deleted = cookie.deletes;
            if seen.evidence.len() < 5 {
                seen.evidence.push(ev.clone());
            }
            let slot = Slot(format!("cookie:{}:{domain}:{cookie_path}", cookie.name));
            if cookie.deletes {
                if let Some(previous) = tracker.slots.remove(&slot)
                    && let Some(token) = tracker.tokens.get_mut(&previous)
                {
                    token.cleared_by = Some(ev.clone());
                }
                tracker.mechanism("cookie_cleared", "response", &cookie.name, &at, &ev, None);
            } else {
                if session_like_cookie(&cookie.name) {
                    tracker.mechanism("cookie_issued", "response", &cookie.name, &at, &ev, None);
                }
                tracker.issued("cookie", &cookie.name, &cookie.value, slot, &at, &ev);
            }
        }
        match body_of(&item["response_body"]) {
            Body::Text(text) => {
                let (members, broken) = body_members(&text, &media_type(&response_headers));
                if broken {
                    unreadable_json += 1;
                }
                for (pointer, name, value) in members {
                    if !(credential_name(&name) || csrf_name(&name)) || value.is_empty() {
                        continue;
                    }
                    let ev =
                        evidence.add(fp, id, Side::Response, &format!("body:{pointer}"), &value);
                    let kind = if csrf_name(&name) {
                        "csrf_body_field"
                    } else {
                        "token_in_body"
                    };
                    tracker.mechanism(kind, "response", &name, &at, &ev, None);
                    let slot = Slot(format!("body:{pointer}:{origin}"));
                    tracker.issued("body_member", &name, &value, slot, &at, &ev);
                }
            }
            Body::TooLarge => truncated_bodies += 1,
            Body::Absent => {}
        }
    }
    if truncated_bodies > 0 {
        tracker.report.incomplete.push(format!(
            "{truncated_bodies} bodies were larger than the fetch cap and were not read; token members in them are missing"
        ));
    }
    if unreadable_json > 0 {
        tracker.report.incomplete.push(format!(
            "{unreadable_json} JSON bodies could not be parsed (cut or malformed); their members are missing"
        ));
    }
    finish(tracker, items)
}

fn finish(mut tracker: Tracker<'_>, items: &[Value]) -> Report {
    let mut edges: Vec<Value> = Vec::new();
    let mut hypotheses: Vec<Value> = Vec::new();
    for token in tracker.tokens.values() {
        let interesting =
            !token.issued.is_empty() || token.kind != "cookie" || session_like_cookie(&token.name);
        if !interesting {
            continue;
        }
        let capture_id = |index: usize| items[index]["id"].as_str().unwrap_or("").to_owned();
        let sent_ev: Vec<&str> = token
            .sent
            .iter()
            .map(|(_, _, ev)| ev.as_str())
            .take(3)
            .collect();
        match (token.issued.first(), token.sent.is_empty()) {
            (Some((index, _, issued_ev)), false) => edges.push(json!({
                "kind": "issued_then_sent",
                "token_fingerprint": token.label,
                "carrier": token.kind,
                "name": token.name,
                "issued_in": capture_id(*index),
                "issued_evidence": issued_ev,
                "sent_count": token.sent.len(),
                "sent_evidence": sent_ev,
                "origins": token.origins,
                "format": token.jwt,
            })),
            (None, false) => edges.push(json!({
                "kind": "sent_without_observed_issue",
                "token_fingerprint": token.label,
                "carrier": token.kind,
                "name": token.name,
                "sent_count": token.sent.len(),
                "sent_evidence": sent_ev,
                "origins": token.origins,
                "format": token.jwt,
                "note": "no capture in this sample issued this value; it may predate the sample",
            })),
            _ => {}
        }
        if let Some(next) = &token.replaced_by {
            edges.push(json!({
                "kind": "replaced_by",
                "token_fingerprint": token.label,
                "replaced_by": next,
                "name": token.name,
                "issued_evidence": token.issued.first().map(|(_, _, ev)| ev),
            }));
            let lower = token.name.to_ascii_lowercase();
            if lower.contains("refresh") || lower.contains("access") {
                hypotheses.push(json!({
                    "statement": format!("The value of `{}` is replaced by a newer one during the sample (rotation or refresh).", token.name),
                    "basis": "observed",
                    "evidence": token.issued.first().map(|(_, _, ev)| ev),
                }));
            }
        }
        if let Some(cleared) = &token.cleared_by {
            edges.push(json!({
                "kind": "cleared_by",
                "token_fingerprint": token.label,
                "name": token.name,
                "cleared_evidence": cleared,
                "note": "a Set-Cookie deleted this cookie (an empty value or an expiry in the past)",
            }));
            hypotheses.push(json!({
                "statement": format!("Cookie `{}` is cleared by the server, which is how this application ends a session.", token.name),
                "basis": "observed",
                "evidence": [cleared],
            }));
        }
        if token.origins.len() > 1 {
            edges.push(json!({
                "kind": "reused_across_origins",
                "token_fingerprint": token.label,
                "name": token.name,
                "origins": token.origins,
                "sent_evidence": sent_ev,
                "note": "the same credential value was sent to more than one origin inside the scope. This is an observation, not a claim of exploitability.",
            }));
        }
        // double submit: one value carried by a cookie and by a CSRF header or field
        let in_cookie = token.carriers.iter().any(|c| c.starts_with("cookie:"));
        let csrf_carrier = token.carriers.iter().find(|c| {
            !c.starts_with("cookie:") && csrf_name(c.split_once(':').map_or("", |(_, n)| n))
        });
        if let (true, Some(carrier)) = (in_cookie, csrf_carrier) {
            hypotheses.push(json!({
                "statement": format!("A CSRF value is carried both in a cookie and in `{}` (a double-submit pattern).", carrier.split_once(':').map_or("", |(_, n)| n)),
                "basis": "observed",
                "evidence": sent_ev,
            }));
        }
    }
    edges.truncate(MAX_EDGES);
    let mut findings: Vec<Value> = Vec::new();
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    for seen in tracker.cookies.values() {
        *names.entry(seen.name.as_str()).or_insert(0) += 1;
    }
    for seen in tracker.cookies.values() {
        if seen.deleted {
            findings.push(json!({
                "cookie_name": seen.name, "domain": seen.domain, "path": seen.path,
                "finding": "deleted_by_server", "severity": "info",
                "evidence": seen.evidence,
            }));
            continue;
        }
        let mut problems: Vec<(&str, &str)> = Vec::new();
        if !seen.secure && seen.https {
            problems.push(("missing_secure", "low"));
        }
        if !seen.http_only {
            problems.push(("missing_httponly", "low"));
        }
        match seen.same_site.as_deref() {
            None => problems.push(("samesite_not_set", "info")),
            Some("none") if !seen.secure => {
                problems.push(("samesite_none_without_secure", "medium"));
            }
            _ => {}
        }
        for (finding, severity) in problems {
            findings.push(json!({
                "cookie_name": seen.name,
                "domain": seen.domain,
                "path": seen.path,
                "host_only": seen.host_only,
                "finding": finding,
                "severity": severity,
                "persistent": seen.persistent,
                "observations": seen.observations,
                "context": "an attribute missing from the observed Set-Cookie header; whether it matters depends on the application",
                "evidence": seen.evidence,
            }));
        }
        if names.get(seen.name.as_str()).copied().unwrap_or(0) > 1 {
            findings.push(json!({
                "cookie_name": seen.name,
                "domain": seen.domain,
                "path": seen.path,
                "finding": "same_name_in_several_scopes",
                "severity": "info",
                "context": "cookies of one name with different domain or path are separate cookies",
                "evidence": seen.evidence,
            }));
        }
    }
    for ((kind, side), seen) in &tracker.mechanisms {
        tracker.report.mechanisms.push(json!({
            "mechanism": kind,
            "side": side,
            "names": seen.names,
            "origins": seen.origins,
            "captures": seen.captures.len(),
            "evidence": seen.evidence,
            "notes": seen.notes,
        }));
        if kind == "cookie_issued" {
            hypotheses.push(json!({
                "statement": format!(
                    "The server issues session cookies ({}).",
                    seen.names.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                "basis": "observed",
                "evidence": seen.evidence.first(),
            }));
        }
    }
    tracker.report.cookie_findings = findings;
    tracker.report.flow_edges = edges;
    tracker.report.hypotheses = hypotheses;
    tracker.report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_shape_is_structural_and_unverified() {
        let enc = |value: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        let token = format!(
            "{}.{}.sig",
            enc(&json!({"alg": "HS256", "typ": "JWT"})),
            enc(&json!({"sub": "user-1", "exp": 2000, "iat": 1000, "role": "admin"}))
        );
        let shape = jwt_shape(&token, false).expect("jwt");
        assert_eq!(shape["verified"], false);
        assert_eq!(shape["alg"], "HS256");
        assert_eq!(shape["lifetime_class"], "up_to_1h");
        assert!(shape.get("claim_names").is_none());
        assert!(!shape.to_string().contains("user-1"));
        let named = jwt_shape(&token, true).expect("jwt");
        assert_eq!(named["claim_names"], json!(["exp", "iat", "role", "sub"]));
        assert!(jwt_shape("a.b.c", false).is_none());
        assert!(jwt_shape("not-a-jwt", false).is_none());
    }

    #[test]
    fn set_cookie_attributes_and_deletion() {
        let cookie =
            parse_set_cookie("sid=abc; Path=/app; Secure; HttpOnly; SameSite=Lax; Max-Age=3600")
                .expect("cookie");
        assert!(cookie.secure && cookie.http_only && !cookie.deletes && cookie.persistent);
        assert_eq!(cookie.path.as_deref(), Some("/app"));
        assert!(parse_set_cookie("sid=; Path=/").expect("empty").deletes);
        assert!(parse_set_cookie("sid=x; Max-Age=0").expect("zero").deletes);
        assert!(
            parse_set_cookie("sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                .expect("past")
                .deletes
        );
        assert_eq!(default_cookie_path("/a/b/c?x=1"), "/a/b");
        assert_eq!(default_cookie_path("/login"), "/");
    }

    #[test]
    fn names_are_classified_without_catching_passwords() {
        for name in ["access_token", "X-Api-Key", "sessionid", "id_token", "jwt"] {
            assert!(credential_name(name), "{name}");
        }
        assert!(!credential_name("password"));
        assert!(password_name("new_password"));
        assert!(csrf_name("X-CSRF-Token") && csrf_name("_csrf") && csrf_name("authenticity_token"));
        assert!(!csrf_name("theme"));
    }
}
