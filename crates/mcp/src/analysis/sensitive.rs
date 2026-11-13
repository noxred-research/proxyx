//! Sensitive-data findings over captured exchanges.
//!
//! A local detector registry reads normalized JSON, form, XML and text content and reports where
//! a credential, a piece of personal data or a high-entropy candidate sits. A finding carries a
//! category, a severity, the detector's version, what kind of evidence backs it, a location, a
//! keyed fingerprint and a masked preview. It never carries the matched value, and the operator,
//! not a model, owns the detector list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Body, Evidence, Fingerprinter, Side, body_of, header, headers_of, media_type, safe_name,
};

/// The version of the detector registry, reported with every finding.
pub const DETECTOR_VERSION: &str = "sensitive-1";

/// What a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Credential,
    PersonalData,
    Candidate,
}

impl Category {
    pub const fn name(self) -> &'static str {
        match self {
            Category::Credential => "credential",
            Category::PersonalData => "personal_data",
            Category::Candidate => "candidate",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "credential" => Some(Category::Credential),
            "personal_data" => Some(Category::PersonalData),
            "candidate" => Some(Category::Candidate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    const fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    fn raise(self) -> Self {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }

    fn lower(self) -> Self {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

/// What evidence backs a finding. They are not one scale: a checksum is stronger than a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Basis {
    Pattern,
    Checksum,
    FieldName,
    EntropyHeuristic,
    CustomRule,
}

impl Basis {
    const fn name(self) -> &'static str {
        match self {
            Basis::Pattern => "pattern",
            Basis::Checksum => "checksum",
            Basis::FieldName => "field_name",
            Basis::EntropyHeuristic => "entropy_heuristic",
            Basis::CustomRule => "custom_rule",
        }
    }
}

struct Detector {
    id: &'static str,
    category: Category,
    severity: Severity,
    pattern: Regex,
}

fn detector(id: &'static str, category: Category, severity: Severity, pattern: &str) -> Detector {
    Detector {
        id,
        category,
        severity,
        pattern: Regex::new(pattern).expect("detector pattern is valid"),
    }
}

static PATTERN_DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    use Category::{Credential, PersonalData};
    use Severity::{High, Low, Medium};
    vec![
        detector(
            "private_key_block",
            Credential,
            Severity::Critical,
            r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----",
        ),
        // detection-data: the identifier prefixes of a cloud provider's access keys
        detector(
            "cloud_access_key_id",
            Credential,
            High,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        ),
        detector(
            "repo_host_token",
            Credential,
            High,
            r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        ),
        detector(
            "chat_service_token",
            Credential,
            High,
            r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
        ),
        detector(
            "payment_secret_key",
            Credential,
            High,
            r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
        ),
        detector(
            "maps_api_key",
            Credential,
            High,
            r"\bAIza[0-9A-Za-z_-]{35}\b",
        ),
        detector(
            "service_api_key",
            Credential,
            High,
            r"\b(?:ak|pxk|sk)[_-][A-Za-z0-9_-]{20,}",
        ),
        detector(
            "jwt",
            Credential,
            Medium,
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
        ),
        detector(
            "basic_auth_in_url",
            Credential,
            High,
            r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s/?#]+",
        ),
        detector(
            "bearer_value",
            Credential,
            Medium,
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}",
        ),
        detector(
            "email_address",
            PersonalData,
            Low,
            r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\b",
        ),
        detector(
            "phone_number_intl",
            PersonalData,
            Low,
            r"\+[1-9][0-9 ().-]{7,18}[0-9]",
        ),
        detector(
            "phone_number_us",
            PersonalData,
            Low,
            r"\(?\b[2-9][0-9]{2}\)?[ .-][0-9]{3}[ .-][0-9]{4}\b",
        ),
        detector(
            "payment_card_number",
            PersonalData,
            High,
            r"\b[3-6](?:[ -]?[0-9]){12,18}\b",
        ),
    ]
});

static ASSIGNED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:.*[_.-])?(?:pass(?:word|wd)?|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|credential)$")
        .expect("secret member pattern is valid")
});

static ENTROPY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(key|secret|token|credential|signature|passphrase|bearer|auth)")
        .expect("context pattern is valid")
});

static NOT_A_SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(etag|checksum|sha\d*|md5|digest|hash|uuid|guid|nonce|cache|version|keyboard|monkey)",
    )
    .expect("exclusion pattern is valid")
});

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("uuid pattern is valid")
});

static XML_ELEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<([A-Za-z_][\w:.-]*)[^<>]*>([^<]{1,512})</([A-Za-z_][\w:.-]*)>")
        .expect("xml pattern is valid")
});

/// Field names that hold personal data, with the severity of what they usually hold.
const PERSONAL_FIELDS: &[(&str, Severity)] = &[
    ("email", Severity::Low),
    ("emailaddress", Severity::Low),
    ("phone", Severity::Low),
    ("phonenumber", Severity::Low),
    ("mobile", Severity::Low),
    ("msisdn", Severity::Low),
    ("firstname", Severity::Low),
    ("lastname", Severity::Low),
    ("fullname", Severity::Low),
    ("surname", Severity::Low),
    ("givenname", Severity::Low),
    ("familyname", Severity::Low),
    ("address", Severity::Low),
    ("streetaddress", Severity::Low),
    ("street", Severity::Low),
    ("postalcode", Severity::Low),
    ("zipcode", Severity::Low),
    ("dob", Severity::Medium),
    ("dateofbirth", Severity::Medium),
    ("birthdate", Severity::Medium),
    ("ssn", Severity::High),
    ("socialsecuritynumber", Severity::High),
    ("nationalid", Severity::High),
    ("taxid", Severity::High),
    ("passport", Severity::High),
    ("passportnumber", Severity::High),
    ("driverslicense", Severity::High),
    ("iban", Severity::High),
    ("cardnumber", Severity::High),
    ("cvv", Severity::High),
    ("cvc", Severity::High),
];

/// An operator-supplied detector.
#[derive(Debug)]
struct CustomRule {
    name: String,
    category: Category,
    severity: Severity,
    pattern: Regex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    name: String,
    category: String,
    severity: String,
    pattern: String,
}

/// The operator's extra detectors.
#[derive(Debug, Default)]
pub struct Rules {
    custom: Vec<CustomRule>,
}

impl Rules {
    /// Read `[[rule]]` tables: `name`, `category`, `severity`, `pattern`.
    ///
    /// # Errors
    /// When the file cannot be read or a rule is invalid or too expensive.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read analysis.sensitive.custom_rules_file {}",
                path.display()
            )
        })?;
        let file: RuleFile = toml::from_str(&text)
            .with_context(|| format!("{} is not a valid rules file", path.display()))?;
        anyhow::ensure!(
            file.rule.len() <= 64,
            "analysis.sensitive.custom_rules_file lists at most 64 rules"
        );
        let mut custom = Vec::new();
        for entry in file.rule {
            anyhow::ensure!(
                (1..=64).contains(&entry.name.len())
                    && entry
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "custom rule names are 1 to 64 of [A-Za-z0-9_-]: {:?}",
                entry.name
            );
            let category = Category::parse(&entry.category).with_context(|| {
                format!("rule {}: unknown category {:?}", entry.name, entry.category)
            })?;
            let severity = Severity::parse(&entry.severity).with_context(|| {
                format!("rule {}: unknown severity {:?}", entry.name, entry.severity)
            })?;
            let pattern = regex::RegexBuilder::new(&entry.pattern)
                .size_limit(1 << 20)
                .build()
                .with_context(|| format!("rule {}: invalid pattern", entry.name))?;
            custom.push(CustomRule {
                name: entry.name,
                category,
                severity,
                pattern,
            });
        }
        Ok(Self { custom })
    }

    pub fn len(&self) -> usize {
        self.custom.len()
    }

    pub fn is_empty(&self) -> bool {
        self.custom.is_empty()
    }
}

/// Settings of one scan.
#[derive(Debug, Clone)]
pub struct Options {
    pub categories: BTreeSet<Category>,
    pub min_entropy: f64,
    pub max_findings: usize,
    pub preview_chars: usize,
}

/// What a scan found.
#[derive(Debug, Default)]
pub struct Scan {
    pub findings: Vec<Value>,
    pub by_category: BTreeMap<&'static str, usize>,
    pub limits: Vec<String>,
    pub truncated: bool,
}

struct Hit {
    detector: String,
    category: Category,
    severity: Severity,
    basis: Basis,
    value: String,
    pointer: String,
    kind: &'static str,
}

/// Shannon entropy of `text` in bits per character (bytes).
pub fn entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = f64::from(*count) / len;
            -p * p.log2()
        })
        .sum()
}

fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
}

fn compact_name(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn placeholder(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.is_empty()
        || lower
            .chars()
            .all(|c| matches!(c, '*' | 'x' | '.' | '-' | '•'))
        || matches!(
            lower.as_str(),
            "null"
                | "none"
                | "undefined"
                | "[redacted]"
                | "redacted"
                | "changeme"
                | "example"
                | "string"
        )
        || lower.starts_with("${")
        || lower.starts_with("{{")
        || lower.starts_with('<') && lower.ends_with('>')
}

/// Run every detector over one value. `name` is the member, header or parameter it sits in.
fn detect(text: &str, name: Option<&str>, rules: &Rules, options: &Options) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let wanted = |category: Category| options.categories.contains(&category);
    for detector in PATTERN_DETECTORS.iter().filter(|d| wanted(d.category)) {
        for found in detector.pattern.find_iter(text).take(20) {
            let value = found.as_str();
            let span = (found.start(), found.end());
            match detector.id {
                "email_address" if taken.iter().any(|(s, e)| span.0 >= *s && span.1 <= *e) => {
                    continue;
                }
                "phone_number_intl" | "phone_number_us" => {
                    let digits = value.chars().filter(char::is_ascii_digit).count();
                    if !(8..=15).contains(&digits) {
                        continue;
                    }
                }
                "payment_card_number" => {
                    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
                    if !(13..=19).contains(&digits.len()) || !luhn(&digits) {
                        continue;
                    }
                    hits.push(Hit {
                        detector: detector.id.to_owned(),
                        category: detector.category,
                        severity: detector.severity,
                        basis: Basis::Checksum,
                        value: digits,
                        pointer: String::new(),
                        kind: "text",
                    });
                    continue;
                }
                "jwt" if value.matches('.').count() != 2 => continue,
                _ => {}
            }
            if matches!(detector.category, Category::Credential) {
                taken.push(span);
            }
            hits.push(Hit {
                detector: detector.id.to_owned(),
                category: detector.category,
                severity: detector.severity,
                basis: Basis::Pattern,
                value: value.to_owned(),
                pointer: String::new(),
                kind: "text",
            });
        }
    }
    for rule in &rules.custom {
        if !wanted(rule.category) {
            continue;
        }
        for found in rule.pattern.find_iter(text).take(20) {
            hits.push(Hit {
                detector: format!("custom:{}", rule.name),
                category: rule.category,
                severity: rule.severity,
                basis: Basis::CustomRule,
                value: found.as_str().to_owned(),
                pointer: String::new(),
                kind: "text",
            });
        }
    }
    if let Some(name) = name {
        let compact = compact_name(name);
        let already = |hits: &[Hit]| hits.iter().any(|hit| hit.value == text);
        if wanted(Category::Credential)
            && ASSIGNED_SECRET.is_match(name)
            && text.len() >= 8
            && !placeholder(text)
            && !already(&hits)
        {
            hits.push(Hit {
                detector: "secret_member".to_owned(),
                category: Category::Credential,
                severity: Severity::Medium,
                basis: Basis::FieldName,
                value: text.to_owned(),
                pointer: String::new(),
                kind: "member",
            });
        } else if wanted(Category::PersonalData)
            && let Some((_, severity)) = PERSONAL_FIELDS.iter().find(|(field, _)| *field == compact)
            && text.trim().len() >= 2
            && !placeholder(text)
            && !already(&hits)
        {
            hits.push(Hit {
                detector: "personal_field".to_owned(),
                category: Category::PersonalData,
                severity: *severity,
                basis: Basis::FieldName,
                value: text.to_owned(),
                pointer: String::new(),
                kind: "member",
            });
        } else if wanted(Category::Candidate)
            && ENTROPY_CONTEXT.is_match(name)
            && !NOT_A_SECRET_NAME.is_match(name)
            && (20..=256).contains(&text.len())
            && !text.contains(char::is_whitespace)
            && !text.contains("://")
            && !UUID.is_match(text)
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
            && entropy(text) >= options.min_entropy
            && hits.is_empty()
        {
            hits.push(Hit {
                detector: "high_entropy_candidate".to_owned(),
                category: Category::Candidate,
                severity: Severity::Info,
                basis: Basis::EntropyHeuristic,
                value: text.to_owned(),
                pointer: String::new(),
                kind: "member",
            });
        }
    }
    hits
}

/// A text unit to scan: where it is and what it is called.
struct Unit {
    side: Side,
    kind: &'static str,
    pointer: String,
    name: Option<String>,
    text: String,
    in_url: bool,
}

fn json_units(value: &Value, side: Side, path: &str, depth: usize, out: &mut Vec<Unit>) {
    if depth > 10 || out.len() > 5000 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (name, member) in map {
                let here = format!("{path}/{}", safe_name(name));
                match member {
                    Value::String(text) => out.push(Unit {
                        side,
                        kind: "json_member",
                        pointer: here,
                        name: Some(name.clone()),
                        text: text.clone(),
                        in_url: false,
                    }),
                    Value::Number(number) => out.push(Unit {
                        side,
                        kind: "json_member",
                        pointer: here,
                        name: Some(name.clone()),
                        text: number.to_string(),
                        in_url: false,
                    }),
                    other => json_units(other, side, &here, depth + 1, out),
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(200) {
                json_units(item, side, &format!("{path}/*"), depth + 1, out);
            }
        }
        Value::String(text) => out.push(Unit {
            side,
            kind: "json_value",
            pointer: path.to_owned(),
            name: None,
            text: text.clone(),
            in_url: false,
        }),
        _ => {}
    }
}

fn looks_binary(text: &str) -> bool {
    let total = text.chars().count().max(1);
    let odd = text
        .chars()
        .filter(|c| *c == '\u{fffd}' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
        .count();
    odd * 20 > total
}

/// The units of one body, and a reason when it cannot be read.
fn body_units(
    text: &str,
    content_type: &str,
    side: Side,
    out: &mut Vec<Unit>,
) -> Option<&'static str> {
    if looks_binary(text) {
        return Some("binary_or_compressed");
    }
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return match serde_json::from_str::<Value>(text) {
            Ok(value) => {
                json_units(&value, side, "", 0, out);
                None
            }
            Err(_) => {
                out.push(text_unit(side, text));
                Some("unparsable_json_scanned_as_text")
            }
        };
    }
    if content_type.contains("x-www-form-urlencoded")
        && let Ok(url) = reqwest::Url::parse(&format!("http://form.invalid/?{text}"))
    {
        for (name, value) in url.query_pairs() {
            out.push(Unit {
                side,
                kind: "form_field",
                pointer: format!("/{}", safe_name(&name)),
                name: Some(name.to_string()),
                text: value.into_owned(),
                in_url: false,
            });
        }
        return None;
    }
    if trimmed.starts_with('<') {
        for captures in XML_ELEMENT.captures_iter(text).take(2000) {
            if captures[1] == captures[3] {
                out.push(Unit {
                    side,
                    kind: "xml_element",
                    pointer: format!("/{}", safe_name(&captures[1])),
                    name: Some(captures[1].to_owned()),
                    text: captures[2].to_owned(),
                    in_url: false,
                });
            }
        }
    }
    out.push(text_unit(side, text));
    None
}

fn text_unit(side: Side, text: &str) -> Unit {
    Unit {
        side,
        kind: "text",
        pointer: String::new(),
        name: None,
        text: text.to_owned(),
        in_url: false,
    }
}

fn textual(content_type: &str) -> bool {
    content_type.is_empty()
        || content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("javascript")
        || content_type.contains("x-www-form-urlencoded")
        || content_type.contains("yaml")
}

struct Group {
    hit: Hit,
    side: Side,
    count: usize,
    evidence: Vec<String>,
    captures: BTreeSet<String>,
    in_url: bool,
    in_request_body: bool,
    more_locations: Vec<Value>,
}

fn mask(value: &str, preview_chars: usize, private: bool) -> String {
    let len = value.chars().count();
    if private || preview_chars == 0 || len < preview_chars * 4 {
        return format!("[{len} chars]");
    }
    let head: String = value.chars().take(preview_chars).collect();
    format!("{head}…[{len} chars]")
}

/// Scan captures.
pub fn scan(
    items: &[Value],
    fp: &Fingerprinter,
    evidence: &mut Evidence,
    rules: &Rules,
    options: &Options,
) -> Scan {
    let mut groups: BTreeMap<(String, &'static str, String), Group> = BTreeMap::new();
    let mut scan = Scan::default();
    let mut unsupported: BTreeMap<String, usize> = BTreeMap::new();
    for item in items {
        let id = item["id"].as_str().unwrap_or("");
        let request_headers = headers_of(&item["request_headers"]);
        let response_headers = headers_of(&item["response_headers"]);
        let mut units: Vec<Unit> = Vec::new();
        // request: the URL query and headers other than the expected credential carriers
        if let Some((_, query)) = item["path"].as_str().unwrap_or("").split_once('?')
            && let Ok(url) = reqwest::Url::parse(&format!("http://query.invalid/?{query}"))
        {
            for (name, value) in url.query_pairs() {
                units.push(Unit {
                    side: Side::Request,
                    kind: "query_param",
                    pointer: format!("?{}", safe_name(&name)),
                    name: Some(name.to_string()),
                    text: value.into_owned(),
                    in_url: true,
                });
            }
        }
        for (side, headers) in [
            (Side::Request, &request_headers),
            (Side::Response, &response_headers),
        ] {
            for (name, value) in headers {
                let expected = matches!(
                    name.as_str(),
                    "authorization"
                        | "cookie"
                        | "set-cookie"
                        | "www-authenticate"
                        | "proxy-authorization"
                );
                if !expected {
                    units.push(Unit {
                        side,
                        kind: "header",
                        pointer: safe_name(name).to_owned(),
                        name: Some(name.clone()),
                        text: value.clone(),
                        in_url: name == "referer" || name == "location",
                    });
                }
            }
        }
        let mut in_request_body = Vec::new();
        for (side, key, headers) in [
            (Side::Request, "request_body", &request_headers),
            (Side::Response, "response_body", &response_headers),
        ] {
            match body_of(&item[key]) {
                Body::Absent => {}
                Body::TooLarge => {
                    *unsupported
                        .entry("body_larger_than_fetch_cap".to_owned())
                        .or_insert(0) += 1;
                }
                Body::Text(text) => {
                    let content_type = media_type(headers);
                    if !textual(&content_type) {
                        *unsupported
                            .entry(format!("unsupported_content_type:{content_type}"))
                            .or_insert(0) += 1;
                        continue;
                    }
                    let encoded = header(headers, "content-encoding")
                        .is_some_and(|enc| !enc.eq_ignore_ascii_case("identity"));
                    let before = units.len();
                    if let Some(reason) = body_units(&text, &content_type, side, &mut units) {
                        let reason = if encoded && reason == "binary_or_compressed" {
                            "compressed_body_unavailable"
                        } else {
                            reason
                        };
                        *unsupported.entry(reason.to_owned()).or_insert(0) += 1;
                    }
                    if side == Side::Request {
                        in_request_body.extend(before..units.len());
                    }
                }
            }
        }
        for (index, unit) in units.iter().enumerate() {
            let hits = detect(&unit.text, unit.name.as_deref(), rules, options);
            for mut hit in hits {
                hit.pointer.clone_from(&unit.pointer);
                hit.kind = unit.kind;
                let location = if unit.pointer.is_empty() {
                    unit.kind.to_owned()
                } else {
                    format!("{}:{}", unit.kind, unit.pointer)
                };
                let fingerprint = fp.label(&hit.value);
                let key = (hit.detector.clone(), hit.category.name(), fingerprint);
                let ev = evidence.add(fp, id, unit.side, &location, &hit.value);
                let request_body = in_request_body.contains(&index);
                match groups.get_mut(&key) {
                    Some(group) => {
                        group.count += 1;
                        group.captures.insert(id.to_owned());
                        if group.evidence.len() < 5 && !group.evidence.contains(&ev) {
                            group.evidence.push(ev);
                            group.more_locations.push(
                                json!({"side": unit.side, "kind": unit.kind, "path": unit.pointer}),
                            );
                        }
                        group.in_url |= unit.in_url;
                    }
                    None => {
                        let mut captures = BTreeSet::new();
                        captures.insert(id.to_owned());
                        groups.insert(
                            key,
                            Group {
                                side: unit.side,
                                count: 1,
                                evidence: vec![ev],
                                captures,
                                in_url: unit.in_url,
                                in_request_body: request_body,
                                more_locations: Vec::new(),
                                hit,
                            },
                        );
                    }
                }
            }
        }
    }
    for ((_, _, fingerprint), group) in groups {
        if scan.findings.len() >= options.max_findings {
            scan.truncated = true;
            scan.limits.push(format!(
                "analysis.sensitive.max_findings ({}) was reached; more findings exist",
                options.max_findings
            ));
            break;
        }
        let mut severity = group.hit.severity;
        if group.in_url && group.hit.category == Category::Credential {
            severity = severity.raise();
        }
        if group.in_request_body
            && group.hit.basis == Basis::FieldName
            && group.hit.category == Category::Credential
        {
            // a credential submitted in a request body is what a login form does
            severity = severity.lower();
        }
        *scan
            .by_category
            .entry(group.hit.category.name())
            .or_insert(0) += 1;
        let private = group.hit.detector == "private_key_block";
        scan.findings.push(json!({
            "id": format!("sf_{}", scan.findings.len() + 1),
            "category": group.hit.category.name(),
            "detector": group.hit.detector,
            "severity": severity.name(),
            "detector_version": DETECTOR_VERSION,
            "confidence_kind": group.hit.basis.name(),
            "location": {
                "side": group.side,
                "kind": group.hit.kind,
                "path": group.hit.pointer,
            },
            "other_locations": group.more_locations,
            "masked_preview": mask(&group.hit.value, options.preview_chars, private),
            "fingerprint": fingerprint,
            "occurrences": group.count,
            "captures": group.captures.len(),
            "evidence_ref": group.evidence.first(),
            "evidence_refs": group.evidence,
            "in_url": group.in_url,
        }));
    }
    for (reason, count) in unsupported {
        scan.limits
            .push(format!("{count} bodies were not scanned: {reason}"));
    }
    scan.truncated |= !scan.limits.is_empty();
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            categories: [
                Category::Credential,
                Category::PersonalData,
                Category::Candidate,
            ]
            .into_iter()
            .collect(),
            min_entropy: 4.0,
            max_findings: 200,
            preview_chars: 0,
        }
    }

    fn detectors(text: &str, name: Option<&str>) -> Vec<String> {
        detect(text, name, &Rules::default(), &options())
            .into_iter()
            .map(|hit| hit.detector)
            .collect()
    }

    #[test]
    fn credential_shapes_are_found() {
        assert!(
            detectors("-----BEGIN RSA PRIVATE KEY-----", None)
                .contains(&"private_key_block".to_owned())
        );
        assert!(
            detectors("id AKIAIOSFODNN7EXAMPLE here", None)
                .contains(&"cloud_access_key_id".to_owned())
        );
        assert!(
            detectors("ghp_0123456789abcdefghijklmnopqrstuvwxyz", None)
                .contains(&"repo_host_token".to_owned())
        );
        assert!(
            detectors("postgres://admin:hunter22@db.test/app", None)
                .contains(&"basic_auth_in_url".to_owned())
        );
        assert!(
            detectors("Bearer abcdefghijklmnop012345", None).contains(&"bearer_value".to_owned())
        );
        let found = detectors("postgres://admin:hunter22@db.test/app", None);
        assert!(!found.contains(&"email_address".to_owned()), "{found:?}");
    }

    #[test]
    fn personal_data_needs_structure_or_a_checksum() {
        assert!(
            detectors("write to jane.doe@mail.test", None).contains(&"email_address".to_owned())
        );
        assert!(detectors("4111 1111 1111 1111", None).contains(&"payment_card_number".to_owned()));
        assert!(
            !detectors("4111 1111 1111 1112", None).contains(&"payment_card_number".to_owned())
        );
        assert!(!detectors("1731232862345", None).contains(&"payment_card_number".to_owned()));
        assert!(detectors("+44 20 7946 0958", None).contains(&"phone_number_intl".to_owned()));
        assert!(detectors("Jane", Some("first_name")).contains(&"personal_field".to_owned()));
        assert!(detectors("", Some("first_name")).is_empty());
    }

    #[test]
    fn ordinary_values_are_not_findings() {
        for (text, name) in [
            (
                "0190aaaa-0000-4000-8000-000000000001",
                Some("session_token"),
            ),
            ("0190aaaa-0000-4000-8000-000000000001", Some("id")),
            ("d41d8cd98f00b204e9800998ecf8427e", Some("etag")),
            ("const apiKey = process.env.API_KEY;", None),
            ("Authorization: Bearer <token>", None),
            (
                "hello world, this is a long ordinary sentence of text",
                Some("description"),
            ),
            ("short", Some("password")),
            ("********", Some("password")),
            (
                "https://cdn.example.test/assets/app.0123456789abcdef.js",
                Some("script_key"),
            ),
        ] {
            assert!(detectors(text, name).is_empty(), "{text:?} {name:?}");
        }
    }

    #[test]
    fn entropy_needs_context_and_randomness() {
        let random = "Zk3pQ9vXr7LmN2sTb8WdYf5HcJ1gAe4U";
        assert!(
            detectors(random, Some("client_key")).contains(&"high_entropy_candidate".to_owned())
        );
        assert!(detectors(random, Some("title")).is_empty());
        assert!(detectors("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Some("client_key")).is_empty());
    }

    #[test]
    fn masking_never_shows_most_of_a_value() {
        assert_eq!(mask("abcdefghijklmnopqrst", 0, false), "[20 chars]");
        assert_eq!(mask("abcdefghijklmnopqrst", 4, false), "abcd…[20 chars]");
        assert_eq!(mask("abcdefgh", 4, false), "[8 chars]");
        assert_eq!(mask("-----BEGIN PRIVATE KEY-----", 4, true), "[27 chars]");
    }

    #[test]
    fn luhn_and_entropy() {
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
        assert!(entropy("aaaa") < 0.1);
        assert!(entropy("Zk3pQ9vXr7LmN2sTb8WdYf5HcJ1gAe4U") > 4.0);
    }
}
