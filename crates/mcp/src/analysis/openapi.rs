//! OpenAPI 3.1 drafts inferred from observed captures.
//!
//! The inferencer groups captures by origin, method and path template, merges the JSON shapes it
//! saw per status code and content type, and says only what the traffic showed: a property seen
//! in every sample is `x-proxyx-observed-required`, never `required`; an unseen status code, route
//! or body does not exist in the draft; a conflicting type stays a union with a note; a body that
//! was cut or unreadable leaves the schema unknown. Server origins come from the captures and
//! nowhere else. A draft is documentation of what was observed, not a contract and not a
//! permission to call anything.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::{
    Body, Evidence, Fingerprinter, Side, body_of, headers_of, media_type, plain_word, safe_name,
};

/// The version of the inference rules, reported with every draft.
pub const DETECTOR_VERSION: &str = "openapi-draft-1";

/// Evidence ids kept per operation and per schema node.
const EVIDENCE_PER_NODE: usize = 3;

/// Settings of one inference.
#[derive(Debug, Clone)]
pub struct Options {
    pub max_routes: usize,
    pub max_depth: usize,
    pub max_properties: usize,
    pub allowed_content_types: Vec<String>,
}

/// What was inferred.
#[derive(Debug, Default)]
pub struct Draft {
    /// OpenAPI documents by origin.
    pub documents: BTreeMap<String, Value>,
    /// One entry per route, with its `route_ref`.
    pub routes: Vec<Value>,
    pub diagnostics: Vec<Value>,
    pub route_refs: BTreeSet<String>,
}

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("uuid pattern is valid")
});
static DATE_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})$")
        .expect("date-time pattern is valid")
});
static DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("date pattern is valid"));

// --- shapes --------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Shape {
    types: BTreeSet<&'static str>,
    props: BTreeMap<String, Prop>,
    /// The values under keys that are not plain identifiers (ids, addresses, tokens): their
    /// names are never printed.
    extra: Option<Box<Shape>>,
    items: Option<Box<Shape>>,
    /// Objects merged into this shape.
    objects: usize,
    strings: usize,
    uuid: usize,
    date_time: usize,
    date: usize,
    empty_arrays: usize,
    truncated: bool,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct Prop {
    shape: Shape,
    seen: usize,
}

impl Shape {
    fn note(&mut self, evidence: &str) {
        if self.evidence.len() < EVIDENCE_PER_NODE && !self.evidence.iter().any(|e| e == evidence) {
            self.evidence.push(evidence.to_owned());
        }
    }

    fn observe(&mut self, value: &Value, depth: usize, options: &Options, evidence: &str) {
        self.note(evidence);
        if depth > options.max_depth {
            self.truncated = true;
            return;
        }
        match value {
            Value::Null => {
                self.types.insert("null");
            }
            Value::Bool(_) => {
                self.types.insert("boolean");
            }
            Value::Number(number) => {
                self.types.insert(if number.is_i64() || number.is_u64() {
                    "integer"
                } else {
                    "number"
                });
            }
            Value::String(text) => {
                self.types.insert("string");
                self.strings += 1;
                if UUID.is_match(text) {
                    self.uuid += 1;
                } else if DATE_TIME.is_match(text) {
                    self.date_time += 1;
                } else if DATE.is_match(text) {
                    self.date += 1;
                }
            }
            Value::Array(items) => {
                self.types.insert("array");
                if items.is_empty() {
                    self.empty_arrays += 1;
                }
                let inner = self.items.get_or_insert_with(Box::default);
                for item in items.iter().take(50) {
                    inner.observe(item, depth + 1, options, evidence);
                }
            }
            Value::Object(map) => {
                self.types.insert("object");
                self.objects += 1;
                for (name, member) in map {
                    if safe_name(name) != name.as_str() {
                        self.extra.get_or_insert_with(Box::default).observe(
                            member,
                            depth + 1,
                            options,
                            evidence,
                        );
                        continue;
                    }
                    if self.props.len() >= options.max_properties && !self.props.contains_key(name)
                    {
                        self.truncated = true;
                        continue;
                    }
                    let prop = self.props.entry(name.clone()).or_default();
                    prop.seen += 1;
                    prop.shape.observe(member, depth + 1, options, evidence);
                }
            }
        }
    }

    fn render(&self) -> Value {
        let mut schema = Map::new();
        let mut types: Vec<&str> = self.types.iter().copied().collect();
        if types.contains(&"integer") && types.contains(&"number") {
            types.retain(|t| *t != "integer");
        }
        let conflict = types.iter().filter(|t| **t != "null").count() > 1;
        match types.as_slice() {
            [] => {}
            [one] => {
                schema.insert("type".to_owned(), json!(one));
            }
            many => {
                schema.insert("type".to_owned(), json!(many));
            }
        }
        if self.strings > 0 {
            let format = if self.uuid == self.strings {
                Some("uuid")
            } else if self.date_time == self.strings {
                Some("date-time")
            } else if self.date == self.strings {
                Some("date")
            } else {
                None
            };
            if let Some(format) = format {
                schema.insert("format".to_owned(), json!(format));
            }
        }
        if !self.props.is_empty() {
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (name, prop) in &self.props {
                properties.insert(name.clone(), prop.shape.render());
                if prop.seen == self.objects && self.objects > 0 {
                    required.push(name.clone());
                }
            }
            schema.insert("properties".to_owned(), Value::Object(properties));
            schema.insert("x-proxyx-observed-required".to_owned(), json!(required));
        }
        if let Some(extra) = &self.extra {
            schema.insert("additionalProperties".to_owned(), extra.render());
        }
        if let Some(items) = &self.items
            && (items.types.len() + usize::from(items.truncated)) > 0
        {
            schema.insert("items".to_owned(), items.render());
        }
        let mut observed = Map::new();
        observed.insert("objects".to_owned(), json!(self.objects));
        observed.insert("evidence".to_owned(), json!(self.evidence));
        if conflict {
            observed.insert("conflicting_types".to_owned(), json!(true));
        }
        if self.empty_arrays > 0
            && self
                .items
                .as_ref()
                .is_none_or(|items| items.types.is_empty())
        {
            observed.insert(
                "items_unknown".to_owned(),
                json!("only empty arrays were observed"),
            );
        }
        if self.extra.is_some() {
            observed.insert(
                "keys_withheld".to_owned(),
                json!("some keys were identifiers or not plain names; they are not printed"),
            );
        }
        if self.truncated {
            observed.insert(
                "truncated".to_owned(),
                json!("depth or property limit reached"),
            );
        }
        schema.insert("x-proxyx-observed".to_owned(), Value::Object(observed));
        Value::Object(schema)
    }
}

// --- routes ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Seg {
    Lit(String),
    Param,
}

type Template = Vec<Seg>;

fn singular(word: &str) -> String {
    let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if let Some(stem) = word.strip_suffix("ies").filter(|s| !s.is_empty()) {
        return format!("{stem}y");
    }
    match word.strip_suffix('s') {
        Some(stem) if stem.len() >= 2 => stem.to_owned(),
        _ => word.to_owned(),
    }
}

/// The path text of a template and the names of its parameters.
fn render_template(template: &Template) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut names: Vec<String> = Vec::new();
    let mut previous: Option<&str> = None;
    for seg in template {
        out.push('/');
        match seg {
            Seg::Lit(text) => {
                out.push_str(text);
                previous = Some(text);
            }
            Seg::Param => {
                let base = match previous {
                    Some(word) if !singular(word).is_empty() => format!("{}Id", singular(word)),
                    _ => "id".to_owned(),
                };
                let mut name = base.clone();
                let mut n = 2;
                while names.contains(&name) {
                    name = format!("{base}{n}");
                    n += 1;
                }
                out.push('{');
                out.push_str(&name);
                out.push('}');
                names.push(name);
                previous = None;
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    (out, names)
}

#[derive(Debug)]
struct Observation {
    path: Template,
    /// The path segments as observed. Used to type parameters; never printed.
    segments: Vec<String>,
    query: Vec<(String, String)>,
    status: u64,
    request_type: String,
    request_json: Option<Value>,
    request_evidence: Option<String>,
    response_type: String,
    response_json: Option<Value>,
    evidence: String,
    body_gap: bool,
}

fn json_media(media: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| a.eq_ignore_ascii_case(media))
}

fn scalar_type(values: &[&str]) -> (&'static str, Option<&'static str>) {
    if values.is_empty() {
        return ("string", None);
    }
    if values.iter().all(|v| v.parse::<i64>().is_ok()) {
        return ("integer", None);
    }
    if values.iter().all(|v| v.parse::<f64>().is_ok()) {
        return ("number", None);
    }
    if values.iter().all(|v| matches!(*v, "true" | "false")) {
        return ("boolean", None);
    }
    if values.iter().all(|v| UUID.is_match(v)) {
        return ("string", Some("uuid"));
    }
    ("string", None)
}

/// Infer drafts from captures.
pub fn infer(
    items: &[Value],
    fp: &Fingerprinter,
    evidence: &mut Evidence,
    options: &Options,
) -> Draft {
    let mut draft = Draft::default();
    let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
    let mut duplicates = 0_usize;
    let mut skipped_types: BTreeMap<String, usize> = BTreeMap::new();
    let mut gaps = 0_usize;
    let mut withheld_names = 0_usize;
    // origin -> method -> observations
    let mut grouped: BTreeMap<String, BTreeMap<String, Vec<Observation>>> = BTreeMap::new();
    for item in items {
        let id = item["id"].as_str().unwrap_or("");
        if !seen_ids.insert(id) {
            duplicates += 1;
            continue;
        }
        let origin = format!(
            "{}://{}",
            item["scheme"].as_str().unwrap_or("https"),
            item["host"].as_str().unwrap_or("").to_ascii_lowercase()
        );
        let method = item["method"]
            .as_str()
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let raw_path = item["path"].as_str().unwrap_or("/");
        let (path_only, query_text) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        let segments: Vec<String> = path_only
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(str::to_owned)
            .collect();
        // a segment that is not a plain word is an identifier or a secret: it is never printed
        let path: Template = segments
            .iter()
            .map(|segment| {
                if plain_word(segment) {
                    Seg::Lit(segment.clone())
                } else {
                    Seg::Param
                }
            })
            .collect();
        let query: Vec<(String, String)> =
            reqwest::Url::parse(&format!("http://query.invalid/?{query_text}"))
                .map(|url| {
                    url.query_pairs()
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect()
                })
                .unwrap_or_default();
        let before = query.len();
        let query: Vec<(String, String)> = query
            .into_iter()
            .filter(|(name, _)| safe_name(name) == name.as_str())
            .collect();
        withheld_names += before - query.len();
        let request_headers = headers_of(&item["request_headers"]);
        let response_headers = headers_of(&item["response_headers"]);
        let status = item["status_code"].as_u64().unwrap_or(0);
        let ev = evidence.add(
            fp,
            id,
            Side::Response,
            "status",
            &format!("{method} {path_only} {status}"),
        );
        let mut body_gap = false;
        let mut parse = |side: Side,
                         key: &str,
                         headers: &[(String, String)]|
         -> (String, Option<Value>, Option<String>) {
            let media = media_type(headers);
            match body_of(&item[key]) {
                Body::Absent => (media, None, None),
                Body::TooLarge => {
                    body_gap = true;
                    (media, None, None)
                }
                Body::Text(text) => {
                    if !json_media(&media, &options.allowed_content_types) {
                        if !text.is_empty() {
                            *skipped_types.entry(media.clone()).or_insert(0) += 1;
                        }
                        return (media, None, None);
                    }
                    match serde_json::from_str::<Value>(&text) {
                        Ok(value) => {
                            let ev = evidence.add(fp, id, side, "body", &text);
                            (media, Some(value), Some(ev))
                        }
                        Err(_) => {
                            body_gap = true;
                            (media, None, None)
                        }
                    }
                }
            }
        };
        let (request_type, request_json, request_evidence) =
            parse(Side::Request, "request_body", &request_headers);
        let (response_type, response_json, response_evidence) =
            parse(Side::Response, "response_body", &response_headers);
        if body_gap {
            gaps += 1;
        }
        grouped
            .entry(origin)
            .or_default()
            .entry(method)
            .or_default()
            .push(Observation {
                path,
                segments,
                query,
                status,
                request_type,
                request_json,
                request_evidence,
                response_type,
                response_json,
                evidence: response_evidence.unwrap_or(ev),
                body_gap,
            });
    }
    if duplicates > 0 {
        draft
            .diagnostics
            .push(json!({"kind": "duplicate_captures_ignored", "count": duplicates}));
    }
    if gaps > 0 {
        draft.diagnostics.push(json!({
            "kind": "bodies_unknown",
            "count": gaps,
            "detail": "a body that was cut, too large or not valid JSON leaves its schema unknown; nothing was guessed",
        }));
    }
    for (media, count) in skipped_types {
        draft.diagnostics.push(json!({
            "kind": "content_type_not_allowed",
            "content_type": if media.is_empty() { "(none)".to_owned() } else { media },
            "count": count,
            "detail": "analysis.openapi.allowed_content_types does not list it; the body shape is unknown",
        }));
    }
    let mut route_count = 0_usize;
    let mut dropped_routes = 0_usize;
    let mut parameterized_routes = 0_usize;
    for (origin, methods) in &grouped {
        let mut paths = Map::new();
        for (method, observations) in methods {
            let mut by_template: BTreeMap<Template, Vec<&Observation>> = BTreeMap::new();
            for observation in observations {
                by_template
                    .entry(observation.path.clone())
                    .or_default()
                    .push(observation);
            }
            for (template, group) in by_template {
                if route_count >= options.max_routes {
                    dropped_routes += 1;
                    continue;
                }
                route_count += 1;
                if template.contains(&Seg::Param) {
                    parameterized_routes += 1;
                }
                let (path, names) = render_template(&template);
                let route_ref = format!("r{route_count}");
                draft.route_refs.insert(route_ref.clone());
                let operation =
                    build_operation(&template, &names, method, &route_ref, &group, options);
                let statuses: BTreeSet<u64> = group.iter().map(|o| o.status).collect();
                draft.routes.push(json!({
                    "route_ref": route_ref,
                    "origin": origin,
                    "method": method,
                    "path": path,
                    "samples": group.len(),
                    "statuses": statuses,
                    "evidence": operation["x-proxyx-observed"]["evidence"],
                }));
                let item = paths.entry(path).or_insert_with(|| json!({}));
                item[method.to_ascii_lowercase()] = operation;
            }
        }
        let total: usize = methods.values().map(Vec::len).sum();
        draft.documents.insert(
            origin.clone(),
            json!({
                "openapi": "3.1.0",
                "info": {
                    "title": format!("Observed API draft for {origin}"),
                    "version": "0.0.0-observed",
                    "description": "Inferred from stored captures only. This is documentation of what was observed, not a contract: a property listed in x-proxyx-observed-required was present in every sample, which says nothing about what the server requires. It is not authorization to call anything.",
                },
                "servers": [{"url": origin}],
                "paths": Value::Object(paths),
                "x-proxyx-observed": {
                    "detector_version": DETECTOR_VERSION,
                    "captures": total,
                },
            }),
        );
    }
    if parameterized_routes > 0 {
        draft.diagnostics.push(json!({
            "kind": "identifier_segments_parameterized",
            "routes": parameterized_routes,
            "detail": "a path segment that is not a plain word (digits, a UUID, a token, an address) is shown as a parameter even when one value was seen: identifier-like values are never printed",
        }));
    }
    if withheld_names > 0 {
        draft.diagnostics.push(json!({
            "kind": "names_withheld",
            "count": withheld_names,
            "detail": "query parameter names that are not plain identifiers were left out",
        }));
    }
    if dropped_routes > 0 {
        draft.diagnostics.push(json!({
            "kind": "routes_truncated",
            "dropped": dropped_routes,
            "detail": "analysis.openapi.max_routes was reached",
        }));
    }
    draft
}

fn build_operation(
    template: &Template,
    names: &[String],
    method: &str,
    route_ref: &str,
    group: &[&Observation],
    options: &Options,
) -> Value {
    let mut operation = Map::new();
    let mut parameters: Vec<Value> = Vec::new();
    // path parameters
    let mut param_values: Vec<Vec<&str>> = vec![Vec::new(); names.len()];
    for observation in group {
        let mut index = 0;
        for (seg, actual) in template.iter().zip(&observation.segments) {
            if *seg == Seg::Param {
                if let Some(values) = param_values.get_mut(index) {
                    values.push(actual.as_str());
                }
                index += 1;
            }
        }
    }
    for (name, values) in names.iter().zip(&param_values) {
        let (kind, format) = scalar_type(values);
        let mut schema = json!({"type": kind});
        if let Some(format) = format {
            schema["format"] = json!(format);
        }
        parameters.push(json!({
            "name": name, "in": "path", "required": true, "schema": schema,
            "x-proxyx-observed": {"distinct_values": values.iter().collect::<BTreeSet<_>>().len()},
        }));
    }
    // query parameters
    let mut query: BTreeMap<&str, (usize, Vec<&str>)> = BTreeMap::new();
    for observation in group {
        let mut names_here: BTreeSet<&str> = BTreeSet::new();
        for (name, value) in &observation.query {
            let entry = query.entry(name).or_default();
            if names_here.insert(name) {
                entry.0 += 1;
            }
            entry.1.push(value);
        }
    }
    for (name, (seen, values)) in &query {
        let (kind, format) = scalar_type(values);
        let mut schema = json!({"type": kind});
        if let Some(format) = format {
            schema["format"] = json!(format);
        }
        parameters.push(json!({
            "name": name, "in": "query", "required": false, "schema": schema,
            "x-proxyx-observed": {"samples": seen, "of": group.len(), "observed_required": *seen == group.len()},
        }));
    }
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    // request body
    let mut request_shapes: BTreeMap<&str, Shape> = BTreeMap::new();
    for observation in group {
        if let (Some(value), Some(ev)) = (&observation.request_json, &observation.request_evidence)
        {
            request_shapes
                .entry(&observation.request_type)
                .or_default()
                .observe(value, 0, options, ev);
        }
    }
    if !request_shapes.is_empty() {
        let mut content = Map::new();
        for (media, shape) in &request_shapes {
            content.insert((*media).to_owned(), json!({"schema": shape.render()}));
        }
        operation.insert(
            "requestBody".to_owned(),
            json!({"content": Value::Object(content), "x-proxyx-observed": {"note": "whether a body is required was not observed"}}),
        );
    }
    // responses
    let mut by_status: BTreeMap<u64, Vec<&Observation>> = BTreeMap::new();
    for observation in group {
        by_status
            .entry(observation.status)
            .or_default()
            .push(observation);
    }
    let mut responses = Map::new();
    let mut all_evidence: Vec<String> = Vec::new();
    for (status, observations) in &by_status {
        let mut shapes: BTreeMap<&str, Shape> = BTreeMap::new();
        let mut evidence: Vec<String> = Vec::new();
        let mut unknown = 0;
        for observation in observations {
            if !evidence.contains(&observation.evidence) && evidence.len() < 5 {
                evidence.push(observation.evidence.clone());
            }
            match &observation.response_json {
                Some(value) => shapes
                    .entry(&observation.response_type)
                    .or_default()
                    .observe(value, 0, options, &observation.evidence),
                None if observation.body_gap => unknown += 1,
                None => {}
            }
        }
        for id in &evidence {
            if all_evidence.len() < 5 && !all_evidence.contains(id) {
                all_evidence.push(id.clone());
            }
        }
        let mut response = Map::new();
        response.insert(
            "description".to_owned(),
            json!(format!("Observed response (HTTP {status})")),
        );
        if !shapes.is_empty() {
            let mut content = Map::new();
            for (media, shape) in &shapes {
                content.insert((*media).to_owned(), json!({"schema": shape.render()}));
            }
            response.insert("content".to_owned(), Value::Object(content));
        }
        response.insert(
            "x-proxyx-observed".to_owned(),
            json!({"samples": observations.len(), "evidence": evidence, "bodies_unknown": unknown}),
        );
        let key = if (100..=599).contains(status) {
            status.to_string()
        } else {
            "default".to_owned()
        };
        responses.insert(key, Value::Object(response));
    }
    operation.insert("responses".to_owned(), Value::Object(responses));
    operation.insert(
        "operationId".to_owned(),
        json!(operation_id(method, template)),
    );
    operation.insert("x-proxyx-route-ref".to_owned(), json!(route_ref));
    operation.insert(
        "x-proxyx-observed".to_owned(),
        json!({"samples": group.len(), "evidence": all_evidence}),
    );
    Value::Object(operation)
}

fn operation_id(method: &str, template: &Template) -> String {
    let mut out = method.to_ascii_lowercase();
    for seg in template {
        let word = match seg {
            Seg::Lit(text) => text.clone(),
            Seg::Param => "by".to_owned(),
        };
        let mut upper = true;
        for ch in word.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(if upper { ch.to_ascii_uppercase() } else { ch });
                upper = false;
            } else {
                upper = true;
            }
        }
    }
    if out.len() > 64 {
        out.truncate(64);
    }
    out
}

/// Apply operation names from a model: only to routes this draft has, only as
/// `operationId` and `summary`. Returns how many were applied.
pub fn apply_names(draft: &mut Draft, names: &[(String, String, String)]) -> usize {
    let mut applied = 0;
    let mut used: BTreeSet<String> = BTreeSet::new();
    for document in draft.documents.values() {
        for item in document["paths"]
            .as_object()
            .into_iter()
            .flat_map(Map::values)
        {
            for operation in item.as_object().into_iter().flat_map(Map::values) {
                if let Some(id) = operation["operationId"].as_str() {
                    used.insert(id.to_owned());
                }
            }
        }
    }
    for document in draft.documents.values_mut() {
        let Some(paths) = document["paths"].as_object_mut() else {
            continue;
        };
        for item in paths.values_mut() {
            let Some(operations) = item.as_object_mut() else {
                continue;
            };
            for operation in operations.values_mut() {
                let Some(route_ref) = operation["x-proxyx-route-ref"].as_str().map(str::to_owned)
                else {
                    continue;
                };
                let Some((_, id, summary)) = names.iter().find(|(r, _, _)| *r == route_ref) else {
                    continue;
                };
                let valid = (1..=64).contains(&id.len())
                    && id.starts_with(|c: char| c.is_ascii_alphabetic())
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !valid || used.contains(id) {
                    continue;
                }
                if let Some(old) = operation["operationId"].as_str() {
                    used.remove(old);
                }
                used.insert(id.clone());
                operation["operationId"] = json!(id);
                let summary: String = crate::redact::redact_text(summary)
                    .chars()
                    .take(120)
                    .collect();
                operation["summary"] = json!(summary);
                operation["x-proxyx-naming"] =
                    json!("model-suggested wording; paths, methods and servers come from captures");
                applied += 1;
            }
        }
    }
    applied
}

/// The data a model may see about routes: names and types, never values.
pub fn route_digest(draft: &Draft) -> Value {
    let mut out = Vec::new();
    for document in draft.documents.values() {
        for (path, item) in document["paths"].as_object().into_iter().flatten() {
            for (method, operation) in item.as_object().into_iter().flatten() {
                let names = |schema: &Value| -> Vec<String> {
                    schema["properties"]
                        .as_object()
                        .map(|map| map.keys().take(30).cloned().collect())
                        .unwrap_or_default()
                };
                let response_props: Vec<String> = operation["responses"]
                    .as_object()
                    .into_iter()
                    .flat_map(Map::values)
                    .flat_map(|response| {
                        response["content"]
                            .as_object()
                            .into_iter()
                            .flat_map(Map::values)
                            .flat_map(|content| names(&content["schema"]))
                    })
                    .take(30)
                    .collect();
                out.push(json!({
                    "route_ref": operation["x-proxyx-route-ref"],
                    "method": method,
                    "path": path,
                    "response_properties": response_props,
                }));
            }
        }
    }
    Value::Array(out)
}

/// Check a document against the parts of OpenAPI 3.1 this inferencer emits. Returns every problem.
pub fn validate(document: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    if !document["openapi"]
        .as_str()
        .is_some_and(|v| v.starts_with("3.1"))
    {
        problems.push("openapi must be a 3.1 version string".to_owned());
    }
    for field in ["title", "version"] {
        if !document["info"][field]
            .as_str()
            .is_some_and(|v| !v.is_empty())
        {
            problems.push(format!("info.{field} is required"));
        }
    }
    let Some(paths) = document["paths"].as_object() else {
        problems.push("paths must be an object".to_owned());
        return problems;
    };
    for (path, item) in paths {
        if !path.starts_with('/') {
            problems.push(format!("path {path:?} must start with /"));
        }
        let placeholders: Vec<&str> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .collect();
        let Some(operations) = item.as_object() else {
            problems.push(format!("{path}: a path item must be an object"));
            continue;
        };
        for (method, operation) in operations {
            let here = format!("{path} {method}");
            if ![
                "get", "put", "post", "delete", "options", "head", "patch", "trace",
            ]
            .contains(&method.as_str())
            {
                problems.push(format!("{here}: not an HTTP method"));
            }
            let declared: Vec<&str> = operation["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["in"] == "path")
                .filter_map(|p| p["name"].as_str())
                .collect();
            for placeholder in &placeholders {
                if !declared.contains(placeholder) {
                    problems.push(format!(
                        "{here}: path parameter {placeholder:?} is not declared"
                    ));
                }
            }
            for parameter in operation["parameters"].as_array().into_iter().flatten() {
                if parameter["in"] == "path" && parameter["required"] != true {
                    problems.push(format!("{here}: a path parameter must be required"));
                }
                if !parameter["name"].is_string() || !parameter["in"].is_string() {
                    problems.push(format!("{here}: a parameter needs name and in"));
                }
            }
            match operation["responses"].as_object() {
                Some(responses) if !responses.is_empty() => {
                    for (code, response) in responses {
                        let ok = code == "default"
                            || (code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
                        if !ok {
                            problems.push(format!("{here}: {code:?} is not a status code"));
                        }
                        if !response["description"].is_string() {
                            problems.push(format!("{here} {code}: description is required"));
                        }
                    }
                }
                _ => problems.push(format!("{here}: responses must not be empty")),
            }
            if operation["x-proxyx-observed"]["evidence"]
                .as_array()
                .is_none_or(Vec::is_empty)
            {
                problems.push(format!("{here}: no evidence"));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_words_are_printed_in_a_path() {
        for id in [
            "123",
            "0190aaaa-0000-4000-8000-000000000001",
            "deadbeef01",
            "a1b2c3d4e5f6g7h8",
            "alice@example.com",
            "9f8e7d6c5b4a39281716f5e4d3c2b1a0",
            "kJh3Xz9Q",
        ] {
            assert!(!plain_word(id), "{id}");
        }
        for word in [
            "me",
            "search",
            "latest",
            "v1",
            "oauth2",
            "users",
            ".well-known",
            "robots.txt",
            "openid-configuration",
        ] {
            assert!(plain_word(word), "{word}");
        }
    }

    #[test]
    fn unsafe_keys_are_collapsed_into_one_shape() {
        let mut shape = Shape::default();
        let options = options();
        shape.observe(
            &json!({"alice@example.com": {"n": 1}, "bob@example.com": {"n": 2}, "plain": 1}),
            0,
            &options,
            "ev_1",
        );
        let schema = shape.render();
        let text = schema.to_string();
        assert!(!text.contains("alice") && !text.contains("bob"), "{text}");
        assert_eq!(
            schema["additionalProperties"]["properties"]["n"]["type"],
            "integer"
        );
        assert!(schema["properties"]["plain"].is_object());
        assert!(schema["x-proxyx-observed"]["keys_withheld"].is_string());
    }

    fn options() -> Options {
        Options {
            max_routes: 50,
            max_depth: 12,
            max_properties: 50,
            allowed_content_types: vec!["application/json".to_owned()],
        }
    }

    #[test]
    fn shapes_merge_without_claiming_requirements() {
        let mut shape = Shape::default();
        let options = options();
        shape.observe(
            &json!({"id": 1, "name": "a", "tags": []}),
            0,
            &options,
            "ev_1",
        );
        shape.observe(
            &json!({"id": 2, "name": null, "extra": true}),
            0,
            &options,
            "ev_2",
        );
        let schema = shape.render();
        assert_eq!(schema["properties"]["id"]["type"], "integer");
        assert_eq!(
            schema["properties"]["name"]["type"],
            json!(["null", "string"])
        );
        assert_eq!(schema["x-proxyx-observed-required"], json!(["id", "name"]));
        assert!(schema.get("required").is_none());
        assert_eq!(
            schema["properties"]["tags"]["x-proxyx-observed"]["items_unknown"],
            "only empty arrays were observed"
        );
        let mut conflict = Shape::default();
        conflict.observe(&json!({"v": 1}), 0, &options, "ev_1");
        conflict.observe(&json!({"v": "x"}), 0, &options, "ev_2");
        assert_eq!(
            conflict.render()["properties"]["v"]["x-proxyx-observed"]["conflicting_types"],
            true
        );
    }

    #[test]
    fn depth_and_property_caps_are_visible() {
        let mut options = options();
        options.max_depth = 2;
        options.max_properties = 2;
        let mut shape = Shape::default();
        shape.observe(
            &json!({"a": {"b": {"c": {"d": 1}}}, "x": 1, "y": 2}),
            0,
            &options,
            "ev_1",
        );
        let schema = shape.render();
        assert_eq!(
            schema["x-proxyx-observed"]["truncated"],
            "depth or property limit reached"
        );
    }

    #[test]
    fn the_validator_catches_missing_path_parameters() {
        let document = json!({
            "openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a/{id}": {"get": {"responses": {"200": {"description": "ok"}},
                "x-proxyx-observed": {"evidence": ["ev_1"]}}}}
        });
        assert!(
            validate(&document)
                .iter()
                .any(|p| p.contains("not declared"))
        );
    }
}
