//! Validation of tool arguments against the JSON Schema subset the tools advertise.
//!
//! The schema value sent to the client in `tools/list` is the value enforced here, so what a
//! tool advertises is what it accepts. Supported keywords: `type` (`object`, `string`,
//! `integer`, `number`, `boolean`, `array`), `enum`, `properties`, `required`,
//! `additionalProperties` (`false`, or a schema), `items`, `minimum`, `maximum`, `minLength`,
//! `maxLength`, `minItems`, `maxItems`, `pattern` and `format` (`uuid`, `ip`).
//!
//! Tolerance is deliberate and narrow: `null` for an optional property counts as absent
//! (models send it often). Unknown properties are rejected, not dropped, so a model that
//! misspells `dry_run` is told instead of silently running a real change.

use std::net::IpAddr;

use regex::Regex;
use serde_json::{Map, Value};

/// Most issues reported at once; the model fixes them in one round trip.
const MAX_ISSUES: usize = 8;

/// Check `value` against `schema`; return it with `null` members of optional properties removed.
///
/// # Errors
/// Every violation found (at most [`MAX_ISSUES`]), each prefixed with its JSON path.
pub fn check(schema: &Value, value: Value) -> Result<Value, Vec<String>> {
    let mut issues = Vec::new();
    let out = walk(schema, value, "arguments", &mut issues);
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(issues)
    }
}

fn push(issues: &mut Vec<String>, message: String) {
    if issues.len() < MAX_ISSUES {
        issues.push(message);
    }
}

fn walk(schema: &Value, value: Value, path: &str, issues: &mut Vec<String>) -> Value {
    let Some(schema) = schema.as_object() else {
        return value;
    };
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !type_matches(expected, &value)
    {
        push(
            issues,
            format!("{path}: expected {expected}, got {}", kind(&value)),
        );
        return value;
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(&value)
    {
        let list: Vec<String> = allowed.iter().map(Value::to_string).collect();
        push(
            issues,
            format!("{path}: must be one of {}", list.join(", ")),
        );
        return value;
    }
    match value {
        Value::Object(map) => Value::Object(walk_object(schema, map, path, issues)),
        Value::Array(items) => Value::Array(walk_array(schema, items, path, issues)),
        Value::String(text) => {
            check_string(schema, &text, path, issues);
            Value::String(text)
        }
        Value::Number(number) => {
            if let Some(n) = number.as_f64() {
                check_number(schema, n, path, issues);
            }
            Value::Number(number)
        }
        other => other,
    }
}

fn walk_object(
    schema: &Map<String, Value>,
    map: Map<String, Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Map<String, Value> {
    let empty = Map::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let additional = schema.get("additionalProperties");
    let mut out = Map::new();
    for (name, member) in map {
        let child = format!("{path}.{name}");
        match properties.get(&name) {
            Some(_) if member.is_null() && !required.contains(&name.as_str()) => {}
            Some(property) => {
                let checked = walk(property, member, &child, issues);
                out.insert(name, checked);
            }
            None => match additional {
                Some(Value::Bool(false)) => push(
                    issues,
                    format!(
                        "{child}: unknown property (accepted: {})",
                        names(properties)
                    ),
                ),
                Some(extra @ Value::Object(_)) => {
                    let checked = walk(extra, member, &child, issues);
                    out.insert(name, checked);
                }
                _ => {
                    out.insert(name, member);
                }
            },
        }
    }
    for name in required {
        if !out.contains_key(name) {
            push(issues, format!("{path}.{name}: required"));
        }
    }
    out
}

fn names(properties: &Map<String, Value>) -> String {
    let mut list: Vec<&str> = properties.keys().map(String::as_str).collect();
    list.sort_unstable();
    list.join(", ")
}

fn walk_array(
    schema: &Map<String, Value>,
    items: Vec<Value>,
    path: &str,
    issues: &mut Vec<String>,
) -> Vec<Value> {
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
        && (items.len() as u64) < min
    {
        push(issues, format!("{path}: needs at least {min} items"));
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
        && items.len() as u64 > max
    {
        push(issues, format!("{path}: allows at most {max} items"));
    }
    match schema.get("items") {
        Some(item_schema) => items
            .into_iter()
            .enumerate()
            .map(|(index, item)| walk(item_schema, item, &format!("{path}[{index}]"), issues))
            .collect(),
        None => items,
    }
}

fn check_string(schema: &Map<String, Value>, text: &str, path: &str, issues: &mut Vec<String>) {
    let length = text.chars().count() as u64;
    if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
        && length < min
    {
        push(issues, format!("{path}: needs at least {min} characters"));
    }
    if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
        && length > max
    {
        push(issues, format!("{path}: allows at most {max} characters"));
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        match Regex::new(pattern) {
            Ok(regex) if !regex.is_match(text) => {
                push(issues, format!("{path}: must match {pattern}"));
            }
            Ok(_) | Err(_) => {}
        }
    }
    match schema.get("format").and_then(Value::as_str) {
        Some("uuid") if !is_uuid(text) => push(issues, format!("{path}: must be a UUID")),
        Some("ip") if text.parse::<IpAddr>().is_err() => {
            push(issues, format!("{path}: must be an IP address"));
        }
        _ => {}
    }
}

fn check_number(schema: &Map<String, Value>, n: f64, path: &str, issues: &mut Vec<String>) {
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
        && n < min
    {
        push(issues, format!("{path}: must be at least {min}"));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
        && n > max
    {
        push(issues, format!("{path}: must be at most {max}"));
    }
}

/// 8-4-4-4-12 hexadecimal digits.
pub fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "org": {"type": "string", "pattern": "^[a-z0-9_-]{1,64}$"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                "mode": {"type": "string", "enum": ["a", "b"]},
                "ids": {"type": "array", "items": {"type": "string", "format": "uuid"}, "maxItems": 2},
                "dry_run": {"type": "boolean"}
            },
            "required": ["org"],
            "additionalProperties": false
        })
    }

    #[test]
    fn accepts_valid_and_drops_null_optionals() {
        let out = check(
            &schema(),
            json!({"org": "acme", "limit": null, "dry_run": true}),
        )
        .expect("valid arguments");
        assert_eq!(out, json!({"org": "acme", "dry_run": true}));
    }

    #[test]
    fn reports_every_problem_with_paths() {
        let issues = check(
            &schema(),
            json!({"limit": 99, "mode": "z", "ids": ["x", "y", "z"], "dryrun": true}),
        )
        .expect_err("invalid arguments");
        let text = issues.join("\n");
        for needle in [
            "arguments.org: required",
            "arguments.limit: must be at most 10",
            "arguments.mode: must be one of",
            "arguments.ids: allows at most 2 items",
            "arguments.ids[0]: must be a UUID",
            "arguments.dryrun: unknown property",
        ] {
            assert!(text.contains(needle), "{needle} missing from\n{text}");
        }
    }

    #[test]
    fn integers_are_not_floats() {
        assert!(check(&schema(), json!({"org": "a", "limit": 1.5})).is_err());
        assert!(check(&schema(), json!({"org": "A"})).is_err());
    }
}
