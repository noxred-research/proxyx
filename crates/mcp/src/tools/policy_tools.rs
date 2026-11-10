//! Policy parsing, validation and diffing with the gateway's own crate (`proxyx-policy`).
//!
//! The pool control API validates every write as part of the whole set, plus facts only the
//! gateway knows (the loaded provider adapters and their session life). This module checks
//! everything that can be checked offline: strict document parsing, merged-set rules (ceilings,
//! required regions, duplicate names) against the policies already stored, so a bad draft is
//! rejected before it reaches the API, and so a diff against the current document can be shown.

use common::types::OrgId;
use policy::{PolicyDoc, PolicyFile, PolicySet, Scope};
use serde_json::{Map, Value, json};

use super::util::{Args, ToolError};

/// Policy documents from either input form.
///
/// # Errors
/// When both or neither input is given, or a document does not parse strictly.
pub fn parse_input(args: &Args) -> Result<Vec<PolicyDoc>, ToolError> {
    match (
        args.str("toml"),
        args.get("policies").and_then(Value::as_array),
    ) {
        (Some(_), Some(_)) => Err(ToolError::invalid(
            "give either `toml` or `policies`, not both",
        )),
        (None, None) => Err(ToolError::invalid(
            "give `toml` (a [[policy]] file) or `policies` (JSON documents)",
        )),
        (Some(text), None) => PolicyFile::parse(text)
            .map(|file| file.policies)
            .map_err(|error| ToolError::invalid(format!("the policy does not parse: {error}"))),
        (None, Some(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                serde_json::from_value::<PolicyDoc>(item.clone()).map_err(|error| {
                    ToolError::invalid(format!("policies[{index}] does not parse: {error}"))
                })
            })
            .collect(),
    }
    .and_then(|docs| {
        if docs.is_empty() {
            Err(ToolError::invalid("the input holds no policy"))
        } else {
            Ok(docs)
        }
    })
}

/// One stored policy as `GET /v1/policies` reports it.
#[derive(Debug, Clone)]
pub struct Stored {
    pub scope: String,
    pub name: String,
    pub actor: String,
    pub doc: PolicyDoc,
    pub raw: Value,
}

/// The stored policies of a `GET /v1/policies` body.
///
/// # Errors
/// When an item does not have the documented shape.
pub fn stored_policies(body: &Value) -> Result<Vec<Stored>, String> {
    let items = body["items"]
        .as_array()
        .ok_or_else(|| "the policies answer has no `items` list".to_owned())?;
    items
        .iter()
        .map(|item| {
            let doc: PolicyDoc = serde_json::from_value(item["doc"].clone())
                .map_err(|error| format!("a stored policy does not parse: {error}"))?;
            Ok(Stored {
                scope: item["scope"].as_str().unwrap_or("").to_owned(),
                name: item["name"].as_str().unwrap_or("").to_owned(),
                actor: item["actor"].as_str().unwrap_or("").to_owned(),
                raw: compact(&serde_json::to_value(&doc).unwrap_or(Value::Null)),
                doc,
            })
        })
        .collect()
}

/// The merged set of the stored policies.
///
/// # Errors
/// When the stored policies do not parse or do not form a valid set.
pub fn policy_set_from_listing(body: &Value) -> Result<PolicySet, String> {
    let docs = stored_policies(body)?
        .into_iter()
        .map(|stored| stored.doc)
        .collect();
    PolicySet::from_docs(docs).map_err(|error| error.to_string())
}

/// Replace the stored policies that `incoming` names (same scope and name) and validate the
/// whole set.
///
/// # Errors
/// The gateway's own validation message.
pub fn validate_merged(stored: &[Stored], incoming: &[PolicyDoc]) -> Result<PolicySet, String> {
    let mut docs: Vec<PolicyDoc> = stored
        .iter()
        .filter(|current| {
            !incoming
                .iter()
                .any(|doc| doc.scope.to_string() == current.scope && doc.name == current.name)
        })
        .map(|current| current.doc.clone())
        .collect();
    docs.extend(incoming.iter().cloned());
    PolicySet::from_docs(docs).map_err(|error| error.to_string())
}

/// Remove nulls and empty objects: the compact form of a document.
pub fn compact(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, member) in map {
                let member = compact(member);
                let empty = member.is_null() || member.as_object().is_some_and(Map::is_empty);
                if !empty {
                    out.insert(key.clone(), member);
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// A document as the compact JSON the API takes.
pub fn doc_json(doc: &PolicyDoc) -> Value {
    compact(&serde_json::to_value(doc).unwrap_or(Value::Null))
}

fn flatten(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (key, member) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&path, member, out);
            }
        }
        other => out.push((prefix.to_owned(), other.clone())),
    }
}

/// Field-level changes from `old` to `new` (compact documents).
pub fn diff_docs(old: Option<&Value>, new: &Value) -> Vec<Value> {
    let mut before = Vec::new();
    let mut after = Vec::new();
    if let Some(old) = old {
        flatten("", old, &mut before);
    }
    flatten("", new, &mut after);
    let mut changes = Vec::new();
    for (path, value) in &after {
        match before.iter().find(|(p, _)| p == path) {
            None => changes.push(json!({"path": path, "from": null, "to": value})),
            Some((_, old_value)) if old_value != value => {
                changes.push(json!({"path": path, "from": old_value, "to": value}));
            }
            Some(_) => {}
        }
    }
    for (path, value) in &before {
        if !after.iter().any(|(p, _)| p == path) {
            changes.push(json!({"path": path, "from": value, "to": null}));
        }
    }
    changes
}

/// What the merged set gives one org (or the default row), for a preview.
pub fn effective_summary(set: &PolicySet, org: Option<&str>) -> Value {
    let effective = match org.and_then(|org| org.parse::<OrgId>().ok()) {
        Some(org) => set.effective(&org, None),
        None => set.effective_default(None),
    };
    json!({
        "kinds": effective.kinds.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "providers": effective.providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "regions": effective.regions.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "lease_ttl_secs": effective.lease_ttl.as_secs(),
        "max_tunnels_per_org": effective.max_tunnels_per_org,
        "org_max_gb_per_day": effective.limits.org_max_gb_per_day,
        "sticky_scope": format!("{:?}", effective.sticky_scope).to_lowercase(),
    })
}

/// A short statement of what a document covers: `org/acme-limits`.
pub fn doc_label(doc: &PolicyDoc) -> String {
    format!("{}/{}", doc.scope, doc.name)
}

/// The scope word of a document.
pub fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::Global => "global",
        Scope::RouteClass => "route_class",
        Scope::Org => "org",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL: &str = r#"
[[policy]]
name = "global"
scope = "global"
kinds = ["rotating"]
regions = ["fr"]
min_ready = 4
"#;

    fn stored_from(toml: &str) -> Vec<Stored> {
        let docs = PolicyFile::parse(toml).expect("parse").policies;
        let items: Vec<Value> = docs
            .iter()
            .map(|doc| {
                json!({
                    "scope": scope_name(doc.scope),
                    "name": doc.name,
                    "match": doc.target,
                    "version": 1,
                    "actor": "gitops",
                    "doc": serde_json::to_value(doc).expect("doc json"),
                })
            })
            .collect();
        stored_policies(&json!({"items": items})).expect("stored")
    }

    #[test]
    fn strict_parsing_names_the_problem() {
        let args = Args::from_value(json!({"toml": "[[policy]]\nname = \"x\"\nmin_redy = 3"}));
        let error = parse_input(&args).expect_err("unknown field");
        assert!(error.message.contains("min_redy"), "{}", error.message);
        let both = Args::from_value(json!({"toml": GLOBAL, "policies": []}));
        assert!(parse_input(&both).is_err());
        assert!(parse_input(&Args::default()).is_err());
    }

    #[test]
    fn merged_validation_uses_the_stored_set() {
        let stored = stored_from(GLOBAL);
        let good = parse_input(&Args::from_value(json!({
            "policies": [{"name": "acme", "scope": "org", "match": "acme", "min_ready": 8, "limits": {"org_max_gb_per_day": 5}}]
        })))
        .expect("parse");
        let set = validate_merged(&stored, &good).expect("valid merge");
        assert_eq!(
            effective_summary(&set, Some("acme"))["regions"],
            json!(["fr"])
        );
        let bad = parse_input(&Args::from_value(json!({
            "policies": [{"name": "acme", "scope": "org", "match": "acme", "regions": []}]
        })))
        .expect("parse");
        assert!(
            validate_merged(&stored, &bad).is_err(),
            "an org policy cannot leave the set without regions"
        );
        // an org policy with no global policy cannot form a set
        assert!(validate_merged(&[], &good).is_err());
    }

    #[test]
    fn replaced_policies_are_not_duplicates() {
        let stored = stored_from(GLOBAL);
        let replacement = parse_input(&Args::from_value(json!({
            "policies": [{"name": "global", "scope": "global", "kinds": ["rotating"], "regions": ["de"], "min_ready": 2}]
        })))
        .expect("parse");
        let set = validate_merged(&stored, &replacement).expect("same name replaces");
        assert_eq!(effective_summary(&set, None)["regions"], json!(["de"]));
    }

    #[test]
    fn diff_lists_added_changed_and_removed_fields() {
        let old = json!({"name": "a", "min_ready": 4, "limits": {"org_max_gb_per_day": 5}});
        let new = json!({"name": "a", "min_ready": 8, "rotating": {"headroom": 1}});
        let diff = diff_docs(Some(&old), &new);
        let paths: Vec<&str> = diff.iter().filter_map(|c| c["path"].as_str()).collect();
        assert!(paths.contains(&"min_ready"));
        assert!(paths.contains(&"rotating.headroom"));
        assert!(paths.contains(&"limits.org_max_gb_per_day"));
        assert_eq!(diff_docs(Some(&new), &new).len(), 0);
        assert_eq!(
            compact(&json!({"a": null, "b": {}, "c": {"d": null}, "e": 1})),
            json!({"e": 1})
        );
    }
}
