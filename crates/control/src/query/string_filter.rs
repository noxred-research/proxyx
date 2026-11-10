//! String-valued filter tree for the columns exposed via `TrafficQuery`.
//!
//! `StringFilter` covers the operators a caller actually wants for HTTP
//! traffic: substring match (case-insensitive — the only substring form
//! we expose), exact equality, RE2 regex, byte-length predicates over
//! `IntFilter`, and explicit NULL/present checks. `All` / `Any` / `Not`
//! compose them per-column.
//!
//! ## tokenbf body optimization
//!
//! The body columns carry `lower(body)` `tokenbf_v1` skip indexes (see
//! `clickhouse/indexes.sql`). ClickHouse 24.x does not extract tokens
//! from `LIKE` patterns (issue #68985), so a plain `lower(body) LIKE
//! '%foo%'` reads every granule even when the bloom would prune most of
//! them. For single-token alphanumeric patterns we additionally emit
//! `hasToken(lower(body), lower(?))`, which the planner translates to a
//! direct bloom probe. The trailing `LIKE` keeps the result
//! semantically identical (`hasToken` matches whole tokens; `LIKE` keeps
//! substring semantics for, say, `foo` inside `foobar`).

use serde::{Deserialize, Serialize};

use super::int_filter::{IntFilter, NonEmpty, lower_int, paren_join};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StringFilter {
    /// Case-insensitive substring match. The only substring operator we
    /// expose — case-sensitive callers use `RegexMatch`.
    Contains {
        value: String,
    },
    Exact {
        value: String,
    },
    /// RE2 regex, unanchored, case-sensitive. Use `(?i)` for case
    /// insensitivity. Patterns are pre-validated at the API entrypoint.
    RegexMatch {
        value: String,
    },
    /// Octet length over the column. Composes any `IntFilter`.
    Length {
        value: IntFilter,
    },
    IsNull,
    IsPresent,
    All {
        filters: NonEmpty<StringFilter>,
    },
    Any {
        filters: NonEmpty<StringFilter>,
    },
    Not {
        filter: Box<StringFilter>,
    },
}

/// Static description of a filterable column. The filter lowerer needs
/// to know two things beyond the column name: whether `lower(col)`
/// carries a tokenbf skip index (gates the `hasToken` probe), and
/// whether the column is nullable (informational — `IsNull` /
/// `IsPresent` are legal on any column).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ColumnDescriptor {
    pub name: &'static str,
    pub has_lower_tokenbf: bool,
}

impl ColumnDescriptor {
    const fn plain(name: &'static str) -> Self {
        Self {
            name,
            has_lower_tokenbf: false,
        }
    }
    const fn body(name: &'static str) -> Self {
        Self {
            name,
            has_lower_tokenbf: true,
        }
    }
}

pub(crate) const HOST: ColumnDescriptor = ColumnDescriptor::plain("host");
pub(crate) const METHOD: ColumnDescriptor = ColumnDescriptor::plain("method");
pub(crate) const PATH: ColumnDescriptor = ColumnDescriptor::plain("path");
pub(crate) const REQUEST_BODY: ColumnDescriptor = ColumnDescriptor::body("request_body");
pub(crate) const RESPONSE_BODY: ColumnDescriptor = ColumnDescriptor::body("response_body");
pub(crate) const CORRELATION_ID: ColumnDescriptor = ColumnDescriptor::plain("correlation_id");
pub(crate) const PARENT_CORRELATION_ID: ColumnDescriptor =
    ColumnDescriptor::plain("parent_correlation_id");
pub(crate) const ACCOUNT_ID: ColumnDescriptor = ColumnDescriptor::plain("account_id");
pub(crate) const TOOL_CALL_ID: ColumnDescriptor = ColumnDescriptor::plain("tool_call_id");
/// Response media type: the first `Content-Type` value (header names keep
/// their wire case, so matched case-insensitively) without parameters,
/// lower-cased. `''` when the response has no `Content-Type`.
pub(crate) const MIME_TYPE: ColumnDescriptor = ColumnDescriptor::plain(
    "lower(trimBoth(splitByChar(';', arrayFirst((v, k) -> lower(k) = 'content-type', \
     mapValues(response_headers), mapKeys(response_headers)))[1]))",
);

// WebSocket column descriptors. `payload` carries a tokenbf body index
// (matches the http_captures request_body / response_body pattern); the
// rest are plain string columns. CH `Enum8` columns (direction, opcode)
// expose as plain string columns at the filter level — implicit
// String<->Enum conversion at WHERE time means a `lower_string` fragment
// against an Enum8 column with a string bind is accepted as-is.
pub(crate) const WS_HOST: ColumnDescriptor = ColumnDescriptor::plain("host");
pub(crate) const WS_PAYLOAD: ColumnDescriptor = ColumnDescriptor::body("payload");
// `direction`/`opcode` are CH `Enum8`. `lower(...)` and `match(...)` both
// require `String`, so the column expression is `toString(...)` rather than
// the raw column name. CH still uses the underlying Enum8 sort key + skip
// indexes when the predicate folds back to a constant compare.
pub(crate) const WS_DIRECTION: ColumnDescriptor = ColumnDescriptor::plain("toString(direction)");
pub(crate) const WS_OPCODE: ColumnDescriptor = ColumnDescriptor::plain("toString(opcode)");
pub(crate) const WS_CLOSE_REASON: ColumnDescriptor = ColumnDescriptor::plain("close_reason");

/// Escape LIKE wildcards. ClickHouse's default `LIKE` escape character
/// is backslash; values bind through positional `?` so we don't need to
/// quote the string itself.
pub(crate) fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// True for short, single-token patterns where the body bloom probe is
/// safe and useful. ClickHouse's tokenbf tokenizer splits on any
/// non-alphanumeric byte; `hasToken` rejects needles containing separators
/// such as `_`, `-`, or whitespace. Keep this predicate intentionally
/// stricter than substring semantics: anything outside ClickHouse's token
/// alphabet must fall back to `LIKE`.
fn is_single_token(s: &str) -> bool {
    s.len() >= 3 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Lower a `StringFilter` against the named column. Returns a SQL
/// fragment; positional bind values are pushed onto `binds` in the
/// order `?` placeholders appear in the fragment.
pub(crate) fn lower_string(
    col: &ColumnDescriptor,
    f: &StringFilter,
    binds: &mut Vec<String>,
) -> String {
    let name = col.name;
    match f {
        StringFilter::Contains { value } => {
            let pattern = format!("%{}%", escape_like(value));
            if col.has_lower_tokenbf && is_single_token(value) {
                // Bloom-prune via hasToken, refine via LIKE for substring
                // semantics. Both operands case-insensitive.
                binds.push(value.clone());
                binds.push(pattern);
                format!("hasToken(lower({name}), lower(?)) AND lower({name}) LIKE lower(?)")
            } else {
                binds.push(pattern);
                format!("lower({name}) LIKE lower(?)")
            }
        }
        StringFilter::Exact { value } => {
            binds.push(value.clone());
            format!("{name} = ?")
        }
        StringFilter::RegexMatch { value } => {
            binds.push(value.clone());
            format!("match({name}, ?)")
        }
        StringFilter::Length { value } => {
            let length_expr = format!("length({name})");
            lower_int(&length_expr, value, binds)
        }
        StringFilter::IsNull => format!("{name} IS NULL"),
        StringFilter::IsPresent => format!("{name} IS NOT NULL"),
        StringFilter::All { filters } => paren_join(
            " AND ",
            filters.0.iter().map(|f| lower_string(col, f, binds)),
        ),
        StringFilter::Any { filters } => paren_join(
            " OR ",
            filters.0.iter().map(|f| lower_string(col, f, binds)),
        ),
        StringFilter::Not { filter } => {
            format!("NOT ({})", lower_string(col, filter, binds))
        }
    }
}

/// Recursively collect every `RegexMatch` pattern in the filter tree.
/// Used by the API entrypoint to pre-validate patterns with the `regex`
/// crate before sending the query to ClickHouse.
pub(crate) fn collect_regex_patterns<'a>(f: &'a StringFilter, out: &mut Vec<&'a str>) {
    match f {
        StringFilter::RegexMatch { value } => out.push(value.as_str()),
        StringFilter::All { filters } | StringFilter::Any { filters } => {
            for c in &filters.0 {
                collect_regex_patterns(c, out);
            }
        }
        StringFilter::Not { filter } => collect_regex_patterns(filter, out),
        // Length wraps an IntFilter — no string regex inside.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(col: ColumnDescriptor, f: &StringFilter) -> (String, Vec<String>) {
        let mut binds = Vec::new();
        let sql = lower_string(&col, f, &mut binds);
        (sql, binds)
    }

    #[test]
    fn contains_non_body_uses_plain_like() {
        let (sql, binds) = lower(
            HOST,
            &StringFilter::Contains {
                value: "Stripe".to_string(),
            },
        );
        assert_eq!(sql, "lower(host) LIKE lower(?)");
        assert_eq!(binds, vec!["%Stripe%"]);
    }

    #[test]
    fn contains_body_single_token_uses_has_token() {
        let (sql, binds) = lower(
            RESPONSE_BODY,
            &StringFilter::Contains {
                value: "openresty".to_string(),
            },
        );
        assert_eq!(
            sql,
            "hasToken(lower(response_body), lower(?)) AND lower(response_body) LIKE lower(?)"
        );
        assert_eq!(binds, vec!["openresty", "%openresty%"]);
    }

    #[test]
    fn contains_body_multiword_falls_back_to_like() {
        let (sql, binds) = lower(
            RESPONSE_BODY,
            &StringFilter::Contains {
                value: "open resty".to_string(),
            },
        );
        assert_eq!(sql, "lower(response_body) LIKE lower(?)");
        assert_eq!(binds, vec!["%open resty%"]);
    }

    #[test]
    fn contains_body_separator_falls_back_to_like() {
        let (sql, binds) = lower(
            REQUEST_BODY,
            &StringFilter::Contains {
                value: "anonymous_visitor".to_string(),
            },
        );
        assert_eq!(sql, "lower(request_body) LIKE lower(?)");
        assert_eq!(binds, vec!["%anonymous\\_visitor%"]);
    }

    #[test]
    fn contains_body_punctuation_falls_back_to_like() {
        let (sql, binds) = lower(
            REQUEST_BODY,
            &StringFilter::Contains {
                value: "X-Frame".to_string(),
            },
        );
        assert_eq!(sql, "lower(request_body) LIKE lower(?)");
        assert_eq!(binds, vec!["%X-Frame%"]);
    }

    #[test]
    fn contains_body_short_pattern_falls_back_to_like() {
        let (sql, binds) = lower(
            REQUEST_BODY,
            &StringFilter::Contains {
                value: "ab".to_string(),
            },
        );
        assert_eq!(sql, "lower(request_body) LIKE lower(?)");
        assert_eq!(binds, vec!["%ab%"]);
    }

    #[test]
    fn exact_method() {
        let (sql, binds) = lower(
            METHOD,
            &StringFilter::Exact {
                value: "GET".to_string(),
            },
        );
        assert_eq!(sql, "method = ?");
        assert_eq!(binds, vec!["GET"]);
    }

    #[test]
    fn regex_match() {
        let (sql, binds) = lower(
            PATH,
            &StringFilter::RegexMatch {
                value: "^/api/v\\d+/".to_string(),
            },
        );
        assert_eq!(sql, "match(path, ?)");
        assert_eq!(binds, vec!["^/api/v\\d+/"]);
    }

    #[test]
    fn length_composes_int_filter() {
        let (sql, binds) = lower(
            PATH,
            &StringFilter::Length {
                value: IntFilter::All {
                    filters: NonEmpty(vec![
                        IntFilter::Gte { value: 1 },
                        IntFilter::Lte { value: 200 },
                    ]),
                },
            },
        );
        assert_eq!(sql, "(length(path) >= 1 AND length(path) <= 200)");
        assert!(binds.is_empty());
    }

    #[test]
    fn is_null_and_is_present() {
        let (sql, _) = lower(CORRELATION_ID, &StringFilter::IsNull);
        assert_eq!(sql, "correlation_id IS NULL");
        let (sql, _) = lower(CORRELATION_ID, &StringFilter::IsPresent);
        assert_eq!(sql, "correlation_id IS NOT NULL");
    }

    #[test]
    fn all_any_not_compose() {
        let (sql, binds) = lower(
            HOST,
            &StringFilter::All {
                filters: NonEmpty(vec![
                    StringFilter::Contains {
                        value: "stripe".to_string(),
                    },
                    StringFilter::Not {
                        filter: Box::new(StringFilter::Exact {
                            value: "test.stripe.com".to_string(),
                        }),
                    },
                ]),
            },
        );
        assert_eq!(sql, "(lower(host) LIKE lower(?) AND NOT (host = ?))");
        assert_eq!(binds, vec!["%stripe%", "test.stripe.com"]);
    }

    #[test]
    fn empty_filters_rejected() {
        let bad = r#"{"op":"all","filters":[]}"#;
        let err = serde_json::from_str::<StringFilter>(bad).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn collect_regex_walks_tree() {
        let f = StringFilter::Any {
            filters: NonEmpty(vec![
                StringFilter::RegexMatch {
                    value: "a".to_string(),
                },
                StringFilter::Not {
                    filter: Box::new(StringFilter::RegexMatch {
                        value: "b".to_string(),
                    }),
                },
                StringFilter::Contains {
                    value: "c".to_string(),
                },
            ]),
        };
        let mut out = Vec::new();
        collect_regex_patterns(&f, &mut out);
        assert_eq!(out, vec!["a", "b"]);
    }

    #[test]
    fn escape_like_wildcards() {
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
    }
}
