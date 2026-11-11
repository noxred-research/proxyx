//! String-valued filter tree for the columns exposed via `TrafficQuery`.
//!
//! `StringFilter` covers the operators a caller actually wants for HTTP
//! traffic: substring match (case-insensitive — the only substring form
//! we expose), exact equality, RE2 regex, byte-length predicates over
//! `IntFilter`, and explicit NULL/present checks. `All` / `Any` / `Not`
//! compose them per-column.
//!
//! ## No token probe on bodies
//!
//! The body columns carry `lower(body)` `tokenbf_v1` skip indexes (see
//! `clickhouse/indexes.sql`), and `hasToken(lower(body), lower(?))` would
//! probe them directly. It cannot guard a `contains`: `hasToken` matches
//! whole tokens, so `hasToken(..) AND lower(body) LIKE ..` drops every row
//! where the needle is only part of a token (`line` in `line1`). Substring
//! semantics are `lower(col) LIKE lower(?)` alone.

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
    /// RE2 regex, unanchored, case-sensitive, `.` not matching a newline.
    /// Use `(?i)` for case insensitivity and `(?s)` to let `.` match a
    /// newline. Patterns are pre-validated at the API entrypoint.
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

/// Static description of a filterable column: the SQL expression that
/// names it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ColumnDescriptor {
    pub name: &'static str,
}

impl ColumnDescriptor {
    const fn plain(name: &'static str) -> Self {
        Self { name }
    }
}

pub(crate) const HOST: ColumnDescriptor = ColumnDescriptor::plain("host");
pub(crate) const METHOD: ColumnDescriptor = ColumnDescriptor::plain("method");
pub(crate) const PATH: ColumnDescriptor = ColumnDescriptor::plain("path");
pub(crate) const REQUEST_BODY: ColumnDescriptor = ColumnDescriptor::plain("request_body");
pub(crate) const RESPONSE_BODY: ColumnDescriptor = ColumnDescriptor::plain("response_body");
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

// WebSocket column descriptors.
pub(crate) const WS_HOST: ColumnDescriptor = ColumnDescriptor::plain("host");
pub(crate) const WS_PAYLOAD: ColumnDescriptor = ColumnDescriptor::plain("payload");
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
            binds.push(format!("%{}%", escape_like(value)));
            format!("lower({name}) LIKE lower(?)")
        }
        StringFilter::Exact { value } => {
            binds.push(value.clone());
            format!("{name} = ?")
        }
        StringFilter::RegexMatch { value } => {
            // ClickHouse compiles with `.` matching newlines, unlike RE2
            // and the validating `regex` crate. A leading `(?-s)` restores
            // the standard default for the whole pattern; the pattern's own
            // flags, `(?s)` included, still apply after it.
            binds.push(format!("(?-s){value}"));
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
    fn contains_is_a_plain_like_on_every_column() {
        for (col, name) in [
            (HOST, "host"),
            (RESPONSE_BODY, "response_body"),
            (REQUEST_BODY, "request_body"),
            (WS_PAYLOAD, "payload"),
        ] {
            let (sql, binds) = lower(
                col,
                &StringFilter::Contains {
                    value: "Spayco".to_string(),
                },
            );
            assert_eq!(sql, format!("lower({name}) LIKE lower(?)"));
            assert_eq!(binds, vec!["%Spayco%"]);
        }
    }

    #[test]
    fn contains_escapes_like_wildcards_in_the_needle() {
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
        assert_eq!(binds, vec!["(?-s)^/api/v\\d+/"]);
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
                        value: "spayco".to_string(),
                    },
                    StringFilter::Not {
                        filter: Box::new(StringFilter::Exact {
                            value: "test.spayco.example".to_string(),
                        }),
                    },
                ]),
            },
        );
        assert_eq!(sql, "(lower(host) LIKE lower(?) AND NOT (host = ?))");
        assert_eq!(binds, vec!["%spayco%", "test.spayco.example"]);
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
