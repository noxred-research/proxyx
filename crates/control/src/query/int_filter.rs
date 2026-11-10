//! Integer-valued filter tree for `IntFilter` columns.
//!
//! `IntFilter` mirrors `StringFilter`'s shape: leaf comparison operators
//! plus `All` / `Any` / `Not` combinators. Every variant lowers to a
//! single SQL expression. Integer values format directly into SQL — the
//! type system already guarantees they're parsed `i64`s, so binds stay
//! string-only and the call site is simpler.

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IntFilter {
    Exact { value: i64 },
    Lt { value: i64 },
    Lte { value: i64 },
    Gt { value: i64 },
    Gte { value: i64 },
    All { filters: NonEmpty<IntFilter> },
    Any { filters: NonEmpty<IntFilter> },
    Not { filter: Box<IntFilter> },
}

/// Newtype wrapper that rejects empty `Vec<T>` at deserialize time.
/// Used for `All`/`Any` filter lists where empty is always a programming
/// error (SQL identity for empty AND/OR matches no caller intent).
#[derive(Debug, Clone, Serialize)]
pub struct NonEmpty<T>(pub Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<T>::deserialize(d)?;
        if v.is_empty() {
            return Err(serde::de::Error::custom("filters list must not be empty"));
        }
        Ok(NonEmpty(v))
    }
}

/// Lower an `IntFilter` against `col` (a SQL expression — column name or
/// `length(col)` from `StringFilter::Length`) into a single SQL fragment.
///
/// Bindable string parameters go through `binds`; integer values format
/// directly. The string `binds` vec carries no entries from `IntFilter`
/// itself but is threaded through so callers can compose with
/// `lower_string` results.
#[allow(clippy::only_used_in_recursion)] // signature mirrors lower_string for composition
pub(crate) fn lower_int(col: &str, f: &IntFilter, binds: &mut Vec<String>) -> String {
    match f {
        IntFilter::Exact { value } => format!("{col} = {value}"),
        IntFilter::Lt { value } => format!("{col} < {value}"),
        IntFilter::Lte { value } => format!("{col} <= {value}"),
        IntFilter::Gt { value } => format!("{col} > {value}"),
        IntFilter::Gte { value } => format!("{col} >= {value}"),
        IntFilter::All { filters } => {
            paren_join(" AND ", filters.0.iter().map(|f| lower_int(col, f, binds)))
        }
        IntFilter::Any { filters } => {
            paren_join(" OR ", filters.0.iter().map(|f| lower_int(col, f, binds)))
        }
        IntFilter::Not { filter } => format!("NOT ({})", lower_int(col, filter, binds)),
    }
}

/// Join expressions with `sep`, wrapping in parens unless there is exactly
/// one element. Avoids redundant parens that obscure SQL output without
/// changing semantics.
pub(crate) fn paren_join(sep: &str, parts: impl IntoIterator<Item = String>) -> String {
    let parts: Vec<String> = parts.into_iter().collect();
    if parts.len() == 1 {
        parts.into_iter().next().unwrap()
    } else {
        format!("({})", parts.join(sep))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(f: &IntFilter) -> String {
        let mut binds = Vec::new();
        let sql = lower_int("status_code", f, &mut binds);
        assert!(binds.is_empty(), "IntFilter must not push string binds");
        sql
    }

    #[test]
    fn leaves() {
        assert_eq!(lower(&IntFilter::Exact { value: 200 }), "status_code = 200");
        assert_eq!(lower(&IntFilter::Lt { value: 300 }), "status_code < 300");
        assert_eq!(lower(&IntFilter::Lte { value: 299 }), "status_code <= 299");
        assert_eq!(lower(&IntFilter::Gt { value: 199 }), "status_code > 199");
        assert_eq!(lower(&IntFilter::Gte { value: 200 }), "status_code >= 200");
    }

    #[test]
    fn all_any_not() {
        let f = IntFilter::All {
            filters: NonEmpty(vec![
                IntFilter::Gte { value: 200 },
                IntFilter::Lt { value: 300 },
            ]),
        };
        assert_eq!(lower(&f), "(status_code >= 200 AND status_code < 300)");

        let f = IntFilter::Any {
            filters: NonEmpty(vec![
                IntFilter::Exact { value: 401 },
                IntFilter::Exact { value: 403 },
            ]),
        };
        assert_eq!(lower(&f), "(status_code = 401 OR status_code = 403)");

        let f = IntFilter::Not {
            filter: Box::new(IntFilter::Exact { value: 200 }),
        };
        assert_eq!(lower(&f), "NOT (status_code = 200)");
    }

    #[test]
    fn singleton_all_collapses() {
        let f = IntFilter::All {
            filters: NonEmpty(vec![IntFilter::Gte { value: 200 }]),
        };
        assert_eq!(lower(&f), "status_code >= 200");
    }

    #[test]
    fn empty_filters_rejected() {
        let bad = r#"{"op":"all","filters":[]}"#;
        let err = serde_json::from_str::<IntFilter>(bad).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));

        let bad = r#"{"op":"any","filters":[]}"#;
        let err = serde_json::from_str::<IntFilter>(bad).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }
}
