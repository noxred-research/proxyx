//! Compile-time placeholder rewriting.
//!
//! Shared statements are written once with `?` placeholders, in the order
//! their values are bound. MariaDB and SQLite take that text as it is.
//! PostgreSQL wants `$1`, `$2`, ...: [`pg_sql!`] rewrites a statement in a
//! `const` context, so the PostgreSQL text is a `&'static str` like the others
//! and no statement is rewritten (or allocated) at run time.
//!
//! A `?` inside a single-quoted string literal is data, not a placeholder.

/// The length of `sql` after [`pg_rewrite`].
#[doc(hidden)]
pub const fn pg_len(sql: &str) -> usize {
    let bytes = sql.as_bytes();
    let (mut i, mut out, mut n, mut quoted) = (0, 0, 0, false);
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' {
            quoted = !quoted;
            out += 1;
        } else if c == b'?' && !quoted {
            n += 1;
            out += 1 + digits(n);
        } else {
            out += 1;
        }
        i += 1;
    }
    out
}

/// `sql` with every `?` outside a string literal numbered: `$1`, `$2`, ...
/// `N` is [`pg_len`] of the same text.
#[doc(hidden)]
pub const fn pg_rewrite<const N: usize>(sql: &str) -> [u8; N] {
    let bytes = sql.as_bytes();
    let mut buf = [0u8; N];
    let (mut i, mut at, mut n, mut quoted) = (0, 0, 0, false);
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' {
            quoted = !quoted;
            buf[at] = c;
            at += 1;
        } else if c == b'?' && !quoted {
            n += 1;
            buf[at] = b'$';
            at += 1;
            let width = digits(n);
            let (mut rest, mut place) = (n, at + width);
            while place > at {
                place -= 1;
                buf[place] = b'0' + (rest % 10) as u8;
                rest /= 10;
            }
            at += width;
        } else {
            buf[at] = c;
            at += 1;
        }
        i += 1;
    }
    buf
}

const fn digits(mut n: usize) -> usize {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

/// `buf` as text. Panics at compile time when it is not UTF-8, which the
/// rewrite of a `&str` cannot produce.
#[doc(hidden)]
pub const fn from_buf(buf: &'static [u8]) -> &'static str {
    match core::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => panic!("rewritten statement is not utf-8"),
    }
}

/// `$expr` (a `const` string, such as a literal or a `concat!`) with `?`
/// placeholders numbered for PostgreSQL.
#[macro_export]
macro_rules! pg_sql {
    ($sql:expr) => {{
        const IN: &str = $sql;
        const N: usize = $crate::sql::pg_len(IN);
        const BUF: [u8; N] = $crate::sql::pg_rewrite::<N>(IN);
        const OUT: &str = $crate::sql::from_buf(&BUF);
        OUT
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholders_are_numbered_in_order() {
        assert_eq!(
            crate::pg_sql!("SELECT a FROM t WHERE b = ? AND c = ? LIMIT ?"),
            "SELECT a FROM t WHERE b = $1 AND c = $2 LIMIT $3"
        );
        assert_eq!(crate::pg_sql!("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn a_question_mark_in_a_literal_is_data() {
        assert_eq!(
            crate::pg_sql!("SELECT '?', ? WHERE x = 'it''s ?' AND y = ?"),
            "SELECT '?', $1 WHERE x = 'it''s ?' AND y = $2"
        );
    }

    #[test]
    fn numbers_past_nine_get_more_digits() {
        assert_eq!(
            crate::pg_sql!("VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"),
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
        );
    }

    #[test]
    fn concat_is_accepted() {
        assert_eq!(
            crate::pg_sql!(concat!("SELECT ", "a, b", " FROM t WHERE x = ?")),
            "SELECT a, b FROM t WHERE x = $1"
        );
    }
}
