//! RE2 to Lucene regular expressions, and Unicode case folding for them.
//!
//! ClickHouse's `match(col, re)` is an unanchored RE2 search. OpenSearch's
//! `regexp` query is an anchored Lucene automaton regex with a different
//! syntax (no `\d`, no anchors, `.` matches newlines, `&`, `~`, `<`, `>`, `@`,
//! `#` are operators). Only a subset of RE2 translates exactly, and this
//! module translates that subset and names the first construct it cannot
//! translate:
//!
//! - literals, `.`, `[...]` classes of literals, ranges and ASCII classes,
//!   `\d \D \w \W \s \S` with their RE2 (ASCII) meaning;
//! - groups (capturing or not), alternation, `? * + {n} {n,} {n,m}` (lazy
//!   forms match the same set, so they translate too);
//! - `^`, `$`, `\A`, `\z` at the start or end of a top-level alternative;
//! - `(?i)` at the very start of the pattern, as the query's
//!   `case_insensitive` flag.
//!
//! Everything else (`\b`, `\p{..}`, other flags, inline flag groups, set
//! operations in classes, anchors inside a pattern) is rejected rather than
//! approximated.
//!
//! ## Case folding
//!
//! Lucene's `case_insensitive` flag folds ASCII only, and the `wildcard`
//! field type applies it unevenly outside ASCII. The documented behaviour is
//! Unicode simple case folding, so a letter that has a non-ASCII case variant
//! is written out as a class of all its variants ([`variants`]); `contains`
//! uses the same expansion ([`contains_pattern`]) for every value with a
//! non-ASCII character or an ASCII `k` or `s` (which also match U+212A
//! KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S), and the plain
//! `wildcard` query only for values where its folding is identical.
//! Under `(?i)` a class that covers `k` or `s` (`[a-z]`, `\w`, `[[:alpha:]]`)
//! gains the same two characters.
//!
//! ## Single-string patterns
//!
//! The `wildcard` field type of OpenSearch answers a regexp whose automaton
//! accepts exactly one string by comparing the stored value with the *source
//! text* of the regexp, so `(x{100})` and `()` match nothing. A pattern
//! anchored at both ends can have such a language (`^x{100}$`, `^$`,
//! `^.{0}$`); [`translate`] reports that string in [`Translated::exact`] and
//! the lowering asks for an exact match instead.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use regex_syntax::ast::{
    self, Ast, ClassAsciiKind, ClassPerlKind, ClassSet, ClassSetItem, RepetitionKind,
    RepetitionRange, parse::Parser,
};

/// Longest string, in bytes, that an anchored pattern may spell out; patterns
/// that would expand beyond it are rejected instead of materialized.
const MAX_EXACT_LEN: usize = 64 * 1024;

/// Longest Lucene regex a `contains` expansion may produce, the
/// `index.max_regex_length` the store sets on its indices.
const MAX_CONTAINS_PATTERN: usize = 10_000;

/// A Lucene regex equivalent to an unanchored RE2 search.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Translated {
    pub pattern: String,
    pub case_insensitive: bool,
    /// `Some(s)` when the pattern is anchored at both ends and matches `s`
    /// and nothing else.
    pub exact: Option<String>,
}

/// What an anchored pattern can match.
#[derive(Debug, PartialEq, Eq)]
enum Strings {
    /// Exactly this string.
    One(String),
    /// Anything else: no string, several strings or unknown.
    Many,
}

/// Translate `re2` or name the construct that cannot be translated exactly.
pub(super) fn translate(re2: &str) -> Result<Translated, String> {
    let ast = Parser::new().parse(re2).map_err(|e| e.to_string())?;
    let alternatives: Vec<&Ast> = match &ast {
        Ast::Alternation(alt) => alt.asts.iter().collect(),
        other => vec![other],
    };

    let mut case_insensitive = false;
    let mut out: Vec<String> = Vec::with_capacity(alternatives.len());
    let mut languages: Vec<Strings> = Vec::with_capacity(alternatives.len());
    for (index, alternative) in alternatives.into_iter().enumerate() {
        let mut items: Vec<&Ast> = match alternative {
            Ast::Concat(concat) => concat.asts.iter().collect(),
            other => vec![other],
        };
        if index == 0
            && let Some(Ast::Flags(flags)) = items.first()
        {
            case_insensitive = leading_flags(&flags.flags)?;
            items.remove(0);
        }

        let mut anchored_start = false;
        let mut anchored_end = false;
        if let Some(Ast::Assertion(a)) = items.first()
            && matches!(
                a.kind,
                ast::AssertionKind::StartLine | ast::AssertionKind::StartText
            )
        {
            anchored_start = true;
            items.remove(0);
        }
        if let Some(Ast::Assertion(a)) = items.last()
            && matches!(
                a.kind,
                ast::AssertionKind::EndLine | ast::AssertionKind::EndText
            )
        {
            anchored_end = true;
            items.pop();
        }

        let mut body = String::new();
        for item in &items {
            emit(item, &mut body, case_insensitive)?;
        }
        out.push(format!(
            "{}({body}){}",
            if anchored_start { "" } else { ".*" },
            if anchored_end { "" } else { ".*" },
        ));
        languages.push(if anchored_start && anchored_end {
            concat_strings(items.iter().copied(), case_insensitive)?
        } else {
            Strings::Many
        });
    }

    let pattern = if out.len() == 1 {
        out.remove(0)
    } else {
        out.iter()
            .map(|a| format!("({a})"))
            .collect::<Vec<_>>()
            .join("|")
    };
    Ok(Translated {
        pattern,
        case_insensitive,
        exact: union_strings(languages),
    })
}

/// `(?i)` is the only flag a pattern may start with.
fn leading_flags(flags: &ast::Flags) -> Result<bool, String> {
    let mut case_insensitive = false;
    for item in &flags.items {
        match item.kind {
            ast::FlagsItemKind::Flag(ast::Flag::CaseInsensitive) => case_insensitive = true,
            _ => return Err("flags other than a leading (?i)".to_string()),
        }
    }
    Ok(case_insensitive)
}

fn emit(ast: &Ast, out: &mut String, ci: bool) -> Result<(), String> {
    match ast {
        Ast::Empty(_) => out.push_str("()"),
        Ast::Literal(lit) => push_literal_folded(lit.c, ci, out),
        // RE2's `.` does not match a newline; Lucene's does.
        Ast::Dot(_) => out.push_str("[^\n]"),
        Ast::ClassPerl(class) => push_perl(class, out, ci),
        Ast::ClassBracketed(class) => {
            out.push('[');
            if class.negated {
                out.push('^');
            }
            match &class.kind {
                ClassSet::Item(item) => {
                    let start = out.len();
                    push_class_item(item, out, ci)?;
                    if ci {
                        push_fold_extras(item, out, start);
                    }
                }
                ClassSet::BinaryOp(_) => {
                    return Err("set operations inside a character class".to_string());
                }
            }
            out.push(']');
        }
        Ast::Repetition(rep) => {
            push_atom(&rep.ast, out, ci)?;
            match &rep.op.kind {
                RepetitionKind::ZeroOrOne => out.push('?'),
                RepetitionKind::ZeroOrMore => out.push('*'),
                RepetitionKind::OneOrMore => out.push('+'),
                RepetitionKind::Range(RepetitionRange::Exactly(n)) => {
                    out.push_str(&format!("{{{n}}}"));
                }
                RepetitionKind::Range(RepetitionRange::AtLeast(n)) => {
                    out.push_str(&format!("{{{n},}}"));
                }
                RepetitionKind::Range(RepetitionRange::Bounded(m, n)) => {
                    out.push_str(&format!("{{{m},{n}}}"));
                }
            }
        }
        Ast::Group(group) => {
            if let ast::GroupKind::NonCapturing(flags) = &group.kind
                && !flags.items.is_empty()
            {
                return Err("an inline flag group such as (?i:...)".to_string());
            }
            out.push('(');
            match &*group.ast {
                // The group's own parentheses already delimit the branches.
                Ast::Alternation(alt) => emit_branches(&alt.asts, out, ci)?,
                inner => emit(inner, out, ci)?,
            }
            out.push(')');
        }
        Ast::Alternation(alt) => {
            out.push('(');
            emit_branches(&alt.asts, out, ci)?;
            out.push(')');
        }
        Ast::Concat(concat) => {
            for item in &concat.asts {
                emit(item, out, ci)?;
            }
        }
        Ast::Flags(_) => return Err("flags other than a leading (?i)".to_string()),
        Ast::Assertion(a) => {
            return Err(match a.kind {
                ast::AssertionKind::StartLine
                | ast::AssertionKind::EndLine
                | ast::AssertionKind::StartText
                | ast::AssertionKind::EndText => {
                    "an anchor that is not at the start or end of the pattern".to_string()
                }
                _ => "a word boundary assertion".to_string(),
            });
        }
        Ast::ClassUnicode(_) => return Err("a Unicode class such as \\p{L}".to_string()),
    }
    Ok(())
}

fn emit_branches(branches: &[Ast], out: &mut String, ci: bool) -> Result<(), String> {
    for (i, branch) in branches.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        emit(branch, out, ci)?;
    }
    Ok(())
}

/// Emit `ast` as one repetition operand: a single atom, else parenthesized.
fn push_atom(ast: &Ast, out: &mut String, ci: bool) -> Result<(), String> {
    match ast {
        Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_)
        | Ast::Group(_) => emit(ast, out, ci),
        other => {
            out.push('(');
            emit(other, out, ci)?;
            out.push(')');
            Ok(())
        }
    }
}

/// Lucene treats `\` + any character as that literal character, so every
/// ASCII punctuation character is escaped; control characters and non-ASCII
/// text go in as they are.
fn push_literal(c: char, out: &mut String) {
    if c.is_ascii_alphanumeric() || !c.is_ascii() || c.is_control() {
        out.push(c);
    } else {
        out.push('\\');
        out.push(c);
    }
}

/// A literal; under `(?i)` a letter with non-ASCII case variants becomes a
/// class of all of them. Lucene's own flag covers the ASCII letters.
fn push_literal_folded(c: char, ci: bool, out: &mut String) {
    if ci && needs_expansion(c) {
        out.push('[');
        for v in variants(c) {
            push_literal(v, out);
        }
        out.push(']');
    } else {
        push_literal(c, out);
    }
}

fn push_perl(class: &ast::ClassPerl, out: &mut String, ci: bool) {
    out.push('[');
    if class.negated {
        out.push('^');
    }
    out.push_str(perl_body(&class.kind));
    // Under `(?i)` RE2's `\w` also folds `k` and `s` to their non-ASCII forms.
    if ci && class.kind == ClassPerlKind::Word {
        out.push('\u{212a}');
        out.push('\u{17f}');
    }
    out.push(']');
}

/// RE2's Perl classes are ASCII-only.
fn perl_body(kind: &ClassPerlKind) -> &'static str {
    match kind {
        ClassPerlKind::Digit => "0-9",
        ClassPerlKind::Word => "0-9A-Za-z_",
        ClassPerlKind::Space => "\t\n\x0c\r ",
    }
}

fn push_class_item(item: &ClassSetItem, out: &mut String, ci: bool) -> Result<(), String> {
    match item {
        ClassSetItem::Empty(_) => {}
        ClassSetItem::Literal(lit) => {
            // Lucene's case flag does not reach inside a class, so every
            // variant is written out.
            if ci {
                for v in variants(lit.c) {
                    push_literal(v, out);
                }
            } else {
                push_literal(lit.c, out);
            }
        }
        ClassSetItem::Range(range) => {
            if ci && !(range.start.c.is_ascii() && range.end.c.is_ascii()) {
                return Err("a range with non-ASCII ends under (?i)".to_string());
            }
            push_literal(range.start.c, out);
            out.push('-');
            push_literal(range.end.c, out);
            if ci {
                // The other case of the letters the range covers.
                for (lo, hi, shift) in [('a', 'z', -32_i32), ('A', 'Z', 32)] {
                    let (start, end) = (range.start.c.max(lo), range.end.c.min(hi));
                    if start <= end {
                        for c in [start, end] {
                            push_literal(char::from((c as i32 + shift) as u8), out);
                            if c == start {
                                out.push('-');
                            }
                        }
                    }
                }
            }
        }
        ClassSetItem::Ascii(class) => {
            if class.negated {
                return Err("a negated ASCII class inside a character class".to_string());
            }
            out.push_str(match class.kind {
                ClassAsciiKind::Alnum => "0-9A-Za-z",
                ClassAsciiKind::Alpha => "A-Za-z",
                ClassAsciiKind::Digit => "0-9",
                ClassAsciiKind::Lower | ClassAsciiKind::Upper if ci => "a-zA-Z",
                ClassAsciiKind::Lower => "a-z",
                ClassAsciiKind::Upper => "A-Z",
                ClassAsciiKind::Word => "0-9A-Za-z_",
                ClassAsciiKind::Xdigit => "0-9A-Fa-f",
                ClassAsciiKind::Space => "\t\n\x0b\x0c\r ",
                ClassAsciiKind::Blank => "\t ",
                _ => return Err("this POSIX character class".to_string()),
            });
        }
        ClassSetItem::Perl(class) => {
            if class.negated {
                return Err("a negated \\D \\W \\S inside a character class".to_string());
            }
            out.push_str(perl_body(&class.kind));
        }
        ClassSetItem::Union(union) => {
            for item in &union.items {
                push_class_item(item, out, ci)?;
            }
        }
        ClassSetItem::Unicode(_) => return Err("a Unicode class such as \\p{L}".to_string()),
        ClassSetItem::Bracketed(_) => return Err("a nested character class".to_string()),
    }
    Ok(())
}

// ---- the language of an anchored pattern ----

/// The strings of the concatenation of `items`.
fn concat_strings<'a>(items: impl Iterator<Item = &'a Ast>, ci: bool) -> Result<Strings, String> {
    let mut whole = String::new();
    let mut many = false;
    for item in items {
        match strings(item, ci)? {
            Strings::One(s) => {
                if whole.len() + s.len() > MAX_EXACT_LEN {
                    return Err(format!(
                        "an anchored pattern that spells out more than {MAX_EXACT_LEN} bytes"
                    ));
                }
                whole.push_str(&s);
            }
            Strings::Many => many = true,
        }
    }
    Ok(if many {
        Strings::Many
    } else {
        Strings::One(whole)
    })
}

/// `One` when every alternative is the same single string.
fn union_strings(languages: Vec<Strings>) -> Option<String> {
    let mut only: Option<String> = None;
    for language in languages {
        match (language, &only) {
            (Strings::Many, _) => return None,
            (Strings::One(s), None) => only = Some(s),
            (Strings::One(s), Some(first)) if &s == first => {}
            (Strings::One(_), Some(_)) => return None,
        }
    }
    only
}

fn strings(ast: &Ast, ci: bool) -> Result<Strings, String> {
    Ok(match ast {
        Ast::Empty(_) => Strings::One(String::new()),
        Ast::Literal(lit) => letter_strings(lit.c, ci),
        Ast::ClassBracketed(class) if !class.negated => match &class.kind {
            ClassSet::Item(item) => {
                let mut chars = BTreeSet::new();
                if collect_class_chars(item, ci, &mut chars) && chars.len() == 1 {
                    chars
                        .into_iter()
                        .next()
                        .map_or(Strings::Many, |c| Strings::One(c.to_string()))
                } else {
                    Strings::Many
                }
            }
            ClassSet::BinaryOp(_) => Strings::Many,
        },
        Ast::Repetition(rep) => {
            let child = strings(&rep.ast, ci)?;
            let (min, max) = match &rep.op.kind {
                RepetitionKind::ZeroOrOne => (0, Some(1)),
                RepetitionKind::ZeroOrMore => (0, None),
                RepetitionKind::OneOrMore => (1, None),
                RepetitionKind::Range(RepetitionRange::Exactly(n)) => (*n, Some(*n)),
                RepetitionKind::Range(RepetitionRange::AtLeast(n)) => (*n, None),
                RepetitionKind::Range(RepetitionRange::Bounded(m, n)) => (*m, Some(*n)),
            };
            match child {
                // Any number of copies of the empty string is the empty string.
                Strings::One(s) if s.is_empty() => Strings::One(s),
                _ if max == Some(0) => Strings::One(String::new()),
                Strings::One(s) if max == Some(min) => {
                    if s.len().saturating_mul(min as usize) > MAX_EXACT_LEN {
                        return Err(format!(
                            "an anchored pattern that spells out more than {MAX_EXACT_LEN} bytes"
                        ));
                    }
                    Strings::One(s.repeat(min as usize))
                }
                _ => Strings::Many,
            }
        }
        Ast::Group(group) => strings(&group.ast, ci)?,
        Ast::Concat(concat) => concat_strings(concat.asts.iter(), ci)?,
        Ast::Alternation(alt) => {
            let mut languages = Vec::with_capacity(alt.asts.len());
            for branch in &alt.asts {
                languages.push(strings(branch, ci)?);
            }
            union_strings(languages).map_or(Strings::Many, Strings::One)
        }
        _ => Strings::Many,
    })
}

fn letter_strings(c: char, ci: bool) -> Strings {
    if ci && variants(c).len() > 1 {
        Strings::Many
    } else {
        Strings::One(c.to_string())
    }
}

/// Collect the characters a non-negated class of literals can match.
/// `false` when it contains anything but single characters.
fn collect_class_chars(item: &ClassSetItem, ci: bool, out: &mut BTreeSet<char>) -> bool {
    match item {
        ClassSetItem::Empty(_) => true,
        ClassSetItem::Literal(lit) => {
            if ci {
                out.extend(variants(lit.c));
            } else {
                out.insert(lit.c);
            }
            true
        }
        ClassSetItem::Range(range) if range.start.c == range.end.c => {
            if ci {
                out.extend(variants(range.start.c));
            } else {
                out.insert(range.start.c);
            }
            true
        }
        ClassSetItem::Union(union) => union
            .items
            .iter()
            .all(|item| collect_class_chars(item, ci, out)),
        _ => false,
    }
}

// ---- Unicode simple case folding ----

fn single_upper(c: char) -> char {
    let mut it = c.to_uppercase();
    match (it.next(), it.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

fn single_lower(c: char) -> char {
    let mut it = c.to_lowercase();
    match (it.next(), it.next()) {
        (Some(l), None) => l,
        _ => c,
    }
}

/// The representative of `c`'s simple case-folding orbit. The standard
/// library has no simple folding table; lower(upper(c)) reproduces
/// `CaseFolding.txt` (statuses C and S) except for dotless `ı`, whose only
/// folding is the Turkic one.
fn fold_key(c: char) -> char {
    if c == '\u{131}' {
        c
    } else {
        single_lower(single_upper(c))
    }
}

/// For every orbit with several members: its representative and the other
/// members. Only code points below U+20000 are cased.
static ORBITS: LazyLock<HashMap<char, Vec<char>>> = LazyLock::new(|| {
    let mut orbits: HashMap<char, Vec<char>> = HashMap::new();
    for c in (0..0x20000u32).filter_map(char::from_u32) {
        let key = fold_key(c);
        if key != c {
            orbits.entry(key).or_default().push(c);
        }
    }
    orbits
});

/// All characters that match `c` ignoring case, `c` included: `k` has
/// U+212A KELVIN SIGN and `s` has U+017F LATIN SMALL LETTER LONG S.
fn variants(c: char) -> Vec<char> {
    let key = fold_key(c);
    let mut all = vec![key];
    if let Some(rest) = ORBITS.get(&key) {
        all.extend(rest);
    }
    if !all.contains(&c) {
        all.push(c);
    }
    all.sort_unstable();
    all.dedup();
    all
}

/// A letter with case variants beyond what Lucene's ASCII `case_insensitive`
/// flag covers: every non-ASCII letter that has any, and ASCII `k` and `s`.
fn needs_expansion(c: char) -> bool {
    let all = variants(c);
    all.len() > 1 && all.iter().any(|v| !v.is_ascii())
}

/// The non-ASCII characters RE2's `(?i)` adds to a class that contains the
/// ASCII letter `letter` or its capital.
const ASCII_FOLD_EXTRAS: [(char, char); 2] = [('k', '\u{212a}'), ('s', '\u{17f}')];

/// Whether the non-negated class item matches the ASCII letter `c`.
fn item_covers(item: &ClassSetItem, c: char) -> bool {
    match item {
        ClassSetItem::Literal(lit) => lit.c == c,
        ClassSetItem::Range(range) => (range.start.c..=range.end.c).contains(&c),
        ClassSetItem::Ascii(class) => {
            matches!(
                class.kind,
                ClassAsciiKind::Alnum | ClassAsciiKind::Alpha | ClassAsciiKind::Word
            ) || (class.kind == ClassAsciiKind::Lower && c.is_ascii_lowercase())
                || (class.kind == ClassAsciiKind::Upper && c.is_ascii_uppercase())
        }
        ClassSetItem::Perl(class) => class.kind == ClassPerlKind::Word,
        ClassSetItem::Union(union) => union.items.iter().any(|i| item_covers(i, c)),
        _ => false,
    }
}

/// Under `(?i)`, push KELVIN SIGN and LONG S when `item` covers `k`/`K` or
/// `s`/`S`, as RE2's case folding of a class does.
fn push_fold_extras(item: &ClassSetItem, out: &mut String, class_start: usize) {
    for (letter, extra) in ASCII_FOLD_EXTRAS {
        if (item_covers(item, letter) || item_covers(item, letter.to_ascii_uppercase()))
            && !out[class_start..].contains(extra)
        {
            out.push(extra);
        }
    }
}

/// The Lucene regex for a case-insensitive substring match of `value` when
/// it has a non-ASCII character, `None` for ASCII text, which the `wildcard`
/// query folds itself. The `wildcard` query lower-cases stored text and
/// pattern differently outside ASCII (it misses `İ` in `İstanbul`). Run the
/// regex with `case_insensitive: true`, which covers the ASCII letters left
/// as literals.
pub(super) fn contains_pattern(value: &str) -> Result<Option<String>, String> {
    if value.is_ascii() && !value.chars().any(needs_expansion) {
        return Ok(None);
    }
    let mut out = String::from(".*");
    for c in value.chars() {
        push_literal_folded(c, true, &mut out);
        if out.len() > MAX_CONTAINS_PATTERN {
            return Err(format!(
                "a value with non-ASCII characters whose case-folded pattern exceeds \
                 {MAX_CONTAINS_PATTERN} characters"
            ));
        }
    }
    out.push_str(".*");
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lucene(re2: &str) -> String {
        translate(re2).unwrap().pattern
    }

    fn exact(re2: &str) -> Option<String> {
        translate(re2).unwrap().exact
    }

    #[test]
    fn unanchored_literal_is_wrapped_in_wildcards() {
        assert_eq!(lucene("abc"), ".*(abc).*");
    }

    #[test]
    fn punctuation_is_escaped_so_lucene_operators_stay_literal() {
        assert_eq!(
            lucene("a.b&c~d<e>f@g#h"),
            ".*(a[^\n]b\\&c\\~d\\<e\\>f\\@g\\#h).*"
        );
        assert_eq!(lucene(r"a\.b"), ".*(a\\.b).*");
    }

    #[test]
    fn anchors_at_the_edges_drop_the_wildcards() {
        assert_eq!(lucene("^abc"), "(abc).*");
        assert_eq!(lucene("abc$"), ".*(abc)");
        assert_eq!(lucene("^abc$"), "(abc)");
        assert_eq!(lucene(r"\Aabc\z"), "(abc)");
    }

    #[test]
    fn alternatives_are_anchored_independently() {
        assert_eq!(lucene("^a|b$"), "((a).*)|(.*(b))");
    }

    #[test]
    fn perl_classes_use_their_ascii_meaning() {
        assert_eq!(lucene(r"\d+"), ".*([0-9]+).*");
        assert_eq!(lucene(r"\W"), ".*([^0-9A-Za-z_]).*");
        assert_eq!(lucene(r"[\d_]"), ".*([0-9\\_]).*");
    }

    #[test]
    fn character_classes_and_repetition() {
        assert_eq!(lucene("[a-c]{2,4}"), ".*([a-c]{2,4}).*");
        assert_eq!(lucene("[^x]*"), ".*([^x]*).*");
        assert_eq!(lucene("(ab)+?"), ".*((ab)+).*");
        assert_eq!(lucene("(?:ab|cd)e"), ".*((ab|cd)e).*");
    }

    #[test]
    fn leading_case_insensitive_flag_becomes_a_query_flag() {
        let t = translate("(?i)abc").unwrap();
        assert_eq!(t.pattern, ".*(abc).*");
        assert!(t.case_insensitive);
        assert!(!translate("abc").unwrap().case_insensitive);
    }

    #[test]
    fn empty_pattern_matches_everything() {
        assert_eq!(lucene(""), ".*(()).*");
    }

    #[test]
    fn untranslatable_constructs_are_rejected() {
        for re2 in [
            r"\bfoo",
            r"\p{L}+",
            "(?s).",
            "(?m)^a",
            "a(?i)b",
            "(?i:a)b",
            "a^b",
            "a$b",
            "[[:^alpha:]]",
            r"[\D]",
            "[a-z&&[^b]]",
            "(?i)[à-ÿ]",
        ] {
            assert!(translate(re2).is_err(), "{re2} must be rejected");
        }
    }

    #[test]
    fn a_pattern_anchored_at_both_ends_with_one_match_is_exact() {
        assert_eq!(exact("^x{100}$"), Some("x".repeat(100)));
        assert_eq!(exact("x{100}"), None, "unanchored patterns match more");
        assert_eq!(exact("^x{100}"), None);
        for empty in ["^$", "^.{0}$", r"\A\z", "^(){3}$", "^(a|b){0}$", "^(?:)*$"] {
            assert_eq!(exact(empty), Some(String::new()), "{empty}");
        }
        assert_eq!(exact("^(ab){2}c$"), Some("ababc".into()));
        assert_eq!(exact("^[a]b$"), Some("ab".into()));
        assert_eq!(exact("^(?:a|a)$"), Some("a".into()));
        assert_eq!(exact("^a$|^a$"), Some("a".into()));
        assert_eq!(exact("^a{2,2}$"), Some("aa".into()));
        assert_eq!(exact("(?i)^12$"), Some("12".into()));
    }

    #[test]
    fn a_pattern_with_several_matches_is_not_exact() {
        for re2 in [
            "^a?$",
            "^a*$",
            "^a+$",
            "^a{1,2}$",
            "^a|b$",
            "^a$|^b$",
            "^[ab]$",
            "^[a-b]$",
            "^.$",
            r"^\d$",
            "^[^a]$",
            "(?i)^a$",
            "(?i)^ü$",
            "^x{0,}$|^$",
        ] {
            assert_eq!(exact(re2), None, "{re2}");
        }
    }

    #[test]
    fn an_exact_pattern_that_is_too_long_is_rejected() {
        assert!(translate("^(x{1000}){1000}$").is_err());
    }

    #[test]
    fn non_ascii_letters_fold_under_the_case_flag() {
        assert_eq!(lucene("(?i)ünï"), ".*([Üü]n[Ïï]).*");
        assert_eq!(lucene("ünï"), ".*(ünï).*", "case-sensitive stays literal");
        assert_eq!(lucene("(?i)[ü]"), ".*([Üü]).*");
        assert_eq!(lucene("(?i)[^ü]"), ".*([^Üü]).*");
        assert_eq!(lucene("(?i)σ+"), ".*([Σςσ]+).*");
        assert_eq!(lucene("(?i)abc"), ".*(abc).*", "ASCII is left to Lucene");
    }

    #[test]
    fn case_insensitive_classes_list_both_cases_and_the_unicode_variants() {
        assert_eq!(lucene("(?i)[a-c]"), ".*([a-cA-C]).*");
        assert_eq!(lucene("(?i)[X-Z0-9]"), ".*([X-Zx-z0-9]).*");
        assert_eq!(lucene("(?i)[k]"), ".*([Kk\u{212a}]).*");
        assert_eq!(lucene("(?i)[j-l]"), ".*([j-lJ-L\u{212a}]).*");
        assert_eq!(lucene("(?i)[^a-z]"), ".*([^a-zA-Z\u{212a}\u{17f}]).*");
        assert_eq!(lucene("(?i)[[:lower:]]"), ".*([a-zA-Z\u{212a}\u{17f}]).*");
        assert_eq!(lucene(r"(?i)\w"), ".*([0-9A-Za-z_\u{212a}\u{17f}]).*");
        assert_eq!(lucene(r"(?i)\W"), ".*([^0-9A-Za-z_\u{212a}\u{17f}]).*");
        assert_eq!(lucene(r"(?i)\d"), ".*([0-9]).*");
        assert_eq!(
            lucene("[a-z]"),
            ".*([a-z]).*",
            "case-sensitive classes are untouched"
        );
    }

    #[test]
    fn fold_orbits_follow_simple_case_folding() {
        assert_eq!(variants('ü'), vec!['Ü', 'ü']);
        assert_eq!(variants('ς'), vec!['Σ', 'ς', 'σ']);
        assert_eq!(variants('ǅ'), vec!['Ǆ', 'ǅ', 'ǆ']);
        assert_eq!(variants('\u{212a}'), vec!['K', 'k', '\u{212a}']);
        assert_eq!(variants('ß'), vec!['ß', 'ẞ']);
        assert_eq!(variants('ı'), vec!['ı'], "dotless i has no simple folding");
        assert_eq!(variants('İ'), vec!['İ']);
        assert_eq!(variants('1'), vec!['1']);
        assert_eq!(variants('k'), vec!['K', 'k', '\u{212a}']);
        assert_eq!(variants('S'), vec!['S', 's', '\u{17f}']);
        assert_eq!(variants('a'), vec!['A', 'a']);
    }

    #[test]
    fn every_orbit_member_has_the_same_orbit() {
        for c in (0..0x20000u32).filter_map(char::from_u32) {
            let own = variants(c);
            assert!(own.contains(&c), "{c:?}");
            if !c.is_ascii() {
                for member in &own {
                    if !member.is_ascii() {
                        assert_eq!(variants(*member), own, "{c:?} / {member:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn contains_uses_a_regexp_for_non_ascii_values_only() {
        assert_eq!(contains_pattern("hello"), Ok(None));
        assert_eq!(contains_pattern("a1.5*?"), Ok(None));
        assert_eq!(
            contains_pattern("ask").unwrap().as_deref(),
            Some(".*a[Ssſ][Kk\u{212a}].*")
        );
        assert_eq!(
            contains_pattern("ÜNÏ b*").unwrap().as_deref(),
            Some(".*[Üü]N[Ïï]\\ b\\*.*")
        );
        assert_eq!(
            contains_pattern("\u{212a}x").unwrap().as_deref(),
            Some(".*[Kk\u{212a}]x.*")
        );
        assert_eq!(
            contains_pattern("İstanbul").unwrap().as_deref(),
            Some(".*İ[Ssſ]tanbul.*")
        );
        assert!(contains_pattern(&"Ü".repeat(5_000)).is_err());
    }
}
