//! RE2 to Lucene regular expressions.
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

use regex_syntax::ast::{
    self, Ast, ClassAsciiKind, ClassPerlKind, ClassSet, ClassSetItem, RepetitionKind,
    RepetitionRange, parse::Parser,
};

/// A Lucene regex equivalent to an unanchored RE2 search.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Translated {
    pub pattern: String,
    pub case_insensitive: bool,
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
        for item in items {
            emit(item, &mut body)?;
        }
        out.push(format!(
            "{}({body}){}",
            if anchored_start { "" } else { ".*" },
            if anchored_end { "" } else { ".*" },
        ));
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

fn emit(ast: &Ast, out: &mut String) -> Result<(), String> {
    match ast {
        Ast::Empty(_) => out.push_str("()"),
        Ast::Literal(lit) => push_literal(lit.c, out),
        // RE2's `.` does not match a newline; Lucene's does.
        Ast::Dot(_) => out.push_str("[^\n]"),
        Ast::ClassPerl(class) => push_perl(class, out),
        Ast::ClassBracketed(class) => {
            out.push('[');
            if class.negated {
                out.push('^');
            }
            match &class.kind {
                ClassSet::Item(item) => push_class_item(item, out)?,
                ClassSet::BinaryOp(_) => {
                    return Err("set operations inside a character class".to_string());
                }
            }
            out.push(']');
        }
        Ast::Repetition(rep) => {
            push_atom(&rep.ast, out)?;
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
                Ast::Alternation(alt) => emit_branches(&alt.asts, out)?,
                inner => emit(inner, out)?,
            }
            out.push(')');
        }
        Ast::Alternation(alt) => {
            out.push('(');
            emit_branches(&alt.asts, out)?;
            out.push(')');
        }
        Ast::Concat(concat) => {
            for item in &concat.asts {
                emit(item, out)?;
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

fn emit_branches(branches: &[Ast], out: &mut String) -> Result<(), String> {
    for (i, branch) in branches.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        emit(branch, out)?;
    }
    Ok(())
}

/// Emit `ast` as one repetition operand: a single atom, else parenthesized.
fn push_atom(ast: &Ast, out: &mut String) -> Result<(), String> {
    match ast {
        Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_)
        | Ast::Group(_) => emit(ast, out),
        other => {
            out.push('(');
            emit(other, out)?;
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

fn push_perl(class: &ast::ClassPerl, out: &mut String) {
    out.push('[');
    if class.negated {
        out.push('^');
    }
    out.push_str(perl_body(&class.kind));
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

fn push_class_item(item: &ClassSetItem, out: &mut String) -> Result<(), String> {
    match item {
        ClassSetItem::Empty(_) => {}
        ClassSetItem::Literal(lit) => push_literal(lit.c, out),
        ClassSetItem::Range(range) => {
            push_literal(range.start.c, out);
            out.push('-');
            push_literal(range.end.c, out);
        }
        ClassSetItem::Ascii(class) => {
            if class.negated {
                return Err("a negated ASCII class inside a character class".to_string());
            }
            out.push_str(match class.kind {
                ClassAsciiKind::Alnum => "0-9A-Za-z",
                ClassAsciiKind::Alpha => "A-Za-z",
                ClassAsciiKind::Digit => "0-9",
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
                push_class_item(item, out)?;
            }
        }
        ClassSetItem::Unicode(_) => return Err("a Unicode class such as \\p{L}".to_string()),
        ClassSetItem::Bracketed(_) => return Err("a nested character class".to_string()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lucene(re2: &str) -> String {
        translate(re2).unwrap().pattern
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
        ] {
            assert!(translate(re2).is_err(), "{re2} must be rejected");
        }
    }
}
