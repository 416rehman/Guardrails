//! Check S6, panic paths (owner instruction 15), on the lines a change adds outside test code.
//! Rust: `unwrap`, `expect` and their `_err` forms, `panic!`, `todo!`, `unimplemented!`,
//! `unreachable!`, `process::exit`, and indexing or slicing that panics when the input is shorter
//! than the code assumed (`[..]`, the whole slice, cannot). Script: `process.exit`,
//! `process.abort` and `Deno.exit`. The workspace lints catch the Rust half again at compile
//! time; S6 says it at the edit.

use super::lexer::{Token, TokenKind, text, text_before};
use super::{Check, Language, Raw, Source};

const UNWRAPS: &[&str] = &["unwrap", "expect", "unwrap_err", "expect_err"];
const PANIC_MACROS: &[&str] = &["panic", "todo", "unimplemented", "unreachable"];
const SCRIPT_EXITS: &[(&str, &str)] =
    &[("process", "exit"), ("process", "abort"), ("Deno", "exit")];
/// Keywords after which `[` opens an array, a slice pattern or a type, never an index.
const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "static", "struct", "trait", "type", "unsafe", "use", "where", "while", "yield",
];

pub(super) fn findings(source: &Source) -> Vec<Raw> {
    let tokens = source.tokens();
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if source.in_test(token.line) || !source.added.contains(token.line) {
            continue;
        }
        let construct = match source.language {
            Language::Rust => rust_panic(tokens, index),
            Language::Script | Language::Markup => script_exit(tokens, index),
            Language::Style => None,
        };
        if let Some((value, fix)) = construct {
            found.push(Raw::valued(
                Check::S6,
                token.line,
                format!("`{value}` is a panic path in non-test code; {fix}"),
                &value,
            ));
        }
    }
    found
}

/// The construct at `index` and how to remove it.
fn rust_panic(tokens: &[Token], index: usize) -> Option<(String, &'static str)> {
    let token = tokens.get(index)?;
    let next = text(tokens, index + 1);
    let previous = text_before(tokens, index, 1);
    if token.kind == TokenKind::Ident
        && previous == "."
        && next == "("
        && UNWRAPS.contains(&token.text.as_str())
    {
        let fix = "return a typed error with its GRDR code, or handle the case";
        return Some((format!(".{}(", token.text), fix));
    }
    if token.kind == TokenKind::Ident
        && next == "!"
        && previous != "."
        && PANIC_MACROS.contains(&token.text.as_str())
    {
        let fix = "return a typed error, or make the state unrepresentable with a type";
        return Some((format!("{}!", token.text), fix));
    }
    if token.text == "exit" && previous == "::" && text_before(tokens, index, 2) == "process" {
        let fix = "return an exit code from main through the error path";
        return Some(("process::exit".to_owned(), fix));
    }
    if token.text == "[" && indexes(tokens, index) {
        let fix = "use `get`, `get(..)`, `split_first` or a pattern, and handle the short input";
        return Some((index_text(tokens, index), fix));
    }
    None
}

fn script_exit(tokens: &[Token], index: usize) -> Option<(String, &'static str)> {
    let token = tokens.get(index)?;
    let owner = text_before(tokens, index, 2);
    let call = SCRIPT_EXITS
        .iter()
        .any(|(object, method)| owner == *object && token.text == *method);
    let shaped = text_before(tokens, index, 1) == "." && text(tokens, index + 1) == "(";
    (call && shaped).then(|| {
        let fix = "throw a typed error and let the entry point set the exit code";
        (format!("{owner}.{}", token.text), fix)
    })
}

/// Whether the `[` at `index` indexes or slices a value: it follows an expression and holds
/// something other than one string literal, which is a map key that the map type checks.
fn indexes(tokens: &[Token], index: usize) -> bool {
    let Some(previous) = index.checked_sub(1).and_then(|p| tokens.get(p)) else {
        return false;
    };
    let after_expression = match previous.kind {
        TokenKind::Ident => {
            !RUST_KEYWORDS.contains(&previous.text.as_str()) && text_before(tokens, index, 2) != "'"
        }
        TokenKind::Punct => matches!(previous.text.as_str(), ")" | "]" | "?"),
        _ => false,
    };
    let string_key = tokens
        .get(index + 1)
        .is_some_and(|key| key.kind == TokenKind::Literal && text(tokens, index + 2) == "]");
    let whole = text(tokens, index + 1) == "."
        && text(tokens, index + 2) == "."
        && text(tokens, index + 3) == "]";
    after_expression && !string_key && !whole
}

/// `name[...]` as written, joined without spaces, for the message and the exemption value.
fn index_text(tokens: &[Token], open: usize) -> String {
    let base = text_before(tokens, open, 1);
    let mut inner = String::new();
    let mut depth = 0usize;
    for token in tokens.iter().skip(open) {
        match token.text.as_str() {
            "[" => depth += 1,
            "]" => depth = depth.saturating_sub(1),
            _ => {}
        }
        inner.push_str(&token.text);
        if depth == 0 {
            break;
        }
    }
    format!("{base}{inner}")
}

#[cfg(test)]
mod tests {
    use super::super::{Policy, analyse};
    use super::*;
    use crate::git::AddedLines;
    use crate::paths::RepoPath;

    fn s6(path: &str, source: &str, added: &AddedLines) -> Vec<(usize, String)> {
        analyse(
            &RepoPath::new(path).unwrap(),
            source,
            added,
            &Policy::for_tests(),
        )
        .into_iter()
        .filter(|finding| finding.check == Check::S6)
        .map(|finding| (finding.line, finding.message))
        .collect()
    }

    fn lines(found: &[(usize, String)]) -> Vec<usize> {
        found.iter().map(|(line, _)| *line).collect()
    }

    #[test]
    fn flags_each_panic_path_in_code() {
        let source = "fn f(args: &[String], v: Option<u8>) -> u8 {\n    let a = v.unwrap();\n    let b = v.expect(\"set\");\n    let c = &args[0];\n    let d = &args[1..];\n    if a > 9 { panic!(\"no\") }\n    todo!();\n    std::process::exit(2);\n    unreachable!()\n}\n";
        let found = s6("crates/a/src/lib.rs", source, &AddedLines::All);
        assert_eq!(lines(&found), vec![2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(found[2].1.contains("`args[0]`"));
    }

    #[test]
    fn passes_safe_forms_types_and_attributes() {
        let source = "#[expect(dead_code, reason = \"wired in #12\")]\nconst T: [u8; 4] = [1, 2, 3, 4];\nfn f<'a>(x: &'a [u8], v: Option<u8>, m: &serde_json::Value) -> u8 {\n    let [a, b] = [1u8, 2];\n    let first = x.first().copied().unwrap_or_default();\n    let all = &x[..];\n    let s = m[\"packages\"].as_str();\n    let w = vec![a, b];\n    for z in [a, b] {}\n    v.unwrap_or(first)\n}\nmacro_rules! m { () => {} }\n";
        assert!(s6("crates/a/src/lib.rs", source, &AddedLines::All).is_empty());
    }

    #[test]
    fn judges_only_added_lines_outside_tests() {
        let source = "fn f(v: Option<u8>) -> u8 {\n    v.unwrap()\n}\nfn g(v: Option<u8>) -> u8 {\n    v.unwrap()\n}\n#[cfg(test)]\nmod tests {\n    fn t() { Some(1).unwrap(); }\n}\n";
        let only_fifth = AddedLines::Only([5, 9].into_iter().collect());
        assert_eq!(
            lines(&s6("crates/a/src/lib.rs", source, &only_fifth)),
            vec![5]
        );
        assert!(s6("crates/a/tests/it.rs", source, &AddedLines::All).is_empty());
    }

    #[test]
    fn flags_script_exits_but_not_lookalikes() {
        let source = "import { exit } from './exit';\nexport function main() {\n  process.exit(1);\n}\nconst code = process.exitCode;\nexit(2);\n";
        assert_eq!(
            lines(&s6("web/tools/run.ts", source, &AddedLines::All)),
            vec![3]
        );
    }
}
