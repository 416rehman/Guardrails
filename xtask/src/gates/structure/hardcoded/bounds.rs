//! The numeric bounds of S7: a number other than zero and one written where a bound, timeout,
//! retry count, size, capacity or threshold goes. That is the argument of a duration constructor,
//! a capacity or channel constructor or a script timer; the value of a binding, field or property
//! whose name says it is a bound (`max_*`, `*_timeout`, `retries`, `*_ms`); one side of a
//! comparison whose other side is such a name; and a numeric constant that the file uses in any
//! of those places or as the bound of `take`, `min`, `max`, `clamp`, `truncate`, `reserve`,
//! `slice` or a comparison. Index arithmetic and structural counts (`len() >= 2`, `.take(2)`)
//! are not bounds and pass.

use std::collections::BTreeSet;

use super::super::lexer::{Token, TokenKind, text, text_before};
use super::super::{Check, Language, Raw, Source};

/// Name segments that mark a binding as a bound.
const BOUND_WORDS: &[&str] = &[
    "max",
    "maximum",
    "min",
    "minimum",
    "limit",
    "limits",
    "timeout",
    "timeouts",
    "deadline",
    "retry",
    "retries",
    "attempt",
    "attempts",
    "tries",
    "capacity",
    "cap",
    "threshold",
    "thresholds",
    "budget",
    "interval",
    "delay",
    "backoff",
    "ttl",
    "quota",
    "cooldown",
    "grace",
    "burst",
    "ceiling",
    "depth",
    "elapsed",
    "port",
    "ports",
    "secs",
    "seconds",
    "ms",
    "millis",
    "minutes",
    "hours",
    "days",
];
/// Name segments of a unit conversion (`SECONDS_PER_DAY`, `PERCENT`), a fact rather than a bound.
const CONVERSION_WORDS: &[&str] = &["per", "percent", "permille"];
/// Measures of a value's own shape; a constant compared with one is a format fact.
const MEASURES: &[&str] = &["len", "length", "count", "size"];
const DURATION_TYPES: &[&str] = &["Duration"];
const DURATION_CONSTRUCTORS: &[&str] = &[
    "from_secs",
    "from_millis",
    "from_micros",
    "from_nanos",
    "from_secs_f32",
    "from_secs_f64",
    "from_mins",
    "from_hours",
    "new",
];
/// Calls whose single argument is a capacity or a wait.
const LITERAL_BOUND_CALLS: &[&str] = &[
    "with_capacity",
    "bounded",
    "channel",
    "sync_channel",
    "timeout",
    "sleep",
];
/// Script timers, whose second argument is the wait.
const TIMERS: &[&str] = &["setTimeout", "setInterval"];
/// Calls that bound a value; a named constant as their argument is a bound.
const CONSTANT_BOUND_CALLS: &[&str] = &[
    "take",
    "min",
    "max",
    "clamp",
    "truncate",
    "reserve",
    "slice",
    "substring",
    "with_capacity",
    "bounded",
    "channel",
    "sync_channel",
    "timeout",
    "sleep",
    "setTimeout",
    "setInterval",
];
const COMPARISONS: &[&str] = &["<", "<=", ">"];
const BINDING_KEYWORDS: &[&str] = &["const", "static", "let", "var"];
/// Bindings whose duration-typed initialiser makes them a bound whatever their name.
const CONSTANT_KEYWORDS: &[&str] = &["const", "static"];
const NOT_NAMES: &[&str] = &["fn", "unsafe", "async", "extern", "impl", "_"];
const TYPE_SUFFIXES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64",
];
const EXPRESSION_ENDS: &[&str] = &[";", ",", ")", "}", "]"];

/// A binding whose value is a number expression with at least one number other than 0 and 1.
struct Constant {
    name: String,
    line: usize,
    number: String,
    bound_name: bool,
}

pub(super) fn findings(source: &Source) -> Vec<Raw> {
    let tokens = source.tokens();
    let constants = constants(tokens, source.language);
    let constant_lines: BTreeSet<usize> = constants.iter().map(|constant| constant.line).collect();
    let mut found = Vec::new();
    let mut reported: BTreeSet<(usize, String)> = BTreeSet::new();
    let mut report = |line: usize, value: &str, message: String| {
        if source.in_test(line) || !reported.insert((line, value.to_owned())) {
            return;
        }
        found.push(Raw::valued(Check::S7, line, message, value));
    };
    for constant in constants.iter().filter(|constant| constant.bound_name) {
        report(constant.line, &constant.name, constant_message(constant));
    }
    for (index, token) in tokens.iter().enumerate() {
        if constant_lines.contains(&token.line) {
            continue;
        }
        if let Some(number) = literal_bound(tokens, index, source.language) {
            report(token.line, &number, literal_message(&number));
        }
        if let Some(constant) = constant_used_as_bound(tokens, index, &constants) {
            report(constant.line, &constant.name, constant_message(constant));
        }
    }
    found
}

/// The number at a literal-only bound position starting at token `index`, if any.
fn literal_bound(tokens: &[Token], index: usize, language: Language) -> Option<String> {
    let token = tokens.get(index)?;
    let call_open = text(tokens, index + 1) == "(";
    if token.kind == TokenKind::Ident && call_open {
        let duration = language == Language::Rust
            && DURATION_CONSTRUCTORS.contains(&token.text.as_str())
            && text_before(tokens, index, 1) == "::"
            && DURATION_TYPES.contains(&text_before(tokens, index, 2));
        if duration || LITERAL_BOUND_CALLS.contains(&token.text.as_str()) {
            return number_argument(tokens, index + 2, language);
        }
        if TIMERS.contains(&token.text.as_str()) {
            let comma = top_level_comma(tokens, index + 2)?;
            return number_argument(tokens, comma + 1, language);
        }
    }
    if token.kind == TokenKind::Ident
        && bound_name(&token.text)
        && matches!(text(tokens, index + 1), ":" | "=")
        && !BINDING_KEYWORDS.contains(&text_before(tokens, index, 1))
    {
        return number_argument(tokens, index + 2, language);
    }
    if COMPARISONS.contains(&token.text.as_str()) {
        return compared_literal(tokens, index);
    }
    None
}

/// The constant named at `index` when the token sits at a bound position.
fn constant_used_as_bound<'c>(
    tokens: &[Token],
    index: usize,
    constants: &'c [Constant],
) -> Option<&'c Constant> {
    let token = tokens.get(index)?;
    let constant = constants
        .iter()
        .find(|constant| token.kind == TokenKind::Ident && constant.name == token.text)?;
    let opener = text_before(tokens, index, 1);
    let caller = text_before(tokens, index, 2);
    let sole_argument = matches!(opener, "(" | ",") && matches!(text(tokens, index + 1), ")" | ",");
    let in_call = sole_argument && CONSTANT_BOUND_CALLS.contains(&caller);
    let in_duration = opener == "("
        && DURATION_CONSTRUCTORS.contains(&caller)
        && DURATION_TYPES.contains(&text_before(tokens, index, 4));
    let in_timer = opener == ","
        && call_name_of_argument(tokens, index).is_some_and(|name| TIMERS.contains(&name));
    let after = text(tokens, index + 1);
    let compared_left =
        COMPARISONS.contains(&opener) || (opener == "=" && text_before(tokens, index, 2) == ">");
    let compared_right = COMPARISONS.contains(&after);
    let measured = (compared_left
        && index
            .checked_sub(2)
            .and_then(|end| operand_name(tokens, end))
            .is_some_and(|name| MEASURES.contains(&name)))
        || (compared_right
            && tokens.get(index + 2).is_some_and(|other| {
                MEASURES.contains(&other.text.as_str())
                    || operand_ends_in_measure(tokens, index + 2)
            }));
    let compared = (compared_left || compared_right) && !measured;
    (in_call || in_duration || in_timer || compared).then_some(constant)
}

/// Bindings and constants whose initialiser is a number expression with a number other than 0
/// and 1: `const MAX: usize = 1 << 20;`, `let delay_ms = 250;`, `const LIMIT = 3`.
fn constants(tokens: &[Token], language: Language) -> Vec<Constant> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if !BINDING_KEYWORDS.contains(&token.text.as_str()) || token.kind != TokenKind::Ident {
            continue;
        }
        let mut name_at = index + 1;
        if text(tokens, name_at) == "mut" {
            name_at += 1;
        }
        let Some(name) = tokens
            .get(name_at)
            .filter(|t| t.kind == TokenKind::Ident && !NOT_NAMES.contains(&t.text.as_str()))
        else {
            continue;
        };
        let Some(equals) = (name_at + 1..tokens.len())
            .find(|&i| matches!(text(tokens, i), "=" | ";" | "{"))
            .filter(|&i| text(tokens, i) == "=")
        else {
            continue;
        };
        let duration = language == Language::Rust
            && CONSTANT_KEYWORDS.contains(&token.text.as_str())
            && DURATION_TYPES.contains(&text(tokens, equals + 1))
            && text(tokens, equals + 2) == "::";
        let start = if duration { equals + 5 } else { equals + 1 };
        let conversion = segments(&name.text)
            .iter()
            .any(|segment| CONVERSION_WORDS.contains(&segment.as_str()));
        if conversion {
            continue;
        }
        if let Some(number) = number_argument(tokens, start, language) {
            found.push(Constant {
                name: name.text.clone(),
                line: name.line,
                number,
                bound_name: bound_name(&name.text) || duration,
            });
        }
    }
    found
}

/// The number expression starting at `start`, as written, when it holds a number other than 0
/// and 1. It runs to the first `;`, `,`, `)`, `}` or `]` at its own depth; `None` when it holds
/// anything but numbers, operators, parentheses and numeric type casts.
fn number_argument(tokens: &[Token], start: usize, language: Language) -> Option<String> {
    let first_line = tokens.get(start).map(|token| token.line);
    let mut depth = 0usize;
    let mut written = String::new();
    let mut bound = false;
    let mut previous_as = false;
    for token in tokens.iter().skip(start) {
        let text = token.text.as_str();
        let next_statement = language != Language::Rust && Some(token.line) != first_line;
        if depth == 0 && (EXPRESSION_ENDS.contains(&text) || next_statement) {
            break;
        }
        written.push_str(text);
        match (token.kind, text) {
            (TokenKind::Number, _) => bound |= !trivial(text),
            (_, "(") => depth += 1,
            (_, ")") => depth = depth.saturating_sub(1),
            (_, "-" | "+" | "*" | "/" | "<" | ">" | "%") => {}
            (TokenKind::Ident, "as") => {
                previous_as = true;
                continue;
            }
            (TokenKind::Ident, _) if previous_as && TYPE_SUFFIXES.contains(&text) => {}
            _ => return None,
        }
        previous_as = false;
    }
    bound.then_some(written)
}

/// The literal on either side of the comparison at `index` when the other side is a bound name.
fn compared_literal(tokens: &[Token], index: usize) -> Option<String> {
    let mut right = index + 1;
    if text(tokens, right) == "=" {
        right += 1;
    }
    let left_name = operand_name(tokens, index.checked_sub(1)?);
    let right_number = tokens
        .get(right)
        .filter(|token| token.kind == TokenKind::Number && !trivial(&token.text));
    if let (Some(number), true) = (right_number, left_name.is_some_and(bound_name)) {
        return Some(number.text.clone());
    }
    let left_number = tokens
        .get(index.checked_sub(1)?)
        .filter(|token| token.kind == TokenKind::Number && !trivial(&token.text))?;
    let right_name = tokens
        .get(right)
        .filter(|token| token.kind == TokenKind::Ident)?;
    bound_name(&right_name.text).then(|| left_number.text.clone())
}

/// The name an operand ends with, skipping a call's parentheses: `self.retries`, `elapsed()`.
fn operand_name(tokens: &[Token], end: usize) -> Option<&str> {
    let mut index = end;
    let mut depth = 0usize;
    loop {
        let token = tokens.get(index)?;
        match token.text.as_str() {
            ")" => depth += 1,
            "(" if depth > 0 => depth -= 1,
            _ if depth == 0 && token.kind == TokenKind::Ident => return Some(token.text.as_str()),
            _ if depth == 0 => return None,
            _ => {}
        }
        index = index.checked_sub(1)?;
    }
}

/// Whether the operand starting at `start` (`fields.len()`, `self.count`) ends in a measure.
fn operand_ends_in_measure(tokens: &[Token], start: usize) -> bool {
    let mut index = start;
    let mut last = None;
    while let Some(token) = tokens.get(index) {
        match token.text.as_str() {
            "." | "(" | ")" => {}
            _ if token.kind == TokenKind::Ident => last = Some(token.text.as_str()),
            _ => break,
        }
        index += 1;
    }
    last.is_some_and(|name| MEASURES.contains(&name))
}

/// The name of the call whose argument list holds the token at `index`.
fn call_name_of_argument(tokens: &[Token], index: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut cursor = index;
    loop {
        cursor = cursor.checked_sub(1)?;
        match text(tokens, cursor) {
            ")" => depth += 1,
            "(" if depth == 0 => return Some(text_before(tokens, cursor, 1)),
            "(" => depth -= 1,
            ";" | "{" | "}" => return None,
            _ => {}
        }
    }
}

fn top_level_comma(tokens: &[Token], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" if depth == 0 => return None,
            ")" | "]" | "}" => depth -= 1,
            "," if depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// Whether a `snake_case`, `camelCase` or `SCREAMING_CASE` name has a bound word as a segment.
pub(super) fn bound_name(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|segment| BOUND_WORDS.contains(&segment.as_str()))
}

fn segments(name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        let boundary = c == '_' || c == '-' || (c.is_uppercase() && previous_lower);
        if boundary && !current.is_empty() {
            found.push(std::mem::take(&mut current));
        }
        if c != '_' && c != '-' {
            current.extend(c.to_lowercase());
        }
        previous_lower = c.is_lowercase() || c.is_ascii_digit();
    }
    if !current.is_empty() {
        found.push(current);
    }
    found
}

/// Zero and one in any notation: `0`, `1_u32`, `0x1`, `1.0`.
fn trivial(number: &str) -> bool {
    let digits: String = number.chars().filter(|c| *c != '_').collect();
    let unsuffixed = TYPE_SUFFIXES
        .iter()
        .find_map(|suffix| digits.strip_suffix(suffix))
        .unwrap_or(&digits);
    let radix = [("0x", 16), ("0o", 8), ("0b", 2)]
        .iter()
        .find_map(|(prefix, radix)| unsuffixed.strip_prefix(prefix).map(|rest| (rest, *radix)));
    match radix {
        Some((rest, radix)) => u128::from_str_radix(rest, radix).is_ok_and(|value| value <= 1),
        None => unsuffixed
            .parse::<f64>()
            .is_ok_and(|value| value == 0.0 || value == 1.0),
    }
}

fn constant_message(constant: &Constant) -> String {
    format!(
        "`{}` holds the bound `{}` in code; move it to limits.toml (or the configuration schema for a product setting) and read it",
        constant.name, constant.number
    )
}

fn literal_message(number: &str) -> String {
    format!(
        "the number {number} is a bound written in code; name it in limits.toml (or the configuration schema for a product setting) and read it"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::AddedLines;
    use crate::paths::RepoPath;

    fn s7(path: &str, source: &str) -> Vec<(usize, String)> {
        let path = RepoPath::new(path).unwrap();
        let added = AddedLines::All;
        let source = Source::read(&path, source, &added).unwrap();
        findings(&source)
            .into_iter()
            .map(|raw| match raw.key {
                Some(super::super::super::Key::Value(value)) => (raw.line, value),
                _ => (raw.line, String::new()),
            })
            .collect()
    }

    #[test]
    fn flags_rust_bounds_and_constants_used_as_bounds() {
        let source = "const FORMAT_TIMEOUT: Duration = Duration::from_secs(30);\nconst PRINTED: usize = 9;\nconst MAX_BODY: usize = 1 << 20;\nfn f(items: &[u8], attempts: u32) {\n    let shown = items.iter().take(PRINTED);\n    let pause = Duration::from_millis(250);\n    let buffer = Vec::<u8>::with_capacity(64);\n    if attempts >= 5 {}\n    let config = Config { max_turns: 40, name: 2 };\n}\n";
        let found = s7("crates/a/src/lib.rs", source);
        let values: Vec<(usize, &str)> = found.iter().map(|(l, v)| (*l, v.as_str())).collect();
        assert_eq!(
            values,
            vec![
                (1, "FORMAT_TIMEOUT"),
                (3, "MAX_BODY"),
                (2, "PRINTED"),
                (6, "250"),
                (7, "64"),
                (8, "5"),
                (9, "40"),
            ]
        );
    }

    #[test]
    fn flags_script_timers_and_bound_properties() {
        let source = "const MAX_ROUNDS = 3\nconst options = { timeoutMs: 30000, label: 2 };\nsetTimeout(() => run(), 5000);\nsetTimeout(run, 0);\nif (retries > 4) {}\n";
        let values: Vec<usize> = s7("web/tools/a.ts", source)
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert_eq!(values, vec![1, 2, 3, 5]);
    }

    #[test]
    fn passes_structure_indexes_and_trivial_numbers() {
        let source = "const PAIRS: usize = 2;\nconst SECONDS_PER_DAY: u64 = 86_400;\nconst PERCENT: u64 = 100;\nconst LINE_FIELDS: usize = 4;\nfn g(fields: &[u8], p: u64) -> bool { fields.len() < LINE_FIELDS && p.min(PERCENT) > 0 }\nfn f(parts: &[&str], s: &str) -> bool {\n    let first = parts.iter().take(2).count();\n    let short = &s[..s.len().min(12)];\n    let next = index + 2;\n    let none = Duration::from_secs(0);\n    let one = Duration::from_secs(1);\n    let ok = parts.len() >= 4 && first > 1;\n    let max = parts.len();\n    let depth = 0;\n    matches!(x, 3..=9)\n}\n#[cfg(test)]\nmod tests {\n    const MAX_T: u8 = 9;\n    fn t() { let d = Duration::from_secs(30); }\n}\n";
        assert!(
            s7("crates/a/src/lib.rs", source).is_empty(),
            "{:?}",
            s7("crates/a/src/lib.rs", source)
        );
    }

    #[test]
    fn names_split_in_every_case() {
        assert!(bound_name("MAX_ROUNDS"));
        assert!(bound_name("retryDelayMs"));
        assert!(bound_name("format_timeout_s"));
        assert!(!bound_name("PAIRS"));
        assert!(!bound_name("minute_hand"));
        assert!(trivial("1_u32") && trivial("0x0") && trivial("1.0") && !trivial("2"));
    }
}
