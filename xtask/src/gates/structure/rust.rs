//! Rust structure: top-level items in file order, the test module, struct fields, and the
//! implicit state machines of check S4.

use std::collections::{BTreeMap, BTreeSet};

use super::items::{Item, ItemKind, brace_body, items_between, matching, skip_visibility};
use super::lexer::{Lexed, Token, TokenKind, text};
use super::nesting;
use super::{Analysis, Check, Pattern, Raw, within};
use crate::config::limits::StructureLimits;

const STATE_NAMES: &[&str] = &["state", "status", "phase", "stage", "mode"];
const STATE_SUFFIXES: &[&str] = &["_state", "_status", "_phase", "_stage", "_mode"];
const INTEGER_TYPES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];
const TEXT_TYPES: &[&str] = &[
    "String",
    "str",
    "CompactString",
    "SmolStr",
    "OsString",
    "OsStr",
];
const TYPE_WRAPPERS: &[&str] = &[
    "Option", "Box", "Arc", "Rc", "Cow", "std", "sync", "rc", "borrow", "boxed", "option",
    "string", "mut", "dyn",
];
const PRESENCE_METHODS: &[&str] = &["is_some", "is_none", "is_some_and", "is_none_or"];
const CONTROL_KEYWORDS: &[&str] = &["if", "else", "for", "while", "loop", "match"];
const CLOSURE_MARKERS: &[&str] = &["|", "||"];

#[derive(Debug, Clone)]
struct Field {
    name: String,
    ty: Vec<String>,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    Bool,
    Integer,
    Text,
    Other,
}

struct Struct {
    name: String,
    line: usize,
    fields: Vec<Field>,
}

impl FieldType {
    fn of(ty: &[String]) -> FieldType {
        let core: Vec<&str> = ty
            .iter()
            .enumerate()
            .filter(|(index, token)| {
                let lifetime = index
                    .checked_sub(1)
                    .and_then(|previous| ty.get(previous))
                    .is_some_and(|previous| previous == "'");
                is_ident(token) && !TYPE_WRAPPERS.contains(&token.as_str()) && !lifetime
            })
            .map(|(_, token)| token.as_str())
            .collect();
        match core.as_slice() {
            ["bool"] => FieldType::Bool,
            [first, ..] if first.starts_with("NonZero") => FieldType::Integer,
            [one] if INTEGER_TYPES.contains(one) => FieldType::Integer,
            [one] if TEXT_TYPES.contains(one) => FieldType::Text,
            _ => FieldType::Other,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FieldType::Bool => "bool",
            FieldType::Integer => "integer",
            FieldType::Text => "string",
            FieldType::Other => "value",
        }
    }
}

/// The first and last line of each `#[cfg(test)]` item.
pub fn test_lines(lexed: &Lexed) -> Vec<(usize, usize)> {
    items_between(&lexed.tokens, 0, lexed.tokens.len())
        .iter()
        .filter(|item| item.test)
        .map(|item| (item.first_line, item.last_line))
        .collect()
}

pub fn analyse(lexed: &Lexed, limits: &StructureLimits) -> Analysis {
    let tokens = &lexed.tokens;
    let items = items_between(tokens, 0, tokens.len());
    let test_lines: Vec<(usize, usize)> = items
        .iter()
        .filter(|item| item.test)
        .map(|item| (item.first_line, item.last_line))
        .collect();
    let test_tokens: Vec<(usize, usize)> = items
        .iter()
        .filter(|item| item.test)
        .map(|item| (item.start, item.end))
        .collect();
    let in_test = |index: usize| {
        test_tokens
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&index))
    };
    let code_lines = lexed
        .lines
        .iter()
        .enumerate()
        .filter(|(index, line)| line.has_code && !within(&test_lines, index + 1))
        .count();
    let structs = structs_in(tokens, &items);
    let mut findings = order_findings(&items);
    findings.extend(
        structs
            .iter()
            .flat_map(|item| struct_findings(item, limits.bool_field_threshold)),
    );
    findings.extend(presence_findings(tokens, &structs, &in_test));
    findings.extend(nesting::findings(
        tokens,
        CONTROL_KEYWORDS,
        CLOSURE_MARKERS,
        limits.max_nesting_depth,
        &in_test,
    ));
    Analysis {
        code_lines,
        findings,
    }
}

fn order_findings(items: &[Item]) -> Vec<Raw> {
    let mut first_code: Option<&Item> = None;
    let mut findings = Vec::new();
    for item in items.iter().filter(|item| !item.test) {
        match item.kind {
            ItemKind::Impl | ItemKind::Function => {
                first_code.get_or_insert(item);
            }
            ItemKind::Type | ItemKind::TypeAlias | ItemKind::Constant | ItemKind::Static => {
                let Some(first) = first_code else { continue };
                let what = if first.kind == ItemKind::Impl {
                    "impl"
                } else {
                    "function"
                };
                findings.push(Raw::new(
                    Check::S2,
                    item.line,
                    format!(
                        "{} `{}` comes after the first {what} (line {}); declare constants, statics and types before impls and functions",
                        item.keyword, item.name, first.line
                    ),
                ));
            }
            _ => {}
        }
    }
    findings
}

/// Every struct, tuple struct and enum variant with fields, each judged as one type.
fn structs_in(tokens: &[Token], items: &[Item]) -> Vec<Struct> {
    let mut found = Vec::new();
    for item in items.iter().filter(|item| !item.test) {
        if item.keyword == "struct"
            && let Some((open, close)) = tuple_body(tokens, item)
        {
            found.push(Struct {
                name: item.name.clone(),
                line: item.line,
                fields: tuple_fields(tokens, open + 1, close),
            });
            continue;
        }
        let Some((open, close)) = brace_body(tokens, item) else {
            continue;
        };
        if item.kind == ItemKind::Module {
            let inner = items_between(tokens, open + 1, close);
            found.extend(structs_in(tokens, &inner));
        } else if item.keyword == "struct" {
            found.push(Struct {
                name: item.name.clone(),
                line: item.line,
                fields: fields(tokens, open + 1, close),
            });
        } else if item.keyword == "enum" {
            found.extend(variants(tokens, &item.name, open + 1, close));
        }
    }
    found
}

/// The parentheses of a tuple struct, `struct Flags(bool, bool);`.
fn tuple_body(tokens: &[Token], item: &Item) -> Option<(usize, usize)> {
    let open =
        (item.start..=item.end).find(|&index| matches!(text(tokens, index), "{" | "(" | ";"))?;
    if text(tokens, open) != "(" {
        return None;
    }
    Some((open, matching(tokens, open, item.end + 1)?))
}

/// The enum's variants that carry fields, named `Enum::Variant`.
fn variants(tokens: &[Token], name: &str, from: usize, to: usize) -> Vec<Struct> {
    let mut found = Vec::new();
    let mut index = from;
    while index < to {
        let Some(token) = tokens.get(index) else {
            break;
        };
        let opens = text(tokens, index + 1);
        let named = token.kind == TokenKind::Ident && matches!(opens, "{" | "(");
        let close = named.then(|| matching(tokens, index + 1, to)).flatten();
        let Some(close) = close else {
            index = match text(tokens, index) {
                "(" | "[" | "{" | "<" => matching(tokens, index, to).map_or(index + 1, |c| c + 1),
                _ => index + 1,
            };
            continue;
        };
        let fields = if opens == "{" {
            fields(tokens, index + 2, close)
        } else {
            tuple_fields(tokens, index + 2, close)
        };
        found.push(Struct {
            name: format!("{name}::{}", token.text),
            line: token.line,
            fields,
        });
        index = close + 1;
    }
    found
}

/// Tuple fields, named by position.
fn tuple_fields(tokens: &[Token], from: usize, to: usize) -> Vec<Field> {
    let mut found = Vec::new();
    for (start, end) in entry_ranges(tokens, from, to) {
        let cursor = entry_start(tokens, start, end);
        if let (Some(first), Some(ty)) = (tokens.get(cursor), tokens.get(cursor..end)) {
            found.push(Field {
                name: found.len().to_string(),
                ty: ty.iter().map(|t| t.text.clone()).collect(),
                line: first.line,
            });
        }
    }
    found
}

fn fields(tokens: &[Token], from: usize, to: usize) -> Vec<Field> {
    entry_ranges(tokens, from, to)
        .into_iter()
        .filter_map(|(start, end)| field(tokens, start, end))
        .collect()
}

/// The `(start, end)` token range, end exclusive, of each top-level entry between commas in
/// `from..to`.
fn entry_ranges(tokens: &[Token], from: usize, to: usize) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut start = from;
    let mut depth = 0i32;
    for index in from..=to {
        let token = if index == to {
            ","
        } else {
            text(tokens, index)
        };
        match token {
            "<" | "(" | "[" | "{" => depth += 1,
            ">" | ")" | "]" | "}" => depth -= 1,
            "," if depth == 0 => {
                found.push((start, index));
                start = index + 1;
            }
            _ => {}
        }
    }
    found
}

/// The first token of the entry `from..to` after its attributes and visibility.
fn entry_start(tokens: &[Token], from: usize, to: usize) -> usize {
    let mut cursor = from;
    while text(tokens, cursor) == "#" && cursor < to {
        cursor = matching(tokens, cursor + 1, to).map_or(to, |close| close + 1);
    }
    skip_visibility(tokens, cursor, to)
}

fn field(tokens: &[Token], from: usize, to: usize) -> Option<Field> {
    let cursor = entry_start(tokens, from, to);
    let name = tokens
        .get(cursor)
        .filter(|token| token.kind == TokenKind::Ident && cursor < to)?;
    if text(tokens, cursor + 1) != ":" {
        return None;
    }
    let ty = tokens
        .get(cursor + 2..to)
        .unwrap_or_default()
        .iter()
        .map(|token| token.text.clone())
        .collect();
    Some(Field {
        name: name.text.clone(),
        ty,
        line: name.line,
    })
}

fn struct_findings(item: &Struct, threshold: usize) -> Vec<Raw> {
    let mut findings = Vec::new();
    let bools: Vec<&str> = item
        .fields
        .iter()
        .filter(|field| field.ty == ["bool"])
        .map(|field| field.name.as_str())
        .collect();
    if bools.len() >= threshold {
        let message = format!(
            "struct `{}` has {} bool fields ({}); replace them with an enum whose variants are the valid combinations",
            item.name,
            bools.len(),
            bools.join(", ")
        );
        findings.push(Raw::state(
            item.line,
            message,
            &item.name,
            Pattern::BoolFields,
        ));
    }
    for field in &item.fields {
        let state_like = STATE_NAMES.contains(&field.name.as_str())
            || STATE_SUFFIXES
                .iter()
                .any(|suffix| field.name.ends_with(suffix));
        let kind = FieldType::of(&field.ty);
        if state_like && kind != FieldType::Other {
            let message = format!(
                "field `{}` of `{}` is a {}; make it an enum of the states, each variant owning its data",
                field.name,
                item.name,
                kind.label()
            );
            findings.push(Raw::state(
                field.line,
                message,
                &item.name,
                Pattern::StatusField,
            ));
        }
    }
    findings
}

/// Two `Option` fields of one struct tested together in one condition: presence encodes a phase.
fn presence_findings(
    tokens: &[Token],
    structs: &[Struct],
    in_test: &dyn Fn(usize) -> bool,
) -> Vec<Raw> {
    let mut owners: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for item in structs {
        for field in item
            .fields
            .iter()
            .filter(|field| field.ty.first().is_some_and(|t| t == "Option"))
        {
            owners
                .entry(field.name.as_str())
                .or_default()
                .insert(item.name.as_str());
        }
    }
    if owners.len() < 2 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut reported: BTreeSet<(String, usize)> = BTreeSet::new();
    let mut segment: Vec<usize> = Vec::new();
    for index in 0..=tokens.len() {
        let boundary = index == tokens.len()
            || matches!(text(tokens, index), ";" | "{" | "}")
            || in_test(index);
        if !boundary {
            segment.push(index);
            continue;
        }
        if let Some((owner, fields, line)) = presence_together(tokens, &segment, &owners)
            && reported.insert((owner.to_owned(), line))
        {
            let message = format!(
                "Option fields {} of `{owner}` are checked together; replace them with an enum whose variants own the data",
                fields
                    .iter()
                    .map(|field| format!("`{field}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            );
            findings.push(Raw::state(line, message, owner, Pattern::OptionGroup));
        }
        segment.clear();
    }
    findings
}

fn presence_together<'a>(
    tokens: &'a [Token],
    segment: &[usize],
    owners: &BTreeMap<&'a str, BTreeSet<&'a str>>,
) -> Option<(&'a str, Vec<&'a str>, usize)> {
    let mut accessed: BTreeSet<&str> = BTreeSet::new();
    let mut presence_calls = 0;
    let mut matches_option = false;
    for &index in segment {
        let token = text(tokens, index);
        matches_option |= token == "Some" || token == "None";
        let member = tokens
            .get(index + 1)
            .filter(|next| token == "." && next.kind == TokenKind::Ident);
        let Some(member) = member.filter(|member| owners.contains_key(member.text.as_str())) else {
            continue;
        };
        if text(tokens, index + 2) == "(" {
            continue;
        }
        accessed.insert(member.text.as_str());
        if text(tokens, index + 2) == "." && PRESENCE_METHODS.contains(&text(tokens, index + 3)) {
            presence_calls += 1;
        }
    }
    let starts_match = segment
        .first()
        .is_some_and(|&index| text(tokens, index) == "match");
    if accessed.len() < 2 || !(presence_calls >= 2 || matches_option || starts_match) {
        return None;
    }
    let owner = owners.values().flatten().find(|owner| {
        accessed
            .iter()
            .filter(|field| owners.get(*field).is_some_and(|set| set.contains(*owner)))
            .count()
            >= 2
    })?;
    let fields = accessed
        .iter()
        .copied()
        .filter(|field| owners.get(field).is_some_and(|set| set.contains(owner)))
        .collect();
    let line = segment.first().and_then(|&index| tokens.get(index))?.line;
    Some((owner, fields, line))
}

fn is_ident(token: &str) -> bool {
    token.starts_with(|c: char| c == '_' || c.is_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::super::lexer::{Language, lex};
    use super::*;

    fn checks(source: &str) -> Vec<(Check, usize)> {
        analyse(
            &lex(source, Language::Rust),
            &crate::config::limits::Limits::built_with()
                .unwrap()
                .gates
                .structure,
        )
        .findings
        .iter()
        .map(|f| (f.check, f.line))
        .collect()
    }

    #[test]
    fn s2_flags_types_after_the_first_function() {
        let source = "use std::fmt;\nconst A: u8 = 1;\nstruct S;\nimpl S {}\nfn f() {}\nenum Late {}\nconst B: [u8; 2] = [1, 2];\n";
        assert_eq!(checks(source), vec![(Check::S2, 6), (Check::S2, 7)]);
    }

    #[test]
    fn s2_passes_ordered_files_and_ignores_the_test_module() {
        let source = "use a::b;\n\nconst X: u8 = 1;\nstatic Y: u8 = 2;\npub(crate) struct S { a: u8 }\ntype T = u8;\nimpl S { fn g(&self) {} }\npub const fn h() {}\n#[cfg(test)]\nmod tests {\n    struct Fixture;\n    fn t() {}\n}\n";
        assert!(checks(source).is_empty());
    }

    #[test]
    fn s1_counts_code_lines_outside_tests_and_comments() {
        let source = "// comment\n\nfn a() {\n    let x = \"two\nlines\";\n}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
        let limits = &crate::config::limits::Limits::built_with()
            .unwrap()
            .gates
            .structure;
        assert_eq!(analyse(&lex(source, Language::Rust), limits).code_lines, 4);
    }

    #[test]
    fn s4_counts_tuple_structs_variants_and_status_suffixes() {
        let tuple = checks("pub struct Flags(pub bool, pub bool, pub bool);\n");
        assert!(
            tuple.iter().any(|(check, _)| *check == Check::S4),
            "{tuple:?}"
        );
        let variant = checks("pub enum E {\n    A,\n    V { a: bool, b: bool, c: bool },\n}\n");
        assert!(
            variant.iter().any(|(check, _)| *check == Check::S4),
            "{variant:?}"
        );
        let status = checks("struct Job {\n    job_status: String,\n}\n");
        assert_eq!(status, vec![(Check::S4, 2)]);
        let fine =
            checks("pub enum E { A(u8), B { name: String } }\npub struct P(pub u8, pub bool);\n");
        assert!(fine.is_empty(), "{fine:?}");
    }

    #[test]
    fn s4_flags_three_bools_and_stringly_status() {
        let source = "struct Job {\n    started: bool,\n    finished: bool,\n    #[serde(default)]\n    pub failed: bool,\n    status: String,\n    retry_state: Option<u8>,\n    mode: Mode,\n}\n";
        assert_eq!(
            checks(source),
            vec![(Check::S4, 1), (Check::S4, 6), (Check::S4, 7)]
        );
    }

    #[test]
    fn s4_passes_an_explicit_state_type() {
        let source = "enum Job { Queued, Running { since: u64 }, Done(Outcome) }\nstruct Runner {\n    job: Job,\n    verbose: bool,\n    status: Status,\n    name: String,\n}\n";
        assert!(checks(source).is_empty());
    }

    #[test]
    fn s4_flags_option_fields_checked_together() {
        let source = "struct Lease {\n    started: Option<u64>,\n    finished: Option<u64>,\n}\nimpl Lease {\n    fn running(&self) -> bool {\n        self.started.is_some() && self.finished.is_none()\n    }\n    fn phase(&self) -> u8 {\n        match (self.started, self.finished) {\n            (Some(_), None) => 1,\n            _ => 0,\n        }\n    }\n}\n";
        assert_eq!(checks(source), vec![(Check::S4, 7), (Check::S4, 10)]);
    }

    #[test]
    fn s4_ignores_unrelated_option_use() {
        let source = "struct A {\n    x: Option<u8>,\n    y: Option<u8>,\n}\nfn f(a: &A) -> u8 {\n    let total = a.x.unwrap_or(0) + a.y.unwrap_or(0);\n    if a.x.is_some() { total } else { 0 }\n}\n";
        assert!(checks(source).is_empty());
    }

    #[test]
    fn s5_warns_past_four_levels() {
        let deep = "fn f(v: &[u8]) {\n    for a in v {\n        if *a > 1 {\n            while true {\n                match a {\n                    _ => if true {\n                        loop {}\n                    }\n                }\n            }\n        }\n    }\n}\n";
        assert_eq!(checks(deep), vec![(Check::S5, 6)]);
        let shallow = "fn f(v: &[u8]) {\n    for a in v {\n        if let Some(S { x, .. }) = g(a) {\n            let s = S { x };\n            h(|y| { if y { k() } });\n        }\n    }\n}\n";
        assert!(checks(shallow).is_empty());
    }
}
