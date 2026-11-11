//! TypeScript and JavaScript structure: imports, constants, types and interfaces, then functions and
//! classes (owner instruction 4, rule 1), and the S4 field rules on interfaces and object types.

use super::lexer::{Lexed, Token, TokenKind, text};
use super::nesting;
use super::{Analysis, Check, Pattern, Raw};
use crate::config::limits::StructureLimits;

const MODIFIERS: &[&str] = &["export", "default", "declare", "async", "abstract"];
const STARTERS: &[&str] = &[
    "export",
    "import",
    "const",
    "let",
    "var",
    "type",
    "interface",
    "enum",
    "function",
    "class",
    "declare",
    "abstract",
    "async",
];
const STATE_NAMES: &[&str] = &["state", "status", "phase", "stage", "mode"];
const PRIMITIVE_TYPES: &[&str] = &["string", "number", "boolean"];
const CONTROL_KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "switch", "try", "catch", "finally",
];
const CLOSURE_MARKERS: &[&str] = &["=>"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Import,
    Constant,
    Type,
    Function,
    Other,
}

struct Statement {
    kind: Kind,
    keyword: String,
    name: String,
    line: usize,
    start: usize,
}

struct Member {
    name: String,
    ty: Vec<String>,
    line: usize,
}

pub fn analyse(lexed: &Lexed, limits: &StructureLimits) -> Analysis {
    let tokens = &lexed.tokens;
    let statements = statements(tokens);
    let mut findings = order_findings(&statements);
    for statement in statements.iter().filter(|s| s.kind == Kind::Type) {
        findings.extend(member_findings(
            tokens,
            statement,
            limits.bool_field_threshold,
        ));
    }
    findings.extend(nesting::findings(
        tokens,
        CONTROL_KEYWORDS,
        CLOSURE_MARKERS,
        limits.max_nesting_depth,
        &|_| false,
    ));
    let code_lines = lexed.lines.iter().filter(|line| line.has_code).count();
    Analysis {
        code_lines,
        findings,
    }
}

fn statements(tokens: &[Token]) -> Vec<Statement> {
    let mut found = Vec::new();
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        let previous = index.checked_sub(1).and_then(|p| tokens.get(p));
        let begins = previous.is_none_or(|p| p.text == ";" || p.text == "}" || token.line > p.line);
        if depth == 0 && begins && STARTERS.contains(&token.text.as_str()) {
            found.push(classify(tokens, index));
        }
        match token.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    found
}

fn classify(tokens: &[Token], start: usize) -> Statement {
    let mut cursor = start;
    while MODIFIERS.contains(&text(tokens, cursor)) {
        cursor += 1;
    }
    let keyword = text(tokens, cursor);
    let next = text(tokens, cursor + 1);
    let kind = match keyword {
        "import" => Kind::Import,
        "interface" | "enum" => Kind::Type,
        "type"
            if tokens
                .get(cursor + 1)
                .is_some_and(|t| t.kind == TokenKind::Ident) =>
        {
            Kind::Type
        }
        "const" if next == "enum" => Kind::Type,
        "function" | "class" => Kind::Function,
        "const" | "let" | "var" if binds_function(tokens, cursor) => Kind::Function,
        "const" if is_constant_name(next) => Kind::Constant,
        _ => Kind::Other,
    };
    Statement {
        kind,
        keyword: keyword.to_owned(),
        name: next.to_owned(),
        line: tokens.get(start).map_or(0, |token| token.line),
        start: cursor,
    }
}

/// `const f = (a) => ...`, `const f = async x => ...`, `const f = function ...`.
fn binds_function(tokens: &[Token], keyword: usize) -> bool {
    let Some(equals) = (keyword..tokens.len().min(keyword + 12)).find(|&i| text(tokens, i) == "=")
    else {
        return false;
    };
    let mut cursor = equals + 1;
    if text(tokens, cursor) == "async" {
        cursor += 1;
    }
    match text(tokens, cursor) {
        "function" => true,
        "(" => {
            let mut depth = 0usize;
            for index in cursor..tokens.len() {
                match text(tokens, index) {
                    "(" | "[" | "{" | "<" => depth += 1,
                    ")" | "]" | "}" | ">" => depth = depth.saturating_sub(1),
                    "=>" if depth == 0 => return true,
                    ";" if depth == 0 => return false,
                    "=" if depth == 0 => return false,
                    _ => {}
                }
            }
            false
        }
        _ => text(tokens, cursor + 1) == "=>",
    }
}

fn order_findings(statements: &[Statement]) -> Vec<Raw> {
    let mut first_function: Option<&Statement> = None;
    let mut findings = Vec::new();
    for statement in statements {
        match statement.kind {
            Kind::Function => {
                first_function.get_or_insert(statement);
            }
            Kind::Constant | Kind::Type => {
                let Some(first) = first_function else {
                    continue;
                };
                findings.push(Raw::new(
                    Check::S2,
                    statement.line,
                    format!(
                        "{} `{}` comes after the first function or class (line {}); declare constants and types first",
                        statement.keyword, statement.name, first.line
                    ),
                ));
            }
            Kind::Import | Kind::Other => {}
        }
    }
    findings
}

fn member_findings(tokens: &[Token], statement: &Statement, threshold: usize) -> Vec<Raw> {
    let Some(open) =
        (statement.start..tokens.len().min(statement.start + 40)).find(|&i| text(tokens, i) == "{")
    else {
        return Vec::new();
    };
    let members = members(tokens, open);
    let mut findings = Vec::new();
    let bools: Vec<&str> = members
        .iter()
        .filter(|m| m.ty == ["boolean"])
        .map(|m| m.name.as_str())
        .collect();
    if bools.len() >= threshold {
        let message = format!(
            "type `{}` has {} boolean fields ({}); replace them with a union of the valid states",
            statement.name,
            bools.len(),
            bools.join(", ")
        );
        findings.push(Raw::state(
            statement.line,
            message,
            &statement.name,
            Pattern::BoolFields,
        ));
    }
    for member in &members {
        let primitive = match member.ty.as_slice() {
            [one] if PRIMITIVE_TYPES.contains(&one.as_str()) => Some(one),
            _ => None,
        };
        if let Some(primitive) = primitive.filter(|_| STATE_NAMES.contains(&member.name.as_str())) {
            let message = format!(
                "field `{}` of `{}` is a {primitive}; make it a union of the states, each owning its data",
                member.name, statement.name
            );
            findings.push(Raw::state(
                member.line,
                message,
                &statement.name,
                Pattern::StatusField,
            ));
        }
    }
    findings
}

fn members(tokens: &[Token], open: usize) -> Vec<Member> {
    let mut found = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<Member> = None;
    for (index, token) in tokens.iter().enumerate().skip(open + 1) {
        if depth == 0 && token.text == "}" {
            break;
        }
        let starts_member = depth == 0
            && token.kind == TokenKind::Ident
            && matches!(text(tokens, index + 1), ":" | "?")
            && current
                .as_ref()
                .is_none_or(|member| token.line > member.line || member.ty.is_empty());
        if starts_member {
            found.extend(current.take());
            current = Some(Member {
                name: token.text.clone(),
                ty: Vec::new(),
                line: token.line,
            });
            continue;
        }
        match token.text.as_str() {
            "(" | "[" | "{" | "<" => depth += 1,
            ")" | "]" | "}" | ">" => depth = depth.saturating_sub(1),
            ";" | "," if depth == 0 => {
                found.extend(current.take());
                continue;
            }
            _ => {}
        }
        if let Some(member) = current.as_mut()
            && !matches!(token.text.as_str(), ":" | "?")
        {
            member.ty.push(token.text.clone());
        }
    }
    found.extend(current);
    found
}

/// `MAX_ROUNDS` is a module constant. A camelCase binding at the top of a script, such as
/// `const input = await read()`, is a statement of its body, which rule 1 does not order.
fn is_constant_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::super::lexer::{Language, lex};
    use super::*;

    fn checks(source: &str) -> Vec<(Check, usize)> {
        analyse(
            &lex(source, Language::Script),
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
    fn s2_orders_imports_constants_types_then_functions() {
        let ordered = "import { a } from './a';\nconst LIMIT = 3;\nexport interface Item { id: string }\ntype Id = string;\nexport const load = async (id: Id) => a(id);\nexport function run() {}\nclass Runner {}\n";
        assert!(checks(ordered).is_empty());
        let late = "function run() {}\nconst LIMIT = 3\nexport type Late = number\nconst input = await run();\n";
        assert_eq!(checks(late), vec![(Check::S2, 2), (Check::S2, 3)]);
    }

    #[test]
    fn s4_flags_boolean_flags_and_string_status() {
        let source = "interface Job {\n  started: boolean;\n  finished?: boolean\n  failed: boolean,\n  status: string;\n  kind: 'a' | 'b';\n}\n";
        assert_eq!(checks(source), vec![(Check::S4, 1), (Check::S4, 5)]);
    }

    #[test]
    fn s4_passes_a_union_status() {
        let source = "type Job = {\n  status: 'queued' | 'running';\n  verbose: boolean;\n};\n";
        assert!(checks(source).is_empty());
    }
}
