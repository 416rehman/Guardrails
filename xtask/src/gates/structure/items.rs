//! The top-level items of a Rust file in order (imports, constants, types, impls, functions,
//! macros), each with its keyword line, its token span and whether it is test-only code.

use super::lexer::{Token, TokenKind, text};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ItemKind {
    Import,
    Module,
    Constant,
    Static,
    Type,
    TypeAlias,
    Impl,
    Function,
    Macro,
    Other,
}

#[derive(Debug, Clone)]
pub(super) struct Item {
    pub(super) kind: ItemKind,
    pub(super) keyword: String,
    pub(super) name: String,
    pub(super) line: usize,
    pub(super) first_line: usize,
    pub(super) last_line: usize,
    pub(super) test: bool,
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(super) fn items_between(tokens: &[Token], from: usize, to: usize) -> Vec<Item> {
    let mut found = Vec::new();
    let mut index = from;
    while index < to {
        let item = scan_item(tokens, index, to);
        index = item.end + 1;
        found.push(item);
    }
    found
}

fn scan_item(tokens: &[Token], start: usize, limit: usize) -> Item {
    let mut cursor = start;
    let mut test = false;
    while text(tokens, cursor) == "#" && cursor < limit {
        let inner = text(tokens, cursor + 1) == "!";
        let open = if inner { cursor + 2 } else { cursor + 1 };
        let close = matching(tokens, open, limit).unwrap_or(open.min(limit.saturating_sub(1)));
        if inner {
            return item(tokens, ItemKind::Other, "#!", start, start, close, false);
        }
        test |= is_cfg_test(tokens.get(open.min(close)..=close).unwrap_or_default());
        cursor = close + 1;
    }
    cursor = skip_visibility(tokens, cursor, limit);
    cursor = skip_qualifiers(tokens, cursor, limit);
    let keyword = text(tokens, cursor);
    let kind = classify(keyword, text(tokens, cursor + 1));
    let end = item_end(tokens, cursor, limit, kind);
    item(tokens, kind, keyword, start, cursor, end, test)
}

fn item(
    tokens: &[Token],
    kind: ItemKind,
    keyword: &str,
    start: usize,
    at: usize,
    end: usize,
    test: bool,
) -> Item {
    let name_at = match kind {
        ItemKind::Macro => at + 2,
        ItemKind::Static if text(tokens, at + 1) == "mut" => at + 2,
        _ => at + 1,
    };
    Item {
        kind,
        keyword: keyword.to_owned(),
        name: text(tokens, name_at).to_owned(),
        line: tokens
            .get(at)
            .or(tokens.get(start))
            .map_or(0, |token| token.line),
        first_line: tokens.get(start).map_or(0, |token| token.line),
        last_line: tokens.get(end).map_or(0, |token| token.line),
        test,
        start,
        end,
    }
}

fn classify(keyword: &str, next: &str) -> ItemKind {
    match keyword {
        "use" => ItemKind::Import,
        "extern" if next == "crate" => ItemKind::Import,
        "mod" => ItemKind::Module,
        "const" => ItemKind::Constant,
        "static" => ItemKind::Static,
        "struct" | "enum" | "union" | "trait" => ItemKind::Type,
        "type" => ItemKind::TypeAlias,
        "impl" => ItemKind::Impl,
        "fn" => ItemKind::Function,
        "macro_rules" => ItemKind::Macro,
        _ => ItemKind::Other,
    }
}

pub(super) fn skip_visibility(tokens: &[Token], cursor: usize, limit: usize) -> usize {
    if text(tokens, cursor) != "pub" {
        return cursor;
    }
    if text(tokens, cursor + 1) == "(" {
        return matching(tokens, cursor + 1, limit).map_or(cursor + 1, |close| close + 1);
    }
    cursor + 1
}

fn skip_qualifiers(tokens: &[Token], mut cursor: usize, limit: usize) -> usize {
    while cursor < limit {
        let next = text(tokens, cursor + 1);
        match text(tokens, cursor) {
            "unsafe" | "async" | "default" | "safe" => cursor += 1,
            "const" if matches!(next, "fn" | "unsafe" | "async" | "extern") => cursor += 1,
            "extern" if next != "crate" => {
                cursor += 1;
                if tokens
                    .get(cursor)
                    .is_some_and(|token| token.kind == TokenKind::Literal)
                {
                    cursor += 1;
                }
            }
            _ => break,
        }
    }
    cursor
}

fn item_end(tokens: &[Token], from: usize, limit: usize, kind: ItemKind) -> usize {
    let semicolon_only = matches!(
        kind,
        ItemKind::Import | ItemKind::Constant | ItemKind::Static | ItemKind::TypeAlias
    );
    let mut depth = 0usize;
    for index in from..limit {
        match text(tokens, index) {
            "(" | "[" | "{" => depth += 1,
            closer @ (")" | "]" | "}") => {
                depth = depth.saturating_sub(1);
                if depth == 0 && closer == "}" && !semicolon_only {
                    return index;
                }
            }
            ";" if depth == 0 => return index,
            _ => {}
        }
    }
    limit
        .saturating_sub(1)
        .max(from.min(limit.saturating_sub(1)))
}

fn is_cfg_test(attribute: &[Token]) -> bool {
    let idents: Vec<&str> = attribute
        .iter()
        .filter(|t| t.kind == TokenKind::Ident)
        .map(|t| t.text.as_str())
        .collect();
    idents.first() == Some(&"cfg") && idents.contains(&"test") && !idents.contains(&"not")
}

/// The `{ ... }` of a struct or module; `None` for tuple and unit structs and `mod x;`.
pub(super) fn brace_body(tokens: &[Token], item: &Item) -> Option<(usize, usize)> {
    let open =
        (item.start..=item.end).find(|&index| matches!(text(tokens, index), "{" | "(" | ";"))?;
    if text(tokens, open) != "{" {
        return None;
    }
    Some((open, matching(tokens, open, item.end + 1)?))
}

pub(super) fn matching(tokens: &[Token], open: usize, limit: usize) -> Option<usize> {
    if !matches!(text(tokens, open), "(" | "[" | "{") {
        return None;
    }
    let mut depth = 0usize;
    for index in open..limit.min(tokens.len()) {
        match text(tokens, index) {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}
