//! Standalone scanning over a `&[char]`: the redirect operators, and finding the `)` that closes a
//! command substitution across quotes, nested substitutions, comments and here-document bodies.

use super::lexer::{Dialect, RedirectKind};

const OPERATORS: &[(&str, RedirectKind)] = &[
    ("&>>", RedirectKind::Write),
    ("<<<", RedirectKind::Document),
    ("<<-", RedirectKind::Document),
    ("&>", RedirectKind::Write),
    (">>", RedirectKind::Write),
    (">|", RedirectKind::Write),
    (">&", RedirectKind::Duplicate),
    ("<&", RedirectKind::Duplicate),
    ("<>", RedirectKind::Write),
    ("<<", RedirectKind::Document),
    (">", RedirectKind::Write),
    ("<", RedirectKind::Read),
];

pub(super) fn redirect_operator(rest: &str) -> (usize, RedirectKind) {
    OPERATORS
        .iter()
        .find(|(operator, _)| rest.starts_with(operator))
        .map_or((1, RedirectKind::Read), |(operator, kind)| {
            (operator.len(), *kind)
        })
}

pub(super) fn is_descriptor(target: &str) -> bool {
    target == "-" || (!target.is_empty() && target.chars().all(|c| c.is_ascii_digit()))
}

/// The index of the `)` that closes a substitution whose body starts at `from`, skipping quotes,
/// nested substitutions, comments and here-document bodies.
pub(super) fn find_close(chars: &[char], from: usize, dialect: Dialect) -> Option<usize> {
    let mut depth = 1usize;
    let mut index = from;
    let mut documents: Vec<(String, bool)> = Vec::new();
    while let Some(&c) = chars.get(index) {
        let next = chars.get(index + 1).copied();
        match (dialect, c) {
            (Dialect::Bash, '\\') | (Dialect::PowerShell, '`') => index += 1,
            (_, '\'') => index = skip_to(chars, index + 1, '\''),
            (_, '"') => index = skip_double(chars, index + 1, dialect),
            (Dialect::Bash, '`') => index = skip_to(chars, index + 1, '`'),
            (_, '$') if next == Some('(') => index = find_close(chars, index + 2, dialect)?,
            (_, '(') => depth += 1,
            (_, ')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            (_, '#') if after_space(chars, index) => {
                while chars.get(index + 1).is_some_and(|c| *c != '\n') {
                    index += 1;
                }
            }
            (Dialect::Bash, '<') if next == Some('<') && chars.get(index + 2) != Some(&'<') => {
                let (delimiter, strip, end) = document_delimiter(chars, index + 2);
                documents.push((delimiter, strip));
                index = end;
                continue;
            }
            (_, '\n') if !documents.is_empty() => {
                index = skip_documents(chars, index + 1, &std::mem::take(&mut documents));
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Whether the character at `index` starts the input or follows whitespace, as a comment must.
fn after_space(chars: &[char], index: usize) -> bool {
    index
        .checked_sub(1)
        .is_none_or(|before| chars.get(before).is_some_and(|c| c.is_whitespace()))
}

fn skip_to(chars: &[char], from: usize, close: char) -> usize {
    chars
        .get(from..)
        .unwrap_or_default()
        .iter()
        .position(|c| *c == close)
        .map_or(chars.len(), |offset| from + offset)
}

fn skip_double(chars: &[char], from: usize, dialect: Dialect) -> usize {
    let escape = if dialect == Dialect::Bash { '\\' } else { '`' };
    let mut index = from;
    while let Some(&c) = chars.get(index) {
        match c {
            c if c == escape => index += 1,
            '"' => return index,
            '$' if chars.get(index + 1) == Some(&'(') => {
                index = find_close(chars, index + 2, dialect).unwrap_or(chars.len());
            }
            _ => {}
        }
        index += 1;
    }
    chars.len()
}

/// The delimiter after `<<` or `<<-` at `from`, whether tabs are stripped, and where it ends.
fn document_delimiter(chars: &[char], from: usize) -> (String, bool, usize) {
    let mut index = from;
    let strip = chars.get(index) == Some(&'-');
    if strip {
        index += 1;
    }
    while chars.get(index).is_some_and(|c| *c == ' ' || *c == '\t') {
        index += 1;
    }
    let mut delimiter = String::new();
    while let Some(c) = chars.get(index).copied() {
        if c.is_whitespace() || ";&|()<>".contains(c) {
            break;
        }
        if !matches!(c, '\'' | '"' | '\\') {
            delimiter.push(c);
        }
        index += 1;
    }
    (delimiter, strip, index)
}

fn skip_documents(chars: &[char], from: usize, documents: &[(String, bool)]) -> usize {
    let mut index = from;
    for (delimiter, strip) in documents {
        while let Some(rest) = chars.get(index..).filter(|rest| !rest.is_empty()) {
            let end = rest
                .iter()
                .position(|c| *c == '\n')
                .map_or(chars.len(), |offset| index + offset);
            let line: String = chars.get(index..end).unwrap_or_default().iter().collect();
            index = (end + 1).min(chars.len());
            let line = line.trim_end_matches('\r');
            let line = if *strip {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if line == delimiter {
                break;
            }
        }
    }
    index
}
