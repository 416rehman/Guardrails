//! Check S5: control-flow nesting deeper than four levels, in either language. A brace counts as a
//! level when it opens the body of a control keyword or a closure; struct literals, patterns and
//! item bodies do not.

use super::lexer::{Token, TokenKind};
use super::{Check, Raw};

struct Level {
    counted: bool,
    outer_paren: usize,
    outer_control: bool,
}

pub fn findings(
    tokens: &[Token],
    control: &[&str],
    closure_markers: &[&str],
    max_depth: usize,
    skip: &dyn Fn(usize) -> bool,
) -> Vec<Raw> {
    let mut findings = Vec::new();
    let mut levels: Vec<Level> = Vec::new();
    let mut paren = 0usize;
    let mut control_seen = false;
    let mut reported = false;
    let mut previous = "";
    for (index, token) in tokens.iter().enumerate() {
        if skip(index) {
            continue;
        }
        match token.text.as_str() {
            "(" | "[" => paren += 1,
            ")" | "]" => paren = paren.saturating_sub(1),
            "{" => {
                let closure = closure_markers.contains(&previous);
                let counted = closure || (paren == 0 && control_seen);
                levels.push(Level {
                    counted,
                    outer_paren: paren,
                    outer_control: control_seen,
                });
                paren = 0;
                control_seen = false;
                let depth = levels.iter().filter(|level| level.counted).count();
                if counted && depth > max_depth && !reported {
                    let message = format!(
                        "nesting depth {depth} exceeds {max_depth}; return early or extract a function"
                    );
                    findings.push(Raw::new(Check::S5, token.line, message));
                    reported = true;
                }
            }
            "}" => {
                if let Some(level) = levels.pop() {
                    paren = level.outer_paren;
                    control_seen = level.outer_paren > 0 && level.outer_control;
                }
                reported &= levels.iter().filter(|level| level.counted).count() > max_depth;
            }
            ";" => control_seen = false,
            word if token.kind == TokenKind::Ident && paren == 0 && control.contains(&word) => {
                control_seen = true
            }
            _ => {}
        }
        previous = token.text.as_str();
    }
    findings
}
