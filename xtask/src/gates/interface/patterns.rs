//! UX7, an unregistered pattern: a component `kit` exports that the pattern registry does not
//! list. The registry's own rules (states, fixtures per declared `ViewState`, one `ViewState` per
//! screen) belong to `cargo xtask interface check`, which reads the registry's full schema.

use crate::gates::structure::lexer::{Token, TokenKind};
use crate::gates::structure::{Check, Raw, Source};

use super::config::{Config, normalise};

const EXPORT: &str = "export";
const DECLARATIONS: &[&str] = &["function", "const", "let", "class"];
const SKIPPED: &[&str] = &["default", "async"];
const ALIAS: &str = "as";

pub(super) fn findings(source: &Source, config: &Config) -> Vec<Raw> {
    if !config.kit.is_match(source.path.as_str()) {
        return Vec::new();
    }
    exported_components(source.tokens())
        .into_iter()
        .filter(|(name, _)| {
            !config
                .patterns
                .as_ref()
                .is_some_and(|ids| ids.contains(&normalise(name)))
        })
        .map(|(name, line)| {
            let registry = &config.patterns_path;
            let message = match &config.patterns {
                Some(_) => format!("`kit` exports `{name}`, which {registry} does not register; register it with a fixture per state (`cargo xtask scaffold pattern <id>`), or use the registered pattern"),
                None => format!("`kit` exports `{name}`, and {registry} does not exist yet; create the registry and register the pattern (`cargo xtask scaffold pattern <id>`)"),
            };
            Raw::new(Check::UX7, line, message)
        })
        .collect()
}

/// Exported names that start with a capital letter, the convention for components:
/// `export function Card`, `export const Card =`, `export default function Card`, `export { Card }`.
fn exported_components(tokens: &[Token]) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.text != EXPORT || token.kind != TokenKind::Ident {
            continue;
        }
        let mut cursor = index + 1;
        while tokens
            .get(cursor)
            .is_some_and(|next| SKIPPED.contains(&next.text.as_str()))
        {
            cursor += 1;
        }
        let Some(next) = tokens.get(cursor) else {
            continue;
        };
        if DECLARATIONS.contains(&next.text.as_str()) {
            found.extend(tokens.get(cursor + 1).and_then(component));
        } else if next.text == "{" {
            found.extend(listed(tokens, cursor));
        }
    }
    found
}

/// The names `export { A, B as C }` exports.
fn listed(tokens: &[Token], open: usize) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    let mut previous: Option<&Token> = None;
    for token in tokens.iter().skip(open + 1) {
        match token.text.as_str() {
            "}" | "," => {
                found.extend(previous.and_then(component));
                if token.text == "}" {
                    break;
                }
                previous = None;
            }
            ALIAS => previous = None,
            _ if token.kind == TokenKind::Ident => previous = Some(token),
            _ => {}
        }
    }
    found
}

fn component(token: &Token) -> Option<(String, usize)> {
    let capital = token.text.starts_with(|c: char| c.is_uppercase());
    (token.kind == TokenKind::Ident && capital).then(|| (token.text.clone(), token.line))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, run};
    use crate::gates::structure::Check;

    #[test]
    fn ux7_kit_exports_need_a_registered_pattern() {
        let source = "export function ApprovalCard() { return null; }\nexport const ModeControl = () => null;\nexport type ModeProps = { a: number };\nexport const helper = 1;\nexport { Timeline, inner as Setup };\n";
        let found = run(Check::UX7, "web/packages/kit/src/index.tsx", source);
        assert_eq!(lines(&found), vec![2, 5, 5]);
        assert!(found[0].1.contains("`ModeControl`"));
        assert!(run(Check::UX7, "web/apps/console/src/index.tsx", source).is_empty());
    }
}
