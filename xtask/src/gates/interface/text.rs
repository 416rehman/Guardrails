//! UX3, hand-written text: a literal a person reads in markup, and the product name anywhere on
//! the interface paths. UX4, assembled or hand-formatted text: a message accessor's result joined
//! with other text, and `Intl` or `toLocale*` outside `@grdr/i18n`.

use crate::gates::structure::lexer::{Token, TokenKind, text, text_before};
use crate::gates::structure::visible::visible_strings;
use crate::gates::structure::{Check, Language, NameKind, Policy, Raw, Source, excerpt};

use super::config::Config;

const INTL: &str = "Intl";
const LOCALE_METHOD_PREFIX: &str = "toLocale";
const JOINERS: &[&str] = &["+", "+="];
const TEMPLATE: &str = "`";

pub(super) fn findings(source: &Source, config: &Config, policy: &Policy) -> Vec<Raw> {
    let tokens = source.tokens();
    let mut found = Vec::new();
    if source.language == Language::Markup {
        for (line, text) in visible_strings(tokens) {
            let quoted = excerpt(&text, policy.limits.excerpt_chars);
            found.push(Raw::new(
                Check::UX3,
                line,
                format!("hand-written text `{quoted}`; scaffold a language token (`cargo xtask scaffold token <id>`) and call its accessor"),
            ));
        }
    }
    for token in tokens
        .iter()
        .filter(|token| matches!(token.kind, TokenKind::Literal | TokenKind::Text))
    {
        if let Some((_, name)) = policy.names.find(&token.value, &[NameKind::Brand]) {
            found.push(Raw::new(
                Check::UX3,
                token.line,
                format!("the product name `{name}` is written in code; put `:grdr:brand` in the message, which reads the brand manifest"),
            ));
        }
    }
    if !config.i18n.is_match(source.path.as_str()) {
        found.extend(formatting(tokens));
    }
    found.extend(assembled(tokens, &config.accessor));
    found
}

fn formatting(tokens: &[Token]) -> Vec<Raw> {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| {
            let intl = token.text == INTL && text(tokens, index + 1) == ".";
            let locale = token.text.starts_with(LOCALE_METHOD_PREFIX)
                && text_before(tokens, *index, 1) == "."
                && text(tokens, index + 1) == "(";
            token.kind == TokenKind::Ident && (intl || locale)
        })
        .map(|(_, token)| {
            Raw::new(
                Check::UX4,
                token.line,
                format!("`{}` formats text outside @grdr/i18n; format through the message's typed arguments and its functions", token.text),
            )
        })
        .collect()
}

/// An accessor call (`t.console.tile.newAgents(...)`) joined with `+`, or interpolated into a
/// template literal beside other text.
fn assembled(tokens: &[Token], accessor: &str) -> Vec<Raw> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let call = token.kind == TokenKind::Ident
            && token.text == accessor
            && text(tokens, index + 1) == "."
            && text_before(tokens, index, 1) != ".";
        if call {
            let end = call_end(tokens, index);
            let joined = JOINERS.contains(&text_before(tokens, index, 1))
                || JOINERS.contains(&text(tokens, end + 1));
            if joined {
                found.push(assembled_finding(token.line));
            }
        }
        if token.kind == TokenKind::Literal
            && token.text == TEMPLATE
            && interpolates_beside_text(&token.value, accessor)
        {
            found.push(assembled_finding(token.line));
        }
    }
    found
}

fn assembled_finding(line: usize) -> Raw {
    Raw::new(
        Check::UX4,
        line,
        "a message is joined with other text; make the sentence one token with typed arguments"
            .to_owned(),
    )
}

/// The index of the last token of the member chain and calls starting at `start`.
fn call_end(tokens: &[Token], start: usize) -> usize {
    let mut index = start;
    loop {
        match text(tokens, index + 1) {
            "." if tokens
                .get(index + 2)
                .is_some_and(|next| next.kind == TokenKind::Ident) =>
            {
                index += 2;
            }
            "(" => index = closing_paren(tokens, index + 1),
            _ => return index,
        }
    }
}

fn closing_paren(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

/// Whether a template literal interpolates an accessor and also holds text with a letter.
fn interpolates_beside_text(template: &str, accessor: &str) -> bool {
    let mut outside = String::new();
    let mut interpolations = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match (depth, c) {
            (0, '$') if chars.peek() == Some(&'{') => {
                chars.next();
                depth = 1;
            }
            (0, _) => outside.push(c),
            (_, '{') => {
                depth += 1;
                current.push(c);
            }
            (1, '}') => {
                depth = 0;
                interpolations.push(std::mem::take(&mut current));
            }
            (_, '}') => {
                depth -= 1;
                current.push(c);
            }
            _ => current.push(c),
        }
    }
    let prefix = format!("{accessor}.");
    let uses_accessor = interpolations
        .iter()
        .any(|inner| inner.trim_start().starts_with(&prefix));
    uses_accessor && outside.chars().any(char::is_alphabetic)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, policy, run};
    use crate::gates::structure::{Check, Names, analyse};
    use crate::git::AddedLines;
    use crate::paths::RepoPath;

    #[test]
    fn ux3_hand_written_text_and_the_product_name() {
        let source = "export const A = () => (\n  <Dialog title=\"Delete agent\" aria-label={t.agent.delete()}>\n    Are you sure?\n    {t.agent.confirm()}\n  </Dialog>\n);\n";
        assert_eq!(
            lines(&run(Check::UX3, "web/apps/console/src/A.tsx", source)),
            vec![2, 3]
        );
        let mut named = policy();
        named.names = Names {
            brand: vec!["Acme Shield".into()],
            vendors: Vec::new(),
        };
        let brand = "export const NAME = 'Acme Shield';\n";
        let found = analyse(
            &RepoPath::new("web/apps/console/src/b.ts").unwrap(),
            brand,
            &AddedLines::All,
            &named,
        );
        let checks: Vec<Check> = found.iter().map(|finding| finding.check).collect();
        assert!(
            checks.contains(&Check::UX3) && !checks.contains(&Check::S7),
            "{checks:?}"
        );
    }

    #[test]
    fn ux4_assembled_and_hand_formatted_text() {
        let source = "const a = t.home.count({ n }) + ' devices';\nconst b = `${t.home.title()} today`;\nconst c = new Intl.NumberFormat().format(n);\nconst d = when.toLocaleDateString();\nconst e = t.home.summary({ n, when });\nconst f = `${id}-${slot}`;\n";
        assert_eq!(
            lines(&run(Check::UX4, "web/apps/console/src/a.ts", source)),
            vec![1, 2, 3, 4]
        );
        assert!(
            run(
                Check::UX4,
                "web/packages/i18n/src/format.ts",
                "const c = new Intl.NumberFormat();\n"
            )
            .is_empty()
        );
    }
}
