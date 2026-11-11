//! UX8, hand-rolled navigation or confirmation in application code: a browser dialog or a
//! confirmation element instead of `useAction`'s confirmation class, a mutation hook instead of
//! `useAction(Service.Method)`, a route written as a path instead of a route id, and a keyboard
//! shortcut bound by hand instead of through the shortcut registry.

use crate::gates::structure::lexer::{Token, TokenKind, text, text_before};
use crate::gates::structure::syntax::{Value, elements};
use crate::gates::structure::{Check, Raw, Source};

use super::config::Config;

const BROWSER_DIALOGS: &[&str] = &["confirm", "alert", "prompt"];
const GLOBAL_OBJECT: &str = "window";
const ROLE: &str = "role";
const CONFIRMATION_ROLE: &str = "alertdialog";
const ROUTE_ATTRIBUTES: &[&str] = &["href", "to"];
const NAVIGATION_CALLS: &[&str] = &["navigate", "redirect"];
const KEY_EVENTS: &[&str] = &["keydown", "keyup", "keypress"];
const LISTENER: &str = "addEventListener";
const KEY_FIELDS: &[&str] = &["key", "code"];
const ROUTE_STARTS: &[&str] = &["/", "#/", "./", "../"];

pub(super) fn findings(source: &Source, config: &Config) -> Vec<Raw> {
    if !config.apps.is_match(source.path.as_str()) {
        return Vec::new();
    }
    let tokens = source.tokens();
    let mut found: Vec<Raw> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| call_finding(tokens, index, token, config))
        .collect();
    for element in elements(tokens) {
        let confirmation_role = element.attributes.iter().any(|attribute| {
            attribute.name == ROLE
                && attribute.value == Value::Literal(CONFIRMATION_ROLE.to_owned())
        });
        if config.confirmation_elements.contains(&element.name) || confirmation_role {
            found.push(ux8(element.line, format!("`<{}>` builds a confirmation by hand; call `useAction(Service.Method)`, which renders the method's confirmation class", element.name)));
        }
        for attribute in &element.attributes {
            if let Value::Literal(target) = &attribute.value
                && ROUTE_ATTRIBUTES.contains(&attribute.name.as_str())
                && route(target)
            {
                found.push(route_finding(attribute.line, target));
            }
        }
    }
    found
}

fn call_finding(tokens: &[Token], index: usize, token: &Token, config: &Config) -> Option<Raw> {
    if token.kind != TokenKind::Ident || text(tokens, index + 1) != "(" {
        return route_property(tokens, index, token);
    }
    let name = token.text.as_str();
    let owner = text_before(tokens, index, 1);
    let global = owner != "." || text_before(tokens, index, 2) == GLOBAL_OBJECT;
    if BROWSER_DIALOGS.contains(&name) && global {
        return Some(ux8(
            token.line,
            format!(
                "`{name}()` is a browser dialog; call `useAction(Service.Method)`, which renders the method's confirmation class"
            ),
        ));
    }
    if config.mutation_hooks.iter().any(|hook| hook == name) {
        return Some(ux8(
            token.line,
            format!("`{name}` mutates outside `useAction`; call `useAction(Service.Method)`"),
        ));
    }
    if config.shortcut_hooks.iter().any(|hook| hook == name) {
        return Some(shortcut_finding(token.line, name));
    }
    let first = tokens.get(index + 2);
    if name == LISTENER
        && first.is_some_and(|event| {
            event.kind == TokenKind::Literal && KEY_EVENTS.contains(&event.value.as_str())
        })
    {
        return Some(shortcut_finding(token.line, name));
    }
    if NAVIGATION_CALLS.contains(&name)
        && let Some(target) =
            first.filter(|target| target.kind == TokenKind::Literal && route(&target.value))
    {
        return Some(route_finding(token.line, &target.value));
    }
    None
}

/// `to: '/agents'` in an object, and `event.key === 'k'`.
fn route_property(tokens: &[Token], index: usize, token: &Token) -> Option<Raw> {
    if token.kind != TokenKind::Ident {
        return None;
    }
    let value = tokens
        .get(index + 2)
        .filter(|value| value.kind == TokenKind::Literal);
    if ROUTE_ATTRIBUTES.contains(&token.text.as_str())
        && text(tokens, index + 1) == ":"
        && let Some(target) = value.filter(|target| route(&target.value))
    {
        return Some(route_finding(token.line, &target.value));
    }
    let compared = matches!(text(tokens, index + 1), "==" | "!=")
        && text_before(tokens, index, 1) == "."
        && KEY_FIELDS.contains(&token.text.as_str());
    compared.then(|| shortcut_finding(token.line, &token.text))
}

fn route(target: &str) -> bool {
    ROUTE_STARTS.iter().any(|start| target.starts_with(start))
}

fn route_finding(line: usize, target: &str) -> Raw {
    ux8(
        line,
        format!(
            "the route `{target}` is written as a path; link by route id from interface/routes.toml"
        ),
    )
}

fn shortcut_finding(line: usize, what: &str) -> Raw {
    ux8(
        line,
        format!(
            "`{what}` binds a keyboard shortcut by hand; register it in interface/shortcuts.toml and use the kit's shortcut binding"
        ),
    )
}

fn ux8(line: usize, message: String) -> Raw {
    Raw::new(Check::UX8, line, message)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, run};
    use crate::gates::structure::Check;

    #[test]
    fn ux8_confirmations_mutations_routes_and_shortcuts() {
        let source = "export function P() {\n  if (window.confirm(t.x())) {}\n  const m = useMutation(api.revoke);\n  navigate('/agents');\n  const link = { to: '/devices' };\n  useHotkeys('mod+k', open);\n  document.addEventListener('keydown', onKey);\n  if (event.key === 'k') {}\n  return <><Link to=\"/home\">{t.nav.home()}</Link><AlertDialog /><div role=\"alertdialog\" /></>;\n}\n";
        let found = run(Check::UX8, "web/apps/console/src/P.tsx", source);
        assert_eq!(lines(&found), vec![2, 3, 4, 5, 6, 7, 8, 9, 9, 9]);
        let fine = "export function P() {\n  const revoke = useAction(Agents.Revoke);\n  list.confirm();\n  return <Link to={routes.home}>{t.nav.home()}</Link>;\n}\n";
        assert!(run(Check::UX8, "web/apps/console/src/P.tsx", fine).is_empty());
        assert!(run(Check::UX8, "web/packages/kit/src/P.tsx", source).is_empty());
    }
}
