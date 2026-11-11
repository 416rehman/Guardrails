//! Check S7, hard-coded values (owner instruction 26), in non-test code: endpoint literals,
//! brand and vendor names read from the data that names them, numeric bounds, colour and spacing
//! literals, and text a person reads written into markup. On the interface paths the interface
//! checks report the colours, spacing, readable text and the product name instead (UX1, UX3),
//! so each literal is reported once.

mod bounds;
mod endpoints;
mod names;
pub(crate) mod visible;
pub(crate) mod visual;

pub(crate) use names::NameKind;
pub use names::{BRAND_PATH, Names, VENDORS_PATH};

use super::lexer::TokenKind;
use super::syntax::is_specifier;
use super::{Check, Language, Policy, Raw, Source, excerpt};

pub(super) fn findings(source: &Source, policy: &Policy) -> Vec<Raw> {
    let interface = policy.interface.covers(source.path);
    if source.language == Language::Style {
        if interface || source.in_test(1) {
            return Vec::new();
        }
        return style_findings(&visual::css_declarations(source.text, 1));
    }
    let mut found = literal_findings(source, policy, interface);
    let script = matches!(source.language, Language::Script | Language::Markup);
    let mut declarations = if script {
        visual::script_declarations(source.tokens())
    } else {
        Vec::new()
    };
    declarations.retain(|declaration| !source.in_test(declaration.line));
    let styled: Vec<usize> = declarations
        .iter()
        .map(|declaration| declaration.line)
        .collect();
    found.extend(
        bounds::findings(source)
            .into_iter()
            .filter(|raw| !styled.contains(&raw.line)),
    );
    if script && !interface {
        found.extend(style_findings(&declarations));
        let taken: Vec<usize> = found.iter().map(|raw| raw.line).collect();
        found.extend(markup_findings(source, policy, &taken));
    }
    found
}

/// Endpoints and names in every string and markup text. On the interface paths UX3 reports the
/// product name, so only vendor names are looked for there.
fn literal_findings(source: &Source, policy: &Policy, interface: bool) -> Vec<Raw> {
    let tokens = source.tokens();
    let names: &[NameKind] = if interface {
        &[NameKind::Vendor]
    } else {
        &[NameKind::Brand, NameKind::Vendor]
    };
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let string = matches!(token.kind, TokenKind::Literal | TokenKind::Text);
        if !string || source.in_test(token.line) || is_specifier(tokens, index) {
            continue;
        }
        for (endpoint, value) in endpoints::find(&token.value) {
            let message = format!(
                "{} literal `{value}`; read it from configuration, whose default lives in the brand manifest",
                endpoint.label()
            );
            found.push(Raw::valued(Check::S7, token.line, message, &value));
        }
        if let Some((kind, name)) = policy.names.find(&token.value, names) {
            found.push(name_finding(kind, name, token.line));
        }
    }
    found
}

/// Colour literals in strings, on lines no other S7 finding took, and readable text in markup.
fn markup_findings(source: &Source, policy: &Policy, taken: &[usize]) -> Vec<Raw> {
    let tokens = source.tokens();
    let mut found: Vec<Raw> = visual::loose_colours(tokens)
        .into_iter()
        .filter(|(line, _)| !source.in_test(*line) && !taken.contains(line))
        .map(|(line, colour)| colour_finding(line, &colour))
        .collect();
    if source.language != Language::Markup {
        return found;
    }
    for (line, text) in visible::visible_strings(tokens) {
        if source.in_test(line) {
            continue;
        }
        let quoted = excerpt(&text, policy.limits.excerpt_chars);
        let message = format!(
            "text `{quoted}` is written into markup; make it a language token in interface/strings/ (D-69) and call its generated accessor"
        );
        found.push(Raw::valued(Check::S7, line, message, &text));
    }
    found
}

fn name_finding(kind: NameKind, name: &str, line: usize) -> Raw {
    let (what, fix) = match kind {
        NameKind::Brand => (
            "brand name",
            "take it from the brand manifest through configuration or a language token (D-69)",
        ),
        NameKind::Vendor => (
            "vendor name",
            "express the vendor as an adapter, pack or manifest entry and read its name from there",
        ),
    };
    Raw::valued(
        Check::S7,
        line,
        format!("{what} `{name}` in code; {fix}"),
        name,
    )
}

fn style_findings(declarations: &[visual::Declaration]) -> Vec<Raw> {
    declarations
        .iter()
        .filter_map(|declaration| {
            let (kind, value) = visual::classify(declaration)
                .into_iter()
                .find(|(kind, _)| {
                    matches!(kind, visual::Visual::Colour | visual::Visual::Spacing)
                })?;
            let message = format!(
                "{} literal `{value}` in `{}`; use the design token by name",
                kind.label(),
                declaration.property
            );
            Some(Raw::valued(Check::S7, declaration.line, message, &value))
        })
        .collect()
}

fn colour_finding(line: usize, colour: &str) -> Raw {
    let message = format!("colour literal `{colour}`; use the design token by name");
    Raw::valued(Check::S7, line, message, colour)
}

#[cfg(test)]
mod tests {
    use super::super::analyse;
    use super::*;
    use crate::git::AddedLines;
    use crate::paths::RepoPath;

    fn s7(path: &str, source: &str, policy: &Policy) -> Vec<(usize, String)> {
        analyse(
            &RepoPath::new(path).unwrap(),
            source,
            &AddedLines::All,
            policy,
        )
        .into_iter()
        .filter(|finding| finding.check == Check::S7)
        .map(|finding| (finding.line, finding.message))
        .collect()
    }

    fn named_policy() -> Policy {
        let mut policy = Policy::for_tests();
        policy.names = Names {
            brand: vec!["Acme Shield".into()],
            vendors: vec!["Northwind".into()],
        };
        policy
    }

    #[test]
    fn rust_endpoints_names_and_specifiers() {
        let source = "const DOCS: &str = include_str!(\"docs.example/x.md\");\nfn f() {\n    let a = \"https://api.vendor.io/v1\";\n    let b = format!(\"https://{host}/v1\");\n    let c = \"Welcome to Acme Shield\";\n    let d = \"works like Northwind\";\n    let e = \"see Cargo.toml\";\n}\n#[cfg(test)]\nmod tests {\n    const URL: &str = \"https://api.vendor.io\";\n}\n";
        let found = s7("crates/a/src/lib.rs", source, &named_policy());
        let lines: Vec<usize> = found.iter().map(|(line, _)| *line).collect();
        assert_eq!(lines, vec![3, 5, 6]);
        assert!(found[0].1.contains("URL literal"));
        assert!(found[1].1.contains("brand name"));
        assert!(found[2].1.contains("vendor name"));
    }

    #[test]
    fn script_colours_spacing_and_markup_text_outside_the_interface() {
        let source = "import x from 'socket.io';\nconst tone = '#ff8800';\nconst box = { style: { margin: 12, color: 'var(--c)' } };\nexport const A = () => <p title=\"Close\">Saved</p>;\n";
        let found = s7("tools/report/a.tsx", source, &Policy::for_tests());
        let lines: Vec<usize> = found.iter().map(|(line, _)| *line).collect();
        assert_eq!(lines, vec![2, 3, 4, 4]);
    }

    #[test]
    fn stylesheets_outside_the_interface() {
        let found = s7(
            "docs/theme/a.css",
            "a { color: #333; padding: var(--s); }\n",
            &Policy::for_tests(),
        );
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("colour literal `#333`"));
    }
}
