//! UX1, a raw visual value, and UX6, a physical direction or a casing, in stylesheets, style
//! objects and CSS-in-JS templates; UX1 also takes a colour literal in any string.

use std::collections::BTreeSet;

use crate::gates::structure::visual::{
    Declaration, classify, css_declarations, loose_colours, physical, script_declarations,
};
use crate::gates::structure::{Check, Language, Raw, Source};

pub(super) fn findings(source: &Source) -> Vec<Raw> {
    let declarations: Vec<Declaration> = match source.language {
        Language::Style => css_declarations(source.text, 1),
        _ => script_declarations(source.tokens()),
    };
    let mut found = Vec::new();
    let mut ux1_lines = BTreeSet::new();
    for declaration in &declarations {
        if let Some((kind, value)) = classify(declaration).into_iter().next() {
            ux1_lines.insert(declaration.line);
            found.push(Raw::new(
                Check::UX1,
                declaration.line,
                format!(
                    "raw {} value `{value}` in `{}`; use the token by name (`space-3`, `color-text-danger`, `motion-quick`), or add a semantic token in interface/tokens/ when none fits",
                    kind.label(),
                    declaration.property
                ),
            ));
        }
        if let Some(side) = physical(declaration) {
            found.push(Raw::new(
                Check::UX6,
                declaration.line,
                format!(
                    "`{side}` fixes a physical side or the casing; use the logical property (`margin-inline-start`, `text-align: start`) and write casing in the message"
                ),
            ));
        }
    }
    if source.language != Language::Style {
        for (line, colour) in loose_colours(source.tokens()) {
            if ux1_lines.insert(line) {
                found.push(Raw::new(
                    Check::UX1,
                    line,
                    format!("raw colour value `{colour}`; use the colour token by name"),
                ));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, run};
    use crate::gates::structure::Check;

    #[test]
    fn ux1_raw_values_in_css_and_style_objects() {
        let css = ".a {\n  color: var(--color-text);\n  padding: 12px;\n  z-index: 3;\n  transition: opacity var(--motion-quick);\n}\n";
        assert_eq!(
            lines(&run(Check::UX1, "web/apps/console/src/a.css", css)),
            vec![3, 4]
        );
        let tsx = "export const A = () => <Box style={{ gap: 4, color: '#0af' }} />;\nconst B = 'oklch(60% 0.1 30)';\n";
        let found = run(Check::UX1, "web/packages/ui/src/A.tsx", tsx);
        assert_eq!(lines(&found), vec![1, 1, 2]);
        assert!(found[0].1.contains("`gap`"));
    }

    #[test]
    fn ux6_physical_sides_and_casing() {
        let css = ".a { margin-left: var(--space-2); text-transform: uppercase; inset-inline-start: 0; float: right; }\n";
        assert_eq!(run(Check::UX6, "site/src/css/a.css", css).len(), 3);
        let fine = ".a { margin-inline-start: var(--space-2); text-align: start; }\n";
        assert!(run(Check::UX6, "site/src/css/a.css", fine).is_empty());
        assert!(run(Check::UX6, "docs/a.css", css).is_empty());
    }
}
