//! UX2, a one-off building block. In application code and in `kit`, whose parts are compositions
//! of `ui` and nothing else: a stylesheet, a `style` prop, a `className` string, or a raw
//! interactive or layout element. Everywhere on the interface paths the building blocks come from
//! one source (owner instruction 21): the component library only inside `ui` (ARCH-101), a
//! registered exception's packages only in the files its entry lists, and `kit` composed only of
//! `ui`, `tokens` and `i18n` (ARCH-102).

use crate::gates::structure::syntax::{Value, elements, imports};
use crate::gates::structure::{Check, Language, Raw, Source};

use super::config::{Config, imports_package};

const STYLESHEET_EXTENSIONS: &[&str] = &[".css", ".scss", ".sass", ".less"];
const RAW_ELEMENTS: &[&str] = &[
    "button", "input", "select", "textarea", "a", "table", "dialog", "div", "span",
];
const STYLE_PROP: &str = "style";
const CLASS_PROP: &str = "className";
const RELATIVE: &[&str] = &["./", "../"];

pub(super) fn findings(source: &Source, config: &Config) -> Vec<Raw> {
    let path = source.path.as_str();
    let composed = config.apps.is_match(path) || config.kit.is_match(path);
    let mut found = Vec::new();
    if source.language == Language::Style {
        if composed {
            found.push(ux2(1, "a stylesheet outside `ui`; compose the kit's layout primitives and patterns, which carry their styles".to_owned()));
        }
        return found;
    }
    let tokens = source.tokens();
    for import in imports(tokens) {
        let specifier = import.specifier.as_str();
        if composed
            && STYLESHEET_EXTENSIONS
                .iter()
                .any(|extension| specifier.ends_with(extension))
        {
            found.push(ux2(import.line, format!("imports the stylesheet `{specifier}` outside `ui`; compose the kit's patterns instead")));
        }
        if let Some(problem) = import_problem(source, config, specifier) {
            found.push(ux2(import.line, problem));
        }
    }
    if composed {
        found.extend(element_findings(source));
    }
    found
}

fn import_problem(source: &Source, config: &Config, specifier: &str) -> Option<String> {
    let path = source.path;
    let in_ui = config.ui.is_match(path.as_str());
    if !in_ui
        && config
            .ui_only_imports
            .iter()
            .any(|package| imports_package(specifier, package))
    {
        return Some(format!(
            "imports `{specifier}` outside `ui` (ARCH-101); import the component from @grdr/ui"
        ));
    }
    if let Some(package) = config
        .governed_imports
        .iter()
        .find(|package| imports_package(specifier, package))
        && !config.excepted(path, package)
    {
        return Some(format!(
            "imports `{specifier}`, which only the files of a registered exception may use; use the @grdr/ui component, or register the gap in {} through its protected change",
            config.exceptions_path
        ));
    }
    let relative = RELATIVE.iter().any(|prefix| specifier.starts_with(prefix));
    let allowed = config
        .kit_imports
        .iter()
        .any(|package| imports_package(specifier, package));
    if config.kit.is_match(path.as_str()) && !relative && !allowed {
        return Some(format!(
            "`kit` imports `{specifier}` (ARCH-102); a kit part composes only {}",
            config.kit_imports.join(", ")
        ));
    }
    None
}

fn element_findings(source: &Source) -> Vec<Raw> {
    let mut found = Vec::new();
    for element in elements(source.tokens()) {
        if RAW_ELEMENTS.contains(&element.name.as_str()) {
            found.push(ux2(element.line, format!("raw `<{}>` outside `ui`; compose the kit's layout primitive or pattern, or scaffold a pattern (`cargo xtask scaffold pattern <id>`)", element.name)));
        }
        for attribute in &element.attributes {
            let literal_class = attribute.name == CLASS_PROP
                && match &attribute.value {
                    Value::Literal(_) => true,
                    Value::Expression(open) => source.tokens().get(open + 1).is_some_and(|first| {
                        first.text == "`" || first.text == "'" || first.text == "\""
                    }),
                    Value::Flag => false,
                };
            if attribute.name == STYLE_PROP || literal_class {
                found.push(ux2(attribute.line, format!("`{}` on `<{}>` styles one element by hand; pass the kit part's variant or layout props", attribute.name, element.name)));
            }
        }
    }
    found
}

fn ux2(line: usize, message: String) -> Raw {
    Raw::new(Check::UX2, line, message)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, run};
    use crate::gates::structure::Check;

    #[test]
    fn ux2_one_off_blocks_in_application_code() {
        let source = "import './page.css';\nimport { Stack } from '@grdr/kit';\nexport const P = () => (\n  <Stack gap=\"space-3\">\n    <div className=\"row\">\n      <button style={{ gap: 'var(--s)' }} onClick={go}>x</button>\n    </div>\n  </Stack>\n);\n";
        let found = run(Check::UX2, "web/apps/console/src/Page.tsx", source);
        assert_eq!(lines(&found), vec![1, 5, 5, 6, 6]);
        assert!(run(Check::UX2, "web/apps/console/src/page.css", ".a {}\n").len() == 1);
        assert!(
            run(
                Check::UX2,
                "web/packages/ui/src/Box.tsx",
                source.replace("import './page.css';\n", "").as_str()
            )
            .is_empty()
        );
    }

    #[test]
    fn ux2_imports_follow_instruction_21() {
        let library = "import { Button } from '@astryxdesign/react';\n";
        assert_eq!(
            run(Check::UX2, "web/apps/console/src/A.tsx", library).len(),
            1
        );
        assert!(run(Check::UX2, "web/packages/ui/src/Button.tsx", library).is_empty());
        let aria = "import { ComboBox } from 'react-aria-components';\n";
        assert!(run(Check::UX2, "web/packages/ui/src/combo/Combo.tsx", aria).is_empty());
        assert_eq!(
            run(Check::UX2, "web/packages/ui/src/Other.tsx", aria).len(),
            1
        );
        let kit = "import { useState } from 'react';\nimport { Card } from '@grdr/ui';\nimport { t } from '@grdr/i18n';\nimport { part } from './part';\nimport { Chart } from 'echarts';\n";
        let found = run(Check::UX2, "web/packages/kit/src/Approval.tsx", kit);
        assert_eq!(lines(&found), vec![5]);
        assert!(found[0].1.contains("ARCH-102"));
        let raw = "export const Card = () => <div className=\"card\" />;\n";
        assert_eq!(
            run(Check::UX2, "web/packages/kit/src/Card.tsx", raw).len(),
            2
        );
    }
}
