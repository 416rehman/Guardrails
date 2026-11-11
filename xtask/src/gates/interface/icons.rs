//! UX5, an icon or an enum rendered by hand: a pictograph (emoji) in a string or in markup text,
//! and an icon package imported outside `ui`, whose `Icon` takes a meaning key. The registry
//! halves of UX5 (an enum matched in renderer code, an icon key without its `interface/icons.toml`
//! entry) belong to `cargo xtask interface check`.

use crate::gates::structure::lexer::TokenKind;
use crate::gates::structure::syntax::imports;
use crate::gates::structure::{Check, Raw, Source};

use super::config::{Config, imports_package};

/// Code point ranges of the pictographs drawn as emoji: the emoji blocks, the miscellaneous
/// symbols and dingbats, the arrows and stars drawn in colour, and the emoji variation selector.
const PICTOGRAPHS: &[(u32, u32)] = &[
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x231A, 0x231B),
    (0x2328, 0x2328),
    (0x23CF, 0x23CF),
    (0x23E9, 0x23F3),
    (0x23F8, 0x23FA),
    (0x2B05, 0x2B07),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
    (0xFE0F, 0xFE0F),
];

pub(super) fn findings(source: &Source, config: &Config) -> Vec<Raw> {
    let tokens = source.tokens();
    let mut found = Vec::new();
    for token in tokens
        .iter()
        .filter(|token| matches!(token.kind, TokenKind::Literal | TokenKind::Text))
    {
        if let Some(glyph) = token.value.chars().find(|c| pictograph(*c)) {
            found.push(Raw::new(
                Check::UX5,
                token.line,
                format!("the pictograph `{glyph}` stands in for an icon; pass the meaning key to `Icon` (one glyph, one meaning)"),
            ));
        }
    }
    if !config.ui.is_match(source.path.as_str()) {
        for import in imports(tokens) {
            if config
                .icon_imports
                .iter()
                .any(|package| imports_package(&import.specifier, package))
            {
                found.push(Raw::new(
                    Check::UX5,
                    import.line,
                    format!(
                        "imports `{}` outside `ui`; render icons through `Icon` with a meaning key",
                        import.specifier
                    ),
                ));
            }
        }
    }
    found
}

fn pictograph(c: char) -> bool {
    let point = u32::from(c);
    PICTOGRAPHS
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&point))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{lines, run};
    use crate::gates::structure::Check;

    #[test]
    fn ux5_pictographs_and_icon_imports() {
        let source = "import { Shield } from 'lucide-react';\nexport const A = () => <p>Done \u{2705}</p>;\nconst B = 'Ready \u{1F680}';\nconst C = 'Ctrl \u{2318} K';\n";
        assert_eq!(
            lines(&run(Check::UX5, "web/apps/console/src/A.tsx", source)),
            vec![1, 2, 3]
        );
        let icon = "import { Shield } from 'lucide-react';\n";
        assert!(run(Check::UX5, "web/packages/ui/src/Icon.tsx", icon).is_empty());
    }
}
