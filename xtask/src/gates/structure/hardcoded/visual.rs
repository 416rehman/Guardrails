//! Raw visual values: the declarations of a stylesheet, a style object or a CSS-in-JS template,
//! and the colour literals of any string. S7 reports the colours and the spacing among them;
//! interface check UX1 reports every kind, and UX6 the physical directions.

use std::sync::LazyLock;

use super::super::lexer::{Token, TokenKind, text, text_before};
use super::super::patterns::{Compiled, compile, find, is_match};
use super::super::syntax::closing_brace;

const CSS_TAGS: &[&str] = &["css", "keyframes", "createGlobalStyle", "injectGlobal"];
const STYLED: &str = "styled";
const STYLE_KEYS: &[&str] = &["style", "sx"];
const SPACING_PROPERTIES: &[&str] = &[
    "margin",
    "padding",
    "gap",
    "row-gap",
    "column-gap",
    "grid-gap",
    "inset",
    "scroll-margin",
    "scroll-padding",
];
const COLOUR_PROPERTIES: &[&str] = &[
    "color",
    "background",
    "border",
    "outline",
    "fill",
    "stroke",
    "box-shadow",
    "text-shadow",
    "caret-color",
    "accent-color",
    "text-decoration",
    "column-rule",
];
const MOTION_PROPERTIES: &[&str] = &["transition", "animation"];
const FONT_PROPERTIES: &[&str] = &["font-family", "font"];
const SHADOW_PROPERTIES: &[&str] = &["box-shadow", "text-shadow"];
/// Properties whose unitless numbers are raw values; zero and the keywords stay allowed.
const NUMBER_PROPERTIES: &[&str] = &["z-index", "font-weight", "line-height", "opacity"];
const NAMED_COLOURS: &[&str] = &[
    "aqua", "black", "blue", "fuchsia", "gray", "grey", "green", "lime", "maroon", "navy", "olive",
    "orange", "purple", "red", "silver", "teal", "white", "yellow",
];
const EASINGS: &[&str] = &[
    "ease",
    "ease-in",
    "ease-out",
    "ease-in-out",
    "step-start",
    "step-end",
];
const PHYSICAL_PROPERTIES: &[&str] = &[
    "margin-left",
    "margin-right",
    "padding-left",
    "padding-right",
    "left",
    "right",
    "border-top-left-radius",
    "border-top-right-radius",
    "border-bottom-left-radius",
    "border-bottom-right-radius",
    "scroll-margin-left",
    "scroll-margin-right",
    "scroll-padding-left",
    "scroll-padding-right",
];
const PHYSICAL_PREFIXES: &[&str] = &["border-left", "border-right"];
const SIDED_PROPERTIES: &[&str] = &["text-align", "float", "clear"];
const SIDES: &[&str] = &["left", "right"];
const CASING_PROPERTY: &str = "text-transform";

static HEX: Compiled = LazyLock::new(|| {
    compile(r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b")
});
static HEX_WITH_LETTER: Compiled = LazyLock::new(|| compile(r"[a-fA-F]"));
static COLOUR_FUNCTION: Compiled =
    LazyLock::new(|| compile(r"(?i)\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\("));
static LENGTH: Compiled = LazyLock::new(|| {
    compile(
        r"(?i)(?:^|[^\w.#-])-?(?:\d*\.)?\d+(?:px|rem|em|pt|pc|ch|ex|cm|mm|in|q|lh|rlh|cqw|cqh|cqi|cqb|cqmin|cqmax)\b",
    )
});
static DURATION: Compiled = LazyLock::new(|| compile(r"(?i)(?:^|[^\w.])(?:\d*\.)?\d+m?s\b"));
static EASING_FUNCTION: Compiled =
    LazyLock::new(|| compile(r"(?i)\b(?:cubic-bezier|steps|linear)\("));
static VAR: Compiled = LazyLock::new(|| compile(r"var\([^()]*(?:\([^()]*\)[^()]*)*\)"));
static NUMBER: Compiled = LazyLock::new(|| compile(r"^-?(?:\d*\.)?\d+$"));
static ZERO: Compiled = LazyLock::new(|| compile(r"^-?0*\.?0+(?:[a-z%]+)?$"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visual {
    Colour,
    Spacing,
    Length,
    Duration,
    Easing,
    Font,
    Shadow,
    Number,
}

/// One `property: value` pair, the property in kebab case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) property: String,
    pub(crate) value: String,
    pub(crate) line: usize,
    /// A bare number in a style object, which the browser reads as pixels for lengths.
    pub(crate) bare_number: bool,
}

impl Visual {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Visual::Colour => "colour",
            Visual::Spacing => "spacing",
            Visual::Length => "length",
            Visual::Duration => "duration",
            Visual::Easing => "easing",
            Visual::Font => "font",
            Visual::Shadow => "shadow",
            Visual::Number => "visual number",
        }
    }
}

/// The declarations of stylesheet text that starts on `first_line`; selectors and at-rules are
/// skipped.
pub(crate) fn css_declarations(text: &str, first_line: usize) -> Vec<Declaration> {
    let mut found = Vec::new();
    let mut segment = String::new();
    let mut segment_line = first_line;
    let mut line = first_line;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            let mut previous = ' ';
            for inner in chars.by_ref() {
                if inner == '\n' {
                    line += 1;
                }
                if previous == '*' && inner == '/' {
                    break;
                }
                previous = inner;
            }
            continue;
        }
        match c {
            '{' => segment.clear(),
            ';' | '}' => {
                found.extend(declaration(&segment, segment_line));
                segment.clear();
            }
            _ => {
                if segment.trim().is_empty() && !c.is_whitespace() {
                    segment_line = line;
                }
                segment.push(c);
            }
        }
        if c == '\n' {
            line += 1;
        }
    }
    found.extend(declaration(&segment, segment_line));
    found
}

fn declaration(segment: &str, line: usize) -> Option<Declaration> {
    let (property, value) = segment.split_once(':')?;
    let property = property.trim().to_ascii_lowercase();
    let named = property.starts_with(|c: char| c.is_ascii_lowercase() || c == '-')
        && property
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    named.then(|| Declaration {
        property,
        value: value.trim().to_owned(),
        line,
        bare_number: false,
    })
}

/// The declarations of style objects (`style={{ ... }}`, `style: { ... }`) and CSS-in-JS
/// templates (`css\`...\``, `styled.div\`...\``) in a script.
pub(crate) fn script_declarations(tokens: &[Token]) -> Vec<Declaration> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Literal && token.text == "`" && css_template(tokens, index) {
            found.extend(css_declarations(&token.value, token.line));
        }
        let style_key = token.kind == TokenKind::Ident && STYLE_KEYS.contains(&token.text.as_str());
        if !style_key {
            continue;
        }
        let object = match (
            text(tokens, index + 1),
            text(tokens, index + 2),
            text(tokens, index + 3),
        ) {
            ("=", "{", "{") => Some(index + 3),
            (":", "{", _) => Some(index + 2),
            _ => None,
        };
        if let Some(open) = object {
            found.extend(object_declarations(tokens, open));
        }
    }
    found
}

/// Colour literals in any string of a script, with their lines.
pub(crate) fn loose_colours(tokens: &[Token]) -> Vec<(usize, String)> {
    tokens
        .iter()
        .filter(|token| token.kind == TokenKind::Literal)
        .filter_map(|token| {
            let hex = find(&HEX, &token.value)
                .filter(|found| is_match(&HEX_WITH_LETTER, found.as_str()))
                .map(|found| found.as_str().to_owned());
            hex.or_else(|| function_colour(&token.value))
                .map(|colour| (token.line, colour))
        })
        .collect()
}

/// Every raw visual value in `declaration`, with the text that shows it; `var()` references,
/// zero and keywords are not raw.
pub(crate) fn classify(declaration: &Declaration) -> Vec<(Visual, String)> {
    let property = declaration.property.as_str();
    let value = strip_vars(&declaration.value);
    let mut found = Vec::new();
    if let Some(hex) = find(&HEX, &value) {
        found.push((Visual::Colour, hex.as_str().to_owned()));
    } else if let Some(colour) = function_colour(&value) {
        found.push((Visual::Colour, colour));
    } else if family(property, COLOUR_PROPERTIES) {
        let named = value
            .split(|c: char| c.is_whitespace() || c == ',')
            .find(|word| NAMED_COLOURS.contains(&word.to_ascii_lowercase().as_str()));
        found.extend(named.map(|word| (Visual::Colour, word.to_owned())));
    }
    let length = find(&LENGTH, &value).map(|found| {
        found
            .as_str()
            .trim_start_matches(|c: char| !c.is_ascii_digit() && c != '-' && c != '.')
            .to_owned()
    });
    let bare = declaration.bare_number
        && is_match(&NUMBER, &value)
        && !is_match(&ZERO, &value)
        && !NUMBER_PROPERTIES.contains(&property);
    let length_kind = if family(property, SPACING_PROPERTIES) {
        Visual::Spacing
    } else {
        Visual::Length
    };
    match (length, bare) {
        (Some(length), _) if !is_match(&ZERO, &length) => found.push((length_kind, length)),
        (None, true) => found.push((length_kind, value.clone())),
        _ => {}
    }
    if family(property, MOTION_PROPERTIES) {
        if let Some(duration) =
            find(&DURATION, &value).filter(|found| !is_match(&ZERO, found.as_str().trim()))
        {
            found.push((Visual::Duration, duration.as_str().trim().to_owned()));
        }
        let easing = find(&EASING_FUNCTION, &value)
            .map(|found| found.as_str().to_owned())
            .or_else(|| {
                value
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .find(|word| EASINGS.contains(word))
                    .map(str::to_owned)
            });
        found.extend(easing.map(|easing| (Visual::Easing, easing)));
    }
    if FONT_PROPERTIES.contains(&property) && !value.trim().is_empty() && !keyword_only(&value) {
        found.push((Visual::Font, value.trim().to_owned()));
    }
    if SHADOW_PROPERTIES.contains(&property)
        && !value.trim().is_empty()
        && !keyword_only(&value)
        && found.is_empty()
    {
        found.push((Visual::Shadow, value.trim().to_owned()));
    }
    if NUMBER_PROPERTIES.contains(&property)
        && is_match(&NUMBER, value.trim())
        && !is_match(&ZERO, value.trim())
    {
        found.push((Visual::Number, value.trim().to_owned()));
    }
    found
}

/// The physical side or the casing a declaration fixes, which a logical property or the message
/// itself should carry instead.
pub(crate) fn physical(declaration: &Declaration) -> Option<String> {
    let property = declaration.property.as_str();
    let value = declaration.value.trim().to_ascii_lowercase();
    if PHYSICAL_PROPERTIES.contains(&property)
        || PHYSICAL_PREFIXES
            .iter()
            .any(|prefix| property.starts_with(prefix))
        || property == CASING_PROPERTY
    {
        return Some(property.to_owned());
    }
    (SIDED_PROPERTIES.contains(&property) && SIDES.contains(&value.as_str()))
        .then(|| format!("{property}: {value}"))
}

fn object_declarations(tokens: &[Token], open: usize) -> Vec<Declaration> {
    let close = closing_brace(tokens, open);
    let mut found = Vec::new();
    let mut index = open + 1;
    while index < close {
        let key = tokens.get(index);
        let colon = text(tokens, index + 1) == ":";
        let value = tokens.get(index + 2);
        let ends = matches!(text(tokens, index + 3), "," | "}");
        if let (Some(key), true, Some(value), true) = (key, colon, value, ends) {
            let name = if key.kind == TokenKind::Literal {
                key.value.clone()
            } else {
                key.text.clone()
            };
            let (written, bare_number) = match value.kind {
                TokenKind::Literal => (value.value.clone(), false),
                TokenKind::Number => (value.text.clone(), true),
                _ => (String::new(), false),
            };
            if !written.is_empty() {
                found.push(Declaration {
                    property: kebab(&name),
                    value: written,
                    line: key.line,
                    bare_number,
                });
            }
        }
        index += 1;
    }
    found
}

fn css_template(tokens: &[Token], index: usize) -> bool {
    let before = |back: usize| text_before(tokens, index, back);
    if CSS_TAGS.contains(&before(1)) {
        return true;
    }
    if before(2) == "." && before(3) == STYLED {
        return true;
    }
    if before(1) != ")" {
        return false;
    }
    let mut depth = 0usize;
    let mut cursor = index.saturating_sub(1);
    while let Some(token) = tokens.get(cursor) {
        match token.text.as_str() {
            ")" => depth += 1,
            "(" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return cursor
                        .checked_sub(1)
                        .is_some_and(|previous| text(tokens, previous) == STYLED);
                }
            }
            _ => {}
        }
        let Some(next) = cursor.checked_sub(1) else {
            break;
        };
        cursor = next;
    }
    false
}

fn function_colour(value: &str) -> Option<String> {
    let start = find(&COLOUR_FUNCTION, value)?.start();
    let rest = value.get(start..)?;
    let end = rest.find(')').map_or(rest.len(), |close| close + 1);
    rest.get(..end).map(str::to_owned)
}

fn strip_vars(value: &str) -> String {
    let mut out = value.to_owned();
    while let Some(found) = find(&VAR, &out) {
        let range = found.range();
        out.replace_range(range, " ");
    }
    out
}

fn keyword_only(value: &str) -> bool {
    value
        .split_whitespace()
        .all(|word| matches!(word, "inherit" | "initial" | "unset" | "revert" | "none"))
}

/// Whether `property` is one of `families` or a longhand of one (`margin-top`, `border-color`).
fn family(property: &str, families: &[&str]) -> bool {
    families.iter().any(|family| {
        property == *family
            || property
                .strip_prefix(family)
                .is_some_and(|rest| rest.starts_with('-'))
    })
}

fn kebab(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('-');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::super::lexer::{Language, lex};
    use super::super::super::patterns::all_compile;
    use super::*;

    fn kinds(declarations: &[Declaration]) -> Vec<(usize, Visual, String)> {
        declarations
            .iter()
            .flat_map(|d| {
                classify(d)
                    .into_iter()
                    .map(|(kind, value)| (d.line, kind, value))
            })
            .collect()
    }

    #[test]
    fn every_pattern_compiles() {
        assert!(all_compile(&[
            &HEX,
            &HEX_WITH_LETTER,
            &COLOUR_FUNCTION,
            &LENGTH,
            &DURATION,
            &EASING_FUNCTION,
            &VAR,
            &NUMBER,
            &ZERO,
        ]));
    }

    #[test]
    fn stylesheet_values_by_kind() {
        let css = ".card:hover {\n  color: #1a2b3c;\n  margin-top: 12px;\n  padding: var(--space-3);\n  width: 100%;\n  transition: opacity 150ms ease-in;\n  z-index: 10;\n  font-family: Inter, sans-serif;\n  border: 0;\n  background: oklch(70% 0.1 200);\n}\n@media (min-width: 768px) { .a { gap: var(--space-2) } }\n/* color: red; */\n";
        let found = kinds(&css_declarations(css, 1));
        let expected = vec![
            (2, Visual::Colour, "#1a2b3c".to_owned()),
            (3, Visual::Spacing, "12px".to_owned()),
            (6, Visual::Duration, "150ms".to_owned()),
            (6, Visual::Easing, "ease-in".to_owned()),
            (7, Visual::Number, "10".to_owned()),
            (8, Visual::Font, "Inter, sans-serif".to_owned()),
            (10, Visual::Colour, "oklch(70% 0.1 200)".to_owned()),
        ];
        assert_eq!(found, expected);
    }

    #[test]
    fn style_objects_templates_and_loose_colours() {
        let source = "const A = () => <div style={{ padding: 8, color: 'var(--c)', marginLeft: 0 }} />;\nconst B = styled.div`\n  gap: 4px;\n`;\nconst C = { tone: '#fff', issue: '#123', label: 'see #12' };\n";
        let tokens = lex(source, Language::Markup).tokens;
        let found = kinds(&script_declarations(&tokens));
        assert_eq!(
            found,
            vec![
                (1, Visual::Spacing, "8".to_owned()),
                (3, Visual::Spacing, "4px".to_owned()),
            ]
        );
        assert_eq!(loose_colours(&tokens), vec![(5, "#fff".to_owned())]);
    }

    #[test]
    fn physical_sides_and_casing() {
        let css = "a { margin-left: 4px; text-align: left; text-transform: uppercase; margin-inline-start: 4px; text-align: start; border-left-width: 1px; }";
        let found: Vec<String> = css_declarations(css, 1)
            .iter()
            .filter_map(physical)
            .collect();
        assert_eq!(
            found,
            vec![
                "margin-left",
                "text-align: left",
                "text-transform",
                "border-left-width"
            ]
        );
    }
}
