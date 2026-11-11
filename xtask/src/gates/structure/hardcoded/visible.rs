//! Text a person reads that markup holds as a literal: element text, a string child
//! (`{"Save"}`), and a string in an attribute that is shown or announced (`aria-label`, `title`,
//! `alt`, `placeholder`, and the text props of the component library). S7 reports it outside the
//! interface paths; interface check UX3 reports it inside them.

use super::super::lexer::{Token, TokenKind};
use super::super::syntax::{Value, elements};

/// Attributes whose string is shown or announced.
const VISIBLE_ATTRIBUTES: &[&str] = &[
    "aria-label",
    "aria-description",
    "aria-placeholder",
    "aria-roledescription",
    "aria-valuetext",
    "title",
    "alt",
    "placeholder",
    "label",
    "description",
    "errorMessage",
    "helperText",
    "tooltip",
    "caption",
    "heading",
    "summary",
];

/// Each literal a person reads, with its line.
pub(crate) fn visible_strings(tokens: &[Token]) -> Vec<(usize, String)> {
    let mut found: Vec<(usize, String)> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            let text = token.kind == TokenKind::Text;
            let child = token.kind == TokenKind::Literal
                && index
                    .checked_sub(1)
                    .and_then(|previous| tokens.get(previous))
                    .is_some_and(|open| open.kind == TokenKind::ChildOpen)
                && tokens.get(index + 1).is_some_and(|close| close.text == "}");
            ((text || child) && readable(&token.value)).then(|| (token.line, token.value.clone()))
        })
        .collect();
    for element in elements(tokens) {
        for attribute in element.attributes {
            if let Value::Literal(value) = attribute.value
                && VISIBLE_ATTRIBUTES.contains(&attribute.name.as_str())
                && readable(&value)
            {
                found.push((attribute.line, value));
            }
        }
    }
    found.sort();
    found
}

/// Whether the text holds a letter, so punctuation and entities alone pass.
fn readable(text: &str) -> bool {
    let without_entities: String = text
        .split('&')
        .enumerate()
        .map(|(index, piece)| match (index, piece.split_once(';')) {
            (0, _) => piece,
            (_, Some((_, rest))) => rest,
            (_, None) => piece,
        })
        .collect();
    without_entities.chars().any(char::is_alphabetic)
}

#[cfg(test)]
mod tests {
    use super::super::super::lexer::{Language, lex};
    use super::*;

    #[test]
    fn text_children_and_visible_attributes() {
        let source = "const A = () => (\n  <Card title=\"Agents\" size=\"sm\" aria-label={t.card.label()}>\n    Seen this week\n    {'by sponsor'}\n    {count}&nbsp;&middot;\n    <Icon name=\"shield\" alt=\"Shield\" />\n  </Card>\n);\n";
        let found = visible_strings(&lex(source, Language::Markup).tokens);
        assert_eq!(
            found,
            vec![
                (2, "Agents".to_owned()),
                (3, "Seen this week".to_owned()),
                (4, "by sponsor".to_owned()),
                (6, "Shield".to_owned()),
            ]
        );
    }
}
