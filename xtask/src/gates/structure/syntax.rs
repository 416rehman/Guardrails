//! What a script declares, read from its tokens: the modules it imports and the markup elements
//! it renders with their attributes. S7 and the interface checks judge these.

use super::lexer::{Token, TokenKind, text_before};

/// Rust macros whose string argument is a file path, not a value.
const PATH_MACROS: &[&str] = &["include_str", "include_bytes", "include"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Import {
    pub(crate) specifier: String,
    pub(crate) line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// `name="text"`.
    Literal(String),
    /// `name={...}`: the token index of the `{`.
    Expression(usize),
    /// `name` alone.
    Flag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub(crate) name: String,
    pub(crate) line: usize,
    pub(crate) value: Value,
}

/// An opening or self-closing tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    pub(crate) name: String,
    pub(crate) line: usize,
    pub(crate) attributes: Vec<Attribute>,
}

/// `import ... from 'x'`, `import 'x'`, `export ... from 'x'`, `import('x')` and `require('x')`.
pub(crate) fn imports(tokens: &[Token]) -> Vec<Import> {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| token.kind == TokenKind::Literal && is_specifier(tokens, *index))
        .map(|(_, token)| Import {
            specifier: token.value.clone(),
            line: token.line,
        })
        .collect()
}

/// Whether the literal at `index` names a module or a file rather than holding a value.
pub(crate) fn is_specifier(tokens: &[Token], index: usize) -> bool {
    let before = |back: usize| text_before(tokens, index, back);
    match before(1) {
        "from" | "import" => true,
        "(" => matches!(before(2), "require" | "import") || PATH_MACROS.contains(&before(3)),
        _ => false,
    }
}

/// Every opening and self-closing tag, with its attributes in order.
pub(crate) fn elements(tokens: &[Token]) -> Vec<Element> {
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != TokenKind::TagOpen || token.text != "<" {
            continue;
        }
        let name = tokens
            .get(index + 1)
            .filter(|next| next.kind == TokenKind::Ident)
            .map_or(String::new(), |next| next.text.clone());
        let start = if name.is_empty() {
            index + 1
        } else {
            index + 2
        };
        found.push(Element {
            name,
            line: token.line,
            attributes: attributes(tokens, start),
        });
    }
    found
}

/// The attributes from `start` to the tag's end, skipping the expressions inside them.
fn attributes(tokens: &[Token], start: usize) -> Vec<Attribute> {
    let mut found = Vec::new();
    let mut index = start;
    while let Some(token) = tokens.get(index) {
        match token.kind {
            TokenKind::TagEnd => break,
            TokenKind::Ident => {
                let (value, next) = attribute_value(tokens, index);
                found.push(Attribute {
                    name: token.text.clone(),
                    line: token.line,
                    value,
                });
                index = next;
            }
            _ if token.text == "{" => index = closing_brace(tokens, index) + 1,
            _ => index += 1,
        }
    }
    found
}

/// The value of the attribute named at `index` and the index after it.
fn attribute_value(tokens: &[Token], index: usize) -> (Value, usize) {
    let equals = tokens.get(index + 1).is_some_and(|token| token.text == "=");
    if !equals {
        return (Value::Flag, index + 1);
    }
    match tokens.get(index + 2) {
        Some(token) if token.kind == TokenKind::Literal => {
            (Value::Literal(token.value.clone()), index + 3)
        }
        Some(token) if token.text == "{" => (
            Value::Expression(index + 2),
            closing_brace(tokens, index + 2) + 1,
        ),
        _ => (Value::Flag, index + 2),
    }
}

/// The index of the `}` that closes the `{` at `open`, or the last token.
pub(crate) fn closing_brace(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    tokens.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::super::lexer::{Language, lex};
    use super::*;

    #[test]
    fn imports_of_every_form() {
        let source = "import a from 'a';\nimport 'b.css';\nexport { c } from \"c\";\nconst d = await import('d');\nconst e = require('e');\nconst f = 'not-an-import';\n";
        let found: Vec<String> = imports(&lex(source, Language::Script).tokens)
            .into_iter()
            .map(|import| import.specifier)
            .collect();
        assert_eq!(found, vec!["a", "b.css", "c", "d", "e"]);
        let rust = lex(
            "const S: &str = include_str!(\"x.toml\");\n",
            Language::Rust,
        );
        assert!(is_specifier(&rust.tokens, 9));
    }

    #[test]
    fn elements_with_literal_expression_and_flag_attributes() {
        let source = "const x = <Button size=\"sm\" onPress={() => go({ a: 1 })} disabled aria-label='Close'>Go</Button>;\n";
        let found = elements(&lex(source, Language::Markup).tokens);
        assert_eq!(found.len(), 1);
        let button = &found[0];
        assert_eq!(button.name, "Button");
        let names: Vec<&str> = button.attributes.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["size", "onPress", "disabled", "aria-label"]);
        assert_eq!(button.attributes[0].value, Value::Literal("sm".into()));
        assert!(matches!(button.attributes[1].value, Value::Expression(_)));
        assert_eq!(button.attributes[2].value, Value::Flag);
        assert_eq!(button.attributes[3].value, Value::Literal("Close".into()));
    }
}
