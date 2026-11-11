//! TSX and JSX markup: tags, attributes, text and the `{ }` expressions inside them, lexed through
//! the explicit mode stack of [`Lexer`], so nesting depth costs no recursion.

use super::{Lexer, Mode, TokenKind};

/// Tokens after which `<` begins an element rather than a comparison or a type argument.
const MARKUP_AFTER: &[&str] = &[
    "(", ",", "=", "return", "=>", "?", ":", "&&", "||", "[", "{",
];

impl Lexer {
    pub(super) fn starts_markup(&self) -> bool {
        let opens = self
            .peek(1)
            .is_some_and(|next| next == '>' || next.is_alphabetic());
        let after = self
            .tokens
            .last()
            .is_none_or(|token| MARKUP_AFTER.contains(&token.text.as_str()));
        opens && after
    }

    pub(super) fn open_tag(&mut self) {
        let line = self.line;
        self.bump();
        let closing = self.peek(0) == Some('/');
        let text = if closing {
            self.bump();
            "</"
        } else {
            "<"
        };
        self.token(text.to_owned(), TokenKind::TagOpen, line);
        self.modes.push(Mode::Tag { closing });
    }

    pub(super) fn tag(&mut self, closing: bool) {
        let line = self.line;
        let Some(c) = self.peek(0) else {
            return;
        };
        match c {
            c if c.is_whitespace() => {
                self.bump();
            }
            '/' if self.peek(1) == Some('>') => {
                self.bump();
                self.bump();
                self.token("/>".to_owned(), TokenKind::TagEnd, line);
                self.modes.pop();
            }
            '>' => {
                self.bump();
                self.token(">".to_owned(), TokenKind::TagEnd, line);
                self.modes.pop();
                if !closing {
                    self.modes.push(Mode::Children);
                } else if self.modes.last() == Some(&Mode::Children) {
                    self.modes.pop();
                }
            }
            '{' => {
                self.bump();
                self.token("{".to_owned(), TokenKind::Punct, line);
                self.modes.push(Mode::Expression { braces: 0 });
            }
            '"' | '\'' => self.quoted(c),
            '=' => self.punct(),
            c if is_name_char(c) => self.name(),
            _ => {
                self.modes.pop();
            }
        }
    }

    pub(super) fn children(&mut self) {
        let mut text = String::new();
        let mut first_line = None;
        while let Some(c) = self.peek(0) {
            if c == '<' || c == '{' {
                break;
            }
            if !c.is_whitespace() && first_line.is_none() {
                first_line = Some(self.line);
            }
            text.push(c);
            self.bump();
        }
        if let Some(line) = first_line {
            self.token_with(String::new(), TokenKind::Text, line, text.trim().to_owned());
        }
        let line = self.line;
        match self.peek(0) {
            Some('<') => self.open_tag(),
            Some('{') => {
                self.bump();
                self.token("{".to_owned(), TokenKind::ChildOpen, line);
                self.modes.push(Mode::Expression { braces: 0 });
            }
            _ => {}
        }
    }

    pub(super) fn expression(&mut self, braces: usize) {
        let next = match self.peek(0) {
            Some('{') => Some(braces + 1),
            Some('}') => braces.checked_sub(1),
            _ => {
                self.code();
                return;
            }
        };
        self.punct();
        self.modes.pop();
        if let Some(braces) = next {
            self.modes.push(Mode::Expression { braces });
        }
    }

    fn name(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if !is_name_char(c) {
                break;
            }
            text.push(c);
            self.bump();
        }
        self.token(text, TokenKind::Ident, line);
    }
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '$' | '-' | ':' | '.')
}
