//! Splits Rust or TypeScript and JavaScript source into code tokens and comments, with line
//! numbers, so the checks never mistake a brace in a string or a keyword in a comment for code.
//! String literals keep their contents in `value`, and TSX and JSX markup is lexed into tags,
//! attributes and text (`markup.rs`).

mod markup;

const PAIRS: &[&str] = &["::", "->", "=>", "&&", "||", "==", "!=", "<=", "+=", "-="];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Script,
    /// TSX and JSX: script with markup.
    Markup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Ident,
    Punct,
    /// A string, template or character literal; its text is the quote and `value` the contents.
    Literal,
    Number,
    /// Text between markup tags; `value` holds it, trimmed.
    Text,
    /// The `<` or `</` that opens a markup tag.
    TagOpen,
    /// The `>` or `/>` that ends a markup tag.
    TagEnd,
    /// The `{` that opens an expression among an element's children.
    ChildOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub kind: TokenKind,
    pub line: usize,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub text: String,
    /// `///`, `//!`, `/** */` and `/*! */`: documentation, not commentary.
    pub doc: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Line {
    pub has_code: bool,
    pub comments: Vec<Comment>,
}

#[derive(Debug, Clone)]
pub struct Lexed {
    /// Index 0 is line 1.
    pub lines: Vec<Line>,
    pub tokens: Vec<Token>,
}

/// Where the markup lexer is; the stack is empty in plain code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Inside `{ }` in markup; `braces` counts the braces opened since.
    Expression { braces: usize },
    /// Between `<` and `>`.
    Tag { closing: bool },
    /// Between an element's opening and closing tags.
    Children,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    language: Language,
    lines: Vec<Line>,
    tokens: Vec<Token>,
    modes: Vec<Mode>,
}

impl Language {
    fn is_script(self) -> bool {
        self != Language::Rust
    }
}

impl Lexer {
    fn new(source: &str, language: Language) -> Lexer {
        Lexer {
            chars: source.chars().collect(),
            pos: 0,
            line: 1,
            language,
            lines: vec![Line::default()],
            tokens: Vec::new(),
            modes: Vec::new(),
        }
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            if self.lines.len() < self.line {
                self.lines.push(Line::default());
            }
        }
        Some(c)
    }

    fn comment(&mut self, comment: Comment) {
        if let Some(line) = self.lines.get_mut(self.line.saturating_sub(1)) {
            line.comments.push(comment);
        }
    }

    fn token(&mut self, text: String, kind: TokenKind, line: usize) {
        self.token_with(text, kind, line, String::new());
    }

    fn token_with(&mut self, text: String, kind: TokenKind, line: usize, value: String) {
        let first = line.saturating_sub(1);
        for entry in self.lines.iter_mut().take(self.line).skip(first) {
            entry.has_code = true;
        }
        self.tokens.push(Token {
            text,
            kind,
            line,
            value,
        });
    }

    /// The tokens and lines, and whether every markup element was closed.
    fn run(mut self) -> (Lexed, bool) {
        while self.peek(0).is_some() {
            match self.modes.last().copied() {
                None => self.code(),
                Some(Mode::Expression { braces }) => self.expression(braces),
                Some(Mode::Tag { closing }) => self.tag(closing),
                Some(Mode::Children) => self.children(),
            }
        }
        let balanced = self.modes.is_empty();
        let lexed = Lexed {
            lines: self.lines,
            tokens: self.tokens,
        };
        (lexed, balanced)
    }

    fn code(&mut self) {
        let Some(c) = self.peek(0) else {
            return;
        };
        match c {
            '/' if self.peek(1) == Some('/') => self.line_comment(),
            '/' if self.peek(1) == Some('*') => self.block_comment(),
            '"' => self.quoted('"'),
            '\'' if self.language.is_script() => self.quoted('\''),
            '`' if self.language.is_script() => self.quoted('`'),
            '\'' => self.char_or_lifetime(),
            '<' if self.language == Language::Markup && self.starts_markup() => self.open_tag(),
            c if c.is_whitespace() => {
                self.bump();
            }
            c if c.is_ascii_digit() => self.number(),
            c if c == '_' || c == '$' || c.is_alphabetic() => self.word(),
            _ => self.punct(),
        }
    }

    fn line_comment(&mut self) {
        let third = self.peek(2);
        let doc = (third == Some('/') && self.peek(3) != Some('/')) || third == Some('!');
        let skip = if doc { 3 } else { 2 };
        for _ in 0..skip {
            self.bump();
        }
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            text.push(c);
            self.bump();
        }
        self.comment(Comment {
            text: text.trim().to_owned(),
            doc,
        });
    }

    fn block_comment(&mut self) {
        let third = self.peek(2);
        let doc = (third == Some('*') && self.peek(3) != Some('/')) || third == Some('!');
        self.bump();
        self.bump();
        let nests = self.language == Language::Rust;
        let mut depth = 1;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if c == '*' && self.peek(1) == Some('/') {
                self.bump();
                self.bump();
                depth -= 1;
                if depth == 0 {
                    break;
                }
                continue;
            }
            if nests && c == '/' && self.peek(1) == Some('*') {
                depth += 1;
            }
            if c == '\n' {
                self.push_block_piece(&mut text, doc);
            } else {
                text.push(c);
            }
            self.bump();
        }
        self.push_block_piece(&mut text, doc);
    }

    fn push_block_piece(&mut self, text: &mut String, doc: bool) {
        let piece = text.trim().trim_start_matches('*').trim().to_owned();
        text.clear();
        if !piece.is_empty() {
            self.comment(Comment { text: piece, doc });
        }
    }

    fn quoted(&mut self, quote: char) {
        let line = self.line;
        let mut value = String::new();
        self.bump();
        while let Some(c) = self.bump() {
            if c == quote {
                break;
            }
            value.push(c);
            if c == '\\'
                && let Some(escaped) = self.bump()
            {
                value.push(escaped);
            }
        }
        self.token_with(quote.to_string(), TokenKind::Literal, line, value);
    }

    fn raw_string(&mut self, line: usize) {
        let mut hashes = 0;
        while self.peek(0) == Some('#') {
            hashes += 1;
            self.bump();
        }
        self.bump();
        let mut value = String::new();
        while let Some(c) = self.bump() {
            let closes = c == '"' && (0..hashes).all(|offset| self.peek(offset) == Some('#'));
            if closes {
                for _ in 0..hashes {
                    self.bump();
                }
                break;
            }
            value.push(c);
        }
        self.token_with("\"".to_owned(), TokenKind::Literal, line, value);
    }

    fn char_or_lifetime(&mut self) {
        let line = self.line;
        let escaped = self.peek(1) == Some('\\');
        let single = self.peek(2) == Some('\'');
        if !escaped && !single {
            self.bump();
            self.token("'".to_owned(), TokenKind::Punct, line);
            return;
        }
        self.bump();
        let mut value = String::new();
        if escaped {
            value.extend(self.bump());
            value.extend(self.bump());
        }
        while let Some(c) = self.bump() {
            if c == '\'' || c == '\n' {
                break;
            }
            value.push(c);
        }
        self.token_with("'".to_owned(), TokenKind::Literal, line, value);
    }

    fn word(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            if !(c == '_' || c == '$' || c.is_alphanumeric()) {
                break;
            }
            text.push(c);
            self.bump();
        }
        if self.language == Language::Rust && self.rust_prefixed_literal(&text, line) {
            return;
        }
        self.token(text, TokenKind::Ident, line);
    }

    /// `r"..."`, `br#"..."#`, `b"..."`, `b'x'`, `c"..."` and raw identifiers `r#type`.
    fn rust_prefixed_literal(&mut self, word: &str, line: usize) -> bool {
        let next = self.peek(0);
        let raw = matches!(word, "r" | "br" | "cr");
        if raw && next == Some('#') && self.peek(1).is_some_and(|c| c == '_' || c.is_alphabetic()) {
            self.bump();
            return false;
        }
        if raw && matches!(next, Some('"') | Some('#')) {
            self.raw_string(line);
            return true;
        }
        if matches!(word, "b" | "c") && next == Some('"') {
            self.quoted('"');
            return true;
        }
        if word == "b" && next == Some('\'') {
            self.char_or_lifetime();
            return true;
        }
        false
    }

    fn number(&mut self) {
        let line = self.line;
        let mut text = String::new();
        while let Some(c) = self.peek(0) {
            let fraction = c == '.' && self.peek(1).is_some_and(|d| d.is_ascii_digit());
            if !(c.is_ascii_alphanumeric() || c == '_' || fraction) {
                break;
            }
            text.push(c);
            self.bump();
        }
        self.token(text, TokenKind::Number, line);
    }

    fn punct(&mut self) {
        let line = self.line;
        let first = self.bump().unwrap_or_default();
        let mut text = first.to_string();
        if let Some(second) = self.peek(0) {
            let pair = format!("{first}{second}");
            if PAIRS.contains(&pair.as_str()) {
                self.bump();
                text = pair;
            }
        }
        self.token(text, TokenKind::Punct, line);
    }
}

/// Lexes `source`. Markup that never closes was not markup (a generic type in a TSX file, say),
/// so such a file is lexed again as plain script.
pub fn lex(source: &str, language: Language) -> Lexed {
    let (lexed, balanced) = Lexer::new(source, language).run();
    if balanced || language != Language::Markup {
        return lexed;
    }
    Lexer::new(source, Language::Script).run().0
}

/// The text of the token at `index`, or `""` past the end.
pub(crate) fn text(tokens: &[Token], index: usize) -> &str {
    tokens.get(index).map_or("", |token| token.text.as_str())
}

/// The text of the token `back` places before `index`, or `""` before the start.
pub(crate) fn text_before(tokens: &[Token], index: usize, back: usize) -> &str {
    index
        .checked_sub(back)
        .map_or("", |position| text(tokens, position))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(lexed: &Lexed) -> Vec<&str> {
        lexed.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    #[test]
    fn strings_and_comments_hide_braces() {
        let lexed = lex(
            "let s = \"{ // }\"; // a { comment\nlet r = r#\"}\"#;\n",
            Language::Rust,
        );
        assert_eq!(
            texts(&lexed),
            vec!["let", "s", "=", "\"", ";", "let", "r", "=", "\"", ";"]
        );
        assert_eq!(lexed.tokens[3].value, "{ // }");
        assert_eq!(lexed.tokens[8].value, "}");
        assert_eq!(lexed.lines[0].comments[0].text, "a { comment");
        assert!(!lexed.lines[0].comments[0].doc);
    }

    #[test]
    fn doc_comments_and_nested_blocks() {
        let lexed = lex(
            "/// Doc.\n//// not doc\n/* a /* b */ c */ fn x() {}\n",
            Language::Rust,
        );
        assert!(lexed.lines[0].comments[0].doc);
        assert!(!lexed.lines[1].comments[0].doc);
        assert_eq!(texts(&lexed), vec!["fn", "x", "(", ")", "{", "}"]);
        assert!(!lexed.lines[1].has_code);
        assert!(lexed.lines[2].has_code);
    }

    #[test]
    fn lifetimes_chars_numbers_and_multiline_strings() {
        let lexed = lex(
            "fn f<'a>(x: &'a str) -> char { '{' }\nlet s = \"one\ntwo\";\nlet n = 1_000u32;\n",
            Language::Rust,
        );
        let toks = texts(&lexed);
        assert!(toks.contains(&"->"));
        assert_eq!(toks.iter().filter(|t| **t == "{").count(), 1);
        assert!(lexed.lines[2].has_code);
        let number = lexed.tokens.iter().find(|t| t.text == "1_000u32").unwrap();
        assert_eq!(number.kind, TokenKind::Number);
    }

    #[test]
    fn script_templates_and_quotes() {
        let lexed = lex(
            "const a = `x ${ {y} }`; const b = '}'; // c\n",
            Language::Script,
        );
        assert_eq!(
            texts(&lexed),
            vec!["const", "a", "=", "`", ";", "const", "b", "=", "'", ";"]
        );
        assert_eq!(lexed.tokens[3].value, "x ${ {y} }");
    }

    #[test]
    fn markup_text_attributes_and_child_expressions() {
        let source = "const A = () => (\n  <Card title=\"Hi\" on={x > 1}>\n    Don't stop {count} <b>now</b>\n    {'later'}\n  </Card>\n);\nconst B = 1;\n";
        let lexed = lex(source, Language::Markup);
        let kinds: Vec<(TokenKind, &str, usize)> = lexed
            .tokens
            .iter()
            .filter(|t| matches!(t.kind, TokenKind::Text | TokenKind::Literal))
            .map(|t| (t.kind, t.value.as_str(), t.line))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (TokenKind::Literal, "Hi", 2),
                (TokenKind::Text, "Don't stop", 3),
                (TokenKind::Text, "now", 3),
                (TokenKind::Literal, "later", 4),
            ]
        );
        assert!(texts(&lexed).ends_with(&["const", "B", "=", "1", ";"]));
    }

    #[test]
    fn unclosed_markup_is_lexed_again_as_script() {
        let lexed = lex(
            "let f: <T>(x: T) => T = id;\nconst s = 'a';\n",
            Language::Markup,
        );
        assert!(lexed.tokens.iter().all(|t| t.kind != TokenKind::Text));
        assert!(lexed.tokens.iter().any(|t| t.value == "a"));
    }
}
