// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded recursive subset TOML AST parser for compliance manifests, trust roots, and limits.

use std::collections::BTreeMap;

use crate::ComplyError;

const MAX_TOML_DEPTH: usize = 64;
const MAX_TOML_NODES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TomlVal {
    Str(String),
    Bool(bool),
    Int(i64),
    Array(Vec<TomlVal>),
    Table(BTreeMap<String, TomlVal>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    Table,
    ArrayTable,
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    nodes: usize,
}

pub(crate) fn parse_toml_document(raw: &str) -> Result<BTreeMap<String, TomlVal>, ComplyError> {
    let clean = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let mut parser = Parser {
        src: clean,
        pos: 0,
        nodes: 0,
    };
    let mut root: BTreeMap<String, TomlVal> = BTreeMap::new();
    let mut section: Vec<String> = Vec::new();
    while !parser.at_eof() {
        parser.skip_ws_comments_newlines();
        if parser.at_eof() {
            break;
        }
        if parser.starts_with("[[") {
            let path = parser.parse_header(HeaderKind::ArrayTable)?;
            parser.expect_line_end()?;
            if path.len() > MAX_TOML_DEPTH {
                return Err(toml_err("TOML table nesting exceeds cap"));
            }
            parser.count_node()?;
            append_array_table(&mut root, &path)?;
            section = path;
        } else if parser.starts_with("[") {
            let path = parser.parse_header(HeaderKind::Table)?;
            parser.expect_line_end()?;
            if path.len() > MAX_TOML_DEPTH {
                return Err(toml_err("TOML table nesting exceeds cap"));
            }
            parser.count_node()?;
            navigate_table_mut(&mut root, &path)?;
            section = path;
        } else {
            let key_path = parser.parse_dotted_key()?;
            if key_path.len() > MAX_TOML_DEPTH {
                return Err(toml_err("TOML key nesting exceeds cap"));
            }
            parser.skip_hws();
            parser.expect_char('=')?;
            parser.skip_hws();
            let val = parser.parse_value(0)?;
            parser.expect_line_end()?;
            parser.count_node()?;
            let tbl = navigate_table_mut(&mut root, &section)?;
            insert_dotted(tbl, &key_path, val)?;
        }
    }
    Ok(root)
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        self.src.get(self.pos..).unwrap_or("")
    }

    fn at_eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    fn advance(&mut self, bytes: usize) {
        self.pos = self.pos.saturating_add(bytes);
    }

    fn count_node(&mut self) -> Result<(), ComplyError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_TOML_NODES {
            return Err(toml_err("TOML AST node count exceeds cap"));
        }
        Ok(())
    }

    fn peek_char(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.advance(ch.len_utf8());
        Some(ch)
    }

    fn skip_hws(&mut self) {
        while matches!(self.peek_char(), Some(' ' | '\t')) {
            self.advance(1);
        }
    }

    fn skip_ws_comments_newlines(&mut self) {
        loop {
            while matches!(self.peek_char(), Some(' ' | '\t' | '\r' | '\n')) {
                self.advance(1);
            }
            if self.starts_with("#") {
                while let Some(ch) = self.next_char() {
                    if ch == '\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), ComplyError> {
        match self.next_char() {
            Some(ch) if ch == expected => Ok(()),
            _ => Err(toml_err(&format!("expected `{expected}`"))),
        }
    }

    fn expect_line_end(&mut self) -> Result<(), ComplyError> {
        self.skip_hws();
        if self.starts_with("#") {
            while let Some(ch) = self.next_char() {
                if ch == '\n' {
                    return Ok(());
                }
            }
            return Ok(());
        }
        match self.peek_char() {
            None => Ok(()),
            Some('\n') => {
                self.advance(1);
                Ok(())
            }
            Some('\r') => {
                self.advance(1);
                if self.peek_char() == Some('\n') {
                    self.advance(1);
                }
                Ok(())
            }
            Some(other) => Err(toml_err(&format!("unexpected trailing `{other}`"))),
        }
    }

    fn parse_header(&mut self, kind: HeaderKind) -> Result<Vec<String>, ComplyError> {
        let (open, close) = match kind {
            HeaderKind::ArrayTable => ("[[", "]]"),
            HeaderKind::Table => ("[", "]"),
        };
        if !self.starts_with(open) {
            return Err(toml_err("invalid TOML table header"));
        }
        self.advance(open.len());
        self.skip_hws();
        let path = self.parse_dotted_key()?;
        self.skip_hws();
        if !self.starts_with(close) {
            return Err(toml_err("unclosed TOML table header"));
        }
        self.advance(close.len());
        Ok(path)
    }

    fn parse_dotted_key(&mut self) -> Result<Vec<String>, ComplyError> {
        let mut parts = Vec::new();
        loop {
            self.skip_hws();
            parts.push(self.parse_key_segment()?);
            self.skip_hws();
            if self.peek_char() == Some('.') {
                self.advance(1);
                continue;
            }
            break;
        }
        Ok(parts)
    }

    fn parse_key_segment(&mut self) -> Result<String, ComplyError> {
        match self.peek_char() {
            Some('"') => self.parse_basic_string(),
            Some('\'') => self.parse_literal_string(),
            Some(_) => {
                let start = self.pos;
                while let Some(ch) = self.peek_char() {
                    if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                        self.advance(1);
                    } else {
                        break;
                    }
                }
                let seg = self.src.get(start..self.pos).unwrap_or("");
                if seg.is_empty() {
                    return Err(toml_err("empty TOML key segment"));
                }
                Ok(seg.to_owned())
            }
            None => Err(toml_err("unexpected EOF while reading TOML key")),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<TomlVal, ComplyError> {
        if depth > MAX_TOML_DEPTH {
            return Err(toml_err("TOML value nesting exceeds cap"));
        }
        self.count_node()?;
        if self.starts_with("\"\"\"") {
            return self
                .parse_multiline_string("\"\"\"", true)
                .map(TomlVal::Str);
        }
        if self.starts_with("'''") {
            return self.parse_multiline_string("'''", false).map(TomlVal::Str);
        }
        match self.peek_char() {
            Some('"') => self.parse_basic_string().map(TomlVal::Str),
            Some('\'') => self.parse_literal_string().map(TomlVal::Str),
            Some('[') => self.parse_array(depth),
            Some('{') => self.parse_inline_table(depth),
            Some(_) => self.parse_bare_scalar(),
            None => Err(toml_err("expected TOML value, found EOF")),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, ComplyError> {
        self.expect_char('"')?;
        let mut out = String::new();
        while let Some(ch) = self.next_char() {
            match ch {
                '"' => return Ok(out),
                '\\' => out.push(self.parse_escape()?),
                '\n' | '\r' => return Err(toml_err("unescaped newline in TOML string")),
                c => out.push(c),
            }
        }
        Err(toml_err("unterminated TOML basic string"))
    }

    fn parse_literal_string(&mut self) -> Result<String, ComplyError> {
        self.expect_char('\'')?;
        let mut out = String::new();
        while let Some(ch) = self.next_char() {
            match ch {
                '\'' => return Ok(out),
                '\n' | '\r' => return Err(toml_err("unescaped newline in TOML literal string")),
                c => out.push(c),
            }
        }
        Err(toml_err("unterminated TOML literal string"))
    }

    fn parse_multiline_string(
        &mut self,
        delim: &str,
        allow_escapes: bool,
    ) -> Result<String, ComplyError> {
        self.advance(delim.len());
        if self.starts_with("\r\n") {
            self.advance(2);
        } else if self.starts_with("\n") {
            self.advance(1);
        }
        let mut out = String::new();
        let quote_ch = delim.chars().next().unwrap_or('"');
        while !self.at_eof() {
            if self.starts_with(delim) {
                self.advance(delim.len());
                let mut extra = 0usize;
                while extra < 2 && self.peek_char() == Some(quote_ch) {
                    out.push(quote_ch);
                    self.advance(1);
                    extra = extra.saturating_add(1);
                }
                return Ok(out);
            }
            match self.next_char() {
                Some('\\') if allow_escapes => {
                    if matches!(self.peek_char(), Some(' ' | '\t' | '\r' | '\n')) {
                        while matches!(self.peek_char(), Some(' ' | '\t' | '\r' | '\n')) {
                            self.advance(1);
                        }
                    } else {
                        out.push(self.parse_escape()?);
                    }
                }
                Some(c) => out.push(c),
                None => break,
            }
        }
        Err(toml_err("unterminated TOML multiline string"))
    }

    fn parse_escape(&mut self) -> Result<char, ComplyError> {
        match self.next_char() {
            Some('b') => Ok('\u{0008}'),
            Some('t') => Ok('\t'),
            Some('n') => Ok('\n'),
            Some('f') => Ok('\u{000c}'),
            Some('r') => Ok('\r'),
            Some('"') => Ok('"'),
            Some('\\') => Ok('\\'),
            Some('u') => self.parse_hex_char(4),
            Some('U') => self.parse_hex_char(8),
            Some(other) => Err(toml_err(&format!("invalid TOML escape `\\{other}`"))),
            None => Err(toml_err("truncated TOML escape sequence")),
        }
    }

    fn parse_hex_char(&mut self, digits: usize) -> Result<char, ComplyError> {
        let mut hex = String::with_capacity(digits);
        for _ in 0..digits {
            match self.next_char() {
                Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                _ => return Err(toml_err("invalid TOML unicode escape")),
            }
        }
        u32::from_str_radix(&hex, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| toml_err("invalid TOML unicode scalar value"))
    }

    fn parse_array(&mut self, depth: usize) -> Result<TomlVal, ComplyError> {
        let next_depth = depth.saturating_add(1);
        if next_depth > MAX_TOML_DEPTH {
            return Err(toml_err("TOML array nesting exceeds cap"));
        }
        self.expect_char('[')?;
        let mut items = Vec::new();
        loop {
            self.skip_ws_comments_newlines();
            if self.peek_char() == Some(']') {
                self.advance(1);
                return Ok(TomlVal::Array(items));
            }
            items.push(self.parse_value(next_depth)?);
            self.skip_ws_comments_newlines();
            match self.peek_char() {
                Some(',') => self.advance(1),
                Some(']') => {
                    self.advance(1);
                    return Ok(TomlVal::Array(items));
                }
                _ => return Err(toml_err("expected `,` or `]` in TOML array")),
            }
        }
    }

    fn parse_inline_table(&mut self, depth: usize) -> Result<TomlVal, ComplyError> {
        let next_depth = depth.saturating_add(1);
        if next_depth > MAX_TOML_DEPTH {
            return Err(toml_err("TOML inline table nesting exceeds cap"));
        }
        self.expect_char('{')?;
        let mut tbl: BTreeMap<String, TomlVal> = BTreeMap::new();
        loop {
            self.skip_hws();
            if self.peek_char() == Some('}') {
                self.advance(1);
                return Ok(TomlVal::Table(tbl));
            }
            let key_path = self.parse_dotted_key()?;
            if next_depth.saturating_add(key_path.len()) > MAX_TOML_DEPTH {
                return Err(toml_err("TOML inline key nesting exceeds cap"));
            }
            self.skip_hws();
            self.expect_char('=')?;
            self.skip_hws();
            let val = self.parse_value(next_depth)?;
            insert_dotted(&mut tbl, &key_path, val)?;
            self.skip_hws();
            match self.peek_char() {
                Some(',') => self.advance(1),
                Some('}') => {
                    self.advance(1);
                    return Ok(TomlVal::Table(tbl));
                }
                _ => return Err(toml_err("expected `,` or `}` in inline table")),
            }
        }
    }

    fn parse_bare_scalar(&mut self) -> Result<TomlVal, ComplyError> {
        let start = self.pos;
        while let Some(ch) = self.peek_char() {
            if matches!(ch, ' ' | '\t' | '\r' | '\n' | '#' | ',' | ']' | '}') {
                break;
            }
            self.advance(ch.len_utf8());
        }
        let token = self.src.get(start..self.pos).unwrap_or("");
        match token {
            "true" => Ok(TomlVal::Bool(true)),
            "false" => Ok(TomlVal::Bool(false)),
            _ => parse_toml_int(token)
                .map(TomlVal::Int)
                .ok_or_else(|| toml_err(&format!("invalid TOML scalar `{token}`"))),
        }
    }
}

fn parse_toml_int(token: &str) -> Option<i64> {
    if token.is_empty() || token.starts_with('_') || token.ends_with('_') || token.contains("__") {
        return None;
    }
    let clean = token.replace('_', "");
    if let Some(hex) = clean.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    if let Some(oct) = clean.strip_prefix("0o") {
        return i64::from_str_radix(oct, 8).ok();
    }
    if let Some(bin) = clean.strip_prefix("0b") {
        return i64::from_str_radix(bin, 2).ok();
    }
    // Truncate float tokens only at explicit numeric parsing callers if not int.
    clean.parse::<i64>().ok().or_else(|| {
        clean.split_once('.').and_then(|(a, b)| {
            if b.chars().all(|c| c.is_ascii_digit()) {
                a.parse::<i64>().ok()
            } else {
                None
            }
        })
    })
}

fn navigate_table_mut<'a>(
    mut cur: &'a mut BTreeMap<String, TomlVal>,
    path: &[String],
) -> Result<&'a mut BTreeMap<String, TomlVal>, ComplyError> {
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| TomlVal::Table(BTreeMap::new()));
        cur = match entry {
            TomlVal::Table(sub) => sub,
            TomlVal::Array(arr) => match arr.last_mut() {
                Some(TomlVal::Table(sub)) => sub,
                _ => return Err(toml_err(&format!("`{seg}` is not a table array"))),
            },
            _ => return Err(toml_err(&format!("TOML key `{seg}` collides with scalar"))),
        };
    }
    Ok(cur)
}

fn append_array_table(
    root: &mut BTreeMap<String, TomlVal>,
    path: &[String],
) -> Result<(), ComplyError> {
    let Some((leaf, parents)) = path.split_last() else {
        return Err(toml_err("empty TOML array-table path"));
    };
    let parent = navigate_table_mut(root, parents)?;
    let entry = parent
        .entry(leaf.clone())
        .or_insert_with(|| TomlVal::Array(Vec::new()));
    let TomlVal::Array(items) = entry else {
        return Err(toml_err(&format!("`{leaf}` collides with non-array")));
    };
    items.push(TomlVal::Table(BTreeMap::new()));
    Ok(())
}

fn insert_dotted(
    tbl: &mut BTreeMap<String, TomlVal>,
    key_path: &[String],
    val: TomlVal,
) -> Result<(), ComplyError> {
    let Some((leaf, parents)) = key_path.split_last() else {
        return Err(toml_err("empty TOML key"));
    };
    let target = navigate_table_mut(tbl, parents)?;
    if target.contains_key(leaf) {
        return Err(toml_err(&format!("duplicate TOML key `{leaf}`")));
    }
    target.insert(leaf.clone(), val);
    Ok(())
}

fn toml_err(detail: &str) -> ComplyError {
    ComplyError::VerificationFailed {
        detail: detail.to_owned(),
    }
}
