// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Fail-closed subset TOML AST parser for P7 pack manifest inspection.

use std::collections::BTreeMap;

use crate::ConformanceError;
use crate::pack_manifest::conf_err;

const MAX_TOML_DEPTH: usize = 64;

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
}

pub(crate) fn parse_toml_document(
    raw: &str,
) -> Result<BTreeMap<String, TomlVal>, ConformanceError> {
    let clean = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let mut parser = Parser { src: clean, pos: 0 };
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
                return Err(conf_err("pack-toml", "TOML table nesting exceeds cap"));
            }
            append_array_table(&mut root, &path)?;
            section = path;
        } else if parser.starts_with("[") {
            let path = parser.parse_header(HeaderKind::Table)?;
            parser.expect_line_end()?;
            if path.len() > MAX_TOML_DEPTH {
                return Err(conf_err("pack-toml", "TOML table nesting exceeds cap"));
            }
            navigate_table_mut(&mut root, &path)?;
            section = path;
        } else {
            let key_path = parser.parse_dotted_key()?;
            if key_path.len() > MAX_TOML_DEPTH {
                return Err(conf_err("pack-toml", "TOML key nesting exceeds cap"));
            }
            parser.skip_hws();
            parser.expect_char('=')?;
            parser.skip_hws();
            let val = parser.parse_value(0)?;
            parser.expect_line_end()?;
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

    fn expect_char(&mut self, expected: char) -> Result<(), ConformanceError> {
        match self.next_char() {
            Some(ch) if ch == expected => Ok(()),
            _ => Err(conf_err("pack-toml", &format!("expected `{expected}`"))),
        }
    }

    fn expect_line_end(&mut self) -> Result<(), ConformanceError> {
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
            Some(other) => Err(conf_err(
                "pack-toml",
                &format!("unexpected trailing `{other}`"),
            )),
        }
    }

    fn parse_header(&mut self, kind: HeaderKind) -> Result<Vec<String>, ConformanceError> {
        let open = if kind == HeaderKind::ArrayTable {
            "[["
        } else {
            "["
        };
        let close = if kind == HeaderKind::ArrayTable {
            "]]"
        } else {
            "]"
        };
        if !self.starts_with(open) {
            return Err(conf_err("pack-toml", "invalid table header"));
        }
        self.advance(open.len());
        self.skip_hws();
        let path = self.parse_dotted_key()?;
        self.skip_hws();
        if !self.starts_with(close) {
            return Err(conf_err("pack-toml", "unclosed TOML table header"));
        }
        self.advance(close.len());
        Ok(path)
    }

    fn parse_dotted_key(&mut self) -> Result<Vec<String>, ConformanceError> {
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

    fn parse_key_segment(&mut self) -> Result<String, ConformanceError> {
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
                    return Err(conf_err("pack-toml", "empty TOML key segment"));
                }
                Ok(seg.to_owned())
            }
            None => Err(conf_err("pack-toml", "unexpected EOF while reading key")),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<TomlVal, ConformanceError> {
        if depth > MAX_TOML_DEPTH {
            return Err(conf_err("pack-toml", "TOML value nesting exceeds cap"));
        }
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
            None => Err(conf_err("pack-toml", "expected TOML value, found EOF")),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, ConformanceError> {
        self.expect_char('"')?;
        let mut out = String::new();
        while let Some(ch) = self.next_char() {
            match ch {
                '"' => return Ok(out),
                '\\' => out.push(self.parse_escape()?),
                '\n' | '\r' => return Err(conf_err("pack-toml", "unescaped newline in string")),
                c => out.push(c),
            }
        }
        Err(conf_err("pack-toml", "unterminated basic string"))
    }

    fn parse_literal_string(&mut self) -> Result<String, ConformanceError> {
        self.expect_char('\'')?;
        let mut out = String::new();
        while let Some(ch) = self.next_char() {
            match ch {
                '\'' => return Ok(out),
                '\n' | '\r' => {
                    return Err(conf_err("pack-toml", "unescaped newline in literal string"));
                }
                c => out.push(c),
            }
        }
        Err(conf_err("pack-toml", "unterminated literal string"))
    }

    fn parse_multiline_string(
        &mut self,
        delim: &str,
        allow_escapes: bool,
    ) -> Result<String, ConformanceError> {
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
        Err(conf_err("pack-toml", "unterminated multiline string"))
    }

    fn parse_escape(&mut self) -> Result<char, ConformanceError> {
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
            Some(other) => Err(conf_err(
                "pack-toml",
                &format!("invalid escape `\\{other}`"),
            )),
            None => Err(conf_err("pack-toml", "truncated escape sequence")),
        }
    }

    fn parse_hex_char(&mut self, digits: usize) -> Result<char, ConformanceError> {
        let mut hex = String::with_capacity(digits);
        for _ in 0..digits {
            match self.next_char() {
                Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                _ => return Err(conf_err("pack-toml", "invalid unicode escape")),
            }
        }
        u32::from_str_radix(&hex, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| conf_err("pack-toml", "invalid unicode scalar value"))
    }

    fn parse_array(&mut self, depth: usize) -> Result<TomlVal, ConformanceError> {
        let next_depth = depth.saturating_add(1);
        if next_depth > MAX_TOML_DEPTH {
            return Err(conf_err("pack-toml", "TOML array nesting exceeds cap"));
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
                _ => return Err(conf_err("pack-toml", "expected `,` or `]` in array")),
            }
        }
    }

    fn parse_inline_table(&mut self, depth: usize) -> Result<TomlVal, ConformanceError> {
        let next_depth = depth.saturating_add(1);
        if next_depth > MAX_TOML_DEPTH {
            return Err(conf_err(
                "pack-toml",
                "TOML inline table nesting exceeds cap",
            ));
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
                return Err(conf_err("pack-toml", "TOML key nesting exceeds cap"));
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
                _ => return Err(conf_err("pack-toml", "expected `,` or `}` in inline table")),
            }
        }
    }

    fn parse_bare_scalar(&mut self) -> Result<TomlVal, ConformanceError> {
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
                .ok_or_else(|| conf_err("pack-toml", &format!("invalid TOML scalar `{token}`"))),
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
    clean.parse::<i64>().ok()
}

fn navigate_table_mut<'a>(
    mut cur: &'a mut BTreeMap<String, TomlVal>,
    path: &[String],
) -> Result<&'a mut BTreeMap<String, TomlVal>, ConformanceError> {
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| TomlVal::Table(BTreeMap::new()));
        cur = match entry {
            TomlVal::Table(sub) => sub,
            TomlVal::Array(arr) => match arr.last_mut() {
                Some(TomlVal::Table(sub)) => sub,
                _ => {
                    return Err(conf_err(
                        "pack-toml",
                        &format!("`{seg}` is not a table array"),
                    ));
                }
            },
            _ => {
                return Err(conf_err(
                    "pack-toml",
                    &format!("key `{seg}` collides with scalar"),
                ));
            }
        };
    }
    Ok(cur)
}

fn append_array_table(
    root: &mut BTreeMap<String, TomlVal>,
    path: &[String],
) -> Result<(), ConformanceError> {
    let Some((leaf, parents)) = path.split_last() else {
        return Err(conf_err("pack-toml", "empty array-table path"));
    };
    let parent = navigate_table_mut(root, parents)?;
    let entry = parent
        .entry(leaf.clone())
        .or_insert_with(|| TomlVal::Array(Vec::new()));
    let TomlVal::Array(items) = entry else {
        return Err(conf_err(
            "pack-toml",
            &format!("`{leaf}` collides with non-array"),
        ));
    };
    items.push(TomlVal::Table(BTreeMap::new()));
    Ok(())
}

fn insert_dotted(
    tbl: &mut BTreeMap<String, TomlVal>,
    key_path: &[String],
    val: TomlVal,
) -> Result<(), ConformanceError> {
    let Some((leaf, parents)) = key_path.split_last() else {
        return Err(conf_err("pack-toml", "empty TOML key"));
    };
    let target = navigate_table_mut(tbl, parents)?;
    if target.contains_key(leaf) {
        return Err(conf_err(
            "pack-toml",
            &format!("duplicate TOML key `{leaf}`"),
        ));
    }
    target.insert(leaf.clone(), val);
    Ok(())
}
