// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use serde_json::Value;

use crate::McpProtoError;

pub const MAX_MCP_DEPTH: usize = 64;
pub const MAX_MCP_FRAME_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Object,
    Array,
}

#[derive(Debug)]
struct ContainerScope {
    kind: ScopeKind,
    seen_keys: BTreeSet<String>,
}

enum FinishStep {
    NeedValue,
    Complete,
}

struct JsonScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl<'a> JsonScanner<'a> {
    fn new(bytes: &'a [u8], max_depth: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            max_depth,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.bytes.get(self.pos).copied()?;
        self.pos = self.pos.saturating_add(1);
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn validate(&mut self) -> Result<(), McpProtoError> {
        let mut stack: Vec<ContainerScope> = Vec::new();
        loop {
            self.skip_ws();
            let Some(first) = self.peek() else {
                return Err(McpProtoError::InvalidFrame(
                    "unexpected end of JSON".to_string(),
                ));
            };
            match first {
                b'{' => {
                    self.open_scope(&mut stack, ScopeKind::Object)?;
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos = self.pos.saturating_add(1);
                        stack.pop();
                    } else {
                        self.parse_key(&mut stack)?;
                        continue;
                    }
                }
                b'[' => {
                    self.open_scope(&mut stack, ScopeKind::Array)?;
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.pos = self.pos.saturating_add(1);
                        stack.pop();
                    } else {
                        continue;
                    }
                }
                _ => self.parse_primitive(first)?,
            }
            match self.advance(&mut stack)? {
                FinishStep::NeedValue => continue,
                FinishStep::Complete => break,
            }
        }
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(McpProtoError::InvalidFrame(
                "trailing JSON tokens".to_string(),
            ));
        }
        Ok(())
    }

    fn open_scope(
        &mut self,
        stack: &mut Vec<ContainerScope>,
        kind: ScopeKind,
    ) -> Result<(), McpProtoError> {
        if stack.len() >= self.max_depth {
            return Err(McpProtoError::InvalidFrame(
                "JSON nesting depth exceeds limit".to_string(),
            ));
        }
        self.pos = self.pos.saturating_add(1);
        stack.push(ContainerScope {
            kind,
            seen_keys: BTreeSet::new(),
        });
        Ok(())
    }

    fn parse_key(&mut self, stack: &mut [ContainerScope]) -> Result<(), McpProtoError> {
        self.skip_ws();
        let key = self.parse_string()?;
        let scope = stack
            .last_mut()
            .ok_or_else(|| McpProtoError::InvalidFrame("missing object scope".to_string()))?;
        if !scope.seen_keys.insert(key) {
            return Err(McpProtoError::InvalidFrame(
                "duplicate JSON key rejected".to_string(),
            ));
        }
        self.skip_ws();
        if self.bump() != Some(b':') {
            return Err(McpProtoError::InvalidFrame("expected colon".to_string()));
        }
        Ok(())
    }

    fn advance(&mut self, stack: &mut Vec<ContainerScope>) -> Result<FinishStep, McpProtoError> {
        while let Some(top) = stack.last() {
            self.skip_ws();
            match (top.kind, self.bump()) {
                (ScopeKind::Object, Some(b',')) => {
                    self.parse_key(stack)?;
                    return Ok(FinishStep::NeedValue);
                }
                (ScopeKind::Object, Some(b'}')) | (ScopeKind::Array, Some(b']')) => {
                    stack.pop();
                }
                (ScopeKind::Array, Some(b',')) => return Ok(FinishStep::NeedValue),
                _ => {
                    return Err(McpProtoError::InvalidFrame(
                        "malformed JSON syntax".to_string(),
                    ));
                }
            }
        }
        Ok(FinishStep::Complete)
    }

    fn parse_primitive(&mut self, first: u8) -> Result<(), McpProtoError> {
        match first {
            b'"' => self.parse_string().map(|_| ()),
            b't' => self.consume_literal(b"true"),
            b'f' => self.consume_literal(b"false"),
            b'n' => self.consume_literal(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(McpProtoError::InvalidFrame(
                "unexpected JSON value".to_string(),
            )),
        }
    }

    fn consume_literal(&mut self, lit: &[u8]) -> Result<(), McpProtoError> {
        let end = self.pos.saturating_add(lit.len());
        if self.bytes.get(self.pos..end) != Some(lit) {
            return Err(McpProtoError::InvalidFrame(
                "invalid JSON literal".to_string(),
            ));
        }
        self.pos = end;
        Ok(())
    }

    fn parse_number(&mut self) -> Result<(), McpProtoError> {
        if self.peek() == Some(b'-') {
            self.pos = self.pos.saturating_add(1);
        }
        match self.bump() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos = self.pos.saturating_add(1);
                }
            }
            _ => return Err(McpProtoError::InvalidFrame("invalid number".to_string())),
        }
        if self.peek() == Some(b'.') {
            self.pos = self.pos.saturating_add(1);
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(McpProtoError::InvalidFrame("invalid fraction".to_string()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos = self.pos.saturating_add(1);
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(McpProtoError::InvalidFrame("invalid exponent".to_string()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, McpProtoError> {
        if self.bump() != Some(b'"') {
            return Err(McpProtoError::InvalidFrame("expected quote".to_string()));
        }
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos = self.pos.saturating_add(1);
            }
            if self.pos > start {
                let slice = self
                    .bytes
                    .get(start..self.pos)
                    .ok_or_else(|| McpProtoError::InvalidFrame("string oob".to_string()))?;
                let txt = std::str::from_utf8(slice)
                    .map_err(|_| McpProtoError::InvalidFrame("non-UTF8 string".to_string()))?;
                out.push_str(txt);
            }
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.parse_escape()?),
                _ => {
                    return Err(McpProtoError::InvalidFrame(
                        "unterminated string".to_string(),
                    ));
                }
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, McpProtoError> {
        match self.bump() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\x08'),
            Some(b'f') => Ok('\x0c'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.parse_u16_escape(),
            _ => Err(McpProtoError::InvalidFrame("invalid escape".to_string())),
        }
    }

    fn parse_u16_escape(&mut self) -> Result<char, McpProtoError> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                return Err(McpProtoError::InvalidFrame(
                    "unpaired surrogate".to_string(),
                ));
            }
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(McpProtoError::InvalidFrame("bad low surrogate".to_string()));
            }
            let hi = u32::from(code).saturating_sub(0xD800);
            let lo = u32::from(low).saturating_sub(0xDC00);
            return char::from_u32(0x1_0000_u32.saturating_add((hi << 10) | lo))
                .ok_or_else(|| McpProtoError::InvalidFrame("bad code point".to_string()));
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(McpProtoError::InvalidFrame(
                "unexpected low surrogate".to_string(),
            ));
        }
        char::from_u32(u32::from(code))
            .ok_or_else(|| McpProtoError::InvalidFrame("invalid scalar".to_string()))
    }

    fn read_hex4(&mut self) -> Result<u16, McpProtoError> {
        let mut acc: u16 = 0;
        for _ in 0..4 {
            let b = self
                .bump()
                .ok_or_else(|| McpProtoError::InvalidFrame("truncated hex escape".to_string()))?;
            let nibble = match b {
                b'0'..=b'9' => u16::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u16::from(b.saturating_sub(b'a')).saturating_add(10),
                b'A'..=b'F' => u16::from(b.saturating_sub(b'A')).saturating_add(10),
                _ => return Err(McpProtoError::InvalidFrame("bad hex escape".to_string())),
            };
            acc = (acc << 4) | nibble;
        }
        Ok(acc)
    }
}

pub fn parse_strict_mcp_json(raw: &str) -> Result<Value, McpProtoError> {
    if raw.is_empty() {
        return Err(McpProtoError::InvalidFrame(
            "empty JSON payload".to_string(),
        ));
    }
    if raw.len() > MAX_MCP_FRAME_BYTES {
        return Err(McpProtoError::InvalidFrame(
            "JSON payload exceeds 32 MiB cap".to_string(),
        ));
    }
    let mut scanner = JsonScanner::new(raw.as_bytes(), MAX_MCP_DEPTH);
    scanner.validate()?;
    serde_json::from_str(raw).map_err(|e| McpProtoError::InvalidFrame(e.to_string()))
}
