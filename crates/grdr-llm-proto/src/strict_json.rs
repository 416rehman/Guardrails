// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use serde_json::Value;

use crate::error::ProtoError;

pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_LLM_REQUEST_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SSE_EVENT_BYTES: usize = 1_048_576;
pub const MAX_TOOL_CALLS: usize = 1_024;
pub const MAX_DECOMPRESSION_RATIO: usize = 100;

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

    fn validate_document(&mut self) -> Result<(), ProtoError> {
        let mut stack: Vec<ContainerScope> = Vec::new();
        loop {
            self.skip_ws();
            let Some(first) = self.peek() else {
                return Err(ProtoError::Parse(
                    "unexpected end of JSON input".to_string(),
                ));
            };
            match first {
                b'{' => {
                    self.open_object(&mut stack)?;
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos = self.pos.saturating_add(1);
                        stack.pop();
                    } else {
                        self.parse_object_member_key(&mut stack)?;
                        continue;
                    }
                }
                b'[' => {
                    self.open_array(&mut stack)?;
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.pos = self.pos.saturating_add(1);
                        stack.pop();
                    } else {
                        continue;
                    }
                }
                _ => {
                    self.parse_primitive(first)?;
                }
            }
            match self.advance_containers(&mut stack)? {
                FinishStep::NeedValue => continue,
                FinishStep::Complete => break,
            }
        }
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(ProtoError::Parse("trailing JSON bytes".to_string()));
        }
        Ok(())
    }

    fn open_object(&mut self, stack: &mut Vec<ContainerScope>) -> Result<(), ProtoError> {
        if stack.len() >= self.max_depth {
            return Err(ProtoError::DepthLimitExceeded);
        }
        self.pos = self.pos.saturating_add(1);
        stack.push(ContainerScope {
            kind: ScopeKind::Object,
            seen_keys: BTreeSet::new(),
        });
        Ok(())
    }

    fn open_array(&mut self, stack: &mut Vec<ContainerScope>) -> Result<(), ProtoError> {
        if stack.len() >= self.max_depth {
            return Err(ProtoError::DepthLimitExceeded);
        }
        self.pos = self.pos.saturating_add(1);
        stack.push(ContainerScope {
            kind: ScopeKind::Array,
            seen_keys: BTreeSet::new(),
        });
        Ok(())
    }

    fn parse_object_member_key(&mut self, stack: &mut [ContainerScope]) -> Result<(), ProtoError> {
        self.skip_ws();
        let key = self.parse_string()?;
        let scope = stack
            .last_mut()
            .ok_or_else(|| ProtoError::Parse("missing object scope".to_string()))?;
        if !scope.seen_keys.insert(key) {
            return Err(ProtoError::DuplicateJsonKey);
        }
        self.skip_ws();
        if self.bump() != Some(b':') {
            return Err(ProtoError::Parse(
                "expected colon in JSON object".to_string(),
            ));
        }
        Ok(())
    }

    fn advance_containers(
        &mut self,
        stack: &mut Vec<ContainerScope>,
    ) -> Result<FinishStep, ProtoError> {
        while let Some(top) = stack.last() {
            self.skip_ws();
            let kind = top.kind;
            match (kind, self.bump()) {
                (ScopeKind::Object, Some(b',')) => {
                    self.parse_object_member_key(stack)?;
                    return Ok(FinishStep::NeedValue);
                }
                (ScopeKind::Object, Some(b'}')) | (ScopeKind::Array, Some(b']')) => {
                    stack.pop();
                }
                (ScopeKind::Array, Some(b',')) => {
                    return Ok(FinishStep::NeedValue);
                }
                _ => return Err(ProtoError::Parse("malformed JSON delimiter".to_string())),
            }
        }
        Ok(FinishStep::Complete)
    }

    fn parse_primitive(&mut self, first: u8) -> Result<(), ProtoError> {
        match first {
            b'"' => {
                let _ = self.parse_string()?;
                Ok(())
            }
            b't' => self.expect_literal(b"true"),
            b'f' => self.expect_literal(b"false"),
            b'n' => self.expect_literal(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(ProtoError::Parse("unexpected JSON token".to_string())),
        }
    }

    fn expect_literal(&mut self, literal: &[u8]) -> Result<(), ProtoError> {
        let end = self.pos.saturating_add(literal.len());
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| ProtoError::Parse("truncated JSON literal".to_string()))?;
        if slice != literal {
            return Err(ProtoError::Parse("invalid JSON literal".to_string()));
        }
        self.pos = end;
        Ok(())
    }

    fn parse_number(&mut self) -> Result<(), ProtoError> {
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
            _ => return Err(ProtoError::Parse("invalid JSON number integer".to_string())),
        }
        if self.peek() == Some(b'.') {
            self.pos = self.pos.saturating_add(1);
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ProtoError::Parse(
                    "invalid JSON fraction digits".to_string(),
                ));
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
                return Err(ProtoError::Parse(
                    "invalid JSON exponent digits".to_string(),
                ));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos = self.pos.saturating_add(1);
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, ProtoError> {
        if self.bump() != Some(b'"') {
            return Err(ProtoError::Parse("expected opening quote".to_string()));
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
                let segment = self
                    .bytes
                    .get(start..self.pos)
                    .ok_or_else(|| ProtoError::Parse("invalid string slice".to_string()))?;
                let text = std::str::from_utf8(segment)
                    .map_err(|_| ProtoError::Parse("non-UTF8 JSON string".to_string()))?;
                out.push_str(text);
            }
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => out.push(self.parse_escape()?),
                _ => {
                    return Err(ProtoError::Parse(
                        "unterminated or control JSON string".to_string(),
                    ));
                }
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, ProtoError> {
        match self.bump() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\x08'),
            Some(b'f') => Ok('\x0c'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => self.parse_unicode_escape(),
            _ => Err(ProtoError::Parse("invalid JSON string escape".to_string())),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, ProtoError> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                return Err(ProtoError::Parse(
                    "unpaired UTF-16 high surrogate".to_string(),
                ));
            }
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(ProtoError::Parse(
                    "invalid UTF-16 low surrogate".to_string(),
                ));
            }
            let hi = u32::from(code).saturating_sub(0xD800);
            let lo = u32::from(low).saturating_sub(0xDC00);
            let scalar = 0x1_0000_u32.saturating_add((hi << 10) | lo);
            return char::from_u32(scalar)
                .ok_or_else(|| ProtoError::Parse("invalid surrogate code point".to_string()));
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(ProtoError::Parse(
                "unexpected UTF-16 low surrogate".to_string(),
            ));
        }
        char::from_u32(u32::from(code))
            .ok_or_else(|| ProtoError::Parse("invalid unicode scalar".to_string()))
    }

    fn read_hex4(&mut self) -> Result<u16, ProtoError> {
        let mut acc: u16 = 0;
        for _ in 0..4 {
            let b = self
                .bump()
                .ok_or_else(|| ProtoError::Parse("truncated unicode escape".to_string()))?;
            let nibble = match b {
                b'0'..=b'9' => u16::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u16::from(b.saturating_sub(b'a')).saturating_add(10),
                b'A'..=b'F' => u16::from(b.saturating_sub(b'A')).saturating_add(10),
                _ => return Err(ProtoError::Parse("invalid hex escape digit".to_string())),
            };
            acc = (acc << 4) | nibble;
        }
        Ok(acc)
    }
}

pub fn validate_strict_json_bytes(
    bytes: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<(), ProtoError> {
    if bytes.is_empty() {
        return Err(ProtoError::Parse("empty JSON payload".to_string()));
    }
    if bytes.len() > max_bytes {
        return Err(ProtoError::PayloadTooLarge);
    }
    if max_depth == 0 {
        return Err(ProtoError::DepthLimitExceeded);
    }
    let mut scanner = JsonScanner::new(bytes, max_depth);
    scanner.validate_document()
}

pub fn parse_strict_json_bytes(
    bytes: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<Value, ProtoError> {
    validate_strict_json_bytes(bytes, max_bytes, max_depth)?;
    serde_json::from_slice(bytes).map_err(|e| ProtoError::Parse(e.to_string()))
}

pub fn parse_strict_json_str(
    raw: &str,
    max_bytes: usize,
    max_depth: usize,
) -> Result<Value, ProtoError> {
    parse_strict_json_bytes(raw.as_bytes(), max_bytes, max_depth)
}

#[must_use]
pub fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    decode_base64_inner(input.as_bytes(), true)
}

#[must_use]
pub fn decode_base64_std(input: &str) -> Option<Vec<u8>> {
    decode_base64_inner(input.as_bytes(), false)
}

#[must_use]
pub fn encode_base64_url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(
        bytes
            .len()
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(2),
    );
    let mut idx = 0usize;
    while idx < bytes.len() {
        let b0 = bytes.get(idx).copied().unwrap_or(0);
        let b1 = bytes.get(idx.saturating_add(1)).copied();
        let b2 = bytes.get(idx.saturating_add(2)).copied();
        let combined =
            (u32::from(b0) << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
        let push_idx = |out: &mut String, i: usize| {
            if let Some(&ch) = TABLE.get(i & 0x3f) {
                out.push(char::from(ch));
            }
        };
        push_idx(
            &mut out,
            usize::try_from((combined >> 18) & 0x3f).unwrap_or(0),
        );
        push_idx(
            &mut out,
            usize::try_from((combined >> 12) & 0x3f).unwrap_or(0),
        );
        if b1.is_some() {
            push_idx(
                &mut out,
                usize::try_from((combined >> 6) & 0x3f).unwrap_or(0),
            );
        }
        if b2.is_some() {
            push_idx(&mut out, usize::try_from(combined & 0x3f).unwrap_or(0));
        }
        idx = idx.saturating_add(3);
    }
    out
}

fn decode_base64_inner(raw: &[u8], url_safe: bool) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return Some(Vec::new());
    }
    let len_no_pad = raw
        .iter()
        .rposition(|&b| b != b'=')
        .map_or(0, |i| i.saturating_add(1));
    let pad_count = raw.len().saturating_sub(len_no_pad);
    if len_no_pad == 0 || pad_count > 2 {
        return None;
    }
    if pad_count > 0 && !raw.len().is_multiple_of(4) {
        return None;
    }
    let trimmed = raw.get(..len_no_pad)?;
    let rem = trimmed.len() % 4;
    if rem == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len().saturating_mul(3).saturating_div(4));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    let mut last_sextet: u8 = 0;
    for &b in trimmed {
        let val = base64_sextet(b, url_safe)?;
        last_sextet = val;
        buf = (buf << 6) | u32::from(val);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    // Reject non-zero trailing pad bits per RFC 4648 section 3.5.
    if (rem == 2 && (last_sextet & 0x0F) != 0) || (rem == 3 && (last_sextet & 0x03) != 0) {
        return None;
    }
    Some(out)
}

fn base64_sextet(b: u8, url_safe: bool) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b.saturating_sub(b'A')),
        b'a'..=b'z' => Some(b.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(b.saturating_sub(b'0').saturating_add(52)),
        b'-' if url_safe => Some(62),
        b'_' if url_safe => Some(63),
        b'+' if !url_safe => Some(62),
        b'/' if !url_safe => Some(63),
        _ => None,
    }
}
