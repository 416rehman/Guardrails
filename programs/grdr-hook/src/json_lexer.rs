// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Low-level zero-`serde_json` RFC 8259 cursor and UTF-8 helpers for hook stdin payloads.

use crate::json_scan::HookCodecError;

pub(crate) struct JsonScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonScanner<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) const fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn slice_bytes(&self, start: usize, end: usize) -> Option<&[u8]> {
        self.bytes.get(start..end)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub(crate) fn next(&mut self) -> Option<u8> {
        let ch = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(ch)
    }

    pub(crate) fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    pub(crate) fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    pub(crate) fn read_string(&mut self) -> Result<String, HookCodecError> {
        if self.next() != Some(b'"') {
            return Err(HookCodecError::MalformedJson {
                detail: "expected opening quote".to_string(),
            });
        }
        let mut out = String::new();
        while let Some(b) = self.next() {
            match b {
                b'"' => return Ok(out),
                b'\\' => self.read_escaped_char(&mut out)?,
                0x00..=0x1F => {
                    return Err(HookCodecError::MalformedJson {
                        detail: "unescaped control char inside JSON string".to_string(),
                    });
                }
                _ => {
                    let start = self.pos.saturating_sub(1);
                    let rest = self.bytes.get(start..).unwrap_or(&[]);
                    let ch =
                        decode_utf8_prefix(rest).ok_or_else(|| HookCodecError::MalformedJson {
                            detail: "invalid UTF-8 byte in JSON string".to_string(),
                        })?;
                    self.pos = self.pos.saturating_add(ch.len_utf8().saturating_sub(1));
                    out.push(ch);
                }
            }
        }
        Err(HookCodecError::MalformedJson {
            detail: "unterminated JSON string".to_string(),
        })
    }

    fn read_escaped_char(&mut self, out: &mut String) -> Result<(), HookCodecError> {
        let esc = self.next().ok_or_else(|| HookCodecError::MalformedJson {
            detail: "unterminated escape sequence".to_string(),
        })?;
        match esc {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000C}'),
            b'u' => {
                let code = self.read_hex4()?;
                if (0xD800..=0xDBFF).contains(&code) {
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err(HookCodecError::MalformedJson {
                            detail: "unpaired UTF-16 high surrogate".to_string(),
                        });
                    }
                    let lo = self.read_hex4()?;
                    if !(0xDC00..=0xDFFF).contains(&lo) {
                        return Err(HookCodecError::MalformedJson {
                            detail: "invalid UTF-16 low surrogate".to_string(),
                        });
                    }
                    let hi_bits = u32::from(code.saturating_sub(0xD800)) << 10;
                    let lo_bits = u32::from(lo.saturating_sub(0xDC00));
                    let cp = 0x1_0000_u32.saturating_add(hi_bits | lo_bits);
                    let ch = char::from_u32(cp).ok_or_else(|| HookCodecError::MalformedJson {
                        detail: "out-of-range UTF-16 surrogate pair".to_string(),
                    })?;
                    out.push(ch);
                } else if (0xDC00..=0xDFFF).contains(&code) {
                    return Err(HookCodecError::MalformedJson {
                        detail: "unpaired UTF-16 low surrogate".to_string(),
                    });
                } else if let Some(ch) = char::from_u32(u32::from(code)) {
                    out.push(ch);
                }
            }
            _ => {
                return Err(HookCodecError::MalformedJson {
                    detail: "invalid JSON escape".to_string(),
                });
            }
        }
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u16, HookCodecError> {
        let mut val: u16 = 0;
        for _ in 0..4 {
            let b = self.next().ok_or_else(|| HookCodecError::MalformedJson {
                detail: "truncated \\uXXXX escape".to_string(),
            })?;
            let nib: u16 = match b {
                b'0'..=b'9' => u16::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u16::from(b.saturating_sub(b'a').saturating_add(10)),
                b'A'..=b'F' => u16::from(b.saturating_sub(b'A').saturating_add(10)),
                _ => {
                    return Err(HookCodecError::MalformedJson {
                        detail: "invalid hex digit in \\uXXXX".to_string(),
                    });
                }
            };
            val = (val << 4) | nib;
        }
        Ok(val)
    }

    pub(crate) fn skip_keyword(&mut self) -> Result<(), HookCodecError> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]);
        if rest.starts_with(b"true") || rest.starts_with(b"null") {
            self.pos = self.pos.saturating_add(4);
            Ok(())
        } else if rest.starts_with(b"false") {
            self.pos = self.pos.saturating_add(5);
            Ok(())
        } else {
            Err(HookCodecError::MalformedJson {
                detail: "invalid JSON literal".to_string(),
            })
        }
    }

    pub(crate) fn skip_number(&mut self) -> Result<(), HookCodecError> {
        if self.peek() == Some(b'-') {
            let _ = self.next();
        }
        match self.next() {
            Some(b'0') => {
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(HookCodecError::MalformedJson {
                        detail: "leading zero in JSON number".to_string(),
                    });
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    let _ = self.next();
                }
            }
            _ => {
                return Err(HookCodecError::MalformedJson {
                    detail: "invalid integer part in JSON number".to_string(),
                });
            }
        }
        if self.peek() == Some(b'.') {
            let _ = self.next();
            if !matches!(self.next(), Some(b'0'..=b'9')) {
                return Err(HookCodecError::MalformedJson {
                    detail: "expected fraction digit in JSON number".to_string(),
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                let _ = self.next();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let _ = self.next();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                let _ = self.next();
            }
            if !matches!(self.next(), Some(b'0'..=b'9')) {
                return Err(HookCodecError::MalformedJson {
                    detail: "expected exponent digit in JSON number".to_string(),
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                let _ = self.next();
            }
        }
        Ok(())
    }
}

pub(crate) fn decode_utf8_prefix(bytes: &[u8]) -> Option<char> {
    let max_len = bytes.len().min(4);
    for len in 1..=max_len {
        if let Ok(s) = std::str::from_utf8(bytes.get(..len)?) {
            return s.chars().next();
        }
    }
    None
}

pub(crate) fn bounded_utf8_prefix(bytes: &[u8], max_bytes: usize) -> String {
    let cap = bytes.len().min(max_bytes);
    let mut end = cap;
    while end > 0 {
        if let Some(slice) = bytes.get(..end)
            && let Ok(valid) = std::str::from_utf8(slice)
        {
            return valid.to_string();
        }
        end = end.saturating_sub(1);
    }
    String::new()
}

pub(crate) fn first_non_empty<'a>(items: &[&'a str]) -> &'a str {
    for &item in items {
        if !item.trim().is_empty() {
            return item;
        }
    }
    ""
}
