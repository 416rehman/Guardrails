// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict streaming JSON validator rejecting duplicate object keys and excessive nesting.

use std::collections::BTreeSet;

const MAX_JSON_DEPTH: usize = 32;

struct JsonKeyScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

pub(crate) fn reject_duplicate_json_keys(raw_json: &str) -> Result<(), String> {
    let mut scanner = JsonKeyScanner {
        bytes: raw_json.as_bytes(),
        pos: 0,
    };
    scanner.check_value(0)?;
    scanner.skip_ws();
    if scanner.pos < scanner.bytes.len() {
        return Err("trailing characters after JSON document".into());
    }
    Ok(())
}

impl<'a> JsonKeyScanner<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn check_value(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting depth exceeded".into());
        }
        self.skip_ws();
        let Some(&b) = self.bytes.get(self.pos) else {
            return Err("unexpected end of JSON".into());
        };
        match b {
            b'{' => self.check_object(depth.saturating_add(1)),
            b'[' => self.check_array(depth.saturating_add(1)),
            b'"' => {
                let _ = self.parse_string()?;
                Ok(())
            }
            _ => self.skip_primitive(),
        }
    }

    fn check_object(&mut self, depth: usize) -> Result<(), String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(());
        }
        let mut keys = BTreeSet::new();
        loop {
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err("expected string key in JSON object".into());
            }
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(format!("duplicate JSON key `{key}` rejected"));
            }
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err("expected `:` after JSON key".into());
            }
            self.pos = self.pos.saturating_add(1);
            self.check_value(depth)?;
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos = self.pos.saturating_add(1),
                Some(&b'}') => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(());
                }
                _ => return Err("expected `,` or `}` in JSON object".into()),
            }
        }
    }

    fn check_array(&mut self, depth: usize) -> Result<(), String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos = self.pos.saturating_add(1);
            return Ok(());
        }
        loop {
            self.check_value(depth)?;
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos = self.pos.saturating_add(1),
                Some(&b']') => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(());
                }
                _ => return Err("expected `,` or `]` in JSON array".into()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos = self.pos.saturating_add(1);
        let mut out = Vec::new();
        while let Some(&b) = self.bytes.get(self.pos) {
            self.pos = self.pos.saturating_add(1);
            match b {
                b'"' => {
                    return String::from_utf8(out)
                        .map_err(|_| "invalid UTF-8 inside JSON string".into());
                }
                b'\\' => {
                    let Some(&esc) = self.bytes.get(self.pos) else {
                        return Err("unterminated JSON string escape".into());
                    };
                    self.pos = self.pos.saturating_add(1);
                    match esc {
                        b'"' | b'\\' | b'/' => out.push(esc),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.bytes.get(self.pos) != Some(&b'\\')
                                    || self.bytes.get(self.pos.saturating_add(1)) != Some(&b'u')
                                {
                                    return Err("unpaired high UTF-16 surrogate in JSON".into());
                                }
                                self.pos = self.pos.saturating_add(2);
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err("invalid low UTF-16 surrogate in JSON".into());
                                }
                                let combined = 0x1_0000_u32
                                    .saturating_add(u32::from(cp.saturating_sub(0xD800)) << 10)
                                    .saturating_add(u32::from(low.saturating_sub(0xDC00)));
                                char::from_u32(combined)
                                    .ok_or_else(|| "invalid Unicode scalar in JSON".to_owned())?
                            } else {
                                char::from_u32(u32::from(cp))
                                    .ok_or_else(|| "invalid Unicode scalar in JSON".to_owned())?
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("invalid JSON string escape".into()),
                    }
                }
                c if c < 0x20 => return Err("unescaped control byte in JSON string".into()),
                c => out.push(c),
            }
        }
        Err("unterminated JSON string".into())
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let mut val: u16 = 0;
        for _ in 0..4 {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Err("truncated JSON unicode escape".into());
            };
            self.pos = self.pos.saturating_add(1);
            let nib = match b {
                b'0'..=b'9' => u16::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u16::from(b.saturating_sub(b'a')).saturating_add(10),
                b'A'..=b'F' => u16::from(b.saturating_sub(b'A')).saturating_add(10),
                _ => return Err("invalid hex digit in JSON unicode escape".into()),
            };
            val = (val << 4) | nib;
        }
        Ok(val)
    }

    fn skip_primitive(&mut self) -> Result<(), String> {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                break;
            }
            self.pos = self.pos.saturating_add(1);
        }
        if self.pos == start {
            return Err("empty JSON token".into());
        }
        Ok(())
    }
}
