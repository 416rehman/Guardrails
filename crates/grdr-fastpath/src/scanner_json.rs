// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded `#![no_std]` JSON field decoders and shell-quote helpers for the fastpath scanner.

use core::str;

pub(crate) fn decode_utf8_prefix(bytes: &[u8]) -> Option<&str> {
    if let Ok(s) = str::from_utf8(bytes) {
        return Some(s);
    }
    let back_max = bytes.len().min(3);
    for trim in 1..=back_max {
        let len = bytes.len().saturating_sub(trim);
        if let Some(prefix) = bytes.get(..len)
            && let Ok(s) = str::from_utf8(prefix)
        {
            return Some(s);
        }
    }
    None
}

pub(crate) fn scan_json_quoted_span(
    bytes: &[u8],
    quote_pos: usize,
    max_len: usize,
) -> (&[u8], usize, bool) {
    let val_start = quote_pos.saturating_add(1);
    let mut cursor = val_start;
    let mut escaped = false;
    while let Some(&ch) = bytes.get(cursor) {
        if escaped {
            escaped = false;
            cursor = cursor.saturating_add(1);
            continue;
        }
        if ch == b'\\' {
            escaped = true;
            cursor = cursor.saturating_add(1);
            continue;
        }
        if ch == b'"' {
            let len = cursor.saturating_sub(val_start);
            let capped = len.min(max_len);
            let slice = bytes
                .get(val_start..val_start.saturating_add(capped))
                .unwrap_or(&[]);
            return (slice, cursor.saturating_add(1), len > max_len);
        }
        cursor = cursor.saturating_add(1);
    }
    let len = cursor.saturating_sub(val_start).min(max_len);
    let slice = bytes
        .get(val_start..val_start.saturating_add(len))
        .unwrap_or(&[]);
    (slice, cursor, true)
}

pub(crate) fn skip_ws(bytes: &[u8], mut idx: usize) -> usize {
    while let Some(&b) = bytes.get(idx) {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            idx = idx.saturating_add(1);
        } else {
            break;
        }
    }
    idx
}

pub(crate) fn decode_json_string_into<'a>(raw: &str, out: &'a mut [u8]) -> (&'a str, bool) {
    let bytes = raw.as_bytes();
    let mut i: usize = 0;
    let mut written: usize = 0;
    let mut truncated = false;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            let Some(&next) = bytes.get(i.saturating_add(1)) else {
                if !push_bytes(out, &mut written, b"\\") {
                    truncated = true;
                }
                break;
            };
            if next == b'u'
                && let Some(hex) = bytes.get(i.saturating_add(2)..i.saturating_add(6))
                && let Some(cp) = parse_hex4(hex)
            {
                let (scalar, advance) = if (0xD800..=0xDBFF).contains(&cp)
                    && bytes.get(i.saturating_add(6)..i.saturating_add(8)) == Some(b"\\u")
                    && let Some(lo_hex) = bytes.get(i.saturating_add(8)..i.saturating_add(12))
                    && let Some(lo) = parse_hex4(lo_hex)
                    && (0xDC00..=0xDFFF).contains(&lo)
                {
                    let combined = 0x10000u32.saturating_add(
                        (cp.saturating_sub(0xD800) << 10) | lo.saturating_sub(0xDC00),
                    );
                    (combined, 12usize)
                } else {
                    (cp, 6usize)
                };
                let ch = char::from_u32(scalar).unwrap_or('\u{FFFD}');
                let mut tmp = [0u8; 4];
                let encoded = ch.encode_utf8(&mut tmp).as_bytes();
                if !push_bytes(out, &mut written, encoded) {
                    truncated = true;
                    break;
                }
                i = i.saturating_add(advance);
                continue;
            }
            let unescaped = match next {
                b'"' => b'"',
                b'\\' => b'\\',
                b'/' => b'/',
                b'b' => 0x08,
                b'f' => 0x0C,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                other => other,
            };
            if !push_bytes(out, &mut written, &[unescaped]) {
                truncated = true;
                break;
            }
            i = i.saturating_add(2);
            continue;
        }
        if !push_bytes(out, &mut written, &[b]) {
            truncated = true;
            break;
        }
        i = i.saturating_add(1);
    }
    let slice = out.get(..written).unwrap_or(&[]);
    (decode_utf8_prefix(slice).unwrap_or(""), truncated)
}

fn push_bytes(out: &mut [u8], written: &mut usize, src: &[u8]) -> bool {
    let next_len = written.saturating_add(src.len());
    let Some(dst) = out.get_mut(*written..next_len) else {
        return false;
    };
    dst.copy_from_slice(src);
    *written = next_len;
    true
}

fn parse_hex4(hex: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &b in hex {
        let nibble = match b {
            b'0'..=b'9' => u32::from(b.saturating_sub(b'0')),
            b'a'..=b'f' => u32::from(b.saturating_sub(b'a')).saturating_add(10),
            b'A'..=b'F' => u32::from(b.saturating_sub(b'A')).saturating_add(10),
            _ => return None,
        };
        acc = (acc << 4) | nibble;
    }
    Some(acc)
}

pub(crate) fn has_malformed_quotes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for &b in bytes {
        step_shell_quote_byte(b, &mut in_double, &mut in_single, &mut escaped);
    }
    escaped || in_double || in_single
}

fn step_shell_quote_byte(b: u8, in_double: &mut bool, in_single: &mut bool, escaped: &mut bool) {
    if *escaped {
        *escaped = false;
        return;
    }
    if b == b'\\' && !*in_single {
        *escaped = true;
        return;
    }
    if b == b'"' && !*in_single {
        *in_double = !*in_double;
    } else if b == b'\'' && !*in_double {
        *in_single = !*in_single;
    }
}
