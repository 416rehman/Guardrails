// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Comment/string sanitization and bounded AST lexical scanners for Cedar lints.

use super::PolicyError;

pub(crate) const MAX_CEDAR_SOURCE_BYTES: usize = 65_536;
pub(crate) const MAX_CEDAR_NESTING_DEPTH: usize = 64;

pub(crate) fn check_cedar_nesting_depth(rule_id: &str, source: &str) -> Result<(), PolicyError> {
    if source.len() > MAX_CEDAR_SOURCE_BYTES {
        return Err(PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: format!("Cedar source exceeds {MAX_CEDAR_SOURCE_BYTES} bytes"),
        });
    }
    let mut depth: usize = 0;
    let mut unary_chain: usize = 0;
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                let _ = chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            let _ = chars.next();
            in_line_comment = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            in_block_comment = true;
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                unary_chain = 0;
            }
            '!' | '-' if (ch == '!' && chars.peek() != Some(&'=')) || ch == '-' => {
                unary_chain = unary_chain.saturating_add(1);
                if unary_chain > MAX_CEDAR_NESTING_DEPTH {
                    return Err(PolicyError::CompileFailed {
                        rule_id: rule_id.into(),
                        detail: format!(
                            "Cedar unary expression depth exceeds limit {MAX_CEDAR_NESTING_DEPTH}"
                        ),
                    });
                }
            }
            '(' | '{' | '[' => {
                unary_chain = 0;
                depth = depth.saturating_add(1);
                if depth > MAX_CEDAR_NESTING_DEPTH {
                    return Err(PolicyError::CompileFailed {
                        rule_id: rule_id.into(),
                        detail: format!(
                            "Cedar expression depth exceeds limit {MAX_CEDAR_NESTING_DEPTH}"
                        ),
                    });
                }
            }
            ')' | '}' | ']' => {
                unary_chain = 0;
                depth = depth.saturating_sub(1);
            }
            c if !c.is_whitespace() => unary_chain = 0,
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn cedar_body_slice(source: &str) -> &str {
    let bytes = source.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut depth: usize = 0;

    while let Some(&b) = bytes.get(i) {
        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if in_block_comment {
            if b == b'*' && bytes.get(i.saturating_add(1)) == Some(&b'/') {
                in_block_comment = false;
                i = i.saturating_add(2);
            } else {
                i = i.saturating_add(1);
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if b == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'/') {
            in_line_comment = true;
            i = i.saturating_add(2);
            continue;
        }
        if b == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'*') {
            in_block_comment = true;
            i = i.saturating_add(2);
            continue;
        }
        if b == b'"' {
            in_string = true;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(b, b'(' | b'{' | b'[') {
            depth = depth.saturating_add(1);
            i = i.saturating_add(1);
            continue;
        }
        if matches!(b, b')' | b'}' | b']') {
            depth = depth.saturating_sub(1);
            i = i.saturating_add(1);
            continue;
        }
        if depth == 0 {
            let prev_ok = i == 0
                || bytes
                    .get(i.saturating_sub(1))
                    .is_some_and(|p| !p.is_ascii_alphanumeric() && *p != b'_' && *p != b'@');
            if prev_ok {
                for kw in [b"forbid" as &[u8], b"permit" as &[u8]] {
                    let end = i.saturating_add(kw.len());
                    if bytes.get(i..end) == Some(kw)
                        && bytes
                            .get(end)
                            .is_some_and(|n| n.is_ascii_whitespace() || *n == b'(')
                    {
                        return source.get(i..).unwrap_or(source);
                    }
                }
            }
        }
        i = i.saturating_add(1);
    }
    source
}

pub(crate) fn strip_comments_and_strings(input: &str, keep_strings: bool) -> String {
    let bytes = input.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut out = String::with_capacity(input.len());
    while let Some(&b) = bytes.get(i) {
        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
                out.push('\n');
            }
            i = i.saturating_add(1);
            continue;
        }
        if in_block_comment {
            if b == b'*' && bytes.get(i.saturating_add(1)) == Some(&b'/') {
                in_block_comment = false;
                out.push(' ');
                i = i.saturating_add(2);
            } else {
                i = i.saturating_add(1);
            }
            continue;
        }
        if in_string {
            if keep_strings {
                out.push(b as char);
            }
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if b == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'/') {
            in_line_comment = true;
            i = i.saturating_add(2);
            continue;
        }
        if b == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'*') {
            in_block_comment = true;
            i = i.saturating_add(2);
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push('"');
            if !keep_strings {
                out.push('"');
            }
            i = i.saturating_add(1);
            continue;
        }
        out.push(b as char);
        i = i.saturating_add(1);
    }
    out
}

pub(crate) fn scope_header_slice(body: &str) -> &str {
    let bytes = body.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut depth: usize = 0;
    while let Some(&b) = bytes.get(i) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if b == b'"' {
            in_string = true;
            i = i.saturating_add(1);
            continue;
        }
        if b == b'(' {
            depth = depth.saturating_add(1);
        } else if b == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return body.get(..i.saturating_add(1)).unwrap_or(body);
            }
        }
        i = i.saturating_add(1);
    }
    body
}
