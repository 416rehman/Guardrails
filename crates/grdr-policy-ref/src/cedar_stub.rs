// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Comment-aware Cedar annotation validation and grant matching helpers for `grdr-policy-ref`.

use grdr_model::{ApprovalGrade, Grant, Mode, PolicyRule};

pub(crate) fn rule_is_final(rule: &PolicyRule) -> bool {
    if let Some(anns) = rule
        .cedar
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .and_then(parse_prefix_annotations)
        && anns.iter().any(|(k, v)| k == "final" && v == "true")
    {
        return true;
    }
    rule.cedar.as_deref().is_none_or(|s| s.trim().is_empty())
        && rule.mode == Mode::Block
        && rule.locked
}

pub(crate) fn rule_effective_mode(rule: &PolicyRule) -> Mode {
    let mut mode = rule.mode;
    if let Some(val) = extract_annotation(rule.cedar.as_deref(), "max_mode") {
        let max_mode = match val.as_str() {
            "Off" => Mode::Off,
            "Watch" => Mode::Watch,
            "Ask" => Mode::Ask,
            "Block" => Mode::Block,
            _ => Mode::Block,
        };
        mode = mode.min(max_mode);
    }
    if rule_is_final(rule) && mode >= Mode::Ask {
        return Mode::Block;
    }
    mode
}

pub(crate) fn rule_effective_min_grade(rule: &PolicyRule) -> ApprovalGrade {
    let mut grade = rule.min_grade;
    if let Some(val) = extract_annotation(rule.cedar.as_deref(), "min_grade") {
        let parsed = match val.as_str() {
            "G0" => Some(ApprovalGrade::G0),
            "G1" => Some(ApprovalGrade::G1),
            "G2" => Some(ApprovalGrade::G2),
            "G3" => Some(ApprovalGrade::G3),
            _ => None,
        };
        if let Some(g) = parsed {
            grade = grade.max(g);
        }
    }
    grade
}

pub(crate) fn rule_approver(rule: &PolicyRule) -> String {
    extract_annotation(rule.cedar.as_deref(), "approver")
        .unwrap_or_else(|| "self".into())
        .to_ascii_lowercase()
}

pub(crate) fn grant_satisfies_rule_ref(
    eff_mode: Mode,
    eff_grade: ApprovalGrade,
    is_final: bool,
    approver: &str,
    grant: &Grant,
) -> bool {
    if is_final {
        return false;
    }
    let parsed_approver = extract_approver_kind_ref(&grant.note);
    if eff_mode == Mode::Block {
        if grant.grade < eff_grade.max(ApprovalGrade::G1) {
            return false;
        }
        let Some(kind) = parsed_approver else {
            return false;
        };
        if kind.eq_ignore_ascii_case("self") || !is_non_self_exception_role_ref(kind) {
            return false;
        }
        return approver == "self" || kind.eq_ignore_ascii_case(approver);
    }
    if grant.grade < eff_grade {
        return false;
    }
    if approver != "self" {
        return parsed_approver.is_some_and(|k| k.eq_ignore_ascii_case(approver));
    }
    true
}

pub(crate) fn validate_inline_cedar_stub(source: &str) -> bool {
    let Some(cleaned) = strip_cedar_comments(source) else {
        return false;
    };
    let Some(kw_idx) = find_policy_keyword_idx(&cleaned) else {
        return false;
    };
    let (Some(prefix), Some(body)) = (cleaned.get(..kw_idx), cleaned.get(kw_idx..)) else {
        return false;
    };
    let Some(anns) = parse_strict_annotations(prefix) else {
        return false;
    };
    for (k, v) in &anns {
        if !validate_annotation_value(k, v) {
            return false;
        }
    }
    let mut in_string = false;
    let mut escaped = false;
    let mut paren_depth: i32 = 0;
    let mut brace_depth: i32 = 0;
    for ch in body.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth < 0 {
                    return false;
                }
            }
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    if in_string || escaped || paren_depth != 0 || brace_depth != 0 {
        return false;
    }
    let trimmed = body.trim();
    trimmed.ends_with(';')
        && trimmed.starts_with("forbid")
        && !contains_unquoted_keyword(trimmed, "permit")
}

fn extract_approver_kind_ref(note: &str) -> Option<&str> {
    let trimmed = note.trim();
    let rest = trimmed
        .get(..9)
        .filter(|p| p.eq_ignore_ascii_case("approver:"))
        .and_then(|_| trimmed.get(9..))?
        .trim_start();
    let end = rest
        .find(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';' || c == '[')
        .unwrap_or(rest.len());
    rest.get(..end).filter(|s| !s.is_empty())
}

fn is_non_self_exception_role_ref(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("sponsor")
        || kind.eq_ignore_ascii_case("admin")
        || kind.eq_ignore_ascii_case("quorum")
}

fn extract_annotation(cedar: Option<&str>, name: &str) -> Option<String> {
    let src = cedar?;
    let anns = parse_prefix_annotations(src)?;
    anns.into_iter().rfind(|(k, _)| k == name).map(|(_, v)| v)
}

fn parse_prefix_annotations(source: &str) -> Option<Vec<(String, String)>> {
    let cleaned = strip_cedar_comments(source)?;
    let kw_idx = find_policy_keyword_idx(&cleaned)?;
    let prefix = cleaned.get(..kw_idx)?;
    parse_strict_annotations(prefix)
}

fn validate_annotation_value(name: &str, val: &str) -> bool {
    match name {
        "max_mode" => matches!(val, "Off" | "Watch" | "Ask" | "Block"),
        "min_grade" => matches!(val, "G0" | "G1" | "G2" | "G3"),
        "final" => matches!(val, "true" | "false"),
        "approver" => {
            val.eq_ignore_ascii_case("self")
                || val.eq_ignore_ascii_case("sponsor")
                || val.eq_ignore_ascii_case("admin")
                || val.eq_ignore_ascii_case("quorum")
        }
        "on_loss" => {
            val.eq_ignore_ascii_case("allow")
                || val.eq_ignore_ascii_case("step-up")
                || val.eq_ignore_ascii_case("fail-closed")
                || val.eq_ignore_ascii_case("block")
        }
        _ => true,
    }
}

fn strip_cedar_comments(source: &str) -> Option<String> {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            let _ = chars.next();
            for nc in chars.by_ref() {
                if nc == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            let mut closed = false;
            while let Some(bc) = chars.next() {
                if bc == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    closed = true;
                    break;
                }
                if bc == '\n' {
                    out.push('\n');
                }
            }
            if !closed {
                return None;
            }
            out.push(' ');
            continue;
        }
        out.push(ch);
    }
    if in_string || escaped {
        return None;
    }
    Some(out)
}

fn find_policy_keyword_idx(cleaned: &str) -> Option<usize> {
    let bytes = cleaned.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
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
        let prev_ok = i == 0
            || bytes
                .get(i.saturating_sub(1))
                .is_some_and(|c| !is_ident_byte(*c));
        if prev_ok {
            for kw in ["forbid", "permit"] {
                let end = i.saturating_add(kw.len());
                if cleaned.get(i..end) == Some(kw)
                    && bytes
                        .get(end)
                        .is_some_and(|c| c.is_ascii_whitespace() || *c == b'(')
                {
                    return Some(i);
                }
            }
        }
        i = i.saturating_add(1);
    }
    None
}

fn parse_strict_annotations(prefix: &str) -> Option<Vec<(String, String)>> {
    let bytes = prefix.as_bytes();
    let mut i: usize = 0;
    let mut anns = Vec::new();
    while i < bytes.len() {
        while let Some(&b) = bytes.get(i) {
            if b.is_ascii_whitespace() {
                i = i.saturating_add(1);
            } else {
                break;
            }
        }
        let Some(&b) = bytes.get(i) else {
            break;
        };
        if b != b'@' {
            return None;
        }
        i = i.saturating_add(1);
        let name_start = i;
        while let Some(&c) = bytes.get(i) {
            if is_ident_byte(c) {
                i = i.saturating_add(1);
            } else {
                break;
            }
        }
        let name = prefix.get(name_start..i)?.to_string();
        if name.is_empty() {
            return None;
        }
        i = skip_ws_bytes(bytes, i);
        if bytes.get(i) != Some(&b'(') {
            return None;
        }
        i = skip_ws_bytes(bytes, i.saturating_add(1));
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        i = i.saturating_add(1);
        let mut val = String::new();
        let mut esc = false;
        let mut closed = false;
        while let Some(rest) = prefix.get(i..) {
            let Some(ch) = rest.chars().next() else {
                break;
            };
            i = i.saturating_add(ch.len_utf8());
            if esc {
                esc = false;
                val.push(ch);
                continue;
            }
            if ch == '\\' {
                esc = true;
                continue;
            }
            if ch == '"' {
                closed = true;
                break;
            }
            val.push(ch);
        }
        if !closed {
            return None;
        }
        i = skip_ws_bytes(bytes, i);
        if bytes.get(i) != Some(&b')') {
            return None;
        }
        i = i.saturating_add(1);
        anns.push((name, val));
    }
    Some(anns)
}

fn contains_unquoted_keyword(src: &str, kw: &str) -> bool {
    let bytes = src.as_bytes();
    let mut i: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
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
        let prev_ok = i == 0
            || bytes
                .get(i.saturating_sub(1))
                .is_some_and(|c| !is_ident_byte(*c));
        let end = i.saturating_add(kw.len());
        if prev_ok
            && src.get(i..end) == Some(kw)
            && bytes
                .get(end)
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'(')
        {
            return true;
        }
        i = i.saturating_add(1);
    }
    false
}

fn skip_ws_bytes(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&b) = bytes.get(i) {
        if b.is_ascii_whitespace() {
            i = i.saturating_add(1);
        } else {
            break;
        }
    }
    i
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
