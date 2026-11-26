// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Target-specific term formatting, field mapping, expansion, and escaping for L0 compilers.

use crate::detect::types::{DetectError, FieldPredicate, HostProfile, SigmaModifier};

use super::l0::L0Target;

pub(super) fn format_single_term(pred: &FieldPredicate, val: &str, target: L0Target) -> String {
    let f = if target == L0Target::Kql {
        map_field_kql(&pred.field)
    } else {
        pred.field.as_str()
    };
    let is_contains = pred.modifiers.contains(&SigmaModifier::Contains);
    let is_starts = pred.modifiers.contains(&SigmaModifier::StartsWith);
    let is_ends = pred.modifiers.contains(&SigmaModifier::EndsWith);
    let is_re = pred.modifiers.contains(&SigmaModifier::Re);
    let is_cidr = pred.modifiers.contains(&SigmaModifier::Cidr);
    let is_exists = pred.modifiers.contains(&SigmaModifier::Exists);
    let exists_want = !val.trim().eq_ignore_ascii_case("false");
    match target {
        L0Target::Kql => {
            let esc = escape_kql(val);
            if is_exists {
                if exists_want {
                    format!("isnotempty({f})")
                } else {
                    format!("isempty({f})")
                }
            } else if is_cidr {
                format!("ipv4_is_in_range({f}, '{esc}')")
            } else if is_re {
                format!("{f} matches regex '{esc}'")
            } else if is_contains {
                format!("{f} contains '{esc}'")
            } else if is_starts {
                format!("{f} startswith '{esc}'")
            } else if is_ends {
                format!("{f} endswith '{esc}'")
            } else {
                format!("{f} =~ '{esc}'")
            }
        }
        L0Target::LogScale => {
            let esc_dq = escape_dq(val);
            let esc_glob = escape_glob_dq(val);
            let esc_rx = escape_regex_slashes(val);
            if is_exists {
                if exists_want {
                    format!("{f}=*")
                } else {
                    format!("NOT ({f}=*)")
                }
            } else if is_cidr {
                format!("cidr({f}, subnet=\"{esc_dq}\")")
            } else if is_re {
                format!("{f}=/{esc_rx}/")
            } else if is_contains {
                format!("{f}=\"*{esc_glob}*\"")
            } else if is_starts {
                format!("{f}=\"{esc_glob}*\"")
            } else if is_ends {
                format!("{f}=\"*{esc_glob}\"")
            } else {
                format!("{f}=\"{esc_dq}\"")
            }
        }
        L0Target::Eql => {
            let esc = escape_dq(val);
            let esc_glob = escape_glob_dq(val);
            if is_exists {
                if exists_want {
                    format!("{f} != null")
                } else {
                    format!("{f} == null")
                }
            } else if is_cidr {
                format!("cidrmatch({f}, \"{esc}\")")
            } else if is_re {
                format!("{f} regex \"{esc}\"")
            } else if is_contains {
                format!("{f} : \"*{esc_glob}*\"")
            } else if is_starts {
                format!("{f} : \"{esc_glob}*\"")
            } else if is_ends {
                format!("{f} : \"*{esc_glob}\"")
            } else {
                format!("{f} == \"{esc}\"")
            }
        }
        L0Target::Xql => {
            let esc = escape_dq(val);
            let esc_rx_dq = escape_dq(&escape_regex_meta(val));
            if is_exists {
                if exists_want {
                    format!("{f} != null")
                } else {
                    format!("{f} = null")
                }
            } else if is_cidr {
                format!("incidr({f}, \"{esc}\")")
            } else if is_re {
                format!("{f} ~= \"{esc}\"")
            } else if is_contains {
                format!("{f} contains \"{esc}\"")
            } else if is_starts {
                format!("{f} ~= \"^{esc_rx_dq}\"")
            } else if is_ends {
                format!("{f} ~= \"{esc_rx_dq}$\"")
            } else {
                format!("{f} = \"{esc}\"")
            }
        }
        L0Target::Spl => {
            let esc = escape_dq(val);
            let esc_glob = escape_glob_dq(val);
            if is_exists {
                if exists_want {
                    format!("{f}=*")
                } else {
                    format!("NOT {f}=*")
                }
            } else if is_cidr {
                format!("cidrmatch(\"{esc}\", {f})")
            } else if is_re {
                format!("match({f}, \"{esc}\")")
            } else if is_contains {
                format!("{f}=\"*{esc_glob}*\"")
            } else if is_starts {
                format!("{f}=\"{esc_glob}*\"")
            } else if is_ends {
                format!("{f}=\"*{esc_glob}\"")
            } else {
                format!("{f}=\"{esc}\"")
            }
        }
        L0Target::GenericSigma => format!("{f}: \"{}\"", escape_dq(val)),
    }
}

pub(super) fn format_spl_where_term(pred: &FieldPredicate, val: &str) -> String {
    let f = pred.field.as_str();
    let esc = escape_dq(val);
    let esc_like = escape_dq(&escape_spl_like(val));
    let exists_want = !val.trim().eq_ignore_ascii_case("false");
    if pred.modifiers.contains(&SigmaModifier::Exists) {
        if exists_want {
            format!("isnotnull({f})")
        } else {
            format!("isnull({f})")
        }
    } else if pred.modifiers.contains(&SigmaModifier::Cidr) {
        format!("cidrmatch(\"{esc}\", {f})")
    } else if pred.modifiers.contains(&SigmaModifier::Re) {
        format!("match({f}, \"{esc}\")")
    } else if pred.modifiers.contains(&SigmaModifier::Contains) {
        format!("like({f}, \"%{esc_like}%\")")
    } else if pred.modifiers.contains(&SigmaModifier::StartsWith) {
        format!("like({f}, \"{esc_like}%\")")
    } else if pred.modifiers.contains(&SigmaModifier::EndsWith) {
        format!("like({f}, \"%{esc_like}\")")
    } else {
        format!("{f}==\"{esc}\"")
    }
}

fn escape_spl_like(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        if !ch.is_control() {
            out.push(ch);
        }
    }
    out
}

pub(super) fn expand_l0_values(
    pred: &FieldPredicate,
    host: &HostProfile,
) -> Result<Vec<String>, DetectError> {
    if !pred.modifiers.contains(&SigmaModifier::Expand) {
        return Ok(pred.values.clone());
    }
    let mut out = Vec::new();
    for v in &pred.values {
        let Some(var) = v.strip_prefix('%').and_then(|s| s.strip_suffix('%')) else {
            out.push(v.clone());
            continue;
        };
        let vals = host.expand_vars.get(var).ok_or_else(|| {
            DetectError::L0Unsupported(format!("unresolved L0 expand variable `%{var}%`"))
        })?;
        out.extend(vals.iter().cloned());
    }
    Ok(out)
}

pub(super) fn valid_field_ident(field: &str) -> bool {
    !field.is_empty()
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn map_field_kql(field: &str) -> &str {
    match field {
        "ParentImage" => "InitiatingProcessFileName",
        "Image" => "FileName",
        "CommandLine" => "ProcessCommandLine",
        "TargetFilename" | "target" => "FolderPath",
        "DestinationIp" => "RemoteIP",
        "DestinationHostname" => "RemoteUrl",
        "DestinationPort" => "RemotePort",
        other => other,
    }
}

fn escape_kql(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn escape_dq(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn escape_glob_dq(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '*' => out.push_str("\\*"),
            '?' => out.push_str("\\?"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

pub(super) fn escape_regex_slashes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut backslashes: usize = 0;
    for ch in raw.chars() {
        if ch == '\n' {
            out.push_str("\\n");
            backslashes = 0;
            continue;
        }
        if ch == '\r' {
            out.push_str("\\r");
            backslashes = 0;
            continue;
        }
        if ch.is_control() {
            backslashes = 0;
            continue;
        }
        if ch == '\\' {
            backslashes = backslashes.saturating_add(1);
            out.push(ch);
        } else if ch == '/' {
            if backslashes.is_multiple_of(2) {
                out.push('\\');
            }
            out.push('/');
            backslashes = 0;
        } else {
            backslashes = 0;
            out.push(ch);
        }
    }
    if !backslashes.is_multiple_of(2) {
        out.push('\\');
    }
    out
}

fn escape_regex_meta(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}
