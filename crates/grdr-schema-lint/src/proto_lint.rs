// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Protobuf schema and data_class annotation linter (`docs/design/04`).

use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    LintDomain, LintError, LintFinding, LintSeverity, MAX_LINT_DIR_DEPTH, MAX_LINT_FILE_BYTES,
    read_bounded_regular_file,
};

const REQUIRED_DATA_CLASS_MESSAGE_FIELDS: &[(&str, &str)] = &[
    ("ActionAttempt", "target"),
    ("DecisionReceipt", "target"),
    ("ApprovalRequest", "target"),
    ("Finding", "target"),
    ("EvaluateRequest", "target"),
    ("ReplaySample", "target"),
];

const VALID_DATA_CLASSES: &[&str] = &[
    "DATA_CLASS_PUBLIC",
    "DATA_CLASS_METADATA",
    "DATA_CLASS_IDENTIFIER",
    "DATA_CLASS_PSEUDONYM",
    "DATA_CLASS_CONTENT",
    "DATA_CLASS_SECRET",
];

pub fn lint_proto_dir(dir: &Path, findings: &mut Vec<LintFinding>) -> Result<usize, LintError> {
    let dir_meta = fs::symlink_metadata(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: "proto root must be a real non-symlink directory".into(),
        });
    }
    let canon_root = fs::canonicalize(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;

    let mut proto_files = Vec::new();
    collect_proto_files(&canon_root, &canon_root, 0, &mut proto_files)?;
    proto_files.sort();

    for path in &proto_files {
        let content = read_bounded_regular_file(&canon_root, path, MAX_LINT_FILE_BYTES)?;
        let display = path.display().to_string();
        lint_proto_source(&display, &content, findings);
    }
    Ok(proto_files.len())
}

pub fn lint_proto_source(file_label: &str, source: &str, findings: &mut Vec<LintFinding>) {
    let lines = strip_proto_comments(source);
    let has_proto3 = lines.iter().any(|l| l.trim() == r#"syntax = "proto3";"#);
    if !has_proto3 {
        findings.push(proto_err(
            file_label,
            "missing `syntax = \"proto3\";` declaration",
        ));
    }

    let has_grdr_pkg = lines.iter().any(|l| l.trim().starts_with("package grdr."));
    if !has_grdr_pkg {
        findings.push(proto_err(
            file_label,
            "missing `package grdr.*;` declaration",
        ));
    }

    let mut scope_stack: Vec<String> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx.saturating_add(1);
        for segment in split_proto_segments(line) {
            let code = segment.trim();
            if code.is_empty() {
                continue;
            }
            if code == "}" {
                let _ = scope_stack.pop();
                continue;
            }
            if let Some(name) = parse_block_header(code, "message ") {
                scope_stack.push(format!("msg:{name}"));
                continue;
            }
            if parse_block_header(code, "oneof ").is_some()
                || parse_block_header(code, "enum ").is_some()
                || parse_block_header(code, "service ").is_some()
            {
                let kind = code.split_whitespace().next().unwrap_or("block");
                scope_stack.push(format!("sub:{kind}"));
                continue;
            }
            if code.ends_with('{') {
                scope_stack.push("sub:anon".into());
                continue;
            }

            let target = format!("{file_label}:{line_no}");
            check_proto_statement(&target, code, &scope_stack, findings);
        }
    }
}

fn check_proto_statement(
    target: &str,
    code: &str,
    scope_stack: &[String],
    findings: &mut Vec<LintFinding>,
) {
    if code.contains("google.protobuf.Any") || code.contains("google.protobuf.Struct") {
        findings.push(proto_err(
            target,
            "forbidden `google.protobuf.Any` or `google.protobuf.Struct` field",
        ));
    }

    let tokens: Vec<&str> = code.split_whitespace().collect();
    let compact: String = code.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let has_float_type = tokens.iter().any(|tok| matches!(*tok, "float" | "double"))
        || compact.contains(",float>")
        || compact.contains(",double>");
    if code.contains("policy_readable") && has_float_type {
        findings.push(proto_err(
            target,
            "floating-point fields cannot carry `policy_readable`",
        ));
    }

    if code.contains("data_class)") {
        check_data_class_annotation(target, code, findings);
    }

    let active_message = scope_stack
        .iter()
        .rev()
        .find_map(|s| s.strip_prefix("msg:"));
    if let Some(msg_name) = active_message {
        for (req_msg, req_field) in REQUIRED_DATA_CLASS_MESSAGE_FIELDS {
            if msg_name == *req_msg
                && is_field_decl_named(code, req_field)
                && !code.contains("data_class)")
            {
                findings.push(proto_err(
                    target,
                    &format!("sensitive field `{req_msg}.{req_field}` must declare `data_class`"),
                ));
            }
        }
    }
}

fn check_data_class_annotation(target: &str, code: &str, findings: &mut Vec<LintFinding>) {
    if code.contains("DATA_CLASS_UNSPECIFIED") {
        findings.push(proto_err(
            target,
            "`data_class` must never be `DATA_CLASS_UNSPECIFIED`",
        ));
        return;
    }
    if !VALID_DATA_CLASSES.iter().any(|dc| code.contains(dc)) {
        findings.push(proto_err(
            target,
            "unrecognized `DATA_CLASS_*` value on field option",
        ));
    }
}

fn proto_err(target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0002".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}

fn is_field_decl_named(code: &str, field_name: &str) -> bool {
    let needle = format!(" {field_name} ");
    let needle_eq = format!(" {field_name}=");
    (code.contains(&needle) || code.contains(&needle_eq)) && code.contains('=')
}

fn parse_block_header<'a>(code: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = code.strip_prefix(prefix)?;
    if !code.ends_with('{') {
        return None;
    }
    let name = rest
        .split(|c: char| c.is_whitespace() || c == '{')
        .next()
        .unwrap_or("")
        .trim();
    if name.is_empty() { None } else { Some(name) }
}

fn split_proto_segments(line: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            cur.push(ch);
            continue;
        }
        if !in_string && (ch == '{' || ch == '}' || ch == ';') {
            if ch == '{' {
                cur.push('{');
                segments.push(std::mem::take(&mut cur));
            } else if ch == ';' {
                cur.push(';');
                if !cur.trim().is_empty() {
                    segments.push(std::mem::take(&mut cur));
                }
            } else {
                if !cur.trim().is_empty() {
                    segments.push(std::mem::take(&mut cur));
                }
                segments.push("}".into());
            }
            continue;
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        segments.push(cur);
    }
    segments
}

fn strip_proto_comments(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw_line in source.lines() {
        let mut line = String::new();
        let mut in_string = false;
        let mut escaped = false;
        let mut chars = raw_line.chars().peekable();
        while let Some(ch) = chars.next() {
            if in_block {
                if ch == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    in_block = false;
                }
                continue;
            }
            if escaped {
                line.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' && in_string {
                line.push(ch);
                escaped = true;
                continue;
            }
            if ch == '"' {
                in_string = !in_string;
                line.push(ch);
                continue;
            }
            if !in_string && ch == '/' {
                if chars.peek() == Some(&'/') {
                    break;
                }
                if chars.peek() == Some(&'*') {
                    let _ = chars.next();
                    in_block = true;
                    line.push(' ');
                    continue;
                }
            }
            line.push(ch);
        }
        out.push(line);
    }
    out
}

fn collect_proto_files(
    canon_root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
) -> Result<(), LintError> {
    if depth > MAX_LINT_DIR_DEPTH {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: format!("proto directory recursion exceeded depth limit {MAX_LINT_DIR_DEPTH}"),
        });
    }
    let entries = fs::read_dir(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LintError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let ft = entry.file_type().map_err(|e| LintError::Io {
            path: entry.path().display().to_string(),
            detail: e.to_string(),
        })?;
        let path = entry.path();
        if ft.is_symlink() {
            return Err(LintError::Io {
                path: path.display().to_string(),
                detail: "symlinks are forbidden inside proto schema directories".into(),
            });
        }
        if ft.is_dir() {
            let canon_sub = fs::canonicalize(&path).map_err(|e| LintError::Io {
                path: path.display().to_string(),
                detail: e.to_string(),
            })?;
            if !canon_sub.starts_with(canon_root) {
                return Err(LintError::Io {
                    path: path.display().to_string(),
                    detail: "subdirectory escapes proto root".into(),
                });
            }
            collect_proto_files(canon_root, &canon_sub, depth.saturating_add(1), out)?;
        } else if ft.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto") {
            out.push(path);
        }
    }
    Ok(())
}
