// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Protobuf `.proto` source linter and disk-to-descriptor parity validator (`docs/design/04`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_proto::descriptor::{DescriptorSet, ResolvedOptionsExtension};

use crate::proto_option_lex::{
    extract_enum_opt, extract_raw_option, find_char_outside_quotes, remove_all_ws,
};
use crate::proto_source_parity::verify_source_parity;
use crate::{
    LintDomain, LintError, LintFinding, LintSeverity, MAX_LINT_DIR_DEPTH, MAX_LINT_FILE_BYTES,
    canonicalize_real_dir, is_symlink_or_reparse, read_bounded_regular_file, reject_symlinks_under,
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
    "DATA_CLASS_IDENTIFIER",
    "DATA_CLASS_STRUCTURAL",
    "DATA_CLASS_DERIVED",
    "DATA_CLASS_CONTENT",
];

pub fn lint_proto_dir(dir: &Path, findings: &mut Vec<LintFinding>) -> Result<usize, LintError> {
    lint_proto_dir_with_namespace(dir, "grdr", findings)
}

pub fn lint_proto_dir_with_namespace(
    dir: &Path,
    namespace: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<usize, LintError> {
    if !grdr_schema::is_valid_brand_namespace(namespace) {
        return Err(LintError::ProtoViolation {
            file: dir.display().to_string(),
            detail: format!("invalid brand namespace `{namespace}`"),
        });
    }
    let canon_dir = canonicalize_real_dir(dir, "proto root")?;
    lint_proto_dir_under(&canon_dir, &canon_dir, namespace, findings)
}

pub(crate) fn lint_proto_dir_under(
    canon_root: &Path,
    dir: &Path,
    namespace: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<usize, LintError> {
    let checked = reject_symlinks_under(canon_root, dir, true)?;
    let canon_proto = canonicalize_real_dir(&checked, "proto root")?;
    if !canon_proto.starts_with(canon_root) {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: "proto root escapes repository root".into(),
        });
    }

    let mut proto_files = Vec::new();
    collect_proto_files(&canon_proto, &canon_proto, 0, &mut proto_files)?;
    proto_files.sort();

    for path in &proto_files {
        let content = read_bounded_regular_file(canon_root, path, MAX_LINT_FILE_BYTES)?;
        let display = path.display().to_string();
        lint_proto_source_with_namespace(&display, &content, namespace, findings);
    }
    Ok(proto_files.len())
}

pub fn lint_proto_source(file_label: &str, source: &str, findings: &mut Vec<LintFinding>) {
    lint_proto_source_with_namespace(file_label, source, "grdr", findings);
}

pub fn lint_proto_source_with_namespace(
    file_label: &str,
    source: &str,
    namespace: &str,
    findings: &mut Vec<LintFinding>,
) {
    let lines = strip_proto_comments(source);
    let stmts = buffer_proto_statements(&lines);

    let has_proto3 = stmts.iter().any(|(_, s)| {
        let c = remove_all_ws(s);
        c == "syntax=\"proto3\";" || c == "syntax='proto3';"
    });
    if !has_proto3 {
        findings.push(proto_err(
            file_label,
            "missing `syntax = \"proto3\";` declaration",
        ));
    }

    let pkg_prefix = format!("{namespace}.");
    let has_ns_pkg = stmts.iter().any(|(_, s)| {
        let trimmed = s.trim_start();
        let Some(rest) = trimmed.strip_prefix("package") else {
            return false;
        };
        if !rest.chars().next().is_some_and(|c| c.is_ascii_whitespace()) {
            return false;
        }
        let Some(inner) = remove_all_ws(rest).strip_suffix(';').map(str::to_owned) else {
            return false;
        };
        inner
            .strip_prefix(&pkg_prefix)
            .is_some_and(|tail| !tail.is_empty() && !tail.ends_with('.'))
    });
    if !has_ns_pkg {
        findings.push(proto_err(
            file_label,
            &format!("missing `package {namespace}.*;` declaration"),
        ));
    }

    let mut scope_stack: Vec<String> = Vec::new();
    for (line_no, code) in &stmts {
        if code == "}" {
            let _ = scope_stack.pop();
            continue;
        }
        if let Some(name) = parse_block_header(code, "message") {
            scope_stack.push(format!("msg:{name}"));
            continue;
        }
        if parse_block_header(code, "oneof").is_some() {
            scope_stack.push("sub:oneof".into());
            continue;
        }
        if parse_block_header(code, "enum").is_some()
            || parse_block_header(code, "service").is_some()
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_proto_sources_against_descriptors(
    canon_proto: &Path,
    set: &DescriptorSet,
    namespace: &str,
    ext: &ResolvedOptionsExtension,
    dc_nums: &BTreeMap<String, i32>,
    ck_nums: &BTreeMap<String, i32>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let mut proto_files = Vec::new();
    collect_proto_files(canon_proto, canon_proto, 0, &mut proto_files)?;
    proto_files.sort();

    let by_name: BTreeMap<&str, &grdr_proto::descriptor::FileDescriptor> =
        set.files.iter().map(|f| (f.name.as_str(), f)).collect();
    let ns_prefix = format!("{namespace}/");

    for abs in &proto_files {
        let Ok(rel_path) = abs.strip_prefix(canon_proto) else {
            continue;
        };
        let rel = rel_path.to_string_lossy().replace('\\', "/");
        if !rel.starts_with(&ns_prefix) {
            findings.push(proto_err(
                &rel,
                &format!("SL09: unexpected `.proto` file `{rel}` outside namespace `{ns_prefix}`"),
            ));
            continue;
        }
        let Some(desc) = by_name.get(rel.as_str()) else {
            continue;
        };
        let source = read_bounded_regular_file(canon_proto, abs, MAX_LINT_FILE_BYTES)?;
        let lines = strip_proto_comments(&source);
        let stmts = buffer_proto_statements(&lines);
        let schema = crate::proto_source_parity::ParitySchema {
            set,
            ext,
            dc_nums,
            ck_nums,
        };
        verify_source_parity(&rel, &stmts, desc, &schema, findings)?;
    }
    Ok(())
}

fn buffer_proto_statements(lines: &[String]) -> Vec<(usize, String)> {
    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut start_line = 1usize;
    let mut in_string = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut bracket_depth: usize = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx.saturating_add(1);
        for ch in line.chars() {
            if cur.trim().is_empty() && !ch.is_whitespace() {
                start_line = line_no;
            }
            if escaped {
                cur.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' && (in_string || in_single) {
                cur.push(ch);
                escaped = true;
                continue;
            }
            if ch == '"' && !in_single {
                in_string = !in_string;
                cur.push(ch);
                continue;
            }
            if ch == '\'' && !in_string {
                in_single = !in_single;
                cur.push(ch);
                continue;
            }
            if !in_string && !in_single {
                if ch == '[' {
                    bracket_depth = bracket_depth.saturating_add(1);
                } else if ch == ']' {
                    bracket_depth = bracket_depth.saturating_sub(1);
                } else if bracket_depth == 0 && (ch == '{' || ch == '}' || ch == ';') {
                    if ch == '{' {
                        cur.push('{');
                        stmts.push((start_line, cur.trim().to_owned()));
                        cur.clear();
                    } else if ch == ';' {
                        cur.push(';');
                        let trimmed = cur.trim().to_owned();
                        if !trimmed.is_empty() {
                            stmts.push((start_line, trimmed));
                        }
                        cur.clear();
                    } else {
                        let before = cur.trim().to_owned();
                        if !before.is_empty() {
                            stmts.push((start_line, before));
                        }
                        stmts.push((line_no, "}".into()));
                        cur.clear();
                    }
                    continue;
                }
            }
            cur.push(ch);
        }
        if !cur.trim().is_empty() && !cur.ends_with(' ') {
            cur.push(' ');
        }
    }
    if !cur.trim().is_empty() {
        stmts.push((start_line, cur.trim().to_owned()));
    }
    stmts
}

fn check_proto_statement(
    target: &str,
    code: &str,
    scope_stack: &[String],
    findings: &mut Vec<LintFinding>,
) {
    let compact = remove_all_ws(code);
    if compact.contains("google.protobuf.Any")
        || compact.contains("google.protobuf.Struct")
        || compact.contains("google.protobuf.Value")
        || compact.contains("google.protobuf.ListValue")
    {
        findings.push(proto_err(
            target,
            "forbidden `google.protobuf.Any`, `Struct`, `Value`, or `ListValue` field",
        ));
    }

    let opts_slice = find_char_outside_quotes(code, '[')
        .and_then(|idx| code.get(idx..))
        .unwrap_or("");
    let tokens: Vec<&str> = code.split_whitespace().collect();
    let has_float_type = tokens.iter().any(|tok| matches!(*tok, "float" | "double"))
        || compact.contains(",float>")
        || compact.contains(",double>");
    if extract_raw_option(opts_slice, "policy_readable", None).is_some() && has_float_type {
        findings.push(proto_err(
            target,
            "floating-point fields cannot carry `policy_readable`",
        ));
    }

    if extract_raw_option(opts_slice, "data_class", None).is_some() {
        check_data_class_annotation(target, opts_slice, findings);
    }

    let active_message = scope_stack
        .iter()
        .rev()
        .find_map(|s| s.strip_prefix("msg:"));
    if let Some(msg_name) = active_message {
        for (req_msg, req_field) in REQUIRED_DATA_CLASS_MESSAGE_FIELDS {
            if msg_name == *req_msg
                && is_field_decl_named(code, req_field)
                && extract_raw_option(opts_slice, "data_class", None).is_none()
            {
                findings.push(proto_err(
                    target,
                    &format!("sensitive field `{req_msg}.{req_field}` must declare `data_class`"),
                ));
            }
        }
    }
}

fn check_data_class_annotation(target: &str, opts_slice: &str, findings: &mut Vec<LintFinding>) {
    let tok = extract_enum_opt(opts_slice, "data_class", None);
    match tok.as_deref() {
        Some("DATA_CLASS_UNSPECIFIED") => findings.push(proto_err(
            target,
            "`data_class` must never be `DATA_CLASS_UNSPECIFIED`",
        )),
        Some(v) if VALID_DATA_CLASSES.contains(&v) => {}
        _ => findings.push(proto_err(
            target,
            "unrecognized `DATA_CLASS_*` value on field option",
        )),
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
    let Some((lhs, _)) = code.split_once('=') else {
        return false;
    };
    lhs.split_whitespace().last() == Some(field_name)
}

fn parse_block_header<'a>(code: &'a str, kw: &str) -> Option<&'a str> {
    let trimmed = code.trim();
    if !trimmed.ends_with('{') {
        return None;
    }
    let body = trimmed.strip_suffix('{')?.trim();
    let mut parts = body.split_whitespace();
    if parts.next()? != kw {
        return None;
    }
    parts.next().filter(|s| !s.is_empty())
}

fn strip_proto_comments(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw_line in source.lines() {
        let mut line = String::new();
        let mut in_string = false;
        let mut in_single = false;
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
            if ch == '\\' && (in_string || in_single) {
                line.push(ch);
                escaped = true;
                continue;
            }
            if ch == '"' && !in_single {
                in_string = !in_string;
                line.push(ch);
                continue;
            }
            if ch == '\'' && !in_string {
                in_single = !in_single;
                line.push(ch);
                continue;
            }
            if !in_string && !in_single && ch == '/' {
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

pub(crate) fn collect_proto_files(
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
        let meta = fs::symlink_metadata(&path).map_err(|e| LintError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        if ft.is_symlink() || is_symlink_or_reparse(&meta) {
            return Err(LintError::Io {
                path: path.display().to_string(),
                detail: "symlinks are forbidden inside proto schema directories".into(),
            });
        }
        if meta.is_dir() {
            let canon_sub = canonicalize_real_dir(&path, "proto subdirectory")?;
            if !canon_sub.starts_with(canon_root) {
                return Err(LintError::Io {
                    path: path.display().to_string(),
                    detail: "subdirectory escapes proto root".into(),
                });
            }
            collect_proto_files(canon_root, &canon_sub, depth.saturating_add(1), out)?;
        } else if meta.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto") {
            out.push(path);
        }
    }
    Ok(())
}
