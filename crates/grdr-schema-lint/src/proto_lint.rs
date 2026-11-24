// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Protobuf schema and data_class annotation linter (`docs/design/04`).

use std::fs;
use std::path::{Path, PathBuf};

use crate::{LintDomain, LintError, LintFinding, LintSeverity};

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
    if !dir.is_dir() {
        return Err(LintError::Io {
            path: dir.display().to_string(),
            detail: "proto directory not found".into(),
        });
    }
    let mut proto_files = Vec::new();
    collect_proto_files(dir, &mut proto_files)?;
    proto_files.sort();

    for path in &proto_files {
        let content = fs::read_to_string(path).map_err(|e| LintError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let display = path.display().to_string();
        lint_proto_source(&display, &content, findings);
    }
    Ok(proto_files.len())
}

pub fn lint_proto_source(file_label: &str, source: &str, findings: &mut Vec<LintFinding>) {
    let has_proto3 = source.lines().any(|l| l.trim() == r#"syntax = "proto3";"#);
    if !has_proto3 {
        findings.push(LintFinding {
            code: "GRDR-LINT-0002".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: file_label.into(),
            message: "missing `syntax = \"proto3\";` declaration".into(),
        });
    }

    let has_grdr_pkg = source
        .lines()
        .any(|l| l.trim().starts_with("package grdr."));
    if !has_grdr_pkg {
        findings.push(LintFinding {
            code: "GRDR-LINT-0002".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: file_label.into(),
            message: "missing `package grdr.*;` declaration".into(),
        });
    }

    let mut current_message: Option<String> = None;
    let mut brace_depth: usize = 0;

    for (idx, raw_line) in source.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        let code = raw_line.split("//").next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }

        if code.contains("google.protobuf.Any") || code.contains("google.protobuf.Struct") {
            findings.push(LintFinding {
                code: "GRDR-LINT-0002".into(),
                domain: LintDomain::Proto,
                severity: LintSeverity::Error,
                target: format!("{file_label}:{line_no}"),
                message: "forbidden `google.protobuf.Any` or `google.protobuf.Struct` field".into(),
            });
        }

        if code.contains("policy_readable")
            && (code.starts_with("float ") || code.starts_with("double "))
        {
            findings.push(LintFinding {
                code: "GRDR-LINT-0002".into(),
                domain: LintDomain::Proto,
                severity: LintSeverity::Error,
                target: format!("{file_label}:{line_no}"),
                message: "floating-point fields cannot carry `policy_readable`".into(),
            });
        }

        if let Some(rest) = code.strip_prefix("message ") {
            let name = rest
                .split(|c: char| c.is_whitespace() || c == '{')
                .next()
                .unwrap_or("")
                .trim();
            if brace_depth == 0 && !name.is_empty() {
                current_message = Some(name.to_owned());
            }
        }

        if code.contains("data_class)") {
            check_data_class_annotation(file_label, line_no, code, findings);
        }

        if let Some(msg_name) = current_message.as_deref()
            && brace_depth == 1
        {
            for (req_msg, req_field) in REQUIRED_DATA_CLASS_MESSAGE_FIELDS {
                if msg_name == *req_msg
                    && is_field_decl_named(code, req_field)
                    && !code.contains("data_class)")
                {
                    findings.push(LintFinding {
                        code: "GRDR-LINT-0002".into(),
                        domain: LintDomain::Proto,
                        severity: LintSeverity::Error,
                        target: format!("{file_label}:{line_no}"),
                        message: format!(
                            "sensitive field `{req_msg}.{req_field}` must declare `data_class`"
                        ),
                    });
                }
            }
        }

        let opens = code.chars().filter(|c| *c == '{').count();
        let closes = code.chars().filter(|c| *c == '}').count();
        brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
        if brace_depth == 0 {
            current_message = None;
        }
    }
}

fn check_data_class_annotation(
    file_label: &str,
    line_no: usize,
    code: &str,
    findings: &mut Vec<LintFinding>,
) {
    if code.contains("DATA_CLASS_UNSPECIFIED") {
        findings.push(LintFinding {
            code: "GRDR-LINT-0002".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: format!("{file_label}:{line_no}"),
            message: "`data_class` must never be `DATA_CLASS_UNSPECIFIED`".into(),
        });
        return;
    }
    let has_valid = VALID_DATA_CLASSES.iter().any(|dc| code.contains(dc));
    if !has_valid {
        findings.push(LintFinding {
            code: "GRDR-LINT-0002".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: format!("{file_label}:{line_no}"),
            message: "unrecognized `DATA_CLASS_*` value on field option".into(),
        });
    }
}

fn is_field_decl_named(code: &str, field_name: &str) -> bool {
    let needle = format!(" {field_name} ");
    let needle_eq = format!(" {field_name}=");
    (code.contains(&needle) || code.contains(&needle_eq)) && code.contains('=')
}

fn collect_proto_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), LintError> {
    let entries = fs::read_dir(dir).map_err(|e| LintError::Io {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LintError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_proto_files(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("proto") {
            out.push(path);
        }
    }
    Ok(())
}
