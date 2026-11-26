// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Enum (`SL04`, `SL07`) and `options.proto` class enum validation rules.

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::{
    EnumDescriptor, FileDescriptor, ResolvedOptionsExtension, read_string_option,
};

use crate::descriptor_env::lint_err;
use crate::schema_compare::EnumValueSnapshot;
use crate::{LintError, LintFinding};

pub(crate) const OPEN_ENUM_NAMES: &[&str] = &[
    "ArtifactKind",
    "AttributionEvidenceKind",
    "ChannelKind",
    "EvidenceKind",
    "ExportDialect",
    "FindingClass",
    "GapReason",
    "HashAlgorithm",
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_enum_sl04_sl07(
    file_name: &str,
    enum_path: &str,
    enm: &EnumDescriptor,
    ext: &ResolvedOptionsExtension,
    is_class_enum: bool,
    options_class_wire_names: &mut BTreeSet<String>,
    out_enums: &mut Vec<EnumValueSnapshot>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let mut seen_wire = BTreeSet::new();
    let mut seen_numbers = BTreeSet::new();
    let is_closed = !OPEN_ENUM_NAMES.contains(&enm.name.as_str());
    let mut has_zero = false;
    let mut has_open_other = false;
    for val in &enm.values {
        let val_path = format!("{enum_path}.{}", val.name);
        if !seen_numbers.insert(val.number) {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                &format!("SL04: duplicate enum tag number {}", val.number),
            ));
        }
        let w = read_string_option(&val.raw_options, ext.enum_wire_name_tag).map_err(|e| {
            LintError::ProtoViolation {
                file: file_name.into(),
                detail: e.to_string(),
            }
        })?;
        if val.number == 0 {
            has_zero = true;
            if !val.name.ends_with("_UNSPECIFIED") {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &val_path,
                    "SL04: zero enum value must end with _UNSPECIFIED",
                ));
            }
            if w.is_some() {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &val_path,
                    "SL04: zero value cannot carry wire_name",
                ));
            }
            out_enums.push(EnumValueSnapshot {
                path: val_path,
                number: 0,
                wire_name: String::new(),
            });
            continue;
        }
        let Some(wire_name) = w.filter(|s| !s.is_empty()) else {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                "SL04: non-zero enum value missing (wire_name)",
            ));
            continue;
        };
        if !wire_name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        }) {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                &format!("SL04: wire_name `{wire_name}` must match [a-z0-9_.-]+"),
            ));
        }
        if !seen_wire.insert(wire_name.clone()) {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                &format!("SL04: duplicate wire_name `{wire_name}`"),
            ));
        }
        if is_class_enum {
            if enm.name == "DataClass" && wire_name != "content" {
                options_class_wire_names.insert(wire_name.clone());
            } else if enm.name == "ContentKind" {
                options_class_wire_names.insert(format!("content.{wire_name}"));
            }
        }
        if is_closed && (val.name.ends_with("_OTHER") || val.number == 99 || wire_name == "other") {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                "SL07: closed enum cannot declare _OTHER = 99",
            ));
        } else if (val.name.ends_with("_OTHER") || wire_name == "other") && val.number != 99 {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                "SL07: open enum _OTHER must use number 99",
            ));
        } else if val.number == 99 && (!val.name.ends_with("_OTHER") || wire_name != "other") {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &val_path,
                "SL07: number 99 must be *_OTHER with wire_name \"other\"",
            ));
        } else if !is_closed
            && val.number == 99
            && val.name.ends_with("_OTHER")
            && wire_name == "other"
        {
            has_open_other = true;
        }
        out_enums.push(EnumValueSnapshot {
            path: val_path,
            number: val.number,
            wire_name,
        });
    }
    if !has_zero {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            enum_path,
            "SL04: proto3 enum must declare a zero value",
        ));
    }
    if !is_closed && !has_open_other {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            enum_path,
            "SL07: open enum must declare *_OTHER = 99 with wire_name \"other\"",
        ));
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub(crate) fn extract_options_enums(
    options_file: &FileDescriptor,
    ext: &ResolvedOptionsExtension,
    findings: &mut Vec<LintFinding>,
) -> Result<
    (
        BTreeMap<i32, String>,
        BTreeMap<i32, String>,
        BTreeMap<String, i32>,
        BTreeMap<String, i32>,
    ),
    LintError,
> {
    let mut dc_n2w = BTreeMap::new();
    let mut ck_n2w = BTreeMap::new();
    let mut dc_w2n = BTreeMap::new();
    let mut ck_w2n = BTreeMap::new();

    if let Some(dc) = options_file.enums.iter().find(|e| e.name == "DataClass") {
        load_options_enum(
            options_file,
            ext,
            dc,
            &[
                ("DATA_CLASS_IDENTIFIER", "identifier"),
                ("DATA_CLASS_STRUCTURAL", "structural"),
                ("DATA_CLASS_DERIVED", "derived"),
                ("DATA_CLASS_CONTENT", "content"),
            ],
            &mut dc_n2w,
            &mut dc_w2n,
            findings,
        )?;
    } else {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &options_file.name,
            "SL10: options.proto missing DataClass enum",
        ));
    }
    if let Some(ck) = options_file.enums.iter().find(|e| e.name == "ContentKind") {
        load_options_enum(
            options_file,
            ext,
            ck,
            &[
                ("CONTENT_KIND_ARGUMENT", "argument"),
                ("CONTENT_KIND_BODY", "body"),
            ],
            &mut ck_n2w,
            &mut ck_w2n,
            findings,
        )?;
    } else {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &options_file.name,
            "SL10: options.proto missing ContentKind enum",
        ));
    }
    Ok((dc_n2w, ck_n2w, dc_w2n, ck_w2n))
}

fn load_options_enum(
    options_file: &FileDescriptor,
    ext: &ResolvedOptionsExtension,
    enm: &EnumDescriptor,
    expected_pairs: &[(&str, &str)],
    n2w: &mut BTreeMap<i32, String>,
    w2n: &mut BTreeMap<String, i32>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    for val in &enm.values {
        if val.number == 0 {
            continue;
        }
        if val.number < 0 {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &options_file.name,
                &format!("R11: negative enum tag on `{}.{}`", enm.name, val.name),
            ));
            continue;
        }
        let wire = read_string_option(&val.raw_options, ext.enum_wire_name_tag)
            .map_err(|e| LintError::ForeignDescriptorViolation {
                file: options_file.name.clone(),
                detail: e.to_string(),
            })?
            .unwrap_or_default();
        let Some((_, expected_w)) = expected_pairs.iter().find(|(n, _)| *n == val.name) else {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &options_file.name,
                &format!("R11: unexpected enum variant `{}.{}`", enm.name, val.name),
            ));
            continue;
        };
        if wire != *expected_w {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &options_file.name,
                &format!(
                    "R11: `{}` must carry wire_name \"{expected_w}\", found `{wire}`",
                    val.name
                ),
            ));
        }
        if n2w.insert(val.number, wire.clone()).is_some()
            || (!wire.is_empty() && w2n.insert(wire, val.number).is_some())
        {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &options_file.name,
                &format!(
                    "R11: duplicate tag or wire_name on `{}.{}`",
                    enm.name, val.name
                ),
            ));
        }
    }
    for (req_name, req_wire) in expected_pairs {
        if !enm
            .values
            .iter()
            .any(|v| v.name == *req_name && v.number > 0)
        {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &options_file.name,
                &format!(
                    "R11: `{}` missing required `{req_name}` ({req_wire})",
                    enm.name
                ),
            ));
        }
    }
    Ok(())
}
