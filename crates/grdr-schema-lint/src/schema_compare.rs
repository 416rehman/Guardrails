// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Schema compatibility comparison (`SL12`, RFC 0006 R17) across field, level, and enum snapshots.

use std::collections::{BTreeMap, BTreeSet};

use crate::capture_toml::{CANONICAL_CLASSES, CaptureConfig, CaptureLevelRow};
pub use crate::reclass_toml::validate_reclassifications_entries;
use crate::reclass_toml::{ReclassKind, ReclassificationEntry};
use crate::{LintDomain, LintFinding, LintSeverity};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSnapshot {
    pub path: String,
    pub package: String,
    pub message: String,
    pub field: String,
    pub number: i32,
    pub data_class: String,
    pub content_kind: Option<String>,
    pub commitment_class: String,
    pub policy_readable: bool,
    pub sealable: bool,
    pub wire_type: i32,
    pub label: String,
    pub type_name: String,
    pub oneof_index: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumValueSnapshot {
    pub path: String,
    pub number: i32,
    pub wire_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaCompareReport {
    pub findings: Vec<LintFinding>,
}

#[allow(clippy::too_many_arguments)]
pub fn compare_schemas_sl12(
    base_fields: &[FieldSnapshot],
    head_fields: &[FieldSnapshot],
    base_enums: &[EnumValueSnapshot],
    head_enums: &[EnumValueSnapshot],
    base_capture: &CaptureConfig,
    head_capture: &CaptureConfig,
    base_reclass: &[ReclassificationEntry],
    head_reclass: &[ReclassificationEntry],
    accepted_rfcs: &BTreeSet<String>,
) -> SchemaCompareReport {
    let mut findings = Vec::new();
    validate_reclassifications_entries(head_reclass, &mut findings);
    if !head_reclass.starts_with(base_reclass) {
        findings.push(compare_err(
            "reclassifications.toml",
            "SL12: `reclassifications.toml` must be strictly append-only relative to base",
        ));
    }
    if base_capture.classes != head_capture.classes {
        findings.push(compare_err(
            "capture.toml",
            "SL12: editing commitment class set or order is forbidden",
        ));
    }
    if base_capture.default_level != head_capture.default_level {
        findings.push(compare_err(
            "capture.toml",
            "SL12: changing `capture.toml` default level is forbidden",
        ));
    }

    let head_map: BTreeMap<&str, &FieldSnapshot> =
        head_fields.iter().map(|f| (f.path.as_str(), f)).collect();
    let head_enum_map: BTreeMap<&str, &EnumValueSnapshot> =
        head_enums.iter().map(|e| (e.path.as_str(), e)).collect();

    for entry in head_reclass.iter().skip(base_reclass.len()) {
        if !accepted_rfcs.contains(&entry.rfc) {
            findings.push(compare_err(
                &entry.target,
                &format!("SL12: RFC `{}` is not listed as Accepted", entry.rfc),
            ));
        }
        if entry.kind == ReclassKind::Field
            && entry.to == "removed"
            && head_map.contains_key(entry.target.as_str())
        {
            findings.push(compare_err(
                &entry.target,
                "SL12: `to = \"removed\"` entry target still exists in head schema",
            ));
        }
        if let Some(ref succ) = entry.successor
            && !head_map.contains_key(succ.as_str())
        {
            findings.push(compare_err(
                &entry.target,
                &format!("SL12: successor `{succ}` does not exist in head schema"),
            ));
        }
    }

    check_field_transitions(
        base_fields,
        head_fields,
        &head_map,
        base_reclass,
        head_reclass,
        &mut findings,
    );
    check_level_transitions(
        base_capture,
        head_capture,
        base_reclass,
        head_reclass,
        &mut findings,
    );
    check_enum_transitions(
        base_enums,
        head_enums,
        &head_enum_map,
        base_reclass,
        head_reclass,
        &mut findings,
    );

    SchemaCompareReport { findings }
}

fn check_field_transitions(
    base_fields: &[FieldSnapshot],
    head_fields: &[FieldSnapshot],
    head_map: &BTreeMap<&str, &FieldSnapshot>,
    base_reclass: &[ReclassificationEntry],
    head_reclass: &[ReclassificationEntry],
    findings: &mut Vec<LintFinding>,
) {
    let added = head_reclass.get(base_reclass.len()..).unwrap_or(&[]);
    let mut base_tags: BTreeMap<(&str, &str, i32), &str> = BTreeMap::new();
    for bf in base_fields {
        base_tags.insert(
            (bf.package.as_str(), bf.message.as_str(), bf.number),
            bf.field.as_str(),
        );
    }
    for hf in head_fields {
        if let Some(&prev_name) =
            base_tags.get(&(hf.package.as_str(), hf.message.as_str(), hf.number))
            && prev_name != hf.field
        {
            findings.push(compare_err(
                &hf.path,
                &format!(
                    "SL12: wire tag {} in `{}.{}` previously belonged to `{prev_name}` and cannot be reused",
                    hf.number, hf.package, hf.message
                ),
            ));
        }
    }

    for bf in base_fields {
        match head_map.get(bf.path.as_str()) {
            None => {
                let covered = added.iter().any(|e| {
                    let seal_ok = if bf.sealable {
                        e.from_sealable == Some(true) && e.to_sealable.is_none_or(|v| !v)
                    } else {
                        e.from_sealable.is_none_or(|v| !v) && e.to_sealable.is_none_or(|v| !v)
                    };
                    e.kind == ReclassKind::Field
                        && e.target == bf.path
                        && e.from == bf.commitment_class
                        && e.to == "removed"
                        && e.successor.as_deref().is_some_and(|s| !s.is_empty())
                        && seal_ok
                        && e.from_policy_readable
                            .is_none_or(|v| v == bf.policy_readable)
                });
                if !covered {
                    findings.push(compare_err(
                        &bf.path,
                        "SL12: removed field requires append-only `[[field]]` entry with `to = \"removed\"` and `successor`",
                    ));
                }
            }
            Some(hf) => {
                if bf.wire_type != hf.wire_type
                    || bf.number != hf.number
                    || bf.label != hf.label
                    || bf.type_name != hf.type_name
                    || bf.oneof_index != hf.oneof_index
                {
                    findings.push(compare_err(
                        &bf.path,
                        "SL12: incompatible wire number, label, type, or oneof change on existing field",
                    ));
                }
                if bf.commitment_class != hf.commitment_class
                    || bf.sealable != hf.sealable
                    || bf.policy_readable != hf.policy_readable
                {
                    let covered = added.iter().any(|e| {
                        let seal_ok = if bf.sealable != hf.sealable {
                            e.from_sealable == Some(bf.sealable)
                                && e.to_sealable == Some(hf.sealable)
                        } else {
                            e.from_sealable.is_none_or(|v| v == bf.sealable)
                                && e.from_sealable == e.to_sealable
                        };
                        let pr_ok = if bf.policy_readable != hf.policy_readable {
                            e.from_policy_readable == Some(bf.policy_readable)
                                && e.to_policy_readable == Some(hf.policy_readable)
                        } else {
                            e.from_policy_readable
                                .is_none_or(|v| v == bf.policy_readable)
                                && e.from_policy_readable == e.to_policy_readable
                        };
                        e.kind == ReclassKind::Field
                            && e.target == bf.path
                            && e.from == bf.commitment_class
                            && e.to == hf.commitment_class
                            && seal_ok
                            && pr_ok
                    });
                    if !covered {
                        findings.push(compare_err(
                            &bf.path,
                            &format!(
                                "SL12: reclassification `{}` -> `{}` (or sealable/policy_readable shift) requires explicit `[[field]]` entry",
                                bf.commitment_class, hf.commitment_class
                            ),
                        ));
                    }
                }
            }
        }
    }
    for retired in base_reclass.iter().filter(|r| r.to == "removed") {
        if head_map.contains_key(retired.target.as_str()) {
            findings.push(compare_err(
                &retired.target,
                "SL12: retired field path cannot be reintroduced",
            ));
        }
    }
}

fn check_level_transitions(
    base_capture: &CaptureConfig,
    head_capture: &CaptureConfig,
    base_reclass: &[ReclassificationEntry],
    head_reclass: &[ReclassificationEntry],
    findings: &mut Vec<LintFinding>,
) {
    let added = head_reclass.get(base_reclass.len()..).unwrap_or(&[]);
    let base_names: BTreeSet<&str> = base_capture
        .levels
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    let head_levels: BTreeMap<&str, &CaptureLevelRow> = head_capture
        .levels
        .iter()
        .map(|l| (l.name.as_str(), l))
        .collect();
    for (idx, bl) in base_capture.levels.iter().enumerate() {
        let Some(hl) = head_levels.get(bl.name.as_str()) else {
            findings.push(compare_err(
                &bl.name,
                "SL12: existing capture level cannot be removed",
            ));
            continue;
        };
        if head_capture.levels.get(idx).map(|l| l.name.as_str()) != Some(bl.name.as_str()) {
            findings.push(compare_err(
                &bl.name,
                "SL12: capture levels cannot be reordered",
            ));
        }
        if bl.rank != hl.rank {
            findings.push(compare_err(
                &bl.name,
                "SL12: capture level rank cannot change",
            ));
        }
        for cls in CANONICAL_CLASSES {
            let b_disp = bl.dispositions.get(*cls).map(String::as_str).unwrap_or("");
            let h_disp = hl.dispositions.get(*cls).map(String::as_str).unwrap_or("");
            if b_disp != h_disp {
                let target_key = format!("{}:{cls}", bl.name);
                let covered = added.iter().any(|e| {
                    e.kind == ReclassKind::Level
                        && e.target == target_key
                        && e.from == b_disp
                        && e.to == h_disp
                });
                if !covered {
                    findings.push(compare_err(
                        &target_key,
                        &format!(
                            "SL12: capture transition `{b_disp}` -> `{h_disp}` requires `[[level]]` entry"
                        ),
                    ));
                }
            }
        }
    }
    for hl in &head_capture.levels {
        if base_names.contains(hl.name.as_str()) {
            continue;
        }
        for cls in CANONICAL_CLASSES {
            let h_disp = hl.dispositions.get(*cls).map(String::as_str).unwrap_or("");
            let target_key = format!("{}:{cls}", hl.name);
            let covered = added.iter().any(|e| {
                e.kind == ReclassKind::Level
                    && e.target == target_key
                    && e.from == "absent"
                    && e.to == h_disp
            });
            if !covered {
                findings.push(compare_err(
                    &target_key,
                    &format!(
                        "SL12: newly added level `{}` class `{cls}` requires `[[level]]` entry with `from = \"absent\"`",
                        hl.name
                    ),
                ));
            }
        }
    }
}

fn check_enum_transitions(
    base_enums: &[EnumValueSnapshot],
    head_enums: &[EnumValueSnapshot],
    head_enum_map: &BTreeMap<&str, &EnumValueSnapshot>,
    base_reclass: &[ReclassificationEntry],
    head_reclass: &[ReclassificationEntry],
    findings: &mut Vec<LintFinding>,
) {
    let added = head_reclass.get(base_reclass.len()..).unwrap_or(&[]);
    let mut base_by_num: BTreeMap<(&str, i32), &str> = BTreeMap::new();
    for be in base_enums {
        if let Some((enum_path, _)) = be.path.rsplit_once('.') {
            base_by_num.insert((enum_path, be.number), be.path.as_str());
        }
        match head_enum_map.get(be.path.as_str()) {
            None => findings.push(compare_err(
                &be.path,
                if be.number == 0 {
                    "SL12: zero enum value cannot be renamed or removed"
                } else {
                    "SL12: non-zero enum value cannot be deleted across compatible schemas"
                },
            )),
            Some(he) => {
                if be.number != he.number {
                    findings.push(compare_err(
                        &be.path,
                        "SL12: enum tag number cannot be renumbered",
                    ));
                }
                if be.number != 0 && be.wire_name != he.wire_name {
                    let covered = added.iter().any(|e| {
                        e.kind == ReclassKind::WireName
                            && e.target == be.path
                            && e.from == be.wire_name
                            && e.to == he.wire_name
                    });
                    if !covered {
                        findings.push(compare_err(
                            &be.path,
                            &format!(
                                "SL12: enum wire_name `{}` -> `{}` requires `[[wire_name]]` entry reviewed by persona-soc-analyst",
                                be.wire_name, he.wire_name
                            ),
                        ));
                    }
                }
            }
        }
    }
    for he in head_enums {
        if let Some((enum_path, _)) = he.path.rsplit_once('.')
            && let Some(&old_val_path) = base_by_num.get(&(enum_path, he.number))
            && old_val_path != he.path
        {
            findings.push(compare_err(
                &he.path,
                &format!(
                    "SL12: enum tag {} previously belonged to `{old_val_path}` and cannot be reused or aliased",
                    he.number
                ),
            ));
        }
    }
}

fn compare_err(target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0008".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}
