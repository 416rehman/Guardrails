// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Field, map, and sealable (`SL01`..`SL06`) descriptor rules.

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::{
    FieldDescriptor, FieldLabel, FieldType, FileDescriptor, MessageDescriptor,
    ResolvedOptionsExtension, read_varint_option,
};

use crate::descriptor_env::lint_err;
use crate::schema_compare::FieldSnapshot;
use crate::{LintError, LintFinding};

pub(crate) type ForeignLeaf = (String, i32, i32, String, String);

const ALLOWED_TYPED_MAPS: &[(&str, &str, &str)] = &[
    ("common.v1alpha1", "ErrorInfo", "metadata"),
    ("common.v1alpha1", "ErrorDetail", "metadata"),
    ("api.activity.v1alpha1", "QueryRow", "columns"),
];

const FORBIDDEN_ANY_STRUCT_TYPES: &[&str] = &[
    ".google.protobuf.Any",
    ".google.protobuf.Struct",
    ".google.protobuf.Value",
    ".google.protobuf.ListValue",
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_field_rules(
    file: &FileDescriptor,
    rel_pkg: &str,
    ns_pkg_prefix: &str,
    msg: &MessageDescriptor,
    msg_full_path: &str,
    field: &FieldDescriptor,
    ext: &ResolvedOptionsExtension,
    dc_n2w: &BTreeMap<i32, String>,
    ck_n2w: &BTreeMap<i32, String>,
    map_entries: &BTreeMap<String, &MessageDescriptor>,
    msg_by_fqn: &BTreeMap<String, &MessageDescriptor>,
    foreign_leaves: &BTreeMap<String, Vec<ForeignLeaf>>,
    open_enum_full_names: &BTreeSet<String>,
    out_fields: &mut Vec<FieldSnapshot>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let field_path = format!("{msg_full_path}.{}", field.name);
    if (900..=999).contains(&field.number) {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            &field_path,
            "SL06: field number 900..=999 is reserved exclusively for sealed twins",
        ));
    }
    if matches!(field.kind, FieldType::Message | FieldType::Enum)
        && !field.type_name.starts_with('.')
    {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            &field_path,
            "SL05: Message/Enum field type_name must be fully qualified with leading `.`",
        ));
    }
    if FORBIDDEN_ANY_STRUCT_TYPES.contains(&field.type_name.as_str()) {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            &field_path,
            "SL05: google.protobuf.Any/Struct/Value/ListValue is forbidden",
        ));
    }
    let map_proto_err = |e: grdr_proto::ProtoError| LintError::ProtoViolation {
        file: file.name.clone(),
        detail: e.to_string(),
    };
    let dc_raw =
        read_varint_option(&field.raw_options, ext.field_data_class_tag).map_err(map_proto_err)?;
    let ck_raw = read_varint_option(&field.raw_options, ext.field_content_kind_tag)
        .map_err(map_proto_err)?;
    let dc = dc_raw.map(i32::try_from);
    let ck = ck_raw.map(i32::try_from);
    let pr = read_varint_option(&field.raw_options, ext.field_policy_readable_tag)
        .map_err(map_proto_err)?
        .is_some_and(|v| v != 0);
    let seal = read_varint_option(&field.raw_options, ext.field_sealable_tag)
        .map_err(map_proto_err)?
        .is_some_and(|v| v != 0);

    let dc_str: &str = match dc {
        Some(Ok(0)) => {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL01: data_class must never be DATA_CLASS_UNSPECIFIED",
            ));
            "unspecified"
        }
        Some(Ok(n)) => {
            if let Some(wire) = dc_n2w.get(&n) {
                wire.as_str()
            } else {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &field_path,
                    "SL01: field references unknown DataClass enum value",
                ));
                "missing"
            }
        }
        Some(Err(_)) => {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL01: field references out-of-range DataClass tag value",
            ));
            "missing"
        }
        None => {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL01: field missing required (data_class) option",
            ));
            "missing"
        }
    };

    let msg_display = msg_full_path
        .strip_prefix(&format!("{}.", file.package))
        .unwrap_or(&msg.name)
        .to_owned();

    if field.kind == FieldType::Message
        && field.label != FieldLabel::Repeated
        && map_entries.contains_key(&field.type_name)
    {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            &field_path,
            "SL05: non-repeated reference to map entry message is forbidden",
        ));
    }

    if field.label == FieldLabel::Repeated
        && field.kind == FieldType::Message
        && let Some(entry_desc) = map_entries.get(&field.type_name)
    {
        let allow_native = field.name == "native" && rel_pkg.starts_with("event.");
        let allowed =
            ALLOWED_TYPED_MAPS.contains(&(rel_pkg, msg_display.as_str(), field.name.as_str()))
                || allow_native;
        if !allowed {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL05: unallowlisted free-form map field is forbidden",
            ));
        }
        if field.name == "native" && dc_str != "content" {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL01: native payload map must be tagged DATA_CLASS_CONTENT",
            ));
        }
        if let Some(key_field) = entry_desc.fields.iter().find(|f| f.number == 1)
            && !matches!(
                key_field.kind,
                FieldType::Int32
                    | FieldType::Int64
                    | FieldType::Uint32
                    | FieldType::Uint64
                    | FieldType::Sint32
                    | FieldType::Sint64
                    | FieldType::Fixed32
                    | FieldType::Fixed64
                    | FieldType::Sfixed32
                    | FieldType::Sfixed64
                    | FieldType::Bool
                    | FieldType::String
            )
        {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL05: invalid map key type (must be integral, bool, or string)",
            ));
        }
        if let Some(val_field) = entry_desc.fields.iter().find(|f| f.number == 2) {
            if FORBIDDEN_ANY_STRUCT_TYPES.contains(&val_field.type_name.as_str()) {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &field_path,
                    "SL05: map value cannot be google.protobuf.Any/Struct/Value/ListValue",
                ));
            }
            if pr && matches!(val_field.kind, FieldType::Float | FieldType::Double) {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &field_path,
                    "SL03: map<K, float/double> cannot carry (policy_readable)",
                ));
            }
        }
    }

    if field.kind == FieldType::Enum && open_enum_full_names.contains(&field.type_name) {
        let sibling = format!("{}_other", field.name);
        if !msg
            .fields
            .iter()
            .any(|f| f.name == sibling && f.kind == FieldType::String)
        {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                &format!(
                    "SL07: open enum field `{}` requires string sibling `{sibling}`",
                    field.name
                ),
            ));
        }
    }

    let ck_str = match (dc_str, ck) {
        ("content", Some(Ok(n))) => {
            if let Some(wire) = ck_n2w.get(&n) {
                Some(wire.clone())
            } else {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &field_path,
                    "SL02: DATA_CLASS_CONTENT field must set valid (content_kind)",
                ));
                None
            }
        }
        ("content", Some(Err(_)) | None) => {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL02: DATA_CLASS_CONTENT field must set valid (content_kind)",
            ));
            None
        }
        (_, Some(_)) => {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL02: (content_kind) only permitted on DATA_CLASS_CONTENT fields",
            ));
            None
        }
        (_, None) => None,
    };

    if pr {
        let direct_bad =
            matches!(field.kind, FieldType::Float | FieldType::Double) || dc_str == "content";
        let mut visited = BTreeSet::new();
        let nested_bad = field.kind == FieldType::Message
            && subtree_violates_policy_readable(
                &field.type_name,
                ns_pkg_prefix,
                ext,
                dc_n2w,
                msg_by_fqn,
                &mut visited,
            );
        if direct_bad || nested_bad {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &field_path,
                "SL03: float/double or content fields (including nested subtrees) cannot carry (policy_readable)",
            ));
        }
    }

    let commitment_class = match (dc_str, ck_str.as_deref()) {
        ("content", Some(k)) => format!("content.{k}"),
        ("content", None) => "content.body".into(),
        _ => dc_str.to_owned(),
    };
    let label_str = format_label(field.label);
    out_fields.push(FieldSnapshot {
        path: field_path.clone(),
        package: file.package.clone(),
        message: msg_display.clone(),
        field: field.name.clone(),
        number: field.number,
        data_class: dc_str.to_owned(),
        content_kind: ck_str.clone(),
        commitment_class: commitment_class.clone(),
        policy_readable: pr,
        sealable: seal,
        wire_type: map_wire_type(field.kind),
        label: label_str,
        type_name: field.type_name.clone(),
        oneof_index: if field.proto3_optional {
            None
        } else {
            field.oneof_index
        },
    });
    if let Some(leaves) = foreign_leaves.get(&field.type_name) {
        for (leaf_name, leaf_num, leaf_wt, leaf_label, leaf_type) in leaves {
            out_fields.push(FieldSnapshot {
                path: format!("{field_path}.{leaf_name}"),
                package: file.package.clone(),
                message: format!("{msg_display}.{}", field.name),
                field: leaf_name.clone(),
                number: *leaf_num,
                data_class: dc_str.to_owned(),
                content_kind: ck_str.clone(),
                commitment_class: commitment_class.clone(),
                policy_readable: pr,
                sealable: seal,
                wire_type: *leaf_wt,
                label: leaf_label.clone(),
                type_name: leaf_type.clone(),
                oneof_index: None,
            });
        }
    }
    Ok(())
}

fn subtree_violates_policy_readable(
    fqn: &str,
    ns_pkg_prefix: &str,
    ext: &ResolvedOptionsExtension,
    dc_n2w: &BTreeMap<i32, String>,
    msg_by_fqn: &BTreeMap<String, &MessageDescriptor>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visited.contains(fqn) {
        return false;
    }
    if visited.len() >= 256 {
        return true;
    }
    visited.insert(fqn.to_owned());
    let Some(msg) = msg_by_fqn.get(fqn) else {
        return true;
    };
    let in_ns = fqn
        .strip_prefix('.')
        .is_some_and(|trimmed| trimmed.starts_with(ns_pkg_prefix));
    for f in &msg.fields {
        if matches!(f.kind, FieldType::Float | FieldType::Double) {
            return true;
        }
        if in_ns && !msg.is_map_entry {
            match read_varint_option(&f.raw_options, ext.field_data_class_tag) {
                Err(_) => return true,
                Ok(Some(raw)) => match i32::try_from(raw) {
                    Err(_) => return true,
                    Ok(dc_i) if dc_n2w.get(&dc_i).map(String::as_str) == Some("content") => {
                        return true;
                    }
                    Ok(_) => {}
                },
                Ok(None) => {}
            }
        }
        if f.kind == FieldType::Message
            && subtree_violates_policy_readable(
                &f.type_name,
                ns_pkg_prefix,
                ext,
                dc_n2w,
                msg_by_fqn,
                visited,
            )
        {
            return true;
        }
    }
    false
}

pub(crate) fn format_label(label: FieldLabel) -> String {
    match label {
        FieldLabel::Optional => "optional".into(),
        FieldLabel::Required => "required".into(),
        FieldLabel::Repeated => "repeated".into(),
        FieldLabel::Unknown(v) => format!("unknown({v})"),
    }
}

pub(crate) fn map_wire_type(kind: FieldType) -> i32 {
    match kind {
        FieldType::Double => 1,
        FieldType::Float => 2,
        FieldType::Int64 => 3,
        FieldType::Uint64 => 4,
        FieldType::Int32 => 5,
        FieldType::Fixed64 => 6,
        FieldType::Fixed32 => 7,
        FieldType::Bool => 8,
        FieldType::String => 9,
        FieldType::Group => 10,
        FieldType::Message => 11,
        FieldType::Bytes => 12,
        FieldType::Uint32 => 13,
        FieldType::Enum => 14,
        FieldType::Sfixed32 => 15,
        FieldType::Sfixed64 => 16,
        FieldType::Sint32 => 17,
        FieldType::Sint64 => 18,
        FieldType::Unknown(other) => other,
    }
}
