// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor tree orchestrator (`SL01`..`SL11`) delegating per-item validation to `descriptor_rules`.

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::{
    DescriptorSet, FileDescriptor, MessageDescriptor, ResolvedOptionsExtension,
};

use crate::descriptor_env::{
    ResolvedSchemaContext, check_foreign_descriptors, check_sl08_sl09_layout, check_sl10_imports,
    check_sl11_surfaces, find_and_check_options_file, lint_err, parse_foreign_files_toml,
};
use crate::descriptor_rules::{ForeignLeaf, check_field_rules, format_label, map_wire_type};
use crate::descriptor_rules_enum::{OPEN_ENUM_NAMES, check_enum_sl04_sl07, extract_options_enums};
use crate::schema_compare::{EnumValueSnapshot, FieldSnapshot};
use crate::{LintError, LintFinding};

pub fn check_descriptor_set(
    set: &DescriptorSet,
    disk_proto_rel_paths: &[String],
    foreign_toml_raw: &str,
    brand_toml_raw: &str,
    surfaces_toml_raw: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<ResolvedSchemaContext, LintError> {
    let brand = grdr_schema::parse_brand_identity_toml(brand_toml_raw);
    if !grdr_schema::is_valid_brand_identity(&brand) {
        return Err(LintError::ForeignDescriptorViolation {
            file: "contracts/interface/brand/brand.toml".into(),
            detail: "invalid or missing [identity].namespace or [identity].domain".into(),
        });
    }
    let ns = brand.namespace;
    let foreign_pins = parse_foreign_files_toml(foreign_toml_raw)?;
    let ns_path_prefix = format!("{ns}/");
    let ns_pkg_prefix = format!("{ns}.");

    check_foreign_descriptors(set, &ns_path_prefix, &foreign_pins, findings);
    let (options_file, resolved_ext) = find_and_check_options_file(set, &ns, findings)?;

    check_sl08_sl09_layout(
        set,
        disk_proto_rel_paths,
        &ns_path_prefix,
        &ns_pkg_prefix,
        findings,
    );
    check_sl10_imports(set, &ns_path_prefix, &options_file.name, findings);
    check_sl11_surfaces(set, &ns_pkg_prefix, surfaces_toml_raw, findings)?;

    let (dc_num_to_wire, ck_num_to_wire, dc_wire_to_num, ck_wire_to_num) =
        extract_options_enums(options_file, &resolved_ext, findings)?;
    let (method_scope_tag, method_mcp_tag) = extract_method_option_tags(options_file);

    let map_entries = collect_map_entries(set, findings);
    let msg_by_fqn = collect_messages_by_fqn(set);
    let foreign_leaves = collect_foreign_message_leaves(set, &ns_path_prefix);
    let open_enum_full_names = collect_open_enum_full_names(set);
    let mut fields = Vec::new();
    let mut enums = Vec::new();
    let mut options_class_wire_names = BTreeSet::new();

    for file in &set.files {
        if !file.name.starts_with(&ns_path_prefix) {
            continue;
        }
        let rel_pkg = file.package.strip_prefix(&ns_pkg_prefix).unwrap_or("");
        for e in &file.enums {
            let enum_path = format!("{}.{}", file.package, e.name);
            let is_cls = file.name == options_file.name
                && (e.name == "DataClass" || e.name == "ContentKind");
            check_enum_sl04_sl07(
                &file.name,
                &enum_path,
                e,
                &resolved_ext,
                is_cls,
                &mut options_class_wire_names,
                &mut enums,
                findings,
            )?;
        }
        for msg in &file.messages {
            if msg.is_map_entry {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &format!("{}.{}", file.package, msg.name),
                    "SL05: top-level message cannot carry map_entry option",
                ));
                continue;
            }
            walk_message_sl01_sl07(
                file,
                rel_pkg,
                &ns_pkg_prefix,
                &file.package,
                msg,
                &resolved_ext,
                &dc_num_to_wire,
                &ck_num_to_wire,
                &map_entries,
                &msg_by_fqn,
                &foreign_leaves,
                &open_enum_full_names,
                &mut fields,
                &mut enums,
                findings,
            )?;
        }
    }

    Ok(ResolvedSchemaContext {
        namespace: ns,
        options_file: options_file.name.clone(),
        options_package: resolved_ext.package.clone(),
        options_class_wire_names,
        options_ext: resolved_ext,
        dc_wire_to_num,
        ck_wire_to_num,
        method_scope_tag,
        method_mcp_tag,
        fields,
        enums,
    })
}

fn extract_method_option_tags(options_file: &FileDescriptor) -> (i32, i32) {
    let mut scope_tag = 0;
    let mut mcp_tag = 0;
    for ext in &options_file.extensions {
        if ext.extendee == ".google.protobuf.MethodOptions" {
            if ext.name == "scope" {
                scope_tag = ext.number;
            } else if ext.name == "mcp_exposed" {
                mcp_tag = ext.number;
            }
        }
    }
    (scope_tag, mcp_tag)
}

fn collect_map_entries<'a>(
    set: &'a DescriptorSet,
    findings: &mut Vec<LintFinding>,
) -> BTreeMap<String, &'a MessageDescriptor> {
    fn walk<'a>(
        prefix: &str,
        msg: &'a MessageDescriptor,
        out: &mut BTreeMap<String, &'a MessageDescriptor>,
        findings: &mut Vec<LintFinding>,
    ) {
        let full = format!("{prefix}.{}", msg.name);
        if msg.is_map_entry {
            let valid_fields = msg.fields.len() == 2
                && msg.fields.iter().any(|f| f.number == 1 && f.name == "key")
                && msg
                    .fields
                    .iter()
                    .any(|f| f.number == 2 && f.name == "value");
            if !valid_fields
                || !msg.nested_messages.is_empty()
                || !msg.nested_enums.is_empty()
                || !msg.nested_extensions.is_empty()
            {
                findings.push(lint_err(
                    "GRDR-LINT-0002",
                    &full,
                    "SL05: malformed MapEntry descriptor (must have only key=1, value=2 and no nested declarations)",
                ));
            }
            out.insert(format!(".{full}"), msg);
        }
        for nested in &msg.nested_messages {
            walk(&full, nested, out, findings);
        }
    }
    let mut out = BTreeMap::new();
    for file in &set.files {
        for msg in &file.messages {
            walk(&file.package, msg, &mut out, findings);
        }
    }
    out
}

fn collect_messages_by_fqn(set: &DescriptorSet) -> BTreeMap<String, &MessageDescriptor> {
    fn walk<'a>(
        prefix: &str,
        msg: &'a MessageDescriptor,
        out: &mut BTreeMap<String, &'a MessageDescriptor>,
    ) {
        let full = format!("{prefix}.{}", msg.name);
        out.insert(format!(".{full}"), msg);
        for nested in &msg.nested_messages {
            walk(&full, nested, out);
        }
    }
    let mut out = BTreeMap::new();
    for file in &set.files {
        for msg in &file.messages {
            walk(&file.package, msg, &mut out);
        }
    }
    out
}

fn collect_open_enum_full_names(set: &DescriptorSet) -> BTreeSet<String> {
    fn walk_msgs(prefix: &str, msg: &MessageDescriptor, out: &mut BTreeSet<String>) {
        let full = format!("{prefix}.{}", msg.name);
        for ne in &msg.nested_enums {
            if OPEN_ENUM_NAMES.contains(&ne.name.as_str()) {
                out.insert(format!(".{full}.{}", ne.name));
            }
        }
        for nested in &msg.nested_messages {
            walk_msgs(&full, nested, out);
        }
    }
    let mut out = BTreeSet::new();
    for file in &set.files {
        for e in &file.enums {
            if OPEN_ENUM_NAMES.contains(&e.name.as_str()) {
                out.insert(format!(".{}.{}", file.package, e.name));
            }
        }
        for msg in &file.messages {
            walk_msgs(&file.package, msg, &mut out);
        }
    }
    out
}

fn collect_foreign_message_leaves(
    set: &DescriptorSet,
    ns_path_prefix: &str,
) -> BTreeMap<String, Vec<ForeignLeaf>> {
    fn walk(prefix: &str, msg: &MessageDescriptor, out: &mut BTreeMap<String, Vec<ForeignLeaf>>) {
        let full = format!("{prefix}.{}", msg.name);
        let leaves = msg
            .fields
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    f.number,
                    map_wire_type(f.kind),
                    format_label(f.label),
                    f.type_name.clone(),
                )
            })
            .collect();
        out.insert(format!(".{full}"), leaves);
        for nested in &msg.nested_messages {
            walk(&full, nested, out);
        }
    }
    let mut map = BTreeMap::new();
    for file in &set.files {
        if file.name.starts_with(ns_path_prefix) {
            continue;
        }
        for msg in &file.messages {
            walk(&file.package, msg, &mut map);
        }
    }
    map
}

#[allow(clippy::too_many_arguments)]
fn walk_message_sl01_sl07(
    file: &FileDescriptor,
    rel_pkg: &str,
    ns_pkg_prefix: &str,
    prefix: &str,
    msg: &MessageDescriptor,
    ext: &ResolvedOptionsExtension,
    dc_n2w: &BTreeMap<i32, String>,
    ck_n2w: &BTreeMap<i32, String>,
    map_entries: &BTreeMap<String, &MessageDescriptor>,
    msg_by_fqn: &BTreeMap<String, &MessageDescriptor>,
    foreign_leaves: &BTreeMap<String, Vec<ForeignLeaf>>,
    open_enum_full_names: &BTreeSet<String>,
    out_fields: &mut Vec<FieldSnapshot>,
    out_enums: &mut Vec<EnumValueSnapshot>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    if msg.is_map_entry {
        return Ok(());
    }
    let msg_path = format!("{prefix}.{}", msg.name);
    if !msg.nested_extensions.is_empty() {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &msg_path,
            "SL10: nested extensions are forbidden outside options.proto",
        ));
    }
    for nested_enum in &msg.nested_enums {
        let ep = format!("{msg_path}.{}", nested_enum.name);
        check_enum_sl04_sl07(
            &file.name,
            &ep,
            nested_enum,
            ext,
            false,
            &mut BTreeSet::new(),
            out_enums,
            findings,
        )?;
    }
    for field in &msg.fields {
        check_field_rules(
            file,
            rel_pkg,
            ns_pkg_prefix,
            msg,
            &msg_path,
            field,
            ext,
            dc_n2w,
            ck_n2w,
            map_entries,
            msg_by_fqn,
            foreign_leaves,
            open_enum_full_names,
            out_fields,
            findings,
        )?;
    }
    if !msg.fields.is_empty() || !msg.nested_messages.is_empty() {
        let has_900_999 = msg
            .reserved_ranges
            .iter()
            .any(|r| r.start <= 900 && r.end_exclusive >= 1000);
        if !has_900_999 {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &msg_path,
                "SL06: non-empty message must declare `reserved 900 to 999;`",
            ));
        }
    }
    for nested in &msg.nested_messages {
        walk_message_sl01_sl07(
            file,
            rel_pkg,
            ns_pkg_prefix,
            &msg_path,
            nested,
            ext,
            dc_n2w,
            ck_n2w,
            map_entries,
            msg_by_fqn,
            foreign_leaves,
            open_enum_full_names,
            out_fields,
            out_enums,
            findings,
        )?;
    }
    Ok(())
}
