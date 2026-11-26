// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor parity comparison validating `.proto` source AST against `proto.binpb` (`SL09`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::{
    DescriptorSet, EnumDescriptor, FieldDescriptor, FileDescriptor, MessageDescriptor,
    ResolvedOptionsExtension, read_string_option, read_varint_option,
};

use crate::proto_option_lex::{extract_bool_opt, extract_enum_opt, extract_quoted_opt};
use crate::proto_source_parse::{SrcEnumVal, SrcExtend, SrcField, SrcMsg, parse_proto_statements};
use crate::proto_source_rpc::{
    bounded_type_match, compare_services, extract_method_parity_meta, field_type_matches,
    scalar_or_named_matches,
};
use crate::{LintDomain, LintError, LintFinding, LintSeverity};

pub(crate) struct ParitySchema<'a> {
    pub set: &'a DescriptorSet,
    pub ext: &'a ResolvedOptionsExtension,
    pub dc_nums: &'a BTreeMap<String, i32>,
    pub ck_nums: &'a BTreeMap<String, i32>,
}

pub(crate) fn verify_source_parity(
    rel: &str,
    stmts: &[(usize, String)],
    desc: &FileDescriptor,
    schema: &ParitySchema<'_>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let parsed = parse_proto_statements(stmts);
    if parsed.syntax.as_deref() != Some(desc.syntax.as_str()) {
        findings.push(parity_err(
            rel,
            "SL09: `.proto` syntax differs from committed `proto.binpb`",
        ));
    }
    if parsed.package.as_deref() != Some(desc.package.as_str()) {
        findings.push(parity_err(
            rel,
            "SL09: `.proto` package differs from committed `proto.binpb`",
        ));
        return Ok(());
    }

    let desc_imports: BTreeSet<String> = desc.dependencies.iter().cloned().collect();
    let desc_public: BTreeSet<String> = desc
        .public_dependencies
        .iter()
        .filter_map(|&idx| {
            usize::try_from(idx)
                .ok()
                .and_then(|i| desc.dependencies.get(i))
        })
        .cloned()
        .collect();
    let desc_weak: BTreeSet<String> = desc
        .weak_dependencies
        .iter()
        .filter_map(|&idx| {
            usize::try_from(idx)
                .ok()
                .and_then(|i| desc.dependencies.get(i))
        })
        .cloned()
        .collect();
    if parsed.imports != desc_imports
        || parsed.public_imports != desc_public
        || parsed.weak_imports != desc_weak
    {
        findings.push(parity_err(
            rel,
            "SL09: `.proto` imports differ from committed `proto.binpb`; regenerate descriptor set",
        ));
    }

    check_root_extends_parity(rel, &parsed.root_extends, &desc.extensions, findings);

    let desc_enums: BTreeMap<&str, &EnumDescriptor> =
        desc.enums.iter().map(|e| (e.name.as_str(), e)).collect();
    compare_enum_maps(rel, &parsed.root_enums, &desc_enums, schema.ext, findings)?;

    let desc_msgs: BTreeMap<&str, &MessageDescriptor> = desc
        .messages
        .iter()
        .filter(|m| !m.is_map_entry)
        .map(|m| (m.name.as_str(), m))
        .collect();
    compare_msg_maps(
        rel,
        &desc.package,
        &parsed.root_msgs,
        &desc_msgs,
        schema,
        findings,
    )?;

    let method_meta = extract_method_parity_meta(schema.set, &schema.ext.package);
    compare_services(
        rel,
        &parsed.root_svcs,
        desc,
        &schema.ext.package,
        &method_meta,
        findings,
    )?;
    Ok(())
}

fn check_root_extends_parity(
    rel: &str,
    src_extends: &[SrcExtend],
    desc_extensions: &[FieldDescriptor],
    findings: &mut Vec<LintFinding>,
) {
    let mut unmatched_src = src_extends.to_vec();
    let mut all_ok = src_extends.len() == desc_extensions.len();
    if all_ok {
        for de in desc_extensions {
            let pos = unmatched_src.iter().position(|se| {
                se.name == de.name
                    && se.number == de.number
                    && bounded_type_match(&de.extendee, &se.extendee)
                    && scalar_or_named_matches(&se.type_token, de)
            });
            if let Some(i) = pos {
                unmatched_src.remove(i);
            } else {
                all_ok = false;
                break;
            }
        }
    }
    if !all_ok {
        findings.push(parity_err(
            rel,
            "SL09: `.proto` top-level extensions differ from committed `proto.binpb`",
        ));
    }
}

fn compare_msg_maps(
    rel: &str,
    prefix: &str,
    src_map: &BTreeMap<String, SrcMsg>,
    desc_map: &BTreeMap<&str, &MessageDescriptor>,
    schema: &ParitySchema<'_>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let src_names: BTreeSet<&str> = src_map.keys().map(String::as_str).collect();
    let desc_names: BTreeSet<&str> = desc_map.keys().copied().collect();
    if src_names != desc_names {
        findings.push(parity_err(
            rel,
            &format!("SL09: `.proto` messages in `{prefix}` differ from `proto.binpb`"),
        ));
        return Ok(());
    }
    for (name, smsg) in src_map {
        let Some(&dmsg) = desc_map.get(name.as_str()) else {
            continue;
        };
        let full = format!("{prefix}.{name}");
        if smsg.extension_count != dmsg.nested_extensions.len() {
            findings.push(parity_err(
                rel,
                &format!("SL09: nested extensions on `{full}` differ from `proto.binpb`"),
            ));
        }
        let desc_real_oneofs: BTreeSet<&str> = dmsg
            .oneofs
            .iter()
            .enumerate()
            .filter(|(idx, _)| {
                let idx_i32 = i32::try_from(*idx).unwrap_or(-1);
                dmsg.fields
                    .iter()
                    .any(|f| !f.proto3_optional && f.oneof_index == Some(idx_i32))
            })
            .map(|(_, o)| o.as_str())
            .collect();
        let src_oneofs: BTreeSet<&str> = smsg.oneofs.iter().map(String::as_str).collect();
        if src_oneofs != desc_real_oneofs {
            findings.push(parity_err(
                rel,
                &format!("SL09: oneof declarations on `{full}` differ from `proto.binpb`"),
            ));
        }
        let d_res: BTreeSet<(i32, i32)> = dmsg
            .reserved_ranges
            .iter()
            .map(|r| (r.start, r.end_exclusive))
            .collect();
        let s_res: BTreeSet<(i32, i32)> = smsg
            .reserved
            .iter()
            .map(|&(a, b)| (a, b.saturating_add(1)))
            .collect();
        if s_res != d_res {
            findings.push(parity_err(
                rel,
                &format!("SL09: reserved ranges on `{full}` differ from `proto.binpb`"),
            ));
        }

        let mut d_fields: BTreeMap<&str, &FieldDescriptor> =
            dmsg.fields.iter().map(|f| (f.name.as_str(), f)).collect();
        if smsg.fields.len() != d_fields.len() {
            findings.push(parity_err(
                rel,
                &format!("SL09: field count on `{full}` differs from `proto.binpb`"),
            ));
        } else {
            for sf in &smsg.fields {
                let Some(df) = d_fields.remove(sf.name.as_str()) else {
                    findings.push(parity_err(
                        rel,
                        &format!(
                            "SL09: field `{full}.{}` differs from `proto.binpb`",
                            sf.name
                        ),
                    ));
                    continue;
                };
                check_field_parity(&full, sf, df, dmsg, schema, findings)?;
            }
        }

        let d_nested_enums: BTreeMap<&str, &EnumDescriptor> = dmsg
            .nested_enums
            .iter()
            .map(|e| (e.name.as_str(), e))
            .collect();
        compare_enum_maps(rel, &smsg.enums, &d_nested_enums, schema.ext, findings)?;

        let d_nested_msgs: BTreeMap<&str, &MessageDescriptor> = dmsg
            .nested_messages
            .iter()
            .filter(|m| !m.is_map_entry)
            .map(|m| (m.name.as_str(), m))
            .collect();
        compare_msg_maps(rel, &full, &smsg.messages, &d_nested_msgs, schema, findings)?;
    }
    Ok(())
}

fn check_field_parity(
    msg_full: &str,
    sf: &SrcField,
    df: &FieldDescriptor,
    dmsg: &MessageDescriptor,
    schema: &ParitySchema<'_>,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let ext = schema.ext;
    let opts_pkg = ext.package.as_str();
    let dc_nums = schema.dc_nums;
    let ck_nums = schema.ck_nums;
    let target = format!("{msg_full}.{}", sf.name);
    if sf.number != df.number || sf.label != df.label {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` field number or label differs from `proto.binpb`",
        ));
    }
    let desc_oneof = if df.proto3_optional {
        None
    } else {
        df.oneof_index
            .and_then(|idx| usize::try_from(idx).ok())
            .and_then(|idx| dmsg.oneofs.get(idx))
            .map(String::as_str)
    };
    if sf.oneof_group.as_deref() != desc_oneof {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` field oneof membership differs from `proto.binpb`",
        ));
    }
    if !field_type_matches(&sf.type_token, df, dmsg) {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` field type differs from `proto.binpb`",
        ));
    }
    let src_dc =
        extract_enum_opt(&sf.options_raw, "data_class", Some(opts_pkg)).map(|tok| {
            match tok.as_str() {
                "DATA_CLASS_IDENTIFIER" => dc_nums.get("identifier").copied().unwrap_or(-1),
                "DATA_CLASS_STRUCTURAL" => dc_nums.get("structural").copied().unwrap_or(-1),
                "DATA_CLASS_DERIVED" => dc_nums.get("derived").copied().unwrap_or(-1),
                "DATA_CLASS_CONTENT" => dc_nums.get("content").copied().unwrap_or(-1),
                "DATA_CLASS_UNSPECIFIED" => 0,
                _ => -1,
            }
        });
    let desc_dc = read_varint_option(&df.raw_options, ext.field_data_class_tag)
        .map_err(|e| LintError::ProtoViolation {
            file: target.clone(),
            detail: e.to_string(),
        })?
        .and_then(|v| i32::try_from(v).ok());
    if src_dc != desc_dc {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` data_class option differs from `proto.binpb`",
        ));
    }
    let src_ck = extract_enum_opt(&sf.options_raw, "content_kind", Some(opts_pkg)).map(|tok| {
        match tok.as_str() {
            "CONTENT_KIND_ARGUMENT" => ck_nums.get("argument").copied().unwrap_or(-1),
            "CONTENT_KIND_BODY" => ck_nums.get("body").copied().unwrap_or(-1),
            "CONTENT_KIND_UNSPECIFIED" => 0,
            _ => -1,
        }
    });
    let desc_ck = read_varint_option(&df.raw_options, ext.field_content_kind_tag)
        .map_err(|e| LintError::ProtoViolation {
            file: target.clone(),
            detail: e.to_string(),
        })?
        .and_then(|v| i32::try_from(v).ok());
    if src_ck != desc_ck {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` content_kind option differs from `proto.binpb`",
        ));
    }
    let src_pr = extract_bool_opt(&sf.options_raw, "policy_readable", Some(opts_pkg));
    let desc_pr = read_varint_option(&df.raw_options, ext.field_policy_readable_tag)
        .map_err(|e| LintError::ProtoViolation {
            file: target.clone(),
            detail: e.to_string(),
        })?
        .is_some_and(|v| v != 0);
    if src_pr != desc_pr {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` policy_readable option differs from `proto.binpb`",
        ));
    }
    let src_seal = extract_bool_opt(&sf.options_raw, "sealable", Some(opts_pkg));
    let desc_seal = read_varint_option(&df.raw_options, ext.field_sealable_tag)
        .map_err(|e| LintError::ProtoViolation {
            file: target.clone(),
            detail: e.to_string(),
        })?
        .is_some_and(|v| v != 0);
    if src_seal != desc_seal {
        findings.push(parity_err(
            &target,
            "SL09: `.proto` sealable option differs from `proto.binpb`",
        ));
    }
    Ok(())
}

fn compare_enum_maps(
    rel: &str,
    src_enums: &BTreeMap<String, Vec<SrcEnumVal>>,
    desc_enums: &BTreeMap<&str, &EnumDescriptor>,
    ext: &ResolvedOptionsExtension,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let s_names: BTreeSet<&str> = src_enums.keys().map(String::as_str).collect();
    let d_names: BTreeSet<&str> = desc_enums.keys().copied().collect();
    if s_names != d_names {
        findings.push(parity_err(
            rel,
            "SL09: `.proto` enums differ from committed `proto.binpb`",
        ));
        return Ok(());
    }
    for (name, svals) in src_enums {
        let Some(&de) = desc_enums.get(name.as_str()) else {
            continue;
        };
        let mut s_parsed = Vec::with_capacity(svals.len());
        for sv in svals {
            let wn = extract_quoted_opt(&sv.options_raw, "wire_name", Some(&ext.package));
            s_parsed.push((sv.name.as_str(), sv.number, wn));
        }
        let mut d_parsed = Vec::with_capacity(de.values.len());
        for dv in &de.values {
            let wn = read_string_option(&dv.raw_options, ext.enum_wire_name_tag).map_err(|e| {
                LintError::ProtoViolation {
                    file: rel.into(),
                    detail: e.to_string(),
                }
            })?;
            d_parsed.push((dv.name.as_str(), dv.number, wn));
        }
        if s_parsed != d_parsed {
            findings.push(parity_err(
                rel,
                &format!("SL09: enum `{name}` values or wire_names differ from `proto.binpb`"),
            ));
        }
    }
    Ok(())
}

fn parity_err(target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0002".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}
