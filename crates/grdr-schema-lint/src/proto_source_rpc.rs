// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor parity validation for `.proto` RPC services, streaming, method options, and `.`-bounded types (`SL09`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::{
    DescriptorSet, FieldDescriptor, FieldLabel, FieldType, FileDescriptor, MessageDescriptor,
    MethodDescriptorProto, read_string_option, read_varint_option,
};

use crate::proto_option_lex::{
    bounded_option_key_matches, remove_all_ws, split_once_outside_quotes, strip_keyword,
    unquote_simple,
};
use crate::proto_source_parse::SrcRpc;
use crate::{LintDomain, LintError, LintFinding, LintSeverity};

const METHOD_OPTION_IDEMPOTENCY_TAG: i32 = 34;

pub(crate) struct MethodParityMeta {
    pub scope_tag: i32,
    pub audit_tag: i32,
    pub rate_class_tag: i32,
    pub confirm_tag: i32,
    pub mcp_exposed_tag: i32,
    pub audit_nums: BTreeMap<String, i32>,
    pub rate_nums: BTreeMap<String, i32>,
    pub confirm_nums: BTreeMap<String, i32>,
}

struct ParsedRpcOptions {
    scope: Option<String>,
    audit: Option<i32>,
    rate_class: Option<i32>,
    confirm: Option<i32>,
    idempotency_level: Option<i32>,
    mcp_exposed: Result<Option<bool>, ()>,
}

pub(crate) fn extract_method_parity_meta(
    set: &DescriptorSet,
    options_pkg: &str,
) -> MethodParityMeta {
    let mut meta = MethodParityMeta {
        scope_tag: 0,
        audit_tag: 0,
        rate_class_tag: 0,
        confirm_tag: 0,
        mcp_exposed_tag: 0,
        audit_nums: BTreeMap::new(),
        rate_nums: BTreeMap::new(),
        confirm_nums: BTreeMap::new(),
    };
    let Some(opts_file) = set
        .files
        .iter()
        .find(|f| f.package == options_pkg && !f.extensions.is_empty())
    else {
        return meta;
    };
    for ext in &opts_file.extensions {
        if ext.extendee == ".google.protobuf.MethodOptions" {
            match ext.name.as_str() {
                "scope" => meta.scope_tag = ext.number,
                "audit" => meta.audit_tag = ext.number,
                "rate_class" => meta.rate_class_tag = ext.number,
                "confirm" => meta.confirm_tag = ext.number,
                "mcp_exposed" => meta.mcp_exposed_tag = ext.number,
                _ => {}
            }
        }
    }
    for enm in &opts_file.enums {
        let map = match enm.name.as_str() {
            "AuditClass" => &mut meta.audit_nums,
            "RateClass" => &mut meta.rate_nums,
            "ConfirmClass" => &mut meta.confirm_nums,
            _ => continue,
        };
        for val in &enm.values {
            map.insert(val.name.clone(), val.number);
        }
    }
    meta
}

pub(crate) fn bounded_type_match(desc_fqn: &str, src_tok: &str) -> bool {
    let full = desc_fqn.trim_start_matches('.');
    let src = src_tok.trim_start_matches('.');
    if src.is_empty() {
        return false;
    }
    full == src
        || full
            .strip_suffix(src)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub(crate) fn scalar_or_named_matches(tok: &str, df: &FieldDescriptor) -> bool {
    let expected_scalar = match df.kind {
        FieldType::Double => Some("double"),
        FieldType::Float => Some("float"),
        FieldType::Int64 => Some("int64"),
        FieldType::Uint64 => Some("uint64"),
        FieldType::Int32 => Some("int32"),
        FieldType::Fixed64 => Some("fixed64"),
        FieldType::Fixed32 => Some("fixed32"),
        FieldType::Bool => Some("bool"),
        FieldType::String => Some("string"),
        FieldType::Bytes => Some("bytes"),
        FieldType::Uint32 => Some("uint32"),
        FieldType::Sfixed32 => Some("sfixed32"),
        FieldType::Sfixed64 => Some("sfixed64"),
        FieldType::Sint32 => Some("sint32"),
        FieldType::Sint64 => Some("sint64"),
        FieldType::Message | FieldType::Enum | FieldType::Group | FieldType::Unknown(_) => None,
    };
    if let Some(sc) = expected_scalar {
        return tok == sc;
    }
    matches!(df.kind, FieldType::Message | FieldType::Enum)
        && bounded_type_match(&df.type_name, tok)
}

pub(crate) fn field_type_matches(
    src_tok: &str,
    df: &FieldDescriptor,
    parent: &MessageDescriptor,
) -> bool {
    if let Some(inner) = src_tok
        .strip_prefix("map<")
        .and_then(|s| s.strip_suffix('>'))
    {
        if df.label != FieldLabel::Repeated || df.kind != FieldType::Message {
            return false;
        }
        let Some((sk, sv)) = inner.split_once(',') else {
            return false;
        };
        let entry_short = df.type_name.rsplit('.').next().unwrap_or("");
        let Some(entry) = parent
            .nested_messages
            .iter()
            .find(|m| m.is_map_entry && m.name == entry_short)
        else {
            return false;
        };
        let dk = entry.fields.iter().find(|f| f.number == 1);
        let dv = entry.fields.iter().find(|f| f.number == 2);
        return dk.is_some_and(|f| scalar_or_named_matches(sk, f))
            && dv.is_some_and(|f| scalar_or_named_matches(sv, f));
    }
    scalar_or_named_matches(src_tok, df)
}

pub(crate) fn compare_services(
    rel: &str,
    src_svcs: &BTreeMap<String, Vec<SrcRpc>>,
    desc: &FileDescriptor,
    options_pkg: &str,
    meta: &MethodParityMeta,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let desc_svcs: BTreeMap<&str, BTreeMap<&str, &MethodDescriptorProto>> = desc
        .services
        .iter()
        .map(|s| {
            let methods = s.methods.iter().map(|m| (m.name.as_str(), m)).collect();
            (s.name.as_str(), methods)
        })
        .collect();
    let src_names: BTreeSet<&str> = src_svcs.keys().map(String::as_str).collect();
    let desc_names: BTreeSet<&str> = desc_svcs.keys().copied().collect();
    if src_names != desc_names {
        findings.push(rpc_parity_err(
            rel,
            "SL09: `.proto` service declarations differ from committed `proto.binpb`",
        ));
        return Ok(());
    }
    for (svc_name, rpcs) in src_svcs {
        let Some(d_methods) = desc_svcs.get(svc_name.as_str()) else {
            continue;
        };
        let src_m: BTreeSet<&str> = rpcs.iter().map(|r| r.name.as_str()).collect();
        let desc_m: BTreeSet<&str> = d_methods.keys().copied().collect();
        if src_m != desc_m {
            findings.push(rpc_parity_err(
                rel,
                &format!("SL09: RPC methods on `{svc_name}` differ from `proto.binpb`"),
            ));
            continue;
        }
        for srpc in rpcs {
            if let Some(&dm) = d_methods.get(srpc.name.as_str()) {
                check_rpc_parity(rel, svc_name, srpc, dm, options_pkg, meta, findings)?;
            }
        }
    }
    Ok(())
}

fn check_rpc_parity(
    rel: &str,
    svc_name: &str,
    srpc: &SrcRpc,
    dm: &MethodDescriptorProto,
    options_pkg: &str,
    meta: &MethodParityMeta,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    if !bounded_type_match(&dm.input_type, &srpc.input_type)
        || !bounded_type_match(&dm.output_type, &srpc.output_type)
        || srpc.client_streaming != dm.client_streaming
        || srpc.server_streaming != dm.server_streaming
    {
        findings.push(rpc_parity_err(
            rel,
            &format!(
                "SL09: `.proto` RPC `{svc_name}.{}` request/response or streaming differs from `proto.binpb`",
                srpc.name
            ),
        ));
    }

    let parsed = parse_rpc_options(&srpc.options, options_pkg, meta);
    check_rpc_str_opt(
        rel,
        svc_name,
        &srpc.name,
        "scope",
        parsed.scope,
        &dm.raw_options,
        meta.scope_tag,
        findings,
    )?;
    check_rpc_enum_opt(
        rel,
        svc_name,
        &srpc.name,
        "audit",
        parsed.audit,
        &dm.raw_options,
        meta.audit_tag,
        findings,
    )?;
    check_rpc_enum_opt(
        rel,
        svc_name,
        &srpc.name,
        "rate_class",
        parsed.rate_class,
        &dm.raw_options,
        meta.rate_class_tag,
        findings,
    )?;
    check_rpc_enum_opt(
        rel,
        svc_name,
        &srpc.name,
        "confirm",
        parsed.confirm,
        &dm.raw_options,
        meta.confirm_tag,
        findings,
    )?;
    check_rpc_enum_opt(
        rel,
        svc_name,
        &srpc.name,
        "idempotency_level",
        parsed.idempotency_level,
        &dm.raw_options,
        METHOD_OPTION_IDEMPOTENCY_TAG,
        findings,
    )?;
    if meta.mcp_exposed_tag > 0 {
        let desc_mcp = read_varint_option(&dm.raw_options, meta.mcp_exposed_tag)
            .map_err(|e| LintError::ProtoViolation {
                file: rel.into(),
                detail: e.to_string(),
            })?
            .map(|v| v != 0);
        let matches = match (parsed.mcp_exposed, desc_mcp) {
            (Ok(src), Some(d)) => src.unwrap_or(false) == d,
            (Ok(src), None) => src != Some(true),
            (Err(()), _) => false,
        };
        if !matches {
            findings.push(rpc_parity_err(
                rel,
                &format!(
                    "SL09: `.proto` RPC `{svc_name}.{}` mcp_exposed option differs from `proto.binpb`",
                    srpc.name
                ),
            ));
        }
    }
    Ok(())
}

fn enum_ident_token(rhs: &str) -> String {
    let compact = remove_all_ws(rhs);
    compact
        .rsplit('.')
        .next()
        .unwrap_or("")
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn parse_rpc_options(
    opts: &[String],
    options_pkg: &str,
    meta: &MethodParityMeta,
) -> ParsedRpcOptions {
    let mut out = ParsedRpcOptions {
        scope: None,
        audit: None,
        rate_class: None,
        confirm: None,
        idempotency_level: None,
        mcp_exposed: Ok(None),
    };
    for line in opts {
        let Some(stmt) = line.trim().strip_suffix(';') else {
            continue;
        };
        let Some(rest) = strip_keyword(stmt, "option") else {
            continue;
        };
        let Some((lhs, rhs)) = split_once_outside_quotes(rest, '=') else {
            continue;
        };
        if bounded_option_key_matches(lhs, "scope", Some(options_pkg)) {
            out.scope = unquote_simple(rhs.trim());
        } else if bounded_option_key_matches(lhs, "audit", Some(options_pkg)) {
            let tok = enum_ident_token(rhs);
            out.audit = Some(meta.audit_nums.get(&tok).copied().unwrap_or(-1));
        } else if bounded_option_key_matches(lhs, "rate_class", Some(options_pkg)) {
            let tok = enum_ident_token(rhs);
            out.rate_class = Some(meta.rate_nums.get(&tok).copied().unwrap_or(-1));
        } else if bounded_option_key_matches(lhs, "confirm", Some(options_pkg)) {
            let tok = enum_ident_token(rhs);
            out.confirm = Some(meta.confirm_nums.get(&tok).copied().unwrap_or(-1));
        } else if bounded_option_key_matches(lhs, "mcp_exposed", Some(options_pkg)) {
            out.mcp_exposed = match rhs.trim() {
                "true" => Ok(Some(true)),
                "false" => Ok(Some(false)),
                _ => Err(()),
            };
        } else if bounded_option_key_matches(lhs, "idempotency_level", None) {
            let tok = enum_ident_token(rhs);
            let num = match tok.as_str() {
                "IDEMPOTENCY_UNKNOWN" => 0,
                "NO_SIDE_EFFECTS" => 1,
                "IDEMPOTENT" => 2,
                _ => -1,
            };
            out.idempotency_level = Some(num);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn check_rpc_str_opt(
    rel: &str,
    svc: &str,
    rpc: &str,
    opt_name: &str,
    src_val: Option<String>,
    raw_opts: &[u8],
    tag: i32,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    if tag <= 0 {
        return Ok(());
    }
    let desc_val = read_string_option(raw_opts, tag).map_err(|e| LintError::ProtoViolation {
        file: rel.into(),
        detail: e.to_string(),
    })?;
    if src_val != desc_val {
        findings.push(rpc_parity_err(
            rel,
            &format!(
                "SL09: `.proto` RPC `{svc}.{rpc}` {opt_name} option differs from `proto.binpb`"
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_rpc_enum_opt(
    rel: &str,
    svc: &str,
    rpc: &str,
    opt_name: &str,
    src_val: Option<i32>,
    raw_opts: &[u8],
    tag: i32,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    if tag <= 0 {
        return Ok(());
    }
    let desc_val = read_varint_option(raw_opts, tag)
        .map_err(|e| LintError::ProtoViolation {
            file: rel.into(),
            detail: e.to_string(),
        })?
        .map(|v| i32::try_from(v).unwrap_or(-2));
    if src_val != desc_val {
        findings.push(rpc_parity_err(
            rel,
            &format!(
                "SL09: `.proto` RPC `{svc}.{rpc}` {opt_name} option differs from `proto.binpb`"
            ),
        ));
    }
    Ok(())
}

fn rpc_parity_err(target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0002".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}
