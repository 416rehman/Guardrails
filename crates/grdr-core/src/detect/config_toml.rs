// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded TOML subset parser and MCP/env/endpoint extractor for Codex configurations (`D-09`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_crypto::sha256_hex;

use crate::detect::config_integrity::ConfigBaselineEntry;
use crate::detect::config_parse::{record_endpoint_url, record_env_pair_scoped};
use crate::detect::config_toml_lex::{
    TomlVal, ensure_section_table_path, insert_toml_nested, join_toml_statements,
    parse_toml_key_path, parse_toml_value, resolve_active_prefix, split_unquoted_eq,
};

#[derive(Default)]
struct McpAccum {
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    env: BTreeMap<String, String>,
}

pub(super) fn extract_from_toml(text: &str, entry: &mut ConfigBaselineEntry) -> Result<(), ()> {
    let stmts = join_toml_statements(text)?;
    let mut root: BTreeMap<String, TomlVal> = BTreeMap::new();
    let mut section_path: Vec<String> = Vec::new();
    let mut explicit_tables: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut dotted_tables: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut array_tables: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut array_indices: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    let mut mcp_servers: BTreeMap<String, McpAccum> = BTreeMap::new();

    for stmt in stmts {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("[[") {
            let inner = rest.strip_suffix("]]").ok_or(())?.trim();
            let segs = parse_toml_key_path(inner)?;
            let target = resolve_active_prefix(&segs, &array_tables, &array_indices)?;
            if explicit_tables.contains(&target) || dotted_tables.contains(&target) {
                return Err(());
            }
            if !array_tables.contains(&target) {
                insert_toml_nested(&mut root, &target, TomlVal::Table(BTreeMap::new()))?;
                array_tables.insert(target.clone());
            }
            let idx = array_indices.entry(target.clone()).or_insert(0);
            *idx = idx.saturating_add(1);
            let mut next_sec = target;
            next_sec.push(format!("#{idx}"));
            ensure_section_table_path(&mut root, &next_sec)?;
            section_path = next_sec;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            let inner = rest.strip_suffix(']').ok_or(())?.trim();
            let segs = parse_toml_key_path(inner)?;
            let target = resolve_active_prefix(&segs, &array_tables, &array_indices)?;
            if array_tables.contains(&target)
                || dotted_tables.contains(&target)
                || !explicit_tables.insert(target.clone())
            {
                return Err(());
            }
            ensure_section_table_path(&mut root, &target)?;
            section_path = target;
            continue;
        }
        let (raw_k, raw_v) = split_unquoted_eq(trimmed).ok_or(())?;
        let key_segs = parse_toml_key_path(raw_k)?;
        let val = parse_toml_value(raw_v.trim(), 0)?;
        for prefix_len in 1..key_segs.len() {
            let Some(sub) = key_segs.get(..prefix_len) else {
                return Err(());
            };
            let mut prefix_path = section_path.clone();
            prefix_path.extend_from_slice(sub);
            if explicit_tables.contains(&prefix_path) || array_tables.contains(&prefix_path) {
                return Err(());
            }
            dotted_tables.insert(prefix_path);
        }
        let mut full = section_path.clone();
        full.extend(key_segs);
        insert_toml_nested(&mut root, &full, val)?;
    }

    apply_toml_kv(&[], &TomlVal::Table(root), entry, &mut mcp_servers);

    for (srv, acc) in mcp_servers {
        if acc.command.is_some() || acc.url.is_some() || !acc.args.is_empty() || !acc.env.is_empty()
        {
            entry.mcp_stdio_entries.insert(format!(
                "{srv}:{}:{:?}:{}:{:?}",
                acc.command.as_deref().unwrap_or(""),
                acc.args,
                acc.url.as_deref().unwrap_or(""),
                acc.env
            ));
        }
    }
    Ok(())
}

fn apply_toml_kv(
    path: &[String],
    val: &TomlVal,
    entry: &mut ConfigBaselineEntry,
    mcp_servers: &mut BTreeMap<String, McpAccum>,
) {
    if let TomlVal::Table(tbl) | TomlVal::InlineTable(tbl) = val {
        for (k, v) in tbl {
            let mut next = path.to_vec();
            next.push(k.clone());
            apply_toml_kv(&next, v, entry, mcp_servers);
        }
        return;
    }
    let Some(leaf) = path.last().map(String::as_str) else {
        return;
    };
    let scope_slot = encode_toml_path(path);
    if path.first().map(String::as_str) == Some("mcp_servers") && path.len() >= 3 {
        if path.get(path.len().saturating_sub(2)).map(String::as_str) == Some("env") {
            let srv = path
                .get(1..path.len().saturating_sub(2))
                .map_or(String::new(), encode_toml_path);
            let s_val = toml_val_scalar_string(val);
            record_env_pair_scoped(entry, &scope_slot, leaf, &s_val);
            mcp_servers
                .entry(srv)
                .or_default()
                .env
                .insert(leaf.to_owned(), sha256_hex(s_val.as_bytes()));
            return;
        }
        let srv_name = path
            .get(1..path.len().saturating_sub(1))
            .map_or(String::new(), encode_toml_path);
        let acc = mcp_servers.entry(srv_name).or_default();
        match leaf {
            "command" => acc.command = Some(toml_val_scalar_string(val)),
            "url" => acc.url = Some(toml_val_scalar_string(val)),
            "args" => {
                if let TomlVal::Array(items) = val {
                    acc.args = items.iter().map(toml_val_scalar_string).collect();
                } else {
                    acc.args = vec![toml_val_scalar_string(val)];
                }
            }
            _ => {}
        }
        return;
    }
    if path.len() >= 2 && path.get(path.len().saturating_sub(2)).map(String::as_str) == Some("env")
    {
        let s_val = toml_val_scalar_string(val);
        record_env_pair_scoped(entry, &scope_slot, leaf, &s_val);
        return;
    }
    let s_val = toml_val_scalar_string(val);
    if matches!(
        leaf,
        "base_url"
            | "model_provider_base_url"
            | "openai_base_url"
            | "anthropic_base_url"
            | "api_base_url"
            | "proxy"
    ) {
        record_endpoint_url(entry, &scope_slot, &s_val);
    } else if (leaf == "approval_policy" && s_val.eq_ignore_ascii_case("never"))
        || (leaf == "sandbox_mode" && s_val.eq_ignore_ascii_case("danger-full-access"))
    {
        entry.has_bypass_permissions = true;
    } else if leaf == "policy_source" || leaf == "managed_settings" {
        entry.policy_sources.insert(format!("{leaf}:{s_val}"));
    }
}

fn encode_toml_path(segs: &[String]) -> String {
    segs.iter()
        .map(|s| format!("{}:{s}", s.len()))
        .collect::<Vec<_>>()
        .join("/")
}

fn toml_val_scalar_string(val: &TomlVal) -> String {
    match val {
        TomlVal::Str(s) | TomlVal::Other(s) => s.clone(),
        TomlVal::Array(items) => items
            .iter()
            .map(toml_val_scalar_string)
            .collect::<Vec<_>>()
            .join(","),
        TomlVal::Table(_) | TomlVal::InlineTable(_) => String::new(),
    }
}
