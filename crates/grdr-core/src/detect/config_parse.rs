// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Fail-closed JSONC, YAML, and Git INI extractors for `detect::config_integrity` (`D-09`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use grdr_crypto::sha256_hex;
use grdr_schema::limits::load_embedded_limits;
use serde_json::Value;

use crate::detect::config_formats::{
    extract_from_git_ini, extract_from_yaml, parse_json_unique_keys,
};
use crate::detect::config_integrity::{
    ConfigBaselineEntry, ConfigParseStatus, MonitoredConfigKind,
};
use crate::detect::config_toml::extract_from_toml;
use crate::detect::yaml::parse_yaml;

const BYTES_PER_MIB: usize = 1_048_576;

const ENDPOINT_ENV_VARS: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "GEMINI_API_BASE_URL",
    "OLLAMA_HOST",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];

fn max_config_bytes_cached() -> usize {
    static MAX_BYTES: OnceLock<usize> = OnceLock::new();
    *MAX_BYTES.get_or_init(|| {
        let max_mb = load_embedded_limits()
            .ok()
            .and_then(|l| usize::try_from(l.packs.detections_max_mb).ok())
            .unwrap_or(4);
        max_mb.saturating_mul(BYTES_PER_MIB)
    })
}

pub(super) fn summarize_config(
    canonical_path: &str,
    kind: MonitoredConfigKind,
    content: &[u8],
) -> ConfigBaselineEntry {
    let mut entry = ConfigBaselineEntry {
        canonical_path: canonical_path.to_owned(),
        kind,
        sha256_digest: sha256_hex(content),
        hook_entries: BTreeSet::new(),
        mcp_stdio_entries: BTreeSet::new(),
        allow_rules: BTreeSet::new(),
        recipients: BTreeSet::new(),
        base_url: None,
        endpoint_urls: BTreeMap::new(),
        env_keys: BTreeSet::new(),
        env_entries: BTreeMap::new(),
        policy_sources: BTreeSet::new(),
        has_bypass_permissions: false,
        has_folder_open_task: false,
        parse_status: ConfigParseStatus::Parsed,
    };
    if content.len() > max_config_bytes_cached() {
        entry.parse_status = ConfigParseStatus::Failed;
        return entry;
    }
    let Ok(raw_text) = std::str::from_utf8(content) else {
        entry.parse_status = ConfigParseStatus::Failed;
        return entry;
    };
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text);
    if text.trim().is_empty() {
        return entry;
    }

    match kind {
        MonitoredConfigKind::ClaudeSettings
        | MonitoredConfigKind::VsCodeWorkspace
        | MonitoredConfigKind::CursorConfig
        | MonitoredConfigKind::GeminiConfig => {
            if let Ok(cleaned) = strip_jsonc_and_trailing_commas(text)
                && let Ok(val) = parse_json_unique_keys(&cleaned)
                && val.is_object()
            {
                extract_from_json(&val, &mut entry);
            } else {
                entry.parse_status = ConfigParseStatus::Failed;
            }
        }
        MonitoredConfigKind::CodexConfig => {
            if let Ok(cleaned) = strip_jsonc_and_trailing_commas(text)
                && cleaned.trim_start().starts_with('{')
            {
                match parse_json_unique_keys(&cleaned) {
                    Ok(val) if val.is_object() => extract_from_json(&val, &mut entry),
                    _ => entry.parse_status = ConfigParseStatus::Failed,
                }
            } else if extract_from_toml(text, &mut entry).is_err() {
                entry.parse_status = ConfigParseStatus::Failed;
            }
        }
        MonitoredConfigKind::GitConfig => {
            if extract_from_git_ini(text, &mut entry).is_err() {
                entry.parse_status = ConfigParseStatus::Failed;
            }
        }
        MonitoredConfigKind::MonitoringConfig => {
            if let Ok(cleaned) = strip_jsonc_and_trailing_commas(text)
                && cleaned.trim_start().starts_with('{')
            {
                match parse_json_unique_keys(&cleaned) {
                    Ok(val) if val.is_object() => extract_from_json(&val, &mut entry),
                    _ => entry.parse_status = ConfigParseStatus::Failed,
                }
            } else if let Ok(yaml) = parse_yaml(text) {
                extract_from_yaml(&yaml, &mut entry);
            } else {
                entry.parse_status = ConfigParseStatus::Failed;
            }
        }
        MonitoredConfigKind::AgentMarkdown => match extract_markdown_frontmatter(text) {
            Ok(Some(fm)) => match parse_yaml(fm) {
                Ok(yaml) => extract_from_yaml(&yaml, &mut entry),
                Err(_) => entry.parse_status = ConfigParseStatus::Failed,
            },
            Ok(None) => {}
            Err(()) => entry.parse_status = ConfigParseStatus::Failed,
        },
    }
    entry
}

pub(super) fn record_env_pair_scoped(
    entry: &mut ConfigBaselineEntry,
    scope_slot: &str,
    key: &str,
    val: &str,
) {
    entry.env_keys.insert(key.to_owned());
    entry
        .env_entries
        .insert(scope_slot.to_owned(), sha256_hex(val.as_bytes()));
    let upper = key.to_ascii_uppercase();
    if ENDPOINT_ENV_VARS.contains(&upper.as_str()) && !val.trim().is_empty() {
        record_endpoint_url(entry, &format!("{scope_slot}:{upper}"), val);
    }
}

pub(super) fn record_env_pair(entry: &mut ConfigBaselineEntry, key: &str, val: &str) {
    record_env_pair_scoped(entry, &format!("env.{key}"), key, val);
}

pub(super) fn record_endpoint_url(entry: &mut ConfigBaselineEntry, slot: &str, url: &str) {
    let clean = url.trim().to_owned();
    if !clean.is_empty() {
        entry.endpoint_urls.insert(slot.to_owned(), clean.clone());
        if entry.base_url.is_none()
            || slot.ends_with("BASE_URL")
            || slot == "base_url"
            || slot == "8:base_url"
            || slot == "baseUrl"
        {
            entry.base_url = Some(clean);
        }
    }
}

fn extract_markdown_frontmatter(text: &str) -> Result<Option<&str>, ()> {
    let trimmed = text.trim_start();
    let Some(after_open) = trimmed.strip_prefix("---") else {
        return Ok(None);
    };
    let rest = if let Some(r) = after_open.strip_prefix("\r\n") {
        r
    } else if let Some(r) = after_open.strip_prefix('\n') {
        r
    } else {
        return Err(());
    };
    let mut offset: usize = 0;
    for chunk in rest.split_inclusive('\n') {
        let line = chunk
            .trim_end_matches(['\r', '\n'])
            .trim_end_matches([' ', '\t']);
        if line == "---" {
            return Ok(rest.get(..offset));
        }
        offset = offset.saturating_add(chunk.len());
    }
    Err(())
}

fn extract_from_json(val: &Value, entry: &mut ConfigBaselineEntry) {
    if let Some(hooks) = val.get("hooks").and_then(Value::as_object) {
        for (event_name, hook_val) in hooks {
            if let Some(arr) = hook_val.as_array() {
                for (idx, item) in arr.iter().enumerate() {
                    entry
                        .hook_entries
                        .insert(format!("{event_name}#{idx}:{item}"));
                }
            } else {
                entry
                    .hook_entries
                    .insert(format!("{event_name}:{hook_val}"));
            }
        }
    }
    if let Some(mcp) = val.get("mcpServers").and_then(Value::as_object) {
        for (name, srv) in mcp {
            if srv.get("command").is_some() || srv.get("url").is_some() || srv.get("env").is_some()
            {
                entry
                    .mcp_stdio_entries
                    .insert(format!("{name}:{}", redact_mcp_json_value(srv, false)));
            }
            if let Some(env_map) = srv.get("env").and_then(Value::as_object) {
                for (k, v) in env_map {
                    let v_str = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
                    record_env_pair_scoped(entry, &format!("mcpServers.{name}.env.{k}"), k, &v_str);
                }
            }
        }
    }
    if let Some(env_map) = val.get("env").and_then(Value::as_object) {
        for (k, v) in env_map {
            let v_str = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
            record_env_pair(entry, k, &v_str);
        }
    }
    for key in [
        "baseUrl",
        "base_url",
        "openaiBaseUrl",
        "anthropicBaseUrl",
        "apiBaseUrl",
        "proxy",
    ] {
        if let Some(s) = val.get(key).and_then(Value::as_str) {
            record_endpoint_url(entry, key, s);
        }
    }
    if let Some(allow) = val
        .get("permissions")
        .and_then(|p| p.get("allow"))
        .and_then(Value::as_array)
    {
        for rule in allow {
            if let Some(s) = rule.as_str() {
                entry.allow_rules.insert(s.to_owned());
            }
        }
    }
    for key in ["recipients", "alert_targets"] {
        if let Some(arr) = val.get(key).and_then(Value::as_array) {
            for r in arr {
                if let Some(s) = r.as_str() {
                    entry.recipients.insert(s.to_owned());
                }
            }
        }
    }
    if json_contains_truthy_key_ci(val, "bypassPermissions")
        || val
            .get("permissions")
            .and_then(|p| p.get("defaultMode"))
            .and_then(Value::as_str)
            .is_some_and(|m| m.eq_ignore_ascii_case("bypassPermissions"))
    {
        entry.has_bypass_permissions = true;
    }
    if json_contains_value_ci(val, "folderOpen") {
        entry.has_folder_open_task = true;
    }
    for key in ["policy_source", "managed_settings"] {
        if let Some(v) = val.get(key) {
            entry.policy_sources.insert(format!("{key}:{v}"));
        }
    }
}

fn strip_jsonc_and_trailing_commas(raw: &str) -> Result<String, ()> {
    let mut no_comments = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i: usize = 0;
    let mut in_str = false;
    let mut escaped = false;
    while let Some(&c) = chars.get(i) {
        if in_str {
            no_comments.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if c == '"' {
            in_str = true;
            no_comments.push(c);
            i = i.saturating_add(1);
            continue;
        }
        if c == '/' && chars.get(i.saturating_add(1)) == Some(&'/') {
            i = i.saturating_add(2);
            while let Some(&nc) = chars.get(i) {
                if nc == '\n' {
                    break;
                }
                i = i.saturating_add(1);
            }
            continue;
        }
        if c == '/' && chars.get(i.saturating_add(1)) == Some(&'*') {
            i = i.saturating_add(2);
            let mut closed = false;
            while let Some(&nc) = chars.get(i) {
                if nc == '*' && chars.get(i.saturating_add(1)) == Some(&'/') {
                    i = i.saturating_add(2);
                    closed = true;
                    break;
                }
                i = i.saturating_add(1);
            }
            if !closed {
                return Err(());
            }
            no_comments.push(' ');
            continue;
        }
        no_comments.push(c);
        i = i.saturating_add(1);
    }

    let c2: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(c2.len());
    let mut j: usize = 0;
    in_str = false;
    escaped = false;
    while let Some(&c) = c2.get(j) {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            j = j.saturating_add(1);
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            j = j.saturating_add(1);
            continue;
        }
        if c == ',' {
            let mut k = j.saturating_add(1);
            while c2.get(k).is_some_and(|ch| ch.is_ascii_whitespace()) {
                k = k.saturating_add(1);
            }
            if matches!(c2.get(k), Some(']' | '}')) {
                j = j.saturating_add(1);
                continue;
            }
        }
        out.push(c);
        j = j.saturating_add(1);
    }
    Ok(out)
}

fn json_contains_truthy_key_ci(val: &Value, needle: &str) -> bool {
    match val {
        Value::Object(map) => map.iter().any(|(k, v)| {
            let key_truthy = k.eq_ignore_ascii_case(needle)
                && !matches!(v, Value::Bool(false) | Value::Null)
                && !v
                    .as_str()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("false"));
            key_truthy || json_contains_truthy_key_ci(v, needle)
        }),
        Value::Array(arr) => arr.iter().any(|v| json_contains_truthy_key_ci(v, needle)),
        _ => false,
    }
}

fn redact_mcp_json_value(val: &Value, redact_scalar: bool) -> Value {
    match val {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let child_redact = redact_scalar
                    || k.eq_ignore_ascii_case("env")
                    || k.eq_ignore_ascii_case("headers");
                out.insert(k.clone(), redact_mcp_json_value(v, child_redact));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| redact_mcp_json_value(v, redact_scalar))
                .collect(),
        ),
        other if redact_scalar => {
            let s = other
                .as_str()
                .map_or_else(|| other.to_string(), str::to_owned);
            Value::String(sha256_hex(s.as_bytes()))
        }
        other => other.clone(),
    }
}

fn json_contains_value_ci(val: &Value, needle: &str) -> bool {
    match val {
        Value::String(s) => s.eq_ignore_ascii_case(needle),
        Value::Array(arr) => arr.iter().any(|v| json_contains_value_ci(v, needle)),
        Value::Object(map) => map.values().any(|v| json_contains_value_ci(v, needle)),
        _ => false,
    }
}
