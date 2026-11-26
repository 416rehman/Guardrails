// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! JSON strict key-uniqueness parser, YAML, and Git INI extractors for `detect::config_integrity` (`D-09`).

use grdr_crypto::sha256_hex;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::detect::config_integrity::ConfigBaselineEntry;
use crate::detect::config_parse::{record_endpoint_url, record_env_pair, record_env_pair_scoped};
use crate::detect::yaml::YamlValue;

const MAX_JSON_DEPTH: usize = 64;

struct UniqueJsonValue(usize);

struct UniqueJsonVisitor(usize);

impl<'de> DeserializeSeed<'de> for UniqueJsonValue {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.0 > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting depth exceeded"));
        }
        deserializer.deserialize_any(UniqueJsonVisitor(self.0))
    }
}

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite JSON float"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(elem) = seq.next_element_seed(UniqueJsonValue(self.0.saturating_add(1)))? {
            out.push(elem);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let v = map.next_value_seed(UniqueJsonValue(self.0.saturating_add(1)))?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

pub(super) fn parse_json_unique_keys(raw: &str) -> Result<Value, ()> {
    let mut de = serde_json::Deserializer::from_str(raw);
    let val = UniqueJsonValue(0).deserialize(&mut de).map_err(|_| ())?;
    de.end().map_err(|_| ())?;
    Ok(val)
}

pub(super) fn extract_from_yaml(yaml: &YamlValue, entry: &mut ConfigBaselineEntry) {
    for key in ["recipients", "alert_targets"] {
        if let Some(list) = yaml.get(key) {
            for r in list.to_string_list() {
                entry.recipients.insert(r);
            }
        }
    }
    if let Some(hooks) = yaml.get("hooks").and_then(YamlValue::as_map) {
        for (k, v) in hooks {
            entry.hook_entries.insert(format!("{k}:{v:?}"));
        }
    }
    if let Some(mcp) = yaml.get("mcpServers").and_then(YamlValue::as_map) {
        for (name, srv) in mcp {
            if srv.get("command").is_some() || srv.get("url").is_some() || srv.get("env").is_some()
            {
                entry
                    .mcp_stdio_entries
                    .insert(format!("{name}:{}", format_redacted_yaml_mcp(srv, false)));
            }
            if let Some(env_map) = srv.get("env").and_then(YamlValue::as_map) {
                for (k, v) in env_map {
                    let v_str = v.as_str().map_or_else(|| format!("{v:?}"), str::to_owned);
                    record_env_pair_scoped(entry, &format!("mcpServers.{name}.env.{k}"), k, &v_str);
                }
            }
        }
    }
    if let Some(env_map) = yaml.get("env").and_then(YamlValue::as_map) {
        for (k, v) in env_map {
            let v_str = v.as_str().map_or_else(|| format!("{v:?}"), str::to_owned);
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
        if let Some(s) = yaml.get(key).and_then(YamlValue::as_str) {
            record_endpoint_url(entry, key, s);
        }
    }
    if let Some(allow) = yaml.get("permissions").and_then(|p| p.get("allow")) {
        for rule in allow.to_string_list() {
            entry.allow_rules.insert(rule);
        }
    }
    if yaml_contains_truthy_key_ci(yaml, "bypassPermissions")
        || yaml
            .get("permissions")
            .and_then(|p| p.get("defaultMode"))
            .and_then(YamlValue::as_str)
            .is_some_and(|m| m.eq_ignore_ascii_case("bypassPermissions"))
    {
        entry.has_bypass_permissions = true;
    }
    for key in ["policy_source", "managed_settings"] {
        if let Some(v) = yaml.get(key) {
            entry.policy_sources.insert(format!("{key}:{v:?}"));
        }
    }
}

fn format_redacted_yaml_mcp(val: &YamlValue, redact_scalar: bool) -> String {
    match val {
        YamlValue::Map(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let child_redact = redact_scalar
                        || k.eq_ignore_ascii_case("env")
                        || k.eq_ignore_ascii_case("headers");
                    format!("{k}={}", format_redacted_yaml_mcp(v, child_redact))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        YamlValue::Seq(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|v| format_redacted_yaml_mcp(v, redact_scalar))
                .collect();
            format!("[{}]", parts.join(","))
        }
        other if redact_scalar => {
            let raw = other
                .as_str()
                .map_or_else(|| format!("{other:?}"), str::to_owned);
            format!("sha256:{}", sha256_hex(raw.as_bytes()))
        }
        other => format!("{other:?}"),
    }
}

fn yaml_contains_truthy_key_ci(val: &YamlValue, needle: &str) -> bool {
    match val {
        YamlValue::Map(map) => map.iter().any(|(k, v)| {
            let key_truthy = k.eq_ignore_ascii_case(needle)
                && !matches!(v, YamlValue::Bool(false) | YamlValue::Null)
                && !v
                    .as_str()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("false"));
            key_truthy || yaml_contains_truthy_key_ci(v, needle)
        }),
        YamlValue::Seq(items) => items.iter().any(|v| yaml_contains_truthy_key_ci(v, needle)),
        _ => false,
    }
}

pub(super) fn extract_from_git_ini(text: &str, entry: &mut ConfigBaselineEntry) -> Result<(), ()> {
    let mut section = String::new();
    for raw_line in text.lines() {
        let line = strip_git_ini_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(after) = trimmed.strip_prefix('[') {
            let sec = after.strip_suffix(']').ok_or(())?;
            if has_unquoted_ini_meta(sec) {
                return Err(());
            }
            section = sec.trim().to_ascii_lowercase();
            continue;
        }
        let (k, v) = trimmed.split_once('=').ok_or(())?;
        let key = k.trim().to_ascii_lowercase();
        let val = unquote_ini_val(v.trim());
        let base_sec = section
            .split(|c: char| c.is_ascii_whitespace() || c == '"' || c == '.')
            .next()
            .unwrap_or("");
        if base_sec == "core"
            && (key == "fsmonitor" || key == "sshcommand" || key == "hookspath" || key == "askpass")
        {
            entry.hook_entries.insert(format!("git.{key}:{val}"));
        } else if (base_sec == "include" || base_sec == "includeif") && key == "path" {
            entry
                .hook_entries
                .insert(format!("git.include:{section}:{val}"));
            entry
                .policy_sources
                .insert(format!("git.include:{section}:{val}"));
        } else if base_sec == "credential" && key == "helper" {
            entry
                .hook_entries
                .insert(format!("git.{section}.helper:{val}"));
        } else if base_sec == "http" && key == "proxy" {
            record_endpoint_url(entry, &format!("git.{section}.proxy"), &val);
        }
    }
    Ok(())
}

fn strip_git_ini_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if in_quotes {
            out.push(ch);
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }
        if ch == '#' || ch == ';' {
            break;
        }
        if ch == '"' {
            in_quotes = true;
        }
        out.push(ch);
    }
    out
}

fn unquote_ini_val(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw.get(1..raw.len().saturating_sub(1))
            .unwrap_or("")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        raw.to_owned()
    }
}

fn has_unquoted_ini_meta(sec: &str) -> bool {
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in sec.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }
        match ch {
            '"' => in_quotes = true,
            '[' | ']' | '=' => return true,
            _ => {}
        }
    }
    in_quotes
}
