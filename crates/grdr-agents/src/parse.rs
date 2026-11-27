// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Safe regular-file JSON parsing, hook command matching, and MCP endpoint/command scrubbing.

use std::path::Path;

use serde_json::Value;

use grdr_model::McpServerEntry;
use grdr_ports::LocalFsPort;

const MAX_CONFIG_READ_BYTES: u64 = 1_048_576;
const MAX_JSON_INSPECT_DEPTH: usize = 64;

struct PendingTomlMcp {
    name: String,
    command: Option<String>,
    url: Option<String>,
    pinned: bool,
}

pub(crate) fn read_json(path: &Path, fs: &dyn LocalFsPort) -> Result<Value, String> {
    let raw = fs.read_bounded_regular_string(path, MAX_CONFIG_READ_BYTES)?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn json_contains_hook_command(val: &Value, root_key: &str, hook_command: &str) -> bool {
    let key = if root_key.is_empty() {
        "hooks"
    } else {
        root_key
    };
    let Some(hooks) = val.get(key) else {
        return false;
    };
    json_value_contains_hook_command(hooks, hook_command)
}

pub(crate) fn json_value_contains_hook_command(val: &Value, expected_cmd: &str) -> bool {
    let expected_bin = command_basename_normalized(expected_cmd);
    if expected_bin.is_empty() {
        return false;
    }
    let mut stack = vec![(val, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_JSON_INSPECT_DEPTH {
            continue;
        }
        match node {
            Value::Array(items) => {
                for item in items {
                    stack.push((item, depth.saturating_add(1)));
                }
            }
            Value::Object(map) => {
                for (k, v) in map {
                    if matches!(k.as_str(), "command" | "cmd" | "script") {
                        if let Some(text) = v.as_str()
                            && !text.contains("://")
                            && command_basename_normalized(text) == expected_bin
                        {
                            return true;
                        }
                        if k == "command"
                            && let Some(items) = v.as_array()
                            && let Some(text) = items.first().and_then(Value::as_str)
                            && !text.contains("://")
                            && command_basename_normalized(text) == expected_bin
                        {
                            return true;
                        }
                    }
                    if v.is_object() || v.is_array() {
                        stack.push((v, depth.saturating_add(1)));
                    }
                }
            }
            _ => {}
        }
    }
    false
}

pub(crate) fn extract_mcp_servers_by_key(
    val: &Value,
    preferred_key: &str,
    source_agent: &str,
    config_path: &Path,
    out: &mut Vec<McpServerEntry>,
) {
    let servers = if !preferred_key.is_empty() {
        val.get(preferred_key)
    } else {
        None
    }
    .or_else(|| val.get("mcpServers"))
    .or_else(|| val.get("servers"))
    .or_else(|| val.get("mcp"))
    .or_else(|| val.get("context_servers"))
    .and_then(Value::as_object);
    let Some(map) = servers else {
        return;
    };

    for (name, cfg) in map {
        let transport = if cfg.get("url").is_some() {
            "http"
        } else {
            "stdio"
        };
        let command = cfg
            .get("command")
            .and_then(Value::as_str)
            .map(command_basename)
            .or_else(|| cfg.get("url").and_then(Value::as_str).map(strip_url_query))
            .unwrap_or_else(|| "unknown".into());

        out.push(McpServerEntry {
            name: name.clone(),
            transport: transport.into(),
            command,
            source_agent: source_agent.into(),
            config_path: display_path(config_path),
            pinned: cfg.get("digest").is_some() || cfg.get("sha256").is_some(),
        });
    }
}

fn flush_toml_mcp(
    pending: Option<PendingTomlMcp>,
    source_agent: &str,
    config_path: &Path,
    out: &mut Vec<McpServerEntry>,
) {
    let Some(entry) = pending else {
        return;
    };
    let (transport, command) = if let Some(cmd) = entry.command.as_deref() {
        let base = command_basename(cmd);
        let cleaned = if base.is_empty() {
            "stdio-toml".into()
        } else {
            base
        };
        ("stdio", cleaned)
    } else if let Some(url) = entry.url.as_deref() {
        let cleaned = strip_url_query(url);
        let value = if cleaned.is_empty() {
            "stdio-toml".into()
        } else {
            cleaned
        };
        ("http", value)
    } else {
        ("stdio", "stdio-toml".into())
    };
    out.push(McpServerEntry {
        name: entry.name,
        transport: transport.into(),
        command,
        source_agent: source_agent.into(),
        config_path: display_path(config_path),
        pinned: entry.pinned,
    });
}

fn parse_toml_scalar_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            if c == '"' {
                return Some(out);
            }
            if c == '\\'
                && let Some(esc) = chars.next()
            {
                out.push(esc);
                continue;
            }
            out.push(c);
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('\'') {
        let end = rest.find('\'')?;
        return rest.get(..end).map(str::to_owned);
    }
    let no_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if no_comment.is_empty() {
        None
    } else {
        Some(no_comment.to_owned())
    }
}

pub(crate) fn extract_toml_mcp_headers(
    text: &str,
    source_agent: &str,
    config_path: &Path,
    out: &mut Vec<McpServerEntry>,
) {
    let mut current: Option<PendingTomlMcp> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush_toml_mcp(current.take(), source_agent, config_path, out);
            if let Some(rest) = trimmed.strip_prefix("[mcp_servers.")
                && let Some(raw_name) = rest.strip_suffix(']')
            {
                let unquoted = raw_name.trim().trim_matches('"').trim_matches('\'').trim();
                if !unquoted.is_empty() && !unquoted.contains('.') {
                    current = Some(PendingTomlMcp {
                        name: unquoted.to_owned(),
                        command: None,
                        url: None,
                        pinned: false,
                    });
                }
            }
            continue;
        }
        if let Some(pending) = current.as_mut()
            && let Some((raw_k, raw_v)) = trimmed.split_once('=')
        {
            match raw_k.trim() {
                "command" => {
                    if let Some(cmd) = parse_toml_scalar_string(raw_v)
                        && !cmd.is_empty()
                    {
                        pending.command = Some(cmd);
                    }
                }
                "url" => {
                    if let Some(url) = parse_toml_scalar_string(raw_v)
                        && !url.is_empty()
                    {
                        pending.url = Some(url);
                    }
                }
                "digest" | "sha256" => {
                    pending.pinned = true;
                }
                _ => {}
            }
        }
    }
    flush_toml_mcp(current.take(), source_agent, config_path, out);
}

fn leading_exec_token(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(after_quote) = trimmed.strip_prefix('"') {
        if let Some(end) = after_quote.find('"')
            && let Some(slice) = after_quote.get(..end)
        {
            return slice;
        }
    } else if let Some(after_quote) = trimmed.strip_prefix('\'')
        && let Some(end) = after_quote.find('\'')
        && let Some(slice) = after_quote.get(..end)
    {
        return slice;
    }
    trimmed.split_whitespace().next().unwrap_or("")
}

fn command_basename_normalized(raw: &str) -> String {
    let base = command_basename(raw).to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_owned()
}

pub(crate) fn command_basename(raw: &str) -> String {
    let token = leading_exec_token(raw);
    if token.is_empty() {
        return String::new();
    }
    token
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(token)
        .to_string()
}

pub(crate) fn strip_url_query(raw: &str) -> String {
    let without_frag = raw.split('#').next().unwrap_or(raw);
    let without_query = without_frag.split('?').next().unwrap_or(without_frag);
    let Some(scheme_end) = without_query.find("://") else {
        return without_query.to_owned();
    };
    let auth_start = scheme_end.saturating_add(3);
    let Some(rest) = without_query.get(auth_start..) else {
        return without_query.to_owned();
    };
    let auth_len = rest.find('/').unwrap_or(rest.len());
    let Some(authority) = rest.get(..auth_len) else {
        return without_query.to_owned();
    };
    if let Some(at_pos) = authority.rfind('@')
        && let Some(scheme) = without_query.get(..auth_start)
        && let Some(host_and_path) = rest.get(at_pos.saturating_add(1)..)
    {
        return format!("{scheme}{host_and_path}");
    }
    without_query.to_owned()
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
