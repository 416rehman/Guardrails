// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded zero-alloc hook payload scanner for `#![no_std]` fastpath inspection.

use crate::contains_norm_icase;
use crate::scanner_json::{
    decode_json_string_into, decode_utf8_prefix, has_malformed_quotes, scan_json_quoted_span,
    skip_ws,
};

pub const MAX_HOOK_SCAN_BYTES: usize = 16_384;
pub const MAX_EXTRACTED_FIELD_BYTES: usize = 2_048;

pub const FLAG_BYPASS_PERMISSION: u32 = 1 << 0;
pub const FLAG_HOOKS_DISABLED: u32 = 1 << 1;
pub const FLAG_GRDR_DISABLE: u32 = 1 << 2;
pub const FLAG_SUBSHELL: u32 = 1 << 3;
pub const FLAG_BACKTICK: u32 = 1 << 4;
pub const FLAG_ENCODED_CMD: u32 = 1 << 5;
pub const FLAG_PIPE_SHELL: u32 = 1 << 6;
pub const FLAG_RECURSIVE_FORCE: u32 = 1 << 7;
pub const FLAG_CRED_PATH: u32 = 1 << 8;
pub const FLAG_CONTROL_PATH: u32 = 1 << 9;
pub const FLAG_MALFORMED_QUOTES: u32 = 1 << 10;
pub const FLAG_TRUNCATED: u32 = 1 << 11;

const MAX_KEY_DECODE_BYTES: usize = 128;
const MAX_TARGET_SLOTS: usize = 16;

const PATTERN_RULES: &[(u32, &str)] = &[
    (FLAG_BYPASS_PERMISSION, "--dangerously-skip-permissions"),
    (FLAG_BYPASS_PERMISSION, "--no-verify"),
    (FLAG_BYPASS_PERMISSION, "--no-sandbox"),
    (FLAG_BYPASS_PERMISSION, "--disable-sandbox"),
    (FLAG_BYPASS_PERMISSION, "--yolo"),
    (FLAG_HOOKS_DISABLED, "--disable-hooks"),
    (FLAG_GRDR_DISABLE, "grdr_disable"),
    (FLAG_SUBSHELL, "$("),
    (FLAG_BACKTICK, "`"),
    (FLAG_ENCODED_CMD, "-encodedcommand"),
    (FLAG_ENCODED_CMD, " -enc "),
    (FLAG_PIPE_SHELL, "| sh"),
    (FLAG_PIPE_SHELL, "| bash"),
    (FLAG_PIPE_SHELL, "| zsh"),
    (FLAG_PIPE_SHELL, "| /bin/sh"),
    (FLAG_PIPE_SHELL, "| /bin/bash"),
    (FLAG_RECURSIVE_FORCE, "-rf"),
    (FLAG_RECURSIVE_FORCE, "-fr"),
    (FLAG_RECURSIVE_FORCE, "rm -r -f"),
    (FLAG_RECURSIVE_FORCE, "remove-item -recurse -force"),
    (FLAG_CRED_PATH, ".ssh/"),
    (FLAG_CRED_PATH, ".aws/"),
    (FLAG_CRED_PATH, ".gnupg/"),
    (FLAG_CRED_PATH, ".config/gh/"),
    (FLAG_CRED_PATH, "id_rsa"),
    (FLAG_CRED_PATH, "id_ed25519"),
    (FLAG_CRED_PATH, ".env.production"),
    (FLAG_CONTROL_PATH, ".claude/"),
    (FLAG_CONTROL_PATH, ".claude.json"),
    (FLAG_CONTROL_PATH, ".cursor/"),
    (FLAG_CONTROL_PATH, ".codex/"),
    (FLAG_CONTROL_PATH, ".gemini/"),
    (FLAG_CONTROL_PATH, ".windsurf/"),
    (FLAG_CONTROL_PATH, ".grdr/"),
    (FLAG_CONTROL_PATH, "grdr-data/"),
];

const FILE_TOOLS: &[&str] = &[
    "read",
    "edit",
    "write",
    "multiedit",
    "delete",
    "file_read",
    "file_write",
    "file_delete",
    "notebookedit",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
    "create_file",
    "apply_patch",
    "view_file",
    "read_file",
    "write_file",
    "delete_file",
    "removefile",
    "editfile",
    "writetofile",
    "afterfileedit",
    "beforereadfile",
];

const NET_TOOLS: &[&str] = &["webfetch", "websearch", "net_request"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookScanResult<'a> {
    pub flags: u32,
    pub tool_name: &'a str,
    pub target: &'a str,
    pub agent: &'a str,
    pub scanned_bytes: usize,
}

struct RootHeaders<'a> {
    tool_name: &'a str,
    tool_trunc: bool,
    agent: &'a str,
    agent_trunc: bool,
}

pub fn scan_hook_payload<'a>(raw: &'a [u8], max_bytes: usize) -> HookScanResult<'a> {
    let cap = max_bytes.min(MAX_HOOK_SCAN_BYTES);
    let mut flags: u32 = 0;
    let bounded = if raw.len() > cap {
        flags |= FLAG_TRUNCATED;
        raw.get(..cap).unwrap_or(&[])
    } else {
        raw
    };

    let text = match decode_utf8_prefix(bounded) {
        Some(valid) => valid,
        None => {
            return HookScanResult {
                flags: flags | FLAG_MALFORMED_QUOTES | scan_raw_ascii_flags(bounded),
                tool_name: "",
                target: "",
                agent: "",
                scanned_bytes: bounded.len(),
            };
        }
    };

    let hdr = extract_root_headers(text);
    if hdr.tool_trunc || hdr.agent_trunc {
        flags |= FLAG_TRUNCATED;
    }

    let mut tool_buf = [0u8; MAX_KEY_DECODE_BYTES];
    let (decoded_tool, _) = decode_json_string_into(hdr.tool_name, &mut tool_buf);
    let target_keys = target_keys_for_tool(decoded_tool);
    let checks_quotes = target_checks_shell_quotes(decoded_tool);
    let (target, target_trunc, scan_flags) =
        extract_targets_and_flags(text, target_keys, checks_quotes);
    flags |= scan_flags;
    if target_trunc {
        flags |= FLAG_TRUNCATED;
    }

    HookScanResult {
        flags,
        tool_name: hdr.tool_name,
        target,
        agent: hdr.agent,
        scanned_bytes: bounded.len(),
    }
}

fn is_file_tool(tool_name: &str) -> bool {
    FILE_TOOLS.iter().any(|name| eq_tool_ascii(tool_name, name))
}

fn is_net_tool(tool_name: &str) -> bool {
    NET_TOOLS.iter().any(|name| eq_tool_ascii(tool_name, name))
}

fn target_checks_shell_quotes(tool_name: &str) -> bool {
    !(is_file_tool(tool_name) || is_net_tool(tool_name))
}

fn target_keys_for_tool(tool_name: &str) -> &'static [&'static str] {
    if crate::starts_with_norm_icase(tool_name, "mcp__")
        || eq_tool_ascii(tool_name, "mcp_call")
        || eq_tool_ascii(tool_name, "mcp_connect")
    {
        &[
            "path",
            "file_path",
            "TargetFile",
            "AbsolutePath",
            "url",
            "Url",
            "uri",
            "target",
            "command",
            "cmd",
            "CommandLine",
            "command_line",
            "script",
            "server",
            "tool",
            "input",
        ]
    } else if is_file_tool(tool_name) {
        &[
            "file_path",
            "target_file",
            "TargetFile",
            "AbsolutePath",
            "notebook_path",
            "path",
            "patch",
            "target",
            "command",
            "cmd",
            "CommandLine",
            "url",
            "Url",
            "input",
        ]
    } else if is_net_tool(tool_name) {
        &[
            "url",
            "Url",
            "uri",
            "query",
            "target",
            "command",
            "cmd",
            "CommandLine",
            "file_path",
            "path",
        ]
    } else {
        &[
            "command",
            "cmd",
            "CommandLine",
            "command_line",
            "script",
            "file_path",
            "target_file",
            "TargetFile",
            "AbsolutePath",
            "notebook_path",
            "path",
            "patch",
            "target",
            "url",
            "Url",
            "input",
        ]
    }
}

fn key_checks_shell_quotes(key: &str) -> bool {
    matches!(
        key,
        "command" | "cmd" | "CommandLine" | "command_line" | "script" | "target"
    )
}

fn eq_tool_ascii(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn scan_str_flags(text: &str) -> u32 {
    let mut flags: u32 = 0;
    for &(bit, pattern) in PATTERN_RULES {
        if contains_norm_icase(text, pattern) {
            flags |= bit;
        }
    }
    flags
}

fn scan_raw_ascii_flags(bytes: &[u8]) -> u32 {
    let mut flags: u32 = 0;
    for &(bit, pattern) in PATTERN_RULES {
        let pat = pattern.as_bytes();
        if !pat.is_empty()
            && bytes.len() >= pat.len()
            && bytes.windows(pat.len()).any(|w| {
                w.iter()
                    .zip(pat.iter())
                    .all(|(x, y)| norm_ascii(*x) == norm_ascii(*y))
            })
        {
            flags |= bit;
        }
    }
    flags
}

fn norm_ascii(b: u8) -> u8 {
    if b == b'\\' {
        b'/'
    } else {
        b.to_ascii_lowercase()
    }
}

fn extract_root_headers<'a>(text: &'a str) -> RootHeaders<'a> {
    let bytes = text.as_bytes();
    let mut i: usize = 0;
    let mut depth: usize = 0;
    let mut tool_primary: Option<(&'a str, bool)> = None;
    let mut tool_alias: Option<(&'a str, bool)> = None;
    let mut agent_primary: Option<(&'a str, bool)> = None;
    let mut agent_alias: Option<(&'a str, bool)> = None;
    let mut key_buf = [0u8; MAX_KEY_DECODE_BYTES];

    while let Some(&b) = bytes.get(i) {
        match b {
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                i = i.saturating_add(1);
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i = i.saturating_add(1);
            }
            b'"' => {
                let (key_slice, after_key, _) =
                    scan_json_quoted_span(bytes, i, MAX_EXTRACTED_FIELD_BYTES);
                let cursor = skip_ws(bytes, after_key);
                if bytes.get(cursor) == Some(&b':') {
                    let val_ws = skip_ws(bytes, cursor.saturating_add(1));
                    if depth == 1 && bytes.get(val_ws) == Some(&b'"') {
                        let key_str = decode_utf8_prefix(key_slice).unwrap_or("");
                        let (kdec, ktrunc) = decode_json_string_into(key_str, &mut key_buf);
                        let (val_bytes, after_val, trunc) =
                            scan_json_quoted_span(bytes, val_ws, MAX_EXTRACTED_FIELD_BYTES);
                        let val_str = decode_utf8_prefix(val_bytes).unwrap_or("");
                        if !ktrunc {
                            match kdec {
                                "tool_name" => tool_primary = Some((val_str, trunc)),
                                "tool" => tool_alias = Some((val_str, trunc)),
                                "agent_name" => agent_primary = Some((val_str, trunc)),
                                "agent" => agent_alias = Some((val_str, trunc)),
                                _ => {}
                            }
                        }
                        i = after_val;
                        continue;
                    }
                    i = val_ws;
                } else {
                    i = after_key;
                }
            }
            _ => i = i.saturating_add(1),
        }
    }
    let (tool_name, tool_trunc) = tool_primary.or(tool_alias).unwrap_or(("", false));
    let (agent, agent_trunc) = agent_primary.or(agent_alias).unwrap_or(("", false));
    RootHeaders {
        tool_name,
        tool_trunc,
        agent,
        agent_trunc,
    }
}

fn extract_targets_and_flags<'a>(
    text: &'a str,
    keys: &[&str],
    checks_quotes: bool,
) -> (&'a str, bool, u32) {
    let bytes = text.as_bytes();
    let mut i: usize = 0;
    let mut depth: usize = 0;
    let mut tool_input_depth: Option<usize> = None;
    let mut top_slots: [Option<(&'a str, bool)>; MAX_TARGET_SLOTS] = [None; MAX_TARGET_SLOTS];
    let mut ti_slots: [Option<(&'a str, bool)>; MAX_TARGET_SLOTS] = [None; MAX_TARGET_SLOTS];
    let mut flags: u32 = 0;
    let mut key_buf = [0u8; MAX_KEY_DECODE_BYTES];
    let mut val_buf = [0u8; MAX_EXTRACTED_FIELD_BYTES];

    while let Some(&b) = bytes.get(i) {
        match b {
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                i = i.saturating_add(1);
            }
            b'}' | b']' => {
                if tool_input_depth == Some(depth) {
                    tool_input_depth = None;
                }
                depth = depth.saturating_sub(1);
                i = i.saturating_add(1);
            }
            b'"' => {
                let (key_slice, after_key, _) =
                    scan_json_quoted_span(bytes, i, MAX_EXTRACTED_FIELD_BYTES);
                let cursor = skip_ws(bytes, after_key);
                if bytes.get(cursor) == Some(&b':') {
                    let val_ws = skip_ws(bytes, cursor.saturating_add(1));
                    let key_str = decode_utf8_prefix(key_slice).unwrap_or("");
                    let (kdec, ktrunc) = decode_json_string_into(key_str, &mut key_buf);
                    if depth == 1
                        && !ktrunc
                        && kdec == "tool_input"
                        && bytes.get(val_ws) == Some(&b'{')
                    {
                        ti_slots = [None; MAX_TARGET_SLOTS];
                        tool_input_depth = Some(depth.saturating_add(1));
                        depth = depth.saturating_add(1);
                        i = val_ws.saturating_add(1);
                        continue;
                    }
                    if bytes.get(val_ws) == Some(&b'"') {
                        let (val_bytes, after_val, val_trunc) =
                            scan_json_quoted_span(bytes, val_ws, MAX_EXTRACTED_FIELD_BYTES);
                        let val_str = decode_utf8_prefix(val_bytes).unwrap_or("");
                        let in_ti_root = tool_input_depth.is_some_and(|d| depth == d);
                        let in_ti_any = tool_input_depth.is_some_and(|d| depth >= d);
                        let key_idx = if !ktrunc && (in_ti_root || depth == 1) {
                            keys.iter().take(MAX_TARGET_SLOTS).position(|&k| k == kdec)
                        } else {
                            None
                        };
                        if let Some(slot_idx) = key_idx {
                            if in_ti_root {
                                if let Some(slot) = ti_slots.get_mut(slot_idx) {
                                    *slot = Some((val_str, val_trunc));
                                }
                            } else if let Some(slot) = top_slots.get_mut(slot_idx) {
                                *slot = Some((val_str, val_trunc));
                            }
                        }
                        if key_idx.is_some() || in_ti_any {
                            let (decoded, dec_trunc) =
                                decode_json_string_into(val_str, &mut val_buf);
                            if val_trunc || dec_trunc {
                                flags |= FLAG_TRUNCATED;
                            }
                            flags |= scan_str_flags(decoded);
                            if key_idx.is_some()
                                && checks_quotes
                                && key_checks_shell_quotes(kdec)
                                && has_malformed_quotes(decoded)
                            {
                                flags |= FLAG_MALFORMED_QUOTES;
                            }
                        }
                        i = after_val;
                        continue;
                    }
                    i = val_ws;
                } else {
                    if tool_input_depth.is_some_and(|d| depth >= d) {
                        let val_str = decode_utf8_prefix(key_slice).unwrap_or("");
                        let (decoded, dec_trunc) = decode_json_string_into(val_str, &mut val_buf);
                        if dec_trunc {
                            flags |= FLAG_TRUNCATED;
                        }
                        flags |= scan_str_flags(decoded);
                    }
                    i = after_key;
                }
            }
            _ => i = i.saturating_add(1),
        }
    }

    let winner = ti_slots
        .iter()
        .flatten()
        .copied()
        .find(|(v, t)| !v.is_empty() || *t)
        .or_else(|| {
            top_slots
                .iter()
                .flatten()
                .copied()
                .find(|(v, t)| !v.is_empty() || *t)
        })
        .unwrap_or(("", false));
    (winner.0, winner.1, flags)
}
