// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded zero-alloc hook payload scanner for `#![no_std]` fastpath inspection.

use crate::contains_norm_icase;
use crate::manifest::FastpathTablesManifest;
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
    let manifest = FastpathTablesManifest::embedded();
    scan_hook_payload_with_manifest(raw, max_bytes, &manifest)
}

pub fn scan_hook_payload_with_manifest<'a>(
    raw: &'a [u8],
    max_bytes: usize,
    manifest: &FastpathTablesManifest<'_>,
) -> HookScanResult<'a> {
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
                flags: flags | FLAG_MALFORMED_QUOTES | scan_raw_ascii_flags(bounded, manifest),
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
    let target_section = target_section_for_tool(decoded_tool, manifest);
    let checks_quotes = target_checks_shell_quotes(decoded_tool, manifest);
    let (target, target_trunc, scan_flags) =
        extract_targets_and_flags(text, target_section, checks_quotes, manifest);
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

fn target_checks_shell_quotes(tool_name: &str, manifest: &FastpathTablesManifest<'_>) -> bool {
    !(manifest.contains_list_item_icase("file_tools", tool_name)
        || manifest.contains_list_item_icase("net_tools", tool_name))
}

fn target_section_for_tool(tool_name: &str, manifest: &FastpathTablesManifest<'_>) -> &'static str {
    if crate::starts_with_norm_icase(tool_name, "mcp__")
        || tool_name.eq_ignore_ascii_case("mcp_call")
        || tool_name.eq_ignore_ascii_case("mcp_connect")
    {
        "mcp_target_keys"
    } else if manifest.contains_list_item_icase("file_tools", tool_name) {
        "file_target_keys"
    } else if manifest.contains_list_item_icase("net_tools", tool_name) {
        "net_target_keys"
    } else {
        "default_target_keys"
    }
}

fn find_target_slot(
    manifest: &FastpathTablesManifest<'_>,
    section: &str,
    key_name: &str,
) -> Option<usize> {
    let mut slot_idx: usize = 0;
    let mut matched: Option<usize> = None;
    manifest.visit_array_items(section, &mut |item| {
        if matched.is_none() && slot_idx < MAX_TARGET_SLOTS {
            if item == key_name {
                matched = Some(slot_idx);
            }
            slot_idx = slot_idx.saturating_add(1);
        }
    });
    matched
}

fn scan_str_flags(text: &str, manifest: &FastpathTablesManifest<'_>) -> u32 {
    let mut flags: u32 = 0;
    manifest.visit_scanner_patterns(|bit, pattern| {
        if contains_norm_icase(text, pattern) {
            flags |= bit;
        }
    });
    flags
}

fn scan_raw_ascii_flags(bytes: &[u8], manifest: &FastpathTablesManifest<'_>) -> u32 {
    let mut flags: u32 = 0;
    manifest.visit_scanner_patterns(|bit, pattern| {
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
    });
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
    target_section: &str,
    checks_quotes: bool,
    manifest: &FastpathTablesManifest<'_>,
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
                            find_target_slot(manifest, target_section, kdec)
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
                            flags |= scan_str_flags(decoded, manifest);
                            if key_idx.is_some()
                                && checks_quotes
                                && manifest.matches_any_list_exact("shell_quote_keys", kdec)
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
                        flags |= scan_str_flags(decoded, manifest);
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
