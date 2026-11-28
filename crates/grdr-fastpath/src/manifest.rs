// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! `#![no_std]` zero-allocation parser for fastpath tool catalogs, pattern rules, and failsafes.

use crate::scanner::{
    FLAG_BACKTICK, FLAG_BYPASS_PERMISSION, FLAG_CONTROL_PATH, FLAG_CRED_PATH, FLAG_ENCODED_CMD,
    FLAG_GRDR_DISABLE, FLAG_HOOKS_DISABLED, FLAG_PIPE_SHELL, FLAG_RECURSIVE_FORCE, FLAG_SUBSHELL,
};
use crate::{FastActionClass, FastVerdict};

pub const EMBEDDED_SCANNER_TABLES_TOML: &str = include_str!("../manifests/scanner-rules.toml");
pub const EMBEDDED_ESSENTIALS_LISTS_YAML: &str =
    include_str!("../../../packs/essentials/lists/protected-paths.yaml");
pub const EMBEDDED_AGENT_CONTROL_YAML: &str =
    include_str!("../../../packs/agents/lists/agent-control-files.yaml");
pub const EMBEDDED_SECRET_PATHS_YAML: &str =
    include_str!("../../../packs/secrets/lists/secret-paths.yaml");
pub const EMBEDDED_DESTRUCTIVE_YAML: &str =
    include_str!("../../../packs/destructive/lists/destructive-patterns.yaml");
pub const EMBEDDED_SUPPLY_CHAIN_YAML: &str =
    include_str!("../../../packs/supply-chain/lists/supply-chain-patterns.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastpathTablesManifest<'a> {
    pub raw: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailsafeRuleRow<'a> {
    pub action_mask: u32,
    pub verdict: FastVerdict,
    pub needle: &'a str,
    pub rule_id: &'a str,
    pub reason: &'a str,
}

impl<'a> FastpathTablesManifest<'a> {
    pub const fn embedded() -> FastpathTablesManifest<'static> {
        FastpathTablesManifest {
            raw: EMBEDDED_SCANNER_TABLES_TOML,
        }
    }

    pub const fn from_toml(raw: &'a str) -> Self {
        Self { raw }
    }

    pub fn contains_list_item_icase(&self, key_name: &str, value: &str) -> bool {
        let mut found = false;
        self.visit_array_items(key_name, &mut |item| {
            if item.eq_ignore_ascii_case(value) {
                found = true;
            }
        });
        found
    }

    pub fn matches_any_list_exact(&self, key_name: &str, value: &str) -> bool {
        let mut found = false;
        self.visit_array_items(key_name, &mut |item| {
            if item == value {
                found = true;
            }
        });
        found
    }

    pub fn visit_array_items<F>(&self, key_name: &str, visitor: &mut F)
    where
        F: FnMut(&'a str),
    {
        let mut in_array = false;
        for line in self.raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !in_array {
                if let Some((lhs, rhs)) = trimmed.split_once('=')
                    && lhs.trim() == key_name
                    && rhs.trim_start().starts_with('[')
                {
                    in_array = true;
                    let after_open = rhs.trim_start().strip_prefix('[').unwrap_or("");
                    if let Some(before_close) = after_open.strip_suffix(']') {
                        emit_inline_items(before_close, visitor);
                        in_array = false;
                    } else {
                        emit_inline_items(after_open, visitor);
                    }
                }
                continue;
            }
            if let Some(before_close) = trimmed.strip_suffix(']') {
                emit_inline_items(before_close, visitor);
                in_array = false;
            } else {
                emit_inline_items(trimmed, visitor);
            }
        }
    }

    pub fn visit_scanner_patterns<F>(&self, mut visitor: F)
    where
        F: FnMut(u32, &'a str),
    {
        let mut in_section = false;
        for line in self.raw.lines() {
            let trimmed = line.trim();
            if trimmed == "[scanner_patterns]" {
                in_section = true;
                continue;
            }
            if trimmed.starts_with('[') {
                in_section = false;
                continue;
            }
            if !in_section {
                continue;
            }
            if let Some(item) = parse_quoted_line_item(trimmed)
                && let Some((bit_name, pat)) = item.split_once('|')
                && let Some(bit) = scanner_flag_bit(bit_name)
                && !pat.is_empty()
            {
                visitor(bit, pat);
            }
        }
        visit_yaml_list(EMBEDDED_SECRET_PATHS_YAML, &mut |pat| {
            visitor(FLAG_CRED_PATH, pat);
        });
        visit_yaml_list(EMBEDDED_AGENT_CONTROL_YAML, &mut |pat| {
            visitor(FLAG_CONTROL_PATH, pat);
        });
    }

    pub fn visit_failsafe_rules<F>(&self, mut visitor: F)
    where
        F: FnMut(FailsafeRuleRow<'a>),
    {
        let mut in_section = false;
        for line in self.raw.lines() {
            let trimmed = line.trim();
            if trimmed == "[failsafe_rules]" {
                in_section = true;
                continue;
            }
            if trimmed.starts_with('[') {
                in_section = false;
                continue;
            }
            if !in_section {
                continue;
            }
            if let Some(row) = parse_quoted_line_item(trimmed).and_then(parse_failsafe_row) {
                visitor(row);
            }
        }
    }
}

pub fn visit_yaml_list<'a, F>(yaml_raw: &'a str, visitor: &mut F)
where
    F: FnMut(&'a str),
{
    for line in yaml_raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- ") {
            let cleaned = strip_quotes(rest.trim());
            if !cleaned.is_empty() {
                visitor(cleaned);
            }
        }
    }
}

fn emit_inline_items<'a, F>(segment: &'a str, visitor: &mut F)
where
    F: FnMut(&'a str),
{
    if let Some(item) = parse_quoted_line_item(segment) {
        visitor(item);
        return;
    }
    for part in segment.split(',') {
        let p = part.trim();
        if let Some(unquoted) = extract_quoted(p) {
            visitor(unquoted);
        }
    }
}

fn parse_quoted_line_item(trimmed: &str) -> Option<&str> {
    let without_comma = trimmed.strip_suffix(',').unwrap_or(trimmed).trim();
    extract_quoted(without_comma)
}

fn extract_quoted(raw: &str) -> Option<&str> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    if inner.is_empty() { None } else { Some(inner) }
}

fn strip_quotes(raw: &str) -> &str {
    raw.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(raw)
}

fn scanner_flag_bit(name: &str) -> Option<u32> {
    match name {
        "BYPASS_PERMISSION" => Some(FLAG_BYPASS_PERMISSION),
        "HOOKS_DISABLED" => Some(FLAG_HOOKS_DISABLED),
        "GRDR_DISABLE" => Some(FLAG_GRDR_DISABLE),
        "SUBSHELL" => Some(FLAG_SUBSHELL),
        "BACKTICK" => Some(FLAG_BACKTICK),
        "ENCODED_CMD" => Some(FLAG_ENCODED_CMD),
        "PIPE_SHELL" => Some(FLAG_PIPE_SHELL),
        "RECURSIVE_FORCE" => Some(FLAG_RECURSIVE_FORCE),
        "CRED_PATH" => Some(FLAG_CRED_PATH),
        "CONTROL_PATH" => Some(FLAG_CONTROL_PATH),
        _ => None,
    }
}

fn parse_failsafe_row(row: &str) -> Option<FailsafeRuleRow<'_>> {
    let (action_kind, r1) = row.split_once('|')?;
    let (verdict_str, r2) = r1.split_once('|')?;
    let (needle, r3) = r2.split_once('|')?;
    let (rule_id, reason) = r3.split_once('|')?;
    let action_mask = match action_kind {
        "control_file" => {
            FastActionClass::FileWrite.bit()
                | FastActionClass::FileDelete.bit()
                | FastActionClass::ConfigChange.bit()
        }
        "hook_bypass" => {
            FastActionClass::Exec.bit()
                | FastActionClass::AgentSpawn.bit()
                | FastActionClass::ConfigChange.bit()
        }
        "honeytoken_file" => {
            FastActionClass::FileWrite.bit()
                | FastActionClass::FileDelete.bit()
                | FastActionClass::ConfigChange.bit()
                | FastActionClass::FileRead.bit()
        }
        "honeytoken_cred" => FastActionClass::CredUse.bit() | FastActionClass::Exec.bit(),
        "cred_store" => {
            FastActionClass::FileRead.bit()
                | FastActionClass::CredUse.bit()
                | FastActionClass::Exec.bit()
        }
        _ => return None,
    };
    let verdict = match verdict_str {
        "allow" => FastVerdict::Allow,
        "step_up" => FastVerdict::StepUp,
        "deny" => FastVerdict::Deny,
        _ => return None,
    };
    Some(FailsafeRuleRow {
        action_mask,
        verdict,
        needle,
        rule_id,
        reason,
    })
}
