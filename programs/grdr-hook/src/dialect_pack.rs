// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Data-driven P14 hook dialect and classification table loader (zero `serde_json`).

use std::sync::OnceLock;

const EMBEDDED_DIALECTS_YAML: &str = include_str!("../../../packs/catalogue/hook-dialects.yaml");

static DIALECT_REGISTRY_CACHE: OnceLock<DialectRegistry> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseEnvelope {
    HookSpecificOutput,
    ContinuePermission,
    DecisionReason,
    PermissionDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectSpec {
    pub id: String,
    pub agent_id: String,
    pub aliases: Vec<String>,
    pub session_keys: Vec<String>,
    pub event_hints: Vec<String>,
    pub tool_hints: Vec<String>,
    pub response_format: ResponseEnvelope,
    pub modify_field: String,
    pub default_event: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionClassificationSpec {
    pub mcp_prefixes: Vec<String>,
    pub mcp_events: Vec<String>,
    pub prompt_events: Vec<String>,
    pub post_event_prefixes: Vec<String>,
    pub exec_exact: Vec<String>,
    pub exec_substrings: Vec<String>,
    pub exec_events: Vec<String>,
    pub delete_exact: Vec<String>,
    pub delete_substrings: Vec<String>,
    pub write_exact: Vec<String>,
    pub write_substrings: Vec<String>,
    pub write_events: Vec<String>,
    pub read_substrings: Vec<String>,
    pub read_events: Vec<String>,
    pub net_substrings: Vec<String>,
    pub mcp_substrings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectRegistry {
    pub default_dialect: String,
    pub classification: ActionClassificationSpec,
    pub dialects: Vec<DialectSpec>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TopSection {
    Root,
    Classification,
    Dialects,
}

impl ResponseEnvelope {
    fn from_str(raw: &str) -> Self {
        match raw.trim() {
            "continue-permission" => Self::ContinuePermission,
            "decision-reason" => Self::DecisionReason,
            "permission-decision" => Self::PermissionDecision,
            _ => Self::HookSpecificOutput,
        }
    }
}

impl DialectSpec {
    fn empty() -> Self {
        Self {
            id: String::new(),
            agent_id: String::new(),
            aliases: Vec::new(),
            session_keys: Vec::new(),
            event_hints: Vec::new(),
            tool_hints: Vec::new(),
            response_format: ResponseEnvelope::HookSpecificOutput,
            modify_field: String::new(),
            default_event: "PreToolUse".to_string(),
        }
    }
}

impl DialectRegistry {
    #[must_use]
    pub fn embedded() -> &'static Self {
        DIALECT_REGISTRY_CACHE.get_or_init(|| Self::from_yaml_str(EMBEDDED_DIALECTS_YAML))
    }

    #[must_use]
    pub fn from_yaml_str(raw: &str) -> Self {
        let mut reg = Self {
            default_dialect: String::new(),
            classification: ActionClassificationSpec::default(),
            dialects: Vec::new(),
        };
        let mut section = TopSection::Root;
        let mut class_key = "";
        let mut current: Option<DialectSpec> = None;

        for raw_line in raw.lines() {
            let line = raw_line.split('#').next().unwrap_or("");
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let indent = raw_line.bytes().take_while(|b| *b == b' ').count();
            if indent == 0 {
                if let Some(done) = current.take()
                    && !done.id.is_empty()
                {
                    reg.dialects.push(done);
                }
                if trimmed == "classification:" {
                    section = TopSection::Classification;
                    class_key = "";
                } else if trimmed == "dialects:" {
                    section = TopSection::Dialects;
                } else if let Some((k, v)) = split_kv(trimmed) {
                    section = TopSection::Root;
                    if k == "default_dialect" {
                        reg.default_dialect = clean_scalar(v);
                    }
                }
                continue;
            }

            match section {
                TopSection::Classification => {
                    if let Some(item) = trimmed.strip_prefix("- ") {
                        push_classification_item(
                            &mut reg.classification,
                            class_key,
                            clean_scalar(item),
                        );
                    } else if let Some((k, v)) = split_kv(trimmed) {
                        class_key = match k {
                            "mcp_prefixes" => "mcp_prefixes",
                            "mcp_events" => "mcp_events",
                            "prompt_events" => "prompt_events",
                            "post_event_prefixes" => "post_event_prefixes",
                            "exec_exact" => "exec_exact",
                            "exec_substrings" => "exec_substrings",
                            "exec_events" => "exec_events",
                            "delete_exact" => "delete_exact",
                            "delete_substrings" => "delete_substrings",
                            "write_exact" => "write_exact",
                            "write_substrings" => "write_substrings",
                            "write_events" => "write_events",
                            "read_substrings" => "read_substrings",
                            "read_events" => "read_events",
                            "net_substrings" => "net_substrings",
                            "mcp_substrings" => "mcp_substrings",
                            _ => "",
                        };
                        if !v.is_empty() {
                            for item in parse_inline_list(v) {
                                push_classification_item(&mut reg.classification, class_key, item);
                            }
                        }
                    }
                }
                TopSection::Dialects => {
                    if let Some(rest) = trimmed.strip_prefix("- ") {
                        if let Some(done) = current.take()
                            && !done.id.is_empty()
                        {
                            reg.dialects.push(done);
                        }
                        let mut spec = DialectSpec::empty();
                        if let Some((k, v)) = split_kv(rest) {
                            apply_dialect_field(&mut spec, k, v);
                        }
                        current = Some(spec);
                    } else if let Some(spec) = current.as_mut()
                        && let Some((k, v)) = split_kv(trimmed)
                    {
                        apply_dialect_field(spec, k, v);
                    }
                }
                TopSection::Root => {}
            }
        }
        if let Some(done) = current.take()
            && !done.id.is_empty()
        {
            reg.dialects.push(done);
        }
        if reg.default_dialect.is_empty()
            && let Some(first) = reg.dialects.first()
        {
            reg.default_dialect = first.id.clone();
        }
        reg
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&DialectSpec> {
        let needle = name.trim().to_ascii_lowercase();
        if needle.is_empty() || needle == "auto" {
            return None;
        }
        self.dialects.iter().find(|d| {
            d.id.eq_ignore_ascii_case(&needle)
                || d.agent_id.eq_ignore_ascii_case(&needle)
                || d.aliases.iter().any(|a| a.eq_ignore_ascii_case(&needle))
        })
    }

    #[must_use]
    pub fn default_spec(&self) -> Option<&DialectSpec> {
        self.resolve(&self.default_dialect)
            .or_else(|| self.dialects.first())
    }

    #[must_use]
    pub fn infer(
        &self,
        event_name: &str,
        tool_name: &str,
        session_key_hint: &str,
    ) -> Option<&DialectSpec> {
        if !event_name.is_empty()
            && let Some(found) = self
                .dialects
                .iter()
                .find(|d| d.event_hints.iter().any(|ev| ev == event_name))
        {
            return Some(found);
        }
        if !tool_name.is_empty()
            && let Some(found) = self
                .dialects
                .iter()
                .find(|d| d.tool_hints.iter().any(|t| t == tool_name))
        {
            return Some(found);
        }
        if !session_key_hint.is_empty()
            && let Some(found) = self
                .dialects
                .iter()
                .find(|d| d.session_keys.iter().any(|k| k == session_key_hint))
        {
            return Some(found);
        }
        self.default_spec()
    }
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim(), v.trim()))
}

fn clean_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
    {
        return trimmed
            .get(1..trimmed.len().saturating_sub(1))
            .unwrap_or("")
            .to_string();
    }
    trimmed.to_string()
}

fn parse_inline_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        let single = clean_scalar(trimmed);
        return if single.is_empty() {
            vec![]
        } else {
            vec![single]
        };
    };
    inner
        .split(',')
        .map(clean_scalar)
        .filter(|s| !s.is_empty())
        .collect()
}

fn apply_dialect_field(spec: &mut DialectSpec, key: &str, val: &str) {
    match key {
        "id" => spec.id = clean_scalar(val),
        "agent_id" => spec.agent_id = clean_scalar(val),
        "aliases" => spec.aliases = parse_inline_list(val),
        "session_keys" => spec.session_keys = parse_inline_list(val),
        "event_hints" => spec.event_hints = parse_inline_list(val),
        "tool_hints" => spec.tool_hints = parse_inline_list(val),
        "response_format" => spec.response_format = ResponseEnvelope::from_str(&clean_scalar(val)),
        "modify_field" => spec.modify_field = clean_scalar(val),
        "default_event" => spec.default_event = clean_scalar(val),
        _ => {}
    }
}

fn push_classification_item(spec: &mut ActionClassificationSpec, key: &str, val: String) {
    if val.is_empty() {
        return;
    }
    let target = match key {
        "mcp_prefixes" => &mut spec.mcp_prefixes,
        "mcp_events" => &mut spec.mcp_events,
        "prompt_events" => &mut spec.prompt_events,
        "post_event_prefixes" => &mut spec.post_event_prefixes,
        "exec_exact" => &mut spec.exec_exact,
        "exec_substrings" => &mut spec.exec_substrings,
        "exec_events" => &mut spec.exec_events,
        "delete_exact" => &mut spec.delete_exact,
        "delete_substrings" => &mut spec.delete_substrings,
        "write_exact" => &mut spec.write_exact,
        "write_substrings" => &mut spec.write_substrings,
        "write_events" => &mut spec.write_events,
        "read_substrings" => &mut spec.read_substrings,
        "read_events" => &mut spec.read_events,
        "net_substrings" => &mut spec.net_substrings,
        "mcp_substrings" => &mut spec.mcp_substrings,
        _ => return,
    };
    target.push(val);
}
