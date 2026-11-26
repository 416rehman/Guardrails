// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Version-aware agent and monitoring configuration integrity watcher across JSON, JSONC, TOML, INI, and YAML (`D-09`, rows 31 & 39).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::detect::config_parse::summarize_config;

const MAX_CONFIG_BASELINES: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigParseStatus {
    #[default]
    Parsed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoredConfigKind {
    ClaudeSettings,
    CursorConfig,
    CodexConfig,
    GeminiConfig,
    VsCodeWorkspace,
    GitConfig,
    MonitoringConfig,
    AgentMarkdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigChangeClass {
    AddsHook,
    AddsMcpStdio,
    PermissionWidened,
    BaseUrlChanged,
    EnvInjected,
    PolicySourceAdded,
    TaskFolderOpen,
    MonitoringConfigTamper,
    AlertRecipientsEmptied,
    ParseFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAdapterVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigBaselineEntry {
    pub canonical_path: String,
    pub kind: MonitoredConfigKind,
    pub sha256_digest: String,
    pub hook_entries: BTreeSet<String>,
    pub mcp_stdio_entries: BTreeSet<String>,
    pub allow_rules: BTreeSet<String>,
    pub recipients: BTreeSet<String>,
    pub base_url: Option<String>,
    #[serde(default)]
    pub endpoint_urls: BTreeMap<String, String>,
    pub env_keys: BTreeSet<String>,
    #[serde(default)]
    pub env_entries: BTreeMap<String, String>,
    pub policy_sources: BTreeSet<String>,
    pub has_bypass_permissions: bool,
    pub has_folder_open_task: bool,
    #[serde(default)]
    pub parse_status: ConfigParseStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigIntegrityReport {
    pub digest_changed: bool,
    pub change_classes: BTreeSet<ConfigChangeClass>,
    pub entry: ConfigBaselineEntry,
}

#[derive(Clone, Default)]
pub struct ConfigIntegrityMonitor {
    baselines: BTreeMap<String, ConfigBaselineEntry>,
    access_seq: BTreeMap<String, u64>,
    next_seq: u64,
}

impl core::fmt::Debug for ConfigIntegrityMonitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigIntegrityMonitor")
            .field("baselines_count", &self.baselines.len())
            .field("access_seq_count", &self.access_seq.len())
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

impl core::fmt::Debug for ConfigBaselineEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigBaselineEntry")
            .field("canonical_path", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("parse_status", &self.parse_status)
            .field("sha256_len", &self.sha256_digest.len())
            .field("hook_count", &self.hook_entries.len())
            .field("mcp_count", &self.mcp_stdio_entries.len())
            .field("allow_count", &self.allow_rules.len())
            .field("recipient_count", &self.recipients.len())
            .field("has_base_url", &self.base_url.is_some())
            .field("endpoint_count", &self.endpoint_urls.len())
            .field("env_key_count", &self.env_keys.len())
            .field("env_entry_count", &self.env_entries.len())
            .field("policy_source_count", &self.policy_sources.len())
            .field("has_bypass_permissions", &self.has_bypass_permissions)
            .field("has_folder_open_task", &self.has_folder_open_task)
            .finish()
    }
}

impl AgentAdapterVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    #[must_use]
    pub fn bypass_permissions_effective_in_project_settings(&self) -> bool {
        (self.major, self.minor, self.patch) < (2, 1, 257)
    }
}

impl ConfigIntegrityMonitor {
    #[must_use]
    pub fn baseline(&self, canonical_path: &str) -> Option<&ConfigBaselineEntry> {
        self.baselines.get(canonical_path)
    }

    pub fn record_baseline(
        &mut self,
        canonical_path: &str,
        kind: MonitoredConfigKind,
        content: &[u8],
    ) -> ConfigBaselineEntry {
        let entry = summarize_config(canonical_path, kind, content);
        self.insert_bounded_baseline(canonical_path.to_owned(), entry.clone());
        entry
    }

    /// Evaluates a config write against recorded baseline. Preserves last known-good baseline
    /// when an untrusted writer introduces tamper/widening classes (`#230 B5`).
    pub fn inspect_change(
        &mut self,
        canonical_path: &str,
        kind: MonitoredConfigKind,
        content: &[u8],
        writer_is_trusted_mdm_or_grdr: bool,
        agent_version: Option<&AgentAdapterVersion>,
    ) -> ConfigIntegrityReport {
        let next = summarize_config(canonical_path, kind, content);
        let prev = self.baselines.get(canonical_path);
        let mut classes = BTreeSet::new();
        let digest_changed = prev.is_none_or(|b| b.sha256_digest != next.sha256_digest);

        if kind == MonitoredConfigKind::MonitoringConfig {
            classes.insert(ConfigChangeClass::MonitoringConfigTamper);
            if prev.is_some_and(|b| !b.recipients.is_empty() && next.recipients.is_empty())
                || (!writer_is_trusted_mdm_or_grdr
                    && prev.is_some_and(|b| {
                        b.recipients.difference(&next.recipients).next().is_some()
                    }))
            {
                classes.insert(ConfigChangeClass::AlertRecipientsEmptied);
            }
        }

        if next.parse_status == ConfigParseStatus::Failed {
            classes.insert(ConfigChangeClass::ParseFailed);
        }

        inspect_structural_changes(
            canonical_path,
            kind,
            prev,
            &next,
            writer_is_trusted_mdm_or_grdr,
            agent_version,
            &mut classes,
        );

        // Do not poison or wipe the stored baseline on untrusted tamper writes, parse failures,
        // or empty writes that would clear previously tracked security facts.
        let untrusted_wipes_facts = !writer_is_trusted_mdm_or_grdr
            && prev.is_some_and(entry_has_recorded_facts)
            && !entry_has_recorded_facts(&next);
        if next.parse_status != ConfigParseStatus::Failed
            && !untrusted_wipes_facts
            && (writer_is_trusted_mdm_or_grdr || classes.is_empty())
        {
            self.insert_bounded_baseline(canonical_path.to_owned(), next.clone());
        }

        ConfigIntegrityReport {
            digest_changed,
            change_classes: classes,
            entry: next,
        }
    }

    fn insert_bounded_baseline(&mut self, key: String, entry: ConfigBaselineEntry) {
        if !self.baselines.contains_key(&key)
            && self.baselines.len() >= MAX_CONFIG_BASELINES
            && let Some(oldest) = self
                .access_seq
                .iter()
                .min_by_key(|(_, seq)| *seq)
                .map(|(k, _)| k.clone())
        {
            self.baselines.remove(&oldest);
            self.access_seq.remove(&oldest);
        }
        self.next_seq = self.next_seq.saturating_add(1);
        self.access_seq.insert(key.clone(), self.next_seq);
        self.baselines.insert(key, entry);
    }
}

fn is_user_home_claude_settings(canonical_path: &str) -> bool {
    let norm = canonical_path.trim().replace('\\', "/");
    let stripped = norm.strip_prefix("//?/").unwrap_or(&norm);
    let low = stripped.to_ascii_lowercase();
    if low.starts_with("~/.claude/")
        || low.starts_with("$home/.claude/")
        || low.starts_with("%userprofile%/.claude/")
        || low.starts_with("/root/.claude/")
    {
        return true;
    }
    let is_single_user_home = |rest: &str| -> bool {
        let Some((user_seg, tail)) = rest.split_once('/') else {
            return false;
        };
        !user_seg.is_empty() && tail.starts_with(".claude/")
    };
    if let Some(rest) = low.strip_prefix("/home/") {
        return is_single_user_home(rest);
    }
    if let Some(rest) = low.strip_prefix("/var/home/") {
        return is_single_user_home(rest);
    }
    if let Some(rest) = low.strip_prefix("/users/") {
        return is_single_user_home(rest);
    }
    low.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && low.get(1..9) == Some(":/users/")
        && low.get(9..).is_some_and(is_single_user_home)
}

fn is_project_claude_settings(canonical_path: &str) -> bool {
    if is_user_home_claude_settings(canonical_path) {
        return false;
    }
    let norm = canonical_path
        .trim()
        .replace('\\', "/")
        .to_ascii_lowercase();
    norm == ".claude/settings.json"
        || norm == ".claude/settings.local.json"
        || norm.starts_with(".claude/")
        || norm.contains("/.claude/")
}

fn inspect_structural_changes(
    canonical_path: &str,
    kind: MonitoredConfigKind,
    prev: Option<&ConfigBaselineEntry>,
    next: &ConfigBaselineEntry,
    writer_is_trusted_mdm_or_grdr: bool,
    agent_version: Option<&AgentAdapterVersion>,
    classes: &mut BTreeSet<ConfigChangeClass>,
) {
    let hooks_added = match prev {
        Some(p) => next
            .hook_entries
            .difference(&p.hook_entries)
            .next()
            .is_some(),
        None => !next.hook_entries.is_empty(),
    };
    if hooks_added {
        classes.insert(ConfigChangeClass::AddsHook);
    }

    let mcp_added = match prev {
        Some(p) => next
            .mcp_stdio_entries
            .difference(&p.mcp_stdio_entries)
            .next()
            .is_some(),
        None => !next.mcp_stdio_entries.is_empty(),
    };
    if mcp_added {
        classes.insert(ConfigChangeClass::AddsMcpStdio);
    }

    let allow_added = match prev {
        Some(p) => next.allow_rules.difference(&p.allow_rules).next().is_some(),
        None => !next.allow_rules.is_empty(),
    };
    let is_project_settings = is_project_claude_settings(canonical_path);
    let bypass_effective = if is_project_settings {
        agent_version
            .is_none_or(AgentAdapterVersion::bypass_permissions_effective_in_project_settings)
    } else {
        true
    };
    if allow_added
        || (kind == MonitoredConfigKind::ClaudeSettings
            && next.has_bypass_permissions
            && bypass_effective)
        || (kind == MonitoredConfigKind::CodexConfig && next.has_bypass_permissions)
    {
        classes.insert(ConfigChangeClass::PermissionWidened);
    }

    let base_url_changed = match prev {
        Some(p) => {
            next.endpoint_urls
                .iter()
                .any(|(k, v)| p.endpoint_urls.get(k) != Some(v))
                || (next.base_url.is_some() && p.base_url.as_ref() != next.base_url.as_ref())
        }
        None => !next.endpoint_urls.is_empty() || next.base_url.is_some(),
    };
    if base_url_changed {
        classes.insert(ConfigChangeClass::BaseUrlChanged);
    }
    let env_changed = match prev {
        Some(p) => {
            next.env_entries
                .iter()
                .any(|(k, d)| p.env_entries.get(k) != Some(d))
                || next.env_keys.difference(&p.env_keys).next().is_some()
        }
        None => !next.env_entries.is_empty() || !next.env_keys.is_empty(),
    };
    if env_changed {
        classes.insert(ConfigChangeClass::EnvInjected);
    }
    if kind == MonitoredConfigKind::VsCodeWorkspace && next.has_folder_open_task {
        classes.insert(ConfigChangeClass::TaskFolderOpen);
    }
    if !writer_is_trusted_mdm_or_grdr && !next.policy_sources.is_empty() {
        classes.insert(ConfigChangeClass::PolicySourceAdded);
    }
}

fn entry_has_recorded_facts(e: &ConfigBaselineEntry) -> bool {
    !e.hook_entries.is_empty()
        || !e.mcp_stdio_entries.is_empty()
        || !e.allow_rules.is_empty()
        || !e.recipients.is_empty()
        || e.base_url.is_some()
        || !e.endpoint_urls.is_empty()
        || !e.env_keys.is_empty()
        || !e.env_entries.is_empty()
        || !e.policy_sources.is_empty()
        || e.has_bypass_permissions
        || e.has_folder_open_task
}
