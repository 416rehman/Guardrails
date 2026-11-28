// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;
use crate::seatbelt::canonicalize_macos_path;

const MAX_CUSTOM_HARNESSES: usize = 512;

static EMBEDDED_CATALOGUE_CACHE: OnceLock<HarnessCatalogue> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSandboxKind {
    Seatbelt,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPolicy {
    Delegate,
    WrapTools,
    #[default]
    WrapAgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEntry {
    pub id: String,
    pub aliases: Vec<String>,
    pub binaries: Vec<String>,
    pub cmdline_markers: Vec<String>,
    pub signing_ids: Vec<String>,
    pub team_ids: Vec<String>,
    pub native_sandbox: NativeSandboxKind,
    pub delegation_mode: DelegationPolicy,
    pub model_hosts: Vec<String>,
    pub state_dirs: Vec<String>,
    pub config_paths: Vec<String>,
    pub admin_config_path_macos: Option<String>,
    pub transcript_dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HarnessCatalogue {
    pub schema_version: u32,
    pub harnesses: Vec<HarnessEntry>,
}

include!(concat!(env!("OUT_DIR"), "/generated_catalogue.rs"));

impl HarnessEntry {
    pub fn matches_kind(&self, agent_kind: &str) -> bool {
        let lower = agent_kind.trim().to_ascii_lowercase();
        if lower.is_empty() {
            return false;
        }
        self.id.eq_ignore_ascii_case(&lower)
            || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(&lower))
    }

    pub fn matches_process(
        &self,
        exe_path: &str,
        argv: &[String],
        signing_id: Option<&str>,
        team_id: Option<&str>,
    ) -> bool {
        if let Some(sid) = signing_id.map(str::trim).filter(|s| !s.is_empty())
            && self.signing_ids.iter().any(|s| s.eq_ignore_ascii_case(sid))
        {
            return true;
        }
        if let Some(tid) = team_id.map(str::trim).filter(|s| !s.is_empty())
            && self
                .team_ids
                .iter()
                .any(|t| !t.is_empty() && t.eq_ignore_ascii_case(tid))
        {
            return true;
        }
        let exe_base = Path::new(exe_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if !exe_base.is_empty()
            && self
                .binaries
                .iter()
                .any(|b| !b.is_empty() && exe_base == b.trim().to_ascii_lowercase())
        {
            return true;
        }
        let argv_joined = argv.join(" ").to_ascii_lowercase();
        if !argv_joined.is_empty() {
            return self.cmdline_markers.iter().any(|m| {
                let marker = m.trim().to_ascii_lowercase();
                !marker.is_empty() && argv_joined.contains(&marker)
            });
        }
        false
    }
}

impl HarnessCatalogue {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            harnesses: Vec::new(),
        }
    }

    pub fn embedded() -> &'static Self {
        EMBEDDED_CATALOGUE_CACHE.get_or_init(|| {
            let harnesses = EMBEDDED_HARNESSES
                .iter()
                .map(static_spec_to_entry)
                .collect();
            Self {
                schema_version: 1,
                harnesses,
            }
        })
    }

    pub fn from_harnesses(harnesses: Vec<HarnessEntry>) -> Result<Self, MacOsSensorError> {
        if harnesses.len() > MAX_CUSTOM_HARNESSES {
            return Err(MacOsSensorError::Source(format!(
                "harness catalogue exceeds max {MAX_CUSTOM_HARNESSES} entries"
            )));
        }
        Ok(Self {
            schema_version: 1,
            harnesses,
        })
    }

    pub fn find_by_kind(&self, agent_kind: &str) -> Option<&HarnessEntry> {
        self.harnesses.iter().find(|h| h.matches_kind(agent_kind))
    }

    pub fn match_process(
        &self,
        exe_path: &str,
        argv: &[String],
        signing_id: Option<&str>,
        team_id: Option<&str>,
    ) -> Option<&HarnessEntry> {
        self.harnesses
            .iter()
            .find(|h| h.matches_process(exe_path, argv, signing_id, team_id))
    }

    pub fn should_delegate_seatbelt(&self, agent_kind: &str, agent_has_own_seatbelt: bool) -> bool {
        if !agent_has_own_seatbelt {
            return false;
        }
        self.find_by_kind(agent_kind).is_some_and(|entry| {
            entry.native_sandbox == NativeSandboxKind::Seatbelt
                && entry.delegation_mode == DelegationPolicy::Delegate
        })
    }

    pub fn all_model_host_suffixes(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        for entry in &self.harnesses {
            for host in &entry.model_hosts {
                let norm = host.trim().trim_matches('.').to_ascii_lowercase();
                if !norm.is_empty() {
                    seen.insert(norm);
                }
            }
        }
        seen.into_iter().collect()
    }

    pub fn match_model_host(&self, host: &str) -> bool {
        let norm = host.trim().trim_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            return false;
        }
        self.harnesses.iter().any(|entry| {
            entry.model_hosts.iter().any(|suffix| {
                let bare = suffix.trim().trim_matches('.').to_ascii_lowercase();
                !bare.is_empty() && (norm == bare || norm.ends_with(&format!(".{bare}")))
            })
        })
    }

    pub fn resolve_state_dirs(&self, agent_kind: &str, home_dir: Option<&Path>) -> Vec<String> {
        let Some(entry) = self.find_by_kind(agent_kind) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for raw in &entry.state_dirs {
            let clean = raw.trim();
            if clean.is_empty() || clean.contains('\0') || clean.contains("..") {
                continue;
            }
            if clean.starts_with('/') {
                let canon = canonicalize_macos_path(clean);
                if !out.contains(&canon) {
                    out.push(canon);
                }
            } else if let Some(home) = home_dir {
                let home_str = home.to_string_lossy().replace('\\', "/");
                let joined = format!(
                    "{}/{}",
                    home_str.trim_end_matches('/'),
                    clean.trim_start_matches('/')
                );
                let canon = canonicalize_macos_path(&joined);
                if canon.starts_with('/') && !out.contains(&canon) {
                    out.push(canon);
                }
            }
        }
        out
    }

    pub fn resolve_watch_roots(
        &self,
        home_dir: Option<&Path>,
        workspace_root: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut roots = BTreeSet::new();
        for entry in &self.harnesses {
            collect_entry_watch_roots(entry, home_dir, workspace_root, &mut roots);
        }
        roots.into_iter().collect()
    }

    pub fn infer_agent_for_watch_path(
        &self,
        path: &Path,
        home_dir: Option<&Path>,
        workspace_root: Option<&Path>,
    ) -> Option<&str> {
        let candidate = normalize_watch_cmp_path(path);
        for entry in &self.harnesses {
            let mut roots = BTreeSet::new();
            collect_entry_watch_roots(entry, home_dir, workspace_root, &mut roots);
            if let Some(admin) = &entry.admin_config_path_macos {
                let p = PathBuf::from(canonicalize_macos_path(admin));
                if candidate == normalize_watch_cmp_path(&p) {
                    return Some(entry.id.as_str());
                }
            }
            if roots
                .iter()
                .any(|r| candidate.starts_with(normalize_watch_cmp_path(r)))
            {
                return Some(entry.id.as_str());
            }
        }
        None
    }
}

fn collect_entry_watch_roots(
    entry: &HarnessEntry,
    home_dir: Option<&Path>,
    workspace_root: Option<&Path>,
    roots: &mut BTreeSet<PathBuf>,
) {
    if let Some(home) = home_dir {
        for dir in &entry.state_dirs {
            let clean = dir.trim();
            if !clean.is_empty() && !clean.starts_with('/') && !clean.contains("..") {
                roots.insert(home.join(clean));
            }
        }
        for rel in &entry.transcript_dirs {
            let clean = rel.trim();
            if !clean.is_empty() && !clean.starts_with('/') && !clean.contains("..") {
                roots.insert(home.join(clean));
            }
        }
    }
    for cfg in &entry.config_paths {
        let clean = cfg.trim();
        if clean.starts_with('/') {
            let p = Path::new(clean);
            if let Some(parent) = p.parent() {
                roots.insert(parent.to_path_buf());
            }
        } else if let Some(ws) = workspace_root
            && let Some(rel) = clean.strip_prefix("$WORKSPACE/")
        {
            if let Some(parent) = Path::new(rel).parent()
                && !parent.as_os_str().is_empty()
            {
                roots.insert(ws.join(parent));
            } else {
                roots.insert(ws.to_path_buf());
            }
        } else if let Some(home) = home_dir
            && !clean.is_empty()
            && !clean.contains('$')
            && !clean.contains("..")
        {
            let full = home.join(clean);
            if let Some(parent) = full.parent() {
                roots.insert(parent.to_path_buf());
            }
        }
    }
    if let Some(admin) = &entry.admin_config_path_macos {
        let clean = admin.trim();
        if clean.starts_with('/')
            && let Some(parent) = Path::new(clean).parent()
        {
            roots.insert(parent.to_path_buf());
        }
    }
}

fn normalize_watch_cmp_path(p: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(canonicalize_macos_path(&p.to_string_lossy()))
    }
    #[cfg(not(unix))]
    {
        p.to_path_buf()
    }
}

fn static_spec_to_entry(spec: &StaticHarnessSpec) -> HarnessEntry {
    let to_vec = |slice: &[&str]| slice.iter().map(|s| (*s).to_string()).collect();
    HarnessEntry {
        id: spec.id.to_string(),
        aliases: to_vec(spec.aliases),
        binaries: to_vec(spec.binaries),
        cmdline_markers: to_vec(spec.cmdline_markers),
        signing_ids: to_vec(spec.signing_ids),
        team_ids: Vec::new(),
        native_sandbox: spec.native_sandbox,
        delegation_mode: spec.delegation_mode,
        model_hosts: to_vec(spec.model_hosts),
        state_dirs: to_vec(spec.state_dirs),
        config_paths: to_vec(spec.config_paths),
        admin_config_path_macos: spec.admin_config_path_macos.map(str::to_string),
        transcript_dirs: to_vec(spec.transcript_dirs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalogue_matches_canonical_yaml_aliases_and_routes() {
        let cat = HarnessCatalogue::embedded();
        assert_eq!(cat.harnesses.len(), 17);
        assert!(cat.should_delegate_seatbelt("codex", true));
        assert!(cat.should_delegate_seatbelt("claude-code", true));
        assert!(cat.should_delegate_seatbelt("claude", true));
        assert!(!cat.should_delegate_seatbelt("codex", false));
        assert!(!cat.should_delegate_seatbelt("cursor", true));

        let expected_aliases: &[(&str, &[&str])] = &[
            ("kiro", &["kiro-cli", "kiro-ide"]),
            ("opencode", &["open-code"]),
            ("pi", &["pi-agent", "pi-coding-agent"]),
            ("continue", &["continue-dev", "cn"]),
            ("junie", &["jetbrains-junie"]),
            ("amazon-q", &["q", "amazon-q-cli", "aws-q"]),
            ("github-copilot", &["copilot", "copilot-cli", "gh-copilot"]),
            ("windsurf", &["codeium-windsurf", "cascade"]),
            ("cline", &["claude-dev"]),
            ("roo-code", &["roo", "roo-cline"]),
        ];
        for &(id, aliases) in expected_aliases {
            let entry = cat.find_by_kind(id).expect("expected agent id");
            let expected: Vec<String> = aliases.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(entry.aliases, expected, "alias drift for {id}");
            for &alias in aliases {
                assert_eq!(cat.find_by_kind(alias).map(|e| e.id.as_str()), Some(id));
            }
        }

        let codex = cat.find_by_kind("codex").expect("codex");
        assert_eq!(
            codex.config_paths,
            vec![
                ".codex/config.toml".to_string(),
                ".codex/hooks.json".to_string(),
                "$WORKSPACE/.codex/config.toml".to_string(),
            ]
        );
        assert_eq!(
            codex.admin_config_path_macos.as_deref(),
            Some("/Library/Managed Preferences/codex-requirements.toml")
        );

        let home = Path::new("/Users/dev");
        assert_eq!(
            cat.resolve_state_dirs("claude-code", Some(home)),
            vec!["/Users/dev/.claude".to_string()]
        );
        assert_eq!(
            cat.resolve_state_dirs("codex", Some(home)),
            vec!["/Users/dev/.codex".to_string()]
        );

        let custom = HarnessCatalogue::from_harnesses(vec![HarnessEntry {
            id: "custom-native-agent".into(),
            aliases: vec![],
            binaries: vec!["custom-bin".into()],
            cmdline_markers: vec![],
            signing_ids: vec![],
            team_ids: vec![],
            native_sandbox: NativeSandboxKind::Seatbelt,
            delegation_mode: DelegationPolicy::Delegate,
            model_hosts: vec!["models.example.internal".into()],
            state_dirs: vec![],
            config_paths: vec![],
            admin_config_path_macos: None,
            transcript_dirs: vec![],
        }])
        .expect("custom catalogue");
        assert!(custom.should_delegate_seatbelt("custom-native-agent", true));
        assert!(custom.match_model_host("v1.models.example.internal."));
        assert!(!custom.match_model_host("evil.internal"));
    }
}
