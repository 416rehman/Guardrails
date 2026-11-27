// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic P14 agent catalogue and building-block manifest loader (`docs/design/05`, `docs/design/07`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::CodedError;
use grdr_ports::{LocalFsPort, RegularEntryKind};

pub use crate::blocks_catalogue::{
    BuildingBlockCatalogue, BuildingBlockManifest, EcosystemPackages,
};
pub(crate) use crate::catalogue_parse::{
    cat_err, opt_str, parse_agent_map, read_bounded_regular_yaml, req_str, str_list,
    validate_slug_id,
};

const EMBEDDED_CATALOGUE_YAML: &str = include_str!("../../../packs/catalogue/catalogue.yaml");

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminConfigPaths {
    pub macos: Option<String>,
    pub linux: Option<String>,
    pub windows: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentArtifactRoutes {
    pub skills: Vec<String>,
    pub plugins: Vec<String>,
    pub rules: Vec<String>,
    pub commands: Vec<String>,
    pub subagents: Vec<String>,
    pub transcripts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRoutes {
    pub binaries: Vec<String>,
    pub windows_exes: Vec<String>,
    pub wsl_harnesses: Vec<String>,
    pub cmdline_markers: Vec<String>,
    pub npm: Vec<String>,
    pub pypi: Vec<String>,
    pub vscode_extensions: Vec<String>,
    pub state_dirs: Vec<String>,
    pub config_paths: Vec<String>,
    pub admin_config_paths: AdminConfigPaths,
    pub mcp_config_paths: Vec<String>,
    pub mcp_config_key: String,
    pub env_markers: Vec<String>,
    pub net: Vec<String>,
    pub artifacts: AgentArtifactRoutes,
    pub autonomy_flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum HookEntryStyle {
    #[default]
    MatcherHooks,
    CommandItem,
    TomlHook,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutUnit {
    #[default]
    Milliseconds,
    Seconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentFlagMode {
    #[default]
    Append,
    Omit,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdmIds {
    pub plist_domain: Option<String>,
    pub registry_subkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSpec {
    pub supported: bool,
    pub dialect: String,
    pub config_rel: String,
    pub config_format: String,
    pub root_key: String,
    pub version_field: Option<u32>,
    pub entry_style: HookEntryStyle,
    pub matcher: Option<String>,
    pub entry_name: Option<String>,
    pub events: Vec<String>,
    pub all_events: Vec<String>,
    pub payload_session_keys: Vec<String>,
    pub timeout_ms: u32,
    pub timeout_unit: TimeoutUnit,
    pub agent_flag: AgentFlagMode,
    pub fail_mode: String,
    pub mdm_ids: MdmIds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentManifest {
    pub id: String,
    pub aliases: Vec<String>,
    pub name: String,
    pub vendor: String,
    pub kind: String,
    pub catalogue_tier: String,
    pub surfaces: Vec<String>,
    pub declared_action_classes: Vec<String>,
    pub containment_default: String,
    pub adapter: String,
    pub routes: AgentRoutes,
    pub hook: HookSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCatalogue {
    agents: Vec<AgentManifest>,
}

impl Default for HookSpec {
    fn default() -> Self {
        Self {
            supported: false,
            dialect: String::new(),
            config_rel: String::new(),
            config_format: String::new(),
            root_key: String::new(),
            version_field: None,
            entry_style: HookEntryStyle::MatcherHooks,
            matcher: None,
            entry_name: None,
            events: Vec::new(),
            all_events: Vec::new(),
            payload_session_keys: Vec::new(),
            timeout_ms: 250,
            timeout_unit: TimeoutUnit::Milliseconds,
            agent_flag: AgentFlagMode::Append,
            fail_mode: String::new(),
            mdm_ids: MdmIds::default(),
        }
    }
}

impl AgentCatalogue {
    pub fn embedded() -> Result<Self, CodedError> {
        Self::from_catalogue_yaml(EMBEDDED_CATALOGUE_YAML)
    }

    pub fn from_catalogue_yaml(raw: &str) -> Result<Self, CodedError> {
        let root = parse_yaml(raw).map_err(|e| cat_err("GRDR-AGENTS-0004", e.to_string()))?;
        let map = root
            .as_map()
            .ok_or_else(|| cat_err("GRDR-AGENTS-0004", "catalogue root must be a YAML map"))?;
        if let Some(YamlValue::Seq(items)) = map.get("agents") {
            let mut agents = Vec::with_capacity(items.len());
            let mut seen_ids = BTreeSet::new();
            for item in items {
                let entry_map = item.as_map().ok_or_else(|| {
                    cat_err("GRDR-AGENTS-0004", "catalogue agent entry must be a map")
                })?;
                let agent = parse_agent_map(entry_map)?;
                if !seen_ids.insert(agent.id.clone()) {
                    return Err(cat_err(
                        "GRDR-AGENTS-0004",
                        format!("duplicate agent id `{}` in catalogue manifest", agent.id),
                    ));
                }
                agents.push(agent);
            }
            return Ok(Self { agents });
        }
        Ok(Self {
            agents: vec![parse_agent_map(map)?],
        })
    }

    pub fn load_from_dir(dir: &Path, fs: &dyn LocalFsPort) -> Result<Self, CodedError> {
        if !fs.is_regular_dir_nofollow(dir) {
            return Err(cat_err(
                "GRDR-AGENTS-0004",
                format!("unsafe or missing catalogue dir: {}", dir.display()),
            ));
        }
        let agents_dir = dir.join("agents");
        let mut by_id: BTreeMap<String, AgentManifest> = BTreeMap::new();
        let cat_file = dir.join("catalogue.yaml");
        match fs
            .inspect_nofollow(&cat_file)
            .map_err(|e| cat_err("GRDR-AGENTS-0004", e))?
        {
            RegularEntryKind::Missing => {}
            RegularEntryKind::File => {
                let raw = read_bounded_regular_yaml(&cat_file, fs)?;
                for agent in Self::from_catalogue_yaml(&raw)?.agents {
                    by_id.insert(agent.id.clone(), agent);
                }
            }
            RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
                return Err(cat_err(
                    "GRDR-AGENTS-0004",
                    format!("unsafe catalogue manifest: {}", cat_file.display()),
                ));
            }
        }
        match fs
            .inspect_nofollow(&agents_dir)
            .map_err(|e| cat_err("GRDR-AGENTS-0004", e))?
        {
            RegularEntryKind::Missing => {}
            RegularEntryKind::Dir => {
                let mut entries = Vec::new();
                for path in fs
                    .read_dir_entries(&agents_dir)
                    .map_err(|e| cat_err("GRDR-AGENTS-0004", e))?
                {
                    if path
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    {
                        entries.push(path);
                    }
                }
                entries.sort();
                for path in entries {
                    let raw = read_bounded_regular_yaml(&path, fs)?;
                    let parsed = Self::from_catalogue_yaml(&raw)?;
                    for agent in parsed.agents {
                        by_id.insert(agent.id.clone(), agent);
                    }
                }
            }
            RegularEntryKind::File | RegularEntryKind::UnsafeOrOther => {
                return Err(cat_err(
                    "GRDR-AGENTS-0004",
                    format!("unsafe agents directory: {}", agents_dir.display()),
                ));
            }
        }
        if by_id.is_empty() {
            return Err(cat_err(
                "GRDR-AGENTS-0004",
                "no catalogue agent manifests found",
            ));
        }
        Ok(Self {
            agents: by_id.into_values().collect(),
        })
    }

    #[must_use]
    pub fn agents(&self) -> &[AgentManifest] {
        &self.agents
    }

    #[must_use]
    pub fn resolve(&self, name_or_alias: &str) -> Option<&AgentManifest> {
        let needle = name_or_alias.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        self.agents.iter().find(|a| {
            a.id.eq_ignore_ascii_case(&needle)
                || a.aliases.iter().any(|al| al.eq_ignore_ascii_case(&needle))
                || a.name.eq_ignore_ascii_case(&needle)
        })
    }

    #[must_use]
    pub fn hook_targets(&self) -> Vec<&AgentManifest> {
        self.agents.iter().filter(|a| a.hook.supported).collect()
    }
}
