// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic P14 building-block and behavioral classifier manifest loader (`docs/design/05`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_core::discover::{
    AgenticIndicator, BuildingBlockRole, ClassifierConfig, ClassifierWeights,
};
use grdr_model::CodedError;
use grdr_ports::{LocalFsPort, RegularEntryKind};

use crate::catalogue::{
    cat_err, opt_str, read_bounded_regular_yaml, req_str, str_list, validate_slug_id,
};

const EMBEDDED_BLOCKS_YAML: &str =
    include_str!("../../../packs/building-blocks/building-blocks.yaml");

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemPackages {
    pub pypi: Vec<String>,
    pub npm: Vec<String>,
    pub cargo: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildingBlockManifest {
    pub id: String,
    pub name: String,
    pub role: BuildingBlockRole,
    pub agentic: AgenticIndicator,
    pub ecosystems: EcosystemPackages,
    pub binaries: Vec<String>,
    pub env_markers: Vec<String>,
    pub net: Vec<String>,
    pub classifier_boost_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildingBlockCatalogue {
    pub classifier: ClassifierConfig,
    blocks: Vec<BuildingBlockManifest>,
}

impl BuildingBlockCatalogue {
    pub fn embedded() -> Result<Self, CodedError> {
        Self::from_yaml(EMBEDDED_BLOCKS_YAML)
    }

    pub fn from_yaml(raw: &str) -> Result<Self, CodedError> {
        let root = parse_yaml(raw).map_err(|e| cat_err("GRDR-AGENTS-0005", e.to_string()))?;
        let map = root.as_map().ok_or_else(|| {
            cat_err(
                "GRDR-AGENTS-0005",
                "building-blocks root must be a YAML map",
            )
        })?;
        let classifier = if let Some(clf_val) = map.get("classifier") {
            let clf_map = clf_val.as_map().ok_or_else(|| {
                cat_err("GRDR-AGENTS-0005", "classifier config must be a YAML map")
            })?;
            parse_classifier_map(clf_map)?
        } else {
            ClassifierConfig::default()
        };
        let mut blocks = Vec::new();
        if let Some(YamlValue::Seq(items)) = map.get("blocks") {
            let mut seen_ids = BTreeSet::new();
            for item in items {
                let m = item.as_map().ok_or_else(|| {
                    cat_err("GRDR-AGENTS-0005", "building-block entry must be a map")
                })?;
                let block = parse_block_map(m)?;
                if !seen_ids.insert(block.id.clone()) {
                    return Err(cat_err(
                        "GRDR-AGENTS-0005",
                        format!("duplicate building-block id `{}`", block.id),
                    ));
                }
                blocks.push(block);
            }
        } else if map.contains_key("id") {
            blocks.push(parse_block_map(map)?);
        }
        Ok(Self { classifier, blocks })
    }

    pub fn load_from_dir(dir: &Path, fs: &dyn LocalFsPort) -> Result<Self, CodedError> {
        if !fs.is_regular_dir_nofollow(dir) {
            return Err(cat_err(
                "GRDR-AGENTS-0005",
                format!("unsafe or missing building-blocks dir: {}", dir.display()),
            ));
        }
        let mut classifier = ClassifierConfig::default();
        let mut by_id: BTreeMap<String, BuildingBlockManifest> = BTreeMap::new();
        let pack_file = dir.join("building-blocks.yaml");
        match fs
            .inspect_nofollow(&pack_file)
            .map_err(|e| cat_err("GRDR-AGENTS-0005", e))?
        {
            RegularEntryKind::Missing => {}
            RegularEntryKind::File => {
                let parsed = Self::from_yaml(&read_bounded_regular_yaml(&pack_file, fs)?)?;
                classifier = parsed.classifier;
                for b in parsed.blocks {
                    by_id.insert(b.id.clone(), b);
                }
            }
            RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
                return Err(cat_err(
                    "GRDR-AGENTS-0005",
                    format!("unsafe building-blocks file: {}", pack_file.display()),
                ));
            }
        }
        let clf_file = dir.join("classifier.yaml");
        match fs
            .inspect_nofollow(&clf_file)
            .map_err(|e| cat_err("GRDR-AGENTS-0005", e))?
        {
            RegularEntryKind::Missing => {}
            RegularEntryKind::File => {
                let root = parse_yaml(&read_bounded_regular_yaml(&clf_file, fs)?)
                    .map_err(|e| cat_err("GRDR-AGENTS-0005", e.to_string()))?;
                let m = root.as_map().ok_or_else(|| {
                    cat_err("GRDR-AGENTS-0005", "classifier.yaml root must be a map")
                })?;
                classifier = parse_classifier_map(m)?;
            }
            RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther => {
                return Err(cat_err(
                    "GRDR-AGENTS-0005",
                    format!("unsafe classifier file: {}", clf_file.display()),
                ));
            }
        }
        let blocks_dir = dir.join("blocks");
        match fs
            .inspect_nofollow(&blocks_dir)
            .map_err(|e| cat_err("GRDR-AGENTS-0005", e))?
        {
            RegularEntryKind::Missing => {}
            RegularEntryKind::Dir => {
                let mut entries = Vec::new();
                for path in fs
                    .read_dir_entries(&blocks_dir)
                    .map_err(|e| cat_err("GRDR-AGENTS-0005", e))?
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
                    let parsed = Self::from_yaml(&read_bounded_regular_yaml(&path, fs)?)?;
                    for b in parsed.blocks {
                        by_id.insert(b.id.clone(), b);
                    }
                }
            }
            RegularEntryKind::File | RegularEntryKind::UnsafeOrOther => {
                return Err(cat_err(
                    "GRDR-AGENTS-0005",
                    format!("unsafe blocks dir: {}", blocks_dir.display()),
                ));
            }
        }
        Ok(Self {
            classifier,
            blocks: by_id.into_values().collect(),
        })
    }

    #[must_use]
    pub fn blocks(&self) -> &[BuildingBlockManifest] {
        &self.blocks
    }
}

fn parse_block_map(m: &BTreeMap<String, YamlValue>) -> Result<BuildingBlockManifest, CodedError> {
    let id = req_str(m, "id", "GRDR-AGENTS-0005")?;
    validate_slug_id(&id, "GRDR-AGENTS-0005")?;
    let role_raw = opt_str(m, "role");
    let role = match role_raw.as_str() {
        "orchestrator" => BuildingBlockRole::Orchestrator,
        "protocol-bridge" => BuildingBlockRole::ProtocolBridge,
        "llm-sdk" => BuildingBlockRole::LlmSdk,
        "runtime" => BuildingBlockRole::Runtime,
        other => {
            return Err(cat_err(
                "GRDR-AGENTS-0005",
                format!("unknown building-block role `{other}` in `{id}`"),
            ));
        }
    };
    let agentic_raw = opt_str(m, "agentic");
    let agentic = match agentic_raw.as_str() {
        "yes" => AgenticIndicator::Yes,
        "corroborated" => AgenticIndicator::Corroborated,
        "no" => AgenticIndicator::No,
        other => {
            return Err(cat_err(
                "GRDR-AGENTS-0005",
                format!("unknown building-block agentic indicator `{other}` in `{id}`"),
            ));
        }
    };
    let classifier_boost_bp = match m.get("classifier_boost_bp") {
        None => 0,
        Some(v) => v
            .as_i64()
            .and_then(|x| u16::try_from(x).ok())
            .filter(|x| *x <= 10_000)
            .ok_or_else(|| cat_err("GRDR-AGENTS-0005", "invalid classifier_boost_bp"))?,
    };
    let eco = m.get("ecosystems").and_then(YamlValue::as_map);
    Ok(BuildingBlockManifest {
        id,
        name: req_str(m, "name", "GRDR-AGENTS-0005")?,
        role,
        agentic,
        ecosystems: EcosystemPackages {
            pypi: eco.map(|e| str_list(e, "pypi")).unwrap_or_default(),
            npm: eco.map(|e| str_list(e, "npm")).unwrap_or_default(),
            cargo: eco.map(|e| str_list(e, "cargo")).unwrap_or_default(),
        },
        binaries: str_list(m, "binaries"),
        env_markers: str_list(m, "env_markers"),
        net: str_list(m, "net"),
        classifier_boost_bp,
    })
}

fn opt_yaml_u64(map: &BTreeMap<String, YamlValue>, key: &str) -> Result<Option<u64>, CodedError> {
    match map.get(key) {
        None => Ok(None),
        Some(val) => val
            .as_i64()
            .and_then(|x| u64::try_from(x).ok())
            .map(Some)
            .ok_or_else(|| cat_err("GRDR-AGENTS-0005", format!("invalid integer for `{key}`"))),
    }
}

fn opt_yaml_u16(map: &BTreeMap<String, YamlValue>, key: &str) -> Result<Option<u16>, CodedError> {
    match map.get(key) {
        None => Ok(None),
        Some(val) => val
            .as_i64()
            .and_then(|x| u16::try_from(x).ok())
            .map(Some)
            .ok_or_else(|| cat_err("GRDR-AGENTS-0005", format!("invalid u16 for `{key}`"))),
    }
}

fn parse_classifier_map(m: &BTreeMap<String, YamlValue>) -> Result<ClassifierConfig, CodedError> {
    let mut cfg = ClassifierConfig::default();
    if let Some(v) = opt_yaml_u64(m, "window_secs")? {
        cfg.window_secs = v;
    }
    if let Some(v) = opt_yaml_u64(m, "min_cycles")? {
        cfg.min_cycles =
            u32::try_from(v).map_err(|_| cat_err("GRDR-AGENTS-0005", "min_cycles out of range"))?;
    }
    if let Some(v) = opt_yaml_u64(m, "coincidence_window_ms")? {
        cfg.coincidence_window_ms = v;
    }
    if let Some(v) = opt_yaml_u16(m, "min_coincidence_ratio_bp")? {
        cfg.min_coincidence_ratio_bp = v;
    }
    if let Some(v) = opt_yaml_u64(m, "llm_client_min_calls")? {
        cfg.llm_client_min_calls = usize::try_from(v)
            .map_err(|_| cat_err("GRDR-AGENTS-0005", "llm_client_min_calls out of range"))?;
    }
    if let Some(v) = opt_yaml_u64(m, "candidate_scan_budget_ms")? {
        cfg.candidate_scan_budget_ms = v;
    }
    if let Some(v) = opt_yaml_u16(m, "suspected_threshold_bp")? {
        cfg.suspected_threshold_bp = v;
    }
    if let Some(v) = opt_yaml_u16(m, "classified_threshold_bp")? {
        cfg.classified_threshold_bp = v;
    }
    if let Some(w_val) = m.get("weights_bp") {
        let w = w_val
            .as_map()
            .ok_or_else(|| cat_err("GRDR-AGENTS-0005", "weights_bp must be a map"))?;
        cfg.weights = ClassifierWeights {
            llm_stream_then_tool_bp: opt_yaml_u16(w, "llm_stream_then_tool")?
                .unwrap_or(cfg.weights.llm_stream_then_tool_bp),
            multi_turn_cadence_bp: opt_yaml_u16(w, "multi_turn_cadence")?
                .unwrap_or(cfg.weights.multi_turn_cadence_bp),
            sandbox_or_workspace_access_bp: opt_yaml_u16(w, "sandbox_or_workspace_access")?
                .unwrap_or(cfg.weights.sandbox_or_workspace_access_bp),
            orchestrator_package_bp: opt_yaml_u16(w, "orchestrator_package")?
                .unwrap_or(cfg.weights.orchestrator_package_bp),
            headless_env_markers_bp: opt_yaml_u16(w, "headless_env_markers")?
                .unwrap_or(cfg.weights.headless_env_markers_bp),
        };
    }
    cfg.validate()?;
    Ok(cfg)
}
