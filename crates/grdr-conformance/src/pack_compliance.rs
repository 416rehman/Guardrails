// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Structured YAML validation for compliance pack controls, frameworks, and crosswalks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use grdr_comply::default_registry;
use grdr_core::detect::yaml::{YamlValue, parse_yaml};

use crate::ConformanceError;
use crate::pack_manifest::{check_no_em_dash_or_vocab, conf_err, read_regular_text};

const MAX_PARAPHRASE_WORDS: usize = 20;

pub(crate) fn validate_compliance_pack(
    dir: &Path,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(usize, usize), ConformanceError> {
    let controls_dir = dir.join("controls");
    let caps_path = controls_dir.join("capabilities.yaml");
    let fws_path = controls_dir.join("frameworks.yaml");
    let cw_path = controls_dir.join("crosswalks.yaml");

    let caps_raw = read_regular_text(&caps_path)?;
    let fws_raw = read_regular_text(&fws_path)?;
    let cw_raw = read_regular_text(&cw_path)?;
    for (p, t) in [
        (&caps_path, &caps_raw),
        (&fws_path, &fws_raw),
        (&cw_path, &cw_raw),
    ] {
        check_no_em_dash_or_vocab(p, t, vocab)?;
    }

    let registry = default_registry();
    if registry.capabilities.is_empty() || registry.frameworks.is_empty() {
        return Err(conf_err(
            "comply-pack",
            "default_registry returned empty capabilities or frameworks",
        ));
    }

    let parsed_caps = parse_compliance_ids(&caps_raw, "capabilities", "id", &caps_path)?;
    for cap_id in registry.capabilities.keys() {
        if !parsed_caps.contains(cap_id) {
            return Err(conf_err(
                "comply-pack",
                &format!("capabilities.yaml missing capability `{cap_id}`"),
            ));
        }
    }

    let fws_doc = parse_yaml(&fws_raw)
        .map_err(|e| conf_err("comply-pack", &format!("frameworks.yaml: {e}")))?;
    validate_pack_id(&fws_doc, &fws_path)?;
    let fw_entries = fws_doc
        .get("frameworks")
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| {
            conf_err(
                "comply-pack",
                "frameworks.yaml missing `frameworks` sequence",
            )
        })?;
    let mut parsed_fws = BTreeSet::new();
    let mut controls_by_fw: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fw in fw_entries {
        let doc_id = fw
            .get("doc_id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| conf_err("comply-pack", "framework entry missing `doc_id`"))?;
        if !parsed_fws.insert(doc_id.to_owned()) {
            return Err(conf_err(
                "comply-pack",
                &format!("duplicate framework `{doc_id}` in frameworks.yaml"),
            ));
        }
        let controls = fw
            .get("controls")
            .and_then(YamlValue::as_seq)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                conf_err(
                    "comply-pack",
                    &format!("framework `{doc_id}` missing non-empty `controls`"),
                )
            })?;
        let mut fw_controls = BTreeSet::new();
        for ctrl in controls {
            let ctrl_id = ctrl
                .get("control_id")
                .and_then(YamlValue::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    conf_err(
                        "comply-pack",
                        &format!("framework `{doc_id}` control missing `control_id`"),
                    )
                })?;
            if !fw_controls.insert(ctrl_id.to_owned()) {
                return Err(conf_err(
                    "comply-pack",
                    &format!("duplicate control_id `{ctrl_id}` in framework `{doc_id}`"),
                ));
            }
            let paraphrase = ctrl
                .get("paraphrase")
                .and_then(YamlValue::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    conf_err(
                        "comply-pack",
                        &format!("control `{ctrl_id}` missing `paraphrase`"),
                    )
                })?;
            if paraphrase.split_whitespace().count() > MAX_PARAPHRASE_WORDS {
                return Err(conf_err(
                    "comply-pack",
                    &format!("control `{ctrl_id}` paraphrase exceeds {MAX_PARAPHRASE_WORDS} words"),
                ));
            }
        }
        controls_by_fw.insert(doc_id.to_owned(), fw_controls);
    }
    for fw_id in registry.frameworks.keys() {
        if !parsed_fws.contains(fw_id) {
            return Err(conf_err(
                "comply-pack",
                &format!("frameworks.yaml missing framework `{fw_id}`"),
            ));
        }
    }

    validate_crosswalks(
        &cw_raw,
        &cw_path,
        &parsed_caps,
        &parsed_fws,
        &controls_by_fw,
    )?;

    Ok((registry.capabilities.len(), registry.frameworks.len()))
}

fn validate_crosswalks(
    cw_raw: &str,
    cw_path: &Path,
    parsed_caps: &BTreeSet<String>,
    parsed_fws: &BTreeSet<String>,
    controls_by_fw: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), ConformanceError> {
    let cw_doc = parse_yaml(cw_raw)
        .map_err(|e| conf_err("comply-pack", &format!("crosswalks.yaml: {e}")))?;
    validate_pack_id(&cw_doc, cw_path)?;
    let crosswalks = cw_doc
        .get("crosswalks")
        .and_then(YamlValue::as_seq)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            conf_err(
                "comply-pack",
                "crosswalks.yaml missing `crosswalks` sequence",
            )
        })?;
    for entry in crosswalks {
        let cap = entry
            .get("capability")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| conf_err("comply-pack", "crosswalk entry missing `capability`"))?;
        if !parsed_caps.contains(cap) {
            return Err(conf_err(
                "comply-pack",
                &format!("crosswalk cites unknown capability `{cap}`"),
            ));
        }
        let fw_id = entry
            .get("framework_id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| conf_err("comply-pack", "crosswalk entry missing `framework_id`"))?;
        if !parsed_fws.contains(fw_id) {
            return Err(conf_err(
                "comply-pack",
                &format!("crosswalk cites unknown framework `{fw_id}`"),
            ));
        }
        let ctrl_id = entry
            .get("control_id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| conf_err("comply-pack", "crosswalk entry missing `control_id`"))?;
        if !controls_by_fw
            .get(fw_id)
            .is_some_and(|set| set.contains(ctrl_id))
        {
            return Err(conf_err(
                "comply-pack",
                &format!("crosswalk cites unknown control `{ctrl_id}` for framework `{fw_id}`"),
            ));
        }
        let relation = entry
            .get("relation")
            .and_then(YamlValue::as_str)
            .ok_or_else(|| conf_err("comply-pack", "crosswalk entry missing `relation`"))?;
        if !matches!(relation, "satisfies" | "supports") {
            return Err(conf_err(
                "comply-pack",
                &format!("crosswalk cites unknown relation `{relation}`"),
            ));
        }
    }
    Ok(())
}

fn parse_compliance_ids(
    raw: &str,
    list_key: &str,
    id_key: &str,
    path: &Path,
) -> Result<BTreeSet<String>, ConformanceError> {
    let doc = parse_yaml(raw)
        .map_err(|e| conf_err("comply-pack", &format!("{}: {e}", path.display())))?;
    validate_pack_id(&doc, path)?;
    let items = doc
        .get(list_key)
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| {
            conf_err(
                "comply-pack",
                &format!("{} missing `{list_key}`", path.display()),
            )
        })?;
    let mut ids = BTreeSet::new();
    for item in items {
        let id = item
            .get(id_key)
            .and_then(YamlValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                conf_err(
                    "comply-pack",
                    &format!("{} entry missing `{id_key}`", path.display()),
                )
            })?;
        if !ids.insert(id.to_owned()) {
            return Err(conf_err(
                "comply-pack",
                &format!("duplicate `{id}` in {}", path.display()),
            ));
        }
    }
    Ok(ids)
}

fn validate_pack_id(doc: &YamlValue, path: &Path) -> Result<(), ConformanceError> {
    let pack_id = doc
        .get("pack_id")
        .and_then(YamlValue::as_str)
        .unwrap_or_default();
    if pack_id != "grdr.compliance" {
        return Err(conf_err(
            "comply-pack",
            &format!("{} unexpected pack_id `{pack_id}`", path.display()),
        ));
    }
    Ok(())
}
