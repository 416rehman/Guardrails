// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! YAML/catalogue variable expansion loaders for L0 detection compilers (`D-09`, `P14`).

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;

use crate::analyze::pack_io::{detections_max_bytes, ensure_real_dir, read_pack_child_text};
use crate::detect::types::DetectError;
use crate::detect::yaml::{YamlValue, parse_yaml};

const EMBEDDED_L0_VARS_YAML: &str = include_str!("../../../../packs/lists/l0-agent-images.yaml");
const L0_VARS_FORMAT: &str = "grdr.l0-vars.v1";

/// Parses `%var%` L0 expansion lists from YAML (`grdr.l0-vars.v1`).
pub fn parse_l0_vars_yaml(yaml_src: &str) -> Result<BTreeMap<String, Vec<String>>, DetectError> {
    let doc = parse_yaml(yaml_src)?;
    if doc.get("format").and_then(YamlValue::as_str) != Some(L0_VARS_FORMAT) {
        return Err(DetectError::InvalidRule(
            "L0 vars YAML missing expected `format: grdr.l0-vars.v1` header".into(),
        ));
    }
    let vars = doc
        .get("vars")
        .and_then(YamlValue::as_map)
        .ok_or_else(|| DetectError::InvalidRule("L0 vars YAML missing `vars` mapping".into()))?;
    let mut out = BTreeMap::new();
    for (k, v) in vars {
        out.insert(k.clone(), v.try_to_string_list()?);
    }
    Ok(out)
}

/// Parses catalogued agent binary names dynamically from `packs/catalogue/catalogue.yaml`.
pub fn parse_catalogue_agent_binaries_yaml(
    catalogue_yaml: &str,
    tier_filter: Option<&str>,
) -> Result<Vec<String>, DetectError> {
    let doc = parse_yaml(catalogue_yaml)?;
    let agents = doc
        .get("agents")
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| DetectError::InvalidRule("catalogue YAML missing `agents`".into()))?;
    let mut out = Vec::new();
    for entry in agents {
        let tier_ok = match tier_filter {
            Some(want) => entry.get("catalogue_tier").and_then(YamlValue::as_str) == Some(want),
            None => true,
        };
        if !tier_ok {
            continue;
        }
        if let Some(bins_val) = entry.get("routes").and_then(|r| r.get("binaries")) {
            for bin in bins_val.try_to_string_list()? {
                if !bin.is_empty() && !out.contains(&bin) {
                    out.push(bin);
                }
            }
        }
    }
    Ok(out)
}

/// Loads default embedded L0 expansion variables from `packs/lists/l0-agent-images.yaml`.
pub(crate) fn embedded_l0_expand_vars() -> Result<BTreeMap<String, Vec<String>>, DetectError> {
    parse_l0_vars_yaml(EMBEDDED_L0_VARS_YAML)
}

/// Loads L0 expansion vars from `<packs_dir>/lists/l0-agent-images.yaml`, falling back to `catalogue.yaml`.
pub fn load_l0_vars_from_packs_dir(
    packs_dir: &Path,
) -> Result<BTreeMap<String, Vec<String>>, DetectError> {
    let max_bytes = detections_max_bytes().map_err(DetectError::InvalidRule)?;
    ensure_real_dir(packs_dir, "packs_dir").map_err(DetectError::InvalidRule)?;
    let vars_path = packs_dir.join("lists/l0-agent-images.yaml");
    match std::fs::symlink_metadata(&vars_path) {
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        _ => {
            let raw = read_pack_child_text(packs_dir, "lists/l0-agent-images.yaml", max_bytes)
                .map_err(DetectError::InvalidRule)?;
            return parse_l0_vars_yaml(&raw);
        }
    }
    let raw = read_pack_child_text(packs_dir, "catalogue/catalogue.yaml", max_bytes)
        .map_err(DetectError::InvalidRule)?;
    let bins = parse_catalogue_agent_binaries_yaml(&raw, Some("A"))?;
    let mut out = BTreeMap::new();
    out.insert("grdr_agent_images".to_owned(), bins);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::l0::{L0Target, compile_l0_target_with_packs_dir};
    use crate::detect::sigma::parse_sigma_rule;

    #[test]
    fn parses_catalogue_binaries_and_loads_dynamic_l0_vars() {
        let cat_yaml = include_str!("../../../../packs/catalogue/catalogue.yaml");
        let tier_a = parse_catalogue_agent_binaries_yaml(cat_yaml, Some("A"))
            .expect("parse tier A catalogue");
        assert!(tier_a.contains(&"claude".to_owned()));
        assert!(tier_a.contains(&"codex".to_owned()));
        assert!(tier_a.contains(&"cursor".to_owned()));
        assert!(tier_a.contains(&"gemini".to_owned()));
        assert!(tier_a.contains(&"antigravity".to_owned()));

        let tmp = std::env::temp_dir().join(format!("grdr-w1-2-l0-vars-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("lists")).expect("mkdir");
        std::fs::write(
            tmp.join("lists/l0-agent-images.yaml"),
            "format: grdr.l0-vars.v1\npack_id: test.l0\nvars:\n  grdr_agent_images:\n    - custom-agent-bin\n",
        )
        .expect("write vars");
        let r37_src = include_str!(
            "../../../../packs/detections/rules/det-37-encoded-or-nested-payload.yaml"
        );
        let r37 = parse_sigma_rule(r37_src).expect("r37");
        let kql = compile_l0_target_with_packs_dir(&r37, L0Target::Kql, &tmp).expect("kql");
        assert!(kql.query.contains("custom-agent-bin"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
