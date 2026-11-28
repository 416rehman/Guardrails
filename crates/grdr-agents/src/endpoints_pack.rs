// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! P14 YAML loader for model endpoint allowlists, honeytoken prefixes, and API shapes (`docs/design/05`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::CodedError;

const EMBEDDED_MODEL_ENDPOINTS_YAML: &str =
    include_str!("../../../packs/catalogue/model-endpoints.yaml");

static MODEL_ENDPOINTS_PACK: OnceLock<Result<ModelEndpointsPack, String>> = OnceLock::new();

#[derive(Debug, Clone)]
pub(crate) struct ApiShapeRule {
    pub(crate) provider: String,
    pub(crate) path_contains_any: Vec<String>,
    pub(crate) path_contains_all: Vec<String>,
    pub(crate) headers_any: Vec<String>,
    pub(crate) header_prefixes_any: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ModelEndpointsPack {
    pub(crate) base_url_allowlist: Vec<String>,
    pub(crate) honeytoken_prefixes: Vec<String>,
    pub(crate) api_shapes: Vec<ApiShapeRule>,
}

pub(crate) fn load_model_endpoints_pack() -> Result<&'static ModelEndpointsPack, CodedError> {
    MODEL_ENDPOINTS_PACK
        .get_or_init(parse_model_endpoints_pack)
        .as_ref()
        .map_err(|detail| {
            CodedError::new(
                "GRDR-AGENTS-0005",
                detail.clone(),
                "Fix malformed embedded packs/catalogue/model-endpoints.yaml.",
            )
        })
}

pub(crate) fn classify_api_shape(
    path: &str,
    headers: &[(String, String)],
) -> Result<Option<&'static str>, CodedError> {
    let pack = load_model_endpoints_pack()?;
    let lower_path = path.to_ascii_lowercase();
    for rule in &pack.api_shapes {
        let any_path = !rule.path_contains_any.is_empty()
            && rule
                .path_contains_any
                .iter()
                .any(|needle| lower_path.contains(needle));
        let all_path = !rule.path_contains_all.is_empty()
            && rule
                .path_contains_all
                .iter()
                .all(|needle| lower_path.contains(needle));
        let any_hdr = !rule.headers_any.is_empty()
            && rule
                .headers_any
                .iter()
                .any(|h| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(h)));
        let any_hdr_prefix = !rule.header_prefixes_any.is_empty()
            && rule.header_prefixes_any.iter().any(|prefix| {
                headers
                    .iter()
                    .any(|(k, _)| k.to_ascii_lowercase().starts_with(prefix))
            });
        if any_path || all_path || any_hdr || any_hdr_prefix {
            return Ok(Some(rule.provider.as_str()));
        }
    }
    Ok(None)
}

fn parse_model_endpoints_pack() -> Result<ModelEndpointsPack, String> {
    let root = parse_yaml(EMBEDDED_MODEL_ENDPOINTS_YAML)
        .map_err(|e| format!("failed parsing model-endpoints.yaml: {e}"))?;
    let map = root
        .as_map()
        .ok_or_else(|| "model-endpoints.yaml root must be a YAML map".to_owned())?;
    let base_url_allowlist = str_list(map, "base_url_allowlist", false);
    let honeytoken_prefixes = str_list(map, "honeytoken_prefixes", false);
    let api_shapes = map
        .get("api_shapes")
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| "model-endpoints.yaml missing `api_shapes` sequence".to_owned())?
        .iter()
        .filter_map(YamlValue::as_map)
        .filter_map(|item| {
            let provider = item.get("provider").and_then(YamlValue::as_str)?.to_owned();
            Some(ApiShapeRule {
                provider,
                path_contains_any: str_list(item, "path_contains_any", true),
                path_contains_all: str_list(item, "path_contains_all", true),
                headers_any: str_list(item, "headers_any", true),
                header_prefixes_any: str_list(item, "header_prefixes_any", true),
            })
        })
        .collect();
    Ok(ModelEndpointsPack {
        base_url_allowlist,
        honeytoken_prefixes,
        api_shapes,
    })
}

fn str_list(map: &BTreeMap<String, YamlValue>, key: &str, lowercase: bool) -> Vec<String> {
    map.get(key)
        .and_then(YamlValue::as_seq)
        .map(|seq| {
            seq.iter()
                .filter_map(YamlValue::as_str)
                .map(|s| {
                    if lowercase {
                        s.to_ascii_lowercase()
                    } else {
                        s.to_owned()
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
