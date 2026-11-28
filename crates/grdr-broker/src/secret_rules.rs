// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Data-driven secret indicator scanner backed by credential locator packs and core content rules (`P8`, `P14`).

use std::sync::OnceLock;

use grdr_core::analyze::content::scan_deterministic_content;
use grdr_core::detect::yaml::{YamlValue, parse_yaml};

const EMBEDDED_LOCATORS_YAML: &str =
    include_str!("../../../packs/credential-locator/lists/locators.yaml");
const EMBEDDED_INDICATORS_YAML: &str =
    include_str!("../../../spec/hook-broker/secret-indicators.yaml");

const IGNORED_GENERIC_LOCATOR_PREFIXES: &[&str] = &[
    "env_",
    "git_",
    "gcp_",
    "az_",
    "dckr_",
    "kube_",
    "npm_",
    "netrc_",
    "pgp_",
    "ssh_",
    "mcp_",
    "opencode_",
];

static SECRET_INDICATOR_RULES: OnceLock<Result<SecretIndicatorRules, String>> = OnceLock::new();

#[derive(Debug, Clone)]
struct StructuredSecretPrefix {
    prefix_lower: String,
    min_tail: usize,
}

#[derive(Debug, Clone)]
struct SecretIndicatorRules {
    key_value_markers_lower: Vec<String>,
    structured_prefixes_lower: Vec<StructuredSecretPrefix>,
}

#[must_use]
pub(crate) fn contains_secret_indicator(text: &str) -> bool {
    if !scan_deterministic_content(text.as_bytes())
        .matches
        .is_empty()
    {
        return true;
    }
    let Ok(rules) = SECRET_INDICATOR_RULES.get_or_init(build_secret_indicator_rules) else {
        // Fail closed by treating input as redacted if embedded rule packs fail to parse.
        return true;
    };
    let lower = text.to_ascii_lowercase();
    if rules
        .key_value_markers_lower
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }
    rules
        .structured_prefixes_lower
        .iter()
        .any(|rule| matches_structured_prefix(&lower, &rule.prefix_lower, rule.min_tail))
}

fn matches_structured_prefix(lower_text: &str, prefix_lower: &str, min_tail: usize) -> bool {
    if prefix_lower.is_empty() || lower_text.len() < prefix_lower.len() {
        return false;
    }
    for (idx, _) in lower_text.match_indices(prefix_lower) {
        let boundary_ok = idx == 0
            || lower_text
                .get(..idx)
                .and_then(|s| s.chars().next_back())
                .is_some_and(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
        if !boundary_ok {
            continue;
        }
        let tail = lower_text
            .get(idx.saturating_add(prefix_lower.len())..)
            .unwrap_or("");
        let token_len = tail
            .chars()
            .take_while(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '/' | '=')
            })
            .count();
        if token_len >= min_tail {
            return true;
        }
    }
    false
}

fn build_secret_indicator_rules() -> Result<SecretIndicatorRules, String> {
    let mut key_value_markers_lower = Vec::new();
    let mut structured_prefixes_lower = Vec::new();

    let loc_root = parse_yaml(EMBEDDED_LOCATORS_YAML)
        .map_err(|e| format!("failed parsing locators.yaml: {e}"))?;
    let loc_map = loc_root
        .as_map()
        .ok_or_else(|| "locators.yaml root must be a YAML map".to_owned())?;
    let Some(YamlValue::Seq(locators)) = loc_map.get("locators") else {
        return Err("locators.yaml missing `locators` sequence".to_owned());
    };
    for entry in locators.iter().filter_map(YamlValue::as_map) {
        if let Some(prefix) = entry.get("prefix").and_then(YamlValue::as_str)
            && !prefix.is_empty()
            && !IGNORED_GENERIC_LOCATOR_PREFIXES
                .iter()
                .any(|g| g.eq_ignore_ascii_case(prefix))
        {
            let lower = prefix.to_ascii_lowercase();
            let min_tail = if lower.len() <= 4 { 12 } else { 6 };
            push_structured_prefix(&mut structured_prefixes_lower, lower, min_tail);
        }
    }

    let ind_root = parse_yaml(EMBEDDED_INDICATORS_YAML)
        .map_err(|e| format!("failed parsing secret-indicators.yaml: {e}"))?;
    let ind_map = ind_root
        .as_map()
        .ok_or_else(|| "secret-indicators.yaml root must be a YAML map".to_owned())?;
    if let Some(YamlValue::Seq(items)) = ind_map.get("substrings_lower") {
        for item in items.iter().filter_map(YamlValue::as_str) {
            if !item.is_empty() {
                push_unique_lower(&mut key_value_markers_lower, item);
            }
        }
    }
    if let Some(YamlValue::Seq(items)) = ind_map.get("structured_prefixes_lower") {
        for item in items.iter().filter_map(YamlValue::as_map) {
            let Some(prefix) = item.get("prefix").and_then(YamlValue::as_str) else {
                continue;
            };
            let min_tail = item
                .get("min_tail")
                .and_then(YamlValue::as_i64)
                .and_then(|v| usize::try_from(v).ok())
                .unwrap_or(8);
            if !prefix.is_empty() {
                push_structured_prefix(
                    &mut structured_prefixes_lower,
                    prefix.to_ascii_lowercase(),
                    min_tail,
                );
            }
        }
    }
    if key_value_markers_lower.is_empty() && structured_prefixes_lower.is_empty() {
        return Err("secret indicator rule lists cannot be empty".to_owned());
    }
    Ok(SecretIndicatorRules {
        key_value_markers_lower,
        structured_prefixes_lower,
    })
}

fn push_unique_lower(list: &mut Vec<String>, raw: &str) {
    let lower = raw.to_ascii_lowercase();
    if !list.iter().any(|existing| existing == &lower) {
        list.push(lower);
    }
}

fn push_structured_prefix(
    list: &mut Vec<StructuredSecretPrefix>,
    prefix_lower: String,
    min_tail: usize,
) {
    if let Some(existing) = list.iter_mut().find(|r| r.prefix_lower == prefix_lower) {
        existing.min_tail = existing.min_tail.max(min_tail);
    } else {
        list.push(StructuredSecretPrefix {
            prefix_lower,
            min_tail,
        });
    }
}
