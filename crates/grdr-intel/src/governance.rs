// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Signed YAML governance lists for threat-intel validation, aliases, and sighting filters (`P14`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use grdr_schema::limits::load_embedded_limits;

use crate::IntelError;

const EMBEDDED_INTEL_GOV_YAML: &str = include_str!("../../../packs/lists/intel-governance.yaml");
const GOV_FORMAT: &str = "grdr.intel-governance.v1";
const MAX_GOV_LINES: usize = 4_096;
const MAX_GOV_ITEMS_PER_LIST: usize = 2_048;

#[derive(Debug, Clone)]
pub struct IntelGovernancePolicy {
    pub forbidden_intel_keys: BTreeSet<String>,
    pub self_org_aliases: Vec<String>,
    pub self_org_substring_aliases: Vec<String>,
    pub ossf_aliases: Vec<String>,
    pub ghsa_aliases: Vec<String>,
    pub private_host_suffixes: Vec<String>,
}

impl IntelGovernancePolicy {
    /// Parses `grdr.intel-governance.v1` YAML into normalized governance tables.
    pub fn from_yaml(yaml_src: &str) -> Result<Self, IntelError> {
        let lists = parse_gov_lists(yaml_src)?;
        let forbidden_raw = lists.get("forbidden_intel_keys").ok_or_else(|| {
            IntelError::NonRestrictivePack(
                "intel governance YAML missing `forbidden_intel_keys`".into(),
            )
        })?;
        let mut forbidden_intel_keys = BTreeSet::new();
        for key in forbidden_raw {
            forbidden_intel_keys.insert(key.clone());
            forbidden_intel_keys.insert(normalize_intel_key_token(key));
        }
        let mut private_host_suffixes = Vec::new();
        for suffix in lists.get("private_host_suffixes").into_iter().flatten() {
            if !is_valid_dns_suffix(suffix) {
                return Err(IntelError::NonRestrictivePack(format!(
                    "invalid DNS syntax in `private_host_suffixes`: `{suffix}`"
                )));
            }
            let trimmed = suffix.trim();
            let normalized = trimmed.strip_prefix('.').unwrap_or(trimmed).to_owned();
            if !private_host_suffixes.contains(&normalized) {
                private_host_suffixes.push(normalized);
            }
        }
        Ok(Self {
            forbidden_intel_keys,
            self_org_aliases: normalized_alias_list(&lists, "self_org_aliases")?,
            self_org_substring_aliases: normalized_alias_list(
                &lists,
                "self_org_substring_aliases",
            )?,
            ossf_aliases: normalized_alias_list(&lists, "ossf_aliases")?,
            ghsa_aliases: normalized_alias_list(&lists, "ghsa_aliases")?,
            private_host_suffixes,
        })
    }

    /// Loads governance policy lists dynamically from `<packs_dir>/lists/intel-governance.yaml`.
    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, IntelError> {
        let max_bytes = gov_max_bytes()?;
        let raw = crate::gov_io::load_gov_yaml_from_packs_dir(packs_dir, max_bytes)?;
        Self::from_yaml(&raw)
    }

    #[must_use]
    pub fn is_forbidden_key(&self, raw_key: &str) -> bool {
        if raw_key.trim().is_empty() || !raw_key.is_ascii() || raw_key.chars().any(char::is_control)
        {
            return true;
        }
        let trimmed = raw_key.trim().to_ascii_lowercase();
        let compact = normalize_intel_key_token(raw_key);
        self.forbidden_intel_keys.contains(&trimmed) || self.forbidden_intel_keys.contains(&compact)
    }
}

pub(crate) fn normalize_intel_key_token(raw: &str) -> String {
    raw.chars()
        .filter_map(fold_confusable_ascii_char)
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn fold_confusable_ascii_char(ch: char) -> Option<char> {
    if ch.is_ascii() {
        return Some(ch);
    }
    let code = ch as u32;
    if (0xFF01..=0xFF5E).contains(&code) {
        return char::from_u32(code.saturating_sub(0xFEE0));
    }
    match ch {
        '\u{0430}' | '\u{0410}' | '\u{03B1}' | '\u{0391}' => Some('a'),
        '\u{0435}' | '\u{0415}' | '\u{03B5}' | '\u{0395}' => Some('e'),
        '\u{0456}' | '\u{0406}' | '\u{03B9}' | '\u{0399}' => Some('i'),
        '\u{043E}' | '\u{041E}' | '\u{03BF}' | '\u{039F}' => Some('o'),
        '\u{0440}' | '\u{0420}' | '\u{03C1}' | '\u{03A1}' => Some('p'),
        '\u{0441}' | '\u{0421}' => Some('c'),
        '\u{0443}' | '\u{0423}' => Some('y'),
        '\u{0445}' | '\u{0425}' => Some('x'),
        '\u{043A}' | '\u{041A}' => Some('k'),
        '\u{043C}' | '\u{041C}' => Some('m'),
        '\u{0442}' | '\u{0422}' => Some('t'),
        _ => None,
    }
}

pub fn default_intel_governance() -> Result<&'static IntelGovernancePolicy, IntelError> {
    static CACHE: OnceLock<Result<IntelGovernancePolicy, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            IntelGovernancePolicy::from_yaml(EMBEDDED_INTEL_GOV_YAML).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|msg| IntelError::NonRestrictivePack(msg.clone()))
}

fn gov_max_bytes() -> Result<u64, IntelError> {
    let limits = load_embedded_limits()
        .map_err(|e| IntelError::NonRestrictivePack(format!("limits.toml error: {e}")))?;
    Ok(u64::from(limits.packs.essentials_max_kb).saturating_mul(1024))
}

fn parse_gov_lists(src: &str) -> Result<BTreeMap<String, Vec<String>>, IntelError> {
    let max_bytes = usize::try_from(gov_max_bytes()?).unwrap_or(usize::MAX);
    if src.len() > max_bytes {
        return Err(IntelError::NonRestrictivePack(
            "intel governance YAML exceeds schema byte bound".into(),
        ));
    }
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut format: Option<String> = None;
    let mut saw_lists = false;
    let mut in_lists = false;
    let mut current_key: Option<String> = None;

    for (line_idx, raw_line) in src.lines().enumerate() {
        if line_idx >= MAX_GOV_LINES {
            return Err(IntelError::NonRestrictivePack(
                "intel governance YAML exceeds maximum line count".into(),
            ));
        }
        let no_comment = strip_yaml_comment(raw_line);
        let trimmed = no_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = no_comment
            .len()
            .saturating_sub(no_comment.trim_start().len());
        if indent == 0 {
            in_lists = trimmed == "lists:";
            if in_lists {
                if saw_lists {
                    return Err(IntelError::NonRestrictivePack(
                        "duplicate `lists` section in intel governance YAML".into(),
                    ));
                }
                saw_lists = true;
            } else if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim();
                let val = parse_yaml_scalar(v.trim())?;
                if key == "format" {
                    if format.is_some() {
                        return Err(IntelError::NonRestrictivePack(
                            "duplicate `format` header in intel governance YAML".into(),
                        ));
                    }
                    format = Some(val);
                } else if key != "pack_id" && key != "version" {
                    return Err(IntelError::NonRestrictivePack(format!(
                        "unexpected top-level key `{key}` in intel governance YAML"
                    )));
                }
            } else {
                return Err(IntelError::NonRestrictivePack(
                    "malformed top-level line in intel governance YAML".into(),
                ));
            }
            current_key = None;
            continue;
        }
        if !in_lists {
            return Err(IntelError::NonRestrictivePack(
                "unexpected indented entry outside `lists` section".into(),
            ));
        }
        if let Some(after_dash) = trimmed.strip_prefix("- ") {
            let key = current_key.as_ref().ok_or_else(|| {
                IntelError::NonRestrictivePack(
                    "list item without preceding list key in intel governance YAML".into(),
                )
            })?;
            let item = parse_yaml_scalar(after_dash.trim())?.to_ascii_lowercase();
            let entry = map.entry(key.clone()).or_default();
            if entry.len() >= MAX_GOV_ITEMS_PER_LIST {
                return Err(IntelError::NonRestrictivePack(format!(
                    "intel governance list `{key}` exceeds maximum size"
                )));
            }
            if item.is_empty() {
                return Err(IntelError::NonRestrictivePack(format!(
                    "empty entry forbidden in intel governance list `{key}`"
                )));
            }
            entry.push(item);
            continue;
        }
        if let Some((key_name, rest)) = trimmed.split_once(':') {
            let key = key_name.trim();
            if key.is_empty() || map.contains_key(key) {
                return Err(IntelError::NonRestrictivePack(format!(
                    "invalid or duplicate list key `{key}` in intel governance YAML"
                )));
            }
            let val_rest = rest.trim();
            if val_rest.is_empty() {
                map.insert(key.to_owned(), Vec::new());
                current_key = Some(key.to_owned());
                continue;
            }
            if val_rest.starts_with('[') && val_rest.ends_with(']') {
                let inner = val_rest
                    .get(1..val_rest.len().saturating_sub(1))
                    .unwrap_or("");
                let mut items = Vec::new();
                for part in split_flow_items(inner)? {
                    let item = parse_yaml_scalar(part.trim())?.to_ascii_lowercase();
                    if item.is_empty() {
                        return Err(IntelError::NonRestrictivePack(format!(
                            "empty flow item in intel governance list `{key}`"
                        )));
                    }
                    items.push(item);
                }
                if items.len() > MAX_GOV_ITEMS_PER_LIST {
                    return Err(IntelError::NonRestrictivePack(format!(
                        "intel governance list `{key}` exceeds maximum size"
                    )));
                }
                map.insert(key.to_owned(), items);
                current_key = None;
                continue;
            }
        }
        return Err(IntelError::NonRestrictivePack(format!(
            "malformed line `{trimmed}` in intel governance YAML"
        )));
    }

    if format.as_deref() != Some(GOV_FORMAT) {
        return Err(IntelError::NonRestrictivePack(
            "intel governance YAML missing expected format header".into(),
        ));
    }
    if !saw_lists {
        return Err(IntelError::NonRestrictivePack(
            "intel governance YAML missing `lists` section".into(),
        ));
    }
    for (k, v) in &map {
        if v.is_empty() {
            return Err(IntelError::NonRestrictivePack(format!(
                "intel governance list `{k}` cannot be empty"
            )));
        }
    }
    Ok(map)
}

fn split_flow_items(inner: &str) -> Result<Vec<&str>, IntelError> {
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start: usize = 0;
    for (idx, ch) in inner.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            ',' => {
                items.push(inner.get(start..idx).unwrap_or(""));
                start = idx.saturating_add(1);
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped {
        return Err(IntelError::NonRestrictivePack(
            "unclosed quote inside flow array".into(),
        ));
    }
    items.push(inner.get(start..).unwrap_or(""));
    Ok(items)
}

fn strip_yaml_comment(raw: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '#' => return raw.get(..idx).unwrap_or(raw),
            _ => {}
        }
    }
    raw
}

fn parse_yaml_scalar(raw: &str) -> Result<String, IntelError> {
    if raw.starts_with('"') {
        let inner = raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| {
                IntelError::NonRestrictivePack("unclosed double quote in YAML".into())
            })?;
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    return Err(IntelError::NonRestrictivePack(format!(
                        "unsupported escape `\\{other}` in YAML"
                    )));
                }
                None => {
                    return Err(IntelError::NonRestrictivePack(
                        "dangling escape in YAML scalar".into(),
                    ));
                }
            }
        }
        return Ok(out);
    }
    if raw.starts_with('\'') {
        let inner = raw
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .ok_or_else(|| {
                IntelError::NonRestrictivePack("unclosed single quote in YAML".into())
            })?;
        return Ok(inner.replace("''", "'"));
    }
    Ok(raw.to_owned())
}

fn normalized_alias_list(
    lists: &BTreeMap<String, Vec<String>>,
    key: &str,
) -> Result<Vec<String>, IntelError> {
    let mut out = Vec::new();
    for raw in lists.get(key).into_iter().flatten() {
        let norm = normalize_intel_key_token(raw);
        if norm.is_empty() {
            return Err(IntelError::NonRestrictivePack(format!(
                "empty normalized alias `{raw}` in `{key}`"
            )));
        }
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    Ok(out)
}

fn is_valid_dns_suffix(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.starts_with("..") {
        return false;
    }
    let clean = trimmed.strip_prefix('.').unwrap_or(trimmed);
    if clean.is_empty() || clean.len() > 253 || !clean.is_ascii() {
        return false;
    }
    clean.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_suffixes_and_aliases_and_rejects_malformed_inputs() {
        let yaml = concat!(
            "format: grdr.intel-governance.v1\n",
            "pack_id: test\n",
            "lists:\n",
            "  forbidden_intel_keys:\n",
            "    - \"allow\"\n",
            "  self_org_aliases:\n",
            "    - \"Loonaro-Labs\"\n",
            "  ossf_aliases:\n",
            "    - \"OpenSSF-Scorecard\"\n",
            "  ghsa_aliases:\n",
            "    - \"GitHub_Advisory\"\n",
            "  private_host_suffixes:\n",
            "    - \".corp.internal\"\n",
        );
        let policy = IntelGovernancePolicy::from_yaml(yaml).expect("valid governance yaml");
        assert_eq!(policy.private_host_suffixes, vec!["corp.internal"]);
        assert_eq!(policy.self_org_aliases, vec!["loonarolabs"]);
        assert_eq!(policy.ossf_aliases, vec!["openssfscorecard"]);
        assert_eq!(policy.ghsa_aliases, vec!["githubadvisory"]);

        let double_dot = concat!(
            "format: grdr.intel-governance.v1\n",
            "pack_id: test\n",
            "lists:\n",
            "  forbidden_intel_keys:\n",
            "    - \"allow\"\n",
            "  private_host_suffixes:\n",
            "    - \"..corp.internal\"\n",
        );
        assert!(IntelGovernancePolicy::from_yaml(double_dot).is_err());

        let blank_alias = concat!(
            "format: grdr.intel-governance.v1\n",
            "pack_id: test\n",
            "lists:\n",
            "  forbidden_intel_keys:\n",
            "    - \"allow\"\n",
            "  self_org_substring_aliases:\n",
            "    - \"---\"\n",
        );
        assert!(IntelGovernancePolicy::from_yaml(blank_alias).is_err());
    }

    #[test]
    fn load_from_packs_dir_rejects_non_directory_and_symlinks() {
        let base = std::env::temp_dir().join(format!("grdr_gov_io_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let lists = base.join("lists");
        std::fs::create_dir_all(&lists).expect("create test dirs");
        let real_file = lists.join("real.yaml");
        std::fs::write(
            &real_file,
            "format: grdr.intel-governance.v1\npack_id: t\nlists:\n  forbidden_intel_keys:\n    - \"allow\"\n",
        )
        .expect("write real yaml");

        assert!(IntelGovernancePolicy::load_from_packs_dir(&real_file).is_err());

        #[cfg(unix)]
        {
            let link_path = lists.join("intel-governance.yaml");
            std::os::unix::fs::symlink(&real_file, &link_path).expect("create unix symlink");
            assert!(IntelGovernancePolicy::load_from_packs_dir(&base).is_err());
        }

        let _ = std::fs::remove_dir_all(&base);
    }
}
