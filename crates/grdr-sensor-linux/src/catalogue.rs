// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::SensorError;
use crate::fs_safe::{read_nofollow_bounded_utf8, verify_non_symlink_dir};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessMatchKind {
    CommExact,
    CommPrefix,
    CommContains,
    ExeBasename,
    ArgvContains,
    EnvKeyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessMatchRule {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    pub kind: HarnessMatchKind,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HarnessCatalogue {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default, alias = "harnesses")]
    pub rules: Vec<HarnessMatchRule>,
}

impl HarnessMatchRule {
    pub fn matches(
        &self,
        comm_lower: &str,
        argv_joined_lower: &str,
        exe_basename_lower: Option<&str>,
        env_keys: &[String],
    ) -> bool {
        self.patterns.iter().any(|raw_pat| {
            let pat = raw_pat.trim().to_ascii_lowercase();
            if pat.is_empty() {
                return false;
            }
            match self.kind {
                HarnessMatchKind::CommExact => comm_lower == pat,
                HarnessMatchKind::CommPrefix => comm_lower.starts_with(&pat),
                HarnessMatchKind::CommContains => comm_lower.contains(&pat),
                HarnessMatchKind::ExeBasename => exe_basename_lower.is_some_and(|exe| exe == pat),
                HarnessMatchKind::ArgvContains => argv_joined_lower.contains(&pat),
                HarnessMatchKind::EnvKeyPresent => {
                    env_keys.iter().any(|k| k.eq_ignore_ascii_case(&pat))
                }
            }
        })
    }
}

impl HarnessCatalogue {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            rules: Vec::new(),
        }
    }

    pub fn from_rules(rules: Vec<HarnessMatchRule>) -> Self {
        Self {
            schema_version: 1,
            rules,
        }
    }

    pub fn from_json_str(raw: &str, source_label: &str) -> Result<Self, SensorError> {
        serde_json::from_str(raw).map_err(|err| SensorError::CatalogueLoad {
            path: source_label.to_string(),
            detail: err.to_string(),
        })
    }

    pub fn from_toml_str(raw: &str, source_label: &str) -> Result<Self, SensorError> {
        parse_toml_catalogue(raw, source_label)
    }

    pub fn load_from_dir(dir: &Path, max_file_bytes: u64) -> Result<Self, SensorError> {
        if !dir.exists() {
            return Ok(Self::empty());
        }
        let entries = verify_non_symlink_dir(dir, "harness catalogue dir")?;
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| !name.starts_with('.'))
            })
            .collect();
        paths.sort();

        let mut merged = Self::empty();
        for path in paths {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            if !matches!(ext.as_deref(), Some("json" | "toml")) {
                continue;
            }
            let raw = read_nofollow_bounded_utf8(&path, max_file_bytes, "harness catalogue")?;
            let path_str = path.display().to_string();
            let parsed = match ext.as_deref() {
                Some("json") => Self::from_json_str(&raw, &path_str)?,
                Some("toml") => Self::from_toml_str(&raw, &path_str)?,
                _ => continue,
            };
            merged.rules.extend(parsed.rules);
        }
        Ok(merged)
    }

    pub fn match_process(
        &self,
        comm: &str,
        cmdline: &[String],
        exe_path: Option<&str>,
        env_keys: &[String],
    ) -> Option<String> {
        let comm_lower = comm.trim().to_ascii_lowercase();
        let argv_lower = cmdline.join(" ").to_ascii_lowercase();
        let exe_base_lower = exe_path
            .and_then(|p| Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .map(|n| n.trim().to_ascii_lowercase());
        for rule in &self.rules {
            if rule.matches(
                &comm_lower,
                &argv_lower,
                exe_base_lower.as_deref(),
                env_keys,
            ) {
                if rule.id.trim().is_empty() {
                    return Some(rule.display_name.clone());
                }
                return Some(rule.id.clone());
            }
        }
        None
    }
}

fn default_schema_version() -> u32 {
    1
}

fn parse_toml_catalogue(raw: &str, source_label: &str) -> Result<HarnessCatalogue, SensorError> {
    let mut catalogue = HarnessCatalogue::empty();
    let mut current: Option<HarnessMatchRule> = None;

    for (line_idx, raw_line) in raw.lines().enumerate() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[harnesses]]" || line == "[[rules]]" {
            if let Some(rule) = current.take() {
                validate_rule(&rule, source_label, line_idx)?;
                catalogue.rules.push(rule);
            }
            current = Some(HarnessMatchRule {
                id: String::new(),
                display_name: String::new(),
                kind: HarnessMatchKind::CommContains,
                patterns: Vec::new(),
            });
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            return Err(SensorError::CatalogueLoad {
                path: source_label.to_string(),
                detail: format!("invalid TOML line {}", line_idx.saturating_add(1)),
            });
        };
        let key = key.trim();
        let val = val.trim();
        if current.is_none() && key == "schema_version" {
            catalogue.schema_version =
                val.parse::<u32>().map_err(|_| SensorError::CatalogueLoad {
                    path: source_label.to_string(),
                    detail: "invalid schema_version".into(),
                })?;
            continue;
        }
        let Some(rule) = current.as_mut() else {
            continue;
        };
        match key {
            "id" => rule.id = parse_quoted_str(val, source_label)?,
            "display_name" => rule.display_name = parse_quoted_str(val, source_label)?,
            "kind" => {
                let kind_str = parse_quoted_str(val, source_label)?;
                rule.kind = match kind_str.as_str() {
                    "comm_exact" => HarnessMatchKind::CommExact,
                    "comm_prefix" => HarnessMatchKind::CommPrefix,
                    "comm_contains" => HarnessMatchKind::CommContains,
                    "exe_basename" => HarnessMatchKind::ExeBasename,
                    "argv_contains" => HarnessMatchKind::ArgvContains,
                    "env_key_present" => HarnessMatchKind::EnvKeyPresent,
                    other => {
                        return Err(SensorError::CatalogueLoad {
                            path: source_label.to_string(),
                            detail: format!("unknown match kind `{other}`"),
                        });
                    }
                };
            }
            "patterns" => rule.patterns = parse_string_array(val, source_label)?,
            _ => {}
        }
    }
    if let Some(rule) = current {
        validate_rule(&rule, source_label, 0)?;
        catalogue.rules.push(rule);
    }
    Ok(catalogue)
}

fn validate_rule(
    rule: &HarnessMatchRule,
    source_label: &str,
    line_idx: usize,
) -> Result<(), SensorError> {
    if rule.id.trim().is_empty() || rule.patterns.is_empty() {
        return Err(SensorError::CatalogueLoad {
            path: source_label.to_string(),
            detail: format!(
                "rule near line {} missing id or patterns",
                line_idx.saturating_add(1)
            ),
        });
    }
    Ok(())
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return line.get(..idx).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn parse_quoted_str(raw: &str, source_label: &str) -> Result<String, SensorError> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| SensorError::CatalogueLoad {
            path: source_label.to_string(),
            detail: format!("expected quoted string, found `{trimmed}`"),
        })?;
    Ok(inner.to_string())
}

fn parse_string_array(raw: &str, source_label: &str) -> Result<Vec<String>, SensorError> {
    let inner = raw
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| SensorError::CatalogueLoad {
            path: source_label.to_string(),
            detail: "expected TOML string array".into(),
        })?;
    let mut items = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        items.push(parse_quoted_str(p, source_label)?);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn loads_json_and_toml_catalogues_without_hardcoded_lists() {
        let dir = std::env::temp_dir().join(format!("grdr-cat-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join("01-runtime.toml"),
            r#"
schema_version = 1

[[harnesses]]
id = "sample-agent"
display_name = "Sample Agent"
kind = "argv_contains"
patterns = ["--sample-mode", "sample-cli"]
"#,
        )
        .unwrap();
        fs::write(
            dir.join("02-extra.json"),
            r#"{"schema_version":1,"rules":[{"id":"custom-harness","display_name":"Custom","kind":"exe_basename","patterns":["custom-bin"]}]}"#,
        )
        .unwrap();

        let catalogue = HarnessCatalogue::load_from_dir(&dir, 1_048_576).unwrap();
        assert_eq!(catalogue.rules.len(), 2);
        assert_eq!(
            catalogue.match_process(
                "node",
                &["node".into(), "sample-cli".into()],
                Some("/usr/bin/node"),
                &[],
            ),
            Some("sample-agent".into())
        );
        assert_eq!(
            catalogue.match_process("worker", &[], Some("/opt/bin/custom-bin"), &[]),
            Some("custom-harness".into())
        );
        assert_eq!(
            catalogue.match_process("curl", &["curl".into()], Some("/usr/bin/curl"), &[]),
            None
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
