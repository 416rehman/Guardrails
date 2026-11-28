// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Zero-dep reader for `contracts/interface/brand/brand.toml` in `grdr-hook`.

use std::path::PathBuf;
use std::sync::OnceLock;

const EMBEDDED_BRAND_TOML: &str = include_str!("../../../contracts/interface/brand/brand.toml");

static BRAND_CACHE: OnceLock<HookBrandConfig> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookBrandConfig {
    pub namespace: String,
    pub product_name: String,
    pub short_name: String,
    pub windows_data_dir: String,
    pub windows_daemon_service: String,
}

impl HookBrandConfig {
    #[must_use]
    pub fn embedded() -> &'static Self {
        BRAND_CACHE.get_or_init(|| Self::from_toml_str(EMBEDDED_BRAND_TOML))
    }

    #[must_use]
    pub fn from_toml_str(raw: &str) -> Self {
        let mut cfg = Self {
            namespace: "grdr".to_string(),
            product_name: "Guardrails ADR".to_string(),
            short_name: "Guardrails".to_string(),
            windows_data_dir: "grdr".to_string(),
            windows_daemon_service: "grdr-daemon".to_string(),
        };
        let mut section = "";
        for line in raw.lines() {
            let trimmed = strip_toml_comment(line).trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section = trimmed.trim_start_matches('[').trim_end_matches(']').trim();
                continue;
            }
            let Some((key_raw, val_raw)) = trimmed.split_once('=') else {
                continue;
            };
            let key = key_raw.trim();
            let Some(val) = unquote_toml_str(val_raw.trim()) else {
                continue;
            };
            match (section, key) {
                ("identity", "namespace") if !val.is_empty() => cfg.namespace = val,
                ("identity", "product_name") if !val.is_empty() => cfg.product_name = val,
                ("identity", "short_name") if !val.is_empty() => cfg.short_name = val,
                ("os_identity", "windows_data_dir") if !val.is_empty() => {
                    cfg.windows_data_dir = val;
                }
                ("os_identity", "windows_daemon_service") if !val.is_empty() => {
                    cfg.windows_daemon_service = val;
                }
                _ => {}
            }
        }
        cfg
    }

    #[must_use]
    pub fn protected_state_dir(&self) -> PathBuf {
        #[cfg(windows)]
        {
            if let Some(pd) = std::env::var_os("ProgramData")
                && let Some(text) = pd.to_str()
                && !text.trim().is_empty()
            {
                return PathBuf::from(text)
                    .join(&self.windows_data_dir)
                    .join("state");
            }
            PathBuf::from("C:\\ProgramData")
                .join(&self.windows_data_dir)
                .join("state")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from(format!("/var/lib/{}/state", self.namespace))
        }
    }

    #[must_use]
    pub fn protected_run_dirs(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from(format!("/run/{}", self.namespace)),
            PathBuf::from(format!("/Library/Application Support/{}", self.namespace)),
            self.protected_state_dir(),
        ]
    }

    #[must_use]
    pub fn windows_scm_services(&self) -> Vec<String> {
        vec![
            self.windows_daemon_service.clone(),
            self.short_name.clone(),
            format!("{}Handover", self.short_name),
        ]
    }

    #[must_use]
    pub fn user_state_candidate_xdg(&self, xdg: &str) -> PathBuf {
        PathBuf::from(xdg).join(&self.namespace)
    }

    #[must_use]
    pub fn user_state_candidate_home(&self, home: &str) -> PathBuf {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(&self.namespace)
    }

    #[must_use]
    pub fn user_state_candidate_local_appdata(&self, local_appdata: &str) -> PathBuf {
        PathBuf::from(local_appdata)
            .join(&self.windows_data_dir)
            .join("state")
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, b) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if b == b'\\' && in_double {
            escaped = true;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
        } else if b == b'"' && !in_single {
            in_double = !in_double;
        } else if b == b'#' && !in_single && !in_double {
            return line.get(..idx).unwrap_or(line);
        }
    }
    line
}

fn unquote_toml_str(raw: &str) -> Option<String> {
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        return raw.get(1..raw.len().saturating_sub(1)).map(str::to_owned);
    }
    if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        return raw.get(1..raw.len().saturating_sub(1)).map(str::to_owned);
    }
    None
}
