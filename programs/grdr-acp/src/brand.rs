// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Zero-dep reader for `contracts/interface/brand/brand.toml` in `grdr-acp`.

use std::path::PathBuf;
use std::sync::OnceLock;

const EMBEDDED_BRAND_TOML: &str = include_str!("../../../contracts/interface/brand/brand.toml");
static BRAND_CACHE: OnceLock<AcpBrandConfig> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcpBrandConfig {
    pub namespace: String,
    pub short_name: String,
    pub windows_data_dir: String,
    pub windows_daemon_service: String,
}

impl AcpBrandConfig {
    pub(crate) fn embedded() -> &'static Self {
        BRAND_CACHE.get_or_init(|| Self::from_toml_str(EMBEDDED_BRAND_TOML))
    }

    fn from_toml_str(raw: &str) -> Self {
        let mut cfg = Self {
            namespace: "grdr".to_string(),
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
            let Some((k, v)) = trimmed.split_once('=') else {
                continue;
            };
            let Some(val) = unquote_toml_str(v.trim()) else {
                continue;
            };
            match (section, k.trim()) {
                ("identity", "namespace") if !val.is_empty() => cfg.namespace = val,
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

    pub(crate) fn protected_state_dir(&self) -> PathBuf {
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
        #[cfg(target_os = "macos")]
        {
            PathBuf::from(format!(
                "/Library/Application Support/{}/state",
                self.namespace
            ))
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            PathBuf::from(format!("/var/lib/{}/state", self.namespace))
        }
    }

    #[cfg(windows)]
    pub(crate) fn windows_scm_services(&self) -> Vec<String> {
        vec![
            self.windows_daemon_service.clone(),
            self.short_name.clone(),
            format!("{}Handover", self.short_name),
        ]
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
    if ((raw.starts_with('"') && raw.ends_with('"'))
        || (raw.starts_with('\'') && raw.ends_with('\'')))
        && raw.len() >= 2
    {
        return raw.get(1..raw.len().saturating_sub(1)).map(str::to_owned);
    }
    None
}
