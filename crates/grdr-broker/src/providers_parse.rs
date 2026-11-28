// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! YAML field parsers and transport validators for `providers.d/` manifests (`docs/design/07`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use grdr_core::detect::yaml::YamlValue;
use grdr_model::CodedError;

use crate::providers::{
    DEFAULT_PROVIDER_DEADLINE_MS, MAX_PROVIDER_DEADLINE_MS, ProviderCapabilities,
    ProviderCaptureCeiling, ProviderKind, ProviderOnFailure, ProviderTrustModel,
};

pub(crate) fn brk_manifest_err(msg: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-BRK-0005",
        msg,
        "Validate providers.d manifest against spec/hook-broker/provider-manifest.schema.yaml.",
    )
}

pub(crate) fn is_valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

pub(crate) fn validate_provider_transport(
    kind: ProviderKind,
    endpoint: &str,
    command: Option<&str>,
    args: &[String],
) -> Result<(), CodedError> {
    match kind {
        ProviderKind::Native | ProviderKind::Acs => validate_ipc_endpoint(endpoint),
        ProviderKind::CommandHook => {
            let cmd = command
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    brk_manifest_err("command-hook provider requires non-empty `command`")
                })?;
            if !(cmd.starts_with('/') || Path::new(cmd).is_absolute()) {
                return Err(brk_manifest_err(
                    "command-hook `command` must be an absolute path",
                ));
            }
            if cmd.chars().any(|c| {
                c.is_control() || matches!(c, '\t' | ';' | '|' | '&' | '`' | '$' | '<' | '>')
            }) || cmd.contains("..")
            {
                return Err(brk_manifest_err(
                    "command-hook `command` contains forbidden shell or traversal characters",
                ));
            }
            for arg in args {
                if arg.chars().any(char::is_control) || arg.contains('\t') || arg.contains(',') {
                    return Err(brk_manifest_err(
                        "command-hook `args` contains control char, tab, or comma",
                    ));
                }
            }
            if !endpoint.is_empty() {
                validate_ipc_endpoint(endpoint)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn validate_ipc_endpoint(endpoint: &str) -> Result<(), CodedError> {
    if endpoint.is_empty()
        || endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || endpoint.contains(['@', '#', '?'])
    {
        return Err(brk_manifest_err(
            "endpoint contains forbidden control, whitespace, userinfo, query, or fragment characters",
        ));
    }
    if let Some(sock_path) = endpoint.strip_prefix("unix:///") {
        if sock_path.is_empty()
            || sock_path.contains('\\')
            || Path::new(sock_path)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            || is_temp_unix_socket_path(sock_path)
        {
            return Err(brk_manifest_err(
                "invalid or temporary unix:/// endpoint path",
            ));
        }
        return Ok(());
    }
    if let Some(pipe_name) = endpoint.strip_prefix(r"\\.\pipe\") {
        if pipe_name.is_empty() || pipe_name.contains(['\\', '/']) || pipe_name.contains("..") {
            return Err(brk_manifest_err("invalid Windows named-pipe endpoint"));
        }
        return Ok(());
    }
    let stripped = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .or_else(|| endpoint.strip_prefix("ipc://"))
        .unwrap_or(endpoint)
        .trim_end_matches('/');
    let port_str = stripped
        .strip_prefix("127.0.0.1:")
        .or_else(|| stripped.strip_prefix("[::1]:"))
        .ok_or_else(|| {
            brk_manifest_err(
                "endpoint must use unix:///, \\\\.\\pipe\\, or loopback IPC (127.0.0.1 / [::1])",
            )
        })?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| brk_manifest_err("loopback IPC endpoint port must be 1..=65535"))?;
    if port == 0 {
        return Err(brk_manifest_err(
            "loopback IPC endpoint port must be non-zero",
        ));
    }
    Ok(())
}

pub(crate) fn parse_provider_kind(
    map: &BTreeMap<String, YamlValue>,
) -> Result<ProviderKind, CodedError> {
    match map.get("kind") {
        None => Ok(ProviderKind::Native),
        Some(v) => match v.as_str() {
            Some("native") => Ok(ProviderKind::Native),
            Some("command-hook" | "command_hook") => Ok(ProviderKind::CommandHook),
            Some("acs") => Ok(ProviderKind::Acs),
            _ => Err(brk_manifest_err("unknown `kind` in provider manifest")),
        },
    }
}

pub(crate) fn parse_string_list(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
) -> Result<Vec<String>, CodedError> {
    match map.get(key) {
        None => Ok(Vec::new()),
        Some(YamlValue::Seq(seq)) => seq
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| brk_manifest_err(format!("`{key}` entries must be strings")))
            })
            .collect(),
        Some(_) => Err(brk_manifest_err(format!("`{key}` must be a YAML sequence"))),
    }
}

pub(crate) fn req_nonempty_str(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
) -> Result<String, CodedError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| brk_manifest_err(format!("provider manifest missing `{key}`")))
}

pub(crate) fn parse_capabilities_map(
    id: &str,
    caps_map: &BTreeMap<String, YamlValue>,
) -> Result<ProviderCapabilities, CodedError> {
    let provider_id = match caps_map.get("provider_id") {
        None => id.to_owned(),
        Some(v) => v
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| brk_manifest_err("`capabilities.provider_id` must be non-empty"))?
            .to_owned(),
    };
    let action_classes = match caps_map.get("action_classes") {
        None => BTreeSet::new(),
        Some(YamlValue::Seq(seq)) => {
            let mut set = BTreeSet::new();
            for item in seq {
                let s = item
                    .as_str()
                    .ok_or_else(|| brk_manifest_err("`action_classes` entries must be strings"))?;
                set.insert(s.to_owned());
            }
            set
        }
        Some(_) => {
            return Err(brk_manifest_err(
                "`capabilities.action_classes` must be a list",
            ));
        }
    };
    let max_capture_level = match caps_map.get("max_capture_level") {
        None => ProviderCaptureCeiling::MetadataOnly,
        Some(v) => match v.as_str() {
            Some("metadata_only") => ProviderCaptureCeiling::MetadataOnly,
            Some("argument_preview") => ProviderCaptureCeiling::ArgumentPreview,
            Some("full_minimised") => ProviderCaptureCeiling::FullMinimised,
            _ => return Err(brk_manifest_err("unknown `capabilities.max_capture_level`")),
        },
    };
    let on_failure = match caps_map.get("on_failure") {
        None => ProviderOnFailure::FailClosed,
        Some(v) => match v.as_str() {
            Some("fail_closed") => ProviderOnFailure::FailClosed,
            Some("step_up") => ProviderOnFailure::StepUp,
            Some("ignore") => ProviderOnFailure::Ignore,
            _ => return Err(brk_manifest_err("unknown `capabilities.on_failure`")),
        },
    };
    let trust_model = match caps_map.get("trust_model") {
        None => ProviderTrustModel::DeterministicRule,
        Some(v) => match v.as_str() {
            Some("deterministic_rule") => ProviderTrustModel::DeterministicRule,
            Some("model_backed") => ProviderTrustModel::ModelBacked,
            _ => return Err(brk_manifest_err("unknown `capabilities.trust_model`")),
        },
    };
    let may_modify = match caps_map.get("may_modify") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| brk_manifest_err("`capabilities.may_modify` must be a boolean"))?,
    };
    let timeout_ms = match caps_map.get("timeout_ms") {
        None => DEFAULT_PROVIDER_DEADLINE_MS,
        Some(v) => v
            .as_i64()
            .and_then(|n| u64::try_from(n).ok())
            .filter(|&ms| ms > 0 && ms <= MAX_PROVIDER_DEADLINE_MS)
            .ok_or_else(|| brk_manifest_err("`capabilities.timeout_ms` must be 1..=1000"))?,
    };
    let priority = match caps_map.get("priority") {
        None => 100,
        Some(v) => v
            .as_i64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| brk_manifest_err("`capabilities.priority` must be 0..=65535"))?,
    };

    Ok(ProviderCapabilities {
        provider_id,
        action_classes,
        max_capture_level,
        on_failure,
        trust_model,
        may_modify,
        timeout_ms,
        priority,
    })
}

fn is_temp_unix_socket_path(sock_path: &str) -> bool {
    let normalized = sock_path.trim_start_matches('/').to_ascii_lowercase();
    for prefix in ["tmp/", "var/tmp/", "private/tmp/", "dev/shm/"] {
        if normalized == prefix.trim_end_matches('/') || normalized.starts_with(prefix) {
            return true;
        }
    }
    let tmp_str = std::env::temp_dir()
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_ascii_lowercase();
    let trimmed_tmp = tmp_str.trim_end_matches('/');
    !trimmed_tmp.is_empty()
        && (normalized == trimmed_tmp || normalized.starts_with(&format!("{trimmed_tmp}/")))
}
