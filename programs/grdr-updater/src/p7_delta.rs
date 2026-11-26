// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! P7 schema purity verification, pack channel byte budgets, safe relative path
//! validation, and verified delta reconstruction with fallback (`P7`, `D-22`).

use std::collections::BTreeSet;

use grdr_compat::{
    CompatMatrix, NegotiationOutcome, NegotiationRequest, ProtocolCapability, SemVer,
    negotiate_compatibility,
};
use grdr_update::{PackKind, canonical_sha256};
use grdr_wire::limits::embedded_limits;
use serde::{Deserialize, Serialize};

use crate::error::UpdaterError;

const MAX_P7_JSON_DEPTH: usize = 24;
const DEFAULT_MAX_P7_JSON_BYTES: usize = 16 * 1024 * 1024;

/// Component version pair extracted from verified signed metadata/payloads.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ComponentVersionCheck {
    pub component: String,
    pub version: SemVer,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedPackCompatHeader {
    #[serde(default)]
    pub(crate) components: Vec<ComponentVersionCheck>,
    #[serde(default)]
    pub(crate) required_capabilities: Vec<ProtocolCapability>,
}

/// Exhaustive P7 forbidden keys blocked anywhere inside policy/intel/layer/config packs.
const P7_FORBIDDEN_KEYS: &[&str] = &[
    "command",
    "cmd",
    "args",
    "argv",
    "shell",
    "script",
    "exec",
    "executable",
    "executablepath",
    "binary",
    "url",
    "uri",
    "endpoint",
    "webhook",
    "env",
    "environment",
    "envvars",
    "mcpserver",
    "mcpservers",
    "stdio",
];

/// Delta byte patch reconstructed over an already-verified local base artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaPackage {
    pub target_path: String,
    pub base_sha256: String,
    pub expected_target_sha256: String,
    pub operations: Vec<DeltaOp>,
}

/// Bounded copy/insert operation inside a delta artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaOp {
    CopyBase { offset: usize, len: usize },
    Insert { data: Vec<u8> },
}

/// Hard per-channel size ceiling sourced from embedded `contracts/limits.toml` before parsing.
#[must_use]
pub fn max_bytes_for_pack(pack_kind: PackKind) -> u64 {
    let lim = embedded_limits().ok();
    match pack_kind {
        PackKind::Binary => 134_217_728,
        PackKind::SchemaPolicy => lim
            .and_then(|l| u64::try_from(l.essentials_max_bytes).ok())
            .filter(|&v| v > 0)
            .unwrap_or(524_288),
        PackKind::Detection => lim
            .and_then(|l| u64::try_from(l.detections_max_bytes).ok())
            .filter(|&v| v > 0)
            .unwrap_or(4_194_304),
        PackKind::Intel | PackKind::OrgIntel => lim
            .and_then(|l| u64::try_from(l.max_pack_bundle_bytes).ok())
            .filter(|&v| v > 0)
            .unwrap_or(16_777_216),
        PackKind::Integration
        | PackKind::LayerDocument
        | PackKind::AgentConfig
        | PackKind::OrgCatalogue => 2_097_152,
        PackKind::Rollout => 524_288,
    }
}

/// Enforce strict relative target path hygiene (rejecting traversal, root prefixes, backslashes).
pub fn validate_safe_target_path(target_path: &str) -> Result<(), UpdaterError> {
    if target_path.is_empty()
        || target_path.starts_with('/')
        || target_path.contains('\\')
        || target_path.contains(':')
        || target_path.contains('\0')
        || target_path.chars().any(char::is_control)
    {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("invalid TUF target path '{target_path}'"),
        });
    }
    for segment in target_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(UpdaterError::PathUnsafe {
                detail: format!("unsafe segment in TUF target path '{target_path}'"),
            });
        }
    }
    Ok(())
}

/// Enforce P7 schema purity: payload size bound first, then JSON object with zero forbidden keys.
pub fn enforce_p7_json_purity(channel: &str, json_bytes: &[u8]) -> Result<(), UpdaterError> {
    let max_bytes = embedded_limits()
        .ok()
        .map(|l| l.max_pack_bundle_bytes.max(DEFAULT_MAX_P7_JSON_BYTES))
        .unwrap_or(DEFAULT_MAX_P7_JSON_BYTES);
    if json_bytes.len() > max_bytes {
        return Err(UpdaterError::BudgetExceeded {
            channel: channel.to_string(),
            actual_bytes: u64::try_from(json_bytes.len()).unwrap_or(u64::MAX),
            max_bytes: u64::try_from(max_bytes).unwrap_or(u64::MAX),
        });
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(json_bytes).map_err(|e| UpdaterError::TufVerification {
            detail: format!("pack '{channel}' payload must be valid JSON object: {e}"),
        })?;
    if !matches!(parsed, serde_json::Value::Object(_)) {
        return Err(UpdaterError::TufVerification {
            detail: format!("pack '{channel}' top-level payload must be a JSON object"),
        });
    }
    let forbidden: BTreeSet<&'static str> = P7_FORBIDDEN_KEYS.iter().copied().collect();
    scan_json_value(channel, &parsed, &forbidden, 0)
}

/// Reconstruct an artifact from a verified local base and delta patch, rejecting mismatches
/// with [`UpdaterError::DeltaFallbackRequired`] so uplink falls back to full download cleanly.
pub fn reconstruct_delta_or_request_full(
    base_bytes: &[u8],
    delta: &DeltaPackage,
    max_bytes: u64,
) -> Result<Vec<u8>, UpdaterError> {
    validate_safe_target_path(&delta.target_path)?;
    let actual_base = canonical_sha256(base_bytes);
    if actual_base != delta.base_sha256 {
        return Err(UpdaterError::DeltaFallbackRequired {
            target_path: delta.target_path.clone(),
            expected_sha256: delta.base_sha256.clone(),
            actual_sha256: actual_base,
        });
    }

    if delta.operations.is_empty() {
        return Err(UpdaterError::DeltaFallbackRequired {
            target_path: delta.target_path.clone(),
            expected_sha256: delta.expected_target_sha256.clone(),
            actual_sha256: "empty-delta-operations".to_string(),
        });
    }
    let mut out = Vec::new();
    for op in &delta.operations {
        match op {
            DeltaOp::CopyBase { offset, len } => {
                if *len == 0 {
                    return Err(UpdaterError::DeltaFallbackRequired {
                        target_path: delta.target_path.clone(),
                        expected_sha256: delta.expected_target_sha256.clone(),
                        actual_sha256: "zero-len-copy-op".to_string(),
                    });
                }
                let end = offset.saturating_add(*len);
                let slice = base_bytes.get(*offset..end).ok_or_else(|| {
                    UpdaterError::DeltaFallbackRequired {
                        target_path: delta.target_path.clone(),
                        expected_sha256: delta.expected_target_sha256.clone(),
                        actual_sha256: "out-of-bounds-base-copy".to_string(),
                    }
                })?;
                ensure_within_budget(&delta.target_path, out.len(), slice.len(), max_bytes)?;
                out.extend_from_slice(slice);
            }
            DeltaOp::Insert { data } => {
                if data.is_empty() {
                    return Err(UpdaterError::DeltaFallbackRequired {
                        target_path: delta.target_path.clone(),
                        expected_sha256: delta.expected_target_sha256.clone(),
                        actual_sha256: "empty-insert-op".to_string(),
                    });
                }
                ensure_within_budget(&delta.target_path, out.len(), data.len(), max_bytes)?;
                out.extend_from_slice(data);
            }
        }
    }

    let actual_target = canonical_sha256(&out);
    if actual_target != delta.expected_target_sha256 {
        return Err(UpdaterError::DeltaFallbackRequired {
            target_path: delta.target_path.clone(),
            expected_sha256: delta.expected_target_sha256.clone(),
            actual_sha256: actual_target,
        });
    }
    Ok(out)
}

fn scan_json_value(
    channel: &str,
    value: &serde_json::Value,
    forbidden: &BTreeSet<&'static str>,
    depth: usize,
) -> Result<(), UpdaterError> {
    if depth > MAX_P7_JSON_DEPTH {
        return Err(UpdaterError::TufVerification {
            detail: format!("pack '{channel}' exceeds max JSON nesting depth"),
        });
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let normalized: String = k
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect();
                if forbidden.contains(normalized.as_str()) {
                    return Err(UpdaterError::ForbiddenField {
                        channel: channel.to_string(),
                        field: k.clone(),
                    });
                }
                scan_json_value(channel, v, forbidden, depth.saturating_add(1))?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scan_json_value(channel, item, forbidden, depth.saturating_add(1))?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

fn ensure_within_budget(
    channel: &str,
    current_len: usize,
    add_len: usize,
    max_bytes: u64,
) -> Result<(), UpdaterError> {
    let total = u64::try_from(current_len.saturating_add(add_len)).unwrap_or(u64::MAX);
    if total > max_bytes {
        return Err(UpdaterError::BudgetExceeded {
            channel: channel.to_string(),
            actual_bytes: total,
            max_bytes,
        });
    }
    Ok(())
}

/// Gate activation against `grdr-compat` ranges and non-tautological `host_capabilities` (`D-71`).
pub fn check_bundle_compatibility(
    matrix: &CompatMatrix,
    specs: &[ComponentVersionCheck],
    required_capabilities: &[ProtocolCapability],
    host_capabilities: &[ProtocolCapability],
) -> Result<Vec<String>, UpdaterError> {
    for req_cap in required_capabilities {
        if !host_capabilities.contains(req_cap) {
            return Err(UpdaterError::CompatibilityRejected {
                component: specs
                    .first()
                    .map_or_else(String::new, |s| s.component.clone()),
                code: "GRDR-COMPAT-0003".to_string(),
                reason: format!("host missing bundle required capability {:?}", req_cap),
            });
        }
    }

    let mut out_warnings = Vec::new();
    for spec in specs {
        let req = NegotiationRequest {
            component: spec.component.clone(),
            client_version: spec.version,
            advertised_capabilities: host_capabilities.to_vec(),
        };
        match negotiate_compatibility(matrix, &req) {
            NegotiationOutcome::Compatible { .. } => {}
            NegotiationOutcome::CompatibleWithWarnings { warnings, .. } => {
                if let Some(entry) = matrix
                    .entries
                    .iter()
                    .find(|e| e.component == spec.component)
                {
                    for cap in &entry.required_capabilities {
                        if !host_capabilities.contains(cap) {
                            return Err(UpdaterError::CompatibilityRejected {
                                component: spec.component.clone(),
                                code: "GRDR-COMPAT-0003".to_string(),
                                reason: format!(
                                    "host missing matrix required capability {:?}",
                                    cap
                                ),
                            });
                        }
                    }
                }
                for w in warnings {
                    out_warnings.push(format!("{}: {w}", spec.component));
                }
            }
            NegotiationOutcome::Incompatible { code, reason, .. } => {
                return Err(UpdaterError::CompatibilityRejected {
                    component: spec.component.clone(),
                    code: code.to_string(),
                    reason,
                });
            }
        }
    }
    Ok(out_warnings)
}
