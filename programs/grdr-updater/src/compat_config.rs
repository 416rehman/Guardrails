// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Compatibility matrix resolution from versioned/expiring signed DSSE directives,
//! persisted `state_root` anchors, and `contracts/support.toml` + `compat-components.toml`.

use std::collections::BTreeSet;
use std::path::Path;

use grdr_compat::{CompatMatrix, ProtocolCapability};
use grdr_update::{
    DsseEnvelope, DsseLimits, RootMetadata, SignedMetadata, TufRole, UpdateTrust,
    verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub use crate::compat_toml::load_support_toml_compat_matrix;
use crate::dsse_guard::decode_ed25519_pubkey_b64_strict;
use crate::error::UpdaterError;
use crate::fs_safe::{atomic_write_bytes, path_exists_nofollow, read_bounded_bytes};

pub const COMPAT_MATRIX_DSSE_PAYLOAD_TYPE: &str = "application/vnd.guardrails.compat-matrix+json";
const COMPAT_MATRIX_STATE_FILE: &str = "compat-matrix.dsse.json";
const MAX_COMPAT_MATRIX_BYTES: u64 = 1_048_576;

/// Signed, versioned, expiring `CompatMatrix` payload preventing policy rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCompatMatrixPayload {
    pub version: u64,
    pub expires: Timestamp,
    pub matrix: CompatMatrix,
}

/// Resolve the active `CompatMatrix` strictly from monotonic/unexpired signed DSSE
/// metadata or parsed `contracts/support.toml` + `compat-components.toml` config.
///
/// An expired persisted `compat-matrix.dsse.json` still fails closed when no override
/// is provided, while permitting recovery when a strictly newer valid `signed_override`
/// is verified against the pinned `project_root`.
pub fn resolve_worker_compat_matrix(
    state_root: Option<&Path>,
    project_root: Option<&SignedMetadata<RootMetadata>>,
    signed_override: Option<&DsseEnvelope>,
    now: Timestamp,
) -> Result<CompatMatrix, UpdaterError> {
    let persisted = load_persisted_compat_payload(state_root, project_root, now)?;

    if let Some(env) = signed_override {
        let root = project_root.ok_or_else(|| UpdaterError::TufVerification {
            detail: "refusing signed compat_matrix_dsse without pinned project root".to_string(),
        })?;
        let incoming = verify_signed_compat_dsse(env, root, now)?;
        if let Some(ref prev) = persisted {
            if incoming.version < prev.version {
                return Err(UpdaterError::StaleOrRollback {
                    detail: format!(
                        "compat_matrix_dsse version {} < persisted {}",
                        incoming.version, prev.version
                    ),
                });
            }
            if incoming.version == prev.version {
                if incoming != *prev {
                    return Err(UpdaterError::TufVerification {
                        detail: "compat_matrix_dsse payload conflicts with persisted matrix at same version"
                            .to_string(),
                    });
                }
                if now > prev.expires {
                    return Err(UpdaterError::StaleOrRollback {
                        detail: format!("persisted compat_matrix_dsse expired at {}", prev.expires),
                    });
                }
                return Ok(incoming.matrix);
            }
        }
        if let Some(dir) = state_root {
            let raw = serde_json::to_vec_pretty(env).map_err(|e| UpdaterError::Io {
                detail: format!("failed to encode verified compat-matrix.dsse.json: {e}"),
            })?;
            atomic_write_bytes(&dir.join(COMPAT_MATRIX_STATE_FILE), &raw)?;
        }
        return Ok(incoming.matrix);
    }

    if let Some(prev) = persisted {
        if now > prev.expires {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "persisted compat-matrix.dsse.json expired at {}",
                    prev.expires
                ),
            });
        }
        return Ok(prev.matrix);
    }

    load_support_toml_compat_matrix()
}

fn load_persisted_compat_payload(
    state_root: Option<&Path>,
    project_root: Option<&SignedMetadata<RootMetadata>>,
    now: Timestamp,
) -> Result<Option<SignedCompatMatrixPayload>, UpdaterError> {
    let Some(dir) = state_root else {
        return Ok(None);
    };
    let persisted = dir.join(COMPAT_MATRIX_STATE_FILE);
    if !path_exists_nofollow(&persisted)? {
        return Ok(None);
    }
    let root = project_root.ok_or_else(|| UpdaterError::TufVerification {
        detail: "persisted compat-matrix.dsse.json requires pinned project root".to_string(),
    })?;
    let raw = read_bounded_bytes(&persisted, MAX_COMPAT_MATRIX_BYTES)?;
    let env: DsseEnvelope =
        serde_json::from_slice(&raw).map_err(|e| UpdaterError::TufVerification {
            detail: format!("corrupt persisted compat-matrix.dsse.json: {e}"),
        })?;
    verify_signed_compat_dsse_inner(&env, root, now, false).map(Some)
}

/// Verify a `TufRole::Targets`-signed DSSE envelope encoding a versioned `SignedCompatMatrixPayload`.
pub fn verify_signed_compat_dsse(
    env: &DsseEnvelope,
    project_root: &SignedMetadata<RootMetadata>,
    now: Timestamp,
) -> Result<SignedCompatMatrixPayload, UpdaterError> {
    verify_signed_compat_dsse_inner(env, project_root, now, true)
}

fn verify_signed_compat_dsse_inner(
    env: &DsseEnvelope,
    project_root: &SignedMetadata<RootMetadata>,
    now: Timestamp,
    enforce_expiry: bool,
) -> Result<SignedCompatMatrixPayload, UpdaterError> {
    if env.payload_type != COMPAT_MATRIX_DSSE_PAYLOAD_TYPE {
        return Err(UpdaterError::CompatibilityRejected {
            component: "compat-matrix".into(),
            code: "GRDR-COMPAT-0003".into(),
            reason: format!(
                "unexpected compat matrix DSSE payloadType `{}`",
                env.payload_type
            ),
        });
    }
    let _trust =
        UpdateTrust::new(project_root.clone(), now).map_err(|e| UpdaterError::TufVerification {
            detail: e.to_string(),
        })?;
    let role_def = project_root
        .signed
        .roles
        .get(&TufRole::Targets)
        .ok_or_else(|| UpdaterError::TufVerification {
            detail: "missing TufRole::Targets in pinned project root for compat matrix".to_string(),
        })?;
    let mut seen_kids = BTreeSet::new();
    let mut seen_pks = BTreeSet::new();
    let mut keys = Vec::new();
    for key_id in &role_def.key_ids {
        if !seen_kids.insert(key_id.as_str()) {
            return Err(UpdaterError::TufVerification {
                detail: format!("duplicate key_id '{key_id}' in Targets role"),
            });
        }
        if let Some(info) = project_root.signed.keys.get(key_id) {
            let pk = decode_ed25519_pubkey_b64_strict(&info.public_key_b64)?;
            if !seen_pks.insert(pk) {
                return Err(UpdaterError::TufVerification {
                    detail: "duplicate Ed25519 public key in Targets role".to_string(),
                });
            }
            keys.push(info.clone());
        }
    }
    let key_count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    if role_def.threshold == 0 || key_count < role_def.threshold {
        return Err(UpdaterError::TufVerification {
            detail: "insufficient unique Targets keys for compat matrix DSSE threshold".to_string(),
        });
    }
    let payload_bytes =
        verify_dsse_envelope_with_limits(env, &keys, role_def.threshold, &DsseLimits::default())
            .map_err(|e| UpdaterError::TufVerification {
                detail: e.to_string(),
            })?;
    let payload: SignedCompatMatrixPayload =
        serde_json::from_slice(&payload_bytes).map_err(|e| {
            UpdaterError::CompatibilityRejected {
                component: "compat-matrix".into(),
                code: "GRDR-COMPAT-0003".into(),
                reason: format!("invalid SignedCompatMatrixPayload JSON: {e}"),
            }
        })?;
    if payload.version == 0 {
        return Err(UpdaterError::StaleOrRollback {
            detail: "compat_matrix_dsse version must be >= 1".to_string(),
        });
    }
    if enforce_expiry && now > payload.expires {
        return Err(UpdaterError::StaleOrRollback {
            detail: format!("compat_matrix_dsse expired at {}", payload.expires),
        });
    }
    validate_compat_matrix(&payload.matrix)?;
    Ok(payload)
}

pub(crate) fn parse_capability_name(raw: &str) -> Option<ProtocolCapability> {
    match raw.trim() {
        "mcp_tool_pinning" => Some(ProtocolCapability::McpToolPinning),
        "signed_receipts" => Some(ProtocolCapability::SignedReceipts),
        "session_labels" => Some(ProtocolCapability::SessionLabels),
        "fastpath_floor" => Some(ProtocolCapability::FastpathFloor),
        "ocsf19_export" => Some(ProtocolCapability::Ocsf19Export),
        "step_up_approval" => Some(ProtocolCapability::StepUpApproval),
        _ => None,
    }
}

pub(crate) fn validate_compat_matrix(matrix: &CompatMatrix) -> Result<(), UpdaterError> {
    if matrix.entries.is_empty() {
        return Err(compat_cfg_err(
            "compat-matrix",
            "compat matrix contains zero component entries",
        ));
    }
    for entry in &matrix.entries {
        if entry.component.is_empty() {
            return Err(compat_cfg_err(
                "compat-matrix",
                "compat matrix entry missing component name",
            ));
        }
        if let Some(max_ex) = entry.range.max_exclusive
            && entry.range.min_inclusive >= max_ex
        {
            return Err(compat_cfg_err(
                &entry.component,
                "compat matrix entry has empty version range",
            ));
        }
    }
    Ok(())
}

pub(crate) fn compat_cfg_err(component: &str, reason: &str) -> UpdaterError {
    UpdaterError::CompatibilityRejected {
        component: component.to_owned(),
        code: "GRDR-COMPAT-0003".into(),
        reason: reason.to_owned(),
    }
}
