// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Signed `audit.checkpoint` persistence verifying local spool heads across restarts.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use grdr_crypto::{SigningKeypair, verify_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fs_hardening::{
    atomic_write_private_in_verified_dir, read_bounded_nofollow, redact_path_label,
};
use crate::spool_io::SpoolLane;

const CHECKPOINT_DOMAIN: &str = "grdr.checkpoint.v1\0";
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const MAX_CHECKPOINT_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    #[error("GRDR-LSTORE-0011: checkpoint I/O failure: {detail}")]
    Io { detail: String },
    #[error("GRDR-LSTORE-0012: checkpoint signature invalid or tampered")]
    InvalidSignature,
    #[error("GRDR-LSTORE-0013: checkpoint payload malformed: {detail}")]
    Malformed { detail: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneCheckpointHead {
    pub head_seq: u64,
    pub head_hash_hex: String,
    pub durable_through_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpointPayload {
    pub schema_version: u32,
    pub updated_at_unix_s: i64,
    pub gap_count: u64,
    pub lanes: BTreeMap<SpoolLane, LaneCheckpointHead>,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub recorder_head_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditCheckpoint {
    pub payload: AuditCheckpointPayload,
    pub signer_pubkey_b64: String,
    pub signature_b64: String,
}

pub fn save_audit_checkpoint(
    path: impl AsRef<Path>,
    payload: &AuditCheckpointPayload,
    keypair: &SigningKeypair,
) -> Result<SignedAuditCheckpoint, CheckpointError> {
    if payload.schema_version != CHECKPOINT_SCHEMA_VERSION {
        return Err(CheckpointError::Malformed {
            detail: format!(
                "unsupported checkpoint schema_version {}",
                payload.schema_version
            ),
        });
    }
    let canonical = serde_json::to_vec(payload).map_err(|err| CheckpointError::Malformed {
        detail: format!("encode canonical checkpoint payload: {err}"),
    })?;
    let signature_b64 = keypair.sign_bytes(CHECKPOINT_DOMAIN, &canonical);
    let envelope = SignedAuditCheckpoint {
        payload: payload.clone(),
        signer_pubkey_b64: keypair.public_key_b64(),
        signature_b64,
    };
    let encoded =
        serde_json::to_vec_pretty(&envelope).map_err(|err| CheckpointError::Malformed {
            detail: format!("serialize audit checkpoint: {err}"),
        })?;
    let target = path.as_ref();
    atomic_write_private_in_verified_dir(target, &encoded)
        .map_err(|detail| CheckpointError::Io { detail })?;
    Ok(envelope)
}

pub fn load_and_verify_checkpoint(
    path: impl AsRef<Path>,
    expected_pubkey_b64: &str,
) -> Result<Option<SignedAuditCheckpoint>, CheckpointError> {
    let target = path.as_ref();
    let raw = match read_bounded_nofollow(target, MAX_CHECKPOINT_BYTES) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(CheckpointError::Io {
                detail: format!("read checkpoint {}: {err}", redact_path_label(target)),
            });
        }
    };
    let parsed: SignedAuditCheckpoint =
        serde_json::from_slice(&raw).map_err(|err| CheckpointError::Malformed {
            detail: format!("parse audit checkpoint: {err}"),
        })?;
    if parsed.signer_pubkey_b64 != expected_pubkey_b64 {
        return Err(CheckpointError::InvalidSignature);
    }
    let canonical =
        serde_json::to_vec(&parsed.payload).map_err(|err| CheckpointError::Malformed {
            detail: format!("re-encode checkpoint payload: {err}"),
        })?;
    verify_bytes(
        expected_pubkey_b64,
        CHECKPOINT_DOMAIN,
        &canonical,
        &parsed.signature_b64,
    )
    .map_err(|_| CheckpointError::InvalidSignature)?;
    if parsed.payload.schema_version != CHECKPOINT_SCHEMA_VERSION {
        return Err(CheckpointError::Malformed {
            detail: format!(
                "unsupported checkpoint schema_version {}",
                parsed.payload.schema_version
            ),
        });
    }
    Ok(Some(parsed))
}

pub fn load_and_verify_checkpoint_checked(
    path: impl AsRef<Path>,
    expected_pubkey_b64: &str,
    expected_device_id: &str,
    min_epoch: u64,
) -> Result<Option<SignedAuditCheckpoint>, CheckpointError> {
    let Some(ckpt) = load_and_verify_checkpoint(path, expected_pubkey_b64)? else {
        return Ok(None);
    };
    if !expected_device_id.is_empty() && ckpt.payload.device_id != expected_device_id {
        return Err(CheckpointError::Malformed {
            detail: "checkpoint device_id mismatch".to_string(),
        });
    }
    if ckpt.payload.epoch < min_epoch {
        return Err(CheckpointError::Malformed {
            detail: format!(
                "checkpoint anti-rollback violation: epoch {} < expected {min_epoch}",
                ckpt.payload.epoch
            ),
        });
    }
    Ok(Some(ckpt))
}
