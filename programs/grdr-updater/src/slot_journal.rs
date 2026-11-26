// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Authenticated slot journal types, serialization, and lockstep floor verification (`D-11`).

use std::collections::BTreeMap;
use std::path::Path;

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_update::{SlotState, UpdateSlot};
use serde::{Deserialize, Serialize};

use crate::error::UpdaterError;
use crate::fs_safe::{atomic_write_bytes, read_bounded_bytes};

const MAX_JOURNAL_BYTES: u64 = 4_194_304;

/// Governing update authority on this host (`docs/design/11` & `24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateAuthority {
    SelfManaged,
    Managed,
    Image,
}

/// Binary integrity observation in `Managed` or `SelfManaged` authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinaryIntegrityOutcome {
    MatchesExpected,
    ExternalBinaryTamperDetected {
        expected_sha256: String,
        actual_sha256: String,
    },
}

/// Versioned snapshot of an inactive/active slot used for deterministic rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSnapshot {
    pub slot: UpdateSlot,
    pub version: String,
    pub generation: u64,
    pub sha256: String,
}

/// Persistent active/LKG metadata for one policy/pack channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackChannelRecord {
    pub channel: String,
    pub active_version: String,
    pub active_generation: u64,
    pub active_sha256: String,
    pub lkg_version: Option<String>,
    pub lkg_generation: Option<u64>,
    pub lkg_sha256: Option<String>,
}

/// Explicit stabilization lifecycle for a pending A/B slot activation (`D-11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PendingCommitWindow {
    Idle,
    Pending {
        issued_wall_s: i64,
        until_wall_s: i64,
        issued_mono_ms: u64,
    },
}

/// Durable journal persisted atomically on every state transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotJournal {
    pub authority: UpdateAuthority,
    pub slot_state: SlotState,
    pub security_floor: u64,
    pub active: SlotSnapshot,
    pub previous: Option<SlotSnapshot>,
    pub pending_commit: PendingCommitWindow,
    pub consecutive_crashes: u32,
    pub pack_channels: BTreeMap<String, PackChannelRecord>,
}

/// Ed25519-authenticated slot journal envelope preventing unauthorized local mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSlotJournal {
    pub journal: SlotJournal,
    pub key_id: String,
    pub signature_b64: String,
}

pub(crate) fn slot_state_floor(state: &SlotState) -> u64 {
    match state {
        SlotState::Active { security_floor, .. }
        | SlotState::Staging { security_floor, .. }
        | SlotState::PendingActivation { security_floor, .. }
        | SlotState::RolledBack { security_floor, .. } => *security_floor,
    }
}

pub(crate) fn sync_slot_state_floor(journal: &mut SlotJournal) {
    let floor = journal.security_floor;
    match &mut journal.slot_state {
        SlotState::Active { security_floor, .. }
        | SlotState::Staging { security_floor, .. }
        | SlotState::PendingActivation { security_floor, .. }
        | SlotState::RolledBack { security_floor, .. } => *security_floor = floor,
    }
}

pub(crate) fn load_verified_journal(
    journal_path: &Path,
    authority: UpdateAuthority,
    journal_signer: &SigningKeypair,
) -> Result<SlotJournal, UpdaterError> {
    let raw = read_bounded_bytes(journal_path, MAX_JOURNAL_BYTES)?;
    let envelope: SignedSlotJournal =
        serde_json::from_slice(&raw).map_err(|e| UpdaterError::SlotTransitionInvalid {
            detail: format!("corrupt signed slot journal: {e}"),
        })?;
    if envelope.key_id != journal_signer.key_id() {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: "slot journal key_id does not match pinned journal signer".to_string(),
        });
    }
    let canonical = serde_json::to_vec(&envelope.journal).map_err(|e| UpdaterError::Io {
        detail: format!("canonical slot journal encode failed: {e}"),
    })?;
    verify_bytes(
        &journal_signer.public_key_b64(),
        "grdr-slot-journal-v1",
        &canonical,
        &envelope.signature_b64,
    )
    .map_err(|_| UpdaterError::SlotTransitionInvalid {
        detail: "slot journal signature verification failed (tamper detected)".to_string(),
    })?;
    if envelope.journal.authority != authority {
        return Err(UpdaterError::AuthorityDisallowed {
            authority: format!("{:?}", envelope.journal.authority),
            action: format!("reopen with mismatched authority {authority:?}"),
        });
    }
    let state_floor = slot_state_floor(&envelope.journal.slot_state);
    if envelope.journal.security_floor != state_floor {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: format!(
                "slot journal security_floor {} != slot_state.security_floor {state_floor}",
                envelope.journal.security_floor
            ),
        });
    }
    if let PendingCommitWindow::Pending {
        issued_wall_s,
        until_wall_s,
        ..
    } = envelope.journal.pending_commit
        && until_wall_s < issued_wall_s
    {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: "corrupt slot journal pending_commit stabilization window".to_string(),
        });
    }
    Ok(envelope.journal)
}

pub(crate) fn persist_signed_journal(
    journal_path: &Path,
    journal_signer: &SigningKeypair,
    journal: &SlotJournal,
) -> Result<(), UpdaterError> {
    let canonical = serde_json::to_vec(journal).map_err(|e| UpdaterError::Io {
        detail: format!("failed to canonicalize slot journal: {e}"),
    })?;
    let signature_b64 = journal_signer.sign_bytes("grdr-slot-journal-v1", &canonical);
    let envelope = SignedSlotJournal {
        journal: journal.clone(),
        key_id: journal_signer.key_id().to_string(),
        signature_b64,
    };
    let encoded = serde_json::to_vec_pretty(&envelope).map_err(|e| UpdaterError::Io {
        detail: format!("failed to encode slot journal: {e}"),
    })?;
    atomic_write_bytes(journal_path, &encoded)
}

pub(crate) fn initial_slot_journal(
    authority: UpdateAuthority,
    version: String,
    initial_generation: u64,
    initial_sha: String,
) -> SlotJournal {
    let slot_state = SlotState::initial(
        version.clone(),
        initial_generation,
        initial_sha.clone(),
        initial_generation,
    );
    SlotJournal {
        authority,
        slot_state,
        security_floor: initial_generation,
        active: SlotSnapshot {
            slot: UpdateSlot::SlotA,
            version,
            generation: initial_generation,
            sha256: initial_sha,
        },
        previous: None,
        pending_commit: PendingCommitWindow::Idle,
        consecutive_crashes: 0,
        pack_channels: BTreeMap::new(),
    }
}

pub(crate) fn validate_channel_name(channel: &str) -> Result<(), UpdaterError> {
    if channel.is_empty()
        || !channel
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(UpdaterError::PathUnsafe {
            detail: format!("invalid pack channel name '{channel}'"),
        });
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex(sha256: &str) -> Result<(), UpdaterError> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: format!("invalid SHA-256 hex digest '{sha256}'"),
        });
    }
    Ok(())
}
