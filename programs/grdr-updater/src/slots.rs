// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Signed A/B slot activation, LKG pack channels, `security_floor` enforcement,
//! update authority isolation (`self`/`managed`/`image`), and crash auto-revert (`D-11`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_update::{PackKind, SlotState, UpdateSlot, canonical_sha256};
use serde::{Deserialize, Serialize};

use crate::error::UpdaterError;
use crate::fs_safe::{atomic_write_bytes, ensure_not_symlink, ensure_safe_dir, read_bounded_bytes};
use crate::verify::VerifiedUpdateArtifact;

/// Startup failures during 30-minute stabilization window before automatic rollback.
pub const MAX_CONSECUTIVE_BOOT_CRASHES: u32 = 3;
/// Post-activation binary stabilization window in wall seconds (30 minutes).
pub const COMMIT_STABILIZATION_WINDOW_S: i64 = 1_800;
/// Maximum slot journal size permitted from disk (4 MiB).
const MAX_JOURNAL_BYTES: u64 = 4_194_304;
/// Maximum slot binary size permitted from disk (128 MiB).
const MAX_SLOT_BINARY_BYTES: u64 = 134_217_728;

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

/// Durable journal persisted atomically on every state transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotJournal {
    pub authority: UpdateAuthority,
    pub slot_state: SlotState,
    pub security_floor: u64,
    pub active: SlotSnapshot,
    pub previous: Option<SlotSnapshot>,
    pub pending_commit_issued_wall_s: Option<i64>,
    pub pending_commit_until_wall_s: Option<i64>,
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

/// Atomic updater controller for binary slots and pack channels.
pub struct SlotActivationManager {
    state_root: PathBuf,
    journal_path: PathBuf,
    journal_signer: SigningKeypair,
    journal: SlotJournal,
}

impl SlotActivationManager {
    /// Load and cryptographically verify `slots.journal.json` or initialize safely on Slot A.
    pub fn open_or_init(
        state_root: PathBuf,
        authority: UpdateAuthority,
        journal_signer: SigningKeypair,
        initial_version: impl Into<String>,
        initial_generation: u64,
        initial_sha256: impl Into<String>,
    ) -> Result<Self, UpdaterError> {
        ensure_safe_dir(&state_root)?;
        let initial_sha = initial_sha256.into();
        validate_sha256_hex(&initial_sha)?;
        let journal_path = state_root.join("slots.journal.json");

        if journal_path.exists() {
            let raw = read_bounded_bytes(&journal_path, MAX_JOURNAL_BYTES)?;
            let envelope: SignedSlotJournal =
                serde_json::from_slice(&raw).map_err(|e| UpdaterError::SlotTransitionInvalid {
                    detail: format!("corrupt signed slot journal: {e}"),
                })?;
            if envelope.key_id != journal_signer.key_id() {
                return Err(UpdaterError::SlotTransitionInvalid {
                    detail: "slot journal key_id does not match pinned journal signer".to_string(),
                });
            }
            let canonical =
                serde_json::to_vec(&envelope.journal).map_err(|e| UpdaterError::Io {
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
            return Ok(Self {
                state_root,
                journal_path,
                journal_signer,
                journal: envelope.journal,
            });
        }

        let version = initial_version.into();
        let slot_state = SlotState::initial(
            version.clone(),
            initial_generation,
            initial_sha.clone(),
            initial_generation,
        );
        let journal = SlotJournal {
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
            pending_commit_issued_wall_s: None,
            pending_commit_until_wall_s: None,
            consecutive_crashes: 0,
            pack_channels: BTreeMap::new(),
        };
        let mgr = Self {
            state_root,
            journal_path,
            journal_signer,
            journal,
        };
        mgr.persist()?;
        Ok(mgr)
    }

    /// Stage, verify state transitions, write atomically, and activate a TUF/DSSE-verified binary.
    pub fn activate_verified_binary(
        &mut self,
        verified: &VerifiedUpdateArtifact,
        new_security_floor: Option<u64>,
        now_wall_unix_s: i64,
    ) -> Result<SlotSnapshot, UpdaterError> {
        if verified.pack_kind() != PackKind::Binary {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "verified artifact is not a PackKind::Binary".to_string(),
            });
        }
        if self.journal.authority != UpdateAuthority::SelfManaged {
            return Err(UpdaterError::AuthorityDisallowed {
                authority: format!("{:?}", self.journal.authority),
                action: "activate_verified_binary".to_string(),
            });
        }

        let candidate_bytes = verified.verified_bytes();
        let byte_len = u64::try_from(candidate_bytes.len()).unwrap_or(u64::MAX);
        if byte_len > MAX_SLOT_BINARY_BYTES {
            return Err(UpdaterError::BudgetExceeded {
                channel: verified.channel().to_string(),
                actual_bytes: byte_len,
                max_bytes: MAX_SLOT_BINARY_BYTES,
            });
        }

        let generation = verified.generation();
        if generation < self.journal.security_floor {
            return Err(UpdaterError::SecurityFloorViolation {
                current_floor: self.journal.security_floor,
                candidate_generation: generation,
            });
        }

        let version = verified.version().to_string();
        let sha256 = verified.sha256().to_string();

        let staged = self
            .journal
            .slot_state
            .clone()
            .stage_candidate(version.clone(), generation, sha256.clone())
            .map_err(|e| UpdaterError::SlotTransitionInvalid {
                detail: e.to_string(),
            })?;
        let marked = staged
            .mark_verified()
            .map_err(|e| UpdaterError::SlotTransitionInvalid {
                detail: e.to_string(),
            })?;
        let activated = marked
            .activate()
            .map_err(|e| UpdaterError::SlotTransitionInvalid {
                detail: e.to_string(),
            })?;

        let next_slot = inactive_slot(self.journal.active.slot);
        let staged_path = self.slot_binary_path(next_slot);
        atomic_write_bytes(&staged_path, candidate_bytes)?;

        let prev = self.journal.active.clone();
        let next_snapshot = SlotSnapshot {
            slot: next_slot,
            version,
            generation,
            sha256,
        };
        if let Some(floor) = new_security_floor
            && floor > self.journal.security_floor
        {
            self.journal.security_floor = floor.min(generation);
        }

        self.journal.slot_state = activated;
        self.journal.previous = Some(prev);
        self.journal.active = next_snapshot.clone();
        self.journal.pending_commit_issued_wall_s = Some(now_wall_unix_s);
        self.journal.pending_commit_until_wall_s =
            Some(now_wall_unix_s.saturating_add(COMMIT_STABILIZATION_WINDOW_S));
        self.journal.consecutive_crashes = 0;
        self.persist()?;
        Ok(next_snapshot)
    }

    /// Record a startup crash during the bounded `[issued..=deadline]` stabilization window.
    pub fn record_startup_crash(
        &mut self,
        reason: &str,
        now_wall_unix_s: i64,
    ) -> Result<Option<SlotSnapshot>, UpdaterError> {
        let within_window = matches!(
            (
                self.journal.pending_commit_issued_wall_s,
                self.journal.pending_commit_until_wall_s,
            ),
            (Some(issued), Some(deadline)) if (issued..=deadline).contains(&now_wall_unix_s)
        );
        if !within_window {
            return Ok(None);
        }

        self.journal.consecutive_crashes = self.journal.consecutive_crashes.saturating_add(1);
        if self.journal.consecutive_crashes < MAX_CONSECUTIVE_BOOT_CRASHES {
            self.persist()?;
            return Ok(None);
        }

        let prev =
            self.journal
                .previous
                .clone()
                .ok_or_else(|| UpdaterError::SlotTransitionInvalid {
                    detail: "cannot auto-revert: no previous slot snapshot exists".to_string(),
                })?;
        if prev.generation < self.journal.security_floor {
            return Err(UpdaterError::SecurityFloorViolation {
                current_floor: self.journal.security_floor,
                candidate_generation: prev.generation,
            });
        }

        let prev_path = self.slot_binary_path(prev.slot);
        let prev_bytes = read_bounded_bytes(&prev_path, MAX_SLOT_BINARY_BYTES)?;
        let actual_sha = canonical_sha256(&prev_bytes);
        if actual_sha != prev.sha256 {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: format!(
                    "rollback target {:?} binary digest mismatch (expected {}, got {actual_sha})",
                    prev.slot, prev.sha256
                ),
            });
        }

        let rolled = self
            .journal
            .slot_state
            .clone()
            .rollback_to_previous(
                prev.version.clone(),
                prev.generation,
                prev.sha256.clone(),
                reason.to_string(),
            )
            .map_err(|e| UpdaterError::SlotTransitionInvalid {
                detail: e.to_string(),
            })?;

        self.journal.slot_state = rolled;
        self.journal.active = prev.clone();
        self.journal.previous = None;
        self.journal.pending_commit_issued_wall_s = None;
        self.journal.pending_commit_until_wall_s = None;
        self.journal.consecutive_crashes = 0;
        self.persist()?;
        Ok(Some(prev))
    }

    /// Commit the pending slot once health checks stabilize.
    pub fn confirm_stable_commit(&mut self) -> Result<(), UpdaterError> {
        self.journal.pending_commit_issued_wall_s = None;
        self.journal.pending_commit_until_wall_s = None;
        self.journal.consecutive_crashes = 0;
        self.persist()
    }

    /// Stage and swap a verified content/policy pack channel, preserving its previous LKG.
    pub fn activate_verified_pack(
        &mut self,
        verified: &VerifiedUpdateArtifact,
    ) -> Result<PackChannelRecord, UpdaterError> {
        if verified.pack_kind() == PackKind::Binary {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "PackKind::Binary must use activate_verified_binary".to_string(),
            });
        }
        if self.journal.authority == UpdateAuthority::Image {
            return Err(UpdaterError::AuthorityDisallowed {
                authority: "Image".to_string(),
                action: format!("activate_verified_pack({})", verified.channel()),
            });
        }
        let channel = verified.channel();
        validate_channel_name(channel)?;

        let generation = verified.generation();
        let sha256 = verified.sha256().to_string();
        let version = verified.version().to_string();
        let next_record = if let Some(existing) = self.journal.pack_channels.get(channel) {
            if generation <= existing.active_generation {
                return Err(UpdaterError::StaleOrRollback {
                    detail: format!(
                        "pack channel '{channel}' generation {generation} <= active {}",
                        existing.active_generation
                    ),
                });
            }
            PackChannelRecord {
                channel: channel.to_string(),
                active_version: version,
                active_generation: generation,
                active_sha256: sha256,
                lkg_version: Some(existing.active_version.clone()),
                lkg_generation: Some(existing.active_generation),
                lkg_sha256: Some(existing.active_sha256.clone()),
            }
        } else {
            PackChannelRecord {
                channel: channel.to_string(),
                active_version: version,
                active_generation: generation,
                active_sha256: sha256,
                lkg_version: None,
                lkg_generation: None,
                lkg_sha256: None,
            }
        };

        let pack_file = self.state_root.join(format!("pack_{channel}.json"));
        atomic_write_bytes(&pack_file, verified.verified_bytes())?;
        self.journal
            .pack_channels
            .insert(channel.to_string(), next_record.clone());
        self.persist()?;
        Ok(next_record)
    }

    /// Detect external binary modification under `Managed` mode without modifying slots.
    pub fn verify_managed_binary_integrity(
        &self,
        binary_path: &Path,
        expected_sha256: &str,
    ) -> Result<BinaryIntegrityOutcome, UpdaterError> {
        ensure_not_symlink(binary_path)?;
        let bytes = read_bounded_bytes(binary_path, MAX_SLOT_BINARY_BYTES)?;
        let actual = canonical_sha256(&bytes);
        if actual == expected_sha256 {
            Ok(BinaryIntegrityOutcome::MatchesExpected)
        } else {
            Ok(BinaryIntegrityOutcome::ExternalBinaryTamperDetected {
                expected_sha256: expected_sha256.to_string(),
                actual_sha256: actual,
            })
        }
    }

    /// Read current active slot snapshot.
    #[must_use]
    pub const fn active_slot(&self) -> &SlotSnapshot {
        &self.journal.active
    }

    /// Current enforced binary security floor generation.
    #[must_use]
    pub const fn security_floor(&self) -> u64 {
        self.journal.security_floor
    }

    /// File path backing a given slot binary.
    #[must_use]
    pub fn slot_binary_path(&self, slot: UpdateSlot) -> PathBuf {
        let name = match slot {
            UpdateSlot::SlotA => "slot_a.bin",
            UpdateSlot::SlotB => "slot_b.bin",
        };
        self.state_root.join(name)
    }

    fn persist(&self) -> Result<(), UpdaterError> {
        let canonical = serde_json::to_vec(&self.journal).map_err(|e| UpdaterError::Io {
            detail: format!("failed to canonicalize slot journal: {e}"),
        })?;
        let signature_b64 = self
            .journal_signer
            .sign_bytes("grdr-slot-journal-v1", &canonical);
        let envelope = SignedSlotJournal {
            journal: self.journal.clone(),
            key_id: self.journal_signer.key_id().to_string(),
            signature_b64,
        };
        let encoded = serde_json::to_vec_pretty(&envelope).map_err(|e| UpdaterError::Io {
            detail: format!("failed to encode slot journal: {e}"),
        })?;
        atomic_write_bytes(&self.journal_path, &encoded)
    }
}

const fn inactive_slot(active: UpdateSlot) -> UpdateSlot {
    match active {
        UpdateSlot::SlotA => UpdateSlot::SlotB,
        UpdateSlot::SlotB => UpdateSlot::SlotA,
    }
}

fn validate_channel_name(channel: &str) -> Result<(), UpdaterError> {
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

fn validate_sha256_hex(sha256: &str) -> Result<(), UpdaterError> {
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
