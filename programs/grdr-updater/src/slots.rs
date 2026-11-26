// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Signed A/B slot activation, LKG pack channels, `security_floor` enforcement,
//! update authority isolation (`self`/`managed`/`image`), and crash auto-revert (`D-11`).

use std::path::{Path, PathBuf};

use grdr_crypto::SigningKeypair;
use grdr_update::{PackKind, UpdateSlot, canonical_sha256};

use crate::error::UpdaterError;
use crate::fs_safe::{
    atomic_write_bytes, ensure_not_symlink, ensure_safe_dir, path_exists_nofollow,
    read_bounded_bytes,
};
use crate::p7_delta::max_bytes_for_pack;
use crate::slot_journal::{
    initial_slot_journal, load_verified_journal, persist_signed_journal, sync_slot_state_floor,
    validate_channel_name, validate_sha256_hex,
};
use crate::verify::VerifiedUpdateArtifact;

pub use crate::slot_journal::{
    BinaryIntegrityOutcome, PackChannelRecord, PendingCommitWindow, SignedSlotJournal, SlotJournal,
    SlotSnapshot, UpdateAuthority,
};

/// Startup failures during 30-minute stabilization window before automatic rollback.
pub const MAX_CONSECUTIVE_BOOT_CRASHES: u32 = 3;
/// Post-activation binary stabilization window in wall seconds (30 minutes).
pub const COMMIT_STABILIZATION_WINDOW_S: i64 = 1_800;
/// Maximum slot binary size permitted from disk (128 MiB).
const MAX_SLOT_BINARY_BYTES: u64 = 134_217_728;

/// Atomic updater controller for binary slots and pack channels.
pub struct SlotActivationManager {
    state_root: PathBuf,
    journal_path: PathBuf,
    journal_signer: SigningKeypair,
    journal: SlotJournal,
}

impl SlotActivationManager {
    /// Initialize a brand-new Slot A state root with a concrete initial binary payload.
    pub fn init_new(
        state_root: PathBuf,
        authority: UpdateAuthority,
        journal_signer: SigningKeypair,
        initial_version: impl Into<String>,
        initial_generation: u64,
        initial_bytes: &[u8],
    ) -> Result<Self, UpdaterError> {
        ensure_safe_dir(&state_root)?;
        let journal_path = state_root.join("slots.journal.json");
        if path_exists_nofollow(&journal_path)? {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "refusing init_new when slots.journal.json already exists".to_string(),
            });
        }
        let initial_sha = canonical_sha256(initial_bytes);
        let journal = initial_slot_journal(
            authority,
            initial_version.into(),
            initial_generation,
            initial_sha,
        );
        let mgr = Self {
            state_root,
            journal_path,
            journal_signer,
            journal,
        };
        atomic_write_bytes(&mgr.slot_binary_path(UpdateSlot::SlotA), initial_bytes)?;
        mgr.persist()?;
        Ok(mgr)
    }

    /// Open and verify an existing `slots.journal.json` without ever resetting `security_floor`.
    pub fn open_existing(
        state_root: PathBuf,
        authority: UpdateAuthority,
        journal_signer: SigningKeypair,
    ) -> Result<Self, UpdaterError> {
        ensure_safe_dir(&state_root)?;
        let journal_path = state_root.join("slots.journal.json");
        if !path_exists_nofollow(&journal_path)? {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "missing signed slots.journal.json".to_string(),
            });
        }
        let journal = load_verified_journal(&journal_path, authority, &journal_signer)?;
        let mgr = Self {
            state_root,
            journal_path,
            journal_signer,
            journal,
        };
        mgr.verify_active_binary_on_disk(false)?;
        Ok(mgr)
    }

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

        if path_exists_nofollow(&journal_path)? {
            let journal = load_verified_journal(&journal_path, authority, &journal_signer)?;
            if journal.security_floor < initial_generation {
                return Err(UpdaterError::SecurityFloorViolation {
                    current_floor: initial_generation,
                    candidate_generation: journal.security_floor,
                });
            }
            let mgr = Self {
                state_root,
                journal_path,
                journal_signer,
                journal,
            };
            mgr.verify_active_binary_on_disk(true)?;
            return Ok(mgr);
        }

        if path_exists_nofollow(&state_root.join("slot_a.bin"))?
            || path_exists_nofollow(&state_root.join("slot_b.bin"))?
        {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "refusing initial journal creation when slot binaries already exist"
                    .to_string(),
            });
        }

        let journal = initial_slot_journal(
            authority,
            initial_version.into(),
            initial_generation,
            initial_sha,
        );
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
        now_mono_ms: u64,
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

        let generation = verified.generation();
        if generation < self.journal.security_floor {
            return Err(UpdaterError::SecurityFloorViolation {
                current_floor: self.journal.security_floor,
                candidate_generation: generation,
            });
        }
        if let Some(floor) = new_security_floor
            && floor > generation
        {
            return Err(UpdaterError::SecurityFloorViolation {
                current_floor: floor,
                candidate_generation: generation,
            });
        }

        if !matches!(self.journal.pending_commit, PendingCommitWindow::Idle) {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "pending unconfirmed slot activation must commit before another activation"
                    .to_string(),
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
            self.journal.security_floor = floor;
        }

        self.journal.slot_state = activated;
        sync_slot_state_floor(&mut self.journal);
        self.journal.previous = Some(prev);
        self.journal.active = next_snapshot.clone();
        self.journal.pending_commit = PendingCommitWindow::Pending {
            issued_wall_s: now_wall_unix_s,
            until_wall_s: now_wall_unix_s.saturating_add(COMMIT_STABILIZATION_WINDOW_S),
            issued_mono_ms: now_mono_ms,
        };
        self.journal.consecutive_crashes = 0;
        self.persist()?;
        Ok(next_snapshot)
    }

    /// Record a startup crash during the bounded wall + monotonic stabilization window.
    pub fn record_startup_crash(
        &mut self,
        reason: &str,
        now_wall_unix_s: i64,
        now_mono_ms: u64,
    ) -> Result<Option<SlotSnapshot>, UpdaterError> {
        let window_ms = u64::try_from(COMMIT_STABILIZATION_WINDOW_S)
            .unwrap_or(1_800)
            .saturating_mul(1_000);
        let within_window = matches!(
            self.journal.pending_commit,
            PendingCommitWindow::Pending {
                issued_wall_s,
                until_wall_s,
                issued_mono_ms,
            } if (issued_wall_s..=until_wall_s).contains(&now_wall_unix_s)
                && now_mono_ms >= issued_mono_ms
                && now_mono_ms.saturating_sub(issued_mono_ms) <= window_ms
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
        sync_slot_state_floor(&mut self.journal);
        self.journal.active = prev.clone();
        self.journal.previous = None;
        self.journal.pending_commit = PendingCommitWindow::Idle;
        self.journal.consecutive_crashes = 0;
        self.persist()?;
        Ok(Some(prev))
    }

    /// Commit the pending slot once both wall and monotonic stabilization windows have elapsed.
    pub fn confirm_stable_commit(
        &mut self,
        now_wall_unix_s: i64,
        now_mono_ms: u64,
    ) -> Result<(), UpdaterError> {
        let window_ms = u64::try_from(COMMIT_STABILIZATION_WINDOW_S)
            .unwrap_or(1_800)
            .saturating_mul(1_000);
        match self.journal.pending_commit {
            PendingCommitWindow::Idle => {
                return Err(UpdaterError::SlotTransitionInvalid {
                    detail: "no pending unconfirmed slot activation to commit".to_string(),
                });
            }
            PendingCommitWindow::Pending {
                until_wall_s,
                issued_mono_ms,
                ..
            } => {
                if now_wall_unix_s < until_wall_s {
                    return Err(UpdaterError::SlotTransitionInvalid {
                        detail: format!(
                            "stabilization window active until {until_wall_s} (now {now_wall_unix_s})"
                        ),
                    });
                }
                let elapsed_mono_ms = now_mono_ms.saturating_sub(issued_mono_ms);
                if now_mono_ms < issued_mono_ms || elapsed_mono_ms < window_ms {
                    return Err(UpdaterError::SlotTransitionInvalid {
                        detail: format!(
                            "monotonic stabilization window active ({elapsed_mono_ms}ms < {window_ms}ms)"
                        ),
                    });
                }
            }
        }
        self.journal.pending_commit = PendingCommitWindow::Idle;
        self.journal.consecutive_crashes = 0;
        self.persist()
    }

    /// Stage and swap a verified content/policy pack channel, persisting its previous LKG payload.
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
        let pack_file = self.state_root.join(format!("pack_{channel}.json"));
        let lkg_file = self.state_root.join(format!("pack_{channel}.lkg.json"));

        let next_record = if let Some(existing) = self.journal.pack_channels.get(channel) {
            if generation <= existing.active_generation {
                return Err(UpdaterError::StaleOrRollback {
                    detail: format!(
                        "pack channel '{channel}' generation {generation} <= active {}",
                        existing.active_generation
                    ),
                });
            }
            if path_exists_nofollow(&pack_file)? {
                let prev_bytes =
                    read_bounded_bytes(&pack_file, max_bytes_for_pack(verified.pack_kind()))?;
                if canonical_sha256(&prev_bytes) != existing.active_sha256 {
                    return Err(UpdaterError::SlotTransitionInvalid {
                        detail: format!(
                            "existing active pack '{channel}' digest mismatch before LKG save"
                        ),
                    });
                }
                atomic_write_bytes(&lkg_file, &prev_bytes)?;
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

    #[must_use]
    pub const fn active_slot(&self) -> &SlotSnapshot {
        &self.journal.active
    }

    #[must_use]
    pub const fn security_floor(&self) -> u64 {
        self.journal.security_floor
    }

    #[must_use]
    pub fn slot_binary_path(&self, slot: UpdateSlot) -> PathBuf {
        let name = match slot {
            UpdateSlot::SlotA => "slot_a.bin",
            UpdateSlot::SlotB => "slot_b.bin",
        };
        self.state_root.join(name)
    }

    fn verify_active_binary_on_disk(&self, allow_absent: bool) -> Result<(), UpdaterError> {
        let active_path = self.slot_binary_path(self.journal.active.slot);
        if !path_exists_nofollow(&active_path)? {
            if allow_absent {
                return Ok(());
            }
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: format!("missing active slot binary {}", active_path.display()),
            });
        }
        let bytes = read_bounded_bytes(&active_path, MAX_SLOT_BINARY_BYTES)?;
        let actual = canonical_sha256(&bytes);
        if actual != self.journal.active.sha256 {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: format!(
                    "active slot {:?} binary digest mismatch (expected {}, got {actual})",
                    self.journal.active.slot, self.journal.active.sha256
                ),
            });
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), UpdaterError> {
        persist_signed_journal(&self.journal_path, &self.journal_signer, &self.journal)
    }
}

const fn inactive_slot(active: UpdateSlot) -> UpdateSlot {
    match active {
        UpdateSlot::SlotA => UpdateSlot::SlotB,
        UpdateSlot::SlotB => UpdateSlot::SlotA,
    }
}
