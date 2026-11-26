// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Inherited-channel daemon worker state machine for `grdr-updater` (`docs/design/11`, `docs/design/24`).
//! Coordinates signed A/B slot state, `security_floor` enforcement, P7 pack purity,
//! persistent pinned `DualRootVerifier`, and `<= 2s` atomic handover markers.

use std::path::PathBuf;

use grdr_compat::CompatMatrix;
use grdr_crypto::load_or_create_keypair;
use grdr_os_clock::{Clock, SystemClock};
use grdr_update::{
    DsseEnvelope, DsseLimits, FreshnessStatement, PackKind, RootMetadata, SignedMetadata,
    SnapshotMetadata, TargetsMetadata, TimestampMetadata, TufRootKind, UpdateSlot,
};
use grdr_wire::messages::{UpdaterCommandFrame, UpdaterEventFrame};
use serde::Deserialize;

use crate::error::UpdaterError;
use crate::fs_safe::{confine_path_under_root, ensure_safe_dir, path_exists_nofollow};
use crate::handover::{DEFAULT_HANDOVER_WINDOW_MS, HandoverCoordinator, boot_mono_ms};
use crate::p7_delta::enforce_p7_json_purity;
use crate::slots::{SlotActivationManager, UpdateAuthority};
use crate::verify::{DualRootVerifier, StagedUpdateBundle};

pub use crate::worker_ipc::{run_stdio_daemon_worker, run_stdio_daemon_worker_with_config};

const INITIAL_SLOT_A_IMAGE: &[u8] = b"grdr-initial-slot-a";

/// Startup configuration provisioned by `grdr-daemon` or CLI for an `UpdaterWorkerState`.
#[derive(Clone, Debug)]
pub struct UpdaterWorkerConfig {
    pub authority: UpdateAuthority,
    pub project_root: Option<SignedMetadata<RootMetadata>>,
    pub deployment_root: Option<SignedMetadata<RootMetadata>>,
}

#[derive(Debug, Deserialize)]
struct HandoverDirective {
    slot: String,
    binary_path: PathBuf,
    expected_sha256: String,
    #[serde(default = "default_handover_ms")]
    window_ms: u64,
}

#[derive(Debug, Deserialize)]
struct RotateRootDirective {
    root_kind: TufRootKind,
    next_root: SignedMetadata<RootMetadata>,
}

#[derive(Debug, Deserialize)]
struct VerifyAndActivateDirective {
    channel: String,
    target_path: String,
    component_name: String,
    snapshot_published_unix_s: i64,
    artifact_bytes: Vec<u8>,
    timestamp: SignedMetadata<TimestampMetadata>,
    snapshot: SignedMetadata<SnapshotMetadata>,
    targets: SignedMetadata<TargetsMetadata>,
    binaries_targets: Option<SignedMetadata<TargetsMetadata>>,
    freshness: Option<SignedMetadata<FreshnessStatement>>,
    dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Default, Deserialize)]
struct SignedBinaryStatement {
    #[serde(default)]
    security_floor: Option<u64>,
}

/// Stateful worker managing verified slot transitions, handover markers, and persistent TUF roots.
pub struct UpdaterWorkerState {
    state_root: PathBuf,
    slots: SlotActivationManager,
    handover: HandoverCoordinator,
    verifier: Option<DualRootVerifier>,
}

impl Default for UpdaterWorkerConfig {
    fn default() -> Self {
        Self {
            authority: UpdateAuthority::SelfManaged,
            project_root: None,
            deployment_root: None,
        }
    }
}

const fn default_handover_ms() -> u64 {
    DEFAULT_HANDOVER_WINDOW_MS
}

impl UpdaterWorkerState {
    /// Open worker with default `SelfManaged` authority and unpinned initial roots.
    pub fn open(state_root: PathBuf) -> Result<Self, UpdaterError> {
        let clock = SystemClock::new();
        Self::open_with_config(state_root, UpdaterWorkerConfig::default(), &clock)
    }

    /// Open worker with pinned initial TUF roots and strict anti-reset journal loading.
    pub fn open_with_config(
        state_root: PathBuf,
        config: UpdaterWorkerConfig,
        clock: &dyn Clock,
    ) -> Result<Self, UpdaterError> {
        ensure_safe_dir(&state_root)?;
        let signer = load_or_create_keypair(&state_root.join("slot-journal.key")).map_err(|e| {
            UpdaterError::Io {
                detail: format!("load updater slot journal key: {e}"),
            }
        })?;
        let journal_path = state_root.join("slots.journal.json");
        let slots = if path_exists_nofollow(&journal_path)? {
            SlotActivationManager::open_existing(
                state_root.clone(),
                config.authority,
                signer.clone(),
            )?
        } else if path_exists_nofollow(&state_root.join("slot_a.bin"))?
            || path_exists_nofollow(&state_root.join("slot_b.bin"))?
        {
            return Err(UpdaterError::SlotTransitionInvalid {
                detail: "slot binary exists without signed slots.journal.json".to_string(),
            });
        } else {
            SlotActivationManager::init_new(
                state_root.clone(),
                config.authority,
                signer.clone(),
                "0.1.0",
                1,
                INITIAL_SLOT_A_IMAGE,
            )?
        };
        let verifier = match config.project_root {
            Some(proj) => Some(DualRootVerifier::open_or_init(
                &state_root,
                &signer,
                proj,
                config.deployment_root,
                clock,
            )?),
            None => None,
        };
        let handover = HandoverCoordinator::new(&state_root);
        Ok(Self {
            state_root,
            slots,
            handover,
            verifier,
        })
    }

    #[must_use]
    pub const fn security_floor(&self) -> u64 {
        self.slots.security_floor()
    }

    /// Dispatch one `UpdaterCommandFrame` without failing open or rewriting pinned trust roots from payload.
    pub fn handle_command(
        &mut self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> UpdaterEventFrame {
        let res = match cmd.action.as_str() {
            "query_slots" => self.query_slots_event(&cmd.command_id, clock),
            "prepare_handover" => self.handle_prepare_handover(cmd, clock),
            "confirm_commit" => self.handle_confirm_commit(cmd, clock),
            "record_crash" => self.handle_record_crash(cmd, clock),
            "rotate_root" => self.handle_rotate_root(cmd, clock),
            "verify_and_activate" => self.handle_verify_and_activate(cmd, clock),
            "verify_pack_p7" => self.handle_verify_p7(cmd),
            other => Err(UpdaterError::SlotTransitionInvalid {
                detail: format!("unsupported updater action `{other}`"),
            }),
        };

        match res {
            Ok(ev) => ev,
            Err(err) => self.error_event(&cmd.command_id, &err),
        }
    }

    fn query_slots_event(
        &self,
        command_id: &str,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let active = self.slots.active_slot();
        let handover_active = self.handover.peek_active(clock)?.is_some();
        Ok(UpdaterEventFrame {
            command_id: command_id.to_string(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active,
            ok: true,
            error_code: String::new(),
            detail: format!("generation:{}", active.generation),
        })
    }

    fn handle_prepare_handover(
        &self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let dir: HandoverDirective =
            serde_json::from_slice(&cmd.payload).map_err(|e| UpdaterError::HandoverInvalid {
                detail: format!("invalid handover directive JSON: {e}"),
            })?;
        let slot = parse_slot(&dir.slot)?;
        let active = self.slots.active_slot();
        if slot != active.slot {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover target slot {:?} does not match active slot {:?}",
                    slot, active.slot
                ),
            });
        }
        if dir.expected_sha256 != active.sha256 {
            return Err(UpdaterError::HandoverInvalid {
                detail: "handover expected_sha256 does not match active slot digest".to_string(),
            });
        }
        let canonical_root =
            std::fs::canonicalize(&self.state_root).map_err(|e| UpdaterError::Io {
                detail: format!("failed to canonicalize state root: {e}"),
            })?;
        let requested_path = confine_path_under_root(&canonical_root, &dir.binary_path)?;
        let expected_path =
            std::fs::canonicalize(self.slots.slot_binary_path(slot)).map_err(|e| {
                UpdaterError::HandoverInvalid {
                    detail: format!("active slot binary unreadable: {e}"),
                }
            })?;
        if requested_path != expected_path {
            return Err(UpdaterError::HandoverInvalid {
                detail: format!(
                    "handover binary_path {} must match active slot binary {}",
                    requested_path.display(),
                    expected_path.display()
                ),
            });
        }

        let marker = self.handover.prepare_handover(
            slot,
            &requested_path,
            &dir.expected_sha256,
            dir.window_ms,
            clock,
        )?;
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: true,
            ok: true,
            error_code: String::new(),
            detail: format!("expires_mono_ms:{}", marker.expires_mono_ms),
        })
    }

    fn handle_confirm_commit(
        &mut self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let now_s = clock
            .now_wall()
            .map_err(|e| UpdaterError::ClockFailed {
                detail: e.to_string(),
            })?
            .as_second();
        let now_mono_ms = boot_mono_ms(clock)?;
        self.slots.confirm_stable_commit(now_s, now_mono_ms)?;
        let active = self.slots.active_slot();
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: true,
            error_code: String::new(),
            detail: "committed".to_string(),
        })
    }

    fn handle_record_crash(
        &mut self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let now_s = clock
            .now_wall()
            .map_err(|e| UpdaterError::ClockFailed {
                detail: e.to_string(),
            })?
            .as_second();
        let now_mono_ms = boot_mono_ms(clock)?;
        let rolled_to =
            self.slots
                .record_startup_crash("daemon-crash-report", now_s, now_mono_ms)?;
        let active = self.slots.active_slot();
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: true,
            error_code: String::new(),
            detail: match rolled_to {
                Some(prev) => format!("rolled-back-to:{}", slot_label(prev.slot)),
                None => "crash-recorded".to_string(),
            },
        })
    }

    fn handle_rotate_root(
        &mut self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let verifier = self
            .verifier
            .as_mut()
            .ok_or_else(|| UpdaterError::TufVerification {
                detail: "refusing root rotation without pinned initial TUF roots".to_string(),
            })?;
        let dir: RotateRootDirective =
            serde_json::from_slice(&cmd.payload).map_err(|e| UpdaterError::TufVerification {
                detail: format!("invalid rotate_root JSON: {e}"),
            })?;
        let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
            detail: e.to_string(),
        })?;
        verifier.rotate_root(dir.root_kind, dir.next_root, now)?;
        let active = self.slots.active_slot();
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: true,
            error_code: String::new(),
            detail: "root-rotated".to_string(),
        })
    }

    fn handle_verify_and_activate(
        &mut self,
        cmd: &UpdaterCommandFrame,
        clock: &dyn Clock,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        let verifier = self
            .verifier
            .as_mut()
            .ok_or_else(|| UpdaterError::TufVerification {
                detail: "refusing update verification without pinned TUF roots".to_string(),
            })?;
        let directive: VerifyAndActivateDirective =
            serde_json::from_slice(&cmd.payload).map_err(|e| UpdaterError::TufVerification {
                detail: format!("invalid verify_and_activate JSON: {e}"),
            })?;
        let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
            detail: e.to_string(),
        })?;
        let trusted_compat = CompatMatrix::default_v1();
        let verified = verifier.verify_bundle(
            &StagedUpdateBundle {
                root_kind: TufRootKind::Project,
                pack_kind: PackKind::Binary,
                channel: &directive.channel,
                target_path: &directive.target_path,
                component_name: &directive.component_name,
                snapshot_published_unix_s: directive.snapshot_published_unix_s,
                artifact_bytes: &directive.artifact_bytes,
                timestamp: &directive.timestamp,
                snapshot: &directive.snapshot,
                targets: &directive.targets,
                binaries_targets: directive.binaries_targets.as_ref(),
                freshness: directive.freshness.as_ref(),
                dsse_envelope: &directive.dsse_envelope,
                compat_matrix: &trusted_compat,
            },
            now,
        )?;
        let decoded = directive
            .dsse_envelope
            .decode_payload_with_limits(&DsseLimits::default())
            .map_err(|e| UpdaterError::TufVerification {
                detail: format!("failed to decode verified DSSE statement: {e}"),
            })?;
        let signed_stmt: SignedBinaryStatement =
            serde_json::from_slice(&decoded).map_err(|e| UpdaterError::TufVerification {
                detail: format!("invalid DSSE SignedBinaryStatement JSON: {e}"),
            })?;
        let effective_floor = signed_stmt.security_floor.filter(|&f| f > 0);
        let now_mono_ms = boot_mono_ms(clock)?;
        let snap = self.slots.activate_verified_binary(
            &verified,
            effective_floor,
            now.as_second(),
            now_mono_ms,
        )?;
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(snap.slot).to_string(),
            active_version: snap.version,
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: true,
            error_code: String::new(),
            detail: format!("activated:{}", snap.sha256),
        })
    }

    fn handle_verify_p7(
        &self,
        cmd: &UpdaterCommandFrame,
    ) -> Result<UpdaterEventFrame, UpdaterError> {
        enforce_p7_json_purity("policy_core", &cmd.payload)?;
        let active = self.slots.active_slot();
        Ok(UpdaterEventFrame {
            command_id: cmd.command_id.clone(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: true,
            error_code: String::new(),
            detail: "p7-pure".to_string(),
        })
    }

    fn error_event(&self, command_id: &str, err: &UpdaterError) -> UpdaterEventFrame {
        let active = self.slots.active_slot();
        let _ = &self.state_root;
        UpdaterEventFrame {
            command_id: command_id.to_string(),
            active_slot: slot_label(active.slot).to_string(),
            active_version: active.version.clone(),
            security_floor: self.slots.security_floor(),
            handover_active: false,
            ok: false,
            error_code: err.code().to_string(),
            detail: err.to_string(),
        }
    }
}

fn parse_slot(raw: &str) -> Result<UpdateSlot, UpdaterError> {
    match raw.to_ascii_lowercase().as_str() {
        "a" | "slot_a" | "slota" => Ok(UpdateSlot::SlotA),
        "b" | "slot_b" | "slotb" => Ok(UpdateSlot::SlotB),
        _ => Err(UpdaterError::HandoverInvalid {
            detail: format!("invalid slot `{raw}` (expected slot_a or slot_b)"),
        }),
    }
}

const fn slot_label(slot: UpdateSlot) -> &'static str {
    match slot {
        UpdateSlot::SlotA => "slot_a",
        UpdateSlot::SlotB => "slot_b",
    }
}
