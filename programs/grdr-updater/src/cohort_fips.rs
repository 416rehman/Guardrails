// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Cohort rollout gating, native agent-config revert journal, FIPS 140-3 startup
//! self-tests, PQ dual-root verification, and offer-time handshake negotiation.

use std::path::Path;

use grdr_compat::{
    CompatMatrix, NegotiationOutcome, NegotiationRequest, SemVer, negotiate_compatibility,
};
use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_os_clock::Clock;
use grdr_update::{
    CohortGateVerdict, CohortTelemetrySnapshot, DsseEnvelope, DualSignedPayload,
    FailClosedPqBackend, FipsMode, FipsSelfTestReport, HandshakeContractOffer, HandshakePolicy,
    HandshakeResolution, HostOsProfile, PqPolicyActivation, PqPublicKeyRecord, PqVerifierBackend,
    RollbackDirective, RollbackTargetKind, RolloutCoordinator, RootMetadata, SignedMetadata,
    TufRole, canonical_sha256, evaluate_offer_handshake, run_fips_startup_self_test,
    verify_dual_signed_payload,
};
use grdr_wire::messages::{UpdaterCommandFrame, UpdaterEventFrame};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::compat_config::{parse_capability_name, resolve_worker_compat_matrix};
use crate::error::UpdaterError;
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir, path_exists_nofollow, read_bounded_bytes,
};

const AGENT_CFG_JOURNAL_FILE: &str = "agent-config.journal.json";
const AGENT_CFG_JOURNAL_DOMAIN: &str = "grdr.updater.agentcfg.v1";
const MAX_JOURNAL_BYTES: u64 = 1_048_576;
const MAX_FAILED_CONFIG_HISTORY: usize = 32;

/// Recorded failed/reverted agent-config generation + digest preventing infinite crash-revert loops.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedAgentConfigRecord {
    pub generation: u64,
    pub sha256: String,
    pub reason: String,
}

/// Persisted native agent-config activation state supporting zero-egress revert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfigJournal {
    pub active_generation: u64,
    pub active_sha256: String,
    pub previous_generation: Option<u64>,
    pub previous_sha256: Option<String>,
    pub revert_count: u64,
    pub last_reason: Option<String>,
    #[serde(default)]
    pub failed_configs: Vec<FailedAgentConfigRecord>,
}

/// Signed envelope protecting `agent-config.journal.json` against tampering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAgentConfigJournal {
    pub journal: AgentConfigJournal,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct HandshakeCheckDirective {
    offer: HandshakeContractOffer,
    policy: HandshakePolicy,
    #[serde(default)]
    compat_matrix_dsse: Option<DsseEnvelope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct FipsSelfTestDirective {
    fips_mode: FipsMode,
}

/// Detect the active runtime OS profile for FIPS 140-3 readiness checks.
#[must_use]
pub fn detect_host_os_profile() -> HostOsProfile {
    match std::env::consts::OS {
        "linux" => HostOsProfile::Linux,
        "windows" => HostOsProfile::Windows,
        "macos" => HostOsProfile::MacOs,
        _ => HostOsProfile::Other,
    }
}

/// Execute FIPS 140-3 startup known-answer self-tests before releasing signing operations.
pub fn enforce_fips_startup(
    os: HostOsProfile,
    fips_mode: FipsMode,
    now: Timestamp,
) -> Result<FipsSelfTestReport, UpdaterError> {
    run_fips_startup_self_test(os, fips_mode, now).map_err(|e| {
        if matches!(e, grdr_update::UpdateError::SecurityFloorViolation { .. }) {
            UpdaterError::SecurityFloorViolation {
                current_floor: 1,
                candidate_generation: 0,
            }
        } else {
            UpdaterError::TufVerification {
                detail: e.to_string(),
            }
        }
    })
}

/// Verify dual classical + post-quantum `ml-dsa-65` metadata failing closed unless a real PQ backend verifies.
pub fn verify_dual_root_payload<T: Serialize>(
    root: &RootMetadata,
    role: TufRole,
    pq_activation: PqPolicyActivation,
    pq_keys: &[PqPublicKeyRecord],
    payload: &DualSignedPayload<T>,
) -> Result<(), UpdaterError> {
    verify_dual_root_payload_with_backend(
        root,
        role,
        pq_activation,
        pq_keys,
        payload,
        &FailClosedPqBackend,
    )
}

/// Verify dual classical + post-quantum `ml-dsa-65` metadata using an explicit FIPS 204 backend.
pub fn verify_dual_root_payload_with_backend<T: Serialize>(
    root: &RootMetadata,
    role: TufRole,
    pq_activation: PqPolicyActivation,
    pq_keys: &[PqPublicKeyRecord],
    payload: &DualSignedPayload<T>,
    backend: &dyn PqVerifierBackend,
) -> Result<(), UpdaterError> {
    verify_dual_signed_payload(root, role, pq_activation, pq_keys, payload, backend).map_err(|e| {
        UpdaterError::TufVerification {
            detail: e.to_string(),
        }
    })
}

/// Evaluate control-plane `BootstrapService/Hello` offer handshake against matrix & skew window.
pub fn negotiate_offer_with_matrix(
    offer: &HandshakeContractOffer,
    policy: &HandshakePolicy,
    compat: &CompatMatrix,
    now: Timestamp,
) -> Result<HandshakeResolution, UpdaterError> {
    let resolution = evaluate_offer_handshake(offer, policy, now);
    if matches!(resolution, HandshakeResolution::UpgradeRequired { .. }) {
        return Ok(resolution);
    }
    let client_ver = SemVer::new(
        offer.version_major,
        offer.version_minor,
        offer.version_patch,
    );
    let advertised_capabilities = offer
        .capabilities
        .iter()
        .filter_map(|cap| parse_capability_name(cap))
        .collect();
    let req = NegotiationRequest {
        component: offer.component.clone(),
        client_version: client_ver,
        advertised_capabilities,
    };
    match negotiate_compatibility(compat, &req) {
        NegotiationOutcome::Compatible { .. } => Ok(resolution),
        NegotiationOutcome::CompatibleWithWarnings { warnings, .. } => {
            Ok(HandshakeResolution::UpgradeRequired {
                code: "GRDR-COMPAT-0003".into(),
                reason: warnings.join("; "),
                minimum_version: format!(
                    "{}.{}.0",
                    policy.server_major,
                    policy.server_minor.saturating_sub(policy.max_minor_behind)
                ),
                retry_after_ms: policy.retry_base_ms,
                not_before: now,
                guidance: "advertise required protocol capabilities for active CompatMatrix".into(),
            })
        }
        NegotiationOutcome::Incompatible { code, reason } => {
            Ok(HandshakeResolution::UpgradeRequired {
                code,
                reason,
                minimum_version: format!(
                    "{}.{}.0",
                    policy.server_major,
                    policy.server_minor.saturating_sub(policy.max_minor_behind)
                ),
                retry_after_ms: policy.retry_base_ms,
                not_before: now,
                guidance: "align component version with CompatMatrix".into(),
            })
        }
    }
}

/// Record a verified `agent-config` generation promotion into the signed rollback journal.
pub fn commit_agent_config_generation(
    state_root: &Path,
    signer: &SigningKeypair,
    generation: u64,
    payload_bytes: &[u8],
) -> Result<AgentConfigJournal, UpdaterError> {
    ensure_safe_dir(state_root)?;
    let journal_path = state_root.join(AGENT_CFG_JOURNAL_FILE);
    let sha = canonical_sha256(payload_bytes);
    let journal = if path_exists_nofollow(&journal_path)? {
        let mut prev = load_verified_agent_config_journal(&journal_path, signer)?;
        if prev
            .failed_configs
            .iter()
            .any(|f| f.sha256 == sha || (f.generation == generation && f.sha256 == sha))
        {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "agent-config generation {generation} ({sha}) was previously reverted and cannot re-apply"
                ),
            });
        }
        if generation <= prev.active_generation {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "agent-config generation {generation} <= active {}",
                    prev.active_generation
                ),
            });
        }
        prev.previous_generation = Some(prev.active_generation);
        prev.previous_sha256 = Some(prev.active_sha256);
        prev.active_generation = generation;
        prev.active_sha256 = sha;
        prev
    } else {
        AgentConfigJournal {
            active_generation: generation,
            active_sha256: sha,
            previous_generation: None,
            previous_sha256: None,
            revert_count: 0,
            last_reason: None,
            failed_configs: Vec::new(),
        }
    };
    persist_agent_config_journal(&journal_path, signer, &journal)?;
    Ok(journal)
}

/// Evaluate cohort rollout gates and immediately revert `agent-config` journal on breach.
pub fn evaluate_cohort_and_maybe_revert(
    state_root: &Path,
    signer: &SigningKeypair,
    coordinator: &mut RolloutCoordinator,
    telemetry: &CohortTelemetrySnapshot,
    revert_target: RollbackTargetKind,
    now: Timestamp,
) -> Result<CohortGateVerdict, UpdaterError> {
    let verdict = coordinator
        .evaluate_cohort(telemetry, revert_target, now)
        .map_err(|e| UpdaterError::StaleOrRollback {
            detail: e.to_string(),
        })?;
    if let Some(directive) = &verdict.rollback
        && directive.target == RollbackTargetKind::AgentConfigJournal
    {
        revert_agent_config_journal(state_root, signer, directive)?;
    }
    Ok(verdict)
}

/// Revert `agent-config.journal.json` to the prior known-good generation on startup failure.
pub fn revert_agent_config_journal(
    state_root: &Path,
    signer: &SigningKeypair,
    directive: &RollbackDirective,
) -> Result<AgentConfigJournal, UpdaterError> {
    let journal_path = state_root.join(AGENT_CFG_JOURNAL_FILE);
    let mut journal = load_verified_agent_config_journal(&journal_path, signer)?;
    let Some(prev_gen) = journal.previous_generation else {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: "no prior agent-config generation recorded to revert".into(),
        });
    };
    let Some(prev_sha) = journal.previous_sha256.clone() else {
        return Err(UpdaterError::SlotTransitionInvalid {
            detail: "missing previous agent-config digest in journal".into(),
        });
    };
    if prev_gen > directive.revert_to_generation {
        return Err(UpdaterError::StaleOrRollback {
            detail: format!(
                "journal previous generation {prev_gen} > directive {}",
                directive.revert_to_generation
            ),
        });
    }
    let reason = format!("{:?}", directive.reason);
    journal.failed_configs.push(FailedAgentConfigRecord {
        generation: journal.active_generation,
        sha256: journal.active_sha256.clone(),
        reason: reason.clone(),
    });
    if journal.failed_configs.len() > MAX_FAILED_CONFIG_HISTORY {
        let drop_n = journal
            .failed_configs
            .len()
            .saturating_sub(MAX_FAILED_CONFIG_HISTORY);
        journal.failed_configs.drain(..drop_n);
    }
    journal.active_generation = prev_gen;
    journal.active_sha256 = prev_sha;
    journal.previous_generation = None;
    journal.previous_sha256 = None;
    journal.revert_count = journal.revert_count.saturating_add(1);
    journal.last_reason = Some(reason);
    persist_agent_config_journal(&journal_path, signer, &journal)?;
    Ok(journal)
}

/// Read signed `RootMetadata` from a JSON slice.
pub fn parse_signed_root_json(raw: &[u8]) -> Result<SignedMetadata<RootMetadata>, UpdaterError> {
    serde_json::from_slice(raw).map_err(|e| UpdaterError::TufVerification {
        detail: format!("invalid root metadata JSON: {e}"),
    })
}

/// Execute FIPS startup self-test for worker command dispatch using typed JSON payload.
pub(crate) fn worker_fips_self_test(
    cmd: &UpdaterCommandFrame,
    active_slot: &str,
    active_version: &str,
    security_floor: u64,
    clock: &dyn Clock,
) -> Result<UpdaterEventFrame, UpdaterError> {
    let directive: FipsSelfTestDirective = if cmd.payload.is_empty() {
        FipsSelfTestDirective {
            fips_mode: FipsMode::Disabled,
        }
    } else {
        serde_json::from_slice(&cmd.payload).map_err(|e| UpdaterError::TufVerification {
            detail: format!("invalid fips_self_test directive JSON: {e}"),
        })?
    };
    let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
        detail: e.to_string(),
    })?;
    let report = enforce_fips_startup(detect_host_os_profile(), directive.fips_mode, now)?;
    let detail = serde_json::to_string(&report).map_err(|e| UpdaterError::Io {
        detail: format!("failed to serialize FIPS report: {e}"),
    })?;
    Ok(UpdaterEventFrame {
        command_id: cmd.command_id.clone(),
        active_slot: active_slot.to_owned(),
        active_version: active_version.to_owned(),
        security_floor,
        handover_active: false,
        ok: true,
        error_code: String::new(),
        detail,
    })
}

/// Execute offer-time handshake check for worker command dispatch.
pub(crate) fn worker_verify_handshake(
    cmd: &UpdaterCommandFrame,
    state_root: &Path,
    project_root: Option<&SignedMetadata<RootMetadata>>,
    active_slot: &str,
    active_version: &str,
    security_floor: u64,
    clock: &dyn Clock,
) -> Result<UpdaterEventFrame, UpdaterError> {
    let dir: HandshakeCheckDirective =
        serde_json::from_slice(&cmd.payload).map_err(|e| UpdaterError::CompatibilityRejected {
            component: "handshake".into(),
            code: "GRDR-COMPAT-0003".into(),
            reason: format!("invalid handshake directive JSON: {e}"),
        })?;
    let now = clock.now_wall().map_err(|e| UpdaterError::ClockFailed {
        detail: e.to_string(),
    })?;
    let compat = resolve_worker_compat_matrix(
        Some(state_root),
        project_root,
        dir.compat_matrix_dsse.as_ref(),
        now,
    )?;
    let resolution = negotiate_offer_with_matrix(&dir.offer, &dir.policy, &compat, now)?;
    let admitted = matches!(resolution, HandshakeResolution::Admitted { .. });
    let detail = serde_json::to_string(&resolution).map_err(|e| UpdaterError::Io {
        detail: format!("failed to serialize handshake resolution: {e}"),
    })?;
    if !admitted {
        return Err(UpdaterError::CompatibilityRejected {
            component: dir.offer.component,
            code: "GRDR-COMPAT-0003".into(),
            reason: detail,
        });
    }
    Ok(UpdaterEventFrame {
        command_id: cmd.command_id.clone(),
        active_slot: active_slot.to_owned(),
        active_version: active_version.to_owned(),
        security_floor,
        handover_active: false,
        ok: true,
        error_code: String::new(),
        detail,
    })
}

fn load_verified_agent_config_journal(
    path: &Path,
    signer: &SigningKeypair,
) -> Result<AgentConfigJournal, UpdaterError> {
    let raw = read_bounded_bytes(path, MAX_JOURNAL_BYTES)?;
    let signed: SignedAgentConfigJournal =
        serde_json::from_slice(&raw).map_err(|e| UpdaterError::TufVerification {
            detail: format!("corrupt agent-config journal JSON: {e}"),
        })?;
    if signed.signer_key_id != signer.key_id() {
        return Err(UpdaterError::TufVerification {
            detail: "agent-config journal signer key_id mismatch".into(),
        });
    }
    let payload =
        serde_json::to_vec(&signed.journal).map_err(|e| UpdaterError::TufVerification {
            detail: format!("failed to canonicalize agent-config journal: {e}"),
        })?;
    verify_bytes(
        &signer.public_key_b64(),
        AGENT_CFG_JOURNAL_DOMAIN,
        &payload,
        &signed.signature,
    )
    .map_err(|_| UpdaterError::TufVerification {
        detail: "agent-config journal signature verification failed".into(),
    })?;
    Ok(signed.journal)
}

fn persist_agent_config_journal(
    path: &Path,
    signer: &SigningKeypair,
    journal: &AgentConfigJournal,
) -> Result<(), UpdaterError> {
    let payload = serde_json::to_vec(journal).map_err(|e| UpdaterError::TufVerification {
        detail: format!("failed to encode agent-config journal: {e}"),
    })?;
    let sig = signer.sign_bytes(AGENT_CFG_JOURNAL_DOMAIN, &payload);
    let signed = SignedAgentConfigJournal {
        journal: journal.clone(),
        signer_key_id: signer.key_id().to_owned(),
        signature: sig,
    };
    let encoded = serde_json::to_vec_pretty(&signed).map_err(|e| UpdaterError::Io {
        detail: format!("failed to serialize signed agent-config journal: {e}"),
    })?;
    atomic_write_bytes(path, &encoded)
}
