// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Cryptographic receipt signing (`SigningKeypairExt::sign_receipt`), floor non-weakening guard,
//! `LocalStore` snapshot/WAL persistence, and signed `audit.checkpoint` persistence.

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_fastpath::FastVerdict;
use grdr_model::{
    ActionClass, ControlPoint, DecisionReceipt, KillSwitchState, Mode, SigningKeypairExt, Verdict,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_store_local::checkpoint::{
    AuditCheckpointPayload, LaneCheckpointHead, save_audit_checkpoint,
};
use grdr_store_local::daemon_codecs::{encode_grant_json, encode_pack_json, encode_receipt_json};
use grdr_store_local::spool_io::SpoolLane;
use grdr_store_local::{PersistedDaemonSnapshot, SNAPSHOT_SCHEMA_VERSION};
use grdr_wire::messages::{
    BundleLoadFrame, DecideRequestFrame, DecideVerdictFrame, EngineAuthoredRecord,
    EngineResultFrame, WireActionClass, WireControlPoint, WireVerdict,
};
use jiff::Timestamp;

use crate::dir_guard::{p8_redact_target, scrub_p8_text, session_recorder_key};
use crate::grant_ops::verify_matching_active_grant;
use crate::state::{CallerPrincipal, DaemonData, DaemonLifecycle};

const MAX_ENGINE_AUTHORED_RECORDS: usize = 16;
const MAX_ENGINE_RECORD_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_RECENT_RECEIPTS: usize = 128;

pub(crate) struct EngineOutcome {
    pub(crate) verdict: WireVerdict,
    pub(crate) rule_id: String,
    pub(crate) reason: String,
    pub(crate) labels: Vec<String>,
    pub(crate) floor_fallback: bool,
    pub(crate) degraded_reason: String,
    pub(crate) consumed_grant_id: Option<String>,
    pub(crate) authored_records: Vec<EngineAuthoredRecord>,
}

pub(crate) fn persist_snapshot(guard: &mut DaemonData) -> Result<(), String> {
    let snap = PersistedDaemonSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        device_id: guard.device_id.clone(),
        hostname: guard.hostname.clone(),
        packs: guard.packs.clone(),
        grants: guard.grants.clone(),
        revoked_grant_ids: guard.revoked_grant_ids.iter().cloned().collect(),
        trusted_keys: guard.trusted_keys.clone(),
        kill_switch: guard.kill_switch.clone(),
        attempts: Vec::new(),
        receipts: guard.recent_receipts.clone(),
        pending_attempts: Vec::new(),
        pending_receipts: Vec::new(),
    };
    guard
        .local_store
        .save_snapshot(&snap)
        .map_err(|e| e.to_string())
}

#[allow(clippy::type_complexity)]
pub(crate) fn restore_daemon_snapshot(
    snap: Option<PersistedDaemonSnapshot>,
    derived_id: String,
) -> (
    String,
    Vec<grdr_model::PolicyPack>,
    Vec<grdr_model::Grant>,
    std::collections::VecDeque<String>,
    Vec<grdr_model::TrustedKeyInfo>,
    KillSwitchState,
    Vec<DecisionReceipt>,
) {
    let (device_id, packs, mut grants, raw_revoked, trusted_keys, kill_switch, recent_receipts) =
        match snap {
            Some(s) => (
                if s.device_id.trim().is_empty() {
                    derived_id
                } else {
                    s.device_id
                },
                s.packs,
                s.grants,
                s.revoked_grant_ids,
                s.trusted_keys,
                s.kill_switch,
                s.receipts,
            ),
            None => (
                derived_id,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                KillSwitchState::Inactive,
                Vec::new(),
            ),
        };
    let revoked_grant_ids = crate::grant_ops::restore_revoked_grant_ids(&mut grants, &raw_revoked);
    (
        device_id,
        packs,
        grants,
        revoked_grant_ids,
        trusted_keys,
        kill_switch,
        recent_receipts,
    )
}

pub(crate) fn build_bundle_frame(guard: &DaemonData) -> Result<BundleLoadFrame, String> {
    let mut pack_blobs = Vec::with_capacity(guard.packs.len());
    for pack in &guard.packs {
        pack_blobs.push(encode_pack_json(pack).map_err(|e| e.to_string())?);
    }
    let mut grant_blobs = Vec::with_capacity(guard.grants.len());
    for grant in &guard.grants {
        grant_blobs.push(encode_grant_json(grant).map_err(|e| e.to_string())?);
    }
    let (kill_switch_active, kill_switch_reason) = match &guard.kill_switch {
        KillSwitchState::Inactive => (false, String::new()),
        KillSwitchState::Frozen { reason, .. } | KillSwitchState::Killed { reason, .. } => {
            (true, reason.clone())
        }
    };
    Ok(BundleLoadFrame {
        epoch: guard.epoch,
        pack_blobs,
        grant_blobs,
        kill_switch_active,
        kill_switch_reason,
    })
}

pub(crate) fn kill_switch_block_reason(
    kill_switch: &KillSwitchState,
    session_id: &str,
    device_id: &str,
    now: Timestamp,
) -> Option<String> {
    if !kill_switch.is_active_for(session_id, device_id, now) {
        return None;
    }
    Some(match kill_switch {
        KillSwitchState::Frozen { reason, .. } | KillSwitchState::Killed { reason, .. } => {
            if reason.trim().is_empty() {
                "kill switch active".to_string()
            } else {
                reason.clone()
            }
        }
        KillSwitchState::Inactive => "kill switch active".to_string(),
    })
}

pub(crate) fn persist_checkpoint(
    guard: &mut DaemonData,
    now: Timestamp,
    recorder_head_seq: u64,
) -> Result<(), String> {
    let mut lanes = BTreeMap::new();
    for lane in SpoolLane::all() {
        if let Some((head_seq, head_hash, durable_through_seq)) = guard.spool.head_state(lane) {
            lanes.insert(
                lane,
                LaneCheckpointHead {
                    head_seq,
                    head_hash_hex: grdr_crypto::encode_lower_hex(&head_hash),
                    durable_through_seq,
                },
            );
        }
    }
    let payload = AuditCheckpointPayload {
        schema_version: 1,
        updated_at_unix_s: now.as_second(),
        gap_count: u64::try_from(guard.spool.gap_records().len()).unwrap_or(0),
        lanes,
        device_id: guard.device_id.clone(),
        epoch: guard.epoch,
        recorder_head_seq,
    };
    let ckpt_path = guard.state_dir.join("audit.checkpoint");
    save_audit_checkpoint(&ckpt_path, &payload, &guard.signing_key).map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_signed_receipt(
    key: &SigningKeypair,
    device_id: &str,
    receipt_id: &str,
    attempt_id: &str,
    req: &DecideRequestFrame,
    verdict: WireVerdict,
    rule_id: &str,
    redacted_reason: &str,
    grant_id: Option<String>,
    now: Timestamp,
) -> Result<DecisionReceipt, String> {
    let model_verdict = match verdict {
        WireVerdict::Allow => Verdict::Allow,
        WireVerdict::Ask => Verdict::StepUp,
        WireVerdict::Block | WireVerdict::Unspecified => Verdict::Deny,
    };
    let redacted_target = p8_redact_target(&req.target);
    let digest = sha256_hex(format!("{receipt_id}:{attempt_id}:{redacted_target}").as_bytes());
    let mut receipt = DecisionReceipt {
        receipt_id: receipt_id.to_string(),
        attempt_id: attempt_id.to_string(),
        session_id: req.session_id.clone(),
        device_id: device_id.to_string(),
        agent_name: req.agent.clone(),
        action_class: WireActionClass::from_wire_i32(req.action_class)
            .and_then(WireActionClass::to_model)
            .unwrap_or(ActionClass::Exec),
        control_point: WireControlPoint::from_wire_i32(req.control_point)
            .and_then(WireControlPoint::to_model)
            .unwrap_or(ControlPoint::Hook),
        target: redacted_target,
        verdict: model_verdict,
        would_be: None,
        rule_id: (!rule_id.is_empty()).then(|| rule_id.to_string()),
        pack_id: Some("floor-or-engine".to_string()),
        mode_applied: Some(Mode::Block),
        grant_id,
        reason: redacted_reason.to_string(),
        next_step: String::new(),
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    };
    key.sign_receipt(&mut receipt)
        .map_err(|e| format!("sign receipt: {e}"))?;
    Ok(receipt)
}

pub(crate) fn now_wall_checked() -> Result<Timestamp, String> {
    SystemClock::new()
        .now_wall()
        .map_err(|e| format!("system wall clock unavailable: {e}"))
}

pub(crate) fn resolve_outcome(
    guard: &mut DaemonData,
    req: &DecideRequestFrame,
    kill_reason: Option<String>,
    engine_outcome: Result<EngineResultFrame, String>,
    now: Timestamp,
) -> EngineOutcome {
    if let Some(reason) = kill_reason {
        return EngineOutcome {
            verdict: WireVerdict::Block,
            rule_id: "system.kill-switch".to_string(),
            reason,
            labels: Vec::new(),
            floor_fallback: false,
            degraded_reason: "kill-switch".to_string(),
            consumed_grant_id: None,
            authored_records: Vec::new(),
        };
    }
    match engine_outcome {
        Ok(res) => {
            guard.lifecycle = DaemonLifecycle::Healthy;
            guard.degraded_reason.clear();
            let claimed_gid = res.consumed_grant_id.trim();
            let verified_gid = verify_matching_active_grant(guard, claimed_gid, req, now);
            let forged_grant_claim = !claimed_gid.is_empty() && verified_gid.is_none();
            let mut verdict = match WireVerdict::try_from(res.verdict) {
                Ok(WireVerdict::Unspecified) | Err(_) => WireVerdict::Block,
                Ok(valid) => valid,
            };
            let mut rule_id = res.rule_id;
            let mut reason = scrub_p8_text(&res.reason);
            if forged_grant_claim {
                verdict = WireVerdict::Block;
                rule_id = "system.invalid-grant-claim".to_string();
                reason = "rejected unverified or mismatched engine grant claim".to_string();
            }
            // Enforce floor non-weakening (D-02) whenever no verified grant authorized relaxation.
            if verified_gid.is_none() {
                let (floor_v, floor_rule_id, floor_msg) = guard.floor.evaluate_overload_fallback(
                    req.action_class,
                    &req.agent,
                    &req.target,
                    &req.command_line,
                );
                match floor_v {
                    FastVerdict::Deny => {
                        verdict = WireVerdict::Block;
                        rule_id = floor_rule_id;
                        reason = format!("floor non-weakening override ({floor_msg})");
                    }
                    FastVerdict::StepUp if verdict != WireVerdict::Block => {
                        verdict = WireVerdict::Ask;
                        rule_id = floor_rule_id;
                        reason = format!("floor non-weakening override ({floor_msg})");
                    }
                    FastVerdict::StepUp | FastVerdict::Allow => {}
                }
            }
            EngineOutcome {
                verdict,
                rule_id,
                reason,
                labels: res.labels,
                floor_fallback: false,
                degraded_reason: String::new(),
                consumed_grant_id: verified_gid,
                authored_records: res.authored_records,
            }
        }
        Err(err_reason) => {
            let (fast_v, rule_id, msg) = guard.floor.evaluate_overload_fallback(
                req.action_class,
                &req.agent,
                &req.target,
                &req.command_line,
            );
            let verdict = match fast_v {
                FastVerdict::Allow => WireVerdict::Allow,
                FastVerdict::StepUp => WireVerdict::Ask,
                FastVerdict::Deny => WireVerdict::Block,
            };
            guard.degraded_reason = "overload".to_string();
            guard.lifecycle = DaemonLifecycle::Degraded;
            EngineOutcome {
                verdict,
                rule_id,
                reason: format!("{msg} ({})", scrub_p8_text(&err_reason)),
                labels: Vec::new(),
                floor_fallback: true,
                degraded_reason: "overload".to_string(),
                consumed_grant_id: None,
                authored_records: Vec::new(),
            }
        }
    }
}

pub(crate) fn record_decision_audit(
    guard: &mut DaemonData,
    attempt_id: &str,
    req: &DecideRequestFrame,
    out: EngineOutcome,
    now: Timestamp,
    principal: CallerPrincipal,
) -> Result<DecideVerdictFrame, String> {
    if out.authored_records.len() > MAX_ENGINE_AUTHORED_RECORDS {
        return Err("GRDR-DAEM-0002: engine authored record count exceeded cap".to_string());
    }
    let mut mapped_records = Vec::with_capacity(out.authored_records.len());
    for rec in &out.authored_records {
        if rec.record_type == "unsigned_receipt" {
            continue;
        }
        if rec.payload.len() > MAX_ENGINE_RECORD_PAYLOAD_BYTES {
            return Err(
                "GRDR-DAEM-0002: engine authored record payload exceeded limit".to_string(),
            );
        }
        let lane = match rec.lane.as_str() {
            "decision" => SpoolLane::Decision,
            "spine" => SpoolLane::Spine,
            "evidence" => SpoolLane::Evidence,
            "bulk" => SpoolLane::Bulk,
            _ => {
                return Err(format!(
                    "GRDR-DAEM-0002: unknown engine authored record lane '{}'",
                    rec.lane
                ));
            }
        };
        mapped_records.push((lane, rec.payload.as_slice()));
    }

    let receipt_id = format!("rcp-{}", uuid::Uuid::now_v7().simple());
    let redacted_reason = scrub_p8_text(&out.reason);
    let signed = build_signed_receipt(
        &guard.signing_key,
        &guard.device_id,
        &receipt_id,
        attempt_id,
        req,
        out.verdict,
        &out.rule_id,
        &redacted_reason,
        out.consumed_grant_id,
        now,
    )?;
    let receipt_bytes = encode_receipt_json(&signed).map_err(|e| e.to_string())?;
    let must_fsync = out.verdict != WireVerdict::Allow;
    let sp_out = guard
        .spool
        .append(SpoolLane::Decision, &receipt_bytes, must_fsync)
        .map_err(|e| format!("append decision spool: {e}"))?;

    let hashed_session = session_recorder_key(&guard.device_id, &req.session_id);
    let recorder_seq = match guard.recorder.append_event(
        now.as_second(),
        "decision",
        "receipt",
        &hashed_session,
        &receipt_bytes,
    ) {
        Ok(id) => {
            let seq = u64::try_from(id).unwrap_or(guard.last_recorder_head_seq);
            guard.last_recorder_head_seq = seq;
            seq
        }
        Err(err) => {
            guard.persistence_errors = guard.persistence_errors.saturating_add(1);
            tracing::warn!(error = %err, "flight recorder append failed; preserving prior seq");
            guard.last_recorder_head_seq
        }
    };

    for (lane, payload) in mapped_records {
        guard
            .spool
            .append(lane, payload, false)
            .map_err(|e| format!("append authored record spool: {e}"))?;
    }

    persist_checkpoint(guard, now, recorder_seq)?;
    guard.receipts_total = guard.receipts_total.saturating_add(1);
    guard.recent_receipts.push(signed.clone());
    guard.receipt_owners.push((receipt_id.clone(), principal));
    if guard.recent_receipts.len() > MAX_RECENT_RECEIPTS {
        let _ = guard.recent_receipts.remove(0);
    }
    if guard.receipt_owners.len() > MAX_RECENT_RECEIPTS {
        let _ = guard.receipt_owners.remove(0);
    }
    guard
        .local_store
        .append_receipt_wal(&signed)
        .map_err(|e| format!("append receipt WAL: {e}"))?;

    Ok(DecideVerdictFrame {
        request_id: req.request_id.clone(),
        verdict: out.verdict as i32,
        receipt_id,
        rule_id: out.rule_id,
        reason: redacted_reason,
        degraded_reason: out.degraded_reason,
        floor_fallback: out.floor_fallback,
        audit_fsynced: sp_out.fsynced,
        labels: out.labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir_guard::default_principal;
    use crate::grant_ops::validate_and_insert_grant;
    use crate::state::DaemonState;
    use grdr_model::{ApprovalGrade, Grant, GrantScope, InstallProfile};

    #[test]
    fn rejects_forged_and_mismatched_engine_grant_claims_and_enforces_floor() {
        let base = crate::dir_guard::private_ephemeral_base_dir().join(format!(
            ".grdr-daemon-grant-test-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let data_dir = base.join("data");
        let state_dir = base.join("state");
        let state = DaemonState::initialize(data_dir, state_dir, InstallProfile::User)
            .expect("init daemon state");
        let now = now_wall_checked().expect("wall clock");

        let mut guard = state.inner.lock().expect("lock daemon state");
        let mut valid_grant = Grant {
            grant_id: "gr-valid-ssh-read".to_string(),
            rule_id: "essentials.credential-stores".to_string(),
            session_id: "sess-authorized".to_string(),
            device_id: guard.device_id.clone(),
            action_class: ActionClass::FileRead,
            target_pattern: "/home/dev/.ssh/known_hosts".to_string(),
            scope: GrantScope::Once,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: None,
            remaining_uses: Some(1),
            note: "allow single authorized ssh read".to_string(),
            key_id: None,
            signature: None,
        };
        let signer = guard.signing_key.clone();
        signer.sign_grant(&mut valid_grant).expect("sign grant");
        validate_and_insert_grant(&mut guard, valid_grant, now).expect("insert valid grant");

        let dangerous_exec = DecideRequestFrame {
            request_id: "req-forged".to_string(),
            hook_seq: 1,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-attacker".to_string(),
            target: "bash".to_string(),
            summary: "rm -rf /".to_string(),
            command_line: "rm -rf /".to_string(),
            cwd: "/tmp".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 10,
            tool_name: "Bash".to_string(),
            raw_payload: Vec::new(),
        };

        // 1. Nonexistent grant_id claimed by engine must fail closed and enforce floor.
        let forged_out = resolve_outcome(
            &mut guard,
            &dangerous_exec,
            None,
            Ok(EngineResultFrame {
                request_id: "req-forged".to_string(),
                attempt_id: "att-forged".to_string(),
                verdict: WireVerdict::Allow as i32,
                rule_id: "custom.allow".to_string(),
                reason: "forged".to_string(),
                labels: Vec::new(),
                obligations: Vec::new(),
                authored_records: Vec::new(),
                session_step: 1,
                consumed_grant_id: "gr-nonexistent".to_string(),
            }),
            now,
        );
        assert_eq!(forged_out.verdict, WireVerdict::Block);
        assert!(forged_out.consumed_grant_id.is_none());

        // 2. Active grant from another session/action/target claimed by engine must not bypass floor
        // or appear on the signed DecisionReceipt or be consumed.
        let mismatched_out = resolve_outcome(
            &mut guard,
            &dangerous_exec,
            None,
            Ok(EngineResultFrame {
                request_id: "req-mismatched".to_string(),
                attempt_id: "att-mismatched".to_string(),
                verdict: WireVerdict::Allow as i32,
                rule_id: "custom.allow".to_string(),
                reason: "mismatched".to_string(),
                labels: Vec::new(),
                obligations: Vec::new(),
                authored_records: Vec::new(),
                session_step: 1,
                consumed_grant_id: "gr-valid-ssh-read".to_string(),
            }),
            now,
        );
        assert_eq!(mismatched_out.verdict, WireVerdict::Block);
        assert!(mismatched_out.consumed_grant_id.is_none());
        assert_eq!(guard.grants.len(), 1);

        let verdict_frame = record_decision_audit(
            &mut guard,
            "att-mismatched",
            &dangerous_exec,
            mismatched_out,
            now,
            default_principal(),
        )
        .expect("record decision audit");
        assert_eq!(verdict_frame.verdict, WireVerdict::Block as i32);
        let latest = guard.recent_receipts.last().expect("stored receipt");
        assert!(latest.grant_id.is_none());

        // 3. Matching authorized session/action/target grant claim succeeds cleanly.
        let authorized_req = DecideRequestFrame {
            request_id: "req-ok".to_string(),
            hook_seq: 2,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::FileRead as i32,
            session_id: "sess-authorized".to_string(),
            target: "/home/dev/.ssh/known_hosts".to_string(),
            summary: "read".to_string(),
            command_line: String::new(),
            cwd: "/tmp".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 20,
            tool_name: "Read".to_string(),
            raw_payload: Vec::new(),
        };
        let ok_out = resolve_outcome(
            &mut guard,
            &authorized_req,
            None,
            Ok(EngineResultFrame {
                request_id: "req-ok".to_string(),
                attempt_id: "att-ok".to_string(),
                verdict: WireVerdict::Allow as i32,
                rule_id: "essentials.credential-stores".to_string(),
                reason: "approved".to_string(),
                labels: Vec::new(),
                obligations: Vec::new(),
                authored_records: Vec::new(),
                session_step: 2,
                consumed_grant_id: "gr-valid-ssh-read".to_string(),
            }),
            now,
        );
        assert_eq!(ok_out.verdict, WireVerdict::Allow);
        assert_eq!(
            ok_out.consumed_grant_id.as_deref(),
            Some("gr-valid-ssh-read")
        );

        drop(guard);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn protected_state_dir_0755_and_once_plus_revoked_grant_anti_replay_across_restart() {
        let base = crate::dir_guard::private_ephemeral_base_dir().join(format!(
            ".grdr-daemon-restart-test-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let data_dir = base.join("data");
        let state_dir = base.join("state");
        let state = DaemonState::initialize(
            data_dir.clone(),
            state_dir.clone(),
            InstallProfile::Protected,
        )
        .expect("init protected daemon state");
        let now = now_wall_checked().expect("wall clock");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let st_mode = std::fs::metadata(&state_dir)
                .expect("stat state_dir")
                .permissions()
                .mode()
                & 0o777;
            let dt_mode = std::fs::metadata(&data_dir)
                .expect("stat data_dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(st_mode, 0o755, "state_dir must preserve 0o755 for hooks");
            assert_eq!(dt_mode, 0o700, "data_dir must remain 0o700");
        }
        assert!(data_dir.join("recorder.db").is_file());
        assert!(state_dir.join("floor.bin").is_file());

        let (signer, dev_id) = {
            let g = state.inner.lock().expect("lock state");
            (g.signing_key.clone(), g.device_id.clone())
        };
        let mut once_grant = Grant {
            grant_id: "gr-once-restart".to_string(),
            rule_id: "essentials.credential-stores".to_string(),
            session_id: "sess-restart".to_string(),
            device_id: dev_id.clone(),
            action_class: ActionClass::FileRead,
            target_pattern: "/home/dev/.ssh/id_ed25519".to_string(),
            scope: GrantScope::Once,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: None,
            remaining_uses: Some(1),
            note: "single use grant".to_string(),
            key_id: None,
            signature: None,
        };
        signer.sign_grant(&mut once_grant).expect("sign once");

        let mut rev_grant = once_grant.clone();
        rev_grant.grant_id = "gr-rev-restart".to_string();
        rev_grant.scope = GrantScope::Session;
        rev_grant.remaining_uses = Some(5);
        signer.sign_grant(&mut rev_grant).expect("sign rev");

        state
            .issue_grant(once_grant.clone())
            .expect("issue once grant");
        state
            .issue_grant(rev_grant.clone())
            .expect("issue rev grant");
        state
            .revoke_grant(&rev_grant.grant_id)
            .expect("revoke grant");

        let read_req = DecideRequestFrame {
            request_id: "req-consume-once".to_string(),
            hook_seq: 1,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::FileRead as i32,
            session_id: "sess-restart".to_string(),
            target: "/home/dev/.ssh/id_ed25519".to_string(),
            summary: "read".to_string(),
            command_line: String::new(),
            cwd: "/tmp".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 15,
            tool_name: "Read".to_string(),
            raw_payload: Vec::new(),
        };
        {
            let mut guard = state.inner.lock().expect("lock for consume");
            let outcome = resolve_outcome(
                &mut guard,
                &read_req,
                None,
                Ok(EngineResultFrame {
                    request_id: "req-consume-once".to_string(),
                    attempt_id: "att-consume-once".to_string(),
                    verdict: WireVerdict::Allow as i32,
                    rule_id: "essentials.credential-stores".to_string(),
                    reason: "grant matched".to_string(),
                    labels: Vec::new(),
                    obligations: Vec::new(),
                    authored_records: Vec::new(),
                    session_step: 1,
                    consumed_grant_id: "gr-once-restart".to_string(),
                }),
                now,
            );
            assert_eq!(outcome.verdict, WireVerdict::Allow);
            assert_eq!(
                outcome.consumed_grant_id.as_deref(),
                Some("gr-once-restart")
            );
            let d = &mut *guard;
            assert!(crate::grant_ops::consume_grant(
                &mut d.grants,
                &mut d.revoked_grant_ids,
                "gr-once-restart"
            ));
            record_decision_audit(
                &mut guard,
                "att-consume-once",
                &read_req,
                outcome,
                now,
                default_principal(),
            )
            .expect("record decision audit and checkpoint");
            persist_snapshot(&mut guard).expect("persist consumed once snapshot");
        }
        assert!(state_dir.join("audit.checkpoint").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let st_mode = std::fs::metadata(&state_dir)
                .expect("stat state_dir after checkpoint")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(st_mode, 0o755, "audit.checkpoint must not chmod state_dir");
        }
        drop(state);

        let restarted = DaemonState::initialize(
            data_dir.clone(),
            state_dir.clone(),
            InstallProfile::Protected,
        )
        .expect("reinit daemon state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let st_mode = std::fs::metadata(&state_dir)
                .expect("stat restarted state_dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(st_mode, 0o755);
        }
        assert!(restarted.issue_grant(once_grant).is_err());
        assert!(restarted.issue_grant(rev_grant).is_err());
        {
            let g = restarted.inner.lock().expect("lock restarted");
            assert!(g.revoked_grant_ids.iter().any(|r| r == "gr-once-restart"));
            assert!(g.revoked_grant_ids.iter().any(|r| r == "gr-rev-restart"));
        }

        drop(restarted);
        let _ = std::fs::remove_dir_all(&base);
    }
}
