// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Snapshot HMAC verification, receipt building, and note epoch parsing helpers.

use std::collections::BTreeSet;

use grdr_crypto::{constant_time_eq, domain_hmac_sha256};
use grdr_model::{
    ActionAttempt, DecisionReceipt, FindingLifecycle, FindingSeverity, GrantScope, Incident,
    KillSwitchState, Mode, Verdict,
};
use jiff::Timestamp;

use super::engine::{APPROVAL_STREAK_LIMIT, Engine, MAX_TRACKED_SESSIONS};
use super::engine_bundle::verify_grant_signature_for_bundle;
use super::engine_types::{EngineOutput, EngineSnapshot, VerifiedBundle, push_len};
use super::{PolicyError, ReceiptDigestInput, compute_receipt_digest};
use crate::analyze::classify_target;
use crate::session::SessionRuleState;

pub(crate) fn compute_snapshot_mac(snap: &EngineSnapshot, snapshot_key: &[u8; 32]) -> String {
    let payload = canonical_snapshot_bytes(snap);
    let tag = domain_hmac_sha256(snapshot_key, "grdr.engine.snapshot.v2", &payload);
    grdr_crypto::encode_lower_hex(&tag)
}

pub(crate) fn verify_snapshot_mac(snap: &EngineSnapshot, snapshot_key: &[u8; 32]) -> bool {
    if *snapshot_key == [0u8; 32] {
        return false;
    }
    let expected = compute_snapshot_mac(snap, snapshot_key);
    constant_time_eq(expected.as_bytes(), snap.snapshot_mac.as_bytes())
}

fn canonical_snapshot_bytes(snap: &EngineSnapshot) -> Vec<u8> {
    let mut buf = String::new();
    push_len(&mut buf, &snap.bundle_hash);
    push_len(&mut buf, &snap.effective_hash);
    buf.push_str(&format!("{};", snap.session_state_seq));
    match &snap.kill_switch {
        KillSwitchState::Inactive => push_len(&mut buf, "inactive"),
        KillSwitchState::Frozen {
            scope,
            target_id,
            reason,
            issued_at,
            expires_at,
        } => {
            push_len(&mut buf, "frozen");
            push_len(&mut buf, &format!("{scope:?}"));
            push_len(&mut buf, target_id);
            push_len(&mut buf, reason);
            buf.push_str(&format!(
                "{}:{};",
                issued_at.as_nanosecond(),
                expires_at.as_nanosecond(),
            ));
        }
        KillSwitchState::Killed {
            scope,
            target_id,
            reason,
            issued_at,
        } => {
            push_len(&mut buf, "killed");
            push_len(&mut buf, &format!("{scope:?}"));
            push_len(&mut buf, target_id);
            push_len(&mut buf, reason);
            buf.push_str(&format!("{};", issued_at.as_nanosecond()));
        }
    }
    buf.push_str(&format!("G{};", snap.grants.len()));
    for g in &snap.grants {
        push_len(&mut buf, &g.grant_id);
        push_len(&mut buf, &g.rule_id);
        push_len(&mut buf, &g.session_id);
        push_len(&mut buf, &g.device_id);
        push_len(&mut buf, &g.target_pattern);
        push_len(&mut buf, &g.note);
        push_len(&mut buf, g.key_id.as_deref().unwrap_or(""));
        push_len(&mut buf, g.signature.as_deref().unwrap_or(""));
        buf.push_str(&format!(
            "{:?}:{:?}:{:?}:{}:{:?}:{:?};",
            g.scope,
            g.action_class,
            g.grade,
            g.granted_at.as_nanosecond(),
            g.expires_at.map(|t| t.as_nanosecond()),
            g.remaining_uses,
        ));
    }
    buf.push_str(&format!("GE{};", snap.grant_label_epochs.len()));
    for (gid, ep) in &snap.grant_label_epochs {
        push_len(&mut buf, gid);
        buf.push_str(&format!("{ep};"));
    }
    buf.push_str(&format!("SE{};", snap.session_label_epochs.len()));
    for (sid, ep) in &snap.session_label_epochs {
        push_len(&mut buf, sid);
        buf.push_str(&format!("{ep};"));
    }
    buf.push_str(&format!("LT{};", snap.session_last_taint_at.len()));
    for (sid, ts) in &snap.session_last_taint_at {
        push_len(&mut buf, sid);
        buf.push_str(&format!("{};", ts.as_nanosecond()));
    }
    buf.push_str(&format!("SO{};", snap.spent_once_grants.len()));
    for (gid, ts) in &snap.spent_once_grants {
        push_len(&mut buf, gid);
        buf.push_str(&format!("{};", ts.as_nanosecond()));
    }
    buf.push_str(&format!("AS{};", snap.approval_streaks.len()));
    for (sid, st) in &snap.approval_streaks {
        push_len(&mut buf, sid);
        buf.push_str(&format!("{st};"));
    }
    buf.push_str(&format!("FR{};", snap.frozen_sessions.len()));
    for sid in &snap.frozen_sessions {
        push_len(&mut buf, sid);
    }
    buf.push_str(&format!("SS{};", snap.sessions.len()));
    for s in &snap.sessions {
        push_len(&mut buf, &s.session_id);
        buf.push_str(&format!(
            "{}:{}:{}:{}:{};",
            s.labels.len(),
            s.denial_count,
            s.step_up_count,
            s.event_seq,
            s.approval_streak,
        ));
        for lbl in &s.labels {
            push_len(&mut buf, lbl.as_str());
        }
    }
    buf.into_bytes()
}

#[allow(
    clippy::too_many_arguments,
    reason = "receipt builder maps decision metadata fields into signed DecisionReceipt"
)]
pub(crate) fn build_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    would_be: Option<Verdict>,
    rule_id: Option<String>,
    pack_id: Option<String>,
    mode_applied: Option<Mode>,
    grant_id: Option<String>,
    reason: String,
    next_step: String,
    now: Timestamp,
) -> DecisionReceipt {
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict,
        rule_id: rule_id.as_deref(),
        decided_at: now,
    });
    let short_id: String = digest.chars().take(32).collect();
    DecisionReceipt {
        receipt_id: format!("rcp_{short_id}"),
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be,
        rule_id,
        pack_id,
        mode_applied,
        grant_id,
        reason,
        next_step,
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

pub(crate) fn parse_note_epoch(note: &str) -> Result<Option<u64>, PolicyError> {
    let Some(idx) = note.find("[epoch:") else {
        return Ok(None);
    };
    let tail = note.get(idx.saturating_add(7)..).unwrap_or("");
    let Some(end) = tail.find(']') else {
        return Err(PolicyError::ValidationFailed {
            rule_id: "grant".into(),
            detail: "malformed [epoch:N] marker in grant note".into(),
        });
    };
    let raw_num = tail.get(..end).unwrap_or("").trim();
    if raw_num.is_empty() || !raw_num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyError::ValidationFailed {
            rule_id: "grant".into(),
            detail: format!("invalid [epoch:{raw_num}] marker in grant note"),
        });
    }
    raw_num
        .parse::<u64>()
        .map(Some)
        .map_err(|e| PolicyError::ValidationFailed {
            rule_id: "grant".into(),
            detail: format!("invalid [epoch:{raw_num}] marker: {e}"),
        })
}

pub(crate) fn validate_snapshot_envelope(
    bundle: &VerifiedBundle,
    snapshot: &EngineSnapshot,
    snapshot_key: &[u8; 32],
    max_grants: usize,
    max_sessions: usize,
    max_tombstones: usize,
) -> Result<(), PolicyError> {
    if *snapshot_key == [0u8; 32] {
        return Err(PolicyError::SnapshotCorrupt {
            detail: "snapshot_key must not be all zeros".into(),
        });
    }
    if bundle.bundle_hash != snapshot.bundle_hash {
        return Err(PolicyError::SnapshotCorrupt {
            detail: format!(
                "bundle hash mismatch: expected {}, got {}",
                bundle.bundle_hash, snapshot.bundle_hash
            ),
        });
    }
    if !verify_snapshot_mac(snapshot, snapshot_key) {
        return Err(PolicyError::SnapshotCorrupt {
            detail: "snapshot authentication tag mismatch".into(),
        });
    }
    if snapshot.grants.len() > max_grants
        || snapshot.sessions.len() > max_sessions
        || snapshot.spent_once_grants.len() > max_tombstones
        || snapshot.grant_label_epochs.len() > max_grants.saturating_mul(2)
        || snapshot.session_label_epochs.len() > max_sessions
        || snapshot.session_last_taint_at.len() > max_sessions
        || snapshot.approval_streaks.len() > max_sessions
        || snapshot.frozen_sessions.len() > max_sessions
    {
        return Err(PolicyError::SnapshotCorrupt {
            detail: "snapshot collection exceeds bounded limits".into(),
        });
    }
    let mut seen_grants = BTreeSet::new();
    for grant in &snapshot.grants {
        if !seen_grants.insert(grant.grant_id.as_str()) {
            return Err(PolicyError::SnapshotCorrupt {
                detail: format!("duplicate grant_id `{}` in snapshot", grant.grant_id),
            });
        }
        verify_grant_signature_for_bundle(grant, &bundle.trusted_keys)?;
        parse_note_epoch(&grant.note).map_err(|e| PolicyError::SnapshotCorrupt {
            detail: e.to_string(),
        })?;
        if (grant.scope == GrantScope::Once && grant.remaining_uses.is_none())
            || (grant.scope == GrantScope::OneHour && grant.expires_at.is_none())
        {
            return Err(PolicyError::SnapshotCorrupt {
                detail: format!(
                    "grant `{}` missing required expiry or remaining_uses",
                    grant.grant_id
                ),
            });
        }
    }
    let mut seen_sessions = BTreeSet::new();
    for entry in &snapshot.sessions {
        if !seen_sessions.insert(entry.session_id.as_str()) {
            return Err(PolicyError::SnapshotCorrupt {
                detail: format!("duplicate session_id `{}` in snapshot", entry.session_id),
            });
        }
    }
    Ok(())
}

pub(crate) fn build_streak_incident(
    session_id: String,
    next_streak: u32,
    seq: u64,
    labels: Vec<grdr_model::SessionLabel>,
    at: Timestamp,
) -> Incident {
    Incident {
        id: format!("inc_streak_{seq}"),
        session_id: session_id.clone(),
        device_id: "local".into(),
        device_name: "local".into(),
        agent_name: String::new(),
        title: "Repeated unapproved step-up attempts frozen".into(),
        summary: format!(
            "Session {session_id} hit {next_streak} consecutive denied/unanswered prompts."
        ),
        severity: FindingSeverity::High,
        lifecycle: FindingLifecycle::Contained,
        finding_ids: Vec::new(),
        finding_count: 0,
        labels,
        first_seen: at,
        last_seen: at,
    }
}

impl Engine {
    pub(crate) fn step_approval_outcome(
        &mut self,
        session_id: String,
        approved: bool,
        at: Timestamp,
    ) -> Result<EngineOutput, PolicyError> {
        if approved {
            self.approval_streaks.remove(&session_id);
            self.session_state_seq = self.session_state_seq.saturating_add(1);
            return Ok(EngineOutput::StateAdvanced {
                session_state_seq: self.session_state_seq,
            });
        }
        let next_streak = self
            .approval_streaks
            .get(&session_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if !self.approval_streaks.contains_key(&session_id)
            && self.approval_streaks.len() >= MAX_TRACKED_SESSIONS
            && let Some(evict) = self
                .approval_streaks
                .keys()
                .find(|sid| !self.frozen_sessions.contains(*sid))
                .cloned()
                .or_else(|| self.approval_streaks.keys().next().cloned())
        {
            self.approval_streaks.remove(&evict);
        }
        self.approval_streaks
            .insert(session_id.clone(), next_streak);
        self.session_state_seq = self.session_state_seq.saturating_add(1);
        if next_streak >= APPROVAL_STREAK_LIMIT {
            if !self.frozen_sessions.contains(&session_id)
                && self.frozen_sessions.len() >= MAX_TRACKED_SESSIONS
            {
                return Err(PolicyError::ValidationFailed {
                    rule_id: "grdr.approval-streak".into(),
                    detail: "frozen session capacity exceeded".into(),
                });
            }
            self.frozen_sessions.insert(session_id.clone());
            self.verdict_cache.clear();
            let labels = self
                .sessions
                .get(&session_id)
                .map(|s| s.labels_vec())
                .unwrap_or_default();
            let incident = build_streak_incident(
                session_id.clone(),
                next_streak,
                self.session_state_seq,
                labels,
                at,
            );
            return Ok(EngineOutput::ApprovalStreakFrozen {
                session_id,
                incident,
                session_state_seq: self.session_state_seq,
            });
        }
        Ok(EngineOutput::StateAdvanced {
            session_state_seq: self.session_state_seq,
        })
    }

    pub(crate) fn record_session_outcome(
        &mut self,
        attempt: &ActionAttempt,
        verdict: Verdict,
        label_epoch: u64,
        now: Timestamp,
    ) {
        let analysis = classify_target(attempt.action_class, &attempt.target);
        if !self.sessions.contains_key(&attempt.session_id)
            && self.sessions.len() >= MAX_TRACKED_SESSIONS
        {
            let evict_id = self
                .session_lru_seq
                .iter()
                .filter(|(sid, _)| !self.frozen_sessions.contains(*sid))
                .min_by_key(|(_, seq)| **seq)
                .map(|(sid, _)| sid.clone())
                .or_else(|| {
                    self.sessions
                        .keys()
                        .find(|sid| !self.frozen_sessions.contains(*sid))
                        .cloned()
                });
            if let Some(oldest) = evict_id {
                self.sessions.remove(&oldest);
                self.session_lru_seq.remove(&oldest);
                self.session_label_epochs.remove(&oldest);
                self.session_last_taint_at.remove(&oldest);
                self.approval_streaks.remove(&oldest);
                self.grants.retain(|g| {
                    !(g.session_id == oldest
                        && matches!(g.scope, GrantScope::Once | GrantScope::Session))
                });
                let live_gids: BTreeSet<&str> =
                    self.grants.iter().map(|g| g.grant_id.as_str()).collect();
                self.grant_label_epochs
                    .retain(|gid, _| live_gids.contains(gid.as_str()));
            } else {
                self.session_state_seq = self.session_state_seq.saturating_add(1);
                return;
            }
        }
        self.lru_counter = self.lru_counter.saturating_add(1);
        self.session_lru_seq
            .insert(attempt.session_id.clone(), self.lru_counter);
        let session_entry = self
            .sessions
            .entry(attempt.session_id.clone())
            .or_insert_with(|| SessionRuleState::new(attempt.session_id.clone()));
        let labels_before = session_entry.labels.clone();
        session_entry.record_outcome(attempt, &analysis, verdict);
        if session_entry.labels != labels_before {
            self.session_label_epochs
                .insert(attempt.session_id.clone(), label_epoch.saturating_add(1));
            self.session_last_taint_at
                .entry(attempt.session_id.clone())
                .and_modify(|prev| *prev = (*prev).max(now))
                .or_insert(now);
        }
        self.session_state_seq = self.session_state_seq.saturating_add(1);
    }
}
