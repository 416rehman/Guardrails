// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Cryptographic grant verification, anti-replay tracking, single-use consumption, and local
//! kill-switch invariants for `grdr-daemon`.

use std::collections::VecDeque;

use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, Grant, GrantScope, KillScope, KillSwitchState,
    SignatureStatus, TrustedKeyInfo, verify_grant,
};
use grdr_wire::messages::{DecideRequestFrame, WireActionClass, WireControlPoint};
use jiff::Timestamp;

use crate::state::DaemonData;

const MAX_ACTIVE_GRANTS: usize = 256;
const MAX_REVOKED_GRANT_HISTORY: usize = 2_048;

pub(crate) fn validate_and_insert_grant(
    guard: &mut DaemonData,
    grant: Grant,
    now: Timestamp,
) -> Result<(), String> {
    let gid = grant.grant_id.trim();
    if gid.is_empty() || gid.len() > 128 || gid.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err("GRDR-DAEM-0004: invalid grant_id".to_string());
    }
    if grant.rule_id.trim().is_empty() {
        return Err("GRDR-DAEM-0004: grant rule_id must not be empty".to_string());
    }
    let target = grant.target_pattern.trim();
    if target.is_empty() || target == "*" || target == "**" {
        return Err(
            "GRDR-DAEM-0004: grant target_pattern cannot be empty or universal wildcard"
                .to_string(),
        );
    }
    match grant.scope {
        GrantScope::Once => {
            if grant.remaining_uses != Some(1) {
                return Err(
                    "GRDR-DAEM-0004: Once grant requires remaining_uses == Some(1)".to_string(),
                );
            }
        }
        GrantScope::OneHour => {
            let Some(exp) = grant.expires_at else {
                return Err("GRDR-DAEM-0004: OneHour grant requires expires_at".to_string());
            };
            if exp <= now || exp.as_second() > now.as_second().saturating_add(3_660) {
                return Err("GRDR-DAEM-0004: OneHour grant expiry out of bounds".to_string());
            }
        }
        GrantScope::Session => {
            if grant.session_id.trim().is_empty() {
                return Err("GRDR-DAEM-0004: Session grant requires session_id".to_string());
            }
        }
    }
    if grant.expires_at.is_some_and(|exp| exp <= now) {
        return Err("GRDR-DAEM-0004: grant is already expired".to_string());
    }
    if grant.granted_at.as_second() > now.as_second().saturating_add(60) {
        return Err("GRDR-DAEM-0004: grant issued_at in future".to_string());
    }
    if grant.device_id != guard.device_id {
        return Err("GRDR-DAEM-0004: grant device_id mismatch".to_string());
    }
    if guard.revoked_grant_ids.iter().any(|r| r == gid) {
        return Err(format!("GRDR-DAEM-0004: grant '{gid}' replay rejected"));
    }
    if guard.grants.len() >= MAX_ACTIVE_GRANTS {
        return Err("GRDR-DAEM-0002: active grant table full".to_string());
    }

    let mut verifier_keys = guard.trusted_keys.clone();
    verifier_keys.push(TrustedKeyInfo {
        key_id: guard.signing_key.key_id().to_string(),
        public_key_b64: guard.signing_key.public_key_b64().to_string(),
    });
    if verify_grant(&grant, &verifier_keys) != SignatureStatus::Verified {
        return Err(
            "GRDR-DAEM-0004: grant missing valid cryptographic approval signature".to_string(),
        );
    }
    guard.grants.retain(|g| g.grant_id != gid);
    guard.grants.push(grant);
    Ok(())
}

pub(crate) fn revoke_grant_entry(guard: &mut DaemonData, grant_id: &str) -> Result<(), String> {
    let trimmed = grant_id.trim();
    if trimmed.is_empty() {
        return Err("grant_id must not be empty".to_string());
    }
    let before = guard.grants.len();
    guard.grants.retain(|g| g.grant_id != trimmed);
    if guard.grants.len() == before {
        return Err(format!("grant '{trimmed}' not found"));
    }
    record_revoked_grant_id(&mut guard.revoked_grant_ids, trimmed);
    Ok(())
}

pub(crate) fn apply_local_kill_switch(
    guard: &mut DaemonData,
    active: bool,
    reason: &str,
    now: Timestamp,
) -> Result<(), String> {
    if !active {
        match &guard.kill_switch {
            KillSwitchState::Frozen {
                scope: KillScope::Organisation,
                ..
            }
            | KillSwitchState::Killed { .. } => {
                return Err(
                    "GRDR-DAEM-0004: org-level or permanent Killed switch cannot be cleared locally"
                        .to_string(),
                );
            }
            KillSwitchState::Inactive | KillSwitchState::Frozen { .. } => {}
        }
    }
    guard.kill_switch = if active {
        KillSwitchState::Frozen {
            scope: KillScope::Device,
            target_id: guard.device_id.clone(),
            reason: reason.to_string(),
            issued_at: now,
            expires_at: Timestamp::MAX,
        }
    } else {
        KillSwitchState::Inactive
    };
    Ok(())
}

pub(crate) fn record_revoked_grant_id(ring: &mut VecDeque<String>, id: &str) {
    if ring.iter().any(|existing| existing == id) {
        return;
    }
    if ring.len() >= MAX_REVOKED_GRANT_HISTORY {
        let _ = ring.pop_front();
    }
    ring.push_back(id.to_string());
}

pub(crate) fn consume_grant(
    grants: &mut Vec<Grant>,
    revoked_ring: &mut VecDeque<String>,
    grant_id: &str,
) -> bool {
    let Some(idx) = grants.iter().position(|g| g.grant_id == grant_id) else {
        return false;
    };
    let Some(grant) = grants.get_mut(idx) else {
        return false;
    };
    let Some(rem) = grant.remaining_uses else {
        return false;
    };
    let next = rem.saturating_sub(1);
    if next == 0 {
        let _ = grants.remove(idx);
        record_revoked_grant_id(revoked_ring, grant_id);
    } else {
        grant.remaining_uses = Some(next);
    }
    true
}

pub(crate) fn verify_matching_active_grant(
    guard: &DaemonData,
    grant_id: &str,
    req: &DecideRequestFrame,
    now: Timestamp,
) -> Option<String> {
    let trimmed = grant_id.trim();
    if trimmed.is_empty() || guard.revoked_grant_ids.iter().any(|r| r == trimmed) {
        return None;
    }
    let grant = guard.grants.iter().find(|g| g.grant_id == trimmed)?;
    let pat = grant.target_pattern.trim();
    if pat.is_empty() || pat == "*" || pat == "**" {
        return None;
    }
    if grant.device_id != guard.device_id
        || grant.granted_at.as_second() > now.as_second().saturating_add(60)
    {
        return None;
    }
    if matches!(grant.scope, GrantScope::OneHour) && grant.expires_at.is_none_or(|exp| exp <= now) {
        return None;
    }
    let action_class =
        WireActionClass::from_wire_i32(req.action_class).and_then(WireActionClass::to_model)?;
    let control_point = WireControlPoint::from_wire_i32(req.control_point)
        .and_then(WireControlPoint::to_model)
        .unwrap_or(ControlPoint::Hook);
    let resolved_target = if matches!(action_class, ActionClass::Exec | ActionClass::Elevate)
        && !req.command_line.trim().is_empty()
    {
        req.command_line.clone()
    } else if !req.target.trim().is_empty() {
        req.target.clone()
    } else if !req.command_line.trim().is_empty() {
        req.command_line.clone()
    } else {
        req.summary.clone()
    };
    let attempt = ActionAttempt {
        id: req.request_id.clone(),
        session_id: if req.session_id.is_empty() {
            "default".to_string()
        } else {
            req.session_id.clone()
        },
        device_id: guard.device_id.clone(),
        device_name: guard.hostname.clone(),
        agent_name: req.agent.clone(),
        action_class,
        control_point,
        target: resolved_target,
        summary: req.summary.clone(),
        timestamp: now,
        ..ActionAttempt::default()
    };
    grant.matches(&attempt, now).then(|| trimmed.to_string())
}

pub(crate) fn restore_revoked_grant_ids(
    grants: &mut Vec<Grant>,
    raw_revoked: &[String],
) -> VecDeque<String> {
    let mut ring = VecDeque::new();
    for id in raw_revoked {
        record_revoked_grant_id(&mut ring, id);
    }
    grants.retain(|g| !ring.iter().any(|rev| rev == &g.grant_id));
    ring
}
