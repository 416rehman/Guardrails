// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use core::fmt::Write as _;

use grdr_fastpath::{
    FLAG_BACKTICK, FLAG_ENCODED_CMD, FLAG_MALFORMED_QUOTES, FLAG_SUBSHELL, FastVerdict,
    FloorRuleRef, MAX_HOOK_SCAN_BYTES, evaluate_floor_entries, scan_hook_payload,
};
use jiff::Timestamp;

use crate::model_dto::{
    WasmActionAttempt, WasmActionClass, WasmDecisionReceipt, WasmGrant, WasmGrantScope,
    WasmKillScope, WasmKillSwitchState, WasmMode, WasmPolicyPack, WasmPolicyRule, WasmVerdict,
};
use crate::sha256::sha256_hex;
use crate::types::WasmSessionState;

const LABEL_CREDENTIAL_ACCESSED_BIT: u8 = 1 << 0;

struct OutcomeSpec<'a> {
    verdict: WasmVerdict,
    would_be: Option<WasmVerdict>,
    rule_id: Option<&'a str>,
    pack_id: Option<&'a str>,
    mode_applied: Option<WasmMode>,
    grant_id: Option<&'a str>,
    reason: String,
    next_step: String,
}

pub fn evaluate_wasm_with_session(
    attempt: &WasmActionAttempt,
    packs: &[WasmPolicyPack],
    grants: &mut [WasmGrant],
    kill_switch: &WasmKillSwitchState,
    session_state: &mut WasmSessionState,
    now: Timestamp,
) -> WasmDecisionReceipt {
    if let Some(reason) = active_kill_reason(kill_switch, attempt, now) {
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::Deny,
                would_be: None,
                rule_id: Some("system.kill-switch"),
                pack_id: Some("system"),
                mode_applied: Some(WasmMode::Block),
                grant_id: None,
                reason,
                next_step: "Clear active kill-switch in Respond before retrying.".into(),
            },
            now,
        );
    }

    let scan_flags = if attempt.action_class == WasmActionClass::Exec {
        scan_hook_payload(attempt.target.as_bytes(), MAX_HOOK_SCAN_BYTES).flags
    } else {
        0
    };
    if (scan_flags & FLAG_MALFORMED_QUOTES) != 0 {
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::Deny,
                would_be: None,
                rule_id: Some("session.malformed-command"),
                pack_id: Some("session"),
                mode_applied: Some(WasmMode::Block),
                grant_id: None,
                reason: "Malformed command syntax (unclosed quote or trailing escape) blocked by normalizer.".into(),
                next_step: "Fix quoting or inspect the command before retrying.".into(),
            },
            now,
        );
    }

    let mut matched: Vec<(&WasmPolicyPack, &WasmPolicyRule)> = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == WasmMode::Off {
                continue;
            }
            if rule_matches_attempt(rule, attempt, session_state) {
                matched.push((pack, rule));
            }
        }
    }

    let mut blocks: Vec<(&WasmPolicyPack, &WasmPolicyRule)> = matched
        .iter()
        .copied()
        .filter(|(_, r)| r.mode == WasmMode::Block)
        .collect();
    blocks.sort_by(|(_, a), (_, b)| a.id.cmp(&b.id));
    if let Some((pack, rule)) = blocks.first().copied() {
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::Deny,
                would_be: None,
                rule_id: Some(&rule.id),
                pack_id: Some(&pack.id),
                mode_applied: Some(WasmMode::Block),
                grant_id: None,
                reason: rule_reason(rule),
                next_step: rule_steer(rule, "Blocked by active Block policy rule."),
            },
            now,
        );
    }

    let mut asks: Vec<(&WasmPolicyPack, &WasmPolicyRule)> = matched
        .iter()
        .copied()
        .filter(|(_, r)| r.mode == WasmMode::Ask)
        .collect();
    asks.sort_by(|(_, a), (_, b)| a.id.cmp(&b.id));
    if let Some((top_pack, top_rule)) = asks.first().copied() {
        return resolve_ask_matches(
            attempt,
            grants,
            session_state,
            &asks,
            top_pack,
            top_rule,
            now,
        );
    }

    if (scan_flags & (FLAG_SUBSHELL | FLAG_BACKTICK | FLAG_ENCODED_CMD)) != 0 {
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::StepUp,
                would_be: None,
                rule_id: Some("session.opaque-command"),
                pack_id: Some("session"),
                mode_applied: Some(WasmMode::Ask),
                grant_id: None,
                reason: "Opaque shell construct (subshell, backtick, or encoded command) requires approval.".into(),
                next_step: "Review the expanded command and approve in Respond before retrying.".into(),
            },
            now,
        );
    }

    let mut watches: Vec<(&WasmPolicyPack, &WasmPolicyRule)> = matched
        .iter()
        .copied()
        .filter(|(_, r)| r.mode == WasmMode::Watch)
        .collect();
    watches.sort_by(|(_, a), (_, b)| a.id.cmp(&b.id));
    if let Some((pack, rule)) = watches.first().copied() {
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::Allow,
                would_be: Some(WasmVerdict::StepUp),
                rule_id: Some(&rule.id),
                pack_id: Some(&pack.id),
                mode_applied: Some(WasmMode::Watch),
                grant_id: None,
                reason: rule.reason_template.clone(),
                next_step: "Run replay to review before promoting from Watch.".into(),
            },
            now,
        );
    }

    finish_receipt(
        attempt,
        session_state,
        OutcomeSpec {
            verdict: WasmVerdict::Allow,
            would_be: None,
            rule_id: None,
            pack_id: None,
            mode_applied: None,
            grant_id: None,
            reason: "No policy rule restricted this action.".into(),
            next_step: "No action needed.".into(),
        },
        now,
    )
}

fn resolve_ask_matches(
    attempt: &WasmActionAttempt,
    grants: &mut [WasmGrant],
    session_state: &mut WasmSessionState,
    asks: &[(&WasmPolicyPack, &WasmPolicyRule)],
    top_pack: &WasmPolicyPack,
    top_rule: &WasmPolicyRule,
    now: Timestamp,
) -> WasmDecisionReceipt {
    let mut grant_indices = Vec::with_capacity(asks.len());
    let mut all_lifted = true;
    for (_, rule) in asks {
        if let Some(idx) = find_matching_grant(grants, rule, attempt, now) {
            if !grant_indices.contains(&idx) {
                grant_indices.push(idx);
            }
        } else {
            all_lifted = false;
            break;
        }
    }
    if all_lifted && let Some(&primary_idx) = grant_indices.first() {
        let gid = grants
            .get(primary_idx)
            .map(|g| g.grant_id.clone())
            .unwrap_or_default();
        for idx in grant_indices {
            if let Some(grant) = grants.get_mut(idx) {
                consume_grant_use(grant);
            }
        }
        return finish_receipt(
            attempt,
            session_state,
            OutcomeSpec {
                verdict: WasmVerdict::Allow,
                would_be: Some(WasmVerdict::StepUp),
                rule_id: Some(&top_rule.id),
                pack_id: Some(&top_pack.id),
                mode_applied: Some(WasmMode::Ask),
                grant_id: Some(&gid),
                reason: format!("Allowed by active approval grant {gid}."),
                next_step: "Action permitted within grant expiry window.".into(),
            },
            now,
        );
    }
    finish_receipt(
        attempt,
        session_state,
        OutcomeSpec {
            verdict: WasmVerdict::StepUp,
            would_be: None,
            rule_id: Some(&top_rule.id),
            pack_id: Some(&top_pack.id),
            mode_applied: Some(WasmMode::Ask),
            grant_id: None,
            reason: rule_reason(top_rule),
            next_step: rule_steer(top_rule, "Approve in Respond before retrying."),
        },
        now,
    )
}

pub fn rule_matches_attempt(
    rule: &WasmPolicyRule,
    attempt: &WasmActionAttempt,
    session: &WasmSessionState,
) -> bool {
    if !rule.matcher.agents.is_empty()
        && !rule
            .matcher
            .agents
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&attempt.agent_name))
    {
        return false;
    }
    let cedar_src = rule.cedar.as_deref().unwrap_or("");
    if (cedar_src.contains("context.session.tainted") || cedar_src.contains("labels."))
        && session.label_flags == 0
        && session.extra_labels.is_empty()
        && session.denial_count < 3
    {
        return false;
    }
    let primary = single_action_matches(rule, attempt.action_class, &attempt.target);
    let secondary = attempt
        .secondary_actions
        .iter()
        .any(|s| single_action_matches(rule, s.action_class, &s.target));
    primary || secondary
}

fn single_action_matches(
    rule: &WasmPolicyRule,
    action_class: WasmActionClass,
    target: &str,
) -> bool {
    if !rule.matcher.action_classes.is_empty()
        && !rule.matcher.action_classes.contains(&action_class)
    {
        return false;
    }
    if rule.matcher.target_prefixes.is_empty() && rule.matcher.target_contains.is_empty() {
        return true;
    }
    let prefixes: Vec<&str> = rule
        .matcher
        .target_prefixes
        .iter()
        .map(String::as_str)
        .collect();
    let contains: Vec<&str> = rule
        .matcher
        .target_contains
        .iter()
        .map(String::as_str)
        .collect();
    let refs = [FloorRuleRef {
        rule_id: &rule.id,
        action_mask: action_class.to_fast().bit(),
        prefixes: &prefixes,
        contains: &contains,
        agents: &[],
        verdict: FastVerdict::Deny,
    }];
    evaluate_floor_entries(&refs, action_class.to_fast(), "", target).is_some()
}

fn active_kill_reason(
    ks: &WasmKillSwitchState,
    attempt: &WasmActionAttempt,
    now: Timestamp,
) -> Option<String> {
    match ks {
        WasmKillSwitchState::Inactive => None,
        WasmKillSwitchState::Frozen {
            scope,
            target_id,
            reason,
            expires_at,
            ..
        } => {
            if now < *expires_at && kill_scope_matches(*scope, target_id, attempt) {
                Some(reason.clone())
            } else {
                None
            }
        }
        WasmKillSwitchState::Killed {
            scope,
            target_id,
            reason,
            ..
        } => {
            if kill_scope_matches(*scope, target_id, attempt) {
                Some(reason.clone())
            } else {
                None
            }
        }
    }
}

fn kill_scope_matches(scope: WasmKillScope, target_id: &str, attempt: &WasmActionAttempt) -> bool {
    match scope {
        WasmKillScope::Session => attempt.session_id == target_id,
        WasmKillScope::Device => attempt.device_id == target_id,
        WasmKillScope::Organisation => true,
    }
}

fn find_matching_grant(
    grants: &[WasmGrant],
    rule: &WasmPolicyRule,
    attempt: &WasmActionAttempt,
    now: Timestamp,
) -> Option<usize> {
    grants.iter().position(|g| {
        g.rule_id == rule.id
            && g.grade >= rule.min_grade
            && g.action_class == attempt.action_class
            && g.session_id == attempt.session_id
            && g.device_id == attempt.device_id
            && g.expires_at.is_none_or(|exp| now < exp)
            && g.remaining_uses != Some(0)
            && (g.target_pattern == "*" || g.target_pattern == attempt.target)
    })
}

fn consume_grant_use(grant: &mut WasmGrant) {
    if matches!(grant.scope, WasmGrantScope::Once) {
        grant.remaining_uses = Some(grant.remaining_uses.unwrap_or(1).saturating_sub(1));
    } else if let Some(rem) = grant.remaining_uses {
        grant.remaining_uses = Some(rem.saturating_sub(1));
    }
}

fn finish_receipt(
    attempt: &WasmActionAttempt,
    session: &mut WasmSessionState,
    outcome: OutcomeSpec<'_>,
    now: Timestamp,
) -> WasmDecisionReceipt {
    match outcome.verdict {
        WasmVerdict::Deny => session.denial_count = session.denial_count.saturating_add(1),
        WasmVerdict::StepUp => session.step_up_count = session.step_up_count.saturating_add(1),
        _ => {}
    }
    if outcome.rule_id == Some("essentials.credential-stores") {
        session.label_flags |= LABEL_CREDENTIAL_ACCESSED_BIT;
    }

    let mut payload = String::new();
    for field in [
        attempt.id.as_str(),
        attempt.session_id.as_str(),
        attempt.agent_name.as_str(),
        attempt.action_class.as_str(),
        attempt.target.as_str(),
        outcome.rule_id.unwrap_or("none"),
    ] {
        let _ = write!(payload, "{}:{field}", field.len());
    }
    let _ = write!(payload, "{:?}:{}", outcome.verdict, now.as_second());
    let receipt_digest = sha256_hex(payload.as_bytes());
    let short_id: String = receipt_digest.chars().take(32).collect();

    WasmDecisionReceipt {
        receipt_id: format!("rcp_{short_id}"),
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict: outcome.verdict,
        would_be: outcome.would_be,
        rule_id: outcome.rule_id.map(str::to_owned),
        pack_id: outcome.pack_id.map(str::to_owned),
        mode_applied: outcome.mode_applied,
        grant_id: outcome.grant_id.map(str::to_owned),
        reason: outcome.reason,
        next_step: outcome.next_step,
        receipt_digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

fn rule_reason(rule: &WasmPolicyRule) -> String {
    extract_cedar_annotation(rule.cedar.as_deref(), "message")
        .map(str::to_owned)
        .unwrap_or_else(|| rule.reason_template.clone())
}

fn rule_steer(rule: &WasmPolicyRule, default: &str) -> String {
    extract_cedar_annotation(rule.cedar.as_deref(), "steer")
        .unwrap_or(default)
        .to_owned()
}

fn extract_cedar_annotation<'a>(cedar: Option<&'a str>, key: &str) -> Option<&'a str> {
    let src = cedar?;
    let marker = format!("@{key}(\"");
    let (_, after) = src.split_once(&marker)?;
    let (val, _) = after.split_once("\")")?;
    Some(val)
}
