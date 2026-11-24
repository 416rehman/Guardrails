// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Replays a single PolicyRule over historical ActionAttempts using Cedar 4.x.

use cedar_policy::{Authorizer, Decision, PolicySet};
use grdr_model::{
    ActionAttempt, Mode, PolicyPack, PolicyRule, ReplaySample, ReplaySummary, Verdict,
};

use super::compiler::compile_single_rule_for_replay;
use super::request::build_cedar_request;
use crate::analyze::normalize_attempt_target;

const MAX_REPLAY_SAMPLES: usize = 25;

pub fn replay_rule(
    attempts: &[ActionAttempt],
    rule: &PolicyRule,
    candidate_mode: Mode,
) -> ReplaySummary {
    let current_set = compile_single_rule_for_replay(rule, rule.mode)
        .ok()
        .flatten();
    let candidate_set = compile_single_rule_for_replay(rule, candidate_mode)
        .ok()
        .flatten();
    let authorizer = Authorizer::new();

    let mut total_scanned: u64 = 0;
    let mut matched: u64 = 0;
    let mut would_ask: u64 = 0;
    let mut would_block: u64 = 0;
    let mut not_matched: u64 = 0;
    let mut samples = Vec::new();

    let mut replay_pack = PolicyPack {
        id: "replay".into(),
        name: "Replay".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "replay".into(),
        rules: vec![rule.clone()],
        key_id: None,
        signature: None,
    };
    if let Some(first) = replay_pack.rules.first_mut() {
        first.enabled = true;
        first.mode = if candidate_mode == Mode::Off {
            Mode::Watch
        } else {
            candidate_mode
        };
    }

    for attempt in attempts {
        total_scanned = total_scanned.saturating_add(1);
        let (normalized_target, _) =
            normalize_attempt_target(attempt.action_class, &attempt.target);
        let mut match_attempt = attempt.clone();
        if !normalized_target.is_empty() {
            match_attempt.target = normalized_target;
        }

        let current_hit = current_set
            .as_ref()
            .is_some_and(|set| eval_replay_set(&authorizer, set, &match_attempt, &replay_pack));
        let candidate_hit = candidate_set
            .as_ref()
            .is_some_and(|set| eval_replay_set(&authorizer, set, &match_attempt, &replay_pack));

        let current_verdict = if current_hit {
            verdict_for_mode(rule.mode)
        } else {
            Verdict::Allow
        };

        if !candidate_hit {
            not_matched = not_matched.saturating_add(1);
            continue;
        }

        matched = matched.saturating_add(1);
        let candidate_verdict = verdict_for_mode(candidate_mode);
        match candidate_mode {
            Mode::Ask => would_ask = would_ask.saturating_add(1),
            Mode::Block => would_block = would_block.saturating_add(1),
            Mode::Watch | Mode::Off => {}
        }

        if samples.len() < MAX_REPLAY_SAMPLES {
            samples.push(ReplaySample {
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                target: attempt.target.clone(),
                current_verdict,
                candidate_verdict,
                timestamp: attempt.timestamp,
            });
        }
    }

    ReplaySummary {
        rule_id: rule.id.clone(),
        candidate_mode,
        window_label: "Last 7 days".into(),
        total_scanned,
        matched,
        would_ask,
        would_block,
        not_matched,
        samples,
    }
}

fn eval_replay_set(
    authorizer: &Authorizer,
    set: &PolicySet,
    attempt: &ActionAttempt,
    replay_pack: &PolicyPack,
) -> bool {
    let pack_slice = std::slice::from_ref(replay_pack);
    let Ok(built) = build_cedar_request(attempt, pack_slice, &[], &[], None, attempt.timestamp)
    else {
        return false;
    };
    let resp = authorizer.is_authorized(&built.request, set, &built.entities);
    resp.decision() == Decision::Deny
}

fn verdict_for_mode(mode: Mode) -> Verdict {
    match mode {
        Mode::Off | Mode::Watch => Verdict::Allow,
        Mode::Ask => Verdict::StepUp,
        Mode::Block => Verdict::Deny,
    }
}
