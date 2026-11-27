// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Fail-safe session receipt replay and summary label attachment (`D-54`, `D-28`).

use std::collections::BTreeMap;

use grdr_model::{ActionAttempt, DecisionReceipt, SessionSummary, Verdict};

use crate::analyze::classify_target;
use crate::session::SessionRuleState;

/// Replays session state transitions fail-safely, picking the most restrictive verdict
/// on conflicting duplicate attempt receipts and flagging missing receipts as coverage gaps.
pub fn replay_session_states_checked(
    attempts: &[ActionAttempt],
    receipts: &[DecisionReceipt],
) -> (BTreeMap<String, SessionRuleState>, Vec<String>) {
    let mut receipt_by_attempt: BTreeMap<&str, Verdict> = BTreeMap::new();
    let mut gaps = Vec::new();
    for receipt in receipts {
        if let Some(prev) = receipt_by_attempt.get(receipt.attempt_id.as_str()).copied() {
            if prev != receipt.verdict {
                gaps.push(format!(
                    "session.replay-conflicting-receipt:{}",
                    receipt.attempt_id
                ));
                let strict = more_restrictive_verdict(prev, receipt.verdict);
                receipt_by_attempt.insert(receipt.attempt_id.as_str(), strict);
            }
        } else {
            receipt_by_attempt.insert(receipt.attempt_id.as_str(), receipt.verdict);
        }
    }

    let mut ordered_attempts: Vec<&ActionAttempt> = attempts.iter().collect();
    ordered_attempts.sort_by_key(|a| a.timestamp);

    let mut states: BTreeMap<String, SessionRuleState> = BTreeMap::new();
    for attempt in ordered_attempts {
        let (verdict, missing) = match receipt_by_attempt.get(attempt.id.as_str()).copied() {
            Some(v) => (v, false),
            None => (Verdict::StepUp, true),
        };
        let analysis = classify_target(attempt.action_class, &attempt.target);
        let state = states
            .entry(attempt.session_id.clone())
            .or_insert_with(|| SessionRuleState::new(attempt.session_id.clone()));
        if missing {
            let gap = format!("session.replay-missing-receipt:{}", attempt.id);
            state.replay_coverage_gaps.push(gap.clone());
            gaps.push(gap);
        }
        state.record_outcome(attempt, &analysis, verdict);
    }
    (states, gaps)
}

#[must_use]
pub fn replay_session_states(
    attempts: &[ActionAttempt],
    receipts: &[DecisionReceipt],
) -> BTreeMap<String, SessionRuleState> {
    replay_session_states_checked(attempts, receipts).0
}

pub fn attach_session_labels(
    summaries: &mut [SessionSummary],
    states: &BTreeMap<String, SessionRuleState>,
) {
    for summary in summaries {
        if let Some(state) = states.get(&summary.id) {
            summary.labels = state.labels_vec();
        }
    }
}

const fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Deny => 4,
        Verdict::StepUp => 3,
        Verdict::Defer | Verdict::Modify => 2,
        Verdict::Allow => 1,
    }
}

const fn more_restrictive_verdict(a: Verdict, b: Verdict) -> Verdict {
    if verdict_rank(b) > verdict_rank(a) {
        b
    } else {
        a
    }
}
