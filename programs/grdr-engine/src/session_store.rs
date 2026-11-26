// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Bounded per-session policy evaluation state map for the stateless `grdr-engine`,
//! prioritizing retention of high-taint sessions ahead of low-taint and clean ones.

use std::collections::BTreeMap;

use grdr_core::session::SessionRuleState;
use grdr_model::SessionLabel;

pub const DEFAULT_MAX_ENGINE_SESSIONS: usize = 256;

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub last_touched_step: u64,
    pub eval_count: u64,
    pub state: SessionRuleState,
}

#[derive(Debug)]
pub struct BoundedSessionMap {
    max_sessions: usize,
    tick: u64,
    entries: BTreeMap<String, SessionEntry>,
}

impl BoundedSessionMap {
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions: max_sessions.max(1),
            tick: 0,
            entries: BTreeMap::new(),
        }
    }

    pub fn get_or_insert_mut(&mut self, session_id: &str) -> &mut SessionEntry {
        let key = normalize_session_key(session_id);
        self.tick = self.tick.saturating_add(1);
        let step = self.tick;

        if !self.entries.contains_key(key) && self.entries.len() >= self.max_sessions {
            self.evict_lru_preserving_tainted();
        }
        let entry = self
            .entries
            .entry(key.to_string())
            .or_insert_with(|| SessionEntry {
                last_touched_step: step,
                eval_count: 0,
                state: SessionRuleState::new(key),
            });
        entry.last_touched_step = step;
        entry.eval_count = entry.eval_count.saturating_add(1);
        entry
    }

    fn evict_lru_preserving_tainted(&mut self) {
        // Tier 2 (CredentialAccessed / RepeatedDenials / TaintedExfilRisk / denials) outlives
        // Tier 1 (UntrustedWebFetched) and Tier 0 (clean), preventing WebFetch churn eviction.
        let oldest_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| (taint_tier(&entry.state), entry.last_touched_step))
            .map(|(k, _)| k.clone());
        if let Some(victim) = oldest_key {
            let _ = self.entries.remove(&victim);
        }
    }
}

fn normalize_session_key(session_id: &str) -> &str {
    if session_id.trim().is_empty() {
        "default"
    } else {
        session_id
    }
}

fn taint_tier(state: &SessionRuleState) -> u8 {
    let high_taint = state.denial_count > 0
        || state.step_up_count > 0
        || state.labels.iter().any(|lbl| {
            matches!(
                lbl,
                SessionLabel::CredentialAccessed
                    | SessionLabel::RepeatedDenials
                    | SessionLabel::TaintedExfilRisk
            )
        });
    if high_taint {
        2
    } else if !state.labels.is_empty() {
        1
    } else {
        0
    }
}
