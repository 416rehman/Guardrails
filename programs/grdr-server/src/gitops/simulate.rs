// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use grdr_core::policy::{ReplayAttemptRecord, replay_pack_4bucket};
use grdr_model::eval::FourBucketSummary;
use grdr_model::{ActionAttempt, PolicyPack, PolicyRule};

use super::types::PolicyDiffSummary;

const REPLAY_DEFAULT_DAYS: u32 = 7;

pub fn index_all_rules(packs: &[PolicyPack]) -> BTreeMap<String, (String, PolicyRule)> {
    let mut map = BTreeMap::new();
    for pack in packs {
        for rule in &pack.rules {
            map.insert(rule.id.clone(), (pack.id.clone(), rule.clone()));
        }
    }
    map
}

pub fn run_four_bucket_simulation(
    attempts: &[ActionAttempt],
    candidate_packs: &[PolicyPack],
    diff: &PolicyDiffSummary,
) -> FourBucketSummary {
    let records: Vec<ReplayAttemptRecord> = attempts
        .iter()
        .enumerate()
        .map(|(idx, attempt)| ReplayAttemptRecord {
            seq: u64::try_from(idx).unwrap_or(0),
            attempt: attempt.clone(),
            absent_fields: BTreeSet::new(),
            pending_fields: BTreeSet::new(),
        })
        .collect();

    let candidate_index = index_all_rules(candidate_packs);
    let mut agg = FourBucketSummary {
        matched: 0,
        almost_matched: 0,
        not_matched: 0,
        not_evaluable: 0,
        watch_days: REPLAY_DEFAULT_DAYS,
        median_prompts_per_dev_day: 0,
        p95_prompts_per_dev_day: 0,
        promotion_ready: true,
    };

    for entry in &diff.entries {
        if let Some((_, rule)) = candidate_index.get(&entry.rule_id) {
            let mode = entry.candidate_mode.unwrap_or(rule.mode);
            if let Ok(res) = replay_pack_4bucket(&records, rule, mode, REPLAY_DEFAULT_DAYS, 1) {
                agg.matched = agg.matched.saturating_add(res.summary.matched);
                agg.almost_matched = agg
                    .almost_matched
                    .saturating_add(res.summary.almost_matched);
                agg.not_matched = agg.not_matched.saturating_add(res.summary.not_matched);
                agg.not_evaluable = agg.not_evaluable.saturating_add(res.summary.not_evaluable);
                agg.median_prompts_per_dev_day = agg
                    .median_prompts_per_dev_day
                    .max(res.summary.median_prompts_per_dev_day);
                agg.p95_prompts_per_dev_day = agg
                    .p95_prompts_per_dev_day
                    .max(res.summary.p95_prompts_per_dev_day);
                if !res.summary.promotion_ready {
                    agg.promotion_ready = false;
                }
            }
        }
    }
    agg
}
