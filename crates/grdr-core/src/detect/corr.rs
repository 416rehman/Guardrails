// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded Sigma correlation engine state, per-rule oldest-key eviction, and length-prefixed SHA-256 deduplication (`D-09`, Doc 13 s.4).

use std::collections::BTreeSet;

use grdr_crypto::{domain_sha256_digest, encode_lower_hex};

use crate::detect::eval::{CompiledSigmaRule, collect_event_field_values, evaluate_compiled_rule};
use crate::detect::types::{
    CorrelationHitRecord, CorrelationKind, CorrelationSpec, DeploymentScope, EventView,
    LineageCorrelationState, MAX_CORRELATION_ENTRIES_PER_LINEAGE, MAX_GROUP_KEYS_PER_LINEAGE,
    MAX_GROUP_KEYS_PER_RULE,
};

const DEDUP_DOMAIN: &str = "grdr.detect.dedup.v1";

pub(super) struct CorrelationStepOutcome {
    pub(super) matched: bool,
    pub(super) group_key: String,
    pub(super) overflow_triggered_now: bool,
}

/// Computes deterministic SHA-256 dedup key with explicit length-prefixed boundaries (`rule_id`, `session_id`, `group_key`, `bucket`).
#[must_use]
pub fn compute_dedup_key(rule_id: &str, session_id: &str, group_key: &str, bucket: i64) -> String {
    let mut buf = Vec::new();
    for part in [
        rule_id.as_bytes(),
        session_id.as_bytes(),
        group_key.as_bytes(),
    ] {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(part);
    }
    buf.extend_from_slice(&bucket.to_le_bytes());
    let digest = domain_sha256_digest(DEDUP_DOMAIN, &buf);
    encode_lower_hex(&digest)
}

/// Computes Doc 13 s.4 canonical dedup key over `(organisation, rule_id, group_key, window_start)`.
#[must_use]
pub fn compute_scoped_dedup_key(
    organisation_id: &str,
    rule_id: &str,
    group_key: &str,
    window_start_sec: i64,
) -> String {
    compute_dedup_key(organisation_id, rule_id, group_key, window_start_sec)
}

pub(super) fn correlation_container_key(corr: &CorrelationSpec, ev: &EventView<'_>) -> String {
    let has_session_key = corr.group_by.is_empty()
        || corr.group_by.iter().any(|g| {
            matches!(
                g.as_str(),
                "root_session_id" | "session.root" | "session_id"
            )
        });
    let has_device_key = corr.group_by.iter().any(|g| g == "device_id");
    let is_org_scope =
        corr.scope == Some(DeploymentScope::Server) || (!has_session_key && !has_device_key);
    if is_org_scope {
        format!("org:{}", ev.organisation_id)
    } else if has_session_key {
        format!(
            "lin:{}:{}:{}",
            ev.organisation_id.len(),
            ev.organisation_id,
            ev.root_session_id
        )
    } else {
        format!(
            "dev:{}:{}:{}",
            ev.organisation_id.len(),
            ev.organisation_id,
            ev.device_id
        )
    }
}

pub(super) fn encode_group_key(corr: &CorrelationSpec, ev: &EventView<'_>) -> String {
    if corr.group_by.is_empty() {
        return ev.root_session_id.to_owned();
    }
    let mut out = String::new();
    for (idx, field) in corr.group_by.iter().enumerate() {
        if idx > 0 {
            out.push('\x1f');
        }
        let val = collect_event_field_values(field, ev)
            .into_iter()
            .next()
            .unwrap_or_default();
        let len = val.len();
        out.push_str(&format!("{len}:{val}"));
    }
    out
}

pub(super) fn derive_hit_rule_key(compiled: &CompiledSigmaRule, ev: &EventView<'_>) -> String {
    if compiled.rule.rule_id == "grdr.det.core.r35.write-then-exec-digest" {
        if ev.action_class.as_str() == "file.write" {
            return "write-digest".into();
        }
        if ev.action_class.as_str() == "exec" {
            return "exec-digest".into();
        }
    }
    let corr_rules = compiled
        .rule
        .correlation
        .as_ref()
        .map(|c| c.rules.as_slice())
        .unwrap_or(&[]);
    if !corr_rules.is_empty() {
        for sel_name in compiled.selections.keys() {
            if !corr_rules.iter().any(|r| r == sel_name) {
                continue;
            }
            let mut subset = compiled.clone();
            subset.selections.retain(|k, _| k == sel_name);
            if compiled.selections.contains_key(sel_name) {
                subset.rule.selections.retain(|k, _| k == sel_name);
                subset.rule.condition = sel_name.clone();
                subset.rule.condition_ast =
                    crate::detect::types::ConditionExpr::Sel(sel_name.clone());
                if evaluate_compiled_rule(&subset, ev) {
                    return sel_name.clone();
                }
            }
        }
    }
    compiled.rule.rule_id.clone()
}

pub(super) fn record_and_evaluate_correlation(
    state: &mut LineageCorrelationState,
    rule_id: &str,
    hit_rule_key: String,
    corr: &CorrelationSpec,
    ev: &EventView<'_>,
) -> CorrelationStepOutcome {
    let group_key = encode_group_key(corr, ev);
    let mut overflow_triggered_now = false;
    let belongs_to_rule = |e: &CorrelationHitRecord, target_rid: &str| -> bool {
        if let Some(parent) = e.parent_rule_id.as_deref() {
            return parent == target_rid;
        }
        e.rule_id == target_rid
    };
    let belongs_for_spec = |e: &CorrelationHitRecord| -> bool {
        if let Some(parent) = e.parent_rule_id.as_deref() {
            return parent == rule_id;
        }
        e.rule_id == rule_id
            || e.rule_id == hit_rule_key
            || (!corr.rules.is_empty() && corr.rules.contains(&e.rule_id))
    };

    if !state.group_keys_by_rule.contains_key(rule_id)
        && state.group_keys_by_rule.len() >= MAX_GROUP_KEYS_PER_LINEAGE
        && let Some(oldest_rule) = state
            .group_keys_by_rule
            .keys()
            .min_by_key(|rid| {
                state
                    .entries
                    .iter()
                    .filter(|e| belongs_to_rule(e, rid))
                    .map(|e| e.observed_sec)
                    .max()
                    .unwrap_or(i64::MIN)
            })
            .cloned()
    {
        state.group_keys_by_rule.remove(&oldest_rule);
        state.overflow_emitted_rules.remove(&oldest_rule);
        state.entries.retain(|e| !belongs_to_rule(e, &oldest_rule));
        overflow_triggered_now = true;
    }
    let keys_for_rule = state
        .group_keys_by_rule
        .entry(rule_id.to_owned())
        .or_default();
    if let Some(existing_pos) = keys_for_rule.iter().position(|k| k == &group_key) {
        if let Some(item) = keys_for_rule.remove(existing_pos) {
            keys_for_rule.push_back(item);
        }
    } else {
        while keys_for_rule.len() >= MAX_GROUP_KEYS_PER_RULE {
            let Some(evicted_key) = keys_for_rule.pop_front() else {
                break;
            };
            state
                .entries
                .retain(|e| !(e.group_key == evicted_key && belongs_for_spec(e)));
            if state.overflow_emitted_rules.insert(rule_id.to_owned()) {
                overflow_triggered_now = true;
            }
        }
        keys_for_rule.push_back(group_key.clone());
    }

    let observed_sec = ev.observed_at.as_second();
    let distinct_value = corr
        .count_field
        .as_deref()
        .and_then(|f| collect_event_field_values(f, ev).into_iter().next());
    let secondary_distinct_value = corr
        .distinct_field
        .as_deref()
        .and_then(|f| collect_event_field_values(f, ev).into_iter().next());

    let window_i64 = i64::try_from(corr.timespan_secs).unwrap_or(i64::MAX);
    let cutoff = observed_sec.saturating_sub(window_i64);
    let threshold = usize::try_from(corr.threshold.max(1)).unwrap_or(1);

    let mut skip_insert = false;
    if corr.kind == CorrelationKind::ValueCount
        && corr.distinct_threshold == 0
        && let Some(dv) = distinct_value.as_deref()
    {
        if let Some(existing) = state.entries.iter_mut().find(|e| {
            belongs_for_spec(e)
                && e.group_key == group_key
                && e.distinct_value.as_deref() == Some(dv)
        }) {
            existing.observed_sec = existing.observed_sec.max(observed_sec);
            skip_insert = true;
        } else {
            let distinct_in_win: BTreeSet<&str> = state
                .entries
                .iter()
                .filter(|e| {
                    belongs_for_spec(e)
                        && e.group_key == group_key
                        && e.observed_sec >= cutoff
                        && e.observed_sec <= observed_sec
                })
                .filter_map(|e| e.distinct_value.as_deref())
                .collect();
            if distinct_in_win.len() >= threshold.saturating_add(1) {
                skip_insert = true;
            }
        }
    }

    if !skip_insert {
        const MAX_CORR_ENTRIES_PER_RULE_PER_LINEAGE: usize = 512;
        let rule_entry_count = state.entries.iter().filter(|e| belongs_for_spec(e)).count();
        if rule_entry_count >= MAX_CORR_ENTRIES_PER_RULE_PER_LINEAGE
            && let Some(pos) = state
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| belongs_for_spec(e))
                .min_by_key(|(_, e)| e.observed_sec)
                .map(|(idx, _)| idx)
        {
            state.entries.remove(pos);
            if state.overflow_emitted_rules.insert(rule_id.to_owned()) {
                overflow_triggered_now = true;
            }
        }
        while state.entries.len() >= MAX_CORRELATION_ENTRIES_PER_LINEAGE {
            let heaviest_rule = state
                .entries
                .iter()
                .fold(
                    std::collections::BTreeMap::<&str, usize>::new(),
                    |mut acc, e| {
                        let key = e.parent_rule_id.as_deref().unwrap_or(e.rule_id.as_str());
                        let slot = acc.entry(key).or_insert(0);
                        *slot = slot.saturating_add(1);
                        acc
                    },
                )
                .into_iter()
                .max_by_key(|(_, cnt)| *cnt)
                .map(|(r, _)| r.to_owned());
            if let Some(target_r) = heaviest_rule
                && let Some(pos) = state
                    .entries
                    .iter()
                    .position(|e| belongs_to_rule(e, &target_r))
            {
                state.entries.remove(pos);
            } else if state.entries.pop_front().is_none() {
                break;
            }
            if state.overflow_emitted_rules.insert(rule_id.to_owned()) {
                overflow_triggered_now = true;
            }
        }

        state.entries.push_back(CorrelationHitRecord {
            rule_id: hit_rule_key,
            parent_rule_id: Some(rule_id.to_owned()),
            group_key: group_key.clone(),
            observed_sec,
            distinct_value,
            secondary_distinct_value,
        });
    }

    let matched =
        check_correlation_satisfied(state, corr, rule_id, &group_key, cutoff, observed_sec);
    CorrelationStepOutcome {
        matched,
        group_key,
        overflow_triggered_now,
    }
}

pub(super) fn check_correlation_satisfied(
    state: &LineageCorrelationState,
    corr: &CorrelationSpec,
    rule_id: &str,
    group_key: &str,
    cutoff: i64,
    now_sec: i64,
) -> bool {
    let belongs = |e: &CorrelationHitRecord| -> bool {
        if let Some(parent) = e.parent_rule_id.as_deref()
            && parent != rule_id
        {
            return false;
        }
        e.rule_id == rule_id || (!corr.rules.is_empty() && corr.rules.contains(&e.rule_id))
    };
    let mut window_hits: Vec<&CorrelationHitRecord> = state
        .entries
        .iter()
        .filter(|e| {
            e.group_key == group_key
                && e.observed_sec >= cutoff
                && e.observed_sec <= now_sec
                && belongs(e)
        })
        .collect();
    window_hits.sort_by_key(|e| e.observed_sec);

    let threshold = usize::try_from(corr.threshold.max(1)).unwrap_or(1);

    let base_ok = match corr.kind {
        CorrelationKind::EventCount => window_hits.len() >= threshold,
        CorrelationKind::ValueCount => {
            let cap = threshold.saturating_add(1);
            let mut distinct = BTreeSet::new();
            for hit in window_hits.iter().copied() {
                if let Some(val) = hit.distinct_value.as_deref() {
                    distinct.insert(val);
                    if distinct.len() >= cap {
                        break;
                    }
                }
            }
            distinct.len() >= threshold
        }
        CorrelationKind::Temporal => {
            let seen: BTreeSet<&str> = window_hits.iter().map(|e| e.rule_id.as_str()).collect();
            !corr.rules.is_empty() && corr.rules.iter().all(|r| seen.contains(r.as_str()))
        }
        CorrelationKind::TemporalOrdered => {
            let mut next_needed: usize = 0;
            for hit in window_hits.iter().copied() {
                if corr.rules.get(next_needed) == Some(&hit.rule_id) {
                    next_needed = next_needed.saturating_add(1);
                    if next_needed >= corr.rules.len() {
                        break;
                    }
                }
            }
            !corr.rules.is_empty() && next_needed >= corr.rules.len()
        }
    };
    if !base_ok {
        return false;
    }
    if corr.distinct_threshold > 0 {
        let min_dist = usize::try_from(corr.distinct_threshold).unwrap_or(1);
        let mut seen = BTreeSet::new();
        for hit in window_hits {
            if let Some(v) = hit.secondary_distinct_value.as_deref() {
                seen.insert(v);
                if seen.len() >= min_dist {
                    return true;
                }
            }
        }
        return false;
    }
    true
}
