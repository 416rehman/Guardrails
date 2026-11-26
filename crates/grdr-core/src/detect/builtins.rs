// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Built-in tamper/coverage-gap detectors (rows 33, 34, 45, 46) and bounded dedup helpers (`D-09`, `D-54`).

use std::collections::BTreeSet;

use grdr_crypto::{domain_sha256_digest, encode_lower_hex};
use grdr_model::{Finding, FindingClass, FindingLifecycle, FindingSeverity};

use crate::detect::corr::compute_scoped_dedup_key;
use crate::detect::types::{
    DetectOutput, DetectState, EventView, MAX_ENGINE_DEDUP_KEYS, MAX_ENGINE_LINEAGES,
    MAX_PROBE_BUCKETS,
};

const HOOK_SILENT_WINDOW_SECS: i64 = 120;
const JUDGE_PROBE_WINDOW_SECS: i64 = 600;
const JUDGE_PROBE_MIN_EVENTS: usize = 5;
const JUDGE_PROBE_MIN_DIGESTS: usize = 3;

pub(super) struct BuiltinFindingSpec<'a> {
    pub(super) rule_id: &'a str,
    pub(super) class: FindingClass,
    pub(super) severity: FindingSeverity,
    pub(super) title: &'a str,
    pub(super) summary: &'a str,
}

pub(super) fn evaluate_builtin_rules(
    state: &mut DetectState,
    loaded_ids: &BTreeSet<String>,
    skip_yaml_covered: bool,
    ev: &EventView<'_>,
    out: &mut DetectOutput,
) {
    let now_sec = ev.observed_at.as_second();

    let org_sess = format!(
        "{}:{}:{}:{}",
        ev.organisation_id.len(),
        ev.organisation_id,
        ev.session_id.len(),
        ev.session_id
    );
    if ev.fields.get("telemetry.source") == Some(&"hook") {
        if state.hook_last_seen_sec.len() >= MAX_ENGINE_LINEAGES
            && !state.hook_last_seen_sec.contains_key(&org_sess)
            && let Some(oldest) = state
                .hook_last_seen_sec
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
        {
            state.hook_last_seen_sec.remove(&oldest);
        }
        let next_hook = state
            .hook_last_seen_sec
            .get(&org_sess)
            .copied()
            .map_or(now_sec, |prev| prev.max(now_sec));
        state.hook_last_seen_sec.insert(org_sess.clone(), next_hook);
        state.sensor_exec_without_hook.remove(&org_sess);
        state.sensor_exec_last_seen_sec.remove(&org_sess);
    } else if ev.fields.get("telemetry.source") == Some(&"sensor")
        && ev.fields.get("hook.matched") == Some(&"false")
    {
        if state.sensor_exec_without_hook.len() >= MAX_ENGINE_LINEAGES
            && !state.sensor_exec_without_hook.contains_key(&org_sess)
            && let Some(oldest) = state
                .sensor_exec_without_hook
                .iter()
                .min_by_key(|(k, _)| {
                    state
                        .sensor_exec_last_seen_sec
                        .get(*k)
                        .copied()
                        .unwrap_or(i64::MIN)
                })
                .map(|(k, _)| k.clone())
        {
            state.sensor_exec_without_hook.remove(&oldest);
            state.sensor_exec_last_seen_sec.remove(&oldest);
        }
        let count = state
            .sensor_exec_without_hook
            .entry(org_sess.clone())
            .or_insert(0);
        *count = count.saturating_add(1);
        let next_exec = state
            .sensor_exec_last_seen_sec
            .get(&org_sess)
            .copied()
            .map_or(now_sec, |prev| prev.max(now_sec));
        state
            .sensor_exec_last_seen_sec
            .insert(org_sess.clone(), next_exec);
        let stale_hook = state
            .hook_last_seen_sec
            .get(&org_sess)
            .is_some_and(|last| now_sec.saturating_sub(*last) > HOOK_SILENT_WINDOW_SECS);
        let yaml_covers_exact_process_event = skip_yaml_covered
            && loaded_ids.contains("grdr.det.core.r33.hook-dark")
            && !stale_hook
            && ev.category.eq_ignore_ascii_case("process")
            && ev.service.eq_ignore_ascii_case("sensor");
        if !yaml_covers_exact_process_event
            && (*count >= 2 || stale_hook || ev.action_class == grdr_model::ActionClass::Exec)
        {
            emit_builtin_finding(
                state,
                ev,
                &BuiltinFindingSpec {
                    rule_id: "grdr.det.core.r33.hook-dark",
                    class: FindingClass::Tamper,
                    severity: FindingSeverity::High,
                    title: "Hook dark or silent across observed session",
                    summary: "Sensor observed agent action with absent or stale hook heartbeat.",
                },
                "",
                out,
            );
        }
    }

    let r34_yaml_covers = skip_yaml_covered
        && loaded_ids.contains("grdr.det.core.r34.effect-mismatch")
        && ev.category.eq_ignore_ascii_case("process")
        && ev.service.eq_ignore_ascii_case("sensor");
    if !r34_yaml_covers && ev.fields.get("effect.mismatch") == Some(&"true") {
        emit_builtin_finding(
            state,
            ev,
            &BuiltinFindingSpec {
                rule_id: "grdr.det.core.r34.effect-mismatch",
                class: FindingClass::Tamper,
                severity: FindingSeverity::Critical,
                title: "Executed effect differs from approved request",
                summary: "Observed OS command/target did not match granted approval digest.",
            },
            "",
            out,
        );
    }

    if (!skip_yaml_covered || !loaded_ids.contains("grdr.det.core.r45.label-late"))
        && ev.fields.get("label.late") == Some(&"true")
    {
        emit_builtin_finding(
            state,
            ev,
            &BuiltinFindingSpec {
                rule_id: "grdr.det.core.r45.label-late",
                class: FindingClass::CoverageGap,
                severity: FindingSeverity::Medium,
                title: "Enforcing session label arrived after decision",
                summary: "Delayed label state arrived after evaluation completed.",
            },
            "",
            out,
        );
    }

    let r46_yaml_covers = skip_yaml_covered
        && loaded_ids.contains("grdr.det.judge-probing")
        && ev.category.eq_ignore_ascii_case("hook");
    if !r46_yaml_covers && ev.fields.get("judge.objection") == Some(&"true") {
        const MAX_PROBE_ENTRIES_PER_BUCKET: usize = 128;
        let tool_class = ev
            .fields
            .get("tool.class")
            .copied()
            .unwrap_or(ev.action_class.as_str());
        let action_digest = ev.fields.get("action.digest").copied().unwrap_or(ev.target);
        let key = format!(
            "{}:{}:{}:{}:{}:{}",
            ev.organisation_id.len(),
            ev.organisation_id,
            ev.root_session_id.len(),
            ev.root_session_id,
            tool_class.len(),
            tool_class
        );
        if !state.judge_probe_history.contains_key(&key)
            && state.judge_probe_history.len() >= MAX_PROBE_BUCKETS
            && let Some(oldest) = state
                .judge_probe_history
                .iter()
                .min_by_key(|(_, entries)| {
                    entries
                        .iter()
                        .map(|(ts, _, _)| *ts)
                        .max()
                        .unwrap_or(i64::MIN)
                })
                .map(|(k, _)| k.clone())
        {
            state.judge_probe_history.remove(&oldest);
            state.judge_probe_pending_future_sec.remove(&oldest);
        }
        let prev_max = state
            .judge_probe_history
            .get(&key)
            .and_then(|l| l.iter().map(|(ts, _, _)| *ts).max());
        let mut effective_ts = now_sec;
        let mut is_future_outlier = false;
        if let Some(prev) = prev_max {
            const PROBE_OUTLIER_SECS: i64 = 3_600;
            if now_sec.saturating_sub(prev) > PROBE_OUTLIER_SECS {
                if let Some(&pending) = state.judge_probe_pending_future_sec.get(&key)
                    && now_sec >= pending.saturating_sub(JUDGE_PROBE_WINDOW_SECS)
                    && now_sec.saturating_sub(pending) <= PROBE_OUTLIER_SECS
                {
                    state.judge_probe_pending_future_sec.remove(&key);
                    effective_ts = prev.max(pending.max(now_sec));
                } else {
                    state
                        .judge_probe_pending_future_sec
                        .insert(key.clone(), now_sec);
                    effective_ts = prev;
                    is_future_outlier = true;
                }
            } else {
                state.judge_probe_pending_future_sec.remove(&key);
                effective_ts = prev.max(now_sec);
            }
        } else {
            state.judge_probe_pending_future_sec.remove(&key);
        }
        let list = state.judge_probe_history.entry(key).or_default();
        if !is_future_outlier {
            let max_ts = prev_max.map_or(effective_ts, |p| p.max(effective_ts));
            let cutoff = max_ts.saturating_sub(JUDGE_PROBE_WINDOW_SECS);
            list.retain(|(ts, _, _)| *ts >= cutoff);
        }
        while list.len() >= MAX_PROBE_ENTRIES_PER_BUCKET {
            list.pop_front();
        }
        list.push_back((
            effective_ts,
            action_digest.to_owned(),
            ev.event_id.to_owned(),
        ));

        let distinct_digests: BTreeSet<&str> = list.iter().map(|(_, d, _)| d.as_str()).collect();
        if list.len() >= JUDGE_PROBE_MIN_EVENTS && distinct_digests.len() >= JUDGE_PROBE_MIN_DIGESTS
        {
            emit_builtin_finding(
                state,
                ev,
                &BuiltinFindingSpec {
                    rule_id: "grdr.det.judge-probing",
                    class: FindingClass::Tamper,
                    severity: FindingSeverity::High,
                    title: "Probing of model-backed judge provider detected",
                    summary: "Five model objections within 10 minutes across >=3 distinct action digests.",
                },
                tool_class,
                out,
            );
        }
    }
}

pub(super) fn emit_builtin_finding(
    state: &mut DetectState,
    ev: &EventView<'_>,
    spec: &BuiltinFindingSpec<'_>,
    dedup_scope: &str,
    out: &mut DetectOutput,
) {
    let bucket = ev.observed_at.as_second().checked_div(60).unwrap_or(0);
    let grp = if dedup_scope.is_empty() {
        ev.root_session_id.to_owned()
    } else {
        format!(
            "{}:{}:{}:{}",
            ev.root_session_id.len(),
            ev.root_session_id,
            dedup_scope.len(),
            dedup_scope
        )
    };
    let dedup_key = compute_scoped_dedup_key(ev.organisation_id, spec.rule_id, &grp, bucket);
    if !insert_bounded_dedup_key(state, dedup_key.clone()) {
        return;
    }
    out.dedup_keys.push(dedup_key.clone());
    out.findings.push(Finding {
        id: format!("fnd_{}", dedup_key.get(..24).unwrap_or(&dedup_key)),
        session_id: ev.session_id.to_owned(),
        device_id: ev.device_id.to_owned(),
        device_name: ev.device_name.to_owned(),
        agent_name: ev.agent_name.to_owned(),
        class: spec.class,
        finding_class_other: None,
        severity: spec.severity,
        lifecycle: FindingLifecycle::Open,
        rule_id: Some(spec.rule_id.to_owned()),
        title: spec.title.to_owned(),
        summary: spec.summary.to_owned(),
        target: ev.target.to_owned(),
        detected_at: ev.observed_at,
    });
}

pub(super) fn insert_bounded_dedup_key(state: &mut DetectState, key: String) -> bool {
    if state.emitted_dedup_keys.contains(&key) {
        return false;
    }
    while state.emitted_dedup_keys.len() >= MAX_ENGINE_DEDUP_KEYS {
        if let Some(oldest) = state.emitted_dedup_order.pop_front() {
            state.emitted_dedup_keys.remove(&oldest);
        } else {
            break;
        }
    }
    state.emitted_dedup_order.push_back(key.clone());
    state.emitted_dedup_keys.insert(key)
}

pub(super) fn deterministic_id(kind: &str, device_id: &str, suffix: &str) -> String {
    let mut buf = Vec::new();
    for p in [kind.as_bytes(), device_id.as_bytes(), suffix.as_bytes()] {
        let len = u32::try_from(p.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(p);
    }
    let digest = domain_sha256_digest("grdr.detect.id.v1", &buf);
    let hex = encode_lower_hex(&digest);
    hex.get(..20).unwrap_or(&hex).to_owned()
}
