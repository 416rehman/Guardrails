// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `SigmaDetectionEngine` implementing `DetectionEngine` with bounded state, precompiled rules,
//! built-in telemetry tamper/gap detectors, and deterministic SHA-256 deduplication (`D-09`, `D-54`).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use jiff::Timestamp;

use grdr_model::{Finding, FindingClass, FindingLifecycle, FindingSeverity, Mode};
use grdr_schema::limits::load_embedded_limits;

use crate::detect::builtins::{
    BuiltinFindingSpec, deterministic_id, emit_builtin_finding, evaluate_builtin_rules,
    insert_bounded_dedup_key,
};
use crate::detect::corr::{
    compute_scoped_dedup_key, correlation_container_key, derive_hit_rule_key,
    record_and_evaluate_correlation,
};
use crate::detect::eval::{
    CompiledSigmaRule, compile_sigma_rule, evaluate_compiled_rule, scope_permits_rule,
};
use crate::detect::response::{ResponseBreakerState, ResponseExecutor, ResponsePlanRequest};
use crate::detect::sigma::parse_sigma_rule_for_verified_pack;
use crate::detect::types::{
    DEFAULT_DETECT_LAG_BACKLOG_EVENTS, DEFAULT_DETECT_LAG_MS, DetectError, DetectOutput,
    DetectState, DetectionEngine, EventView, HostProfile, LoadReport,
    MAX_CORRELATION_ENTRIES_PER_LINEAGE, MAX_ENGINE_DEDUP_KEYS, MAX_ENGINE_LINEAGES,
    MAX_GROUP_KEYS_PER_LINEAGE, MAX_GROUP_KEYS_PER_RULE, MAX_PROBE_BUCKETS, RuleOrigin, SigmaRule,
    SkippedRule, VerifiedDetectionContent,
};

const JUDGE_PROBE_WINDOW_SECS: i64 = 600;
const BYTES_PER_MIB: usize = 1_048_576;
const DEFAULT_SINGLE_DEDUP_BUCKET_SECS: i64 = 60;

pub struct SigmaDetectionEngine {
    rules: Vec<CompiledSigmaRule>,
    loaded_ids: BTreeSet<String>,
    pack_mode: Mode,
    host: HostProfile,
    state: DetectState,
    executor: ResponseExecutor,
    fleet_active_devices: usize,
    max_rule_timespan_secs: i64,
}

fn detections_max_mb_cached() -> usize {
    static MAX_MB: OnceLock<usize> = OnceLock::new();
    *MAX_MB.get_or_init(|| {
        load_embedded_limits()
            .ok()
            .and_then(|l| usize::try_from(l.packs.detections_max_mb).ok())
            .unwrap_or(4)
    })
}

impl SigmaDetectionEngine {
    pub fn loaded_rules(&self) -> impl Iterator<Item = &SigmaRule> {
        self.rules.iter().map(|compiled| &compiled.rule)
    }

    pub fn set_fleet_active_devices(&mut self, count: usize) {
        self.fleet_active_devices = count.max(1);
    }

    pub fn record_backlog_metrics(
        &self,
        queued_events: usize,
        lag_ms: i64,
        observed_at: Timestamp,
        out: &mut DetectOutput,
    ) {
        if queued_events > DEFAULT_DETECT_LAG_BACKLOG_EVENTS || lag_ms > DEFAULT_DETECT_LAG_MS {
            out.coverage_gaps.push("detect-lag".into());
            out.findings.push(Finding {
                id: format!(
                    "fnd_{}",
                    deterministic_id(
                        "detect-lag",
                        &self.host.device_id,
                        &queued_events.to_string(),
                    )
                ),
                session_id: "system".into(),
                device_id: self.host.device_id.clone(),
                device_name: self.host.device_name.clone(),
                agent_name: "grdr-engine".into(),
                class: FindingClass::CoverageGap,
                finding_class_other: None,
                severity: FindingSeverity::Medium,
                lifecycle: FindingLifecycle::Open,
                rule_id: Some("health.coverage.detect-lag".into()),
                title: "Detection pipeline backlog exceeded target".into(),
                summary: format!("queued={queued_events}, lag_ms={lag_ms}"),
                target: "detect-lag".into(),
                detected_at: observed_at,
            });
        }
    }

    fn process_matched_rule(
        &mut self,
        compiled: &CompiledSigmaRule,
        ev: &EventView<'_>,
        out: &mut DetectOutput,
    ) {
        let rule = &compiled.rule;
        let Some(corr) = &rule.correlation else {
            let bucket = ev
                .observed_at
                .as_second()
                .checked_div(DEFAULT_SINGLE_DEDUP_BUCKET_SECS)
                .unwrap_or(0);
            let grp = format!(
                "{}:{}:{}:{}",
                ev.session_id.len(),
                ev.session_id,
                ev.target.len(),
                ev.target
            );
            let dedup_key =
                compute_scoped_dedup_key(ev.organisation_id, &rule.rule_id, &grp, bucket);
            if insert_bounded_dedup_key(&mut self.state, dedup_key.clone()) {
                self.emit_rule_finding(compiled, ev, &dedup_key, out);
            }
            return;
        };

        let container_key = correlation_container_key(corr, ev);
        if !self.state.by_lineage.contains_key(&container_key)
            && self.state.by_lineage.len() >= MAX_ENGINE_LINEAGES
            && let Some(oldest) = self
                .state
                .by_lineage
                .iter()
                .min_by_key(|(_, lin)| {
                    lin.entries
                        .iter()
                        .map(|e| e.observed_sec)
                        .max()
                        .unwrap_or(i64::MIN)
                })
                .map(|(k, _)| k.clone())
        {
            self.state.by_lineage.remove(&oldest);
        }
        let hit_rule_key = derive_hit_rule_key(compiled, ev);
        let outcome = {
            let lineage_state = self
                .state
                .by_lineage
                .entry(container_key.clone())
                .or_default();
            record_and_evaluate_correlation(lineage_state, &rule.rule_id, hit_rule_key, corr, ev)
        };
        if outcome.overflow_triggered_now {
            out.coverage_gaps.push("detect.state-overflow".into());
            emit_builtin_finding(
                &mut self.state,
                ev,
                &BuiltinFindingSpec {
                    rule_id: "detect.state-overflow",
                    class: FindingClass::CoverageGap,
                    severity: FindingSeverity::Medium,
                    title: "Correlation state capacity reached; evicted oldest group key",
                    summary: "Rule reached 256 group keys or 4096 lineage entries; oldest key evicted.",
                },
                &format!(
                    "{}:{}:{}:{}",
                    rule.rule_id.len(),
                    rule.rule_id,
                    container_key.len(),
                    container_key
                ),
                out,
            );
        }
        if outcome.matched {
            let win = i64::try_from(corr.timespan_secs.max(1)).unwrap_or(1);
            let bucket = ev.observed_at.as_second().checked_div(win).unwrap_or(0);
            let dedup_key = compute_scoped_dedup_key(
                ev.organisation_id,
                &rule.rule_id,
                &outcome.group_key,
                bucket,
            );
            if insert_bounded_dedup_key(&mut self.state, dedup_key.clone()) {
                self.emit_rule_finding(compiled, ev, &dedup_key, out);
            }
        }
    }

    fn emit_rule_finding(
        &mut self,
        compiled: &CompiledSigmaRule,
        ev: &EventView<'_>,
        dedup_key: &str,
        out: &mut DetectOutput,
    ) {
        let rule = &compiled.rule;
        out.dedup_keys.push(dedup_key.to_owned());
        out.findings.push(Finding {
            id: format!("fnd_{}", dedup_key.get(..24).unwrap_or(dedup_key)),
            session_id: ev.session_id.to_owned(),
            device_id: ev.device_id.to_owned(),
            device_name: ev.device_name.to_owned(),
            agent_name: ev.agent_name.to_owned(),
            class: rule.finding_class,
            finding_class_other: rule.finding_class_other.clone(),
            severity: rule.severity,
            lifecycle: FindingLifecycle::Open,
            rule_id: Some(rule.rule_id.clone()),
            title: rule.title.clone(),
            summary: format!("row={} version={}", rule.row, rule.version),
            target: ev.target.to_owned(),
            detected_at: ev.observed_at,
        });

        if let Some(binding) = &rule.response {
            let effective_ceiling = rule.ceiling.clamp_by_origin(rule.status, rule.origin);
            let external_remediate_approved = self
                .host
                .remediate_approvers
                .get(&rule.rule_id)
                .is_some_and(|approver| {
                    let trimmed = approver.trim();
                    !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case(rule.author.trim())
                });
            if let Ok(plan) = self.executor.evaluate_binding(&ResponsePlanRequest {
                rule_id: &rule.rule_id,
                dedup_key,
                binding,
                ceiling: effective_ceiling,
                pack_mode: self.pack_mode,
                device_id: ev.device_id,
                fleet_active_devices: self.fleet_active_devices,
                now_sec: ev.observed_at.as_second(),
                external_remediate_approved,
            }) {
                if plan.breaker_state == ResponseBreakerState::TrippedFleetShare {
                    out.coverage_gaps
                        .push("response.fleet-share-breaker".into());
                }
                out.response_intents.push(plan.intent);
            }
        }
    }
}

impl DetectionEngine for SigmaDetectionEngine {
    fn load(
        content: &VerifiedDetectionContent,
        host: &HostProfile,
    ) -> Result<(Self, LoadReport), DetectError> {
        let max_mb = detections_max_mb_cached();
        let max_bytes = max_mb.saturating_mul(BYTES_PER_MIB);
        let total_bytes: usize = content.raw_rules_yaml.iter().map(String::len).sum();
        if total_bytes > max_bytes {
            return Err(DetectError::InvalidRule(format!(
                "detection pack size ({total_bytes} bytes) exceeds schema limit {max_bytes} bytes"
            )));
        }

        let mut rules = Vec::new();
        let mut loaded_ids = BTreeSet::new();
        let mut report = LoadReport::default();
        let mut max_span: i64 = 3_600;
        let is_official_pack = content.pack_id == "grdr.det.core"
            || content.pack_id == "grdr.det.experimental"
            || content.pack_id == "grdr.det.tripwires";

        for (idx, raw) in content.raw_rules_yaml.iter().enumerate() {
            match parse_sigma_rule_for_verified_pack(raw, is_official_pack) {
                Ok(mut rule) => {
                    if rule.status == crate::detect::types::SigmaStatus::Deprecated {
                        report.skipped_rules.push(SkippedRule {
                            rule_id: rule.rule_id,
                            reason: "could not evaluate: deprecated rules are replay-only".into(),
                        });
                        continue;
                    }
                    if !rule.origin_declared
                        && is_official_pack
                        && rule.author == "The Guardrails ADR Authors"
                    {
                        rule.origin = RuleOrigin::Official;
                    }
                    if !scope_permits_rule(host.scope, rule.scope) {
                        report.skipped_rules.push(SkippedRule {
                            rule_id: rule.rule_id,
                            reason: "could not evaluate: host placement scope mismatch".into(),
                        });
                        continue;
                    }
                    if !loaded_ids.insert(rule.rule_id.clone()) {
                        report.skipped_rules.push(SkippedRule {
                            rule_id: rule.rule_id,
                            reason: "could not evaluate: duplicate rule_id".into(),
                        });
                        continue;
                    }
                    match compile_sigma_rule(&rule, host) {
                        Ok(compiled) => {
                            if let Some(corr) = &compiled.rule.correlation {
                                let span_i64 =
                                    i64::try_from(corr.timespan_secs).unwrap_or(i64::MAX);
                                max_span = max_span.max(span_i64);
                            }
                            report.loaded_rules.push(compiled.rule.rule_id.clone());
                            rules.push(compiled);
                        }
                        Err(err) => {
                            loaded_ids.remove(&rule.rule_id);
                            report.skipped_rules.push(SkippedRule {
                                rule_id: rule.rule_id,
                                reason: format!("could not evaluate: {err}"),
                            });
                        }
                    }
                }
                Err(err) => {
                    report.skipped_rules.push(SkippedRule {
                        rule_id: format!("rule-index-{idx}"),
                        reason: format!("could not evaluate: {err}"),
                    });
                }
            }
        }

        Ok((
            Self {
                rules,
                loaded_ids,
                pack_mode: content.pack_mode,
                host: host.clone(),
                state: DetectState::default(),
                executor: ResponseExecutor::default(),
                fleet_active_devices: 1,
                max_rule_timespan_secs: max_span,
            },
            report,
        ))
    }

    fn on_event(&mut self, ev: &EventView<'_>, out: &mut DetectOutput) {
        evaluate_builtin_rules(
            &mut self.state,
            &self.loaded_ids,
            self.pack_mode != Mode::Off,
            ev,
            out,
        );
        if self.pack_mode == Mode::Off {
            return;
        }
        let matching_indices: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, compiled)| evaluate_compiled_rule(compiled, ev))
            .map(|(i, _)| i)
            .collect();
        for idx in matching_indices {
            if let Some(compiled) = self.rules.get(idx).cloned() {
                self.process_matched_rule(&compiled, ev, out);
            }
        }
    }

    fn on_tick(&mut self, now: Timestamp, _out: &mut DetectOutput) {
        let now_sec = now.as_second();
        let cutoff = now_sec.saturating_sub(self.max_rule_timespan_secs);
        self.state.by_lineage.retain(|_, lineage| {
            lineage.entries.retain(|e| e.observed_sec >= cutoff);
            !lineage.entries.is_empty()
        });
        let probe_cutoff = now_sec.saturating_sub(JUDGE_PROBE_WINDOW_SECS);
        self.state.judge_probe_history.retain(|_, list| {
            list.retain(|(ts, _, _)| *ts >= probe_cutoff);
            !list.is_empty()
        });
        self.state
            .judge_probe_pending_future_sec
            .retain(|k, _| self.state.judge_probe_history.contains_key(k));
    }

    fn snapshot(&self) -> DetectState {
        let mut snap = self.state.clone();
        snap.breaker_hourly_devices = self.executor.snapshot_devices();
        snap
    }

    fn restore(&mut self, s: &DetectState) -> Result<(), DetectError> {
        const MAX_PROBE_ENTRIES_PER_BUCKET: usize = 128;
        if s.by_lineage.len() > MAX_ENGINE_LINEAGES
            || s.emitted_dedup_keys.len() > MAX_ENGINE_DEDUP_KEYS
            || s.emitted_dedup_order.len() != s.emitted_dedup_keys.len()
            || s.judge_probe_history.len() > MAX_PROBE_BUCKETS
            || s.judge_probe_pending_future_sec.len() > MAX_PROBE_BUCKETS
            || s.hook_last_seen_sec.len() > MAX_ENGINE_LINEAGES
            || s.sensor_exec_without_hook.len() > MAX_ENGINE_LINEAGES
            || s.sensor_exec_last_seen_sec.len() > MAX_ENGINE_LINEAGES
        {
            return Err(DetectError::StateRestore(
                "restored engine state exceeds global map bounds".into(),
            ));
        }
        if !s
            .judge_probe_pending_future_sec
            .keys()
            .all(|k| s.judge_probe_history.contains_key(k))
            || s.sensor_exec_last_seen_sec.len() != s.sensor_exec_without_hook.len()
            || !s
                .sensor_exec_last_seen_sec
                .keys()
                .all(|k| s.sensor_exec_without_hook.contains_key(k))
        {
            return Err(DetectError::StateRestore(
                "restored companion map invariant mismatch".into(),
            ));
        }
        let order_set: BTreeSet<&str> = s.emitted_dedup_order.iter().map(String::as_str).collect();
        if order_set.len() != s.emitted_dedup_keys.len()
            || !s
                .emitted_dedup_keys
                .iter()
                .all(|k| order_set.contains(k.as_str()))
        {
            return Err(DetectError::StateRestore(
                "restored dedup key/order invariant mismatch".into(),
            ));
        }
        if s.judge_probe_history
            .values()
            .any(|v| v.is_empty() || v.len() > MAX_PROBE_ENTRIES_PER_BUCKET)
        {
            return Err(DetectError::StateRestore(
                "restored judge probe bucket exceeds entry bound".into(),
            ));
        }
        for lineage in s.by_lineage.values() {
            if lineage.entries.len() > MAX_CORRELATION_ENTRIES_PER_LINEAGE
                || lineage.group_keys_by_rule.len() > MAX_GROUP_KEYS_PER_LINEAGE
                || lineage.overflow_emitted_rules.len() > MAX_GROUP_KEYS_PER_LINEAGE
                || !lineage
                    .overflow_emitted_rules
                    .iter()
                    .all(|r| lineage.group_keys_by_rule.contains_key(r))
                || lineage
                    .group_keys_by_rule
                    .values()
                    .any(|keys| keys.len() > MAX_GROUP_KEYS_PER_RULE)
            {
                return Err(DetectError::StateRestore(
                    "restored correlation state exceeds lineage bounds".into(),
                ));
            }
        }
        let mut restored_exec = self.executor.clone();
        restored_exec.restore_devices(&s.breaker_hourly_devices)?;
        self.state = s.clone();
        self.executor = restored_exec;
        Ok(())
    }
}
