// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Replays PolicyRules across historical sequences (4-bucket classification & prompt budgets).

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::{Authorizer, Decision, PolicySet};
use grdr_model::eval::{FourBucketSummary, ReplayBucket, promotion_gate_passes};
use grdr_model::{
    ActionAttempt, ActionClass, CommandParseStatus, Mode, PolicyPack, PolicyRule, ReplaySample,
    ReplaySummary, Verdict,
};

use super::PolicyError;
use super::caps::cached_limits;
use super::compiler::compile_single_rule_for_replay;
use super::lint::compute_cedar_reads;
use super::render::render_rule_cedar;
use super::request::{ContextField, RequestBuildOptions, build_cedar_request_with_options};
use crate::analyze::classify_target;
use crate::session::SessionRuleState;

const MAX_REPLAY_SAMPLES: usize = 25;
const MAX_REPLAY_EVALS: usize = 50_000;
const MIN_REPLAY_WATCH_DAYS: u32 = 7;

struct ReplayEvalOutcome {
    matched: bool,
    uncertain: bool,
}

#[derive(Debug, Clone)]
pub struct ReplayAttemptRecord {
    pub seq: u64,
    pub attempt: ActionAttempt,
    pub absent_fields: BTreeSet<ContextField>,
    pub pending_fields: BTreeSet<ContextField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourBucketReplayResult {
    pub rule_id: String,
    pub candidate_mode: Mode,
    pub summary: FourBucketSummary,
    pub bucket_by_attempt_id: BTreeMap<String, ReplayBucket>,
    pub samples: Vec<ReplaySample>,
}

pub fn replay_rule(
    attempts: &[ActionAttempt],
    rule: &PolicyRule,
    candidate_mode: Mode,
) -> ReplaySummary {
    let current_compiled = compile_single_rule_for_replay(rule, rule.mode);
    let candidate_compiled = compile_single_rule_for_replay(rule, candidate_mode);
    let current_err = current_compiled.is_err();
    let candidate_err = candidate_compiled.is_err();
    let current_set = current_compiled.ok().flatten();
    let candidate_set = candidate_compiled.ok().flatten();
    let authorizer = Authorizer::new();

    let mut total_scanned: u64 = 0;
    let mut matched: u64 = 0;
    let mut would_ask: u64 = 0;
    let mut would_block: u64 = 0;
    let mut not_matched: u64 = 0;
    let mut samples = Vec::new();
    let replay_pack = single_rule_replay_pack(rule, candidate_mode);
    let empty_reads = BTreeSet::new();

    for attempt in attempts {
        total_scanned = total_scanned.saturating_add(1);

        let current_hit = if current_err && rule.mode != Mode::Off {
            true
        } else {
            current_set.as_ref().is_some_and(|set| {
                eval_replay_set(
                    &authorizer,
                    set,
                    attempt,
                    &replay_pack,
                    &empty_reads,
                    None,
                    &RequestBuildOptions::default(),
                )
                .map_or(true, |o| o.matched)
            })
        };
        let candidate_hit = if candidate_err && candidate_mode != Mode::Off {
            true
        } else {
            candidate_set.as_ref().is_some_and(|set| {
                eval_replay_set(
                    &authorizer,
                    set,
                    attempt,
                    &replay_pack,
                    &empty_reads,
                    None,
                    &RequestBuildOptions::default(),
                )
                .map_or(true, |o| o.matched)
            })
        };

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

pub fn replay_pack_4bucket(
    records: &[ReplayAttemptRecord],
    rule: &PolicyRule,
    candidate_mode: Mode,
    watched_days: u32,
    developer_days: u32,
) -> Result<FourBucketReplayResult, PolicyError> {
    if records.len() > MAX_REPLAY_EVALS {
        return Err(PolicyError::ReplayBudgetExceeded {
            rule_id: rule.id.clone(),
            detail: format!(
                "record count {} exceeds replay budget {MAX_REPLAY_EVALS}",
                records.len()
            ),
        });
    }
    let limits = cached_limits().ok_or_else(|| PolicyError::ValidationFailed {
        rule_id: rule.id.clone(),
        detail: "embedded policy limits unavailable".into(),
    })?;
    let candidate_set = compile_single_rule_for_replay(rule, candidate_mode)?;
    let rendered;
    let source = match rule.cedar.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(raw) => raw,
        None => {
            rendered = render_rule_cedar(rule);
            &rendered
        }
    };
    let rule_reads = compute_cedar_reads(source);
    let authorizer = Authorizer::new();
    let replay_pack = single_rule_replay_pack(rule, candidate_mode);

    let mut ordered: Vec<&ReplayAttemptRecord> = records.iter().collect();
    ordered.sort_by_key(|r| r.seq);

    let mut sessions: BTreeMap<String, SessionRuleState> = BTreeMap::new();
    let mut bucket_by_attempt_id = BTreeMap::new();
    let mut matched: u64 = 0;
    let mut almost_matched: u64 = 0;
    let mut not_matched: u64 = 0;
    let mut not_evaluable: u64 = 0;
    let mut opaque_execs: u32 = 0;
    let mut total_execs: u32 = 0;
    let mut samples = Vec::new();
    let mut prompts_per_day: BTreeMap<String, u32> = BTreeMap::new();

    for record in ordered {
        let attempt = &record.attempt;
        let analysis = classify_target(attempt.action_class, &attempt.target);
        if attempt.action_class == ActionClass::Exec {
            total_execs = total_execs.saturating_add(1);
            if analysis.command_status != CommandParseStatus::Resolved {
                opaque_execs = opaque_execs.saturating_add(1);
            }
        }
        let session_state = sessions
            .entry(attempt.session_id.clone())
            .or_insert_with(|| SessionRuleState::new(attempt.session_id.clone()));

        let opts = RequestBuildOptions {
            extra_absent: record.absent_fields.clone(),
            extra_pending: record.pending_fields.clone(),
            ..Default::default()
        };

        let eval_outcome = match candidate_set.as_ref() {
            Some(set) => eval_replay_set(
                &authorizer,
                set,
                attempt,
                &replay_pack,
                &rule_reads,
                Some(session_state),
                &opts,
            ),
            None => Ok(ReplayEvalOutcome {
                matched: false,
                uncertain: !rule_reads.is_disjoint(&record.absent_fields)
                    || !rule_reads.is_disjoint(&record.pending_fields),
            }),
        };

        let bucket = match eval_outcome {
            Err(_) => {
                not_evaluable = not_evaluable.saturating_add(1);
                ReplayBucket::NotEvaluable
            }
            Ok(outcome) if outcome.uncertain => {
                not_evaluable = not_evaluable.saturating_add(1);
                ReplayBucket::NotEvaluable
            }
            Ok(outcome) if outcome.matched => {
                matched = matched.saturating_add(1);
                if candidate_mode == Mode::Ask {
                    let dev_id = attempt
                        .user_id
                        .as_deref()
                        .filter(|u| !u.is_empty())
                        .unwrap_or(&attempt.device_id);
                    let day_bucket = attempt.timestamp.as_second().div_euclid(86_400);
                    let dev_day_key = format!("{dev_id}:{day_bucket}");
                    let count = prompts_per_day.entry(dev_day_key).or_insert(0);
                    *count = count.saturating_add(1);
                }
                if samples.len() < MAX_REPLAY_SAMPLES {
                    samples.push(ReplaySample {
                        attempt_id: attempt.id.clone(),
                        session_id: attempt.session_id.clone(),
                        agent_name: attempt.agent_name.clone(),
                        action_class: attempt.action_class,
                        target: attempt.target.clone(),
                        current_verdict: verdict_for_mode(rule.mode),
                        candidate_verdict: verdict_for_mode(candidate_mode),
                        timestamp: attempt.timestamp,
                    });
                }
                ReplayBucket::Matched
            }
            Ok(_)
                if rule.matcher.action_classes.contains(&attempt.action_class)
                    && !rule.matcher.target_contains.is_empty()
                    && is_near_target_match(&attempt.target, &rule.matcher.target_contains) =>
            {
                almost_matched = almost_matched.saturating_add(1);
                ReplayBucket::AlmostMatched
            }
            Ok(_) => {
                not_matched = not_matched.saturating_add(1);
                ReplayBucket::NotMatched
            }
        };

        let sim_verdict = if bucket == ReplayBucket::Matched {
            verdict_for_mode(candidate_mode)
        } else {
            Verdict::Allow
        };
        session_state.record_outcome(attempt, &analysis, sim_verdict);
        bucket_by_attempt_id.insert(attempt.id.clone(), bucket);
    }

    let mut daily_rates: Vec<u32> = prompts_per_day.values().copied().collect();
    let total_dev_days = usize::try_from(developer_days)
        .unwrap_or(MAX_REPLAY_EVALS)
        .min(MAX_REPLAY_EVALS);
    while daily_rates.len() < total_dev_days {
        daily_rates.push(0);
    }
    daily_rates.sort_unstable();
    let median = daily_rates.get(daily_rates.len() / 2).copied().unwrap_or(0);
    let p95 = if daily_rates.is_empty() {
        0
    } else {
        let p95_idx = daily_rates
            .len()
            .saturating_mul(95)
            .div_ceil(100)
            .saturating_sub(1);
        daily_rates.get(p95_idx).copied().unwrap_or(0)
    };

    let opaque_pct = if total_execs == 0 {
        0.0
    } else {
        (f64::from(opaque_execs) * 100.0) / f64::from(total_execs)
    };
    let opaque_ok = opaque_pct <= limits.endpoint.prompts.max_opaque_pct;
    let dev_days_ok = !records.is_empty() && developer_days > 0;

    let promotion_ready = dev_days_ok
        && opaque_ok
        && watched_days >= MIN_REPLAY_WATCH_DAYS
        && promotion_gate_passes(
            watched_days,
            median,
            p95,
            limits.endpoint.prompts.median_per_dev_day,
            limits.endpoint.prompts.p95_per_dev_day,
        );

    Ok(FourBucketReplayResult {
        rule_id: rule.id.clone(),
        candidate_mode,
        summary: FourBucketSummary {
            matched,
            almost_matched,
            not_matched,
            not_evaluable,
            watch_days: watched_days,
            median_prompts_per_dev_day: median,
            p95_prompts_per_dev_day: p95,
            promotion_ready,
        },
        bucket_by_attempt_id,
        samples,
    })
}

fn single_rule_replay_pack(rule: &PolicyRule, candidate_mode: Mode) -> PolicyPack {
    let mut r = rule.clone();
    r.enabled = true;
    r.mode = if candidate_mode == Mode::Off {
        Mode::Watch
    } else {
        candidate_mode
    };
    PolicyPack {
        id: "replay".into(),
        name: "Replay".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "replay".into(),
        rules: vec![r],
        key_id: None,
        signature: None,
    }
}

fn eval_replay_set(
    authorizer: &Authorizer,
    set: &PolicySet,
    attempt: &ActionAttempt,
    replay_pack: &PolicyPack,
    rule_reads: &BTreeSet<ContextField>,
    session_state: Option<&SessionRuleState>,
    opts: &RequestBuildOptions,
) -> Result<ReplayEvalOutcome, PolicyError> {
    let pack_slice = std::slice::from_ref(replay_pack);
    let built = build_cedar_request_with_options(
        attempt,
        pack_slice,
        &[],
        &[],
        session_state,
        opts,
        attempt.timestamp,
    )?;
    let uncertain =
        !rule_reads.is_disjoint(&built.absent) || !rule_reads.is_disjoint(&built.pending);
    let primary_resp = authorizer.is_authorized(&built.request, set, &built.entities);
    if primary_resp.diagnostics().errors().next().is_some() {
        return Err(PolicyError::CompileFailed {
            rule_id: "replay".into(),
            detail: "Cedar evaluation error on replay request".into(),
        });
    }
    let primary_deny = primary_resp.decision() == Decision::Deny;
    let df_deny = if let Some(ref df) = built.data_flow_request {
        let df_resp = authorizer.is_authorized(df, set, &built.entities);
        if df_resp.diagnostics().errors().next().is_some() {
            return Err(PolicyError::CompileFailed {
                rule_id: "replay".into(),
                detail: "Cedar evaluation error on replay data.flow request".into(),
            });
        }
        df_resp.decision() == Decision::Deny
    } else {
        false
    };
    Ok(ReplayEvalOutcome {
        matched: primary_deny || df_deny,
        uncertain,
    })
}

fn is_near_target_match(target: &str, patterns: &[String]) -> bool {
    let norm = target.replace('\\', "/").to_ascii_lowercase();
    patterns.iter().any(|pat| {
        let p = pat.trim_matches('/').to_ascii_lowercase();
        let stem = p.split('.').next().unwrap_or(&p);
        !stem.is_empty() && norm.contains(stem)
    })
}

fn verdict_for_mode(mode: Mode) -> Verdict {
    match mode {
        Mode::Off | Mode::Watch => Verdict::Allow,
        Mode::Ask => Verdict::StepUp,
        Mode::Block => Verdict::Deny,
    }
}
