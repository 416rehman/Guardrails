// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Evaluation loop, bounded MODIFY retries, caching, and grant consumption for `Engine`.

use grdr_model::eval::{CacheScope, ObligationKind, add_seconds};
use grdr_model::{ActionAttempt, Grant, GrantScope, Mode, TimelockAllowance, Verdict};
use jiff::Timestamp;

use super::caps::{Entropy, Obligation, default_control_point_caps};
use super::engine::{CachedVerdictEntry, Engine, MAX_SPENT_TOMBSTONES};
use super::engine_snapshot::{build_receipt, parse_note_epoch};
use super::engine_types::{EngineOutput, verdict_cache_key};
use super::matrix::{MAX_MODIFY_RETRIES, degrade_verdict};
use super::request::{RequestBuildOptions, SessionFreezeState, build_cedar_request_with_options};
use super::verdict::{VerdictEvalConfig, resolve_verdict};

const CACHE_TTL_SECONDS: i64 = 60;
const MAX_CACHE_ENTRIES: usize = 1024;

impl Engine {
    pub(crate) fn step_evaluate(
        &mut self,
        attempt: ActionAttempt,
        mut options: RequestBuildOptions,
        host_deadline_ms: Option<u64>,
        entropy: &mut dyn Entropy,
        now: Timestamp,
    ) -> EngineOutput {
        let session_frozen = self.frozen_sessions.contains(&attempt.session_id);
        if session_frozen {
            options.session_freeze = SessionFreezeState::Frozen;
        }
        let label_epoch = self
            .session_label_epochs
            .get(&attempt.session_id)
            .copied()
            .unwrap_or(0);
        options.label_epoch = label_epoch;
        // Include event_seq in cache keys only when a rule reads label_epoch dynamically.
        let session_event_seq = if self.compiled.reads_label_epoch {
            self.sessions
                .get(&attempt.session_id)
                .map_or(0, |s| s.event_seq)
        } else {
            0
        };
        let cache_key = verdict_cache_key(
            &self.compiled.effective_hash,
            label_epoch,
            session_event_seq,
            &attempt,
            &options,
        );
        let ks_active =
            self.kill_switch
                .is_active_for(&attempt.session_id, &attempt.device_id, now);
        if !ks_active
            && !session_frozen
            && let Some(cached) = self.verdict_cache.get(&cache_key).cloned()
            && cached.expires_at > now
            && cached.scope != CacheScope::None
        {
            self.cache_lru_counter = self.cache_lru_counter.saturating_add(1);
            if let Some(entry) = self.verdict_cache.get_mut(&cache_key) {
                entry.last_used_seq = self.cache_lru_counter;
            }
            self.record_session_outcome(&attempt, cached.verdict, label_epoch, now);
            let receipt = build_receipt(
                &attempt,
                cached.verdict,
                cached.would_be,
                cached.rule_id,
                cached.pack_id,
                cached.mode_applied,
                None,
                cached.reason,
                cached.next_step,
                now,
            );
            return EngineOutput::Evaluated {
                receipt: Box::new(receipt),
                executed_verb: cached.executed_verb,
                obligations: vec![Obligation {
                    kind: grdr_model::eval::ObligationKind::Receipt,
                    rule_id: None,
                    detail: "Record signed DecisionReceipt.".into(),
                }],
                retry_token: None,
                modified_attempt: None,
                cache_hit: true,
                session_state_seq: self.session_state_seq,
            };
        }

        let active_grants = self.collect_active_grants(&attempt, label_epoch, now);
        let eval_bundle = if ks_active {
            match self.compile_for_state(&attempt.session_id, &attempt.device_id, now) {
                Ok(b) => Some(b),
                Err(_) => {
                    return self.finish_fail_closed(
                        attempt,
                        "policy.compile-error",
                        "system",
                        "Bundle compilation failed during evaluation (fail-closed).",
                        "Inspect policy rules and retry.",
                        now,
                    );
                }
            }
        } else {
            None
        };
        let bundle_ref = eval_bundle.as_ref().unwrap_or(&self.compiled);
        let caps = default_control_point_caps(attempt.control_point, host_deadline_ms);

        let mut working_attempt = attempt.clone();
        let mut modify_attempts: u8 = 0;
        let mut first_modify_out: Option<super::verdict::VerdictEvalOutput> = None;
        let mut resolved = loop {
            let built = match build_cedar_request_with_options(
                &working_attempt,
                &self.effective_packs,
                &bundle_ref.active_rules,
                &active_grants,
                self.sessions.get(&attempt.session_id),
                &options,
                now,
            ) {
                Ok(req) => req,
                Err(_) => {
                    return self.finish_fail_closed(
                        attempt,
                        "policy.request-error",
                        "system",
                        "Policy request construction failed (fail-closed).",
                        "Inspect request attributes and retry.",
                        now,
                    );
                }
            };
            let cfg = VerdictEvalConfig {
                host_profile: self.bundle.host_profile,
                device_max_grade: self.bundle.device_max_grade,
                timelock_enabled: self.bundle.user_timelock_enabled,
                observer: options.observer,
                caps: caps.clone(),
                modify_attempts,
            };
            let out = match resolve_verdict(&working_attempt, bundle_ref, &built, &cfg, entropy) {
                Ok(res) => res,
                Err(_) => {
                    return self.finish_fail_closed(
                        attempt,
                        "policy.eval-error",
                        "system",
                        "Policy evaluation failed (fail-closed).",
                        "Inspect rule diagnostics before retrying.",
                        now,
                    );
                }
            };
            if out.verdict == Verdict::Allow
                && let Some(mut mod_out) = first_modify_out.take()
            {
                if let Some(ref mut tr) = mod_out.transform {
                    tr.rewritten_target = working_attempt.target.clone();
                }
                mod_out.hit_session_rule |= out.hit_session_rule;
                for ob in out.obligations {
                    if ob.kind != ObligationKind::Receipt && !mod_out.obligations.contains(&ob) {
                        mod_out.obligations.push(ob);
                    }
                }
                break mod_out;
            }
            if out.verdict == Verdict::Modify
                && let Some(ref tr) = out.transform
                && tr.rewritten_target != working_attempt.target
                && modify_attempts < MAX_MODIFY_RETRIES
            {
                working_attempt.target = tr.rewritten_target.clone();
                modify_attempts = modify_attempts.saturating_add(1);
                if first_modify_out.is_none() {
                    first_modify_out = Some(out);
                } else if let Some(ref mut prev) = first_modify_out
                    && let Some(ref mut prev_tr) = prev.transform
                {
                    prev_tr.rewritten_target = tr.rewritten_target.clone();
                }
                continue;
            }
            break out;
        };

        if session_frozen && resolved.verdict != Verdict::Deny {
            return self.finish_fail_closed(
                attempt,
                "grdr.approval-streak",
                "base",
                "Session frozen after three consecutive denied or unanswered step-ups.",
                "Ask a human operator to release the session freeze.",
                now,
            );
        }
        if resolved.verdict != Verdict::Modify && !resolved.consumed_grant_ids.is_empty() {
            self.spent_once_grants.retain(|_, exp| *exp > now);
            let pending_once_spends = resolved
                .consumed_grant_ids
                .iter()
                .filter(|gid| {
                    self.grants.iter().any(|g| {
                        g.grant_id == **gid
                            && g.scope == GrantScope::Once
                            && g.remaining_uses.is_none_or(|n| n <= 1)
                    }) && !self.spent_once_grants.contains_key(*gid)
                })
                .count();
            if self
                .spent_once_grants
                .len()
                .saturating_add(pending_once_spends)
                > MAX_SPENT_TOMBSTONES
            {
                return self.finish_fail_closed(
                    attempt,
                    "policy.tombstone-capacity",
                    "system",
                    "Spent once-grant tombstone capacity saturated (fail-closed).",
                    "Wait for spent once-grant tombstones to expire before consuming new Once grants.",
                    now,
                );
            }
            for used_gid in &resolved.consumed_grant_ids {
                if let Some(idx) = self.grants.iter().position(|g| g.grant_id == *used_gid)
                    && let Some(grant) = self.grants.get_mut(idx)
                {
                    grant.consume_use();
                    let exhausted_once =
                        grant.scope == GrantScope::Once && grant.remaining_uses == Some(0);
                    if exhausted_once {
                        let spent = self.grants.remove(idx);
                        self.grant_label_epochs.remove(&spent.grant_id);
                        let exp = spent
                            .expires_at
                            .unwrap_or_else(|| add_seconds(now, 86_400 * 365 * 10));
                        self.spent_once_grants.insert(spent.grant_id, exp);
                    }
                }
            }
        }
        self.record_session_outcome(&attempt, resolved.verdict, label_epoch, now);

        let modified_attempt = if resolved.verdict == Verdict::Modify {
            resolved.transform.take().map(|t| {
                let mut next = attempt.clone();
                next.target = t.rewritten_target;
                next
            })
        } else {
            None
        };

        let receipt = build_receipt(
            &attempt,
            resolved.verdict,
            resolved.would_be,
            resolved.top_rule_id,
            resolved.top_pack_id,
            resolved.mode_applied,
            resolved.grant_id,
            resolved.reason,
            resolved.next_step,
            now,
        );

        let has_extra_obligations = resolved
            .obligations
            .iter()
            .any(|o| o.kind != ObligationKind::Receipt);
        let cacheable = resolved.verdict == Verdict::Allow
            && receipt.grant_id.is_none()
            && resolved.consumed_grant_ids.is_empty()
            && !has_extra_obligations
            && !resolved.hit_session_rule
            && !ks_active;
        if cacheable {
            self.insert_cache_entry(cache_key, &receipt, resolved.executed_verb, now);
        }

        EngineOutput::Evaluated {
            receipt: Box::new(receipt),
            executed_verb: resolved.executed_verb,
            obligations: resolved.obligations,
            retry_token: resolved.retry_token,
            modified_attempt,
            cache_hit: false,
            session_state_seq: self.session_state_seq,
        }
    }

    fn collect_active_grants(
        &self,
        attempt: &ActionAttempt,
        label_epoch: u64,
        now: Timestamp,
    ) -> Vec<Grant> {
        self.grants
            .iter()
            .filter(|g| {
                if self.spent_once_grants.contains_key(&g.grant_id) {
                    return false;
                }
                let Ok(note_epoch) = parse_note_epoch(&g.note) else {
                    return false;
                };
                if let Some(ne) = note_epoch
                    && ne != label_epoch
                {
                    return false;
                }
                let issued_epoch = self
                    .grant_label_epochs
                    .get(&g.grant_id)
                    .copied()
                    .unwrap_or(0);
                let last_taint = self.session_last_taint_at.get(&attempt.session_id).copied();
                let label_valid = if matches!(g.scope, GrantScope::Once | GrantScope::Session)
                    || g.session_id == attempt.session_id
                {
                    let taint_ok = last_taint.is_none_or(|t| {
                        g.granted_at > t
                            || (g.granted_at == t
                                && note_epoch == Some(label_epoch)
                                && label_epoch > 0)
                    });
                    issued_epoch == label_epoch && taint_ok
                } else {
                    last_taint.is_none_or(|t| g.granted_at > t)
                };
                label_valid && g.is_active(now)
            })
            .cloned()
            .collect()
    }

    fn insert_cache_entry(
        &mut self,
        cache_key: String,
        receipt: &grdr_model::DecisionReceipt,
        executed_verb: grdr_model::ExecutedVerb,
        now: Timestamp,
    ) {
        if self.verdict_cache.len() >= MAX_CACHE_ENTRIES {
            self.verdict_cache.retain(|_, v| v.expires_at > now);
            if self.verdict_cache.len() >= MAX_CACHE_ENTRIES
                && let Some(lru_key) = self
                    .verdict_cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used_seq)
                    .map(|(k, _)| k.clone())
            {
                self.verdict_cache.remove(&lru_key);
            }
        }
        self.cache_lru_counter = self.cache_lru_counter.saturating_add(1);
        let expires_at = add_seconds(now, CACHE_TTL_SECONDS);
        self.verdict_cache.insert(
            cache_key,
            CachedVerdictEntry {
                scope: CacheScope::Session,
                expires_at,
                last_used_seq: self.cache_lru_counter,
                verdict: receipt.verdict,
                would_be: receipt.would_be,
                rule_id: receipt.rule_id.clone(),
                pack_id: receipt.pack_id.clone(),
                mode_applied: receipt.mode_applied,
                reason: receipt.reason.clone(),
                next_step: receipt.next_step.clone(),
                executed_verb,
            },
        );
    }

    fn finish_fail_closed(
        &mut self,
        attempt: ActionAttempt,
        rule_id: &str,
        pack_id: &str,
        reason: &str,
        next_step: &str,
        now: Timestamp,
    ) -> EngineOutput {
        let label_epoch = self
            .session_label_epochs
            .get(&attempt.session_id)
            .copied()
            .unwrap_or(0);
        self.record_session_outcome(&attempt, Verdict::Deny, label_epoch, now);
        let caps = default_control_point_caps(attempt.control_point, None);
        let executed_verb =
            degrade_verdict(Verdict::Deny, &caps, false, TimelockAllowance::Unavailable);
        let receipt = build_receipt(
            &attempt,
            Verdict::Deny,
            None,
            Some(rule_id.into()),
            Some(pack_id.into()),
            Some(Mode::Block),
            None,
            reason.into(),
            next_step.into(),
            now,
        );
        EngineOutput::Evaluated {
            receipt: Box::new(receipt),
            executed_verb,
            obligations: vec![Obligation {
                kind: ObligationKind::Receipt,
                rule_id: Some(rule_id.into()),
                detail: "Record fail-closed DecisionReceipt.".into(),
            }],
            retry_token: None,
            modified_attempt: None,
            cache_hit: false,
            session_state_seq: self.session_state_seq,
        }
    }
}
