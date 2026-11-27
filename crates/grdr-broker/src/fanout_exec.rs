// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded-deadline pooled provider fan-out, P8 payload scrubbing, and conservative decision merge (`docs/design/07`).

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use grdr_messages::{AgentNoticeInput, AgentVerb, NextStepKind, format_agent_message};
use grdr_model::{ActionAttempt, DecisionReceipt};
use grdr_ports::DecisionEnginePort;
use grdr_strings::sanitize_untrusted_text;

use crate::brand::BrokerBrand;
use crate::fanout::{
    FanoutDecision, ProviderEvalError, ProviderEvalRequest, ProviderVerdictKind,
    ProviderVerdictResponse, VerdictProvider,
};
use crate::providers::{ProviderCapabilities, ProviderCaptureCeiling};
use crate::worker_pool::BrokerWorkerPool;

const ARGUMENT_PREVIEW_MAX_CHARS: usize = 256;
const FULL_MINIMISED_MAX_CHARS: usize = 2_048;
const SECRET_MARKERS_LOWER: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "akia",
    "asia",
    "bearer ",
    "basic ",
    "xoxb-",
    "xoxp-",
    "aiza",
    "password=",
    "token=",
    "secret=",
    "api_key=",
];

pub(crate) fn preview_for_ceiling(raw_target: &str, ceiling: ProviderCaptureCeiling) -> String {
    match ceiling {
        ProviderCaptureCeiling::MetadataOnly => String::new(),
        ProviderCaptureCeiling::ArgumentPreview => {
            scrub_preview(raw_target, ARGUMENT_PREVIEW_MAX_CHARS)
        }
        ProviderCaptureCeiling::FullMinimised => {
            scrub_preview(raw_target, FULL_MINIMISED_MAX_CHARS)
        }
    }
}

fn scrub_preview(raw_target: &str, max_chars: usize) -> String {
    let safe = sanitize_untrusted_text(raw_target);
    let lower = safe.to_ascii_lowercase();
    if SECRET_MARKERS_LOWER.iter().any(|m| lower.contains(m)) {
        return "[REDACTED]".into();
    }
    let scrubbed_tokens: Vec<String> = safe.split_whitespace().map(scrub_url_token).collect();
    let joined = scrubbed_tokens.join(" ");
    let joined_lower = joined.to_ascii_lowercase();
    if SECRET_MARKERS_LOWER
        .iter()
        .any(|m| joined_lower.contains(m))
    {
        return "[REDACTED]".into();
    }
    let count = joined.chars().count();
    if count <= max_chars {
        return joined;
    }
    let truncated: String = joined.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{truncated}...")
}

fn scrub_url_token(tok: &str) -> String {
    if !tok.contains("://") {
        return tok.to_owned();
    }
    let no_frag = tok.split('#').next().unwrap_or(tok);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let Some(scheme_end) = no_query.find("://") else {
        return no_query.to_owned();
    };
    let auth_start = scheme_end.saturating_add(3);
    let Some(rest) = no_query.get(auth_start..) else {
        return no_query.to_owned();
    };
    let auth_len = rest.find('/').unwrap_or(rest.len());
    let Some(authority) = rest.get(..auth_len) else {
        return no_query.to_owned();
    };
    if let Some(at_pos) = authority.rfind('@')
        && let Some(scheme) = no_query.get(..auth_start)
        && let Some(host_and_path) = rest.get(at_pos.saturating_add(1)..)
    {
        return format!("{scheme}{host_and_path}");
    }
    no_query.to_owned()
}

pub(crate) fn execute_bounded_fanout(
    worker_pool: &BrokerWorkerPool,
    providers: &[Arc<dyn VerdictProvider>],
    base_req: &ProviderEvalRequest,
    fanout_deadline_ms: u64,
) -> Vec<(
    ProviderCapabilities,
    Result<ProviderVerdictResponse, ProviderEvalError>,
    u64,
)> {
    if providers.is_empty() {
        return Vec::new();
    }

    let (tx, rx) = mpsc::channel();
    let total = providers.len();
    let mut caps_list = Vec::with_capacity(total);
    let cancelled = Arc::new(AtomicBool::new(false));

    for (idx, prov) in providers.iter().enumerate() {
        let caps = prov.capabilities().clone();
        caps_list.push(caps.clone());
        let p = Arc::clone(prov);
        let mut local_req = base_req.clone();
        local_req.deadline_ms = caps.timeout_ms.min(fanout_deadline_ms);
        local_req.target_preview =
            preview_for_ceiling(&base_req.target_preview, caps.max_capture_level);
        let sender = tx.clone();
        let cancel_flag = Arc::clone(&cancelled);

        let job = Box::new(move || {
            let started = Instant::now();
            let res = match catch_unwind(AssertUnwindSafe(|| p.evaluate(&local_req))) {
                Ok(inner) => inner,
                Err(_) => Err(ProviderEvalError::Unavailable(
                    "provider worker panicked".into(),
                )),
            };
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let _ = sender.send((idx, res, elapsed));
        });

        if let Err(err) = worker_pool.dispatch(job, cancel_flag) {
            let _ = tx.send((idx, Err(ProviderEvalError::Unavailable(err)), 0));
        }
    }
    drop(tx);

    let Some(deadline) = Instant::now().checked_add(Duration::from_millis(fanout_deadline_ms))
    else {
        cancelled.store(true, std::sync::atomic::Ordering::Release);
        return caps_list
            .into_iter()
            .map(|caps| (caps, Err(ProviderEvalError::Timeout), fanout_deadline_ms))
            .collect();
    };
    let mut resolved = Vec::with_capacity(total);
    let mut received_idx = BTreeSet::new();

    while received_idx.len() < total {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let rem = deadline.saturating_duration_since(now);
        match rx.recv_timeout(rem) {
            Ok((idx, res, elapsed)) => {
                if received_idx.insert(idx)
                    && let Some(caps) = caps_list.get(idx)
                {
                    resolved.push((idx, caps.clone(), res, elapsed));
                }
            }
            Err(_) => break,
        }
    }
    cancelled.store(true, std::sync::atomic::Ordering::Release);

    for (idx, caps) in caps_list.into_iter().enumerate() {
        if !received_idx.contains(&idx) {
            resolved.push((
                idx,
                caps,
                Err(ProviderEvalError::Timeout),
                fanout_deadline_ms,
            ));
        }
    }

    resolved.sort_by_key(|(idx, _, _, _)| *idx);
    resolved
        .into_iter()
        .map(|(_, caps, res, elapsed)| (caps, res, elapsed))
        .collect()
}

pub(crate) fn finalize_merged_decision<E: DecisionEnginePort>(
    attempt: &ActionAttempt,
    action_class: &str,
    core_receipt: Option<&DecisionReceipt>,
    responses: &[(ProviderCapabilities, ProviderVerdictResponse)],
    engine: Option<&mut E>,
    brand: &BrokerBrand,
    mut diagnostics: Vec<String>,
) -> FanoutDecision {
    let core_verdict = core_receipt
        .map(|r| ProviderVerdictKind::from_model_verdict(r.verdict))
        .unwrap_or(ProviderVerdictKind::Allow);
    let mut best: Option<&ProviderVerdictResponse> = None;
    for (_, resp) in responses {
        if best.is_none_or(|cur| resp.verdict.severity_rank() > cur.verdict.severity_rank()) {
            best = Some(resp);
        }
    }

    let (
        mut final_verdict,
        mut final_reason_code,
        mut final_reason,
        mut winner_id,
        rewritten_target,
    ) = match best {
        Some(winner) if winner.verdict.severity_rank() >= core_verdict.severity_rank() => (
            winner.verdict,
            winner.reason_code.clone(),
            winner.reason.clone(),
            Some(winner.provider_id.clone()),
            if winner.verdict == ProviderVerdictKind::Modify {
                winner.rewritten_target.clone()
            } else {
                None
            },
        ),
        _ => match core_receipt {
            Some(r) if core_verdict != ProviderVerdictKind::Allow => (
                core_verdict,
                r.rule_id.clone().unwrap_or_else(|| "policy.core".into()),
                r.reason.clone(),
                Some("grdr.core".into()),
                None,
            ),
            _ => {
                return FanoutDecision {
                    verdict: ProviderVerdictKind::Allow,
                    winning_provider_id: None,
                    reason_code: "provider/none/allow".into(),
                    message: String::new(),
                    rewritten_target: None,
                    reevaluated_after_modify: false,
                    diagnostics,
                };
            }
        },
    };

    let mut reevaluated_after_modify = false;
    if final_verdict == ProviderVerdictKind::Modify {
        let valid_rewrite = rewritten_target
            .as_deref()
            .filter(|t| !t.trim().is_empty() && *t != attempt.target.as_str());
        if core_verdict != ProviderVerdictKind::Allow {
            final_verdict = ProviderVerdictKind::StepUp;
            winner_id = Some("grdr.core".into());
            if let Some(r) = core_receipt {
                final_reason_code = r.rule_id.clone().unwrap_or_else(|| "policy.core".into());
                final_reason = r.reason.clone();
            }
            diagnostics.push("modify-rejected-non-allow-core".into());
        } else if let (Some(rewritten), Some(eng)) = (valid_rewrite, engine) {
            let mut updated_attempt = attempt.clone();
            updated_attempt.target = rewritten.to_owned();
            match eng.evaluate(&updated_attempt) {
                Ok(receipt) => {
                    reevaluated_after_modify = true;
                    let engine_verdict = ProviderVerdictKind::from_model_verdict(receipt.verdict);
                    if engine_verdict == ProviderVerdictKind::Modify {
                        final_verdict = ProviderVerdictKind::StepUp;
                        winner_id = Some("grdr.core".into());
                        final_reason_code =
                            receipt.rule_id.unwrap_or_else(|| "policy.reeval".into());
                        final_reason = receipt.reason;
                        diagnostics.push("modify-reeval-cascaded-to-step-up".into());
                    } else if engine_verdict != ProviderVerdictKind::Allow {
                        final_verdict = engine_verdict;
                        winner_id = Some("grdr.core".into());
                        final_reason_code =
                            receipt.rule_id.unwrap_or_else(|| "policy.reeval".into());
                        final_reason = receipt.reason;
                    }
                }
                Err(err) => {
                    reevaluated_after_modify = true;
                    final_verdict = ProviderVerdictKind::Deny;
                    final_reason_code = "GRDR-BRK-0001".into();
                    final_reason = err.display_line();
                    winner_id = Some("grdr.core".into());
                }
            }
        } else {
            final_verdict = ProviderVerdictKind::StepUp;
            winner_id = Some("grdr.core".into());
            final_reason_code = "policy.reeval.missing".into();
            final_reason = "modified target requires core verification or approval".into();
            diagnostics.push("modify-missing-reevaluator-or-rewrite".into());
        }
    }

    let message = format_broker_notice(
        brand,
        attempt,
        action_class,
        final_verdict,
        &final_reason_code,
        &final_reason,
    );

    FanoutDecision {
        verdict: final_verdict,
        winning_provider_id: winner_id,
        reason_code: final_reason_code,
        message,
        rewritten_target: if final_verdict == ProviderVerdictKind::Modify {
            rewritten_target
        } else {
            None
        },
        reevaluated_after_modify,
        diagnostics,
    }
}

pub(crate) fn format_broker_notice(
    brand: &BrokerBrand,
    attempt: &ActionAttempt,
    action_class: &str,
    verdict: ProviderVerdictKind,
    reason_code: &str,
    reason: &str,
) -> String {
    match verdict {
        ProviderVerdictKind::Allow | ProviderVerdictKind::Modify => String::new(),
        ProviderVerdictKind::Defer | ProviderVerdictKind::StepUp => {
            format_agent_message(&AgentNoticeInput {
                brand: brand.product_name.clone(),
                verb: AgentVerb::Held,
                action_class: action_class.to_owned(),
                status_code: reason_code.to_owned(),
                rule_id: reason_code.to_owned(),
                reference: attempt.id.clone(),
                reason: sanitize_untrusted_text(reason),
                next_step: NextStepKind::RetryAfterApproval {
                    approver: "the device owner".into(),
                },
            })
        }
        ProviderVerdictKind::Deny => format_agent_message(&AgentNoticeInput {
            brand: brand.product_name.clone(),
            verb: AgentVerb::Blocked,
            action_class: action_class.to_owned(),
            status_code: reason_code.to_owned(),
            rule_id: reason_code.to_owned(),
            reference: attempt.id.clone(),
            reason: sanitize_untrusted_text(reason),
            next_step: NextStepKind::Blocked,
        }),
    }
}

pub(crate) fn format_action_class(class: grdr_model::ActionClass) -> String {
    serde_json::to_value(class)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{class:?}").to_ascii_lowercase())
}
