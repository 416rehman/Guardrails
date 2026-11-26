// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Full 9-row verdict derivation, control-point degradation, retry tokens, and obligations.

use std::cmp::Reverse;

use cedar_policy::{Authorizer, Decision};
use grdr_model::eval::ObligationKind;
use grdr_model::{
    ActionAttempt, ApprovalGrade, BoundaryObserver, CommandParseStatus, ControlPointCaps,
    DeriveInput, DeterminingForbid, ExecutedVerb, InputValidity, InstallProfile, LayerKind,
    LossBehaviour, Mode, ObligationSupport, Verdict,
};

use super::PolicyError;
use super::caps::{
    AppliedTransform, Entropy, Obligation, apply_modify_transform, generate_retry_token,
};
use super::compiler::{CompiledPolicyBundle, CompiledRuleMeta};
use super::matrix::{
    MAX_MODIFY_RETRIES, collect_uncertainty_and_obligations, default_deny_output, degrade_verdict,
    derive_verdict, effective_timelock_allowance, eval_error_output, finalize_matched_and_lifted,
    finalize_shadow_hits, malformed_output, unmet_snapshot_output,
};
use super::request::CedarRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictEvalConfig {
    pub host_profile: InstallProfile,
    pub device_max_grade: ApprovalGrade,
    pub timelock_enabled: bool,
    pub observer: BoundaryObserver,
    pub caps: ControlPointCaps,
    pub modify_attempts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictEvalOutput {
    pub verdict: Verdict,
    pub executed_verb: ExecutedVerb,
    pub would_be: Option<Verdict>,
    pub top_rule_id: Option<String>,
    pub top_pack_id: Option<String>,
    pub mode_applied: Option<Mode>,
    pub grant_id: Option<String>,
    pub consumed_grant_ids: Vec<String>,
    pub reason: String,
    pub next_step: String,
    pub obligations: Vec<Obligation>,
    pub retry_token: Option<String>,
    pub transform: Option<AppliedTransform>,
    pub hit_session_rule: bool,
}

pub fn resolve_verdict(
    attempt: &ActionAttempt,
    bundle: &CompiledPolicyBundle,
    built: &CedarRequest,
    cfg: &VerdictEvalConfig,
    entropy: &mut dyn Entropy,
) -> Result<VerdictEvalOutput, PolicyError> {
    let authorizer = Authorizer::new();
    let resp = authorizer.is_authorized(&built.request, &bundle.enforced, &built.entities);
    let df_resp = built
        .data_flow_request
        .as_ref()
        .map(|df_req| authorizer.is_authorized(df_req, &bundle.enforced, &built.entities));

    let has_eval_err = resp.diagnostics().errors().next().is_some()
        || df_resp
            .as_ref()
            .is_some_and(|r| r.diagnostics().errors().next().is_some());
    if has_eval_err {
        return Ok(eval_error_output(&cfg.caps));
    }

    let mut matched_metas: Vec<&CompiledRuleMeta> = resp
        .diagnostics()
        .reason()
        .filter_map(|pid| bundle.meta_by_policy_id.get(&pid.to_string()))
        .collect();
    if let Some(ref dfr) = df_resp {
        for pid in dfr.diagnostics().reason() {
            if let Some(meta) = bundle.meta_by_policy_id.get(&pid.to_string())
                && !matched_metas.iter().any(|m| m.policy_id == meta.policy_id)
            {
                matched_metas.push(meta);
            }
        }
    }

    let mut lifted_rules =
        finalize_matched_and_lifted(&mut matched_metas, &authorizer, bundle, built, attempt);

    let candidate_modify = !matched_metas.is_empty()
        && matched_metas
            .iter()
            .all(|m| m.remedy == grdr_model::RemedyCapability::ModifyTransform)
        && cfg.caps.modify == ObligationSupport::Supported
        && cfg.modify_attempts < MAX_MODIFY_RETRIES;
    let remedy_hint = matched_metas
        .first()
        .and_then(|m| m.remedy_transform.as_deref())
        .filter(|first| {
            matched_metas
                .iter()
                .all(|m| m.remedy_transform.as_deref() == Some(*first))
        });
    let planned_transform = if candidate_modify {
        apply_modify_transform(attempt, remedy_hint)
    } else {
        None
    };

    let determining_forbids: Vec<DeterminingForbid> = matched_metas
        .iter()
        .map(|m| DeterminingForbid {
            rule_id: m.rule_id.clone(),
            mode: m.mode,
            min_grade: m.min_grade,
            mutability: m.mutability,
            remedy: if planned_transform.is_some() {
                m.remedy
            } else {
                grdr_model::RemedyCapability::Plain
            },
            on_loss: m.on_loss,
        })
        .collect();

    let has_data_flow = built.data_flow_request.is_some();
    let (pending_rules, not_evaluable_rules, snapshot_required) =
        collect_uncertainty_and_obligations(
            bundle,
            built,
            attempt.action_class,
            has_data_flow,
            &matched_metas,
            &lifted_rules,
        );
    if cfg.observer != BoundaryObserver::ScopedBoundary {
        for nr in &not_evaluable_rules {
            if nr.grant_lifted == ObligationSupport::Supported
                && matches!(nr.on_loss, LossBehaviour::Block | LossBehaviour::FailClosed)
                && !lifted_rules.iter().any(|(m, _)| m.rule_id == nr.rule_id)
                && let Some(meta) = bundle.active_rules.iter().find(|m| m.rule_id == nr.rule_id)
                && let Some(gid) = built.lifted_grant_by_rule_id.get(&nr.rule_id)
            {
                lifted_rules.push((meta, gid.clone()));
            }
        }
        lifted_rules.sort_by(|(a, _), (b, _)| {
            Reverse(a.mode)
                .cmp(&Reverse(b.mode))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
    }

    let has_forbid = |r: &cedar_policy::Response| {
        r.diagnostics()
            .reason()
            .any(|pid| bundle.meta_by_policy_id.contains_key(&pid.to_string()))
    };
    let resp_unpermitted = resp.decision() == Decision::Deny && !has_forbid(&resp);
    let df_unpermitted = df_resp
        .as_ref()
        .is_some_and(|r| r.decision() == Decision::Deny && !has_forbid(r));
    let base_permit_ok = !(resp_unpermitted || df_unpermitted);

    let rule_ids: Vec<&str> = matched_metas.iter().map(|m| m.rule_id.as_str()).collect();
    let all_user_local = !matched_metas.is_empty()
        && matched_metas
            .iter()
            .all(|m| m.layer == LayerKind::User && !m.locked);
    let timelock = effective_timelock_allowance(
        cfg.host_profile,
        &rule_ids,
        all_user_local,
        cfg.timelock_enabled,
    );

    let pending_rule_id = pending_rules.first().map(|r| r.rule_id.clone());
    let ne_top = not_evaluable_rules
        .iter()
        .filter(|r| {
            r.grant_lifted == ObligationSupport::Unsupported
                && matches!(r.on_loss, LossBehaviour::Block | LossBehaviour::FailClosed)
        })
        .min_by_key(|r| {
            (
                u8::from(r.on_loss != LossBehaviour::Block),
                r.rule_id.as_str(),
            )
        });
    let ne_rule_id = ne_top.map(|r| r.rule_id.clone());
    let ne_top_meta = ne_rule_id
        .as_deref()
        .and_then(|id| bundle.active_rules.iter().find(|m| m.rule_id == id));
    let pending_meta = pending_rule_id
        .as_deref()
        .and_then(|id| bundle.active_rules.iter().find(|m| m.rule_id == id));
    let validity = if built.command_status == CommandParseStatus::Malformed {
        InputValidity::Malformed
    } else {
        InputValidity::Valid
    };
    let ne_required_grade = not_evaluable_rules
        .iter()
        .filter(|r| {
            r.grant_lifted == ObligationSupport::Unsupported
                && matches!(r.on_loss, LossBehaviour::Block | LossBehaviour::FailClosed)
        })
        .filter_map(|r| {
            bundle
                .active_rules
                .iter()
                .find(|m| m.rule_id == r.rule_id)
                .map(|m| m.min_grade)
        })
        .max();

    let derive_input = DeriveInput {
        validity,
        modify_attempts: cfg.modify_attempts,
        device_max_grade: cfg.device_max_grade,
        timelock,
        base_permit: if base_permit_ok {
            ObligationSupport::Supported
        } else {
            ObligationSupport::Unsupported
        },
        observer: cfg.observer,
        snapshot_required: if snapshot_required {
            ObligationSupport::Supported
        } else {
            ObligationSupport::Unsupported
        },
        control_snapshot: cfg.caps.snapshot,
        control_modify: if planned_transform.is_some() {
            cfg.caps.modify
        } else {
            ObligationSupport::Unsupported
        },
        determining_forbids,
        pending_rules,
        not_evaluable_rules,
    };

    let verdict = derive_verdict(&derive_input);
    let required_grade = matched_metas
        .iter()
        .map(|m| m.min_grade)
        .max()
        .or(ne_required_grade)
        .unwrap_or(ApprovalGrade::G1);
    let min_grade_available = cfg.device_max_grade >= required_grade;
    let executed_verb = degrade_verdict(verdict, &cfg.caps, min_grade_available, timelock);

    let retry_token = if executed_verb == ExecutedVerb::DenyWithRetryToken {
        Some(generate_retry_token(entropy)?)
    } else {
        None
    };
    let transform = if verdict == Verdict::Modify {
        planned_transform
    } else {
        None
    };

    let obligation_rule_id = matched_metas
        .first()
        .map(|m| m.rule_id.clone())
        .or_else(|| lifted_rules.first().map(|(m, _)| m.rule_id.clone()))
        .or_else(|| ne_rule_id.clone())
        .or_else(|| pending_rule_id.clone());
    let mut obligations = vec![Obligation {
        kind: ObligationKind::Receipt,
        rule_id: obligation_rule_id.clone(),
        detail: "Record signed DecisionReceipt.".into(),
    }];
    if validity == InputValidity::Malformed {
        return Ok(malformed_output(obligations, &cfg.caps));
    }
    if snapshot_required
        && (verdict == Verdict::Allow
            || (verdict == Verdict::Deny
                && cfg.caps.snapshot != ObligationSupport::Supported
                && matched_metas.is_empty()
                && base_permit_ok
                && pending_rule_id.is_none()))
    {
        if cfg.caps.snapshot == ObligationSupport::Supported {
            obligations.push(Obligation {
                kind: ObligationKind::Snapshot,
                rule_id: obligation_rule_id.clone(),
                detail: "Capture pre-mutation workspace snapshot.".into(),
            });
        } else {
            return Ok(unmet_snapshot_output(obligations, &cfg.caps));
        }
    }
    if verdict == Verdict::Allow
        && cfg.observer == BoundaryObserver::ScopedBoundary
        && !derive_input.not_evaluable_rules.is_empty()
    {
        obligations.push(Obligation {
            kind: ObligationKind::Expect,
            rule_id: obligation_rule_id.clone(),
            detail: "Issue OS control-point expectation for unscored condition.".into(),
        });
    }
    if verdict == Verdict::StepUp && executed_verb != ExecutedVerb::Deny {
        obligations.push(Obligation {
            kind: if required_grade >= ApprovalGrade::G2 {
                ObligationKind::NotifySponsor
            } else {
                ObligationKind::NotifyUser
            },
            rule_id: obligation_rule_id,
            detail: "Notify designated approver for step-up.".into(),
        });
    }

    if let Some(top) = matched_metas.first().copied() {
        return Ok(VerdictEvalOutput {
            verdict,
            executed_verb,
            would_be: None,
            top_rule_id: Some(top.rule_id.clone()),
            top_pack_id: Some(top.pack_id.clone()),
            mode_applied: Some(top.mode),
            grant_id: None,
            consumed_grant_ids: Vec::new(),
            reason: top.reason_template.clone(),
            next_step: top.steer.clone(),
            obligations,
            retry_token,
            transform,
            hit_session_rule: matched_metas.iter().any(|m| !m.stateless)
                || lifted_rules.iter().any(|(m, _)| !m.stateless),
        });
    }

    if !base_permit_ok {
        return Ok(default_deny_output(obligations, &cfg.caps));
    }

    if verdict == Verdict::Defer
        && let Some(pid) = pending_rule_id
    {
        return Ok(VerdictEvalOutput {
            verdict,
            executed_verb,
            would_be: None,
            top_rule_id: Some(pid),
            top_pack_id: pending_meta
                .map(|m| m.pack_id.clone())
                .or_else(|| Some("policy".into())),
            mode_applied: pending_meta.map(|m| m.mode).or(Some(Mode::Ask)),
            grant_id: None,
            consumed_grant_ids: Vec::new(),
            reason: "Required policy evidence is pending verification.".into(),
            next_step: "Wait for pending pin or manifest verification before retrying.".into(),
            obligations,
            retry_token,
            transform,
            hit_session_rule: pending_meta.is_some_and(|m| !m.stateless),
        });
    }

    if matches!(verdict, Verdict::StepUp | Verdict::Deny)
        && let Some(nid) = ne_rule_id
    {
        return Ok(VerdictEvalOutput {
            verdict,
            executed_verb,
            would_be: None,
            top_rule_id: Some(nid),
            top_pack_id: ne_top_meta
                .map(|m| m.pack_id.clone())
                .or_else(|| Some("policy".into())),
            mode_applied: ne_top_meta
                .map(|m| m.mode)
                .or(Some(if verdict == Verdict::Deny {
                    Mode::Block
                } else {
                    Mode::Ask
                })),
            grant_id: None,
            consumed_grant_ids: Vec::new(),
            reason: "Required policy context field absent on non-boundary control point.".into(),
            next_step: "Approve or supply complete context before retrying.".into(),
            obligations,
            retry_token,
            transform,
            hit_session_rule: ne_top_meta.is_some_and(|m| !m.stateless),
        });
    }

    if let Some((top, _)) = lifted_rules.first() {
        let mut consumed = Vec::new();
        for (_, gid) in &lifted_rules {
            if !consumed.contains(gid) {
                consumed.push(gid.clone());
            }
        }
        let primary_gid = consumed.first().cloned();
        let gid_label = primary_gid.as_deref().unwrap_or("grant");
        return Ok(VerdictEvalOutput {
            verdict: Verdict::Allow,
            executed_verb: ExecutedVerb::Allow,
            would_be: Some(Verdict::StepUp),
            top_rule_id: Some(top.rule_id.clone()),
            top_pack_id: Some(top.pack_id.clone()),
            mode_applied: Some(top.mode),
            grant_id: primary_gid.clone(),
            consumed_grant_ids: consumed,
            reason: format!("Allowed by active approval grant {gid_label}."),
            next_step: "Action permitted within grant expiry window.".into(),
            obligations,
            retry_token: None,
            transform: None,
            hit_session_rule: lifted_rules.iter().any(|(m, _)| !m.stateless),
        });
    }

    let shadow_resp = authorizer.is_authorized(&built.request, &bundle.shadow, &built.entities);
    let mut shadow_hits: Vec<&CompiledRuleMeta> = shadow_resp
        .diagnostics()
        .reason()
        .filter_map(|pid| bundle.meta_by_policy_id.get(&pid.to_string()))
        .collect();
    if let Some(ref dfr) = built.data_flow_request {
        let df_shadow = authorizer.is_authorized(dfr, &bundle.shadow, &built.entities);
        for pid in df_shadow.diagnostics().reason() {
            if let Some(meta) = bundle.meta_by_policy_id.get(&pid.to_string())
                && !shadow_hits.iter().any(|m| m.policy_id == meta.policy_id)
            {
                shadow_hits.push(meta);
            }
        }
    }
    finalize_shadow_hits(&mut shadow_hits, bundle, built, attempt);
    if let Some(watch) = shadow_hits.first().copied() {
        return Ok(VerdictEvalOutput {
            verdict,
            executed_verb,
            would_be: Some(Verdict::StepUp),
            top_rule_id: Some(watch.rule_id.clone()),
            top_pack_id: Some(watch.pack_id.clone()),
            mode_applied: Some(Mode::Watch),
            grant_id: None,
            consumed_grant_ids: Vec::new(),
            reason: watch.reason_template.clone(),
            next_step: "Run replay to review before promoting from Watch.".into(),
            obligations,
            retry_token: None,
            transform: None,
            hit_session_rule: shadow_hits.iter().any(|m| !m.stateless),
        });
    }

    Ok(VerdictEvalOutput {
        verdict,
        executed_verb,
        would_be: None,
        top_rule_id: None,
        top_pack_id: None,
        mode_applied: None,
        grant_id: None,
        consumed_grant_ids: Vec::new(),
        reason: "No policy rule restricted this action.".into(),
        next_step: "No action needed.".into(),
        obligations,
        retry_token: None,
        transform: None,
        hit_session_rule: false,
    })
}
