// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Production 9-row verdict derivation, timelock allowance, and control-point degradation (`docs/design/12` s.3-4).

use std::cmp::Reverse;

use cedar_policy::{Authorizer, Decision};
use grdr_model::eval::{ObligationKind, is_essentials_rule_id};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, BoundaryObserver, ControlPointCaps, DeriveInput,
    ExecutedVerb, FailureDisposition, HoldCapability, InputValidity, InstallProfile, LossBehaviour,
    Mode, NotEvaluableRuleRef, ObligationSupport, PendingRuleRef, RemedyCapability,
    TimelockAllowance, Verdict, VerdictDiscriminant,
};

use super::caps::Obligation;
use super::compiler::{CompiledPolicyBundle, CompiledRuleMeta};
use super::layers::glob_matches_target;
use super::request::CedarRequest;
use super::signals_scan::has_traversal_segment;
use super::verdict::VerdictEvalOutput;
use crate::analyze::normalize_attempt_target;

pub(crate) const MAX_MODIFY_RETRIES: u8 = 2;

pub fn effective_timelock_allowance(
    profile: InstallProfile,
    rule_ids: &[&str],
    all_user_local: bool,
    timelock_enabled: bool,
) -> TimelockAllowance {
    if profile == InstallProfile::User
        && timelock_enabled
        && all_user_local
        && !rule_ids.is_empty()
        && rule_ids.iter().all(|id| !is_essentials_rule_id(id))
    {
        TimelockAllowance::DisclosedTimeLock
    } else {
        TimelockAllowance::Unavailable
    }
}

pub fn derive_verdict(input: &DeriveInput) -> Verdict {
    if input.validity != InputValidity::Valid {
        return Verdict::Deny;
    }
    if !input.determining_forbids.is_empty() {
        let all_modify = input
            .determining_forbids
            .iter()
            .all(|f| f.remedy == RemedyCapability::ModifyTransform);
        if all_modify
            && input.control_modify == ObligationSupport::Supported
            && input.modify_attempts < MAX_MODIFY_RETRIES
        {
            return Verdict::Modify;
        }
        let unliftable = input.determining_forbids.iter().any(|f| {
            f.mode != Mode::Ask
                || !grade_satisfiable(f.min_grade, input.device_max_grade, input.timelock)
        });
        return if unliftable {
            Verdict::Deny
        } else {
            Verdict::StepUp
        };
    }
    if !input.pending_rules.is_empty() {
        return Verdict::Defer;
    }
    let unlifted_ne: Vec<&NotEvaluableRuleRef> = input
        .not_evaluable_rules
        .iter()
        .filter(|r| r.grant_lifted == ObligationSupport::Unsupported)
        .collect();
    if !unlifted_ne.is_empty()
        && input.observer != BoundaryObserver::ScopedBoundary
        && unlifted_ne
            .iter()
            .any(|r| matches!(r.on_loss, LossBehaviour::FailClosed | LossBehaviour::Block))
    {
        return Verdict::StepUp;
    }
    if input.base_permit == ObligationSupport::Supported {
        if input.snapshot_required == ObligationSupport::Supported
            && input.control_snapshot == ObligationSupport::Unsupported
        {
            return Verdict::Deny;
        }
        return Verdict::Allow;
    }
    Verdict::Deny
}

pub fn degrade_verdict(
    verdict: Verdict,
    caps: &ControlPointCaps,
    min_grade_available: bool,
    timelock: TimelockAllowance,
) -> ExecutedVerb {
    let can_deny = caps.verbs.contains(&VerdictDiscriminant::Deny);
    match verdict {
        Verdict::Allow => ExecutedVerb::Allow,
        Verdict::Deny => {
            if can_deny {
                ExecutedVerb::Deny
            } else {
                ExecutedVerb::ObserveOnly
            }
        }
        Verdict::Modify => {
            if caps.modify == ObligationSupport::Supported
                && caps.verbs.contains(&VerdictDiscriminant::Modify)
            {
                ExecutedVerb::Modify
            } else if can_deny {
                ExecutedVerb::Deny
            } else {
                ExecutedVerb::ObserveOnly
            }
        }
        Verdict::StepUp => {
            if !min_grade_available && timelock == TimelockAllowance::Unavailable {
                return if can_deny {
                    ExecutedVerb::Deny
                } else {
                    ExecutedVerb::ObserveOnly
                };
            }
            match caps.hold {
                HoldCapability::CanHold { deadline_ms }
                    if deadline_ms > 0
                        && caps.failure_mode == FailureDisposition::Closed
                        && caps.verbs.contains(&VerdictDiscriminant::StepUp) =>
                {
                    ExecutedVerb::Hold
                }
                _ if can_deny => ExecutedVerb::DenyWithRetryToken,
                _ => ExecutedVerb::ObserveOnly,
            }
        }
        Verdict::Defer => match caps.hold {
            HoldCapability::CanHold { deadline_ms }
                if deadline_ms > 0
                    && caps.failure_mode == FailureDisposition::Closed
                    && caps.verbs.contains(&VerdictDiscriminant::Defer) =>
            {
                ExecutedVerb::Hold
            }
            _ if can_deny => ExecutedVerb::Deny,
            _ => ExecutedVerb::ObserveOnly,
        },
    }
}

fn grade_satisfiable(
    required: ApprovalGrade,
    device_max: ApprovalGrade,
    timelock: TimelockAllowance,
) -> bool {
    device_max >= required
        || (timelock == TimelockAllowance::DisclosedTimeLock && required == ApprovalGrade::G1)
}

fn system_deny_output(
    rule_id: &str,
    reason: &str,
    next_step: &str,
    obligations: Vec<Obligation>,
    caps: &ControlPointCaps,
) -> VerdictEvalOutput {
    VerdictEvalOutput {
        verdict: Verdict::Deny,
        executed_verb: degrade_verdict(Verdict::Deny, caps, false, TimelockAllowance::Unavailable),
        would_be: None,
        top_rule_id: Some(rule_id.into()),
        top_pack_id: Some("system".into()),
        mode_applied: Some(Mode::Block),
        grant_id: None,
        consumed_grant_ids: Vec::new(),
        reason: reason.into(),
        next_step: next_step.into(),
        obligations,
        retry_token: None,
        transform: None,
        hit_session_rule: false,
    }
}

pub(crate) fn eval_error_output(caps: &ControlPointCaps) -> VerdictEvalOutput {
    system_deny_output(
        "policy.eval-error",
        "Policy evaluation error (fail-closed).",
        "Inspect the Cedar rule attributes and context before retrying.",
        vec![Obligation {
            kind: ObligationKind::Receipt,
            rule_id: Some("policy.eval-error".into()),
            detail: "Record fail-closed evaluation receipt.".into(),
        }],
        caps,
    )
}

pub(crate) fn unmet_snapshot_output(
    obligations: Vec<Obligation>,
    caps: &ControlPointCaps,
) -> VerdictEvalOutput {
    system_deny_output(
        "policy.obligation-unmet",
        "Required snapshot obligation unsupported by control point.",
        "Run action from a snapshot-capable control point.",
        obligations,
        caps,
    )
}

pub(crate) fn malformed_output(
    obligations: Vec<Obligation>,
    caps: &ControlPointCaps,
) -> VerdictEvalOutput {
    system_deny_output(
        "policy.malformed-command",
        "Malformed command syntax (unclosed quote or trailing escape) rejected fail-closed.",
        "Fix shell quoting or inspect the command before retrying.",
        obligations,
        caps,
    )
}

pub(crate) fn default_deny_output(
    obligations: Vec<Obligation>,
    caps: &ControlPointCaps,
) -> VerdictEvalOutput {
    system_deny_output(
        "policy.default-deny",
        "Action did not match base permit (default-deny).",
        "Verify grdr.base policy configuration.",
        obligations,
        caps,
    )
}

pub(crate) fn collect_lifted_grants<'a>(
    authorizer: &Authorizer,
    bundle: &'a CompiledPolicyBundle,
    built: &CedarRequest,
) -> Vec<(&'a CompiledRuleMeta, String)> {
    let mut lifted: Vec<(&'a CompiledRuleMeta, String)> = Vec::new();
    for req_no_grants in [
        built.request_without_grants.as_ref(),
        built.data_flow_request_without_grants.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let shadow_check =
            authorizer.is_authorized(req_no_grants, &bundle.enforced, &built.entities);
        if shadow_check.decision() == Decision::Deny {
            for pid in shadow_check.diagnostics().reason() {
                if let Some(meta) = bundle.meta_by_policy_id.get(&pid.to_string())
                    && let Some(gid) = built.lifted_grant_by_rule_id.get(&meta.rule_id)
                    && !lifted.iter().any(|(m, _)| m.rule_id == meta.rule_id)
                {
                    lifted.push((meta, gid.clone()));
                }
            }
        }
    }
    lifted.sort_by(|(a, _), (b, _)| {
        Reverse(a.mode)
            .cmp(&Reverse(b.mode))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    lifted
}

pub(crate) fn collect_uncertainty_and_obligations(
    bundle: &CompiledPolicyBundle,
    built: &CedarRequest,
    action_class: ActionClass,
    has_data_flow: bool,
    matched_metas: &[&CompiledRuleMeta],
    lifted_rules: &[(&CompiledRuleMeta, String)],
) -> (Vec<PendingRuleRef>, Vec<NotEvaluableRuleRef>, bool) {
    let mut pending_rules = Vec::new();
    let mut not_evaluable_rules = Vec::new();
    let mut snapshot_required = false;
    for rule in &bundle.active_rules {
        if rule.mode == Mode::Watch || rule.mode == Mode::Off {
            continue;
        }
        let applies = rule.actions.is_empty()
            || rule.actions.contains(&action_class)
            || (has_data_flow && rule.actions.contains(&ActionClass::DataFlow));
        if !applies {
            continue;
        }
        let has_absent = rule.reads.intersection(&built.absent).next().is_some();
        let lifted = built.lifted_grant_by_rule_id.contains_key(&rule.rule_id);
        let matched_or_lifted = matched_metas.iter().any(|m| m.rule_id == rule.rule_id)
            || lifted_rules.iter().any(|(m, _)| m.rule_id == rule.rule_id)
            || (has_absent && lifted);
        if rule.requires_snapshot && matched_or_lifted {
            snapshot_required = true;
        }
        if rule.reads.intersection(&built.pending).next().is_some() {
            pending_rules.push(PendingRuleRef {
                rule_id: rule.rule_id.clone(),
            });
        }
        if has_absent {
            not_evaluable_rules.push(NotEvaluableRuleRef {
                rule_id: rule.rule_id.clone(),
                on_loss: rule.on_loss,
                grant_lifted: if lifted {
                    ObligationSupport::Supported
                } else {
                    ObligationSupport::Unsupported
                },
            });
        }
    }
    (pending_rules, not_evaluable_rules, snapshot_required)
}

fn rule_matches_protect_list(
    meta: &CompiledRuleMeta,
    action_class: ActionClass,
    has_data_flow: bool,
    raw_target: &str,
    norm_target: &str,
) -> bool {
    if meta.protect_list.is_empty() || meta.mode == Mode::Off {
        return false;
    }
    let applies = meta.actions.is_empty()
        || meta.actions.contains(&action_class)
        || (has_data_flow && meta.actions.contains(&ActionClass::DataFlow));
    if !applies {
        return false;
    }
    meta.protect_list
        .iter()
        .any(|pat| glob_matches_target(pat, raw_target) || glob_matches_target(pat, norm_target))
}

fn rule_matches_allow_list(
    meta: &CompiledRuleMeta,
    raw_target: &str,
    norm_target: &str,
    has_dotdot: bool,
) -> bool {
    if has_dotdot || meta.allow_list.is_empty() {
        return false;
    }
    meta.allow_list
        .iter()
        .any(|pat| glob_matches_target(pat, raw_target) || glob_matches_target(pat, norm_target))
}

pub(crate) fn finalize_matched_and_lifted<'a>(
    matched_metas: &mut Vec<&'a CompiledRuleMeta>,
    authorizer: &Authorizer,
    bundle: &'a CompiledPolicyBundle,
    built: &CedarRequest,
    attempt: &ActionAttempt,
) -> Vec<(&'a CompiledRuleMeta, String)> {
    let (norm_target, _) = normalize_attempt_target(attempt.action_class, &attempt.target);
    let has_dotdot = has_traversal_segment(&attempt.target);
    let has_df = built.data_flow_request.is_some();

    matched_metas
        .retain(|m| !rule_matches_allow_list(m, &attempt.target, &norm_target, has_dotdot));
    let mut lifted_rules = collect_lifted_grants(authorizer, bundle, built);

    for meta in &bundle.active_rules {
        if matches!(meta.mode, Mode::Ask | Mode::Block)
            && rule_matches_protect_list(
                meta,
                attempt.action_class,
                has_df,
                &attempt.target,
                &norm_target,
            )
            && !rule_matches_allow_list(meta, &attempt.target, &norm_target, has_dotdot)
        {
            if !meta.is_final
                && let Some(gid) = built.lifted_grant_by_rule_id.get(&meta.rule_id)
            {
                if !lifted_rules.iter().any(|(m, _)| m.rule_id == meta.rule_id) {
                    lifted_rules.push((meta, gid.clone()));
                }
            } else if !matched_metas.iter().any(|m| m.rule_id == meta.rule_id) {
                matched_metas.push(meta);
            }
        }
    }

    // Ask rules blocked only by a Pending pin defer to Row 6; never drop Block rules or Absent reads.
    matched_metas.retain(|m| !(m.mode == Mode::Ask && !m.reads.is_disjoint(&built.pending)));
    matched_metas.sort_by(|a, b| {
        Reverse(a.mode)
            .cmp(&Reverse(b.mode))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    lifted_rules.sort_by(|(a, _), (b, _)| {
        Reverse(a.mode)
            .cmp(&Reverse(b.mode))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    lifted_rules
}

pub(crate) fn finalize_shadow_hits<'a>(
    shadow_hits: &mut Vec<&'a CompiledRuleMeta>,
    bundle: &'a CompiledPolicyBundle,
    built: &CedarRequest,
    attempt: &ActionAttempt,
) {
    let (norm_target, _) = normalize_attempt_target(attempt.action_class, &attempt.target);
    let has_dotdot = has_traversal_segment(&attempt.target);
    let has_df = built.data_flow_request.is_some();
    for meta in &bundle.active_rules {
        if meta.mode == Mode::Watch
            && rule_matches_protect_list(
                meta,
                attempt.action_class,
                has_df,
                &attempt.target,
                &norm_target,
            )
            && !shadow_hits.iter().any(|m| m.rule_id == meta.rule_id)
        {
            shadow_hits.push(meta);
        }
    }
    shadow_hits.retain(|m| !rule_matches_allow_list(m, &attempt.target, &norm_target, has_dotdot));
    shadow_hits.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
}
