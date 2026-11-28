// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_core::policy::{lint_cedar_source_extended, render_rule_cedar, validate_cedar_rule};
use grdr_crypto::domain_sha256_hex;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{ApprovalGrade, IdentityMode, Mode, PolicyPack, PolicyRule};
use grdr_proto::common::ErrorClass;
use uuid::Uuid;

use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};

use super::simulate::index_all_rules;
use super::types::{DiffEffect, PolicyChangeOp, PolicyDiffEntry, PolicyDiffSummary};

const HASH_DOMAIN: &str = "grdr-gitops-effective-hash-v1";
const RESERVED_BASE_PACK: &str = "grdr.base";

fn mode_rank(mode: Mode) -> u8 {
    match mode {
        Mode::Off => 0,
        Mode::Watch => 1,
        Mode::Ask => 2,
        Mode::Block => 3,
    }
}

fn grade_rank(grade: ApprovalGrade) -> u8 {
    match grade {
        ApprovalGrade::G0 => 0,
        ApprovalGrade::G1 => 1,
        ApprovalGrade::G2 => 2,
        ApprovalGrade::G3 => 3,
    }
}

pub fn is_reserved_base_pack(pack_id: &str) -> bool {
    pack_id.trim().eq_ignore_ascii_case(RESERVED_BASE_PACK)
}

pub fn compute_effective_hash(packs: &[PolicyPack]) -> String {
    let encoded = serde_json::to_vec(packs).unwrap_or_default();
    domain_sha256_hex(HASH_DOMAIN, &encoded)
}

pub fn validate_candidate_rule(pack_id: &str, rule: &PolicyRule) -> Result<(), String> {
    if is_reserved_base_pack(pack_id) {
        return Err(format!(
            "pack `{pack_id}` is reserved and cannot be modified or bypassed via PolicyChange"
        ));
    }
    let source = match rule.cedar.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(raw) => raw.to_owned(),
        None => render_rule_cedar(rule),
    };
    validate_cedar_rule(&source).map_err(|e| e.to_string())?;
    lint_cedar_source_extended(pack_id, &rule.id, &source, None, IdentityMode::Named)
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn compute_policy_diff(
    current_packs: &[PolicyPack],
    ops: &[PolicyChangeOp],
) -> Result<(PolicyDiffSummary, Vec<PolicyPack>, Vec<String>), ApiError> {
    if ops.is_empty() {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::InvalidArgument,
            grdr_code: CODE_INVALID_INPUT.into(),
            reason: "EMPTY_POLICY_CHANGE".into(),
            class: ErrorClass::Validation,
            message: "PolicyChange must contain at least one operation.".into(),
            fix: "Include at least one policy operation.".into(),
            metadata: BTreeMap::new(),
        }));
    }

    let before_hash = compute_effective_hash(current_packs);
    let mut next_packs = current_packs.to_vec();
    let mut check_errors = Vec::new();
    let mut entries = Vec::new();
    let mut risk_reasons = Vec::new();
    let mut is_widening = false;
    let mut promotes_enforcement = false;

    for op in ops {
        let before_rules = index_all_rules(&next_packs);
        match op {
            PolicyChangeOp::UpsertRule {
                pack_id,
                id,
                title,
                description,
                mode,
                min_grade,
                matcher,
                reason_template,
                cedar,
                enabled,
            } => {
                if is_reserved_base_pack(pack_id) {
                    check_errors.push(format!(
                        "pack `{pack_id}` cannot be targeted by PolicyChange"
                    ));
                    continue;
                }
                let rule_id = id
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| format!("rule-{}", Uuid::now_v7().simple()));
                let candidate = PolicyRule {
                    id: rule_id.clone(),
                    title: title.clone(),
                    description: description.clone(),
                    mode: *mode,
                    min_grade: min_grade.unwrap_or(ApprovalGrade::G1),
                    enabled: enabled.unwrap_or(true),
                    locked: false,
                    matcher: matcher.clone(),
                    hits: 0,
                    would_ask_hits: 0,
                    would_block_hits: 0,
                    reason_template: reason_template.clone(),
                    cedar: cedar.clone(),
                };
                if let Err(msg) = validate_candidate_rule(pack_id, &candidate) {
                    check_errors.push(format!("{rule_id}: {msg}"));
                }
                if let Some((prev_pack_id, prev_rule)) = before_rules.get(&rule_id) {
                    if prev_rule.locked {
                        check_errors.push(format!(
                            "{rule_id}: rule is locked by upstream layer {prev_pack_id}"
                        ));
                    }
                    let (effect, promo, widen_reason) = classify_rule_delta(prev_rule, &candidate);
                    if effect == DiffEffect::Widening {
                        is_widening = true;
                        if let Some(rsn) = widen_reason {
                            risk_reasons.push(rsn);
                        }
                    }
                    if promo {
                        promotes_enforcement = true;
                    }
                    entries.push(PolicyDiffEntry {
                        pack_id: pack_id.clone(),
                        rule_id: rule_id.clone(),
                        change_kind: "update_rule".into(),
                        previous_mode: Some(prev_rule.mode),
                        candidate_mode: Some(candidate.mode),
                        effect,
                        summary: format!(
                            "Updated rule {rule_id} ({:?} -> {:?})",
                            prev_rule.mode, candidate.mode
                        ),
                    });
                } else {
                    let promo =
                        matches!(candidate.mode, Mode::Ask | Mode::Block) && candidate.enabled;
                    if promo {
                        promotes_enforcement = true;
                        risk_reasons.push(format!(
                            "New enforcing rule {rule_id} ({:?})",
                            candidate.mode
                        ));
                    }
                    entries.push(PolicyDiffEntry {
                        pack_id: pack_id.clone(),
                        rule_id: rule_id.clone(),
                        change_kind: "create_rule".into(),
                        previous_mode: None,
                        candidate_mode: Some(candidate.mode),
                        effect: DiffEffect::Narrowing,
                        summary: format!("Created rule {rule_id} in {:?} mode", candidate.mode),
                    });
                }
                upsert_rule_into_packs(&mut next_packs, pack_id, candidate);
            }
            PolicyChangeOp::UpdateRuleMode { rule_id, mode } => {
                let Some((pack_id, prev_rule)) = before_rules.get(rule_id) else {
                    return Err(ApiError::new(ApiErrorInner {
                        code: ConnectCode::NotFound,
                        grdr_code: CODE_NOT_FOUND.into(),
                        reason: "RULE_NOT_FOUND".into(),
                        class: ErrorClass::NotFound,
                        message: format!("Rule `{rule_id}` does not exist."),
                        fix: "Provide an existing rule ID.".into(),
                        metadata: BTreeMap::new(),
                    }));
                };
                if prev_rule.locked {
                    check_errors.push(format!("{rule_id}: rule is locked in pack {pack_id}"));
                }
                let prev_rank = mode_rank(prev_rule.mode);
                let next_rank = mode_rank(*mode);
                let effect = if next_rank < prev_rank {
                    is_widening = true;
                    risk_reasons.push(format!(
                        "Mode relaxation on {rule_id}: {:?} -> {:?}",
                        prev_rule.mode, mode
                    ));
                    DiffEffect::Widening
                } else if next_rank > prev_rank {
                    if matches!(mode, Mode::Ask | Mode::Block) {
                        promotes_enforcement = true;
                        risk_reasons.push(format!(
                            "Enforcement promotion on {rule_id}: {:?} -> {:?}",
                            prev_rule.mode, mode
                        ));
                    }
                    DiffEffect::Narrowing
                } else {
                    DiffEffect::Neutral
                };
                set_rule_mode(&mut next_packs, rule_id, *mode);
                entries.push(PolicyDiffEntry {
                    pack_id: pack_id.clone(),
                    rule_id: rule_id.clone(),
                    change_kind: "update_mode".into(),
                    previous_mode: Some(prev_rule.mode),
                    candidate_mode: Some(*mode),
                    effect,
                    summary: format!("Rule {rule_id} mode {:?} -> {:?}", prev_rule.mode, mode),
                });
            }
            PolicyChangeOp::DeleteRule { rule_id } => {
                let Some((pack_id, prev_rule)) = before_rules.get(rule_id) else {
                    return Err(ApiError::new(ApiErrorInner {
                        code: ConnectCode::NotFound,
                        grdr_code: CODE_NOT_FOUND.into(),
                        reason: "RULE_NOT_FOUND".into(),
                        class: ErrorClass::NotFound,
                        message: format!("Rule `{rule_id}` does not exist."),
                        fix: "Provide an existing rule ID.".into(),
                        metadata: BTreeMap::new(),
                    }));
                };
                if prev_rule.locked {
                    return Err(ApiError::new(ApiErrorInner {
                        code: ConnectCode::FailedPrecondition,
                        grdr_code: CODE_CONFLICT.into(),
                        reason: "RULE_LOCKED".into(),
                        class: ErrorClass::Conflict,
                        message: format!("Locked rule `{rule_id}` cannot be deleted."),
                        fix: "Only unlocked organisation rules can be removed.".into(),
                        metadata: BTreeMap::new(),
                    }));
                }
                if prev_rule.enabled && mode_rank(prev_rule.mode) > 0 {
                    is_widening = true;
                    risk_reasons.push(format!(
                        "Deleting active rule {rule_id} ({:?})",
                        prev_rule.mode
                    ));
                }
                delete_rule_from_packs(&mut next_packs, rule_id);
                entries.push(PolicyDiffEntry {
                    pack_id: pack_id.clone(),
                    rule_id: rule_id.clone(),
                    change_kind: "delete_rule".into(),
                    previous_mode: Some(prev_rule.mode),
                    candidate_mode: None,
                    effect: if prev_rule.enabled && prev_rule.mode != Mode::Off {
                        DiffEffect::Widening
                    } else {
                        DiffEffect::Neutral
                    },
                    summary: format!("Deleted rule {rule_id}"),
                });
            }
            PolicyChangeOp::ReplacePackRules { pack_id, packs } => {
                if is_reserved_base_pack(pack_id) {
                    check_errors.push(format!(
                        "pack `{pack_id}` is reserved and cannot be replaced"
                    ));
                    continue;
                }
                let Some(replacement) = packs.iter().find(|p| &p.id == pack_id) else {
                    check_errors.push(format!("ReplacePackRules missing pack `{pack_id}`"));
                    continue;
                };
                for r in &replacement.rules {
                    if let Err(msg) = validate_candidate_rule(pack_id, r) {
                        check_errors.push(format!("{}: {msg}", r.id));
                    }
                }
                let pack_before = index_pack_rules(&next_packs, pack_id);
                let next_rules = index_pack_rules(std::slice::from_ref(replacement), pack_id);
                for (rid, prev_rule) in &pack_before {
                    if let Some(next_rule) = next_rules.get(rid) {
                        if prev_rule.locked && !locked_rule_unchanged(prev_rule, next_rule) {
                            check_errors.push(format!(
                                "{rid}: locked rule cannot be modified in pack {pack_id}"
                            ));
                        }
                        let (effect, promo, widen_reason) =
                            classify_rule_delta(prev_rule, next_rule);
                        if effect == DiffEffect::Widening {
                            is_widening = true;
                            if let Some(rsn) = widen_reason {
                                risk_reasons.push(rsn);
                            }
                        }
                        if promo {
                            promotes_enforcement = true;
                        }
                        entries.push(PolicyDiffEntry {
                            pack_id: pack_id.clone(),
                            rule_id: rid.clone(),
                            change_kind: "replace_pack_rule".into(),
                            previous_mode: Some(prev_rule.mode),
                            candidate_mode: Some(next_rule.mode),
                            effect,
                            summary: format!("Synchronized rule {rid} in pack {pack_id}"),
                        });
                    } else {
                        if prev_rule.locked {
                            check_errors.push(format!(
                                "{rid}: locked rule cannot be deleted from pack {pack_id}"
                            ));
                        }
                        if prev_rule.enabled && prev_rule.mode != Mode::Off {
                            is_widening = true;
                            risk_reasons.push(format!("Bundle removes active rule {rid}"));
                        }
                        entries.push(PolicyDiffEntry {
                            pack_id: pack_id.clone(),
                            rule_id: rid.clone(),
                            change_kind: "delete_rule".into(),
                            previous_mode: Some(prev_rule.mode),
                            candidate_mode: None,
                            effect: if prev_rule.enabled && prev_rule.mode != Mode::Off {
                                DiffEffect::Widening
                            } else {
                                DiffEffect::Neutral
                            },
                            summary: format!("Removed rule {rid} from pack {pack_id}"),
                        });
                    }
                }
                for (rid, next_rule) in &next_rules {
                    if !pack_before.contains_key(rid) {
                        if matches!(next_rule.mode, Mode::Ask | Mode::Block) && next_rule.enabled {
                            promotes_enforcement = true;
                        }
                        entries.push(PolicyDiffEntry {
                            pack_id: pack_id.clone(),
                            rule_id: rid.clone(),
                            change_kind: "create_rule".into(),
                            previous_mode: None,
                            candidate_mode: Some(next_rule.mode),
                            effect: DiffEffect::Narrowing,
                            summary: format!("Added rule {rid} to pack {pack_id}"),
                        });
                    }
                }
                replace_pack(&mut next_packs, replacement.clone());
            }
        }
    }

    let after_hash = compute_effective_hash(&next_packs);
    let summary_effect = if is_widening {
        DiffEffect::Widening
    } else if entries.iter().any(|e| e.effect == DiffEffect::Narrowing) {
        DiffEffect::Narrowing
    } else {
        DiffEffect::Neutral
    };
    Ok((
        PolicyDiffSummary {
            is_widening,
            promotes_enforcement,
            effect: summary_effect,
            entries,
            effective_hash_before: before_hash,
            effective_hash_after: after_hash,
            risk_reasons,
        },
        next_packs,
        check_errors,
    ))
}

fn classify_rule_delta(prev: &PolicyRule, next: &PolicyRule) -> (DiffEffect, bool, Option<String>) {
    let prev_effective = if prev.enabled {
        mode_rank(prev.mode)
    } else {
        0
    };
    let next_effective = if next.enabled {
        mode_rank(next.mode)
    } else {
        0
    };
    let cedar_changed = prev.cedar != next.cedar;
    let matcher_changed = prev.matcher != next.matcher;
    let grade_weakened = grade_rank(next.min_grade) < grade_rank(prev.min_grade);
    let promo = next_effective > prev_effective && matches!(next.mode, Mode::Ask | Mode::Block);

    if next_effective < prev_effective {
        return (
            DiffEffect::Widening,
            false,
            Some(format!(
                "Rule {} weakened from {:?} (enabled={}) to {:?} (enabled={})",
                next.id, prev.mode, prev.enabled, next.mode, next.enabled
            )),
        );
    }
    if grade_weakened {
        return (
            DiffEffect::Widening,
            promo,
            Some(format!(
                "Rule {} approval grade weakened from {:?} to {:?}",
                next.id, prev.min_grade, next.min_grade
            )),
        );
    }
    if cedar_changed || matcher_changed {
        return (
            DiffEffect::Widening,
            promo,
            Some(format!(
                "Rule {} predicate or Cedar source modified",
                next.id
            )),
        );
    }
    if next_effective > prev_effective {
        (DiffEffect::Narrowing, promo, None)
    } else {
        (DiffEffect::Neutral, false, None)
    }
}

pub fn locked_rule_unchanged(prev: &PolicyRule, next: &PolicyRule) -> bool {
    prev.mode == next.mode
        && prev.min_grade == next.min_grade
        && prev.enabled == next.enabled
        && prev.locked == next.locked
        && prev.matcher == next.matcher
        && prev.cedar == next.cedar
}

fn index_pack_rules(packs: &[PolicyPack], pack_id: &str) -> BTreeMap<String, PolicyRule> {
    let mut map = BTreeMap::new();
    for pack in packs {
        if pack.id == pack_id {
            for rule in &pack.rules {
                map.insert(rule.id.clone(), rule.clone());
            }
        }
    }
    map
}

fn upsert_rule_into_packs(packs: &mut Vec<PolicyPack>, pack_id: &str, rule: PolicyRule) {
    if let Some(pack) = packs.iter_mut().find(|p| p.id == pack_id) {
        if let Some(slot) = pack.rules.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule;
        } else {
            pack.rules.push(rule);
        }
        return;
    }
    packs.push(PolicyPack {
        id: pack_id.to_owned(),
        name: pack_id.to_owned(),
        description: "GitOps managed policy pack".into(),
        version: "1.0.0".into(),
        channel: "gitops".into(),
        rules: vec![rule],
        key_id: None,
        signature: None,
    });
}

fn set_rule_mode(packs: &mut [PolicyPack], rule_id: &str, mode: Mode) {
    for pack in packs {
        for rule in &mut pack.rules {
            if rule.id == rule_id {
                rule.mode = mode;
            }
        }
    }
}

fn delete_rule_from_packs(packs: &mut [PolicyPack], rule_id: &str) {
    for pack in packs {
        pack.rules.retain(|r| r.id != rule_id);
    }
}

fn replace_pack(packs: &mut Vec<PolicyPack>, replacement: PolicyPack) {
    if let Some(slot) = packs.iter_mut().find(|p| p.id == replacement.id) {
        *slot = replacement;
    } else {
        packs.push(replacement);
    }
}
