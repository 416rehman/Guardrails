// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Cedar 4.x policy compilation, evaluation, session integration, and replay.

mod caps;
mod compile_down;
mod compile_down_render;
mod compile_down_targets;
mod compile_down_verify;
mod compiler;
mod engine;
mod engine_bundle;
mod engine_eval;
mod engine_snapshot;
mod engine_types;
mod entities;
mod essentials_cedar;
mod layers;
mod lint;
mod lint_scan;
mod matrix;
mod pack_meta;
mod render;
mod replay;
mod request;
mod request_ctx;
mod signals;
mod signals_scan;
mod verdict;
mod views;

pub use caps::{
    AppliedTransform, CryptoEntropy, DeterministicEntropy, Entropy, Obligation,
    default_control_point_caps,
};
pub use compile_down::{
    ClaudeCodeManagedSettings, CodexRequirements, CompileDownSkip, CompileDownSkipReason,
    compile_down_claude_code, compile_down_codex, render_claude_settings_json,
    render_codex_requirements_toml, verify_compile_down_subset,
};
pub use compile_down_render::parse_compile_targets_yaml;
pub use compile_down_targets::{
    CompileTargetProfile, CompiledTargetBundle, TargetRenderFormat, TargetRuleSpec,
    compile_down_for_target, compile_down_with_profile, default_compile_targets,
    load_compile_targets_from_dir,
};
pub use compiler::{
    CompileOptions, CompiledPolicyBundle, CompiledRuleMeta, compile_packs_with_options,
};
pub use engine::Engine;
pub use engine_types::{
    EngineInput, EngineOutput, EngineSnapshot, InterestSet, SessionSnapshotEntry, VerifiedBundle,
};
pub use essentials_cedar::{
    ESSENTIALS_DISK_CEDAR, ESSENTIALS_PARITY_CEDAR, canonical_essentials_pack,
    compile_cedar_pack_from_sources,
};
pub use grdr_model::eval::{essentials_pack, sha256_hex};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, BoundaryObserver, CommandParseStatus,
    DecisionReceipt, Grant, InstallProfile, KillSwitchState, Mode, PolicyPack, Verdict,
};
use jiff::Timestamp;
pub use layers::{
    EffectiveLayerRule, LayerRuleEntry, MergedPolicyLayers, PolicyLayerSpec,
    check_glob_list_containment, merge_policy_layers,
};
pub(crate) use lint::body_has_unless_clause as body_has_unless_clause_for_compile;
pub(crate) use lint::extract_policy_actions as extract_policy_actions_for_compile;
pub(crate) use lint_scan::{
    cedar_body_slice as cedar_body_slice_for_compile,
    scope_header_slice as scope_header_slice_for_compile,
    strip_comments_and_strings as strip_comments_for_compile,
};
pub use matrix::{degrade_verdict, derive_verdict, effective_timelock_allowance};
pub use pack_meta::{load_cedar_policy_pack_from_dir, load_signed_cedar_policy_pack_from_dir};
pub use render::{render_rule_cedar, validate_cedar_rule};
pub use replay::{FourBucketReplayResult, ReplayAttemptRecord, replay_pack_4bucket, replay_rule};
pub use request::{
    ActorKind, AssuranceHints, CedarRequest, ContextField, CredUseMode, McpRequestHints,
    RequestBuildOptions, SessionFreezeState, SkillRequestMeta, VerificationHints,
    build_cedar_request_with_options,
};
pub use verdict::{VerdictEvalConfig, VerdictEvalOutput, resolve_verdict};
pub use views::{
    AdvancedRuleAst, PrincipalFilter, RecursionFilter, RuleAnnotations, SimpleRuleView,
    SnapshotObligation, WorkspaceScope, advanced_to_cedar, canonicalize_cedar_via_roundtrip,
    lint_cedar_source_extended, parse_cedar_to_advanced, simple_to_advanced,
};

use compiler::compile_packs;
use request::build_cedar_request;

use crate::analyze::{classify_target, normalize_attempt_target};
use crate::session::SessionRuleState;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("GRDR-POL-0001: Cedar schema unavailable: {detail}")]
    SchemaUnavailable { detail: String },
    #[error("GRDR-POL-0002: failed to compile Cedar rule `{rule_id}`: {detail}")]
    CompileFailed { rule_id: String, detail: String },
    #[error("GRDR-POL-0003: permit policies are forbidden outside grdr.base (`{rule_id}`)")]
    PermitNotAllowed { rule_id: String },
    #[error("GRDR-POL-0004: Cedar policy `{rule_id}` failed strict validation: {detail}")]
    ValidationFailed { rule_id: String, detail: String },
    #[error("GRDR-POL-0005: failed to build Cedar request: {detail}")]
    RequestBuildFailed { detail: String },
    #[error("GRDR-POL-0006: layer `{layer}` violated locked ceiling on `{rule_id}`: {detail}")]
    LayerViolation {
        layer: String,
        rule_id: String,
        detail: String,
    },
    #[error("GRDR-POL-0007: replay budget exceeded for `{rule_id}`: {detail}")]
    ReplayBudgetExceeded { rule_id: String, detail: String },
    #[error("GRDR-POL-0008: unsupported compile-down for {target} (`{rule_id}`): {detail}")]
    UnsupportedCompileDown {
        target: String,
        rule_id: String,
        detail: String,
    },
    #[error("GRDR-POL-0009: corrupt engine snapshot: {detail}")]
    SnapshotCorrupt { detail: String },
    #[error("GRDR-POL-0010: privacy policy violation on `{rule_id}`: {detail}")]
    PrivacyViolation { rule_id: String, detail: String },
}

pub struct ReceiptDigestInput<'a> {
    pub attempt_id: &'a str,
    pub session_id: &'a str,
    pub agent_name: &'a str,
    pub action_class: ActionClass,
    pub target: &'a str,
    pub verdict: Verdict,
    pub rule_id: Option<&'a str>,
    pub decided_at: Timestamp,
}

struct ReceiptOutcome {
    verdict: Verdict,
    would_be: Option<Verdict>,
    rule_id: Option<String>,
    pack_id: Option<String>,
    mode_applied: Option<Mode>,
    grant_id: Option<String>,
    reason: String,
    next_step: String,
}

pub fn evaluate(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &[Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> DecisionReceipt {
    evaluate_internal(attempt, packs, grants, kill_switch, None, now).0
}

pub fn evaluate_mut(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> DecisionReceipt {
    let (receipt, consumed_ids) = evaluate_internal(attempt, packs, grants, kill_switch, None, now);
    consume_matched_grants(&receipt, &consumed_ids, grants);
    receipt
}

pub fn evaluate_with_session(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    session_state: &mut SessionRuleState,
    now: Timestamp,
) -> DecisionReceipt {
    let (_normalized_target, command_status) =
        normalize_attempt_target(attempt.action_class, &attempt.target);
    let analysis = classify_target(attempt.action_class, &attempt.target);

    if command_status == CommandParseStatus::Malformed {
        let receipt = build_receipt(
            attempt,
            ReceiptOutcome {
                verdict: Verdict::Deny,
                would_be: None,
                rule_id: Some("session.malformed-command".into()),
                pack_id: Some("session".into()),
                mode_applied: Some(Mode::Block),
                grant_id: None,
                reason: "Malformed command syntax (unclosed quote or trailing escape) blocked by normalizer.".into(),
                next_step: "Fix quoting or inspect the command before retrying.".into(),
            },
            now,
        );
        session_state.record_outcome(attempt, &analysis, receipt.verdict);
        return receipt;
    }

    let (mut receipt, consumed_ids) = evaluate_internal(
        attempt,
        packs,
        grants,
        kill_switch,
        Some(session_state),
        now,
    );
    consume_matched_grants(&receipt, &consumed_ids, grants);

    if receipt.verdict == Verdict::Allow {
        if command_status == CommandParseStatus::Unresolved {
            receipt = evaluate_synthetic_step_up(
                attempt,
                grants,
                "session.opaque-command",
                "Opaque shell construct (subshell, backtick, or encoded command) requires approval.",
                "Review the expanded command and approve in Respond before retrying.",
                now,
            );
        } else if let Some(escalation) = session_state.pre_evaluate_escalation(attempt, &analysis) {
            receipt = evaluate_synthetic_step_up(
                attempt,
                grants,
                escalation.rule_id,
                escalation.reason,
                escalation.next_step,
                now,
            );
        }
    }

    session_state.record_outcome(attempt, &analysis, receipt.verdict);
    receipt
}

fn evaluate_internal(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &[Grant],
    kill_switch: &KillSwitchState,
    session_state: Option<&SessionRuleState>,
    now: Timestamp,
) -> (DecisionReceipt, Vec<String>) {
    let bundle = match compile_packs(
        packs,
        kill_switch,
        &attempt.session_id,
        &attempt.device_id,
        now,
    ) {
        Ok(compiled) => compiled,
        Err(err) => {
            return (
                fail_closed_receipt(
                    attempt,
                    "policy.compile-error",
                    format!("Policy bundle failed validation (fail-closed): {err}"),
                    "Fix or replace the invalid policy rule before retrying.",
                    now,
                ),
                Vec::new(),
            );
        }
    };

    let built = match build_cedar_request(
        attempt,
        packs,
        &bundle.active_rules,
        grants,
        session_state,
        now,
    ) {
        Ok(req) => req,
        Err(err) => {
            return (
                fail_closed_receipt(
                    attempt,
                    "policy.request-error",
                    format!("Request construction failed (fail-closed): {err}"),
                    "Inspect the normalized attempt fields before retrying.",
                    now,
                ),
                Vec::new(),
            );
        }
    };

    let cfg = VerdictEvalConfig {
        host_profile: InstallProfile::User,
        device_max_grade: ApprovalGrade::G3,
        timelock_enabled: false,
        observer: BoundaryObserver::None,
        caps: default_control_point_caps(attempt.control_point, None),
        modify_attempts: 0,
    };
    let mut entropy = DeterministicEntropy::from_seed_bytes(attempt.id.as_bytes());
    let resolved = match resolve_verdict(attempt, &bundle, &built, &cfg, &mut entropy) {
        Ok(out) => out,
        Err(err) => {
            return (
                fail_closed_receipt(
                    attempt,
                    "policy.eval-error",
                    format!("Policy evaluation failed (fail-closed): {err}"),
                    "Inspect the Cedar rule attributes and context before retrying.",
                    now,
                ),
                Vec::new(),
            );
        }
    };

    let consumed_grant_ids = resolved.consumed_grant_ids;
    let receipt = build_receipt(
        attempt,
        ReceiptOutcome {
            verdict: resolved.verdict,
            would_be: resolved.would_be,
            rule_id: resolved.top_rule_id,
            pack_id: resolved.top_pack_id,
            mode_applied: resolved.mode_applied,
            grant_id: resolved.grant_id,
            reason: resolved.reason,
            next_step: resolved.next_step,
        },
        now,
    );
    (receipt, consumed_grant_ids)
}

fn evaluate_synthetic_step_up(
    attempt: &ActionAttempt,
    grants: &mut [Grant],
    rule_id: &str,
    reason: &str,
    next_step: &str,
    now: Timestamp,
) -> DecisionReceipt {
    let match_attempt = if matches!(
        attempt.action_class,
        ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete
    ) {
        attempt.clone()
    } else {
        let (norm, _) = normalize_attempt_target(attempt.action_class, &attempt.target);
        let mut cloned = attempt.clone();
        if !norm.is_empty() {
            cloned.target = norm;
        }
        cloned
    };
    if let Some(grant) = grants.iter_mut().find(|g| {
        g.rule_id == rule_id && g.grade >= ApprovalGrade::G1 && g.matches(&match_attempt, now)
    }) {
        let grant_id = grant.grant_id.clone();
        grant.consume_use();
        return build_receipt(
            attempt,
            ReceiptOutcome {
                verdict: Verdict::Allow,
                would_be: Some(Verdict::StepUp),
                rule_id: Some(rule_id.into()),
                pack_id: Some("session".into()),
                mode_applied: Some(Mode::Ask),
                grant_id: Some(grant_id.clone()),
                reason: format!("Allowed by active approval grant {grant_id}."),
                next_step: "Action permitted within grant expiry window.".into(),
            },
            now,
        );
    }

    build_receipt(
        attempt,
        ReceiptOutcome {
            verdict: Verdict::StepUp,
            would_be: None,
            rule_id: Some(rule_id.into()),
            pack_id: Some("session".into()),
            mode_applied: Some(Mode::Ask),
            grant_id: None,
            reason: reason.into(),
            next_step: next_step.into(),
        },
        now,
    )
}

fn consume_matched_grants(
    receipt: &DecisionReceipt,
    consumed_ids: &[String],
    grants: &mut [Grant],
) {
    let single_id = receipt.grant_id.as_deref();
    for grant in grants {
        if single_id == Some(grant.grant_id.as_str())
            || consumed_ids.iter().any(|id| id == &grant.grant_id)
        {
            grant.consume_use();
        }
    }
}

fn fail_closed_receipt(
    attempt: &ActionAttempt,
    rule_id: &str,
    reason: String,
    next_step: &str,
    now: Timestamp,
) -> DecisionReceipt {
    build_receipt(
        attempt,
        ReceiptOutcome {
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some(rule_id.into()),
            pack_id: Some("system".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason,
            next_step: next_step.into(),
        },
        now,
    )
}

pub fn compute_receipt_digest(input: &ReceiptDigestInput<'_>) -> String {
    let mut payload = String::new();
    for field in [
        input.attempt_id,
        input.session_id,
        input.agent_name,
        input.action_class.as_str(),
        input.target,
        input.rule_id.unwrap_or("none"),
    ] {
        engine_types::push_len(&mut payload, field);
    }
    payload.push_str(&format!(
        "{:?}:{}",
        input.verdict,
        input.decided_at.as_second()
    ));
    sha256_hex(payload.as_bytes())
}

fn build_receipt(
    attempt: &ActionAttempt,
    outcome: ReceiptOutcome,
    now: Timestamp,
) -> DecisionReceipt {
    let receipt_digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict: outcome.verdict,
        rule_id: outcome.rule_id.as_deref(),
        decided_at: now,
    });
    let short_id: String = receipt_digest.chars().take(32).collect();

    DecisionReceipt {
        receipt_id: format!("rcp_{short_id}"),
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict: outcome.verdict,
        would_be: outcome.would_be,
        rule_id: outcome.rule_id,
        pack_id: outcome.pack_id,
        mode_applied: outcome.mode_applied,
        grant_id: outcome.grant_id,
        reason: outcome.reason,
        next_step: outcome.next_step,
        receipt_digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

#[cfg(test)]
mod tests_wave1;

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::eval::add_seconds;
    use grdr_model::{
        ActionClass, ApprovalGrade, ControlPoint, GrantScope, KillScope, PolicyRule, RuleMatch,
    };

    fn sample_attempt(id: &str, class: ActionClass, target: &str) -> ActionAttempt {
        ActionAttempt {
            id: id.into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "host".into(),
            agent_name: "claude-code".into(),
            action_class: class,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn essentials_blocks_control_files_and_steps_up_keys_via_cedar() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];

        let write_hook = evaluate(
            &sample_attempt("a1", ActionClass::FileWrite, ".claude/settings.json"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(write_hook.verdict, Verdict::Deny);
        assert_eq!(
            write_hook.rule_id.as_deref(),
            Some("essentials.agent-control-files")
        );

        let read_ssh = evaluate(
            &sample_attempt("a2", ActionClass::FileRead, "/home/dev/.ssh/id_rsa"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(read_ssh.verdict, Verdict::StepUp);
        assert_eq!(
            read_ssh.rule_id.as_deref(),
            Some("essentials.credential-stores")
        );
    }

    #[test]
    fn grant_allows_matching_step_up_until_expired_and_consumes_once() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let mut grants = vec![Grant {
            grant_id: "grn_once".into(),
            rule_id: "essentials.credential-stores".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            action_class: ActionClass::FileRead,
            target_pattern: "/home/dev/.ssh/id_rsa".into(),
            scope: GrantScope::Once,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: Some(add_seconds(now, 60)),
            remaining_uses: Some(1),
            note: "Single use".into(),
            key_id: None,
            signature: None,
        }];

        let attempt = sample_attempt("a1", ActionClass::FileRead, "/home/dev/.ssh/id_rsa");
        let first = evaluate_mut(
            &attempt,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(first.verdict, Verdict::Allow);
        assert_eq!(first.grant_id.as_deref(), Some("grn_once"));
        assert_eq!(grants.first().and_then(|g| g.remaining_uses), Some(0));

        let second = evaluate_mut(
            &attempt,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            add_seconds(now, 5),
        );
        assert_eq!(second.verdict, Verdict::StepUp);
        assert!(second.grant_id.is_none());
    }

    #[test]
    fn kill_switch_and_deny_wins_across_layers_hold() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let ks = KillSwitchState::Killed {
            scope: KillScope::Device,
            target_id: "dev-1".into(),
            reason: "Containment test".into(),
            issued_at: now,
        };
        let safe_read = evaluate(
            &sample_attempt("a1", ActionClass::Exec, "git status"),
            &packs,
            &[],
            &ks,
            now,
        );
        assert_eq!(safe_read.verdict, Verdict::Deny);
        assert_eq!(safe_read.rule_id.as_deref(), Some("system.kill-switch"));

        let ask_pack = PolicyPack {
            id: "layer-ask".into(),
            name: "Layer Ask".into(),
            description: "Ask layer".into(),
            version: "1.0.0".into(),
            channel: "custom".into(),
            rules: vec![PolicyRule {
                id: "custom.ask-curl".into(),
                title: "Ask curl".into(),
                description: "Ask curl".into(),
                mode: Mode::Ask,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: vec![],
                    target_contains: vec!["curl ".into()],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Ask curl".into(),
                cedar: None,
            }],
            key_id: None,
            signature: None,
        };
        let block_pack = PolicyPack {
            id: "layer-block".into(),
            name: "Layer Block".into(),
            description: "Block layer".into(),
            version: "1.0.0".into(),
            channel: "custom".into(),
            rules: vec![PolicyRule {
                id: "custom.block-curl".into(),
                title: "Block curl".into(),
                description: "Block curl".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: true,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: vec![],
                    target_contains: vec!["curl ".into()],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Block curl".into(),
                cedar: None,
            }],
            key_id: None,
            signature: None,
        };

        let layered = evaluate(
            &sample_attempt("a2", ActionClass::Exec, "curl https://example.test"),
            &[ask_pack, block_pack],
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(layered.verdict, Verdict::Deny);
        assert_eq!(layered.rule_id.as_deref(), Some("custom.block-curl"));
    }

    #[test]
    fn replay_counts_matches_accurately_before_promotion() {
        let rule = PolicyRule {
            id: "test.egress".into(),
            title: "Outbound curl".into(),
            description: "Track curl transfers".into(),
            mode: Mode::Watch,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec],
                target_prefixes: vec![],
                target_contains: vec!["curl ".into()],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Outbound transfer".into(),
            cedar: None,
        };

        let attempts = vec![
            sample_attempt("1", ActionClass::Exec, "curl https://webhook.site/abc"),
            sample_attempt("2", ActionClass::Exec, "git status"),
        ];

        let summary = replay_rule(&attempts, &rule, Mode::Block);
        assert_eq!(summary.total_scanned, 2);
        assert_eq!(summary.matched, 1);
        assert_eq!(summary.would_block, 1);
        assert_eq!(summary.not_matched, 1);
        assert_eq!(summary.samples.len(), 1);
    }

    #[test]
    fn evaluate_with_session_blocks_traversal_and_malformed_and_escalates_taint() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let mut grants = Vec::new();
        let mut session_state = SessionRuleState::new("sess-1");

        let traversal = sample_attempt(
            "a1",
            ActionClass::FileWrite,
            "workspace/../../.claude/settings.json",
        );
        let r1 = evaluate_with_session(
            &traversal,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r1.verdict, Verdict::Deny);
        assert_eq!(r1.target, "workspace/../../.claude/settings.json");

        let malformed = sample_attempt("a2", ActionClass::Exec, r#"bash -c "unclosed"#);
        let r2 = evaluate_with_session(
            &malformed,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r2.verdict, Verdict::Deny);
        assert_eq!(r2.rule_id.as_deref(), Some("session.malformed-command"));

        let opaque = sample_attempt("a3", ActionClass::Exec, "echo $(id)");
        let r3 = evaluate_with_session(
            &opaque,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r3.verdict, Verdict::StepUp);
        assert_eq!(r3.rule_id.as_deref(), Some("session.opaque-command"));

        let cred = sample_attempt("a4", ActionClass::FileRead, "~/.ssh/id_rsa");
        let _ = evaluate_with_session(
            &cred,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        let exfil = sample_attempt(
            "a5",
            ActionClass::NetRequest,
            "https://example.test/collect",
        );
        let r5 = evaluate_with_session(
            &exfil,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            &mut session_state,
            now,
        );
        assert_eq!(r5.verdict, Verdict::StepUp);
        assert_eq!(
            r5.rule_id.as_deref(),
            Some("session.tainted-exfil-escalation")
        );
    }

    #[test]
    fn all_worked_policies_from_design_12_validate_strictly() {
        let worked = [
            r#"@id("essentials.control-files.write") @class("config-tamper") @final("true")
            forbid (principal is Grdr::Session, action in [Grdr::Action::"file.write", Grdr::Action::"file.delete", Grdr::Action::"config.change"], resource)
            when { resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"]) };"#,
            r#"@id("essentials.delete-outside-workspace") @class("irreversible") @max_mode("Ask")
            forbid (principal is Grdr::Session, action == Grdr::Action::"file.delete", resource)
            when { context.recursive && !resource.in_workspace }
            unless { resource.classes.contains("session-tmp") };"#,
            r#"@id("destructive.opaque-command") @class("out-of-boundary") @max_mode("Ask")
            forbid (principal is Grdr::Session, action == Grdr::Action::"exec", resource)
            when { context.facts.contains("exec.opaque") && context.assurance.control < 2 };"#,
            r#"@id("mcp.server-allow-list") @class("out-of-boundary")
            forbid (principal, action == Grdr::Action::"mcp.connect", resource is Grdr::McpServer)
            unless { resource.identity_pinned && resource.classes.contains("org.mcp-approved") };"#,
            r#"@id("mcp.tool-pin") @class("out-of-boundary")
            forbid (principal, action == Grdr::Action::"mcp.call", resource is Grdr::McpTool)
            when { !resource.manifest_pinned };"#,
            r#"@id("dataflow.trifecta") @class("out-of-boundary")
            forbid (principal is Grdr::Session, action == Grdr::Action::"data.flow", resource is Grdr::Sink)
            when { context.session.labels.containsAll(["untrusted", "sensitive"]) };"#,
            r#"@id("cloud.aws-account-pin") @class("out-of-boundary")
            forbid (principal is Grdr::Session, action == Grdr::Action::"net.request", resource is Grdr::Endpoint)
            when { context.cloud.provider == "aws" && context.cloud.verified && !context.cloud.account_classes.contains("org.aws-approved") };"#,
            r#"@id("agents.subagent-ceiling") @class("config-tamper")
            forbid (principal is Grdr::Session, action == Grdr::Action::"agent.spawn", resource is Grdr::Agent)
            when { context.child.depth > 2 || context.child.classes.containsAny(["bypass-flags", "weaker-settings"]) || (principal.contained && !context.child.contained) };"#,
            r#"@id("agents.undetermined.control-files") @class("config-tamper") @max_mode("Ask")
            forbid (principal is Grdr::Process, action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"], resource)
            when { principal.agent_capable_host && principal.actor_kind == "undetermined" && resource.classes.contains("agent-control") };"#,
        ];
        for policy in worked {
            assert!(
                validate_cedar_rule(policy).is_ok(),
                "worked policy failed validation: {policy}"
            );
        }
    }

    #[test]
    fn permit_outside_base_pack_is_rejected() {
        let permit =
            r#"permit (principal is Grdr::Session, action == Grdr::Action::"exec", resource);"#;
        let err = validate_cedar_rule(permit).unwrap_err();
        assert!(matches!(err, PolicyError::PermitNotAllowed { .. }));
    }

    #[test]
    fn watch_shadow_agent_scope_and_final_vs_nonfinal_block_work_via_cedar() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];

        let watch_egress = evaluate(
            &sample_attempt("w1", ActionClass::Exec, "curl https://webhook.site/abc"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(watch_egress.verdict, Verdict::Allow);
        assert_eq!(watch_egress.mode_applied, Some(Mode::Watch));
        assert_eq!(watch_egress.would_be, Some(Verdict::StepUp));
        assert_eq!(
            watch_egress.rule_id.as_deref(),
            Some("essentials.secret-exfil-egress")
        );

        let scoped_pack = PolicyPack {
            id: "scoped".into(),
            name: "Scoped".into(),
            description: "Agent scoped".into(),
            version: "1.0.0".into(),
            channel: "custom".into(),
            rules: vec![PolicyRule {
                id: "custom.cursor-only".into(),
                title: "Ask cursor".into(),
                description: "Ask cursor".into(),
                mode: Mode::Ask,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: vec![],
                    target_contains: vec!["deploy".into()],
                    agents: vec!["cursor".into()],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Cursor deploy requires approval.".into(),
                cedar: None,
            }],
            key_id: None,
            signature: None,
        };

        let claude_res = evaluate(
            &sample_attempt("a-claude", ActionClass::Exec, "deploy staging"),
            std::slice::from_ref(&scoped_pack),
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(claude_res.verdict, Verdict::Allow);

        let mut cursor_attempt = sample_attempt("a-cursor", ActionClass::Exec, "deploy staging");
        cursor_attempt.agent_name = "Cursor".into();
        let cursor_res = evaluate(
            &cursor_attempt,
            &[scoped_pack],
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(cursor_res.verdict, Verdict::StepUp);
        assert_eq!(cursor_res.rule_id.as_deref(), Some("custom.cursor-only"));
    }
}
