// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Cedar 4.x policy compilation, evaluation, session integration, and replay.

mod compiler;
mod replay;
mod request;
mod signals;

use cedar_policy::{Authorizer, Decision};
pub use grdr_model::eval::{essentials_pack, sha256_hex};
use grdr_model::{
    ActionAttempt, CommandParseStatus, DecisionReceipt, Grant, KillSwitchState, Mode, PolicyPack,
    Verdict,
};
use jiff::Timestamp;

use compiler::{CompiledRuleMeta, compile_packs};
pub use compiler::{render_rule_cedar, validate_cedar_rule};
pub use replay::replay_rule;
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
    evaluate_internal(attempt, packs, grants, kill_switch, None, now)
}

pub fn evaluate_mut(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> DecisionReceipt {
    let receipt = evaluate(attempt, packs, grants, kill_switch, now);
    consume_matched_grant(&receipt, grants);
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
    let (normalized_target, command_status) =
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

    let mut match_attempt = attempt.clone();
    if !normalized_target.is_empty() {
        match_attempt.target = normalized_target;
    }

    let mut receipt = evaluate_internal(
        &match_attempt,
        packs,
        grants,
        kill_switch,
        Some(session_state),
        now,
    );
    receipt.target = attempt.target.clone();
    consume_matched_grant(&receipt, grants);

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
) -> DecisionReceipt {
    let bundle = match compile_packs(
        packs,
        kill_switch,
        &attempt.session_id,
        &attempt.device_id,
        now,
    ) {
        Ok(compiled) => compiled,
        Err(err) => {
            return fail_closed_receipt(
                attempt,
                "policy.compile-error",
                format!("Policy bundle failed validation (fail-closed): {err}"),
                "Fix or replace the invalid policy rule before retrying.",
                now,
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
            return fail_closed_receipt(
                attempt,
                "policy.request-error",
                format!("Request construction failed (fail-closed): {err}"),
                "Inspect the normalized attempt fields before retrying.",
                now,
            );
        }
    };

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&built.request, &bundle.enforced, &built.entities);

    if let Some(err) = response.diagnostics().errors().next() {
        return fail_closed_receipt(
            attempt,
            "policy.eval-error",
            format!("Policy evaluation error (fail-closed): {err}"),
            "Inspect the Cedar rule attributes and context before retrying.",
            now,
        );
    }

    if response.decision() == Decision::Deny {
        let mut matched: Vec<&CompiledRuleMeta> = response
            .diagnostics()
            .reason()
            .filter_map(|pid| bundle.meta_by_policy_id.get(&pid.to_string()))
            .collect();
        matched.sort_by_key(|meta| std::cmp::Reverse(meta.mode));

        if let Some(top) = matched.first().copied() {
            if top.mode == Mode::Block {
                let next_step = if top.rule_id == "system.kill-switch" {
                    "Release the freeze or kill switch on the Respond screen once investigated."
                } else {
                    "Choose a workspace-safe path or ask an administrator for an exception."
                };
                return build_receipt(
                    attempt,
                    ReceiptOutcome {
                        verdict: Verdict::Deny,
                        would_be: None,
                        rule_id: Some(top.rule_id.clone()),
                        pack_id: Some(top.pack_id.clone()),
                        mode_applied: Some(Mode::Block),
                        grant_id: None,
                        reason: top.reason_template.clone(),
                        next_step: next_step.into(),
                    },
                    now,
                );
            }
            return build_receipt(
                attempt,
                ReceiptOutcome {
                    verdict: Verdict::StepUp,
                    would_be: None,
                    rule_id: Some(top.rule_id.clone()),
                    pack_id: Some(top.pack_id.clone()),
                    mode_applied: Some(Mode::Ask),
                    grant_id: None,
                    reason: top.reason_template.clone(),
                    next_step: "Approve the pending request in Respond, then retry.".into(),
                },
                now,
            );
        }

        return build_receipt(
            attempt,
            ReceiptOutcome {
                verdict: Verdict::Deny,
                would_be: None,
                rule_id: Some("policy.default-deny".into()),
                pack_id: Some("system".into()),
                mode_applied: Some(Mode::Block),
                grant_id: None,
                reason: "Action did not match base permit (default-deny).".into(),
                next_step: "Verify policy pack configuration.".into(),
            },
            now,
        );
    }

    if let Some(req_no_grants) = built.request_without_grants.as_ref() {
        let shadow_check =
            authorizer.is_authorized(req_no_grants, &bundle.enforced, &built.entities);
        if shadow_check.decision() == Decision::Deny {
            let mut lifted: Vec<&CompiledRuleMeta> = shadow_check
                .diagnostics()
                .reason()
                .filter_map(|pid| bundle.meta_by_policy_id.get(&pid.to_string()))
                .filter(|meta| built.lifted_grant_by_rule_id.contains_key(&meta.rule_id))
                .collect();
            lifted.sort_by_key(|meta| std::cmp::Reverse(meta.mode));
            if let Some(top) = lifted.first().copied()
                && let Some(grant_id) = built.lifted_grant_by_rule_id.get(&top.rule_id)
            {
                return build_receipt(
                    attempt,
                    ReceiptOutcome {
                        verdict: Verdict::Allow,
                        would_be: Some(Verdict::StepUp),
                        rule_id: Some(top.rule_id.clone()),
                        pack_id: Some(top.pack_id.clone()),
                        mode_applied: Some(top.mode),
                        grant_id: Some(grant_id.clone()),
                        reason: format!("Allowed by active approval grant {grant_id}."),
                        next_step: "Action permitted within grant expiry window.".into(),
                    },
                    now,
                );
            }
        }
    }

    let shadow_resp = authorizer.is_authorized(&built.request, &bundle.shadow, &built.entities);
    let watch_hit = shadow_resp
        .diagnostics()
        .reason()
        .filter_map(|pid| bundle.meta_by_policy_id.get(&pid.to_string()))
        .next();

    if let Some(watch) = watch_hit {
        return build_receipt(
            attempt,
            ReceiptOutcome {
                verdict: Verdict::Allow,
                would_be: Some(Verdict::StepUp),
                rule_id: Some(watch.rule_id.clone()),
                pack_id: Some(watch.pack_id.clone()),
                mode_applied: Some(Mode::Watch),
                grant_id: None,
                reason: watch.reason_template.clone(),
                next_step: "Run replay on Protect to decide whether to promote this rule to Ask."
                    .into(),
            },
            now,
        );
    }

    build_receipt(
        attempt,
        ReceiptOutcome {
            verdict: Verdict::Allow,
            would_be: None,
            rule_id: None,
            pack_id: None,
            mode_applied: None,
            grant_id: None,
            reason: "No policy rule restricted this action.".into(),
            next_step: "No action needed.".into(),
        },
        now,
    )
}

fn evaluate_synthetic_step_up(
    attempt: &ActionAttempt,
    grants: &mut [Grant],
    rule_id: &str,
    reason: &str,
    next_step: &str,
    now: Timestamp,
) -> DecisionReceipt {
    if let Some(grant) = grants
        .iter_mut()
        .find(|g| g.rule_id == rule_id && g.matches(attempt, now))
    {
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

fn consume_matched_grant(receipt: &DecisionReceipt, grants: &mut [Grant]) {
    if let Some(grant_id) = receipt.grant_id.as_deref()
        && let Some(grant) = grants.iter_mut().find(|g| g.grant_id == grant_id)
    {
        grant.consume_use();
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

fn build_receipt(
    attempt: &ActionAttempt,
    outcome: ReceiptOutcome,
    now: Timestamp,
) -> DecisionReceipt {
    let payload = format!(
        "{}:{}:{}:{}:{}:{:?}:{}:{}",
        attempt.id,
        attempt.session_id,
        attempt.agent_name,
        attempt.action_class.as_str(),
        attempt.target,
        outcome.verdict,
        outcome.rule_id.as_deref().unwrap_or("none"),
        now.as_second()
    );
    let receipt_digest = sha256_hex(payload.as_bytes());
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
