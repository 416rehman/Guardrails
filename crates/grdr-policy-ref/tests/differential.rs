// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Differential tests comparing `grdr-policy-ref` against `grdr-core::policy`.

use grdr_core::policy::{essentials_pack, evaluate, evaluate_mut, evaluate_with_session};
use grdr_core::session::SessionRuleState;
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, Grant, GrantScope, KillScope,
    KillSwitchState, Mode, PolicyPack, PolicyRule, RuleMatch, Verdict,
};
use grdr_policy_ref::{RefSessionState, evaluate_ref, evaluate_ref_mut, evaluate_ref_with_session};
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
fn differential_vectors_match_core_policy_across_classes_paths_chains_and_cedar() {
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
                id: "custom.win-secret-read".into(),
                title: "Block Windows root read".into(),
                description: "Block C:/secrets".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileRead],
                    target_prefixes: vec!["C:/secrets/".into()],
                    target_contains: vec![],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "C:/secrets blocked.".into(),
                cedar: Some(
                    "@id(\"custom.win-secret-read\")\n@mode(\"Block\")\n@final(\"true\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource) when { resource.classes.contains(\"match:custom.win-secret-read\") };".into(),
                ),
            },
            PolicyRule {
                id: "custom.nonfinal-block-delete".into(),
                title: "Liftable block delete".into(),
                description: "Liftable block delete".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileDelete],
                    target_prefixes: vec!["prod/".into()],
                    target_contains: vec![],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Prod delete blocked.".into(),
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
            r#"r"m" -rf /tmp/scratch && git status"#,
        ),
        sample_attempt(
            "v6",
            "claude-code",
            ActionClass::Elevate,
            r#"s'u'do cat /etc/shadow"#,
        ),
        sample_attempt(
            "v7",
            "claude-code",
            ActionClass::NetRequest,
            "https://webhook.site/leak",
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
        sample_attempt(
            "v12",
            "claude-code",
            ActionClass::FileRead,
            r"C:\..\..\secrets\key.pem",
        ),
        sample_attempt(
            "v13",
            "claude-code",
            ActionClass::FileDelete,
            "prod/data.db",
        ),
        sample_attempt("v14", "claude-code", ActionClass::CredUse, "aws_sts_token"),
        sample_attempt(
            "v15",
            "claude-code",
            ActionClass::AgentSpawn,
            "subagent-helper",
        ),
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

    let mut invalid_cedar_pack = packs;
    if let Some(p) = invalid_cedar_pack.get_mut(1)
        && let Some(r) = p.rules.get_mut(0)
    {
        r.cedar = Some("permit (principal, action, resource);".into());
    }
    let safe_att = sample_attempt(
        "v_bad_cedar",
        "claude-code",
        ActionClass::Exec,
        "git status",
    );
    assert_eq!(
        evaluate(
            &safe_att,
            &invalid_cedar_pack,
            &[],
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        evaluate_ref(
            &safe_att,
            &invalid_cedar_pack,
            &[],
            &KillSwitchState::Inactive,
            now
        )
        .verdict
    );
}

#[test]
fn differential_grants_final_annotation_grades_and_session_taint_match_core_policy() {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let essentials = essentials_pack();
    let custom_pack = PolicyPack {
        id: "custom-layer".into(),
        name: "Custom Layer".into(),
        description: "Grant/final parity".into(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![
            PolicyRule {
                id: "custom.final-block".into(),
                title: "Final via annotation".into(),
                description: "Final via annotation".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileRead],
                    target_prefixes: vec!["C:/vault/".into()],
                    target_contains: vec![],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Final vault read.".into(),
                cedar: Some(
                    "@id(\"custom.final-block\")\n@mode(\"Block\")\n@final(\"true\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource) when { resource.classes.contains(\"match:custom.final-block\") };".into(),
                ),
            },
            PolicyRule {
                id: "custom.liftable-block".into(),
                title: "Liftable block".into(),
                description: "Liftable block".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileDelete],
                    target_prefixes: vec!["prod/".into()],
                    target_contains: vec![],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Prod delete requires G2 grant.".into(),
                cedar: None,
            },
        ],
        key_id: None,
        signature: None,
    };
    let packs = vec![essentials, custom_pack];

    let final_grant = Grant {
        grant_id: "grn_final_try".into(),
        rule_id: "custom.final-block".into(),
        session_id: "sess-diff-1".into(),
        device_id: "dev-diff-1".into(),
        action_class: ActionClass::FileRead,
        target_pattern: "C:/vault/key".into(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G3,
        granted_at: now,
        expires_at: Some(add_seconds(now, 60)),
        remaining_uses: Some(1),
        note: "Should not lift @final".into(),
        key_id: None,
        signature: None,
    };
    let vault_attempt = sample_attempt(
        "f1",
        "claude-code",
        ActionClass::FileRead,
        r"C:\vault\..\vault\key",
    );
    let core_final = evaluate(
        &vault_attempt,
        &packs,
        std::slice::from_ref(&final_grant),
        &KillSwitchState::Inactive,
        now,
    );
    let ref_final = evaluate_ref(
        &vault_attempt,
        &packs,
        &[final_grant],
        &KillSwitchState::Inactive,
        now,
    );
    assert_eq!(ref_final.verdict, core_final.verdict);
    assert_eq!(ref_final.grant_id, core_final.grant_id);

    let weak_grant = Grant {
        grant_id: "grn_weak".into(),
        rule_id: "custom.liftable-block".into(),
        session_id: "sess-diff-1".into(),
        device_id: "dev-diff-1".into(),
        action_class: ActionClass::FileDelete,
        target_pattern: "prod/data.db".into(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G1,
        granted_at: now,
        expires_at: Some(add_seconds(now, 60)),
        remaining_uses: Some(1),
        note: "Insufficient G1".into(),
        key_id: None,
        signature: None,
    };
    let unattributed_grant = Grant {
        grant_id: "grn_unattributed".into(),
        grade: ApprovalGrade::G2,
        note: "Insufficient G1".into(),
        ..weak_grant.clone()
    };
    let strong_grant = Grant {
        grant_id: "grn_strong".into(),
        grade: ApprovalGrade::G2,
        note: "approver:admin".into(),
        ..weak_grant.clone()
    };
    let del_attempt = sample_attempt("d1", "claude-code", ActionClass::FileDelete, "prod/data.db");
    assert_eq!(
        evaluate(
            &del_attempt,
            &packs,
            std::slice::from_ref(&unattributed_grant),
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::Deny
    );
    assert_eq!(
        evaluate_ref(
            &del_attempt,
            &packs,
            &[unattributed_grant],
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::Deny
    );
    assert_eq!(
        evaluate(
            &del_attempt,
            &packs,
            &[weak_grant],
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        evaluate_ref(
            &del_attempt,
            &packs,
            &[Grant {
                grant_id: "grn_weak".into(),
                rule_id: "custom.liftable-block".into(),
                session_id: "sess-diff-1".into(),
                device_id: "dev-diff-1".into(),
                action_class: ActionClass::FileDelete,
                target_pattern: "prod/data.db".into(),
                scope: GrantScope::Once,
                grade: ApprovalGrade::G1,
                granted_at: now,
                expires_at: Some(add_seconds(now, 60)),
                remaining_uses: Some(1),
                note: "Insufficient G1".into(),
                key_id: None,
                signature: None,
            }],
            &KillSwitchState::Inactive,
            now
        )
        .verdict
    );

    let mut core_grants = vec![strong_grant.clone()];
    let mut ref_grants = vec![strong_grant];
    let core_lifted = evaluate_mut(
        &del_attempt,
        &packs,
        &mut core_grants,
        &KillSwitchState::Inactive,
        now,
    );
    let ref_lifted = evaluate_ref_mut(
        &del_attempt,
        &packs,
        &mut ref_grants,
        &KillSwitchState::Inactive,
        now,
    );
    assert_eq!(ref_lifted.verdict, core_lifted.verdict);
    assert_eq!(ref_lifted.grant_id, core_lifted.grant_id);
    assert_eq!(
        ref_grants.first().and_then(|g| g.remaining_uses),
        core_grants.first().and_then(|g| g.remaining_uses)
    );

    let mut core_sess = SessionRuleState::new("sess-diff-1");
    let mut ref_sess = RefSessionState::new("sess-diff-1");
    let mut g_none_core = Vec::new();
    let mut g_none_ref = Vec::new();

    let session_seq = [
        sample_attempt("s1", "claude-code", ActionClass::CredUse, "aws_sts_token"),
        sample_attempt(
            "s2",
            "claude-code",
            ActionClass::NetRequest,
            "https://api.example.com/upload",
        ),
        sample_attempt(
            "s3",
            "claude-code",
            ActionClass::Exec,
            "echo $(cat ~/.ssh/id_rsa)",
        ),
        sample_attempt("s4", "claude-code", ActionClass::Exec, "bash -c \"unclosed"),
    ];

    for att in &session_seq {
        let c = evaluate_with_session(
            att,
            &packs,
            &mut g_none_core,
            &KillSwitchState::Inactive,
            &mut core_sess,
            now,
        );
        let r = evaluate_ref_with_session(
            att,
            &packs,
            &mut g_none_ref,
            &KillSwitchState::Inactive,
            &mut ref_sess,
            now,
        );
        assert_eq!(
            r.verdict, c.verdict,
            "session verdict mismatch on {}",
            att.id
        );
        assert_eq!(
            r.rule_id, c.rule_id,
            "session rule_id mismatch on {}",
            att.id
        );
    }
    assert_eq!(ref_sess.labels, core_sess.labels);

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

    // Round 4 differential parity: @max_mode, @min_grade, @approver, [epoch:0], multi-Once grants, signals essentials
    let parity_pack = PolicyPack {
        id: "custom-p2".into(),
        name: "Custom Parity".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![
            PolicyRule {
                id: "custom.max-mode-ask".into(),
                title: "Max mode caps Block->Ask".into(),
                description: String::new(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileRead],
                    target_prefixes: vec!["maxmode/".into()],
                    target_contains: Vec::new(),
                    agents: Vec::new(),
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Capped to Ask.".into(),
                cedar: Some(
                    "@id(\"custom.max-mode-ask\")\n@max_mode(\"Ask\")\n@min_grade(\"G2\")\n@approver(\"sponsor\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource) when { resource.classes.contains(\"match:custom.max-mode-ask\") };".into(),
                ),
            },
            PolicyRule {
                id: "custom.second-ask".into(),
                title: "Second Ask".into(),
                description: String::new(),
                mode: Mode::Ask,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileRead],
                    target_prefixes: vec!["multi/".into()],
                    target_contains: Vec::new(),
                    agents: Vec::new(),
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Second ask.".into(),
                cedar: None,
            },
            PolicyRule {
                id: "custom.multi-ask".into(),
                title: "Multi Ask".into(),
                description: String::new(),
                mode: Mode::Ask,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::FileRead],
                    target_prefixes: vec!["multi/".into()],
                    target_contains: Vec::new(),
                    agents: Vec::new(),
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Multi ask.".into(),
                cedar: None,
            },
        ],
        key_id: None,
        signature: None,
    };
    let p_packs = vec![essentials_pack(), parity_pack];
    let mm_att = sample_attempt("mm1", "claude-code", ActionClass::FileRead, "maxmode/f");
    let mm_self = Grant {
        grant_id: "g_self_ep".into(),
        rule_id: "custom.max-mode-ask".into(),
        session_id: "sess-diff-1".into(),
        device_id: "dev-diff-1".into(),
        action_class: ActionClass::FileRead,
        target_pattern: "maxmode/f".into(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G2,
        granted_at: now,
        expires_at: Some(add_seconds(now, 60)),
        remaining_uses: Some(1),
        note: "approver:self [epoch:0]".into(),
        key_id: Some("k1".into()),
        signature: None,
    };
    let mm_g1_sponsor = Grant {
        grant_id: "g_low".into(),
        grade: ApprovalGrade::G1,
        note: "approver:sponsor [epoch:0]".into(),
        ..mm_self.clone()
    };
    let mm_ok = Grant {
        grant_id: "g_ok".into(),
        grade: ApprovalGrade::G2,
        note: "approver:sponsor [epoch:0]".into(),
        ..mm_self.clone()
    };
    assert_eq!(
        evaluate(
            &mm_att,
            &p_packs,
            std::slice::from_ref(&mm_self),
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::StepUp
    );
    assert_eq!(
        evaluate_ref(
            &mm_att,
            &p_packs,
            std::slice::from_ref(&mm_self),
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::StepUp
    );
    assert_eq!(
        evaluate(
            &mm_att,
            &p_packs,
            std::slice::from_ref(&mm_g1_sponsor),
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::StepUp
    );
    assert_eq!(
        evaluate_ref(
            &mm_att,
            &p_packs,
            &[mm_g1_sponsor],
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::StepUp
    );
    assert_eq!(
        evaluate(
            &mm_att,
            &p_packs,
            std::slice::from_ref(&mm_ok),
            &KillSwitchState::Inactive,
            now
        )
        .verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate_ref(&mm_att, &p_packs, &[mm_ok], &KillSwitchState::Inactive, now).verdict,
        Verdict::Allow
    );

    let g_m1 = Grant {
        grant_id: "g_m1".into(),
        rule_id: "custom.second-ask".into(),
        target_pattern: "multi/".into(),
        note: "approver:self [epoch:0]".into(),
        ..mm_self
    };
    let g_m2 = Grant {
        grant_id: "g_m2".into(),
        rule_id: "custom.multi-ask".into(),
        ..g_m1.clone()
    };
    let m_att = sample_attempt("m1", "claude-code", ActionClass::FileRead, "multi/secret");
    let mut cg = vec![g_m1.clone(), g_m2.clone()];
    let mut rg = vec![g_m1, g_m2];
    assert_eq!(
        evaluate_mut(&m_att, &p_packs, &mut cg, &KillSwitchState::Inactive, now).verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate_ref_mut(&m_att, &p_packs, &mut rg, &KillSwitchState::Inactive, now).verdict,
        Verdict::Allow
    );
    assert_eq!(cg[0].remaining_uses, Some(0));
    assert_eq!(cg[1].remaining_uses, Some(0));
    assert_eq!(rg[0].remaining_uses, cg[0].remaining_uses);
    assert_eq!(rg[1].remaining_uses, cg[1].remaining_uses);

    for (id, cls, tgt) in [
        ("sig1", ActionClass::Exec, "codex --yolo"),
        ("sig2", ActionClass::Exec, "codex --disable-sandbox"),
        ("sig3", ActionClass::FileRead, "~/.gnupg/secring.gpg"),
        (
            "sig4",
            ActionClass::Exec,
            "Remove-Item -Recurse -Force ./build",
        ),
        (
            "sig5",
            ActionClass::Elevate,
            "Start-Process -Verb RunAs powershell",
        ),
    ] {
        let a = sample_attempt(id, "claude-code", cls, tgt);
        assert_eq!(
            evaluate(&a, &p_packs, &[], &KillSwitchState::Inactive, now).verdict,
            evaluate_ref(&a, &p_packs, &[], &KillSwitchState::Inactive, now).verdict,
            "essentials signal mismatch on {tgt}"
        );
    }
}
