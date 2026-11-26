// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended differential parity tests between `grdr-policy-ref` and `grdr-core` `Engine`.

use std::collections::BTreeSet;

use grdr_core::policy::{
    ActorKind, CompileOptions, DeterministicEntropy, Engine, EngineInput, EngineOutput,
    RequestBuildOptions, VerifiedBundle, compile_packs_with_options,
    degrade_verdict as core_degrade_verdict, derive_verdict as core_derive_verdict,
    effective_timelock_allowance, essentials_pack, evaluate,
};
use grdr_model::eval::SigningKeypair;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, BoundaryObserver, ControlPoint, ControlPointCaps,
    DeriveInput, DeterminingForbid, FailureDisposition, HoldCapability, IdentityMode,
    InputValidity, InstallProfile, KillSwitchState, LayerKind, LossBehaviour, Mode,
    NotEvaluableRuleRef, ObligationSupport, PendingRuleRef, PolicyPack, PolicyRule,
    RemedyCapability, RuleMatch, RuleMutability, SessionLabel, SigningKeypairExt as _, Verdict,
    VerdictDiscriminant,
};
use grdr_policy_ref::{
    RefSessionState, degrade_verdict as ref_degrade_verdict, derive_verdict as ref_derive_verdict,
    evaluate_ref, evaluate_ref_with_session,
};
use jiff::Timestamp;

fn sample_attempt(id: &str, class: ActionClass, target: &str) -> ActionAttempt {
    ActionAttempt {
        id: id.into(),
        session_id: "sess-eng-diff".into(),
        device_id: "dev-eng-diff".into(),
        device_name: "host-eng".into(),
        agent_name: "claude-code".into(),
        action_class: class,
        control_point: ControlPoint::Hook,
        target: target.into(),
        summary: target.into(),
        timestamp: Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        ..Default::default()
    }
}

#[test]
fn core_and_reference_verdict_matrices_match_over_128_combinations() {
    let cps = [
        ControlPointCaps {
            verbs: BTreeSet::from([
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
            ]),
            hold: HoldCapability::NoHold,
            failure_mode: FailureDisposition::Open,
            snapshot: ObligationSupport::Unsupported,
            modify: ObligationSupport::Unsupported,
        },
        ControlPointCaps {
            verbs: BTreeSet::from([
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Modify,
                VerdictDiscriminant::StepUp,
                VerdictDiscriminant::Defer,
                VerdictDiscriminant::Deny,
            ]),
            hold: HoldCapability::CanHold { deadline_ms: 8000 },
            failure_mode: FailureDisposition::Closed,
            snapshot: ObligationSupport::Supported,
            modify: ObligationSupport::Supported,
        },
        ControlPointCaps {
            verbs: BTreeSet::from([VerdictDiscriminant::Allow]),
            hold: HoldCapability::NoHold,
            failure_mode: FailureDisposition::Open,
            snapshot: ObligationSupport::Unsupported,
            modify: ObligationSupport::Unsupported,
        },
    ];

    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..128u64 {
        rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let validity = match (rng >> 1) % 3 {
            0 => InputValidity::Valid,
            1 => InputValidity::Malformed,
            _ => InputValidity::EvalError,
        };
        let mode = if (rng >> 3) & 1 == 0 {
            Mode::Ask
        } else {
            Mode::Block
        };
        let min_grade = match (rng >> 4) % 3 {
            0 => ApprovalGrade::G0,
            1 => ApprovalGrade::G1,
            _ => ApprovalGrade::G2,
        };
        let device_max_grade = match (rng >> 6) % 3 {
            0 => ApprovalGrade::G0,
            1 => ApprovalGrade::G1,
            _ => ApprovalGrade::G2,
        };
        let remedy = if (rng >> 8) & 1 == 0 {
            RemedyCapability::Plain
        } else {
            RemedyCapability::ModifyTransform
        };
        let on_loss = match (rng >> 9) % 3 {
            0 => LossBehaviour::AllowOnLoss,
            1 => LossBehaviour::FailClosed,
            _ => LossBehaviour::Block,
        };
        let timelock = effective_timelock_allowance(
            InstallProfile::User,
            &["user.rule"],
            (rng >> 11) & 1 == 0,
            (rng >> 12) & 1 == 0,
        );
        let has_forbid = (rng >> 13) & 1 == 0;
        let two_forbids = (rng >> 23) & 1 == 0;
        let has_pending = (rng >> 14) & 1 == 0;
        let has_ne = (rng >> 15) & 1 == 0;
        let ne_lifted = if (rng >> 24) & 1 == 0 {
            ObligationSupport::Supported
        } else {
            ObligationSupport::Unsupported
        };
        let caps = &cps[((rng >> 16) as usize) % cps.len()];

        let forbids = if !has_forbid {
            vec![]
        } else if two_forbids {
            vec![
                DeterminingForbid {
                    rule_id: format!("user.r{i}.a"),
                    mode,
                    min_grade,
                    mutability: RuleMutability::Liftable,
                    remedy,
                    on_loss,
                },
                DeterminingForbid {
                    rule_id: format!("user.r{i}.b"),
                    mode: Mode::Block,
                    min_grade: ApprovalGrade::G2,
                    mutability: RuleMutability::Liftable,
                    remedy: RemedyCapability::Plain,
                    on_loss: LossBehaviour::Block,
                },
            ]
        } else {
            vec![DeterminingForbid {
                rule_id: format!("user.r{i}"),
                mode,
                min_grade,
                mutability: RuleMutability::Liftable,
                remedy,
                on_loss,
            }]
        };

        let input = DeriveInput {
            validity,
            modify_attempts: ((rng >> 18) % 3) as u8,
            device_max_grade,
            timelock,
            base_permit: if (rng >> 20) & 1 == 0 {
                ObligationSupport::Supported
            } else {
                ObligationSupport::Unsupported
            },
            observer: if (rng >> 21) & 1 == 0 {
                BoundaryObserver::None
            } else {
                BoundaryObserver::ScopedBoundary
            },
            snapshot_required: if (rng >> 22) & 1 == 0 {
                ObligationSupport::Unsupported
            } else {
                ObligationSupport::Supported
            },
            control_snapshot: caps.snapshot,
            control_modify: caps.modify,
            determining_forbids: forbids,
            pending_rules: if has_pending {
                vec![PendingRuleRef {
                    rule_id: "mcp.pin".into(),
                }]
            } else {
                vec![]
            },
            not_evaluable_rules: if has_ne {
                vec![NotEvaluableRuleRef {
                    rule_id: "cloud.verify".into(),
                    on_loss,
                    grant_lifted: ne_lifted,
                }]
            } else {
                vec![]
            },
        };

        let cv = core_derive_verdict(&input);
        let rv = ref_derive_verdict(&input);
        assert_eq!(cv, rv, "matrix verdict mismatch at iter {i}: {input:?}");

        let min_ok = device_max_grade >= min_grade;
        let ce = core_degrade_verdict(cv, caps, min_ok, timelock);
        let re = ref_degrade_verdict(rv, caps, min_ok, timelock);
        assert_eq!(ce, re, "degraded verb mismatch at iter {i}: {cv:?}");
    }

    let mut ess = essentials_pack();
    if let Some(first) = ess.rules.first_mut() {
        first.cedar = Some(grdr_core::policy::ESSENTIALS_PARITY_CEDAR.into());
    }
    let bhash = VerifiedBundle::compute_bundle_hash(
        std::slice::from_ref(&ess),
        &[],
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
    );
    let b_ne = VerifiedBundle::new_verified(
        "diff-ne".into(),
        bhash,
        "1.0.0".into(),
        vec![ess],
        Vec::new(),
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
        Vec::new(),
    )
    .unwrap();
    assert!(Engine::load(b_ne, [5u8; 32], Timestamp::UNIX_EPOCH).is_ok());
}

#[test]
fn honeytoken_remains_blocked_for_process_principal_and_untrusted_packs_cannot_shadow_base() {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let mut ess = essentials_pack();
    ess.rules[0].cedar = Some(grdr_core::policy::ESSENTIALS_PARITY_CEDAR.into());
    let kp = SigningKeypair::generate().unwrap();
    kp.sign_pack(&mut ess).unwrap();
    let ess_hash = VerifiedBundle::compute_bundle_hash(
        std::slice::from_ref(&ess),
        &[],
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
    );
    let mut tampered = ess.clone();
    tampered.version = "9.9.9".into();
    let bad_hash = VerifiedBundle::compute_bundle_hash(
        std::slice::from_ref(&tampered),
        &[],
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
    );
    assert!(
        VerifiedBundle::new_verified(
            "diff-tampered".into(),
            bad_hash,
            "1.0.0".into(),
            vec![tampered],
            Vec::new(),
            IdentityMode::Named,
            InstallProfile::Protected,
            false,
            ApprovalGrade::G2,
            vec![kp.public_info()],
        )
        .is_err()
    );
    let bundle = VerifiedBundle::new_verified(
        "diff-eng".into(),
        ess_hash,
        "1.0.0".into(),
        vec![ess],
        Vec::new(),
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
        vec![kp.public_info()],
    )
    .unwrap();

    let snap_key = [7u8; 32];
    assert!(Engine::load(bundle.clone(), [0u8; 32], now).is_err());
    let mut eng = Engine::load(bundle.clone(), snap_key, now).unwrap();
    let mut ent = DeterministicEntropy::from_seed_bytes(b"diff-proc");
    let att = sample_attempt("ht-1", ActionClass::CredUse, "honeytoken_prod");
    let proc_opts = RequestBuildOptions {
        actor_kind: ActorKind::Human,
        attribution_grade: ApprovalGrade::G0,
        min_attribution_grade: ApprovalGrade::G1,
        ..Default::default()
    };
    let EngineOutput::Evaluated { receipt, .. } = eng
        .step(
            EngineInput::Evaluate {
                attempt: att,
                options: Box::new(proc_opts),
                host_deadline_ms: None,
            },
            &mut ent,
            now,
        )
        .unwrap()
    else {
        panic!("expected Evaluated");
    };
    assert_ne!(receipt.verdict, Verdict::Allow);
    assert_eq!(receipt.verdict, Verdict::Deny);

    let snap = eng.snapshot();
    assert!(Engine::restore(bundle.clone(), snap.clone(), &snap_key, now).is_ok());
    assert!(Engine::restore(bundle, snap, &[8u8; 32], now).is_err());

    let rogue_base = PolicyPack {
        id: "rogue".into(),
        name: "Rogue".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![PolicyRule {
            id: "grdr.base.fake".into(),
            title: "Rogue".into(),
            description: String::new(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G0,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: Vec::new(),
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Rogue".into(),
            cedar: Some("permit (principal, action, resource);".into()),
        }],
        key_id: None,
        signature: None,
    };
    assert!(
        compile_packs_with_options(
            &[rogue_base],
            &KillSwitchState::Inactive,
            "s",
            "d",
            &CompileOptions {
                identity_mode: IdentityMode::Named,
                pack_layer: LayerKind::User,
                ..CompileOptions::default()
            },
            now,
        )
        .is_err()
    );
}

#[test]
fn randomized_differential_parity_core_ref_and_binary_floor() {
    use grdr_core::compile::{compile_binary_floor_table, evaluate_binary_floor};

    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let packs = vec![essentials_pack()];
    let binary_floor = compile_binary_floor_table(&packs).unwrap();

    let agents = ["claude-code", "cursor", "codex", "unknown-agent"];
    let samples = [
        (ActionClass::FileWrite, ".claude/settings.json"),
        (ActionClass::FileWrite, "src/main.rs"),
        (ActionClass::FileDelete, ".claude/hooks/pre.js"),
        (ActionClass::FileDelete, "tmp/scratch.txt"),
        (ActionClass::Exec, "claude --dangerously-skip-permissions"),
        (ActionClass::Exec, "rm -rf /var/tmp/bad"),
        (ActionClass::Exec, "sudo apt-get update"),
        (ActionClass::Exec, "git status"),
        (ActionClass::FileRead, "~/.ssh/id_ed25519"),
        (ActionClass::FileRead, "README.md"),
        (ActionClass::CredUse, "aws_sts_token"),
        (ActionClass::Elevate, "sudo -i"),
        (ActionClass::NetRequest, "https://pastebin.com/raw/test"),
        (ActionClass::NetRequest, "https://api.example.com/v1/health"),
        (ActionClass::McpCall, "github.write_issue"),
    ];

    let mut rng: u64 = 0x5EED_CAFE_1234_ABCD;
    for iter in 0..200u64 {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let agent = agents[(rng as usize) % agents.len()];
        let (class, target) = samples[((rng >> 16) as usize) % samples.len()];
        let mut att = sample_attempt(&format!("rnd_{iter}"), class, target);
        att.agent_name = agent.into();

        let core_r = evaluate(&att, &packs, &[], &KillSwitchState::Inactive, now);
        let ref_r = evaluate_ref(&att, &packs, &[], &KillSwitchState::Inactive, now);
        assert_eq!(
            ref_r.verdict, core_r.verdict,
            "iter {iter} mismatch on {target}"
        );
        assert_eq!(
            ref_r.rule_id, core_r.rule_id,
            "iter {iter} rule mismatch on {target}"
        );

        let principal_sess = iter & 1 == 0;
        let labels: &[SessionLabel] = if iter % 3 == 0 {
            &[SessionLabel::CredentialAccessed]
        } else {
            &[]
        };
        if let Some(floor_hit) =
            evaluate_binary_floor(&binary_floor, class, principal_sess, labels, agent, target)
                .unwrap()
        {
            if principal_sess {
                assert_eq!(core_r.verdict, Verdict::Deny);
                assert_eq!(Some(floor_hit.rule_id), core_r.rule_id);
            }
        } else if principal_sess
            && core_r.verdict == Verdict::Deny
            && matches!(
                core_r.rule_id.as_deref(),
                Some("essentials.agent-control-files" | "essentials.hook-bypass")
            )
        {
            panic!(
                "floor missed locked Block rule {:?} on {target}",
                core_r.rule_id
            );
        }
    }

    let mut ref_s = RefSessionState::new("sess-diff-eng");
    let mut g_empty = Vec::new();
    let d_ht = evaluate_ref_with_session(
        &sample_attempt("rht", ActionClass::CredUse, "honeytoken_prod"),
        &packs,
        &mut g_empty,
        &KillSwitchState::Inactive,
        &mut ref_s,
        now,
    );
    assert_ne!(d_ht.verdict, Verdict::Deny);
    let mut ess_parity = essentials_pack();
    ess_parity.rules[0].cedar = Some(grdr_core::policy::ESSENTIALS_PARITY_CEDAR.into());
    let eng_bundle_hash = VerifiedBundle::compute_bundle_hash(
        std::slice::from_ref(&ess_parity),
        &[],
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
    );
    let eng_bundle = VerifiedBundle::new_verified(
        "eng-parity".into(),
        eng_bundle_hash,
        "1.0.0".into(),
        vec![ess_parity],
        Vec::new(),
        IdentityMode::Named,
        InstallProfile::Protected,
        false,
        ApprovalGrade::G2,
        Vec::new(),
    )
    .unwrap();
    let mut eng = Engine::load(eng_bundle, [1u8; 32], now).unwrap();
    let mut ent = DeterministicEntropy::from_seed_bytes(b"diff-p");
    let bypass_spawn = sample_attempt(
        "sp-1",
        ActionClass::AgentSpawn,
        "claude --dangerously-skip-permissions",
    );
    let EngineOutput::Evaluated { receipt: r_sp, .. } = eng
        .step(
            EngineInput::Evaluate {
                attempt: bypass_spawn,
                options: Box::new(RequestBuildOptions::default()),
                host_deadline_ms: None,
            },
            &mut ent,
            now,
        )
        .unwrap()
    else {
        panic!("expected Evaluated");
    };
    assert_eq!(r_sp.verdict, Verdict::Deny);
}
