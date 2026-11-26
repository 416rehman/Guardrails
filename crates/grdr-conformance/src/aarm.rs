// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! CSA AARM 1.0 conformance scenarios R1 through R5 (`docs/design/29` s.7).

use std::collections::BTreeSet;

use grdr_core::policy::{essentials_pack, evaluate, evaluate_mut};
use grdr_crypto::SigningKeypair;
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, Grant, GrantScope, KillSwitchState,
    PolicyPack, PolicyRule, RuleMatch, SignatureStatus, SigningKeypairExt as _, Verdict,
    verify_receipt,
};
use grdr_policy_ref::{
    BoundaryObserver, DeriveInput, DeterminingForbid, InputValidity, LossBehaviour,
    ObligationSupport, PendingRuleRef, RemedyCapability, RuleMutability, TimelockAllowance,
    derive_verdict,
};
use jiff::Timestamp;

use crate::aarm_tail::{
    check_r6_attribution_and_principal, check_r7_supplychain_mcp_pin_drift,
    check_r8_export_digest_integrity, check_r9_containment_secret_isolation,
};
use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

pub fn run_aarm_r1_to_r9() -> Result<Vec<ScenarioResult>, ConformanceError> {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let packs = vec![essentials_pack()];

    let r1 = check_r1_preexec_classification(&packs, now)?;
    let r2 = check_r2_five_verdicts_and_deny_wins()?;
    let r3 = check_r3_control_files_and_bypass(&packs, now)?;
    let r4 = check_r4_approval_and_unavailable_fails(&packs, now)?;
    let r5 = check_r5_offline_signed_receipt_verify(&packs, now)?;
    let r6 = check_r6_attribution_and_principal(&packs, now)?;
    let r7 = check_r7_supplychain_mcp_pin_drift(&packs, now)?;
    let r8 = check_r8_export_digest_integrity(&packs, now)?;
    let r9 = check_r9_containment_secret_isolation()?;

    Ok(vec![r1, r2, r3, r4, r5, r6, r7, r8, r9])
}

pub(crate) fn attempt(id: &str, class: ActionClass, target: &str, now: Timestamp) -> ActionAttempt {
    ActionAttempt {
        id: id.into(),
        session_id: "ses_aarm_1".into(),
        device_id: "dev_aarm_1".into(),
        device_name: "conformance-host".into(),
        agent_name: "claude-code".into(),
        action_class: class,
        control_point: ControlPoint::Hook,
        target: target.into(),
        summary: target.into(),
        timestamp: now,
        user_id: Some("prn_aarm_user".into()),
        ..Default::default()
    }
}

pub(crate) fn pass(id: &str, title: &str) -> ScenarioResult {
    ScenarioResult {
        id: id.into(),
        category: ScenarioCategory::Aarm,
        title: title.into(),
        outcome: ScenarioOutcome::Pass,
        detail: "verified".into(),
    }
}

fn check_r1_preexec_classification(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let att = attempt("aarm-r1", ActionClass::Exec, "git status", now);
    let receipt = evaluate(&att, packs, &[], &KillSwitchState::Inactive, now);
    if receipt.verdict != Verdict::Allow || receipt.action_class != ActionClass::Exec {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R1".into(),
            detail: "safe exec attempt did not allow cleanly".into(),
        });
    }
    Ok(pass(
        "AARM-R1",
        "Pre-execution interception and action classification",
    ))
}

fn check_r2_five_verdicts_and_deny_wins() -> Result<ScenarioResult, ConformanceError> {
    let base = DeriveInput {
        validity: InputValidity::Valid,
        modify_attempts: 0,
        device_max_grade: ApprovalGrade::G2,
        timelock: TimelockAllowance::Unavailable,
        base_permit: ObligationSupport::Supported,
        observer: BoundaryObserver::None,
        snapshot_required: ObligationSupport::Unsupported,
        control_snapshot: ObligationSupport::Supported,
        control_modify: ObligationSupport::Supported,
        determining_forbids: vec![],
        pending_rules: vec![],
        not_evaluable_rules: vec![],
    };

    let allow = derive_verdict(&base);
    let mut defer_in = base.clone();
    defer_in.pending_rules.push(PendingRuleRef {
        rule_id: "mcp.pin".into(),
    });
    let defer = derive_verdict(&defer_in);

    let mut modify_in = base.clone();
    modify_in.determining_forbids.push(DeterminingForbid {
        rule_id: "secrets.redact".into(),
        mode: grdr_model::Mode::Ask,
        min_grade: ApprovalGrade::G1,
        mutability: RuleMutability::Liftable,
        remedy: RemedyCapability::ModifyTransform,
        on_loss: LossBehaviour::AllowOnLoss,
    });
    let modify = derive_verdict(&modify_in);

    let mut deny_wins_in = base;
    deny_wins_in.determining_forbids.push(DeterminingForbid {
        rule_id: "custom.ask".into(),
        mode: grdr_model::Mode::Ask,
        min_grade: ApprovalGrade::G1,
        mutability: RuleMutability::Liftable,
        remedy: RemedyCapability::Plain,
        on_loss: LossBehaviour::AllowOnLoss,
    });
    let step_up = derive_verdict(&deny_wins_in);

    deny_wins_in.determining_forbids.push(DeterminingForbid {
        rule_id: "essentials.block".into(),
        mode: grdr_model::Mode::Block,
        min_grade: ApprovalGrade::G2,
        mutability: RuleMutability::Final,
        remedy: RemedyCapability::Plain,
        on_loss: LossBehaviour::FailClosed,
    });
    let deny = derive_verdict(&deny_wins_in);

    let distinct = BTreeSet::from([
        format!("{allow:?}"),
        format!("{modify:?}"),
        format!("{step_up:?}"),
        format!("{defer:?}"),
        format!("{deny:?}"),
    ]);
    if distinct.len() != 5 || deny != Verdict::Deny {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R2".into(),
            detail: "five AARM verdicts or deny-wins invariant failed".into(),
        });
    }
    Ok(pass(
        "AARM-R2",
        "Five AARM verdicts and deny-wins precedence",
    ))
}

fn check_r3_control_files_and_bypass(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let write_ctrl = evaluate(
        &attempt(
            "aarm-r3a",
            ActionClass::FileWrite,
            ".claude/settings.json",
            now,
        ),
        packs,
        &[],
        &KillSwitchState::Inactive,
        now,
    );
    let bypass = evaluate(
        &attempt(
            "aarm-r3b",
            ActionClass::Exec,
            "claude --dangerously-skip-permissions",
            now,
        ),
        packs,
        &[],
        &KillSwitchState::Inactive,
        now,
    );
    if write_ctrl.verdict != Verdict::Deny || bypass.verdict != Verdict::Deny {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R3".into(),
            detail: "control-file write or bypass flag was not denied".into(),
        });
    }
    Ok(pass("AARM-R3", "Control-file and bypass protection"))
}

fn check_r4_approval_and_unavailable_fails(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let ssh_read = attempt(
        "aarm-r4",
        ActionClass::FileRead,
        "/home/dev/.ssh/id_rsa",
        now,
    );

    if evaluate(&ssh_read, packs, &[], &KillSwitchState::Inactive, now).verdict != Verdict::StepUp {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R4".into(),
            detail: "expected StepUp before approval grant".into(),
        });
    }

    let unavail_input = DeriveInput {
        validity: InputValidity::Valid,
        modify_attempts: 0,
        device_max_grade: ApprovalGrade::G0,
        timelock: TimelockAllowance::Unavailable,
        base_permit: ObligationSupport::Supported,
        observer: BoundaryObserver::None,
        snapshot_required: ObligationSupport::Unsupported,
        control_snapshot: ObligationSupport::Supported,
        control_modify: ObligationSupport::Supported,
        determining_forbids: vec![DeterminingForbid {
            rule_id: "essentials.credential-stores".into(),
            mode: grdr_model::Mode::Ask,
            min_grade: ApprovalGrade::G1,
            mutability: RuleMutability::Liftable,
            remedy: RemedyCapability::Plain,
            on_loss: LossBehaviour::FailClosed,
        }],
        pending_rules: vec![],
        not_evaluable_rules: vec![],
    };
    if derive_verdict(&unavail_input) != Verdict::Deny {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R4".into(),
            detail: "system unavailable must fail closed with Deny".into(),
        });
    }

    let valid_grant = Grant {
        grant_id: "grn_aarm_r4".into(),
        rule_id: "essentials.credential-stores".into(),
        session_id: "ses_aarm_1".into(),
        device_id: "dev_aarm_1".into(),
        action_class: ActionClass::FileRead,
        target_pattern: "/home/dev/.ssh/id_rsa".into(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G1,
        granted_at: now,
        expires_at: Some(add_seconds(now, 60)),
        remaining_uses: Some(1),
        note: "AARM R4 approval".into(),
        key_id: None,
        signature: None,
    };

    let bad_grants = [
        Grant {
            expires_at: Some(add_seconds(now, -5)),
            ..valid_grant.clone()
        },
        Grant {
            session_id: "ses_other".into(),
            ..valid_grant.clone()
        },
        Grant {
            device_id: "dev_other".into(),
            ..valid_grant.clone()
        },
    ];
    for bad_grant in bad_grants {
        if evaluate(
            &ssh_read,
            packs,
            &[bad_grant],
            &KillSwitchState::Inactive,
            now,
        )
        .verdict
            != Verdict::StepUp
        {
            return Err(ConformanceError::ScenarioFailed {
                scenario_id: "AARM-R4".into(),
                detail: "expired or mismatched-scope grant unexpectedly allowed".into(),
            });
        }
    }

    let g2_pack = PolicyPack {
        id: "r4-g2".into(),
        name: "R4 G2".into(),
        description: "Requires G2 approval".into(),
        version: "1.0.0".into(),
        channel: "test".into(),
        rules: vec![PolicyRule {
            id: "r4.g2-delete".into(),
            title: "G2 delete".into(),
            description: "G2 delete".into(),
            mode: grdr_model::Mode::Ask,
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
            reason_template: "Needs G2".into(),
            cedar: None,
        }],
        key_id: None,
        signature: None,
    };
    let g1_insufficient = Grant {
        rule_id: "r4.g2-delete".into(),
        action_class: ActionClass::FileDelete,
        target_pattern: "prod/app.db".into(),
        grade: ApprovalGrade::G1,
        ..valid_grant.clone()
    };
    let del_att = attempt("aarm-r4-g2", ActionClass::FileDelete, "prod/app.db", now);
    if evaluate(
        &del_att,
        &[g2_pack],
        &[g1_insufficient],
        &KillSwitchState::Inactive,
        now,
    )
    .verdict
        != Verdict::StepUp
    {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R4".into(),
            detail: "insufficient G1 grant allowed a G2 rule".into(),
        });
    }

    let mut grants = vec![valid_grant];
    let first = evaluate_mut(
        &ssh_read,
        packs,
        &mut grants,
        &KillSwitchState::Inactive,
        now,
    );
    let replay = evaluate_mut(
        &ssh_read,
        packs,
        &mut grants,
        &KillSwitchState::Inactive,
        add_seconds(now, 1),
    );
    if first.verdict != Verdict::Allow || replay.verdict != Verdict::StepUp {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R4".into(),
            detail: "single-use grant must allow once and block replay".into(),
        });
    }

    Ok(pass(
        "AARM-R4",
        "Approval checkpoint, scope/grade rejection, replay denial, and fail-closed",
    ))
}

fn check_r5_offline_signed_receipt_verify(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let kp = SigningKeypair::generate().map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "AARM-R5".into(),
        detail: e.to_string(),
    })?;
    let mut receipt = evaluate(
        &attempt(
            "aarm-r5",
            ActionClass::FileWrite,
            ".claude/settings.json",
            now,
        ),
        packs,
        &[],
        &KillSwitchState::Inactive,
        now,
    );
    kp.sign_receipt(&mut receipt)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R5".into(),
            detail: e.to_string(),
        })?;
    if verify_receipt(&receipt, &[kp.public_info()]) != SignatureStatus::Verified {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R5".into(),
            detail: "offline receipt verification failed".into(),
        });
    }
    receipt.verdict = Verdict::Allow;
    if verify_receipt(&receipt, &[kp.public_info()]) != SignatureStatus::Invalid {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R5".into(),
            detail: "tampered receipt verified unexpectedly".into(),
        });
    }
    Ok(pass(
        "AARM-R5",
        "Offline signed decision receipt verification",
    ))
}
