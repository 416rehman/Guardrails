// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! CSA AARM 1.0 conformance scenarios R1 through R9 (`docs/design/29` s.7).

use std::collections::BTreeSet;

use grdr_broker::{BrokerOutcome, McpBroker};
use grdr_core::policy::{
    ReceiptDigestInput, compute_receipt_digest, essentials_pack, evaluate, evaluate_mut,
};
use grdr_crypto::{SigningKeypair, verify_receipt};
use grdr_mcp_proto::{McpAttemptContext, ToolDescriptor, parse_mcp_request};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, CodedError, ControlPoint, DecisionReceipt, Grant,
    GrantScope, KillSwitchState, PolicyPack, SignatureStatus, Verdict,
};
use grdr_policy_ref::{
    BoundaryObserver, DeriveInput, DeterminingForbid, InputValidity, LossBehaviour,
    ObligationSupport, PendingRuleRef, RemedyCapability, RuleMutability, TimelockAllowance,
    derive_verdict,
};
use grdr_ports::DecisionEnginePort;
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};
use jiff::Timestamp;
use serde_json::json;

use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

struct CorePort {
    packs: Vec<PolicyPack>,
    grants: Vec<Grant>,
}

impl DecisionEnginePort for CorePort {
    fn load_packs(&mut self, packs: Vec<PolicyPack>) -> Result<(), CodedError> {
        self.packs = packs;
        Ok(())
    }

    fn add_grant(&mut self, grant: Grant) -> Result<(), CodedError> {
        self.grants.push(grant);
        Ok(())
    }

    fn evaluate(&mut self, attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError> {
        Ok(evaluate_mut(
            attempt,
            &self.packs,
            &mut self.grants,
            &KillSwitchState::Inactive,
            attempt.timestamp,
        ))
    }
}

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

fn attempt(id: &str, class: ActionClass, target: &str, now: Timestamp) -> ActionAttempt {
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

    let no_grant = evaluate(&ssh_read, packs, &[], &KillSwitchState::Inactive, now);
    if no_grant.verdict != Verdict::StepUp {
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

    let mut grants = vec![Grant {
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
    }];
    let granted = evaluate_mut(
        &ssh_read,
        packs,
        &mut grants,
        &KillSwitchState::Inactive,
        now,
    );
    if granted.verdict != Verdict::Allow {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R4".into(),
            detail: "valid grant failed to allow approved retry".into(),
        });
    }

    Ok(pass(
        "AARM-R4",
        "Approval checkpoint and unavailable-approver fail-closed",
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

fn check_r6_attribution_and_principal(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let att = attempt("aarm-r6", ActionClass::Exec, "git status", now);
    let receipt = evaluate(&att, packs, &[], &KillSwitchState::Inactive, now);
    if receipt.agent_name != "claude-code" || receipt.session_id != "ses_aarm_1" {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R6".into(),
            detail: "missing agent or session attribution on receipt".into(),
        });
    }
    Ok(pass("AARM-R6", "Per-agent and session attribution binding"))
}

fn check_r7_supplychain_mcp_pin_drift(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let engine = CorePort {
        packs: packs.to_vec(),
        grants: vec![],
    };
    let mut broker = McpBroker::new(engine);
    let clean = ToolDescriptor {
        name: "read_file".into(),
        description: "Read repository file".into(),
        input_schema: json!({"type": "object"}),
    };
    let _ = broker
        .register_or_verify_tools("fs", std::slice::from_ref(&clean))
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R7".into(),
            detail: e.to_string(),
        })?;

    let mut drifted = clean;
    drifted.description = "Silent schema mutation".into();
    let req = parse_mcp_request(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"Cargo.toml"}}}"#,
    )
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "AARM-R7".into(),
        detail: e.to_string(),
    })?;
    let ctx = McpAttemptContext {
        attempt_id: "aarm-r7".into(),
        session_id: "ses_aarm_1".into(),
        device_id: "dev_aarm_1".into(),
        device_name: "conformance-host".into(),
        agent_name: "claude-code".into(),
        server_name: "fs".into(),
        timestamp: now,
    };
    let outcome = broker
        .mediate_call(&req, Some(&drifted), &ctx)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R7".into(),
            detail: e.to_string(),
        })?;
    if !matches!(outcome, BrokerOutcome::Block { .. }) {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R7".into(),
            detail: "MCP manifest pin drift was not blocked".into(),
        });
    }
    Ok(pass(
        "AARM-R7",
        "Supply-chain MCP manifest pin drift detection",
    ))
}

fn check_r8_export_digest_integrity(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let att = attempt(
        "aarm-r8",
        ActionClass::FileWrite,
        ".claude/settings.json",
        now,
    );
    let receipt = evaluate(&att, packs, &[], &KillSwitchState::Inactive, now);
    let recomputed = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &receipt.attempt_id,
        session_id: &receipt.session_id,
        agent_name: &receipt.agent_name,
        action_class: receipt.action_class,
        target: &receipt.target,
        verdict: receipt.verdict,
        rule_id: receipt.rule_id.as_deref(),
        decided_at: receipt.decided_at,
    });
    if recomputed != receipt.receipt_digest {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R8".into(),
            detail: "receipt digest did not match canonical computation".into(),
        });
    }
    Ok(pass(
        "AARM-R8",
        "Structured telemetry export digest integrity",
    ))
}

fn check_r9_containment_secret_isolation() -> Result<ScenarioResult, ConformanceError> {
    let spec = SandboxSpec {
        session_id: "ses_aarm_9".into(),
        agent_name: "claude-code".into(),
        mode: ContainmentMode::WorkspaceContained,
        workdir: None,
        extra_allow_env: vec![],
        strip_secret_env: true,
    };
    let env = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("AWS_SECRET_ACCESS_KEY".into(), "secret_xyz".into()),
    ];
    let (_cmd, report) = prepare_contained_command("git", &["status".into()], &spec, &env)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R9".into(),
            detail: e.to_string(),
        })?;
    if !report
        .stripped_env_vars
        .iter()
        .any(|k| k == "AWS_SECRET_ACCESS_KEY")
    {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R9".into(),
            detail: "sensitive env credential was not stripped in contained sandbox".into(),
        });
    }
    Ok(pass(
        "AARM-R9",
        "Scoped credential isolation and sandbox containment",
    ))
}

fn pass(id: &str, title: &str) -> ScenarioResult {
    ScenarioResult {
        id: id.into(),
        category: ScenarioCategory::Aarm,
        title: title.into(),
        outcome: ScenarioOutcome::Pass,
        detail: "verified".into(),
    }
}
