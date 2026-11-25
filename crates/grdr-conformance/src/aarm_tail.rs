// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! CSA AARM 1.0 conformance scenarios R6 through R9 (`docs/design/29` s.7).

use grdr_broker::{BrokerOutcome, McpBroker};
use grdr_core::policy::{
    ReceiptDigestInput, compute_receipt_digest, evaluate, evaluate_mut, evaluate_with_session,
};
use grdr_core::session::SessionRuleState;
use grdr_crypto::SigningKeypair;
use grdr_export::{
    ExportFormat, RedactionPolicy, receipt_to_ocsf19, sign_export_bundle, verify_export_bundle,
};
use grdr_mcp_proto::{McpAttemptContext, ToolDescriptor, parse_mcp_request};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, ControlPoint, DecisionReceipt, Grant, KillSwitchState,
    PolicyPack, SessionLabel, Verdict,
};
use grdr_ports::DecisionEnginePort;
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};
use grdr_schema::{SchemaKind, schema_for, validate_json};
use jiff::Timestamp;
use serde_json::json;

use crate::aarm::{attempt, pass};
use crate::{ConformanceError, ScenarioResult};

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

pub(crate) fn check_r6_attribution_and_principal(
    packs: &[PolicyPack],
    now: Timestamp,
) -> Result<ScenarioResult, ConformanceError> {
    let att = attempt("aarm-r6", ActionClass::Exec, "git status", now);
    let receipt = evaluate(&att, packs, &[], &KillSwitchState::Inactive, now);
    if receipt.agent_name != "claude-code"
        || receipt.session_id != "ses_aarm_1"
        || receipt.device_id != "dev_aarm_1"
        || receipt.control_point != ControlPoint::Hook
    {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R6".into(),
            detail: "missing agent, session, device, or control-point attribution binding".into(),
        });
    }

    let mut session = SessionRuleState::new("ses_aarm_1");
    let mut grants = Vec::new();
    let cred_att = attempt("aarm-r6-cred", ActionClass::CredUse, "aws_sts_token", now);
    let _ = evaluate_with_session(
        &cred_att,
        packs,
        &mut grants,
        &KillSwitchState::Inactive,
        &mut session,
        add_seconds(now, 1),
    );
    let exfil_att = attempt(
        "aarm-r6-exfil",
        ActionClass::NetRequest,
        "https://api.example.com/upload",
        add_seconds(now, 2),
    );
    let exfil_rcpt = evaluate_with_session(
        &exfil_att,
        packs,
        &mut grants,
        &KillSwitchState::Inactive,
        &mut session,
        add_seconds(now, 2),
    );
    if exfil_rcpt.verdict != Verdict::StepUp
        || !session.labels.contains(&SessionLabel::TaintedExfilRisk)
    {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R6".into(),
            detail: "session taint did not escalate outbound call after credential access".into(),
        });
    }
    Ok(pass(
        "AARM-R6",
        "Per-agent, session, device attribution binding and session taint",
    ))
}

pub(crate) fn check_r7_supplychain_mcp_pin_drift(
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

pub(crate) fn check_r8_export_digest_integrity(
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

    let tampered_digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &receipt.attempt_id,
        session_id: &receipt.session_id,
        agent_name: &receipt.agent_name,
        action_class: receipt.action_class,
        target: &receipt.target,
        verdict: Verdict::Allow,
        rule_id: receipt.rule_id.as_deref(),
        decided_at: receipt.decided_at,
    });
    if tampered_digest == receipt.receipt_digest {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R8".into(),
            detail: "tampered verdict collided with receipt digest".into(),
        });
    }

    let ocsf = receipt_to_ocsf19(&receipt, RedactionPolicy::StrictP8);
    if validate_json(&schema_for(SchemaKind::OcsfEvent), &ocsf).is_err() {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R8".into(),
            detail: "exported OCSF 1.9 record failed schema validation".into(),
        });
    }

    let kp = SigningKeypair::generate().map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "AARM-R8".into(),
        detail: e.to_string(),
    })?;
    let mut bundle = sign_export_bundle(
        "exp_aarm_r8",
        std::slice::from_ref(&receipt),
        ExportFormat::Ocsf19Jsonl,
        RedactionPolicy::StrictP8,
        &kp,
        now,
    )
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "AARM-R8".into(),
        detail: e.to_string(),
    })?;
    if verify_export_bundle(&bundle, &kp.public_key_b64()).is_err() {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R8".into(),
            detail: "signed OCSF export bundle failed verification".into(),
        });
    }
    bundle.records_jsonl.push_str("\ntampered");
    if verify_export_bundle(&bundle, &kp.public_key_b64()).is_ok() {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R8".into(),
            detail: "tampered OCSF export bundle verified unexpectedly".into(),
        });
    }

    Ok(pass(
        "AARM-R8",
        "Structured OCSF export schema, digest, and signature integrity",
    ))
}

pub(crate) fn check_r9_containment_secret_isolation() -> Result<ScenarioResult, ConformanceError> {
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
    let (cmd, report) =
        prepare_contained_command("git", &["status".into()], &spec, &env).map_err(|e| {
            ConformanceError::ScenarioFailed {
                scenario_id: "AARM-R9".into(),
                detail: e.to_string(),
            }
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
    let has_secret_on_cmd = cmd
        .get_envs()
        .any(|(k, _)| k.to_string_lossy() == "AWS_SECRET_ACCESS_KEY");
    let has_path_on_cmd = cmd.get_envs().any(|(k, _)| k.to_string_lossy() == "PATH");
    if has_secret_on_cmd || !has_path_on_cmd {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "AARM-R9".into(),
            detail: "Command environment still exposed stripped secret or dropped PATH".into(),
        });
    }
    Ok(pass(
        "AARM-R9",
        "Scoped credential isolation and sandbox containment",
    ))
}
