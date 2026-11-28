// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_core::policy::{essentials_pack, evaluate_with_session};
use grdr_core::session::SessionRuleState;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState, PolicyPack, Verdict};
use grdr_wasm::{
    WASM_ABI_VERSION, WasmActionAttempt, WasmAssuranceKind, WasmCapPresence, WasmEngine,
    WasmHostProfile, WasmMode, WasmPolicyPack, WasmPolicyRule, WasmRequiredSignal, WasmRuleMatch,
    WasmVerdict, compile_floor_json_at, essentials_pack_json, evaluate_attempt_json, grdr_alloc,
    grdr_free, grdr_result_len, grdr_result_ptr, grdr_wasm_abi_version, grdr_wasm_eval_attempt,
};
use jiff::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn sample_attempt(id: &str, action_class: ActionClass, target: &str) -> ActionAttempt {
    ActionAttempt {
        id: id.into(),
        session_id: "sess-parity".into(),
        device_id: "dev-parity".into(),
        device_name: "parity-host".into(),
        agent_name: "claude-code".into(),
        action_class,
        control_point: ControlPoint::Hook,
        target: target.into(),
        summary: "parity check".into(),
        timestamp: Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        ..Default::default()
    }
}

#[cfg(test)]
fn via_json<S: Serialize, D: DeserializeOwned>(value: &S) -> D {
    let encoded = serde_json::to_string(value).unwrap();
    serde_json::from_str(&encoded).unwrap()
}

#[test]
fn wasm_essentials_manifest_matches_native_policy_pack_exactly() {
    let wasm_raw = essentials_pack_json().unwrap();
    let wasm_parsed: PolicyPack = serde_json::from_str(&wasm_raw).unwrap();
    assert_eq!(wasm_parsed, essentials_pack());
}

#[test]
fn wasm_engine_matches_native_grdr_core_byte_for_byte_and_supports_rollback() {
    let pack = essentials_pack();
    let wasm_pack: WasmPolicyPack = via_json(&pack);
    let cases = [
        sample_attempt("v1", ActionClass::FileRead, "~/.ssh/id_rsa"),
        sample_attempt("v2", ActionClass::FileWrite, ".claude/settings.json"),
        sample_attempt(
            "v3",
            ActionClass::Exec,
            "claude --dangerously-skip-permissions",
        ),
        sample_attempt("v4", ActionClass::FileRead, "src/main.rs"),
    ];

    let mut wasm_engine = WasmEngine::new(10);
    wasm_engine
        .load(
            vec![wasm_pack],
            Vec::new(),
            via_json(&KillSwitchState::Inactive),
            WasmHostProfile::full_endpoint(),
            "bundle-1".into(),
        )
        .unwrap();

    let mut native_session = SessionRuleState::default();
    let mut native_grants = Vec::new();
    for attempt in &cases {
        let wasm_attempt: WasmActionAttempt = via_json(attempt);
        let wasm_out = wasm_engine.step(&wasm_attempt).unwrap();
        let native_receipt = evaluate_with_session(
            attempt,
            std::slice::from_ref(&pack),
            &mut native_grants,
            &KillSwitchState::Inactive,
            &mut native_session,
            attempt.timestamp,
        );
        let native_verdict_in_wasm: Verdict = via_json(&wasm_out.receipt.verdict);
        assert_eq!(native_verdict_in_wasm, native_receipt.verdict);
        assert_eq!(wasm_out.receipt.rule_id, native_receipt.rule_id);
        assert_eq!(wasm_out.receipt.reason, native_receipt.reason);

        let stateless_json = evaluate_attempt_json(
            &serde_json::json!({ "attempt": attempt, "packs": [pack] }).to_string(),
        )
        .unwrap();
        let stateless: grdr_model::DecisionReceipt = serde_json::from_str(&stateless_json).unwrap();
        assert_eq!(stateless.verdict, native_receipt.verdict);
    }

    let snap = wasm_engine.snapshot("before-bad".into());
    assert_eq!(snap.steps_executed, 4);
    let bad_attempt: WasmActionAttempt = via_json(&sample_attempt("bad", ActionClass::Exec, ""));
    assert!(wasm_engine.step(&bad_attempt).is_err());
    assert_eq!(wasm_engine.checkpoint().steps_executed, 4);
    assert!(wasm_engine.restore("before-bad").is_ok());

    let compiled_floor =
        compile_floor_json_at(&serde_json::to_string(&vec![pack.clone()]).unwrap(), 0).unwrap();
    assert!(!compiled_floor.is_empty());

    assert_eq!(
        WasmEngine::brand_manifest(None).schema,
        "grdr.brand.v1alpha1"
    );
    let _ = Verdict::Deny;
    let _ = WasmVerdict::Deny;
}

#[test]
fn wasm_host_profile_defaults_minimal_and_reports_worst_case_assurance() {
    let def = WasmHostProfile::default();
    assert_eq!(def, WasmHostProfile::minimal_sandbox());
    assert_eq!(def.user_identity, WasmCapPresence::Absent);
    assert_eq!(def.net_egress_sensor, WasmCapPresence::Absent);
    assert_eq!(def.session_store, WasmCapPresence::Absent);

    let pack = essentials_pack();
    let sample_grade = pack.rules[0].min_grade;
    let net_only = WasmPolicyPack {
        id: "net".into(),
        name: "Net".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![WasmPolicyRule {
            id: "r.net".into(),
            title: "Net".into(),
            description: String::new(),
            mode: WasmMode::Block,
            min_grade: via_json(&sample_grade),
            enabled: true,
            locked: false,
            matcher: WasmRuleMatch {
                action_classes: vec![via_json(&ActionClass::NetRequest)],
                target_prefixes: Vec::new(),
                target_contains: vec!["evil.example".into()],
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "blocked".into(),
            cedar: Some(
                r#"forbid(principal is Grdr::Session, action == Grdr::Action::"net.request", resource);"#
                    .into(),
            ),
        }],
        key_id: None,
        signature: None,
    };

    let mut engine_net = WasmEngine::default();
    engine_net
        .load(
            vec![net_only],
            Vec::new(),
            via_json(&KillSwitchState::Inactive),
            WasmHostProfile::default(),
            String::new(),
        )
        .unwrap();
    let ass = engine_net.assess_host_profile();
    assert_eq!(ass[0].assurance, WasmAssuranceKind::NotEvaluable);

    // File rule requires os_file_sensor; labels rule requires session_store.
    let file_pack = WasmPolicyPack {
        id: "file".into(),
        name: "File".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![WasmPolicyRule {
            id: "r.file".into(),
            title: "File".into(),
            description: String::new(),
            mode: WasmMode::Block,
            min_grade: via_json(&sample_grade),
            enabled: true,
            locked: false,
            matcher: WasmRuleMatch {
                action_classes: vec![via_json(&ActionClass::FileWrite)],
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "blocked".into(),
            cedar: None,
        }],
        key_id: None,
        signature: None,
    };
    let mut no_file = WasmHostProfile::full_endpoint();
    no_file.os_file_sensor = WasmCapPresence::Absent;
    let interest = engine_net
        .load(
            vec![file_pack.clone()],
            Vec::new(),
            via_json(&KillSwitchState::Inactive),
            no_file,
            String::new(),
        )
        .unwrap();
    assert!(
        interest
            .required_signals
            .contains(&WasmRequiredSignal::FileSensor)
    );
    assert_eq!(
        engine_net.assess_host_profile()[0].assurance,
        WasmAssuranceKind::NotEvaluable
    );

    // WatchOnly + Enforced across two packs yields WatchOnly.
    let watch_pack = WasmPolicyPack {
        id: "watch".into(),
        name: "Watch".into(),
        description: String::new(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![WasmPolicyRule {
            id: "r.watch".into(),
            title: "Watch".into(),
            description: String::new(),
            mode: WasmMode::Watch,
            min_grade: via_json(&sample_grade),
            enabled: true,
            locked: false,
            matcher: WasmRuleMatch {
                action_classes: vec![via_json(&ActionClass::FileRead)],
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "watch".into(),
            cedar: None,
        }],
        key_id: None,
        signature: None,
    };
    engine_net
        .load(
            vec![file_pack, watch_pack],
            Vec::new(),
            via_json(&KillSwitchState::Inactive),
            WasmHostProfile::default(),
            String::new(),
        )
        .unwrap();
    let read_attempt: WasmActionAttempt =
        via_json(&sample_attempt("r1", ActionClass::FileRead, "README.md"));
    let out = engine_net.step(&read_attempt).unwrap();
    assert_eq!(out.assurance, WasmAssuranceKind::WatchOnly);
}

#[test]
#[allow(unsafe_code)]
fn wasm_c_abi_roundtrip_handles_minimal_sdk_attempt_and_bounds() {
    assert_eq!(grdr_wasm_abi_version(), WASM_ABI_VERSION);
    let pack = essentials_pack();
    let req = serde_json::json!({
        "attempt": {
            "agent_name": "claude-code",
            "action_class": "file.write",
            "target": ".claude/settings.json"
        },
        "packs": [pack]
    })
    .to_string();
    let req_bytes = req.as_bytes();
    let ptr = grdr_alloc(req_bytes.len());
    assert!(!ptr.is_null());

    // SAFETY: `ptr` was allocated for `req_bytes.len()` bytes by `grdr_alloc`.
    unsafe {
        std::ptr::copy_nonoverlapping(req_bytes.as_ptr(), ptr, req_bytes.len());
    }
    // SAFETY: Valid populated allocation.
    let rc = unsafe { grdr_wasm_eval_attempt(ptr, req_bytes.len()) };
    assert_eq!(rc, 0);

    let out_ptr = grdr_result_ptr();
    let out_len = grdr_result_len();
    assert!(!out_ptr.is_null() && out_len > 0);
    // SAFETY: `grdr_result_ptr` / `grdr_result_len` reflect the static buffer written by `grdr_wasm_eval_attempt`.
    let out_slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
    let parsed: serde_json::Value = serde_json::from_slice(out_slice).unwrap();
    assert_eq!(parsed["verdict"], "block");
    assert_eq!(parsed["rule_id"], "essentials.agent-control-files");

    // Wrong length free is ignored safely, followed by exact free and idempotent second free.
    // SAFETY: Exercising guard paths on allocated pointer and subsequent valid cleanup.
    unsafe {
        grdr_free(ptr, req_bytes.len() + 1);
        grdr_free(ptr, req_bytes.len());
        grdr_free(ptr, req_bytes.len());
    }
    assert!(grdr_alloc(0).is_null());
}
