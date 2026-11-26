// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_core::policy::{
    DeterministicEntropy, ESSENTIALS_PARITY_CEDAR, Engine, EngineInput, EngineOutput,
    RequestBuildOptions, VerifiedBundle, canonicalize_cedar_via_roundtrip,
    compile_down_claude_code, compile_down_codex, essentials_pack, evaluate,
    lint_cedar_source_extended, validate_cedar_rule, verify_compile_down_subset,
};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, IdentityMode, InstallProfile,
    KillSwitchState, Verdict,
};
use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = validate_cedar_rule(text) {
        assert!(parsed.to_string().contains("forbid"));
    }
    let _ = lint_cedar_source_extended(
        "grdr.fuzz",
        "fuzz.rule",
        text,
        None,
        IdentityMode::Pseudonymous,
    );
    if let Ok(canon) = canonicalize_cedar_via_roundtrip(text) {
        assert_eq!(
            canonicalize_cedar_via_roundtrip(&canon).as_deref(),
            Ok(canon.as_str())
        );
    }

    let mut ess = essentials_pack();
    if let Some(first) = ess.rules.first_mut() {
        first.cedar = Some(ESSENTIALS_PARITY_CEDAR.into());
    }
    let packs = vec![ess];
    let claude = compile_down_claude_code(&packs, &[]);
    let codex = compile_down_codex(&packs, &[]);
    assert!(codex.prefix_rules.is_empty());

    let action_class = data
        .first()
        .map(|b| match b % 5 {
            0 => ActionClass::Exec,
            1 => ActionClass::FileRead,
            2 => ActionClass::FileWrite,
            3 => ActionClass::NetRequest,
            _ => ActionClass::McpCall,
        })
        .unwrap_or(ActionClass::Exec);
    let attempt = ActionAttempt {
        id: "att_fuzz".into(),
        session_id: "sess_fuzz".into(),
        device_id: "dev_fuzz".into(),
        device_name: "fuzz-host".into(),
        agent_name: "claude-code".into(),
        action_class,
        control_point: ControlPoint::Hook,
        target: text.to_string(),
        summary: String::new(),
        timestamp: Timestamp::UNIX_EPOCH,
        user_id: Some("fuzz_user".into()),
        ..Default::default()
    };
    let eval_out = evaluate(
        &attempt,
        &packs,
        &[],
        &KillSwitchState::Inactive,
        Timestamp::UNIX_EPOCH,
    );
    assert!(verify_compile_down_subset(
        &packs,
        std::slice::from_ref(&attempt),
        &claude,
        Timestamp::UNIX_EPOCH,
    ));

    let bundle_hash = VerifiedBundle::compute_bundle_hash(
        &packs,
        &[],
        IdentityMode::Pseudonymous,
        InstallProfile::User,
        false,
        ApprovalGrade::G3,
    );
    let Ok(bundle) = VerifiedBundle::new_verified(
        "fuzz".into(),
        bundle_hash,
        "1.0.0".into(),
        packs,
        Vec::new(),
        IdentityMode::Pseudonymous,
        InstallProfile::User,
        false,
        ApprovalGrade::G3,
        Vec::new(),
    ) else {
        return;
    };
    let snap_key = [9u8; 32];
    assert!(Engine::load(bundle.clone(), [0u8; 32], Timestamp::UNIX_EPOCH).is_err());
    if let Ok(mut engine) = Engine::load(bundle.clone(), snap_key, Timestamp::UNIX_EPOCH) {
        let mut entropy = DeterministicEntropy::from_seed_bytes(data);
        if let Ok(EngineOutput::Evaluated { receipt, .. }) = engine.step(
            EngineInput::Evaluate {
                attempt: attempt.clone(),
                options: Box::new(RequestBuildOptions {
                    identity_mode: IdentityMode::Pseudonymous,
                    ..Default::default()
                }),
                host_deadline_ms: None,
            },
            &mut entropy,
            Timestamp::UNIX_EPOCH,
        ) {
            if attempt.action_class == ActionClass::FileRead
                && text.to_ascii_lowercase().contains("honeytoken")
            {
                assert_eq!(receipt.verdict, Verdict::Deny);
            }
            assert_eq!(receipt.verdict, eval_out.verdict);
        }
        let mut snap = engine.snapshot();
        assert!(
            Engine::restore(
                bundle.clone(),
                snap.clone(),
                &snap_key,
                Timestamp::UNIX_EPOCH
            )
            .is_ok()
        );
        snap.snapshot_mac.clear();
        assert!(Engine::restore(bundle, snap, &snap_key, Timestamp::UNIX_EPOCH).is_err());
    }
});
