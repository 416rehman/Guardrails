// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration test executing the full CSA AARM R1-R9 and D-12/D-14/D-15/D-21 conformance suite.

use grdr_conformance::{
    ConformanceError, HOOK_ACK_BUDGET_MS, SHIM_MAX_EXIT_MS, run_full_conformance_suite,
    sign_handover_ack, simulate_shim_fail_safe_eval,
};
use grdr_crypto::SigningKeypair;
use grdr_model::{ActionClass, SigningKeypairExt as _, Verdict};
use jiff::Timestamp;

#[test]
fn full_conformance_suite_passes_all_scenarios() {
    let report_res = run_full_conformance_suite();
    assert!(
        report_res.is_ok(),
        "conformance suite failed: {report_res:?}"
    );
    if let Ok(report) = report_res {
        assert_eq!(report.spec_version, "AARM-1.0");
        assert!(
            report.total >= 14,
            "expected >= 14 conformance scenarios, got {}",
            report.total
        );
        assert!(
            report.all_passed(),
            "conformance failures: {:?}",
            report.results
        );
    }
}

#[test]
fn shim_bounds_enforce_signed_handover_250ms_ack_and_2s_max_ceiling() {
    assert_eq!(HOOK_ACK_BUDGET_MS, 250);
    assert_eq!(SHIM_MAX_EXIT_MS, 2_000);

    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let kp_res = SigningKeypair::generate();
    assert!(kp_res.is_ok());
    let Ok(kp) = kp_res else {
        return;
    };
    let ack_res = sign_handover_ack(
        &kp,
        1_500,
        2_000,
        Verdict::Deny,
        ActionClass::Exec,
        "claude --dangerously-skip-permissions",
    );
    assert!(ack_res.is_ok());
    let Ok(ack) = ack_res else {
        return;
    };

    let handover_ok = simulate_shim_fail_safe_eval(
        Some(&ack),
        Some(&kp.public_info()),
        Some(2_000),
        ActionClass::Exec,
        "claude-code",
        "claude --dangerously-skip-permissions",
        now,
    );
    assert!(handover_ok.is_ok());
    if let Ok(ok_res) = handover_ok {
        assert!(!ok_res.used_fail_safe_table);
        assert_eq!(ok_res.verdict, Verdict::Deny);
    }

    let handover_expired = simulate_shim_fail_safe_eval(
        None,
        Some(&kp.public_info()),
        Some(2_000),
        ActionClass::Exec,
        "claude-code",
        "claude --dangerously-skip-permissions",
        now,
    );
    assert!(handover_expired.is_ok());
    if let Ok(exp_res) = handover_expired {
        assert!(exp_res.used_fail_safe_table);
        assert_eq!(exp_res.verdict, Verdict::Deny);
    }

    let handover_too_long = simulate_shim_fail_safe_eval(
        None,
        None,
        Some(2_001),
        ActionClass::Exec,
        "claude-code",
        "git status",
        now,
    );
    assert!(matches!(
        handover_too_long,
        Err(ConformanceError::HandoverCeilingExceeded {
            requested_ms: 2_001
        })
    ));
}
