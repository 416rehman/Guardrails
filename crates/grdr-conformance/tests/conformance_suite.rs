// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Integration test executing the full CSA AARM R1-R9 and D-12/D-14/D-15/D-21 conformance suite.

use grdr_conformance::{
    ConformanceError, HOOK_ACK_BUDGET_MS, SHIM_MAX_EXIT_MS, run_full_conformance_suite,
    simulate_shim_fail_safe_eval,
};
use grdr_model::{ActionClass, Verdict};
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
fn shim_bounds_enforce_250ms_ack_and_2s_max_ceiling() {
    assert_eq!(HOOK_ACK_BUDGET_MS, 250);
    assert_eq!(SHIM_MAX_EXIT_MS, 2_000);

    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let handover_ok = simulate_shim_fail_safe_eval(
        Some(1_500),
        Some(2_000),
        ActionClass::Exec,
        "claude-code",
        "claude --dangerously-skip-permissions",
        now,
    );
    assert!(handover_ok.is_ok());
    if let Ok(ok_res) = handover_ok {
        assert!(!ok_res.used_fail_safe_table);
    }

    let handover_expired = simulate_shim_fail_safe_eval(
        None,
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
