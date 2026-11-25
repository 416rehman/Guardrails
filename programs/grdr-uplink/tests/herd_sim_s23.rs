// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::error::Error;
use std::time::Instant;

use grdr_uplink::herd_sim::{HerdScenario, HerdSimConfig, run_s23_suite};

#[test]
fn s23_one_million_device_fleet_herd_simulator() {
    let res = run_s23_one_million_device_suite();
    assert!(res.is_ok(), "{res:?}");
}

fn run_s23_one_million_device_suite() -> Result<(), Box<dyn Error>> {
    let cfg = HerdSimConfig {
        device_count: 1_000_000,
        cell_count: 100,
        duration_secs: 1_200,
        ..HerdSimConfig::default()
    };

    let started = Instant::now();
    let reports = run_s23_suite(&cfg)?;
    let elapsed_ms = started.elapsed().as_millis();

    if reports.len() != 7 {
        return Err(format!("expected 7 scenario reports, got {}", reports.len()).into());
    }
    for report in &reports {
        if report.device_count != 1_000_000 || report.cell_count != 100 {
            return Err("unexpected fleet dimensions in S-23 report".into());
        }
        if report.peak_new_tls_per_sec_per_cell >= 2_000 {
            return Err(format!(
                "{:?} exceeded TLS handshake cap: {}",
                report.scenario, report.peak_new_tls_per_sec_per_cell
            )
            .into());
        }
        if report.peak_hb_ratio > 2.0
            || report.peak_spine_ratio > 2.0
            || report.peak_evidence_ratio > 2.0
        {
            return Err(format!(
                "{:?} exceeded 2x steady rate: hb={:.2}x spine={:.2}x ev={:.2}x",
                report.scenario,
                report.peak_hb_ratio,
                report.peak_spine_ratio,
                report.peak_evidence_ratio
            )
            .into());
        }
        if report.false_syncing_denials != 0 {
            return Err("false syncing denials observed".into());
        }
        if report.scenario == HerdScenario::KillSwitchBroadcast
            && (report.kill_reach_10s_ratio < 0.99
                || (report.kill_reach_60s_ratio - 1.0).abs() >= f64::EPSILON)
        {
            return Err(format!(
                "kill-switch SLA failed: 10s={:.4} 60s={:.4}",
                report.kill_reach_10s_ratio, report.kill_reach_60s_ratio
            )
            .into());
        }
    }
    if elapsed_ms >= 120_000 {
        return Err(format!("S-23 runtime too slow: {elapsed_ms}ms").into());
    }
    Ok(())
}
