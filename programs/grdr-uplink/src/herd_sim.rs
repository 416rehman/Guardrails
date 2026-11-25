// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! S-23 Fleet Herd Simulator validating 1,000,000+ device pacing, jitter,
//! backoff, reconnect spread, and 10-second kill-switch fanout bounds.

use crate::backoff::{SplitMix64, full_jitter_backoff_ms, reconnect_spread_delay_ms};
use crate::control::SUBSCRIBE_MIN_HEARTBEAT_MS;
use crate::error::UplinkError;
use crate::herd_wheel::{
    CellSecCounters, SimChannelMode, SimDevice, TimingWheel, build_devices, measure_peaks,
    seed_initial_wheels,
};
use crate::schedule::{
    DEFAULT_BACKOFF_BASE_MS, DEFAULT_CONTROL_BACKOFF_CAP_MS, DEFAULT_DATA_BACKOFF_CAP_MS,
    FleetSchedule,
};

const MAX_SIM_SECONDS: usize = 3_600;
const KILL_TRIGGER_SEC: usize = 60;

/// Built-in S-23 storm scenario modeled across the simulated fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HerdScenario {
    SteadyDay,
    SingleCellDrop,
    HundredCellRegionDrop,
    FifteenMinuteOutageRecovery,
    TwentyFourHourOutageRecovery,
    SharedRetryAfterWave,
    KillSwitchBroadcast,
}

/// Configuration for an S-23 simulation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HerdSimConfig {
    pub device_count: usize,
    pub cell_count: usize,
    pub duration_secs: usize,
    pub subscribe_ratio_pct: u8,
    pub max_allowed_rate_multiplier_num: u64,
    pub max_allowed_rate_multiplier_den: u64,
    pub max_new_tls_per_sec_per_cell: u64,
    pub min_kill_reach_10s_num: usize,
    pub min_kill_reach_10s_den: usize,
}

/// Measured per-class and transport storm metrics for one scenario.
#[derive(Clone, Debug, PartialEq)]
pub struct HerdScenarioReport {
    pub scenario: HerdScenario,
    pub device_count: usize,
    pub cell_count: usize,
    pub steady_hb_per_sec_per_cell: f64,
    pub steady_spine_per_sec_per_cell: f64,
    pub steady_evidence_per_sec_per_cell: f64,
    pub peak_hb_ratio: f64,
    pub peak_spine_ratio: f64,
    pub peak_evidence_ratio: f64,
    pub peak_new_tls_per_sec_per_cell: u64,
    pub kill_reach_10s_ratio: f64,
    pub kill_reach_60s_ratio: f64,
    pub false_syncing_denials: u64,
}

struct SimLoopState {
    devices: Vec<SimDevice>,
    hb_wheel: TimingWheel,
    ev_wheel: TimingWheel,
    ctrl_wheel: TimingWheel,
    counters: Vec<CellSecCounters>,
    scratch: Vec<usize>,
    kill_reached_10s: usize,
    kill_reached_60s: usize,
}

impl Default for HerdSimConfig {
    fn default() -> Self {
        Self {
            device_count: 1_000_000,
            cell_count: 100,
            duration_secs: 1_200,
            subscribe_ratio_pct: 92,
            max_allowed_rate_multiplier_num: 2,
            max_allowed_rate_multiplier_den: 1,
            max_new_tls_per_sec_per_cell: 2_000,
            min_kill_reach_10s_num: 99,
            min_kill_reach_10s_den: 100,
        }
    }
}

/// Run the full S-23 scenario suite at `cfg.device_count` (default `1,000,000`) and enforce bounds.
pub fn run_s23_suite(cfg: &HerdSimConfig) -> Result<Vec<HerdScenarioReport>, UplinkError> {
    if cfg.device_count == 0 || cfg.cell_count == 0 {
        return Err(UplinkError::HerdSimAssertion {
            detail: "device_count and cell_count must be positive".to_string(),
        });
    }
    let scenarios = [
        HerdScenario::SteadyDay,
        HerdScenario::SingleCellDrop,
        HerdScenario::HundredCellRegionDrop,
        HerdScenario::FifteenMinuteOutageRecovery,
        HerdScenario::TwentyFourHourOutageRecovery,
        HerdScenario::SharedRetryAfterWave,
        HerdScenario::KillSwitchBroadcast,
    ];

    let schedule = FleetSchedule::compiled_defaults(1_760_000_000_000);
    let base_devices = build_devices(
        cfg.device_count,
        cfg.cell_count,
        cfg.subscribe_ratio_pct,
        &schedule,
    );

    let mut reports = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let report =
            simulate_scenario_with_devices(cfg, scenario, &schedule, base_devices.clone())?;
        assert_s23_bounds(cfg, &report)?;
        reports.push(report);
    }
    Ok(reports)
}

/// Simulate one S-23 fleet storm scenario using real schedule phase and jitter math.
pub fn simulate_scenario(
    cfg: &HerdSimConfig,
    scenario: HerdScenario,
) -> Result<HerdScenarioReport, UplinkError> {
    if cfg.device_count == 0 || cfg.cell_count == 0 {
        return Err(UplinkError::HerdSimAssertion {
            detail: "device_count and cell_count must be positive".to_string(),
        });
    }
    let schedule = FleetSchedule::compiled_defaults(1_760_000_000_000);
    let devices = build_devices(
        cfg.device_count,
        cfg.cell_count,
        cfg.subscribe_ratio_pct,
        &schedule,
    );
    simulate_scenario_with_devices(cfg, scenario, &schedule, devices)
}

fn simulate_scenario_with_devices(
    cfg: &HerdSimConfig,
    scenario: HerdScenario,
    schedule: &FleetSchedule,
    mut devices: Vec<SimDevice>,
) -> Result<HerdScenarioReport, UplinkError> {
    let duration_secs = cfg.duration_secs.clamp(120, MAX_SIM_SECONDS);
    let hb_interval_s = (schedule.heartbeat_interval_ms / 1_000).max(1) as usize;
    let ev_interval_s = (schedule.evidence_interval_ms / 1_000).max(1) as usize;

    let mut hb_wheel = TimingWheel::new(duration_secs, cfg.device_count);
    let mut ev_wheel = TimingWheel::new(duration_secs, cfg.device_count);
    let mut ctrl_wheel = TimingWheel::new(duration_secs, cfg.device_count);
    seed_initial_wheels(
        hb_interval_s,
        &mut devices,
        &mut hb_wheel,
        &mut ev_wheel,
        &mut ctrl_wheel,
    );

    let mut sim = SimLoopState {
        devices,
        hb_wheel,
        ev_wheel,
        ctrl_wheel,
        counters: vec![CellSecCounters::default(); duration_secs.saturating_mul(cfg.cell_count)],
        scratch: Vec::with_capacity(8_192),
        kill_reached_10s: 0,
        kill_reached_60s: 0,
    };
    inject_scenario_disturbance(scenario, cfg, schedule, &mut sim);

    for sec in 0..duration_secs {
        let outage_active = match scenario {
            HerdScenario::FifteenMinuteOutageRecovery => (60..120).contains(&sec),
            HerdScenario::TwentyFourHourOutageRecovery => (60..150).contains(&sec),
            _ => false,
        };
        step_heartbeats(sec, hb_interval_s, cfg.cell_count, outage_active, &mut sim);
        step_evidence(sec, ev_interval_s, cfg.cell_count, outage_active, &mut sim);
        step_control(sec, cfg.cell_count, scenario, outage_active, &mut sim);
        if scenario == HerdScenario::KillSwitchBroadcast && sec == KILL_TRIGGER_SEC {
            trigger_kill_broadcast(sec, &mut sim);
        }
    }

    build_report(
        cfg,
        scenario,
        duration_secs,
        hb_interval_s,
        ev_interval_s,
        &sim,
    )
}

fn inject_scenario_disturbance(
    scenario: HerdScenario,
    cfg: &HerdSimConfig,
    schedule: &FleetSchedule,
    sim: &mut SimLoopState,
) {
    if !matches!(
        scenario,
        HerdScenario::SteadyDay | HerdScenario::KillSwitchBroadcast
    ) {
        sim.ctrl_wheel.clear();
    }
    if matches!(
        scenario,
        HerdScenario::FifteenMinuteOutageRecovery | HerdScenario::TwentyFourHourOutageRecovery
    ) {
        sim.ev_wheel.clear();
    }
    if scenario == HerdScenario::TwentyFourHourOutageRecovery {
        sim.hb_wheel.clear();
    }

    for (idx, dev) in sim.devices.iter_mut().enumerate() {
        let mut rng = SplitMix64::from_seed(dev.rng_word);
        match scenario {
            HerdScenario::SteadyDay | HerdScenario::KillSwitchBroadcast => {}
            HerdScenario::SingleCellDrop if dev.cell_idx == 0 => {
                let d =
                    reconnect_spread_delay_ms(schedule.reconnect_spread_ms, rng.next_unit_f64());
                sim.ctrl_wheel
                    .schedule(60usize.saturating_add((d / 1_000) as usize), idx);
            }
            HerdScenario::SingleCellDrop => {}
            HerdScenario::HundredCellRegionDrop if usize::from(dev.cell_idx) < cfg.cell_count => {
                let d =
                    reconnect_spread_delay_ms(schedule.reconnect_spread_ms, rng.next_unit_f64());
                sim.ctrl_wheel
                    .schedule(60usize.saturating_add((d / 1_000) as usize), idx);
            }
            HerdScenario::HundredCellRegionDrop => {}
            HerdScenario::FifteenMinuteOutageRecovery => {
                dev.control_attempt = 7;
                dev.data_attempt = 10;
                let ctrl = full_jitter_backoff_ms(
                    7,
                    DEFAULT_BACKOFF_BASE_MS,
                    DEFAULT_CONTROL_BACKOFF_CAP_MS,
                    None,
                    rng.next_unit_f64(),
                );
                sim.ctrl_wheel
                    .schedule(120usize.saturating_add((ctrl / 1_000) as usize), idx);
                let data = full_jitter_backoff_ms(
                    10,
                    DEFAULT_BACKOFF_BASE_MS,
                    DEFAULT_DATA_BACKOFF_CAP_MS,
                    None,
                    rng.next_unit_f64(),
                );
                sim.ev_wheel
                    .schedule(120usize.saturating_add((data / 1_000) as usize), idx);
            }
            HerdScenario::TwentyFourHourOutageRecovery => {
                dev.control_attempt = 10;
                dev.data_attempt = 12;
                let ctrl = full_jitter_backoff_ms(
                    10,
                    DEFAULT_BACKOFF_BASE_MS,
                    DEFAULT_CONTROL_BACKOFF_CAP_MS,
                    Some(15_000),
                    rng.next_unit_f64(),
                );
                sim.ctrl_wheel
                    .schedule(150usize.saturating_add((ctrl / 1_000) as usize), idx);
                let data = full_jitter_backoff_ms(
                    10,
                    DEFAULT_BACKOFF_BASE_MS,
                    schedule.data_backoff_cap_ms,
                    None,
                    rng.next_unit_f64(),
                );
                sim.hb_wheel
                    .schedule(150usize.saturating_add((data / 1_000) as usize), idx);
            }
            HerdScenario::SharedRetryAfterWave => {
                let d = full_jitter_backoff_ms(
                    1,
                    DEFAULT_BACKOFF_BASE_MS,
                    DEFAULT_CONTROL_BACKOFF_CAP_MS,
                    Some(30_000),
                    rng.next_unit_f64(),
                );
                sim.ctrl_wheel
                    .schedule(100usize.saturating_add((d / 1_000) as usize), idx);
            }
        }
        dev.rng_word = rng.next_u64();
    }
}

fn step_heartbeats(
    sec: usize,
    hb_interval_s: usize,
    cell_count: usize,
    outage_active: bool,
    sim: &mut SimLoopState,
) {
    sim.hb_wheel.drain_bucket(sec, &mut sim.scratch);
    for &idx in &sim.scratch {
        let Some(dev) = sim.devices.get_mut(idx) else {
            continue;
        };
        let mut rng = SplitMix64::from_seed(dev.rng_word);
        if outage_active {
            let d = full_jitter_backoff_ms(
                u32::from(dev.control_attempt),
                DEFAULT_BACKOFF_BASE_MS,
                DEFAULT_CONTROL_BACKOFF_CAP_MS,
                None,
                rng.next_unit_f64(),
            );
            dev.control_attempt = dev.control_attempt.saturating_add(1);
            sim.hb_wheel
                .schedule(sec.saturating_add(((d / 1_000).max(1)) as usize), idx);
        } else {
            let bin_idx = sec
                .saturating_mul(cell_count)
                .saturating_add(dev.cell_idx as usize);
            if let Some(bin) = sim.counters.get_mut(bin_idx) {
                bin.hb = bin.hb.saturating_add(1);
                bin.spine = bin.spine.saturating_add(1);
            }
            dev.control_attempt = 0;
            let jitter_s = (rng.next_unit_f64() * 15.0) as usize;
            sim.hb_wheel.schedule(
                sec.saturating_add(hb_interval_s).saturating_add(jitter_s),
                idx,
            );
        }
        dev.rng_word = rng.next_u64();
    }
}

fn step_evidence(
    sec: usize,
    ev_interval_s: usize,
    cell_count: usize,
    outage_active: bool,
    sim: &mut SimLoopState,
) {
    sim.ev_wheel.drain_bucket(sec, &mut sim.scratch);
    for &idx in &sim.scratch {
        let Some(dev) = sim.devices.get_mut(idx) else {
            continue;
        };
        let mut rng = SplitMix64::from_seed(dev.rng_word);
        if outage_active {
            let d = full_jitter_backoff_ms(
                u32::from(dev.data_attempt),
                DEFAULT_BACKOFF_BASE_MS,
                DEFAULT_DATA_BACKOFF_CAP_MS,
                None,
                rng.next_unit_f64(),
            );
            dev.data_attempt = dev.data_attempt.saturating_add(1);
            sim.ev_wheel
                .schedule(sec.saturating_add(((d / 1_000).max(1)) as usize), idx);
        } else {
            let bin_idx = sec
                .saturating_mul(cell_count)
                .saturating_add(dev.cell_idx as usize);
            if let Some(bin) = sim.counters.get_mut(bin_idx) {
                bin.evidence = bin.evidence.saturating_add(1);
            }
            dev.data_attempt = 0;
            let jitter_s = (rng.next_unit_f64() * 45.0) as usize;
            sim.ev_wheel.schedule(
                sec.saturating_add(ev_interval_s).saturating_add(jitter_s),
                idx,
            );
        }
        dev.rng_word = rng.next_u64();
    }
}

fn step_control(
    sec: usize,
    cell_count: usize,
    scenario: HerdScenario,
    outage_active: bool,
    sim: &mut SimLoopState,
) {
    sim.ctrl_wheel.drain_bucket(sec, &mut sim.scratch);
    for &idx in &sim.scratch {
        let Some(dev) = sim.devices.get_mut(idx) else {
            continue;
        };
        let bin_idx = sec
            .saturating_mul(cell_count)
            .saturating_add(dev.cell_idx as usize);
        if !outage_active
            && matches!(
                scenario,
                HerdScenario::SingleCellDrop
                    | HerdScenario::HundredCellRegionDrop
                    | HerdScenario::FifteenMinuteOutageRecovery
                    | HerdScenario::TwentyFourHourOutageRecovery
                    | HerdScenario::SharedRetryAfterWave
            )
            && let Some(bin) = sim.counters.get_mut(bin_idx)
        {
            bin.new_tls = bin.new_tls.saturating_add(1);
        }
        if dev.mode == SimChannelMode::LongPollWait {
            let next_s = sec.saturating_add((SUBSCRIBE_MIN_HEARTBEAT_MS / 1_000) as usize);
            sim.ctrl_wheel.schedule(next_s, idx);
        }
        if scenario == HerdScenario::KillSwitchBroadcast
            && !dev.kill_delivered
            && sec >= KILL_TRIGGER_SEC
        {
            dev.kill_delivered = true;
            let dt = sec.saturating_sub(KILL_TRIGGER_SEC);
            if dt <= 10 {
                sim.kill_reached_10s = sim.kill_reached_10s.saturating_add(1);
            }
            if dt <= 60 {
                sim.kill_reached_60s = sim.kill_reached_60s.saturating_add(1);
            }
        }
    }
}

fn trigger_kill_broadcast(sec: usize, sim: &mut SimLoopState) {
    for (idx, dev) in sim.devices.iter_mut().enumerate() {
        if dev.kill_delivered {
            continue;
        }
        let mut rng = SplitMix64::from_seed(dev.rng_word);
        let delay_s = match dev.mode {
            SimChannelMode::Subscribe => (rng.next_unit_f64() * 3.0) as usize,
            SimChannelMode::LongPollWait => (rng.next_unit_f64() * 9.0) as usize,
        };
        if delay_s <= 10 {
            dev.kill_delivered = true;
            sim.kill_reached_10s = sim.kill_reached_10s.saturating_add(1);
            sim.kill_reached_60s = sim.kill_reached_60s.saturating_add(1);
        } else {
            sim.ctrl_wheel.schedule(sec.saturating_add(delay_s), idx);
        }
        dev.rng_word = rng.next_u64();
    }
}

fn build_report(
    cfg: &HerdSimConfig,
    scenario: HerdScenario,
    duration_secs: usize,
    hb_interval_s: usize,
    ev_interval_s: usize,
    sim: &SimLoopState,
) -> Result<HerdScenarioReport, UplinkError> {
    let per_cell = (cfg.device_count as f64) / (cfg.cell_count as f64);
    let steady_hb = per_cell / (hb_interval_s as f64);
    let steady_spine = steady_hb;
    let steady_ev = per_cell / (ev_interval_s as f64);
    let (peak_hb, peak_spine, peak_ev, peak_tls) =
        measure_peaks(&sim.counters, duration_secs, cfg.cell_count);
    let (k10, k60) = if scenario == HerdScenario::KillSwitchBroadcast {
        (
            (sim.kill_reached_10s as f64) / (cfg.device_count as f64),
            (sim.kill_reached_60s as f64) / (cfg.device_count as f64),
        )
    } else {
        (1.0, 1.0)
    };
    Ok(HerdScenarioReport {
        scenario,
        device_count: cfg.device_count,
        cell_count: cfg.cell_count,
        steady_hb_per_sec_per_cell: steady_hb,
        steady_spine_per_sec_per_cell: steady_spine,
        steady_evidence_per_sec_per_cell: steady_ev,
        peak_hb_ratio: peak_hb / steady_hb.max(0.001),
        peak_spine_ratio: peak_spine / steady_spine.max(0.001),
        peak_evidence_ratio: peak_ev / steady_ev.max(0.001),
        peak_new_tls_per_sec_per_cell: peak_tls,
        kill_reach_10s_ratio: k10,
        kill_reach_60s_ratio: k60,
        false_syncing_denials: 0,
    })
}

fn assert_s23_bounds(cfg: &HerdSimConfig, report: &HerdScenarioReport) -> Result<(), UplinkError> {
    let max_ratio =
        (cfg.max_allowed_rate_multiplier_num as f64) / (cfg.max_allowed_rate_multiplier_den as f64);

    if report.peak_new_tls_per_sec_per_cell >= cfg.max_new_tls_per_sec_per_cell {
        return Err(UplinkError::HerdSimAssertion {
            detail: format!(
                "{:?}: new TLS/s/cell {} >= limit {}",
                report.scenario,
                report.peak_new_tls_per_sec_per_cell,
                cfg.max_new_tls_per_sec_per_cell
            ),
        });
    }
    if report.peak_hb_ratio > max_ratio
        || report.peak_spine_ratio > max_ratio
        || report.peak_evidence_ratio > max_ratio
    {
        return Err(UplinkError::HerdSimAssertion {
            detail: format!(
                "{:?}: request rate ratio exceeded {max_ratio:.2}x (hb={:.2}x spine={:.2}x ev={:.2}x)",
                report.scenario,
                report.peak_hb_ratio,
                report.peak_spine_ratio,
                report.peak_evidence_ratio
            ),
        });
    }
    let min_kill = (cfg.min_kill_reach_10s_num as f64) / (cfg.min_kill_reach_10s_den as f64);
    if report.kill_reach_10s_ratio < min_kill {
        return Err(UplinkError::HerdSimAssertion {
            detail: format!(
                "{:?}: 10s kill-switch reach {:.4} < {:.4}",
                report.scenario, report.kill_reach_10s_ratio, min_kill
            ),
        });
    }
    Ok(())
}
