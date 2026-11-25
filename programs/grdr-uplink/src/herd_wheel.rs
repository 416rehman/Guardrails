// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Intrusive O(1) timing wheel, compact 1M+ device initialization, and per-cell
//! sliding-window rate measurement for the S-23 Fleet Herd Simulator.

use sha2::{Digest, Sha256};

use crate::backoff::SplitMix64;
use crate::schedule::{FleetSchedule, deterministic_phase_ms};

pub const WHEEL_EMPTY: u32 = u32::MAX;
pub const RATE_WINDOW_SECS: usize = 10;

/// Control transport mode simulated per device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimChannelMode {
    Subscribe,
    LongPollWait,
}

/// Compact per-device state vector (`24B`) supporting `1,000,000+` simulated endpoints.
#[derive(Clone, Copy, Debug)]
pub struct SimDevice {
    pub cell_idx: u16,
    pub mode: SimChannelMode,
    pub hb_phase_s: u16,
    pub ev_phase_s: u16,
    pub control_attempt: u8,
    pub data_attempt: u8,
    pub kill_delivered: bool,
    pub rng_word: u64,
}

/// Zero-allocation intrusive linked-list timing wheel with single-membership guard.
pub struct TimingWheel {
    heads: Vec<u32>,
    nexts: Vec<u32>,
    enqueued_bucket: Vec<u32>,
}

/// Per-cell 1-second request and TLS handshake counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct CellSecCounters {
    pub hb: u32,
    pub spine: u32,
    pub evidence: u32,
    pub new_tls: u32,
}

impl TimingWheel {
    /// Allocate a timing wheel over `0..=horizon_secs` for `device_count` devices.
    #[must_use]
    pub fn new(horizon_secs: usize, device_count: usize) -> Self {
        Self {
            heads: vec![WHEEL_EMPTY; horizon_secs.saturating_add(1)],
            nexts: vec![WHEEL_EMPTY; device_count],
            enqueued_bucket: vec![WHEEL_EMPTY; device_count],
        }
    }

    /// Clear all scheduled buckets without freeing backing buffers.
    pub fn clear(&mut self) {
        self.heads.fill(WHEEL_EMPTY);
        self.nexts.fill(WHEEL_EMPTY);
        self.enqueued_bucket.fill(WHEEL_EMPTY);
    }

    /// Push `dev_idx` onto bucket `sec` if not already scheduled in a bucket.
    pub fn schedule(&mut self, sec: usize, dev_idx: usize) {
        if sec >= self.heads.len() || dev_idx >= self.nexts.len() {
            return;
        }
        if self.enqueued_bucket.get(dev_idx).copied() != Some(WHEEL_EMPTY) {
            return;
        }
        let dev_u32 = u32::try_from(dev_idx).unwrap_or(WHEEL_EMPTY);
        let sec_u32 = u32::try_from(sec).unwrap_or(WHEEL_EMPTY);
        if dev_u32 == WHEEL_EMPTY || sec_u32 == WHEEL_EMPTY {
            return;
        }
        let prev_head = self.heads.get(sec).copied().unwrap_or(WHEEL_EMPTY);
        if let Some(next_slot) = self.nexts.get_mut(dev_idx) {
            *next_slot = prev_head;
        }
        if let Some(bucket_slot) = self.enqueued_bucket.get_mut(dev_idx) {
            *bucket_slot = sec_u32;
        }
        if let Some(head_slot) = self.heads.get_mut(sec) {
            *head_slot = dev_u32;
        }
    }

    /// Pop all device indices queued at bucket `sec` into reusable scratch storage.
    pub fn drain_bucket(&mut self, sec: usize, out: &mut Vec<usize>) {
        out.clear();
        let Some(head_slot) = self.heads.get_mut(sec) else {
            return;
        };
        let mut cursor = *head_slot;
        *head_slot = WHEEL_EMPTY;
        while cursor != WHEEL_EMPTY {
            let idx = cursor as usize;
            out.push(idx);
            let next_val = self.nexts.get(idx).copied().unwrap_or(WHEEL_EMPTY);
            if let Some(slot) = self.nexts.get_mut(idx) {
                *slot = WHEEL_EMPTY;
            }
            if let Some(bucket_slot) = self.enqueued_bucket.get_mut(idx) {
                *bucket_slot = WHEEL_EMPTY;
            }
            cursor = next_val;
        }
    }
}

/// Allocate compact per-device states with deterministic `SHA-256` phase offsets.
#[must_use]
pub fn build_devices(
    device_count: usize,
    cell_count: usize,
    subscribe_ratio_pct: u8,
    schedule: &FleetSchedule,
) -> Vec<SimDevice> {
    let mut devices = Vec::with_capacity(device_count);
    let seed_digest = Sha256::digest(schedule.phase_salt.as_bytes());
    let base_seed = u64::from_le_bytes(
        seed_digest
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([1u8; 8]),
    );
    let hb_interval_s = (schedule.heartbeat_interval_ms / 1_000).max(1);
    let ev_interval_s = (schedule.evidence_interval_ms / 1_000).max(1);
    let ev_phase_tag = format!("{}-ev", schedule.phase_salt);

    for idx in 0..device_count {
        let cell_idx = (idx.checked_rem(cell_count).unwrap_or(0)) as u16;
        let id_bytes = (idx as u64).to_be_bytes();
        let hb_ms = deterministic_phase_ms(
            &id_bytes,
            &schedule.phase_salt,
            schedule.heartbeat_interval_ms,
        );
        let ev_ms = deterministic_phase_ms(&id_bytes, &ev_phase_tag, schedule.evidence_interval_ms);
        let mode = if idx.checked_rem(100).unwrap_or(0) < usize::from(subscribe_ratio_pct) {
            SimChannelMode::Subscribe
        } else {
            SimChannelMode::LongPollWait
        };
        let mut rng = SplitMix64::from_seed(base_seed ^ ((idx as u64).wrapping_mul(0x9e37_79b9)));
        let rng_word = rng.next_u64();
        devices.push(SimDevice {
            cell_idx,
            mode,
            hb_phase_s: ((hb_ms / 1_000).min(hb_interval_s.saturating_sub(1))) as u16,
            ev_phase_s: ((ev_phase_raw_ms(ev_ms) / 1_000).min(ev_interval_s.saturating_sub(1)))
                as u16,
            control_attempt: 0,
            data_attempt: 0,
            kill_delivered: false,
            rng_word,
        });
    }
    devices
}

const fn ev_phase_raw_ms(ms: u64) -> u64 {
    ms
}

/// Seed baseline phase-aligned heartbeat, evidence, and long-poll timers into timing wheels.
pub fn seed_initial_wheels(
    hb_interval_s: usize,
    devices: &mut [SimDevice],
    hb_wheel: &mut TimingWheel,
    ev_wheel: &mut TimingWheel,
    ctrl_wheel: &mut TimingWheel,
) {
    for (idx, dev) in devices.iter_mut().enumerate() {
        let mut rng = SplitMix64::from_seed(dev.rng_word);
        let jitter_s = ((rng.next_unit_f64() * 5.0) as usize).min(hb_interval_s.saturating_sub(1));
        hb_wheel.schedule((dev.hb_phase_s as usize).saturating_add(jitter_s), idx);
        ev_wheel.schedule(dev.ev_phase_s as usize, idx);
        if dev.mode == SimChannelMode::LongPollWait {
            let poll_offset = ((rng.next_unit_f64() * 55.0) as usize).saturating_add(1);
            ctrl_wheel.schedule(poll_offset, idx);
        }
        dev.rng_word = rng.next_u64();
    }
}

/// Measure peak sliding `RATE_WINDOW_SECS` request rates and peak 1s TLS handshakes across all cells.
#[must_use]
pub fn measure_peaks(
    counters: &[CellSecCounters],
    duration_secs: usize,
    cell_count: usize,
) -> (f64, f64, f64, u64) {
    let mut peak_hb = 0.0_f64;
    let mut peak_spine = 0.0_f64;
    let mut peak_ev = 0.0_f64;
    let mut peak_tls = 0u64;

    for cell in 0..cell_count {
        for start in 0..duration_secs {
            if let Some(c) = counters.get(start.saturating_mul(cell_count).saturating_add(cell)) {
                peak_tls = peak_tls.max(u64::from(c.new_tls));
            }
            if start.saturating_add(RATE_WINDOW_SECS) <= duration_secs {
                let mut hb_sum = 0u64;
                let mut sp_sum = 0u64;
                let mut ev_sum = 0u64;
                for off in 0..RATE_WINDOW_SECS {
                    let idx = start
                        .saturating_add(off)
                        .saturating_mul(cell_count)
                        .saturating_add(cell);
                    if let Some(c) = counters.get(idx) {
                        hb_sum = hb_sum.saturating_add(u64::from(c.hb));
                        sp_sum = sp_sum.saturating_add(u64::from(c.spine));
                        ev_sum = ev_sum.saturating_add(u64::from(c.evidence));
                    }
                }
                peak_hb = peak_hb.max((hb_sum as f64) / (RATE_WINDOW_SECS as f64));
                peak_spine = peak_spine.max((sp_sum as f64) / (RATE_WINDOW_SECS as f64));
                peak_ev = peak_ev.max((ev_sum as f64) / (RATE_WINDOW_SECS as f64));
            }
        }
    }
    (peak_hb, peak_spine, peak_ev, peak_tls)
}
