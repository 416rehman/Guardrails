// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub const CRASH_WINDOW_SECS: i64 = 600;
pub const CORRELATED_ACTIVATION_WINDOW_SECS: i64 = 7_200;
pub const STABLE_RECOVERY_SECS: i64 = 1_800;
pub const QUARANTINE_TTL_SECS: i64 = 86_400;
pub const DAEMON_SUPPRESSION_SECS: i64 = 3_600;
pub const BOOT_LOOP_WINDOW_SECS: i64 = 600;
pub const BOOT_LOOP_THRESHOLD: u32 = 2;
pub const MAX_TRACKED_DIGESTS: usize = 1_024;
pub const MAX_WINDOW_TIMESTAMPS: usize = 256;
pub const SAFE_MODE_BACKOFF_SECS: &[i64] = &[900, 3_600, 14_400];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LadderRung {
    Normal,
    Quarantine,
    ContentRevert,
    BinaryRevert,
    SafeMode,
    MinimalCore,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LadderAction {
    ContinueNormal,
    QuarantineDigest { digest: String },
    RevertPackKeepFloorUnion,
    RevertBinarySlot { target_slot: String },
    EnterSafeMode { retry_after_secs: i64 },
    EnterMinimalCoreNoCollectors,
    StopServiceSuppressed { suppress_secs: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthTransitionEvent {
    pub from: LadderRung,
    pub to: LadderRung,
    pub reason: String,
    pub correlated_digest: Option<String>,
    pub action: LadderAction,
    pub occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FloorRuleUnion {
    pub fail_closed_rule_ids: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct CrashLoopLadder {
    rung: LadderRung,
    entered_rung_at: Timestamp,
    engine_crashes: VecDeque<Timestamp>,
    daemon_crashes: VecDeque<Timestamp>,
    digest_strikes: BTreeMap<String, u32>,
    digest_strike_order: VecDeque<String>,
    quarantined_digests: BTreeMap<String, Timestamp>,
    quarantine_order: VecDeque<String>,
    last_pack_activated_at: Option<Timestamp>,
    last_slot_switch_at: Option<Timestamp>,
    previous_slot_version: u64,
    security_floor_version: u64,
    safe_mode_attempt: usize,
    floor: FloorRuleUnion,
}

#[derive(Debug, Clone)]
pub struct BootLoopGuard {
    unexplained_reboots: VecDeque<Timestamp>,
    kernel_loading_disabled: bool,
}

impl FloorRuleUnion {
    pub fn union_with(&mut self, incoming: &FloorRuleUnion) {
        for rule_id in &incoming.fail_closed_rule_ids {
            self.fail_closed_rule_ids.insert(rule_id.clone());
        }
    }

    pub fn is_superset_of(&self, other: &FloorRuleUnion) -> bool {
        other
            .fail_closed_rule_ids
            .iter()
            .all(|rule_id| self.fail_closed_rule_ids.contains(rule_id))
    }
}

impl CrashLoopLadder {
    pub fn new(now: Timestamp, initial_floor: FloorRuleUnion) -> Self {
        Self {
            rung: LadderRung::Normal,
            entered_rung_at: now,
            engine_crashes: VecDeque::new(),
            daemon_crashes: VecDeque::new(),
            digest_strikes: BTreeMap::new(),
            digest_strike_order: VecDeque::new(),
            quarantined_digests: BTreeMap::new(),
            quarantine_order: VecDeque::new(),
            last_pack_activated_at: None,
            last_slot_switch_at: None,
            previous_slot_version: 1,
            security_floor_version: 1,
            safe_mode_attempt: 0,
            floor: initial_floor,
        }
    }

    pub fn rung(&self) -> LadderRung {
        self.rung
    }

    pub fn effective_floor(&self) -> &FloorRuleUnion {
        &self.floor
    }

    pub fn tracked_digest_counts(&self) -> (usize, usize) {
        (self.digest_strikes.len(), self.quarantined_digests.len())
    }

    pub fn is_quarantined(&self, digest: &str, now: Timestamp) -> bool {
        self.quarantined_digests
            .get(digest)
            .is_some_and(|until| *until > now)
    }

    pub fn note_pack_activation(&mut self, now: Timestamp, new_floor: &FloorRuleUnion) {
        self.last_pack_activated_at = Some(now);
        self.floor.union_with(new_floor);
        self.quarantined_digests.clear();
        self.quarantine_order.clear();
        self.digest_strikes.clear();
        self.digest_strike_order.clear();
        if self.rung == LadderRung::SafeMode {
            self.rung = LadderRung::Normal;
            self.entered_rung_at = now;
            self.safe_mode_attempt = 0;
        }
    }

    pub fn note_slot_switch(
        &mut self,
        now: Timestamp,
        previous_slot_version: u64,
        security_floor_version: u64,
    ) {
        self.last_slot_switch_at = Some(now);
        self.previous_slot_version = previous_slot_version;
        self.security_floor_version = security_floor_version;
        if self.rung == LadderRung::SafeMode {
            self.rung = LadderRung::Normal;
            self.entered_rung_at = now;
            self.safe_mode_attempt = 0;
        }
    }

    pub fn record_engine_crash(
        &mut self,
        now: Timestamp,
        in_flight_digests: &[String],
    ) -> HealthTransitionEvent {
        self.prune_expired_digests(now);
        record_window_event(&mut self.engine_crashes, now, CRASH_WINDOW_SECS);

        let newly_quarantined = self.record_digest_strikes(now, in_flight_digests);
        if self.engine_crashes.len() >= 3 {
            return self.escalate_engine_crash_loop(now, newly_quarantined);
        }

        if let Some(digest) = newly_quarantined
            && self.rung < LadderRung::Quarantine
        {
            let prev = self.rung;
            self.rung = LadderRung::Quarantine;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "input-quarantined".into(),
                correlated_digest: Some(digest.clone()),
                action: LadderAction::QuarantineDigest { digest },
                occurred_at: now,
            };
        }

        HealthTransitionEvent {
            from: self.rung,
            to: self.rung,
            reason: "engine-crash-recorded".into(),
            correlated_digest: None,
            action: LadderAction::ContinueNormal,
            occurred_at: now,
        }
    }

    pub fn record_daemon_crash(&mut self, now: Timestamp) -> HealthTransitionEvent {
        record_window_event(&mut self.daemon_crashes, now, CRASH_WINDOW_SECS);
        let prev = self.rung;

        if matches!(prev, LadderRung::MinimalCore | LadderRung::Stopped) {
            self.rung = LadderRung::Stopped;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: if prev == LadderRung::Stopped {
                    "daemon-crash-while-suppressed"
                } else {
                    "daemon-crash-in-minimal-core"
                }
                .into(),
                correlated_digest: None,
                action: LadderAction::StopServiceSuppressed {
                    suppress_secs: DAEMON_SUPPRESSION_SECS,
                },
                occurred_at: now,
            };
        }

        if self.daemon_crashes.len() >= 3 {
            self.rung = LadderRung::MinimalCore;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "minimal-core".into(),
                correlated_digest: None,
                action: LadderAction::EnterMinimalCoreNoCollectors,
                occurred_at: now,
            };
        }

        HealthTransitionEvent {
            from: prev,
            to: prev,
            reason: "daemon-crash-recorded".into(),
            correlated_digest: None,
            action: LadderAction::ContinueNormal,
            occurred_at: now,
        }
    }

    pub fn tick_stability(&mut self, now: Timestamp) -> Option<HealthTransitionEvent> {
        self.prune_expired_digests(now);
        if now < self.entered_rung_at {
            // Re-anchor on backward wall-clock jump so recovery is delayed by one full window, not forever.
            self.entered_rung_at = now;
            return None;
        }
        let elapsed = now
            .as_second()
            .saturating_sub(self.entered_rung_at.as_second());
        match self.rung {
            LadderRung::Quarantine
            | LadderRung::ContentRevert
            | LadderRung::BinaryRevert
            | LadderRung::SafeMode
            | LadderRung::MinimalCore
                if elapsed >= STABLE_RECOVERY_SECS =>
            {
                let prev = self.rung;
                self.rung = LadderRung::Normal;
                self.entered_rung_at = now;
                self.engine_crashes.clear();
                self.daemon_crashes.clear();
                self.safe_mode_attempt = 0;
                Some(HealthTransitionEvent {
                    from: prev,
                    to: LadderRung::Normal,
                    reason: "stability-window-passed".into(),
                    correlated_digest: None,
                    action: LadderAction::ContinueNormal,
                    occurred_at: now,
                })
            }
            LadderRung::Stopped if elapsed >= DAEMON_SUPPRESSION_SECS => {
                let prev = self.rung;
                self.rung = LadderRung::MinimalCore;
                self.entered_rung_at = now;
                Some(HealthTransitionEvent {
                    from: prev,
                    to: LadderRung::MinimalCore,
                    reason: "suppression-window-ended".into(),
                    correlated_digest: None,
                    action: LadderAction::EnterMinimalCoreNoCollectors,
                    occurred_at: now,
                })
            }
            _ => None,
        }
    }

    fn record_digest_strikes(
        &mut self,
        now: Timestamp,
        in_flight_digests: &[String],
    ) -> Option<String> {
        let mut first_quarantined = None;
        for digest in in_flight_digests {
            if !self.digest_strikes.contains_key(digest) {
                evict_fifo_if_full(
                    &mut self.digest_strikes,
                    &mut self.digest_strike_order,
                    MAX_TRACKED_DIGESTS,
                );
                self.digest_strike_order.push_back(digest.clone());
            }
            let count = self.digest_strikes.entry(digest.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= 2 && !self.is_quarantined(digest, now) {
                if !self.quarantined_digests.contains_key(digest) {
                    evict_fifo_if_full(
                        &mut self.quarantined_digests,
                        &mut self.quarantine_order,
                        MAX_TRACKED_DIGESTS,
                    );
                    self.quarantine_order.push_back(digest.clone());
                }
                self.quarantined_digests
                    .insert(digest.clone(), add_secs(now, QUARANTINE_TTL_SECS));
                if first_quarantined.is_none() {
                    first_quarantined = Some(digest.clone());
                }
            }
        }
        first_quarantined
    }

    fn escalate_engine_crash_loop(
        &mut self,
        now: Timestamp,
        correlated_digest: Option<String>,
    ) -> HealthTransitionEvent {
        let prev = self.rung;
        if prev == LadderRung::Stopped {
            return HealthTransitionEvent {
                from: prev,
                to: LadderRung::Stopped,
                reason: "stopped-suppressed".into(),
                correlated_digest,
                action: LadderAction::StopServiceSuppressed {
                    suppress_secs: DAEMON_SUPPRESSION_SECS,
                },
                occurred_at: now,
            };
        }
        if prev == LadderRung::MinimalCore {
            return HealthTransitionEvent {
                from: prev,
                to: LadderRung::MinimalCore,
                reason: "minimal-core".into(),
                correlated_digest,
                action: LadderAction::EnterMinimalCoreNoCollectors,
                occurred_at: now,
            };
        }
        if within_window(
            self.last_pack_activated_at,
            now,
            CORRELATED_ACTIVATION_WINDOW_SECS,
        ) && matches!(prev, LadderRung::Normal | LadderRung::Quarantine)
        {
            self.rung = LadderRung::ContentRevert;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "pack-activation-crash-loop".into(),
                correlated_digest,
                action: LadderAction::RevertPackKeepFloorUnion,
                occurred_at: now,
            };
        }

        if within_window(
            self.last_slot_switch_at,
            now,
            CORRELATED_ACTIVATION_WINDOW_SECS,
        ) && matches!(prev, LadderRung::Normal | LadderRung::Quarantine)
            && self.previous_slot_version >= self.security_floor_version
        {
            self.rung = LadderRung::BinaryRevert;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "slot-switch-crash-loop".into(),
                correlated_digest,
                action: LadderAction::RevertBinarySlot {
                    target_slot: "previous".into(),
                },
                occurred_at: now,
            };
        }

        self.rung = LadderRung::SafeMode;
        self.entered_rung_at = now;
        let delay = self.next_safe_mode_delay();
        HealthTransitionEvent {
            from: prev,
            to: self.rung,
            reason: "safe-mode".into(),
            correlated_digest,
            action: LadderAction::EnterSafeMode {
                retry_after_secs: delay,
            },
            occurred_at: now,
        }
    }

    fn prune_expired_digests(&mut self, now: Timestamp) {
        self.quarantined_digests.retain(|_, until| *until > now);
        self.quarantine_order
            .retain(|d| self.quarantined_digests.contains_key(d));
    }

    fn next_safe_mode_delay(&mut self) -> i64 {
        let idx = self
            .safe_mode_attempt
            .min(SAFE_MODE_BACKOFF_SECS.len().saturating_sub(1));
        self.safe_mode_attempt = self.safe_mode_attempt.saturating_add(1);
        SAFE_MODE_BACKOFF_SECS.get(idx).copied().unwrap_or(14_400)
    }
}

impl Default for BootLoopGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BootLoopGuard {
    pub fn new() -> Self {
        Self {
            unexplained_reboots: VecDeque::new(),
            kernel_loading_disabled: false,
        }
    }

    pub fn kernel_loading_disabled(&self) -> bool {
        self.kernel_loading_disabled
    }

    pub fn record_unexplained_reboot(&mut self, now: Timestamp) -> bool {
        record_window_event(&mut self.unexplained_reboots, now, BOOT_LOOP_WINDOW_SECS);
        if self.unexplained_reboots.len() >= usize::try_from(BOOT_LOOP_THRESHOLD).unwrap_or(2) {
            self.kernel_loading_disabled = true;
        }
        self.kernel_loading_disabled
    }

    pub fn record_boot_ok(&mut self) {
        self.unexplained_reboots.clear();
        self.kernel_loading_disabled = false;
    }
}

fn evict_fifo_if_full<V>(map: &mut BTreeMap<String, V>, order: &mut VecDeque<String>, cap: usize) {
    while map.len() >= cap {
        let Some(oldest) = order.pop_front() else {
            break;
        };
        map.remove(&oldest);
    }
}

fn add_secs(ts: Timestamp, secs: i64) -> Timestamp {
    Timestamp::from_second(ts.as_second().saturating_add(secs)).unwrap_or(ts)
}

fn record_window_event(queue: &mut VecDeque<Timestamp>, now: Timestamp, window_secs: i64) {
    let now_s = now.as_second();
    let cutoff = now_s.saturating_sub(window_secs);
    queue.retain(|ts| {
        let s = ts.as_second();
        s >= cutoff && s <= now_s
    });
    while queue.len() >= MAX_WINDOW_TIMESTAMPS {
        queue.pop_front();
    }
    queue.push_back(now);
}

pub fn within_window(event: Option<Timestamp>, now: Timestamp, window_secs: i64) -> bool {
    let Some(ts) = event else {
        return false;
    };
    let Some(delta) = now.as_second().checked_sub(ts.as_second()) else {
        return false;
    };
    delta >= 0 && delta <= window_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: i64) -> Timestamp {
        Timestamp::from_second(sec).unwrap()
    }

    #[test]
    fn crash_loop_ladder_quarantines_reverts_and_keeps_floor_union() {
        let mut initial = FloorRuleUnion::default();
        initial.fail_closed_rule_ids.insert("floor.cred".into());
        let mut ladder = CrashLoopLadder::new(ts(1_000), initial.clone());

        let mut newer = FloorRuleUnion::default();
        newer.fail_closed_rule_ids.insert("floor.elevate".into());
        ladder.note_pack_activation(ts(1_010), &newer);
        assert!(ladder.effective_floor().is_superset_of(&initial));
        assert!(ladder.effective_floor().is_superset_of(&newer));

        let d = vec!["sha256:bad".to_string()];
        let ev1 = ladder.record_engine_crash(ts(1_020), &d);
        assert_eq!(ev1.to, LadderRung::Normal);
        let ev2 = ladder.record_engine_crash(ts(1_030), &d);
        assert_eq!(ev2.to, LadderRung::Quarantine);
        assert!(ladder.is_quarantined("sha256:bad", ts(1_035)));

        let ev3 = ladder.record_engine_crash(ts(1_040), &[]);
        assert_eq!(ev3.to, LadderRung::ContentRevert);
        assert!(ladder.effective_floor().is_superset_of(&newer));
    }

    #[test]
    fn rejects_backward_clock_jump_in_within_window_and_bounds_digests() {
        assert!(!within_window(Some(ts(2_000)), ts(1_000), 600));
        assert!(within_window(Some(ts(1_000)), ts(1_500), 600));

        let mut ladder = CrashLoopLadder::new(ts(1_000), FloorRuleUnion::default());
        for idx in 0..(MAX_TRACKED_DIGESTS + 20) {
            let d = vec![format!("sha256:{idx}")];
            ladder.record_engine_crash(ts(1_000 + i64::try_from(idx).unwrap()), &d);
        }
        let (strikes, _) = ladder.tracked_digest_counts();
        assert!(strikes <= MAX_TRACKED_DIGESTS);

        let mut stopped_ladder = CrashLoopLadder::new(ts(1_000), FloorRuleUnion::default());
        stopped_ladder.record_daemon_crash(ts(1_010));
        stopped_ladder.record_daemon_crash(ts(1_020));
        assert_eq!(
            stopped_ladder.record_daemon_crash(ts(1_030)).to,
            LadderRung::MinimalCore
        );
        assert_eq!(
            stopped_ladder.record_daemon_crash(ts(1_040)).to,
            LadderRung::Stopped
        );
        assert_eq!(
            stopped_ladder.record_daemon_crash(ts(1_050)).to,
            LadderRung::Stopped
        );
        for step in 0..4 {
            assert_eq!(
                stopped_ladder.record_engine_crash(ts(1_060 + step), &[]).to,
                LadderRung::Stopped
            );
        }
        assert!(stopped_ladder.tick_stability(ts(900)).is_none());
        assert_eq!(
            stopped_ladder
                .tick_stability(ts(900 + DAEMON_SUPPRESSION_SECS))
                .unwrap()
                .to,
            LadderRung::MinimalCore
        );
    }

    #[test]
    fn boot_loop_guard_disables_kernel_loading_after_two_reboots() {
        let mut guard = BootLoopGuard::new();
        assert!(!guard.record_unexplained_reboot(ts(1_000)));
        assert!(guard.record_unexplained_reboot(ts(1_200)));
        assert!(guard.kernel_loading_disabled());
        guard.record_boot_ok();
        assert!(!guard.kernel_loading_disabled());
    }
}
