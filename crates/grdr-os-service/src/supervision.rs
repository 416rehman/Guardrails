// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub const MAX_MISSED_HEARTBEATS: u32 = 5;
pub const CRASH_WINDOW_SECS: i64 = 600;
pub const CORRELATED_ACTIVATION_WINDOW_SECS: i64 = 7_200;
pub const STABLE_RECOVERY_SECS: i64 = 1_800;
pub const QUARANTINE_TTL_SECS: i64 = 86_400;
pub const DAEMON_SUPPRESSION_SECS: i64 = 3_600;
pub const BOOT_LOOP_WINDOW_SECS: i64 = 600;
pub const BOOT_LOOP_THRESHOLD: u32 = 2;
pub const SAFE_MODE_BACKOFF_SECS: &[i64] = &[900, 3_600, 14_400];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum ChildLifecycle {
    PendingStart {
        started_at: Timestamp,
    },
    Running {
        pid: u32,
        last_heartbeat: Timestamp,
        missed_beats: u32,
    },
    Unresponsive {
        pid: u32,
        detected_at: Timestamp,
        missed_beats: u32,
    },
    RestartBackoff {
        attempt: u32,
        retry_at: Timestamp,
    },
    Quarantined {
        reason: String,
    },
    Stopped,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisionDecision {
    pub lifecycle: ChildLifecycle,
    pub should_kill_and_restart: bool,
    pub health_condition: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FloorRuleUnion {
    pub fail_closed_rule_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildHeartbeatMonitor {
    child_role: String,
    lifecycle: ChildLifecycle,
}

#[derive(Debug, Clone)]
pub struct CrashLoopLadder {
    rung: LadderRung,
    entered_rung_at: Timestamp,
    engine_crashes: VecDeque<Timestamp>,
    daemon_crashes: VecDeque<Timestamp>,
    digest_strikes: BTreeMap<String, u32>,
    quarantined_digests: BTreeMap<String, Timestamp>,
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

impl ChildHeartbeatMonitor {
    pub fn new(child_role: impl Into<String>, started_at: Timestamp) -> Self {
        Self {
            child_role: child_role.into(),
            lifecycle: ChildLifecycle::PendingStart { started_at },
        }
    }

    pub fn role(&self) -> &str {
        &self.child_role
    }

    pub fn lifecycle(&self) -> &ChildLifecycle {
        &self.lifecycle
    }

    pub fn mark_running(&mut self, pid: u32, now: Timestamp) {
        self.lifecycle = ChildLifecycle::Running {
            pid,
            last_heartbeat: now,
            missed_beats: 0,
        };
    }

    pub fn record_heartbeat(&mut self, now: Timestamp) {
        if let ChildLifecycle::Running { pid, .. } = self.lifecycle {
            self.lifecycle = ChildLifecycle::Running {
                pid,
                last_heartbeat: now,
                missed_beats: 0,
            };
        }
    }

    pub fn tick_missed_heartbeat(&mut self, now: Timestamp) -> SupervisionDecision {
        match self.lifecycle {
            ChildLifecycle::Running {
                pid,
                last_heartbeat,
                missed_beats,
            } => {
                let next_missed = missed_beats.saturating_add(1);
                if next_missed >= MAX_MISSED_HEARTBEATS {
                    self.lifecycle = ChildLifecycle::Unresponsive {
                        pid,
                        detected_at: now,
                        missed_beats: next_missed,
                    };
                    SupervisionDecision {
                        lifecycle: self.lifecycle.clone(),
                        should_kill_and_restart: true,
                        health_condition: Some("child-unresponsive"),
                    }
                } else {
                    self.lifecycle = ChildLifecycle::Running {
                        pid,
                        last_heartbeat,
                        missed_beats: next_missed,
                    };
                    SupervisionDecision {
                        lifecycle: self.lifecycle.clone(),
                        should_kill_and_restart: false,
                        health_condition: None,
                    }
                }
            }
            _ => SupervisionDecision {
                lifecycle: self.lifecycle.clone(),
                should_kill_and_restart: false,
                health_condition: None,
            },
        }
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
            quarantined_digests: BTreeMap::new(),
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

    pub fn is_quarantined(&self, digest: &str, now: Timestamp) -> bool {
        self.quarantined_digests
            .get(digest)
            .is_some_and(|until| *until > now)
    }

    pub fn note_pack_activation(&mut self, now: Timestamp, new_floor: &FloorRuleUnion) {
        self.last_pack_activated_at = Some(now);
        self.floor.union_with(new_floor);
        self.quarantined_digests.clear();
        self.digest_strikes.clear();
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
        prune_window(&mut self.engine_crashes, now, CRASH_WINDOW_SECS);
        self.engine_crashes.push_back(now);

        for digest in in_flight_digests {
            let count = self.digest_strikes.entry(digest.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= 2 && !self.is_quarantined(digest, now) {
                let until = add_secs(now, QUARANTINE_TTL_SECS);
                self.quarantined_digests.insert(digest.clone(), until);
                let prev = self.rung;
                self.rung = LadderRung::Quarantine;
                self.entered_rung_at = now;
                return HealthTransitionEvent {
                    from: prev,
                    to: self.rung,
                    reason: "input-quarantined".into(),
                    correlated_digest: Some(digest.clone()),
                    action: LadderAction::QuarantineDigest {
                        digest: digest.clone(),
                    },
                    occurred_at: now,
                };
            }
        }

        if self.engine_crashes.len() >= 3 {
            let prev = self.rung;
            if within_window(
                self.last_pack_activated_at,
                now,
                CORRELATED_ACTIVATION_WINDOW_SECS,
            ) && prev == LadderRung::Normal
            {
                self.rung = LadderRung::ContentRevert;
                self.entered_rung_at = now;
                return HealthTransitionEvent {
                    from: prev,
                    to: self.rung,
                    reason: "pack-activation-crash-loop".into(),
                    correlated_digest: None,
                    action: LadderAction::RevertPackKeepFloorUnion,
                    occurred_at: now,
                };
            }

            if within_window(
                self.last_slot_switch_at,
                now,
                CORRELATED_ACTIVATION_WINDOW_SECS,
            ) && prev == LadderRung::Normal
                && self.previous_slot_version >= self.security_floor_version
            {
                self.rung = LadderRung::BinaryRevert;
                self.entered_rung_at = now;
                return HealthTransitionEvent {
                    from: prev,
                    to: self.rung,
                    reason: "slot-switch-crash-loop".into(),
                    correlated_digest: None,
                    action: LadderAction::RevertBinarySlot {
                        target_slot: "previous".into(),
                    },
                    occurred_at: now,
                };
            }

            self.rung = LadderRung::SafeMode;
            self.entered_rung_at = now;
            let delay = self.next_safe_mode_delay();
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "safe-mode".into(),
                correlated_digest: None,
                action: LadderAction::EnterSafeMode {
                    retry_after_secs: delay,
                },
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
        prune_window(&mut self.daemon_crashes, now, CRASH_WINDOW_SECS);
        self.daemon_crashes.push_back(now);
        let prev = self.rung;

        if prev == LadderRung::MinimalCore {
            self.rung = LadderRung::Stopped;
            self.entered_rung_at = now;
            return HealthTransitionEvent {
                from: prev,
                to: self.rung,
                reason: "daemon-crash-in-minimal-core".into(),
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
        let elapsed = now
            .as_second()
            .saturating_sub(self.entered_rung_at.as_second());
        match self.rung {
            LadderRung::Quarantine
            | LadderRung::ContentRevert
            | LadderRung::BinaryRevert
            | LadderRung::MinimalCore
                if elapsed >= STABLE_RECOVERY_SECS =>
            {
                let prev = self.rung;
                self.rung = LadderRung::Normal;
                self.entered_rung_at = now;
                self.engine_crashes.clear();
                self.daemon_crashes.clear();
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
        prune_window(&mut self.unexplained_reboots, now, BOOT_LOOP_WINDOW_SECS);
        self.unexplained_reboots.push_back(now);
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

fn add_secs(ts: Timestamp, secs: i64) -> Timestamp {
    Timestamp::from_second(ts.as_second().saturating_add(secs)).unwrap_or(ts)
}

fn prune_window(queue: &mut VecDeque<Timestamp>, now: Timestamp, window_secs: i64) {
    let cutoff = now.as_second().saturating_sub(window_secs);
    while let Some(front) = queue.front() {
        if front.as_second() < cutoff {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn within_window(event: Option<Timestamp>, now: Timestamp, window_secs: i64) -> bool {
    event.is_some_and(|ts| now.as_second().saturating_sub(ts.as_second()) <= window_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: i64) -> Timestamp {
        Timestamp::from_second(sec).unwrap()
    }

    #[test]
    fn heartbeat_monitor_marks_unresponsive_after_five_misses() {
        let mut mon = ChildHeartbeatMonitor::new("grdr-engine", ts(100));
        mon.mark_running(9001, ts(101));

        for i in 1..5 {
            let dec = mon.tick_missed_heartbeat(ts(101 + i));
            assert!(!dec.should_kill_and_restart);
            assert!(dec.health_condition.is_none());
        }
        let fifth = mon.tick_missed_heartbeat(ts(106));
        assert!(fifth.should_kill_and_restart);
        assert_eq!(fifth.health_condition, Some("child-unresponsive"));
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
        assert_eq!(ev3.to, LadderRung::SafeMode);
        assert!(ladder.effective_floor().is_superset_of(&newer));
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
