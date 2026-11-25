// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub const MAX_MISSED_HEARTBEATS: u32 = 5;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisionDecision {
    pub lifecycle: ChildLifecycle,
    pub should_kill_and_restart: bool,
    pub health_condition: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildHeartbeatMonitor {
    child_role: String,
    lifecycle: ChildLifecycle,
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
}
