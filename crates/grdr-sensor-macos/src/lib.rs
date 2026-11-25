// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod assurance;
pub mod es_tree;
pub mod network_ext;
pub mod seatbelt;

use std::collections::VecDeque;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::error::CODE_STORE_IO;
use grdr_model::{ActionAttempt, ActionClass, CodedError, ControlPoint};
use grdr_ports::SensorPort;

pub use assurance::{
    MacOsCapabilityFlags, MacOsTier, compute_macos_assurance, macos_session_level,
};
pub use es_tree::{
    AuthDeadlineBudget, DeadlineMissPolicy, DeniedExecAuditRecord, EsAuditToken, EsClientConcern,
    EsClientStatus, EsEventPayload, EsTreeFollower, HealthGapEvent, ProcessTreeKey,
    SupervisorWatchdogOutcome, synthesize_denied_exec_audit,
};
pub use network_ext::{
    EgressDefaultPolicy, FilterGrade, NeFlowRecord, NeFlowVerdict, SlotBrokerState, SlotCapability,
    SlotProbeReport, SlotRung, evaluate_ne_flow,
};
pub use seatbelt::{
    MacOsContainmentMode, SeatbeltLaunchPlan, SeatbeltProfileSpec, canonicalize_macos_path,
    generate_sbpl_profile, plan_macos_launch,
};

pub const CODE_MACSENS_SEATBELT: &str = "GRDR-MACSENS-0001";
pub const CODE_MACSENS_NETWORK_EXT: &str = "GRDR-MACSENS-0002";
pub const CODE_MACSENS_ES_TREE: &str = "GRDR-MACSENS-0003";
pub const CODE_MACSENS_SOURCE: &str = "GRDR-MACSENS-0004";
pub const MAX_BUFFERED_GAPS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MacOsSensorError {
    #[error("GRDR-MACSENS-0001: Seatbelt profile error: {0}")]
    Seatbelt(String),
    #[error("GRDR-MACSENS-0002: Network Extension slot broker fault: {0}")]
    NetworkExt(String),
    #[error("GRDR-MACSENS-0003: Endpoint Security tree follower fault: {0}")]
    EsTree(String),
    #[error("GRDR-MACSENS-0004: macOS sensor source error: {0}")]
    Source(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MacOsRawEvent {
    EsEvent {
        payload: EsEventPayload,
        seq_num: u64,
        agent_name: String,
        target: String,
        timestamp: Timestamp,
    },
    DeniedExecSynthesized {
        audit: DeniedExecAuditRecord,
        agent_name: String,
    },
    TranscriptClaim {
        session_id: String,
        agent_name: String,
        action_class: ActionClass,
        target: String,
        timestamp: Timestamp,
    },
}

pub trait MacOsEventSource: Send {
    fn source_name(&self) -> &str;
    fn poll_raw_events(
        &mut self,
        max_events: usize,
    ) -> Result<Vec<MacOsRawEvent>, MacOsSensorError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopMacOsEventSource;

#[derive(Debug)]
pub struct MacOsSensor<S> {
    source: S,
    device_id: String,
    device_name: String,
    tree: EsTreeFollower,
    gaps: VecDeque<HealthGapEvent>,
    dropped_gaps_count: u64,
}

impl From<MacOsSensorError> for CodedError {
    fn from(err: MacOsSensorError) -> Self {
        let code = match &err {
            MacOsSensorError::Seatbelt(_) => CODE_MACSENS_SEATBELT,
            MacOsSensorError::NetworkExt(_) => CODE_MACSENS_NETWORK_EXT,
            MacOsSensorError::EsTree(_) => CODE_MACSENS_ES_TREE,
            MacOsSensorError::Source(_) => CODE_MACSENS_SOURCE,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Check macOS Full Disk Access, system extension approval, and entitlements.",
        )
    }
}

impl MacOsEventSource for NoopMacOsEventSource {
    fn source_name(&self) -> &str {
        "macos-noop"
    }

    fn poll_raw_events(
        &mut self,
        _max_events: usize,
    ) -> Result<Vec<MacOsRawEvent>, MacOsSensorError> {
        Ok(Vec::new())
    }
}

impl Default for MacOsSensor<NoopMacOsEventSource> {
    fn default() -> Self {
        Self::new(NoopMacOsEventSource, "local-macos", "macos-host")
    }
}

impl<S: MacOsEventSource> MacOsSensor<S> {
    pub fn new(source: S, device_id: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            source,
            device_id: device_id.into(),
            device_name: device_name.into(),
            tree: EsTreeFollower::new(),
            gaps: VecDeque::new(),
            dropped_gaps_count: 0,
        }
    }

    pub fn tree_follower(&self) -> &EsTreeFollower {
        &self.tree
    }

    pub fn drain_health_gaps(&mut self) -> Vec<HealthGapEvent> {
        self.gaps.drain(..).collect()
    }

    pub fn dropped_gaps_count(&self) -> u64 {
        self.dropped_gaps_count
    }

    fn push_gap(&mut self, gap: HealthGapEvent) {
        if self.gaps.len() >= MAX_BUFFERED_GAPS {
            self.gaps.pop_front();
            self.dropped_gaps_count = self.dropped_gaps_count.saturating_add(1);
        }
        self.gaps.push_back(gap);
    }
}

impl<S: MacOsEventSource> SensorPort for MacOsSensor<S> {
    fn sensor_name(&self) -> &'static str {
        "macos-sensor"
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        let raw_events = self.source.poll_raw_events(max_events).map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!(
                    "macOS sensor source `{}` failed: {e}",
                    self.source.source_name()
                ),
                "Inspect macOS sensor permissions and extension state.",
            )
        })?;

        let mut out = Vec::new();
        for ev in raw_events {
            if out.len() >= max_events {
                break;
            }
            match ev {
                MacOsRawEvent::EsEvent {
                    payload,
                    seq_num,
                    agent_name,
                    target,
                    timestamp,
                } => {
                    if let Some(gap) = self.tree.record_sequence(seq_num, timestamp) {
                        self.push_gap(gap);
                    }
                    let outcome = self.tree.apply_event(&payload);
                    if let Some(session_id) = outcome.session_id {
                        out.push(ActionAttempt {
                            id: format!("att-mac-es-{seq_num}"),
                            session_id,
                            device_id: self.device_id.clone(),
                            device_name: self.device_name.clone(),
                            agent_name,
                            action_class: outcome.action_class,
                            control_point: ControlPoint::Sensor,
                            target,
                            summary: outcome.summary,
                            timestamp,
                            ..Default::default()
                        });
                    }
                }
                MacOsRawEvent::DeniedExecSynthesized { audit, agent_name } => {
                    out.push(ActionAttempt {
                        id: format!("att-mac-deny-{}", audit.target_key.pid),
                        session_id: audit.session_id,
                        device_id: self.device_id.clone(),
                        device_name: self.device_name.clone(),
                        agent_name,
                        action_class: ActionClass::Exec,
                        control_point: ControlPoint::Sensor,
                        target: audit.executable_path,
                        summary: format!("Denied exec (synthesized from EXIT): {}", audit.reason),
                        timestamp: audit.occurred_at,
                        ..Default::default()
                    });
                }
                MacOsRawEvent::TranscriptClaim {
                    session_id,
                    agent_name,
                    action_class,
                    target,
                    timestamp,
                } => {
                    out.push(ActionAttempt {
                        id: format!("att-mac-claim-{}", timestamp.as_second()),
                        session_id,
                        device_id: self.device_id.clone(),
                        device_name: self.device_name.clone(),
                        agent_name,
                        action_class,
                        control_point: ControlPoint::Hook,
                        target,
                        summary: "Tier 1 macOS claimed transcript/hook event".into(),
                        timestamp,
                        ..Default::default()
                    });
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedMacSource {
        queue: VecDeque<MacOsRawEvent>,
    }

    impl MacOsEventSource for ScriptedMacSource {
        fn source_name(&self) -> &str {
            "mock-macos"
        }

        fn poll_raw_events(
            &mut self,
            max_events: usize,
        ) -> Result<Vec<MacOsRawEvent>, MacOsSensorError> {
            let mut out = Vec::new();
            for _ in 0..max_events {
                let Some(item) = self.queue.pop_front() else {
                    break;
                };
                out.push(item);
            }
            Ok(out)
        }
    }

    #[test]
    fn macos_sensor_satisfies_sensor_port_contract() {
        let mut queue = VecDeque::new();
        queue.push_back(MacOsRawEvent::TranscriptClaim {
            session_id: "sess-mac-1".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            target: "cargo test".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        });
        let mut sensor = MacOsSensor::new(ScriptedMacSource { queue }, "dev-mac-1", "macbook-pro");
        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut sensor).is_ok());

        let untracked = MacOsRawEvent::EsEvent {
            payload: EsEventPayload::NotifyFork {
                parent: ProcessTreeKey {
                    pid: 9999,
                    pidversion: 1,
                },
                child: EsAuditToken {
                    key: ProcessTreeKey {
                        pid: 10000,
                        pidversion: 1,
                    },
                    uid: 501,
                    team_id: None,
                },
            },
            seq_num: 1,
            agent_name: "unknown".into(),
            target: "/bin/ls".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        };
        let mut untracked_q = VecDeque::new();
        untracked_q.push_back(untracked);
        let mut s2 = MacOsSensor::new(
            ScriptedMacSource { queue: untracked_q },
            "dev-mac-1",
            "macbook-pro",
        );
        assert!(s2.poll_events(10).unwrap().is_empty());
    }
}
