// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod assurance;
pub mod brand;
pub mod catalogue;
pub mod es_clients;
pub mod es_eval;
mod es_eval_self;
pub mod es_tree;
pub mod ffi;
mod ffi_common;
pub mod ffi_net;
pub mod ffi_types;
pub mod macos_probes;
pub mod network_ext;
pub mod seatbelt;
pub mod tier1_source;
pub mod tls_dns;
pub mod transcript_tail;

#[cfg(target_os = "macos")]
mod macos_fsevents;
#[cfg(target_os = "macos")]
mod macos_seccode;
#[cfg(target_os = "macos")]
mod macos_sys;

use std::collections::VecDeque;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::error::CODE_STORE_IO;
use grdr_model::{ActionAttempt, ActionClass, CodedError, ControlPoint, DecideInput};
use grdr_ports::SensorPort;

pub use assurance::{
    MacOsCapabilityFlags, MacOsTier, compute_macos_assurance, macos_session_level,
};
pub use brand::{MacOsBrandConfig, MacOsLimitsSnapshot, is_valid_apple_team_id};
pub use catalogue::{DelegationPolicy, HarnessCatalogue, HarnessEntry, NativeSandboxKind};
pub use es_clients::{
    EsClientRoleSpec, EsClientSetState, EsMutingStrategy, EsSubscribedEventKind,
    all_client_concerns, check_full_client_budget, role_spec_for_concern,
};
pub use es_eval::{
    EsAuthAction, EsAuthDecision, EsCoordinatorRuntime, EsGovernanceEvaluation, EsNotifyEventKind,
    EsNotifyEventRecord, FloorEvaluator,
};
pub use es_tree::{
    AuthDeadlineBudget, DeadlineMissPolicy, DeniedExecAuditRecord, EsAuditToken, EsClientConcern,
    EsClientStatus, EsEventPayload, EsTreeFollower, HealthGapEvent, ProcessTreeKey,
    SupervisorWatchdogOutcome, synthesize_denied_exec_audit,
};
pub use ffi::{
    grdr_macos_abi_version, grdr_macos_eval_es_event_bin_c, grdr_macos_eval_es_event_c,
    grdr_macos_follower_add_protected_path, grdr_macos_follower_add_self_path,
    grdr_macos_follower_free, grdr_macos_follower_lookup_token, grdr_macos_follower_mute_team,
    grdr_macos_follower_new, grdr_macos_follower_register_self_pid, grdr_macos_get_brand_info,
    grdr_macos_probe_capabilities_c, grdr_macos_probe_capabilities_with_follower_c,
    grdr_macos_self_signing_info_c,
};
pub use ffi_net::{
    grdr_macos_eval_ne_flow_bin_c, grdr_macos_eval_ne_flow_c, grdr_macos_match_model_host_c,
    grdr_macos_parse_dns_packet_c, grdr_macos_peek_tls_sni_c, grdr_macos_plan_seatbelt_c,
};
pub use ffi_types::{
    GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH, GRDR_MACOS_ABI_VERSION, GrdrMacAuditTokenC,
    GrdrMacBrandInfoC, GrdrMacCapabilitiesC, GrdrMacDnsParseOutC, GrdrMacEsConcernCode,
    GrdrMacEsEventC, GrdrMacEsEventKind, GrdrMacEsFollower, GrdrMacEsVerdictC, GrdrMacFfiStatus,
    GrdrMacFloorRuleC, GrdrMacNeFlowC, GrdrMacNeVerdictC, GrdrMacProcessKeyC, GrdrMacSeatbeltPlanC,
    GrdrMacSeatbeltRequestC, GrdrMacStrSliceC, GrdrMacTlsSniOutC, GrdrMacTlsSniStatusCode,
    GrdrMacTokenLookupOutC, GrdrMacVerdictCode,
};
pub use macos_probes::{
    DeveloperSigningStatus, FseventsBackendKind, FseventsDirectoryWatch, MacOsExtensionEntry,
    MacOsExtensionState, MacOsExternalProbeInputs, MacOsLiveCapabilities, MacOsProcessIdentity,
    apply_seatbelt_profile, build_slot_broker_from_probes_with_brand, enumerate_macos_processes,
    evaluate_developer_signing_status, evaluate_host_capabilities, inspect_macos_process,
    parse_kern_procargs2, probe_local_capabilities, probe_self_signing_team_and_es_entitlement,
    resolve_developer_program_held,
};
pub use network_ext::{
    EgressDefaultPolicy, FilterGrade, NeFlowRecord, NeFlowVerdict, SlotBrokerState, SlotCapability,
    SlotProbeReport, SlotRung, evaluate_ne_flow, evaluate_ne_flow_table,
};
pub use seatbelt::{
    MacOsContainmentMode, SeatbeltLaunchPlan, SeatbeltProfileSpec, canonicalize_macos_path,
    ensure_scoped_session_tmp_dir, generate_sbpl_profile, generate_sbpl_profile_with_options,
    generate_sbpl_profile_with_tmp, plan_macos_launch, plan_macos_launch_with_catalogue,
    scoped_session_tmp_dir,
};
pub use tier1_source::{
    LiveProcessProbe, MacOsTier1Config, MacOsTier1EventSource, ProcessDiscoveryProbe,
};
pub use tls_dns::{
    DnsDomainIpCache, DnsParsedPacket, TlsSniPeekResult, parse_dns_packet,
    peek_tls_client_hello_sni,
};
pub use transcript_tail::{
    TranscriptCanaryOutcome, TranscriptDeltaParser, TranscriptFdHandoff, TranscriptRawDelta,
    TranscriptTailer, TranscriptToolUseEntry,
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
    FseventsConfigWatch {
        session_id: String,
        agent_name: String,
        target: String,
        timestamp: Timestamp,
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

impl Default for MacOsSensor<MacOsTier1EventSource<LiveProcessProbe>> {
    fn default() -> Self {
        Self::new(MacOsTier1EventSource::live(), "local-macos", "macos-host")
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

    #[allow(clippy::too_many_arguments)]
    fn mint_attempt(
        &self,
        session_id: String,
        agent_name: String,
        action_class: ActionClass,
        control_point: ControlPoint,
        target: String,
        summary: String,
        timestamp: Timestamp,
    ) -> ActionAttempt {
        DecideInput {
            session_id: Some(session_id),
            device_id: Some(self.device_id.clone()),
            device_name: Some(self.device_name.clone()),
            agent_name,
            action_class,
            control_point: Some(control_point),
            target,
            summary: Some(summary),
        }
        .into_attempt(
            "sess-macos",
            &self.device_id,
            &self.device_name,
            "macOS sensor event",
            timestamp,
        )
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
                        out.push(self.mint_attempt(
                            session_id,
                            agent_name,
                            outcome.action_class,
                            ControlPoint::Sensor,
                            target,
                            outcome.summary,
                            timestamp,
                        ));
                    }
                }
                MacOsRawEvent::DeniedExecSynthesized { audit, agent_name } => {
                    out.push(self.mint_attempt(
                        audit.session_id,
                        agent_name,
                        ActionClass::Exec,
                        ControlPoint::Sensor,
                        audit.executable_path,
                        format!("Denied exec (synthesized from EXIT): {}", audit.reason),
                        audit.occurred_at,
                    ));
                }
                MacOsRawEvent::FseventsConfigWatch {
                    session_id,
                    agent_name,
                    target,
                    timestamp,
                } => {
                    out.push(self.mint_attempt(
                        session_id,
                        agent_name,
                        ActionClass::ConfigChange,
                        ControlPoint::Sensor,
                        target,
                        "Tier 1 macOS FSEvents config integrity watch change".into(),
                        timestamp,
                    ));
                }
                MacOsRawEvent::TranscriptClaim {
                    session_id,
                    agent_name,
                    action_class,
                    target,
                    timestamp,
                } => {
                    out.push(self.mint_attempt(
                        session_id,
                        agent_name,
                        action_class,
                        ControlPoint::Hook,
                        target,
                        "Tier 1 macOS claimed transcript/hook event".into(),
                        timestamp,
                    ));
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
    fn macos_sensor_satisfies_sensor_port_contract_and_mints_unique_model_ids() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let mut queue = VecDeque::new();
        queue.push_back(MacOsRawEvent::FseventsConfigWatch {
            session_id: "sess-mac-fs".into(),
            agent_name: "claude-code".into(),
            target: "/Users/dev/.claude/settings.json".into(),
            timestamp: ts,
        });
        queue.push_back(MacOsRawEvent::TranscriptClaim {
            session_id: "sess-mac-1".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            target: "cargo test".into(),
            timestamp: ts,
        });
        let mut sensor = MacOsSensor::new(ScriptedMacSource { queue }, "dev-mac-1", "macbook-pro");
        let batch = sensor.poll_events(10).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].control_point, ControlPoint::Sensor);
        assert_eq!(batch[0].action_class, ActionClass::ConfigChange);
        assert_eq!(batch[1].control_point, ControlPoint::Hook);
        assert!(batch[0].id.starts_with("att_"));
        assert!(batch[1].id.starts_with("att_"));
        assert_ne!(batch[0].id, batch[1].id);

        let mut q_contract = VecDeque::new();
        q_contract.push_back(MacOsRawEvent::TranscriptClaim {
            session_id: "sess-mac-2".into(),
            agent_name: "codex".into(),
            action_class: ActionClass::Exec,
            target: "ls".into(),
            timestamp: ts,
        });
        let mut contract_sensor = MacOsSensor::new(
            ScriptedMacSource { queue: q_contract },
            "dev-mac-1",
            "macbook-pro",
        );
        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut contract_sensor).is_ok());

        let default_live = MacOsSensor::default();
        assert_eq!(default_live.source.source_name(), "macos-tier1-live");

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
            timestamp: ts,
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
