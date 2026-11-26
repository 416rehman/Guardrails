// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical wire codecs for `entity`, `event`, `feed`, and `export`.

pub mod entity {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{ExecutableRef, PathRef, ProtoTimestamp};
    pub use crate::canonical::entity_extra::entity_defs::*;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Principal {
        #[prost(string, tag = "1")]
        pub pseudonym: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::canonical::common_types::actor_kind_serde")]
        pub kind: i32,
        #[prost(string, tag = "3")]
        pub mapping: String,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::canonical::common_types::identity_proof_serde")]
        pub identity_proof: i32,
        #[prost(string, optional, tag = "5")]
        pub display_name: Option<String>,
        #[prost(string, optional, tag = "6")]
        pub email: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AgentInstance {
        #[prost(string, tag = "1")]
        pub agent_instance_id: String,
        #[prost(string, tag = "2")]
        pub agent_type_id: String,
        #[prost(string, tag = "3")]
        pub device_id: String,
        #[prost(string, tag = "4")]
        pub program_identity: String,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::canonical::common_types::agent_lifecycle_serde")]
        pub lifecycle: i32,
        #[prost(int32, tag = "6")]
        #[serde(with = "crate::canonical::common_types::containment_mode_serde")]
        pub containment_mode: i32,
        #[prost(message, optional, tag = "7")]
        pub executable: Option<ExecutableRef>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Session {
        #[prost(string, tag = "1")]
        pub session_id: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(string, tag = "3")]
        pub device_id: String,
        #[prost(message, optional, tag = "4")]
        pub principal: Option<Principal>,
        #[prost(int32, repeated, tag = "5")]
        #[serde(with = "crate::common::enums_ext::session_label_serde::vec")]
        pub labels: Vec<i32>,
        #[prost(message, optional, tag = "6")]
        pub workspace: Option<PathRef>,
        #[prost(message, optional, tag = "7")]
        pub started_at: Option<ProtoTimestamp>,
        #[prost(string, optional, tag = "8")]
        pub parent_session_id: Option<String>,
    }
}

pub mod event {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{ProtoTimestamp, Redaction, TraceContext};
    use crate::canonical::entity::Principal;
    use crate::canonical::governance::{
        assurance::AssuranceRecord, decision::DecisionRecord, finding::Finding,
        inventory::InventoryChange,
    };

    pub use super::super::telemetry_action::{
        Action, CredAction, DeterministicFact, ElevateAction, ExecAction, FileAction, LlmAction,
        McpAction, NetAction, SecondaryActionRef, action, deterministic_fact,
    };

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Source {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::control_point_serde")]
        pub control_point: i32,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums_open::channel_kind_serde")]
        pub channel: i32,
        #[prost(string, optional, tag = "4")]
        pub channel_other: Option<String>,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::canonical::common_types::provenance_kind_serde")]
        pub provenance: i32,
        #[prost(string, tag = "6")]
        pub component: String,
        #[prost(string, optional, tag = "7")]
        pub adapter: Option<String>,
        #[prost(string, optional, tag = "8")]
        pub agent_version: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ActorChain {
        #[prost(string, tag = "1")]
        pub agent_type_id: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(string, repeated, tag = "3")]
        pub sessions: Vec<String>,
        #[prost(string, optional, tag = "4")]
        pub tool_call_id: Option<String>,
        #[prost(string, optional, tag = "5")]
        pub process_key: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Attribution {
        #[prost(int32, repeated, tag = "1")]
        #[serde(with = "crate::common::enums_open::attribution_evidence_kind_serde::vec")]
        pub evidence: Vec<i32>,
        #[prost(string, optional, tag = "2")]
        pub evidence_other: Option<String>,
        #[prost(uint32, tag = "3")]
        pub grade: u32,
        #[prost(uint32, tag = "4")]
        pub score: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct FiveWayCommitments {
        #[prost(string, tag = "1")]
        pub d_identifier: String,
        #[prost(string, tag = "2")]
        pub d_structural: String,
        #[prost(string, tag = "3")]
        pub d_derived: String,
        #[prost(string, tag = "4")]
        pub d_argument: String,
        #[prost(string, tag = "5")]
        pub d_body: String,
        #[prost(bytes = "vec", optional, tag = "6")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub salt_identifier: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "7")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub salt_structural: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "8")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub salt_derived: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "9")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub salt_argument: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "10")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub salt_body: Option<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct MerkleRollupProof {
        #[prost(string, tag = "1")]
        pub merkle_root: String,
        #[prost(uint64, tag = "2")]
        pub leaf_count: u64,
        #[prost(string, repeated, tag = "3")]
        pub audit_path: Vec<String>,
        #[prost(uint64, optional, tag = "4")]
        pub leaf_index: Option<u64>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Integrity {
        #[prost(string, tag = "1")]
        pub prev: String,
        #[prost(string, tag = "2")]
        pub digest: String,
        #[prost(message, optional, tag = "3")]
        pub commitments: Option<FiveWayCommitments>,
        #[prost(string, optional, tag = "4")]
        pub signature: Option<String>,
        #[prost(string, optional, tag = "5")]
        pub signer_key_id: Option<String>,
        #[prost(string, optional, tag = "6")]
        pub checkpoint_ref: Option<String>,
        #[prost(bytes = "vec", optional, tag = "7")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub inclusion_proof: Option<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Envelope {
        #[prost(string, tag = "1")]
        pub event_id: String,
        #[prost(string, tag = "2")]
        pub organisation_id: String,
        #[prost(string, tag = "3")]
        pub device_id: String,
        #[prost(uint64, tag = "4")]
        pub epoch: u64,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::canonical::common_types::lane_serde")]
        pub lane: i32,
        #[prost(uint64, tag = "6")]
        pub seq: u64,
        #[prost(message, optional, tag = "7")]
        pub observed_time: Option<ProtoTimestamp>,
        #[prost(uint64, tag = "8")]
        pub monotonic_ns: u64,
        #[prost(string, tag = "9")]
        pub event_class: String,
        #[prost(message, optional, tag = "10")]
        pub trace: Option<TraceContext>,
        #[prost(message, optional, tag = "11")]
        pub principal: Option<Principal>,
        #[prost(message, optional, tag = "12")]
        pub actor_chain: Option<ActorChain>,
        #[prost(int32, tag = "13")]
        #[serde(with = "crate::canonical::common_types::actor_kind_serde")]
        pub actor_kind: i32,
        #[prost(message, optional, tag = "14")]
        pub attribution: Option<Attribution>,
        #[prost(message, optional, tag = "15")]
        pub source: Option<Source>,
        #[prost(message, optional, tag = "16")]
        pub integrity: Option<Integrity>,
        #[prost(int32, tag = "17")]
        #[serde(with = "crate::canonical::common_types::capture_level_serde")]
        pub capture_level: i32,
        #[prost(message, optional, tag = "18")]
        pub redaction: Option<Redaction>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ActionRollup {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
        #[prost(uint64, tag = "2")]
        pub event_count: u64,
        #[prost(uint64, tag = "3")]
        pub first_seq: u64,
        #[prost(uint64, tag = "4")]
        pub last_seq: u64,
        #[prost(message, optional, tag = "5")]
        pub merkle: Option<MerkleRollupProof>,
        #[prost(uint32, tag = "6")]
        pub distinct_targets: u32,
        #[prost(string, tag = "7")]
        pub summary_digest: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct SessionLifecycleEvent {
        #[prost(string, tag = "1")]
        pub kind: String,
        #[prost(string, tag = "2")]
        pub session_id: String,
        #[prost(int32, optional, tag = "3")]
        #[serde(with = "crate::canonical::common_types::containment_mode_serde::opt")]
        pub containment_mode: Option<i32>,
        #[prost(string, optional, tag = "4")]
        pub lease_id: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HealthEvent {
        #[prost(string, tag = "1")]
        pub code: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums_ext::finding_severity_serde")]
        pub severity: i32,
        #[prost(int32, optional, tag = "3")]
        #[serde(with = "crate::canonical::common_types::gap_reason_serde::opt")]
        pub gap_reason: Option<i32>,
        #[prost(uint64, tag = "4")]
        pub dropped_count: u64,
        #[prost(uint64, optional, tag = "5")]
        pub gap_start_seq: Option<u64>,
        #[prost(uint64, optional, tag = "6")]
        pub gap_end_seq: Option<u64>,
        #[prost(string, optional, tag = "7")]
        pub gap_reason_other: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ConfigEvent {
        #[prost(string, tag = "1")]
        pub target_id: String,
        #[prost(string, tag = "2")]
        pub previous_digest: String,
        #[prost(string, tag = "3")]
        pub next_digest: String,
        #[prost(bool, tag = "4")]
        pub widened: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Event {
        #[prost(message, optional, tag = "1")]
        pub envelope: Option<Envelope>,
        #[prost(oneof = "event_payload::Payload", tags = "2, 3, 4, 5, 6, 7, 8, 9, 10")]
        #[serde(flatten)]
        pub payload: Option<event_payload::Payload>,
    }

    pub mod event_payload {
        use super::*;

        #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum Payload {
            #[prost(message, tag = "2")]
            Action(Action),
            #[prost(message, tag = "3")]
            ActionRollup(ActionRollup),
            #[prost(message, tag = "4")]
            Decision(Box<DecisionRecord>),
            #[prost(message, tag = "5")]
            Finding(Finding),
            #[prost(message, tag = "6")]
            Assurance(AssuranceRecord),
            #[prost(message, tag = "7")]
            Inventory(InventoryChange),
            #[prost(message, tag = "8")]
            SessionEvent(SessionLifecycleEvent),
            #[prost(message, tag = "9")]
            HealthEvent(HealthEvent),
            #[prost(message, tag = "10")]
            ConfigEvent(ConfigEvent),
        }
    }
}

pub mod feed {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::event::Envelope;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct FeedHeader {
        #[prost(string, tag = "1")]
        pub schema_version: String,
        #[prost(string, tag = "2")]
        pub device_id: String,
        #[prost(string, tag = "3")]
        pub org_id: String,
        #[prost(uint64, tag = "4")]
        pub epoch: u64,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::canonical::common_types::lane_serde")]
        pub lane: i32,
        #[prost(uint64, tag = "6")]
        pub first_seq: u64,
        #[prost(message, optional, tag = "7")]
        pub opened_at: Option<ProtoTimestamp>,
        #[prost(string, tag = "8")]
        pub writer_key_id: String,
        #[prost(string, tag = "9")]
        pub prev_epoch_final_hash: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct FeedSummaryRecord {
        #[prost(message, optional, tag = "1")]
        pub envelope: Option<Envelope>,
        #[prost(uint64, tag = "2")]
        pub event_count: u64,
        #[prost(string, tag = "3")]
        pub merkle_root: String,
        #[prost(string, tag = "4")]
        pub head_digest: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GapRecord {
        #[prost(string, tag = "1")]
        pub device_id: String,
        #[prost(string, tag = "2")]
        pub org_id: String,
        #[prost(uint64, tag = "3")]
        pub epoch: u64,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::canonical::common_types::lane_serde")]
        pub lane: i32,
        #[prost(uint64, tag = "5")]
        pub start_seq: u64,
        #[prost(uint64, tag = "6")]
        pub end_seq: u64,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::canonical::common_types::gap_reason_serde")]
        pub reason: i32,
        #[prost(string, optional, tag = "8")]
        pub reason_other: Option<String>,
        #[prost(uint64, tag = "9")]
        pub dropped_count: u64,
        #[prost(message, optional, tag = "10")]
        pub detected_at: Option<ProtoTimestamp>,
        #[prost(string, tag = "11")]
        pub prev_chain_hash: String,
        #[prost(string, tag = "12")]
        pub gap_digest: String,
    }
}

pub mod export {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;
    use crate::canonical::governance::{
        decision::{DecisionRecord, Receipt},
        finding::{Finding, Incident},
    };
    use crate::canonical::telemetry_action::Action;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ExportCursor {
        #[prost(string, tag = "1")]
        pub destination_id: String,
        #[prost(string, tag = "2")]
        pub stream_offset: String,
        #[prost(uint64, tag = "3")]
        pub revision: u64,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ExportRecord {
        #[prost(string, tag = "1")]
        pub export_id: String,
        #[prost(message, optional, tag = "2")]
        pub cursor: Option<ExportCursor>,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums_open::export_dialect_serde")]
        pub dialect: i32,
        #[prost(string, optional, tag = "4")]
        pub dialect_other: Option<String>,
        #[prost(message, optional, tag = "5")]
        pub emitted_at: Option<ProtoTimestamp>,
        #[prost(string, tag = "6")]
        pub capture_ceiling: String,
        #[prost(oneof = "export_record::Item", tags = "7, 8, 9, 10, 11")]
        #[serde(flatten)]
        pub item: Option<export_record::Item>,
    }

    pub mod export_record {
        use super::*;

        #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum Item {
            #[prost(message, tag = "7")]
            Finding(Finding),
            #[prost(message, tag = "8")]
            Incident(Incident),
            #[prost(message, tag = "9")]
            Decision(Box<DecisionRecord>),
            #[prost(message, tag = "10")]
            Receipt(Receipt),
            #[prost(message, tag = "11")]
            Action(Action),
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::event::{
        Action, ActionRollup, Envelope, Event, FiveWayCommitments, HealthEvent, Integrity,
        MerkleRollupProof, Source, event_payload,
    };
    use crate::unknown_fields::PreservingEnvelope;

    #[test]
    fn canonical_event_and_reserved_sealed_twins_roundtrip() {
        let evt = Event {
            envelope: Some(Envelope {
                event_id: "evt-1".into(),
                organisation_id: "org-1".into(),
                device_id: "dev-1".into(),
                epoch: 2,
                lane: 1,
                seq: 7,
                event_class: "tool.exec".into(),
                integrity: Some(Integrity {
                    prev: "sha256:0000".into(),
                    digest: "sha256:1111".into(),
                    commitments: Some(FiveWayCommitments {
                        d_identifier: "id".into(),
                        d_structural: "st".into(),
                        d_derived: "dr".into(),
                        d_argument: "ar".into(),
                        d_body: "bd".into(),
                        salt_argument: Some(vec![7u8; 32]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                capture_level: 4,
                ..Default::default()
            }),
            payload: Some(event_payload::Payload::Action(Action {
                action_id: "act-1".into(),
                action_class: 1,
                phase: 1,
                outcome: 1,
                action_digest: "sha256:2222".into(),
                ..Default::default()
            })),
        };

        let mut wire = evt.encode_to_vec();
        prost::encoding::bytes::encode(901, &b"sealed-twin-identifier".to_vec(), &mut wire);
        prost::encoding::bytes::encode(905, &b"sealed-twin-body".to_vec(), &mut wire);

        let wrapped = PreservingEnvelope::<Event>::decode_with_known_tags(
            &wire,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )
        .unwrap();
        assert_eq!(wrapped.message, evt);
        assert!(!wrapped.unknown_fields.is_empty());
        assert_eq!(
            wrapped
                .encode_with_known_tags(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
                .unwrap(),
            wire
        );

        let rollup_evt = Event {
            envelope: evt.envelope.clone(),
            payload: Some(event_payload::Payload::ActionRollup(ActionRollup {
                action_class: 1,
                event_count: 4,
                first_seq: 3,
                last_seq: 6,
                merkle: Some(MerkleRollupProof {
                    merkle_root: "sha256:3333".into(),
                    leaf_count: 4,
                    audit_path: vec!["sha256:4444".into()],
                    leaf_index: Some(0),
                }),
                distinct_targets: 2,
                summary_digest: "sha256:5555".into(),
            })),
        };

        let json = serde_json::to_string(&rollup_evt).unwrap();
        let from_json: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, rollup_evt);

        // Source.provenance preserves P3 Observed(1) vs Claimed(2), and HealthEvent tags 5/6 encode as uint64.
        let src_obs: Source = serde_json::from_str(
            r#"{"component":"sensor","provenance":"PROVENANCE_KIND_OBSERVED","host":"h"}"#,
        )
        .unwrap();
        assert_eq!(src_obs.provenance, 1);
        let src_clm: Source =
            serde_json::from_str(r#"{"component":"hook","provenance":"claimed","host":"h"}"#)
                .unwrap();
        assert_eq!(src_clm.provenance, 2);
        let h_evt = HealthEvent {
            code: "gap".into(),
            severity: 2,
            gap_reason: Some(1),
            dropped_count: 5,
            gap_start_seq: Some(10),
            gap_end_seq: Some(14),
            gap_reason_other: None,
        };
        let h_dec = HealthEvent::decode(h_evt.encode_to_vec().as_slice()).unwrap();
        assert_eq!(h_dec, h_evt);
    }
}
