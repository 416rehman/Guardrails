// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical wire codecs for `decision`, `finding`, `assurance`, `inventory`, `decide`, and `provider`.

pub use super::governance_rpc::{decide, provider};

pub mod decision {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{ProtoDuration, ProtoTimestamp, TargetRef};
    pub use crate::canonical::entity_extra::decision_defs::Grant;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Verdict {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::verdict_serde")]
        pub code: i32,
        #[prost(string, optional, tag = "2")]
        pub rule_id: Option<String>,
        #[prost(string, optional, tag = "3")]
        pub pack_id: Option<String>,
        #[prost(int32, optional, tag = "4")]
        #[serde(with = "crate::common::enums::mode_serde::opt")]
        pub mode_applied: Option<i32>,
        #[prost(string, tag = "5")]
        pub reason_code: String,
        #[prost(int32, optional, tag = "6")]
        #[serde(with = "crate::common::enums::approval_grade_serde::opt")]
        pub min_grade: Option<i32>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Receipt {
        #[prost(string, tag = "1")]
        pub receipt_id: String,
        #[prost(string, tag = "2")]
        pub decision_id: String,
        #[prost(string, tag = "3")]
        pub attempt_id: String,
        #[prost(string, tag = "4")]
        pub session_id: String,
        #[prost(string, tag = "5")]
        pub device_id: String,
        #[prost(string, tag = "6")]
        pub action_digest: String,
        #[prost(message, optional, tag = "7")]
        pub verdict: Option<Verdict>,
        #[prost(message, optional, tag = "8")]
        pub would_be: Option<Verdict>,
        #[prost(string, optional, tag = "9")]
        pub grant_id: Option<String>,
        #[prost(string, tag = "10")]
        pub receipt_digest: String,
        #[prost(string, tag = "11")]
        pub signature: String,
        #[prost(string, tag = "12")]
        pub signer_key_id: String,
        #[prost(bytes = "vec", optional, tag = "13")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub transparency: Option<Vec<u8>>,
        #[prost(message, optional, tag = "14")]
        pub decided_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Expectation {
        #[prost(string, tag = "1")]
        pub expectation_id: String,
        #[prost(string, tag = "2")]
        pub session_id: String,
        #[prost(string, tag = "3")]
        pub tool_call_id: String,
        #[prost(string, tag = "4")]
        pub agent_process_key: String,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
        #[prost(string, tag = "6")]
        pub effect_digest: String,
        #[prost(string, optional, tag = "7")]
        pub grant_id: Option<String>,
        #[prost(message, optional, tag = "8")]
        pub valid_window: Option<ProtoDuration>,
        #[prost(message, optional, tag = "9")]
        pub target: Option<TargetRef>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DecisionRecord {
        #[prost(string, tag = "1")]
        pub decision_id: String,
        #[prost(string, tag = "2")]
        pub action_id: String,
        #[prost(message, optional, tag = "3")]
        pub receipt: Option<Receipt>,
        #[prost(string, repeated, tag = "4")]
        pub matched_rules: Vec<String>,
        #[prost(int32, repeated, tag = "5")]
        #[serde(with = "crate::common::enums_ext::session_label_serde::vec")]
        pub added_labels: Vec<i32>,
        #[prost(message, optional, tag = "6")]
        pub expectation: Option<Expectation>,
    }
}

pub mod finding {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{ProtoTimestamp, TargetRef};

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EvidenceSpan {
        #[prost(string, tag = "1")]
        pub span_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums_open::evidence_kind_serde")]
        pub kind: i32,
        #[prost(string, optional, tag = "3")]
        pub kind_other: Option<String>,
        #[prost(string, tag = "4")]
        pub source_ref: String,
        #[prost(string, tag = "5")]
        pub digest: String,
        #[prost(string, optional, tag = "6")]
        pub text: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Observable {
        #[prost(string, tag = "1")]
        pub observable_id: String,
        #[prost(string, tag = "2")]
        pub kind: String,
        #[prost(string, tag = "3")]
        pub value_digest: String,
        #[prost(string, optional, tag = "4")]
        pub value: Option<String>,
        #[prost(message, optional, tag = "5")]
        pub first_seen_at: Option<ProtoTimestamp>,
        #[prost(message, optional, tag = "6")]
        pub last_seen_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Finding {
        #[prost(string, tag = "1")]
        pub finding_id: String,
        #[prost(string, tag = "2")]
        pub org_id: String,
        #[prost(string, tag = "3")]
        pub session_id: String,
        #[prost(string, tag = "4")]
        pub device_id: String,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::common::enums_ext::finding_class_serde")]
        pub finding_class: i32,
        #[prost(string, optional, tag = "6")]
        pub finding_class_other: Option<String>,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums_ext::finding_severity_serde")]
        pub severity: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::common::enums_ext::finding_lifecycle_serde")]
        pub lifecycle: i32,
        #[prost(string, optional, tag = "9")]
        pub rule_id: Option<String>,
        #[prost(string, tag = "10")]
        pub title: String,
        #[prost(string, tag = "11")]
        pub summary: String,
        #[prost(message, optional, tag = "12")]
        pub target: Option<TargetRef>,
        #[prost(message, repeated, tag = "13")]
        pub evidence_spans: Vec<EvidenceSpan>,
        #[prost(message, repeated, tag = "14")]
        pub observables: Vec<Observable>,
        #[prost(bool, tag = "15")]
        pub retro: bool,
        #[prost(message, optional, tag = "16")]
        pub detected_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Incident {
        #[prost(string, tag = "1")]
        pub incident_id: String,
        #[prost(string, tag = "2")]
        pub org_id: String,
        #[prost(string, tag = "3")]
        pub session_id: String,
        #[prost(string, tag = "4")]
        pub device_id: String,
        #[prost(string, tag = "5")]
        pub title: String,
        #[prost(string, tag = "6")]
        pub summary: String,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums_ext::finding_severity_serde")]
        pub severity: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::common::enums_ext::finding_lifecycle_serde")]
        pub lifecycle: i32,
        #[prost(string, repeated, tag = "9")]
        pub finding_ids: Vec<String>,
        #[prost(message, optional, tag = "10")]
        pub first_seen_at: Option<ProtoTimestamp>,
        #[prost(message, optional, tag = "11")]
        pub last_seen_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Suppression {
        #[prost(string, tag = "1")]
        pub suppression_id: String,
        #[prost(string, tag = "2")]
        pub rule_id: String,
        #[prost(string, tag = "3")]
        pub scope_digest: String,
        #[prost(string, tag = "4")]
        pub owner: String,
        #[prost(string, tag = "5")]
        pub justification: String,
        #[prost(message, optional, tag = "6")]
        pub expires_at: Option<ProtoTimestamp>,
    }
}

pub mod assurance {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoTimestamp;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ControlPointCapability {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::control_point_serde")]
        pub control_point: i32,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
        #[prost(bool, tag = "3")]
        pub attached: bool,
        #[prost(bool, tag = "4")]
        pub enforcing: bool,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::common::enums::visibility_serde")]
        pub visibility: i32,
        #[prost(int32, tag = "6")]
        #[serde(with = "crate::common::enums::control_strength_serde")]
        pub control: i32,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums::on_failure_serde")]
        pub on_failure: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct CapabilityProbeResult {
        #[prost(string, tag = "1")]
        pub probe_name: String,
        #[prost(bool, tag = "2")]
        pub passed: bool,
        #[prost(string, tag = "3")]
        pub detail_code: String,
        #[prost(message, optional, tag = "4")]
        pub measured_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AssuranceRecord {
        #[prost(string, optional, tag = "1")]
        pub session_id: Option<String>,
        #[prost(string, tag = "2")]
        pub device_id: String,
        #[prost(string, tag = "3")]
        pub agent_instance_id: String,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums::visibility_serde")]
        pub visibility: i32,
        #[prost(int32, tag = "5")]
        #[serde(with = "crate::common::enums::control_strength_serde")]
        pub control: i32,
        #[prost(int32, tag = "6")]
        #[serde(with = "crate::common::enums::on_failure_serde")]
        pub on_failure: i32,
        #[prost(int32, tag = "7")]
        #[serde(with = "crate::common::enums::tamper_grade_serde")]
        pub tamper: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::common::enums::assurance_level_serde")]
        pub level: i32,
        #[prost(message, repeated, tag = "9")]
        pub capabilities: Vec<ControlPointCapability>,
        #[prost(message, repeated, tag = "10")]
        pub probes: Vec<CapabilityProbeResult>,
        #[prost(string, repeated, tag = "11")]
        pub next_level_blockers: Vec<String>,
        #[prost(message, optional, tag = "12")]
        pub evaluated_at: Option<ProtoTimestamp>,
    }
}

pub mod inventory {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{PathRef, ProtoTimestamp};
    pub use crate::canonical::entity_extra::inventory_defs::{
        AgentDeclaration, DeclaredSourceRow, DeclaredToolSpec,
    };
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum DiffState {
        Unspecified = 0,
        Matched = 1,
        ObservedOnly = 2,
        DeclaredOnly = 3,
        Mismatch = 4,
        IncumbentOnly = 5,
    }
    proto_enum_codec!(DiffState, diff_state_serde, [
        DiffState::Unspecified => "DIFF_STATE_UNSPECIFIED",
        DiffState::Matched => "DIFF_STATE_MATCHED" | "matched",
        DiffState::ObservedOnly => "DIFF_STATE_OBSERVED_ONLY" | "observed_only",
        DiffState::DeclaredOnly => "DIFF_STATE_DECLARED_ONLY" | "declared_only",
        DiffState::Mismatch => "DIFF_STATE_MISMATCH" | "mismatch",
        DiffState::IncumbentOnly => "DIFF_STATE_INCUMBENT_ONLY" | "incumbent_only",
    ]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum PinState {
        Unspecified = 0,
        Pinned = 1,
        Unpinned = 2,
        Drifted = 3,
    }
    proto_enum_codec!(PinState, pin_state_serde, [
        PinState::Unspecified => "PIN_STATE_UNSPECIFIED",
        PinState::Pinned => "PIN_STATE_PINNED" | "pinned",
        PinState::Unpinned => "PIN_STATE_UNPINNED" | "unpinned",
        PinState::Drifted => "PIN_STATE_DRIFTED" | "drifted",
    ]);

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DiscoveryEvidence {
        #[prost(uint32, tag = "1")]
        pub pass: u32,
        #[prost(string, tag = "2")]
        pub program_identity: String,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::common::enums_open::disposition_serde")]
        pub disposition: i32,
        #[prost(string, repeated, tag = "4")]
        pub package_markers: Vec<String>,
        #[prost(message, optional, tag = "5")]
        pub config_path: Option<PathRef>,
        #[prost(string, optional, tag = "6")]
        pub blind_spot_reason: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct InventoryChange {
        #[prost(string, tag = "1")]
        pub change_kind: String,
        #[prost(string, tag = "2")]
        pub agent_instance_id: String,
        #[prost(enumeration = "PinState", tag = "3")]
        #[serde(with = "pin_state_serde")]
        pub pin_state: i32,
        #[prost(enumeration = "DiffState", tag = "4")]
        #[serde(with = "diff_state_serde")]
        pub diff_state: i32,
        #[prost(message, optional, tag = "5")]
        pub evidence: Option<DiscoveryEvidence>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct BomComponent {
        #[prost(string, tag = "1")]
        pub component_id: String,
        #[prost(string, tag = "2")]
        pub component_kind: String,
        #[prost(string, tag = "3")]
        pub name: String,
        #[prost(string, optional, tag = "4")]
        pub version: Option<String>,
        #[prost(string, optional, tag = "5")]
        pub digest: Option<String>,
        #[prost(enumeration = "PinState", tag = "6")]
        #[serde(with = "pin_state_serde")]
        pub pin_state: i32,
        #[prost(enumeration = "DiffState", tag = "7")]
        #[serde(with = "diff_state_serde")]
        pub diff_state: i32,
        #[prost(int32, tag = "8")]
        #[serde(with = "crate::canonical::common_types::provenance_kind_serde")]
        pub provenance: i32,
        #[prost(int32, tag = "9")]
        #[serde(with = "crate::common::enums::assurance_level_serde")]
        pub assurance_level: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct BomEdge {
        #[prost(string, tag = "1")]
        pub from_id: String,
        #[prost(string, tag = "2")]
        pub to_id: String,
        #[prost(string, tag = "3")]
        pub relation: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct AgentBom {
        #[prost(string, tag = "1")]
        pub bom_id: String,
        #[prost(string, tag = "2")]
        pub scope: String,
        #[prost(message, optional, tag = "3")]
        pub generated_at: Option<ProtoTimestamp>,
        #[prost(message, repeated, tag = "4")]
        pub components: Vec<BomComponent>,
        #[prost(message, repeated, tag = "5")]
        pub edges: Vec<BomEdge>,
        #[prost(string, optional, tag = "6")]
        pub signature: Option<String>,
    }
}
