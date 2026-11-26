// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended canonical message definitions re-exported into `embed`, `local`, `decide`, and `provider`.

pub mod embed_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::fleet_ops::embed::{Diagnostic, HostProfile, Output, Tick};
    use crate::canonical::telemetry::event::Event;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct Input {
        #[prost(oneof = "input::Kind", tags = "1, 2")]
        #[serde(flatten)]
        pub kind: Option<input::Kind>,
    }

    pub mod input {
        use super::*;

        #[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub enum Kind {
            #[prost(message, tag = "1")]
            Event(Box<Event>),
            #[prost(message, tag = "2")]
            Tick(Tick),
        }
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LoadReport {
        #[prost(string, tag = "1")]
        pub bundle_digest: String,
        #[prost(message, repeated, tag = "2")]
        pub not_evaluable: Vec<load_report::NotEvaluable>,
    }

    pub mod load_report {
        use super::*;

        #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase", default)]
        pub struct NotEvaluable {
            #[prost(string, tag = "1")]
            pub rule_id: String,
            #[prost(string, tag = "2")]
            pub reason_code: String,
        }
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EngineState {
        #[prost(uint32, tag = "1")]
        pub format_version: u32,
        #[prost(string, tag = "2")]
        pub bundle_digest: String,
        #[prost(uint64, tag = "3")]
        pub step_seq: u64,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ActuatorRequest {
        #[prost(string, tag = "1")]
        pub request_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::kill_action_serde")]
        pub action: i32,
        #[prost(string, tag = "3")]
        pub target_id: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ActuatorResult {
        #[prost(string, tag = "1")]
        pub request_id: String,
        #[prost(bool, tag = "2")]
        pub succeeded: bool,
        #[prost(message, optional, tag = "3")]
        pub diagnostic: Option<Diagnostic>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LoadBundleRequest {
        #[prost(bytes = "vec", tag = "1")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub bundle: Vec<u8>,
        #[prost(message, optional, tag = "2")]
        pub host_profile: Option<HostProfile>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LoadBundleResponse {
        #[prost(message, optional, tag = "1")]
        pub report: Option<LoadReport>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct StepRequest {
        #[prost(message, optional, tag = "1")]
        pub input: Option<Input>,
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub entropy: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct StepResponse {
        #[prost(message, optional, tag = "1")]
        pub output: Option<Output>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetEngineHealthRequest {}

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetEngineHealthResponse {
        #[prost(message, optional, tag = "1")]
        pub state: Option<EngineState>,
        #[prost(bool, tag = "2")]
        pub healthy: bool,
    }
}

pub mod local_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{MessageRef, ProtoTimestamp};
    use crate::canonical::fleet_ops::local::{RelayDisposition, relay_disposition_serde};

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetStatusRequest {}

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ExplainRequest {
        #[prost(string, tag = "1")]
        pub reference: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ExplainResponse {
        #[prost(string, tag = "1")]
        pub receipt_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::verdict_serde")]
        pub verdict: i32,
        #[prost(message, optional, tag = "3")]
        pub explanation: Option<MessageRef>,
        #[prost(string, optional, tag = "4")]
        pub rule_id: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ProposeRequest {
        #[prost(string, tag = "1")]
        pub proposal_kind: String,
        #[prost(string, tag = "2")]
        pub target_id: String,
        #[prost(string, tag = "3")]
        pub desired_value: String,
        #[prost(string, tag = "4")]
        pub rationale: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ProposeResponse {
        #[prost(string, tag = "1")]
        pub proposal_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::approval_grade_serde")]
        pub required_grade: i32,
        #[prost(bool, tag = "3")]
        pub requires_step_up: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LocalQueryRequest {
        #[prost(string, tag = "1")]
        pub entity: String,
        #[prost(uint32, tag = "2")]
        pub limit: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct LocalQueryResponse {
        #[prost(string, repeated, tag = "1")]
        pub rows_json: Vec<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct SubscribeRequest {
        #[prost(string, repeated, tag = "1")]
        pub topics: Vec<String>,
        #[prost(uint32, tag = "2")]
        pub credit: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct SubscribeResponse {
        #[prost(string, tag = "1")]
        pub topic: String,
        #[prost(message, optional, tag = "2")]
        pub message: Option<MessageRef>,
        #[prost(uint64, tag = "3")]
        pub seq: u64,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct RequestLeaseRequest {
        #[prost(string, tag = "1")]
        pub helper: String,
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub protocol_frame: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub attestation: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct RequestLeaseResponse {
        #[prost(string, tag = "1")]
        pub lease_id: String,
        #[prost(message, optional, tag = "2")]
        pub expires_at: Option<ProtoTimestamp>,
        #[prost(bytes = "vec", tag = "3")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub response_frame: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct OpenRelayRequest {
        #[prost(string, tag = "1")]
        pub mcp_id: String,
        #[prost(string, tag = "2")]
        pub launch_digest: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct OpenRelayResponse {
        #[prost(string, tag = "1")]
        pub relay_id: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct SendFrameRequest {
        #[prost(string, tag = "1")]
        pub relay_id: String,
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde")]
        pub payload: Vec<u8>,
        #[prost(bool, tag = "3")]
        pub end_of_frame: bool,
    }

    // grdr:allow-s4 prost enum wire tags require i32 fields for RelayDisposition
    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct SendFrameResponse {
        #[prost(enumeration = "RelayDisposition", tag = "1")]
        #[serde(with = "relay_disposition_serde")]
        pub disposition: i32,
        #[prost(bytes = "vec", optional, tag = "2")]
        #[serde(with = "crate::serde_proto::bytes_b64_serde::opt")]
        pub payload: Option<Vec<u8>>,
    }
}

pub mod decide_defs {
    use serde::{Deserialize, Serialize};

    use crate::canonical::telemetry_action::Action;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ControlPointCapability {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::control_point_serde")]
        pub control_point: i32,
        #[prost(int32, repeated, tag = "2")]
        #[serde(with = "crate::common::enums::action_class_serde::vec")]
        pub enforceable_classes: Vec<i32>,
        #[prost(int32, repeated, tag = "3")]
        #[serde(with = "crate::common::enums::action_class_serde::vec")]
        pub observable_classes: Vec<i32>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums::on_failure_serde")]
        pub on_failure: i32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HelloRequest {
        #[prost(string, tag = "1")]
        pub component: String,
        #[prost(message, optional, tag = "2")]
        pub capability: Option<ControlPointCapability>,
        #[prost(string, optional, tag = "3")]
        pub session_id: Option<String>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct HelloResponse {
        #[prost(string, tag = "1")]
        pub daemon_boot_id: String,
        #[prost(string, tag = "2")]
        pub interest_digest: String,
        #[prost(int32, repeated, tag = "3")]
        #[serde(with = "crate::common::enums::action_class_serde::vec")]
        pub active_classes: Vec<i32>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ReportRequest {
        #[prost(int32, tag = "1")]
        #[serde(with = "crate::common::enums::control_point_serde")]
        pub control_point: i32,
        #[prost(string, tag = "2")]
        pub session_id: String,
        #[prost(message, optional, tag = "3")]
        pub action: Option<Action>,
        #[prost(string, optional, tag = "4")]
        pub decision_id: Option<String>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct ReportResponse {
        #[prost(bool, tag = "1")]
        pub accepted: bool,
        #[prost(uint64, tag = "2")]
        pub seq: u64,
    }
}

pub mod provider_defs {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetCapabilitiesRequest {}

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct GetCapabilitiesResponse {
        #[prost(string, tag = "1")]
        pub provider_id: String,
        #[prost(int32, repeated, tag = "2")]
        #[serde(with = "crate::common::enums::action_class_serde::vec")]
        pub action_classes: Vec<i32>,
        #[prost(int32, tag = "3")]
        #[serde(with = "crate::canonical::common_types::capture_level_serde")]
        pub max_capture_level: i32,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums::on_failure_serde")]
        pub on_failure: i32,
    }
}
