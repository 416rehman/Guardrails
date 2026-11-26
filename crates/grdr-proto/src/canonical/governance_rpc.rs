// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical wire codecs for `decide` and `provider`.

pub mod decide {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::{MessageRef, ProtoDuration, ProtoTimestamp};
    use crate::canonical::governance::decision::Verdict;
    use crate::canonical::telemetry_action::Action;
    use crate::proto_enum_codec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum PersonRoute {
        Unspecified = 0,
        ApprovePrompt = 1,
        ConsoleReview = 2,
        CliWhy = 3,
        NoException = 4,
    }
    proto_enum_codec!(PersonRoute, person_route_serde, [
        PersonRoute::Unspecified => "PERSON_ROUTE_UNSPECIFIED",
        PersonRoute::ApprovePrompt => "PERSON_ROUTE_APPROVE_PROMPT" | "approve_prompt",
        PersonRoute::ConsoleReview => "PERSON_ROUTE_CONSOLE_REVIEW" | "console_review",
        PersonRoute::CliWhy => "PERSON_ROUTE_CLI_WHY" | "cli_why",
        PersonRoute::NoException => "PERSON_ROUTE_NO_EXCEPTION" | "no_exception",
    ]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum AgentNext {
        Unspecified = 0,
        WaitForGrant = 1,
        AskUser = 2,
        UseRewritten = 3,
        AbortAction = 4,
    }
    proto_enum_codec!(AgentNext, agent_next_serde, [
        AgentNext::Unspecified => "AGENT_NEXT_UNSPECIFIED",
        AgentNext::WaitForGrant => "AGENT_NEXT_WAIT_FOR_GRANT" | "wait_for_grant",
        AgentNext::AskUser => "AGENT_NEXT_ASK_USER" | "ask_user",
        AgentNext::UseRewritten => "AGENT_NEXT_USE_REWRITTEN" | "use_rewritten",
        AgentNext::AbortAction => "AGENT_NEXT_ABORT_ACTION" | "abort_action",
    ]);

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct BlockNotice {
        #[prost(string, tag = "1")]
        pub reason_code: String,
        #[prost(message, optional, tag = "2")]
        pub headline: Option<MessageRef>,
        #[prost(message, optional, tag = "3")]
        pub detail: Option<MessageRef>,
        #[prost(int32, tag = "4")]
        #[serde(with = "person_route_serde")]
        pub person_route: i32,
        #[prost(int32, tag = "5")]
        #[serde(with = "agent_next_serde")]
        pub agent_next: i32,
        #[prost(string, tag = "6")]
        pub docs_anchor: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DecideRequest {
        #[prost(string, tag = "1")]
        pub request_id: String,
        #[prost(string, tag = "2")]
        pub session_id: String,
        #[prost(string, optional, tag = "3")]
        pub tool_call_id: Option<String>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums::control_point_serde")]
        pub control_point: i32,
        #[prost(message, optional, tag = "5")]
        pub action: Option<Action>,
        #[prost(message, optional, tag = "6")]
        pub deadline: Option<ProtoDuration>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DecideAck {
        #[prost(string, tag = "1")]
        pub decision_id: String,
        #[prost(string, tag = "2")]
        pub daemon_boot_id: String,
        #[prost(message, optional, tag = "3")]
        pub received_at: Option<ProtoTimestamp>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct DecideResponse {
        #[prost(string, tag = "1")]
        pub decision_id: String,
        #[prost(message, optional, tag = "2")]
        pub ack: Option<DecideAck>,
        #[prost(message, optional, tag = "3")]
        pub verdict: Option<Verdict>,
        #[prost(int32, tag = "4")]
        #[serde(with = "crate::common::enums::verdict_serde")]
        pub degraded_verdict: i32,
        #[prost(message, optional, tag = "5")]
        pub block_notice: Option<BlockNotice>,
        #[prost(message, optional, tag = "6")]
        pub rewritten_action: Option<Action>,
        #[prost(string, tag = "7")]
        pub receipt_digest: String,
    }

    pub use crate::canonical::embed_local::decide_defs::*;
}

pub mod provider {
    use serde::{Deserialize, Serialize};

    use crate::canonical::common_types::ProtoDuration;
    use crate::canonical::telemetry_action::Action;

    pub use crate::canonical::embed_local::provider_defs::*;

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EvaluateVerdictRequest {
        #[prost(string, tag = "1")]
        pub request_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::action_class_serde")]
        pub action_class: i32,
        #[prost(message, optional, tag = "3")]
        pub action: Option<Action>,
        #[prost(message, optional, tag = "4")]
        pub deadline: Option<ProtoDuration>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", default)]
    pub struct EvaluateVerdictResponse {
        #[prost(string, tag = "1")]
        pub request_id: String,
        #[prost(int32, tag = "2")]
        #[serde(with = "crate::common::enums::verdict_serde")]
        pub verdict: i32,
        #[prost(string, tag = "3")]
        pub reason_code: String,
        #[prost(string, tag = "4")]
        pub reason: String,
        #[prost(message, optional, tag = "5")]
        pub rewritten_action: Option<Action>,
    }
}
