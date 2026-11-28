// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use grdr_model::proto_conv::{
    proto_to_action_class, proto_to_attempt, proto_to_control_point, proto_to_receipt,
    verdict_to_proto,
};
use grdr_model::{ActionClass, BatchEventsInput, ControlPoint, DecideInput};
use grdr_proto::api::verdict::{EvaluateRequest, IngestBatchRequest};
use grdr_proto::common::CollectionKind;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::AuthContext;
use crate::store::AppState;

use super::super::gitops::api_error_json_response;
use super::authz::{RestPolicy, authorize_rest};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestGuardRequest {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[serde(alias = "action_class")]
    pub action_class: Value,
    #[serde(default, alias = "control_point")]
    pub control_point: Option<Value>,
    pub target: String,
    #[serde(default)]
    pub summary: Option<String>,
}

pub async fn post_guard(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(raw): Json<Value>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("verdict:evaluate")) {
        return api_error_json_response(&err);
    }
    if let Ok(proto_req) = serde_json::from_value::<EvaluateRequest>(raw.clone())
        && let Some(action_class) = proto_to_action_class(proto_req.action_class)
    {
        return run_guard(
            &state,
            DecideInput {
                session_id: proto_req.session_id,
                device_id: proto_req.device_id,
                device_name: proto_req.device_name,
                agent_name: proto_req.agent_name,
                action_class,
                control_point: proto_req
                    .control_point
                    .and_then(proto_to_control_point)
                    .or(Some(ControlPoint::Gateway)),
                target: proto_req.target,
                summary: proto_req.summary,
            },
        )
        .await;
    }

    let req: RestGuardRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": "invalid_argument",
                    "reason": "INVALID_GUARD_REQUEST",
                    "message": format!("Invalid /v1/guard request: {err}"),
                })),
            )
                .into_response();
        }
    };
    let Some(action_class) = parse_action_class(&req.action_class) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "invalid_argument",
                "reason": "INVALID_ACTION_CLASS",
                "message": "Provide valid action_class string (e.g. exec, file.read, net.request).",
            })),
        )
            .into_response();
    };
    let control_point = req
        .control_point
        .as_ref()
        .and_then(parse_control_point)
        .or(Some(ControlPoint::Gateway));

    run_guard(
        &state,
        DecideInput {
            session_id: req.session_id,
            device_id: req.device_id,
            device_name: req.device_name,
            agent_name: req.agent_name,
            action_class,
            control_point,
            target: req.target,
            summary: req.summary,
        },
    )
    .await
}

pub async fn post_ingest(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<IngestBatchRequest>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("ingest:write")) {
        return api_error_json_response(&err);
    }
    let mut attempts = Vec::with_capacity(req.attempts.len());
    for a in req.attempts {
        match proto_to_attempt(a) {
            Ok(parsed) => attempts.push(parsed),
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "code": "invalid_argument",
                        "reason": "INVALID_ATTEMPT",
                        "message": msg,
                    })),
                )
                    .into_response();
            }
        }
    }
    let mut receipts = Vec::with_capacity(req.receipts.len());
    for r in req.receipts {
        match proto_to_receipt(r) {
            Ok(parsed) => receipts.push(parsed),
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "code": "invalid_argument",
                        "reason": "INVALID_RECEIPT",
                        "message": msg,
                    })),
                )
                    .into_response();
            }
        }
    }
    match state
        .ingest_batch(BatchEventsInput {
            device_id: req.device_id,
            attempts,
            receipts,
        })
        .await
    {
        Ok(res) => {
            state.bump_revision(CollectionKind::Sessions);
            state.bump_revision(CollectionKind::Approvals);
            state.bump_revision(CollectionKind::Findings);
            state.bump_revision(CollectionKind::Incidents);
            state.bump_revision(CollectionKind::Users);
            (
                StatusCode::OK,
                Json(json!({
                    "accepted": res.accepted,
                    "findingsCreated": res.findings_created,
                })),
            )
                .into_response()
        }
        Err(err) => api_error_json_response(&err.into()),
    }
}

async fn run_guard(state: &AppState, input: DecideInput) -> Response {
    match state.evaluate_and_record(input).await {
        Ok(receipt) => {
            let verdict_proto = verdict_to_proto(receipt.verdict);
            let verdict_str = match receipt.verdict {
                grdr_model::Verdict::Allow => "allow",
                grdr_model::Verdict::Modify => "modify",
                grdr_model::Verdict::StepUp | grdr_model::Verdict::Defer => "ask",
                grdr_model::Verdict::Deny => "block",
            };
            (
                StatusCode::OK,
                Json(json!({
                    "receipt": {
                        "id": receipt.receipt_id,
                        "receiptId": receipt.receipt_id,
                        "attemptId": receipt.attempt_id,
                        "sessionId": receipt.session_id,
                        "agentName": receipt.agent_name,
                        "verdict": verdict_str,
                        "verdictProto": format!("{verdict_proto:?}"),
                        "ruleId": receipt.rule_id,
                        "reason": receipt.reason,
                        "timestamp": receipt.decided_at.to_string(),
                    }
                })),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "code": "invalid_argument",
                "reason": err.code,
                "message": err.message,
            })),
        )
            .into_response(),
    }
}

fn parse_action_class(val: &Value) -> Option<ActionClass> {
    if let Ok(ac) = serde_json::from_value::<ActionClass>(val.clone()) {
        return Some(ac);
    }
    let s = val.as_str()?.trim().to_ascii_lowercase();
    match s.as_str() {
        "exec" | "action_class_exec" => Some(ActionClass::Exec),
        "file.read" | "file_read" | "action_class_file_read" => Some(ActionClass::FileRead),
        "file.write" | "file_write" | "action_class_file_write" => Some(ActionClass::FileWrite),
        "file.delete" | "file_delete" | "action_class_file_delete" => Some(ActionClass::FileDelete),
        "net.connect" | "net_connect" | "action_class_net_connect" => Some(ActionClass::NetConnect),
        "net.request" | "net_request" | "action_class_net_request" => Some(ActionClass::NetRequest),
        "llm.request" | "llm_request" | "action_class_llm_request" => Some(ActionClass::LlmRequest),
        "mcp.connect" | "mcp_connect" | "action_class_mcp_connect" => Some(ActionClass::McpConnect),
        "mcp.call" | "mcp_call" | "action_class_mcp_call" => Some(ActionClass::McpCall),
        "cred.use" | "cred_use" | "action_class_cred_use" => Some(ActionClass::CredUse),
        "agent.spawn" | "agent_spawn" | "action_class_agent_spawn" => Some(ActionClass::AgentSpawn),
        "config.change" | "config_change" | "action_class_config_change" => {
            Some(ActionClass::ConfigChange)
        }
        "elevate" | "action_class_elevate" => Some(ActionClass::Elevate),
        "ui.act" | "ui_act" | "action_class_ui_act" => Some(ActionClass::UiAct),
        "data.flow" | "data_flow" | "action_class_data_flow" => Some(ActionClass::DataFlow),
        _ => None,
    }
}

fn parse_control_point(val: &Value) -> Option<ControlPoint> {
    if let Ok(cp) = serde_json::from_value::<ControlPoint>(val.clone()) {
        return Some(cp);
    }
    let s = val.as_str()?.trim().to_ascii_lowercase();
    match s.as_str() {
        "hook" | "control_point_hook" => Some(ControlPoint::Hook),
        "mcp-broker" | "mcp_broker" | "control_point_mcp_broker" => Some(ControlPoint::McpBroker),
        "proxy" | "control_point_proxy" => Some(ControlPoint::Proxy),
        "sandbox" | "control_point_sandbox" => Some(ControlPoint::Sandbox),
        "sensor" | "control_point_sensor" => Some(ControlPoint::Sensor),
        "browser" | "control_point_browser" => Some(ControlPoint::Browser),
        "gateway" | "control_point_gateway" => Some(ControlPoint::Gateway),
        _ => None,
    }
}
