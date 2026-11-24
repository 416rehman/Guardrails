// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::proto_conv::{
    browser_eval_to_proto, proto_to_action_class, proto_to_attempt, proto_to_browser_dlp,
    proto_to_control_point, proto_to_receipt, receipt_to_proto,
};
use grdr_model::{BatchEventsInput, BrowserEvaluateRequest, DecideInput};
use grdr_proto::api::verdict::{
    EvaluateBrowserRequest, EvaluateRequest, EvaluateResponse, IngestBatchRequest,
    IngestBatchResponse,
};
use grdr_proto::common::CollectionKind;

use crate::connect_error::{ApiError, CODE_API_BAD_REQUEST};
use crate::rpc::run_rpc;
use crate::store::AppState;

pub async fn evaluate(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        state,
        request,
        |state, req: EvaluateRequest| async move {
            let action_class = proto_to_action_class(req.action_class).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_ACTION_CLASS",
                    "Missing or unknown action_class.",
                    "Supply a valid ActionClass enum value.",
                )
            })?;
            let input = DecideInput {
                session_id: req.session_id,
                device_id: req.device_id,
                device_name: req.device_name,
                agent_name: req.agent_name,
                action_class,
                control_point: req.control_point.and_then(proto_to_control_point),
                target: req.target,
                summary: req.summary,
            };
            let receipt = state.evaluate_and_record(input).await?;
            state.bump_revision(CollectionKind::Sessions);
            state.bump_revision(CollectionKind::Approvals);
            state.bump_revision(CollectionKind::Findings);
            state.bump_revision(CollectionKind::Incidents);
            state.bump_revision(CollectionKind::Users);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                EvaluateResponse {
                    receipt: Some(receipt_to_proto(&receipt)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn evaluate_browser(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.verdict.v1alpha1.VerdictService/EvaluateBrowser",
        state,
        request,
        |state, req: EvaluateBrowserRequest| async move {
            let dlp_class = proto_to_browser_dlp(req.dlp_class).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_DLP_CLASS",
                    "Missing or unknown browser dlp_class.",
                    "Supply a valid BrowserDlpClass enum value.",
                )
            })?;
            let out = state
                .evaluate_browser(BrowserEvaluateRequest {
                    app_id: req.app_id,
                    domain: req.domain,
                    dlp_class,
                    file_extension: req.file_extension,
                    has_secret_match: req.has_secret_match,
                })
                .await?;
            state.bump_revision(CollectionKind::BrowserPolicies);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((browser_eval_to_proto(&out), None))
        },
    )
    .await
}

pub async fn ingest_batch(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.verdict.v1alpha1.VerdictService/IngestBatch",
        state,
        request,
        |state, req: IngestBatchRequest| async move {
            let mut attempts = Vec::with_capacity(req.attempts.len());
            for a in req.attempts {
                attempts.push(proto_to_attempt(a).map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_ATTEMPT",
                        msg,
                        "Ensure attempt timestamps are valid RFC 3339.",
                    )
                })?);
            }
            let mut receipts = Vec::with_capacity(req.receipts.len());
            for r in req.receipts {
                receipts.push(proto_to_receipt(r).map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_RECEIPT",
                        msg,
                        "Ensure receipt timestamps are valid RFC 3339.",
                    )
                })?);
            }
            let res = state
                .ingest_batch(BatchEventsInput {
                    device_id: req.device_id,
                    attempts,
                    receipts,
                })
                .await?;
            state.bump_revision(CollectionKind::Sessions);
            state.bump_revision(CollectionKind::Approvals);
            state.bump_revision(CollectionKind::Findings);
            state.bump_revision(CollectionKind::Incidents);
            state.bump_revision(CollectionKind::Users);
            Ok((
                IngestBatchResponse {
                    accepted: u64::try_from(res.accepted).unwrap_or(u64::MAX),
                    findings_created: u64::try_from(res.findings_created).unwrap_or(u64::MAX),
                },
                None,
            ))
        },
    )
    .await
}
