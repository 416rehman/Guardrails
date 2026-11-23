// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{CodedError, DecideInput, DecisionReceipt, DiscoveryReport, SessionSummary};

use crate::state::{DaemonState, DaemonStatus};

pub fn build_router(state: DaemonState) -> Router {
    Router::new()
        .route("/local/v1/status", get(status))
        .route("/local/v1/inventory", get(inventory))
        .route("/local/v1/scan", post(scan))
        .route("/local/v1/decide", post(decide))
        .route("/local/v1/sessions", get(sessions))
        .route("/local/v1/receipts", get(receipts))
        .with_state(state)
}

async fn status(State(state): State<DaemonState>) -> Json<DaemonStatus> {
    Json(state.status().await)
}

async fn inventory(State(state): State<DaemonState>) -> Json<DiscoveryReport> {
    let guard = state.inner.read().await;
    Json(guard.discovery.clone())
}

async fn scan(State(state): State<DaemonState>) -> Json<DiscoveryReport> {
    Json(state.rescan().await)
}

async fn decide(
    State(state): State<DaemonState>,
    Json(input): Json<DecideInput>,
) -> Result<Json<DecisionReceipt>, (StatusCode, Json<CodedError>)> {
    if input.target.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CodedError::new(
                CODE_INVALID_INPUT,
                "Decision target cannot be empty.",
                "Provide a target path, command, or tool name.",
            )),
        ));
    }
    Ok(Json(state.decide_local(input).await))
}

async fn sessions(State(state): State<DaemonState>) -> Json<Vec<SessionSummary>> {
    Json(state.sessions().await)
}

async fn receipts(State(state): State<DaemonState>) -> Json<Vec<DecisionReceipt>> {
    let guard = state.inner.read().await;
    Json(guard.receipts.clone())
}
