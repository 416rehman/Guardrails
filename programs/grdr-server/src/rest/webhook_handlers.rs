// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::AuthContext;

use super::super::gitops::api_error_json_response;
use super::authz::{AssuranceRule, RestPolicy, authorize_rest};
use super::webhook_ssrf::deliver_webhook_ssrf_safe;
use super::webhooks::{
    ChangeFeedQuery, CreateWebhookEndpointRequest, SendTestWebhookRequest, WebhookStore,
};

pub async fn list_endpoints(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("webhooks:read")) {
        return api_error_json_response(&err);
    }
    let endpoints = webhooks.list_endpoints(&auth.tenant_id).await;
    (StatusCode::OK, Json(json!({ "endpoints": endpoints }))).into_response()
}

pub async fn create_endpoint(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateWebhookEndpointRequest>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("webhooks:write", AssuranceRule::None),
    ) {
        return api_error_json_response(&err);
    }
    match webhooks.create_endpoint(&auth.tenant_id, req).await {
        Ok((endpoint, secret)) => {
            webhooks
                .append_change_event(
                    &auth.tenant_id,
                    "webhook.endpoint.created",
                    json!({ "endpointId": endpoint.id }),
                )
                .await;
            (
                StatusCode::OK,
                Json(json!({ "endpoint": endpoint, "secret": secret })),
            )
                .into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn get_endpoint(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("webhooks:read")) {
        return api_error_json_response(&err);
    }
    match webhooks.get_endpoint(&auth.tenant_id, &id).await {
        Ok(ep) => (StatusCode::OK, Json(json!({ "endpoint": ep }))).into_response(),
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn delete_endpoint(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = authorize_rest(
        &auth,
        RestPolicy::human_write("webhooks:write", AssuranceRule::Confirmed),
    ) {
        return api_error_json_response(&err);
    }
    match webhooks.delete_endpoint(&auth.tenant_id, &id).await {
        Ok(()) => {
            webhooks
                .append_change_event(
                    &auth.tenant_id,
                    "webhook.endpoint.deleted",
                    json!({ "endpointId": id }),
                )
                .await;
            (StatusCode::OK, Json(json!({ "deleted": true, "id": id }))).into_response()
        }
        Err(err) => api_error_json_response(&err),
    }
}

pub async fn dispatch_endpoint_action(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
    Path(action_path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some((id, action)) = action_path.split_once(':') else {
        return (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response();
    };
    match action {
        "rotate-key" => {
            if let Err(err) = authorize_rest(
                &auth,
                RestPolicy::human_write("webhooks:write", AssuranceRule::Confirmed),
            ) {
                return api_error_json_response(&err);
            }
            match webhooks.rotate_key(&auth.tenant_id, id).await {
                Ok((ep, secret)) => {
                    webhooks
                        .append_change_event(
                            &auth.tenant_id,
                            "webhook.endpoint.key_rotated",
                            json!({ "endpointId": ep.id }),
                        )
                        .await;
                    (
                        StatusCode::OK,
                        Json(json!({ "endpoint": ep, "secret": secret })),
                    )
                        .into_response()
                }
                Err(err) => api_error_json_response(&err),
            }
        }
        "send-test" => {
            if let Err(err) = authorize_rest(
                &auth,
                RestPolicy::human_write("webhooks:write", AssuranceRule::None),
            ) {
                return api_error_json_response(&err);
            }
            let req: SendTestWebhookRequest = serde_json::from_slice(&body).unwrap_or_default();
            let (url, signed) = match webhooks
                .prepare_signed_test_delivery(&auth.tenant_id, id, req)
                .await
            {
                Ok(v) => v,
                Err(err) => return api_error_json_response(&err),
            };
            let delivery = deliver_webhook_ssrf_safe(&url, &signed).await;
            let (delivered, status_opt, err_str) = match &delivery {
                Ok(code) => ((200..300).contains(code), Some(*code), None),
                Err(_) => (false, None, Some("delivery failed")),
            };
            let next_state = webhooks
                .record_delivery_status(
                    &auth.tenant_id,
                    id,
                    &signed.webhook_id,
                    status_opt,
                    err_str,
                )
                .await;
            (
                StatusCode::OK,
                Json(json!({
                    "delivered": delivered,
                    "httpStatus": status_opt,
                    "endpointState": next_state,
                    "webhookId": signed.webhook_id,
                    "webhookTimestamp": signed.webhook_timestamp,
                    "webhookSignature": signed.webhook_signature,
                })),
            )
                .into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({ "code": "not_found" }))).into_response(),
    }
}

pub async fn get_change_feed(
    Extension(webhooks): Extension<WebhookStore>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ChangeFeedQuery>,
) -> Response {
    if let Err(err) = authorize_rest(&auth, RestPolicy::read("webhooks:read")) {
        return api_error_json_response(&err);
    }
    let after = query
        .cursor
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let (events, next_cursor) = webhooks
        .read_change_feed(&auth.tenant_id, after, query.limit.unwrap_or(50))
        .await;
    (
        StatusCode::OK,
        Json(json!({
            "events": events,
            "nextCursor": next_cursor,
        })),
    )
        .into_response()
}
