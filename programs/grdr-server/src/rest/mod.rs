// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod authz;
pub mod collections;
pub mod collections_ops;
pub mod guard;
pub mod idempotency;
pub mod limits;
pub mod openapi;
pub mod openapi_spec;
pub mod policy_rest;
pub mod rate_limit;
pub mod resources;
pub mod response_rest;
pub mod webhook_handlers;
pub mod webhook_signing;
pub mod webhook_ssrf;
pub mod webhooks;

#[cfg(test)]
mod tests;

use axum::body::Body;
use axum::extract::{Extension, Path, Request};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value};

use crate::auth::{
    AuthContext, AuthLayerState, require_console_auth, require_dedicated_operator_auth,
};
use crate::store::AppState;

use super::gitops::gitops_router;
use idempotency::{
    IdempotencyCache, IdempotencyLookup, idempotency_error_response, replay_response,
};
use limits::rest_limits;
use rate_limit::{
    TenantRateLimiter, TrafficClass, attach_rate_limit_headers, rate_limited_response,
};

pub use openapi::BrandInfo;
pub use resources::ResourceCatalogStore;
pub use webhooks::WebhookStore;

pub fn public_v1_router() -> Router<AppState> {
    Router::new()
        .route("/v1/openapi.json", get(openapi::get_openapi_json))
        .route("/v1/health", get(collections::get_health))
}

pub fn v1_router(auth_state: AuthLayerState) -> Router<AppState> {
    let protected = Router::new()
        .route("/overview", get(collections::get_overview))
        .route("/guard", post(guard::post_guard))
        .route("/ingest", post(guard::post_ingest))
        .route("/devices", get(collections::list_devices))
        .route("/agents", get(collections::list_agents))
        .route("/mcp-servers", get(collections::list_mcp_servers))
        .route("/artifacts", get(collections::list_artifacts))
        .route("/sessions", get(collections::list_sessions))
        .route("/sessions/{id}", get(collections::get_session))
        .route("/findings", get(collections_ops::list_findings))
        .route(
            "/findings/{id}",
            axum::routing::patch(response_rest::update_finding),
        )
        .route("/incidents", get(collections_ops::list_incidents))
        .route("/approvals", get(collections_ops::list_approvals))
        .route(
            "/approvals/{action_path}",
            post(response_rest::decide_approval),
        )
        .route(
            "/kill-switch",
            get(response_rest::get_kill_switch).put(response_rest::put_kill_switch),
        )
        .route("/audit-events", get(collections_ops::list_audit_events))
        .route("/users", get(collections_ops::list_users))
        .route("/packs", get(policy_rest::list_packs))
        .route("/browser-policies", get(policy_rest::list_browser_policies))
        .route(
            "/browser-policies/{id}",
            axum::routing::put(policy_rest::update_browser_policy),
        )
        .route("/rules", post(policy_rest::create_rule))
        .route(
            "/rules/{id}",
            axum::routing::patch(policy_rest::update_rule)
                .delete(policy_rest::delete_rule)
                .post(policy_rest::rule_action),
        )
        .route("/integrations", get(response_rest::list_integrations))
        .route(
            "/deployment-keys",
            post(response_rest::create_deployment_key),
        )
        .route(
            "/deployment-keys/{id}",
            axum::routing::delete(response_rest::delete_deployment_key),
        )
        .route(
            "/operations/{id}",
            get(response_rest::get_operation).post(response_rest::operation_action),
        )
        .route(
            "/webhook-endpoints",
            get(webhook_handlers::list_endpoints).post(webhook_handlers::create_endpoint),
        )
        .route(
            "/webhook-endpoints/{id}",
            get(webhook_handlers::get_endpoint)
                .delete(webhook_handlers::delete_endpoint)
                .post(webhook_handlers::dispatch_endpoint_action),
        )
        .route("/change-feed", get(webhook_handlers::get_change_feed))
        .merge(gitops_router())
        .merge(managed_resource_routes())
        .layer(Extension(auth_state.clone()))
        .layer(middleware::from_fn(idempotency_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        .route_layer(middleware::from_fn_with_state(
            auth_state,
            require_console_auth,
        ));

    Router::new().nest("/v1", protected)
}

pub fn operator_v1_router(auth_state: AuthLayerState) -> Router<AppState> {
    let protected = Router::new()
        .merge(collection_crud("/operator/settings", "settings"))
        .layer(middleware::from_fn(idempotency_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        .route_layer(middleware::from_fn_with_state(
            auth_state,
            require_dedicated_operator_auth,
        ));

    Router::new().nest("/v1", protected)
}

fn managed_resource_routes() -> Router<AppState> {
    Router::new()
        .merge(collection_crud("/tenancy/groups", "groups"))
        .merge(collection_crud("/tenancy/role-bindings", "roleBindings"))
        .merge(collection_crud(
            "/tenancy/service-accounts",
            "serviceAccounts",
        ))
        .merge(collection_crud(
            "/tenancy/federated-identities",
            "federatedIdentities",
        ))
        .merge(collection_crud(
            "/tenancy/identity-providers",
            "identityProviders",
        ))
        .merge(collection_crud("/tenancy/roles", "roles"))
        .merge(collection_crud("/export-destinations", "destinations"))
        .merge(collection_crud("/provider/organisations", "organisations"))
        .merge(collection_crud(
            "/provider/organisation-sets",
            "organisationSets",
        ))
        .merge(collection_crud("/provider/delegations", "delegations"))
        .merge(collection_crud(
            "/provider/branding-profiles",
            "brandingProfiles",
        ))
}

fn collection_crud(base_path: &'static str, items_key: &'static str) -> Router<AppState> {
    let item_path = format!("{base_path}/{{id}}");
    Router::new()
        .route(
            base_path,
            get(move |ext, auth| {
                resources::list_collection_handler(ext, auth, base_path, items_key)
            })
            .post(move |ext, auth, Json(payload): Json<Map<String, Value>>| {
                resources::create_collection_handler(ext, auth, base_path, payload)
            }),
        )
        .route(
            &item_path,
            get(move |ext, auth, id: Path<String>| {
                resources::get_collection_handler(ext, auth, base_path, id)
            })
            .put(
                move |ext, auth, id: Path<String>, Json(payload): Json<Map<String, Value>>| {
                    resources::update_collection_handler(ext, auth, base_path, id, payload)
                },
            )
            .delete(move |ext, auth, id: Path<String>| {
                resources::delete_collection_handler(ext, auth, base_path, id)
            }),
        )
}

async fn rate_limit_middleware(
    Extension(limiter): Extension<TenantRateLimiter>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(auth) = request.extensions().get::<AuthContext>().cloned() else {
        return idempotency_error_response(
            "UNAUTHENTICATED",
            StatusCode::UNAUTHORIZED,
            "Authentication context required.",
        );
    };
    let path = request.uri().path();
    let class = classify_traffic(path, request.method());
    let window_secs = rest_limits().rate_limit_window_secs;
    let decision = limiter
        .check(&auth.tenant_id, &auth.principal_id, class)
        .await;
    if !decision.allowed {
        return rate_limited_response(&decision, window_secs);
    }
    let mut response = next.run(request).await;
    attach_rate_limit_headers(response.headers_mut(), &decision, window_secs);
    response
}

fn classify_traffic(path: &str, method: &Method) -> TrafficClass {
    let p = path.strip_prefix("/v1").unwrap_or(path);
    if p == "/ingest" {
        TrafficClass::Ingest
    } else if p == "/guard" || *method != Method::GET {
        TrafficClass::Critical
    } else if p == "/change-feed" || p == "/audit-events" || p == "/findings" {
        TrafficClass::Bulk
    } else {
        TrafficClass::Standard
    }
}

async fn idempotency_middleware(
    Extension(cache): Extension<IdempotencyCache>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if method != Method::POST
        && method != Method::PUT
        && method != Method::PATCH
        && method != Method::DELETE
    {
        return next.run(request).await;
    }

    let key_header = request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let requires_key = requires_idempotency_key(&method, &path);
    let Some(idem_key) = key_header else {
        if requires_key {
            return idempotency_error_response(
                "IDEMPOTENCY_KEY_MISSING",
                StatusCode::BAD_REQUEST,
                "Mutating REST requests require an Idempotency-Key header.",
            );
        }
        return next.run(request).await;
    };

    let Some(auth) = request.extensions().get::<AuthContext>().cloned() else {
        return idempotency_error_response(
            "UNAUTHENTICATED",
            StatusCode::UNAUTHORIZED,
            "Authentication context required.",
        );
    };
    let composite = IdempotencyCache::composite_key(
        &auth.tenant_id,
        &auth.principal_id,
        method.as_str(),
        &path,
        &idem_key,
    );

    let max_body = rest_limits().max_idempotent_body_bytes;
    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, max_body).await else {
        return idempotency_error_response(
            "BODY_TOO_LARGE",
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeded max size.",
        );
    };

    match cache.begin(composite.clone(), &bytes).await {
        IdempotencyLookup::InFlight => {
            return idempotency_error_response(
                "REQUEST_IN_FLIGHT",
                StatusCode::CONFLICT,
                "Another request with the same Idempotency-Key is currently in flight.",
            );
        }
        IdempotencyLookup::PayloadConflict => {
            return idempotency_error_response(
                "IDEMPOTENCY_KEY_REUSED",
                StatusCode::UNPROCESSABLE_ENTITY,
                "Idempotency-Key was reused with a different request payload.",
            );
        }
        IdempotencyLookup::Replay {
            status,
            content_type,
            body,
        } => {
            return replay_response(status, content_type, body);
        }
        IdempotencyLookup::Miss => {}
    }

    let rebuilt = Request::from_parts(parts, Body::from(bytes.clone()));
    let response = next.run(rebuilt).await;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let (resp_parts, resp_body) = response.into_parts();
    let Ok(resp_bytes) = axum::body::to_bytes(resp_body, max_body).await else {
        cache.abort(&composite).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if status.is_server_error() {
        cache.abort(&composite).await;
    } else {
        cache
            .finish(
                &composite,
                &bytes,
                status.as_u16(),
                content_type,
                resp_bytes.to_vec(),
            )
            .await;
    }
    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

fn requires_idempotency_key(method: &Method, path: &str) -> bool {
    let p = path.strip_prefix("/v1").unwrap_or(path);
    *method == Method::POST
        && p != "/guard"
        && p != "/ingest"
        && !p.ends_with(":check")
        && !p.ends_with(":simulate")
        && !p.ends_with(":replay")
        && !p.ends_with(":send-test")
}
