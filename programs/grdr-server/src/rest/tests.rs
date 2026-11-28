// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_crypto::{hmac_sha256, verify_bytes};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::auth::{AuthPlane, ConfirmAssertion, PrincipalIdentity, ServerSecurityConfig};
use crate::routes;
use crate::store::{AppState, StorageBackend};

use super::idempotency::{IdempotencyCache, IdempotencyLookup};
use super::webhook_ssrf::validate_webhook_url;
use super::webhooks::{
    CreateWebhookEndpointRequest, SendTestWebhookRequest, WebhookSigningAlg, WebhookStore,
};

fn server_app() -> axum::Router {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    routes::build_console_router_with_security(
        state,
        None,
        ServerSecurityConfig {
            api_token: Some("rest-tok".into()),
            operator_token: Some("op-tok".into()),
            step_up_token: Some("step-up".into()),
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn openapi_etag_conditional_get_guard_and_idempotency() {
    let app = server_app();

    // Unauthenticated OpenAPI 3.1 document with cache-control and ETag 304 support
    let resp = app
        .clone()
        .oneshot(
            Request::get("/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::CACHE_CONTROL).is_some());
    let etag = resp
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let spec: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    assert!(spec["paths"]["/guard"].is_object());
    assert!(spec["paths"]["/policy-changes"].is_object());
    assert!(spec["paths"]["/webhook-endpoints"].is_object());

    let resp_304 = app
        .clone()
        .oneshot(
            Request::get("/v1/openapi.json")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_304.status(), StatusCode::NOT_MODIFIED);

    // RateLimit headers + POST /v1/guard E7.4 decision evaluation
    let guard_resp = app
        .clone()
        .oneshot(
            Request::post("/v1/guard")
                .header(header::AUTHORIZATION, "Bearer rest-tok")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "agent_name": "claude-code",
                        "action_class": "file.write",
                        "control_point": "gateway",
                        "target": ".claude/settings.json",
                        "summary": "Modify hooks"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(guard_resp.status(), StatusCode::OK);
    assert!(guard_resp.headers().get("ratelimit-policy").is_some());
    assert!(guard_resp.headers().get("ratelimit").is_some());
    let guard_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(guard_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(guard_json["receipt"]["verdict"], "block");

    // Missing Idempotency-Key fails on /v1/rules
    let missing = app
        .clone()
        .oneshot(
            Request::post("/v1/rules")
                .header(header::AUTHORIZATION, "Bearer rest-tok")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b"{}".as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    // Same key + same payload replays; different payload -> 422 IDEMPOTENCY_KEY_REUSED
    let payload_a = serde_json::to_vec(&json!({ "name": "eng-sec" })).unwrap();
    let payload_b = serde_json::to_vec(&json!({ "name": "other-team" })).unwrap();
    let r1 = app
        .clone()
        .oneshot(
            Request::post("/v1/tenancy/groups")
                .header(header::AUTHORIZATION, "Bearer rest-tok")
                .header("x-grdr-confirm", "confirmed")
                .header("idempotency-key", "idem-grp-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload_a.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    let r2 = app
        .clone()
        .oneshot(
            Request::post("/v1/tenancy/groups")
                .header(header::AUTHORIZATION, "Bearer rest-tok")
                .header("x-grdr-confirm", "confirmed")
                .header("idempotency-key", "idem-grp-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload_a))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(r2.headers().get("idempotent-replay").unwrap(), "true");

    let r_conflict = app
        .clone()
        .oneshot(
            Request::post("/v1/tenancy/groups")
                .header(header::AUTHORIZATION, "Bearer rest-tok")
                .header("x-grdr-confirm", "confirmed")
                .header("idempotency-key", "idem-grp-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload_b))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_conflict.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn webhooks_block_ssrf_sign_v1_v1a_rotate_keys_and_handle_410_gone() {
    for bad in [
        "http://127.0.0.1/hook",
        "http://169.254.169.254/latest/meta-data",
        "https://10.0.0.5/hook",
        "https://[::1]/hook",
        "https://[::ffff:169.254.169.254]/hook",
        "http://0xa9fea9fe/hook",
        "http://0177.0.0.1/hook",
        "http://127.1/hook",
        "https://[fe80::1%25eth0]/hook",
        "https://[64:ff9b::10.0.0.1]/hook",
        "https://[2002:7f00:1::]/hook",
        "https://[2001::1]/hook",
        "https://[fec0::1]/hook",
        "https://[100::1]/hook",
        "https://[::127.0.0.1]/hook",
        "https://localhost./hook",
        "https://metadata.google.internal./hook",
        "https://user:pass@hooks.example.com/hook",
        "https://hooks.example.com/a#frag",
        "https://hooks.example.com/a\r\nX-Inject: 1",
        "https://hooks.example.com/\\bad",
        "https://localhost/hook",
        "https://metadata.google.internal/hook",
        "ftp://hooks.example.com/hook",
    ] {
        assert!(
            validate_webhook_url(bad).is_err(),
            "expected SSRF rejection for {bad}"
        );
    }
    assert!(validate_webhook_url("https://hooks.example.com/events").is_ok());

    let store = WebhookStore::default();
    let (ep_ed, secret_ed) = store
        .create_endpoint(
            "org-1",
            CreateWebhookEndpointRequest {
                url: "https://hooks.example.com/ed25519".into(),
                topics: vec!["finding.opened".into()],
                signing_algorithm: WebhookSigningAlg::Ed25519,
            },
        )
        .await
        .unwrap();
    assert!(secret_ed.is_none());
    assert!(ep_ed.public_key_b64.is_some());

    let (_, hdrs) = store
        .prepare_signed_test_delivery("org-1", &ep_ed.id, SendTestWebhookRequest::default())
        .await
        .unwrap();
    assert!(hdrs.webhook_signature.starts_with("v1a,"));

    // Rotate key produces two space-separated v1a signatures during transition window.
    store.rotate_key("org-1", &ep_ed.id).await.unwrap();
    let (_, hdrs_rot) = store
        .prepare_signed_test_delivery("org-1", &ep_ed.id, SendTestWebhookRequest::default())
        .await
        .unwrap();
    assert_eq!(hdrs_rot.webhook_signature.split_whitespace().count(), 2);

    // HTTP 410 Gone disables endpoint permanently.
    let next_state = store
        .record_delivery_status("org-1", &ep_ed.id, &hdrs_rot.webhook_id, Some(410), None)
        .await
        .unwrap();
    assert_eq!(
        next_state,
        super::webhooks::WebhookEndpointState::DisabledGone
    );
    assert!(
        store
            .prepare_signed_test_delivery("org-1", &ep_ed.id, SendTestWebhookRequest::default())
            .await
            .is_err()
    );

    // HMAC-SHA256 v1 signature matches Standard Webhooks HMAC format
    let (ep_hmac, whsec) = store
        .create_endpoint(
            "org-1",
            CreateWebhookEndpointRequest {
                url: "https://hooks.example.com/hmac".into(),
                topics: vec!["finding.opened".into()],
                signing_algorithm: WebhookSigningAlg::HmacSha256,
            },
        )
        .await
        .unwrap();
    let raw_secret = B64
        .decode(whsec.unwrap().strip_prefix("whsec_").unwrap())
        .unwrap();
    let (_, hmac_hdrs) = store
        .prepare_signed_test_delivery("org-1", &ep_hmac.id, SendTestWebhookRequest::default())
        .await
        .unwrap();
    let mut signed =
        format!("{}.{}.", hmac_hdrs.webhook_id, hmac_hdrs.webhook_timestamp).into_bytes();
    signed.extend_from_slice(&hmac_hdrs.body);
    let expected = format!("v1,{}", B64.encode(hmac_sha256(&raw_secret, &signed)));
    assert_eq!(hmac_hdrs.webhook_signature, expected);

    // Cross-tenant isolation: org-2 cannot read, rotate, or delete org-1 endpoints.
    assert!(store.get_endpoint("org-2", &ep_hmac.id).await.is_err());
    assert!(store.rotate_key("org-2", &ep_hmac.id).await.is_err());
    assert!(store.delete_endpoint("org-2", &ep_hmac.id).await.is_err());
    let _ = verify_bytes;
}

#[tokio::test]
async fn rest_authz_operator_isolation_new_endpoints_redaction_and_non_json_idempotency() {
    let mut principal_tokens = BTreeMap::new();
    principal_tokens.insert(
        "human-admin".into(),
        PrincipalIdentity {
            principal_id: "alice".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::StepUpVerified,
        },
    );
    principal_tokens.insert(
        "narrow-reader".into(),
        PrincipalIdentity {
            principal_id: "bob".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["overview:read".into()],
            assurance: ConfirmAssertion::ConfirmedIntent,
        },
    );
    principal_tokens.insert(
        "agent-tok".into(),
        PrincipalIdentity {
            principal_id: "agent:triage".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::ConfirmedIntent,
        },
    );
    let security = ServerSecurityConfig {
        api_token: Some("rest-tok".into()),
        operator_token: Some("op-tok".into()),
        step_up_token: Some("step-up".into()),
        principal_tokens,
        ..Default::default()
    };

    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let console_app =
        routes::build_console_router_with_security(state.clone(), None, security.clone());
    let operator_app = routes::build_operator_router_with_security(state, None, security);

    // D-70 isolation: /v1/operator/settings is absent from Console and isolated on Operator plane.
    let console_op = console_app
        .clone()
        .oneshot(
            Request::get("/v1/operator/settings")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(console_op.status(), StatusCode::NOT_FOUND);

    let op_with_console_tok = operator_app
        .clone()
        .oneshot(
            Request::get("/v1/operator/settings")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_with_console_tok.status(), StatusCode::UNAUTHORIZED);

    let op_ok = operator_app
        .clone()
        .oneshot(
            Request::post("/v1/operator/settings")
                .header(header::AUTHORIZATION, "Bearer op-tok")
                .header("x-grdr-confirm", "confirmed")
                .header("idempotency-key", "idem-op-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "name": "maintenance", "value": "on" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_ok.status(), StatusCode::OK);

    // Narrow scope & AgentSession lineage blocked across sensitive REST endpoints.
    for (tok, path, body) in [
        (
            "narrow-reader",
            "/v1/deployment-keys",
            json!({ "name": "k1" }),
        ),
        (
            "narrow-reader",
            "/v1/provider/organisations",
            json!({ "name": "org-x" }),
        ),
        ("agent-tok", "/v1/deployment-keys", json!({ "name": "k1" })),
        (
            "agent-tok",
            "/v1/webhook-endpoints",
            json!({ "url": "https://hooks.example.com/e" }),
        ),
        ("agent-tok", "/v1/tenancy/groups", json!({ "name": "g1" })),
    ] {
        let resp = console_app
            .clone()
            .oneshot(
                Request::post(path)
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header("x-grdr-confirm", "confirmed")
                    .header("idempotency-key", format!("idem-{tok}-{path}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for {tok} on {path}"
        );
    }

    // Resource catalog redacts secret fields.
    let cred_resp = console_app
        .clone()
        .oneshot(
            Request::post("/v1/tenancy/identity-providers")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .header("x-grdr-confirm", "confirmed")
                .header("idempotency-key", "idem-idp-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "okta",
                        "clientSecret": "super-secret-value",
                        "nested": { "api_token": "tok-123" }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cred_resp.status(), StatusCode::OK);
    let cred_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(cred_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cred_json["clientSecret"], "[REDACTED]");
    assert_eq!(cred_json["nested"]["api_token"], "[REDACTED]");

    // New REST endpoints: /v1/ingest, /v1/browser-policies, PUT /v1/kill-switch, and quoted ETags.
    let bp_list = console_app
        .clone()
        .oneshot(
            Request::get("/v1/browser-policies")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bp_list.status(), StatusCode::OK);

    let ingest_resp = console_app
        .clone()
        .oneshot(
            Request::post("/v1/ingest")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "deviceId": "dev-1",
                        "attempts": [],
                        "receipts": []
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingest_resp.status(), StatusCode::OK);

    let packs_resp = console_app
        .clone()
        .oneshot(
            Request::get("/v1/packs")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let packs_etag = packs_resp
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(packs_etag.starts_with('"') && packs_etag.ends_with('"'));
    let packs_304 = console_app
        .clone()
        .oneshot(
            Request::get("/v1/packs")
                .header(header::AUTHORIZATION, "Bearer human-admin")
                .header(header::IF_NONE_MATCH, packs_etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(packs_304.status(), StatusCode::NOT_MODIFIED);

    // IdempotencyCache preserves exact raw bytes & content-type for non-JSON responses.
    let cache = IdempotencyCache::default();
    let key = IdempotencyCache::composite_key("org-1", "alice", "POST", "/v1/export", "k-raw");
    assert!(matches!(
        cache.begin(key.clone(), b"{}").await,
        IdempotencyLookup::Miss
    ));
    cache
        .finish(
            &key,
            b"{}",
            200,
            Some("text/plain".into()),
            b"line1\nline2".to_vec(),
        )
        .await;
    match cache.begin(key, b"{}").await {
        IdempotencyLookup::Replay {
            content_type, body, ..
        } => {
            assert_eq!(content_type.as_deref(), Some("text/plain"));
            assert_eq!(body, b"line1\nline2");
        }
        other => panic!("expected replay, got {other:?}"),
    }
}
