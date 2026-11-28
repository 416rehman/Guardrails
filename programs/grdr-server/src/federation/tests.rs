// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{SigningKeypair, sha256_digest};
use grdr_identity::jwt_keys::{TokenKeyRing, default_issuer_origin};
use grdr_identity::standards_adapters::{
    ID_JAG_TYP_V06, IdJagClaims, SecurityEventKind, SetSubjectIdentifier,
    build_security_event_token,
};
use grdr_identity::token_exchange::{DpopPayload, sign_dpop_proof};
use grdr_model::error::CODE_STORE_CORRUPT;
use grdr_model::{CreateDeploymentKeyRequest, IdentityMode};
use jiff::Timestamp;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::auth::{AuthPlane, ConfirmAssertion, PrincipalIdentity, ServerSecurityConfig};
use crate::federation::FederationState;
use crate::routes;
use crate::store::{AppState, StorageBackend};

fn test_security_config() -> ServerSecurityConfig {
    let mut sec = ServerSecurityConfig {
        api_token: Some("console-secret".into()),
        operator_token: Some("operator-secret".into()),
        ..Default::default()
    };
    sec.principal_tokens.insert(
        "ordinary-caller".into(),
        PrincipalIdentity {
            principal_id: "usr_bob".into(),
            tenant_id: "org-default".into(),
            plane: AuthPlane::Console,
            scopes: vec!["identity:read".into()],
            assurance: ConfirmAssertion::None,
        },
    );
    sec.principal_tokens.insert(
        "target-alice".into(),
        PrincipalIdentity {
            principal_id: "usr_alice".into(),
            tenant_id: "org-default".into(),
            plane: AuthPlane::Console,
            scopes: vec!["identity:write".into(), "identity:read".into()],
            assurance: ConfirmAssertion::None,
        },
    );
    sec.principal_tokens.insert(
        "acme-admin".into(),
        PrincipalIdentity {
            principal_id: "usr_acme".into(),
            tenant_id: "org-acme".into(),
            plane: AuthPlane::Console,
            scopes: vec!["identity:write".into(), "identity:read".into()],
            assurance: ConfirmAssertion::None,
        },
    );
    sec
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = if let Some(val) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&val).expect("serialize")))
            .expect("req")
    } else {
        builder.body(Body::empty()).expect("req")
    };
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("bytes");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn dpop_header(
    kp: &SigningKeypair,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    jti: &str,
) -> String {
    let ath = access_token.map(|tok| B64_URL.encode(sha256_digest(tok.as_bytes())));
    sign_dpop_proof(
        kp,
        &DpopPayload {
            jti: jti.into(),
            htm: method.into(),
            htu: url.into(),
            iat: Timestamp::now().as_second(),
            ath,
        },
    )
    .expect("dpop proof")
}

#[tokio::test]
async fn server_federation_oidc_device_flow_token_exchange_dpop_and_id_jag() {
    let state = AppState::init(StorageBackend::Memory, true).expect("init");
    let issuer = default_issuer_origin();
    let app = routes::build_router_with_security(state, None, test_security_config());
    let tok = Some("console-secret");

    let (st_disc, disc) = send_json(
        &app,
        "GET",
        "/.well-known/openid-configuration",
        None,
        &[],
        None,
    )
    .await;
    assert_eq!(st_disc, StatusCode::OK);
    assert_eq!(disc["issuer"], issuer);

    let (st_jwks, jwks) = send_json(&app, "GET", "/.well-known/jwks.json", None, &[], None).await;
    assert_eq!(st_jwks, StatusCode::OK);
    assert_eq!(jwks["keys"][0]["kty"], "OKP");

    let (st_res, res_doc) = send_json(
        &app,
        "GET",
        "/.well-known/oauth-protected-resource",
        None,
        &[],
        None,
    )
    .await;
    assert_eq!(st_res, StatusCode::OK);
    assert_eq!(res_doc["authorization_servers"][0], issuer);

    for bad_res_q in [
        "/.well-known/oauth-protected-resource?resource=http%3A%2F%2F127.0.0.1.attacker.test%2Fmcp",
        "/.well-known/oauth-protected-resource?resource=https%3A%2F%2Fuser%40evil.test%2Fmcp",
        "/.well-known/oauth-protected-resource?resource=https%3A%2F%2F169.254.169.254%2Flatest",
        "/.well-known/oauth-protected-resource?resource=https%3A%2F%2Fevil.test%2F..%2Fsecret",
    ] {
        let (st_bad_res, _) = send_json(&app, "GET", bad_res_q, None, &[], None).await;
        assert_eq!(
            st_bad_res,
            StatusCode::BAD_REQUEST,
            "SSRF resource {bad_res_q}"
        );
    }
    let (st_loopback_res, _) = send_json(
        &app,
        "GET",
        "/.well-known/oauth-protected-resource?resource=http%3A%2F%2F127.0.0.1%3A8080%2Fmcp",
        None,
        &[],
        None,
    )
    .await;
    assert_eq!(st_loopback_res, StatusCode::OK);

    let (st_cimd, cimd) = send_json(&app, "GET", "/clients/mcp-broker", None, &[], None).await;
    assert_eq!(st_cimd, StatusCode::OK);
    assert!(
        cimd["client_id"]
            .as_str()
            .expect("cid")
            .starts_with("https://")
    );

    let (st_bad_scope, _) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({
            "client_id": "cli_test_1",
            "scope": "broker:lease admin:root"
        })),
    )
    .await;
    assert_eq!(st_bad_scope, StatusCode::BAD_REQUEST);

    let (st_dev, dev) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({
            "client_id": "cli_test_1",
            "scope": "broker:lease mcp:invoke identity:read"
        })),
    )
    .await;
    assert_eq!(st_dev, StatusCode::OK);
    let device_code = dev["device_code"].as_str().expect("device_code").to_owned();
    let user_code = dev["user_code"].as_str().expect("user_code").to_owned();
    assert!(device_code.starts_with("dvc_"));

    let (st_unauth, _) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        None,
        &[],
        Some(serde_json::json!({
            "user_code": user_code,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test"
        })),
    )
    .await;
    assert_eq!(st_unauth, StatusCode::UNAUTHORIZED);

    let (st_read_only, _) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        Some("ordinary-caller"),
        &[],
        Some(serde_json::json!({
            "user_code": user_code,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test"
        })),
    )
    .await;
    assert_eq!(st_read_only, StatusCode::FORBIDDEN);

    let (st_authz, authz) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        tok,
        &[],
        Some(serde_json::json!({
            "user_code": user_code,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test",
            "approve": true
        })),
    )
    .await;
    assert_eq!(st_authz, StatusCode::OK);
    assert!(
        authz["org_pseudonym"]
            .as_str()
            .expect("pseud")
            .starts_with("prn_")
    );

    let dpop_kp = SigningKeypair::generate().expect("dpop kp");
    let wrong_kp = SigningKeypair::generate().expect("wrong kp");
    let token_url = format!("{issuer}/oauth2/token");

    let (st_cid_mismatch, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "wrong_client",
            "device_code": device_code
        })),
    )
    .await;
    assert_eq!(st_cid_mismatch, StatusCode::UNAUTHORIZED);

    let dpop1 = dpop_header(&dpop_kp, "POST", &token_url, None, "dpop_dev_1");
    let (st_tok1, tok1) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[("DPoP", &dpop1)],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_test_1",
            "device_code": device_code,
            "instance_agi_id": "agi_alice_1"
        })),
    )
    .await;
    assert_eq!(st_tok1, StatusCode::OK);
    assert_eq!(tok1["token_type"], "DPoP");
    let access_jwt = tok1["access_token"].as_str().expect("jwt").to_owned();

    let (st_replay_dc, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_test_1",
            "device_code": device_code
        })),
    )
    .await;
    assert_eq!(st_replay_dc, StatusCode::NOT_FOUND);

    let (st_reg_alice, reg_alice) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_alice_1",
            "org_id": "org-default",
            "sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_reg_alice, StatusCode::OK);
    assert_eq!(reg_alice["instance"]["lifecycle"], "active");

    let (st_no_dpop, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": access_jwt,
            "resource": issuer,
            "scope": "broker:lease"
        })),
    )
    .await;
    assert_eq!(st_no_dpop, StatusCode::UNAUTHORIZED);

    let dpop_wrong = dpop_header(
        &wrong_kp,
        "POST",
        &token_url,
        Some(&access_jwt),
        "dpop_bad_1",
    );
    let (st_wrong_dpop, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[("DPoP", &dpop_wrong)],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": access_jwt,
            "resource": issuer,
            "scope": "broker:lease"
        })),
    )
    .await;
    assert_eq!(st_wrong_dpop, StatusCode::UNAUTHORIZED);

    let dpop_no_ath = dpop_header(&dpop_kp, "POST", &token_url, None, "dpop_no_ath_1");
    let (st_no_ath, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[("DPoP", &dpop_no_ath)],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": access_jwt,
            "resource": issuer,
            "scope": "broker:lease"
        })),
    )
    .await;
    assert_eq!(st_no_ath, StatusCode::UNAUTHORIZED);

    let dpop_ex = dpop_header(&dpop_kp, "POST", &token_url, Some(&access_jwt), "dpop_ex_1");
    let (st_ex, ex) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[("DPoP", &dpop_ex)],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": access_jwt,
            "resource": issuer,
            "scope": "broker:lease"
        })),
    )
    .await;
    assert_eq!(st_ex, StatusCode::OK);
    assert_eq!(ex["scope"], "broker:lease");
    assert_eq!(ex["token_type"], "DPoP");

    let (st_txn_unauth, _) = send_json(
        &app,
        "POST",
        "/oauth2/transaction-token",
        None,
        &[],
        Some(serde_json::json!({
            "subject_token": access_jwt,
            "audience": "https://api.vendor.example/mcp",
            "purpose": "repo:read",
            "tctx": {},
            "rctx": {}
        })),
    )
    .await;
    assert_eq!(st_txn_unauth, StatusCode::UNAUTHORIZED);

    let txn_url = format!("{issuer}/oauth2/transaction-token");
    let dpop_txn = dpop_header(&dpop_kp, "POST", &txn_url, Some(&access_jwt), "dpop_txn_1");
    let (st_txn, txn) = send_json(
        &app,
        "POST",
        "/oauth2/transaction-token",
        tok,
        &[("DPoP", &dpop_txn)],
        Some(serde_json::json!({
            "subject_token": access_jwt,
            "audience": "https://api.vendor.example/mcp",
            "purpose": "repo:read",
            "tctx": {"action": "read"},
            "rctx": {"repo": "acme/web"}
        })),
    )
    .await;
    assert_eq!(st_txn, StatusCode::OK);
    assert_eq!(txn["token_type"], "txn_token");

    let idp_ring = TokenKeyRing::from_active(Arc::new(SigningKeypair::generate().expect("idp")));
    let now_sec = Timestamp::now().as_second();
    let jag_claims = IdJagClaims {
        iss: "https://idp.example.test".into(),
        sub: "usr_alice".into(),
        aud: issuer.clone(),
        resource: "https://mcp.vendor.example/api".into(),
        client_id: "cli_test_1".into(),
        jti: "jti_jag_1".into(),
        iat: now_sec,
        exp: now_sec + 300,
        scope: "mcp:invoke".into(),
        spiffe_id: Some("spiffe://org-default/agi/agi_alice_1".into()),
    };
    let jag_jwt = idp_ring
        .sign_jwt(ID_JAG_TYP_V06, &jag_claims)
        .expect("jag jwt");

    let (st_untrusted_jag, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jag_jwt,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_untrusted_jag, StatusCode::FORBIDDEN);

    let (st_anchor, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
        tok,
        &[],
        Some(serde_json::json!({
            "kind": "idp_jag",
            "jwk": idp_ring.active_jwk(),
            "issuer_url": "https://idp.example.test"
        })),
    )
    .await;
    assert_eq!(st_anchor, StatusCode::OK);

    let bad_aud_jag = idp_ring
        .sign_jwt(
            ID_JAG_TYP_V06,
            &IdJagClaims {
                aud: "https://evil.override.example".into(),
                jti: "jti_jag_bad_aud".into(),
                ..jag_claims.clone()
            },
        )
        .expect("bad aud");
    let (st_bad_aud, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": bad_aud_jag,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_bad_aud, StatusCode::FORBIDDEN);

    let (st_jag, jag_resp) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jag_jwt,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_jag, StatusCode::OK);
    assert!(jag_resp["access_token"].as_str().is_some());

    let (st_jag_replay, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jag_jwt,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_jag_replay, StatusCode::FORBIDDEN);

    let (st_disc_inst, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_disc_1",
            "org_id": "org-default"
        })),
    )
    .await;
    assert_eq!(st_disc_inst, StatusCode::OK);

    for bad_iss_url in [
        "https://169.254.169.254/idp",
        "https://metadata.google.internal/idp",
        "https://user@idp.example.test",
    ] {
        let (st_ssrf_anchor, _) = send_json(
            &app,
            "POST",
            "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
            tok,
            &[],
            Some(serde_json::json!({
                "kind": "idp_jag",
                "jwk": idp_ring.active_jwk(),
                "issuer_url": bad_iss_url
            })),
        )
        .await;
        assert_eq!(st_ssrf_anchor, StatusCode::BAD_REQUEST);
    }

    let (st_reg_acme_inst, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        Some("acme-admin"),
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_acme_1",
            "org_id": "org-acme",
            "sponsor_id": "usr_acme"
        })),
    )
    .await;
    assert_eq!(st_reg_acme_inst, StatusCode::OK);

    let acme_idp_ring =
        TokenKeyRing::from_active(Arc::new(SigningKeypair::generate().expect("acme idp")));
    let (st_acme_anchor, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
        Some("acme-admin"),
        &[],
        Some(serde_json::json!({
            "kind": "idp_jag",
            "jwk": acme_idp_ring.active_jwk(),
            "issuer_url": "https://idp.acme.test"
        })),
    )
    .await;
    assert_eq!(st_acme_anchor, StatusCode::OK);

    let cross_tenant_forgery_jag = idp_ring
        .sign_jwt(
            ID_JAG_TYP_V06,
            &IdJagClaims {
                jti: "jti_cross_forge_1".into(),
                spiffe_id: Some("spiffe://org-acme/agi/agi_acme_1".into()),
                ..jag_claims.clone()
            },
        )
        .expect("cross forgery");
    let (st_cross_forge, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": cross_tenant_forgery_jag,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_cross_forge, StatusCode::FORBIDDEN);

    for (jti, spiffe_uri) in [
        ("jti_unknown_dom_1", "spiffe://org-ghost/agi/agi_1"),
        ("jti_non_agi_1", "spiffe://org-default/wl/gh/repo"),
        ("jti_unreg_inst_1", "spiffe://org-default/agi/agi_missing"),
        ("jti_disc_inst_1", "spiffe://org-default/agi/agi_disc_1"),
    ] {
        let bad_jag = idp_ring
            .sign_jwt(
                ID_JAG_TYP_V06,
                &IdJagClaims {
                    jti: jti.into(),
                    spiffe_id: Some(spiffe_uri.into()),
                    ..jag_claims.clone()
                },
            )
            .expect("bad jag");
        let (st_bad_jag, _) = send_json(
            &app,
            "POST",
            "/oauth2/token",
            None,
            &[],
            Some(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": bad_jag,
                "resource": "https://mcp.vendor.example/api"
            })),
        )
        .await;
        assert_eq!(
            st_bad_jag,
            StatusCode::FORBIDDEN,
            "ID-JAG {spiffe_uri} must fail"
        );
    }

    let valid_acme_jag = acme_idp_ring
        .sign_jwt(
            ID_JAG_TYP_V06,
            &IdJagClaims {
                iss: "https://idp.acme.test".into(),
                sub: "usr_acme".into(),
                jti: "jti_acme_ok_1".into(),
                spiffe_id: Some("spiffe://org-acme/agi/agi_acme_1".into()),
                ..jag_claims
            },
        )
        .expect("acme jag");
    let (st_acme_jag_ok, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": valid_acme_jag,
            "resource": "https://mcp.vendor.example/api"
        })),
    )
    .await;
    assert_eq!(st_acme_jag_ok, StatusCode::OK);

    let (st_dev_short, dev_short) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({"client_id": "cli_short", "scope": "broker:lease"})),
    )
    .await;
    assert_eq!(st_dev_short, StatusCode::OK);
    let uc_short = dev_short["user_code"].as_str().expect("uc").to_owned();
    let dc_short = dev_short["device_code"].as_str().expect("dc").to_owned();
    let (st_authz_short, _) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        tok,
        &[],
        Some(serde_json::json!({
            "user_code": uc_short,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test",
            "approve": true
        })),
    )
    .await;
    assert_eq!(st_authz_short, StatusCode::OK);
    let (st_tok_disc_denied, _) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_short",
            "device_code": dc_short,
            "instance_agi_id": "agi_disc_1"
        })),
    )
    .await;
    assert_eq!(st_tok_disc_denied, StatusCode::FORBIDDEN);

    let (st_dev_disc2, dev_disc2) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({"client_id": "cli_short", "scope": "broker:lease"})),
    )
    .await;
    assert_eq!(st_dev_disc2, StatusCode::OK);
    let uc_disc2 = dev_disc2["user_code"]
        .as_str()
        .expect("uc disc2")
        .to_owned();
    let dc_disc2 = dev_disc2["device_code"]
        .as_str()
        .expect("dc disc2")
        .to_owned();
    let _ = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        tok,
        &[],
        Some(serde_json::json!({
            "user_code": uc_disc2,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test",
            "approve": true
        })),
    )
    .await;
    let (st_tok_short, tok_short) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_short",
            "device_code": dc_disc2,
            "instance_agi_id": "agi_disc_2"
        })),
    )
    .await;
    assert_eq!(st_tok_short, StatusCode::OK);
    let _ = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({"local_agi_id": "agi_disc_2", "org_id": "org-default"})),
    )
    .await;
    let disc_jwt = tok_short["access_token"].as_str().expect("disc jwt");
    let (st_txn_disc, _) = send_json(
        &app,
        "POST",
        "/oauth2/transaction-token",
        tok,
        &[],
        Some(serde_json::json!({
            "subject_token": disc_jwt,
            "audience": "https://api.vendor.example/mcp",
            "purpose": "repo:read",
            "tctx": {},
            "rctx": {}
        })),
    )
    .await;
    assert_eq!(st_txn_disc, StatusCode::FORBIDDEN);

    let (st_dev_cap, dev_cap) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({"client_id": "cli_cap", "scope": "broker:lease"})),
    )
    .await;
    assert_eq!(st_dev_cap, StatusCode::OK);
    let uc_cap = dev_cap["user_code"].as_str().expect("uc cap").to_owned();
    let dc_cap = dev_cap["device_code"].as_str().expect("dc cap").to_owned();
    let _ = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        tok,
        &[],
        Some(serde_json::json!({
            "user_code": uc_cap,
            "os_username": "alice_local",
            "idp_subject": "alice@acme.test",
            "approve": true
        })),
    )
    .await;
    let (st_tok_cap, tok_cap) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_cap",
            "device_code": dc_cap,
            "instance_agi_id": "agi_alice_1",
            "requested_ttl_secs": 60
        })),
    )
    .await;
    assert_eq!(st_tok_cap, StatusCode::OK);
    let cap_jwt = tok_cap["access_token"].as_str().expect("cap jwt");
    let (st_txn_capped, txn_capped) = send_json(
        &app,
        "POST",
        "/oauth2/transaction-token",
        tok,
        &[],
        Some(serde_json::json!({
            "subject_token": cap_jwt,
            "audience": "https://api.vendor.example/mcp",
            "purpose": "repo:read",
            "tctx": {},
            "rctx": {},
            "ttl_secs": 300
        })),
    )
    .await;
    assert_eq!(st_txn_capped, StatusCode::OK);
    assert!(txn_capped["expires_in"].as_i64().expect("exp") <= 60);

    let (st_az_deny_caller, _) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        Some("ordinary-caller"),
        &[],
        Some(serde_json::json!({
            "subject": {"type": "agent", "id": "agi_alice_1"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"}
        })),
    )
    .await;
    assert_eq!(st_az_deny_caller, StatusCode::FORBIDDEN);

    let (st_az_disc, az_disc) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        tok,
        &[],
        Some(serde_json::json!({
            "subject": {"type": "agent", "id": "agi_disc_1"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"}
        })),
    )
    .await;
    assert_eq!(st_az_disc, StatusCode::OK);
    assert_eq!(az_disc["decision"], false);

    let (st_az_ok, az_ok) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        tok,
        &[],
        Some(serde_json::json!({
            "subject": {"type": "agent", "id": "agi_alice_1"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"}
        })),
    )
    .await;
    assert_eq!(st_az_ok, StatusCode::OK);
    assert_eq!(az_ok["decision"], true);

    let (st_az_ctx, az_ctx) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        Some("ordinary-caller"),
        &[],
        Some(serde_json::json!({
            "subject": {"type": "user", "id": "usr_bob"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"},
            "context": {"agi_id": "agi_disc_1"}
        })),
    )
    .await;
    assert_eq!(st_az_ctx, StatusCode::OK);
    assert_eq!(az_ctx["decision"], false);

    let (st_az_non_str, az_non_str) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        Some("ordinary-caller"),
        &[],
        Some(serde_json::json!({
            "subject": {"type": "user", "id": "usr_bob"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"},
            "context": {"agi_id": 123}
        })),
    )
    .await;
    assert_eq!(st_az_non_str, StatusCode::OK);
    assert_eq!(az_non_str["decision"], false);

    let (st_az_bad_type, az_bad_type) = send_json(
        &app,
        "POST",
        "/access/v1/evaluation",
        tok,
        &[],
        Some(serde_json::json!({
            "subject": {"type": "service_account", "id": "svc_1"},
            "action": {"name": "invoke"},
            "resource": {"type": "mcp_tool", "id": "tool_fs"}
        })),
    )
    .await;
    assert_eq!(st_az_bad_type, StatusCode::OK);
    assert_eq!(az_bad_type["decision"], false);
}

#[tokio::test]
async fn server_scim_ssf_tenancy_lifecycle_and_receipts() {
    let state = AppState::init(StorageBackend::Memory, true).expect("init");
    let issuer = default_issuer_origin();
    let app = routes::build_router_with_security(state.clone(), None, test_security_config());
    let tok = Some("console-secret");

    let (st_unauth, _) = send_json(&app, "GET", "/scim/v2/Users", None, &[], None).await;
    assert_eq!(st_unauth, StatusCode::UNAUTHORIZED);

    let (st_u1, u1) = send_json(
        &app,
        "POST",
        "/scim/v2/Users",
        tok,
        &[],
        Some(serde_json::json!({
            "externalId": "usr_sponsor_1",
            "userName": "alice@acme.test",
            "displayName": "Alice"
        })),
    )
    .await;
    assert_eq!(st_u1, StatusCode::OK);
    assert_eq!(u1["id"], "usr_sponsor_1");

    let (st_dup_u, _) = send_json(
        &app,
        "POST",
        "/scim/v2/Users",
        tok,
        &[],
        Some(serde_json::json!({
            "externalId": "usr_sponsor_1",
            "userName": "alice-dup@acme.test"
        })),
    )
    .await;
    assert_eq!(st_dup_u, StatusCode::PRECONDITION_FAILED);

    let (st_cross_tenant_read, _) = send_json(
        &app,
        "GET",
        "/scim/v2/Users/usr_sponsor_1",
        Some("acme-admin"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_cross_tenant_read, StatusCode::NOT_FOUND);

    {
        state.inner.write().await.privacy.identity_mode = IdentityMode::Pseudonymous;
    }
    let (st_pseud_user, pseud_user) = send_json(
        &app,
        "GET",
        "/scim/v2/Users/usr_sponsor_1",
        Some("ordinary-caller"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_pseud_user, StatusCode::OK);
    assert!(
        pseud_user["userName"]
            .as_str()
            .expect("un")
            .starts_with("prn_")
    );
    {
        state.inner.write().await.privacy.identity_mode = IdentityMode::Named;
    }

    let (st_cross_reg, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_cross",
            "org_id": "org-acme",
            "sponsor_id": "usr_sponsor_1"
        })),
    )
    .await;
    assert_eq!(st_cross_reg, StatusCode::FORBIDDEN);

    let (st_inst, inst) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_worker_1",
            "org_id": "org-default",
            "sponsor_id": "usr_sponsor_1"
        })),
    )
    .await;
    assert_eq!(st_inst, StatusCode::OK);
    assert_eq!(inst["instance"]["lifecycle"], "active");

    let (st_agents_al2, agents_al2) = send_json(
        &app,
        "GET",
        "/scim/v2/Agents",
        Some("ordinary-caller"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_agents_al2, StatusCode::OK);
    assert_eq!(
        agents_al2["Resources"][0]["urn:ietf:params:scim:schemas:extension:agent:2.0:Agent"]["assurance_level"],
        "AL2"
    );

    let (st_dev_rev, dev_rev) = send_json(
        &app,
        "POST",
        "/oauth2/device_authorization",
        None,
        &[],
        Some(serde_json::json!({"client_id": "cli_rev_1", "scope": "broker:lease"})),
    )
    .await;
    assert_eq!(st_dev_rev, StatusCode::OK);
    let uc_rev = dev_rev["user_code"].as_str().expect("uc rev").to_owned();
    let dc_rev = dev_rev["device_code"].as_str().expect("dc rev").to_owned();
    let _ = send_json(
        &app,
        "POST",
        "/oauth2/device_authorize",
        tok,
        &[],
        Some(serde_json::json!({
            "user_code": uc_rev,
            "os_username": "alice_local",
            "idp_subject": "usr_sponsor_1",
            "approve": true
        })),
    )
    .await;
    let (st_tok_rev, tok_rev) = send_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        &[],
        Some(serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "cli_rev_1",
            "device_code": dc_rev,
            "instance_agi_id": "agi_worker_1"
        })),
    )
    .await;
    assert_eq!(st_tok_rev, StatusCode::OK);
    let revoked_jwt = tok_rev["access_token"]
        .as_str()
        .expect("rev jwt")
        .to_owned();

    let (st_rev_rpc, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RevokeLease",
        tok,
        &[],
        Some(serde_json::json!({"scope": "instance", "target_id": "agi_worker_1"})),
    )
    .await;
    assert_eq!(st_rev_rpc, StatusCode::OK);

    let (st_patch_404, _) = send_json(
        &app,
        "PATCH",
        "/scim/v2/Users/missing-user",
        tok,
        &[],
        Some(serde_json::json!({"active": false})),
    )
    .await;
    assert_eq!(st_patch_404, StatusCode::NOT_FOUND);

    let (st_del_404, _) = send_json(
        &app,
        "DELETE",
        "/scim/v2/Users/missing-user",
        tok,
        &[],
        None,
    )
    .await;
    assert_eq!(st_del_404, StatusCode::NOT_FOUND);

    let (st_still_revoked, _) = send_json(
        &app,
        "POST",
        "/oauth2/transaction-token",
        tok,
        &[],
        Some(serde_json::json!({
            "subject_token": revoked_jwt,
            "audience": "https://api.vendor.example/mcp",
            "purpose": "repo:read",
            "tctx": {},
            "rctx": {}
        })),
    )
    .await;
    assert_eq!(st_still_revoked, StatusCode::FORBIDDEN);

    let (st_deprov, deprov) = send_json(
        &app,
        "PATCH",
        "/scim/v2/Users/usr_sponsor_1",
        tok,
        &[],
        Some(serde_json::json!({"active": false})),
    )
    .await;
    assert_eq!(st_deprov, StatusCode::OK);
    assert_eq!(deprov["orphaned_instances"][0], "agi_worker_1");

    let (st_agents_al0, agents_al0) = send_json(
        &app,
        "GET",
        "/scim/v2/Agents",
        Some("ordinary-caller"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_agents_al0, StatusCode::OK);
    assert_eq!(
        agents_al0["Resources"][0]["urn:ietf:params:scim:schemas:extension:agent:2.0:Agent"]["assurance_level"],
        "AL0"
    );

    let (st_poll_ro, _) = send_json(
        &app,
        "POST",
        "/ssf/poll",
        Some("ordinary-caller"),
        &[],
        Some(serde_json::json!({"maxEvents": 5})),
    )
    .await;
    assert_eq!(st_poll_ro, StatusCode::FORBIDDEN);

    let (st_poll, poll) = send_json(
        &app,
        "POST",
        "/ssf/poll",
        tok,
        &[],
        Some(serde_json::json!({"maxEvents": 5, "returnImmediately": true})),
    )
    .await;
    assert_eq!(st_poll, StatusCode::OK);
    assert!(!poll["sets"].as_object().expect("sets").is_empty());

    let (st_sl, sl) = send_json(&app, "GET", "/oauth2/status-list", None, &[], None).await;
    assert_eq!(st_sl, StatusCode::OK);
    assert_eq!(sl["bits"], 1);

    let ssf_ring = TokenKeyRing::from_active(Arc::new(SigningKeypair::generate().expect("ssf")));
    let set_tok = build_security_event_token(
        "https://idp.example.test",
        &issuer,
        "set_in_1",
        SecurityEventKind::CaepSessionRevoked,
        &SetSubjectIdentifier {
            format: "iss_sub".into(),
            iss: Some("https://idp.example.test".into()),
            sub: "agi_worker_1".into(),
        },
        None,
        Timestamp::now(),
    );
    let signed_set = ssf_ring
        .sign_jwt("secevent+jwt", &set_tok)
        .expect("set jwt");

    let (st_raw_ssf, _) = send_json(
        &app,
        "POST",
        "/ssf/events",
        tok,
        &[],
        Some(serde_json::json!({"events": {}})),
    )
    .await;
    assert!(st_raw_ssf.is_client_error());

    let (st_untrusted_ssf, _) = send_json(
        &app,
        "POST",
        "/ssf/events",
        tok,
        &[],
        Some(serde_json::json!({"set": signed_set})),
    )
    .await;
    assert_eq!(st_untrusted_ssf, StatusCode::FORBIDDEN);

    let (st_reg_ssf, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
        tok,
        &[],
        Some(serde_json::json!({
            "kind": "ssf_transmitter",
            "jwk": ssf_ring.active_jwk(),
            "issuer_url": "https://idp.example.test"
        })),
    )
    .await;
    assert_eq!(st_reg_ssf, StatusCode::OK);

    let (st_ssf_ok, _) = send_json(
        &app,
        "POST",
        "/ssf/events",
        tok,
        &[],
        Some(serde_json::json!({"set": signed_set})),
    )
    .await;
    assert_eq!(st_ssf_ok, StatusCode::OK);

    let (st_ssf_replay, _) = send_json(
        &app,
        "POST",
        "/ssf/events",
        tok,
        &[],
        Some(serde_json::json!({"set": signed_set})),
    )
    .await;
    assert_eq!(st_ssf_replay, StatusCode::FORBIDDEN);

    let mut stale_set = set_tok;
    stale_set.jti = "set_stale_1".into();
    stale_set.iat = Timestamp::now().as_second() - 305;
    let stale_set_jwt = ssf_ring
        .sign_jwt("secevent+jwt", &stale_set)
        .expect("stale set");
    let (st_stale_ssf, _) = send_json(
        &app,
        "POST",
        "/ssf/events",
        tok,
        &[],
        Some(serde_json::json!({"set": stale_set_jwt})),
    )
    .await;
    assert_eq!(st_stale_ssf, StatusCode::FORBIDDEN);

    let (st_init, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/TransferSponsor",
        tok,
        &[],
        Some(serde_json::json!({
            "agi_id": "agi_worker_1",
            "action": "initiate",
            "target_sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_init, StatusCode::OK);

    let (st_accept_wrong_caller, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/TransferSponsor",
        tok,
        &[("x-grdr-confirm", "confirmed")],
        Some(serde_json::json!({
            "agi_id": "agi_worker_1",
            "action": "accept",
            "target_sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_accept_wrong_caller, StatusCode::FORBIDDEN);

    let (st_accept_unconfirmed, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/TransferSponsor",
        Some("target-alice"),
        &[],
        Some(serde_json::json!({
            "agi_id": "agi_worker_1",
            "action": "accept",
            "target_sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_accept_unconfirmed, StatusCode::FORBIDDEN);

    let (st_accept_ok, accepted) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/TransferSponsor",
        Some("target-alice"),
        &[("x-grdr-confirm", "confirmed")],
        Some(serde_json::json!({
            "agi_id": "agi_worker_1",
            "action": "accept",
            "target_sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_accept_ok, StatusCode::OK);
    assert_eq!(accepted["sponsor"]["sponsor_id"], "usr_alice");

    let (st_rcp, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RecordOutwardReceipt",
        tok,
        &[],
        Some(serde_json::json!({
            "agi_id": "agi_worker_1",
            "session_id": "ses_1",
            "repo": "416rehman/Guardrails",
            "commit_sha": "abc1234",
            "patch_id": "patch_rebase_99",
            "pr_number": 42,
            "signature": "sig_v1"
        })),
    )
    .await;
    assert_eq!(st_rcp, StatusCode::OK);

    let (st_lkp, lkp) = send_json(
        &app,
        "GET",
        "/grdr.api.identity.v1alpha1.IdentityService/LookupOutwardReceipts?patch_id=patch_rebase_99",
        Some("ordinary-caller"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_lkp, StatusCode::OK);
    assert_eq!(lkp.as_array().expect("rcp").len(), 1);

    let (st_ret, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RetireInstance",
        tok,
        &[],
        Some(serde_json::json!({"agi_id": "agi_worker_1"})),
    )
    .await;
    assert_eq!(st_ret, StatusCode::OK);

    let (st_seen, seen) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/ReportRetiredSeen",
        tok,
        &[],
        Some(serde_json::json!({"agi_id": "agi_worker_1", "session_id": "ses_ghost"})),
    )
    .await;
    assert_eq!(st_seen, StatusCode::OK);
    assert_eq!(seen["event_kind"], "identity.retired-seen");

    let (st_resight, resight) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
        tok,
        &[],
        Some(serde_json::json!({
            "local_agi_id": "agi_worker_1",
            "org_id": "org-default",
            "sponsor_id": "usr_alice"
        })),
    )
    .await;
    assert_eq!(st_resight, StatusCode::OK);
    assert_eq!(resight["instance"]["lifecycle"], "discovered");
}

#[tokio::test]
async fn server_enrolment_mdm_vdi_and_tampered_snapshot_fail_closed() {
    let dir = std::env::temp_dir().join(format!("grdr-fed-test-{}", Uuid::now_v7().simple()));
    fs::create_dir_all(&dir).expect("mkdir");
    let state = AppState::init(StorageBackend::Disk(dir.clone()), true).expect("init disk");
    let issuer = default_issuer_origin();
    let app = routes::build_router_with_security(state.clone(), None, test_security_config());
    let tok = Some("console-secret");

    let dev_kp = SigningKeypair::generate().expect("dev kp");
    let user_key = state
        .create_deployment_key(CreateDeploymentKeyRequest {
            label: "UserProfile".into(),
            wave: "w1".into(),
            install_profile: "user".into(),
            max_uses: 2,
            ttl_days: 7,
        })
        .await
        .expect("user key");

    let (st_user_admit, user_admit) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/AdmitDeploymentKey",
        tok,
        &[],
        Some(serde_json::json!({
            "deployment_key_id": user_key.key.id,
            "device_id": "dev_user_1",
            "hostname": "laptop-u1",
            "boot_id": "boot_u1",
            "public_key_b64": dev_kp.public_key_b64(),
            "approve_admission": true
        })),
    )
    .await;
    assert_eq!(st_user_admit, StatusCode::OK);
    assert_eq!(user_admit["device"]["profile"], "user");
    assert_eq!(user_admit["device"]["state"], "pending");
    assert_eq!(user_admit["device"]["essentials_floor_locked"], false);

    let (st_dup_dev, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/AdmitDeploymentKey",
        tok,
        &[],
        Some(serde_json::json!({
            "deployment_key_id": user_key.key.id,
            "device_id": "dev_user_1",
            "hostname": "laptop-dup",
            "boot_id": "boot_dup",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_dup_dev, StatusCode::PRECONDITION_FAILED);

    let prot_key = state
        .create_deployment_key(CreateDeploymentKeyRequest {
            label: "Protected-1".into(),
            wave: "w1".into(),
            install_profile: "protected".into(),
            max_uses: 1,
            ttl_days: 7,
        })
        .await
        .expect("prot key");
    let (st_admit1, admit1) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/AdmitDeploymentKey",
        tok,
        &[],
        Some(serde_json::json!({
            "deployment_key_id": prot_key.key.id,
            "device_id": "dev_m1",
            "hostname": "host-1",
            "boot_id": "boot_1",
            "public_key_b64": dev_kp.public_key_b64(),
            "approve_admission": true
        })),
    )
    .await;
    assert_eq!(st_admit1, StatusCode::OK);
    assert_eq!(admit1["device"]["state"], "admitted");
    assert_eq!(admit1["device"]["essentials_floor_locked"], true);

    let (st_admit2, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/AdmitDeploymentKey",
        tok,
        &[],
        Some(serde_json::json!({
            "deployment_key_id": prot_key.key.id,
            "device_id": "dev_m2",
            "hostname": "host-2",
            "boot_id": "boot_2",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_admit2, StatusCode::FORBIDDEN);

    let oidc_ring = TokenKeyRing::from_active(Arc::new(SigningKeypair::generate().expect("oidc")));
    let now_sec = Timestamp::now().as_second();
    let id_jwt = oidc_ring
        .sign_jwt(
            "JWT",
            &serde_json::json!({
                "iss": "https://token.actions.githubusercontent.com",
                "sub": "repo:org/app:ref:refs/heads/main",
                "aud": issuer,
                "jti": "oidc_jti_1",
                "iat": now_sec,
                "exp": now_sec + 300
            }),
        )
        .expect("id jwt");

    let (st_oidc_untrusted, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": id_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-default",
                "cluster_or_repo": "org/app",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_1",
            "hostname": "gha-runner",
            "boot_id": "boot_gha",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_untrusted, StatusCode::FORBIDDEN);

    let (st_reg_oidc, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
        tok,
        &[],
        Some(serde_json::json!({
            "kind": "workload_oidc",
            "jwk": oidc_ring.active_jwk()
        })),
    )
    .await;
    assert_eq!(st_reg_oidc, StatusCode::OK);

    let (st_oidc_ok, oidc_dev) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": id_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-default",
                "cluster_or_repo": "org/app",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_1",
            "hostname": "gha-runner",
            "boot_id": "boot_gha",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_ok, StatusCode::OK);
    assert!(
        oidc_dev["workload_spiffe_id"]
            .as_str()
            .expect("wl")
            .contains("/wl/gh-actions/")
    );

    let (st_oidc_replay, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": id_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-default",
                "cluster_or_repo": "org/app",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_2",
            "hostname": "gha-runner-2",
            "boot_id": "boot_gha_2",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_replay, StatusCode::FORBIDDEN);

    let oidc_cross_jwt = oidc_ring
        .sign_jwt(
            "JWT",
            &serde_json::json!({
                "iss": "https://token.actions.githubusercontent.com",
                "sub": "repo:org/app:ref:refs/heads/main",
                "aud": issuer,
                "jti": "oidc_jti_cross_1",
                "iat": now_sec,
                "exp": now_sec + 300
            }),
        )
        .expect("cross jwt");
    let (st_oidc_cross, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": oidc_cross_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-acme",
                "cluster_or_repo": "org/app",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_cross",
            "hostname": "gha-runner-cross",
            "boot_id": "boot_gha_cross",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_cross, StatusCode::FORBIDDEN);

    let oidc_oversized_jwt = oidc_ring
        .sign_jwt(
            "JWT",
            &serde_json::json!({
                "iss": "https://token.actions.githubusercontent.com",
                "sub": "repo:org/app:ref:refs/heads/main",
                "aud": issuer,
                "jti": "oidc_jti_ttl_1",
                "iat": now_sec,
                "exp": now_sec + 600
            }),
        )
        .expect("oversized jwt");
    let (st_oidc_ttl, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": oidc_oversized_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-default",
                "cluster_or_repo": "org/app",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_ttl",
            "hostname": "gha-runner-ttl",
            "boot_id": "boot_gha_ttl",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_ttl, StatusCode::FORBIDDEN);

    let oidc_spoof_jwt = oidc_ring
        .sign_jwt(
            "JWT",
            &serde_json::json!({
                "iss": "https://token.actions.githubusercontent.com",
                "sub": "repo:org/app:ref:refs/heads/main",
                "aud": issuer,
                "jti": "oidc_jti_spoof_1",
                "iat": now_sec,
                "exp": now_sec + 300
            }),
        )
        .expect("spoof jwt");
    let (st_oidc_spoof, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
        tok,
        &[],
        Some(serde_json::json!({
            "id_token_jwt": oidc_spoof_jwt,
            "claim": {
                "source": "git_hub_actions_oidc",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:org/app:ref:refs/heads/main",
                "trust_domain": "org-default",
                "cluster_or_repo": "evil/prod",
                "workload_ref": "main",
                "digest": null,
                "expires_at": Timestamp::from_second(now_sec + 300).expect("ts").to_string()
            },
            "device_id": "dev_gha_spoof",
            "hostname": "gha-runner-spoof",
            "boot_id": "boot_gha_spoof",
            "public_key_b64": dev_kp.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st_oidc_spoof, StatusCode::FORBIDDEN);

    let hw_ca_kp = SigningKeypair::generate().expect("hw ca");
    let hw_ring = TokenKeyRing::from_active(Arc::new(hw_ca_kp.clone()));
    let hw_payload = serde_json::json!({
        "device_id": "dev_hw_1",
        "boot_id": "boot_hw_1",
        "hardware_vendor": "tpm2",
        "device_pubkey_b64": dev_kp.public_key_b64(),
        "nonce": "nonce_hw_unique_1",
        "iat": now_sec,
        "exp": now_sec + 300
    })
    .to_string();
    let hw_sig = hw_ca_kp.sign_bytes("grdr.enrol.hardware.v1", hw_payload.as_bytes());

    let (st_hw_untrusted, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolAttestedHardware",
        tok,
        &[],
        Some(serde_json::json!({
            "device_id": "dev_hw_1",
            "hostname": "hw-box-1",
            "boot_id": "boot_hw_1",
            "hardware_vendor": "tpm2",
            "attestation_signature_b64": hw_sig,
            "attestation_payload": hw_payload
        })),
    )
    .await;
    assert_eq!(st_hw_untrusted, StatusCode::FORBIDDEN);

    let (st_reg_hw, _) = send_json(
        &app,
        "POST",
        "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
        tok,
        &[],
        Some(serde_json::json!({
            "kind": "hardware_ca",
            "hardware_vendor": "tpm2",
            "jwk": hw_ring.active_jwk()
        })),
    )
    .await;
    assert_eq!(st_reg_hw, StatusCode::OK);

    let (st_hw_ok, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolAttestedHardware",
        tok,
        &[],
        Some(serde_json::json!({
            "device_id": "dev_hw_1",
            "hostname": "hw-box-1",
            "boot_id": "boot_hw_1",
            "hardware_vendor": "tpm2",
            "attestation_signature_b64": hw_sig,
            "attestation_payload": hw_payload
        })),
    )
    .await;
    assert_eq!(st_hw_ok, StatusCode::OK);

    let hw_payload_replay = serde_json::json!({
        "device_id": "dev_hw_2",
        "boot_id": "boot_hw_2",
        "hardware_vendor": "tpm2",
        "device_pubkey_b64": dev_kp.public_key_b64(),
        "nonce": "nonce_hw_unique_1",
        "iat": now_sec,
        "exp": now_sec + 300
    })
    .to_string();
    let hw_sig_replay = hw_ca_kp.sign_bytes("grdr.enrol.hardware.v1", hw_payload_replay.as_bytes());
    let (st_hw_replay, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/EnrolAttestedHardware",
        tok,
        &[],
        Some(serde_json::json!({
            "device_id": "dev_hw_2",
            "hostname": "hw-box-2",
            "boot_id": "boot_hw_2",
            "hardware_vendor": "tpm2",
            "attestation_signature_b64": hw_sig_replay,
            "attestation_payload": hw_payload_replay
        })),
    )
    .await;
    assert_eq!(st_hw_replay, StatusCode::FORBIDDEN);

    let (st_xxe, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/ValidateMdmArtifact",
        tok,
        &[],
        Some(serde_json::json!({
            "vendor": "jamf",
            "payload": "<!DOCTYPE foo><plist><dict><key>PayloadType</key><string>x</string></dict></plist>"
        })),
    )
    .await;
    assert_eq!(st_xxe, StatusCode::BAD_REQUEST);

    let (st_empty_plist, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/ValidateMdmArtifact",
        tok,
        &[],
        Some(serde_json::json!({
            "vendor": "jamf",
            "payload": "<plist><dict><key>PayloadType</key><string>   </string></dict></plist>"
        })),
    )
    .await;
    assert_eq!(st_empty_plist, StatusCode::BAD_REQUEST);

    let (st_win11_vdi, _) = send_json(
        &app,
        "POST",
        "/grdr.api.connect.v1alpha1.ConnectService/CheckGoldenImagePrepare",
        tok,
        &[],
        Some(serde_json::json!({
            "os": "win11",
            "windows_topology": "multi_session_vdi",
            "residual_artifacts": []
        })),
    )
    .await;
    assert_eq!(st_win11_vdi, StatusCode::PRECONDITION_FAILED);

    drop(app);
    fs::write(dir.join("federation.json"), b"corrupt-ciphertext-tampered").expect("tamper");
    let reloaded = AppState::init(StorageBackend::Disk(dir.clone()), true).expect("reload");
    let fail_err = match FederationState::try_new(reloaded.clone()) {
        Ok(_) => panic!("tampered snapshot must fail try_new"),
        Err(err) => err,
    };
    assert_eq!(fail_err.code, CODE_STORE_CORRUPT);

    let broken_app = routes::build_router_with_security(reloaded, None, test_security_config());
    let (st_broken_sl, sl_body) =
        send_json(&broken_app, "GET", "/oauth2/status-list", None, &[], None).await;
    assert_eq!(st_broken_sl, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        sl_body["details"][0]["debug"]["metadata"]["code"],
        CODE_STORE_CORRUPT
    );

    let (st_broken_list, _) = send_json(
        &broken_app,
        "GET",
        "/grdr.api.identity.v1alpha1.IdentityService/ListInstances",
        Some("ordinary-caller"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_broken_list, StatusCode::INTERNAL_SERVER_ERROR);

    let _ = fs::remove_dir_all(&dir);
}
