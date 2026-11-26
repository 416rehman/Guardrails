// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use jiff::Timestamp;
use serde_json::Value;
use tokio::net::TcpListener;

use grdr_model::SessionLabel;

use crate::{
    AgentLifecycle, AwsStsIssuer, BrokerPolicy, BrokerRequest, Ceiling, ContainmentStatus,
    CredentialBinding, CredentialBroker, CredentialClass, CredentialMode, DpapiSecretStore,
    GcpStsIssuer, GitHubAppIssuer, Hs256JwtSigner, IdentityError, LeaseState, OAuth2Rfc8693Issuer,
    OpenBaoSecretStore, SecretStore, SpiffeId, format_aws_credential_process,
    format_gcp_external_account,
};

#[derive(Default)]
struct MockHttpState {
    kv: Mutex<BTreeMap<String, String>>,
    aws_bodies: Mutex<Vec<String>>,
    gh_mint_headers: Mutex<Vec<String>>,
    gh_revoked_tokens: Mutex<Vec<String>>,
    gcp_bodies: Mutex<Vec<Value>>,
    oauth_forms: Mutex<Vec<String>>,
    oauth_revokes: Mutex<Vec<String>>,
}

async fn start_mock_server(state: Arc<MockHttpState>) -> String {
    let app = Router::new()
        .route("/v1/transit/encrypt/{key}", post(mock_transit_encrypt))
        .route("/v1/transit/decrypt/{key}", post(mock_transit_decrypt))
        .route("/v1/secret/data/{key}", post(mock_kv_write))
        .route("/v1/secret/data/{key}", get(mock_kv_read))
        .route("/v1/secret/metadata/{key}", delete(mock_kv_delete))
        .route("/sts", post(mock_aws_sts))
        .route("/app/installations/{id}/access_tokens", post(mock_gh_issue))
        .route("/installation/token", delete(mock_gh_revoke))
        .route("/v1/token", post(mock_gcp_sts))
        .route("/oauth2/token", post(mock_oauth_exchange))
        .route("/oauth2/revoke", post(mock_oauth_revoke))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn mock_transit_encrypt(Json(body): Json<Value>) -> Json<Value> {
    let pt = body.get("plaintext").and_then(|v| v.as_str()).unwrap_or("");
    Json(serde_json::json!({ "data": { "ciphertext": format!("vault:v1:{pt}") } }))
}

async fn mock_transit_decrypt(Json(body): Json<Value>) -> Result<Json<Value>, StatusCode> {
    let ct = body
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pt = ct
        .strip_prefix("vault:v1:")
        .ok_or(StatusCode::BAD_REQUEST)?;
    Ok(Json(serde_json::json!({ "data": { "plaintext": pt } })))
}

async fn mock_kv_write(
    State(st): State<Arc<MockHttpState>>,
    AxumPath(key): AxumPath<String>,
    Json(body): Json<Value>,
) -> StatusCode {
    let val = body
        .pointer("/data/value_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    st.kv.lock().expect("kv").insert(key, val);
    StatusCode::OK
}

async fn mock_kv_read(
    State(st): State<Arc<MockHttpState>>,
    AxumPath(key): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    let val = st
        .kv
        .lock()
        .expect("kv")
        .get(&key)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        serde_json::json!({ "data": { "data": { "value_b64": val } } }),
    ))
}

async fn mock_kv_delete(
    State(st): State<Arc<MockHttpState>>,
    AxumPath(key): AxumPath<String>,
) -> StatusCode {
    st.kv.lock().expect("kv").remove(&key);
    StatusCode::NO_CONTENT
}

async fn mock_aws_sts(State(st): State<Arc<MockHttpState>>, body: String) -> String {
    st.aws_bodies.lock().expect("aws").push(body);
    let exp = Timestamp::from_second(Timestamp::now().as_second().saturating_add(900))
        .expect("ts")
        .to_string();
    format!(
        "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIATEST987654</AccessKeyId><SecretAccessKey>mock-sts-secret-val</SecretAccessKey><SessionToken>mock-sts-session-tok</SessionToken><Expiration>{exp}</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
    )
}

async fn mock_gh_issue(
    State(st): State<Arc<MockHttpState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    st.gh_mint_headers.lock().expect("gh").push(auth);
    let inst_tok = format!("ghs_mock_{}", 1001);
    let exp = Timestamp::from_second(Timestamp::now().as_second().saturating_add(3_600))
        .expect("ts")
        .to_string();
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "token": inst_tok, "expires_at": exp })),
    )
}

async fn mock_gh_revoke(State(st): State<Arc<MockHttpState>>, headers: HeaderMap) -> StatusCode {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    st.gh_revoked_tokens.lock().expect("gh_rev").push(auth);
    StatusCode::NO_CONTENT
}

async fn mock_gcp_sts(
    State(st): State<Arc<MockHttpState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.gcp_bodies.lock().expect("gcp").push(body);
    Json(serde_json::json!({ "access_token": "ya29.mock_gcp_tok", "expires_in": 300 }))
}

async fn mock_oauth_exchange(State(st): State<Arc<MockHttpState>>, body: String) -> Json<Value> {
    st.oauth_forms.lock().expect("oauth").push(body);
    Json(serde_json::json!({ "access_token": "at_rfc8693_mock", "expires_in": 600 }))
}

async fn mock_oauth_revoke(State(st): State<Arc<MockHttpState>>, body: String) -> StatusCode {
    st.oauth_revokes.lock().expect("oauth_rev").push(body);
    StatusCode::OK
}

fn release_request(
    class: CredentialClass,
    action: &str,
    resource: &str,
    ttl: i64,
) -> BrokerRequest {
    let mut classes = BTreeSet::new();
    classes.insert(class);
    let mut accounts = BTreeSet::new();
    accounts.insert("acct-1".into());
    let mut actions = BTreeSet::new();
    actions.insert(action.into());

    BrokerRequest {
        session_id: "ses_live_1".into(),
        instance_spiffe_id: SpiffeId::agent_instance("org1", "agi_live").expect("spiffe"),
        device_id: "dev_1".into(),
        caller_program: "grdr-cred".into(),
        requested_class: class,
        requested_action: action.into(),
        requested_resource: resource.into(),
        requested_mode: CredentialMode::Release,
        requested_ttl_secs: ttl,
        session_remaining_secs: 3600,
        attribution_grade: 3,
        has_session_container: true,
        containment: ContainmentStatus::Contained,
        lifecycle: AgentLifecycle::Active,
        ceiling: Some(Ceiling {
            allowed_classes: classes,
            allowed_accounts: accounts,
            allowed_actions: actions,
            allowed_resource_prefixes: vec![resource.to_string()],
            max_ttl_secs: 900,
            max_depth: 4,
        }),
        act_chain_depth: 2,
        dpop_jkt: None,
    }
}

#[tokio::test]
async fn openbao_secret_store_and_all_four_issuers_work_against_http_servers() {
    let st = Arc::new(MockHttpState::default());
    let base = start_mock_server(Arc::clone(&st)).await;
    let now = Timestamp::now();

    assert!(
        OpenBaoSecretStore::new("http://vault.example.com", "secret", None, None, "t", true)
            .is_err()
    );
    let bao = OpenBaoSecretStore::new(
        &base,
        "secret",
        Some("transit".into()),
        Some("grdr-key".into()),
        "bao-test-tok",
        true,
    )
    .expect("openbao client");
    bao.store_secret("cred-1", b"super-secret-bytes")
        .await
        .expect("store");
    let loaded = bao
        .load_secret("cred-1")
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded.as_slice(), b"super-secret-bytes");
    bao.delete_secret("cred-1").await.expect("delete");
    assert!(bao.load_secret("cred-1").await.expect("reload").is_none());

    let mut broker = CredentialBroker::new(BrokerPolicy::default());
    let aws_issuer = AwsStsIssuer::new(&format!("{base}/sts"), Some("grdr-src-1".into()), true)
        .expect("aws issuer");
    let aws_binding = CredentialBinding {
        credential_id: "crd_aws".into(),
        class: CredentialClass::Cloud,
        account_id: "acct-1".into(),
        allowed_programs: vec!["grdr-cred".into()],
        allowed_hosts: vec!["sts.amazonaws.com".into()],
        upstream_revocable: false,
        upstream_min_ttl_secs: 900,
        phantom_prefix: "AKIA".into(),
    };
    let short_req = release_request(
        CredentialClass::Cloud,
        "sts:AssumeRole",
        "arn:aws:iam::123:role/readonly",
        300,
    );
    assert!(matches!(
        broker
            .request_release_with_issuer(
                &aws_binding,
                &short_req,
                &aws_issuer,
                Some("oidc-jwt"),
                now
            )
            .await,
        Err(IdentityError::ReleaseUnsupportedByUpstream)
    ));
    let mut ok_aws_req = short_req;
    ok_aws_req.requested_ttl_secs = 900;
    let aws_tok = broker
        .request_release_with_issuer(
            &aws_binding,
            &ok_aws_req,
            &aws_issuer,
            Some("oidc-jwt"),
            now,
        )
        .await
        .expect("aws release");
    assert_eq!(
        aws_tok.session_label,
        Some(SessionLabel::CredentialAccessed)
    );
    let aws_proc_json = format_aws_credential_process(&aws_tok).expect("credential_process");
    assert!(aws_proc_json.contains("ASIATEST987654"));
    let captured_aws = st.aws_bodies.lock().expect("aws").join("\n");
    assert!(captured_aws.contains("SourceIdentity=grdr-src-1"));
    assert!(captured_aws.contains("Policy="));

    let mut perms = BTreeMap::new();
    perms.insert("contents".into(), "read".into());
    let gh_issuer = GitHubAppIssuer::new(
        &base,
        "12345",
        "67890",
        vec!["grdr-repo".into()],
        perms,
        Arc::new(Hs256JwtSigner::new(b"test-app-hmac-key".to_vec())),
        true,
    )
    .expect("gh issuer");
    let gh_binding = CredentialBinding {
        credential_id: "crd_gh".into(),
        class: CredentialClass::Forge,
        account_id: "acct-1".into(),
        allowed_programs: vec!["grdr-cred".into()],
        allowed_hosts: vec!["api.github.com".into()],
        upstream_revocable: true,
        upstream_min_ttl_secs: 60,
        phantom_prefix: "ghs_".into(),
    };
    let gh_req = release_request(
        CredentialClass::Forge,
        "git:read",
        "https://github.com/org",
        300,
    );
    let gh_tok = broker
        .request_release_with_issuer(&gh_binding, &gh_req, &gh_issuer, None, now)
        .await
        .expect("gh release");
    assert!(gh_tok.token_value.starts_with("ghs_mock_"));
    assert_eq!(st.gh_mint_headers.lock().expect("gh").len(), 1);
    assert!(
        broker
            .revoke_lease_with_issuer(&gh_tok.lease_id, &gh_issuer)
            .await
            .expect("revoke gh")
    );
    assert_eq!(st.gh_revoked_tokens.lock().expect("gh_rev").len(), 1);
    assert_eq!(
        broker.lease(&gh_tok.lease_id).expect("lease").state,
        LeaseState::Revoked
    );

    let gcp_issuer = GcpStsIssuer::new(
        &format!("{base}/v1/token"),
        "//iam.googleapis.com/projects/1/pools/p",
        vec!["https://www.googleapis.com/auth/cloud-platform".into()],
        true,
    )
    .expect("gcp issuer");
    let gcp_binding = CredentialBinding {
        credential_id: "crd_gcp".into(),
        upstream_min_ttl_secs: 300,
        ..aws_binding.clone()
    };
    let gcp_req = release_request(
        CredentialClass::Cloud,
        "gcp:read",
        "https://storage.googleapis.com",
        600,
    );
    let gcp_tok = broker
        .request_release_with_issuer(&gcp_binding, &gcp_req, &gcp_issuer, Some("fed-jwt"), now)
        .await
        .expect("gcp release");
    let gcp_exec = format_gcp_external_account(&gcp_tok).expect("gcp external_account");
    assert!(gcp_exec.contains("ya29.mock_gcp_tok"));

    let oauth_issuer = OAuth2Rfc8693Issuer::new(
        &format!("{base}/oauth2/token"),
        Some(&format!("{base}/oauth2/revoke")),
        "spiffe://org1/agi/agi_live",
        60,
        Some("actor-attestation".into()),
        true,
    )
    .expect("oauth issuer");
    let oauth_tok = broker
        .request_release_with_issuer(&gh_binding, &gh_req, &oauth_issuer, Some("subj-tok"), now)
        .await
        .expect("oauth exchange");
    assert_eq!(oauth_tok.token_value.as_str(), "at_rfc8693_mock");
    let forms = st.oauth_forms.lock().expect("oauth").join("\n");
    assert!(forms.contains("actor_token=actor-attestation"));

    // Failing upstream revocation MUST preserve handle and Active state for retry.
    let bad_oauth = OAuth2Rfc8693Issuer::new(
        "http://127.0.0.1:1/oauth2/token",
        Some("http://127.0.0.1:1/oauth2/revoke"),
        "spiffe://org1/agi/agi_live",
        60,
        None,
        true,
    )
    .expect("bad oauth");
    assert!(
        broker
            .revoke_lease_with_issuer(&oauth_tok.lease_id, &bad_oauth)
            .await
            .is_err()
    );
    assert_eq!(
        broker.lease(&oauth_tok.lease_id).expect("lease").state,
        LeaseState::Active
    );
    assert!(
        broker
            .revoke_lease_with_issuer(&oauth_tok.lease_id, &oauth_issuer)
            .await
            .expect("rfc7009 revoke")
    );
    assert_eq!(st.oauth_revokes.lock().expect("oauth_rev").len(), 1);

    // Session-level revocation tracks pending failures and completes on retry.
    let oauth_tok2 = broker
        .request_release_with_issuer(&gh_binding, &gh_req, &oauth_issuer, Some("subj-tok"), now)
        .await
        .expect("oauth exchange 2");
    let sess_rep = broker
        .revoke_by_session_with_issuer(&gh_req.session_id, &bad_oauth)
        .await;
    assert_eq!(
        sess_rep.pending_lease_ids,
        vec![oauth_tok2.lease_id.clone()]
    );
    assert!(
        broker
            .pending_revocation_ids()
            .contains(&oauth_tok2.lease_id)
    );
    assert!(
        broker
            .revoke_lease_with_issuer(&oauth_tok2.lease_id, &oauth_issuer)
            .await
            .expect("retry pending revoke")
    );
    assert!(broker.pending_revocation_ids().is_empty());
}

#[tokio::test]
async fn secret_store_key_validation_and_dpapi_or_platform_guard() {
    let dir = std::env::temp_dir().join(format!("grdr-dpapi-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = DpapiSecretStore::new(&dir, b"grdr-unit-entropy".to_vec()).expect("dpapi store");
    assert!(!format!("{store:?}").contains("grdr-unit-entropy"));
    assert!(store.store_secret("../bad", b"x").await.is_err());

    #[cfg(windows)]
    {
        store
            .store_secret("key_1", b"protected-dpapi-payload")
            .await
            .expect("dpapi protect");
        let plain = store
            .load_secret("key_1")
            .await
            .expect("dpapi unprotect")
            .expect("present");
        assert_eq!(plain.as_slice(), b"protected-dpapi-payload");

        let wrong = DpapiSecretStore::new(&dir, b"wrong-entropy".to_vec()).expect("wrong store");
        assert!(wrong.load_secret("key_1").await.is_err());

        store.delete_secret("key_1").await.expect("delete");
        assert!(store.load_secret("key_1").await.expect("absent").is_none());
    }
    #[cfg(not(windows))]
    {
        assert!(store.store_secret("key_1", b"x").await.is_err());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
