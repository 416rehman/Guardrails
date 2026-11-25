// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;
use zeroize::Zeroizing;

use grdr_identity::{AgentLifecycle, ContainmentStatus, CredentialBinding, CredentialClass};
use grdr_model::{ActionAttempt, Verdict};
use grdr_proxy::cred_inject::{VaultedUpstreamSecret, model_class_ceiling};
use grdr_proxy::egress::{EgressGuardConfig, LoopbackUpstreamPolicy, validate_ip};
use grdr_proxy::router::{ProxyGatewayState, build_proxy_router};
use grdr_proxy::sr39::{EgressState, InstanceTokenRegistry, RouteUpstream, SessionRegistration};
use grdr_proxy::tunnel::{UpstreamProxyConfig, handle_tunnel_connection};
use grdr_proxy::{
    ProxyDecideFuture, ProxyDecisionClient, ProxyError, TenantHeaderPolicy,
    fail_closed_proxy_receipt,
};

struct StubProxyDecisionClient {
    verdict: Verdict,
}

impl ProxyDecisionClient for StubProxyDecisionClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        Box::pin(async move {
            let mut receipt = fail_closed_proxy_receipt(attempt, "stub decision");
            receipt.verdict = self.verdict;
            Ok(receipt)
        })
    }
}

fn random_hex_suffix(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    assert!(grdr_crypto::fill_random(&mut raw).is_ok());
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_test_session(token: String, route: RouteUpstream) -> SessionRegistration {
    let mut routes = BTreeMap::new();
    routes.insert(route.route_id.clone(), route);
    SessionRegistration {
        session_id: "sess-proxy-1".into(),
        spiffe_id: "spiffe://guardrails.local/agent/codex/inst-1".into(),
        device_id: "dev-proxy-1".into(),
        agent_name: "codex".into(),
        caller_program: "grdr-proxy".into(),
        instance_token: token,
        egress: EgressState::Active,
        attribution_grade: 4,
        has_session_container: true,
        containment: ContainmentStatus::Contained,
        lifecycle: AgentLifecycle::Active,
        expected_phantom_tokens: BTreeMap::new(),
        routes,
    }
}

#[tokio::test]
async fn sr39_and_ssrf_guards_reject_browser_origins_bad_host_metadata_and_ip6_mapped() {
    let default_cfg = EgressGuardConfig::default();
    assert!(validate_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), &default_cfg).is_err());
    assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), &default_cfg).is_err());
    assert!(
        validate_ip(
            IpAddr::V6("::ffff:169.254.169.254".parse::<Ipv6Addr>().unwrap()),
            &default_cfg
        )
        .is_err()
    );
    assert!(validate_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &default_cfg).is_err());

    let allow_loop_cfg = EgressGuardConfig {
        loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
    };
    assert!(
        validate_ip(
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            &allow_loop_cfg
        )
        .is_err()
    );
    assert!(validate_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), &allow_loop_cfg).is_ok());

    let state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Allow,
            },
            18080,
            allow_loop_cfg,
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let route = RouteUpstream::parse(
        "openai",
        "openai",
        "http://127.0.0.1:18999",
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    state
        .registry
        .lock()
        .await
        .register_session(build_test_session(token.clone(), route))
        .unwrap();

    let app = build_proxy_router(state);

    // Browser Origin header rejected with 403.
    let origin_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/v1/responses"))
                .header("host", "127.0.0.1:18080")
                .header("origin", "https://attacker.example")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(origin_resp.status(), StatusCode::FORBIDDEN);

    // DNS-rebinding Host header rejected with 403.
    let host_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/v1/responses"))
                .header("host", "evil.internal:18080")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(host_resp.status(), StatusCode::FORBIDDEN);

    // Disallowed Content-Type text/html rejected with 403.
    let ctype_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/v1/responses"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "text/html")
                .body(Body::from("<b>hi</b>"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ctype_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn inject_credential_overwrites_tenant_headers_and_never_leaks_real_secret() {
    let seen_headers = Arc::new(tokio::sync::Mutex::new(HeaderMap::new()));
    let seen_clone = Arc::clone(&seen_headers);
    let upstream_app = Router::new().route(
        "/v1/responses",
        post(move |headers: HeaderMap, body: String| {
            let seen_clone = Arc::clone(&seen_clone);
            async move {
                *seen_clone.lock().await = headers;
                axum::Json(serde_json::json!({ "ok": true, "echo_len": body.len() }))
            }
        }),
    );
    let upstream_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_app).await;
    });

    let mut tenant = TenantHeaderPolicy::default();
    tenant
        .insert("openai-organization", "org-trusted-authoritative")
        .unwrap();

    let route = RouteUpstream::parse(
        "openai",
        "openai",
        &format!("http://127.0.0.1:{upstream_port}"),
        Some("cred-openai-test".into()),
        tenant,
    )
    .unwrap();

    let mut phantom_bytes = [0_u8; 12];
    grdr_crypto::fill_random(&mut phantom_bytes).unwrap();
    let phantom_tok = format!(
        "grdr_ph_{}",
        phantom_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut secret_bytes = [0_u8; 16];
    grdr_crypto::fill_random(&mut secret_bytes).unwrap();
    let real_upstream_secret = Zeroizing::new(format!(
        "upstream-secret-{}",
        secret_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));

    let allow_cfg = EgressGuardConfig {
        loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
    };
    let state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Allow,
            },
            18080,
            allow_cfg,
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let mut session_reg = build_test_session(token.clone(), route);
    session_reg
        .expected_phantom_tokens
        .insert("cred-openai-test".into(), phantom_tok.clone());
    state
        .registry
        .lock()
        .await
        .register_session(session_reg)
        .unwrap();

    state
        .credentials
        .lock()
        .await
        .register_secret(VaultedUpstreamSecret {
            binding: CredentialBinding {
                credential_id: "cred-openai-test".into(),
                class: CredentialClass::Model,
                account_id: "acct-test".into(),
                allowed_programs: vec!["grdr-proxy".into()],
                allowed_hosts: vec!["127.0.0.1".into()],
                upstream_revocable: false,
                upstream_min_ttl_secs: 60,
                phantom_prefix: "grdr_ph_".into(),
            },
            ceiling: model_class_ceiling("acct-test", "127.0.0.1"),
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            secret_value: real_upstream_secret.clone(),
        });

    let app = build_proxy_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{token}/openai/v1/responses"))
        .header("host", "127.0.0.1:18080")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {phantom_tok}"))
        .header("openai-organization", "org-spoofed-by-agent")
        .body(Body::from(
            r#"{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let captured = seen_headers.lock().await;
    assert_eq!(
        captured.get("authorization").and_then(|v| v.to_str().ok()),
        Some(format!("Bearer {}", *real_upstream_secret).as_str())
    );
    let org_vals: Vec<&str> = captured
        .get_all("openai-organization")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(org_vals, vec!["org-trusted-authoritative"]);

    // D-30 egress cut revokes leases and blocks subsequent HTTP requests with 403.
    let revoked = state.cut_session_egress("sess-proxy-1").await;
    assert_eq!(revoked, 1);

    let cut_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/v1/responses"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cut_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn policy_deny_returns_403_otlp_marks_claimed_and_connect_blocks_metadata() {
    let state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Deny,
            },
            18080,
            EgressGuardConfig::default(),
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let route = RouteUpstream::parse(
        "anthropic",
        "anthropic",
        "https://api.anthropic.com",
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    state
        .registry
        .lock()
        .await
        .register_session(build_test_session(token.clone(), route))
        .unwrap();

    let app = build_proxy_router(Arc::clone(&state));
    let denied_http_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/anthropic/v1/messages"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"claude-test","messages":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_http_resp.status(), StatusCode::FORBIDDEN);

    let dynamic_sk = format!("sk-{}", random_hex_suffix(8));
    let otlp_payload = serde_json::json!({
        "session_id": "sess-otlp-1",
        "agent_name": "codex",
        "summary": format!("used {dynamic_sk}")
    })
    .to_string();
    let otlp_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("content-type", "application/json")
                .body(Body::from(otlp_payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(otlp_resp.status(), StatusCode::OK);
    let otlp_bytes = axum::body::to_bytes(otlp_resp.into_body(), 16 * 1024)
        .await
        .unwrap();
    let otlp_json: Value = serde_json::from_slice(&otlp_bytes).unwrap();
    assert_eq!(
        otlp_json.get("provenance").and_then(Value::as_str),
        Some("claimed")
    );
    let events = state.otlp_events.lock().await;
    assert_eq!(events.len(), 1);
    assert!(events[0].attempt.summary.contains("[REDACTED_TOKEN]"));
    drop(events);

    // Upstream proxy chaining parses HTTPS_PROXY cleanly.
    let mut proxy_env = BTreeMap::new();
    proxy_env.insert(
        "HTTPS_PROXY".into(),
        "http://corp-proxy.example:8443".into(),
    );
    let chained = UpstreamProxyConfig::from_env_map(&proxy_env).unwrap();
    assert_eq!(chained.host, "corp-proxy.example");
    assert_eq!(chained.port, 8443);

    // CONNECT tunnel to metadata IP must return 403 Forbidden.
    let tunnel_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let tunnel_addr = tunnel_listener.local_addr().unwrap();
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = tunnel_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_clone, None).await;
        }
    });

    let mut client = TcpStream::connect(tunnel_addr).await.unwrap();
    client
        .write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n")
        .await
        .unwrap();
    let mut reply = [0_u8; 128];
    let n = client.read(&mut reply).await.unwrap();
    let reply_str = std::str::from_utf8(reply.get(..n).unwrap_or(&[])).unwrap();
    assert!(reply_str.starts_with("HTTP/1.1 403"));

    // Unauthenticated SOCKS5 no-auth (0x00) must be rejected with 0xff.
    let unauth_socks_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let unauth_socks_addr = unauth_socks_listener.local_addr().unwrap();
    let state_unauth_socks = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = unauth_socks_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_unauth_socks, None).await;
        }
    });
    let mut unauth_sclient = TcpStream::connect(unauth_socks_addr).await.unwrap();
    unauth_sclient.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reject_method = [0_u8; 2];
    unauth_sclient.read_exact(&mut reject_method).await.unwrap();
    assert_eq!(reject_method, [0x05, 0xff]);

    // Authenticated SOCKS5 (RFC 1929) to private IP 10.0.0.1 must return rule-denied (0x02).
    let socks_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let state_socks = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = socks_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_socks, None).await;
        }
    });

    let mut sclient = TcpStream::connect(socks_addr).await.unwrap();
    sclient.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method_sel = [0_u8; 2];
    sclient.read_exact(&mut method_sel).await.unwrap();
    assert_eq!(method_sel, [0x05, 0x02]);
    let tok_bytes = token.as_bytes();
    let mut rfc1929 = vec![
        0x01,
        4,
        b'g',
        b'r',
        b'd',
        b'r',
        u8::try_from(tok_bytes.len()).unwrap(),
    ];
    rfc1929.extend_from_slice(tok_bytes);
    sclient.write_all(&rfc1929).await.unwrap();
    let mut auth_ack = [0_u8; 2];
    sclient.read_exact(&mut auth_ack).await.unwrap();
    assert_eq!(auth_ack, [0x01, 0x00]);
    sclient
        .write_all(&[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50])
        .await
        .unwrap();
    let mut sreply = [0_u8; 10];
    sclient.read_exact(&mut sreply).await.unwrap();
    assert_eq!(sreply[1], 0x02);

    // Active D-30 egress cut immediately closes authenticated CONNECT requests for the cut session.
    let cut_state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Allow,
            },
            18080,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let cut_token = InstanceTokenRegistry::issue_token().unwrap();
    let cut_route = RouteUpstream::parse(
        "local",
        "openai",
        "http://127.0.0.1:18999",
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    let mut cut_reg = build_test_session(cut_token.clone(), cut_route);
    cut_reg.session_id = "sess-cut-99".into();
    cut_state
        .registry
        .lock()
        .await
        .register_session(cut_reg)
        .unwrap();
    cut_state.cut_session_egress("sess-cut-99").await;

    let cut_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let cut_addr = cut_listener.local_addr().unwrap();
    let cut_clone = Arc::clone(&cut_state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = cut_listener.accept().await {
            let _ = handle_tunnel_connection(sock, cut_clone, None).await;
        }
    });
    let mut cut_client = TcpStream::connect(cut_addr).await.unwrap();
    let cut_connect_req = format!(
        "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nProxy-Authorization: Bearer {cut_token}\r\n\r\n"
    );
    cut_client
        .write_all(cut_connect_req.as_bytes())
        .await
        .unwrap();
    let mut cut_reply = [0_u8; 64];
    let cut_n = cut_client.read(&mut cut_reply).await.unwrap();
    assert!(
        std::str::from_utf8(cut_reply.get(..cut_n).unwrap_or(&[]))
            .unwrap()
            .starts_with("HTTP/1.1 403")
    );

    // OTLP receiver rejects payloads missing explicit Content-Type header with 403.
    let otlp_no_ctype = build_proxy_router(cut_state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(otlp_no_ctype.status(), StatusCode::FORBIDDEN);
    let _unused: Option<ProxyError> = None;
}

#[tokio::test]
async fn blocking_round_1_ssrf_traversal_chained_407_and_otlp_redactions() {
    let default_cfg = EgressGuardConfig::default();
    for blocked in [
        "::169.254.169.254",
        "::ffff:169.254.169.254",
        "fec0::1",
        "64:ff9b::127.0.0.1",
        "64:ff9b:1::1",
        "2002::1",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "100::1",
        "0.0.0.1",
        "192.0.0.1",
        "198.18.0.1",
        "240.0.0.1",
    ] {
        let ip: IpAddr = blocked.parse().unwrap();
        assert!(
            validate_ip(ip, &default_cfg).is_err(),
            "expected SSRF guard to deny {blocked}"
        );
    }

    // Port 0 listener config must reject requests fail-closed.
    let zero_port_state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Allow,
            },
            0,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let tok_zero = InstanceTokenRegistry::issue_token().unwrap();
    let route_zero = RouteUpstream::parse(
        "openai",
        "openai",
        "http://127.0.0.1:18999/v1",
        Some("cred-test".into()),
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    zero_port_state
        .registry
        .lock()
        .await
        .register_session(build_test_session(tok_zero.clone(), route_zero))
        .unwrap();
    let zero_resp = build_proxy_router(zero_port_state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tok_zero}/openai/chat/completions"))
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(zero_resp.status(), StatusCode::FORBIDDEN);

    // Traversal, wrong phantom token, and OTLP multi-pattern redaction checks.
    let state = Arc::new(
        ProxyGatewayState::new(
            StubProxyDecisionClient {
                verdict: Verdict::Allow,
            },
            18080,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let route = RouteUpstream::parse(
        "openai",
        "openai",
        "http://127.0.0.1:18999/v1",
        Some("cred-test".into()),
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    let expected_phantom = format!("grdr_ph_{}", random_hex_suffix(8));
    let wrong_phantom = format!("grdr_ph_{}", random_hex_suffix(8));
    let real_secret = Zeroizing::new(format!("up_{}", random_hex_suffix(12)));
    let mut session = build_test_session(token.clone(), route);
    session
        .expected_phantom_tokens
        .insert("cred-test".into(), expected_phantom);
    state
        .registry
        .lock()
        .await
        .register_session(session)
        .unwrap();
    state
        .credentials
        .lock()
        .await
        .register_secret(VaultedUpstreamSecret {
            binding: CredentialBinding {
                credential_id: "cred-test".into(),
                class: CredentialClass::Model,
                account_id: "acct-test".into(),
                allowed_programs: vec!["grdr-proxy".into()],
                allowed_hosts: vec!["127.0.0.1".into()],
                upstream_revocable: false,
                upstream_min_ttl_secs: 60,
                phantom_prefix: "grdr_ph_".into(),
            },
            ceiling: model_class_ceiling("acct-test", "127.0.0.1"),
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            secret_value: real_secret,
        });
    let app = build_proxy_router(Arc::clone(&state));

    for bad_tail in ["..%2fadmin", "%2e%2e/secrets", "chat?admin=1"] {
        let trav_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{token}/openai/{bad_tail}"))
                    .header("host", "127.0.0.1:18080")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            trav_resp.status(),
            StatusCode::FORBIDDEN,
            "traversal tail {bad_tail} must be rejected"
        );
    }

    let wrong_phantom_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/chat/completions"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {wrong_phantom}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_phantom_resp.status(), StatusCode::FORBIDDEN);

    let dup_host_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/openai/chat/completions"))
                .header("host", "127.0.0.1:18080")
                .header("host", "evil.internal:18080")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_host_resp.status(), StatusCode::FORBIDDEN);

    // Test Authorization: Bearer <tok>, compact JSON fallback without summary, and PEM standalone.
    let bearer_tok = random_hex_suffix(10);
    let pat_tok = format!("github_pat_{}", random_hex_suffix(10));
    let ghs_tok = format!("ghs_{}", random_hex_suffix(10));
    let jwt_tok = format!(
        "eyJ{}.{}.{}",
        random_hex_suffix(6),
        random_hex_suffix(6),
        random_hex_suffix(6)
    );
    let otlp_bearer = serde_json::json!({
        "session_id": "sess-redact-1",
        "agent_name": "codex",
        "summary": format!("Authorization: Bearer {bearer_tok} {pat_tok} {ghs_tok} {jwt_tok}")
    })
    .to_string();
    let redact_bearer_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("content-type", "application/json")
                .body(Body::from(otlp_bearer))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(redact_bearer_resp.status(), StatusCode::OK);
    {
        let retained = state.otlp_events.lock().await;
        let last_summary = &retained.back().unwrap().attempt.summary;
        assert!(!last_summary.contains(&bearer_tok));
        assert!(!last_summary.contains(&pat_tok));
        assert!(!last_summary.contains(&ghs_tok));
        assert!(!last_summary.contains(&jwt_tok));
        assert!(last_summary.contains("[REDACTED_TOKEN]"));
    }

    let compact_secret = random_hex_suffix(10);
    let dsn_secret = random_hex_suffix(10);
    let compact_json = serde_json::json!({
        "session_id": "sess-redact-2",
        "agent_name": "codex",
        "authorization": format!("Bearer {compact_secret}"),
        "dsn": format!("postgres://svc:{dsn_secret}@db.internal/app")
    })
    .to_string();
    let compact_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("content-type", "application/json")
                .body(Body::from(compact_json))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(compact_resp.status(), StatusCode::OK);
    {
        let retained = state.otlp_events.lock().await;
        let last_summary = &retained.back().unwrap().attempt.summary;
        assert!(!last_summary.contains(&compact_secret));
        assert!(!last_summary.contains(&dsn_secret));
        assert!(last_summary.contains("[REDACTED_TOKEN]"));
        assert!(last_summary.contains("[REDACTED_CRED]@db.internal"));
    }

    let otlp_pem = serde_json::json!({
        "session_id": "sess-redact-3",
        "agent_name": "codex",
        "summary": "-----BEGIN PRIVATE KEY-----"
    })
    .to_string();
    let pem_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("content-type", "application/json")
                .body(Body::from(otlp_pem))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pem_resp.status(), StatusCode::OK);
    let retained = state.otlp_events.lock().await;
    let pem_summary = &retained.back().unwrap().attempt.summary;
    assert_eq!(pem_summary, "[REDACTED_PEM_PRIVATE_KEY]");
    drop(retained);

    // Chained proxy returning HTTP 407 with " 200 " inside header must NOT succeed.
    let chain_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let chain_port = chain_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = chain_listener.accept().await {
            let mut req_buf = [0_u8; 512];
            let _ = s.read(&mut req_buf).await;
            let _ = s
                .write_all(
                    b"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"200 ok\"\r\nProxy-Header: 200\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
        }
    });

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let state_chain = Arc::clone(&state);
    let chain_cfg = UpstreamProxyConfig {
        host: "127.0.0.1".into(),
        port: chain_port,
    };
    tokio::spawn(async move {
        if let Ok((sock, _)) = proxy_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_chain, Some(chain_cfg)).await;
        }
    });

    let mut chain_client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_via_407 = format!(
        "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    chain_client
        .write_all(connect_via_407.as_bytes())
        .await
        .unwrap();
    let mut chain_reply = [0_u8; 128];
    let chain_n = chain_client.read(&mut chain_reply).await.unwrap();
    let chain_reply_str = std::str::from_utf8(chain_reply.get(..chain_n).unwrap_or(&[])).unwrap();
    assert!(
        chain_reply_str.starts_with("HTTP/1.1 502"),
        "expected HTTP 502 when chained proxy returns 407, got: {chain_reply_str}"
    );

    // Malformed IPv6 / '#' authority on CONNECT fails closed with 403.
    let bad_conn_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bad_conn_addr = bad_conn_listener.local_addr().unwrap();
    let state_bad_conn = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = bad_conn_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_bad_conn, None).await;
        }
    });
    let mut bad_conn_client = TcpStream::connect(bad_conn_addr).await.unwrap();
    // Send only the invalid request line so the server buffer has zero unread trailing bytes on Windows before 403 close.
    bad_conn_client
        .write_all(b"CONNECT [::bad_ipv6]:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    let mut bad_conn_reply = [0_u8; 64];
    let bad_conn_n = bad_conn_client.read(&mut bad_conn_reply).await.unwrap();
    assert!(
        std::str::from_utf8(bad_conn_reply.get(..bad_conn_n).unwrap_or(&[]))
            .unwrap()
            .starts_with("HTTP/1.1 403")
    );
}
