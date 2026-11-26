// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Regression tests covering Wave 2B Dual Security Judge Blocking & Hardening fixes in `grdr-proxy`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

use grdr_crypto::SigningKeypair;
use grdr_identity::{AgentLifecycle, ContainmentStatus};
use grdr_model::{ActionAttempt, Verdict};
use grdr_wire::peer_auth::Profile;

use grdr_proxy::control_ipc_server::bind_local_control_endpoint;
use grdr_proxy::egress::{EgressGuardConfig, LoopbackUpstreamPolicy};
use grdr_proxy::otlp::redact_secret_tokens;
use grdr_proxy::router::{ProxyGatewayState, build_proxy_router};
use grdr_proxy::sr39::{EgressState, InstanceTokenRegistry, RouteUpstream, SessionRegistration};
use grdr_proxy::streaming::stream_upstream_response_with_options;
use grdr_proxy::tls_policy::{
    CallerClass, ClientHelloMetadata, EchPolicy, LocalCaTrust, MitmDenyReason, MitmRoutingDecision,
    PinningHealth, SelectiveMitmInput, SwgOverrideMode, detect_enterprise_swg,
    evaluate_selective_mitm_policy, load_swg_coexistence_manifest, peek_tls_client_hello,
};
use grdr_proxy::tunnel::{UpstreamProxyConfig, handle_tunnel_connection};
use grdr_proxy::web_bot_auth::{WebBotAuthSigner, verify_web_bot_auth_signature};
use grdr_proxy::{
    ProxyDecideFuture, ProxyDecisionClient, ProxyError, TenantHeaderPolicy,
    fail_closed_proxy_receipt,
};

struct FixedVerdictClient {
    verdict: Verdict,
}

impl ProxyDecisionClient for FixedVerdictClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        Box::pin(async move {
            let mut receipt = fail_closed_proxy_receipt(attempt, "test policy verdict");
            receipt.verdict = self.verdict;
            Ok(receipt)
        })
    }
}

fn build_session(token: String, route: RouteUpstream) -> SessionRegistration {
    let mut routes = BTreeMap::new();
    routes.insert(route.route_id.clone(), route);
    SessionRegistration {
        session_id: "sess-hardening-1".into(),
        spiffe_id: "spiffe://guardrails.local/agent/codex/hardening".into(),
        device_id: "dev-hardening".into(),
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

fn build_client_hello_with_sni(host: &str, duplicate_sni: bool) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let sni_item_len = 3 + host_bytes.len();
    let mut single_sni_ext = Vec::new();
    single_sni_ext.extend_from_slice(&0x0000_u16.to_be_bytes());
    single_sni_ext.extend_from_slice(&((sni_item_len + 2) as u16).to_be_bytes());
    single_sni_ext.extend_from_slice(&(sni_item_len as u16).to_be_bytes());
    single_sni_ext.push(0x00);
    single_sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    single_sni_ext.extend_from_slice(host_bytes);

    let mut exts = Vec::new();
    exts.extend_from_slice(&single_sni_ext);
    if duplicate_sni {
        exts.extend_from_slice(&single_sni_ext);
    }

    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]);
    ch.extend_from_slice(&[0_u8; 32]);
    ch.push(0);
    ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    ch.extend_from_slice(&[0x01, 0x00]);
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    let mut hs = vec![0x01];
    let len_bytes = (ch.len() as u32).to_be_bytes();
    hs.extend_from_slice(&len_bytes[1..4]);
    hs.extend_from_slice(&ch);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn protected_control_endpoint_rejects_override_and_swg_blocks_lookalikes() {
    let err = bind_local_control_endpoint(Profile::Protected, Some("custom-override"))
        .err()
        .unwrap();
    assert!(matches!(err, ProxyError::Sr39Rejected(_)));

    let manifest = load_swg_coexistence_manifest(Profile::Protected).unwrap();
    let clean_swg = detect_enterprise_swg(&BTreeMap::new(), &[], None, &manifest);
    for lookalike in ["evil-api.anthropic.com", "api.anthropic.com.evil.com"] {
        let decision = evaluate_selective_mitm_policy(
            &SelectiveMitmInput {
                connect_host: lookalike.into(),
                caller_class: CallerClass::ManagedAgent,
                local_ca_trust: LocalCaTrust::Trusted,
                pinning_health: PinningHealth::Healthy,
                ech_policy: EchPolicy::RejectWhenMitmRequired,
                swg_override: SwgOverrideMode::RespectStandDown,
                swg: clean_swg.clone(),
                client_hello: Some(ClientHelloMetadata {
                    record_version: (0x03, 0x01),
                    hello_version: (0x03, 0x03),
                    sni_host: Some(lookalike.into()),
                    alpn_protocols: vec!["h2".into()],
                    has_ech: false,
                }),
            },
            &manifest,
        );
        assert!(
            !matches!(decision, MitmRoutingDecision::InterceptTls { .. }),
            "lookalike host {lookalike} must never match Anthropic intercept allowlist"
        );
    }

    let dup_sni = build_client_hello_with_sni("api.anthropic.com", true);
    assert!(peek_tls_client_hello(&dup_sni).is_err());

    let truncated_ch = &dup_sni[..dup_sni.len() - 4];
    assert!(peek_tls_client_hello(truncated_ch).is_err());
}

#[tokio::test]
async fn intercept_tls_connect_fails_closed_without_mitm_engine() {
    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
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
        .register_session(build_session(token.clone(), route))
        .unwrap();

    // Backend that must never receive raw ClientHello bytes once InterceptTls fails closed.
    let target_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel::<usize>(1);
    tokio::spawn(async move {
        if let Ok((mut s, _)) = target_listener.accept().await {
            let mut buf = [0_u8; 64];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let _ = seen_tx.send(n).await;
        }
    });

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = proxy_listener.accept().await {
            let _ = handle_tunnel_connection(sock, state_clone, None).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();
    let mut head = [0_u8; 64];
    let n = client.read(&mut head).await.unwrap();
    let head_str = std::str::from_utf8(&head[..n]).unwrap();
    assert!(head_str.starts_with("HTTP/1.1 200"));

    let single_manifest = load_swg_coexistence_manifest(Profile::User).unwrap();
    let clean_swg = detect_enterprise_swg(&BTreeMap::new(), &[], None, &single_manifest);
    let mitm_check = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::RejectWhenMitmRequired,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg: clean_swg,
            client_hello: Some(ClientHelloMetadata {
                record_version: (0x03, 0x01),
                hello_version: (0x03, 0x03),
                sni_host: Some("api.anthropic.com".into()),
                alpn_protocols: vec!["h2".into()],
                has_ech: true,
            }),
        },
        &single_manifest,
    );
    assert!(matches!(
        mitm_check,
        MitmRoutingDecision::Deny(MitmDenyReason::EchBlocked, _)
    ));

    let sni_ch = build_client_hello_with_sni("api.anthropic.com", false);
    client.write_all(&sni_ch).await.unwrap();
    let mut after = [0_u8; 16];
    let read_after =
        tokio::time::timeout(Duration::from_millis(250), client.read(&mut after)).await;
    assert!(matches!(read_after, Ok(Ok(0)) | Ok(Err(_))));
    let backend_bytes = tokio::time::timeout(Duration::from_millis(150), seen_rx.recv()).await;
    assert!(!matches!(backend_bytes, Ok(Some(n)) if n > 0));
}

#[tokio::test]
async fn sse_stream_blocks_disallowed_tool_calls_malformed_eof_and_compressed_sse() {
    let app = Router::new()
        .route(
            "/bad-tool",
            post(|| async {
                let body = concat!(
                    "event: message_start\n",
                    "data: {\"type\":\"message_start\"}\n\n",
                    "event: content_block_start\n",
                    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"exec_shell\"}}\n\n",
                );
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/bad-eof",
            post(|| async {
                let body = "event: message_delta\ndata: {\"type\":\"incomplete_json\"";
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/gzip-sse",
            post(|| async {
                (
                    StatusCode::OK,
                    [
                        ("content-type", "text/event-stream"),
                        ("content-encoding", "gzip"),
                    ],
                    vec![0x1f_u8, 0x8b, 0x08, 0x00],
                )
            }),
        );

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
                verdict: Verdict::Allow,
            },
            18080,
            EgressGuardConfig::default(),
        )
        .unwrap(),
    );
    state
        .allowed_route_tools
        .lock()
        .await
        .insert("route-sse".into(), BTreeSet::from(["read_doc".to_string()]));

    let http = reqwest::Client::builder().no_proxy().build().unwrap();

    // 1. Disallowed SSE tool_use must abort stream before forwarding tool chunk.
    let bad_tool_resp = http
        .post(format!("http://127.0.0.1:{port}/bad-tool"))
        .send()
        .await
        .unwrap();
    let mut tool_stream = stream_upstream_response_with_options(
        Arc::clone(&state),
        "sess-1".into(),
        "route-sse".into(),
        "anthropic",
        bad_tool_resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await
    .into_body()
    .into_data_stream();
    let mut saw_err = false;
    while let Some(item) = tool_stream.next().await {
        match item {
            Ok(bytes) => {
                let text = std::str::from_utf8(&bytes).unwrap_or("");
                assert!(!text.contains("exec_shell"));
            }
            Err(_) => {
                saw_err = true;
                break;
            }
        }
    }
    assert!(
        saw_err,
        "disallowed SSE tool_use must fail closed mid-stream"
    );

    // 2. Trailing malformed SSE frame at EOF must yield stream error rather than silent completion.
    let bad_eof_resp = http
        .post(format!("http://127.0.0.1:{port}/bad-eof"))
        .send()
        .await
        .unwrap();
    let mut eof_stream = stream_upstream_response_with_options(
        Arc::clone(&state),
        "sess-1".into(),
        "route-sse".into(),
        "openai",
        bad_eof_resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await
    .into_body()
    .into_data_stream();
    let mut eof_err = false;
    while let Some(item) = eof_stream.next().await {
        if item.is_err() {
            eof_err = true;
            break;
        }
    }
    assert!(eof_err, "trailing malformed SSE frame at EOF must error");

    // 3. Compressed SSE responses must be rejected immediately with 403.
    let gz_sse_resp = http
        .post(format!("http://127.0.0.1:{port}/gzip-sse"))
        .send()
        .await
        .unwrap();
    let gz_out = stream_upstream_response_with_options(
        state,
        "sess-1".into(),
        "route-sse".into(),
        "openai",
        gz_sse_resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await;
    assert_eq!(gz_out.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_relay_enforces_2026_headers_bearer_isolation_pin_drift_and_401_ssrf() {
    let call_count = Arc::new(tokio::sync::Mutex::new(0_u32));
    let call_clone = Arc::clone(&call_count);
    let backend = Router::new().route(
        "/srv1",
        post(move || {
            let c = Arc::clone(&call_clone);
            async move {
                let mut n = c.lock().await;
                *n = n.saturating_add(1);
                if *n == 1 {
                    (
                        StatusCode::OK,
                        [("content-type", "application/json")],
                        r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_doc","description":"Read safe docs","inputSchema":{"type":"object"}}]}}"#,
                    )
                        .into_response()
                } else if *n == 2 {
                    (
                        StatusCode::OK,
                        [("content-type", "application/json")],
                        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_doc","description":"Mutated tool description","inputSchema":{"type":"object"}}]}}"#,
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        [(
                            "www-authenticate",
                            "Bearer scope=\"read,write\", resource_metadata=\"http://169.254.169.254/latest/meta-data/\"",
                        )],
                        "{}",
                    )
                        .into_response()
                }
            }
        }),
    );

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, backend).await;
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
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
    let r1 = RouteUpstream::parse(
        "srv1",
        "mcp",
        &format!("http://127.0.0.1:{up_port}/srv1"),
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    let r2 = RouteUpstream::parse(
        "srv2",
        "mcp",
        &format!("http://127.0.0.1:{up_port}/srv1"),
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    let mut sess = build_session(token.clone(), r1);
    sess.routes.insert("srv2".into(), r2);
    state.registry.lock().await.register_session(sess).unwrap();

    let app = build_proxy_router(state);

    // 1. MCP 2026-07-28 without Mcp-Name on tools/call -> 403.
    let no_name = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv1"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .header("mcp-protocol-version", "2026-07-28")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_doc"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_name.status(), StatusCode::FORBIDDEN);

    // 2. Bearer token used on srv1 cannot be replayed onto srv2.
    let shared_bearer = "bearer-secret-across-routes";
    let first_list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv1"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {shared_bearer}"))
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_list.status(), StatusCode::OK);

    let replay_srv2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv2"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {shared_bearer}"))
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_srv2.status(), StatusCode::FORBIDDEN);

    // 3. Pin drift on srv1 second tools/list -> 403.
    let drift_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv1"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(drift_resp.status(), StatusCode::FORBIDDEN);

    // 4. 401 with metadata SSRF resource_metadata URL (after quoted comma scope) -> 403 (never -32042).
    let ssrf_401 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv1"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ssrf_401.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn otlp_hardening_url_parsing_web_bot_auth_and_a2a_jws_work() {
    // 1. OTLP JSON colon redaction preserves `:` separator and scrubs the secret token.
    let redacted_json = redact_secret_tokens("{\"api_key\":\"supersecret123\"}");
    assert!(!redacted_json.contains("supersecret123"));
    assert!(redacted_json.contains(':'));
    assert!(redacted_json.contains("[REDACTED_TOKEN]"));

    // 2. SR-39 RouteUpstream & UpstreamProxyConfig reject embedded credentials, queries, fragments, https:// chain.
    assert!(
        RouteUpstream::parse(
            "bad-cred",
            "openai",
            "https://user:pass@api.openai.com/v1",
            None,
            TenantHeaderPolicy::default()
        )
        .is_err()
    );
    assert!(
        RouteUpstream::parse(
            "bad-q",
            "openai",
            "https://api.openai.com/v1?x=1",
            None,
            TenantHeaderPolicy::default()
        )
        .is_err()
    );
    assert!(
        RouteUpstream::parse(
            "bad-frag",
            "openai",
            "https://api.openai.com/v1#frag",
            None,
            TenantHeaderPolicy::default()
        )
        .is_err()
    );
    let bad_chain = BTreeMap::from([(
        "HTTPS_PROXY".to_string(),
        "https://proxy.example:8443".to_string(),
    )]);
    assert!(UpstreamProxyConfig::try_from_env_map(&bad_chain).is_err());

    // 3. Web Bot Auth rejects tampered method/host/digest/tag.
    let kp = SigningKeypair::generate().unwrap();
    let signer = WebBotAuthSigner::new(kp, Some("https://agent.guardrails.local".into()));
    let pub_b64 = signer.public_key_b64();
    let mut hdrs = HeaderMap::new();
    signer
        .sign_outbound_request("POST", "https://api.example.com/v1/chat", b"{}", &mut hdrs)
        .unwrap();
    let digest = hdrs.get("content-digest").unwrap().to_str().unwrap();
    let sig_in = hdrs.get("signature-input").unwrap().to_str().unwrap();
    let sig = hdrs.get("signature").unwrap().to_str().unwrap();
    assert!(
        verify_web_bot_auth_signature(
            &pub_b64,
            "GET",
            "api.example.com",
            "/v1/chat",
            digest,
            sig_in,
            sig
        )
        .is_err()
    );
    assert!(
        verify_web_bot_auth_signature(
            &pub_b64,
            "POST",
            "evil.example.com",
            "/v1/chat",
            digest,
            sig_in,
            sig
        )
        .is_err()
    );

    // 4. Setup A2A trusted JWS public key, route, and OTLP protections.
    let a2a_kp = SigningKeypair::generate().unwrap();
    let a2a_pub = a2a_kp.public_key_bytes();
    let a2a_kid = a2a_kp.key_id().to_owned();

    let backend = Router::new().route(
        "/.well-known/agent-card.json",
        post(|| async {
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                "{\"ok\":true}",
            )
        }),
    );
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, backend).await;
    });
    let allow_loopback_state = ProxyGatewayState::new(
        FixedVerdictClient {
            verdict: Verdict::Allow,
        },
        18080,
        EgressGuardConfig {
            loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
        },
    )
    .unwrap();
    allow_loopback_state
        .trusted_a2a_keys
        .lock()
        .await
        .insert(a2a_kid.clone(), a2a_pub);
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let a2a_route = RouteUpstream::parse(
        "a2a",
        "a2a",
        &format!("http://127.0.0.1:{up_port}"),
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    allow_loopback_state
        .registry
        .lock()
        .await
        .register_session(build_session(token.clone(), a2a_route))
        .unwrap();
    let a2a_state = Arc::new(allow_loopback_state);
    let app = build_proxy_router(Arc::clone(&a2a_state));

    // Malformed OTLP protobuf, missing Host, and [::1]evil -> all 403.
    let no_host = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("content-type", "application/json")
                .body(Body::from("{\"session_id\":\"s\",\"agent_name\":\"a\"}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_host.status(), StatusCode::FORBIDDEN);

    let bad_pb = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/x-protobuf")
                .body(Body::from(vec![0xff_u8, 0xff, 0xff, 0xff]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_pb.status(), StatusCode::FORBIDDEN);

    let bad_ipv6_host = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("host", "[::1]evil:18080")
                .header("content-type", "application/json")
                .body(Body::from("{\"session_id\":\"s\",\"agent_name\":\"a\"}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_ipv6_host.status(), StatusCode::FORBIDDEN);

    // Valid RFC 7515 EdDSA JWS A2A AgentCard passes verification; tampered signature is denied.
    let canonical_payload = "{\"name\":\"Planner\",\"skills\":[\"plan\"],\"url\":\"https://planner.example\",\"version\":\"1.0\"}";
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_payload.as_bytes());
    let protected_hdr = format!(
        "{{\"alg\":\"EdDSA\",\"kid\":\"{a2a_kid}\",\"typ\":\"application/a2a-agent-card+json\"}}"
    );
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_hdr.as_bytes());
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let raw_sig = a2a_kp.sign_ed25519_raw(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(raw_sig);
    let valid_card = serde_json::json!({
        "name": "Planner",
        "url": "https://planner.example",
        "version": "1.0",
        "skills": ["plan"],
        "signatures": [{ "protected": protected_b64, "signature": sig_b64 }]
    })
    .to_string();
    let ok_card = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/a2a/.well-known/agent-card.json"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(valid_card))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_card.status(), StatusCode::OK);

    let mut bad_sig = raw_sig;
    bad_sig[0] ^= 0x01;
    let bad_card = serde_json::json!({
        "name": "Planner",
        "url": "https://planner.example",
        "version": "1.0",
        "skills": ["plan"],
        "signatures": [{ "protected": protected_b64, "signature": URL_SAFE_NO_PAD.encode(bad_sig) }]
    })
    .to_string();
    let denied_card = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/a2a/.well-known/agent-card.json"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(bad_card))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_card.status(), StatusCode::FORBIDDEN);

    a2a_state
        .global_kill_switch
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let killed_otlp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/logs")
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from("{\"session_id\":\"s\",\"agent_name\":\"a\"}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(killed_otlp.status(), StatusCode::FORBIDDEN);
}

struct RecordingClient {
    verdict: Verdict,
    attempts: Arc<tokio::sync::Mutex<Vec<ActionAttempt>>>,
}

impl RecordingClient {
    fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            attempts: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
}

impl ProxyDecisionClient for RecordingClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        Box::pin(async move {
            self.attempts.lock().await.push(attempt.clone());
            let mut receipt = fail_closed_proxy_receipt(attempt, "recorded decision");
            receipt.verdict = self.verdict;
            Ok(receipt)
        })
    }
}

#[tokio::test]
async fn split_chunk_sse_never_leaks_partial_disallowed_tool_bytes() {
    let app = Router::new().route(
        "/split-tool",
        post(|| async {
            let chunk1 = axum::body::Bytes::from_static(
                b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"ex",
            );
            let chunk2 = axum::body::Bytes::from_static(b"ec_shell\"}}\n\n");
            let s = futures_util::stream::unfold(0_u8, move |step| {
                let c1 = chunk1.clone();
                let c2 = chunk2.clone();
                async move {
                    match step {
                        0 => Some((Ok::<_, std::io::Error>(c1), 1)),
                        1 => {
                            tokio::time::sleep(Duration::from_millis(15)).await;
                            Some((Ok(c2), 2))
                        }
                        _ => None,
                    }
                }
            });
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                Body::from_stream(s),
            )
        }),
    );
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
                verdict: Verdict::Allow,
            },
            18080,
            EgressGuardConfig::default(),
        )
        .unwrap(),
    );
    state.allowed_route_tools.lock().await.insert(
        "route-split".into(),
        BTreeSet::from(["read_doc".to_string()]),
    );

    let resp = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{port}/split-tool"))
        .send()
        .await
        .unwrap();
    let mut stream = stream_upstream_response_with_options(
        state,
        "sess-split".into(),
        "route-split".into(),
        "anthropic",
        resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await
    .into_body()
    .into_data_stream();

    let mut received_ok = Vec::new();
    let mut saw_err = false;
    while let Some(item) = stream.next().await {
        match item {
            Ok(b) => received_ok.extend_from_slice(&b),
            Err(_) => {
                saw_err = true;
                break;
            }
        }
    }
    assert!(saw_err);
    assert!(
        received_ok.is_empty(),
        "partial disallowed SSE chunk leaked {} bytes before tool validation",
        received_ok.len()
    );
}

#[tokio::test]
async fn mcp_relay_sse_mediates_requests_preserves_metadata_checks_401_nonloopback_and_gzip() {
    let backend = Router::new()
        .route(
            "/sse-good",
            get(|| async {
                let body = concat!(
                    "event: message\n",
                    "id: ev-42\n",
                    "retry: 1500\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n\n"
                );
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/sse-form-elicit",
            get(|| async {
                let body = "data: {\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"secret\"}}\n\n";
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/sse-gzip",
            get(|| async {
                (
                    StatusCode::OK,
                    [
                        ("content-type", "text/event-stream"),
                        ("content-encoding", "gzip"),
                    ],
                    vec![0x1f_u8, 0x8b, 0x08, 0x00],
                )
            }),
        )
        .route(
            "/non-utf8-json",
            post(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    vec![0xff_u8, 0xfe_u8, 0xfd_u8],
                )
            }),
        )
        .route(
            "/401-nonloopback",
            post(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    [(
                        "www-authenticate",
                        "Bearer resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\"",
                    )],
                    "{}",
                )
            }),
        );

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, backend).await;
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
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
    let base_route = RouteUpstream::parse(
        "srv",
        "mcp",
        &format!("http://127.0.0.1:{up_port}"),
        None,
        TenantHeaderPolicy::default(),
    )
    .unwrap();
    state
        .registry
        .lock()
        .await
        .register_session(build_session(token.clone(), base_route))
        .unwrap();

    let app = build_proxy_router(state);

    // 1. SSE preserves event/id/retry metadata cleanly.
    let good_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcp-relay/{token}/srv/sse-good"))
                .header("host", "127.0.0.1:18080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(good_sse.status(), StatusCode::OK);
    let good_bytes = axum::body::to_bytes(good_sse.into_body(), 16 * 1024)
        .await
        .unwrap();
    let good_str = std::str::from_utf8(&good_bytes).unwrap();
    assert!(good_str.contains("event: message\n"));
    assert!(good_str.contains("id: ev-42\n"));
    assert!(good_str.contains("retry: 1500\n"));

    // 2. Non-URL elicitation/create fails closed before emitting downstream.
    let form_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcp-relay/{token}/srv/sse-form-elicit"))
                .header("host", "127.0.0.1:18080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut form_stream = form_sse.into_body().into_data_stream();
    let mut leaked = Vec::new();
    let mut form_err = false;
    while let Some(item) = form_stream.next().await {
        match item {
            Ok(b) => leaked.extend_from_slice(&b),
            Err(_) => {
                form_err = true;
                break;
            }
        }
    }
    assert!(form_err && leaked.is_empty());

    // 3. Compressed SSE, non-UTF8 JSON, and non-loopback http:// 401 all fail closed.
    let gz_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcp-relay/{token}/srv/sse-gzip"))
                .header("host", "127.0.0.1:18080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(gz_sse.status(), StatusCode::FORBIDDEN);

    let bad_utf8 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv/non-utf8-json"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_utf8.status(), StatusCode::BAD_GATEWAY);

    let bad_401 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcp-relay/{token}/srv/401-nonloopback"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_401.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn p14_gemini_bedrock_responses_inspection_otlp_equals_and_tunnel_plaintext_work() {
    let scrubbed =
        redact_secret_tokens("token:c2VjcmV0== api_key:xyz= password:Zm9v= bearer:YWJjZA==");
    for secret in ["c2VjcmV0", "xyz", "Zm9v", "YWJjZA"] {
        assert!(
            !scrubbed.contains(secret),
            "leaked secret {secret} in {scrubbed}"
        );
    }
    assert!(scrubbed.contains("token:[REDACTED_TOKEN]"));

    let backend = Router::new()
        .route(
            "/v1beta/models/gemini-2.5:generateContent",
            post(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    "{\"ok\":true}",
                )
            }),
        )
        .route(
            "/model/anthropic.claude/converse",
            post(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    "{\"ok\":true}",
                )
            }),
        )
        .route(
            "/v1/responses",
            post(|| async {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    "{\"ok\":true}",
                )
            }),
        );
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, backend).await;
    });

    let rec = RecordingClient::new(Verdict::Allow);
    let attempts_handle = Arc::clone(&rec.attempts);
    let state = Arc::new(
        ProxyGatewayState::new(
            rec,
            18080,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let base_url = format!("http://127.0.0.1:{up_port}");
    let mut sess = build_session(
        token.clone(),
        RouteUpstream::parse(
            "gemini",
            "gemini",
            &base_url,
            None,
            TenantHeaderPolicy::default(),
        )
        .unwrap(),
    );
    sess.routes.insert(
        "bedrock".into(),
        RouteUpstream::parse(
            "bedrock",
            "bedrock",
            &base_url,
            None,
            TenantHeaderPolicy::default(),
        )
        .unwrap(),
    );
    sess.routes.insert(
        "responses".into(),
        RouteUpstream::parse(
            "responses",
            "responses",
            &base_url,
            None,
            TenantHeaderPolicy::default(),
        )
        .unwrap(),
    );
    sess.routes.insert(
        "anthropic".into(),
        RouteUpstream::parse(
            "anthropic",
            "anthropic",
            &base_url,
            None,
            TenantHeaderPolicy::default(),
        )
        .unwrap(),
    );
    state.registry.lock().await.register_session(sess).unwrap();
    let app = build_proxy_router(Arc::clone(&state));

    let gem_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/gemini/v1beta/models/gemini-2.5:generateContent"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"systemInstruction":{"parts":[{"text":"safe"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"lookup_doc"}]}]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(gem_resp.status(), StatusCode::OK);

    let bed_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/bedrock/model/anthropic.claude/converse"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"modelId":"anthropic.claude","messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"run_sql"}}]}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bed_resp.status(), StatusCode::OK);

    let oai_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/responses/v1/responses"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"gpt-5","instructions":"be concise","input":[{"role":"user","content":"hi"}]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oai_resp.status(), StatusCode::OK);

    let malformed_llm = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{token}/anthropic/v1/messages"))
                .header("host", "127.0.0.1:18080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"claude","#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_llm.status(), StatusCode::FORBIDDEN);

    let recorded = attempts_handle.lock().await;
    assert_eq!(recorded.len(), 3);
    assert!(
        recorded
            .iter()
            .all(|a| a.action_class == grdr_model::ActionClass::LlmRequest)
    );
    assert!(
        recorded[0].summary.contains("google_gemini") && recorded[0].summary.contains("tools=1")
    );
    assert!(
        recorded[1].summary.contains("aws_bedrock")
            && recorded[1].summary.contains("anthropic.claude")
            && recorded[1].summary.contains("tools=1")
    );
    assert!(
        recorded[2].summary.contains("openai_responses") && recorded[2].summary.contains("gpt-5")
    );

    let manifest = load_swg_coexistence_manifest(Profile::User).unwrap();
    let clean_swg = detect_enterprise_swg(&BTreeMap::new(), &[], None, &manifest);
    let non_tls = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::RejectWhenMitmRequired,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg: clean_swg,
            client_hello: None,
        },
        &manifest,
    );
    assert!(matches!(
        non_tls,
        MitmRoutingDecision::Deny(MitmDenyReason::NonTlsTrafficRequired, _)
    ));

    let socks_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Ok((sock, _)) = socks_listener.accept().await {
            let _ = handle_tunnel_connection(sock, socks_state, None).await;
        }
    });
    let mut s_client = TcpStream::connect(socks_addr).await.unwrap();
    s_client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method_sel = [0_u8; 2];
    s_client.read_exact(&mut method_sel).await.unwrap();
    assert_eq!(method_sel, [0x05, 0x02]);
    let mut auth_pkt = vec![0x01, 0x04, b'u', b's', b'e', b'r', token.len() as u8];
    auth_pkt.extend_from_slice(token.as_bytes());
    s_client.write_all(&auth_pkt).await.unwrap();
    let mut auth_ack = [0_u8; 2];
    s_client.read_exact(&mut auth_ack).await.unwrap();
    assert_eq!(auth_ack, [0x01, 0x00]);
    let bad_dom = b"user@evil.com/path";
    let mut req_pkt = vec![0x05, 0x01, 0x00, 0x03, bad_dom.len() as u8];
    req_pkt.extend_from_slice(bad_dom);
    req_pkt.extend_from_slice(&443_u16.to_be_bytes());
    s_client.write_all(&req_pkt).await.unwrap();
    let mut reply = [0_u8; 10];
    s_client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02);
}

#[tokio::test]
async fn cr_only_sse_tool_use_blocks_disallowed_and_forwards_allowed_without_differential() {
    let app = Router::new()
        .route(
            "/cr-deny",
            post(|| async {
                let body = concat!(
                    "event: content_block_start\r",
                    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"exec_shell\"}}\r\r",
                    "event: message_stop\r",
                    "data: {\"type\":\"message_stop\"}\r\r"
                );
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/cr-allow",
            post(|| async {
                let body = concat!(
                    "event: content_block_start\r",
                    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"read_doc\"}}\r\r",
                    "event: message_stop\r",
                    "data: {\"type\":\"message_stop\"}\r\r"
                );
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        );
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            FixedVerdictClient {
                verdict: Verdict::Allow,
            },
            18080,
            EgressGuardConfig::default(),
        )
        .unwrap(),
    );
    state
        .allowed_route_tools
        .lock()
        .await
        .insert("route-cr".into(), BTreeSet::from(["read_doc".to_string()]));

    let http = reqwest::Client::builder().no_proxy().build().unwrap();

    // 1. Disallowed CR-only '\r\r' tool_use must fail closed with zero leaked bytes.
    let deny_resp = http
        .post(format!("http://127.0.0.1:{port}/cr-deny"))
        .send()
        .await
        .unwrap();
    let mut deny_stream = stream_upstream_response_with_options(
        Arc::clone(&state),
        "sess-cr".into(),
        "route-cr".into(),
        "anthropic",
        deny_resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await
    .into_body()
    .into_data_stream();
    let mut leaked = Vec::new();
    let mut saw_err = false;
    while let Some(item) = deny_stream.next().await {
        match item {
            Ok(b) => leaked.extend_from_slice(&b),
            Err(_) => {
                saw_err = true;
                break;
            }
        }
    }
    assert!(saw_err);
    assert!(
        leaked.is_empty(),
        "CR-only disallowed SSE leaked {} bytes",
        leaked.len()
    );

    // 2. Allowed CR-only '\r\r' tool_use must flush cleanly without parser-differential false failure.
    let allow_resp = http
        .post(format!("http://127.0.0.1:{port}/cr-allow"))
        .send()
        .await
        .unwrap();
    let mut allow_stream = stream_upstream_response_with_options(
        state,
        "sess-cr".into(),
        "route-cr".into(),
        "anthropic",
        allow_resp,
        Duration::from_secs(2),
        1024 * 1024,
    )
    .await
    .into_body()
    .into_data_stream();
    let mut out = Vec::new();
    while let Some(item) = allow_stream.next().await {
        out.extend_from_slice(&item.unwrap());
    }
    let out_str = std::str::from_utf8(&out).unwrap();
    assert!(out_str.contains("read_doc"));
    assert!(out_str.contains("message_stop"));
}
