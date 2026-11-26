// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use futures_util::stream;
use jiff::Timestamp;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tower::ServiceExt;

use grdr_crypto::SigningKeypair;
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_mcp::decision::{AsyncDecisionSource, DecideFuture, IpcDaemonDecisionSource};
use grdr_mcp::http_upstream::HttpUpstreamConfig;
use grdr_mcp::oauth::{
    OAuthIssuerPinRegistry, TokenDigestRegistry, generate_pkce_s256, parse_rfc9728_metadata,
    parse_www_authenticate_step_up, verify_pkce_s256,
};
use grdr_mcp::revisions::{
    MCP_HEADER_PROTOCOL_VERSION, MCP_HEADER_SESSION_ID, parse_http_mcp_request,
};
use grdr_mcp::ssrf::{SsrfPolicy, resolve_and_vet_upstream};
use grdr_mcp::transport::{McpBrokerService, build_http_router, mediate_stdio_lines};
use grdr_mcp_proto::{JSONRPC_ERR_STEP_UP_OAUTH, McpMethod};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, SigningKeypairExt as _, Verdict};
use grdr_wire::floor_bin::{
    FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
};
use grdr_wire::peer_auth::Profile;

struct StaticAllowSource;

impl AsyncDecisionSource for StaticAllowSource {
    fn evaluate_attempt<'a>(&'a self, attempt: &'a ActionAttempt) -> DecideFuture<'a> {
        Box::pin(async move {
            let mut r = grdr_mcp::decision::synthetic_floor_receipt(
                attempt,
                Verdict::Allow,
                Some("allow.test"),
                "allowed",
            );
            r.next_step.clear();
            Ok(r)
        })
    }
}

#[test]
fn parse_http_mcp_request_preserves_evaluated_arguments() {
    let raw = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"query_sql","arguments":{"sql":"SELECT 1","limit":10,"nested":{"flag":true}}}}"#;
    let parsed = parse_http_mcp_request(raw).unwrap();
    assert_eq!(parsed.method, McpMethod::ToolsCall);
    assert_eq!(parsed.tool_name.as_deref(), Some("query_sql"));
    assert_eq!(parsed.target_hint.as_deref(), Some("SELECT 1"));
    assert_eq!(parsed.arguments["limit"], json!(10));
    assert_eq!(parsed.arguments["nested"]["flag"], json!(true));
}

#[tokio::test]
async fn ssrf_vetting_rejects_private_loopback_under_strict_policy() {
    assert!(
        resolve_and_vet_upstream("http://127.0.0.1:8080/mcp", SsrfPolicy::StrictPublicOnly)
            .await
            .is_err()
    );
    assert!(
        resolve_and_vet_upstream(
            "https://169.254.169.254/latest/meta-data",
            SsrfPolicy::StrictPublicOnly
        )
        .await
        .is_err()
    );
    assert!(
        resolve_and_vet_upstream("https://10.0.0.1/mcp", SsrfPolicy::StrictPublicOnly)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn http_upstream_fails_closed_without_config_and_proxies_post_sse_get_delete_and_401() {
    // 1. No upstream configured -> fails closed with 502 (not fake {"mediated":"allow"})
    let no_up = Arc::new(Mutex::new(McpBrokerService::new(
        StaticAllowSource,
        "srv-no-up",
        "agent-1",
        "sess-1",
    )));
    let app_no_up = build_http_router(no_up);
    let init = app_no_up
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let sid = init
        .headers()
        .get(MCP_HEADER_SESSION_ID)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let fail_call = app_no_up
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"k":1}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fail_call.status(), StatusCode::BAD_GATEWAY);

    // 2. Real upstream server handling POST SSE, POST 401 -> -32042, GET SSE, DELETE
    let deleted = Arc::new(Mutex::new(false));
    let del_flag = Arc::clone(&deleted);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = listener.local_addr().unwrap();
    let up_meta_hdr = format!(
        "Bearer resource_metadata=\"http://{up_addr}/.well-known/oauth-protected-resource\", scope=\"repo:read\""
    );
    let up_router = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |headers: axum::http::HeaderMap, axum::Json(v): axum::Json<Value>| {
            let meta_hdr = up_meta_hdr.clone();
            async move {
                assert!(headers.get("authorization").is_none());
                assert!(headers.get("mcp-session-id").is_none());
                if headers.get("x-force-401").is_some() || v["params"]["name"] == "need_auth" {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [("www-authenticate", meta_hdr)],
                        Body::empty(),
                    )
                        .into_response();
                }
                if v["params"]["name"] == "evil_401" {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [(
                            "www-authenticate",
                            r#"Bearer resource_metadata="http://169.254.169.254/latest", scope="repo:read""#.to_string(),
                        )],
                        Body::empty(),
                    )
                        .into_response();
                }
                if v["params"]["name"] == "stream_tool" {
                    let s = stream::iter(vec![
                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{\"ok\":true}}\n\n",
                        )),
                    ]);
                    return axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(Body::from_stream(s))
                        .unwrap();
                }
                (
                    StatusCode::OK,
                    axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": v["id"],
                        "result": { "args": v["params"]["arguments"] }
                    })),
                )
                    .into_response()
            }
        })
        .get(|| async {
            let s = stream::iter(vec![
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"data: {\"ping\":1}\n\n")),
            ]);
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(s))
                .unwrap()
        })
        .delete(move || {
            let del = Arc::clone(&del_flag);
            async move {
                *del.lock().await = true;
                StatusCode::NO_CONTENT
            }
        }),
    );
    let _srv = tokio::spawn(async move {
        let _ = axum::serve(listener, up_router).await;
    });

    let svc = Arc::new(Mutex::new(
        McpBrokerService::new(StaticAllowSource, "srv-real", "agent-1", "sess-1").with_upstream(
            HttpUpstreamConfig::new(
                format!("http://{up_addr}/mcp"),
                SsrfPolicy::AllowLoopbackTestOnly,
            ),
        ),
    ));
    let app = build_http_router(svc);
    let init2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let sid2 = init2
        .headers()
        .get(MCP_HEADER_SESSION_ID)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Preserved arguments arrive at upstream
    let ok_call = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid2)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .header("authorization", "Bearer secret-token-1")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"foo":"bar"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_call.status(), StatusCode::OK);
    let ok_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(ok_call.into_body(), 16_384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ok_json["result"]["args"]["foo"], json!("bar"));

    // Upstream 401 -> -32042 OAuth step-up
    let auth_call = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid2)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"need_auth","arguments":{}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let auth_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(auth_call.into_body(), 16_384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(auth_json["error"]["code"], json!(JSONRPC_ERR_STEP_UP_OAUTH));

    // Streaming POST SSE
    let sse_call = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid2)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"stream_tool","arguments":{}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        sse_call
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );

    // GET SSE stream
    let get_sse = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid2)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_sse.status(), StatusCode::OK);

    // DELETE propagates upstream
    let del_resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/mcp")
                .header("host", "127.0.0.1:18090")
                .header(MCP_HEADER_SESSION_ID, &sid2)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
    assert!(*deleted.lock().await);
}

#[test]
fn oauth_rfc9728_rfc8707_pkce_and_cross_server_token_reuse_work() {
    let pkce = generate_pkce_s256().unwrap();
    assert!(verify_pkce_s256(&pkce.code_verifier, &pkce.code_challenge));
    assert!(!verify_pkce_s256(
        "wrong-verifier-padded-to-43-chars-minimum-len",
        &pkce.code_challenge
    ));

    let meta = parse_rfc9728_metadata(
        r#"{"resource":"https://mcp.example.com/v1","authorization_servers":["https://auth.example.com"],"scopes_supported":["repo:read"]}"#,
        "https://mcp.example.com/v1",
        false,
    )
    .unwrap();
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
    assert!(
        parse_rfc9728_metadata(
            r#"{"resource":"https://evil.example.com","authorization_servers":["https://auth.example.com"]}"#,
            "https://mcp.example.com/v1",
            false
        )
        .is_err()
    );

    let mut pins = OAuthIssuerPinRegistry::new();
    pins.bind_or_verify("srv-a", &meta.resource, &meta.authorization_servers[0])
        .unwrap();
    assert!(
        pins.bind_or_verify("srv-a", &meta.resource, "https://hijacked-issuer.example")
            .is_err()
    );

    let mut tokens = TokenDigestRegistry::new();
    tokens.check_and_record_bearer("srv-a", "tok-abc").unwrap();
    tokens.check_and_record_bearer("srv-a", "tok-abc").unwrap();
    let reuse_err = tokens
        .check_and_record_bearer("srv-b", "tok-abc")
        .unwrap_err();
    assert!(reuse_err.to_string().contains("mcp.token-reuse"));

    let chall = parse_www_authenticate_step_up(
        r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="write""#,
    )
    .unwrap();
    assert_eq!(chall.scope, "write");
}

#[tokio::test]
async fn stdio_duplex_handles_concurrent_server_initiated_requests_without_deadlock() {
    let (client_in_tx, client_in_rx) = tokio::io::duplex(4096);
    let (client_out_tx, mut client_out_rx) = tokio::io::duplex(4096);
    let (child_in_tx, child_in_rx) = tokio::io::duplex(4096);
    let (mut child_out_tx, child_out_rx) = tokio::io::duplex(4096);

    let child_task = tokio::spawn(async move {
        let mut child_lines = BufReader::new(child_in_rx);
        let mut req = String::new();
        // Child initiates a roots/list request BEFORE reading client's next message
        child_out_tx
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"roots/list\",\"params\":{}}\n")
            .await
            .unwrap();
        child_out_tx.flush().await.unwrap();
        child_lines.read_line(&mut req).await.unwrap();
        child_out_tx
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n")
            .await
            .unwrap();
        child_out_tx.flush().await.unwrap();
        drop(child_out_tx);
    });

    let broker_task = tokio::spawn(async move {
        let mut svc = McpBrokerService::new(
            StaticAllowSource,
            "srv-duplex",
            "agent-duplex",
            "sess-duplex",
        )
        .with_progressive_tools(true);
        mediate_stdio_lines(
            &mut svc,
            BufReader::new(client_in_rx),
            client_out_tx,
            child_in_tx,
            BufReader::new(child_out_rx),
        )
        .await
        .unwrap();
    });

    let mut cw = client_in_tx;
    cw.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
        .await
        .unwrap();
    cw.flush().await.unwrap();
    drop(cw);

    tokio::time::timeout(Duration::from_secs(3), broker_task)
        .await
        .unwrap()
        .unwrap();
    child_task.await.unwrap();

    let mut out = String::new();
    client_out_rx.read_to_string(&mut out).await.unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[tokio::test]
async fn ipc_daemon_source_rejects_protected_override_and_evaluates_signed_floor() {
    assert!(
        IpcDaemonDecisionSource::new(
            Profile::Protected,
            Some("custom".to_string()),
            None,
            None,
            500
        )
        .is_err()
    );

    let dir_name = format!("grdr-mcp-floor-{}", uuid::Uuid::now_v7().simple());
    #[cfg(windows)]
    let base_dir = std::path::PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows\\Temp")),
    )
    .join(&dir_name);
    #[cfg(unix)]
    let base_dir = std::path::PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| std::env::var_os("HOME"))
            .unwrap_or_else(|| std::ffi::OsString::from("/var/tmp")),
    )
    .join(&dir_name);
    std::fs::create_dir_all(&base_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let keypair = SigningKeypair::generate().unwrap();
    let doc = FloorTableDocument {
        epoch: 1,
        expires_at_unix_s: Timestamp::now().as_second() + 3600,
        signer_key_id: keypair.key_id().to_string(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::McpCall,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor.mcp.deny".into(),
            pattern: "drop_table".into(),
            agents: vec![],
        }],
    };
    std::fs::write(
        base_dir.join("floor.bin"),
        encode_signed_floor_table(&doc, &keypair).unwrap(),
    )
    .unwrap();
    std::fs::write(
        base_dir.join("floor.pub"),
        format!("{}:{}", keypair.key_id(), keypair.public_key_b64()),
    )
    .unwrap();

    let ep = if cfg!(windows) {
        format!(
            r"\\.\pipe\grdr-mcp-offline-{}",
            uuid::Uuid::now_v7().simple()
        )
    } else {
        base_dir.join("missing.sock").to_string_lossy().into_owned()
    };
    let src =
        IpcDaemonDecisionSource::new(Profile::User, Some(ep), None, Some(base_dir.clone()), 200)
            .unwrap();
    let attempt = ActionAttempt {
        id: "att-mcp-1".into(),
        session_id: "s1".into(),
        device_id: "d1".into(),
        device_name: "h1".into(),
        agent_name: "mcp-agent".into(),
        action_class: ActionClass::McpCall,
        control_point: ControlPoint::McpBroker,
        target: "srv/drop_table".into(),
        summary: "mcp call".into(),
        timestamp: Timestamp::now(),
        ..Default::default()
    };
    let receipt = src.evaluate_attempt(&attempt).await.unwrap();
    assert_eq!(receipt.verdict, Verdict::Deny);
    assert_eq!(receipt.rule_id.as_deref(), Some("floor.mcp.deny"));
    let expected_digest =
        grdr_core::policy::compute_receipt_digest(&grdr_core::policy::ReceiptDigestInput {
            attempt_id: &receipt.attempt_id,
            session_id: &receipt.session_id,
            agent_name: &receipt.agent_name,
            action_class: receipt.action_class,
            target: &receipt.target,
            verdict: receipt.verdict,
            rule_id: receipt.rule_id.as_deref(),
            decided_at: receipt.decided_at,
        });
    assert_eq!(receipt.receipt_digest, expected_digest);
    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn ssrf_and_oauth_pinning_enforce_strict_bounds_and_non_tool_jsonrpc_errors() {
    // Plain HTTP to public IP must fail even under AllowLoopbackTestOnly.
    assert!(
        resolve_and_vet_upstream("http://1.1.1.1/mcp", SsrfPolicy::AllowLoopbackTestOnly)
            .await
            .is_err()
    );
    // NAT64 / AWS IMDSv6 / bracketed-tail rejection.
    assert!(
        resolve_and_vet_upstream(
            "https://[fd00:ec2::254]/latest",
            SsrfPolicy::StrictPublicOnly
        )
        .await
        .is_err()
    );
    assert!(
        resolve_and_vet_upstream("https://[::1]evil/mcp", SsrfPolicy::StrictPublicOnly)
            .await
            .is_err()
    );

    // Loopback [::1] OAuth normalization + query/fragment rejection.
    let meta_v6 = parse_rfc9728_metadata(
        r#"{"resource":"http://[::1]:8080/mcp","authorization_servers":["http://[::1]:8081/auth"]}"#,
        "http://[::1]:8080/mcp",
        true,
    )
    .unwrap();
    assert_eq!(meta_v6.resource, "http://[::1]:8080/mcp");
    assert!(
        parse_rfc9728_metadata(
            r#"{"resource":"https://mcp.example.com/mcp?x=1","authorization_servers":["https://auth.example.com"]}"#,
            "https://mcp.example.com/mcp?x=1",
            false,
        )
        .is_err()
    );

    // RFC 9110 WWW-Authenticate quoted comma support.
    let chall = parse_www_authenticate_step_up(
        r#"Bearer scope="repo:read,write", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource""#,
    )
    .unwrap();
    assert_eq!(chall.scope, "repo:read,write");

    // Offline floor denies unmatched FileRead (no essentials_pack() bypass) & non-tools/call emits JSON-RPC error.
    let mut svc = McpBrokerService::new(
        IpcDaemonDecisionSource::new(
            Profile::User,
            Some(if cfg!(windows) {
                r"\\.\pipe\grdr-mcp-nonexistent-floor".into()
            } else {
                "/run/guardrails-test/nonexistent-grdr-mcp.sock".into()
            }),
            None,
            None,
            100,
        )
        .unwrap(),
        "srv-strict",
        "agent-1",
        "sess-1",
    )
    .with_progressive_tools(true);
    let key = SigningKeypair::generate().unwrap();
    let mut table = grdr_core::compile::compile_floor_table(&[], Timestamp::now());
    key.sign_floor_table(&mut table).unwrap();
    svc.floor = Some((table, vec![key.public_info()]));

    let res_read = svc
        .handle_jsonrpc_request(
            r#"{"jsonrpc":"2.0","id":77,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}"#,
            grdr_mcp::revisions::McpProtocolRevision::Rev2025_11_25,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(res_read.result.is_none());
    assert_eq!(res_read.error.unwrap().code, -32001);

    // Progressive tools never silently pin server manifest.
    let prog_call = svc
        .handle_jsonrpc_request(
            r#"{"jsonrpc":"2.0","id":78,"method":"tools/call","params":{"name":"describe_schema","arguments":{}}}"#,
            grdr_mcp::revisions::McpProtocolRevision::Rev2025_11_25,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!svc.pins.is_manifest_pinned("srv-strict"));
    assert!(prog_call.result.is_some());
}

struct StaticDenySource;

impl AsyncDecisionSource for StaticDenySource {
    fn evaluate_attempt<'a>(&'a self, attempt: &'a ActionAttempt) -> DecideFuture<'a> {
        Box::pin(async move {
            let mut r = grdr_mcp::decision::synthetic_floor_receipt(
                attempt,
                Verdict::Deny,
                Some("deny.test"),
                "denied by policy",
            );
            r.next_step.clear();
            Ok(r)
        })
    }
}

#[tokio::test]
async fn http_sse_mediates_server_requests_and_enforces_identity_encoding() {
    use futures_util::StreamExt;
    use tokio::net::TcpListener;

    let seen_accept_encoding = Arc::new(Mutex::new(Vec::<String>::new()));
    let enc_clone = Arc::clone(&seen_accept_encoding);
    let upstream_app = axum::Router::new()
        .route(
            "/form-elicit",
            axum::routing::get(|| async {
                let body = "data: {\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"token?\"}}\n\n";
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/sampling",
            axum::routing::get(|| async {
                let body = "data: {\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"sampling/createMessage\",\"params\":{\"messages\":[]}}\n\n";
                (StatusCode::OK, [("content-type", "text/event-stream")], body)
            }),
        )
        .route(
            "/gzip-post",
            axum::routing::post(move |hdrs: axum::http::HeaderMap| {
                let cap = Arc::clone(&enc_clone);
                async move {
                    if let Some(v) = hdrs.get("accept-encoding").and_then(|v| v.to_str().ok()) {
                        cap.lock().await.push(v.to_owned());
                    }
                    (
                        StatusCode::OK,
                        [
                            ("content-type", "application/json"),
                            ("content-encoding", "gzip"),
                        ],
                        vec![0x1f_u8, 0x8b, 0x08, 0x00],
                    )
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_app).await;
    });

    // 1. Form-mode elicitation/create over GET /mcp SSE fails closed before queueing downstream.
    let mut elicit_raw = McpBrokerService::new(StaticAllowSource, "srv-sse", "agent-1", "sess-1")
        .with_upstream(HttpUpstreamConfig::new(
            format!("http://127.0.0.1:{up_port}/form-elicit"),
            SsrfPolicy::AllowLoopbackTestOnly,
        ));
    let elicit_sid = elicit_raw
        .sessions
        .issue_session(grdr_mcp::revisions::McpProtocolRevision::Rev2025_11_25)
        .unwrap()
        .session_id;
    let elicit_router = build_http_router(Arc::new(Mutex::new(elicit_raw)));
    let elicit_resp = elicit_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header(MCP_HEADER_SESSION_ID, &elicit_sid)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(elicit_resp.status(), StatusCode::OK);
    let mut elicit_stream = elicit_resp.into_body().into_data_stream();
    let mut elicit_leaked = Vec::new();
    let mut elicit_err = false;
    while let Some(item) = elicit_stream.next().await {
        match item {
            Ok(b) => elicit_leaked.extend_from_slice(&b),
            Err(_) => {
                elicit_err = true;
                break;
            }
        }
    }
    assert!(elicit_err && elicit_leaked.is_empty());

    // 2. Denied server-initiated sampling/createMessage in SSE aborts before queueing.
    let mut samp_raw = McpBrokerService::new(StaticDenySource, "srv-samp", "agent-1", "sess-1")
        .with_upstream(HttpUpstreamConfig::new(
            format!("http://127.0.0.1:{up_port}/sampling"),
            SsrfPolicy::AllowLoopbackTestOnly,
        ));
    let samp_sid = samp_raw
        .sessions
        .issue_session(grdr_mcp::revisions::McpProtocolRevision::Rev2025_11_25)
        .unwrap()
        .session_id;
    let samp_router = build_http_router(Arc::new(Mutex::new(samp_raw)));
    let samp_resp = samp_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header(MCP_HEADER_SESSION_ID, &samp_sid)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(samp_resp.status(), StatusCode::OK);
    let mut samp_stream = samp_resp.into_body().into_data_stream();
    let mut samp_leaked = Vec::new();
    let mut samp_err = false;
    while let Some(item) = samp_stream.next().await {
        match item {
            Ok(b) => samp_leaked.extend_from_slice(&b),
            Err(_) => {
                samp_err = true;
                break;
            }
        }
    }
    assert!(samp_err && samp_leaked.is_empty());

    // 3. Outbound sets accept-encoding: identity and rejects non-identity upstream response with 403.
    let mut gz_raw = McpBrokerService::new(StaticAllowSource, "srv-gz", "agent-1", "sess-1")
        .with_upstream(HttpUpstreamConfig::new(
            format!("http://127.0.0.1:{up_port}/gzip-post"),
            SsrfPolicy::AllowLoopbackTestOnly,
        ));
    let gz_sid = gz_raw
        .sessions
        .issue_session(grdr_mcp::revisions::McpProtocolRevision::Rev2025_11_25)
        .unwrap()
        .session_id;
    let gz_router = build_http_router(Arc::new(Mutex::new(gz_raw)));
    let gz_resp = gz_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header(MCP_HEADER_SESSION_ID, &gz_sid)
                .header(MCP_HEADER_PROTOCOL_VERSION, "2025-11-25")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(gz_resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen_accept_encoding.lock().await.as_slice(), &["identity"]);
}
