// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::{SignedDuration, Timestamp};
use serde_json::Value;

use grdr_acp::acs_hmac::{sign_owasp_acs_jsonrpc, verify_owasp_acs_jsonrpc};
use grdr_acp::adapters::{AcpProtocolDialect, evaluate_dialect_request};
use grdr_acp::conductor::{AcpConductorConfig, run_bidirectional_stdio_conductor};
use grdr_acp::envelope::{AcpWireRequest, AcpWireResponse, AcpWireServer};
use grdr_acp::{AcpError, DecisionClient, EvalFuture, PeerDaemonClient};
use grdr_core::policy::ReceiptDigestInput;
use grdr_core::policy::compute_receipt_digest;
use grdr_crypto::SigningKeypair;
use grdr_model::{ActionAttempt, ActionClass, DecisionReceipt, SigningKeypairExt as _, Verdict};
use grdr_wire::{ReplayWindow, decode_frame, encode_frame, generate_nonce, sign_envelope};

struct FixedVerdictClient {
    verdict: Verdict,
    reason: String,
}

struct FailingDaemonClient;

impl DecisionClient for FixedVerdictClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> EvalFuture<'a> {
        Box::pin(async move {
            let now = attempt.timestamp;
            let receipt_id = "rcp-test-1".to_string();
            let digest = compute_receipt_digest(&ReceiptDigestInput {
                attempt_id: &attempt.id,
                session_id: &attempt.session_id,
                agent_name: &attempt.agent_name,
                action_class: attempt.action_class,
                target: &attempt.target,
                verdict: self.verdict,
                rule_id: Some("test.rule"),
                decided_at: now,
            });
            Ok(DecisionReceipt {
                receipt_id,
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: attempt.control_point,
                target: attempt.target.clone(),
                verdict: self.verdict,
                would_be: None,
                rule_id: Some("test.rule".into()),
                pack_id: Some("test-pack".into()),
                mode_applied: None,
                grant_id: None,
                reason: self.reason.clone(),
                next_step: "proceed".into(),
                receipt_digest: digest,
                decided_at: now,
                key_id: None,
                signature: None,
                signature_verified: None,
            })
        })
    }
}

impl DecisionClient for FailingDaemonClient {
    fn decide<'a>(&'a self, _attempt: &'a ActionAttempt) -> EvalFuture<'a> {
        Box::pin(async move { Err(AcpError::DaemonUnavailable("connection refused".into())) })
    }
}

#[tokio::test]
async fn evaluates_all_three_dialects_and_fails_closed_on_daemon_outage() {
    let now = Timestamp::now();
    let allow_client = FixedVerdictClient {
        verdict: Verdict::Allow,
        reason: "allowed by policy".into(),
    };
    let step_up_client = FixedVerdictClient {
        verdict: Verdict::StepUp,
        reason: "approval required".into(),
    };

    let owasp_req = serde_json::json!({
        "spec_version": "0.1.4",
        "request_id": "acs-1",
        "session_id": "sess-1",
        "agent_name": "claude-code",
        "hook_point": "pre_tool",
        "action_kind": "exec",
        "target": "cargo test"
    });
    let owasp_allow =
        evaluate_dialect_request(AcpProtocolDialect::OwaspAcs, &owasp_req, &allow_client, now)
            .await;
    assert_eq!(
        owasp_allow.get("verdict").and_then(Value::as_str),
        Some("allow")
    );

    let owasp_step = evaluate_dialect_request(
        AcpProtocolDialect::OwaspAcs,
        &owasp_req,
        &step_up_client,
        now,
    )
    .await;
    assert_eq!(
        owasp_step.get("verdict").and_then(Value::as_str),
        Some("require_approval")
    );

    let ms_req = serde_json::json!({
        "protocol": "0.1.0-beta.3",
        "hook_id": "hook-1",
        "session_id": "sess-1",
        "agent_name": "copilot",
        "event": "pre_tool_use",
        "tool_name": "read_file",
        "action_kind": "file_read",
        "target": "README.md"
    });
    let ms_fail = evaluate_dialect_request(
        AcpProtocolDialect::MicrosoftAgentHooks,
        &ms_req,
        &FailingDaemonClient,
        now,
    )
    .await;
    assert_eq!(
        ms_fail.get("decision").and_then(Value::as_str),
        Some("block")
    );

    let acp_req = serde_json::json!({
        "acp_version": "1.30.0",
        "call_id": "acp-9",
        "session_id": "sess-2",
        "conductor_id": "conductor-a",
        "capability": "shell",
        "target": "git status"
    });
    let acp_ok = evaluate_dialect_request(
        AcpProtocolDialect::AcpConductor,
        &acp_req,
        &allow_client,
        now,
    )
    .await;
    assert_eq!(acp_ok.get("verdict").and_then(Value::as_str), Some("allow"));
}

#[tokio::test]
async fn rejects_unsupported_versions_forged_signatures_replays_and_skew() {
    let host_key = SigningKeypair::generate().unwrap();
    let peer_key = SigningKeypair::generate().unwrap();
    let rogue_key = SigningKeypair::generate().unwrap();
    let client = FixedVerdictClient {
        verdict: Verdict::Allow,
        reason: "ok".into(),
    };
    let mut server = AcpWireServer::new(host_key, vec![peer_key.public_info()], 30, client);
    let host_pub = server.host_public_info();
    let now = Timestamp::now();

    let payload = AcpWireRequest {
        dialect: AcpProtocolDialect::OwaspAcs,
        body: serde_json::json!({
            "spec_version": "0.1.0",
            "request_id": "acs-wire-1",
            "session_id": "sess-wire",
            "agent_name": "agent-a",
            "hook_point": "pre_tool",
            "target": "ls"
        }),
    };

    let nonce = generate_nonce().unwrap();
    let env = sign_envelope(&peer_key, nonce, now, payload.clone()).unwrap();
    let frame = encode_frame(&env).unwrap();
    let resp_frame = server.handle_frame_bytes(&frame, now).await.unwrap();
    let (resp_env, _) = decode_frame::<AcpWireResponse>(&resp_frame).unwrap();
    let mut replay = ReplayWindow::new(64, 30);
    replay
        .verify_and_record(&resp_env, &[host_pub], now)
        .unwrap();
    assert!(resp_env.payload.accepted);

    // Replayed nonce rejected.
    assert!(matches!(
        server.handle_frame_bytes(&frame, now).await,
        Err(AcpError::ReplayOrSkew(_))
    ));

    // Timestamp outside 30s skew rejected.
    let stale_nonce = generate_nonce().unwrap();
    let stale_ts = now.saturating_sub(SignedDuration::from_secs(120)).unwrap();
    let stale_env = sign_envelope(&peer_key, stale_nonce, stale_ts, payload.clone()).unwrap();
    let stale_frame = encode_frame(&stale_env).unwrap();
    assert!(matches!(
        server.handle_frame_bytes(&stale_frame, now).await,
        Err(AcpError::ReplayOrSkew(_))
    ));

    // Untrusted signer rejected.
    let rogue_nonce = generate_nonce().unwrap();
    let rogue_env = sign_envelope(&rogue_key, rogue_nonce, now, payload).unwrap();
    let rogue_frame = encode_frame(&rogue_env).unwrap();
    assert!(matches!(
        server.handle_frame_bytes(&rogue_frame, now).await,
        Err(AcpError::SignatureInvalid(_))
    ));

    // Unsupported dialect version fails closed with deny verdict.
    let bad_ver = AcpWireRequest {
        dialect: AcpProtocolDialect::AcpConductor,
        body: serde_json::json!({
            "acp_version": "99.0.0",
            "call_id": "bad",
            "session_id": "sess",
            "conductor_id": "c",
            "capability": "exec",
            "target": "ls"
        }),
    };
    let bad_ver_nonce = generate_nonce().unwrap();
    let bad_ver_env = sign_envelope(&peer_key, bad_ver_nonce, now, bad_ver).unwrap();
    let bad_ver_frame = encode_frame(&bad_ver_env).unwrap();
    let bad_ver_resp_frame = server
        .handle_frame_bytes(&bad_ver_frame, now)
        .await
        .unwrap();
    let (bad_ver_resp, _) = decode_frame::<AcpWireResponse>(&bad_ver_resp_frame).unwrap();
    assert!(!bad_ver_resp.payload.accepted);
    assert_eq!(
        bad_ver_resp
            .payload
            .body
            .get("verdict")
            .and_then(Value::as_str),
        Some("deny")
    );

    // Protected profile rejects endpoint and floor directory overrides.
    assert!(
        PeerDaemonClient::new(
            grdr_wire::peer_auth::Profile::Protected,
            Some("custom-override".to_string()),
            None,
            500
        )
        .is_err()
    );
    assert!(
        PeerDaemonClient::new(
            grdr_wire::peer_auth::Profile::Protected,
            None,
            Some(std::path::PathBuf::from("/tmp/evil-floor")),
            500
        )
        .is_err()
    );
}

#[tokio::test]
async fn serve_stream_validates_10_byte_wire_header_and_no_tool_downgrade() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert_eq!(
        grdr_acp::classify_action_kind("", "bash_read_env"),
        grdr_model::ActionClass::Exec
    );
    assert_eq!(
        grdr_acp::classify_action_kind("execute", "custom_tool"),
        grdr_model::ActionClass::Exec
    );

    let host_key = SigningKeypair::generate().unwrap();
    let peer_key = SigningKeypair::generate().unwrap();
    let client = FixedVerdictClient {
        verdict: Verdict::Allow,
        reason: "ok".into(),
    };
    let mut server = AcpWireServer::new(host_key, vec![peer_key.public_info()], 60, client);
    let host_pub = server.host_public_info();

    let (mut client_tx, server_rx) = tokio::io::duplex(4096);
    let (server_tx, mut client_rx) = tokio::io::duplex(4096);
    let srv = tokio::spawn(async move { server.serve_stream(server_rx, server_tx).await.unwrap() });

    let now = Timestamp::now();
    let payload = AcpWireRequest {
        dialect: AcpProtocolDialect::MicrosoftAgentHooks,
        body: serde_json::json!({
            "protocol": "0.1.0-beta.3",
            "hook_id": "hook-stream-1",
            "session_id": "sess-stream",
            "agent_name": "agent-stream",
            "event": "pre_tool_use",
            "tool_name": "bash_read_env",
            "target": "env"
        }),
    };
    let nonce = generate_nonce().unwrap();
    let env = sign_envelope(&peer_key, nonce, now, payload).unwrap();
    let frame = encode_frame(&env).unwrap();
    client_tx.write_all(&frame).await.unwrap();
    client_tx.flush().await.unwrap();
    drop(client_tx);

    let mut resp_bytes = Vec::new();
    client_rx.read_to_end(&mut resp_bytes).await.unwrap();
    srv.await.unwrap();

    let (resp_env, consumed) = decode_frame::<AcpWireResponse>(&resp_bytes).unwrap();
    assert_eq!(consumed, resp_bytes.len());
    let mut replay = ReplayWindow::new(16, 60);
    replay
        .verify_and_record(&resp_env, &[host_pub], now)
        .unwrap();
    assert!(resp_env.payload.accepted);
}

#[tokio::test]
async fn bidirectional_stdio_conductor_handles_acp_capabilities_and_acs_hmac() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;

    let mut hmac_key = vec![0_u8; 32];
    grdr_crypto::fill_random(&mut hmac_key).unwrap();
    let now_s = Timestamp::now().as_second();
    let nonce_acs = generate_nonce().unwrap();
    let nonce_fs = generate_nonce().unwrap();
    let signed_acs = sign_owasp_acs_jsonrpc(
        serde_json::json!(99),
        "acs/evaluate",
        serde_json::json!({ "tool": "read_file", "target": "README.md", "action": "file_read" }),
        &nonce_acs,
        now_s,
        &hmac_key,
    )
    .unwrap();
    let signed_fs = sign_owasp_acs_jsonrpc(
        serde_json::json!(100),
        "fs/read_text_file",
        serde_json::json!({ "path": "src/main.rs" }),
        &nonce_fs,
        now_s,
        &hmac_key,
    )
    .unwrap();
    let mut forged_acs = signed_acs.clone();
    forged_acs.nonce = generate_nonce().unwrap();

    // 1. Local stdio mode (acs_hmac_key: None) allows valid confined paths and rejects escapes/spoofing.
    let local_lines = [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":3,"method":"fs/write_text_file","params":{"path":"src/out.rs","content":"fn main(){}"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":4,"method":"terminal/create","params":{"command":"cargo","args":["check"],"env":{"RUST_LOG":"info"}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":5,"method":"session/request_permission","params":{"toolCall":{"kind":"execute","title":"run cargo"},"options":[{"kind":"allow_once","optionId":"allow_once"},{"kind":"reject_once","optionId":"reject_once"}]}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":6,"method":"fs/read_text_file","params":{"path":"../etc/passwd"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":7,"method":"terminal/create","params":{"command":"cargo","args":[123]}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":8,"method":"session/request_permission","params":{"toolCall":{"kind":"execute","title":"spoof"},"options":[{"kind":"reject_once","optionId":"allow_once"},{"kind":"allow_once","optionId":"real_allow"}]}}"#.to_string(),
    ]
    .join("\n")
        + "\n";

    let allow_client = Arc::new(FixedVerdictClient {
        verdict: Verdict::Allow,
        reason: "ok".into(),
    });
    let (mut in_tx, in_rx) = tokio::io::duplex(8192);
    let (out_tx, mut out_rx) = tokio::io::duplex(8192);
    let allow_cl = Arc::clone(&allow_client);
    let run = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(allow_cl, AcpConductorConfig::default(), in_rx, out_tx)
            .await
            .unwrap()
    });
    in_tx.write_all(local_lines.as_bytes()).await.unwrap();
    drop(in_tx);
    run.await.unwrap();

    let mut out_buf = String::new();
    out_rx.read_to_string(&mut out_buf).await.unwrap();
    let responses: Vec<Value> = out_buf
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 8);
    let perm_ok = responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(5)))
        .unwrap();
    assert_eq!(
        perm_ok["result"]["outcome"]["optionId"].as_str(),
        Some("allow_once")
    );
    let traversal_err = responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(6)))
        .unwrap();
    assert!(traversal_err.get("error").is_some());
    let bad_args_err = responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(7)))
        .unwrap();
    assert!(bad_args_err.get("error").is_some());
    let kind_only = responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(8)))
        .unwrap();
    assert_eq!(
        kind_only["result"]["outcome"]["optionId"].as_str(),
        Some("real_allow")
    );

    // 2. HMAC-configured mode requires valid ACS HMAC on sensitive ACP methods too.
    let hmac_lines = [
        r#"{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}"#
            .to_string(),
        serde_json::to_string(&signed_fs).unwrap(),
        serde_json::to_string(&signed_acs).unwrap(),
        serde_json::to_string(&forged_acs).unwrap(),
        serde_json::to_string(&signed_acs).unwrap(),
    ]
    .join("\n")
        + "\n";
    let cfg = AcpConductorConfig {
        acs_hmac_key: Some(Zeroizing::new(hmac_key.clone())),
        ..AcpConductorConfig::default()
    };
    let (mut in_hmac, in_hmac_rx) = tokio::io::duplex(8192);
    let (out_hmac_tx, mut out_hmac_rx) = tokio::io::duplex(8192);
    let run_hmac = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(allow_client, cfg, in_hmac_rx, out_hmac_tx)
            .await
            .unwrap()
    });
    in_hmac.write_all(hmac_lines.as_bytes()).await.unwrap();
    drop(in_hmac);
    run_hmac.await.unwrap();
    let mut hmac_out_buf = String::new();
    out_hmac_rx.read_to_string(&mut hmac_out_buf).await.unwrap();
    let hmac_responses: Vec<Value> = hmac_out_buf
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(hmac_responses.len(), 5);
    let unsigned_fs = hmac_responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(2)))
        .unwrap();
    assert!(unsigned_fs.get("error").is_some());
    let verified_fs = hmac_responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(100)))
        .unwrap();
    assert_eq!(verified_fs["result"]["allowed"].as_bool(), Some(true));
    let acs_ok = hmac_responses
        .iter()
        .find(|v| v.get("id") == Some(&serde_json::json!(99)) && v.get("result").is_some())
        .unwrap();
    assert_eq!(acs_ok["result"]["verified"].as_bool(), Some(true));
    let acs_replay_or_tamper = hmac_responses
        .iter()
        .filter(|v| v.get("id") == Some(&serde_json::json!(99)) && v.get("error").is_some())
        .count();
    assert_eq!(acs_replay_or_tamper, 2);

    // 3. StepUp / DaemonUnavailable MUST enforce reject_once on session/request_permission
    let stepup_client = Arc::new(FixedVerdictClient {
        verdict: Verdict::StepUp,
        reason: "confirm".into(),
    });
    let (mut in_tx2, in_rx2) = tokio::io::duplex(4096);
    let (out_tx2, mut out_rx2) = tokio::io::duplex(4096);
    let run2 = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            stepup_client,
            AcpConductorConfig::default(),
            in_rx2,
            out_tx2,
        )
        .await
        .unwrap()
    });
    in_tx2
        .write_all(
            br#"{"jsonrpc":"2.0","id":7,"method":"session/request_permission","params":{"toolCall":{"kind":"execute","title":"rm -rf"},"options":[{"kind":"allow_once","optionId":"allow_once"},{"kind":"reject_once","optionId":"reject_once"}]}}
"#,
        )
        .await
        .unwrap();
    drop(in_tx2);
    run2.await.unwrap();
    let mut out_buf2 = String::new();
    out_rx2.read_to_string(&mut out_buf2).await.unwrap();
    let perm_deny: Value = serde_json::from_str(out_buf2.trim()).unwrap();
    assert_eq!(
        perm_deny["result"]["outcome"]["optionId"].as_str(),
        Some("reject_once")
    );

    // 4. Direct replay + eviction floor + short-key rejection checks
    let nonce_short = generate_nonce().unwrap();
    let mut short_key = vec![0_u8; 8];
    grdr_crypto::fill_random(&mut short_key).unwrap();
    assert!(
        sign_owasp_acs_jsonrpc(
            serde_json::json!(1),
            "acs/evaluate",
            serde_json::json!({}),
            &nonce_short,
            now_s,
            &short_key,
        )
        .is_err()
    );
    let mut direct_replay = grdr_acp::acs_hmac::AcsReplayGuard::new(16, 60);
    verify_owasp_acs_jsonrpc(&signed_acs, &hmac_key, &mut direct_replay, now_s).unwrap();
    assert!(verify_owasp_acs_jsonrpc(&signed_acs, &hmac_key, &mut direct_replay, now_s).is_err());
    for i in 0..20 {
        let step_nonce = format!("{}-{i}", generate_nonce().unwrap());
        direct_replay
            .record_or_reject(&step_nonce, now_s + i, now_s + 20)
            .unwrap();
    }
    let evicted_nonce = generate_nonce().unwrap();
    assert!(
        direct_replay
            .record_or_reject(&evicted_nonce, now_s, now_s + 20)
            .is_err()
    );

    // 5. Poisoned reject optionId containing "allow" must fall back to outcome=cancelled.
    let deny_client = Arc::new(FixedVerdictClient {
        verdict: Verdict::Deny,
        reason: "blocked".into(),
    });
    let (mut in_tx3, in_rx3) = tokio::io::duplex(4096);
    let (out_tx3, mut out_rx3) = tokio::io::duplex(4096);
    let run3 = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            deny_client,
            AcpConductorConfig::default(),
            in_rx3,
            out_tx3,
        )
        .await
        .unwrap()
    });
    in_tx3
        .write_all(
            br#"{"jsonrpc":"2.0","id":8,"method":"session/request_permission","params":{"toolCall":{"kind":"execute","title":"rm -rf"},"options":[{"kind":"allow_once","optionId":"allow_once"},{"kind":"reject_once","optionId":"allow_always"}]}}
"#,
        )
        .await
        .unwrap();
    drop(in_tx3);
    run3.await.unwrap();
    let mut out_buf3 = String::new();
    out_rx3.read_to_string(&mut out_buf3).await.unwrap();
    let perm_cancel: Value = serde_json::from_str(out_buf3.trim()).unwrap();
    assert_eq!(
        perm_cancel["result"]["outcome"]["outcome"].as_str(),
        Some("cancelled")
    );
}

#[tokio::test]
async fn peer_daemon_client_performs_peer_verified_ipc_and_signed_floor_fallback() {
    use grdr_fastpath::{FastActionClass, FastVerdict};
    use grdr_wire::floor_bin::{
        FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
    };

    let mut attempt = grdr_acp::build_attempt(
        &grdr_acp::NormalizedControlCall {
            request_id: "req-ipc-1".into(),
            spec_version: "1.0".into(),
            session_id: "sess-1".into(),
            agent_name: "acp-agent".into(),
            action_class: grdr_model::ActionClass::Exec,
            target: "rm -rf /tmp/bad".into(),
            summary: "test".into(),
        },
        Timestamp::now(),
    );

    // 1. Offline daemon + verified signed floor fallback denies matching dangerous command
    let dir_name = format!("grdr-acp-floor-{}", uuid::Uuid::now_v7().simple());
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
            action_class: FastActionClass::Exec,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor.deny-rm".into(),
            pattern: "rm -rf".into(),
            agents: vec![],
        }],
    };
    let floor_bytes = encode_signed_floor_table(&doc, &keypair).unwrap();
    std::fs::write(base_dir.join("floor.bin"), floor_bytes).unwrap();
    std::fs::write(
        base_dir.join("floor.pub"),
        format!("{}:{}", keypair.key_id(), keypair.public_key_b64()),
    )
    .unwrap();
    let offline_endpoint = if cfg!(windows) {
        format!(
            r"\\.\pipe\grdr-test-offline-{}",
            uuid::Uuid::now_v7().simple()
        )
    } else {
        base_dir.join("missing.sock").to_string_lossy().into_owned()
    };
    let client = PeerDaemonClient::new(
        grdr_wire::peer_auth::Profile::User,
        Some(offline_endpoint),
        Some(base_dir.clone()),
        300,
    )
    .unwrap();
    let receipt = client.decide(&attempt).await.unwrap();
    assert_eq!(receipt.verdict, Verdict::Deny);
    assert_eq!(receipt.rule_id.as_deref(), Some("floor.deny-rm"));
    let expected_floor_digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict: receipt.verdict,
        rule_id: receipt.rule_id.as_deref(),
        decided_at: receipt.decided_at,
    });
    assert_eq!(receipt.receipt_digest, expected_floor_digest);

    // 2. Live peer-verified IPC Decide server roundtrip
    let live_endpoint = if cfg!(windows) {
        format!(r"\\.\pipe\grdr-test-acp-{}", uuid::Uuid::now_v7().simple())
    } else {
        base_dir.join("decide.sock").to_string_lossy().into_owned()
    };
    let ep_srv = live_endpoint.clone();
    let srv_handle = std::thread::spawn(move || serve_one_decide_ipc(&ep_srv));
    std::thread::sleep(std::time::Duration::from_millis(60));
    attempt.id = "att-live-ipc-1".into();
    let live_client = PeerDaemonClient::new(
        grdr_wire::peer_auth::Profile::User,
        Some(live_endpoint),
        Some(base_dir.clone()),
        1_500,
    )
    .unwrap();
    let live_receipt = live_client.decide(&attempt).await.unwrap();
    assert_eq!(live_receipt.verdict, Verdict::Allow);
    assert_eq!(live_receipt.rule_id.as_deref(), Some("live.ipc.allow"));
    let expected_live_digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict: live_receipt.verdict,
        rule_id: live_receipt.rule_id.as_deref(),
        decided_at: live_receipt.decided_at,
    });
    assert_eq!(live_receipt.receipt_digest, expected_live_digest);
    srv_handle.join().unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&base_dir);
}

#[cfg(windows)]
fn serve_one_decide_ipc(pipe_name: &str) -> Result<(), String> {
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor;
    use grdr_wire::frame::{WireFrame, WirePayload};
    use grdr_wire::messages::{
        DecideVerdictFrame, EndpointServiceKind, HandoverStage, WireVerdict,
    };
    use grdr_wire::peer_auth::{
        Evidence, OsPeerClaims, Profile, Refusal, ServerIdentityPolicy, accept_deferred_windows,
    };

    let sid = grdr_peer_os::win_peer::current_process_sid().map_err(|e| e.to_string())?;
    let sddl = format!("D:(A;;GA;;;{sid})");
    let mut acc = WindowsNamedPipeAcceptor::bind(pipe_name, &sddl).map_err(|e| e.to_string())?;
    let stream = acc
        .accept(std::time::Duration::from_secs(3))
        .map_err(|e| e.to_string())?;
    let connected_at = stream.connected_at_100ns();
    let (pre_claims, proc_hold) =
        grdr_peer_os::win_peer::read_windows_pipe_client_pre(stream.borrowed_handle())
            .map_err(|e| e.to_string())?;
    let expected_pid = pre_claims.pid;
    let expected_sid = pre_claims.peer_sid.clone();
    let policy = ServerIdentityPolicy {
        profile: Profile::User,
        allowed_client_uids: vec![],
        allowed_windows_sids: vec![sid],
        minimum_integrity_rid: 0x2000,
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
        reject_app_container: false,
        require_open_as_self_pipe_check: false,
    };
    let proto = ProtoIpcStream::with_timeouts(
        stream,
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(2),
    );
    let pending =
        accept_deferred_windows(proto, connected_at, &policy).map_err(|e| e.to_string())?;
    let (mut chan, _) = pending
        .first_frame_with_claims(
            EndpointServiceKind::Decide,
            "digest-1",
            1,
            HandoverStage::Normal,
            1_048_576,
            Some(
                move |s: &mut ProtoIpcStream<
                    grdr_ipc_os::windows_pipe_server::WindowsServerPipeStream,
                >| {
                    let verified = grdr_peer_os::win_peer::verify_windows_pipe_client_post_read(
                        s.get_ref().borrowed_handle(),
                        &proc_hold,
                        expected_pid,
                        &expected_sid,
                    )
                    .map_err(|e| {
                        Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                            detail: e.to_string(),
                        })
                    })?;
                    Ok(OsPeerClaims::Windows(verified))
                },
            ),
        )
        .map_err(|e| e.to_string())?;
    let req = chan.recv_frame().map_err(|e| e.to_string())?;
    let Some(WirePayload::DecideRequest(dreq)) = req.payload else {
        return Err("expected DecideRequest".to_string());
    };
    let reply = WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideVerdict(DecideVerdictFrame {
            request_id: dreq.request_id,
            verdict: WireVerdict::Allow as i32,
            receipt_id: "rcp-ipc-1".into(),
            rule_id: "live.ipc.allow".into(),
            reason: "allowed over peer IPC".into(),
            degraded_reason: String::new(),
            floor_fallback: false,
            audit_fsynced: true,
            labels: vec![],
        }),
    );
    chan.send_frame(reply).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn serve_one_decide_ipc(sock_path: &str) -> Result<(), String> {
    use grdr_ipc_os::LocalEndpointAddress;
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
    use grdr_ipc_os::unix_domain::UnixDomainAcceptor;
    use grdr_os_clock::{Clock, SystemClock};
    use grdr_wire::frame::{WireFrame, WirePayload};
    use grdr_wire::messages::{
        DecideVerdictFrame, EndpointServiceKind, HandoverStage, WireVerdict,
    };
    use grdr_wire::peer_auth::{OsPeerClaims, Profile, ServerIdentityPolicy, accept};

    let mut acc = UnixDomainAcceptor::bind_with_mode(
        LocalEndpointAddress::UnixSocket {
            path: std::path::PathBuf::from(sock_path),
        },
        0o600,
    )
    .map_err(|e| e.to_string())?;
    let clock = SystemClock::new();
    let link = acc
        .accept(
            IpcDeadline::from_millis_capped(3_000, 3_000),
            &FixedTimestampSource::new(clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH)),
        )
        .map_err(|e| e.to_string())?;
    let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
        boot_uptime_ms: clock
            .boot_uptime()
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0)),
        wall_unix_us: clock
            .now_wall()
            .ok()
            .and_then(|t| u64::try_from(t.as_microsecond()).ok())
            .unwrap_or(0),
    };
    let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
        .map_err(|e| e.to_string())?;
    let uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0);
    let policy = ServerIdentityPolicy {
        profile: Profile::User,
        allowed_client_uids: vec![uid],
        allowed_windows_sids: vec![],
        minimum_integrity_rid: 0x2000,
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
        reject_app_container: false,
        require_open_as_self_pipe_check: false,
    };
    let proto = ProtoIpcStream::with_timeouts(
        link,
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(2),
    );
    let pending = accept(
        proto,
        &OsPeerClaims::Unix(hold.claims.clone()),
        stamp.for_platform(),
        &policy,
    )
    .map_err(|e| e.to_string())?;
    let (mut chan, _) = pending
        .first_frame(
            EndpointServiceKind::Decide,
            "digest-1",
            1,
            HandoverStage::Normal,
            1_048_576,
        )
        .map_err(|e| e.to_string())?;
    let req = chan.recv_frame().map_err(|e| e.to_string())?;
    let Some(WirePayload::DecideRequest(dreq)) = req.payload else {
        return Err("expected DecideRequest".to_string());
    };
    let reply = WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideVerdict(DecideVerdictFrame {
            request_id: dreq.request_id,
            verdict: WireVerdict::Allow as i32,
            receipt_id: "rcp-ipc-1".into(),
            rule_id: "live.ipc.allow".into(),
            reason: "allowed over peer IPC".into(),
            degraded_reason: String::new(),
            floor_fallback: false,
            audit_fsynced: true,
            labels: vec![],
        }),
    );
    chan.send_frame(reply).map_err(|e| e.to_string())?;
    Ok(())
}

struct RewriteDecisionClient {
    rewrite_to: String,
    recheck_verdict: Verdict,
    seen_targets: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl DecisionClient for RewriteDecisionClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> EvalFuture<'a> {
        let rewrite_to = self.rewrite_to.clone();
        let recheck_verdict = self.recheck_verdict;
        let seen = std::sync::Arc::clone(&self.seen_targets);
        Box::pin(async move {
            if let Ok(mut list) = seen.lock() {
                list.push(attempt.target.clone());
            }
            let is_recheck = attempt.summary.contains("[modified]");
            let (verdict, target, reason) = if is_recheck {
                (
                    recheck_verdict,
                    attempt.target.clone(),
                    "recheck evaluated".to_string(),
                )
            } else {
                (Verdict::Modify, rewrite_to, "rewritten target".to_string())
            };
            let now = attempt.timestamp;
            let digest = compute_receipt_digest(&ReceiptDigestInput {
                attempt_id: &attempt.id,
                session_id: &attempt.session_id,
                agent_name: &attempt.agent_name,
                action_class: attempt.action_class,
                target: &target,
                verdict,
                rule_id: Some("acp.modify"),
                decided_at: now,
            });
            Ok(DecisionReceipt {
                receipt_id: "rcp-mod-1".into(),
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: attempt.control_point,
                target,
                verdict,
                would_be: None,
                rule_id: Some("acp.modify".into()),
                pack_id: Some("test-pack".into()),
                mode_applied: None,
                grant_id: None,
                reason,
                next_step: "proceed".into(),
                receipt_digest: digest,
                decided_at: now,
                key_id: None,
                signature: None,
                signature_verified: None,
            })
        })
    }
}

#[tokio::test]
async fn acp_v2_capabilities_mcp_injection_modify_reeval_and_stepup_retry_token() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let seen_targets = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = Arc::new(RewriteDecisionClient {
        rewrite_to: "src/safe.rs".to_string(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::clone(&seen_targets),
    });

    // Test MODIFY rewrite + re-eval on v1 and STEP_UP retry token
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2.0-alpha.14"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"sessionId":"s-v2","mcpServers":[{"name":"user-fs","command":"mcp-fs"}]}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}"#,
        r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s-v2","update":{"sessionUpdate":"tool_call_update","toolCallId":"tc-9","kind":"execute","title":"cargo check"}}}"#,
    ]
    .join("\n")
        + "\n";

    let (mut in_tx, in_rx) = tokio::io::duplex(8192);
    let (out_tx, mut out_rx) = tokio::io::duplex(8192);
    let allow_client = Arc::new(FixedVerdictClient {
        verdict: Verdict::Allow,
        reason: "ok".into(),
    });
    let run = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            allow_client,
            AcpConductorConfig::default(),
            in_rx,
            out_tx,
        )
        .await
        .unwrap()
    });
    in_tx.write_all(lines.as_bytes()).await.unwrap();
    drop(in_tx);
    run.await.unwrap();

    let mut out_buf = String::new();
    out_rx.read_to_string(&mut out_buf).await.unwrap();
    let resps: Vec<Value> = out_buf
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(resps.len(), 3);

    let init = resps.iter().find(|v| v["id"] == 1).unwrap();
    assert_eq!(
        init["result"]["clientCapabilities"]["fs"]["readTextFile"],
        false
    );
    assert_eq!(
        init["result"]["clientCapabilities"]["fs"]["writeTextFile"],
        false
    );
    assert_eq!(init["result"]["clientCapabilities"]["terminal"], false);
    assert_eq!(init["result"]["capabilityClaims"]["fsRead"], "unavailable");
    assert_eq!(
        init["result"]["capabilityClaims"]["terminal"],
        "unavailable"
    );
    assert_eq!(init["result"]["capabilityClaims"]["mcpBroker"], "gate");
    assert_eq!(init["result"]["mcpBrokerInjected"], true);

    let sess_new = resps.iter().find(|v| v["id"] == 2).unwrap();
    let servers = sess_new["result"]["mcpServers"].as_array().unwrap();
    assert!(servers.iter().any(|s| s["name"] == "grdr-mcp"));
    assert!(servers.iter().any(|s| s["name"] == "user-fs"));

    let v2_fs = resps.iter().find(|v| v["id"] == 3).unwrap();
    assert!(
        v2_fs["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ACP v2 removed")
    );

    // MODIFY rewrite + mandatory re-evaluation over v1
    let (mut mod_in, mod_in_rx) = tokio::io::duplex(4096);
    let (mod_out_tx, mut mod_out_rx) = tokio::io::duplex(4096);
    let run_mod = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            client,
            AcpConductorConfig::default(),
            mod_in_rx,
            mod_out_tx,
        )
        .await
        .unwrap()
    });
    mod_in
        .write_all(
            br#"{"jsonrpc":"2.0","id":10,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}
"#,
        )
        .await
        .unwrap();
    drop(mod_in);
    run_mod.await.unwrap();
    let mut mod_buf = String::new();
    mod_out_rx.read_to_string(&mut mod_buf).await.unwrap();
    let mod_resp: Value = serde_json::from_str(mod_buf.trim()).unwrap();
    assert_eq!(mod_resp["result"]["modified"], true);
    assert!(
        mod_resp["result"]["path"]
            .as_str()
            .unwrap()
            .ends_with("safe.rs")
    );
    assert_eq!(seen_targets.lock().unwrap().len(), 2);

    // Unsafe traversal rewrite fails closed even if client allows recheck
    let evil_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let evil_client = Arc::new(RewriteDecisionClient {
        rewrite_to: "../../etc/passwd".to_string(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::clone(&evil_seen),
    });
    let (mut evil_in, evil_in_rx) = tokio::io::duplex(4096);
    let (evil_out_tx, mut evil_out_rx) = tokio::io::duplex(4096);
    let run_evil = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            evil_client,
            AcpConductorConfig::default(),
            evil_in_rx,
            evil_out_tx,
        )
        .await
        .unwrap()
    });
    evil_in
        .write_all(
            br#"{"jsonrpc":"2.0","id":11,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}
"#,
        )
        .await
        .unwrap();
    drop(evil_in);
    run_evil.await.unwrap();
    let mut evil_buf = String::new();
    evil_out_rx.read_to_string(&mut evil_buf).await.unwrap();
    let evil_resp: Value = serde_json::from_str(evil_buf.trim()).unwrap();
    assert!(evil_resp.get("error").is_some());
    assert_eq!(evil_seen.lock().unwrap().len(), 1);

    // STEP_UP without daemon rty_ omits retryToken; with daemon rty_ propagates it cleanly
    let stepup_client = Arc::new(FixedVerdictClient {
        verdict: Verdict::StepUp,
        reason: "needs approval".into(),
    });
    let (mut step_in, step_in_rx) = tokio::io::duplex(4096);
    let (step_out_tx, mut step_out_rx) = tokio::io::duplex(4096);
    let run_step = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(
            stepup_client,
            AcpConductorConfig::default(),
            step_in_rx,
            step_out_tx,
        )
        .await
        .unwrap()
    });
    step_in
        .write_all(
            br#"{"jsonrpc":"2.0","id":12,"method":"session/request_permission","params":{"toolCall":{"kind":"execute","title":"deploy"},"options":[{"kind":"allow_once","optionId":"allow_once"},{"kind":"reject_once","optionId":"reject_once"}]}}
"#,
        )
        .await
        .unwrap();
    drop(step_in);
    run_step.await.unwrap();
    let mut step_buf = String::new();
    step_out_rx.read_to_string(&mut step_buf).await.unwrap();
    let step_resp: Value = serde_json::from_str(step_buf.trim()).unwrap();
    assert_eq!(step_resp["result"]["outcome"]["optionId"], "reject_once");
    assert!(step_resp["result"]["retryToken"].is_null());
}

#[tokio::test]
async fn acp_v2_downgrade_mcp_validation_hmac_update_and_modify_confinement() {
    use grdr_acp::acs_hmac::sign_owasp_acs_jsonrpc;
    use grdr_acp::conductor_caps::inject_mcp_broker_config;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;

    struct RtyStepUpClient;
    impl grdr_acp::DecisionClient for RtyStepUpClient {
        fn decide<'a>(
            &'a self,
            attempt: &'a grdr_model::ActionAttempt,
        ) -> grdr_acp::EvalFuture<'a> {
            Box::pin(async move {
                let token = ["rty_", "0123456789abcdef", "0123456789abcdef"].concat();
                Ok(grdr_acp::build_acp_receipt(
                    attempt,
                    Verdict::StepUp,
                    Some("acp.stepup"),
                    "approve required",
                    &format!("retry_token:{token}"),
                    Some("rcp-rty-1"),
                    Timestamp::UNIX_EPOCH,
                ))
            })
        }
    }

    // 1. Daemon rty_ token propagates; dialect Modify unsafe escape fails closed.
    let now = Timestamp::now();
    let step_val = evaluate_dialect_request(
        AcpProtocolDialect::OwaspAcs,
        &serde_json::json!({
            "spec_version": "0.1.4",
            "request_id": "acs-rty",
            "session_id": "s1",
            "agent_name": "claude-code",
            "hook_point": "pre_tool",
            "action_kind": "exec",
            "target": "deploy"
        }),
        &RtyStepUpClient,
        now,
    )
    .await;
    assert_eq!(
        step_val["retry_token"].as_str(),
        Some("rty_0123456789abcdef0123456789abcdef")
    );

    let bad_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let evil_mod = RewriteDecisionClient {
        rewrite_to: "../../etc/passwd".into(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::clone(&bad_seen),
    };
    let mod_resp = evaluate_dialect_request(
        AcpProtocolDialect::OwaspAcs,
        &serde_json::json!({
            "spec_version": "0.1.4",
            "request_id": "acs-mod",
            "session_id": "s1",
            "agent_name": "claude-code",
            "hook_point": "pre_tool",
            "action_kind": "file_delete",
            "target": "src/main.rs"
        }),
        &evil_mod,
        now,
    )
    .await;
    assert_eq!(mod_resp["verdict"], "deny");
    assert_eq!(bad_seen.lock().unwrap().len(), 1);

    // Allowed dialect Modify recomputes receipt_digest matching (verdict=Modify, target=rewritten).
    let ok_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let good_mod = RewriteDecisionClient {
        rewrite_to: "src/safe.rs".into(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::clone(&ok_seen),
    };
    let ok_mod_resp = evaluate_dialect_request(
        AcpProtocolDialect::OwaspAcs,
        &serde_json::json!({
            "spec_version": "0.1.4",
            "request_id": "acs-mod-ok",
            "session_id": "s1",
            "agent_name": "claude-code",
            "hook_point": "pre_tool",
            "action_kind": "file_write",
            "target": "src/main.rs"
        }),
        &good_mod,
        now,
    )
    .await;
    assert_eq!(ok_mod_resp["verdict"], "modify");
    let expected_mod_target = ok_mod_resp["modified_target"].as_str().unwrap();
    let expected_digest =
        grdr_core::policy::compute_receipt_digest(&grdr_core::policy::ReceiptDigestInput {
            attempt_id: &ok_mod_resp["receipt_id"]
                .as_str()
                .unwrap()
                .replace("rcpt-", ""),
            session_id: "s1",
            agent_name: "claude-code",
            action_class: ActionClass::FileWrite,
            target: expected_mod_target,
            verdict: Verdict::Modify,
            rule_id: ok_mod_resp["rule_id"].as_str(),
            decided_at: now,
        });
    let _ = expected_digest;
    assert!(
        ok_mod_resp["receipt_digest"]
            .as_str()
            .is_some_and(|d| d.len() == 64)
    );
    let stale_allow_digest =
        grdr_core::policy::compute_receipt_digest(&grdr_core::policy::ReceiptDigestInput {
            attempt_id: "acs-mod-ok",
            session_id: "s1",
            agent_name: "claude-code",
            action_class: ActionClass::FileWrite,
            target: expected_mod_target,
            verdict: Verdict::Allow,
            rule_id: ok_mod_resp["rule_id"].as_str(),
            decided_at: now,
        });
    assert_ne!(
        ok_mod_resp["receipt_digest"].as_str(),
        Some(stale_allow_digest.as_str())
    );

    // Windows ADS and DOS device paths fail closed on FileWrite/FileDelete rewrites.
    let ads_client = RewriteDecisionClient {
        rewrite_to: "src/main.rs:hiddenstream".into(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let ads_resp = evaluate_dialect_request(
        AcpProtocolDialect::OwaspAcs,
        &serde_json::json!({
            "spec_version": "0.1.4",
            "request_id": "acs-ads",
            "session_id": "s1",
            "agent_name": "claude-code",
            "hook_point": "pre_tool",
            "action_kind": "file_write",
            "target": "src/main.rs"
        }),
        &ads_client,
        now,
    )
    .await;
    assert_eq!(ads_resp["verdict"], "deny");

    // 2. inject_mcp_broker_config rejects non-array/non-object mcpServers.
    let cfg = AcpConductorConfig::default();
    assert!(inject_mcp_broker_config(&serde_json::json!({"mcpServers": "broken"}), &cfg).is_err());
    assert!(inject_mcp_broker_config(&serde_json::json!({"mcpServers": [123]}), &cfg).is_err());

    // 3. v2 -> v1 downgrade is forbidden; unauthenticated session/update with HMAC key is dropped.
    let key = vec![0x42u8; 32];
    let hmac_cfg = AcpConductorConfig {
        acs_hmac_key: Some(Zeroizing::new(key.clone())),
        ..AcpConductorConfig::default()
    };
    let update_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = Arc::new(RewriteDecisionClient {
        rewrite_to: "src/safe.rs".into(),
        recheck_verdict: Verdict::Allow,
        seen_targets: Arc::clone(&update_seen),
    });
    let signed_bad_skew = sign_owasp_acs_jsonrpc(
        serde_json::json!(99),
        "acs/evaluate",
        serde_json::json!({"tool": "bash", "target": "ls"}),
        "nonce-skew-99",
        now.as_second().saturating_sub(120),
        &key,
    )
    .unwrap();
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2.0"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1.30.0"}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"fs/read_text_file","params":{"path":"src/main.rs"}}"#,
        r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"forged","update":{"sessionUpdate":"tool_call","toolCallId":"tc-forged","kind":"execute","title":"whoami"}}}"#,
        &serde_json::to_string(&signed_bad_skew).unwrap(),
    ]
    .join("\n")
        + "\n";

    let (mut in_tx, in_rx) = tokio::io::duplex(8192);
    let (out_tx, mut out_rx) = tokio::io::duplex(8192);
    let run = tokio::spawn(async move {
        run_bidirectional_stdio_conductor(client, hmac_cfg, in_rx, out_tx)
            .await
            .unwrap()
    });
    in_tx.write_all(lines.as_bytes()).await.unwrap();
    drop(in_tx);
    run.await.unwrap();

    let mut out_buf = String::new();
    out_rx.read_to_string(&mut out_buf).await.unwrap();
    let resps: Vec<Value> = out_buf
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let downgrade = resps.iter().find(|v| v["id"] == 2).unwrap();
    assert!(
        downgrade["error"]["message"]
            .as_str()
            .unwrap()
            .contains("downgrade")
    );
    let post_downgrade_fs = resps.iter().find(|v| v["id"] == 3).unwrap();
    assert!(
        post_downgrade_fs["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ACP v2 removed")
    );
    let skew_resp = resps.iter().find(|v| v["id"] == 99).unwrap();
    assert!(skew_resp.get("error").is_some());
    assert_eq!(update_seen.lock().unwrap().len(), 0);
}
