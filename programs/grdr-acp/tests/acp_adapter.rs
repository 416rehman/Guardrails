// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::{SignedDuration, Timestamp};
use serde_json::Value;

use grdr_acp::adapters::{AcpProtocolDialect, evaluate_dialect_request};
use grdr_acp::envelope::{AcpWireRequest, AcpWireResponse, AcpWireServer};
use grdr_acp::{AcpError, DecisionClient, EvalFuture, LoopbackDaemonClient};
use grdr_core::policy::ReceiptDigestInput;
use grdr_core::policy::compute_receipt_digest;
use grdr_crypto::SigningKeypair;
use grdr_model::{ActionAttempt, DecisionReceipt, Verdict};
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

    // Loopback URL validation rejects non-loopback and userinfo-smuggled endpoints.
    assert!(LoopbackDaemonClient::new("https://evil.example:8765", 500).is_err());
    assert!(LoopbackDaemonClient::new("http://localhost:pass@evil.example:8765", 500).is_err());
}

#[tokio::test]
async fn serve_stream_validates_10_byte_wire_header_and_no_tool_downgrade() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert_eq!(
        grdr_acp::classify_action_kind("", "bash_read_env"),
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
