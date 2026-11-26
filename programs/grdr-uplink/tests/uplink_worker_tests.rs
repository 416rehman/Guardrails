// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::error::Error;
use std::process::{Child, Command, Stdio};

use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_ipc_os::proto_io::{DuplexPipe, ProtoIpcStream};
use grdr_model::{
    ArtifactEntry, ArtifactKind, ArtifactRiskFlag, ArtifactScope, DeviceCheckinRequest,
    InstallProfile,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_uplink::allowlist::AllowEntry;
use grdr_uplink::auth::{
    EphemeralTransportSigner, FleetTrustAnchor, RequestKind, ResponseKeyCertificate,
    TransportKeyCertificate, sign_fleet_response,
};
use grdr_uplink::dialer::NetworkMode;
use grdr_uplink::lanes::Lane;
use grdr_uplink::worker::{UplinkWorkerConfig, UplinkWorkerState, verify_checkin_response_pinned};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload};
use grdr_wire::generate_nonce;
use grdr_wire::messages::{
    ChannelProfileKind, CreditGrantFrame, EndpointServiceKind, HeartbeatFrame, HelloFrame,
    UplinkCommandFrame,
};
use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile, open};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn uplink_daemon_worker_handles_handshake_heartbeat_credit_flow_and_offline_flush() {
    let res = run_uplink_worker_test();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn uplink_worker_enforces_p8_pinned_acks_multi_chunk_staging_and_isolated_egress() {
    let res = run_uplink_worker_security_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_uplink_worker_test() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-uplink");
    let stage = std::env::temp_dir().join(format!("grdr-uplink-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);

    let mut child = ChildGuard(
        Command::new(exe)
            .args(["daemon-worker", "--staging-root"])
            .arg(&stage)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let stdin = child.0.stdin.take().ok_or("missing stdin")?;
    let stdout = child.0.stdout.take().ok_or("missing stdout")?;

    let (mut chan, ready) = open(
        ProtoIpcStream::new(DuplexPipe::new(stdout, stdin)),
        &OsPeerClaims::Inherited,
        0,
        &ClientIdentityPolicy {
            profile: Profile::Inherited,
            allowed_server_uids: Vec::new(),
            expected_windows_sids: Vec::new(),
            minimum_integrity_rid: 0,
            require_start_time_before_connect: false,
            require_kernel_peer_token: false,
        },
        HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: EndpointServiceKind::ProviderUplink as i32,
            profile: ChannelProfileKind::Inherited as i32,
            client_nonce: uuid::Uuid::now_v7().as_bytes().to_vec(),
            pid: std::process::id(),
            capabilities: vec!["uplink.v1".to_string()],
        },
        1_048_576,
    )?;
    if ready.protocol_version != IPC_WIRE_VERSION {
        return Err("unexpected uplink ReadyFrame version".into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::Heartbeat(HeartbeatFrame {
            seq: 1,
            monotonic_ms: 100,
            rss_bytes: 0,
            queue_depth: 0,
            epoch: 1,
        }),
    ))?;
    let hb_reply = chan.recv_frame()?;
    let Some(WirePayload::Heartbeat(hb)) = hb_reply.payload else {
        return Err("expected Heartbeat reply from uplink worker".into());
    };
    if hb.rss_bytes == 0 {
        return Err("uplink heartbeat must report non-zero live RSS".into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::UplinkCommand(UplinkCommandFrame {
            command_id: "it-flush-offline".to_string(),
            action: "flush_spool".to_string(),
            lane: "decision".to_string(),
            seq_hint: 42,
            payload: b"audit-record".to_vec(),
        }),
    ))?;
    let ev_reply = chan.recv_frame()?;
    let Some(WirePayload::UplinkEvent(ev)) = ev_reply.payload else {
        return Err("expected UplinkEvent reply".into());
    };
    if ev.durable_through_seq != 0
        || !ev.degraded_reason.contains("AckUnverified")
            && !ev.degraded_reason.contains("offline-queued")
    {
        return Err(format!("offline flush must NOT advance durable_through: {ev:?}").into());
    }

    // Exercise >64 frames with explicit CreditGrant replenishment.
    for i in 0..70u64 {
        if i % 16 == 15 {
            chan.send_frame(WireFrame::with_payload(
                0,
                i,
                WirePayload::CreditGrant(CreditGrantFrame { delta: 32 }),
            ))?;
        }
        chan.send_frame(WireFrame::with_payload(
            1,
            i.saturating_add(10),
            WirePayload::UplinkCommand(UplinkCommandFrame {
                command_id: format!("credit-{i}"),
                action: "query_watermarks".to_string(),
                lane: "decision".to_string(),
                seq_hint: 0,
                payload: Vec::new(),
            }),
        ))?;
        let reply = chan.recv_frame()?;
        if !matches!(reply.payload, Some(WirePayload::UplinkEvent(_))) {
            return Err("expected UplinkEvent reply under >64 credit flow".into());
        }
    }

    drop(chan);
    drop(child);
    let _ = std::fs::remove_dir_all(&stage);
    Ok(())
}

fn run_uplink_worker_security_checks() -> Result<(), Box<dyn Error>> {
    let clock = SystemClock::new();
    let stage_dir = std::env::temp_dir().join(format!("grdr-uplink-sec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage_dir);

    let fleet_kp = SigningKeypair::generate()?;
    let resp_kp = SigningKeypair::generate()?;
    let device_kp = SigningKeypair::generate()?;
    let transport_kp = SigningKeypair::generate()?;
    let mut keys = BTreeMap::new();
    keys.insert(fleet_kp.key_id().to_string(), fleet_kp.public_key_b64());
    let anchor = FleetTrustAnchor {
        deployment_id: "dep-1".to_string(),
        fleet_public_keys: keys,
    };

    let mut st = UplinkWorkerState::with_config(
        stage_dir.clone(),
        UplinkWorkerConfig {
            device_id: "dev-real-01".to_string(),
            network_mode: NetworkMode::Isolated {
                allow_list: vec![AllowEntry::parse("cell.fleet.example")?],
            },
            pinned_anchor: Some(anchor),
        },
        &clock,
    )?;

    // Reject unknown lane cleanly.
    let bad_lane = st.handle_command(
        &UplinkCommandFrame {
            command_id: "bad-lane".to_string(),
            action: "flush_spool".to_string(),
            lane: "bogus".to_string(),
            seq_hint: 1,
            payload: b"x".to_vec(),
        },
        &clock,
    );
    if bad_lane.degraded_reason.is_empty() {
        return Err("unknown flush lane must fail closed".into());
    }

    // Unacked flush keeps record buffered with durable_through == 0.
    let unacked = st.handle_command(
        &UplinkCommandFrame {
            command_id: "offline-1".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 9,
            payload: b"spine-ev-1".to_vec(),
        },
        &clock,
    );
    if unacked.durable_through_seq != 0 || st.retained_unacked_count() == 0 {
        return Err("offline flush must stay buffered and keep durable_through=0".into());
    }

    // Signed verified ack advances Spine watermark and prunes Spine without touching Decision.
    let now_s = clock.now_wall()?.as_second();
    let t_cert = TransportKeyCertificate::issue(
        &device_kp,
        "dev-real-01",
        "dep-1",
        &transport_kp,
        now_s.saturating_sub(60),
        3_600,
    )?;
    let signer = EphemeralTransportSigner::new(transport_kp, t_cert)?;
    let body = br#"{"ackedThrough":9,"durableThrough":9,"serverEpoch":"epoch-a","lane":"spine","deviceId":"dev-real-01"}"#;
    let nonce = generate_nonce()?;
    let req_headers = signer.sign_request(
        "POST",
        "https://cell.fleet.example/v1/push",
        b"{}",
        RequestKind::PushBatch,
        now_s,
        Some(&nonce),
    )?;
    let r_cert = ResponseKeyCertificate::issue(
        &fleet_kp,
        "dep-1",
        "cell-0",
        &resp_kp,
        now_s.saturating_sub(60),
        now_s.saturating_add(3_600),
    )?;
    let (cd, sig_in, sig) = sign_fleet_response(
        &resp_kp,
        Some(&r_cert),
        &req_headers.request_sig_digest_b64,
        body,
        now_s,
    )?;
    let signed_payload = serde_json::to_vec(&serde_json::json!({
        "records": [b"spine-ev-2".to_vec()],
        "verified_ack": {
            "request_headers": req_headers,
            "content_digest": cd,
            "signature_input": sig_in,
            "signature": sig,
            "response_cert": r_cert,
            "server_time_unix_s": now_s,
            "response_body": body.to_vec()
        }
    }))?;
    let acked = st.handle_command(
        &UplinkCommandFrame {
            command_id: "signed-flush".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 10,
            payload: signed_payload.clone(),
        },
        &clock,
    );
    if !acked.degraded_reason.is_empty()
        || acked.durable_through_seq != 9
        || st.durable_through_for(Lane::Decision) != 0
    {
        return Err(format!("verified spine ack failed isolation check: {acked:?}").into());
    }

    // Replay of identical signed request_sig_digest_b64 must fail closed.
    let replay_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "signed-flush-replay".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 11,
            payload: signed_payload,
        },
        &clock,
    );
    if replay_ev.degraded_reason.is_empty() {
        return Err("replayed signed flush ack must fail closed".into());
    }

    // ServerEpochChanged must trigger backfill requeue of sent unacked records on that lane.
    let epoch_queued = st.handle_command(
        &UplinkCommandFrame {
            command_id: "epoch-offline".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 10,
            payload: b"spine-ev-10".to_vec(),
        },
        &clock,
    );
    if epoch_queued.degraded_reason.is_empty()
        || st.queued_total() != 0
        || st.retained_unacked_count() == 0
    {
        return Err(
            format!("expected sent_unacked record before epoch flip: {epoch_queued:?}").into(),
        );
    }
    let epoch_body = br#"{"ackedThrough":9,"durableThrough":9,"serverEpoch":"epoch-b","lane":"spine","deviceId":"dev-real-01"}"#;
    let epoch_nonce = generate_nonce()?;
    let epoch_req_hdr = signer.sign_request(
        "POST",
        "https://cell.fleet.example/v1/push",
        b"{}",
        RequestKind::PushBatch,
        now_s,
        Some(&epoch_nonce),
    )?;
    let (ecd, esig_in, esig) = sign_fleet_response(
        &resp_kp,
        Some(&r_cert),
        &epoch_req_hdr.request_sig_digest_b64,
        epoch_body,
        now_s,
    )?;
    let epoch_payload = serde_json::to_vec(&serde_json::json!({
        "records": [b"spine-ev-11".to_vec()],
        "verified_ack": {
            "request_headers": epoch_req_hdr,
            "content_digest": ecd,
            "signature_input": esig_in,
            "signature": esig,
            "response_cert": r_cert,
            "server_time_unix_s": now_s,
            "response_body": epoch_body.to_vec()
        }
    }))?;
    let epoch_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "epoch-flip".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 11,
            payload: epoch_payload,
        },
        &clock,
    );
    if !epoch_ev.degraded_reason.is_empty() || st.queued_total() == 0 {
        return Err(
            format!("ServerEpochChanged must requeue backfill records: {epoch_ev:?}").into(),
        );
    }

    // Mismatched deviceId or wrong lane inside signed PushAck body must fail closed.
    let bad_body = br#"{"ackedThrough":99,"durableThrough":99,"serverEpoch":"epoch-a","lane":"decision","deviceId":"dev-other"}"#;
    let nonce_bad = generate_nonce()?;
    let bad_req_hdr = signer.sign_request(
        "POST",
        "https://cell.fleet.example/v1/push",
        b"{}",
        RequestKind::PushBatch,
        now_s,
        Some(&nonce_bad),
    )?;
    let (bcd, bsig_in, bsig) = sign_fleet_response(
        &resp_kp,
        Some(&r_cert),
        &bad_req_hdr.request_sig_digest_b64,
        bad_body,
        now_s,
    )?;
    let mismatched_payload = serde_json::to_vec(&serde_json::json!({
        "records": [b"spine-ev-3".to_vec()],
        "verified_ack": {
            "request_headers": bad_req_hdr,
            "content_digest": bcd,
            "signature_input": bsig_in,
            "signature": bsig,
            "response_cert": r_cert,
            "server_time_unix_s": now_s,
            "response_body": bad_body.to_vec()
        }
    }))?;
    let mismatch_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "signed-flush-mismatch".to_string(),
            action: "flush_spool".to_string(),
            lane: "spine".to_string(),
            seq_hint: 12,
            payload: mismatched_payload,
        },
        &clock,
    );
    if mismatch_ev.degraded_reason.is_empty() || st.durable_through_for(Lane::Decision) != 0 {
        return Err("PushAck body device/lane mismatch must be rejected".into());
    }

    // CheckIn P8 nested artifact user_id and raw home path rejection.
    let p8_req = DeviceCheckinRequest {
        device_id: Some("dev-real-01".to_string()),
        hostname: "host".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        install_profile: InstallProfile::User,
        daemon_version: "0.1.0".to_string(),
        hook_effective: true,
        agents: Vec::new(),
        mcp_servers: Vec::new(),
        artifacts: vec![ArtifactEntry {
            id: "a1".to_string(),
            name: "skill".to_string(),
            kind: ArtifactKind::Skill,
            scope: ArtifactScope::User,
            source_agent: "claude".to_string(),
            path: "/home/alice/.claude/skill.md".to_string(),
            content_digest: sha256_hex(b"skill"),
            file_count: 1,
            total_bytes: 10,
            usage_count: 1,
            pinned: false,
            risk_flags: Vec::<ArtifactRiskFlag>::new(),
            device_id: "dev-real-01".to_string(),
            device_name: "host".to_string(),
            user_id: Some("alice".to_string()),
            detected_at: clock.now_wall()?,
        }],
        user_id: None,
        user_display: None,
        device_public_key: None,
    };
    let p8_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "p8-bad".to_string(),
            action: "check_in".to_string(),
            lane: "checkin".to_string(),
            seq_hint: 0,
            payload: serde_json::to_vec(&p8_req)?,
        },
        &clock,
    );
    if p8_ev.degraded_reason.is_empty() {
        return Err("nested artifact P8 leak must be rejected".into());
    }

    // Long (>64B) nested path P8 leak and raw hostname leak must both fail closed without 64B truncation.
    let mut long_p8 = p8_req.clone();
    if let Some(first) = long_p8.artifacts.first_mut() {
        first.user_id = None;
        first.path = format!("/opt/shared/{}/Users/alice/.secret", "a".repeat(80));
    }
    let long_p8_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "p8-long-bad".to_string(),
            action: "check_in".to_string(),
            lane: "checkin".to_string(),
            seq_hint: 0,
            payload: serde_json::to_vec(&long_p8)?,
        },
        &clock,
    );
    if long_p8_ev.degraded_reason.is_empty() {
        return Err("P8 path beyond 64 bytes must still be detected and rejected".into());
    }
    let host_p8 = DeviceCheckinRequest {
        hostname: "alice-laptop\\ahmad".to_string(),
        user_id: None,
        artifacts: Vec::new(),
        ..p8_req
    };
    let host_p8_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "p8-host-bad".to_string(),
            action: "check_in".to_string(),
            lane: "checkin".to_string(),
            seq_hint: 0,
            payload: serde_json::to_vec(&host_p8)?,
        },
        &clock,
    );
    if host_p8_ev.degraded_reason.is_empty() {
        return Err("raw Windows account/hostname backslash in hostname must fail P8".into());
    }

    // Isolated mode check_in refuses unlisted egress BEFORE DNS (even with zero resolved_ips).
    let pre_dns_directive = serde_json::to_vec(&serde_json::json!({
        "server_url": "https://evil.unlisted.example/v1/checkin",
        "resolved_ips": [],
        "request_headers": req_headers,
        "content_digest": cd,
        "signature_input": sig_in,
        "signature": sig,
        "server_time_unix_s": now_s,
        "response_payload": b"ok".to_vec()
    }))?;
    let pre_dns_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "egress-pre-dns".to_string(),
            action: "check_in".to_string(),
            lane: "checkin".to_string(),
            seq_hint: 0,
            payload: pre_dns_directive,
        },
        &clock,
    );
    if !pre_dns_ev.degraded_reason.contains("GRDR-CFG-0020") {
        return Err(
            format!("isolated mode must reject unlisted host before DNS: {pre_dns_ev:?}").into(),
        );
    }

    // Isolated mode check_in refuses unlisted egress even with signed response.
    let unlisted_directive = serde_json::to_vec(&serde_json::json!({
        "server_url": "https://evil.unlisted.example/v1/checkin",
        "resolved_ips": ["198.51.100.5"],
        "request_headers": req_headers,
        "content_digest": cd,
        "signature_input": sig_in,
        "signature": sig,
        "server_time_unix_s": now_s,
        "response_payload": b"ok".to_vec()
    }))?;
    let unlisted_ev = st.handle_command(
        &UplinkCommandFrame {
            command_id: "egress-bad".to_string(),
            action: "check_in".to_string(),
            lane: "checkin".to_string(),
            seq_hint: 0,
            payload: unlisted_directive,
        },
        &clock,
    );
    if !unlisted_ev.degraded_reason.contains("GRDR-CFG-0020") {
        return Err(format!("isolated mode must reject unlisted host: {unlisted_ev:?}").into());
    }

    // Multi-chunk artifact staging only promotes once declared total size is reached.
    let art = b"part-one-part-two";
    let digest = sha256_hex(art);
    let (c1, c2) = art.split_at(8);
    let ev1 = st.handle_command(
        &UplinkCommandFrame {
            command_id: "stage-1".to_string(),
            action: "stage_artifact".to_string(),
            lane: digest.clone(),
            seq_hint: u64::try_from(art.len())?,
            payload: c1.to_vec(),
        },
        &clock,
    );
    if ev1.ack_lane != "staging-partial" || !ev1.staged_manifest_path.is_empty() {
        return Err(format!("partial chunk must not finalize: {ev1:?}").into());
    }
    let ev2 = st.handle_command(
        &UplinkCommandFrame {
            command_id: "stage-2".to_string(),
            action: "stage_artifact".to_string(),
            lane: digest.clone(),
            seq_hint: u64::try_from(art.len())?,
            payload: c2.to_vec(),
        },
        &clock,
    );
    if ev2.ack_lane != "staged" || ev2.staged_manifest_path.is_empty() {
        return Err(format!("final chunk must finalize staged file: {ev2:?}").into());
    }

    // Oversized seq_hint > 32 MiB fails closed.
    let bad_size = st.handle_command(
        &UplinkCommandFrame {
            command_id: "stage-big".to_string(),
            action: "stage_artifact".to_string(),
            lane: digest,
            seq_hint: 64 * 1024 * 1024,
            payload: b"abc".to_vec(),
        },
        &clock,
    );
    if bad_size.degraded_reason.is_empty() {
        return Err("oversized stage_artifact seq_hint must fail closed".into());
    }

    if verify_checkin_response_pinned(&[], b"{}", "sig").is_ok() {
        return Err("empty pinned keys must fail".into());
    }
    let dup_key = grdr_model::TrustedKeyInfo {
        key_id: "k-dup".to_string(),
        public_key_b64: fleet_kp.public_key_b64(),
    };
    if verify_checkin_response_pinned(&[dup_key.clone(), dup_key], b"{}", "sig").is_ok() {
        return Err("duplicate key_id in pinned keys must fail closed".into());
    }
    let _ = std::fs::remove_dir_all(&stage_dir);
    Ok(())
}
