// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use futures_util::StreamExt;
use jiff::Timestamp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc};

use grdr_crypto::SigningKeypair;
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, Verdict};
use grdr_proxy::control_ipc_server::{bind_local_control_endpoint, serve_local_control_once};
use grdr_proxy::egress::{EgressGuardConfig, LoopbackUpstreamPolicy};
use grdr_proxy::local_control::{
    ControlCredentialSpec, ControlRouteSpec, ControlSessionSpec, ProxyControlUpdate,
};
use grdr_proxy::otlp::{OtlpCollectorConfig, OtlpUpstreamShipper};
use grdr_proxy::router::{ProxyGatewayState, build_proxy_router};
use grdr_proxy::sr39::InstanceTokenRegistry;
use grdr_proxy::streaming::stream_upstream_response_with_options;
use grdr_proxy::tls_policy::{
    CallerClass, EchPolicy, LocalCaTrust, MitmBypassReason, MitmDenyReason, MitmRoutingDecision,
    PinningHealth, SelectiveMitmInput, SwgOverrideMode, detect_enterprise_swg,
    evaluate_selective_mitm_policy, load_swg_coexistence_manifest, peek_tls_client_hello,
};
use grdr_proxy::tunnel::handle_tunnel_connection;
use grdr_proxy::web_bot_auth::{WebBotAuthSigner, verify_web_bot_auth_signature};
use grdr_proxy::{
    IpcProxyDecisionClient, ProxyDecideFuture, ProxyDecisionClient, fail_closed_proxy_receipt,
};
use grdr_wire::floor_bin::{
    FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload, embedded_max_frame_bytes};
use grdr_wire::messages::{
    ChannelProfileKind, EndpointServiceKind, HelloFrame, LocalCommandKind, LocalRequestFrame,
};
use grdr_wire::peer_auth::Profile;
use url::Url;

struct RecordingDecisionClient {
    verdict: Verdict,
    attempts: Mutex<Vec<ActionAttempt>>,
}

impl RecordingDecisionClient {
    fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            attempts: Mutex::new(Vec::new()),
        }
    }
}

impl ProxyDecisionClient for RecordingDecisionClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        Box::pin(async move {
            self.attempts.lock().await.push(attempt.clone());
            let mut receipt = fail_closed_proxy_receipt(attempt, "test recording decision");
            receipt.verdict = self.verdict;
            Ok(receipt)
        })
    }
}

fn test_state_dir(tag: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "grdr-proxy-test-{tag}-{}",
        uuid::Uuid::now_v7().simple()
    ));
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir
}

fn build_gzip_zeros(count: usize) -> Vec<u8> {
    let mut deflate = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_len: u8 = 0;
    let push_bits = |val: u32, width: u8, b: &mut u32, bl: &mut u8, out: &mut Vec<u8>| {
        *b |= (val & ((1_u32 << width) - 1)) << *bl;
        *bl = bl.saturating_add(width);
        while *bl >= 8 {
            out.push((*b & 0xFF) as u8);
            *b >>= 8;
            *bl = bl.saturating_sub(8);
        }
    };
    let push_huff = |code: u32, width: u8, b: &mut u32, bl: &mut u8, out: &mut Vec<u8>| {
        let mut rev = 0_u32;
        for i in 0..width {
            if (code & (1_u32 << i)) != 0 {
                rev |= 1_u32 << (width - 1 - i);
            }
        }
        push_bits(rev, width, b, bl, out);
    };
    push_bits(0b011, 3, &mut bits, &mut bit_len, &mut deflate);
    push_huff(0b0011_0000, 8, &mut bits, &mut bit_len, &mut deflate);
    let mut emitted = 1usize;
    while emitted < count {
        if count - emitted >= 258 {
            push_huff(0b1100_0101, 8, &mut bits, &mut bit_len, &mut deflate);
            push_huff(0, 5, &mut bits, &mut bit_len, &mut deflate);
            emitted += 258;
        } else {
            push_huff(0b0011_0000, 8, &mut bits, &mut bit_len, &mut deflate);
            emitted += 1;
        }
    }
    push_huff(0, 7, &mut bits, &mut bit_len, &mut deflate);
    if bit_len > 0 {
        deflate.push((bits & 0xFF) as u8);
    }

    let payload = vec![0u8; count];
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in &payload {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    let mut out = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF];
    out.extend_from_slice(&deflate);
    out.extend_from_slice(&(!crc).to_le_bytes());
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out
}

fn build_tls_client_hello(sni: &str, alpn: &[&str], include_ech: bool) -> Vec<u8> {
    let mut extensions = Vec::new();
    let sni_bytes = sni.as_bytes();
    let entry_len = (3 + sni_bytes.len()) as u16;
    let sni_ext_len = 2 + entry_len;
    extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
    extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
    extensions.extend_from_slice(&entry_len.to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let ext_len = (2 + list.len()) as u16;
        extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&list);
    }

    if include_ech {
        extensions.extend_from_slice(&0xfe0d_u16.to_be_bytes());
        extensions.extend_from_slice(&4_u16.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let hs_len = body.len() as u32;
    let mut handshake = vec![
        0x01,
        ((hs_len >> 16) & 0xff) as u8,
        ((hs_len >> 8) & 0xff) as u8,
        (hs_len & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn send_local_control_ipc_command(endpoint: &str, payload: Vec<u8>) -> Result<String, String> {
    use grdr_ipc_os::LocalEndpointAddress;
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
    use grdr_os_clock::{Clock, SystemClock};
    use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, open};

    let addr = if cfg!(windows) {
        LocalEndpointAddress::WindowsPipe {
            pipe_name: endpoint.to_string(),
        }
    } else {
        LocalEndpointAddress::UnixSocket {
            path: std::path::PathBuf::from(endpoint),
        }
    };
    let clock = SystemClock::new();
    let link = SystemConnector::default()
        .connect(
            &addr,
            IpcDeadline::from_millis_capped(2_000, 2_000),
            &FixedTimestampSource::new(clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH)),
        )
        .map_err(|e| e.to_string())?;

    #[cfg(windows)]
    let (claims, connected_ticks, sids, uids, _hold) = {
        let scm = grdr_peer_os::win_peer::probe_scm_services(&[]);
        let c = grdr_peer_os::win_peer::read_windows_pipe_server(
            link.borrowed_handle(),
            Profile::User,
            &[],
            &scm,
        )
        .map_err(|e| e.to_string())?;
        let sid = grdr_peer_os::win_peer::current_process_sid().map_err(|e| e.to_string())?;
        (
            OsPeerClaims::Windows(c),
            grdr_peer_os::win_peer::current_filetime_100ns(),
            vec![sid],
            Vec::new(),
            (),
        )
    };
    #[cfg(unix)]
    let (claims, connected_ticks, sids, uids, _hold) = {
        let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
            boot_uptime_ms: clock
                .boot_uptime()
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            wall_unix_us: clock
                .now_wall()
                .ok()
                .and_then(|t| u64::try_from(t.as_microsecond()).ok())
                .unwrap_or(0),
        };
        let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
            .map_err(|e| e.to_string())?;
        let uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(0, |ids| ids.0);
        (
            OsPeerClaims::Unix(hold.claims.clone()),
            stamp.for_platform(),
            Vec::new(),
            vec![uid, 0],
            hold,
        )
    };

    let policy = ClientIdentityPolicy {
        profile: Profile::User,
        allowed_server_uids: uids,
        expected_windows_sids: sids,
        minimum_integrity_rid: 0x2000,
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
    };
    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        service: EndpointServiceKind::Local as i32,
        profile: ChannelProfileKind::User as i32,
        client_nonce: vec![7_u8; 16],
        pid: std::process::id(),
        capabilities: vec!["local.v1".to_string()],
    };
    let (mut chan, _) = open(
        ProtoIpcStream::with_timeouts(link, Duration::from_secs(2), Duration::from_secs(2)),
        &claims,
        connected_ticks,
        &policy,
        hello,
        embedded_max_frame_bytes().unwrap_or(1_048_576),
    )
    .map_err(|e| e.to_string())?;

    let frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "req-ctrl-1".to_string(),
            kind: LocalCommandKind::Reload as i32,
            argument: String::new(),
            payload,
            limit: 1,
        }),
    );
    chan.send_frame(frame).map_err(|e| e.to_string())?;
    let reply = chan.recv_frame().map_err(|e| e.to_string())?;
    match reply.payload {
        Some(WirePayload::LocalResponse(resp)) if resp.ok => Ok(resp.message),
        other => Err(format!("unexpected local reply: {other:?}")),
    }
}

#[tokio::test]
async fn ipc_client_rejects_protected_overrides_and_evaluates_signed_floor() {
    assert!(
        IpcProxyDecisionClient::new(
            Profile::Protected,
            Some("custom-ep".to_string()),
            None,
            None,
            500,
        )
        .is_err()
    );
    assert!(
        IpcProxyDecisionClient::new(
            Profile::Protected,
            None,
            None,
            Some(std::path::PathBuf::from("override-state")),
            500,
        )
        .is_err()
    );

    let dir = test_state_dir("floor");
    let kp = SigningKeypair::generate().unwrap();
    let doc = FloorTableDocument {
        epoch: 1,
        expires_at_unix_s: Timestamp::now().as_second().saturating_add(3600),
        signer_key_id: kp.key_id().to_string(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::NetConnect,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor.proxy.deny-evil".to_string(),
            pattern: "evil-c2.example".to_string(),
            agents: vec![],
        }],
    };
    std::fs::write(
        dir.join("floor.bin"),
        encode_signed_floor_table(&doc, &kp).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("floor.pub"),
        format!("{}:{}", kp.key_id(), kp.public_key_b64()),
    )
    .unwrap();

    let missing_ep = if cfg!(windows) {
        format!(
            r"\\.\pipe\grdr-proxy-absent-{}",
            uuid::Uuid::now_v7().simple()
        )
    } else {
        dir.join("absent.sock").to_string_lossy().into_owned()
    };
    let client = IpcProxyDecisionClient::new(
        Profile::User,
        Some(missing_ep),
        None,
        Some(dir.clone()),
        200,
    )
    .unwrap();
    let attempt = ActionAttempt {
        id: "att-floor-1".into(),
        session_id: "s1".into(),
        agent_name: "proxy-tunnel".into(),
        action_class: ActionClass::NetConnect,
        control_point: ControlPoint::Proxy,
        target: "evil-c2.example:443".into(),
        timestamp: Timestamp::now(),
        ..Default::default()
    };
    let receipt = client.decide(&attempt).await.unwrap();
    assert_eq!(receipt.verdict, Verdict::Deny);
    assert_eq!(receipt.rule_id.as_deref(), Some("floor.proxy.deny-evil"));

    // Also test live peer-verified Decide IPC round-trip (Windows named pipe / Unix domain socket).
    let live_ep = if cfg!(windows) {
        format!(
            r"\\.\pipe\grdr-proxy-decide-{}",
            uuid::Uuid::now_v7().simple()
        )
    } else {
        dir.join("decide.sock").to_string_lossy().into_owned()
    };
    let srv_ep = live_ep.clone();
    let srv_thread = std::thread::spawn(move || serve_one_decide_ipc(&srv_ep));
    std::thread::sleep(Duration::from_millis(60));
    let live_client =
        IpcProxyDecisionClient::new(Profile::User, Some(live_ep), None, Some(dir.clone()), 1_500)
            .unwrap();
    let live_receipt = live_client.decide(&attempt).await.unwrap();
    assert_eq!(live_receipt.verdict, Verdict::Allow);
    assert_eq!(live_receipt.rule_id.as_deref(), Some("live.proxy.allow"));
    srv_thread.join().unwrap().unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
fn serve_one_decide_ipc(pipe_name: &str) -> Result<(), String> {
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor;
    use grdr_wire::messages::{DecideVerdictFrame, HandoverStage, WireVerdict};
    use grdr_wire::peer_auth::{
        Evidence, OsPeerClaims, Refusal, ServerIdentityPolicy, accept_deferred_windows,
    };

    let sid = grdr_peer_os::win_peer::current_process_sid().map_err(|e| e.to_string())?;
    let sddl = format!("D:(A;;GA;;;{sid})");
    let mut acc = WindowsNamedPipeAcceptor::bind(pipe_name, &sddl).map_err(|e| e.to_string())?;
    let stream = acc
        .accept(Duration::from_secs(3))
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
    let proto =
        ProtoIpcStream::with_timeouts(stream, Duration::from_secs(2), Duration::from_secs(2));
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
            receipt_id: "rcp-proxy-ipc-1".into(),
            rule_id: "live.proxy.allow".into(),
            reason: "allowed over peer IPC".into(),
            degraded_reason: String::new(),
            floor_fallback: false,
            audit_fsynced: true,
            labels: vec![],
        }),
    );
    chan.send_frame(reply).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn serve_one_decide_ipc(sock_path: &str) -> Result<(), String> {
    use grdr_ipc_os::LocalEndpointAddress;
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
    use grdr_ipc_os::unix_domain::UnixDomainAcceptor;
    use grdr_os_clock::{Clock, SystemClock};
    use grdr_wire::messages::{DecideVerdictFrame, HandoverStage, WireVerdict};
    use grdr_wire::peer_auth::{OsPeerClaims, ServerIdentityPolicy, accept};

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
    let proto = ProtoIpcStream::with_timeouts(link, Duration::from_secs(2), Duration::from_secs(2));
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
            receipt_id: "rcp-proxy-ipc-1".into(),
            rule_id: "live.proxy.allow".into(),
            reason: "allowed over peer IPC".into(),
            degraded_reason: String::new(),
            floor_fallback: false,
            audit_fsynced: true,
            labels: vec![],
        }),
    );
    chan.send_frame(reply).map_err(|e| e.to_string())
}

#[tokio::test]
async fn local_control_ipc_registers_session_credential_and_cuts_active_tunnel() {
    let dir = test_state_dir("ctrl-ipc");
    let ctrl_ep = if cfg!(windows) {
        format!(
            r"\\.\pipe\grdr-proxy-ctrl-{}",
            uuid::Uuid::now_v7().simple()
        )
    } else {
        dir.join("ctrl.sock").to_string_lossy().into_owned()
    };

    let state = Arc::new(
        ProxyGatewayState::new(
            RecordingDecisionClient::new(Verdict::Allow),
            18080,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );

    let bound = bind_local_control_endpoint(Profile::User, Some(&ctrl_ep)).unwrap();
    let token = InstanceTokenRegistry::issue_token().unwrap();
    let updates = vec![
        ProxyControlUpdate::RegisterSession(ControlSessionSpec {
            session_id: "sess-live-cut".into(),
            spiffe_id: "spiffe://guardrails.local/agent/codex/live".into(),
            device_id: "dev-1".into(),
            agent_name: "codex".into(),
            caller_program: "grdr-proxy".into(),
            instance_token: token.clone(),
            attribution_grade: 4,
            has_session_container: true,
            expected_phantom_tokens: BTreeMap::from([("cred-1".into(), "grdr_ph_tok".into())]),
            routes: vec![ControlRouteSpec {
                route_id: "openai".into(),
                provider: "openai".into(),
                upstream_url: "http://127.0.0.1:19999".into(),
                credential_id: Some("cred-1".into()),
                tenant_headers: BTreeMap::new(),
            }],
        }),
        ProxyControlUpdate::UpsertCredential(ControlCredentialSpec {
            credential_id: "cred-1".into(),
            account_id: "acct-1".into(),
            allowed_programs: vec!["grdr-proxy".into()],
            allowed_hosts: vec!["127.0.0.1".into()],
            phantom_prefix: "grdr_ph_".into(),
            header_name: "authorization".into(),
            header_prefix: "Bearer ".into(),
            secret_value: "upstream-live-secret".into(),
        }),
    ];
    let payload_bytes = serde_json::to_vec(&updates).unwrap();

    let state_srv = Arc::clone(&state);
    let srv_handle =
        tokio::spawn(async move { serve_local_control_once(&bound, state_srv, 4_000).await });
    tokio::time::sleep(Duration::from_millis(60)).await;
    let ep_copy = ctrl_ep.clone();
    let msg = tokio::task::spawn_blocking(move || {
        send_local_control_ipc_command(&ep_copy, payload_bytes)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(msg.contains("applied 2"));
    assert_eq!(srv_handle.await.unwrap().unwrap(), 2);

    // Start an echo target and live CONNECT tunnel that gets killed mid-stream by D-30 control update.
    let target_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = target_listener.accept().await {
            let mut buf = [0_u8; 64];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        }
    });

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let tunnel_state = Arc::clone(&state);
    let tunnel_task = tokio::spawn(async move {
        let (sock, _) = proxy_listener.accept().await.unwrap();
        handle_tunnel_connection(sock, tunnel_state, None).await
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();
    let mut established = [0_u8; 64];
    let n = client.read(&mut established).await.unwrap();
    assert!(
        std::str::from_utf8(established.get(..n).unwrap_or(&[]))
            .unwrap()
            .contains("200")
    );

    // Send live plaintext data so peek finishes and bridge enters steady-state.
    client
        .write_all(b"GET /health HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Trigger live D-30 kill-switch via control IPC bind #2 (Unix) or apply_local_control_update.
    state.cut_session_egress("sess-live-cut").await;
    let cut_res = tokio::time::timeout(Duration::from_secs(2), tunnel_task)
        .await
        .unwrap()
        .unwrap();
    assert!(cut_res.is_err());
    assert!(state.registry.lock().await.is_session_cut("sess-live-cut"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn incremental_sse_streaming_flows_without_buffering_and_rejects_gzip_bombs() {
    let chunk_gate = Arc::new(Notify::new());
    let gate_clone = Arc::clone(&chunk_gate);
    let upstream = Router::new().route(
        "/v1/messages",
        post(move || {
            let gate = Arc::clone(&gate_clone);
            async move {
                let s = async_stream_chunks(gate);
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    Body::from_stream(s),
                )
            }
        }),
    );
    let up_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream).await;
    });

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let state = Arc::new(
        ProxyGatewayState::new(
            RecordingDecisionClient::new(Verdict::Allow),
            proxy_port,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    grdr_proxy::local_control::apply_local_control_update(
        &state,
        ProxyControlUpdate::RegisterSession(ControlSessionSpec {
            session_id: "sess-sse-1".into(),
            spiffe_id: "spiffe://guardrails.local/agent/claude/s1".into(),
            device_id: "dev-1".into(),
            agent_name: "claude-code".into(),
            caller_program: "grdr-proxy".into(),
            instance_token: token.clone(),
            attribution_grade: 4,
            has_session_container: true,
            expected_phantom_tokens: BTreeMap::new(),
            routes: vec![ControlRouteSpec {
                route_id: "ant".into(),
                provider: "anthropic".into(),
                upstream_url: format!("http://127.0.0.1:{up_port}/v1/messages"),
                credential_id: None,
                tenant_headers: BTreeMap::new(),
            }],
        }),
    )
    .await
    .unwrap();

    let app = build_proxy_router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, app).await;
    });

    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://127.0.0.1:{proxy_port}/t/{token}/ant");
    let mut resp = http
        .post(&url)
        .header("host", format!("127.0.0.1:{proxy_port}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-3-7-sonnet","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Chunk 1 MUST arrive BEFORE chunk_gate unblocks chunk 2 (proving zero full-response buffering)!
    let first_chunk = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first_str = std::str::from_utf8(&first_chunk).unwrap();
    assert!(first_str.contains("hello"));

    chunk_gate.notify_one();
    let second_chunk = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&second_chunk)
            .unwrap()
            .contains("[DONE]")
    );

    // Verify >100:1 gzip bomb is rejected fail-closed with 403.
    let bomb = build_gzip_zeros(65_536);
    assert!(
        65_536 / bomb.len() > 100,
        "bomb len {} must be >100:1",
        bomb.len()
    );
    let bomb_resp = http
        .post(&url)
        .header("host", format!("127.0.0.1:{proxy_port}"))
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(bomb)
        .send()
        .await
        .unwrap();
    assert_eq!(bomb_resp.status(), StatusCode::FORBIDDEN);
}

fn async_stream_chunks(
    gate: Arc<Notify>,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
    let first = axum::body::Bytes::from_static(
        b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
    );
    let second = axum::body::Bytes::from_static(b"data: [DONE]\n\n");
    futures_util::stream::unfold(0_u8, move |step| {
        let gate = Arc::clone(&gate);
        let first = first.clone();
        let second = second.clone();
        async move {
            match step {
                0 => Some((Ok(first), 1)),
                1 => {
                    gate.notified().await;
                    Some((Ok(second), 2))
                }
                _ => None,
            }
        }
    })
}

#[tokio::test]
async fn sse_keepalive_watchdog_emits_ping_on_idle_stream() {
    let keepalive_resp_app = Router::new().route(
        "/idle",
        post(|| async move {
            let pending =
                futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
            (
                StatusCode::OK,
                [("content-type", "text/event-stream")],
                Body::from_stream(pending),
            )
        }),
    );
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, keepalive_resp_app).await;
    });

    let up_resp = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{port}/idle"))
        .send()
        .await
        .unwrap();
    let state = Arc::new(
        ProxyGatewayState::new(
            RecordingDecisionClient::new(Verdict::Allow),
            18080,
            EgressGuardConfig::default(),
        )
        .unwrap(),
    );
    let streamed = stream_upstream_response_with_options(
        state,
        "sess-ka".into(),
        "route-ka".into(),
        "openai",
        up_resp,
        Duration::from_millis(40),
        1024 * 1024,
    )
    .await;
    let mut stream = streamed.into_body().into_data_stream();
    let ping = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(ping.as_ref(), b": keepalive\n\n");
}

#[tokio::test]
async fn grdr_session_tag_web_bot_auth_mcp_relay_and_otlp_shipper_work() {
    type CapturedRequest = (String, HeaderMap, Vec<u8>);
    #[derive(Clone)]
    struct MockUpstream {
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        otlp_tx: mpsc::Sender<String>,
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let (otlp_tx, mut otlp_rx) = mpsc::channel(8);
    let mock_state = MockUpstream {
        captured: Arc::clone(&captured),
        otlp_tx,
    };

    let mock_app =
        Router::new()
            .route(
                "/v1/logs",
                post(
                    |State(st): State<MockUpstream>, body: axum::body::Bytes| async move {
                        let s = String::from_utf8_lossy(&body).to_string();
                        let _ = st.otlp_tx.send(s).await;
                        StatusCode::OK
                    },
                ),
            )
            .route(
                "/mcp",
                any(
                    |State(st): State<MockUpstream>,
                     headers: HeaderMap,
                     body: axum::body::Bytes| async move {
                        st.captured
                            .lock()
                            .await
                            .push(("mcp".into(), headers, body.to_vec()));
                        (
                            StatusCode::OK,
                            [("content-type", "application/json")],
                            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                        )
                            .into_response()
                    },
                ),
            )
            .route(
                "/chat",
                post(
                    |State(st): State<MockUpstream>,
                     headers: HeaderMap,
                     body: axum::body::Bytes| async move {
                        st.captured
                            .lock()
                            .await
                            .push(("chat".into(), headers, body.to_vec()));
                        StatusCode::OK.into_response()
                    },
                ),
            )
            .with_state(mock_state);

    let up_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, mock_app).await;
    });

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();

    let egress_cfg = EgressGuardConfig {
        loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
    };
    let shipper = OtlpUpstreamShipper::spawn(OtlpCollectorConfig {
        endpoint_base_url: Url::parse(&format!("http://127.0.0.1:{up_port}")).unwrap(),
        egress_config: egress_cfg,
        queue_capacity: 16,
    })
    .unwrap();
    let signer_kp = SigningKeypair::generate().unwrap();
    let signer_pub = signer_kp.public_key_b64();
    let signer = WebBotAuthSigner::new(
        signer_kp,
        Some("https://guardrails.local/.well-known/http-message-signatures-directory".into()),
    );

    let state = Arc::new(
        ProxyGatewayState::new(
            RecordingDecisionClient::new(Verdict::Allow),
            proxy_port,
            egress_cfg,
        )
        .unwrap()
        .with_otlp_shipper(Some(shipper))
        .with_web_bot_signer(Some(signer)),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    grdr_proxy::local_control::apply_local_control_update(
        &state,
        ProxyControlUpdate::RegisterSession(ControlSessionSpec {
            session_id: "sess-bot-42".into(),
            spiffe_id: "spiffe://guardrails.local/agent/codex/s42".into(),
            device_id: "dev-1".into(),
            agent_name: "codex".into(),
            caller_program: "grdr-proxy".into(),
            instance_token: token.clone(),
            attribution_grade: 4,
            has_session_container: true,
            expected_phantom_tokens: BTreeMap::new(),
            routes: vec![
                ControlRouteSpec {
                    route_id: "llm".into(),
                    provider: "openai".into(),
                    upstream_url: format!("http://127.0.0.1:{up_port}/chat"),
                    credential_id: None,
                    tenant_headers: BTreeMap::new(),
                },
                ControlRouteSpec {
                    route_id: "srv1".into(),
                    provider: "mcp".into(),
                    upstream_url: format!("http://127.0.0.1:{up_port}/mcp"),
                    credential_id: None,
                    tenant_headers: BTreeMap::new(),
                },
            ],
        }),
    )
    .await
    .unwrap();

    let app = build_proxy_router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, app).await;
    });

    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    // Test outbound SR-39 with spoofed Grdr-Session header -> overwritten + signed RFC 9421.
    let llm_resp = http
        .post(format!("http://127.0.0.1:{proxy_port}/t/{token}/llm"))
        .header("host", format!("127.0.0.1:{proxy_port}"))
        .header("content-type", "application/json")
        .header("grdr-session", "spoofed-session")
        .body(r#"{"model":"gpt-5","messages":[{"role":"user","content":"ping"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(llm_resp.status(), StatusCode::OK);

    // Test McpRelay tools/call route.
    let mcp_resp = http
        .post(format!("http://127.0.0.1:{proxy_port}/mcp-relay/{token}/srv1"))
        .header("host", format!("127.0.0.1:{proxy_port}"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_doc","arguments":{"path":"README.md"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(mcp_resp.status(), StatusCode::OK);

    // Test OTLP ingestion fans out sanitized event (with secret token redacted) to collector.
    let otlp_secret = format!("ghp_{}", "abcdef1234567890abcdef123456");
    let otlp_resp = http
        .post(format!("http://127.0.0.1:{proxy_port}/v1/logs"))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "session_id": "sess-bot-42",
                "agent_name": "codex",
                "summary": format!("Authorization: Bearer {otlp_secret}")
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(otlp_resp.status(), StatusCode::OK);

    let shipped = tokio::time::timeout(Duration::from_secs(3), otlp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!shipped.contains(&otlp_secret));
    assert!(shipped.contains("[REDACTED_TOKEN]"));

    let caps = captured.lock().await;
    assert_eq!(caps.len(), 2);
    for (tag, hdrs, _body) in caps.iter() {
        assert_eq!(
            hdrs.get("grdr-session").and_then(|v| v.to_str().ok()),
            Some("sess-bot-42")
        );
        let digest = hdrs.get("content-digest").unwrap().to_str().unwrap();
        let sig_in = hdrs.get("signature-input").unwrap().to_str().unwrap();
        let sig = hdrs.get("signature").unwrap().to_str().unwrap();
        let path = if tag == "chat" { "/chat" } else { "/mcp" };
        verify_web_bot_auth_signature(
            &signer_pub,
            "POST",
            &format!("127.0.0.1:{up_port}"),
            path,
            digest,
            sig_in,
            sig,
        )
        .unwrap();
    }
    let mcp_att = state.decision_client.attempts.lock().await.iter().any(|a| {
        a.control_point == ControlPoint::McpBroker && a.target.starts_with("srv1/read_doc")
    });
    assert!(mcp_att);
}

#[tokio::test]
async fn tls_client_hello_peeking_selective_mitm_and_connect_sni_mismatch_work() {
    let manifest = load_swg_coexistence_manifest(Profile::User).unwrap();
    let ch = build_tls_client_hello("api.anthropic.com", &["h2", "http/1.1"], false);
    let parsed = peek_tls_client_hello(&ch).unwrap().unwrap();
    assert_eq!(parsed.sni_host.as_deref(), Some("api.anthropic.com"));
    assert_eq!(parsed.alpn_protocols, vec!["h2", "http/1.1"]);
    assert!(!parsed.has_ech);

    let env_zscaler = BTreeMap::from([(
        "HTTPS_PROXY".to_string(),
        "http://gateway.zscalertwo.net:9400".to_string(),
    )]);
    let swg = detect_enterprise_swg(&env_zscaler, &[], None, &manifest);
    assert_eq!(swg.detected_product_id.as_deref(), Some("zscaler"));
    assert!(swg.stand_down_required);

    let swg_decision = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::PassthroughOnEch,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg,
            client_hello: Some(parsed.clone()),
        },
        &manifest,
    );
    assert_eq!(
        swg_decision,
        MitmRoutingDecision::Passthrough(MitmBypassReason::EnterpriseSwgStandDown)
    );

    let clean_swg = detect_enterprise_swg(&BTreeMap::new(), &[], None, &manifest);
    let mismatch_ch = build_tls_client_hello("evil.example.org", &["http/1.1"], false);
    let mismatch_parsed = peek_tls_client_hello(&mismatch_ch).unwrap().unwrap();
    let mismatch = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::PassthroughOnEch,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg: clean_swg.clone(),
            client_hello: Some(mismatch_parsed),
        },
        &manifest,
    );
    assert!(matches!(
        mismatch,
        MitmRoutingDecision::Deny(MitmDenyReason::SniMismatch, _)
    ));

    let ech_ch = build_tls_client_hello("api.anthropic.com", &["h2"], true);
    let ech_parsed = peek_tls_client_hello(&ech_ch).unwrap().unwrap();
    assert!(ech_parsed.has_ech);
    let ech_deny = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::RejectWhenMitmRequired,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg: clean_swg.clone(),
            client_hello: Some(ech_parsed),
        },
        &manifest,
    );
    assert!(matches!(
        ech_deny,
        MitmRoutingDecision::Deny(MitmDenyReason::EchBlocked, _)
    ));

    let allow_mitm = evaluate_selective_mitm_policy(
        &SelectiveMitmInput {
            connect_host: "api.anthropic.com".into(),
            caller_class: CallerClass::ManagedAgent,
            local_ca_trust: LocalCaTrust::Trusted,
            pinning_health: PinningHealth::Healthy,
            ech_policy: EchPolicy::PassthroughOnEch,
            swg_override: SwgOverrideMode::RespectStandDown,
            swg: clean_swg,
            client_hello: Some(parsed),
        },
        &manifest,
    );
    assert!(matches!(
        allow_mitm,
        MitmRoutingDecision::InterceptTls { .. }
    ));

    // End-to-end live CONNECT tunnel blocks net.sni-mismatch before forwarding upstream!
    let target_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    let forwarded_bytes = Arc::new(Mutex::new(Vec::<u8>::new()));
    let fwd_copy = Arc::clone(&forwarded_bytes);
    tokio::spawn(async move {
        if let Ok((mut s, _)) = target_listener.accept().await {
            let mut b = [0_u8; 512];
            if let Ok(n) = s.read(&mut b).await {
                fwd_copy
                    .lock()
                    .await
                    .extend_from_slice(b.get(..n).unwrap_or(&[]));
            }
        }
    });

    let state = Arc::new(
        ProxyGatewayState::new(
            RecordingDecisionClient::new(Verdict::Allow),
            18080,
            EgressGuardConfig {
                loopback_policy: LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams,
            },
        )
        .unwrap(),
    );
    let token = InstanceTokenRegistry::issue_token().unwrap();
    grdr_proxy::local_control::apply_local_control_update(
        &state,
        ProxyControlUpdate::RegisterSession(ControlSessionSpec {
            session_id: "sess-sni-1".into(),
            spiffe_id: "spiffe://guardrails.local/agent/codex/sni".into(),
            device_id: "dev-1".into(),
            agent_name: "codex".into(),
            caller_program: "grdr-proxy".into(),
            instance_token: token.clone(),
            attribution_grade: 4,
            has_session_container: true,
            expected_phantom_tokens: BTreeMap::new(),
            routes: vec![],
        }),
    )
    .await
    .unwrap();

    let proxy_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let t_state = Arc::clone(&state);
    let tunnel_res_handle = tokio::spawn(async move {
        let (sock, _) = proxy_listener.accept().await.unwrap();
        handle_tunnel_connection(sock, t_state, None).await
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    client.write_all(connect.as_bytes()).await.unwrap();
    let mut est = [0_u8; 64];
    let n = client.read(&mut est).await.unwrap();
    assert!(
        std::str::from_utf8(est.get(..n).unwrap_or(&[]))
            .unwrap()
            .contains("200")
    );

    // Send TLS ClientHello claiming SNI=spoofed.attacker.example while CONNECT target was 127.0.0.1!
    let spoofed_hello = build_tls_client_hello("spoofed.attacker.example", &["h2"], false);
    client.write_all(&spoofed_hello).await.unwrap();

    let res = tokio::time::timeout(Duration::from_secs(2), tunnel_res_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(res, Err(grdr_proxy::ProxyError::SniMismatch(_))));
    assert!(forwarded_bytes.lock().await.is_empty());
}
