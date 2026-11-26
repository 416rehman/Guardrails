// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::VecDeque;
use std::error::Error;
use std::path::PathBuf;

use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_wire::endpoint::{
    EndpointOverrides, PathComponentFact, PathExpectation, PathNodeKind, PlatformKind,
    check_directory_path, check_path, resolve_endpoint,
};
use grdr_wire::floor_bin::{
    FloorBinError, FloorMatchKind, FloorRuleRecord, FloorTableDocument, FloorTableFreshness,
    MAX_FLOOR_RULES, encode_signed_floor_table, verify_and_decode_floor_table,
};
use grdr_wire::frame::{
    CreditFlow, DEFAULT_INITIAL_CREDIT, IPC_WIRE_VERSION, IpcFrameError, MAX_CREDIT_WINDOW,
    WireFrame, WirePayload, decode_proto_frame, embedded_max_frame_bytes, encode_proto_frame,
    encode_proto_payload,
};
use grdr_wire::messages::{
    ChannelProfileKind, CreditGrantFrame, DecideRequestFrame, EndpointServiceKind,
    EngineForwardFrame, HandoverStage, HeartbeatFrame, HelloFrame, WireActionClass,
    WireControlPoint,
};
use grdr_wire::peer_auth::{
    ClientIdentityPolicy, FrameStream, OsPeerClaims, Profile, Refusal, RefusalCategory,
    ScmServiceState, ServerIdentityPolicy, UnixPeerClaims, WindowsPeerClaims, accept,
    accept_deferred_windows, open,
};

#[derive(Debug)]
struct MemPipe {
    outbound: VecDeque<Vec<u8>>,
    inbound: VecDeque<Vec<u8>>,
}

impl FrameStream for MemPipe {
    fn send_frame_bytes(&mut self, payload: &[u8]) -> Result<(), IpcFrameError> {
        self.outbound.push_back(payload.to_vec());
        Ok(())
    }

    fn recv_frame_bytes(&mut self, max_bytes: usize) -> Result<Vec<u8>, IpcFrameError> {
        let next = self
            .inbound
            .pop_front()
            .ok_or(IpcFrameError::TruncatedFrame {
                expected: 1,
                available: 0,
            })?;
        if next.len() > max_bytes {
            return Err(IpcFrameError::FrameTooLarge {
                len: next.len(),
                max: max_bytes,
            });
        }
        Ok(next)
    }
}

fn valid_nonce() -> Vec<u8> {
    vec![0xAB; 16]
}

fn root_fact() -> PathComponentFact {
    PathComponentFact {
        path: "/".into(),
        is_leaf: false,
        node_kind: PathNodeKind::Directory,
        owner_uid: 0,
        gid: 0,
        posix_mode: 0o755,
        dev: 1,
        ino: 1,
        post_dev: 1,
        post_ino: 1,
    }
}

#[test]
fn embedded_limit_and_proto_frame_roundtrip_and_bounds() {
    let res = run_proto_frame_bounds();
    assert!(res.is_ok(), "{res:?}");
}

fn run_proto_frame_bounds() -> Result<(), Box<dyn Error>> {
    let max_bytes = embedded_max_frame_bytes()?;
    if max_bytes != 1_048_576 {
        return Err(format!("expected 1_048_576 max_frame_bytes, got {max_bytes}").into());
    }

    let frame = WireFrame::with_payload(
        7,
        42,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: "req-1".into(),
            hook_seq: 9,
            agent: "claude-code".into(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::FileWrite as i32,
            session_id: "sess-1".into(),
            target: "rm -rf /tmp/x".into(),
            summary: "shell command".into(),
            command_line: "rm -rf /tmp/x".into(),
            cwd: "/workspace".into(),
            sha256: "abc".into(),
            emitted_mono_ms: 1234,
            tool_name: "Write".into(),
            raw_payload: Vec::new(),
        }),
    );

    let encoded = encode_proto_frame(&frame, max_bytes)?;
    let (decoded, used) = decode_proto_frame(&encoded, max_bytes)?;
    if used != encoded.len() || decoded != frame {
        return Err("proto frame roundtrip mismatch".into());
    }

    let oversized = u32::try_from(max_bytes.saturating_add(1))?;
    let err = decode_proto_frame(&oversized.to_le_bytes(), max_bytes);
    if !matches!(err, Err(IpcFrameError::FrameTooLarge { .. })) {
        return Err("expected FrameTooLarge".into());
    }

    if decode_proto_frame(&0u32.to_le_bytes(), max_bytes) != Err(IpcFrameError::ZeroLengthFrame) {
        return Err("expected ZeroLengthFrame".into());
    }
    Ok(())
}

#[test]
fn credit_flow_enforces_inbound_outbound_and_prevents_overflow_mutation() {
    let res = run_credit_flow();
    assert!(res.is_ok(), "{res:?}");
}

fn run_credit_flow() -> Result<(), Box<dyn Error>> {
    let zero_flow = CreditFlow::new(0);
    if zero_flow.outbound_available() != 0 || zero_flow.inbound_granted() != 0 {
        return Err("CreditFlow::new(0) must preserve 0 credits".into());
    }

    let mut flow = CreditFlow::new(1);
    let forward = WireFrame::with_payload(
        1,
        1,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "r1".into(),
            ..Default::default()
        }),
    );
    flow.try_consume_send(&forward)?;
    if !matches!(
        flow.try_consume_send(&forward),
        Err(IpcFrameError::CreditExhausted { .. })
    ) {
        return Err("expected outbound CreditExhausted".into());
    }

    flow.record_inbound(&forward)?;
    if !matches!(
        flow.record_inbound(&forward),
        Err(IpcFrameError::CreditExhausted { .. })
    ) {
        return Err("expected inbound CreditExhausted on second frame".into());
    }

    let decide = WireFrame::with_payload(
        2,
        2,
        WirePayload::DecideRequest(DecideRequestFrame::default()),
    );
    let hb = WireFrame::with_payload(
        0,
        3,
        WirePayload::Heartbeat(HeartbeatFrame {
            seq: 3,
            monotonic_ms: 10,
            rss_bytes: 1024,
            queue_depth: 0,
            epoch: 1,
        }),
    );
    flow.try_consume_send(&decide)?;
    flow.try_consume_send(&hb)?;

    let grant = WireFrame::with_payload(
        0,
        4,
        WirePayload::CreditGrant(CreditGrantFrame { delta: 4 }),
    );
    flow.record_inbound(&grant)?;
    if flow.outbound_available() != 4 {
        return Err("expected replenished credit of 4".into());
    }

    let mut combined = WireFrame::with_payload(
        0,
        5,
        WirePayload::CreditGrant(CreditGrantFrame { delta: 10 }),
    );
    combined.credit_delta = 5;
    if flow.record_inbound(&combined).is_ok() || flow.outbound_available() != 4 {
        return Err(
            "combined credit_delta + CreditGrant must fail cleanly without mutation".into(),
        );
    }

    let overflow_grant = WireFrame::with_payload(
        0,
        6,
        WirePayload::CreditGrant(CreditGrantFrame {
            delta: MAX_CREDIT_WINDOW,
        }),
    );
    if !matches!(
        flow.record_inbound(&overflow_grant),
        Err(IpcFrameError::CreditOverflow)
    ) || flow.outbound_available() != 4
    {
        return Err("overflow grant must not mutate outbound_available".into());
    }
    Ok(())
}

#[test]
fn peer_auth_handshake_unix_and_windows_negative_policies() {
    let res = run_peer_auth_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_peer_auth_checks() -> Result<(), Box<dyn Error>> {
    let server_claims = OsPeerClaims::Unix(UnixPeerClaims {
        uid: 0,
        gid: 0,
        pid: Some(100),
        has_pidfd: true,
        peer_started_at_ticks: Some(50),
        local_peertoken_verified: true,
    });
    let client_claims = OsPeerClaims::Unix(UnixPeerClaims {
        uid: 1000,
        gid: 1000,
        pid: Some(200),
        has_pidfd: true,
        peer_started_at_ticks: Some(80),
        local_peertoken_verified: false,
    });

    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        service: EndpointServiceKind::Decide as i32,
        profile: ChannelProfileKind::Protected as i32,
        client_nonce: valid_nonce(),
        pid: 200,
        capabilities: vec!["decide.v1".into()],
    };

    let mut server_inbound = VecDeque::new();
    let encoded_hello = grdr_wire::frame::encode_proto_payload(
        &WireFrame::with_payload(1, 1, WirePayload::Hello(hello.clone())),
        1_048_576,
    )?;
    server_inbound.push_back(encoded_hello);
    let server_pipe = MemPipe {
        outbound: VecDeque::new(),
        inbound: server_inbound,
    };

    let srv_policy = ServerIdentityPolicy {
        profile: Profile::Protected,
        allowed_client_uids: vec![1000],
        allowed_windows_sids: vec![],
        minimum_integrity_rid: 0,
        reject_app_container: true,
        require_start_time_before_connect: true,
        require_open_as_self_pipe_check: true,
        require_kernel_peer_token: true,
    };
    let pending = accept(server_pipe, &client_claims, 100, &srv_policy)?;
    let (srv_chan, got_hello) = pending.first_frame(
        EndpointServiceKind::Decide,
        "sha256:floor",
        9,
        HandoverStage::Normal,
        1_048_576,
    )?;
    if got_hello != hello {
        return Err("hello mismatch".into());
    }

    let mut client_pipe = MemPipe {
        outbound: VecDeque::new(),
        inbound: VecDeque::new(),
    };
    let srv_outbound = srv_chan
        .into_inner()
        .outbound
        .pop_front()
        .ok_or("missing server ready frame")?;
    let post_rehandshake = grdr_wire::frame::encode_proto_payload(
        &WireFrame::with_payload(1, 2, WirePayload::Hello(hello.clone())),
        1_048_576,
    )?;
    client_pipe.inbound.push_back(srv_outbound);
    client_pipe.inbound.push_back(post_rehandshake);
    let (mut cli_chan, ready) = open(
        client_pipe,
        &server_claims,
        100,
        &ClientIdentityPolicy {
            profile: Profile::Protected,
            allowed_server_uids: vec![0],
            expected_windows_sids: vec![],
            minimum_integrity_rid: 0,
            require_start_time_before_connect: true,
            require_kernel_peer_token: true,
        },
        hello,
        1_048_576,
    )?;
    if ready.initial_credit != DEFAULT_INITIAL_CREDIT || cli_chan.peer().uid() != Some(0) {
        return Err("unexpected client ready/peer uid".into());
    }

    // Post-handshake HelloFrame must fail closed.
    if !matches!(cli_chan.recv_frame(), Err(Refusal::ProtocolRejected(_))) {
        return Err("post-handshake HelloFrame must be rejected".into());
    }

    // Reject missing kernel token proof on Unix.
    let no_token = OsPeerClaims::Unix(UnixPeerClaims {
        uid: 1000,
        gid: 1000,
        pid: Some(200),
        has_pidfd: false,
        peer_started_at_ticks: Some(80),
        local_peertoken_verified: false,
    });
    if !matches!(
        accept(
            MemPipe {
                outbound: VecDeque::new(),
                inbound: VecDeque::new(),
            },
            &no_token,
            100,
            &srv_policy,
        ),
        Err(Refusal::UnauthenticatedPeer(_))
    ) {
        return Err("unix peer without pidfd/peertoken must be rejected".into());
    }

    // Windows client negative checks: empty allowlist, AppContainer, no OpenAsSelf, Low IL.
    let win_client = WindowsPeerClaims {
        pid: 42,
        peer_sid: "S-1-5-21-1001".into(),
        integrity_rid: 0x2000,
        is_app_container: false,
        thread_token_open_as_self: true,
        peer_started_at_100ns: Some(50),
        server_pid_from_pipe: None,
        pipe_owner_sid: None,
        scm_pre_pids: vec![],
        scm_post_pids: vec![],
        scm_state: ScmServiceState::Unknown,
        scm_expected_sid: None,
    };
    let win_srv_policy = ServerIdentityPolicy {
        profile: Profile::User,
        allowed_client_uids: vec![],
        allowed_windows_sids: vec!["S-1-5-21-1001".into()],
        minimum_integrity_rid: 0x2000,
        reject_app_container: true,
        require_start_time_before_connect: true,
        require_open_as_self_pipe_check: true,
        require_kernel_peer_token: true,
    };
    let mut empty_sid_policy = win_srv_policy.clone();
    empty_sid_policy.allowed_windows_sids.clear();
    if accept(
        MemPipe {
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
        },
        &OsPeerClaims::Windows(win_client.clone()),
        100,
        &empty_sid_policy,
    )
    .is_ok()
    {
        return Err("empty allowed_windows_sids must fail closed".into());
    }

    let mut ac_client = win_client.clone();
    ac_client.is_app_container = true;
    if !matches!(
        accept(
            MemPipe {
                outbound: VecDeque::new(),
                inbound: VecDeque::new(),
            },
            &OsPeerClaims::Windows(ac_client),
            100,
            &win_srv_policy,
        ),
        Err(Refusal::PrivilegeTooLow(_))
    ) {
        return Err("AppContainer client must be rejected".into());
    }

    let mut no_open_as_self = win_client;
    no_open_as_self.thread_token_open_as_self = false;
    if !matches!(
        accept(
            MemPipe {
                outbound: VecDeque::new(),
                inbound: VecDeque::new(),
            },
            &OsPeerClaims::Windows(no_open_as_self),
            100,
            &win_srv_policy,
        ),
        Err(Refusal::UnauthenticatedPeer(_))
    ) {
        return Err("Windows client without OpenAsSelf must be rejected".into());
    }

    // Deferred Windows two-stage accept without callback fails closed.
    let deferred = accept_deferred_windows(
        MemPipe {
            outbound: VecDeque::new(),
            inbound: VecDeque::from(vec![encoded_hello_user()]),
        },
        100,
        &win_srv_policy,
    )?;
    if deferred
        .first_frame(
            EndpointServiceKind::Decide,
            "sha256:floor",
            9,
            HandoverStage::Normal,
            1_048_576,
        )
        .is_ok()
    {
        return Err("deferred windows channel without post-read claims must fail closed".into());
    }

    // Windows server peer-auth bypass regressions (OR bypass, pipe_owner_sid, transient SCM restart).
    let win_cli_policy = ClientIdentityPolicy {
        profile: Profile::Protected,
        allowed_server_uids: vec![],
        expected_windows_sids: vec!["S-1-5-18".into()],
        minimum_integrity_rid: 0x4000,
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
    };
    let attacker_or_bypass = WindowsPeerClaims {
        pid: 88,
        peer_sid: "S-1-5-21-attacker".into(),
        integrity_rid: 0x4000,
        is_app_container: false,
        thread_token_open_as_self: false,
        peer_started_at_100ns: Some(50),
        server_pid_from_pipe: Some(88),
        pipe_owner_sid: Some("S-1-5-21-attacker".into()),
        scm_pre_pids: vec![88],
        scm_post_pids: vec![88],
        scm_state: ScmServiceState::Running,
        scm_expected_sid: Some("S-1-5-18".into()),
    };
    if !matches!(
        grdr_wire::peer_policy::verify_server_peer(
            &OsPeerClaims::Windows(attacker_or_bypass),
            100,
            &win_cli_policy,
        ),
        Err(Refusal::UntrustedServerIdentity(_))
    ) {
        return Err("scm_expected_sid OR bypass must fail closed".into());
    }

    let restarting_srv = WindowsPeerClaims {
        pid: 88,
        peer_sid: "S-1-5-18".into(),
        integrity_rid: 0x4000,
        is_app_container: false,
        thread_token_open_as_self: false,
        peer_started_at_100ns: Some(50),
        server_pid_from_pipe: Some(88),
        pipe_owner_sid: Some("S-1-5-18".into()),
        scm_pre_pids: vec![77],
        scm_post_pids: vec![88],
        scm_state: ScmServiceState::Running,
        scm_expected_sid: Some("S-1-5-18".into()),
    };
    match grdr_wire::peer_policy::verify_server_peer(
        &OsPeerClaims::Windows(restarting_srv),
        100,
        &win_cli_policy,
    ) {
        Err(ref r) if r.category() == RefusalCategory::Transient => {}
        other => return Err(format!("expected Transient refusal, got {other:?}").into()),
    }

    // P8 Refusal::Display must redact paths, UIDs, and SIDs.
    let path_refusal = Refusal::UnsafeEndpointPath(grdr_wire::peer_auth::Evidence::PathUnsafe {
        path: "/home/alice/.local/state/guardrails/decide.sock".into(),
        detail: "leaky".into(),
    });
    let rendered = path_refusal.to_string();
    if rendered.contains("alice") || rendered.contains("leaky") {
        return Err(format!("Refusal::Display leaked raw evidence: {rendered}").into());
    }
    Ok(())
}

fn encoded_hello_user() -> Vec<u8> {
    grdr_wire::frame::encode_proto_payload(
        &WireFrame::with_payload(
            1,
            1,
            WirePayload::Hello(HelloFrame {
                protocol_version: IPC_WIRE_VERSION,
                service: EndpointServiceKind::Decide as i32,
                profile: ChannelProfileKind::User as i32,
                client_nonce: valid_nonce(),
                pid: 42,
                capabilities: vec![],
            }),
        ),
        1_048_576,
    )
    .unwrap_or_default()
}

#[test]
fn endpoint_resolution_and_path_checks_enforce_strict_invariants() {
    let res = run_endpoint_and_path_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_endpoint_and_path_checks() -> Result<(), Box<dyn Error>> {
    let win_prot = resolve_endpoint(
        EndpointServiceKind::Decide,
        Profile::Protected,
        &EndpointOverrides::default(),
        PlatformKind::Windows,
    )?;
    if win_prot.pipe_name.as_deref() != Some(r"\\.\pipe\grdr-protected-decide") {
        return Err(format!(
            "unexpected Windows protected pipe: {:?}",
            win_prot.pipe_name
        )
        .into());
    }

    let mac_prot = resolve_endpoint(
        EndpointServiceKind::Decide,
        Profile::Protected,
        &EndpointOverrides::default(),
        PlatformKind::MacOs,
    )?;
    if mac_prot.unix_path
        != Some(PathBuf::from(
            "/Library/Application Support/grdr/run/decide.sock",
        ))
    {
        return Err(format!("unexpected macOS protected path: {:?}", mac_prot.unix_path).into());
    }

    let prot_override = resolve_endpoint(
        EndpointServiceKind::Decide,
        Profile::Protected,
        &EndpointOverrides {
            env_override_unix_path: Some(PathBuf::from("/tmp/evil.sock")),
            ..EndpointOverrides::default()
        },
        PlatformKind::Linux,
    );
    if !matches!(prot_override, Err(Refusal::PolicyProfileMismatch(_))) {
        return Err("Protected profile must reject env overrides".into());
    }

    let unc_override = resolve_endpoint(
        EndpointServiceKind::Decide,
        Profile::User,
        &EndpointOverrides {
            env_override_pipe_name: Some(r"\\attacker\pipe\evil".into()),
            ..EndpointOverrides::default()
        },
        PlatformKind::Windows,
    );
    if !matches!(unc_override, Err(Refusal::UnsafeEndpointPath(_))) {
        return Err("remote UNC pipe override must be rejected".into());
    }

    let sticky_tmp = check_path(
        &[
            root_fact(),
            PathComponentFact {
                path: "/tmp".into(),
                is_leaf: false,
                node_kind: PathNodeKind::Directory,
                owner_uid: 0,
                gid: 0,
                posix_mode: 0o1777,
                dev: 1,
                ino: 2,
                post_dev: 1,
                post_ino: 2,
            },
            PathComponentFact {
                path: "/tmp/decide.sock".into(),
                is_leaf: true,
                node_kind: PathNodeKind::Socket,
                owner_uid: 0,
                gid: 0,
                posix_mode: 0o600,
                dev: 1,
                ino: 3,
                post_dev: 1,
                post_ino: 3,
            },
        ],
        &PathExpectation {
            profile: Profile::User,
            trusted_owner_uids: vec![0, 1000],
            trusted_group_gids: vec![0, 1000],
            allow_world_writable_socket_leaf: false,
        },
    );
    if !matches!(sticky_tmp, Err(Refusal::UnsafeEndpointPath(_))) {
        return Err("0o1777 sticky /tmp ancestor must be rejected".into());
    }

    let non_root_protected = check_path(
        &[
            root_fact(),
            PathComponentFact {
                path: "/run".into(),
                is_leaf: false,
                node_kind: PathNodeKind::Directory,
                owner_uid: 1000,
                gid: 1000,
                posix_mode: 0o755,
                dev: 1,
                ino: 2,
                post_dev: 1,
                post_ino: 2,
            },
            PathComponentFact {
                path: "/run/decide.sock".into(),
                is_leaf: true,
                node_kind: PathNodeKind::Socket,
                owner_uid: 0,
                gid: 0,
                posix_mode: 0o666,
                dev: 1,
                ino: 3,
                post_dev: 1,
                post_ino: 3,
            },
        ],
        &PathExpectation {
            profile: Profile::Protected,
            trusted_owner_uids: vec![0, 1000],
            trusted_group_gids: vec![0],
            allow_world_writable_socket_leaf: true,
        },
    );
    if !matches!(non_root_protected, Err(Refusal::UnsafeEndpointPath(_))) {
        return Err("Protected profile must enforce uid 0 regardless of trusted_owner_uids".into());
    }
    Ok(())
}

#[test]
fn signed_floor_bin_verifies_signature_before_expiry_and_rejects_malformed() {
    let res = run_signed_floor_bin();
    assert!(res.is_ok(), "{res:?}");
}

fn run_signed_floor_bin() -> Result<(), Box<dyn Error>> {
    let key = grdr_crypto::SigningKeypair::generate()?;
    let pubkey_b64 = key.public_key_b64();
    let kid = key.key_id().to_string();
    let doc = FloorTableDocument {
        epoch: 77,
        expires_at_unix_s: 2_000_000_000,
        signer_key_id: kid.clone(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::Exec,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "DET-01".into(),
            pattern: "rm -rf /".into(),
            agents: Vec::new(),
        }],
    };
    let mut encoded = encode_signed_floor_table(&doc, &key)?;
    let decoded = verify_and_decode_floor_table(
        &encoded,
        &[(kid.as_str(), pubkey_b64.as_str())],
        1_900_000_000,
    )?;
    if decoded.document != doc || decoded.freshness != FloorTableFreshness::Fresh {
        return Err("decoded floor doc mismatch".into());
    }

    // Validly signed expired table remains active as Stale per D-37.
    let stale = verify_and_decode_floor_table(
        &encoded,
        &[(kid.as_str(), pubkey_b64.as_str())],
        2_100_000_000,
    )?;
    if !matches!(stale.freshness, FloorTableFreshness::Stale { .. }) {
        return Err("valid expired floor table must decode as Stale".into());
    }

    // Wall-clock 0 marks table Stale rather than Fresh.
    let epoch_zero =
        verify_and_decode_floor_table(&encoded, &[(kid.as_str(), pubkey_b64.as_str())], 0)?;
    if !matches!(epoch_zero.freshness, FloorTableFreshness::Stale { .. }) {
        return Err("now_unix_s == 0 must mark floor table Stale".into());
    }

    // Tampering header expires_at=0 MUST fail signature verification before expiry check.
    for slot in encoded.iter_mut().take(28).skip(20) {
        *slot = 0;
    }
    let tampered = verify_and_decode_floor_table(
        &encoded,
        &[(kid.as_str(), pubkey_b64.as_str())],
        1_900_000_000,
    );
    if !matches!(tampered, Err(FloorBinError::UntrustedSignature)) {
        return Err(format!("expected UntrustedSignature, got {tampered:?}").into());
    }

    // Empty trusted keys fails closed.
    if !matches!(
        verify_and_decode_floor_table(&encoded, &[], 1_900_000_000),
        Err(FloorBinError::EmptyTrustedKeys)
    ) {
        return Err("empty trusted keys must fail closed".into());
    }

    // Spoofed max rule count on tiny buffer fails before allocating full rules.
    let mut spoofed = encode_signed_floor_table(&doc, &key)?;
    let count_offset = 8 + 4 + 8 + 8 + 2 + kid.len();
    if let Some(slot) = spoofed.get_mut(count_offset..count_offset + 4) {
        slot.copy_from_slice(&(u32::try_from(MAX_FLOOR_RULES)?).to_le_bytes());
    }
    if verify_and_decode_floor_table(
        &spoofed,
        &[(kid.as_str(), pubkey_b64.as_str())],
        1_900_000_000,
    )
    .is_ok()
    {
        return Err("spoofed rule count must be rejected".into());
    }
    Ok(())
}

#[test]
fn r2_protected_server_start_time_directory_chain_and_floor_match_kinds() {
    let res = run_r2_wire_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_r2_wire_checks() -> Result<(), Box<dyn Error>> {
    use grdr_wire::peer_auth::Evidence;
    use grdr_wire::peer_policy::verify_server_peer;

    let key = grdr_crypto::SigningKeypair::generate()?;
    let pubkey = key.public_key_b64();
    let kid = key.key_id().to_string();
    let doc = FloorTableDocument {
        epoch: 9,
        expires_at_unix_s: 2_000_000_000,
        signer_key_id: kid.clone(),
        rules: vec![
            FloorRuleRecord {
                action_class: FastActionClass::FileRead,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Prefix,
                rule_id: "DET-PRE".into(),
                pattern: "/etc/shadow".into(),
                agents: vec!["claude-code".into()],
            },
            FloorRuleRecord {
                action_class: FastActionClass::Elevate,
                verdict: FastVerdict::StepUp,
                match_kind: FloorMatchKind::Any,
                rule_id: "DET-ANY".into(),
                pattern: String::new(),
                agents: Vec::new(),
            },
        ],
    };
    let encoded = encode_signed_floor_table(&doc, &key)?;
    let decoded =
        verify_and_decode_floor_table(&encoded, &[(kid.as_str(), pubkey.as_str())], 1_900_000_000)?;
    if decoded.document != doc {
        return Err("floor doc with Prefix/Any/agents failed roundtrip".into());
    }
    let r0 = decoded.document.rules.first().ok_or("missing rule 0")?;
    let r1 = decoded.document.rules.get(1).ok_or("missing rule 1")?;
    if !r0.matches(FastActionClass::FileRead, "Claude-Code", "/etc/shadow.bak")
        || r0.matches(FastActionClass::FileRead, "codex", "/etc/shadow")
    {
        return Err("Prefix or agent scoping failed".into());
    }
    if !r1.matches(FastActionClass::Elevate, "codex", "sudo id") {
        return Err("Any floor rule must match regardless of pattern".into());
    }

    let dir_chain = vec![
        PathComponentFact {
            path: "/".into(),
            node_kind: PathNodeKind::Directory,
            owner_uid: 0,
            gid: 0,
            posix_mode: 0o755,
            dev: 1,
            ino: 1,
            post_dev: 1,
            post_ino: 1,
            is_leaf: false,
        },
        PathComponentFact {
            path: "/run".into(),
            node_kind: PathNodeKind::Directory,
            owner_uid: 0,
            gid: 0,
            posix_mode: 0o755,
            dev: 1,
            ino: 2,
            post_dev: 1,
            post_ino: 2,
            is_leaf: false,
        },
    ];
    let dir_exp = PathExpectation {
        profile: Profile::Protected,
        trusted_owner_uids: vec![0],
        trusted_group_gids: vec![0],
        allow_world_writable_socket_leaf: false,
    };
    check_directory_path(&dir_chain, &dir_exp)?;
    let mut bad_dir = dir_chain.clone();
    if let Some(entry) = bad_dir.get_mut(1) {
        entry.node_kind = PathNodeKind::Symlink;
    }
    if check_directory_path(&bad_dir, &dir_exp).is_ok() {
        return Err("check_directory_path must reject symlink in chain".into());
    }

    let prot_win_policy = ClientIdentityPolicy {
        profile: Profile::Protected,
        allowed_server_uids: Vec::new(),
        expected_windows_sids: vec!["S-1-5-80-1234".into()],
        minimum_integrity_rid: 0x3000,
        require_kernel_peer_token: true,
        require_start_time_before_connect: true,
    };
    let mut prot_win_claims = WindowsPeerClaims {
        pid: 4242,
        peer_sid: "S-1-5-80-1234".into(),
        integrity_rid: 0x4000,
        is_app_container: false,
        thread_token_open_as_self: false,
        pipe_owner_sid: Some("S-1-5-80-1234".into()),
        scm_expected_sid: None,
        server_pid_from_pipe: Some(4242),
        scm_pre_pids: vec![4242],
        scm_post_pids: vec![4242],
        scm_state: ScmServiceState::Running,
        peer_started_at_100ns: None,
    };
    verify_server_peer(
        &OsPeerClaims::Windows(prot_win_claims.clone()),
        999,
        &prot_win_policy,
    )?;

    prot_win_claims.peer_started_at_100ns = Some(1000);
    if !matches!(
        verify_server_peer(
            &OsPeerClaims::Windows(prot_win_claims.clone()),
            999,
            &prot_win_policy
        ),
        Err(Refusal::PidReuseSuspected(Evidence::StartTimeSkew { .. }))
    ) {
        return Err("Protected Windows server with future start time must fail skew".into());
    }

    let mut user_win_policy = prot_win_policy;
    user_win_policy.profile = Profile::User;
    prot_win_claims.peer_started_at_100ns = None;
    if !matches!(
        verify_server_peer(
            &OsPeerClaims::Windows(prot_win_claims),
            999,
            &user_win_policy
        ),
        Err(Refusal::PidReuseSuspected(Evidence::StartTimeMissing))
    ) {
        return Err("User Windows server with missing start time must fail closed".into());
    }

    let prot_mac_policy = ClientIdentityPolicy {
        profile: Profile::Protected,
        allowed_server_uids: vec![0],
        expected_windows_sids: Vec::new(),
        minimum_integrity_rid: 0,
        require_kernel_peer_token: true,
        require_start_time_before_connect: true,
    };
    let mac_root_claims = UnixPeerClaims {
        uid: 0,
        gid: 0,
        pid: Some(100),
        has_pidfd: false,
        local_peertoken_verified: true,
        peer_started_at_ticks: None,
    };
    verify_server_peer(&OsPeerClaims::Unix(mac_root_claims), 500, &prot_mac_policy)?;

    let mut pipe = MemPipe {
        outbound: VecDeque::new(),
        inbound: VecDeque::new(),
    };
    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        profile: 2,
        service: EndpointServiceKind::Decide as i32,
        client_nonce: vec![1u8; 16],
        pid: 55,
        capabilities: vec!["decide".into()],
    };
    let ready = grdr_wire::messages::ReadyFrame {
        protocol_version: IPC_WIRE_VERSION,
        initial_credit: DEFAULT_INITIAL_CREDIT,
        max_frame_bytes: 65_536,
        server_nonce: vec![1u8; 32],
        floor_digest: "d".into(),
        epoch: 1,
        handover_stage: HandoverStage::Normal as i32,
    };
    let ready_bytes = encode_proto_payload(
        &WireFrame::with_payload(1, 1, WirePayload::Ready(ready)),
        65_536,
    )?;
    pipe.inbound.push_back(ready_bytes);
    let user_policy = ClientIdentityPolicy {
        profile: Profile::User,
        allowed_server_uids: vec![1000],
        expected_windows_sids: Vec::new(),
        minimum_integrity_rid: 0,
        require_kernel_peer_token: true,
        require_start_time_before_connect: true,
    };
    let (mut ch, _) = open(
        pipe,
        &OsPeerClaims::Unix(UnixPeerClaims {
            uid: 1000,
            gid: 1000,
            pid: Some(55),
            has_pidfd: true,
            local_peertoken_verified: false,
            peer_started_at_ticks: Some(10),
        }),
        20,
        &user_policy,
        hello.clone(),
        65_536,
    )?;
    if !matches!(
        ch.send_frame(WireFrame::with_payload(1, 2, WirePayload::Hello(hello))),
        Err(Refusal::ProtocolRejected(Evidence::FrameError { .. }))
    ) {
        return Err("post-handshake Hello send must fail".into());
    }
    Ok(())
}
