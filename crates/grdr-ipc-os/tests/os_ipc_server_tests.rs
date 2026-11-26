// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#[cfg(windows)]
#[test]
fn windows_named_pipe_server_first_instance_dacl_and_wire_handshake() {
    let res = run_windows_pipe_handshake();
    assert!(res.is_ok(), "{res:?}");
}

#[cfg(windows)]
fn run_windows_pipe_handshake() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    use grdr_ipc_os::LocalEndpointAddress;
    use grdr_ipc_os::endpoint::WindowsPipeOpenPolicy;
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_ipc_os::transport::{Acceptor, Connector, FixedTimestampSource, IpcDeadline};
    use grdr_ipc_os::windows_pipe::WindowsNamedPipeConnector;
    use grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor;
    use grdr_wire::frame::{
        DEFAULT_INITIAL_CREDIT, IPC_WIRE_VERSION, WireFrame, WirePayload, decode_proto_payload,
        encode_proto_payload,
    };
    use grdr_wire::messages::{
        ChannelProfileKind, EndpointServiceKind, HandoverStage, HelloFrame, ReadyFrame,
    };
    use grdr_wire::peer_auth::FrameStream;

    let pipe_name = format!(r"\\.\pipe\grdr-user-test-{}", std::process::id());
    if WindowsNamedPipeAcceptor::bind(r"\\.\pipe\sub\bad", "D:(A;;GA;;;OW)").is_ok() {
        return Err("bind must reject invalid pipe leaf".into());
    }
    if WindowsNamedPipeAcceptor::bind(&pipe_name, "D:(A;;GA;;;OW)\0bad").is_ok() {
        return Err("bind must reject NUL in SDDL".into());
    }

    let test_sddl = "D:(A;;GA;;;OW)(A;;0x00120083;;;AU)S:(ML;;NW;;;ME)";
    let mut acceptor = WindowsNamedPipeAcceptor::bind(&pipe_name, test_sddl)?;

    if WindowsNamedPipeAcceptor::bind(&pipe_name, test_sddl).is_ok() {
        return Err("second bind must fail due to FILE_FLAG_FIRST_PIPE_INSTANCE".into());
    }

    let srv = std::thread::spawn(move || -> Result<u32, String> {
        let stream = acceptor
            .accept(Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
        let connected_at = stream.connected_at_100ns();
        if connected_at == 0 {
            return Err("expected non-zero connected_at".to_string());
        }
        let mut proto = ProtoIpcStream::new(stream);
        let raw = proto
            .recv_frame_bytes(1_048_576)
            .map_err(|e| e.to_string())?;
        let frame = decode_proto_payload(&raw, 1_048_576).map_err(|e| e.to_string())?;
        let hello = match frame.payload {
            Some(WirePayload::Hello(h)) => h,
            other => return Err(format!("expected Hello frame, got {other:?}")),
        };
        let ready = WireFrame {
            stream_id: 1,
            seq: 1,
            credit_delta: DEFAULT_INITIAL_CREDIT,
            payload: Some(WirePayload::Ready(ReadyFrame {
                protocol_version: IPC_WIRE_VERSION,
                server_nonce: grdr_wire::generate_nonce()
                    .map_err(|e| e.to_string())?
                    .into_bytes(),
                max_frame_bytes: 1_048_576,
                handover_stage: HandoverStage::Normal as i32,
                initial_credit: DEFAULT_INITIAL_CREDIT,
                floor_digest: "sha256:test".to_string(),
                epoch: 1,
            })),
        };
        let encoded_ready = encode_proto_payload(&ready, 1_048_576).map_err(|e| e.to_string())?;
        proto
            .send_frame_bytes(&encoded_ready)
            .map_err(|e| e.to_string())?;
        if !matches!(
            proto.recv_frame_bytes(1_048_576),
            Err(grdr_wire::frame::IpcFrameError::EndOfStream)
        ) {
            return Err("expected EndOfStream after client closes pipe".to_string());
        }
        acceptor.stop();
        if !matches!(
            acceptor.accept(Duration::from_millis(50)),
            Err(grdr_ipc_os::IpcError::Stopped)
        ) {
            return Err("stopped acceptor must return Stopped".to_string());
        }
        Ok(hello.pid)
    });

    let addr = LocalEndpointAddress::WindowsPipe { pipe_name };
    let connector = WindowsNamedPipeConnector::with_policy(WindowsPipeOpenPolicy::default());
    let link = connector.connect(
        &addr,
        IpcDeadline::call_default(),
        &FixedTimestampSource::new(jiff::Timestamp::UNIX_EPOCH),
    )?;
    let mut proto = ProtoIpcStream::new(link);
    let hello = WireFrame {
        stream_id: 1,
        seq: 1,
        credit_delta: 0,
        payload: Some(WirePayload::Hello(HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: EndpointServiceKind::Decide as i32,
            profile: ChannelProfileKind::User as i32,
            client_nonce: grdr_wire::generate_nonce()?.into_bytes(),
            pid: std::process::id(),
            capabilities: vec![],
        })),
    };
    let encoded_hello = encode_proto_payload(&hello, 1_048_576)?;
    proto.send_frame_bytes(&encoded_hello)?;
    let raw_reply = proto.recv_frame_bytes(1_048_576)?;
    let reply = decode_proto_payload(&raw_reply, 1_048_576)?;
    let ready = match reply.payload {
        Some(WirePayload::Ready(r)) => r,
        other => return Err(format!("expected Ready frame, got {other:?}").into()),
    };
    if ready.initial_credit != DEFAULT_INITIAL_CREDIT {
        return Err("unexpected initial credit".into());
    }
    drop(proto);

    let pid = srv
        .join()
        .map_err(|_| "server thread panicked".to_string())??;
    if pid != std::process::id() {
        return Err("server saw wrong client pid".into());
    }
    Ok(())
}

#[test]
fn inherited_stdio_duplex_pipes_enforce_deadlines_and_carry_proto_frames() {
    let res = run_stdio_duplex();
    assert!(res.is_ok(), "{res:?}");
}

fn run_stdio_duplex() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    use grdr_ipc_os::proto_io::{DuplexPipe, ProtoIpcStream, create_inherited_stdio_pair};
    use grdr_wire::frame::{IpcFrameError, WireFrame, WirePayload};
    use grdr_wire::messages::HeartbeatFrame;
    use grdr_wire::peer_auth::FrameStream;

    let (mut parent_pipe, (child_r, child_w)) = create_inherited_stdio_pair()?;
    parent_pipe.set_deadlines(Duration::from_millis(40), Duration::from_millis(40));
    let mut child_pipe = DuplexPipe::new(child_r, child_w);
    child_pipe.set_deadlines(Duration::from_millis(40), Duration::from_millis(40));
    let mut parent = ProtoIpcStream::new(parent_pipe);
    let mut child = ProtoIpcStream::new(child_pipe);

    // Watchdog check: reading silent pipe times out cleanly instead of wedging.
    if !matches!(
        child.recv_frame_bytes(65_536),
        Err(IpcFrameError::TimedOut { .. })
    ) {
        return Err("expected TimedOut on idle child DuplexPipe".into());
    }

    let frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::Heartbeat(HeartbeatFrame {
            seq: 5,
            monotonic_ms: 42,
            rss_bytes: 2048,
            queue_depth: 1,
            epoch: 2,
        }),
    );
    let payload = grdr_wire::frame::encode_proto_payload(&frame, 65_536)?;
    parent.send_frame_bytes(&payload)?;
    let got = child.recv_frame_bytes(65_536)?;
    let decoded = grdr_wire::frame::decode_proto_payload(&got, 65_536)?;
    if decoded != frame {
        return Err("frame mismatch over inherited stdio pair".into());
    }
    drop(parent);
    if !matches!(
        child.recv_frame_bytes(65_536),
        Err(IpcFrameError::EndOfStream)
    ) {
        return Err("expected EndOfStream after writer drop".into());
    }
    Ok(())
}
