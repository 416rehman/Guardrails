// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Inherited-channel IPC loop for `grdr-uplink` over `ProtoIpcStream`.

use std::path::PathBuf;
use std::time::Duration;

use grdr_ipc_os::inherited_stdio_pipe;
use grdr_ipc_os::proto_io::ProtoIpcStream;
use grdr_os_clock::{Clock, SystemClock};
use grdr_os_service::current_process_rss_bytes;
use grdr_wire::frame::{WireFrame, WirePayload};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::{EndpointServiceKind, ErrorFrame, HandoverStage, HeartbeatFrame};
use grdr_wire::peer_auth::{
    Evidence, OsPeerClaims, Profile, Refusal, ServerIdentityPolicy, accept,
};

use crate::worker::{UplinkWorkerConfig, UplinkWorkerState};

/// Run the inherited-channel worker loop with default unpinned `Standard` config.
pub fn run_stdio_daemon_worker(staging_root: PathBuf) -> Result<(), String> {
    run_stdio_daemon_worker_with_config(staging_root, UplinkWorkerConfig::default())
}

/// Run the inherited-channel worker loop configured with explicit device id, network mode, and pinned anchor.
pub fn run_stdio_daemon_worker_with_config(
    staging_root: PathBuf,
    config: UplinkWorkerConfig,
) -> Result<(), String> {
    let clock = SystemClock::new();
    let limits = embedded_limits().map_err(|e| e.to_string())?;
    let mut state =
        UplinkWorkerState::with_config(staging_root, config, &clock).map_err(|e| e.to_string())?;
    let read_timeout = Duration::from_millis(limits.read_timeout_ms.max(1));
    let pipe = inherited_stdio_pipe().map_err(|e| format!("GRDR-UPLINK-0012: {e}"))?;
    let stream = ProtoIpcStream::with_timeouts(pipe, read_timeout, read_timeout);
    let policy = ServerIdentityPolicy {
        profile: Profile::Inherited,
        allowed_client_uids: Vec::new(),
        allowed_windows_sids: Vec::new(),
        minimum_integrity_rid: 0,
        reject_app_container: false,
        require_start_time_before_connect: false,
        require_open_as_self_pipe_check: false,
        require_kernel_peer_token: false,
    };
    let (mut chan, _hello) = accept(stream, &OsPeerClaims::Inherited, 0, &policy)
        .and_then(|pending| {
            pending.first_frame(
                EndpointServiceKind::ProviderUplink,
                "",
                0,
                HandoverStage::Normal,
                limits.max_frame_bytes,
            )
        })
        .map_err(|e| format!("GRDR-UPLINK-0013: IPC accept failed: {e}"))?;

    let mut seq: u64 = 1;
    let mut timeout_elapsed_ms: u64 = 0;
    loop {
        let frame = match chan.recv_frame() {
            Ok(f) => {
                timeout_elapsed_ms = 0;
                f
            }
            Err(Refusal::ProtocolRejected(Evidence::FrameError { ref detail }))
                if detail.contains("GRDR-WIRE-0036") =>
            {
                break;
            }
            Err(Refusal::ProtocolRejected(Evidence::FrameError { ref detail }))
                if detail.contains("GRDR-WIRE-0037") =>
            {
                timeout_elapsed_ms = timeout_elapsed_ms.saturating_add(limits.read_timeout_ms);
                if timeout_elapsed_ms >= 5_000 {
                    return Err(
                        "GRDR-UPLINK-0013: daemon heartbeat watchdog timeout exceeded 5s"
                            .to_string(),
                    );
                }
                continue;
            }
            Err(err) => return Err(format!("GRDR-UPLINK-0013: IPC receive failed: {err}")),
        };

        match frame.payload {
            Some(WirePayload::Heartbeat(hb)) => {
                let mono_ms = clock
                    .boot_uptime()
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .map_err(|e| format!("GRDR-UPLINK-0008: {e}"))?;
                chan.send_frame(WireFrame::with_payload(
                    0,
                    seq,
                    WirePayload::Heartbeat(HeartbeatFrame {
                        seq: hb.seq,
                        monotonic_ms: mono_ms,
                        rss_bytes: current_process_rss_bytes(),
                        queue_depth: u32::try_from(state.queued_total()).unwrap_or(u32::MAX),
                        epoch: hb.epoch,
                    }),
                ))
                .map_err(|e| format!("GRDR-UPLINK-0013: failed to send heartbeat: {e}"))?;
            }
            Some(WirePayload::UplinkCommand(cmd)) => {
                let ev = state.handle_command(&cmd, &clock);
                chan.send_frame(WireFrame::with_payload(
                    frame.stream_id,
                    seq,
                    WirePayload::UplinkEvent(ev),
                ))
                .map_err(|e| format!("GRDR-UPLINK-0013: failed to send uplink event: {e}"))?;
            }
            Some(WirePayload::CreditGrant(_)) | None => continue,
            Some(_) => {
                chan.send_frame(WireFrame::with_payload(
                    frame.stream_id,
                    seq,
                    WirePayload::Error(ErrorFrame {
                        code: "GRDR-UPLINK-0001".to_string(),
                        message: "unexpected frame payload on uplink channel".to_string(),
                        retryable: false,
                    }),
                ))
                .map_err(|e| format!("GRDR-UPLINK-0013: failed to send error frame: {e}"))?;
            }
        }
        seq = seq.saturating_add(1);
    }
    Ok(())
}
