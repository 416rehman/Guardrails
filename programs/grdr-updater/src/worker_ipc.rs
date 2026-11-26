// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Inherited-channel IPC loop for `grdr-updater` over `ProtoIpcStream`.

use std::path::Path;
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

use crate::worker::{UpdaterWorkerConfig, UpdaterWorkerState};

/// Run the inherited-channel updater worker loop with default config.
pub fn run_stdio_daemon_worker(state_root: &Path) -> Result<(), String> {
    run_stdio_daemon_worker_with_config(state_root, UpdaterWorkerConfig::default())
}

/// Run the inherited-channel updater worker loop with explicit authority and pinned TUF roots.
pub fn run_stdio_daemon_worker_with_config(
    state_root: &Path,
    config: UpdaterWorkerConfig,
) -> Result<(), String> {
    let clock = SystemClock::new();
    let limits = embedded_limits().map_err(|e| e.to_string())?;
    let mut state = UpdaterWorkerState::open_with_config(state_root.to_path_buf(), config, &clock)
        .map_err(|e| e.to_string())?;
    let read_timeout = Duration::from_millis(limits.read_timeout_ms.max(1));
    let pipe = inherited_stdio_pipe().map_err(|e| format!("GRDR-UPDATER-0005: {e}"))?;
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
    let pending =
        accept(stream, &OsPeerClaims::Inherited, 0, &policy).map_err(|e| e.to_string())?;
    let (mut chan, _hello) = pending
        .first_frame(
            EndpointServiceKind::ProviderUpdater,
            "updater-worker",
            state.security_floor(),
            HandoverStage::Normal,
            limits.max_frame_bytes,
        )
        .map_err(|e| e.to_string())?;

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
                        "GRDR-UPDATER-0007: daemon heartbeat watchdog timeout exceeded 5s"
                            .to_string(),
                    );
                }
                continue;
            }
            Err(err) => return Err(format!("GRDR-UPDATER-0007: IPC receive failed: {err}")),
        };
        let stream_id = frame.stream_id;
        match frame.payload {
            Some(WirePayload::Heartbeat(hb)) => {
                let mono = clock
                    .boot_uptime()
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .map_err(|e| format!("GRDR-UPDATER-0006: {e}"))?;
                chan.send_frame(WireFrame::with_payload(
                    stream_id,
                    seq,
                    WirePayload::Heartbeat(HeartbeatFrame {
                        seq: hb.seq,
                        monotonic_ms: mono,
                        rss_bytes: current_process_rss_bytes(),
                        queue_depth: 0,
                        epoch: state.security_floor(),
                    }),
                ))
                .map_err(|e| format!("GRDR-UPDATER-0007: failed to send heartbeat: {e}"))?;
            }
            Some(WirePayload::UpdaterCommand(cmd)) => {
                let ev = state.handle_command(&cmd, &clock);
                chan.send_frame(WireFrame::with_payload(
                    stream_id,
                    seq,
                    WirePayload::UpdaterEvent(ev),
                ))
                .map_err(|e| format!("GRDR-UPDATER-0007: failed to send updater event: {e}"))?;
            }
            Some(WirePayload::CreditGrant(_)) | None => continue,
            Some(_) => {
                chan.send_frame(WireFrame::with_payload(
                    stream_id,
                    seq,
                    WirePayload::Error(ErrorFrame {
                        code: "GRDR-UPDATER-0007".to_string(),
                        message: "unsupported frame for updater worker".to_string(),
                        retryable: false,
                    }),
                ))
                .map_err(|e| format!("GRDR-UPDATER-0007: failed to send error frame: {e}"))?;
            }
        }
        seq = seq.saturating_add(1);
    }
    Ok(())
}
