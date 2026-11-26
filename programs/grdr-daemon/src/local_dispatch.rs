// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Authenticated client dispatch for `grdr-daemon` (`decide` and `local` IPC endpoints)
//! enforcing caller lineage/privilege gating on mutations, signed grant lifecycle, and scoped receipts.

use std::sync::atomic::{AtomicBool, Ordering};

use grdr_os_clock::{Clock, SystemClock};
use grdr_store_local::daemon_codecs::{
    decode_grant_json, encode_history_entries_json, encode_receipt_list_json,
};
use grdr_wire::frame::{WireFrame, WirePayload};
use grdr_wire::messages::{
    DaemonHealthSummary, DecideRequestFrame, DecideVerdictFrame, EndpointServiceKind, ErrorFrame,
    HandoverStage, HeartbeatFrame, LocalCommandKind, LocalRequestFrame, LocalResponseFrame,
    UpdaterCommandFrame, UplinkCommandFrame, WireVerdict,
};
use grdr_wire::peer_auth::{AuthenticatedChannel, FrameStream};
use prost::Message;

use crate::dir_guard::{is_privileged_local_caller, scrub_p8_text, session_recorder_key};
use crate::state::{CallerPrincipal, DaemonState, now_wall};

const MAX_LOCAL_RECEIPTS: usize = 64;
const MAX_LOCAL_HISTORY: usize = 64;

pub fn handle_authenticated_client<S: FrameStream>(
    mut chan: AuthenticatedChannel<S>,
    service: EndpointServiceKind,
    state: &DaemonState,
    stop: &AtomicBool,
) {
    let clock = SystemClock::new();
    let caller = CallerPrincipal::from_peer(chan.peer());
    let privileged_local = is_privileged_local_caller(chan.peer());
    while !stop.load(Ordering::Acquire) {
        let frame = match chan.recv_frame() {
            Ok(f) => f,
            Err(_) => break,
        };
        let stream_id = frame.stream_id;
        match frame.payload {
            Some(WirePayload::Heartbeat(hb)) => {
                let mono = clock
                    .boot_uptime()
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let epoch = state.inner.lock().map_or(1, |g| g.epoch);
                if let Err(err) = chan.send_frame(WireFrame::with_payload(
                    stream_id,
                    0,
                    WirePayload::Heartbeat(HeartbeatFrame {
                        seq: hb.seq,
                        monotonic_ms: mono,
                        rss_bytes: grdr_os_service::current_process_rss_bytes(),
                        queue_depth: 0,
                        epoch,
                    }),
                )) {
                    tracing::debug!(error = %err, "client heartbeat reply send failed");
                    break;
                }
            }
            Some(WirePayload::CreditGrant(_)) => {}
            Some(WirePayload::DecideRequest(req)) if service == EndpointServiceKind::Decide => {
                handle_decide_frame(&mut chan, stream_id, &req, state, &clock, &caller);
            }
            Some(WirePayload::LocalRequest(req)) if service == EndpointServiceKind::Local => {
                let resp = dispatch_local_command(&req, state, privileged_local, &caller);
                if chan
                    .send_frame(WireFrame::with_payload(
                        stream_id,
                        0,
                        WirePayload::LocalResponse(resp),
                    ))
                    .is_err()
                {
                    break;
                }
            }
            Some(_) => {
                let _ = chan.send_frame(WireFrame::with_payload(
                    stream_id,
                    0,
                    WirePayload::Error(ErrorFrame {
                        code: "GRDR-DAEM-0004".to_string(),
                        message: "unsupported frame for endpoint service".to_string(),
                        retryable: false,
                    }),
                ));
                break;
            }
            None => break,
        }
    }
}

fn handle_decide_frame<S: FrameStream>(
    chan: &mut AuthenticatedChannel<S>,
    stream_id: u64,
    req: &DecideRequestFrame,
    state: &DaemonState,
    clock: &SystemClock,
    caller: &CallerPrincipal,
) {
    let epoch = state.inner.lock().map_or(1, |g| g.epoch);
    let accepted_mono = clock
        .boot_uptime()
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let ack = grdr_wire::messages::DecideAckFrame {
        request_id: req.request_id.clone(),
        epoch,
        accepted_at_mono_ms: accepted_mono,
        handover_stage: HandoverStage::Normal as i32,
    };
    if chan
        .send_frame(WireFrame::with_payload(
            stream_id,
            0,
            WirePayload::DecideAck(ack),
        ))
        .is_err()
    {
        return;
    }

    let verdict = match state.decide_request(req, Some(caller)) {
        Ok(v) => v,
        Err(err) => DecideVerdictFrame {
            request_id: req.request_id.clone(),
            verdict: WireVerdict::Block as i32,
            receipt_id: String::new(),
            rule_id: "DAEMON-FAIL-CLOSED".to_string(),
            reason: scrub_p8_text(&err),
            degraded_reason: "daemon-error".to_string(),
            floor_fallback: false,
            audit_fsynced: false,
            labels: Vec::new(),
        },
    };
    if let Err(err) = chan.send_frame(WireFrame::with_payload(
        stream_id,
        0,
        WirePayload::DecideVerdict(verdict),
    )) {
        tracing::warn!(error = %err, "failed sending DecideVerdictFrame");
    }
}

pub fn dispatch_local_command(
    req: &LocalRequestFrame,
    state: &DaemonState,
    privileged_caller: bool,
    caller: &CallerPrincipal,
) -> LocalResponseFrame {
    let kind = LocalCommandKind::try_from(req.kind).unwrap_or(LocalCommandKind::Unspecified);
    if !privileged_caller
        && !matches!(
            kind,
            LocalCommandKind::Ping | LocalCommandKind::Status | LocalCommandKind::QuerySpool
        )
    {
        return local_err(
            req,
            "GRDR-DAEM-0004",
            "unprivileged local caller limited to status queries",
        );
    }
    match kind {
        LocalCommandKind::Ping => local_ok(req, "pong", Vec::new(), Some(state.health_summary())),
        LocalCommandKind::Status => {
            if let Ok(mut guard) = state.updater_child.lock()
                && let Some(updater) = guard.child.as_mut()
                && let Err(err) = updater.send_updater_command(UpdaterCommandFrame {
                    command_id: req.request_id.clone(),
                    action: "query_slots".to_string(),
                    security_floor: 0,
                    payload: Vec::new(),
                })
            {
                tracing::warn!(error = %err, "updater slot query failed during status");
            }
            local_ok(req, "status", Vec::new(), Some(state.health_summary()))
        }
        LocalCommandKind::Evaluate => handle_local_evaluate(req, state, caller),
        LocalCommandKind::ListReceipts => handle_list_receipts(req, state, caller),
        LocalCommandKind::SetKillSwitch => handle_kill_switch(req, state),
        LocalCommandKind::IssueGrant => handle_issue_grant(req, state),
        LocalCommandKind::RevokeGrant => handle_revoke_grant(req, state),
        LocalCommandKind::Reload => handle_local_reload(req, state),
        LocalCommandKind::QueryHistory => handle_query_history(req, state),
        LocalCommandKind::QuerySpool => handle_query_spool(req, state),
        LocalCommandKind::Unspecified => {
            local_err(req, "GRDR-DAEM-0004", "unspecified local command kind")
        }
    }
}

fn handle_local_reload(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    if let Err(err) = state.recompile_floor(None) {
        return local_err(req, "GRDR-DAEM-0006", &scrub_p8_text(&err));
    }
    let payload = match crate::uplink::build_checkin_payload(state) {
        Ok(bytes) => bytes,
        Err(err) => return local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err)),
    };
    let reply = {
        let Ok(mut guard) = state.uplink_child.lock() else {
            return local_err(req, "GRDR-DAEM-0002", "uplink slot lock poisoned");
        };
        guard.child.as_mut().map(|uplink| {
            uplink.send_uplink_command(UplinkCommandFrame {
                command_id: req.request_id.clone(),
                action: "check_in".to_string(),
                lane: "decision".to_string(),
                seq_hint: 0,
                payload,
            })
        })
    };
    if let Some(reply_res) = reply {
        match reply_res {
            Ok(WireFrame {
                payload: Some(WirePayload::UplinkEvent(ev)),
                ..
            }) => {
                if !ev.degraded_reason.is_empty() && ev.checkin_blob.is_empty() {
                    return local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&ev.degraded_reason));
                }
                if !ev.checkin_blob.is_empty()
                    && ev.ack_lane != "local-checkin-validated"
                    && let Err(err) = crate::uplink::apply_checkin_reply(
                        state,
                        &ev.ack_lane,
                        &ev.checkin_blob,
                        &ev.durable_through_hash,
                    )
                {
                    return local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err));
                }
            }
            Ok(_) => {
                return local_err(req, "GRDR-DAEM-0002", "unexpected reply from uplink worker");
            }
            Err(err) => {
                return local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err.to_string()));
            }
        }
    }
    local_ok(
        req,
        "floor-reloaded",
        Vec::new(),
        Some(state.health_summary()),
    )
}

fn handle_local_evaluate(
    req: &LocalRequestFrame,
    state: &DaemonState,
    caller: &CallerPrincipal,
) -> LocalResponseFrame {
    let Ok(dreq) = DecideRequestFrame::decode(req.payload.as_slice()) else {
        return local_err(req, "GRDR-DAEM-0004", "invalid DecideRequestFrame payload");
    };
    match state.decide_request(&dreq, Some(caller)) {
        Ok(verdict) => local_ok(
            req,
            "evaluated",
            verdict.encode_to_vec(),
            Some(state.health_summary()),
        ),
        Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err)),
    }
}

fn handle_list_receipts(
    req: &LocalRequestFrame,
    state: &DaemonState,
    caller: &CallerPrincipal,
) -> LocalResponseFrame {
    let limit = usize::try_from(req.limit)
        .unwrap_or(MAX_LOCAL_RECEIPTS)
        .clamp(1, MAX_LOCAL_RECEIPTS);
    let session_filter = req.argument.trim();
    let Ok(guard) = state.inner.lock() else {
        return local_err(req, "GRDR-DAEM-0002", "state lock poisoned");
    };
    let filtered: Vec<_> = guard
        .recent_receipts
        .iter()
        .rev()
        .filter(|r| {
            let owner_ok = guard
                .receipt_owners
                .iter()
                .any(|(rid, owner)| rid == &r.receipt_id && owner == caller);
            owner_ok && (session_filter.is_empty() || r.session_id == session_filter)
        })
        .take(limit)
        .cloned()
        .collect();
    let mut ordered = filtered;
    ordered.reverse();
    match encode_receipt_list_json(&ordered) {
        Ok(bytes) => local_ok(req, &format!("receipts:{}", ordered.len()), bytes, None),
        Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err.to_string())),
    }
}

fn handle_kill_switch(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    let normalized = req.argument.trim().to_ascii_lowercase();
    let active = normalized != "off" && normalized != "false" && normalized != "clear";
    match state.set_kill_switch(active, &req.argument) {
        Ok(()) => local_ok(
            req,
            if active {
                "kill-switch-active"
            } else {
                "kill-switch-cleared"
            },
            Vec::new(),
            Some(state.health_summary()),
        ),
        Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err)),
    }
}

fn handle_issue_grant(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    let Ok(grant) = decode_grant_json(&req.payload) else {
        return local_err(req, "GRDR-DAEM-0004", "invalid Grant JSON payload");
    };
    let id = grant.grant_id.clone();
    match state.issue_grant(grant) {
        Ok(()) => local_ok(
            req,
            &format!("grant-issued:{id}"),
            Vec::new(),
            Some(state.health_summary()),
        ),
        Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err)),
    }
}

fn handle_revoke_grant(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    match state.revoke_grant(&req.argument) {
        Ok(()) => local_ok(
            req,
            &format!("grant-revoked:{}", req.argument.trim()),
            Vec::new(),
            Some(state.health_summary()),
        ),
        Err(err) => local_err(req, "GRDR-DAEM-0004", &scrub_p8_text(&err)),
    }
}

fn handle_query_history(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    let limit = usize::try_from(req.limit)
        .unwrap_or(MAX_LOCAL_HISTORY)
        .clamp(1, MAX_LOCAL_HISTORY);
    let now_s = now_wall().as_second();
    let from_s = now_s.saturating_sub(72 * 3600);
    let session_arg = req.argument.trim();
    if session_arg.is_empty() {
        return local_err(
            req,
            "GRDR-DAEM-0004",
            "QueryHistory requires non-empty session argument",
        );
    }
    let query_res = {
        let Ok(guard) = state.inner.lock() else {
            return local_err(req, "GRDR-DAEM-0002", "state lock poisoned");
        };
        let hashed_session = session_recorder_key(&guard.device_id, session_arg);
        guard
            .recorder
            .query_events(from_s, now_s, Some(&hashed_session), limit)
    };
    match query_res {
        Ok(entries) => match encode_history_entries_json(&entries) {
            Ok(bytes) => local_ok(
                req,
                &format!("history_entries:{}", entries.len()),
                bytes,
                Some(state.health_summary()),
            ),
            Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err.to_string())),
        },
        Err(err) => local_err(req, "GRDR-DAEM-0002", &scrub_p8_text(&err.to_string())),
    }
}

fn handle_query_spool(req: &LocalRequestFrame, state: &DaemonState) -> LocalResponseFrame {
    let health = state.health_summary();
    let summary = format!(
        "spool_bytes:{};gap_count:{}",
        health.spool_bytes, health.gap_count
    );
    local_ok(req, &summary, Vec::new(), Some(health))
}

fn local_ok(
    req: &LocalRequestFrame,
    msg: &str,
    payload: Vec<u8>,
    health: Option<DaemonHealthSummary>,
) -> LocalResponseFrame {
    LocalResponseFrame {
        request_id: req.request_id.clone(),
        ok: true,
        error_code: String::new(),
        message: msg.to_string(),
        payload,
        health,
    }
}

fn local_err(req: &LocalRequestFrame, code: &str, msg: &str) -> LocalResponseFrame {
    LocalResponseFrame {
        request_id: req.request_id.clone(),
        ok: false,
        error_code: code.to_string(),
        message: msg.to_string(),
        payload: Vec::new(),
        health: None,
    }
}
