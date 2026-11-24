// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::time::Duration;

use jiff::Timestamp;
use tracing::{info, warn};

use grdr_crypto::{verify_grant, verify_pack};
use grdr_model::proto_conv::{
    agent_to_proto, artifact_to_proto, attempt_to_proto, install_profile_to_proto, key_to_proto,
    mcp_to_proto, parse_ts, proto_to_device, proto_to_grant, proto_to_key, proto_to_kill_switch,
    proto_to_pack, receipt_to_proto,
};
use grdr_model::{
    BatchEventsInput, DeviceCheckinRequest, DeviceCheckinResponse, KillSwitchState, SignatureStatus,
};
use grdr_proto::api::inventory::{
    DeviceCheckinRequest as ProtoCheckinRequest, DeviceCheckinResponse as ProtoCheckinResponse,
};
use grdr_proto::api::verdict::IngestBatchRequest as ProtoIngestBatchRequest;

use crate::state::{
    DaemonData, DaemonState, UplinkState, persist_daemon_snapshot, write_signed_floor_bundle,
};

pub async fn sync_once(
    state: &DaemonState,
    client: &reqwest::Client,
    server_url: &str,
) -> Result<(), String> {
    let base = server_url.trim_end_matches('/');
    let (checkin_req, batch_req) = {
        let guard = state.inner.read().await;
        let checkin = DeviceCheckinRequest {
            device_id: Some(guard.device_id.clone()),
            hostname: guard.hostname.clone(),
            os: guard.discovery.os.clone(),
            arch: guard.discovery.arch.clone(),
            install_profile: guard.install_profile,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            hook_effective: guard.discovery.agents.iter().any(|a| a.hook_installed),
            agents: guard.discovery.agents.clone(),
            mcp_servers: guard.discovery.mcp_servers.clone(),
            artifacts: guard.discovery.artifacts.clone(),
            user_id: None,
            user_display: std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .ok(),
            device_public_key: Some(guard.signing_key.public_info()),
        };
        let batch = if guard.pending_receipts.is_empty() {
            None
        } else {
            Some(BatchEventsInput {
                device_id: guard.device_id.clone(),
                attempts: guard.pending_attempts.clone(),
                receipts: guard.pending_receipts.clone(),
            })
        };
        (checkin, batch)
    };

    let proto_checkin = ProtoCheckinRequest {
        device_id: checkin_req.device_id,
        hostname: checkin_req.hostname,
        os: checkin_req.os,
        arch: checkin_req.arch,
        install_profile: install_profile_to_proto(checkin_req.install_profile),
        daemon_version: checkin_req.daemon_version,
        hook_effective: checkin_req.hook_effective,
        agents: checkin_req.agents.iter().map(agent_to_proto).collect(),
        mcp_servers: checkin_req.mcp_servers.iter().map(mcp_to_proto).collect(),
        artifacts: checkin_req
            .artifacts
            .iter()
            .map(artifact_to_proto)
            .collect(),
        user_id: checkin_req.user_id,
        user_display: checkin_req.user_display,
        device_public_key: checkin_req.device_public_key.as_ref().map(key_to_proto),
    };

    let checkin_url = format!("{base}/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin");
    let resp = client
        .post(&checkin_url)
        .header("connect-protocol-version", "1")
        .timeout(Duration::from_secs(5))
        .json(&proto_checkin)
        .send()
        .await
        .map_err(|e| format!("checkin request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("checkin returned {status}: {body}"));
    }

    let parsed_proto: ProtoCheckinResponse = resp
        .json()
        .await
        .map_err(|e| format!("invalid checkin response JSON: {e}"))?;
    let parsed = proto_checkin_to_model(parsed_proto)?;

    let flushed_count = if let Some(batch) = batch_req {
        let batch_url = format!("{base}/grdr.api.verdict.v1alpha1.VerdictService/IngestBatch");
        let count = batch.receipts.len();
        let proto_batch = ProtoIngestBatchRequest {
            device_id: batch.device_id,
            attempts: batch.attempts.iter().map(attempt_to_proto).collect(),
            receipts: batch.receipts.iter().map(receipt_to_proto).collect(),
        };
        let batch_resp = client
            .post(&batch_url)
            .header("connect-protocol-version", "1")
            .timeout(Duration::from_secs(5))
            .json(&proto_batch)
            .send()
            .await
            .map_err(|e| format!("events batch failed: {e}"))?;
        if !batch_resp.status().is_success() {
            return Err(format!("events batch returned {}", batch_resp.status()));
        }
        count
    } else {
        0
    };

    {
        let mut guard = state.inner.write().await;
        apply_verified_checkin(&mut guard, parsed.clone());
        guard.uplink = UplinkState::Connected {
            server_url: base.to_owned(),
            last_sync: Timestamp::now(),
        };
        if flushed_count > 0 {
            let drain_attempts = guard.pending_attempts.len().min(flushed_count);
            let drain_receipts = guard.pending_receipts.len().min(flushed_count);
            guard.pending_attempts.drain(..drain_attempts);
            guard.pending_receipts.drain(..drain_receipts);
        }
        if let Err(err) = write_signed_floor_bundle(&guard, Timestamp::now()) {
            warn!(error = %err, "Failed writing signed fail-safe floor table");
        }
        if let Err(err) = persist_daemon_snapshot(&guard) {
            warn!(error = %err, "Failed persisting daemon local snapshot");
        }
    }

    info!(
        device_id = %parsed.device.id,
        flushed_events = flushed_count,
        "Synced endpoint state with API server"
    );
    Ok(())
}

pub(crate) fn apply_verified_checkin(data: &mut DaemonData, resp: DeviceCheckinResponse) {
    if resp.trusted_keys.is_empty() {
        data.packs = resp.packs;
        data.grants = resp.grants;
        data.kill_switch = resp.kill_switch;
        return;
    }

    let all_packs_valid = !resp.packs.is_empty()
        && resp
            .packs
            .iter()
            .all(|pack| verify_pack(pack, &resp.trusted_keys) == SignatureStatus::Verified);

    if all_packs_valid {
        data.packs = resp.packs;
    } else {
        warn!("Rejected unsigned or tampered policy packs from server; keeping cached packs");
    }

    let mut verified_grants = Vec::new();
    for grant in resp.grants {
        if verify_grant(&grant, &resp.trusted_keys) == SignatureStatus::Verified {
            verified_grants.push(grant);
        } else {
            warn!(grant_id = %grant.grant_id, "Rejected unsigned or tampered grant from server");
        }
    }
    data.grants = verified_grants;
    data.trusted_keys = resp.trusted_keys;
    data.kill_switch = resp.kill_switch;
}

pub async fn run_sync_loop(state: DaemonState, server_url: String, interval_secs: u64) {
    let client = reqwest::Client::new();
    let period = Duration::from_secs(interval_secs.max(3));

    loop {
        if let Err(err) = sync_once(&state, &client, &server_url).await {
            let mut guard = state.inner.write().await;
            let last_sync = match &guard.uplink {
                UplinkState::Connected { last_sync, .. } => Some(*last_sync),
                UplinkState::Degraded { last_sync, .. } => *last_sync,
                UplinkState::Standalone | UplinkState::Connecting { .. } => None,
            };
            guard.uplink = UplinkState::Degraded {
                server_url: server_url.clone(),
                last_sync,
                error: err.clone(),
            };
            warn!(error = %err, "Server sync failed; continuing with offline policy cache");
        }
        tokio::time::sleep(period).await;
    }
}

fn proto_checkin_to_model(resp: ProtoCheckinResponse) -> Result<DeviceCheckinResponse, String> {
    let device = resp
        .device
        .ok_or_else(|| "missing device in checkin response".to_string())
        .and_then(proto_to_device)?;
    let mut packs = Vec::with_capacity(resp.packs.len());
    for p in resp.packs {
        packs.push(proto_to_pack(p)?);
    }
    let mut grants = Vec::with_capacity(resp.grants.len());
    for g in resp.grants {
        grants.push(proto_to_grant(g)?);
    }
    let kill_switch = resp
        .kill_switch
        .map(proto_to_kill_switch)
        .transpose()?
        .unwrap_or(KillSwitchState::Inactive);
    Ok(DeviceCheckinResponse {
        device,
        packs,
        grants,
        kill_switch,
        server_time: parse_ts(&resp.server_time)?,
        trusted_keys: resp.trusted_keys.into_iter().map(proto_to_key).collect(),
    })
}
