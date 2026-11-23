// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::time::Duration;

use jiff::Timestamp;
use tracing::{info, warn};

use grdr_model::{BatchEventsInput, DeviceCheckinRequest, DeviceCheckinResponse};

use crate::state::DaemonState;

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

    let checkin_url = format!("{base}/api/v1/devices/checkin");
    let resp = client
        .post(&checkin_url)
        .timeout(Duration::from_secs(5))
        .json(&checkin_req)
        .send()
        .await
        .map_err(|e| format!("checkin request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("checkin returned {status}: {body}"));
    }

    let parsed: DeviceCheckinResponse = resp
        .json()
        .await
        .map_err(|e| format!("invalid checkin response JSON: {e}"))?;

    let flushed_count = if let Some(batch) = batch_req {
        let batch_url = format!("{base}/api/v1/events/batch");
        let count = batch.receipts.len();
        let batch_resp = client
            .post(&batch_url)
            .timeout(Duration::from_secs(5))
            .json(&batch)
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
        guard.packs = parsed.packs;
        guard.grants = parsed.grants;
        guard.kill_switch = parsed.kill_switch;
        guard.server_connected = true;
        guard.last_sync = Some(Timestamp::now());
        guard.last_sync_error = None;
        if flushed_count > 0 {
            let drain_attempts = guard.pending_attempts.len().min(flushed_count);
            let drain_receipts = guard.pending_receipts.len().min(flushed_count);
            guard.pending_attempts.drain(..drain_attempts);
            guard.pending_receipts.drain(..drain_receipts);
        }
    }

    info!(
        device_id = %parsed.device.id,
        flushed_events = flushed_count,
        "Synced endpoint state with API server"
    );
    Ok(())
}

pub async fn run_sync_loop(state: DaemonState, server_url: String, interval_secs: u64) {
    let client = reqwest::Client::new();
    let period = Duration::from_secs(interval_secs.max(3));

    loop {
        if let Err(err) = sync_once(&state, &client, &server_url).await {
            let mut guard = state.inner.write().await;
            guard.server_connected = false;
            guard.last_sync_error = Some(err.clone());
            warn!(error = %err, "Server sync failed; continuing with offline policy cache");
        }
        tokio::time::sleep(period).await;
    }
}
