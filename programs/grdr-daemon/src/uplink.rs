// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Cryptographically verified device check-in state sync (pre-parse raw signature verification,
//! device ID, freshness + monotonic server_time checks, floor recompilation, zero P8 username leak).

use grdr_crypto::verify_bytes;
use grdr_model::{DeviceCheckinRequest, DeviceCheckinResponse, TrustedKeyInfo};
use grdr_store_local::daemon_codecs::{decode_checkin_response_json, encode_checkin_request_json};
use grdr_wire::limits::embedded_limits;
use jiff::Timestamp;

use crate::receipt_audit::now_wall_checked;
use crate::state::{DaemonData, DaemonState, UplinkState};

const MAX_CHECKIN_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHECKIN_TIME_SKEW_SECS: i64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckinRejected {
    pub reason: String,
}

pub fn build_checkin_payload(state: &DaemonState) -> Result<Vec<u8>, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "daemon state lock poisoned".to_string())?;
    let req = build_checkin_request(&guard);
    encode_checkin_request_json(&req).map_err(|e| e.to_string())
}

pub fn apply_checkin_reply(
    state: &DaemonState,
    server_url: &str,
    response_json: &[u8],
    signature_b64: &str,
) -> Result<(), String> {
    let now = now_wall_checked()?;
    let outcome = {
        let mut guard = state
            .inner
            .lock()
            .map_err(|_| "daemon state lock poisoned".to_string())?;
        let pinned = guard.trusted_keys.clone();
        match apply_verified_checkin(&mut guard, response_json, &pinned, signature_b64, now) {
            Ok(()) => {
                guard.uplink = UplinkState::Connected {
                    server_url: server_url.to_string(),
                };
                Ok(state.prepare_engine_bundle_from_data(&mut guard)?)
            }
            Err(rejected) => {
                guard.uplink = UplinkState::Degraded {
                    reason: rejected.reason.clone(),
                };
                Err(rejected.reason)
            }
        }
    };
    match outcome {
        Ok(bundle) => state.push_bundle_to_engine_slot(bundle),
        Err(reason) => Err(reason),
    }
}

#[must_use]
pub fn build_checkin_request(data: &DaemonData) -> DeviceCheckinRequest {
    DeviceCheckinRequest {
        device_id: Some(data.device_id.clone()),
        hostname: data.hostname.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        install_profile: data.install_profile,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        hook_effective: true,
        agents: data.discovery.agents.clone(),
        mcp_servers: data.discovery.mcp_servers.clone(),
        artifacts: data.discovery.artifacts.clone(),
        // P8 privacy invariant: never read or transmit USERNAME/USER OS account names.
        user_id: None,
        user_display: None,
        device_public_key: Some(TrustedKeyInfo {
            key_id: data.signing_key.key_id().to_string(),
            public_key_b64: data.signing_key.public_key_b64().to_string(),
        }),
    }
}

pub fn apply_verified_checkin(
    data: &mut DaemonData,
    raw_response_json: &[u8],
    pinned_keys: &[TrustedKeyInfo],
    signature_b64: &str,
    now: Timestamp,
) -> Result<(), CheckinRejected> {
    let max_bytes = embedded_limits().map_or(MAX_CHECKIN_RESPONSE_BYTES, |l| {
        l.max_frame_bytes.min(MAX_CHECKIN_RESPONSE_BYTES)
    });
    if raw_response_json.is_empty() || raw_response_json.len() > max_bytes {
        return Err(CheckinRejected {
            reason: "check-in response payload empty or exceeds size limit".to_string(),
        });
    }
    if pinned_keys.is_empty() {
        return Err(CheckinRejected {
            reason: "refusing check-in response without pinned trusted keys".to_string(),
        });
    }
    if signature_b64.trim().is_empty() {
        return Err(CheckinRejected {
            reason: "refusing unsigned check-in response".to_string(),
        });
    }

    // Verify raw response bytes BEFORE invoking JSON parser.
    let verified = pinned_keys.iter().any(|key| {
        verify_bytes(
            &key.public_key_b64,
            "grdr.checkin.v1\0",
            raw_response_json,
            signature_b64,
        )
        .is_ok()
    });
    if !verified {
        return Err(CheckinRejected {
            reason: "check-in signature rejected against all pinned keys".to_string(),
        });
    }

    let resp: DeviceCheckinResponse =
        decode_checkin_response_json(raw_response_json).map_err(|err| CheckinRejected {
            reason: format!("decode verified check-in payload: {err}"),
        })?;
    if resp.device.id != data.device_id {
        return Err(CheckinRejected {
            reason: "check-in response device_id mismatch".to_string(),
        });
    }
    let server_s = resp.server_time.as_second();
    if let Some(prev_s) = data.last_checkin_server_s
        && server_s < prev_s
    {
        return Err(CheckinRejected {
            reason: "check-in server_time regressed below prior verified response".to_string(),
        });
    }
    let skew_s = server_s.abs_diff(now.as_second());
    if skew_s > u64::try_from(MAX_CHECKIN_TIME_SKEW_SECS).unwrap_or(3_600) {
        return Err(CheckinRejected {
            reason: format!(
                "check-in server_time outside {MAX_CHECKIN_TIME_SKEW_SECS}s freshness window"
            ),
        });
    }

    data.last_checkin_server_s = Some(server_s);
    if !resp.trusted_keys.is_empty() {
        data.trusted_keys = resp.trusted_keys;
    }
    if !resp.packs.is_empty() {
        data.packs = resp.packs;
    }
    data.grants = resp.grants;
    data.kill_switch = resp.kill_switch;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DaemonState;
    use grdr_crypto::SigningKeypair;
    use grdr_model::{Device, DiscoveryReport, InstallProfile, KillSwitchState};

    #[test]
    fn checkin_verifies_raw_bytes_device_id_and_freshness_and_omits_username() {
        let base = crate::dir_guard::private_ephemeral_base_dir().join(format!(
            ".grdr-uplink-unit-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let state =
            DaemonState::initialize(base.join("data"), base.join("state"), InstallProfile::User)
                .expect("init daemon state");
        let mut guard = state.inner.lock().expect("lock");
        let req = build_checkin_request(&guard);
        assert!(req.user_id.is_none());
        assert!(req.user_display.is_none());

        let now = Timestamp::from_second(1_760_000_000).expect("ts");
        let resp = DeviceCheckinResponse {
            device: Device {
                id: guard.device_id.clone(),
                hostname: guard.hostname.clone(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                install_profile: InstallProfile::User,
                daemon_version: "0.1.0".to_string(),
                online: true,
                hook_effective: true,
                agents: Vec::new(),
                mcp_servers: Vec::new(),
                artifacts: Vec::new(),
                user_id: None,
                user_display: None,
                last_seen: now,
                public_key: None,
            },
            packs: Vec::new(),
            grants: Vec::new(),
            kill_switch: KillSwitchState::Inactive,
            server_time: now,
            trusted_keys: Vec::new(),
        };
        let canonical =
            grdr_store_local::daemon_codecs::encode_checkin_response_json_for_test(&resp);
        assert!(apply_verified_checkin(&mut guard, &canonical, &[], "AAAA", now).is_err());

        let kp = SigningKeypair::generate().expect("keygen");
        let sig = kp.sign_bytes("grdr.checkin.v1\0", &canonical);
        let trusted = [TrustedKeyInfo {
            key_id: kp.key_id().to_string(),
            public_key_b64: kp.public_key_b64().to_string(),
        }];
        assert!(apply_verified_checkin(&mut guard, &canonical, &trusted, "bad-sig", now).is_err());
        let stale_now = Timestamp::from_second(1_760_050_000).expect("stale ts");
        assert!(apply_verified_checkin(&mut guard, &canonical, &trusted, &sig, stale_now).is_err());
        assert!(apply_verified_checkin(&mut guard, &canonical, &trusted, &sig, now).is_ok());

        // Monotonic server_time rejection against replay of older server_time.
        let older = Timestamp::from_second(1_759_999_990).expect("older ts");
        let old_resp = DeviceCheckinResponse {
            server_time: older,
            ..resp
        };
        let old_canonical =
            grdr_store_local::daemon_codecs::encode_checkin_response_json_for_test(&old_resp);
        let old_sig = kp.sign_bytes("grdr.checkin.v1\0", &old_canonical);
        assert!(
            apply_verified_checkin(&mut guard, &old_canonical, &trusted, &old_sig, now).is_err()
        );

        let _ = DiscoveryReport {
            device_name: String::new(),
            os: String::new(),
            arch: String::new(),
            install_profile: InstallProfile::User,
            agents: Vec::new(),
            mcp_servers: Vec::new(),
            artifacts: Vec::new(),
            scanned_paths: Vec::new(),
            warnings: Vec::new(),
            scanned_at: now,
        };
        let _ = std::fs::remove_dir_all(&base);
    }
}
