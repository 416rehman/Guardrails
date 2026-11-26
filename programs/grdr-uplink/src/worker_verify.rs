// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Cryptographic check-in, P8 metadata privacy validation, flush ack verification,
//! and egress dial enforcement for `grdr-uplink`.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, ToSocketAddrs as _};

use grdr_crypto::{sha256_hex, verify_bytes};
use grdr_model::{DeviceCheckinRequest, TrustedKeyInfo};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::UplinkEventFrame;
use serde::Deserialize;

use crate::allowlist::parse_https_target;
use crate::auth::{
    FleetTrustAnchor, ResponseKeyCertificate, ResponseVerifier, Rfc9421RequestHeaders,
    SignedResponse,
};
use crate::dialer::{DialPurpose, DialTarget, Dialer, NetworkMode, ProxySelection};
use crate::error::UplinkError;
use crate::lanes::{Lane, WatermarkAdvance};
use crate::watermark::WatermarkTracker;

const MAX_REPLAY_DIGESTS: usize = 1_024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;

const P8_FORBIDDEN_MARKERS: [&str; 15] = [
    "/users/",
    "/home/",
    "\\users\\",
    ":\\users\\",
    ":/users/",
    "%userprofile%",
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "glpat-",
    "akia",
    "xoxb-",
    "bearer ",
    "password=",
];

#[derive(Debug, Deserialize)]
pub(crate) struct CheckInDirective {
    #[serde(default)]
    pub(crate) server_url: String,
    #[serde(default)]
    pub(crate) resolved_ips: Vec<IpAddr>,
    #[serde(default)]
    pub(crate) request_json: Vec<u8>,
    #[serde(default)]
    pub(crate) pinned_keys: Vec<TrustedKeyInfo>,
    pub(crate) request_headers: Option<Rfc9421RequestHeaders>,
    #[serde(default)]
    pub(crate) content_digest: String,
    #[serde(default)]
    pub(crate) signature_input: String,
    #[serde(default)]
    pub(crate) signature: String,
    pub(crate) response_cert: Option<ResponseKeyCertificate>,
    #[serde(default)]
    pub(crate) server_time_unix_s: i64,
    #[serde(default)]
    pub(crate) response_payload: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FlushSpoolDirective {
    #[serde(default)]
    pub(crate) records: Vec<Vec<u8>>,
    pub(crate) verified_ack: Option<SignedFlushAck>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SignedFlushAck {
    pub(crate) request_headers: Rfc9421RequestHeaders,
    pub(crate) content_digest: String,
    pub(crate) signature_input: String,
    pub(crate) signature: String,
    pub(crate) response_cert: Option<ResponseKeyCertificate>,
    pub(crate) server_time_unix_s: i64,
    pub(crate) response_body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct SignedFlushAckBody {
    #[serde(alias = "ackedThrough")]
    acked_through: u64,
    #[serde(alias = "durableThrough")]
    durable_through: u64,
    #[serde(default, alias = "serverEpoch")]
    server_epoch: String,
    #[serde(default, alias = "deviceId")]
    device_id: Option<String>,
    #[serde(default)]
    lane: Option<String>,
}

/// Verify a check-in payload strictly against non-empty pinned trusted fleet keys without duplicates.
pub fn verify_checkin_response_pinned(
    pinned_keys: &[TrustedKeyInfo],
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), UplinkError> {
    if pinned_keys.is_empty() {
        return Err(UplinkError::AckUnverified {
            reason: "refusing check-in verification without pinned trusted keys".to_string(),
        });
    }
    if signature_b64.trim().is_empty() {
        return Err(UplinkError::AckUnverified {
            reason: "refusing unsigned check-in response".to_string(),
        });
    }
    let mut key_map: BTreeMap<&str, &str> = BTreeMap::new();
    for k in pinned_keys {
        if key_map
            .insert(k.key_id.as_str(), k.public_key_b64.as_str())
            .is_some()
        {
            return Err(UplinkError::AckUnverified {
                reason: format!("duplicate key_id '{}' in pinned keys", k.key_id),
            });
        }
    }
    if key_map
        .values()
        .any(|pk| verify_bytes(pk, "grdr.checkin.v1\0", payload, signature_b64).is_ok())
    {
        return Ok(());
    }
    Err(UplinkError::AckUnverified {
        reason: "check-in signature did not verify against any pinned key".to_string(),
    })
}

pub(crate) fn validate_checkin_p8(req: &DeviceCheckinRequest) -> Result<(), UplinkError> {
    if req.user_id.is_some() || req.user_display.is_some() {
        return Err(UplinkError::AckUnverified {
            reason: "P8 privacy violation: user_id/user_display must remain None".to_string(),
        });
    }
    if contains_p8_pii_or_secret(&req.hostname)
        || req.hostname.contains('\\')
        || req.hostname.contains('/')
    {
        return Err(UplinkError::AckUnverified {
            reason: "P8 privacy violation in device checkin hostname".to_string(),
        });
    }
    for artifact in &req.artifacts {
        if artifact.user_id.is_some()
            || artifact
                .kind_other
                .as_deref()
                .is_some_and(contains_p8_pii_or_secret)
            || contains_p8_pii_or_secret(&artifact.path)
            || contains_p8_pii_or_secret(&artifact.name)
            || contains_p8_pii_or_secret(&artifact.device_name)
        {
            return Err(UplinkError::AckUnverified {
                reason: "P8 privacy violation in device checkin artifact entry".to_string(),
            });
        }
    }
    for agent in &req.agents {
        if agent
            .sponsor
            .as_deref()
            .is_some_and(contains_p8_pii_or_secret)
            || contains_p8_pii_or_secret(&agent.config_path)
            || contains_p8_pii_or_secret(&agent.name)
        {
            return Err(UplinkError::AckUnverified {
                reason: "P8 privacy violation in device checkin agent entry".to_string(),
            });
        }
    }
    for mcp in &req.mcp_servers {
        if contains_p8_pii_or_secret(&mcp.command)
            || contains_p8_pii_or_secret(&mcp.config_path)
            || contains_p8_pii_or_secret(&mcp.name)
        {
            return Err(UplinkError::AckUnverified {
                reason: "P8 privacy violation in device checkin mcp entry".to_string(),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_flush_ack_and_advance(
    verifier: Option<&mut ResponseVerifier>,
    watermarks: &mut WatermarkTracker,
    seen_digests: &mut VecDeque<String>,
    expected_device_id: &str,
    lane: Lane,
    ack: &SignedFlushAck,
    now_wall_s: i64,
    now_mono_ms: u64,
) -> Result<(WatermarkAdvance, String), UplinkError> {
    let max_bytes = max_response_bytes();
    if ack.response_body.len() > max_bytes {
        let _ = watermarks.reject_unverified_ack();
        return Err(UplinkError::AckUnverified {
            reason: "flush_spool ack response_body exceeds frame limit".to_string(),
        });
    }
    let Some(verifier) = verifier else {
        let _ = watermarks.reject_unverified_ack();
        return Err(UplinkError::AckUnverified {
            reason: "refusing flush_spool ack verification without pinned trust anchor".to_string(),
        });
    };
    if let Err(err) = verifier.verify_response(
        &ack.request_headers,
        &SignedResponse {
            content_digest: &ack.content_digest,
            signature_input: &ack.signature_input,
            signature: &ack.signature,
            response_cert: ack.response_cert.as_ref(),
            server_time_unix_s: ack.server_time_unix_s,
            body: &ack.response_body,
        },
        now_wall_s,
        now_mono_ms,
    ) {
        let _ = watermarks.reject_unverified_ack();
        return Err(err);
    }

    let body: SignedFlushAckBody =
        serde_json::from_slice(&ack.response_body).map_err(|e| UplinkError::AckUnverified {
            reason: format!("verified PushAck response_body invalid JSON: {e}"),
        })?;
    if let Some(ref body_dev) = body.device_id
        && body_dev != expected_device_id
    {
        return Err(UplinkError::AckUnverified {
            reason: format!(
                "verified PushAck device_id '{}' != '{expected_device_id}'",
                body_dev
            ),
        });
    }
    if let Some(ref body_lane) = body.lane
        && parse_lane_str(body_lane) != Some(lane)
    {
        return Err(UplinkError::AckUnverified {
            reason: format!("verified PushAck lane '{body_lane}' does not match '{lane:?}'"),
        });
    }
    check_and_record_replay(seen_digests, &ack.request_headers.request_sig_digest_b64)?;

    let advance = watermarks.apply_verified_ack_for_lane(
        lane,
        body.acked_through,
        body.durable_through,
        &body.server_epoch,
    );
    Ok((advance, sha256_hex(&ack.response_body)))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_egress_and_directive(
    network_mode: &NetworkMode,
    pinned_anchor: Option<&FleetTrustAnchor>,
    verifier: Option<&mut ResponseVerifier>,
    seen_digests: &mut VecDeque<String>,
    expected_device_id: &str,
    directive: &CheckInDirective,
    now_wall_s: i64,
    now_mono_ms: u64,
) -> Result<(), UplinkError> {
    let (Some(anchor), Some(verifier)) = (pinned_anchor, verifier) else {
        return Err(UplinkError::AckUnverified {
            reason: "refusing check_in verification without pinned fleet trust anchor".to_string(),
        });
    };
    let max_bytes = max_response_bytes();
    if directive.response_payload.len() > max_bytes || directive.request_json.len() > max_bytes {
        return Err(UplinkError::AckUnverified {
            reason: "check_in payload exceeds operational limit".to_string(),
        });
    }
    if !directive.pinned_keys.is_empty() {
        let mut seen_kids = std::collections::BTreeSet::new();
        let all_match = directive.pinned_keys.iter().all(|k| {
            seen_kids.insert(k.key_id.as_str())
                && anchor
                    .fleet_public_keys
                    .get(&k.key_id)
                    .is_some_and(|pk| pk == &k.public_key_b64)
        });
        if !all_match {
            return Err(UplinkError::AckUnverified {
                reason: "check_in directive keys duplicate or mismatch pinned anchor".to_string(),
            });
        }
    }
    if directive.server_url.trim().is_empty() {
        return Err(UplinkError::InvalidEndpoint {
            detail: "check_in server_url must not be empty".to_string(),
        });
    }

    let parsed = parse_https_target(&directive.server_url)?;
    let dialer = Dialer::new(network_mode.clone(), ProxySelection::Direct);
    // Enforce Isolated allowlist BEFORE any DNS resolution leaks hostnames (P16).
    dialer.check_host_allowed(
        &parsed.host,
        "target destination not in isolated allow_list",
    )?;

    let resolved_ips = if !directive.resolved_ips.is_empty() {
        directive.resolved_ips.clone()
    } else if let Some(ip) = parsed.host_ip {
        vec![ip]
    } else {
        (&*parsed.host, parsed.port)
            .to_socket_addrs()
            .map_err(|e| UplinkError::Transport {
                detail: format!("DNS resolution failed for {}: {e}", parsed.host),
            })?
            .map(|sa| sa.ip())
            .collect()
    };

    let plan = dialer.authorize_dial(
        &DialTarget {
            uri: directive.server_url.clone(),
            purpose: DialPurpose::FleetControl,
            resolved_ips,
        },
        None,
        now_mono_ms,
    )?;
    let _client = dialer.build_http_client_for_plan(Some(&plan))?;

    if !directive.request_json.is_empty() {
        let req: DeviceCheckinRequest =
            serde_json::from_slice(&directive.request_json).map_err(|e| {
                UplinkError::InvalidEndpoint {
                    detail: format!("invalid checkin request JSON: {e}"),
                }
            })?;
        if let Some(ref req_dev) = req.device_id
            && req_dev != expected_device_id
        {
            return Err(UplinkError::AckUnverified {
                reason: "check_in request device_id mismatch".to_string(),
            });
        }
        validate_checkin_p8(&req)?;
    }

    let req_headers =
        directive
            .request_headers
            .as_ref()
            .ok_or_else(|| UplinkError::AckUnverified {
                reason: "check_in response verification requires RFC 9421 request_headers binding"
                    .to_string(),
            })?;
    let _meta = verifier.verify_response(
        req_headers,
        &SignedResponse {
            content_digest: &directive.content_digest,
            signature_input: &directive.signature_input,
            signature: &directive.signature,
            response_cert: directive.response_cert.as_ref(),
            server_time_unix_s: directive.server_time_unix_s,
            body: &directive.response_payload,
        },
        now_wall_s,
        now_mono_ms,
    )?;
    check_and_record_replay(seen_digests, &req_headers.request_sig_digest_b64)?;
    Ok(())
}

pub(crate) fn degraded_event(
    command_id: &str,
    lane: &str,
    durable_through: u64,
    err: &UplinkError,
) -> UplinkEventFrame {
    UplinkEventFrame {
        command_id: command_id.to_string(),
        ack_lane: lane.to_string(),
        durable_through_seq: durable_through,
        durable_through_hash: String::new(),
        checkin_blob: Vec::new(),
        staged_manifest_path: String::new(),
        degraded_reason: err.to_string(),
    }
}

fn check_and_record_replay(
    seen: &mut VecDeque<String>,
    req_digest_b64: &str,
) -> Result<(), UplinkError> {
    if req_digest_b64.trim().is_empty() {
        return Err(UplinkError::AckUnverified {
            reason: "missing request_sig_digest_b64 for anti-replay check".to_string(),
        });
    }
    if seen.iter().any(|d| d == req_digest_b64) {
        return Err(UplinkError::AckUnverified {
            reason: "replayed RFC 9421 response request binding rejected".to_string(),
        });
    }
    if seen.len() >= MAX_REPLAY_DIGESTS {
        let _ = seen.pop_front();
    }
    seen.push_back(req_digest_b64.to_string());
    Ok(())
}

fn max_response_bytes() -> usize {
    embedded_limits().map_or(DEFAULT_MAX_RESPONSE_BYTES, |l| l.max_frame_bytes)
}

fn parse_lane_str(raw: &str) -> Option<Lane> {
    match raw.to_ascii_lowercase().as_str() {
        "decision" => Some(Lane::Decision),
        "spine" => Some(Lane::Spine),
        "evidence" => Some(Lane::Evidence),
        "bulk" => Some(Lane::Bulk),
        _ => None,
    }
}

fn contains_p8_pii_or_secret(raw: &str) -> bool {
    if raw.chars().any(char::is_control) {
        return true;
    }
    let lower = raw.to_ascii_lowercase();
    P8_FORBIDDEN_MARKERS.iter().any(|pat| lower.contains(pat)) || lower.contains("api_key=")
}
