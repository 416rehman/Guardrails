// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::sha256_digest;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeContractOffer {
    pub node_id: String,
    pub component: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub sensor_ceiling: Option<(u32, u32, u32)>,
    pub wire_major: u32,
    pub schema_rev: u32,
    pub contracts: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakePolicy {
    pub server_major: u32,
    pub server_minor: u32,
    pub server_patch: u32,
    pub max_minor_behind: u32,
    pub max_minor_ahead: u32,
    pub expected_wire_major: u32,
    pub min_schema_rev: u32,
    pub required_contracts: Vec<String>,
    pub retry_base_ms: u64,
    pub retry_jitter_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum HandshakeResolution {
    Admitted {
        agreed_contracts: Vec<String>,
    },
    UpgradeRequired {
        code: String,
        reason: String,
        minimum_version: String,
        retry_after_ms: u64,
        not_before: Timestamp,
        guidance: String,
    },
}

#[must_use]
pub fn evaluate_offer_handshake(
    offer: &HandshakeContractOffer,
    policy: &HandshakePolicy,
    now: Timestamp,
) -> HandshakeResolution {
    let min_minor = policy.server_minor.saturating_sub(policy.max_minor_behind);
    let max_minor = policy.server_minor.saturating_add(policy.max_minor_ahead);
    let min_ver = format!("{}.{}.0", policy.server_major, min_minor);

    let jitter = deterministic_jitter_ms(&offer.node_id, policy.retry_jitter_ms);
    let retry_after_ms = policy.retry_base_ms.saturating_add(jitter);
    let delay_secs = i64::try_from(retry_after_ms.checked_div(1_000).unwrap_or(1))
        .unwrap_or(1)
        .max(1);
    let not_before =
        Timestamp::from_second(now.as_second().saturating_add(delay_secs)).unwrap_or(now);

    if offer.wire_major != policy.expected_wire_major || offer.schema_rev < policy.min_schema_rev {
        return HandshakeResolution::UpgradeRequired {
            code: "UPGRADE_REQUIRED".into(),
            reason: format!(
                "wire_major={} or schema_rev={} incompatible with server wire_major={} min_schema_rev={}",
                offer.wire_major,
                offer.schema_rev,
                policy.expected_wire_major,
                policy.min_schema_rev
            ),
            minimum_version: min_ver,
            retry_after_ms,
            not_before,
            guidance: "upgrade node agent before retrying BootstrapService/Hello".into(),
        };
    }

    if offer.version_major != policy.server_major
        || offer.version_minor < min_minor
        || offer.version_minor > max_minor
    {
        return HandshakeResolution::UpgradeRequired {
            code: "UPGRADE_REQUIRED".into(),
            reason: format!(
                "component `{}` version {}.{}.{} outside supported skew window {}.{}..={}.{}",
                offer.component,
                offer.version_major,
                offer.version_minor,
                offer.version_patch,
                policy.server_major,
                min_minor,
                policy.server_major,
                max_minor
            ),
            minimum_version: min_ver,
            retry_after_ms,
            not_before,
            guidance: "install signed update bundle within N-2..N+1 compatibility window".into(),
        };
    }

    if let Some((ceil_maj, ceil_min, ceil_pat)) = offer.sensor_ceiling
        && (
            policy.server_major,
            policy.server_minor,
            policy.server_patch,
        ) > (ceil_maj, ceil_min, ceil_pat)
    {
        return HandshakeResolution::UpgradeRequired {
            code: "UPGRADE_REQUIRED".into(),
            reason: format!(
                "host sensor_ceiling {ceil_maj}.{ceil_min}.{ceil_pat} below server target {}.{}.{}",
                policy.server_major, policy.server_minor, policy.server_patch
            ),
            minimum_version: format!("{ceil_maj}.{ceil_min}.{ceil_pat}"),
            retry_after_ms,
            not_before,
            guidance: "raise sensor_ceiling or pin compatible server release".into(),
        };
    }

    for req_contract in &policy.required_contracts {
        if !offer.contracts.iter().any(|c| c == req_contract) {
            return HandshakeResolution::UpgradeRequired {
                code: "UPGRADE_REQUIRED".into(),
                reason: format!("missing required handshake contract `{req_contract}`"),
                minimum_version: min_ver,
                retry_after_ms,
                not_before,
                guidance: "upgrade node agent with required protocol contract support".into(),
            };
        }
    }

    HandshakeResolution::Admitted {
        agreed_contracts: policy.required_contracts.clone(),
    }
}

fn deterministic_jitter_ms(node_id: &str, max_jitter_ms: u64) -> u64 {
    if max_jitter_ms == 0 {
        return 0;
    }
    let digest = sha256_digest(node_id.as_bytes());
    let mut head = [0u8; 8];
    for (dst, src) in head.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    u64::from_le_bytes(head)
        .checked_rem(max_jitter_ms)
        .unwrap_or(0)
}
