// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::sync::OnceLock;

use grdr_schema::brand::{brand_identity, is_valid_brand_identity, load_embedded_brand_display};
use grdr_schema::limits::load_embedded_limits;
use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;

include!(concat!(env!("OUT_DIR"), "/generated_brand.rs"));

const TRANSCRIPT_CHUNK_CAP_BYTES: usize = 65_536;
const BYTES_PER_MIB: u64 = 1_048_576;

static BRAND_CACHE: OnceLock<Result<MacOsBrandConfig, MacOsSensorError>> = OnceLock::new();
static LIMITS_CACHE: OnceLock<Result<MacOsLimitsSnapshot, MacOsSensorError>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsBrandConfig {
    pub namespace: String,
    pub product_name: String,
    pub short_name: String,
    pub app_bundle_name: String,
    pub macos_bundle_id: String,
    pub macos_daemon_label: String,
    pub macos_agent_label: String,
    pub macos_netext_bundle_id: String,
    pub macos_esext_bundle_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsLimitsSnapshot {
    pub ipc_max_frame_bytes: usize,
    pub ipc_read_timeout_ms: u64,
    pub command_hold_max_ms: u64,
    pub hook_macos_p50_ms: u32,
    pub hook_macos_p99_ms: u32,
    pub max_pack_bytes: u64,
    pub transcript_chunk_max_bytes: usize,
    pub transcript_skip_cap_bytes: usize,
}

impl MacOsBrandConfig {
    pub fn try_embedded() -> Result<&'static Self, MacOsSensorError> {
        let cached = BRAND_CACHE.get_or_init(|| {
            let identity = brand_identity();
            if !is_valid_brand_identity(&identity) {
                return Err(MacOsSensorError::Source(
                    "invalid embedded brand identity in brand.toml".into(),
                ));
            }
            let display = load_embedded_brand_display().map_err(|err| {
                MacOsSensorError::Source(format!("failed loading embedded brand display: {err}"))
            })?;
            Ok(Self {
                namespace: identity.namespace,
                product_name: display.product_name,
                short_name: display.short_name,
                app_bundle_name: BRAND_APP_BUNDLE_NAME.to_string(),
                macos_bundle_id: BRAND_MACOS_BUNDLE_ID.to_string(),
                macos_daemon_label: BRAND_MACOS_DAEMON_LABEL.to_string(),
                macos_agent_label: display.macos_agent_label,
                macos_netext_bundle_id: BRAND_MACOS_NETEXT_BUNDLE_ID.to_string(),
                macos_esext_bundle_id: BRAND_MACOS_ESEXT_BUNDLE_ID.to_string(),
            })
        });
        cached.as_ref().map_err(Clone::clone)
    }

    pub fn own_extension_prefix(&self) -> String {
        if self.macos_bundle_id.is_empty() {
            String::new()
        } else {
            format!("{}.", self.macos_bundle_id)
        }
    }

    pub fn is_own_extension_identifier(&self, identifier: &str) -> bool {
        let candidate = identifier.trim();
        if candidate.is_empty() || self.macos_bundle_id.is_empty() {
            return false;
        }
        if candidate == self.macos_netext_bundle_id || candidate == self.macos_esext_bundle_id {
            return true;
        }
        let prefix = self.own_extension_prefix();
        !prefix.is_empty() && candidate.starts_with(&prefix)
    }

    pub fn is_valid_xpc_peer_signing_id(&self, signing_id: &str) -> bool {
        let clean = signing_id.trim();
        if clean.is_empty()
            || !clean
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return false;
        }
        clean == self.macos_bundle_id
            || clean == self.macos_daemon_label
            || clean == self.macos_agent_label
            || clean == self.macos_netext_bundle_id
            || clean == self.macos_esext_bundle_id
            || clean.starts_with(&self.own_extension_prefix())
    }

    pub fn queue_label(&self, suffix: &str) -> String {
        let clean = suffix.trim().trim_start_matches('.');
        if self.macos_bundle_id.is_empty() {
            clean.to_string()
        } else if clean.is_empty() {
            self.macos_bundle_id.clone()
        } else {
            format!("{}.{clean}", self.macos_bundle_id)
        }
    }

    pub fn app_group_id(&self) -> String {
        if self.macos_bundle_id.is_empty() {
            String::new()
        } else {
            format!("group.{}", self.macos_bundle_id)
        }
    }

    pub fn xpc_code_signing_requirement_for_peer(
        &self,
        team_id: &str,
        peer_signing_id: &str,
    ) -> Option<String> {
        let team = team_id.trim();
        let peer = peer_signing_id.trim();
        if !is_valid_apple_team_id(team) || !self.is_valid_xpc_peer_signing_id(peer) {
            return None;
        }
        Some(format!(
            "anchor apple generic and identifier = \"{peer}\" and certificate leaf[subject.OU] = \"{team}\""
        ))
    }

    pub fn xpc_code_signing_requirement_for_peers(
        &self,
        team_id: &str,
        peer_signing_ids: &[&str],
    ) -> Option<String> {
        let team = team_id.trim();
        if !is_valid_apple_team_id(team) || peer_signing_ids.is_empty() {
            return None;
        }
        let mut clauses = Vec::with_capacity(peer_signing_ids.len());
        for &raw in peer_signing_ids {
            let clean = raw.trim();
            if !self.is_valid_xpc_peer_signing_id(clean) {
                return None;
            }
            clauses.push(format!("identifier = \"{clean}\""));
        }
        Some(format!(
            "anchor apple generic and ({}) and certificate leaf[subject.OU] = \"{team}\"",
            clauses.join(" or ")
        ))
    }
}

impl MacOsLimitsSnapshot {
    pub fn try_embedded() -> Result<Self, MacOsSensorError> {
        let cached = LIMITS_CACHE.get_or_init(|| {
            let cfg = load_embedded_limits().map_err(|err| {
                MacOsSensorError::Source(format!("failed loading embedded schema limits: {err}"))
            })?;
            let ipc_max_frame_bytes = cfg.endpoint.ipc.max_frame_bytes;
            let max_pack_bytes = u64::from(cfg.packs.max_pack_bundle_mb)
                .checked_mul(BYTES_PER_MIB)
                .ok_or_else(|| {
                    MacOsSensorError::Source("packs.max_pack_bundle_mb byte size overflow".into())
                })?;
            Ok(Self {
                ipc_max_frame_bytes,
                ipc_read_timeout_ms: cfg.endpoint.ipc.read_timeout_ms,
                command_hold_max_ms: cfg.endpoint.ipc.command_hold_max_ms,
                hook_macos_p50_ms: cfg.endpoint.latency_ms.hook_macos_p50,
                hook_macos_p99_ms: cfg.endpoint.latency_ms.hook_macos_p99,
                max_pack_bytes,
                transcript_chunk_max_bytes: ipc_max_frame_bytes.min(TRANSCRIPT_CHUNK_CAP_BYTES),
                transcript_skip_cap_bytes: ipc_max_frame_bytes,
            })
        });
        cached.clone()
    }
}

pub fn is_valid_apple_team_id(team_id: &str) -> bool {
    team_id.len() == 10
        && team_id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_schema_brand_manifest_and_pins_exact_xpc_signing_ids() {
        let brand = MacOsBrandConfig::try_embedded().expect("valid schema brand");
        assert_eq!(brand.namespace, "grdr");
        assert_eq!(brand.macos_bundle_id, "com.guardrailshq.grdr");
        assert_eq!(brand.macos_daemon_label, "com.guardrailshq.grdr.daemon");
        assert_eq!(brand.macos_netext_bundle_id, "com.guardrailshq.grdr.netext");
        assert_eq!(brand.macos_esext_bundle_id, "com.guardrailshq.grdr.esext");
        assert_eq!(brand.own_extension_prefix(), "com.guardrailshq.grdr.");
        assert!(brand.is_own_extension_identifier("com.guardrailshq.grdr.netext"));
        assert!(brand.is_own_extension_identifier("com.guardrailshq.grdr.esext"));
        assert!(!brand.is_own_extension_identifier("io.guardrails.es"));
        assert!(!brand.is_own_extension_identifier("com.vendor.ztna.ne"));
        assert_eq!(
            brand.queue_label("es.coordinator"),
            "com.guardrailshq.grdr.es.coordinator"
        );
        assert_eq!(brand.app_group_id(), "group.com.guardrailshq.grdr");

        let exact = brand
            .xpc_code_signing_requirement_for_peer("TEAM123456", &brand.macos_daemon_label)
            .expect("exact daemon requirement");
        assert!(exact.contains("identifier = \"com.guardrailshq.grdr.daemon\""));
        assert!(!exact.contains("like"));
        assert!(!exact.contains('*'));

        let multi = brand
            .xpc_code_signing_requirement_for_peers(
                "TEAM123456",
                &[&brand.macos_daemon_label, &brand.macos_esext_bundle_id],
            )
            .expect("multi peer exact requirement");
        assert!(multi.contains("identifier = \"com.guardrailshq.grdr.daemon\""));
        assert!(multi.contains("identifier = \"com.guardrailshq.grdr.esext\""));
        assert!(!multi.contains("like"));
        assert!(
            brand
                .xpc_code_signing_requirement_for_peer("bad", &brand.macos_daemon_label)
                .is_none()
        );
        assert!(
            brand
                .xpc_code_signing_requirement_for_peer("TEAM123456", "com.evil.spoof")
                .is_none()
        );
    }

    #[test]
    fn consumes_typed_schema_limits_without_linux_sensor_or_fallback() {
        let limits = MacOsLimitsSnapshot::try_embedded().expect("schema limits");
        assert_eq!(limits.ipc_max_frame_bytes, 1_048_576);
        assert_eq!(limits.ipc_read_timeout_ms, 1_500);
        assert_eq!(limits.command_hold_max_ms, 1_000);
        assert_eq!(limits.hook_macos_p50_ms, 10);
        assert_eq!(limits.hook_macos_p99_ms, 50);
        assert_eq!(limits.max_pack_bytes, 33_554_432);
        assert_eq!(limits.transcript_chunk_max_bytes, 65_536);
    }
}
