// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! TLS `ClientHello` SNI/ALPN/ECH peeking, data-driven (`P14`) enterprise SWG
//! stand-down detection, and 7-criterion selective MITM routing policy.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use grdr_peer_os::fs_open::{OpenNofollowAccess, open_nofollow_file, verify_open_file_trust};
use grdr_wire::peer_auth::Profile;
use serde::{Deserialize, Serialize};

use crate::ProxyError;
pub use crate::tls_hello::peek_tls_client_hello;

const EMBEDDED_SWG_MANIFEST_JSON: &str = include_str!("../manifests/swg_coexistence.json");
const MAX_SWG_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloMetadata {
    pub record_version: (u8, u8),
    pub hello_version: (u8, u8),
    pub sni_host: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub has_ech: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwgProductRule {
    pub id: String,
    #[serde(default)]
    pub header_hints: Vec<String>,
    #[serde(default)]
    pub env_proxy_indicators: Vec<String>,
    #[serde(default)]
    pub cert_cn_indicators: Vec<String>,
    pub fail_open_standdown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptEligibleHost {
    pub host_suffix: String,
    pub provider_family: String,
    pub route_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwgCoexistenceManifest {
    pub schema_version: u32,
    pub swg_products: Vec<SwgProductRule>,
    pub excluded_caller_classes: Vec<String>,
    pub intercept_eligible_hosts: Vec<InterceptEligibleHost>,
    pub bypass_pinned_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwgDetectionResult {
    pub detected_product_id: Option<String>,
    pub stand_down_required: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerClass {
    ManagedAgent,
    BrowserManaged,
    OsSystem,
    PinnedUpdater,
    CertificateTransparency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCaTrust {
    Trusted,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinningHealth {
    Healthy,
    FailureRecorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwgOverrideMode {
    RespectStandDown,
    ExplicitOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchPolicy {
    PassthroughOnEch,
    RejectWhenMitmRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectiveMitmInput {
    pub connect_host: String,
    pub caller_class: CallerClass,
    pub local_ca_trust: LocalCaTrust,
    pub pinning_health: PinningHealth,
    pub ech_policy: EchPolicy,
    pub swg_override: SwgOverrideMode,
    pub swg: SwgDetectionResult,
    pub client_hello: Option<ClientHelloMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmBypassReason {
    HostNotInterceptEligible,
    BypassPinnedHost,
    ExcludedCallerClass,
    EnterpriseSwgStandDown,
    LocalCaUntrusted,
    PinningFailureRecorded,
    EchPassthrough,
    NonTlsTraffic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmDenyReason {
    SniMismatch,
    EchBlocked,
    NonTlsTrafficRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitmRoutingDecision {
    InterceptTls {
        provider_family: String,
        sni_host: Option<String>,
        alpn_protocols: Vec<String>,
    },
    Passthrough(MitmBypassReason),
    Deny(MitmDenyReason, String),
}

impl CallerClass {
    #[must_use]
    pub const fn as_manifest_key(self) -> &'static str {
        match self {
            Self::ManagedAgent => "managed_agent",
            Self::BrowserManaged => "browser_managed",
            Self::OsSystem => "os_system",
            Self::PinnedUpdater => "pinned_updater",
            Self::CertificateTransparency => "certificate_transparency",
        }
    }
}

pub fn load_swg_coexistence_manifest(
    profile: Profile,
) -> Result<SwgCoexistenceManifest, ProxyError> {
    if let Ok(path) = std::env::var("GRDR_PROXY_SWG_MANIFEST") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            if profile == Profile::Protected {
                return Err(ProxyError::Sr39Rejected(
                    "Protected profile prohibits GRDR_PROXY_SWG_MANIFEST override".to_string(),
                ));
            }
            let raw = read_bounded_regular_manifest(Path::new(trimmed))?;
            return serde_json::from_str::<SwgCoexistenceManifest>(&raw).map_err(|e| {
                ProxyError::Sr39Rejected(format!("invalid external SWG manifest JSON: {e}"))
            });
        }
    }
    serde_json::from_str::<SwgCoexistenceManifest>(EMBEDDED_SWG_MANIFEST_JSON).map_err(|e| {
        ProxyError::Transport(format!("invalid embedded SWG coexistence manifest: {e}"))
    })
}

fn read_bounded_regular_manifest(path: &Path) -> Result<String, ProxyError> {
    let file = open_nofollow_file(path, OpenNofollowAccess::ReadOnly, 0o600).map_err(|e| {
        ProxyError::Transport(format!("open SWG manifest `{}`: {e}", path.display()))
    })?;
    verify_open_file_trust(&file, false)
        .map_err(|e| ProxyError::Transport(format!("untrusted SWG manifest file: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| ProxyError::Transport(format!("stat SWG manifest: {e}")))?;
    if !meta.is_file() {
        return Err(ProxyError::Sr39Rejected(
            "SWG manifest path must be a regular file".to_string(),
        ));
    }
    if usize::try_from(meta.len()).unwrap_or(usize::MAX) > MAX_SWG_MANIFEST_BYTES {
        return Err(ProxyError::Sr39Rejected(
            "SWG manifest exceeds 1 MiB limit".to_string(),
        ));
    }
    let mut raw = Vec::new();
    file.take(u64::try_from(MAX_SWG_MANIFEST_BYTES.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut raw)
        .map_err(|e| ProxyError::Transport(format!("read SWG manifest: {e}")))?;
    if raw.len() > MAX_SWG_MANIFEST_BYTES {
        return Err(ProxyError::Sr39Rejected(
            "SWG manifest exceeded 1 MiB bound while reading".to_string(),
        ));
    }
    String::from_utf8(raw)
        .map_err(|_| ProxyError::Sr39Rejected("SWG manifest must be valid UTF-8".to_string()))
}

#[must_use]
pub fn detect_enterprise_swg(
    env_map: &BTreeMap<String, String>,
    observed_header_names: &[String],
    proxy_cert_cn: Option<&str>,
    manifest: &SwgCoexistenceManifest,
) -> SwgDetectionResult {
    let env_proxy_lower: Vec<String> = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .filter_map(|k| env_map.get(*k))
        .map(|v| v.to_ascii_lowercase())
        .collect();
    let hdr_lower: Vec<String> = observed_header_names
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let cert_cn_lower = proxy_cert_cn.unwrap_or("").to_ascii_lowercase();

    for rule in &manifest.swg_products {
        let env_hit = rule.env_proxy_indicators.iter().any(|ind| {
            env_proxy_lower
                .iter()
                .any(|val| val.contains(&ind.to_ascii_lowercase()))
        });
        let hdr_hit = rule.header_hints.iter().any(|hint| {
            hdr_lower
                .iter()
                .any(|h| h.starts_with(&hint.to_ascii_lowercase()))
        });
        let cert_hit = !cert_cn_lower.is_empty()
            && rule
                .cert_cn_indicators
                .iter()
                .any(|cn| cert_cn_lower.contains(&cn.to_ascii_lowercase()));

        if env_hit || hdr_hit || cert_hit {
            return SwgDetectionResult {
                detected_product_id: Some(rule.id.clone()),
                stand_down_required: rule.fail_open_standdown,
                reason: format!("enterprise SWG `{}` detected; standing down MITM", rule.id),
            };
        }
    }

    SwgDetectionResult {
        detected_product_id: None,
        stand_down_required: false,
        reason: "no conflicting enterprise SWG detected".to_string(),
    }
}

pub fn evaluate_selective_mitm_policy(
    input: &SelectiveMitmInput,
    manifest: &SwgCoexistenceManifest,
) -> MitmRoutingDecision {
    let connect_lower = input.connect_host.trim().to_ascii_lowercase();

    // Reject SNI mismatch before any passthrough rule can apply.
    if let Some(hello) = input.client_hello.as_ref()
        && let Some(sni) = hello.sni_host.as_deref()
        && !sni.eq_ignore_ascii_case(&connect_lower)
    {
        return MitmRoutingDecision::Deny(
            MitmDenyReason::SniMismatch,
            format!(
                "GRDR-PROXY-0008: net.sni-mismatch CONNECT `{}` disagrees with TLS SNI `{sni}`",
                input.connect_host
            ),
        );
    }

    if input.pinning_health == PinningHealth::FailureRecorded {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::PinningFailureRecorded);
    }

    if input.swg.stand_down_required && input.swg_override == SwgOverrideMode::RespectStandDown {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::EnterpriseSwgStandDown);
    }

    let caller_key = input.caller_class.as_manifest_key();
    if manifest
        .excluded_caller_classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case(caller_key))
    {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::ExcludedCallerClass);
    }

    if input.local_ca_trust == LocalCaTrust::Untrusted {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::LocalCaUntrusted);
    }

    if manifest
        .bypass_pinned_hosts
        .iter()
        .any(|p| host_matches_rule(&connect_lower, p))
    {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::BypassPinnedHost);
    }

    let eligible = manifest
        .intercept_eligible_hosts
        .iter()
        .find(|entry| host_matches_rule(&connect_lower, &entry.host_suffix));
    let Some(matched_host) = eligible else {
        return MitmRoutingDecision::Passthrough(MitmBypassReason::HostNotInterceptEligible);
    };

    let Some(hello) = input.client_hello.as_ref() else {
        return MitmRoutingDecision::Deny(
            MitmDenyReason::NonTlsTrafficRequired,
            "GRDR-PROXY-0008: unencrypted non-TLS traffic forbidden on intercept-eligible LLM host"
                .into(),
        );
    };

    if hello.has_ech {
        return match input.ech_policy {
            EchPolicy::RejectWhenMitmRequired => MitmRoutingDecision::Deny(
                MitmDenyReason::EchBlocked,
                "net.ech: ECH extension present on MITM-required route".into(),
            ),
            EchPolicy::PassthroughOnEch => {
                MitmRoutingDecision::Passthrough(MitmBypassReason::EchPassthrough)
            }
        };
    }

    MitmRoutingDecision::InterceptTls {
        provider_family: matched_host.provider_family.clone(),
        sni_host: hello.sni_host.clone(),
        alpn_protocols: hello.alpn_protocols.clone(),
    }
}

fn host_matches_rule(host: &str, rule: &str) -> bool {
    let r = rule.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if r.is_empty() || h.is_empty() {
        return false;
    }
    if rule.trim().ends_with('.') {
        let prefix = rule.trim().to_ascii_lowercase();
        return h.starts_with(&prefix);
    }
    h == r || h.ends_with(&format!(".{r}"))
}
