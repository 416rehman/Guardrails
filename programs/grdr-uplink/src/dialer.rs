// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Egress `Dialer` enforcing `network.mode = "isolated"` (`P16`), explicit TLS proxy
//! chaining (`D-16`), DNS-rebind IP pinning, and 24-hour sticky ladder caching (`D-22`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::allowlist::{
    AllowEntry, PrivateAddressPolicy, ValidatedProxyHost, is_disallowed_private_or_link_local,
    parse_https_target, parse_proxy_host,
};
use crate::error::{OfflineReason, UplinkError, UplinkHealthCondition};

/// Default sticky cache window for egress ladder probing (24 hours).
pub const DEFAULT_LADDER_TTL_MS: u64 = 86_400_000;
const HTTP_CLIENT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const HTTP_CLIENT_REQUEST_TIMEOUT_MS: u64 = 65_000;

/// Egress operating mode for `grdr-uplink`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Standard fleet mode enforcing strict private/SSRF destination blocks.
    Standard,
    /// Strict isolated mode (`P16` / `network.mode = "isolated"`): drops all default origins.
    Isolated { allow_list: Vec<AllowEntry> },
}

/// Purpose for an outbound dial request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialPurpose {
    FleetControl,
    FleetPush,
    ArtifactDownload,
    ThreatFeed,
    Lookup,
    DirectorySync,
}

/// Proxy credential availability for non-interactive system daemons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyCredentialKind {
    None,
    ProtectedMachine,
    UserInteractive,
}

/// Configured proxy selection strategy (`D-16`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelection {
    Direct,
    Explicit {
        host: String,
        port: u16,
        #[serde(default)]
        resolved_ips: Vec<IpAddr>,
        credential: ProxyCredentialKind,
    },
    Pac {
        pac_url: String,
        credential: ProxyCredentialKind,
    },
    System {
        credential: ProxyCredentialKind,
    },
}

/// Transport fallback ladder rung ordered from cleanest to most restricted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRung {
    Http3Direct = 0,
    Http2Direct = 1,
    Http11Tls = 2,
    ExplicitProxyHttp11 = 3,
    DegradedBlocked = 4,
}

/// Pinning validation posture observed on the active network segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinVerification {
    SpkiPinVerified,
    SystemRootFallback,
}

/// Middlebox or TLS inspection classification observed along a path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCondition {
    Normal,
    TlsInspected { issuer: String },
    MtlsRequired,
    RestrictiveFirewall,
}

/// Network fingerprint key (gateway MAC hash + DNS suffix) for 24h ladder caching.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub gateway_mac_hash: String,
    pub dns_suffix: String,
}

/// Sticky cached ladder state for one network fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderCacheEntry {
    pub rung: TransportRung,
    pub condition: NetworkCondition,
    pub pin: PinVerification,
    pub kex: String,
    pub push_channel: String,
    pub expires_at_mono_ms: u64,
}

/// Target metadata supplied at dial/resolve time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialTarget {
    pub uri: String,
    pub purpose: DialPurpose,
    pub resolved_ips: Vec<IpAddr>,
}

/// Authorized dial plan pinning resolved target and proxy IPs for `reqwest::Client::builder().resolve(...)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDialPlan {
    pub host: String,
    pub port: u16,
    pub selected_ip: IpAddr,
    pub selected_proxy_ip: Option<IpAddr>,
    pub proxy: ProxySelection,
    pub rung: TransportRung,
    pub health: UplinkHealthCondition,
}

/// Enforces `Dialer` allow-list, isolated mode, proxy policy, and sticky ladder state.
#[derive(Clone, Debug)]
pub struct Dialer {
    network_mode: NetworkMode,
    proxy: ProxySelection,
    private_policy: PrivateAddressPolicy,
    ladder_ttl_ms: u64,
    ladder_cache: BTreeMap<NetworkFingerprint, LadderCacheEntry>,
}

impl NetworkFingerprint {
    /// Canonical stable lookup key without leaking raw local network names.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.gateway_mac_hash, self.dns_suffix)
    }
}

impl Dialer {
    /// Build a new `Dialer` enforcing `network_mode`, private/SSRF blocks, and proxy policy.
    #[must_use]
    pub fn new(network_mode: NetworkMode, proxy: ProxySelection) -> Self {
        Self {
            network_mode,
            proxy,
            private_policy: PrivateAddressPolicy::BlockPrivateAndLinkLocal,
            ladder_ttl_ms: DEFAULT_LADDER_TTL_MS,
            ladder_cache: BTreeMap::new(),
        }
    }

    /// Test-only override allowing local loopback relay harnesses.
    #[cfg(test)]
    #[must_use]
    pub fn with_loopback_relay_for_tests(mut self) -> Self {
        self.private_policy = PrivateAddressPolicy::AllowLoopbackForLocalRelay;
        self
    }

    /// Override sticky ladder cache TTL.
    #[must_use]
    pub fn with_ladder_ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ladder_ttl_ms = ttl_ms;
        self
    }

    /// Record an observed egress ladder probe in the 24h sticky cache.
    pub fn record_ladder_probe(
        &mut self,
        fingerprint: NetworkFingerprint,
        rung: TransportRung,
        condition: NetworkCondition,
        pin: PinVerification,
        kex: impl Into<String>,
        now_mono_ms: u64,
    ) -> UplinkHealthCondition {
        let expires_at_mono_ms = now_mono_ms.saturating_add(self.ladder_ttl_ms);
        let push_channel = match rung {
            TransportRung::Http3Direct | TransportRung::Http2Direct => "subscribe",
            TransportRung::Http11Tls | TransportRung::ExplicitProxyHttp11 => "long_poll",
            TransportRung::DegradedBlocked => "none",
        }
        .to_string();

        let degraded = rung > TransportRung::Http2Direct
            || matches!(condition, NetworkCondition::TlsInspected { .. })
            || matches!(pin, PinVerification::SystemRootFallback);

        self.ladder_cache.insert(
            fingerprint,
            LadderCacheEntry {
                rung,
                condition,
                pin,
                kex: kex.into(),
                push_channel,
                expires_at_mono_ms,
            },
        );

        if rung == TransportRung::DegradedBlocked {
            UplinkHealthCondition::UplinkOffline(OfflineReason::TlsHandshakeFailed)
        } else if degraded {
            UplinkHealthCondition::UplinkDowngraded
        } else {
            UplinkHealthCondition::Healthy
        }
    }

    /// Look up cached sticky ladder state if it has not expired.
    #[must_use]
    pub fn cached_ladder(
        &self,
        fingerprint: &NetworkFingerprint,
        now_mono_ms: u64,
    ) -> Option<&LadderCacheEntry> {
        self.ladder_cache
            .get(fingerprint)
            .filter(|entry| now_mono_ms <= entry.expires_at_mono_ms)
    }

    /// Validate proxy credential availability, target URI, `network.mode`, and resolved IPs.
    pub fn authorize_dial(
        &self,
        target: &DialTarget,
        fingerprint: Option<&NetworkFingerprint>,
        now_mono_ms: u64,
    ) -> Result<ValidatedDialPlan, UplinkError> {
        self.ensure_proxy_credential_compatible()?;
        let parsed = parse_https_target(&target.uri)?;
        let selected_proxy_ip = self.validate_proxy_policy()?;

        self.enforce_host_allowed(
            &parsed.host,
            "target destination not in isolated allow_list",
        )?;
        let selected_ip = self.validate_candidate_ips(
            "egress target",
            &parsed.host,
            parsed.host_ip,
            &target.resolved_ips,
        )?;

        let cached = fingerprint.and_then(|fp| self.cached_ladder(fp, now_mono_ms));
        let rung = match (cached, &self.proxy) {
            (Some(entry), _) => entry.rung,
            (None, ProxySelection::Explicit { .. }) => TransportRung::ExplicitProxyHttp11,
            (None, _) => TransportRung::Http2Direct,
        };

        let health = if cached.is_some_and(|e| {
            e.rung > TransportRung::Http2Direct
                || matches!(e.condition, NetworkCondition::TlsInspected { .. })
                || matches!(e.pin, PinVerification::SystemRootFallback)
        }) {
            UplinkHealthCondition::UplinkDowngraded
        } else {
            UplinkHealthCondition::Healthy
        };

        Ok(ValidatedDialPlan {
            host: parsed.host,
            port: parsed.port,
            selected_ip,
            selected_proxy_ip,
            proxy: self.proxy.clone(),
            rung,
            health,
        })
    }

    /// Build an HTTPS `reqwest::Client` pinning resolved target and proxy IPs cleanly.
    pub fn build_http_client_for_plan(
        &self,
        plan: Option<&ValidatedDialPlan>,
    ) -> Result<Client, UplinkError> {
        self.ensure_proxy_credential_compatible()?;
        let verified_proxy_ip = self.validate_proxy_policy()?;
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_millis(HTTP_CLIENT_CONNECT_TIMEOUT_MS))
            .timeout(Duration::from_millis(HTTP_CLIENT_REQUEST_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none());

        if let Some(p) = plan {
            builder = builder.resolve(&p.host, SocketAddr::new(p.selected_ip, p.port));
        }

        builder = match (&self.network_mode, &self.proxy) {
            (NetworkMode::Isolated { .. }, ProxySelection::System { .. }) => {
                return Err(UplinkError::EgressUnlisted {
                    host: "system-proxy".to_string(),
                    reason: "ambient system proxy disallowed in isolated mode".to_string(),
                });
            }
            (NetworkMode::Isolated { .. }, ProxySelection::Pac { .. }) => {
                return Err(UplinkError::EgressUnlisted {
                    host: "pac-proxy".to_string(),
                    reason: "PAC proxy disallowed in isolated mode".to_string(),
                });
            }
            (_, ProxySelection::Direct) => builder.no_proxy(),
            (_, ProxySelection::Explicit { host, port, .. }) => {
                let parsed_proxy = parse_proxy_host(host)?;
                let proxy_ip = plan
                    .and_then(|p| p.selected_proxy_ip)
                    .or(verified_proxy_ip)
                    .ok_or_else(|| UplinkError::EgressUnlisted {
                        host: parsed_proxy.host.clone(),
                        reason: "explicit proxy lacks validated IP address".to_string(),
                    })?;
                if parsed_proxy.host_ip.is_none() {
                    builder = builder.resolve(&parsed_proxy.host, SocketAddr::new(proxy_ip, *port));
                }
                let formatted_host = if parsed_proxy.host.contains(':') {
                    format!("[{}]", parsed_proxy.host)
                } else {
                    parsed_proxy.host
                };
                let proxy_url = format!("https://{formatted_host}:{port}");
                let proxy =
                    reqwest::Proxy::all(&proxy_url).map_err(|e| UplinkError::Transport {
                        detail: format!("invalid HTTPS proxy configuration: {e}"),
                    })?;
                builder.proxy(proxy)
            }
            (NetworkMode::Standard, ProxySelection::System { .. })
            | (NetworkMode::Standard, ProxySelection::Pac { .. }) => builder,
        };

        builder.build().map_err(|e| UplinkError::Transport {
            detail: format!("failed to build HTTPS client: {e}"),
        })
    }

    fn ensure_proxy_credential_compatible(&self) -> Result<(), UplinkError> {
        let cred = match &self.proxy {
            ProxySelection::Direct => ProxyCredentialKind::None,
            ProxySelection::Explicit { credential, .. }
            | ProxySelection::Pac { credential, .. }
            | ProxySelection::System { credential } => *credential,
        };
        if cred == ProxyCredentialKind::UserInteractive {
            return Err(UplinkError::ProxyAuthUserOnly {
                detail: "proxy authentication requires interactive user credentials unavailable to system uplink".to_string(),
            });
        }
        Ok(())
    }

    fn validate_proxy_policy(&self) -> Result<Option<IpAddr>, UplinkError> {
        if matches!(self.network_mode, NetworkMode::Isolated { .. }) {
            match &self.proxy {
                ProxySelection::Pac { .. } => {
                    return Err(UplinkError::EgressUnlisted {
                        host: "pac-proxy".to_string(),
                        reason: "PAC proxy discovery is disallowed in isolated mode".to_string(),
                    });
                }
                ProxySelection::System { .. } => {
                    return Err(UplinkError::EgressUnlisted {
                        host: "system-proxy".to_string(),
                        reason: "ambient system proxy is disallowed in isolated mode".to_string(),
                    });
                }
                ProxySelection::Direct | ProxySelection::Explicit { .. } => {}
            }
        }

        if let ProxySelection::Explicit {
            host,
            port,
            resolved_ips,
            ..
        } = &self.proxy
        {
            if *port == 0 {
                return Err(UplinkError::InvalidEndpoint {
                    detail: "explicit proxy port must be non-zero".to_string(),
                });
            }
            let ValidatedProxyHost {
                host: canonical_host,
                host_ip,
            } = parse_proxy_host(host)?;
            self.enforce_host_allowed(
                &canonical_host,
                "explicit proxy host not in isolated allow_list",
            )?;
            let selected = self.validate_candidate_ips(
                "explicit proxy",
                &canonical_host,
                host_ip,
                resolved_ips,
            )?;
            return Ok(Some(selected));
        }

        Ok(None)
    }

    fn enforce_host_allowed(&self, host: &str, reason: &str) -> Result<(), UplinkError> {
        match &self.network_mode {
            NetworkMode::Standard => Ok(()),
            NetworkMode::Isolated { allow_list } => {
                if allow_list.iter().any(|rule| rule.matches_host(host)) {
                    Ok(())
                } else {
                    Err(UplinkError::EgressUnlisted {
                        host: host.to_string(),
                        reason: reason.to_string(),
                    })
                }
            }
        }
    }

    fn validate_candidate_ips(
        &self,
        label: &str,
        host: &str,
        host_ip: Option<IpAddr>,
        resolved_ips: &[IpAddr],
    ) -> Result<IpAddr, UplinkError> {
        let mut candidates = Vec::new();
        if let Some(ip) = host_ip {
            candidates.push(ip);
        }
        candidates.extend_from_slice(resolved_ips);

        if candidates.is_empty() {
            return Err(UplinkError::EgressUnlisted {
                host: host.to_string(),
                reason: format!("{label} DNS hostname requires resolved IPs prior to dial"),
            });
        }

        for ip in &candidates {
            match &self.network_mode {
                NetworkMode::Isolated { allow_list } => {
                    let ip_explicitly_allowed = allow_list.iter().any(|rule| rule.matches_ip(*ip));
                    let host_allowed = allow_list.iter().any(|rule| rule.matches_host(host));
                    if !ip_explicitly_allowed && is_disallowed_private_or_link_local(*ip) {
                        return Err(UplinkError::EgressUnlisted {
                            host: host.to_string(),
                            reason: format!(
                                "resolved address {ip} for {label} is private/link-local and not CIDR-allowlisted"
                            ),
                        });
                    }
                    if !ip_explicitly_allowed && !host_allowed {
                        return Err(UplinkError::EgressUnlisted {
                            host: ip.to_string(),
                            reason: format!(
                                "resolved IP for {label} not permitted in isolated mode"
                            ),
                        });
                    }
                }
                NetworkMode::Standard => match self.private_policy {
                    PrivateAddressPolicy::BlockPrivateAndLinkLocal
                        if is_disallowed_private_or_link_local(*ip) =>
                    {
                        return Err(UplinkError::EgressUnlisted {
                            host: ip.to_string(),
                            reason: format!("private or special-use {label} blocked by SSRF guard"),
                        });
                    }
                    #[cfg(test)]
                    PrivateAddressPolicy::AllowLoopbackForLocalRelay
                        if is_disallowed_private_or_link_local(*ip) && !ip.is_loopback() =>
                    {
                        return Err(UplinkError::EgressUnlisted {
                            host: ip.to_string(),
                            reason: format!(
                                "non-loopback private or special-use {label} egress blocked"
                            ),
                        });
                    }
                    _ => {}
                },
            }
        }

        candidates
            .first()
            .copied()
            .ok_or_else(|| UplinkError::EgressUnlisted {
                host: host.to_string(),
                reason: format!("{label} lacks validated IP"),
            })
    }
}
