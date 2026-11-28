// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Outbound network egress `Dialer` port seam and isolation policy (`P16`, `ARCH-025`).

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub use crate::codes::CODE_WIRE_EGRESS_BLOCKED;
pub use crate::dialer_net::is_non_public_ip;
use crate::dialer_net::{NormalizedHost, normalize_host, validate_pac_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolatedAllowRule {
    pub host: String,
    pub port: u16,
    pub purposes: Vec<DialPurpose>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Standard,
    Isolated { allow_list: Vec<IsolatedAllowRule> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialPurpose {
    FleetControl,
    FleetPush,
    ArtifactDownload,
    ThreatFeed,
    Lookup,
    DirectorySync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelection {
    Direct,
    ExplicitTls {
        host: String,
        port: u16,
        #[serde(default)]
        resolved_ips: Vec<IpAddr>,
    },
    ExplicitHttpConnect {
        host: String,
        port: u16,
        #[serde(default)]
        resolved_ips: Vec<IpAddr>,
    },
    System,
    Pac {
        pac_url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDialRequest {
    pub purpose: DialPurpose,
    pub host: String,
    pub port: u16,
    pub tls_required: bool,
    pub proxy: ProxySelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDialPlan {
    pub host: String,
    pub port: u16,
    pub pinned_ip: IpAddr,
    pub pinned_proxy_ip: Option<IpAddr>,
    pub purpose: DialPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDialReceipt {
    pub host: String,
    pub port: u16,
    pub pinned_ip: IpAddr,
    pub purpose: DialPurpose,
    pub proxy_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressRouteError {
    PolicyBlocked(String),
    PrivateAddressDenied(String),
    InsecureScheme(String),
}

/// Single outbound HTTPS/WSS egress seam enforced across Layer 4 binaries (`ARCH-025`).
pub trait Dialer: Send + Sync {
    fn network_mode(&self) -> &NetworkMode;
    fn check_route(
        &self,
        req: &EgressDialRequest,
        resolved_ips: &[IpAddr],
    ) -> Result<EgressDialPlan, EgressRouteError>;
    fn record_dial_receipt(&mut self, receipt: EgressDialReceipt);
}

impl EgressRouteError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        CODE_WIRE_EGRESS_BLOCKED
    }
}

impl fmt::Display for EgressRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyBlocked(detail) => {
                write!(
                    f,
                    "{CODE_WIRE_EGRESS_BLOCKED}: egress blocked by policy: {detail}"
                )
            }
            Self::PrivateAddressDenied(detail) => {
                write!(
                    f,
                    "{CODE_WIRE_EGRESS_BLOCKED}: private/link-local egress denied: {detail}"
                )
            }
            Self::InsecureScheme(detail) => {
                write!(
                    f,
                    "{CODE_WIRE_EGRESS_BLOCKED}: plain non-TLS egress denied: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for EgressRouteError {}

pub fn validate_egress_request(
    mode: &NetworkMode,
    req: &EgressDialRequest,
    resolved_ips: &[IpAddr],
) -> Result<EgressDialPlan, EgressRouteError> {
    if !req.tls_required {
        return Err(EgressRouteError::InsecureScheme(format!(
            "{}:{} must enable TLS",
            req.host, req.port
        )));
    }
    if req.port == 0 {
        return Err(EgressRouteError::PolicyBlocked(
            "egress TCP port must be 1..=65535".into(),
        ));
    }

    let target = normalize_host(&req.host, "target")?;
    let pinned_ip = validate_pinned_ips("target", &target, resolved_ips)?;
    if let NetworkMode::Isolated { allow_list } = mode {
        enforce_allow_list(allow_list, &target, req.port, req.purpose, "target")?;
    }

    let pinned_proxy_ip = validate_proxy_selection(mode, &req.proxy, req.purpose)?;

    Ok(EgressDialPlan {
        host: target.canonical,
        port: req.port,
        pinned_ip,
        pinned_proxy_ip,
        purpose: req.purpose,
    })
}

fn validate_proxy_selection(
    mode: &NetworkMode,
    proxy: &ProxySelection,
    purpose: DialPurpose,
) -> Result<Option<IpAddr>, EgressRouteError> {
    if matches!(mode, NetworkMode::Isolated { .. }) {
        match proxy {
            ProxySelection::System => {
                return Err(EgressRouteError::PolicyBlocked(
                    "ambient system proxy is disallowed in isolated mode".into(),
                ));
            }
            ProxySelection::Pac { .. } => {
                return Err(EgressRouteError::PolicyBlocked(
                    "PAC proxy discovery is disallowed in isolated mode".into(),
                ));
            }
            ProxySelection::Direct
            | ProxySelection::ExplicitTls { .. }
            | ProxySelection::ExplicitHttpConnect { .. } => {}
        }
    }

    match proxy {
        ProxySelection::Direct | ProxySelection::System => Ok(None),
        ProxySelection::Pac { pac_url } => {
            validate_pac_url(pac_url)?;
            Ok(None)
        }
        ProxySelection::ExplicitTls {
            host,
            port,
            resolved_ips,
        }
        | ProxySelection::ExplicitHttpConnect {
            host,
            port,
            resolved_ips,
        } => {
            if *port == 0 {
                return Err(EgressRouteError::PolicyBlocked(
                    "explicit proxy TCP port must be 1..=65535".into(),
                ));
            }
            let proxy_host = normalize_host(host, "explicit proxy")?;
            let pinned = validate_pinned_ips("explicit proxy", &proxy_host, resolved_ips)?;
            if let NetworkMode::Isolated { allow_list } = mode {
                enforce_allow_list(allow_list, &proxy_host, *port, purpose, "explicit proxy")?;
            }
            Ok(Some(pinned))
        }
    }
}

fn validate_pinned_ips(
    label: &str,
    host: &NormalizedHost,
    resolved_ips: &[IpAddr],
) -> Result<IpAddr, EgressRouteError> {
    if let Some(literal_ip) = host.ip
        && is_non_public_ip(literal_ip)
    {
        return Err(EgressRouteError::PrivateAddressDenied(format!(
            "{label} IP `{literal_ip}` is non-routable/SSRF-protected"
        )));
    }
    let Some(&first_ip) = resolved_ips.first() else {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "{label} DNS resolution produced zero pinned addresses"
        )));
    };
    for &ip in resolved_ips {
        if is_non_public_ip(ip) {
            return Err(EgressRouteError::PrivateAddressDenied(format!(
                "{label} resolved address {ip} is non-routable/SSRF-protected"
            )));
        }
        if let Some(literal_ip) = host.ip
            && ip != literal_ip
        {
            return Err(EgressRouteError::PolicyBlocked(format!(
                "{label} resolved IP {ip} does not match literal IP {literal_ip}"
            )));
        }
    }
    Ok(first_ip)
}

fn enforce_allow_list(
    allow_list: &[IsolatedAllowRule],
    target: &NormalizedHost,
    port: u16,
    purpose: DialPurpose,
    label: &str,
) -> Result<(), EgressRouteError> {
    let allowed = allow_list.iter().any(|rule| {
        let Ok(rule_host) = normalize_host(&rule.host, "allow_list rule") else {
            return false;
        };
        let host_match = match (rule_host.ip, target.ip) {
            (Some(a), Some(b)) => a == b,
            (None, None) => rule_host.canonical == target.canonical,
            _ => false,
        };
        host_match
            && rule.port == port
            && (rule.purposes.is_empty() || rule.purposes.contains(&purpose))
    });
    if !allowed {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "{label} `{}:{port}` ({purpose:?}) is not in network.mode=\"isolated\" allow_list",
            target.canonical
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn public_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    #[test]
    fn dialer_validation_enforces_isolated_allowlist_tls_and_ssrf_blocks() {
        let public = public_ip();
        let metadata_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        let mode = NetworkMode::Isolated {
            allow_list: vec![IsolatedAllowRule {
                host: "fleet.example.com".into(),
                port: 443,
                purposes: vec![DialPurpose::FleetPush],
            }],
        };

        let ok_req = EgressDialRequest {
            purpose: DialPurpose::FleetPush,
            host: "fleet.example.com".into(),
            port: 443,
            tls_required: true,
            proxy: ProxySelection::Direct,
        };
        let plan =
            validate_egress_request(&mode, &ok_req, &[public]).expect("allowed isolated route");
        assert_eq!(plan.pinned_ip, public);
        assert_eq!(plan.pinned_proxy_ip, None);

        let mut wrong_purpose = ok_req.clone();
        wrong_purpose.purpose = DialPurpose::Lookup;
        assert_eq!(
            validate_egress_request(&mode, &wrong_purpose, &[public])
                .expect_err("wrong purpose rejected")
                .code(),
            CODE_WIRE_EGRESS_BLOCKED
        );

        assert_eq!(
            validate_egress_request(&mode, &ok_req, &[metadata_ip])
                .expect_err("SSRF metadata IP rejected")
                .code(),
            CODE_WIRE_EGRESS_BLOCKED
        );

        let mut no_tls = ok_req;
        no_tls.tls_required = false;
        assert_eq!(
            validate_egress_request(&NetworkMode::Standard, &no_tls, &[public])
                .expect_err("plaintext egress rejected")
                .code(),
            CODE_WIRE_EGRESS_BLOCKED
        );
    }

    #[test]
    fn dialer_rejects_proxy_bypasses_and_malformed_hosts() {
        let public = public_ip();
        let proxy_public = IpAddr::V4(Ipv4Addr::new(198, 51, 101, 20));
        let isolated = NetworkMode::Isolated {
            allow_list: vec![
                IsolatedAllowRule {
                    host: "fleet.example.com".into(),
                    port: 443,
                    purposes: vec![DialPurpose::FleetPush],
                },
                IsolatedAllowRule {
                    host: "proxy.example.com".into(),
                    port: 8443,
                    purposes: vec![DialPurpose::FleetPush],
                },
            ],
        };

        let ok_proxy_req = EgressDialRequest {
            purpose: DialPurpose::FleetPush,
            host: "fleet.example.com".into(),
            port: 443,
            tls_required: true,
            proxy: ProxySelection::ExplicitTls {
                host: "proxy.example.com".into(),
                port: 8443,
                resolved_ips: vec![proxy_public],
            },
        };
        let plan = validate_egress_request(&isolated, &ok_proxy_req, &[public])
            .expect("listed proxy with public IP accepted");
        assert_eq!(plan.pinned_proxy_ip, Some(proxy_public));

        for bad_proxy in [
            ProxySelection::System,
            ProxySelection::Pac {
                pac_url: "https://proxy.example.com/proxy.pac".into(),
            },
            ProxySelection::ExplicitTls {
                host: "unlisted-proxy.example.com".into(),
                port: 8443,
                resolved_ips: vec![proxy_public],
            },
            ProxySelection::ExplicitHttpConnect {
                host: "proxy.example.com".into(),
                port: 0,
                resolved_ips: vec![proxy_public],
            },
            ProxySelection::ExplicitTls {
                host: "proxy.example.com".into(),
                port: 8443,
                resolved_ips: vec![IpAddr::V6("::ffff:169.254.169.254".parse().unwrap())],
            },
            ProxySelection::ExplicitTls {
                host: "proxy.example.com".into(),
                port: 8443,
                resolved_ips: vec![],
            },
        ] {
            let mut req = ok_proxy_req.clone();
            req.proxy = bad_proxy;
            assert!(
                validate_egress_request(&isolated, &req, &[public]).is_err(),
                "disallowed/unsafe proxy must fail under isolated mode"
            );
        }

        for bad_pac in [
            "http://proxy.example.com/proxy.pac",
            "https://127.0.0.1/proxy.pac",
            "https://user@proxy.example.com/proxy.pac",
        ] {
            let req = EgressDialRequest {
                purpose: DialPurpose::FleetPush,
                host: "fleet.example.com".into(),
                port: 443,
                tls_required: true,
                proxy: ProxySelection::Pac {
                    pac_url: bad_pac.into(),
                },
            };
            assert!(
                validate_egress_request(&NetworkMode::Standard, &req, &[public]).is_err(),
                "bad PAC URL `{bad_pac}` must fail"
            );
        }

        for bad_host in [
            "localhost.",
            "sub.localhost",
            "127.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f.0.0.1",
            "user@fleet.example.com",
            "fleet.example.com\r\n",
            "[::ffff:127.0.0.1]",
            "[2001:4860:4860::8888]:443",
            "[127.0.0.1]",
            "fleet.example.com:443",
        ] {
            let req = EgressDialRequest {
                purpose: DialPurpose::FleetPush,
                host: bad_host.into(),
                port: 443,
                tls_required: true,
                proxy: ProxySelection::Direct,
            };
            assert!(
                validate_egress_request(&NetworkMode::Standard, &req, &[public]).is_err(),
                "host `{bad_host}` must be rejected"
            );
        }

        let zero_port = EgressDialRequest {
            purpose: DialPurpose::FleetPush,
            host: "fleet.example.com".into(),
            port: 0,
            tls_required: true,
            proxy: ProxySelection::Direct,
        };
        assert!(validate_egress_request(&NetworkMode::Standard, &zero_port, &[public]).is_err());

        for ssrf_ip in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::93.184.216.34",
            "64:ff9b::93.184.216.34",
            "64:ff9b:1::1",
            "2002:5db8:d822::1",
            "2001::1",
            "fec0::1",
            "0.1.2.3",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
        ] {
            let req = EgressDialRequest {
                purpose: DialPurpose::FleetPush,
                host: "fleet.example.com".into(),
                port: 443,
                tls_required: true,
                proxy: ProxySelection::Direct,
            };
            let parsed: IpAddr = ssrf_ip.parse().unwrap();
            assert!(
                validate_egress_request(&NetworkMode::Standard, &req, &[parsed]).is_err(),
                "special-use IP `{ssrf_ip}` must be rejected"
            );
        }
    }
}
