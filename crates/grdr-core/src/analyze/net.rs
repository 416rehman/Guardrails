// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! WHATWG URL parsing, UTS-46 IDNA normalization, IP literal decoding, and host classification (`D-10`).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use grdr_model::DataClass;
use idna::domain_to_ascii;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::analyze::decode::{decode_url_percent_once, decode_url_percent_once_bytes};
use crate::analyze::net_ip::{
    classify_ip_exposure, classify_v6_effective_exposure, extract_embedded_ipv4,
    parse_non_canonical_ipv4,
};
use crate::analyze::net_psl::extract_registrable_domain;
use crate::analyze::types::{
    AnalyzeFact, AnalyzeLimits, FactOriginTag, MalformedKind, MalformedReason, Resolution, Span,
};

pub use crate::analyze::net_ip::IpExposureClass;

use crate::analyze::pack_lists::{NetEndpointCatalog, default_net_endpoint_catalog};

pub const DEFAULT_LONG_QUERY_CHARS: usize = 512;
pub const DEFAULT_HIGH_ENTROPY_MILLI_BITS: u32 = 3_900;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostClass {
    PasteCapture,
    TunnelService,
    CloudMetadata,
    ModelProvider,
    MultiTenantApi,
    PackageRegistry,
    Signup,
    OrgInternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSyntax {
    DomainName,
    RawIpLiteral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserinfoPresence {
    Absent,
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryLengthClass {
    Normal,
    Long,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostClassifierConfig {
    pub org_internal_suffixes: Vec<String>,
    pub org_model_endpoints: Vec<String>,
    pub org_package_mirrors: Vec<String>,
    pub long_query_threshold: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedHostUrl {
    pub scheme: String,
    pub canonical_host: String,
    pub registrable_domain: String,
    pub port: Option<u16>,
    pub resolved_ip: Option<IpAddr>,
    pub ip_exposure: Option<IpExposureClass>,
    pub host_syntax: HostSyntax,
    pub userinfo: UserinfoPresence,
    pub query_length: QueryLengthClass,
    pub label_entropy_milli_bits: u32,
    pub classes: Vec<HostClass>,
    pub facts: Vec<AnalyzeFact>,
}

impl fmt::Debug for NormalizedHostUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NormalizedHostUrl")
            .field("scheme", &self.scheme)
            .field("host_len", &self.canonical_host.len())
            .field("host_syntax", &self.host_syntax)
            .field("ip_exposure", &self.ip_exposure)
            .field("userinfo", &self.userinfo)
            .field("query_length", &self.query_length)
            .field("classes", &self.classes)
            .finish()
    }
}

impl NormalizedHostUrl {
    #[must_use]
    pub const fn data_class() -> DataClass {
        DataClass::Content
    }
}

pub(crate) fn build_net_parse_input(trimmed: &str) -> (String, bool) {
    if trimmed.contains("://") {
        (trimmed.to_owned(), true)
    } else if trimmed.parse::<Ipv6Addr>().is_ok() {
        (format!("https://[{trimmed}]"), false)
    } else {
        (format!("https://{trimmed}"), false)
    }
}

/// Parses and normalizes a URL or bare host using WHATWG rules, IDNA A-labels,
/// non-canonical IPv4, and IPv4-embedded IPv6 decoding.
#[must_use]
pub fn classify_url_or_host(
    raw: &str,
    cfg: &HostClassifierConfig,
) -> Resolution<NormalizedHostUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::InvalidUrl,
            Span::from_usize(0, raw.len()),
            "empty or control-character host/URL",
        ));
    }

    let (parse_input, _) = build_net_parse_input(trimmed);
    let Ok(parsed) = Url::parse(&parse_input) else {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::InvalidUrl,
            Span::from_usize(0, raw.len()),
            "failed WHATWG URL parsing",
        ));
    };

    let Some(host_str) = parsed.host_str() else {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::InvalidUrl,
            Span::from_usize(0, raw.len()),
            "URL contains no host",
        ));
    };

    let raw_host_clean = host_str
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']');
    let (canonical_host, resolved_ip, host_syntax, mut ip_exposure) =
        match canonicalize_host(&parsed, raw_host_clean, raw.len()) {
            Ok(v) => v,
            Err(reason) => return Resolution::Malformed(reason),
        };

    let limits = AnalyzeLimits::from_schema();
    let mut facts = Vec::new();
    let userinfo = if !parsed.username().is_empty() || parsed.password().is_some() {
        facts.push(AnalyzeFact {
            key: "url.userinfo".into(),
            value: "true".into(),
            origin: FactOriginTag::Deterministic,
            span: None,
        });
        UserinfoPresence::Present
    } else {
        UserinfoPresence::Absent
    };

    let query_limit = cfg
        .long_query_threshold
        .unwrap_or(limits.net_long_query_chars);
    let query_length = if parsed.query().is_some_and(|q| q.len() > query_limit) {
        facts.push(AnalyzeFact {
            key: "url.long-query".into(),
            value: parsed.query().map_or(0, str::len).to_string(),
            origin: FactOriginTag::Deterministic,
            span: None,
        });
        QueryLengthClass::Long
    } else {
        QueryLengthClass::Normal
    };

    if ip_exposure.is_none() {
        ip_exposure = resolved_ip.map(classify_ip_exposure);
    }
    if ip_exposure.is_none()
        && (canonical_host == "localhost" || canonical_host.ends_with(".localhost"))
    {
        ip_exposure = Some(IpExposureClass::Loopback);
    }

    if host_syntax == HostSyntax::RawIpLiteral {
        facts.push(AnalyzeFact {
            key: "host.raw-ip".into(),
            value: resolved_ip.map_or_else(|| canonical_host.clone(), |ip| ip.to_string()),
            origin: FactOriginTag::Deterministic,
            span: None,
        });
    }

    let registrable_domain =
        extract_registrable_domain(&canonical_host, &cfg.org_internal_suffixes);
    let label_entropy_milli_bits = max_subdomain_entropy_milli_bits(&canonical_host);
    if label_entropy_milli_bits >= limits.net_high_entropy_milli_bits
        && host_syntax == HostSyntax::DomainName
    {
        facts.push(AnalyzeFact {
            key: "dns.label-entropy".into(),
            value: format!("{label_entropy_milli_bits}"),
            origin: FactOriginTag::Heuristic,
            span: None,
        });
    }

    let decoded_path = decode_url_percent_once(parsed.path());
    let Ok(endpoints) = default_net_endpoint_catalog() else {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::InvalidUrl,
            Span::from_usize(0, raw.len()),
            "network endpoint catalog unavailable",
        ));
    };
    let classes = classify_host_classes_with_catalog(
        &canonical_host,
        &registrable_domain,
        &decoded_path,
        ip_exposure,
        cfg,
        endpoints,
    );

    Resolution::Resolved(NormalizedHostUrl {
        scheme: parsed.scheme().to_ascii_lowercase(),
        canonical_host,
        registrable_domain,
        port: parsed.port_or_known_default(),
        resolved_ip,
        ip_exposure,
        host_syntax,
        userinfo,
        query_length,
        label_entropy_milli_bits,
        classes,
        facts,
    })
}

fn canonicalize_host(
    parsed: &Url,
    raw_clean: &str,
    raw_len: usize,
) -> Result<(String, Option<IpAddr>, HostSyntax, Option<IpExposureClass>), MalformedReason> {
    let invalid = |msg: &str| {
        MalformedReason::new(MalformedKind::InvalidUrl, Span::from_usize(0, raw_len), msg)
    };
    match parsed.host() {
        Some(Host::Ipv4(v4)) => Ok((
            v4.to_string(),
            Some(IpAddr::V4(v4)),
            HostSyntax::RawIpLiteral,
            Some(classify_ip_exposure(IpAddr::V4(v4))),
        )),
        Some(Host::Ipv6(v6)) => Ok(normalize_ipv6_host(v6)),
        Some(Host::Domain(dom)) => {
            let special = is_special_scheme(parsed.scheme());
            let unescaped = if special {
                dom.to_owned()
            } else {
                let bytes = decode_url_percent_once_bytes(dom.as_bytes());
                String::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 percent host"))?
            };
            let trimmed = unescaped.trim_end_matches('.');
            if trimmed.chars().any(|c| {
                c.is_control()
                    || c.is_whitespace()
                    || matches!(c, '/' | '@' | '?' | '#' | '\\' | '%')
            }) {
                return Err(invalid("empty or malformed host characters"));
            }
            let is_bracketed = trimmed.starts_with('[') && trimmed.ends_with(']');
            let unbracketed = if is_bracketed {
                trimmed
                    .get(1..trimmed.len().saturating_sub(1))
                    .unwrap_or("")
            } else {
                trimmed
            };
            if unbracketed.is_empty() {
                return Err(invalid("empty or malformed host characters"));
            }
            if let Ok(v6) = unbracketed.parse::<Ipv6Addr>() {
                return Ok(normalize_ipv6_host(v6));
            }
            if is_bracketed
                || unbracketed.contains('[')
                || unbracketed.contains(']')
                || unbracketed.contains(':')
            {
                return Err(invalid("invalid IPv6 or bracketed host"));
            }
            if !special
                && unbracketed
                    .chars()
                    .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric() && !matches!(c, '-' | '.'))
            {
                return Err(invalid("non-LDH character in non-special scheme host"));
            }
            if let Some(v4) = parse_non_canonical_ipv4(unbracketed) {
                return Ok((
                    v4.to_string(),
                    Some(IpAddr::V4(v4)),
                    HostSyntax::RawIpLiteral,
                    Some(classify_ip_exposure(IpAddr::V4(v4))),
                ));
            }
            let ascii = domain_to_ascii(unbracketed)
                .map_err(|_| invalid("invalid IDNA domain label"))?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if ascii.is_empty() {
                return Err(invalid("domain normalized to empty host"));
            }
            Ok((ascii, None, HostSyntax::DomainName, None))
        }
        None => {
            let _ = raw_clean;
            Err(invalid("missing URL host"))
        }
    }
}

fn normalize_ipv6_host(
    v6: Ipv6Addr,
) -> (String, Option<IpAddr>, HostSyntax, Option<IpExposureClass>) {
    let exposure = Some(classify_v6_effective_exposure(v6));
    if let Some(mapped) = extract_embedded_ipv4(v6) {
        (
            mapped.to_string(),
            Some(IpAddr::V4(mapped)),
            HostSyntax::RawIpLiteral,
            exposure,
        )
    } else {
        (
            v6.to_string(),
            Some(IpAddr::V6(v6)),
            HostSyntax::RawIpLiteral,
            exposure,
        )
    }
}

fn is_special_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp" | "file")
}

fn classify_host_classes_with_catalog(
    host: &str,
    registrable: &str,
    path: &str,
    ip_exposure: Option<IpExposureClass>,
    cfg: &HostClassifierConfig,
    endpoints: &NetEndpointCatalog,
) -> Vec<HostClass> {
    let mut classes = Vec::new();
    if matches!(ip_exposure, Some(IpExposureClass::CloudMetadataLinkLocal))
        || matches_host_or_reg(host, registrable, &endpoints.cloud_metadata_hosts)
    {
        classes.push(HostClass::CloudMetadata);
    }
    if matches_host_or_reg(host, registrable, &endpoints.paste_capture_hosts) {
        classes.push(HostClass::PasteCapture);
    }
    if matches_host_or_reg(host, registrable, &endpoints.tunnel_service_hosts) {
        classes.push(HostClass::TunnelService);
    }
    if matches_host_or_reg(host, registrable, &endpoints.model_provider_hosts)
        || matches_custom_list(host, &cfg.org_model_endpoints)
    {
        classes.push(HostClass::ModelProvider);
    }
    if matches_host_or_reg(host, registrable, &endpoints.multi_tenant_api_hosts) {
        classes.push(HostClass::MultiTenantApi);
    }
    if matches_host_or_reg(host, registrable, &endpoints.package_registry_hosts)
        || matches_custom_list(host, &cfg.org_package_mirrors)
    {
        classes.push(HostClass::PackageRegistry);
    }
    let path_lower = path.to_ascii_lowercase();
    if path_lower.contains("/signup") || path_lower.contains("/register") {
        classes.push(HostClass::Signup);
    }
    if matches_custom_list(host, &cfg.org_internal_suffixes) {
        classes.push(HostClass::OrgInternal);
    }
    classes
}

fn matches_host_or_reg(host: &str, registrable: &str, set: &[String]) -> bool {
    set.iter()
        .any(|entry| host == entry || registrable == entry || host.ends_with(&format!(".{entry}")))
}

fn matches_custom_list(host: &str, custom: &[String]) -> bool {
    custom.iter().any(|entry| {
        let norm = entry.trim().trim_start_matches('.').to_ascii_lowercase();
        !norm.is_empty() && (host == norm || host.ends_with(&format!(".{norm}")))
    })
}

fn max_subdomain_entropy_milli_bits(host: &str) -> u32 {
    host.split('.')
        .filter(|lbl| lbl.len() >= 12)
        .map(shannon_entropy_milli_bits)
        .max()
        .unwrap_or(0)
}

fn shannon_entropy_milli_bits(label: &str) -> u32 {
    let mut counts = [0_u32; 256];
    let total = u32::try_from(label.len()).unwrap_or(u32::MAX);
    if total == 0 {
        return 0;
    }
    for &b in label.as_bytes() {
        if let Some(slot) = counts.get_mut(usize::from(b)) {
            *slot = slot.saturating_add(1);
        }
    }
    let total_f = f64::from(total);
    let mut entropy = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / total_f;
            entropy -= p * p.log2();
        }
    }
    round_milli_bits_to_u32(entropy * 1000.0)
}

fn round_milli_bits_to_u32(val: f64) -> u32 {
    if !val.is_finite() || val <= 0.0 {
        return 0;
    }
    let mut lo = 0_u32;
    let mut hi = 8_000_u32;
    while lo < hi {
        let mid = lo.saturating_add(hi.saturating_sub(lo).div_ceil(2));
        if f64::from(mid) - 0.5 <= val {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_non_canonical_ip_variants_and_ipv6_embeddings() {
        let cfg = HostClassifierConfig::default();
        for url in [
            "http://127.1/",
            "http://127.0.1/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://0/",
            "http://[::]/",
            "http://[::127.0.0.1]/",
            "http://[64:ff9b::127.0.0.1]/",
            "http://[2002:7f00:0001::]/",
        ] {
            let res = classify_url_or_host(url, &cfg);
            let Resolution::Resolved(norm) = res else {
                panic!("expected resolved for {url}");
            };
            assert_eq!(
                norm.ip_exposure,
                Some(IpExposureClass::Loopback),
                "for {url}"
            );
        }
        assert!(matches!(
            classify_url_or_host("http://[fe80::1]/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::CloudMetadataLinkLocal)
        ));
        assert!(matches!(
            classify_url_or_host("http://100.64.0.5/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::PrivateRfc1918)
        ));
        assert!(matches!(
            classify_url_or_host("ssh://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/x", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::CloudMetadataLinkLocal)
        ));
    }

    #[test]
    fn rejects_invalid_idna_and_preserves_internal_label_and_decoded_signup() {
        let cfg = HostClassifierConfig {
            org_internal_suffixes: vec!["corp.internal".into()],
            ..HostClassifierConfig::default()
        };
        assert!(classify_url_or_host("https://xn--invalid--/", &cfg).is_malformed());

        let Resolution::Resolved(internal) =
            classify_url_or_host("https://git.corp.internal/%73ignup", &cfg)
        else {
            panic!("expected resolved internal host");
        };
        assert_eq!(internal.registrable_domain, "git.corp.internal");
        assert!(internal.classes.contains(&HostClass::OrgInternal));
        assert!(internal.classes.contains(&HostClass::Signup));

        let Resolution::Resolved(gh_pages) =
            classify_url_or_host("https://attacker.github.io/", &cfg)
        else {
            panic!("expected resolved pages");
        };
        assert_eq!(gh_pages.registrable_domain, "attacker.github.io");
    }

    #[test]
    fn round2_nat64_special_ranges_non_special_percent_smuggling_and_psl() {
        let cfg = HostClassifierConfig::default();

        assert!(matches!(
            classify_url_or_host("http://[64:ff9b:1:1::169.254.169.254]/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::CloudMetadataLinkLocal)
        ));
        assert!(matches!(
            classify_url_or_host("http://[64:ff9b:1:1:1::169.254.169.254]/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::CloudMetadataLinkLocal)
        ));
        assert!(matches!(
            classify_url_or_host("http://[64:ff9b:1:1::8.8.8.8]/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::PrivateRfc1918)
        ));
        assert!(matches!(
            classify_url_or_host("http://[64:ff9b:1:abcd::1]/", &cfg),
            Resolution::Resolved(n) if n.ip_exposure == Some(IpExposureClass::PrivateRfc1918)
        ));

        for non_pub in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "2001:db8::1",
            "3fff::1",
            "100::1",
        ] {
            let res = classify_url_or_host(non_pub, &cfg);
            assert!(
                matches!(
                    res,
                    Resolution::Resolved(ref n)
                        if n.ip_exposure == Some(IpExposureClass::PrivateRfc1918)
                            && n.host_syntax == HostSyntax::RawIpLiteral
                ),
                "expected PrivateRfc1918 RawIpLiteral for {non_pub}: {res:?}"
            );
        }

        for bad_ssh in [
            "ssh://evil%23.example.com/",
            "ssh://evil%3a80/",
            "ssh://evil%5cpath/",
            "ssh://evil%21host/",
            "ssh://[notipv6/",
        ] {
            assert!(
                classify_url_or_host(bad_ssh, &cfg).is_malformed(),
                "expected Malformed for {bad_ssh}"
            );
        }

        for (url, reg) in [
            ("https://evil.blogspot.com/", "evil.blogspot.com"),
            ("https://sub.site.co.il/", "site.co.il"),
            ("https://sub.uni.edu.cn/", "uni.edu.cn"),
            ("https://sub.site.co.id/", "site.co.id"),
            ("https://sub.site.com.ua/", "site.com.ua"),
        ] {
            let Resolution::Resolved(norm) = classify_url_or_host(url, &cfg) else {
                panic!("expected resolved {url}");
            };
            assert_eq!(norm.registrable_domain, reg);
        }
    }
}
