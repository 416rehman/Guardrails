//! The endpoint literals of S7: URLs, host names and domains, email addresses and IP addresses
//! inside one string. The names RFC 2606 and RFC 6761 reserve (`example.com`, `*.example`,
//! `*.test`, `*.invalid`) and the RFC 5737 and RFC 3849 documentation addresses are never real
//! endpoints and pass. A URL whose host is a placeholder (`https://{host}/`) or absent
//! (`starts_with("https://")`) holds no endpoint. A dotted word is a domain only when its last
//! label is a public suffix from [`SUFFIXES`], which leaves out file names such as `main.rs`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Match;

use super::super::patterns::{Compiled, compile, find_all};

/// Top-level domains that mark a dotted word as a host. Suffixes that are also common file
/// extensions (`rs`, `md`, `sh`, `py`, `pl`, `so`, `cc`, `ml`, `mk`, `in`, `zip`, `mov`) are
/// left out on purpose.
const SUFFIXES: &[&str] = &[
    "com", "org", "net", "io", "dev", "app", "ai", "cloud", "co", "info", "biz", "gov", "edu",
    "mil", "int", "xyz", "tech", "site", "online", "page", "eu", "uk", "us", "de", "fr", "nl",
    "ca", "au", "jp", "cn", "ru", "br", "ch", "se", "no", "es", "it", "be", "at", "dk", "fi", "ie",
    "nz", "kr", "sg", "hk", "tw", "il", "za", "mx", "local", "internal", "corp", "lan", "arpa",
];
const RESERVED_SUFFIXES: &[&str] = &["example", "test", "invalid"];
const EXAMPLE_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];
/// The IPv6 documentation prefix of RFC 3849; the IPv4 ranges of RFC 5737 come from `std`.
const DOCUMENTATION_V6_PREFIX: &str = "2001:db8:";
const PLACEHOLDER_STARTS: &[char] = &['{', '$', '%', '<', '['];

static URL: Compiled = LazyLock::new(|| compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s'`<>]*"));
static EMAIL: Compiled =
    LazyLock::new(|| compile(r"[A-Za-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+"));
static DOTTED: Compiled = LazyLock::new(|| compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+"));
static IPV4: Compiled = LazyLock::new(|| compile(r"[0-9]+(?:\.[0-9]+){3}"));
static IPV6: Compiled = LazyLock::new(|| compile(r"[0-9A-Fa-f:]*::[0-9A-Fa-f:]*"));
static LOCALHOST: Compiled = LazyLock::new(|| compile(r"(?i)\blocalhost\b"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Url,
    Host,
    Email,
    Ip,
    Loopback,
}

/// The spans of `text` already claimed, so a host inside a URL is not reported twice.
#[derive(Default)]
struct Claims {
    spans: Vec<(usize, usize)>,
    endpoints: Vec<(Endpoint, String)>,
}

impl Endpoint {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Endpoint::Url => "URL",
            Endpoint::Host => "host name",
            Endpoint::Email => "email address",
            Endpoint::Ip => "IP address",
            Endpoint::Loopback => "loopback address",
        }
    }
}

impl Claims {
    /// Claims the span of `found`, reporting it as `kind` unless it is `None`, when no earlier
    /// claim overlaps it.
    fn claim(&mut self, kind: Option<Endpoint>, found: &Match) {
        let (start, end) = (found.start(), found.end());
        if self.spans.iter().any(|(a, b)| start < *b && *a < end) {
            return;
        }
        self.spans.push((start, end));
        if let Some(kind) = kind {
            self.endpoints.push((kind, found.as_str().to_owned()));
        }
    }
}

/// Every endpoint in `text`, each with the literal text that names it, without overlaps.
pub(crate) fn find(text: &str) -> Vec<(Endpoint, String)> {
    let mut claims = Claims::default();
    for url in find_all(&URL, text) {
        let kind = url_host(url.as_str())
            .filter(|host| !reserved(host))
            .map(|_| Endpoint::Url);
        claims.claim(kind, &url);
    }
    for email in find_all(&EMAIL, text) {
        let domain = email.as_str().rsplit('@').next().unwrap_or_default();
        let real = has_suffix(domain, |last| last.chars().all(|c| c.is_ascii_alphabetic()))
            && !reserved(domain);
        if real {
            claims.claim(Some(Endpoint::Email), &email);
        }
    }
    for ip in find_all(&IPV4, text) {
        let address = ip.as_str().parse::<Ipv4Addr>().ok();
        if let Some(address) =
            address.filter(|a| ipv4(text, ip.start(), ip.end()) && !a.is_documentation())
        {
            claims.claim(Some(address_kind(address.is_loopback())), &ip);
        }
    }
    for ip in find_all(&IPV6, text) {
        let address = ip.as_str().parse::<Ipv6Addr>().ok();
        if let Some(address) =
            address.filter(|_| ipv6(text, ip.start(), ip.end()) && !documentation(ip.as_str()))
        {
            claims.claim(Some(address_kind(address.is_loopback())), &ip);
        }
    }
    for host in find_all(&DOTTED, text) {
        let bounded = !char_before(text, host.start())
            .is_some_and(|c| c.is_alphanumeric() || matches!(c, '.' | '@' | '_' | '-'))
            && !char_at(text, host.end()).is_some_and(|c| c.is_alphanumeric() || c == '_');
        let public = has_suffix(host.as_str(), |last| SUFFIXES.contains(&last));
        if bounded && public && !reserved(host.as_str()) {
            claims.claim(Some(Endpoint::Host), &host);
        }
    }
    for local in find_all(&LOCALHOST, text) {
        claims.claim(Some(Endpoint::Loopback), &local);
    }
    claims.endpoints
}

fn address_kind(loopback: bool) -> Endpoint {
    if loopback {
        Endpoint::Loopback
    } else {
        Endpoint::Ip
    }
}

/// The host of `url`, or `None` when it has none or only a placeholder.
fn url_host(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if host_and_port.starts_with('[') {
        host_and_port
            .split(']')
            .next()
            .unwrap_or_default()
            .trim_start_matches('[')
    } else {
        host_and_port.split(':').next().unwrap_or_default()
    };
    let placeholder = host.starts_with(PLACEHOLDER_STARTS) || host.contains('{');
    (!host.is_empty() && !placeholder).then_some(host)
}

fn reserved(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let last = host.rsplit('.').next().unwrap_or_default();
    RESERVED_SUFFIXES.contains(&last)
        || EXAMPLE_DOMAINS
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
        || documentation(&host)
}

fn documentation(address: &str) -> bool {
    let v4 = address
        .parse::<Ipv4Addr>()
        .is_ok_and(|v4| v4.is_documentation());
    v4 || address
        .to_ascii_lowercase()
        .starts_with(DOCUMENTATION_V6_PREFIX)
}

fn has_suffix(host: &str, accepts: impl Fn(&str) -> bool) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let well_formed = labels.len() > 1 && labels.iter().all(|label| !label.is_empty());
    well_formed && labels.last().is_some_and(|last| accepts(last))
}

/// A dotted quad not part of a longer dotted number such as a version.
fn ipv4(text: &str, start: usize, end: usize) -> bool {
    !char_before(text, start).is_some_and(|c| c.is_ascii_digit() || c == '.')
        && !(char_at(text, end) == Some('.')
            && char_at(text, end + 1).is_some_and(|c| c.is_ascii_digit()))
}

/// An address with `::` and at least one digit, standing alone, so `std::fs` and `::` pass.
fn ipv6(text: &str, start: usize, end: usize) -> bool {
    let candidate = text.get(start..end).unwrap_or_default();
    let digit = candidate.chars().any(|c| c.is_ascii_digit());
    let alone = !char_before(text, start).is_some_and(|c| c.is_alphanumeric() || c == '_')
        && !char_at(text, end).is_some_and(|c| c.is_alphanumeric() || c == '_');
    digit && alone && !candidate.trim_matches(':').is_empty()
}

fn char_before(text: &str, index: usize) -> Option<char> {
    text.get(..index).and_then(|head| head.chars().next_back())
}

fn char_at(text: &str, index: usize) -> Option<char> {
    text.get(index..).and_then(|tail| tail.chars().next())
}

#[cfg(test)]
mod tests {
    use super::super::super::patterns::all_compile;
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        assert!(all_compile(&[
            &URL, &EMAIL, &DOTTED, &IPV4, &IPV6, &LOCALHOST
        ]));
    }

    #[test]
    fn finds_each_kind_of_endpoint() {
        assert_eq!(
            find("see https://cli.vendor.io/docs"),
            vec![(Endpoint::Url, "https://cli.vendor.io/docs".into())]
        );
        assert_eq!(
            find("security@corp.dev"),
            vec![(Endpoint::Email, "security@corp.dev".into())]
        );
        assert_eq!(
            find("api.vendor.com"),
            vec![(Endpoint::Host, "api.vendor.com".into())]
        );
        assert_eq!(
            find("bind 0.0.0.0:443"),
            vec![(Endpoint::Ip, "0.0.0.0".into())]
        );
        assert_eq!(
            find("127.0.0.1:44444"),
            vec![(Endpoint::Loopback, "127.0.0.1".into())]
        );
        assert_eq!(find("[::1]:80"), vec![(Endpoint::Loopback, "::1".into())]);
        assert_eq!(
            find("http://localhost:8080/x"),
            vec![(Endpoint::Url, "http://localhost:8080/x".into())]
        );
        assert_eq!(
            find("ws on localhost"),
            vec![(Endpoint::Loopback, "localhost".into())]
        );
    }

    #[test]
    fn passes_examples_placeholders_files_paths_and_versions() {
        for text in [
            "https://example.com/a",
            "mail me@example.org",
            "kit@example.invalid",
            "svc.cluster.test",
            "https://{host}/v1",
            "https://",
            "Cargo.toml and main.rs and setup.sh and lib.so",
            "[system.io.file]::",
            ".com",
            "std::fs::read",
            "::",
            "1.2.3.4.5",
            "pnpm@10.4.1",
            "@grdr/kit",
            "192.0.2.10",
            "2001:db8::1",
            "v1.2.3",
            "user.email",
        ] {
            assert!(find(text).is_empty(), "{text}: {:?}", find(text));
        }
    }
}
