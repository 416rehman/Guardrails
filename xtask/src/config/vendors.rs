//! `.agents/kit/vendors.toml` (owner instruction 14): the reference vendors and the source classes
//! of the horizon sweep, each with the domains the research skill may read. `kit render` turns the
//! domains into fetch rules and egress hosts for the roles that load that skill.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::repo::Repo;

pub const VENDORS_FILE: &str = "kit/vendors.toml";
pub const BRIEFS_DIR: &str = "docs/references/research/";
const URL_SCHEME: &str = "https://";
const WILDCARD_PREFIX: &str = "*.";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vendors {
    pub research: Research,
    #[serde(default)]
    pub vendor: BTreeMap<String, Vendor>,
    #[serde(default)]
    pub sources: BTreeMap<String, Source>,
}

/// Who the domains are for and which egress lists carry them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Research {
    /// A roster role whose `skills` include this one gets the fetch and search grant.
    pub skill: String,
    pub egress_lists: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vendor {
    pub name: String,
    /// The short forms code would write, which check S7 also looks for.
    #[serde(default)]
    pub aliases: Vec<String>,
    pub domains: Vec<String>,
    /// Root-relative path of the brief under `docs/references/research/`.
    pub brief: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub domains: Vec<String>,
    /// Where a sweep of this class starts; each host is one of `domains`.
    pub urls: Vec<String>,
}

impl Vendors {
    pub fn load(repo: &Repo) -> Result<Option<Vendors>> {
        let (label, path) = super::agents_file(repo, VENDORS_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        let vendors: Vendors = super::read_toml(&path, &label)?;
        vendors.validate(&label)?;
        Ok(Some(vendors))
    }

    /// Every domain once: the vendor tables, then the source tables, each in id order.
    pub fn domains(&self) -> Vec<&str> {
        let mut seen = Vec::new();
        let all = self
            .vendor
            .values()
            .flat_map(|vendor| &vendor.domains)
            .chain(self.sources.values().flat_map(|source| &source.domains));
        for domain in all {
            if !seen.contains(&domain.as_str()) {
                seen.push(domain.as_str());
            }
        }
        seen
    }

    fn validate(&self, label: &str) -> Result<()> {
        if self.research.skill.trim().is_empty() {
            bail!("{label}: [research] skill is empty");
        }
        let entries = self
            .vendor
            .iter()
            .map(|(id, vendor)| (format!("vendor.{id}"), &vendor.domains))
            .chain(
                self.sources
                    .iter()
                    .map(|(class, source)| (format!("sources.{class}"), &source.domains)),
            );
        for (table, domains) in entries {
            if domains.is_empty() {
                bail!("{label}: [{table}] lists no domains");
            }
            for (index, domain) in domains.iter().enumerate() {
                if !is_domain(domain) {
                    bail!(
                        "{label}: [{table}] domain `{domain}` must be a lower-case host name, optionally `*.` and a host, with no scheme, port or path"
                    );
                }
                if domains.iter().take(index).any(|earlier| earlier == domain) {
                    bail!("{label}: [{table}] lists `{domain}` twice");
                }
            }
        }
        for (id, vendor) in &self.vendor {
            if vendor.name.trim().is_empty() {
                bail!("{label}: [vendor.{id}] name is empty");
            }
            if !vendor.brief.starts_with(BRIEFS_DIR) || !vendor.brief.ends_with(".md") {
                bail!(
                    "{label}: [vendor.{id}] brief `{}` must be a Markdown file under {BRIEFS_DIR}",
                    vendor.brief
                );
            }
        }
        for (class, source) in &self.sources {
            if source.urls.is_empty() {
                bail!("{label}: [sources.{class}] lists no urls");
            }
            for url in &source.urls {
                let Some(host) = url_host(url) else {
                    bail!("{label}: [sources.{class}] url `{url}` must start with {URL_SCHEME}");
                };
                if !source.domains.iter().any(|domain| covers(domain, host)) {
                    bail!(
                        "{label}: [sources.{class}] url `{url}` is on `{host}`, which its domains do not list"
                    );
                }
            }
        }
        Ok(())
    }
}

/// A host name of lower-case labels, or `*.` before one, as WebFetch domain rules accept them.
fn is_domain(domain: &str) -> bool {
    let host = domain.strip_prefix(WILDCARD_PREFIX).unwrap_or(domain);
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() > 1
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// Whether a domain entry covers a host: equal, or a strict subdomain of a `*.` entry.
fn covers(domain: &str, host: &str) -> bool {
    match domain.strip_prefix(WILDCARD_PREFIX) {
        Some(parent) => host
            .strip_suffix(parent)
            .is_some_and(|label| label.len() > 1 && label.ends_with('.')),
        None => domain == host,
    }
}

fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix(URL_SCHEME)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest.get(..end).filter(|host| !host.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[research]
skill = "grdr-vendor-research"
egress_lists = ["intel"]

[vendor.origin]
name = "Origin"
domains = ["docs.originhq.com", "www.originhq.com"]
brief = "docs/references/research/01-origin.md"

[sources.ietf]
domains = ["datatracker.ietf.org", "*.ieee-security.org", "www.originhq.com"]
urls = ["https://datatracker.ietf.org/wg/oauth/documents/", "https://sp2026.ieee-security.org/"]
"#;

    fn parse(text: &str) -> Result<Vendors> {
        let vendors: Vendors = crate::config::parse_toml(text, "vendors.toml")?;
        vendors.validate("vendors.toml")?;
        Ok(vendors)
    }

    #[test]
    fn domains_are_listed_once_vendors_first() {
        let vendors = parse(FILE).unwrap();
        assert_eq!(
            vendors.domains(),
            vec![
                "docs.originhq.com",
                "www.originhq.com",
                "datatracker.ietf.org",
                "*.ieee-security.org"
            ]
        );
    }

    #[test]
    fn hosts_urls_and_briefs_are_validated() {
        for (from, to) in [
            ("\"docs.originhq.com\"", "\"https://docs.originhq.com\""),
            ("\"docs.originhq.com\"", "\"Docs.originhq.com\""),
            ("\"docs.originhq.com\"", "\"localhost\""),
            ("https://datatracker", "http://datatracker"),
            ("https://sp2026.ieee", "https://ieee"),
            ("research/01-origin.md", "research/01-origin.txt"),
            ("brief = \"docs/references", "brief = \"elsewhere"),
            (
                "\"www.originhq.com\"]\nbrief",
                "\"www.originhq.com\", \"www.originhq.com\"]\nbrief",
            ),
        ] {
            assert!(FILE.contains(from), "{from}");
            assert!(parse(&FILE.replacen(from, to, 1)).is_err(), "{to}");
        }
        assert!(parse(&format!("{FILE}\n[vendor.x]\nname = \"X\"\n")).is_err());
    }

    #[test]
    fn wildcards_cover_subdomains_only() {
        assert!(covers("*.example.org", "a.example.org"));
        assert!(covers("*.example.org", "a.b.example.org"));
        assert!(!covers("*.example.org", "example.org"));
        assert!(!covers("*.example.org", "badexample.org"));
        assert!(covers("example.org", "example.org"));
        assert!(!covers("example.org", "a.example.org"));
    }
}
