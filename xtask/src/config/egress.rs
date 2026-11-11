//! `.agents/kit/egress.toml`: the network allow-lists of team/01 section 10, one per roster `net`
//! value. The egress proxy outside each fleet VM (WI-0006) enforces them; `kit render` resolves
//! them into `deploy/fleet/egress.json` for it.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::roster::Group;
use crate::repo::Repo;

pub const EGRESS_FILE: &str = "kit/egress.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub list: BTreeMap<String, EgressList>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressList {
    /// A list whose hosts this one starts from.
    pub extends: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// The project's own mirrors, added as each one exists.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Fetch access to the documentation domains a research request names.
    #[serde(default)]
    pub hosts_from_request: bool,
    /// HTTP methods, when the list allows only some.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Upstream feeds read through the list's hosts.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Hosts one roster group gets on top of the list.
    #[serde(default)]
    pub group: BTreeMap<Group, GroupHosts>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupHosts {
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Egress {
    pub fn load(repo: &Repo) -> Result<Option<Egress>> {
        let (label, path) = super::agents_file(repo, EGRESS_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        let egress: Egress = super::read_toml(&path, &label)?;
        for name in egress.list.keys() {
            egress
                .chain(name)
                .map_err(|error| error.context(label.clone()))?;
        }
        Ok(Some(egress))
    }

    /// The hosts and mirrors of `name` with those of every list it extends, the furthest
    /// ancestor first, each once.
    pub fn hosts(&self, name: &str) -> Result<Vec<&str>> {
        let mut hosts = Vec::new();
        for list in self.chain(name)?.into_iter().rev() {
            for host in list.hosts.iter().chain(&list.mirrors) {
                if !hosts.contains(&host.as_str()) {
                    hosts.push(host.as_str());
                }
            }
        }
        Ok(hosts)
    }

    /// `name` and the lists it extends, nearest first; a missing list or a cycle is an error.
    fn chain(&self, name: &str) -> Result<Vec<&EgressList>> {
        let mut chain = Vec::new();
        let mut visited: Vec<&str> = Vec::new();
        let mut next = Some(name);
        while let Some(current) = next {
            if visited.contains(&current) {
                bail!("egress list `{name}` extends itself through `{current}`");
            }
            let Some(list) = self.list.get(current) else {
                bail!("egress list `{current}` does not exist");
            };
            visited.push(current);
            chain.push(list);
            next = list.extends.as_deref();
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[list.A]
hosts = ["api.anthropic.com", "github.com"]
mirrors = ["mirror.example.org"]

[list.A.group.evaluator]
hosts = ["replay.example.org"]

[list.B]
extends = "A"
hosts = ["github.com", "docs.rs"]
hosts_from_request = true
"#;

    fn parse(text: &str) -> Egress {
        crate::config::parse_toml(text, "egress.toml").unwrap()
    }

    #[test]
    fn extends_resolves_ancestors_first() {
        let egress = parse(FILE);
        assert_eq!(
            egress.hosts("B").unwrap(),
            vec![
                "api.anthropic.com",
                "github.com",
                "mirror.example.org",
                "docs.rs"
            ]
        );
        assert_eq!(
            egress.list["A"].group[&Group::Evaluator].hosts,
            vec!["replay.example.org"]
        );
    }

    #[test]
    fn missing_lists_cycles_and_unknown_groups_are_errors() {
        let egress = parse(&FILE.replace("extends = \"A\"", "extends = \"C\""));
        assert!(egress.hosts("B").is_err());
        let empty_group = parse(&format!("{FILE}\n[list.A.group.lead]\n"));
        assert!(empty_group.list["A"].group[&Group::Lead].hosts.is_empty());
        let looped = parse(&FILE.replace("[list.A]\n", "[list.A]\nextends = \"B\"\n"));
        assert!(looped.hosts("B").is_err());
        let unknown = FILE.replace("group.evaluator", "group.reviewer");
        assert!(crate::config::parse_toml::<Egress>(&unknown, "egress.toml").is_err());
    }
}
