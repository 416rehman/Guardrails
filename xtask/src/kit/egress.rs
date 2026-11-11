//! `deploy/fleet/egress.json` from `.agents/kit/egress.toml`, the roster and `vendors.toml`: every
//! list with its inherited hosts resolved, the research domains added to the lists `vendors.toml`
//! names, and each role's list, group and research grant, so the egress proxy (WI-0006) needs no
//! other file.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

use super::research::Grant;
use crate::config::Kit;

pub const EGRESS_OUTPUT: &str = "deploy/fleet/egress.json";

/// The resolved document, or `None` when the kit has no egress.toml.
pub fn render(kit: &Kit) -> Result<Option<Value>> {
    let Some(egress) = &kit.egress else {
        return Ok(None);
    };
    let grant = Grant::of(kit);
    let research: Vec<&str> = grant.map(|grant| grant.domains()).unwrap_or_default();
    let research_lists = grant.map(|grant| grant.egress_lists()).unwrap_or_default();
    if let Some(missing) = research_lists
        .iter()
        .find(|list| !egress.list.contains_key(*list))
    {
        bail!(
            ".agents/kit/vendors.toml [research] egress_lists names `{missing}`, which egress.toml does not define"
        );
    }
    let mut lists = Map::new();
    for (name, list) in &egress.list {
        let mut hosts = egress.hosts(name)?;
        if research_lists.contains(name) {
            for domain in &research {
                if !hosts.contains(domain) {
                    hosts.push(*domain);
                }
            }
        }
        let mut entry = Map::new();
        entry.insert("hosts".into(), json!(hosts));
        if list.hosts_from_request {
            entry.insert("hosts_from_request".into(), json!(true));
        }
        if !list.methods.is_empty() {
            entry.insert("methods".into(), json!(list.methods));
        }
        if !list.sources.is_empty() {
            entry.insert("sources".into(), json!(list.sources));
        }
        if !list.group.is_empty() {
            let groups: Map<String, Value> = list
                .group
                .iter()
                .map(|(group, extra)| (group.as_str().to_owned(), json!(extra.hosts)))
                .collect();
            entry.insert("groups".into(), Value::Object(groups));
        }
        lists.insert(name.clone(), Value::Object(entry));
    }
    let mut roles = Map::new();
    for (name, agent) in &kit.roster.agents {
        let list = agent.net.list_name();
        if !egress.list.contains_key(list) {
            bail!("agent `{name}`: net `{list}` is not a list in .agents/kit/egress.toml");
        }
        let researches = grant.is_some_and(|grant| grant.covers(agent));
        roles.insert(
            name.clone(),
            json!({ "list": list, "group": agent.group.as_str(), "research": researches }),
        );
    }
    let mut root = Map::new();
    root.insert("lists".into(), Value::Object(lists));
    if let Some(grant) = grant {
        root.insert(
            "research".into(),
            json!({ "skill": grant.skill(), "hosts": research }),
        );
    }
    root.insert("roles".into(), Value::Object(roles));
    Ok(Some(Value::Object(root)))
}
