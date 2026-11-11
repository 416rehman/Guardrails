//! The work item as the hooks see it: `kit launch --item <n>` fetches the issue once and writes
//! `.agent/state/item-<n>.json` and the acceptance text beside it (owner instruction 5). The
//! snapshot is session state, never a work-item store.

use std::path::PathBuf;

use anyhow::{Result, bail};

use super::LaunchKit;
use crate::clock::Utc;
use crate::config::roster::Group;
use crate::config::session::{ItemSnapshot, ItemStatus, RiskTier, SNAPSHOT_SCHEMA};
use crate::orchestrate::issue::{Issue, raise};
use crate::orchestrate::records::{self, Lease};
use crate::orchestrate::tracker::Tracker;
use crate::repo::{Repo, write_if_changed};

const UNSPECIFIED_KIND: &str = "unspecified";
/// The roles that write code or documents for an item, so only its own agent may.
const WRITERS: &[Group] = &[Group::Implementer, Group::Gardener, Group::Operations];

/// Fetches the issue once and writes its snapshot and acceptance text; returns the snapshot and
/// the current lease when it names this agent.
pub(super) fn fetch_item(
    repo: &Repo,
    kit: &LaunchKit,
    tracker: &dyn Tracker,
    number: u64,
    name: &str,
) -> Result<(ItemSnapshot, Option<Lease>)> {
    let issue = tracker.issue(number)?;
    let snapshot = snapshot_of(&issue, kit, name)?;
    snapshot.save(repo)?;
    let acceptance = issue
        .work_item()
        .acceptance
        .map(|a| a.text)
        .unwrap_or_default();
    write_if_changed(
        &acceptance_path(repo, number),
        format!("{acceptance}\n").as_bytes(),
    )?;
    let found = records::records(&issue);
    let lease = records::current_lease(&found, number)
        .filter(|lease| lease.agent == name)
        .cloned();
    Ok((snapshot, lease))
}

/// `.agent/state/item-<n>.acceptance.md`: the acceptance text beside the snapshot, whose
/// format has no field for it.
pub fn acceptance_path(repo: &Repo, number: u64) -> PathBuf {
    repo.path(&format!(".agent/state/item-{number}.acceptance.md"))
}

/// The snapshot the hooks read. The tier is the higher of the issue's and the write set's. Only
/// the item's own agent may write for it; a lead, evaluator or council seat launched on the issue
/// reads it under its own role.
pub fn snapshot_of(issue: &Issue, kit: &LaunchKit, name: &str) -> Result<ItemSnapshot> {
    let item = issue.work_item();
    let writes = WRITERS.contains(&kit.agent(name)?.group);
    if let Some(agent) = &item.agent
        && agent != name
        && writes
    {
        bail!("issue #{} is for {agent}, not {name}", issue.number);
    }
    let floor = kit
        .risk
        .tier_of_write_set(&item.write_set)?
        .unwrap_or(RiskTier::Medium);
    let risk_tier = item.tier.map_or(floor, |tier| raise(tier, floor));
    let trust_core = item.trust_core || kit.risk.touches_trust_core(&item.write_set)?;
    let found = records::records(issue);
    let attempt = records::current_lease(&found, issue.number).map_or(1, |lease| lease.attempt);
    let newest_ready = records::latest_ready(&found, issue.number);
    let acceptance_sha256 = newest_ready
        .map(|(_, ready)| ready.acceptance_sha256.clone())
        .or_else(|| item.acceptance.as_ref().map(|a| a.sha256.clone()))
        .unwrap_or_default();
    if let (Some(current), Some((_, ready))) = (&item.acceptance, newest_ready)
        && current.sha256 != ready.acceptance_sha256
    {
        eprintln!(
            "kit launch: the acceptance section of #{} no longer matches its ready.v1 digest; a lead must ready it again",
            issue.number
        );
    }
    Ok(ItemSnapshot {
        schema: SNAPSHOT_SCHEMA.to_owned(),
        number: issue.number,
        title: issue.title.clone(),
        agent: item.agent.unwrap_or_else(|| name.to_owned()),
        kind: item.kind.unwrap_or_else(|| UNSPECIFIED_KIND.to_owned()),
        squad: item.squad,
        size: item.size,
        risk_tier,
        trust_core,
        write_set: item.write_set,
        status: item.status.unwrap_or(ItemStatus::Proposed),
        acceptance_sha256,
        attempt,
        fetched_at: Utc::now().iso(),
    })
}
