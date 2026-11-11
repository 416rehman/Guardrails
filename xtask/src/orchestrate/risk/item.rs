//! What an issue adds to a classification: its tier label, the lanes its `lane.v1` comments
//! raised, whether its acceptance section changed under the lease, and `--raise`, which posts a
//! `lane.v1` for it.

use anyhow::{Context, Result};

use super::Lane;
use crate::config::session::{AGENT_VARIABLE, RiskTier};
use crate::orchestrate::records::{self, LANE_SCHEMA, LaneRaise, lane_comment};
use crate::orchestrate::tracker::Tracker;

/// Who a `--raise` names when no agent session runs it.
const RAISED_BY_KIT: &str = "kit";

/// What the issue adds to a classification.
pub(super) struct ItemFacts {
    pub(super) tier: Option<RiskTier>,
    pub(super) lane: Option<Lane>,
    pub(super) acceptance_changed: bool,
}

/// The issue's tier label, its raised lane, and whether its acceptance section changed since
/// the current lease.
pub(super) fn item_facts(tracker: &dyn Tracker, number: u64) -> Result<ItemFacts> {
    let issue = tracker.issue(number)?;
    let item = issue.work_item();
    let found = records::records(&issue);
    let acceptance_changed = match (records::current_lease(&found, number), &item.acceptance) {
        (Some(lease), Some(current)) => lease.acceptance_sha256 != current.sha256,
        _ => false,
    };
    Ok(ItemFacts {
        tier: item.tier,
        lane: records::lane_floor(&found, number),
        acceptance_changed,
    })
}

/// Posts `lane.v1` raising `number` to `lane`, named for the agent session that runs it.
pub(super) fn post_raise(
    tracker: &dyn Tracker,
    number: u64,
    lane: Lane,
    reason: &str,
) -> Result<()> {
    let by = std::env::var(AGENT_VARIABLE)
        .ok()
        .filter(|agent| !agent.is_empty())
        .unwrap_or_else(|| RAISED_BY_KIT.to_owned());
    let raise = LaneRaise {
        schema: LANE_SCHEMA.to_owned(),
        item: number,
        lane,
        by,
        reason: reason.to_owned(),
    };
    tracker.comment(number, &lane_comment(&raise)?)?;
    println!("risk: #{number} raised to the {} lane", lane.name());
    Ok(())
}

pub(super) fn lane_option(value: Option<&str>, option: &str) -> Result<Option<Lane>> {
    value
        .map(|name| {
            Lane::parse(name).with_context(|| {
                format!("{option} {name}: the lanes are static, light, standard and full")
            })
        })
        .transpose()
}
