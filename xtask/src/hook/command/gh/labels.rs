//! Every label a `gh` call adds or removes, judged against `.github/labels.toml`: the group's
//! `set_by` (the filer at creation), `raise_only`, and for the status group a transition whose
//! `by` names the agent (owner instruction 5). Label names and prefixes come from that file.

use super::super::Rules;
use super::Call;
use crate::orchestrate::issue::{parse_tier, tier_rank};
use crate::orchestrate::labels::{LabelGroup, LabelsFile};

const ADDED_LABEL_FLAGS: &[&str] = &["-l", "--label", "--add-label"];

const REMOVED_LABEL_FLAGS: &[&str] = &["--remove-label"];

/// The status group of `.github/labels.toml`: its prefix and the status issues are filed with.
pub(super) struct Statuses {
    prefix: String,
    filed_as: String,
}

impl Statuses {
    pub(super) fn of(file: &LabelsFile) -> Result<Statuses, String> {
        let group = file
            .group
            .iter()
            .find(|group| group.is_status())
            .ok_or(".github/labels.toml has no status group")?;
        match (&group.prefix, &group.filed_as) {
            (Some(prefix), Some(filed_as)) => Ok(Statuses {
                prefix: prefix.clone(),
                filed_as: filed_as.clone(),
            }),
            _ => Err(".github/labels.toml's status group needs `prefix` and `filed_as`".to_owned()),
        }
    }

    pub(super) fn filed_as(&self) -> &str {
        &self.filed_as
    }

    fn of_labels(&self, labels: &[String]) -> Vec<String> {
        labels
            .iter()
            .filter(|label| label.starts_with(&self.prefix))
            .cloned()
            .collect()
    }
}

pub(super) fn label_rules(
    rules: &Rules,
    call: &Call,
    file: &LabelsFile,
    statuses: &Statuses,
) -> Result<(), String> {
    let added = call.values(ADDED_LABEL_FLAGS)?;
    let removed = call.values(REMOVED_LABEL_FLAGS)?;
    if added.is_empty() && removed.is_empty() {
        return Ok(());
    }
    let agent = rules.agent_name();
    let creating = call.sub == "create";
    let filed_as = statuses.filed_as();
    match (
        statuses.of_labels(&removed).as_slice(),
        statuses.of_labels(&added).as_slice(),
    ) {
        ([], []) => {}
        ([], [to]) if creating => {
            if to != filed_as {
                return Err(format!(
                    "a new issue is filed with `{filed_as}`, not `{to}`; a lead readies it"
                ));
            }
        }
        ([from], [to]) if !creating => {
            let allowed = file
                .may_move(from, to, agent)
                .map_err(|error| format!("{error:#}"))?;
            if !allowed {
                return Err(format!(
                    "{agent} may not move an issue from `{from}` to `{to}`; .github/labels.toml names who may (readying is `cargo xtask kit ready`)"
                ));
            }
        }
        _ => {
            return Err("an issue carries exactly one status label; swap it in one call with --remove-label <old> --add-label <new>".to_owned());
        }
    }
    for label in removed
        .iter()
        .chain(added.iter())
        .filter(|label| !label.starts_with(&statuses.prefix))
    {
        let group = file
            .group_of(label)
            .filter(|_| file.knows(label))
            .ok_or_else(|| format!("`{label}` is not a label in .github/labels.toml"))?;
        let allowed = group
            .may_set(agent, creating)
            .map_err(|error| format!("{error:#}"))?;
        if !allowed {
            return Err(format!(
                "{agent} may not set or remove `{label}`; .github/labels.toml names who may"
            ));
        }
        let lowered = group.raise_only
            && removed.contains(label)
            && !added.iter().any(|new| raises(group, label, new));
        if lowered {
            return Err(format!("`{label}` may be raised, never removed or lowered"));
        }
        let unswapped = group.raise_only
            && group.prefix.is_some()
            && !creating
            && added.contains(label)
            && !removed.iter().any(|old| raises(group, old, label));
        if unswapped {
            return Err(format!(
                "`{label}` is added only in a swap that removes a lower label of its group in the same call (--remove-label <old> --add-label {label}), so an issue holds one; kit ready sets the first"
            ));
        }
    }
    Ok(())
}

/// Within a ranked group such as `tier:`, `tier:high` raises `tier:low`; nothing raises a flag
/// such as `trust-core`.
fn raises(group: &LabelGroup, old: &str, new: &str) -> bool {
    let Some(prefix) = group.prefix.as_deref() else {
        return false;
    };
    let rank = |label: &str| {
        label
            .strip_prefix(prefix)
            .and_then(parse_tier)
            .map(tier_rank)
    };
    matches!((rank(old), rank(new)), (Some(old), Some(new)) if new > old)
}
