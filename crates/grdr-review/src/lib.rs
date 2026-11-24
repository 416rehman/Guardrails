// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use grdr_model::{ApprovalGrade, Mode, PolicyPack, PolicyRule};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewError {
    #[error("GRDR-REV-0001: candidate pack and base pack produced an invalid state")]
    InvalidPack,
    #[error("GRDR-REV-0002: duplicate rule id `{0}` in policy pack")]
    DuplicateRuleId(String),
    #[error("GRDR-REV-0003: floor weakening detected on locked rule `{0}`")]
    FloorWeakeningBlocked(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRisk {
    Neutral,
    Narrowing,
    Widening,
    FloorViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "requirement", rename_all = "snake_case")]
pub enum ReviewRequirement {
    AutoApply,
    StepUpApproval { min_grade: ApprovalGrade },
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleDeltaKind {
    Added { mode: Mode, locked: bool },
    Removed { was_locked: bool },
    ModeChanged { from: Mode, to: Mode, locked: bool },
    FloorModified { from_locked: bool, to_locked: bool },
    EnabledChanged { from: bool, to: bool, locked: bool },
    ConditionsChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDelta {
    pub rule_id: String,
    pub title: String,
    pub kind: RuleDeltaKind,
    pub risk: ChangeRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub pack_id: String,
    pub base_version: String,
    pub candidate_version: String,
    pub deltas: Vec<RuleDelta>,
    pub overall_risk: ChangeRisk,
    pub requirement: ReviewRequirement,
}

pub fn diff_policy_packs(
    base: &PolicyPack,
    candidate: &PolicyPack,
) -> Result<PolicyDiff, ReviewError> {
    let base_map = index_rules(&base.rules)?;
    let cand_map = index_rules(&candidate.rules)?;

    let mut deltas = Vec::new();

    for (id, base_rule) in &base_map {
        match cand_map.get(id) {
            None => {
                let risk = if base_rule.locked {
                    ChangeRisk::FloorViolation
                } else {
                    ChangeRisk::Widening
                };
                deltas.push(RuleDelta {
                    rule_id: (*id).to_owned(),
                    title: base_rule.title.clone(),
                    kind: RuleDeltaKind::Removed {
                        was_locked: base_rule.locked,
                    },
                    risk,
                });
            }
            Some(cand_rule) => {
                collect_rule_changes(base_rule, cand_rule, &mut deltas);
            }
        }
    }

    for (id, cand_rule) in &cand_map {
        if !base_map.contains_key(id) {
            deltas.push(RuleDelta {
                rule_id: (*id).to_owned(),
                title: cand_rule.title.clone(),
                kind: RuleDeltaKind::Added {
                    mode: cand_rule.mode,
                    locked: cand_rule.locked,
                },
                risk: if cand_rule.mode == Mode::Off {
                    ChangeRisk::Neutral
                } else {
                    ChangeRisk::Narrowing
                },
            });
        }
    }

    let (overall_risk, requirement) = assess_diff_risk(&deltas, &cand_map);

    Ok(PolicyDiff {
        pack_id: candidate.id.clone(),
        base_version: base.version.clone(),
        candidate_version: candidate.version.clone(),
        deltas,
        overall_risk,
        requirement,
    })
}

#[must_use]
pub fn assess_diff_risk(
    deltas: &[RuleDelta],
    candidate_rules: &BTreeMap<&str, &PolicyRule>,
) -> (ChangeRisk, ReviewRequirement) {
    let mut overall = ChangeRisk::Neutral;
    let mut min_grade = ApprovalGrade::G1;

    for delta in deltas {
        if delta.risk > overall {
            overall = delta.risk;
        }
        if delta.risk == ChangeRisk::Widening
            && let Some(rule) = candidate_rules.get(delta.rule_id.as_str())
            && rule.min_grade > min_grade
        {
            min_grade = rule.min_grade;
        }
    }

    let requirement = match overall {
        ChangeRisk::FloorViolation => ReviewRequirement::Denied,
        ChangeRisk::Widening => ReviewRequirement::StepUpApproval { min_grade },
        ChangeRisk::Narrowing | ChangeRisk::Neutral => ReviewRequirement::AutoApply,
    };

    (overall, requirement)
}

fn index_rules(rules: &[PolicyRule]) -> Result<BTreeMap<&str, &PolicyRule>, ReviewError> {
    let mut map = BTreeMap::new();
    for rule in rules {
        if map.insert(rule.id.as_str(), rule).is_some() {
            return Err(ReviewError::DuplicateRuleId(rule.id.clone()));
        }
    }
    Ok(map)
}

fn collect_rule_changes(base: &PolicyRule, cand: &PolicyRule, out: &mut Vec<RuleDelta>) {
    if base.locked != cand.locked {
        let risk = if base.locked && !cand.locked {
            ChangeRisk::FloorViolation
        } else {
            ChangeRisk::Narrowing
        };
        out.push(RuleDelta {
            rule_id: base.id.clone(),
            title: cand.title.clone(),
            kind: RuleDeltaKind::FloorModified {
                from_locked: base.locked,
                to_locked: cand.locked,
            },
            risk,
        });
    }

    if base.enabled != cand.enabled {
        let risk = if !cand.enabled {
            if base.locked {
                ChangeRisk::FloorViolation
            } else {
                ChangeRisk::Widening
            }
        } else {
            ChangeRisk::Narrowing
        };
        out.push(RuleDelta {
            rule_id: base.id.clone(),
            title: cand.title.clone(),
            kind: RuleDeltaKind::EnabledChanged {
                from: base.enabled,
                to: cand.enabled,
                locked: base.locked,
            },
            risk,
        });
    }

    if base.mode != cand.mode {
        let risk = if cand.mode < base.mode {
            if base.locked {
                ChangeRisk::FloorViolation
            } else {
                ChangeRisk::Widening
            }
        } else {
            ChangeRisk::Narrowing
        };
        out.push(RuleDelta {
            rule_id: base.id.clone(),
            title: cand.title.clone(),
            kind: RuleDeltaKind::ModeChanged {
                from: base.mode,
                to: cand.mode,
                locked: base.locked,
            },
            risk,
        });
    }

    if base.matcher != cand.matcher {
        out.push(RuleDelta {
            rule_id: base.id.clone(),
            title: cand.title.clone(),
            kind: RuleDeltaKind::ConditionsChanged,
            risk: ChangeRisk::Widening,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::eval::essentials_pack;

    #[test]
    fn narrowing_auto_applies_widening_requires_step_up_and_floor_weakening_is_denied() {
        let base = essentials_pack();

        let mut tighter = base.clone();
        tighter.version = "1.0.1".into();
        if let Some(rule) = tighter.rules.iter_mut().find(|r| !r.locked) {
            rule.mode = Mode::Block;
        }
        let tight_diff = diff_policy_packs(&base, &tighter).expect("diff ok");
        assert_eq!(tight_diff.overall_risk, ChangeRisk::Narrowing);
        assert_eq!(tight_diff.requirement, ReviewRequirement::AutoApply);

        let mut wider = base.clone();
        wider.version = "1.0.2".into();
        if let Some(rule) = wider
            .rules
            .iter_mut()
            .find(|r| !r.locked && r.mode > Mode::Off)
        {
            rule.mode = Mode::Off;
        }
        let wide_diff = diff_policy_packs(&base, &wider).expect("diff ok");
        assert_eq!(wide_diff.overall_risk, ChangeRisk::Widening);
        assert!(matches!(
            wide_diff.requirement,
            ReviewRequirement::StepUpApproval { .. }
        ));

        let mut weakened_floor = base.clone();
        weakened_floor.version = "1.0.3".into();
        if let Some(rule) = weakened_floor.rules.iter_mut().find(|r| r.locked) {
            rule.mode = Mode::Watch;
        }
        let floor_diff = diff_policy_packs(&base, &weakened_floor).expect("diff ok");
        assert_eq!(floor_diff.overall_risk, ChangeRisk::FloorViolation);
        assert_eq!(floor_diff.requirement, ReviewRequirement::Denied);
    }
}
