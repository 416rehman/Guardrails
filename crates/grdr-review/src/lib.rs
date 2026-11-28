// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod inert;
pub(crate) mod job_frame;
pub mod nl2cedar;
mod nl2cedar_probe;
pub mod packs;
pub mod packs_budget;
pub mod pipeline;
pub mod queue;
pub mod reducer;
pub(crate) mod span_bind;
pub mod verifier;

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
    Added {
        mode: Mode,
        locked: bool,
    },
    Removed {
        was_locked: bool,
    },
    ModeChanged {
        from: Mode,
        to: Mode,
        locked: bool,
    },
    FloorModified {
        from_locked: bool,
        to_locked: bool,
    },
    EnabledChanged {
        from: bool,
        to: bool,
        locked: bool,
    },
    GradeChanged {
        from: ApprovalGrade,
        to: ApprovalGrade,
        locked: bool,
    },
    ConditionsChanged {
        locked: bool,
    },
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

    let (overall_risk, requirement) = assess_diff_risk(&deltas, &base_map, &cand_map);

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
    base_rules: &BTreeMap<&str, &PolicyRule>,
    candidate_rules: &BTreeMap<&str, &PolicyRule>,
) -> (ChangeRisk, ReviewRequirement) {
    let mut overall = ChangeRisk::Neutral;
    let mut min_grade = ApprovalGrade::G1;

    for delta in deltas {
        if delta.risk > overall {
            overall = delta.risk;
        }
        if delta.risk == ChangeRisk::Widening {
            if let Some(base_rule) = base_rules.get(delta.rule_id.as_str())
                && base_rule.min_grade > min_grade
            {
                min_grade = base_rule.min_grade;
            }
            if let Some(cand_rule) = candidate_rules.get(delta.rule_id.as_str())
                && cand_rule.min_grade > min_grade
            {
                min_grade = cand_rule.min_grade;
            }
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

    if base.min_grade != cand.min_grade {
        let risk = if cand.min_grade < base.min_grade {
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
            kind: RuleDeltaKind::GradeChanged {
                from: base.min_grade,
                to: cand.min_grade,
                locked: base.locked,
            },
            risk,
        });
    }

    if base.matcher != cand.matcher || base.cedar != cand.cedar {
        let risk = if base.locked {
            ChangeRisk::FloorViolation
        } else {
            ChangeRisk::Widening
        };
        out.push(RuleDelta {
            rule_id: base.id.clone(),
            title: cand.title.clone(),
            kind: RuleDeltaKind::ConditionsChanged {
                locked: base.locked,
            },
            risk,
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

    #[test]
    fn negative_locked_conditions_change_g3_removal_and_grade_reduction() {
        let mut base = essentials_pack();
        if let Some(rule) = base.rules.iter_mut().find(|r| !r.locked) {
            rule.min_grade = ApprovalGrade::G3;
        }

        // Editing conditions or cedar on a locked rule must be FloorViolation (Denied).
        let mut locked_cond = base.clone();
        if let Some(rule) = locked_cond.rules.iter_mut().find(|r| r.locked) {
            rule.matcher.target_contains.clear();
        }
        let diff_cond = diff_policy_packs(&base, &locked_cond).expect("diff");
        assert_eq!(diff_cond.overall_risk, ChangeRisk::FloorViolation);
        assert_eq!(diff_cond.requirement, ReviewRequirement::Denied);

        // Removing a non-locked G3 rule must preserve base_rule.min_grade (G3).
        let mut removed_g3 = base.clone();
        removed_g3.rules.retain(|r| r.locked);
        let diff_rem = diff_policy_packs(&base, &removed_g3).expect("diff");
        assert_eq!(diff_rem.overall_risk, ChangeRisk::Widening);
        assert_eq!(
            diff_rem.requirement,
            ReviewRequirement::StepUpApproval {
                min_grade: ApprovalGrade::G3
            }
        );

        // Lowering min_grade on non-locked rule from G3 to G1 is Widening requiring G3.
        let mut lowered_grade = base.clone();
        if let Some(rule) = lowered_grade.rules.iter_mut().find(|r| !r.locked) {
            rule.min_grade = ApprovalGrade::G1;
        }
        let diff_grade = diff_policy_packs(&base, &lowered_grade).expect("diff");
        assert_eq!(diff_grade.overall_risk, ChangeRisk::Widening);
        assert_eq!(
            diff_grade.requirement,
            ReviewRequirement::StepUpApproval {
                min_grade: ApprovalGrade::G3
            }
        );
    }
}
