// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Normative 9-row verdict derivation and control-point degradation tables.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_model::{ApprovalGrade, Mode, Verdict};

const MAX_MODIFY_RETRIES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputValidity {
    Valid,
    Malformed,
    EvalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDisposition {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldCapability {
    NoHold,
    CanHold { deadline_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedVerb {
    Allow,
    Deny,
    DenyWithRetryToken,
    Hold,
    Modify,
    ObserveOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDiscriminant {
    Allow,
    Modify,
    StepUp,
    Defer,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMutability {
    Liftable,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemedyCapability {
    Plain,
    ModifyTransform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossBehaviour {
    AllowOnLoss,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockAllowance {
    Unavailable,
    DisclosedTimeLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryObserver {
    None,
    ScopedBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationSupport {
    Unsupported,
    Supported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPointCaps {
    pub verbs: BTreeSet<VerdictDiscriminant>,
    pub hold: HoldCapability,
    pub failure_mode: FailureDisposition,
    pub snapshot: ObligationSupport,
    pub modify: ObligationSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminingForbid {
    pub rule_id: String,
    pub mode: Mode,
    pub min_grade: ApprovalGrade,
    pub mutability: RuleMutability,
    pub remedy: RemedyCapability,
    pub on_loss: LossBehaviour,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRuleRef {
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotEvaluableRuleRef {
    pub rule_id: String,
    pub on_loss: LossBehaviour,
    pub grant_lifted: ObligationSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveInput {
    pub validity: InputValidity,
    pub modify_attempts: u8,
    pub device_max_grade: ApprovalGrade,
    pub timelock: TimelockAllowance,
    pub base_permit: ObligationSupport,
    pub observer: BoundaryObserver,
    pub snapshot_required: ObligationSupport,
    pub control_snapshot: ObligationSupport,
    pub control_modify: ObligationSupport,
    pub determining_forbids: Vec<DeterminingForbid>,
    pub pending_rules: Vec<PendingRuleRef>,
    pub not_evaluable_rules: Vec<NotEvaluableRuleRef>,
}

pub fn derive_verdict(input: &DeriveInput) -> Verdict {
    if input.validity != InputValidity::Valid {
        return Verdict::Deny;
    }

    if !input.determining_forbids.is_empty() {
        let all_modify = input
            .determining_forbids
            .iter()
            .all(|f| f.remedy == RemedyCapability::ModifyTransform);
        if all_modify
            && input.control_modify == ObligationSupport::Supported
            && input.modify_attempts < MAX_MODIFY_RETRIES
        {
            return Verdict::Modify;
        }

        let any_block_or_unliftable = input.determining_forbids.iter().any(|f| {
            f.mode == Mode::Block
                || !grade_satisfiable(f.min_grade, input.device_max_grade, input.timelock)
        });
        if any_block_or_unliftable {
            return Verdict::Deny;
        }
        return Verdict::StepUp;
    }

    if !input.pending_rules.is_empty() {
        return Verdict::Defer;
    }

    let unlifted_ne: Vec<&NotEvaluableRuleRef> = input
        .not_evaluable_rules
        .iter()
        .filter(|r| r.grant_lifted == ObligationSupport::Unsupported)
        .collect();
    if !unlifted_ne.is_empty() {
        if input.observer == BoundaryObserver::ScopedBoundary {
            return Verdict::Allow;
        }
        if unlifted_ne
            .iter()
            .any(|r| r.on_loss == LossBehaviour::FailClosed)
        {
            return Verdict::StepUp;
        }
        return Verdict::Allow;
    }

    if input.base_permit == ObligationSupport::Supported {
        if input.snapshot_required == ObligationSupport::Supported
            && input.control_snapshot == ObligationSupport::Unsupported
        {
            return Verdict::Deny;
        }
        return Verdict::Allow;
    }

    Verdict::Deny
}

pub fn degrade_verdict(
    verdict: Verdict,
    caps: &ControlPointCaps,
    min_grade_available: bool,
    timelock: TimelockAllowance,
) -> ExecutedVerb {
    let can_deny = caps.verbs.contains(&VerdictDiscriminant::Deny);
    match verdict {
        Verdict::Allow => ExecutedVerb::Allow,
        Verdict::Deny => {
            if can_deny {
                ExecutedVerb::Deny
            } else {
                ExecutedVerb::ObserveOnly
            }
        }
        Verdict::Modify => {
            if caps.modify == ObligationSupport::Supported
                && caps.verbs.contains(&VerdictDiscriminant::Modify)
            {
                ExecutedVerb::Modify
            } else if can_deny {
                if min_grade_available || timelock == TimelockAllowance::DisclosedTimeLock {
                    ExecutedVerb::DenyWithRetryToken
                } else {
                    ExecutedVerb::Deny
                }
            } else {
                ExecutedVerb::ObserveOnly
            }
        }
        Verdict::StepUp => {
            if !min_grade_available && timelock == TimelockAllowance::Unavailable {
                return if can_deny {
                    ExecutedVerb::Deny
                } else {
                    ExecutedVerb::ObserveOnly
                };
            }
            match caps.hold {
                HoldCapability::CanHold { deadline_ms }
                    if deadline_ms > 0
                        && caps.failure_mode == FailureDisposition::Closed
                        && caps.verbs.contains(&VerdictDiscriminant::StepUp) =>
                {
                    ExecutedVerb::Hold
                }
                _ => {
                    if can_deny {
                        ExecutedVerb::DenyWithRetryToken
                    } else {
                        ExecutedVerb::ObserveOnly
                    }
                }
            }
        }
        Verdict::Defer => match caps.hold {
            HoldCapability::CanHold { deadline_ms }
                if deadline_ms > 0 && caps.failure_mode == FailureDisposition::Closed =>
            {
                ExecutedVerb::Hold
            }
            _ => {
                if can_deny {
                    ExecutedVerb::Deny
                } else {
                    ExecutedVerb::ObserveOnly
                }
            }
        },
    }
}

fn grade_satisfiable(
    required: ApprovalGrade,
    device_max: ApprovalGrade,
    timelock: TimelockAllowance,
) -> bool {
    if device_max >= required {
        return true;
    }
    timelock == TimelockAllowance::DisclosedTimeLock && required == ApprovalGrade::G1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_verdict_covers_all_nine_normative_rows() {
        let base = DeriveInput {
            validity: InputValidity::Valid,
            modify_attempts: 0,
            device_max_grade: ApprovalGrade::G2,
            timelock: TimelockAllowance::Unavailable,
            base_permit: ObligationSupport::Supported,
            observer: BoundaryObserver::None,
            snapshot_required: ObligationSupport::Unsupported,
            control_snapshot: ObligationSupport::Supported,
            control_modify: ObligationSupport::Supported,
            determining_forbids: vec![],
            pending_rules: vec![],
            not_evaluable_rules: vec![],
        };

        assert_eq!(derive_verdict(&base), Verdict::Allow);

        let mut malformed = base.clone();
        malformed.validity = InputValidity::Malformed;
        assert_eq!(derive_verdict(&malformed), Verdict::Deny);

        let mut eval_err = base.clone();
        eval_err.validity = InputValidity::EvalError;
        assert_eq!(derive_verdict(&eval_err), Verdict::Deny);

        let mut modify = base.clone();
        modify.determining_forbids.push(DeterminingForbid {
            rule_id: "secrets.prompt-redact".into(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G1,
            mutability: RuleMutability::Liftable,
            remedy: RemedyCapability::ModifyTransform,
            on_loss: LossBehaviour::AllowOnLoss,
        });
        assert_eq!(derive_verdict(&modify), Verdict::Modify);
        modify.modify_attempts = 2;
        assert_eq!(derive_verdict(&modify), Verdict::Deny);

        let mut ask = base.clone();
        ask.determining_forbids.push(DeterminingForbid {
            rule_id: "essentials.credential-stores".into(),
            mode: Mode::Ask,
            min_grade: ApprovalGrade::G1,
            mutability: RuleMutability::Liftable,
            remedy: RemedyCapability::Plain,
            on_loss: LossBehaviour::AllowOnLoss,
        });
        assert_eq!(derive_verdict(&ask), Verdict::StepUp);

        ask.device_max_grade = ApprovalGrade::G0;
        assert_eq!(derive_verdict(&ask), Verdict::Deny);
        ask.timelock = TimelockAllowance::DisclosedTimeLock;
        assert_eq!(derive_verdict(&ask), Verdict::StepUp);

        let mut defer = base.clone();
        defer.pending_rules.push(PendingRuleRef {
            rule_id: "mcp.pin".into(),
        });
        assert_eq!(derive_verdict(&defer), Verdict::Defer);

        let mut ne_closed = base.clone();
        ne_closed.not_evaluable_rules.push(NotEvaluableRuleRef {
            rule_id: "destructive.opaque".into(),
            on_loss: LossBehaviour::FailClosed,
            grant_lifted: ObligationSupport::Unsupported,
        });
        assert_eq!(derive_verdict(&ne_closed), Verdict::StepUp);
        ne_closed.observer = BoundaryObserver::ScopedBoundary;
        assert_eq!(derive_verdict(&ne_closed), Verdict::Allow);

        let mut unmet_snapshot = base.clone();
        unmet_snapshot.snapshot_required = ObligationSupport::Supported;
        unmet_snapshot.control_snapshot = ObligationSupport::Unsupported;
        assert_eq!(derive_verdict(&unmet_snapshot), Verdict::Deny);

        let mut no_permit = base;
        no_permit.base_permit = ObligationSupport::Unsupported;
        assert_eq!(derive_verdict(&no_permit), Verdict::Deny);
    }

    #[test]
    fn degrade_verdict_enforces_control_point_capabilities() {
        let caps_hook = ControlPointCaps {
            verbs: BTreeSet::from([
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
            ]),
            hold: HoldCapability::NoHold,
            failure_mode: FailureDisposition::Open,
            snapshot: ObligationSupport::Unsupported,
            modify: ObligationSupport::Unsupported,
        };
        assert_eq!(
            degrade_verdict(
                Verdict::StepUp,
                &caps_hook,
                true,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::DenyWithRetryToken
        );
        assert_eq!(
            degrade_verdict(
                Verdict::StepUp,
                &caps_hook,
                false,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::Deny
        );

        let caps_hold = ControlPointCaps {
            verbs: BTreeSet::from([
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
                VerdictDiscriminant::Defer,
            ]),
            hold: HoldCapability::CanHold { deadline_ms: 5000 },
            failure_mode: FailureDisposition::Closed,
            snapshot: ObligationSupport::Supported,
            modify: ObligationSupport::Unsupported,
        };
        assert_eq!(
            degrade_verdict(
                Verdict::StepUp,
                &caps_hold,
                true,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::Hold
        );
        assert_eq!(
            degrade_verdict(
                Verdict::Defer,
                &caps_hold,
                true,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::Hold
        );
    }
}
