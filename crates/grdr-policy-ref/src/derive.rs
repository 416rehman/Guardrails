// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Independent normative 9-row verdict derivation and control-point degradation (`docs/design/12` s.4).

use grdr_model::{ApprovalGrade, Mode, Verdict};
pub use grdr_model::{
    BoundaryObserver, ControlPointCaps, DeriveInput, DeterminingForbid, ExecutedVerb,
    FailureDisposition, HoldCapability, InputValidity, LossBehaviour, NotEvaluableRuleRef,
    ObligationSupport, PendingRuleRef, RemedyCapability, RuleMutability, TimelockAllowance,
    VerdictDiscriminant,
};

const REF_MAX_MODIFY_RETRIES: u8 = 2;

/// Independently derives the 9-row verdict from normalized evaluation state.
pub fn derive_verdict(input: &DeriveInput) -> Verdict {
    if input.validity != InputValidity::Valid {
        return Verdict::Deny;
    }
    if !input.determining_forbids.is_empty() {
        let can_rewrite = input.control_modify == ObligationSupport::Supported
            && input.modify_attempts < REF_MAX_MODIFY_RETRIES
            && input
                .determining_forbids
                .iter()
                .all(|forbid| forbid.remedy == RemedyCapability::ModifyTransform);
        if can_rewrite {
            return Verdict::Modify;
        }
        let blocked = input.determining_forbids.iter().any(|forbid| {
            forbid.mode != Mode::Ask
                || !ref_grade_satisfiable(forbid.min_grade, input.device_max_grade, input.timelock)
        });
        return if blocked {
            Verdict::Deny
        } else {
            Verdict::StepUp
        };
    }
    if !input.pending_rules.is_empty() {
        return Verdict::Defer;
    }
    if input.observer != BoundaryObserver::ScopedBoundary {
        for ne in &input.not_evaluable_rules {
            if ne.grant_lifted == ObligationSupport::Supported {
                continue;
            }
            match ne.on_loss {
                LossBehaviour::FailClosed | LossBehaviour::Block => return Verdict::StepUp,
                LossBehaviour::AllowOnLoss => {}
            }
        }
    }
    if input.base_permit != ObligationSupport::Supported {
        return Verdict::Deny;
    }
    if input.snapshot_required == ObligationSupport::Supported
        && input.control_snapshot == ObligationSupport::Unsupported
    {
        return Verdict::Deny;
    }
    Verdict::Allow
}

/// Independently degrades a normative verdict onto concrete control-point capabilities.
pub fn degrade_verdict(
    verdict: Verdict,
    caps: &ControlPointCaps,
    min_grade_available: bool,
    timelock: TimelockAllowance,
) -> ExecutedVerb {
    let can_deny = caps.verbs.contains(&VerdictDiscriminant::Deny);
    let deny_or_observe = if can_deny {
        ExecutedVerb::Deny
    } else {
        ExecutedVerb::ObserveOnly
    };
    let can_hold = matches!(caps.hold, HoldCapability::CanHold { deadline_ms } if deadline_ms > 0)
        && caps.failure_mode == FailureDisposition::Closed;
    match verdict {
        Verdict::Allow => ExecutedVerb::Allow,
        Verdict::Deny => deny_or_observe,
        Verdict::Modify => {
            if caps.modify == ObligationSupport::Supported
                && caps.verbs.contains(&VerdictDiscriminant::Modify)
            {
                ExecutedVerb::Modify
            } else {
                deny_or_observe
            }
        }
        Verdict::StepUp => {
            if !min_grade_available && timelock == TimelockAllowance::Unavailable {
                return deny_or_observe;
            }
            if can_hold && caps.verbs.contains(&VerdictDiscriminant::StepUp) {
                ExecutedVerb::Hold
            } else if can_deny {
                ExecutedVerb::DenyWithRetryToken
            } else {
                ExecutedVerb::ObserveOnly
            }
        }
        Verdict::Defer => {
            if can_hold && caps.verbs.contains(&VerdictDiscriminant::Defer) {
                ExecutedVerb::Hold
            } else {
                deny_or_observe
            }
        }
    }
}

fn ref_grade_satisfiable(
    required: ApprovalGrade,
    device_max: ApprovalGrade,
    timelock: TimelockAllowance,
) -> bool {
    device_max >= required
        || (timelock == TimelockAllowance::DisclosedTimeLock && required == ApprovalGrade::G1)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn valid_base_input() -> DeriveInput {
        DeriveInput {
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
        }
    }

    #[test]
    fn derive_verdict_covers_all_nine_normative_rows() {
        let base = valid_base_input();
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

        let mut modify_unavail = modify.clone();
        modify_unavail.modify_attempts = 0;
        modify_unavail.control_modify = ObligationSupport::Unsupported;
        assert_eq!(derive_verdict(&modify_unavail), Verdict::Deny);

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

        let mut invalid_watch_forbid = base.clone();
        invalid_watch_forbid
            .determining_forbids
            .push(DeterminingForbid {
                rule_id: "bad.watch".into(),
                mode: Mode::Watch,
                min_grade: ApprovalGrade::G1,
                mutability: RuleMutability::Liftable,
                remedy: RemedyCapability::Plain,
                on_loss: LossBehaviour::AllowOnLoss,
            });
        assert_eq!(derive_verdict(&invalid_watch_forbid), Verdict::Deny);

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

        let mut ne_block = base.clone();
        ne_block.not_evaluable_rules.push(NotEvaluableRuleRef {
            rule_id: "secrets.honeytoken".into(),
            on_loss: LossBehaviour::Block,
            grant_lifted: ObligationSupport::Unsupported,
        });
        assert_eq!(derive_verdict(&ne_block), Verdict::StepUp);
        ne_block.not_evaluable_rules[0].grant_lifted = ObligationSupport::Supported;
        assert_eq!(derive_verdict(&ne_block), Verdict::Allow);

        let mut ne_unmet_snapshot = ne_closed;
        ne_unmet_snapshot.snapshot_required = ObligationSupport::Supported;
        ne_unmet_snapshot.control_snapshot = ObligationSupport::Unsupported;
        assert_eq!(derive_verdict(&ne_unmet_snapshot), Verdict::Deny);

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
        assert_eq!(
            degrade_verdict(
                Verdict::Modify,
                &caps_hook,
                true,
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

        let no_defer_hold = ControlPointCaps {
            verbs: BTreeSet::from([
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
            ]),
            ..caps_hold
        };
        assert_eq!(
            degrade_verdict(
                Verdict::Defer,
                &no_defer_hold,
                true,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::Deny
        );

        let zero_hold = ControlPointCaps {
            hold: HoldCapability::CanHold { deadline_ms: 0 },
            ..caps_hold
        };
        assert_eq!(
            degrade_verdict(
                Verdict::Defer,
                &zero_hold,
                true,
                TimelockAllowance::Unavailable
            ),
            ExecutedVerb::Deny
        );

        let sensor = ControlPointCaps {
            verbs: BTreeSet::from([VerdictDiscriminant::Allow]),
            hold: HoldCapability::NoHold,
            failure_mode: FailureDisposition::Open,
            snapshot: ObligationSupport::Unsupported,
            modify: ObligationSupport::Unsupported,
        };
        assert_eq!(
            degrade_verdict(Verdict::Deny, &sensor, true, TimelockAllowance::Unavailable),
            ExecutedVerb::ObserveOnly
        );
    }
}
