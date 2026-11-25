// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Legal holds, dual-approver governance, renewals, and subject erasure (`D-57`).

use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{ComplyError, deterministic_prefixed_id};

const MAX_HOLD_REVIEW_SECONDS: i64 = 365 * 86_400;
const MAX_DEFERRED_NOTICE_SECONDS: i64 = 90 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldLifecycle {
    Active,
    ReviewOverdue,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldNotice {
    Immediate,
    Deferred { until: Timestamp, renewals: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldScope {
    pub pseudonyms: Vec<String>,
    pub session_ids: Vec<String>,
    pub incident_id: Option<String>,
    pub classes: Vec<String>,
    #[serde(default)]
    pub from: Option<Timestamp>,
    #[serde(default)]
    pub to: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub hold_id: String,
    pub organisation: String,
    pub scope: HoldScope,
    pub matter_ref: String,
    pub reason: String,
    pub created_by: String,
    pub approvers: Vec<String>,
    pub created_at: Timestamp,
    pub review_by: Timestamp,
    pub notice: HoldNotice,
    pub lifecycle: HoldLifecycle,
    #[serde(default)]
    pub renewals: u32,
    #[serde(default)]
    pub released_at: Option<Timestamp>,
    #[serde(default)]
    pub release_approvers: Vec<String>,
    #[serde(default)]
    pub release_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldCheckQuery<'a> {
    pub organisation: &'a str,
    pub pseudonym: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub incident_id: Option<&'a str>,
    pub data_class: Option<&'a str>,
    pub record_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldCheckResult {
    Clear,
    Held { hold_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldReviewFinding {
    pub hold_id: String,
    pub matter_ref: String,
    pub review_by: Timestamp,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ErasureOutcome {
    Executed {
        subject_ref: String,
    },
    PendingHeld {
        subject_ref: String,
        hold_ids: Vec<String>,
        disclose_hold: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoldsLedger {
    pub holds: Vec<Hold>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceHoldInput {
    pub organisation: String,
    pub scope: HoldScope,
    pub matter_ref: String,
    pub reason: String,
    pub created_by: String,
    pub approvers: Vec<String>,
    pub created_at: Timestamp,
    pub review_by: Timestamp,
    pub notice: HoldNotice,
}

impl HoldsLedger {
    pub fn place_hold(&mut self, input: PlaceHoldInput) -> Result<Hold, ComplyError> {
        let seed = format!(
            "{}:{}:{}:{}",
            input.organisation,
            input.matter_ref,
            input.created_at,
            self.holds.len()
        );
        let hold_id = deterministic_prefixed_id("hld", &seed);

        if input.organisation.trim().is_empty()
            || input.matter_ref.trim().is_empty()
            || input.reason.trim().is_empty()
            || input.created_by.trim().is_empty()
        {
            return Err(ComplyError::InvalidHold {
                hold_id,
                detail: "organisation, matter_ref, reason, and created_by must be non-empty".into(),
            });
        }

        validate_scope(&hold_id, &input.scope)?;
        let approvers = validate_dual_approvers(&hold_id, &input.approvers)?;
        validate_review_window(&hold_id, input.created_at, input.review_by)?;
        if let HoldNotice::Deferred { until, .. } = input.notice {
            validate_deferred_notice(&hold_id, input.created_at, until)?;
        }

        let hold = Hold {
            hold_id,
            organisation: input.organisation.trim().to_owned(),
            scope: input.scope,
            matter_ref: input.matter_ref.trim().to_owned(),
            reason: input.reason.trim().to_owned(),
            created_by: input.created_by.trim().to_owned(),
            approvers,
            created_at: input.created_at,
            review_by: input.review_by,
            notice: input.notice,
            lifecycle: HoldLifecycle::Active,
            renewals: 0,
            released_at: None,
            release_approvers: Vec::new(),
            release_reason: None,
        };
        self.holds.push(hold.clone());
        Ok(hold)
    }

    pub fn check(&self, query: &HoldCheckQuery<'_>) -> HoldCheckResult {
        let matching: Vec<String> = self
            .holds
            .iter()
            .filter(|h| h.lifecycle != HoldLifecycle::Released)
            .filter(|h| h.organisation == query.organisation)
            .filter(|h| {
                let ps_hit = query
                    .pseudonym
                    .is_some_and(|ps| h.scope.pseudonyms.iter().any(|p| p == ps));
                let sess_hit = query
                    .session_id
                    .is_some_and(|sid| h.scope.session_ids.iter().any(|s| s == sid));
                let inc_hit = query
                    .incident_id
                    .is_some_and(|iid| h.scope.incident_id.as_deref() == Some(iid));
                let class_hit = h.scope.classes.is_empty()
                    || query.data_class.is_none()
                    || query
                        .data_class
                        .is_some_and(|c| h.scope.classes.iter().any(|hc| hc == c));
                let time_hit = query.record_at.is_none_or(|ts| {
                    h.scope.from.is_none_or(|f| ts >= f) && h.scope.to.is_none_or(|t| ts <= t)
                });
                (ps_hit || sess_hit || inc_hit) && class_hit && time_hit
            })
            .map(|h| h.hold_id.clone())
            .collect();

        if matching.is_empty() {
            HoldCheckResult::Clear
        } else {
            HoldCheckResult::Held { hold_ids: matching }
        }
    }

    pub fn flag_expired_reviews(&mut self, now: Timestamp) -> Vec<HoldReviewFinding> {
        let mut findings = Vec::new();
        for hold in &mut self.holds {
            if hold.lifecycle == HoldLifecycle::Active && now >= hold.review_by {
                hold.lifecycle = HoldLifecycle::ReviewOverdue;
                findings.push(HoldReviewFinding {
                    hold_id: hold.hold_id.clone(),
                    matter_ref: hold.matter_ref.clone(),
                    review_by: hold.review_by,
                    detail:
                        "Legal hold review_by expired; hold stays pinned until renewed or released."
                            .into(),
                });
            }
        }
        findings
    }

    pub fn renew_hold(
        &mut self,
        hold_id: &str,
        approvers: &[String],
        new_review_by: Timestamp,
        defer_notice_until: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<&Hold, ComplyError> {
        let validated_approvers = validate_dual_approvers(hold_id, approvers)?;
        validate_review_window(hold_id, now, new_review_by)?;
        if let Some(until) = defer_notice_until {
            validate_deferred_notice(hold_id, now, until)?;
        }

        let hold = self
            .holds
            .iter_mut()
            .find(|h| h.hold_id == hold_id)
            .ok_or_else(|| ComplyError::UnknownHold(hold_id.to_owned()))?;
        if hold.lifecycle == HoldLifecycle::Released {
            return Err(ComplyError::InvalidHold {
                hold_id: hold_id.to_owned(),
                detail: "cannot renew a released hold".into(),
            });
        }

        hold.review_by = new_review_by;
        hold.approvers = validated_approvers;
        hold.renewals = hold.renewals.saturating_add(1);
        hold.lifecycle = HoldLifecycle::Active;
        if let Some(until) = defer_notice_until {
            let next_notice_renewals = match hold.notice {
                HoldNotice::Deferred { renewals, .. } => renewals.saturating_add(1),
                HoldNotice::Immediate => 1,
            };
            hold.notice = HoldNotice::Deferred {
                until,
                renewals: next_notice_renewals,
            };
        }
        Ok(hold)
    }

    pub fn release_hold(
        &mut self,
        hold_id: &str,
        approvers: &[String],
        reason: &str,
        now: Timestamp,
    ) -> Result<&Hold, ComplyError> {
        let validated_approvers = validate_dual_approvers(hold_id, approvers)?;
        if reason.trim().is_empty() {
            return Err(ComplyError::InvalidHold {
                hold_id: hold_id.to_owned(),
                detail: "release reason must not be empty".into(),
            });
        }
        let hold = self
            .holds
            .iter_mut()
            .find(|h| h.hold_id == hold_id)
            .ok_or_else(|| ComplyError::UnknownHold(hold_id.to_owned()))?;
        hold.lifecycle = HoldLifecycle::Released;
        hold.released_at = Some(now);
        hold.release_approvers = validated_approvers;
        hold.release_reason = Some(reason.trim().to_owned());
        Ok(hold)
    }

    pub fn process_erasure(
        &self,
        organisation: &str,
        subject_pseudonym: &str,
        now: Timestamp,
    ) -> ErasureOutcome {
        let query = HoldCheckQuery {
            organisation,
            pseudonym: Some(subject_pseudonym),
            session_id: None,
            incident_id: None,
            data_class: None,
            record_at: None,
        };
        match self.check(&query) {
            HoldCheckResult::Clear => ErasureOutcome::Executed {
                subject_ref: subject_pseudonym.to_owned(),
            },
            HoldCheckResult::Held { hold_ids } => {
                let disclose_hold = self
                    .holds
                    .iter()
                    .filter(|h| hold_ids.contains(&h.hold_id))
                    .all(|h| match h.notice {
                        HoldNotice::Immediate => true,
                        HoldNotice::Deferred { until, .. } => now >= until,
                    });
                ErasureOutcome::PendingHeld {
                    subject_ref: subject_pseudonym.to_owned(),
                    hold_ids,
                    disclose_hold,
                }
            }
        }
    }
}

fn validate_scope(hold_id: &str, scope: &HoldScope) -> Result<(), ComplyError> {
    let has_ps = scope.pseudonyms.iter().any(|p| !p.trim().is_empty());
    let has_sess = scope.session_ids.iter().any(|s| !s.trim().is_empty());
    let has_inc = scope
        .incident_id
        .as_deref()
        .is_some_and(|i| !i.trim().is_empty());
    if !has_ps && !has_sess && !has_inc {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail: "hold scope must target at least one pseudonym, session_id, or incident_id"
                .into(),
        });
    }
    if scope.classes.iter().any(|c| c.trim().is_empty()) {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail: "hold scope classes must not contain empty strings".into(),
        });
    }
    if let (Some(from), Some(to)) = (scope.from, scope.to)
        && to < from
    {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail: "hold scope `to` timestamp cannot precede `from`".into(),
        });
    }
    Ok(())
}

fn validate_dual_approvers(
    hold_id: &str,
    approvers: &[String],
) -> Result<Vec<String>, ComplyError> {
    let distinct: BTreeSet<String> = approvers
        .iter()
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .collect();
    if distinct.len() < 2 {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail:
                "legal hold requires at least two distinct non-empty approvers (privacy officer and org owner)"
                    .into(),
        });
    }
    Ok(distinct.into_iter().collect())
}

fn validate_review_window(
    hold_id: &str,
    anchor: Timestamp,
    review_by: Timestamp,
) -> Result<(), ComplyError> {
    let review_delta = review_by.as_second().saturating_sub(anchor.as_second());
    if review_delta <= 0 || review_delta > MAX_HOLD_REVIEW_SECONDS {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail: "hold review_by must be within 12 months of creation/renewal".into(),
        });
    }
    Ok(())
}

fn validate_deferred_notice(
    hold_id: &str,
    anchor: Timestamp,
    until: Timestamp,
) -> Result<(), ComplyError> {
    let defer_delta = until.as_second().saturating_sub(anchor.as_second());
    if defer_delta <= 0 || defer_delta > MAX_DEFERRED_NOTICE_SECONDS {
        return Err(ComplyError::InvalidHold {
            hold_id: hold_id.to_owned(),
            detail: "deferred subject notice cannot exceed 90 days".into(),
        });
    }
    Ok(())
}
