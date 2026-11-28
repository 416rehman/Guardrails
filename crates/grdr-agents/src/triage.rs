// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 4 local/org triage queue, widening dispositions, and reopen triggers (`docs/design/05`).

use std::collections::BTreeSet;

use grdr_core::discover::{BehaviorVerdict, BehavioralAssessment, ProgramIdentity};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

const SECONDS_PER_DAY: u64 = 86_400;
const DEFAULT_SUPPRESSION_DAYS: u16 = 180;
const MAX_SUPPRESSION_DAYS: u16 = 365;
const MAX_SNOOZE_DAYS: u16 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriageReopenTrigger {
    SignerChanged,
    RemoteEndpointAdded,
    PackageChanged,
    CompositionChanged,
    OutcomeEscalatedToSuspected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum TriageDisposition {
    Confirm {
        agent_kind: String,
        session_exclusive: bool,
        min_attribution_grade: u8,
        containment_default: String,
        sponsor_team: String,
    },
    VariantOfCatalogued {
        target_agent_id: String,
        propose_upstream: bool,
    },
    LlmClientNotAgent {
        owner: String,
        approver: Option<String>,
        justification: String,
        ttl_days: u16,
    },
    NotAi {
        owner: String,
        approver: Option<String>,
        justification: String,
        ttl_days: u16,
    },
    Snooze {
        owner: String,
        approver: Option<String>,
        justification: String,
        ttl_days: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageItem {
    pub org_id: String,
    pub program_id: String,
    pub device_ids: BTreeSet<String>,
    pub verdict: BehaviorVerdict,
    pub observed_signer: Option<String>,
    pub observed_hosts: BTreeSet<String>,
    pub observed_package: Option<String>,
    pub building_blocks: BTreeSet<String>,
    pub disposition: Option<TriageDisposition>,
    pub decided_at_epoch_secs: Option<u64>,
    pub expires_at_epoch_secs: Option<u64>,
    pub reopened_by: Option<TriageReopenTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageObservationUpdate {
    pub verdict: BehaviorVerdict,
    pub observed_signer: Option<String>,
    pub observed_hosts: BTreeSet<String>,
    pub observed_package: Option<String>,
    pub building_blocks: BTreeSet<String>,
    pub now_epoch_secs: u64,
}

impl TriageDisposition {
    #[must_use]
    pub fn is_widening(&self) -> bool {
        matches!(
            self,
            Self::LlmClientNotAgent { .. } | Self::NotAi { .. } | Self::Snooze { .. }
        )
    }

    pub fn validate(&self, require_distinct_approver: bool) -> Result<u16, CodedError> {
        match self {
            Self::Confirm { sponsor_team, .. } => {
                if sponsor_team.trim().is_empty() {
                    return Err(triage_err(
                        "confirm decision requires non-empty sponsor_team",
                    ));
                }
                Ok(0)
            }
            Self::VariantOfCatalogued {
                target_agent_id, ..
            } => {
                if target_agent_id.trim().is_empty() {
                    return Err(triage_err("variant decision requires target_agent_id"));
                }
                Ok(0)
            }
            Self::LlmClientNotAgent {
                owner,
                approver,
                justification,
                ttl_days,
            }
            | Self::NotAi {
                owner,
                approver,
                justification,
                ttl_days,
            } => validate_widening_fields(
                owner,
                approver.as_deref(),
                justification,
                *ttl_days,
                DEFAULT_SUPPRESSION_DAYS,
                MAX_SUPPRESSION_DAYS,
                require_distinct_approver,
            ),
            Self::Snooze {
                owner,
                approver,
                justification,
                ttl_days,
            } => validate_widening_fields(
                owner,
                approver.as_deref(),
                justification,
                *ttl_days,
                MAX_SNOOZE_DAYS,
                MAX_SNOOZE_DAYS,
                require_distinct_approver,
            ),
        }
    }
}

pub fn apply_triage_disposition(
    item: &mut TriageItem,
    disposition: TriageDisposition,
    require_distinct_approver: bool,
    now_epoch_secs: u64,
) -> Result<(), CodedError> {
    let ttl_days = disposition.validate(require_distinct_approver)?;
    item.expires_at_epoch_secs = if ttl_days > 0 {
        Some(now_epoch_secs.saturating_add(u64::from(ttl_days).saturating_mul(SECONDS_PER_DAY)))
    } else {
        None
    };
    item.decided_at_epoch_secs = Some(now_epoch_secs);
    item.reopened_by = None;
    item.disposition = Some(disposition);
    Ok(())
}

pub fn evaluate_triage_reopen(
    item: &mut TriageItem,
    update: &TriageObservationUpdate,
) -> Option<TriageReopenTrigger> {
    item.disposition.as_ref()?;
    let trigger = if item
        .expires_at_epoch_secs
        .is_some_and(|exp| update.now_epoch_secs >= exp)
    {
        Some(TriageReopenTrigger::Expired)
    } else if item.observed_signer != update.observed_signer {
        Some(TriageReopenTrigger::SignerChanged)
    } else if !update.observed_hosts.is_empty()
        && update
            .observed_hosts
            .iter()
            .any(|h| !item.observed_hosts.contains(h))
    {
        Some(TriageReopenTrigger::RemoteEndpointAdded)
    } else if item.observed_package != update.observed_package {
        Some(TriageReopenTrigger::PackageChanged)
    } else if matches!(
        item.disposition,
        Some(TriageDisposition::LlmClientNotAgent { .. })
    ) && update
        .building_blocks
        .iter()
        .any(|b| !item.building_blocks.contains(b))
    {
        Some(TriageReopenTrigger::CompositionChanged)
    } else if matches!(
        item.disposition,
        Some(
            TriageDisposition::LlmClientNotAgent { .. }
                | TriageDisposition::NotAi { .. }
                | TriageDisposition::Snooze { .. }
        )
    ) && !matches!(
        item.verdict,
        BehaviorVerdict::AgentSuspected | BehaviorVerdict::AgentClassified
    ) && matches!(
        update.verdict,
        BehaviorVerdict::AgentSuspected | BehaviorVerdict::AgentClassified
    ) {
        Some(TriageReopenTrigger::OutcomeEscalatedToSuspected)
    } else {
        None
    };

    if let Some(reason) = trigger {
        item.reopened_by = Some(reason);
        item.disposition = None;
        item.expires_at_epoch_secs = None;
    }
    item.verdict = update.verdict;
    item.observed_signer.clone_from(&update.observed_signer);
    item.observed_hosts.clone_from(&update.observed_hosts);
    item.observed_package.clone_from(&update.observed_package);
    item.building_blocks.clone_from(&update.building_blocks);
    trigger
}

#[must_use]
pub fn triage_finding_from_assessment(
    org_id: &str,
    device_id: &str,
    identity: &ProgramIdentity,
    assessment: &BehavioralAssessment,
) -> Option<TriageItem> {
    if !matches!(
        assessment.verdict,
        BehaviorVerdict::AgentSuspected | BehaviorVerdict::AgentClassified
    ) {
        return None;
    }
    let mut devices = BTreeSet::new();
    devices.insert(device_id.into());
    Some(TriageItem {
        org_id: org_id.into(),
        program_id: identity.canonical_id(),
        device_ids: devices,
        verdict: assessment.verdict,
        observed_signer: None,
        observed_hosts: BTreeSet::new(),
        observed_package: None,
        building_blocks: BTreeSet::new(),
        disposition: None,
        decided_at_epoch_secs: None,
        expires_at_epoch_secs: None,
        reopened_by: None,
    })
}

fn validate_widening_fields(
    owner: &str,
    approver: Option<&str>,
    justification: &str,
    ttl_days: u16,
    default_days: u16,
    max_days: u16,
    require_distinct_approver: bool,
) -> Result<u16, CodedError> {
    if owner.trim().is_empty() || justification.trim().is_empty() {
        return Err(triage_err(
            "widening disposition requires owner and justification",
        ));
    }
    if require_distinct_approver {
        let Some(app) = approver.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(triage_err(
                "widening disposition requires distinct approver",
            ));
        };
        if app == owner.trim() {
            return Err(triage_err("approver must differ from proposer"));
        }
    }
    let effective = if ttl_days == 0 {
        default_days
    } else {
        ttl_days
    };
    if effective > max_days {
        return Err(triage_err(format!(
            "disposition ttl {effective} exceeds max {max_days} days"
        )));
    }
    Ok(effective)
}

fn triage_err(msg: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-AGENTS-0005",
        msg.into(),
        "Inspect triage disposition owner, distinct approver, and TTL limits.",
    )
}
