// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Server incident grouping, weighted triage queue with 0.2% HMAC sampling and analyst canaries,
//! and second-person time-bounded finding suppressions (`docs/design/18`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_model::{Finding, FindingLifecycle, FindingSeverity};
use grdr_review::queue::{ReviewCandidate, should_sample_lineage};
use grdr_review::verifier::{
    ExtendedReviewSettings, ExtendedReviewSignals, compute_extended_queue_score,
};

const WORTH_A_LOOK_THRESHOLD: u16 = 120;
const WORTH_A_LOOK_TARGET_BP: usize = 200;
const INCIDENT_MERGE_WINDOW_SECS: u64 = 86_400;
const MAX_INCIDENTS: usize = 2_000;
const MAX_INCIDENT_REFS: usize = 1_000;
const MAX_TRIAGE_QUEUE: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageBucket {
    WorthALook,
    Sample,
    Quiet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionStatus {
    PendingSecondPerson,
    Active,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageSessionEntry {
    pub session_id: String,
    pub org_id: String,
    pub score: u16,
    pub bucket: TriageBucket,
    pub has_deterministic_threat_or_tamper: bool,
    pub is_canary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RespondIncident {
    pub incident_id: String,
    pub org_id: String,
    pub group_key: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub session_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub first_seen_sec: i64,
    pub last_seen_sec: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSuppression {
    pub suppression_id: String,
    #[serde(default)]
    pub org_id: String,
    pub finding_id: String,
    pub author_id: String,
    pub approver_id: Option<String>,
    pub prior_lifecycle: FindingLifecycle,
    pub expires_at_sec: i64,
    pub status: SuppressionStatus,
}

pub(crate) fn group_finding_into_incident<'a>(
    incidents: &'a mut Vec<RespondIncident>,
    org_id: &str,
    artefact_or_rule_key: &str,
    finding: &Finding,
    now_sec: i64,
) -> Option<&'a RespondIncident> {
    if org_id.trim().is_empty()
        || artefact_or_rule_key.trim().is_empty()
        || finding.id.trim().is_empty()
        || finding.session_id.trim().is_empty()
        || finding.lifecycle != FindingLifecycle::Open
    {
        return None;
    }
    let group_key = format!("{org_id}::{artefact_or_rule_key}");
    if let Some(pos) = incidents.iter().rposition(|inc| {
        inc.group_key == group_key
            && now_sec.abs_diff(inc.last_seen_sec) <= INCIDENT_MERGE_WINDOW_SECS
    }) {
        if let Some(inc) = incidents.get_mut(pos) {
            if !inc.session_ids.contains(&finding.session_id)
                && inc.session_ids.len() < MAX_INCIDENT_REFS
            {
                inc.session_ids.push(finding.session_id.clone());
            }
            if !inc.finding_ids.contains(&finding.id) && inc.finding_ids.len() < MAX_INCIDENT_REFS {
                inc.finding_ids.push(finding.id.clone());
            }
            if severity_ord(finding.severity) > severity_ord(inc.severity) {
                inc.severity = finding.severity;
            }
            inc.last_seen_sec = inc.last_seen_sec.max(now_sec);
        }
        return incidents.get(pos);
    }

    if incidents.len() >= MAX_INCIDENTS
        && let Some((evict_idx, _)) = incidents
            .iter()
            .enumerate()
            .min_by_key(|(_, inc)| inc.last_seen_sec)
    {
        incidents.remove(evict_idx);
    }
    incidents.push(RespondIncident {
        incident_id: format!("inc_{}", Uuid::now_v7().simple()),
        org_id: org_id.to_owned(),
        group_key,
        title: finding.title.clone(),
        severity: finding.severity,
        session_ids: vec![finding.session_id.clone()],
        finding_ids: vec![finding.id.clone()],
        first_seen_sec: now_sec,
        last_seen_sec: now_sec,
    });
    incidents.last()
}

pub(crate) fn classify_and_enqueue_session(
    queue: &mut Vec<TriageSessionEntry>,
    org_id: &str,
    candidate: &ReviewCandidate,
    ext: &ExtendedReviewSignals,
    sample_key: &[u8; 32],
    is_canary: bool,
    has_deterministic_threat_or_tamper: bool,
) -> TriageSessionEntry {
    let settings = ExtendedReviewSettings::default();
    let score = compute_extended_queue_score(candidate, ext, &settings);

    let bucket =
        if is_canary || has_deterministic_threat_or_tamper || score >= WORTH_A_LOOK_THRESHOLD {
            TriageBucket::WorthALook
        } else if should_sample_lineage(sample_key, &candidate.root_session_id, 20) {
            TriageBucket::Sample
        } else {
            TriageBucket::Quiet
        };
    let entry = TriageSessionEntry {
        session_id: candidate.session_id.clone(),
        org_id: org_id.to_owned(),
        score,
        bucket,
        has_deterministic_threat_or_tamper,
        is_canary,
    };
    if queue.len() >= MAX_TRIAGE_QUEUE {
        let evict_idx = queue
            .iter()
            .position(|e| e.bucket == TriageBucket::Quiet)
            .unwrap_or(0);
        queue.remove(evict_idx);
    }
    queue.push(entry.clone());
    entry
}

#[must_use]
pub(crate) fn worth_a_look_within_cap(queue: &[TriageSessionEntry]) -> bool {
    if queue.is_empty() {
        return true;
    }
    let worth = queue
        .iter()
        .filter(|e| matches!(e.bucket, TriageBucket::WorthALook | TriageBucket::Sample))
        .count();
    let share_bp = worth
        .saturating_mul(10_000)
        .checked_div(queue.len())
        .unwrap_or(0);
    share_bp <= WORTH_A_LOOK_TARGET_BP
}

fn severity_ord(sev: FindingSeverity) -> u8 {
    match sev {
        FindingSeverity::Low => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::High => 3,
        FindingSeverity::Critical => 4,
    }
}
