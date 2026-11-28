// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Sigma detection engine, bounded correlations, config integrity, response execution, and L0 compilers (`D-09`, `D-54`).

pub mod builtins;
pub mod condition;
mod config_formats;
pub mod config_integrity;
mod config_parse;
mod config_toml;
mod config_toml_lex;
pub mod corr;
pub mod engine;
pub mod eval;
pub mod kill_switch;
pub mod l0;
mod l0_format;
pub mod response;
pub mod sigma;
mod sigma_fields;
pub mod types;
pub mod yaml;
pub mod yaml_scalar;

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_crypto::{domain_sha256_digest, encode_lower_hex};
use grdr_model::{
    DecisionReceipt, Finding, FindingClass, FindingLifecycle, FindingSeverity, Incident, Mode,
    Verdict,
};

use crate::analyze::classify_target;
use crate::session::SessionRuleState;

const RECEIPT_FINDING_DOMAIN: &str = "grdr.detect.receipt_finding.v1";
const INCIDENT_ID_DOMAIN: &str = "grdr.detect.incident_id.v1";

struct IncidentAcc {
    session_id: String,
    device_id: String,
    device_name: String,
    agent_name: String,
    severity: FindingSeverity,
    finding_ids: Vec<String>,
    titles: Vec<String>,
    lifecycle: FindingLifecycle,
    first_seen: Timestamp,
    last_seen: Timestamp,
}

fn deterministic_receipt_finding_id(receipt: &DecisionReceipt) -> String {
    let mut buf = Vec::new();
    for field in [
        receipt.receipt_id.as_bytes(),
        receipt.attempt_id.as_bytes(),
        receipt.session_id.as_bytes(),
        receipt.device_id.as_bytes(),
    ] {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(field);
    }
    buf.extend_from_slice(&receipt.decided_at.as_nanosecond().to_le_bytes());
    let digest = domain_sha256_digest(RECEIPT_FINDING_DOMAIN, &buf);
    let hex = encode_lower_hex(&digest);
    format!("fnd_{}", hex.get(..24).unwrap_or(&hex))
}

fn deterministic_incident_id(device_id: &str, session_id: &str) -> String {
    let mut buf = Vec::new();
    for part in [device_id.as_bytes(), session_id.as_bytes()] {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(part);
    }
    let digest = domain_sha256_digest(INCIDENT_ID_DOMAIN, &buf);
    let hex = encode_lower_hex(&digest);
    format!("inc_{}", hex.get(..24).unwrap_or(&hex))
}

pub fn finding_from_receipt(receipt: &DecisionReceipt, device_name: &str) -> Option<Finding> {
    let analysis = classify_target(receipt.action_class, &receipt.target);
    let is_tamper = analysis
        .risk_tags
        .iter()
        .any(|tag| tag == "agent-control-file" || tag == "hook-bypass" || tag == "exec.malformed");
    let finding_id = deterministic_receipt_finding_id(receipt);

    match receipt.verdict {
        Verdict::Deny => Some(Finding {
            id: finding_id,
            session_id: receipt.session_id.clone(),
            device_id: receipt.device_id.clone(),
            device_name: device_name.into(),
            agent_name: receipt.agent_name.clone(),
            class: if is_tamper {
                FindingClass::Tamper
            } else {
                FindingClass::PolicyViolation
            },
            finding_class_other: None,
            severity: if is_tamper || analysis.risk_score >= 70 {
                FindingSeverity::Critical
            } else {
                FindingSeverity::High
            },
            lifecycle: FindingLifecycle::Open,
            rule_id: receipt.rule_id.clone(),
            title: format!(
                "Blocked {} on {}",
                receipt.action_class.as_str(),
                receipt.agent_name
            ),
            summary: receipt.reason.clone(),
            target: receipt.target.clone(),
            detected_at: receipt.decided_at,
        }),
        Verdict::StepUp => Some(Finding {
            id: finding_id,
            session_id: receipt.session_id.clone(),
            device_id: receipt.device_id.clone(),
            device_name: device_name.into(),
            agent_name: receipt.agent_name.clone(),
            class: FindingClass::PolicyViolation,
            finding_class_other: None,
            severity: if analysis.risk_score >= 60 {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            lifecycle: FindingLifecycle::Open,
            rule_id: receipt.rule_id.clone(),
            title: format!("Approval requested for {}", receipt.action_class.as_str()),
            summary: receipt.reason.clone(),
            target: receipt.target.clone(),
            detected_at: receipt.decided_at,
        }),
        Verdict::Allow
            if receipt.mode_applied == Some(Mode::Watch) && analysis.risk_score >= 40 =>
        {
            Some(Finding {
                id: finding_id,
                session_id: receipt.session_id.clone(),
                device_id: receipt.device_id.clone(),
                device_name: device_name.into(),
                agent_name: receipt.agent_name.clone(),
                class: FindingClass::Threat,
                finding_class_other: None,
                severity: FindingSeverity::Low,
                lifecycle: FindingLifecycle::Open,
                rule_id: receipt.rule_id.clone(),
                title: format!(
                    "Watch alert for {} ({})",
                    receipt.action_class.as_str(),
                    receipt.agent_name
                ),
                summary: receipt.reason.clone(),
                target: receipt.target.clone(),
                detected_at: receipt.decided_at,
            })
        }
        _ => None,
    }
}

pub fn correlate_incidents(
    findings: &[Finding],
    session_states: &BTreeMap<String, SessionRuleState>,
) -> Vec<Incident> {
    let mut grouped: BTreeMap<(String, String), IncidentAcc> = BTreeMap::new();

    for finding in findings {
        let key = (finding.device_id.clone(), finding.session_id.clone());
        let acc = grouped.entry(key).or_insert_with(|| IncidentAcc {
            session_id: finding.session_id.clone(),
            device_id: finding.device_id.clone(),
            device_name: finding.device_name.clone(),
            agent_name: finding.agent_name.clone(),
            severity: finding.severity,
            finding_ids: Vec::new(),
            titles: Vec::new(),
            lifecycle: finding.lifecycle,
            first_seen: finding.detected_at,
            last_seen: finding.detected_at,
        });

        if finding.severity > acc.severity {
            acc.severity = finding.severity;
        }
        if finding.detected_at < acc.first_seen {
            acc.first_seen = finding.detected_at;
        }
        if finding.detected_at > acc.last_seen {
            acc.last_seen = finding.detected_at;
        }
        acc.lifecycle = merge_lifecycle(acc.lifecycle, finding.lifecycle);
        acc.finding_ids.push(finding.id.clone());
        if acc.titles.len() < 3 && !acc.titles.contains(&finding.title) {
            acc.titles.push(finding.title.clone());
        }
    }

    let mut incidents: Vec<Incident> = grouped
        .into_values()
        .map(|acc| {
            let labels = session_states
                .get(&acc.session_id)
                .map(SessionRuleState::labels_vec)
                .unwrap_or_default();
            let finding_count = acc.finding_ids.len();
            let summary = if acc.titles.is_empty() {
                format!("{finding_count} correlated finding(s) in session")
            } else {
                acc.titles.join("; ")
            };
            let title = format!("{} session incident ({finding_count})", acc.agent_name);
            Incident {
                id: deterministic_incident_id(&acc.device_id, &acc.session_id),
                session_id: acc.session_id,
                device_id: acc.device_id,
                device_name: acc.device_name,
                agent_name: acc.agent_name,
                title,
                summary,
                severity: acc.severity,
                lifecycle: acc.lifecycle,
                finding_ids: acc.finding_ids,
                finding_count,
                labels,
                first_seen: acc.first_seen,
                last_seen: acc.last_seen,
            }
        })
        .collect();

    incidents.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.last_seen.cmp(&a.last_seen))
    });
    incidents
}

fn lifecycle_priority(lifecycle: FindingLifecycle) -> u8 {
    match lifecycle {
        FindingLifecycle::Resolved => 0,
        FindingLifecycle::Contained => 1,
        FindingLifecycle::Acknowledged => 2,
        FindingLifecycle::Open => 3,
    }
}

fn merge_lifecycle(current: FindingLifecycle, next: FindingLifecycle) -> FindingLifecycle {
    if lifecycle_priority(next) > lifecycle_priority(current) {
        next
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::SessionLabel;

    #[test]
    fn correlate_incidents_groups_findings_by_session_and_attaches_labels() {
        let t1 = Timestamp::from_second(1_700_000_010).unwrap();
        let t2 = Timestamp::from_second(1_700_000_050).unwrap();
        let findings = vec![
            Finding {
                id: "f1".into(),
                session_id: "sess-a".into(),
                device_id: "dev-1".into(),
                device_name: "host-1".into(),
                agent_name: "claude-code".into(),
                class: FindingClass::PolicyViolation,
                finding_class_other: None,
                severity: FindingSeverity::Medium,
                lifecycle: FindingLifecycle::Acknowledged,
                rule_id: Some("essentials.credential-stores".into()),
                title: "Approval requested".into(),
                summary: "ssh read".into(),
                target: "~/.ssh/id_rsa".into(),
                detected_at: t1,
            },
            Finding {
                id: "f2".into(),
                session_id: "sess-a".into(),
                device_id: "dev-1".into(),
                device_name: "host-1".into(),
                agent_name: "claude-code".into(),
                class: FindingClass::Tamper,
                finding_class_other: None,
                severity: FindingSeverity::Critical,
                lifecycle: FindingLifecycle::Open,
                rule_id: Some("essentials.agent-control-files".into()),
                title: "Blocked control edit".into(),
                summary: "claude edit".into(),
                target: ".claude/settings.json".into(),
                detected_at: t2,
            },
        ];

        let mut state = SessionRuleState::new("sess-a");
        state.labels.insert(SessionLabel::CredentialAccessed);
        let mut states = BTreeMap::new();
        states.insert("sess-a".into(), state);

        let incidents = correlate_incidents(&findings, &states);
        assert_eq!(incidents.len(), 1);
        let inc = incidents.first().unwrap();
        assert_eq!(inc.finding_count, 2);
        assert_eq!(inc.severity, FindingSeverity::Critical);
        assert_eq!(inc.lifecycle, FindingLifecycle::Open);
        assert_eq!(inc.labels, vec![SessionLabel::CredentialAccessed]);
        assert_eq!(inc.first_seen, t1);
        assert_eq!(inc.last_seen, t2);
        assert_ne!(
            deterministic_incident_id("a-b", "c"),
            deterministic_incident_id("a", "b-c")
        );
    }
}
