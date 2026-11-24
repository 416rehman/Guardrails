// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::HashMap;

use serde::Serialize;

use grdr_model::{ActionAttempt, DecisionReceipt, Finding, FindingSeverity, Incident, Verdict};

use crate::store::StoreData;

const OCSF_VERSION: &str = "1.9.0";

#[derive(Debug, Serialize)]
pub struct OcsfProduct {
    pub name: &'static str,
    pub vendor_name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OcsfMetadata {
    pub version: &'static str,
    pub uid: String,
    pub event_code: String,
    pub product: OcsfProduct,
}

#[derive(Debug, Serialize)]
pub struct OcsfActorSession {
    pub uid: String,
}

#[derive(Debug, Serialize)]
pub struct OcsfActor {
    pub app_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<OcsfActorSession>,
}

#[derive(Debug, Serialize)]
pub struct OcsfDevice {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OcsfApiService {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct OcsfApiRequest {
    pub uid: String,
}

#[derive(Debug, Serialize)]
pub struct OcsfApi {
    pub operation: String,
    pub request: OcsfApiRequest,
    pub service: OcsfApiService,
}

#[derive(Debug, Serialize)]
pub struct OcsfResource {
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OcsfFindingInfo {
    pub uid: String,
    pub title: String,
    pub desc: String,
}

#[derive(Debug, Serialize)]
pub struct OcsfUnmapped {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OcsfEvent {
    pub class_uid: u16,
    pub class_name: &'static str,
    pub category_uid: u8,
    pub category_name: &'static str,
    pub activity_id: u8,
    pub activity_name: &'static str,
    pub type_uid: u32,
    pub time: i64,
    pub time_dt: String,
    pub severity_id: u8,
    pub severity: &'static str,
    pub status_id: u8,
    pub status_code: String,
    pub status_detail: String,
    pub metadata: OcsfMetadata,
    pub device: OcsfDevice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<OcsfActor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<OcsfApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_info: Option<OcsfFindingInfo>,
    pub resources: Vec<OcsfResource>,
    pub unmapped: OcsfUnmapped,
}

#[derive(Debug, Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum AuditJsonlRecord<'a> {
    DecisionReceipt {
        receipt: &'a DecisionReceipt,
        attempt_summary: Option<&'a str>,
    },
    Incident {
        incident: &'a Incident,
    },
    AuditEntry {
        entry: &'a grdr_model::AuditEntry,
    },
}

pub fn build_ocsf_events(data: &StoreData) -> Vec<OcsfEvent> {
    let receipts_by_attempt: HashMap<&str, &DecisionReceipt> = data
        .receipts
        .iter()
        .map(|r| (r.attempt_id.as_str(), r))
        .collect();

    let mut events = Vec::with_capacity(data.attempts.len().saturating_add(data.findings.len()));

    for attempt in &data.attempts {
        let receipt = receipts_by_attempt.get(attempt.id.as_str()).copied();
        events.push(attempt_to_ocsf(attempt, receipt));
    }
    for finding in &data.findings {
        events.push(finding_to_ocsf(finding));
    }
    events
}

pub fn build_audit_jsonl(data: &StoreData, incidents: &[Incident]) -> String {
    let summary_by_attempt: HashMap<&str, &str> = data
        .attempts
        .iter()
        .map(|a| (a.id.as_str(), a.summary.as_str()))
        .collect();

    let mut lines = Vec::with_capacity(
        data.receipts
            .len()
            .saturating_add(incidents.len())
            .saturating_add(data.audit.len()),
    );

    for receipt in &data.receipts {
        let record = AuditJsonlRecord::DecisionReceipt {
            receipt,
            attempt_summary: summary_by_attempt.get(receipt.attempt_id.as_str()).copied(),
        };
        if let Ok(line) = serde_json::to_string(&record) {
            lines.push(line);
        }
    }

    for incident in incidents {
        let record = AuditJsonlRecord::Incident { incident };
        if let Ok(line) = serde_json::to_string(&record) {
            lines.push(line);
        }
    }

    for entry in &data.audit {
        let record = AuditJsonlRecord::AuditEntry { entry };
        if let Ok(line) = serde_json::to_string(&record) {
            lines.push(line);
        }
    }

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn attempt_to_ocsf(attempt: &ActionAttempt, receipt: Option<&DecisionReceipt>) -> OcsfEvent {
    let verdict = receipt.map(|r| r.verdict);
    let (severity_id, severity, status_id, status_code, status_detail) = match verdict {
        Some(Verdict::Deny) => (
            4,
            "High",
            2,
            "DENY",
            receipt.map(|r| r.reason.clone()).unwrap_or_default(),
        ),
        Some(Verdict::StepUp) => (
            3,
            "Medium",
            2,
            "STEP_UP",
            receipt.map(|r| r.reason.clone()).unwrap_or_default(),
        ),
        Some(Verdict::Defer) => (
            3,
            "Medium",
            2,
            "DEFER",
            receipt.map(|r| r.reason.clone()).unwrap_or_default(),
        ),
        Some(Verdict::Modify) => (
            2,
            "Low",
            1,
            "MODIFY",
            receipt.map(|r| r.reason.clone()).unwrap_or_default(),
        ),
        Some(Verdict::Allow) | None => (
            1,
            "Informational",
            1,
            "ALLOW",
            receipt
                .map(|r| r.reason.clone())
                .unwrap_or_else(|| attempt.summary.clone()),
        ),
    };

    OcsfEvent {
        class_uid: 6003,
        class_name: "API Activity",
        category_uid: 6,
        category_name: "Application Activity",
        activity_id: 1,
        activity_name: "Create",
        type_uid: 600301,
        time: attempt.timestamp.as_millisecond(),
        time_dt: attempt.timestamp.to_string(),
        severity_id,
        severity,
        status_id,
        status_code: status_code.to_string(),
        status_detail,
        metadata: OcsfMetadata {
            version: OCSF_VERSION,
            uid: attempt.id.clone(),
            event_code: attempt.action_class.as_str().to_string(),
            product: OcsfProduct {
                name: "Guardrails ADR",
                vendor_name: "Guardrails",
                version: env!("CARGO_PKG_VERSION"),
            },
        },
        device: OcsfDevice {
            uid: attempt.device_id.clone(),
            hostname: Some(attempt.device_name.clone()),
        },
        actor: Some(OcsfActor {
            app_name: attempt.agent_name.clone(),
            session: Some(OcsfActorSession {
                uid: attempt.session_id.clone(),
            }),
        }),
        api: Some(OcsfApi {
            operation: attempt.action_class.as_str().to_string(),
            request: OcsfApiRequest {
                uid: attempt.id.clone(),
            },
            service: OcsfApiService {
                name: format!("{:?}", attempt.control_point).to_lowercase(),
            },
        }),
        finding_info: None,
        resources: vec![OcsfResource {
            name: attempt.target.clone(),
            resource_type: "agent_action_target",
        }],
        unmapped: OcsfUnmapped {
            receipt_id: receipt.map(|r| r.receipt_id.clone()),
            receipt_digest: receipt.map(|r| r.receipt_digest.clone()),
            rule_id: receipt.and_then(|r| r.rule_id.clone()),
            key_id: receipt.and_then(|r| r.key_id.clone()),
            lifecycle: None,
        },
    }
}

fn finding_to_ocsf(finding: &Finding) -> OcsfEvent {
    let (severity_id, severity) = match finding.severity {
        FindingSeverity::Critical => (5, "Critical"),
        FindingSeverity::High => (4, "High"),
        FindingSeverity::Medium => (3, "Medium"),
        FindingSeverity::Low => (2, "Low"),
    };

    OcsfEvent {
        class_uid: 2004,
        class_name: "Detection Finding",
        category_uid: 2,
        category_name: "Findings",
        activity_id: 1,
        activity_name: "Create",
        type_uid: 200401,
        time: finding.detected_at.as_millisecond(),
        time_dt: finding.detected_at.to_string(),
        severity_id,
        severity,
        status_id: 1,
        status_code: format!("{:?}", finding.lifecycle).to_lowercase(),
        status_detail: finding.summary.clone(),
        metadata: OcsfMetadata {
            version: OCSF_VERSION,
            uid: finding.id.clone(),
            event_code: format!("{:?}", finding.class).to_lowercase(),
            product: OcsfProduct {
                name: "Guardrails ADR",
                vendor_name: "Guardrails",
                version: env!("CARGO_PKG_VERSION"),
            },
        },
        device: OcsfDevice {
            uid: finding.device_id.clone(),
            hostname: Some(finding.device_name.clone()),
        },
        actor: Some(OcsfActor {
            app_name: finding.agent_name.clone(),
            session: Some(OcsfActorSession {
                uid: finding.session_id.clone(),
            }),
        }),
        api: None,
        finding_info: Some(OcsfFindingInfo {
            uid: finding.id.clone(),
            title: finding.title.clone(),
            desc: finding.summary.clone(),
        }),
        resources: vec![OcsfResource {
            name: finding.target.clone(),
            resource_type: "detection_target",
        }],
        unmapped: OcsfUnmapped {
            receipt_id: None,
            receipt_digest: None,
            rule_id: finding.rule_id.clone(),
            key_id: None,
            lifecycle: Some(format!("{:?}", finding.lifecycle).to_lowercase()),
        },
    }
}
