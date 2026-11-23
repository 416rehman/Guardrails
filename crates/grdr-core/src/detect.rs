// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use uuid::Uuid;

use grdr_model::{
    DecisionReceipt, Finding, FindingClass, FindingLifecycle, FindingSeverity, Mode, Verdict,
};

use crate::analyze::classify_target;

pub fn finding_from_receipt(receipt: &DecisionReceipt, device_name: &str) -> Option<Finding> {
    let analysis = classify_target(receipt.action_class, &receipt.target);
    let is_tamper = analysis
        .risk_tags
        .iter()
        .any(|tag| tag == "agent-control-file" || tag == "hook-bypass");

    match receipt.verdict {
        Verdict::Deny => Some(Finding {
            id: format!("fnd_{}", Uuid::now_v7().simple()),
            session_id: receipt.session_id.clone(),
            device_id: receipt.device_id.clone(),
            device_name: device_name.into(),
            agent_name: receipt.agent_name.clone(),
            class: if is_tamper {
                FindingClass::Tamper
            } else {
                FindingClass::PolicyViolation
            },
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
            id: format!("fnd_{}", Uuid::now_v7().simple()),
            session_id: receipt.session_id.clone(),
            device_id: receipt.device_id.clone(),
            device_name: device_name.into(),
            agent_name: receipt.agent_name.clone(),
            class: FindingClass::PolicyViolation,
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
                id: format!("fnd_{}", Uuid::now_v7().simple()),
                session_id: receipt.session_id.clone(),
                device_id: receipt.device_id.clone(),
                device_name: device_name.into(),
                agent_name: receipt.agent_name.clone(),
                class: FindingClass::Threat,
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
