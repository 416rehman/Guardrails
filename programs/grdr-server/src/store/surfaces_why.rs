// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_messages::{AgentNoticeInput, AgentVerb, NextStepKind, build_block_card};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{ActionClass, ApprovalState, CodedError, Verdict};
use grdr_proto::api::surfaces::WhyExplanation;
use grdr_strings::{Locale, MessageKey, lookup, sanitize_untrusted_text as sanitize_inert_text};

use super::{AppState, StoreData};

fn action_class_display(action: ActionClass) -> &'static str {
    match action {
        ActionClass::Exec => "Command run",
        ActionClass::FileRead => "File read",
        ActionClass::FileWrite => "File write",
        ActionClass::FileDelete => "File delete",
        ActionClass::NetConnect => "Network connect",
        ActionClass::NetRequest => "Network request",
        ActionClass::LlmRequest => "LLM request",
        ActionClass::McpConnect => "MCP connect",
        ActionClass::McpCall => "Tool call",
        ActionClass::CredUse => "Credential access",
        ActionClass::AgentSpawn => "Agent spawn",
        ActionClass::ConfigChange => "Config change",
        ActionClass::Elevate => "Privilege elevation",
        ActionClass::UiAct => "UI action",
        ActionClass::DataFlow => "Data transfer",
    }
}

fn clean_rule_heading(raw: &str) -> String {
    raw.replace("file.write", "File write")
        .replace("file.read", "File read")
        .replace("file.delete", "File delete")
        .replace("net.connect", "Network connect")
        .replace("net.request", "Network request")
        .replace("mcp.call", "Tool call")
        .replace("cred.use", "Credential access")
        .replace("config.change", "Config change")
        .replace("data.flow", "Data transfer")
        .replace("claude-code", "Claude Code")
        .replace("gemini-cli", "Gemini CLI")
}

pub(crate) fn resolve_rule_meta(
    data: &StoreData,
    rule_id: &str,
    verdict: Verdict,
) -> (String, String) {
    if let Some((pack_id, title)) = data.packs.iter().find_map(|p| {
        p.rules
            .iter()
            .find(|r| r.id == rule_id)
            .map(|r| (p.id.clone(), clean_rule_heading(&r.title)))
    }) {
        return (pack_id, title);
    }
    if let Some(finding_title) = data
        .findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some(rule_id))
        .map(|f| clean_rule_heading(&f.title))
    {
        return ("pack-essentials".to_owned(), finding_title);
    }
    let slug = rule_id
        .rsplit('.')
        .next()
        .unwrap_or(rule_id)
        .replace(['-', '_'], " ");
    let titled = if slug == "baseline activity" || slug == "baseline" {
        match verdict {
            Verdict::Deny | Verdict::StepUp => "Guardrail policy enforcement".to_owned(),
            Verdict::Modify | Verdict::Defer => "Controlled agent action".to_owned(),
            Verdict::Allow => "Routine agent activity".to_owned(),
        }
    } else {
        let mut chars = slug.chars();
        match chars.next() {
            Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
            None => "Policy evaluation".to_owned(),
        }
    };
    ("pack-essentials".to_owned(), titled)
}

impl AppState {
    pub async fn explain_receipt(&self, raw_ref: &str) -> Result<WhyExplanation, CodedError> {
        let needle = raw_ref.trim();
        if needle.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Explanation reference must not be empty.",
                "Supply a receipt, attempt, approval, or finding identifier.",
            ));
        }

        let guard = self.inner.read().await;
        let receipt = guard
            .receipts
            .iter()
            .rev()
            .find(|r| r.receipt_id == needle || r.attempt_id == needle)
            .or_else(|| {
                let apr = guard.approvals.iter().find(|a| a.id == needle)?;
                guard
                    .receipts
                    .iter()
                    .find(|r| r.receipt_id == apr.receipt_id)
            })
            .or_else(|| {
                let finding = guard.findings.iter().find(|f| f.id == needle)?;
                guard.receipts.iter().rev().find(|r| {
                    r.session_id == finding.session_id
                        && (finding.rule_id.is_none() || r.rule_id == finding.rule_id)
                })
            })
            .cloned()
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("No receipt found matching `{needle}`."),
                    "Pick a receipt or verdict event from Home, Sessions, or Respond.",
                )
            })?;

        let attempt = guard
            .attempts
            .iter()
            .find(|a| a.id == receipt.attempt_id)
            .cloned();
        let approval = guard
            .approvals
            .iter()
            .find(|a| a.receipt_id == receipt.receipt_id)
            .cloned();

        let rule_id = receipt
            .rule_id
            .clone()
            .unwrap_or_else(|| "essentials.baseline".to_owned());
        let (pack_id, rule_title) = resolve_rule_meta(&guard, &rule_id, receipt.verdict);

        let target = attempt
            .as_ref()
            .map(|a| a.target.as_str())
            .unwrap_or("target");
        let agent_name = attempt
            .as_ref()
            .map(|a| a.agent_name.clone())
            .unwrap_or_else(|| "AI Agent".to_owned());
        let device_id = attempt
            .as_ref()
            .map(|a| a.device_id.clone())
            .unwrap_or_else(|| "dev-local".to_owned());
        let device_name = attempt
            .as_ref()
            .map(|a| a.device_name.clone())
            .unwrap_or_else(|| "local-endpoint".to_owned());
        let action_class = attempt
            .as_ref()
            .map(|a| action_class_display(a.action_class).to_owned())
            .unwrap_or_else(|| "Action".to_owned());

        let (verb, status_code, next_step, approver_label, action_route) = match receipt.verdict {
            Verdict::Deny => (
                AgentVerb::Blocked,
                "GRDR-DEC-DENY",
                NextStepKind::Blocked,
                None,
                format!("/protect/rules?ruleId={rule_id}"),
            ),
            Verdict::StepUp => {
                let lbl = lookup(Locale::EnUs, MessageKey::ApproverSelf);
                (
                    AgentVerb::Held,
                    "GRDR-DEC-STEPUP",
                    NextStepKind::RetryAfterApproval {
                        approver: lbl.clone(),
                    },
                    Some(lbl),
                    "/respond".to_owned(),
                )
            }
            Verdict::Modify => (
                AgentVerb::Changed,
                "GRDR-DEC-MODIFY",
                NextStepKind::Modified {
                    summary: receipt.reason.clone(),
                },
                None,
                format!("/sessions/trace?sessionId={}", receipt.session_id),
            ),
            Verdict::Defer => (
                AgentVerb::Delayed,
                "GRDR-DEC-DEFER",
                NextStepKind::RetryLater { seconds: 30 },
                None,
                format!("/sessions/trace?sessionId={}", receipt.session_id),
            ),
            Verdict::Allow => (
                AgentVerb::Changed,
                "GRDR-DEC-ALLOW",
                NextStepKind::UseAlternative {
                    steer: "This action matched current policy and proceeded cleanly.".to_owned(),
                },
                None,
                format!("/sessions/trace?sessionId={}", receipt.session_id),
            ),
        };

        let locale = Locale::EnUs;
        let notice = AgentNoticeInput {
            brand: lookup(locale, MessageKey::BrandName),
            verb,
            action_class: action_class.clone(),
            status_code: status_code.to_owned(),
            rule_id: rule_id.clone(),
            reference: receipt.receipt_id.clone(),
            reason: sanitize_inert_text(&receipt.reason),
            next_step,
        };
        let card = build_block_card(locale, verb, &rule_id, &pack_id, target, &notice);
        let heading = match receipt.verdict {
            Verdict::Allow => "Why this was allowed".to_owned(),
            Verdict::Deny | Verdict::StepUp | Verdict::Modify | Verdict::Defer => card.heading,
        };
        let sig_status = if receipt.signature.is_some() && receipt.key_id.is_some() {
            "verified".to_owned()
        } else {
            "unsigned".to_owned()
        };
        let primary_action_label = match (&receipt.verdict, &approval) {
            (Verdict::StepUp, Some(a)) if matches!(a.state, ApprovalState::Pending { .. }) => {
                "Review pending approval".to_owned()
            }
            (Verdict::Deny, _) => "Inspect rule policy".to_owned(),
            _ => "Inspect session trace".to_owned(),
        };

        Ok(WhyExplanation {
            reference: receipt.receipt_id.clone(),
            receipt_id: receipt.receipt_id,
            attempt_id: receipt.attempt_id,
            heading,
            verdict: verdict_label(receipt.verdict).to_owned(),
            status_code: status_code.to_owned(),
            component: card.component,
            action_class,
            rule_id,
            rule_title,
            pack_id,
            agent_name: sanitize_inert_text(&agent_name),
            device_id,
            device_name: sanitize_inert_text(&device_name),
            session_id: receipt.session_id,
            target_quoted: card.target_quoted,
            reason: card.reason,
            agent_told: card.agent_told,
            timestamp: receipt.decided_at.to_string(),
            key_id: receipt.key_id,
            signature_status: sig_status,
            primary_action_label,
            primary_action_route: action_route,
            approval_id: approval.map(|a| a.id),
            approver_label,
        })
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::StepUp => "step_up",
        Verdict::Modify => "modify",
        Verdict::Deny => "deny",
        Verdict::Defer => "defer",
    }
}
