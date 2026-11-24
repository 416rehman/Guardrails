mod generated;

pub use generated::{GENERATED_BRAND_NAME, PresentedValue, present_enum};
use grdr_strings::{Locale, MessageKey, lookup, sanitize_untrusted_text};
use serde::{Deserialize, Serialize};

/// Maximum UTF-8 scalar count permitted for agent-facing notices (`design/28` section 11).
pub const MAX_AGENT_MESSAGE_CHARS: usize = 600;

/// Verdict verb rendered into the agent-facing three-line notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentVerb {
    Blocked,
    Held,
    Changed,
    Delayed,
}

impl AgentVerb {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Held => "held",
            Self::Changed => "changed",
            Self::Delayed => "delayed",
        }
    }
}

/// Every registered next-step guidance kind (`design/28` section 11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NextStepKind {
    RetryAfterApproval { approver: String },
    UseAlternative { steer: String },
    Blocked,
    Snoozed { until_time: String },
    Frozen,
    OfflineRule,
    RetryLater { seconds: u32 },
    Modified { summary: String },
}

impl NextStepKind {
    /// Formats the deterministic plain-English instruction line sent to the calling agent.
    #[must_use]
    pub fn format_english(&self, brand: &str) -> String {
        match self {
            Self::RetryAfterApproval { approver } => format!(
                "Approval was requested from {approver}. Do not try a different command, path or tool to reach the same result. When you are told it was approved, retry the identical call once."
            ),
            Self::UseAlternative { steer } => sanitize_untrusted_text(steer),
            Self::Blocked => {
                "This is not allowed here. Do not retry or work around it. Tell the user what you were trying to do.".to_owned()
            }
            Self::Snoozed { until_time } => format!(
                "The user has paused approval requests until {until_time}. Continue with other work, or stop and tell the user."
            ),
            Self::Frozen => {
                "This session is frozen after repeated refused requests. Stop and tell the user."
                    .to_owned()
            }
            Self::OfflineRule => format!(
                "{brand} is using its offline rule set. Tell the user to run grdr doctor."
            ),
            Self::RetryLater { seconds } => format!("Retry in {seconds} seconds."),
            Self::Modified { summary } => format!(
                "This call was changed before it ran: {}. Do not resend the original.",
                sanitize_untrusted_text(summary)
            ),
        }
    }
}

/// Inputs for constructing an agent-facing plain-English decision notice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNoticeInput {
    pub brand: String,
    pub verb: AgentVerb,
    pub action_class: String,
    pub status_code: String,
    pub rule_id: String,
    pub reference: String,
    pub reason: String,
    pub next_step: NextStepKind,
}

/// Renders the exact 3-line plain-English agent notice capped at 600 chars with zero Markdown/links.
#[must_use]
pub fn format_agent_message(input: &AgentNoticeInput) -> String {
    let brand = sanitize_untrusted_text(&input.brand);
    let verb = input.verb.as_str();
    let action_class = sanitize_untrusted_text(&input.action_class);
    let status_code = sanitize_untrusted_text(&input.status_code);
    let rule_id = sanitize_untrusted_text(&input.rule_id);
    let reference = sanitize_untrusted_text(&input.reference);
    let reason = sanitize_untrusted_text(&input.reason);
    let next = input.next_step.format_english(&brand);

    let full = format!(
        "{brand} {verb} this {action_class} [{status_code}; rule {rule_id}; ref {reference}].\nReason: {reason}\nNext: {next}"
    );
    truncate_chars(&full, MAX_AGENT_MESSAGE_CHARS)
}

/// Person-facing structured explanation card rendered across Home, Activity, and `grdr why`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCard {
    pub heading: String,
    pub component: String,
    pub rule_id: String,
    pub pack_id: String,
    pub target_quoted: String,
    pub reason: String,
    pub agent_told: String,
    pub primary_action_label: String,
}

#[must_use]
pub fn build_block_card(
    locale: Locale,
    verdict_verb: AgentVerb,
    rule_id: &str,
    pack_id: &str,
    target: &str,
    notice: &AgentNoticeInput,
) -> BlockCard {
    let key = match verdict_verb {
        AgentVerb::Blocked => MessageKey::WhyBlocked,
        AgentVerb::Held => MessageKey::WhyStepUp,
        AgentVerb::Changed => MessageKey::WhyModified,
        AgentVerb::Delayed => MessageKey::WhyDelayed,
    };
    let primary_action_label = match notice.next_step {
        NextStepKind::RetryAfterApproval { .. } => "Review approval".to_owned(),
        NextStepKind::UseAlternative { .. } | NextStepKind::Blocked => {
            "Request exception".to_owned()
        }
        NextStepKind::Modified { .. } => "Inspect change".to_owned(),
        _ => "Check health".to_owned(),
    };
    BlockCard {
        heading: lookup(locale, key),
        component: lookup(locale, MessageKey::BrandName),
        rule_id: rule_id.to_owned(),
        pack_id: pack_id.to_owned(),
        target_quoted: sanitize_untrusted_text(target),
        reason: notice.reason.clone(),
        agent_told: format_agent_message(notice),
        primary_action_label,
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in text.chars().take(max_chars) {
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exact_three_line_agent_notice_under_cap() {
        let input = AgentNoticeInput {
            brand: "Guardrails ADR".to_owned(),
            verb: AgentVerb::Held,
            action_class: "file.read".to_owned(),
            status_code: "GRDR-DEC-STEPUP".to_owned(),
            rule_id: "essentials.cred-store.read".to_owned(),
            reference: "7Q2MK-X4D9PJ".to_owned(),
            reason: "Reading credential stores needs explicit approval.".to_owned(),
            next_step: NextStepKind::RetryAfterApproval {
                approver: "You".to_owned(),
            },
        };
        let rendered = format_agent_message(&input);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(rendered.chars().count() <= MAX_AGENT_MESSAGE_CHARS);
        assert!(rendered.contains("ref 7Q2MK-X4D9PJ"));
    }

    #[test]
    fn caps_long_agent_notices_at_600_chars() {
        let input = AgentNoticeInput {
            brand: "Guardrails ADR".to_owned(),
            verb: AgentVerb::Blocked,
            action_class: "exec".to_owned(),
            status_code: "GRDR-DEC-DENY".to_owned(),
            rule_id: "r1".to_owned(),
            reference: "ref-1".to_owned(),
            reason: "x".repeat(800),
            next_step: NextStepKind::Blocked,
        };
        let rendered = format_agent_message(&input);
        assert_eq!(rendered.chars().count(), MAX_AGENT_MESSAGE_CHARS);
    }
}
