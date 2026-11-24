use clap::Parser;
use grdr_strings::sanitize_untrusted_text;
use serde::{Deserialize, Serialize};

/// Ethical friction arming intervals from `design/28` section 15.
pub const ARM_DEFAULT_MS: u64 = 1000;
pub const ARM_IRREVERSIBLE_MS: u64 = 2000;

#[derive(Debug, Parser)]
#[command(name = "grdr-approve", about = "Guardrails OS-native approval helper")]
struct Cli {
    /// Preview canonical approval prompt payload as JSON
    #[arg(long)]
    preview: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "apr-demo-01")]
    request_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredGrade {
    G0Click,
    G1UserPresence,
    G2StepUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    ApproveAction,
    RequestException,
    ConfirmWidening,
    ConfirmJoinTeam,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptInput<'a> {
    pub request_id: &'a str,
    pub kind: ApprovalKind,
    pub title: &'a str,
    pub rule_id: &'a str,
    pub agent_name: &'a str,
    pub action_class: &'a str,
    pub raw_target: &'a str,
    pub required_grade: RequiredGrade,
    pub irreversible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalApprovalPrompt {
    pub request_id: String,
    pub kind: ApprovalKind,
    pub title: String,
    pub rule_id: String,
    pub agent_name: String,
    pub action_class: String,
    pub quoted_target: String,
    pub required_grade: RequiredGrade,
    pub arming_delay_ms: u64,
    pub irreversible: bool,
}

#[must_use]
pub fn build_prompt(input: PromptInput<'_>) -> CanonicalApprovalPrompt {
    CanonicalApprovalPrompt {
        request_id: sanitize_untrusted_text(input.request_id),
        kind: input.kind,
        title: sanitize_untrusted_text(input.title),
        rule_id: sanitize_untrusted_text(input.rule_id),
        agent_name: sanitize_untrusted_text(input.agent_name),
        action_class: sanitize_untrusted_text(input.action_class),
        quoted_target: sanitize_untrusted_text(input.raw_target),
        required_grade: input.required_grade,
        arming_delay_ms: if input.irreversible {
            ARM_IRREVERSIBLE_MS
        } else {
            ARM_DEFAULT_MS
        },
        irreversible: input.irreversible,
    }
}

fn main() {
    let cli = Cli::parse();
    let prompt = build_prompt(PromptInput {
        request_id: &cli.request_id,
        kind: ApprovalKind::ApproveAction,
        title: "Guard credential stores and private keys",
        rule_id: "essentials.cred-store.read",
        agent_name: "Claude Code",
        action_class: "file.read",
        raw_target: "~/.ssh/id_ed25519",
        required_grade: RequiredGrade::G1UserPresence,
        irreversible: false,
    });
    if cli.preview && cli.json {
        if let Ok(json) = serde_json::to_string_pretty(&prompt) {
            println!("{json}");
        }
    } else {
        println!(
            "[grdr-approve] {} ({:?}, {}ms arming): {}",
            prompt.title, prompt.required_grade, prompt.arming_delay_ms, prompt.quoted_target
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_untrusted_controls_and_applies_ethical_friction_delay() {
        let p = build_prompt(PromptInput {
            request_id: "apr-99",
            kind: ApprovalKind::ConfirmWidening,
            title: "Lower secret protection rule",
            rule_id: "essentials.cred-store.read",
            agent_name: "agent",
            action_class: "config.change",
            raw_target: "~/.aws/credentials\u{202E}evil",
            required_grade: RequiredGrade::G2StepUp,
            irreversible: true,
        });
        assert_eq!(p.arming_delay_ms, ARM_IRREVERSIBLE_MS);
        assert!(!p.quoted_target.contains('\u{202E}'));
    }
}
