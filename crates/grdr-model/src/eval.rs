// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use crate::domain::{ActionClass, ApprovalGrade, Mode};
use crate::policy::{PolicyPack, PolicyRule, RuleMatch};

const PACK_ESSENTIALS_ID: &str = "pack-essentials-slice0";
const PACK_ESSENTIALS_VERSION: &str = "1.0.0";

pub fn essentials_pack() -> PolicyPack {
    PolicyPack {
        id: PACK_ESSENTIALS_ID.into(),
        name: "Essentials".into(),
        description:
            "Baseline protections for control files, credentials, destructive actions, and egress."
                .into(),
        version: PACK_ESSENTIALS_VERSION.into(),
        channel: "schema-policy".into(),
        rules: essentials_rules(),
        key_id: None,
        signature: None,
    }
}

pub fn essentials_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            id: "essentials.agent-control-files".into(),
            title: "Protect agent and Guardrails control files".into(),
            description: "Stop agent-initiated writes to agent hooks, MCP configs, and security configuration files.".into(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G2,
            enabled: true,
            locked: true,
            matcher: RuleMatch {
                action_classes: vec![
                    ActionClass::FileWrite,
                    ActionClass::FileDelete,
                    ActionClass::ConfigChange,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    ".claude/".into(),
                    ".claude.json".into(),
                    ".cursor/".into(),
                    ".codex/".into(),
                    ".gemini/".into(),
                    "grdr-data/".into(),
                    "security/".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Agents cannot modify agent hook settings or Guardrails control files.".into(),
            cedar: Some(
                r#"@id("essentials.agent-control-files")
@class("config-tamper")
@final("true")
@steer("Do not edit hook, settings or MCP configuration. Ask the user to make this change.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete", Grdr::Action::"config.change"],
  resource
)
when { resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"]) };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.hook-bypass".into(),
            title: "Prevent hook disabling and security bypass flags".into(),
            description: "Block commands that disable hooks, remove verification checks, or bypass sandboxing.".into(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G2,
            enabled: true,
            locked: true,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec],
                target_prefixes: vec![],
                target_contains: vec![
                    "--dangerously-skip-permissions".into(),
                    "--no-verify".into(),
                    "--disable-hooks".into(),
                    "GRDR_DISABLE".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Bypassing security hooks or permission boundaries is blocked by Essentials.".into(),
            cedar: Some(
                r#"@id("essentials.hook-bypass")
@class("config-tamper")
@final("true")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"exec", Grdr::Action::"agent.spawn", Grdr::Action::"config.change"],
  resource
)
when { context.facts.containsAny(["flag.bypass-permissions", "flag.hooks-disabled", "grdr.disable"]) };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.credential-stores".into(),
            title: "Guard credential stores and private keys".into(),
            description: "Require approval before an agent reads SSH keys, cloud credentials, or token caches.".into(),
            mode: Mode::Ask,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![
                    ActionClass::FileRead,
                    ActionClass::CredUse,
                    ActionClass::Exec,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    ".ssh/".into(),
                    ".aws/".into(),
                    ".gnupg/".into(),
                    ".config/gh/".into(),
                    "id_rsa".into(),
                    "id_ed25519".into(),
                    ".env.production".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Reading private keys or credential stores requires an explicit approval grant.".into(),
            cedar: Some(
                r#"@id("essentials.credential-stores")
@class("secret")
@max_mode("Ask")
@approver("self")
@min_grade("G1")
@message("Reading credential stores and private keys needs your approval.")
@steer("If you need a token, use the configured credential helper or ask the user.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.read", Grdr::Action::"cred.use", Grdr::Action::"exec"],
  resource
)
when { resource.classes.containsAny(["cred-store", "private-key"]) };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.destructive-delete".into(),
            title: "Review destructive shell commands".into(),
            description: "Require approval for recursive force deletes, disk wipes, and destructive resets.".into(),
            mode: Mode::Ask,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec, ActionClass::FileDelete],
                target_prefixes: vec![],
                target_contains: vec![
                    "rm -rf".into(),
                    "rm -fr".into(),
                    "Remove-Item -Recurse -Force".into(),
                    "git reset --hard".into(),
                    "mkfs.".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Recursive or irreversible deletion requires human approval.".into(),
            cedar: Some(
                r#"@id("essentials.destructive-delete")
@class("irreversible")
@max_mode("Ask")
@min_grade("G1")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"exec", Grdr::Action::"file.delete"],
  resource
)
when { resource.classes.contains("destructive-delete") };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.privilege-elevation".into(),
            title: "Gate privilege elevation attempts".into(),
            description: "Ask before running sudo, doas, or elevated admin shells from an agent session.".into(),
            mode: Mode::Ask,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![
                    ActionClass::Elevate,
                    ActionClass::Exec,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    "sudo ".into(),
                    "doas ".into(),
                    "runas ".into(),
                    "Start-Process -Verb RunAs".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Privilege elevation from an agent session requires approval.".into(),
            cedar: Some(
                r#"@id("essentials.privilege-elevation")
@class("elevate")
@max_mode("Ask")
@min_grade("G1")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"elevate", Grdr::Action::"exec"],
  resource
)
when { action == Grdr::Action::"elevate" || resource.classes.contains("privilege-elevate") };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.secret-exfil-egress".into(),
            title: "Observe outbound paste and webhook transfers".into(),
            description: "Observe external uploads via curl/Invoke-RestMethod before promoting to Ask or Block.".into(),
            mode: Mode::Watch,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![
                    ActionClass::NetRequest,
                    ActionClass::NetConnect,
                    ActionClass::DataFlow,
                    ActionClass::Exec,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    "curl ".into(),
                    "Invoke-WebRequest".into(),
                    "pastebin".into(),
                    "webhook.site".into(),
                    "transfer.sh".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Unreviewed outbound upload pattern matched telemetry Watch rule.".into(),
            cedar: Some(
                r#"@id("essentials.secret-exfil-egress")
@class("out-of-boundary")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"net.request", Grdr::Action::"net.connect", Grdr::Action::"data.flow", Grdr::Action::"exec"],
  resource
)
when { resource.classes.contains("egress-exfil") };"#
                    .into(),
            ),
        },
        PolicyRule {
            id: "essentials.mcp-unpinned-write".into(),
            title: "Monitor write-capable MCP tool invocations".into(),
            description: "Track external MCP state-mutating calls while baselines build.".into(),
            mode: Mode::Watch,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![
                    ActionClass::McpCall,
                    ActionClass::McpConnect,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    "write".into(),
                    "delete".into(),
                    "push".into(),
                    "create".into(),
                    "execute".into(),
                ],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "State-changing MCP tool invocation matched Watch monitoring rule.".into(),
            cedar: Some(
                r#"@id("essentials.mcp-unpinned-write")
@class("out-of-boundary")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"mcp.call", Grdr::Action::"mcp.connect"],
  resource
)
when { resource.classes.contains("mcp-write") };"#
                    .into(),
            ),
        },
    ]
}

pub fn add_seconds(ts: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_second(ts.as_second().saturating_add(seconds)).unwrap_or(ts)
}

pub use grdr_crypto::sha256_hex;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essentials_pack_ships_seven_cedar_rules() {
        let pack = essentials_pack();
        assert_eq!(pack.rules.len(), 7);
        for rule in &pack.rules {
            let cedar = rule.cedar.as_deref().unwrap_or("");
            assert!(
                cedar.contains("forbid"),
                "rule {} missing Cedar forbid policy",
                rule.id
            );
        }
    }
}
