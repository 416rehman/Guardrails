// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use crate::domain::{ActionClass, ApprovalGrade, Mode};
use crate::policy::{PolicyPack, PolicyRule, RuleMatch};

use serde::{Deserialize, Serialize};

pub use grdr_crypto::{SigningKeypair, sha256_hex};

const PACK_ESSENTIALS_ID: &str = "pack-essentials-slice0";
const PACK_ESSENTIALS_VERSION: &str = "1.0.0";
const MAX_HOLD_DEADLINE_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationKind {
    Receipt,
    Expect,
    Snapshot,
    PinRecorder,
    NotifyUser,
    NotifySponsor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    RedactSecrets,
    WrapLauncher,
    SwapCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheScope {
    Bundle,
    Session,
    Call,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayBucket {
    Matched,
    AlmostMatched,
    NotMatched,
    NotEvaluable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourBucketSummary {
    pub matched: u64,
    pub almost_matched: u64,
    pub not_matched: u64,
    pub not_evaluable: u64,
    pub watch_days: u32,
    pub median_prompts_per_dev_day: u32,
    pub p95_prompts_per_dev_day: u32,
    pub promotion_ready: bool,
}

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
                action_classes: vec![
                    ActionClass::Exec,
                    ActionClass::AgentSpawn,
                    ActionClass::ConfigChange,
                ],
                target_prefixes: vec![],
                target_contains: vec![
                    "--dangerously-skip-permissions".into(),
                    "--no-verify".into(),
                    "--disable-hooks".into(),
                    "--no-sandbox".into(),
                    "--disable-sandbox".into(),
                    "--yolo".into(),
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
when { context.facts.containsAny(["flag.bypass-permissions", "flag.hooks-disabled", "flag.no-sandbox", "grdr.disable"]) };"#
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

pub fn is_essentials_rule_id(rule_id: &str) -> bool {
    rule_id.starts_with("essentials.") || rule_id.starts_with("system.")
}

/// Floors the hold deadline to 80% of the host timeout and bounds by both ceiling and requested duration.
pub fn capped_hold_deadline_ms(host_deadline_ms: u64, requested_ms: u64) -> u64 {
    (host_deadline_ms.saturating_mul(4) / 5)
        .min(MAX_HOLD_DEADLINE_MS)
        .min(requested_ms)
}

/// Evaluates whether a Watch rule meets the 7-day replay promotion gate against developer prompt budgets.
pub fn promotion_gate_passes(
    watched_days: u32,
    median_prompts: u32,
    p95_prompts: u32,
    median_limit: u32,
    p95_limit: u32,
) -> bool {
    watched_days >= 7 && median_prompts <= median_limit && p95_prompts <= p95_limit
}

fn split_lexical_root(slash: &str) -> Option<(String, &str)> {
    if let Some(unc_tail) = slash.strip_prefix("//") {
        let (srv, after_srv) = unc_tail.split_once('/')?;
        if srv.is_empty() {
            return None;
        }
        let (share, rest) = match after_srv.split_once('/') {
            Some((s, r)) => (s, r),
            None => (after_srv, ""),
        };
        if share.is_empty() {
            return None;
        }
        if srv == "?" && share.eq_ignore_ascii_case("UNC") {
            let (u_srv, after_u_srv) = rest.split_once('/')?;
            let (u_share, u_rest) = match after_u_srv.split_once('/') {
                Some((s, r)) => (s, r),
                None => (after_u_srv, ""),
            };
            if u_srv.is_empty() || u_share.is_empty() {
                return None;
            }
            return Some((format!("//{srv}/{share}/{u_srv}/{u_share}/"), u_rest));
        }
        return Some((format!("//{srv}/{share}/"), rest));
    }
    if let Some(rest) = slash.strip_prefix('/') {
        return Some(("/".into(), rest));
    }
    if let Some(rest) = slash.strip_prefix("~/") {
        return Some(("~/".into(), rest));
    }
    if slash == "~" {
        return Some(("~/".into(), ""));
    }
    if slash.starts_with('~') {
        let (user, rest) = slash.split_once('/').unwrap_or((slash, ""));
        return Some((format!("{user}/"), rest));
    }
    let mut chars = slash.chars();
    if let (Some(drive), Some(':')) = (chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
    {
        let root_len = if chars.next() == Some('/') { 3 } else { 2 };
        if let (Some(root), Some(rest)) = (slash.get(..root_len), slash.get(root_len..)) {
            return Some((root.to_owned(), rest));
        }
    }
    Some((String::new(), slash))
}

pub(crate) fn normalize_lexical_grant_path(path: &str) -> Option<String> {
    let slash = path.replace('\\', "/");
    let (root, body) = split_lexical_root(&slash)?;
    let mut parts: Vec<&str> = Vec::new();
    for seg in body.split('/') {
        if seg == ".." {
            if parts.is_empty() {
                return None;
            }
            let _ = parts.pop();
        } else if !seg.is_empty() && seg != "." {
            parts.push(seg);
        }
    }
    let joined = parts.join("/");
    Some(format!("{root}{joined}"))
}

fn has_url_traversal(url_lower: &str) -> bool {
    let authority_end = url_lower.find("://").map_or(0, |i| i.saturating_add(3));
    let tail = url_lower.get(authority_end..).unwrap_or("");
    let path_only = tail.split(['?', '#']).next().unwrap_or("");
    let path_start = path_only
        .find('/')
        .and_then(|i| path_only.get(i..))
        .unwrap_or("");
    path_start
        .split('/')
        .any(|seg| matches!(seg, ".." | "%2e%2e" | ".%2e" | "%2e."))
}

pub(crate) fn target_pattern_matches(
    action_class: ActionClass,
    pattern: &str,
    target: &str,
) -> bool {
    if pattern == "*" {
        return true;
    }
    if matches!(
        action_class,
        ActionClass::FileRead
            | ActionClass::FileWrite
            | ActionClass::FileDelete
            | ActionClass::ConfigChange
    ) {
        let (Some(np), Some(nt)) = (
            normalize_lexical_grant_path(pattern.trim()),
            normalize_lexical_grant_path(target.trim()),
        ) else {
            return false;
        };
        let trimmed = np.trim_end_matches('/');
        return nt == np
            || (!trimmed.is_empty()
                && nt.strip_prefix(trimmed).is_some_and(|r| r.starts_with('/')));
    }
    if matches!(
        action_class,
        ActionClass::NetRequest | ActionClass::NetConnect
    ) {
        let p = pattern.trim().trim_end_matches('/').to_ascii_lowercase();
        let t = target.trim().trim_end_matches('/').to_ascii_lowercase();
        if p.is_empty() || p.ends_with(':') || has_url_traversal(&t) {
            return false;
        }
        return t == p
            || t.strip_prefix(&p)
                .is_some_and(|r| r.starts_with('/') || r.starts_with('?'));
    }
    pattern.trim() == target.trim()
}

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

    #[test]
    fn capped_hold_floors_by_five_and_promotion_gate_enforces_seven_days() {
        assert_eq!(capped_hold_deadline_ms(6, 100), 4);
        assert_eq!(capped_hold_deadline_ms(1, 100), 0);
        assert_eq!(
            capped_hold_deadline_ms(u64::MAX, 50_000),
            MAX_HOLD_DEADLINE_MS
        );
        assert!(!promotion_gate_passes(6, 1, 2, 3, 8));
        assert!(promotion_gate_passes(7, 3, 8, 3, 8));
        assert!(!promotion_gate_passes(7, 4, 8, 3, 8));
    }
}
