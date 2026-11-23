// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::{ApprovalGrade, KillSwitchState, Mode, Verdict};
use crate::policy::{ActionAttempt, DecisionReceipt, Grant, PolicyPack, PolicyRule, RuleMatch};

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
                    crate::domain::ActionClass::FileWrite,
                    crate::domain::ActionClass::FileDelete,
                    crate::domain::ActionClass::ConfigChange,
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
                action_classes: vec![crate::domain::ActionClass::Exec],
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
                    crate::domain::ActionClass::FileRead,
                    crate::domain::ActionClass::CredUse,
                    crate::domain::ActionClass::Exec,
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
                action_classes: vec![crate::domain::ActionClass::Exec, crate::domain::ActionClass::FileDelete],
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
                    crate::domain::ActionClass::Elevate,
                    crate::domain::ActionClass::Exec,
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
                    crate::domain::ActionClass::NetRequest,
                    crate::domain::ActionClass::NetConnect,
                    crate::domain::ActionClass::DataFlow,
                    crate::domain::ActionClass::Exec,
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
                    crate::domain::ActionClass::McpCall,
                    crate::domain::ActionClass::McpConnect,
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
        },
    ]
}

pub fn rule_matches(rule: &PolicyRule, attempt: &ActionAttempt) -> bool {
    if !rule.enabled || rule.mode == Mode::Off {
        return false;
    }
    if !rule.matcher.action_classes.is_empty()
        && !rule.matcher.action_classes.contains(&attempt.action_class)
    {
        return false;
    }
    if !rule.matcher.agents.is_empty()
        && !rule
            .matcher
            .agents
            .iter()
            .any(|agent| attempt.agent_name.eq_ignore_ascii_case(agent))
    {
        return false;
    }
    let normalized_target = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let has_prefix_filters = !rule.matcher.target_prefixes.is_empty();
    let has_contains_filters = !rule.matcher.target_contains.is_empty();
    if !has_prefix_filters && !has_contains_filters {
        return true;
    }
    let prefix_hit = rule.matcher.target_prefixes.iter().any(|prefix| {
        let p = prefix.replace('\\', "/").to_ascii_lowercase();
        normalized_target.starts_with(&p)
    });
    let contains_hit = rule.matcher.target_contains.iter().any(|needle| {
        let n = needle.replace('\\', "/").to_ascii_lowercase();
        !n.is_empty() && normalized_target.contains(&n)
    });
    prefix_hit || contains_hit
}

pub fn evaluate_attempt(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &[Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> DecisionReceipt {
    let receipt_id = format!("rcp_{}", Uuid::now_v7().simple());
    if kill_switch.is_active_for(&attempt.session_id, &attempt.device_id, now) {
        let reason = match kill_switch {
            KillSwitchState::Frozen { reason, .. } => format!("Session frozen: {reason}"),
            KillSwitchState::Killed { reason, .. } => format!("Kill switch active: {reason}"),
            KillSwitchState::Inactive => String::new(),
        };
        let digest = compute_receipt_digest(attempt, Verdict::Deny, Some("kill-switch"), now);
        return DecisionReceipt {
            receipt_id,
            attempt_id: attempt.id.clone(),
            session_id: attempt.session_id.clone(),
            device_id: attempt.device_id.clone(),
            agent_name: attempt.agent_name.clone(),
            action_class: attempt.action_class,
            control_point: attempt.control_point,
            target: attempt.target.clone(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("system.kill-switch".into()),
            pack_id: Some("system".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason,
            next_step: "Release the freeze or kill switch on the Respond screen once investigated."
                .into(),
            receipt_digest: digest,
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };
    }

    let mut matched_rules: Vec<(&PolicyPack, &PolicyRule)> = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if rule_matches(rule, attempt) {
                matched_rules.push((pack, rule));
            }
        }
    }

    matched_rules.sort_by_key(|left| std::cmp::Reverse(left.1.mode));

    let Some((pack, rule)) = matched_rules.first().copied() else {
        let digest = compute_receipt_digest(attempt, Verdict::Allow, None, now);
        return DecisionReceipt {
            receipt_id,
            attempt_id: attempt.id.clone(),
            session_id: attempt.session_id.clone(),
            device_id: attempt.device_id.clone(),
            agent_name: attempt.agent_name.clone(),
            action_class: attempt.action_class,
            control_point: attempt.control_point,
            target: attempt.target.clone(),
            verdict: Verdict::Allow,
            would_be: None,
            rule_id: None,
            pack_id: None,
            mode_applied: None,
            grant_id: None,
            reason: "No policy rule restricted this action.".into(),
            next_step: "No action needed.".into(),
            receipt_digest: digest,
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };
    };

    if rule.mode == Mode::Block {
        let digest = compute_receipt_digest(attempt, Verdict::Deny, Some(&rule.id), now);
        return DecisionReceipt {
            receipt_id,
            attempt_id: attempt.id.clone(),
            session_id: attempt.session_id.clone(),
            device_id: attempt.device_id.clone(),
            agent_name: attempt.agent_name.clone(),
            action_class: attempt.action_class,
            control_point: attempt.control_point,
            target: attempt.target.clone(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some(rule.id.clone()),
            pack_id: Some(pack.id.clone()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason: rule.reason_template.clone(),
            next_step: "Choose a workspace-safe path or ask an administrator for an exception."
                .into(),
            receipt_digest: digest,
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };
    }

    if rule.mode == Mode::Ask {
        if let Some(grant) = grants
            .iter()
            .find(|g| g.rule_id == rule.id && g.matches(attempt, now))
        {
            let digest = compute_receipt_digest(attempt, Verdict::Allow, Some(&rule.id), now);
            return DecisionReceipt {
                receipt_id,
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: attempt.control_point,
                target: attempt.target.clone(),
                verdict: Verdict::Allow,
                would_be: Some(Verdict::StepUp),
                rule_id: Some(rule.id.clone()),
                pack_id: Some(pack.id.clone()),
                mode_applied: Some(Mode::Ask),
                grant_id: Some(grant.grant_id.clone()),
                reason: format!("Allowed by active approval grant {}.", grant.grant_id),
                next_step: "Action permitted within grant expiry window.".into(),
                receipt_digest: digest,
                decided_at: now,
                key_id: None,
                signature: None,
                signature_verified: None,
            };
        }
        let digest = compute_receipt_digest(attempt, Verdict::StepUp, Some(&rule.id), now);
        return DecisionReceipt {
            receipt_id,
            attempt_id: attempt.id.clone(),
            session_id: attempt.session_id.clone(),
            device_id: attempt.device_id.clone(),
            agent_name: attempt.agent_name.clone(),
            action_class: attempt.action_class,
            control_point: attempt.control_point,
            target: attempt.target.clone(),
            verdict: Verdict::StepUp,
            would_be: None,
            rule_id: Some(rule.id.clone()),
            pack_id: Some(pack.id.clone()),
            mode_applied: Some(Mode::Ask),
            grant_id: None,
            reason: rule.reason_template.clone(),
            next_step: "Approve the pending request in Respond, then retry.".into(),
            receipt_digest: digest,
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };
    }

    let digest = compute_receipt_digest(attempt, Verdict::Allow, Some(&rule.id), now);
    DecisionReceipt {
        receipt_id,
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict: Verdict::Allow,
        would_be: Some(Verdict::StepUp),
        rule_id: Some(rule.id.clone()),
        pack_id: Some(pack.id.clone()),
        mode_applied: Some(Mode::Watch),
        grant_id: None,
        reason: rule.reason_template.clone(),
        next_step: "Run replay on Protect to decide whether to promote this rule to Ask.".into(),
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

pub fn evaluate_attempt_mut(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    grants: &mut [Grant],
    kill_switch: &KillSwitchState,
    now: Timestamp,
) -> DecisionReceipt {
    let receipt = evaluate_attempt(attempt, packs, grants, kill_switch, now);
    if let Some(grant_id) = receipt.grant_id.as_deref()
        && let Some(grant) = grants.iter_mut().find(|g| g.grant_id == grant_id)
    {
        grant.consume_use();
    }
    receipt
}

pub fn add_seconds(ts: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_second(ts.as_second().saturating_add(seconds)).unwrap_or(ts)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn compute_receipt_digest(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    now: Timestamp,
) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{:?}:{}",
        attempt.session_id,
        attempt.agent_name,
        attempt.action_class.as_str(),
        attempt.target,
        verdict,
        rule_id.unwrap_or("none")
    );
    let seeded = format!("{payload}:{}", now.as_second());
    sha256_hex(seeded.as_bytes())
}

fn hex_nibble(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActionClass, ControlPoint, GrantScope, KillScope};

    fn sample_attempt(class: ActionClass, target: &str) -> ActionAttempt {
        ActionAttempt {
            id: "att-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "workstation".into(),
            agent_name: "claude-code".into(),
            action_class: class,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        }
    }

    #[test]
    fn essentials_blocks_control_files_and_steps_up_keys() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];

        let write_hook = evaluate_attempt(
            &sample_attempt(ActionClass::FileWrite, ".claude/settings.json"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(write_hook.verdict, Verdict::Deny);
        assert_eq!(
            write_hook.rule_id.as_deref(),
            Some("essentials.agent-control-files")
        );

        let read_ssh = evaluate_attempt(
            &sample_attempt(ActionClass::FileRead, "/home/dev/.ssh/id_rsa"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(read_ssh.verdict, Verdict::StepUp);
        assert_eq!(
            read_ssh.rule_id.as_deref(),
            Some("essentials.credential-stores")
        );
    }

    #[test]
    fn grant_allows_matching_step_up_until_expired() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let grant = Grant {
            grant_id: "grn_1".into(),
            rule_id: "essentials.credential-stores".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            action_class: ActionClass::FileRead,
            target_pattern: "/home/dev/.ssh/id_rsa".into(),
            scope: GrantScope::Session,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: Some(add_seconds(now, 60)),
            remaining_uses: None,
            note: "Approved test read".into(),
            key_id: None,
            signature: None,
        };
        let allowed = evaluate_attempt(
            &sample_attempt(ActionClass::FileRead, "/home/dev/.ssh/id_rsa"),
            &packs,
            std::slice::from_ref(&grant),
            &KillSwitchState::Inactive,
            add_seconds(now, 10),
        );
        assert_eq!(allowed.verdict, Verdict::Allow);
        assert_eq!(allowed.grant_id.as_deref(), Some("grn_1"));

        let expired = evaluate_attempt(
            &sample_attempt(ActionClass::FileRead, "/home/dev/.ssh/id_rsa"),
            &packs,
            &[grant],
            &KillSwitchState::Inactive,
            add_seconds(now, 120),
        );
        assert_eq!(expired.verdict, Verdict::StepUp);
    }

    #[test]
    fn once_grant_allows_single_use_then_steps_up() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let mut grants = vec![Grant {
            grant_id: "grn_once".into(),
            rule_id: "essentials.credential-stores".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            action_class: ActionClass::FileRead,
            target_pattern: "/home/dev/.ssh/id_rsa".into(),
            scope: GrantScope::Once,
            grade: ApprovalGrade::G1,
            granted_at: now,
            expires_at: Some(add_seconds(now, 300)),
            remaining_uses: Some(1),
            note: "Single use".into(),
            key_id: None,
            signature: None,
        }];

        let attempt = sample_attempt(ActionClass::FileRead, "/home/dev/.ssh/id_rsa");
        let first = evaluate_attempt_mut(
            &attempt,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(first.verdict, Verdict::Allow);
        assert_eq!(first.grant_id.as_deref(), Some("grn_once"));
        assert_eq!(grants.first().and_then(|g| g.remaining_uses), Some(0));

        let second = evaluate_attempt_mut(
            &attempt,
            &packs,
            &mut grants,
            &KillSwitchState::Inactive,
            add_seconds(now, 5),
        );
        assert_eq!(second.verdict, Verdict::StepUp);
        assert!(second.grant_id.is_none());
    }

    #[test]
    fn kill_switch_overrides_allow() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let packs = vec![essentials_pack()];
        let ks = KillSwitchState::Killed {
            scope: KillScope::Device,
            target_id: "dev-1".into(),
            reason: "Containment test".into(),
            issued_at: now,
        };
        let safe_read = evaluate_attempt(
            &sample_attempt(ActionClass::Exec, "git status"),
            &packs,
            &[],
            &ks,
            now,
        );
        assert_eq!(safe_read.verdict, Verdict::Deny);
        assert_eq!(safe_read.rule_id.as_deref(), Some("system.kill-switch"));
    }
}
