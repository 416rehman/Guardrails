// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ApprovalGrade, ApprovalRequest, ApprovalState, AuditEntry, CodedError, CreateRuleInput,
    DecideApprovalInput, Finding, Grant, GrantScope, KillAction, KillSwitchInput, KillSwitchState,
    Mode, PolicyRule, ReplaySummary, UpdateFindingInput, UpdateRuleModeInput, slugify_id,
};

use super::AppState;
use super::persistence::persist_snapshot;

impl AppState {
    pub async fn create_rule(&self, input: CreateRuleInput) -> Result<PolicyRule, CodedError> {
        if input.title.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Rule title cannot be empty.",
                "Provide a concise sentence-case title for the rule.",
            ));
        }

        let now = Timestamp::now();
        let pack_id = input
            .pack_id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| "pack-essentials-slice0".into());

        let rule = PolicyRule {
            id: format!("custom.{}", slugify_id(&input.title, 48, "node")),
            title: input.title,
            description: input.description,
            mode: input.mode,
            min_grade: input.min_grade.unwrap_or(ApprovalGrade::G1),
            enabled: input.mode != Mode::Off,
            locked: false,
            matcher: input.matcher,
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: input.reason_template,
        };

        {
            let mut guard = self.inner.write().await;
            let Some(pack) = guard.packs.iter_mut().find(|p| p.id == pack_id) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Policy pack `{pack_id}` was not found."),
                    "Select an existing policy pack.",
                ));
            };
            pack.rules.push(rule.clone());
            let _ = self.signing_key.sign_pack(pack);
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "policy.rule.created".into(),
                    actor: "console-operator".into(),
                    summary: format!(
                        "Created rule `{}` in mode {}",
                        rule.title,
                        rule.mode.label()
                    ),
                    target: rule.id.clone(),
                },
            );
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
        }

        self.emit_live(
            "policy.changed",
            format!("Created rule {} in {} mode", rule.title, rule.mode.label()),
            None,
        );
        Ok(rule)
    }

    pub async fn update_rule_mode(
        &self,
        rule_id: &str,
        input: UpdateRuleModeInput,
    ) -> Result<PolicyRule, CodedError> {
        let now = Timestamp::now();
        let updated = {
            let mut guard = self.inner.write().await;
            let mut found_rule = None;
            for pack in &mut guard.packs {
                if let Some(rule) = pack.rules.iter_mut().find(|r| r.id == rule_id) {
                    if rule.locked && input.mode < rule.mode {
                        return Err(CodedError::new(
                            CODE_CONFLICT,
                            format!(
                                "Locked baseline rule `{}` cannot be weakened below {}.",
                                rule.title,
                                rule.mode.label()
                            ),
                            "Keep Essentials floor rules in Block mode or grant a scoped exception.",
                        ));
                    }
                    let old_mode = rule.mode;
                    rule.mode = input.mode;
                    rule.enabled = input.mode != Mode::Off;
                    found_rule = Some((rule.clone(), old_mode));
                    let _ = self.signing_key.sign_pack(pack);
                    break;
                }
            }
            let Some((rule, old_mode)) = found_rule else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Policy rule `{rule_id}` does not exist."),
                    "Verify the rule id on Protect.",
                ));
            };
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "policy.rule.mode_updated".into(),
                    actor: input.actor.unwrap_or_else(|| "console-operator".into()),
                    summary: format!(
                        "Changed `{}` mode from {} to {}{}",
                        rule.id,
                        old_mode.label(),
                        rule.mode.label(),
                        if input.replay_confirmed.unwrap_or(false) {
                            " (replay verified)"
                        } else {
                            ""
                        }
                    ),
                    target: rule.id.clone(),
                },
            );
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
            rule
        };

        self.emit_live(
            "policy.changed",
            format!("Rule {} set to {}", updated.title, updated.mode.label()),
            None,
        );
        Ok(updated)
    }

    pub async fn replay_rule(
        &self,
        rule_id: &str,
        candidate_mode: Mode,
    ) -> Result<ReplaySummary, CodedError> {
        let guard = self.inner.read().await;
        let rule = guard
            .packs
            .iter()
            .flat_map(|p| p.rules.iter())
            .find(|r| r.id == rule_id)
            .cloned()
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Policy rule `{rule_id}` does not exist."),
                    "Refresh policy rules before replaying.",
                )
            })?;
        Ok(policy::replay_rule(&guard.attempts, &rule, candidate_mode))
    }

    pub async fn decide_approval(
        &self,
        approval_id: &str,
        input: DecideApprovalInput,
    ) -> Result<ApprovalRequest, CodedError> {
        let now = Timestamp::now();
        let actor = input.actor.unwrap_or_else(|| "console-operator".into());
        let note = input.note.unwrap_or_default();
        let scope = input.scope.unwrap_or(GrantScope::Session);

        let updated =
            {
                let mut guard = self.inner.write().await;
                let idx = guard
                    .approvals
                    .iter()
                    .position(|a| a.id == approval_id)
                    .ok_or_else(|| {
                        CodedError::new(
                            CODE_NOT_FOUND,
                            format!("Approval request `{approval_id}` not found."),
                            "Refresh Respond to see current requests.",
                        )
                    })?;

                let req =
                    guard.approvals.get(idx).cloned().ok_or_else(|| {
                        CodedError::new(CODE_NOT_FOUND, "Missing approval", "Retry.")
                    })?;

                match req.state {
                    ApprovalState::Pending { expires_at } if expires_at <= now => {
                        if let Some(slot) = guard.approvals.get_mut(idx) {
                            slot.state = ApprovalState::Expired { expired_at: now };
                        }
                        if let Some(dir) = &self.data_dir {
                            persist_snapshot(dir, &guard)?;
                        }
                        return Err(CodedError::new(
                            CODE_CONFLICT,
                            "This approval request has expired.",
                            "Trigger a new action attempt to request fresh approval.",
                        ));
                    }
                    ApprovalState::Pending { .. } => {}
                    _ => {
                        return Err(CodedError::new(
                            CODE_CONFLICT,
                            "This approval request has already been decided or expired.",
                            "Refresh the queue.",
                        ));
                    }
                }

                let new_state = if input.approve {
                    let grant_id = format!("grn_{}", Uuid::now_v7().simple());
                    let (expires_at, remaining_uses) = match scope {
                        GrantScope::Once => (Some(add_seconds(now, 300)), Some(1)),
                        GrantScope::Session => (Some(add_seconds(now, 14_400)), None),
                        GrantScope::OneHour => (Some(add_seconds(now, 3_600)), None),
                    };
                    let mut grant = Grant {
                        grant_id: grant_id.clone(),
                        rule_id: req.rule_id.clone(),
                        session_id: req.session_id.clone(),
                        device_id: req.device_id.clone(),
                        action_class: req.action_class,
                        target_pattern: req.target.clone(),
                        scope,
                        grade: req.required_grade,
                        granted_at: now,
                        expires_at,
                        remaining_uses,
                        note: note.clone(),
                        key_id: None,
                        signature: None,
                    };
                    let _ = self.signing_key.sign_grant(&mut grant);
                    guard.grants.insert(0, grant);
                    ApprovalState::Approved {
                        grant_id,
                        scope,
                        decided_at: now,
                        note: note.clone(),
                    }
                } else {
                    ApprovalState::Denied {
                        decided_at: now,
                        note: note.clone(),
                    }
                };

                if let Some(slot) = guard.approvals.get_mut(idx) {
                    slot.state = new_state;
                }
                let decided =
                    guard.approvals.get(idx).cloned().ok_or_else(|| {
                        CodedError::new(CODE_NOT_FOUND, "Approval missing", "Retry.")
                    })?;

                guard.audit.insert(
                    0,
                    AuditEntry {
                        id: format!("aud_{}", Uuid::now_v7().simple()),
                        timestamp: now,
                        kind: if input.approve {
                            "approval.granted".into()
                        } else {
                            "approval.denied".into()
                        },
                        actor,
                        summary: format!(
                            "{} `{}` for {}",
                            if input.approve { "Approved" } else { "Denied" },
                            decided.target,
                            decided.agent_name
                        ),
                        target: decided.id.clone(),
                    },
                );

                if let Some(dir) = &self.data_dir {
                    persist_snapshot(dir, &guard)?;
                }
                decided
            };

        self.emit_live(
            "approval.decided",
            format!("Approval {} decided for {}", updated.id, updated.agent_name),
            None,
        );
        Ok(updated)
    }

    pub async fn update_finding(
        &self,
        finding_id: &str,
        input: UpdateFindingInput,
    ) -> Result<Finding, CodedError> {
        let now = Timestamp::now();
        let finding = {
            let mut guard = self.inner.write().await;
            let Some(item) = guard.findings.iter_mut().find(|f| f.id == finding_id) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Finding `{finding_id}` does not exist."),
                    "Refresh Respond to reload findings.",
                ));
            };
            item.lifecycle = input.lifecycle;
            let updated = item.clone();
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "finding.lifecycle_updated".into(),
                    actor: "console-operator".into(),
                    summary: format!(
                        "Updated finding `{}` to {:?}{}",
                        updated.title,
                        updated.lifecycle,
                        input
                            .note
                            .as_deref()
                            .filter(|n| !n.trim().is_empty())
                            .map(|n| format!(": {n}"))
                            .unwrap_or_default()
                    ),
                    target: updated.id.clone(),
                },
            );
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
            updated
        };

        self.emit_live(
            "finding.updated",
            format!("Finding {} marked {:?}", finding.id, finding.lifecycle),
            None,
        );
        Ok(finding)
    }

    pub async fn set_kill_switch(
        &self,
        input: KillSwitchInput,
    ) -> Result<KillSwitchState, CodedError> {
        let now = Timestamp::now();
        let next = match input.action {
            KillAction::Release => KillSwitchState::Inactive,
            KillAction::Freeze => {
                let mins = input.duration_minutes.unwrap_or(60).max(1);
                let secs = mins.saturating_mul(60);
                KillSwitchState::Frozen {
                    scope: input.scope,
                    target_id: input.target_id,
                    reason: input.reason,
                    issued_at: now,
                    expires_at: add_seconds(now, secs),
                }
            }
            KillAction::Kill => KillSwitchState::Killed {
                scope: input.scope,
                target_id: input.target_id,
                reason: input.reason,
                issued_at: now,
            },
        };

        {
            let mut guard = self.inner.write().await;
            guard.kill_switch = next.clone();
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "kill_switch.updated".into(),
                    actor: "console-operator".into(),
                    summary: format!("Updated kill switch state: {next:?}"),
                    target: "kill-switch".into(),
                },
            );
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
        }

        self.emit_live(
            "kill_switch.updated",
            "Kill switch state updated".into(),
            None,
        );
        Ok(next)
    }
}
