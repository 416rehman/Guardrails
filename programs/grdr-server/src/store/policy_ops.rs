// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{
    ApprovalGrade, AuditEntry, CodedError, CreateRuleInput, Mode, PolicyRule, ReplaySummary,
    UpdateRuleInput, UpdateRuleModeInput, slugify_id,
};

use super::AppState;

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

        let mut rule = PolicyRule {
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
            cedar: None,
        };
        let cedar_source = match input.cedar.filter(|s| !s.trim().is_empty()) {
            Some(custom) => custom,
            None => policy::render_rule_cedar(&rule),
        };
        policy::validate_cedar_rule(&cedar_source).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("Invalid Cedar rule policy: {err}"),
                "Fix the Cedar policy syntax or schema types before saving.",
            )
        })?;
        rule.cedar = Some(cedar_source);

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
            self.persist_store(&guard)?;
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
            self.persist_store(&guard)?;
            rule
        };

        self.emit_live(
            "policy.changed",
            format!("Rule {} set to {}", updated.title, updated.mode.label()),
            None,
        );
        Ok(updated)
    }

    pub async fn update_rule(
        &self,
        rule_id: &str,
        input: UpdateRuleInput,
    ) -> Result<PolicyRule, CodedError> {
        if let Some(title) = &input.title
            && title.trim().is_empty()
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Rule title cannot be empty.",
                "Provide a concise sentence-case title for the rule.",
            ));
        }

        let now = Timestamp::now();
        let updated = {
            let mut guard = self.inner.write().await;
            let mut found = None;
            for pack in &mut guard.packs {
                if let Some(rule) = pack.rules.iter_mut().find(|r| r.id == rule_id) {
                    if rule.locked {
                        return Err(CodedError::new(
                            CODE_CONFLICT,
                            format!("Locked baseline rule `{}` cannot be edited.", rule.title),
                            "Clone or create a custom rule instead of modifying floor rules.",
                        ));
                    }
                    if let Some(title) = input.title {
                        rule.title = title;
                    }
                    if let Some(description) = input.description {
                        rule.description = description;
                    }
                    if let Some(mode) = input.mode {
                        rule.mode = mode;
                        rule.enabled = mode != Mode::Off;
                    }
                    if let Some(min_grade) = input.min_grade {
                        rule.min_grade = min_grade;
                    }
                    let matcher_updated = input.matcher.is_some();
                    if let Some(matcher) = input.matcher {
                        rule.matcher = matcher;
                    }
                    if let Some(reason_template) = input.reason_template {
                        rule.reason_template = reason_template;
                    }
                    if let Some(cedar_src) = input.cedar.filter(|s| !s.trim().is_empty()) {
                        policy::validate_cedar_rule(&cedar_src).map_err(|err| {
                            CodedError::new(
                                CODE_INVALID_INPUT,
                                format!("Invalid Cedar rule policy: {err}"),
                                "Fix the Cedar policy syntax or schema types before saving.",
                            )
                        })?;
                        rule.cedar = Some(cedar_src);
                    } else if rule.cedar.is_none() || matcher_updated {
                        let rendered = policy::render_rule_cedar(rule);
                        policy::validate_cedar_rule(&rendered).map_err(|err| {
                            CodedError::new(
                                CODE_INVALID_INPUT,
                                format!("Invalid Cedar rule policy: {err}"),
                                "Verify rule action classes and matcher targets.",
                            )
                        })?;
                        rule.cedar = Some(rendered);
                    }
                    let cloned = rule.clone();
                    let _ = self.signing_key.sign_pack(pack);
                    found = Some(cloned);
                    break;
                }
            }
            let Some(rule) = found else {
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
                    kind: "policy.rule.updated".into(),
                    actor: input.actor.unwrap_or_else(|| "console-operator".into()),
                    summary: format!("Updated rule `{}`", rule.title),
                    target: rule.id.clone(),
                },
            );
            self.persist_store(&guard)?;
            rule
        };

        self.emit_live(
            "policy.changed",
            format!("Updated rule {}", updated.title),
            None,
        );
        Ok(updated)
    }

    pub async fn delete_rule(&self, rule_id: &str) -> Result<PolicyRule, CodedError> {
        let now = Timestamp::now();
        let removed = {
            let mut guard = self.inner.write().await;
            let mut deleted = None;
            for pack in &mut guard.packs {
                if let Some(idx) = pack.rules.iter().position(|r| r.id == rule_id) {
                    if let Some(rule) = pack.rules.get(idx)
                        && rule.locked
                    {
                        return Err(CodedError::new(
                            CODE_CONFLICT,
                            format!("Locked baseline rule `{}` cannot be deleted.", rule.title),
                            "Baseline floor rules are locked; switch unlocked custom rules instead.",
                        ));
                    }
                    let rule = pack.rules.remove(idx);
                    let _ = self.signing_key.sign_pack(pack);
                    deleted = Some(rule);
                    break;
                }
            }
            let Some(rule) = deleted else {
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
                    kind: "policy.rule.deleted".into(),
                    actor: "console-operator".into(),
                    summary: format!("Deleted rule `{}`", rule.title),
                    target: rule.id.clone(),
                },
            );
            self.persist_store(&guard)?;
            rule
        };

        self.emit_live(
            "policy.changed",
            format!("Deleted rule {}", removed.title),
            None,
        );
        Ok(removed)
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
}
