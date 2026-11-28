// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::ActionClass;

use crate::es_eval::{
    EsAuthAction, EsAuthDecision, EsCoordinatorRuntime, EsGovernanceEvaluation, FloorEvaluator,
    eval_floor,
};
use crate::es_tree::{EsAuditToken, EsClientConcern};
use crate::seatbelt::canonicalize_macos_path;

impl EsCoordinatorRuntime {
    pub(crate) fn eval_self_protection(
        &self,
        actor: &EsAuditToken,
        target_pid: u32,
        action_class: ActionClass,
    ) -> EsGovernanceEvaluation {
        let tracked = self.tree.lookup_member(actor.key);
        let session_id = tracked.map(|m| m.session_id.clone());
        if !self.is_self_pid(target_pid) {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class,
                governed_member: tracked.is_some(),
                session_id,
                matched_rule_id: None,
                unmuted_target: None,
            };
        }
        // Design doc 09: allow non-agent root admin/launchd signal/uninstall while surfacing tamper alert.
        if actor.uid == 0 && tracked.is_none() {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::AllowWithTamperAlert,
                action_class,
                governed_member: false,
                session_id: None,
                matched_rule_id: Some("macos.es.self_protection.root_tamper".to_string()),
                unmuted_target: None,
            };
        }
        EsGovernanceEvaluation {
            decision: EsAuthDecision::Deny,
            action_class,
            governed_member: tracked.is_some(),
            session_id,
            matched_rule_id: Some("macos.es.self_protection.deny".to_string()),
            unmuted_target: None,
        }
    }

    pub(crate) fn eval_self_protection_path(
        &self,
        actor: &EsAuditToken,
        target_paths: &[&str],
        action_class: ActionClass,
        write_requested: bool,
    ) -> EsGovernanceEvaluation {
        let tracked = self.tree.lookup_member(actor.key);
        let session_id = tracked.map(|m| m.session_id.clone());
        let touches_self_path = target_paths.iter().any(|p| self.is_self_path(p));
        let touches_protected_path = target_paths.iter().any(|p| self.is_protected_path(p));
        if !touches_self_path && !touches_protected_path {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class,
                governed_member: tracked.is_some(),
                session_id,
                matched_rule_id: None,
                unmuted_target: None,
            };
        }

        if action_class == ActionClass::FileRead && !write_requested && !touches_protected_path {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class,
                governed_member: tracked.is_some(),
                session_id,
                matched_rule_id: None,
                unmuted_target: None,
            };
        }

        if actor.uid == 0 && tracked.is_none() {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::AllowWithTamperAlert,
                action_class,
                governed_member: false,
                session_id: None,
                matched_rule_id: Some("macos.es.self_protection.root_tamper".to_string()),
                unmuted_target: None,
            };
        }

        EsGovernanceEvaluation {
            decision: EsAuthDecision::Deny,
            action_class,
            governed_member: tracked.is_some(),
            session_id,
            matched_rule_id: Some("macos.es.self_protection.path_deny".to_string()),
            unmuted_target: None,
        }
    }

    pub(crate) fn dispatch_self_protection(
        &self,
        actor: &EsAuditToken,
        action: EsAuthAction<'_>,
    ) -> EsGovernanceEvaluation {
        match action {
            EsAuthAction::SelfSignal { target_pid }
            | EsAuthAction::SelfGetTask { target_pid }
            | EsAuthAction::SelfSuspend { target_pid } => {
                self.eval_self_protection(actor, target_pid, ActionClass::Elevate)
            }
            EsAuthAction::FileOpen {
                target_path,
                write_requested,
            } => {
                let class = if write_requested {
                    ActionClass::FileWrite
                } else {
                    ActionClass::FileRead
                };
                self.eval_self_protection_path(actor, &[target_path], class, write_requested)
            }
            EsAuthAction::FileUnlink { target_path } => {
                self.eval_self_protection_path(actor, &[target_path], ActionClass::FileDelete, true)
            }
            EsAuthAction::FileRename {
                source_path,
                dest_path,
            } => self.eval_self_protection_path(
                actor,
                &[source_path, dest_path],
                ActionClass::FileWrite,
                true,
            ),
            other => {
                self.eval_self_protection_path(actor, &[], action_class_for_auth(&other), false)
            }
        }
    }

    pub(crate) fn eval_protected_paths(
        &self,
        actor: &EsAuditToken,
        raw_paths: &[&str],
        action_class: ActionClass,
        floor: FloorEvaluator<'_>,
        default_deny: bool,
        write_requested: bool,
    ) -> EsGovernanceEvaluation {
        let member = self.tree.lookup_member(actor.key);
        let session_id = member.map(|m| m.session_id.clone());
        let protected = raw_paths.iter().any(|p| self.is_protected_path(p));
        let touches_self = raw_paths.iter().any(|p| self.is_self_path(p));
        if touches_self && (write_requested || action_class != ActionClass::FileRead || protected) {
            return self.eval_self_protection_path(actor, raw_paths, action_class, write_requested);
        }
        if member.is_none() && !protected {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class,
                governed_member: false,
                session_id: None,
                matched_rule_id: None,
                unmuted_target: None,
            };
        }

        let agent = session_id
            .as_deref()
            .map(|s| self.agent_for_session(s))
            .unwrap_or("");
        let fast_class = match action_class {
            ActionClass::FileRead => FastActionClass::FileRead,
            ActionClass::FileDelete => FastActionClass::FileDelete,
            ActionClass::NetConnect => FastActionClass::NetConnect,
            _ => FastActionClass::FileWrite,
        };

        let mut allow_rule: Option<String> = None;
        for raw_path in raw_paths {
            let canon = canonicalize_macos_path(raw_path);
            if let Some((rule, verdict)) = eval_floor(&floor, fast_class, agent, &canon) {
                match verdict {
                    FastVerdict::Deny | FastVerdict::StepUp => {
                        return EsGovernanceEvaluation {
                            decision: EsAuthDecision::Deny,
                            action_class,
                            governed_member: member.is_some(),
                            session_id,
                            matched_rule_id: Some(rule),
                            unmuted_target: None,
                        };
                    }
                    FastVerdict::Allow if allow_rule.is_none() => allow_rule = Some(rule),
                    FastVerdict::Allow => {}
                }
            }
        }
        if protected && (member.is_some() || actor.uid != 0) {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Deny,
                action_class,
                governed_member: member.is_some(),
                session_id,
                matched_rule_id: Some("macos.es.protected_path_guard".to_string()),
                unmuted_target: None,
            };
        }
        if let Some(rule) = allow_rule {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class,
                governed_member: member.is_some(),
                session_id,
                matched_rule_id: Some(rule),
                unmuted_target: None,
            };
        }

        let decision = if member.is_some() && default_deny {
            EsAuthDecision::Deny
        } else {
            EsAuthDecision::Allow {
                should_cache: false,
            }
        };
        EsGovernanceEvaluation {
            decision,
            action_class,
            governed_member: member.is_some(),
            session_id,
            matched_rule_id: None,
            unmuted_target: None,
        }
    }

    pub(crate) fn eval_deadline_cutoff(
        &mut self,
        concern: EsClientConcern,
        actor: &EsAuditToken,
        action: EsAuthAction<'_>,
        floor: FloorEvaluator<'_>,
    ) -> EsGovernanceEvaluation {
        if concern == EsClientConcern::SelfProtection
            || matches!(
                action,
                EsAuthAction::SelfSignal { .. }
                    | EsAuthAction::SelfGetTask { .. }
                    | EsAuthAction::SelfSuspend { .. }
            )
        {
            return self.dispatch_self_protection(actor, action);
        }

        if let EsAuthAction::Exec {
            old_key,
            target,
            executable_path,
        } = action
        {
            return self.eval_auth_exec_with_budget(
                old_key,
                target,
                executable_path,
                floor,
                false,
                false,
                true,
            );
        }

        let strict = self.evaluate_auth_event_with_concern(
            concern,
            actor,
            action,
            floor,
            false,
            0,
            u64::MAX,
            false,
        );
        if matches!(
            strict.decision,
            EsAuthDecision::Deny | EsAuthDecision::AllowWithTamperAlert
        ) {
            return strict;
        }
        EsGovernanceEvaluation {
            decision: EsAuthDecision::Allow {
                should_cache: false,
            },
            action_class: strict.action_class,
            governed_member: strict.governed_member,
            session_id: strict.session_id,
            matched_rule_id: strict
                .matched_rule_id
                .or_else(|| Some("macos.es.deadline_cutoff_allow".to_string())),
            unmuted_target: strict.unmuted_target,
        }
    }
}

pub(crate) fn path_in_set(set: &BTreeSet<String>, raw_path: &str) -> bool {
    let canon = canonicalize_macos_path(raw_path);
    if canon.is_empty() {
        return false;
    }
    set.iter().any(|p| {
        canon == *p
            || canon
                .strip_prefix(p.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

pub(crate) const fn action_class_for_auth(action: &EsAuthAction<'_>) -> ActionClass {
    match action {
        EsAuthAction::Exec { .. } => ActionClass::Exec,
        EsAuthAction::FileOpen {
            write_requested, ..
        } => {
            if *write_requested {
                ActionClass::FileWrite
            } else {
                ActionClass::FileRead
            }
        }
        EsAuthAction::FileCreate { .. }
        | EsAuthAction::FileTruncate { .. }
        | EsAuthAction::FileLink { .. }
        | EsAuthAction::FileClone { .. }
        | EsAuthAction::FileRename { .. } => ActionClass::FileWrite,
        EsAuthAction::FileUnlink { .. } => ActionClass::FileDelete,
        EsAuthAction::UipcConnect { .. } => ActionClass::NetConnect,
        EsAuthAction::SelfSignal { .. }
        | EsAuthAction::SelfGetTask { .. }
        | EsAuthAction::SelfSuspend { .. } => ActionClass::Elevate,
    }
}
