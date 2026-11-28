// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_fastpath::{
    BinaryFloorTable, FastActionClass, FastVerdict, FloorRuleRef, PRINCIPAL_PROCESS,
    PRINCIPAL_SESSION, evaluate_floor_entries,
};
use grdr_model::ActionClass;

use crate::es_clients::{EsClientSetState, check_full_client_budget};
use crate::es_eval_self::path_in_set;
use crate::es_tree::{
    EsAuditToken, EsClientConcern, EsEventPayload, EsTreeFollower, ProcessTreeKey,
};
use crate::seatbelt::canonicalize_macos_path;

const MAX_PROTECTED_PATHS: usize = 512;
const MAX_SELF_PATHS: usize = 128;
const MAX_SELF_PIDS: usize = 64;
const MAX_SESSION_AGENTS: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsAuthDecision {
    Allow { should_cache: bool },
    AllowWithTamperAlert,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsAuthAction<'a> {
    Exec {
        old_key: ProcessTreeKey,
        target: &'a EsAuditToken,
        executable_path: &'a str,
    },
    FileOpen {
        target_path: &'a str,
        write_requested: bool,
    },
    FileCreate {
        target_path: &'a str,
    },
    FileTruncate {
        target_path: &'a str,
    },
    FileLink {
        source_path: &'a str,
        dest_path: &'a str,
    },
    FileClone {
        source_path: &'a str,
        dest_path: &'a str,
    },
    FileUnlink {
        target_path: &'a str,
    },
    FileRename {
        source_path: &'a str,
        dest_path: &'a str,
    },
    UipcConnect {
        socket_path: &'a str,
    },
    SelfSignal {
        target_pid: u32,
    },
    SelfGetTask {
        target_pid: u32,
    },
    SelfSuspend {
        target_pid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsGovernanceEvaluation {
    pub decision: EsAuthDecision,
    pub action_class: ActionClass,
    pub governed_member: bool,
    pub session_id: Option<String>,
    pub matched_rule_id: Option<String>,
    pub unmuted_target: Option<ProcessTreeKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsNotifyEventKind {
    Sudo,
    Su,
    AuthorizationPetition,
    AuthorizationJudgement,
    TccModify,
    BtmLaunchItemAdd,
    UipcConnect,
    XpcConnect,
    Create,
    Rename,
    Unlink,
    BootstrapLookup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsNotifyEventRecord {
    pub actor: ProcessTreeKey,
    pub kind: EsNotifyEventKind,
    pub target: String,
    pub action_class: ActionClass,
    pub governed_session: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EsCoordinatorRuntime {
    pub tree: EsTreeFollower,
    pub clients: EsClientSetState,
    session_agents: BTreeMap<String, String>,
    protected_paths: BTreeSet<String>,
    self_paths: BTreeSet<String>,
    self_pids: BTreeSet<u32>,
}

pub enum FloorEvaluator<'a> {
    Rules(&'a [FloorRuleRef<'a>]),
    Binary(&'a BinaryFloorTable<'a>),
}

impl EsCoordinatorRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_session_agent(
        &mut self,
        session_id: impl Into<String>,
        agent_name: impl Into<String>,
    ) {
        let sid = session_id.into();
        let agent = agent_name.into();
        if sid.is_empty() || agent.is_empty() {
            return;
        }
        if !self.session_agents.contains_key(&sid)
            && self.session_agents.len() >= MAX_SESSION_AGENTS
            && let Some(oldest) = self.session_agents.keys().next().cloned()
        {
            self.session_agents.remove(&oldest);
        }
        self.session_agents.insert(sid, agent);
    }

    pub fn add_protected_path(&mut self, raw_path: &str) {
        let canon = canonicalize_macos_path(raw_path);
        if canon.is_empty() || self.protected_paths.len() >= MAX_PROTECTED_PATHS {
            return;
        }
        self.protected_paths.insert(canon);
    }

    pub fn add_self_path(&mut self, raw_path: &str) {
        let canon = canonicalize_macos_path(raw_path);
        if canon.is_empty() || self.self_paths.len() >= MAX_SELF_PATHS {
            return;
        }
        self.self_paths.insert(canon);
    }

    pub fn register_self_pid(&mut self, pid: u32) {
        if pid > 0 && self.self_pids.len() < MAX_SELF_PIDS {
            self.self_pids.insert(pid);
        }
    }

    pub fn agent_for_session(&self, session_id: &str) -> &str {
        self.session_agents
            .get(session_id)
            .map(String::as_str)
            .unwrap_or("")
    }

    pub fn is_protected_path(&self, raw_path: &str) -> bool {
        path_in_set(&self.protected_paths, raw_path)
    }

    pub fn is_self_path(&self, raw_path: &str) -> bool {
        path_in_set(&self.self_paths, raw_path)
    }

    pub(crate) fn is_self_pid(&self, pid: u32) -> bool {
        self.self_pids.contains(&pid)
    }

    pub fn evaluate_auth_event(
        &mut self,
        actor: &EsAuditToken,
        action: EsAuthAction<'_>,
        floor: FloorEvaluator<'_>,
        default_deny: bool,
        elapsed_ms: u64,
        kernel_deadline_ms: u64,
    ) -> EsGovernanceEvaluation {
        let concern = default_concern_for_action(&action);
        self.evaluate_auth_event_with_concern(
            concern,
            actor,
            action,
            floor,
            default_deny,
            elapsed_ms,
            kernel_deadline_ms,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_auth_event_for_concern(
        &mut self,
        concern: EsClientConcern,
        actor: &EsAuditToken,
        action: EsAuthAction<'_>,
        floor: FloorEvaluator<'_>,
        default_deny: bool,
        elapsed_ms: u64,
        kernel_deadline_ms: u64,
    ) -> EsGovernanceEvaluation {
        self.evaluate_auth_event_with_concern(
            concern,
            actor,
            action,
            floor,
            default_deny,
            elapsed_ms,
            kernel_deadline_ms,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_auth_event_with_concern(
        &mut self,
        concern: EsClientConcern,
        actor: &EsAuditToken,
        action: EsAuthAction<'_>,
        floor: FloorEvaluator<'_>,
        default_deny: bool,
        elapsed_ms: u64,
        kernel_deadline_ms: u64,
        immutable_cdhash: bool,
    ) -> EsGovernanceEvaluation {
        if !check_full_client_budget(elapsed_ms, kernel_deadline_ms) {
            return self.eval_deadline_cutoff(concern, actor, action, floor);
        }
        if concern == EsClientConcern::SelfProtection {
            return self.dispatch_self_protection(actor, action);
        }

        match action {
            EsAuthAction::SelfSignal { target_pid }
            | EsAuthAction::SelfGetTask { target_pid }
            | EsAuthAction::SelfSuspend { target_pid } => {
                self.eval_self_protection(actor, target_pid, ActionClass::Elevate)
            }
            EsAuthAction::Exec {
                old_key,
                target,
                executable_path,
            } => self.eval_auth_exec_with_budget(
                old_key,
                target,
                executable_path,
                floor,
                default_deny,
                immutable_cdhash,
                false,
            ),
            EsAuthAction::FileOpen {
                target_path,
                write_requested,
            } => {
                let class = if write_requested {
                    ActionClass::FileWrite
                } else {
                    ActionClass::FileRead
                };
                self.eval_protected_paths(
                    actor,
                    &[target_path],
                    class,
                    floor,
                    default_deny,
                    write_requested,
                )
            }
            EsAuthAction::FileCreate { target_path }
            | EsAuthAction::FileTruncate { target_path } => self.eval_protected_paths(
                actor,
                &[target_path],
                ActionClass::FileWrite,
                floor,
                default_deny,
                true,
            ),
            EsAuthAction::FileLink {
                source_path,
                dest_path,
            }
            | EsAuthAction::FileClone {
                source_path,
                dest_path,
            }
            | EsAuthAction::FileRename {
                source_path,
                dest_path,
            } => self.eval_protected_paths(
                actor,
                &[source_path, dest_path],
                ActionClass::FileWrite,
                floor,
                default_deny,
                true,
            ),
            EsAuthAction::FileUnlink { target_path } => self.eval_protected_paths(
                actor,
                &[target_path],
                ActionClass::FileDelete,
                floor,
                default_deny,
                true,
            ),
            EsAuthAction::UipcConnect { socket_path } => self.eval_protected_paths(
                actor,
                &[socket_path],
                ActionClass::NetConnect,
                floor,
                default_deny,
                false,
            ),
        }
    }

    pub fn normalize_notify_event(
        &self,
        actor: ProcessTreeKey,
        kind: EsNotifyEventKind,
        target: impl Into<String>,
    ) -> EsNotifyEventRecord {
        let action_class = match kind {
            EsNotifyEventKind::Sudo
            | EsNotifyEventKind::Su
            | EsNotifyEventKind::AuthorizationPetition
            | EsNotifyEventKind::AuthorizationJudgement => ActionClass::Elevate,
            EsNotifyEventKind::TccModify | EsNotifyEventKind::BtmLaunchItemAdd => {
                ActionClass::ConfigChange
            }
            EsNotifyEventKind::Create | EsNotifyEventKind::Rename => ActionClass::FileWrite,
            EsNotifyEventKind::Unlink => ActionClass::FileDelete,
            EsNotifyEventKind::UipcConnect
            | EsNotifyEventKind::XpcConnect
            | EsNotifyEventKind::BootstrapLookup => ActionClass::NetConnect,
        };
        let governed_session = self.tree.lookup_member(actor).map(|m| m.session_id.clone());
        EsNotifyEventRecord {
            actor,
            kind,
            target: target.into(),
            action_class,
            governed_session,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_auth_exec_with_budget(
        &mut self,
        old_key: ProcessTreeKey,
        target: &EsAuditToken,
        executable_path: &str,
        floor: FloorEvaluator<'_>,
        default_deny: bool,
        immutable_cdhash: bool,
        deadline_tight: bool,
    ) -> EsGovernanceEvaluation {
        let payload = EsEventPayload::AuthExec {
            old_key,
            target: target.clone(),
            executable_path: executable_path.to_string(),
        };
        let outcome = self.tree.apply_event(&payload);
        let unmuted_target = outcome.unmuted_targets.first().copied();
        let Some(sid) = outcome.session_id else {
            return EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class: ActionClass::Exec,
                governed_member: false,
                session_id: None,
                matched_rule_id: deadline_tight
                    .then(|| "macos.es.deadline_cutoff_allow".to_string()),
                unmuted_target: None,
            };
        };
        let agent = self.agent_for_session(&sid);
        let hit = eval_floor(&floor, FastActionClass::Exec, agent, executable_path);
        match hit {
            Some((rule, FastVerdict::Deny | FastVerdict::StepUp)) => {
                self.tree
                    .record_denied_auth_exec(target.key, &sid, executable_path, &rule);
                EsGovernanceEvaluation {
                    decision: EsAuthDecision::Deny,
                    action_class: ActionClass::Exec,
                    governed_member: true,
                    session_id: Some(sid),
                    matched_rule_id: Some(rule),
                    unmuted_target,
                }
            }
            Some((rule, FastVerdict::Allow)) => {
                let global_allow = immutable_cdhash
                    && is_global_floor_allow(&floor, FastActionClass::Exec, executable_path);
                EsGovernanceEvaluation {
                    decision: EsAuthDecision::Allow {
                        should_cache: global_allow && !deadline_tight,
                    },
                    action_class: ActionClass::Exec,
                    governed_member: true,
                    session_id: Some(sid),
                    matched_rule_id: Some(rule),
                    unmuted_target,
                }
            }
            None if default_deny && !deadline_tight => {
                self.tree.record_denied_auth_exec(
                    target.key,
                    &sid,
                    executable_path,
                    "default_deny",
                );
                EsGovernanceEvaluation {
                    decision: EsAuthDecision::Deny,
                    action_class: ActionClass::Exec,
                    governed_member: true,
                    session_id: Some(sid),
                    matched_rule_id: Some("macos.es.default_deny".to_string()),
                    unmuted_target,
                }
            }
            None => EsGovernanceEvaluation {
                decision: EsAuthDecision::Allow {
                    should_cache: false,
                },
                action_class: ActionClass::Exec,
                governed_member: true,
                session_id: Some(sid),
                matched_rule_id: deadline_tight
                    .then(|| "macos.es.deadline_cutoff_allow".to_string()),
                unmuted_target,
            },
        }
    }
}

const fn default_concern_for_action(action: &EsAuthAction<'_>) -> EsClientConcern {
    match action {
        EsAuthAction::Exec { .. } => EsClientConcern::ExecAuthorizer,
        EsAuthAction::SelfSignal { .. }
        | EsAuthAction::SelfGetTask { .. }
        | EsAuthAction::SelfSuspend { .. } => EsClientConcern::SelfProtection,
        _ => EsClientConcern::ProtectedPathGuard,
    }
}

pub(crate) fn eval_floor(
    floor: &FloorEvaluator<'_>,
    action: FastActionClass,
    agent: &str,
    target: &str,
) -> Option<(String, FastVerdict)> {
    match floor {
        FloorEvaluator::Rules(refs) => evaluate_floor_entries(refs, action, agent, target)
            .map(|h| (h.rule_id.to_string(), h.verdict)),
        FloorEvaluator::Binary(table) => table
            .evaluate(
                action,
                PRINCIPAL_SESSION | PRINCIPAL_PROCESS,
                0,
                agent,
                target,
            )
            .map(|h| (h.rule_id.to_string(), h.verdict)),
    }
}

fn is_global_floor_allow(
    floor: &FloorEvaluator<'_>,
    action: FastActionClass,
    target: &str,
) -> bool {
    matches!(
        eval_floor(floor, action, "", target),
        Some((_, FastVerdict::Allow))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_fastpath::{BinaryRuleInput, encode_binary_floor};

    #[test]
    fn enforces_self_protection_protected_paths_and_deadline_budget() {
        let mut rt = EsCoordinatorRuntime::new();
        rt.register_self_pid(777);
        rt.add_protected_path("/var/db/grdr/keys");
        rt.add_self_path("/Library/Application Support/Guardrails");
        rt.register_session_agent("sess-es-1", "claude-code");

        let root_key = ProcessTreeKey {
            pid: 500,
            pidversion: 1,
        };
        let agent_actor = EsAuditToken {
            key: root_key,
            uid: 501,
            team_id: None,
        };
        rt.tree.apply_event(&EsEventPayload::RegisterAgentRoot {
            root: agent_actor.clone(),
            session_id: "sess-es-1".into(),
        });

        let deny_sig = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::SelfSignal { target_pid: 777 },
            FloorEvaluator::Rules(&[]),
            false,
            10,
            10_000,
        );
        assert_eq!(deny_sig.decision, EsAuthDecision::Deny);

        let other_sig = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::SelfSignal { target_pid: 888 },
            FloorEvaluator::Rules(&[]),
            false,
            10,
            10_000,
        );
        assert_eq!(
            other_sig.decision,
            EsAuthDecision::Allow {
                should_cache: false
            }
        );

        let admin_actor = EsAuditToken {
            key: ProcessTreeKey {
                pid: 999,
                pidversion: 2,
            },
            uid: 0,
            team_id: Some("com.apple".into()),
        };
        let admin_sig = rt.evaluate_auth_event(
            &admin_actor,
            EsAuthAction::SelfSignal { target_pid: 777 },
            FloorEvaluator::Rules(&[]),
            false,
            10,
            10_000,
        );
        assert_eq!(admin_sig.decision, EsAuthDecision::AllowWithTamperAlert);

        let deny_self_open = rt.evaluate_auth_event_for_concern(
            EsClientConcern::SelfProtection,
            &agent_actor,
            EsAuthAction::FileOpen {
                target_path: "/Library/Application Support/Guardrails/state.db",
                write_requested: true,
            },
            FloorEvaluator::Rules(&[]),
            false,
            10,
            10_000,
        );
        assert_eq!(deny_self_open.decision, EsAuthDecision::Deny);

        let deny_path = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::FileOpen {
                target_path: "/private/var/db/grdr/keys/signing.key",
                write_requested: false,
            },
            FloorEvaluator::Rules(&[]),
            false,
            10,
            10_000,
        );
        assert_eq!(deny_path.decision, EsAuthDecision::Deny);

        let cutoff_protected_deny = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::FileUnlink {
                target_path: "/private/var/db/grdr/keys/signing.key",
            },
            FloorEvaluator::Rules(&[]),
            true,
            6_000,
            10_000,
        );
        assert_eq!(cutoff_protected_deny.decision, EsAuthDecision::Deny);

        let cutoff_allow = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::FileOpen {
                target_path: "/workspace/src/main.rs",
                write_requested: true,
            },
            FloorEvaluator::Rules(&[]),
            true,
            6_000,
            10_000,
        );
        assert_eq!(
            cutoff_allow.decision,
            EsAuthDecision::Allow {
                should_cache: false
            }
        );

        let mut bin = [0u8; 4_096];
        let rule = BinaryRuleInput {
            rule_id: "floor-deny-rm",
            reason: "deny rm",
            action_mask: FastActionClass::Exec.bit(),
            principal_mask: PRINCIPAL_SESSION | PRINCIPAL_PROCESS,
            label_mask: 0,
            agents: &[],
            prefixes: &["/bin/rm"],
            contains: &[],
            verdict: FastVerdict::Deny,
        };
        let bin_len = encode_binary_floor(&[rule], &mut bin).expect("encode binary floor");
        let table = BinaryFloorTable::parse(&bin[..bin_len]).expect("parse binary floor");
        let child_exec = EsAuditToken {
            key: ProcessTreeKey {
                pid: 500,
                pidversion: 2,
            },
            uid: 501,
            team_id: None,
        };
        let tight_exec_deny = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::Exec {
                old_key: root_key,
                target: &child_exec,
                executable_path: "/bin/rm",
            },
            FloorEvaluator::Binary(&table),
            false,
            6_000,
            10_000,
        );
        assert_eq!(tight_exec_deny.decision, EsAuthDecision::Deny);
        assert_eq!(
            tight_exec_deny.unmuted_target,
            Some(ProcessTreeKey {
                pid: 500,
                pidversion: 2
            })
        );

        let notify = rt.normalize_notify_event(
            root_key,
            EsNotifyEventKind::TccModify,
            "kTCCServiceSystemPolicyAllFiles",
        );
        assert_eq!(notify.action_class, ActionClass::ConfigChange);
        assert_eq!(notify.governed_session.as_deref(), Some("sess-es-1"));

        // Ancestor floor Allow rule MUST NOT bypass dynamic protected_paths on open, rename, or link.
        let mut allow_bin = [0u8; 4_096];
        let allow_parent_rule = BinaryRuleInput {
            rule_id: "floor-allow-var-db",
            reason: "allow /private/var/db/grdr",
            action_mask: FastActionClass::FileRead.bit() | FastActionClass::FileWrite.bit(),
            principal_mask: PRINCIPAL_SESSION | PRINCIPAL_PROCESS,
            label_mask: 0,
            agents: &[],
            prefixes: &["/private/var/db/grdr"],
            contains: &[],
            verdict: FastVerdict::Allow,
        };
        let allow_len =
            encode_binary_floor(&[allow_parent_rule], &mut allow_bin).expect("encode allow floor");
        let allow_table =
            BinaryFloorTable::parse(&allow_bin[..allow_len]).expect("parse allow floor");
        let protected_open = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::FileOpen {
                target_path: "/var/db/grdr/keys/secret.pem",
                write_requested: false,
            },
            FloorEvaluator::Binary(&allow_table),
            false,
            10,
            10_000,
        );
        assert_eq!(protected_open.decision, EsAuthDecision::Deny);
        let protected_rename = rt.evaluate_auth_event(
            &agent_actor,
            EsAuthAction::FileRename {
                source_path: "/workspace/benign.txt",
                dest_path: "/private/var/db/grdr/keys/overwrite.pem",
            },
            FloorEvaluator::Binary(&allow_table),
            false,
            10,
            10_000,
        );
        assert_eq!(protected_rename.decision, EsAuthDecision::Deny);
    }

    #[test]
    fn caches_only_immutable_cdhash_global_floor_exec_allows() {
        let mut rt = EsCoordinatorRuntime::new();
        rt.register_session_agent("sess-cache", "claude-code");
        let root_key = ProcessTreeKey {
            pid: 600,
            pidversion: 1,
        };
        let actor = EsAuditToken {
            key: root_key,
            uid: 501,
            team_id: None,
        };
        rt.tree.apply_event(&EsEventPayload::RegisterAgentRoot {
            root: actor.clone(),
            session_id: "sess-cache".into(),
        });

        let mut bin = [0u8; 4_096];
        let rule = BinaryRuleInput {
            rule_id: "floor-allow-git",
            reason: "allow git",
            action_mask: FastActionClass::Exec.bit(),
            principal_mask: PRINCIPAL_SESSION | PRINCIPAL_PROCESS,
            label_mask: 0,
            agents: &[],
            prefixes: &["/usr/bin/git"],
            contains: &[],
            verdict: FastVerdict::Allow,
        };
        let bin_len = encode_binary_floor(&[rule], &mut bin).expect("encode binary floor");
        let table = BinaryFloorTable::parse(&bin[..bin_len]).expect("parse binary floor");

        let mutable_target = EsAuditToken {
            key: ProcessTreeKey {
                pid: 600,
                pidversion: 2,
            },
            uid: 501,
            team_id: None,
        };
        let mutable_res = rt.evaluate_auth_event_with_concern(
            EsClientConcern::ExecAuthorizer,
            &actor,
            EsAuthAction::Exec {
                old_key: root_key,
                target: &mutable_target,
                executable_path: "/usr/bin/git",
            },
            FloorEvaluator::Binary(&table),
            false,
            10,
            10_000,
            false,
        );
        assert_eq!(
            mutable_res.decision,
            EsAuthDecision::Allow {
                should_cache: false
            }
        );

        let immutable_res = rt.evaluate_auth_event_with_concern(
            EsClientConcern::ExecAuthorizer,
            &actor,
            EsAuthAction::Exec {
                old_key: mutable_target.key,
                target: &EsAuditToken {
                    key: ProcessTreeKey {
                        pid: 600,
                        pidversion: 3,
                    },
                    uid: 501,
                    team_id: None,
                },
                executable_path: "/usr/bin/git",
            },
            FloorEvaluator::Binary(&table),
            false,
            10,
            10_000,
            true,
        );
        assert_eq!(
            immutable_res.decision,
            EsAuthDecision::Allow { should_cache: true }
        );
    }
}
