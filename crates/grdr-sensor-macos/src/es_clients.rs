// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::es_tree::{AuthDeadlineBudget, DeadlineMissPolicy, EsClientConcern, EsClientStatus};

const RECORDER_EVENTS: &[EsSubscribedEventKind] = &[
    EsSubscribedEventKind::NotifyExec,
    EsSubscribedEventKind::NotifyFork,
    EsSubscribedEventKind::NotifyExit,
    EsSubscribedEventKind::NotifyCreate,
    EsSubscribedEventKind::NotifyRename,
    EsSubscribedEventKind::NotifyUnlink,
    EsSubscribedEventKind::NotifyUipcConnect,
    EsSubscribedEventKind::NotifyXpcConnect,
    EsSubscribedEventKind::NotifySudo,
    EsSubscribedEventKind::NotifySu,
    EsSubscribedEventKind::NotifyAuthorizationPetition,
    EsSubscribedEventKind::NotifyAuthorizationJudgement,
    EsSubscribedEventKind::NotifyTccModify,
    EsSubscribedEventKind::NotifyBtmLaunchItemAdd,
    EsSubscribedEventKind::NotifyBootstrapLookup,
];

const EXEC_AUTH_EVENTS: &[EsSubscribedEventKind] = &[EsSubscribedEventKind::AuthExec];

const PROTECTED_PATH_EVENTS: &[EsSubscribedEventKind] = &[
    EsSubscribedEventKind::AuthOpen,
    EsSubscribedEventKind::AuthCreate,
    EsSubscribedEventKind::AuthUnlink,
    EsSubscribedEventKind::AuthRename,
    EsSubscribedEventKind::AuthTruncate,
    EsSubscribedEventKind::AuthLink,
    EsSubscribedEventKind::AuthClone,
    EsSubscribedEventKind::AuthUipcConnect,
];

const SELF_PROTECTION_EVENTS: &[EsSubscribedEventKind] = &[
    EsSubscribedEventKind::AuthSignal,
    EsSubscribedEventKind::AuthGetTask,
    EsSubscribedEventKind::AuthProcSuspendResume,
    EsSubscribedEventKind::AuthOpen,
    EsSubscribedEventKind::AuthUnlink,
    EsSubscribedEventKind::AuthRename,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsMutingStrategy {
    InvertedProcess,
    InvertedTargetPathOnly,
    SelfTargetPathOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsSubscribedEventKind {
    AuthExec,
    AuthOpen,
    AuthCreate,
    AuthTruncate,
    AuthLink,
    AuthClone,
    AuthUnlink,
    AuthRename,
    AuthUipcConnect,
    AuthSignal,
    AuthGetTask,
    AuthProcSuspendResume,
    NotifyExec,
    NotifyFork,
    NotifyExit,
    NotifyCreate,
    NotifyRename,
    NotifyUnlink,
    NotifyUipcConnect,
    NotifyXpcConnect,
    NotifySudo,
    NotifySu,
    NotifyAuthorizationPetition,
    NotifyAuthorizationJudgement,
    NotifyTccModify,
    NotifyBtmLaunchItemAdd,
    NotifyBootstrapLookup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsClientRoleSpec {
    pub concern: EsClientConcern,
    pub deadline_policy: DeadlineMissPolicy,
    pub muting_strategy: EsMutingStrategy,
    pub subscriptions: &'static [EsSubscribedEventKind],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsClientSetState {
    statuses: BTreeMap<EsClientConcern, EsClientStatus>,
}

impl Default for EsClientSetState {
    fn default() -> Self {
        let mut statuses = BTreeMap::new();
        for concern in all_client_concerns() {
            statuses.insert(concern, EsClientStatus::MissingEntitlement);
        }
        Self { statuses }
    }
}

impl EsClientSetState {
    pub fn set_status(&mut self, concern: EsClientConcern, status: EsClientStatus) {
        self.statuses.insert(concern, status);
    }

    pub fn get_status(&self, concern: EsClientConcern) -> EsClientStatus {
        self.statuses
            .get(&concern)
            .copied()
            .unwrap_or(EsClientStatus::MissingEntitlement)
    }

    pub fn all_statuses(&self) -> [(EsClientConcern, EsClientStatus); 4] {
        [
            (
                EsClientConcern::Recorder,
                self.get_status(EsClientConcern::Recorder),
            ),
            (
                EsClientConcern::ExecAuthorizer,
                self.get_status(EsClientConcern::ExecAuthorizer),
            ),
            (
                EsClientConcern::ProtectedPathGuard,
                self.get_status(EsClientConcern::ProtectedPathGuard),
            ),
            (
                EsClientConcern::SelfProtection,
                self.get_status(EsClientConcern::SelfProtection),
            ),
        ]
    }

    pub fn rollup_status(&self) -> EsClientStatus {
        let all = self.all_statuses();
        if all.iter().all(|(_, s)| *s == EsClientStatus::Active) {
            return EsClientStatus::Active;
        }
        for concern in [
            EsClientConcern::ExecAuthorizer,
            EsClientConcern::Recorder,
            EsClientConcern::ProtectedPathGuard,
            EsClientConcern::SelfProtection,
        ] {
            let st = self.get_status(concern);
            if st != EsClientStatus::Active {
                return st;
            }
        }
        EsClientStatus::MissingEntitlement
    }
}

pub const fn all_client_concerns() -> [EsClientConcern; 4] {
    [
        EsClientConcern::Recorder,
        EsClientConcern::ExecAuthorizer,
        EsClientConcern::ProtectedPathGuard,
        EsClientConcern::SelfProtection,
    ]
}

pub fn role_spec_for_concern(concern: EsClientConcern) -> EsClientRoleSpec {
    match concern {
        EsClientConcern::Recorder => EsClientRoleSpec {
            concern,
            deadline_policy: DeadlineMissPolicy::FullClientFailOpen,
            muting_strategy: EsMutingStrategy::InvertedProcess,
            subscriptions: RECORDER_EVENTS,
        },
        EsClientConcern::ExecAuthorizer => EsClientRoleSpec {
            concern,
            deadline_policy: DeadlineMissPolicy::FullClientFailOpen,
            muting_strategy: EsMutingStrategy::InvertedProcess,
            subscriptions: EXEC_AUTH_EVENTS,
        },
        EsClientConcern::ProtectedPathGuard => EsClientRoleSpec {
            concern,
            deadline_policy: DeadlineMissPolicy::FullClientFailOpen,
            muting_strategy: EsMutingStrategy::InvertedTargetPathOnly,
            subscriptions: PROTECTED_PATH_EVENTS,
        },
        EsClientConcern::SelfProtection => EsClientRoleSpec {
            concern,
            deadline_policy: DeadlineMissPolicy::FullClientFailOpen,
            muting_strategy: EsMutingStrategy::SelfTargetPathOnly,
            subscriptions: SELF_PROTECTION_EVENTS,
        },
    }
}

pub fn check_full_client_budget(elapsed_ms: u64, kernel_deadline_ms: u64) -> bool {
    if kernel_deadline_ms == 0 {
        return false;
    }
    let budget = AuthDeadlineBudget::for_full_client(kernel_deadline_ms);
    elapsed_ms <= budget.engine_cutoff_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_isolated_es_clients_enforce_fail_open_muting_and_budget_cutoff() {
        for concern in all_client_concerns() {
            let spec = role_spec_for_concern(concern);
            assert_eq!(spec.deadline_policy, DeadlineMissPolicy::FullClientFailOpen);
            assert!(!spec.subscriptions.is_empty());
        }
        assert_eq!(
            role_spec_for_concern(EsClientConcern::Recorder).muting_strategy,
            EsMutingStrategy::InvertedProcess
        );
        assert_eq!(
            role_spec_for_concern(EsClientConcern::ProtectedPathGuard).muting_strategy,
            EsMutingStrategy::InvertedTargetPathOnly
        );
        assert!(
            role_spec_for_concern(EsClientConcern::SelfProtection)
                .subscriptions
                .contains(&EsSubscribedEventKind::AuthUnlink)
        );
        assert!(
            role_spec_for_concern(EsClientConcern::ProtectedPathGuard)
                .subscriptions
                .contains(&EsSubscribedEventKind::AuthClone)
        );
        assert!(
            role_spec_for_concern(EsClientConcern::Recorder)
                .subscriptions
                .contains(&EsSubscribedEventKind::NotifyBootstrapLookup)
        );

        assert!(check_full_client_budget(4_500, 10_000));
        assert!(!check_full_client_budget(5_001, 10_000));
        assert!(!check_full_client_budget(0, 0));

        let mut set = EsClientSetState::default();
        assert_eq!(set.rollup_status(), EsClientStatus::MissingEntitlement);
        for concern in all_client_concerns() {
            set.set_status(concern, EsClientStatus::Active);
        }
        assert_eq!(set.rollup_status(), EsClientStatus::Active);
        set.set_status(
            EsClientConcern::ProtectedPathGuard,
            EsClientStatus::NotPermittedFda,
        );
        assert_eq!(set.rollup_status(), EsClientStatus::NotPermittedFda);
    }
}
