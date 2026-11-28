// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Granular multi-scope kill switch state, ordered containment transitions, and approval streaks (`D-09`, `D-55`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_schema::limits::load_embedded_limits;

use crate::detect::types::DetectError;

const DESTRUCTIVE_RATE_WINDOW_SECS: i64 = 600;
const APPROVAL_TIMEOUT_FREEZE_STREAK: u8 = 3;

const CONTAINMENT_LADDER: [DeviceContainmentStage; 4] = [
    DeviceContainmentStage::Frozen,
    DeviceContainmentStage::Isolated,
    DeviceContainmentStage::Captured,
    DeviceContainmentStage::Revoked,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerOperationalLimits {
    pub fleet_response_key_hours: u32,
    pub max_batch_events: usize,
    pub max_devices_default: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KillSwitchLimits {
    rate_window_secs: i64,
    destructive_cmds_per_10m_max: usize,
    streak_freeze_limit: u8,
    max_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum KillSwitchScope {
    Session(String),
    Device(String),
    Agent(String),
    ModelEndpoint(String),
    GatewayRoute(String),
    Principal(String),
    ArtefactDigest(String),
    Group(String),
    Organisation(String),
    Provider(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceContainmentStage {
    Active,
    Frozen,
    Isolated,
    Captured,
    Revoked,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActuatorDeliveryForm {
    Exact,
    Gated,
    Cooperative,
    Delegated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcomeSignal {
    Approved,
    UnansweredOrDenied,
    ApproverUnreachableOffline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveKillEntry {
    pub command_id: String,
    pub scope: KillSwitchScope,
    pub stage: DeviceContainmentStage,
    pub dual_signed: bool,
    pub reason_code: String,
    pub expires_at_sec: i64,
    pub executed_stages: Vec<DeviceContainmentStage>,
}

#[derive(Debug, Clone)]
pub struct KillSwitchApplyRequest<'a> {
    pub command_id: &'a str,
    pub scope: KillSwitchScope,
    pub target_stage: DeviceContainmentStage,
    pub dual_signed: bool,
    pub reason_code: &'a str,
    pub epoch: u64,
    pub counter: u64,
    pub expires_at_sec: i64,
    pub now: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GranularKillSwitchState {
    pub deployment_epoch: u64,
    pub last_counter: u64,
    entries: BTreeMap<String, ActiveKillEntry>,
    destructive_stamps: BTreeMap<String, Vec<i64>>,
    timeout_streaks: BTreeMap<String, u8>,
}

pub fn server_operational_limits() -> Result<ServerOperationalLimits, DetectError> {
    let cfg = load_embedded_limits()
        .map_err(|err| restore_err(&format!("embedded operational limits unavailable: {err}")))?;
    Ok(ServerOperationalLimits {
        fleet_response_key_hours: cfg.uplink.schedule.fleet_response_key_hours,
        max_batch_events: cfg.uplink.schedule.max_batch_events,
        max_devices_default: cfg.server.enrolment.max_devices_default,
    })
}

impl KillSwitchLimits {
    fn from_embedded() -> Result<Self, DetectError> {
        let cfg = load_embedded_limits().map_err(|err| {
            restore_err(&format!("embedded operational limits unavailable: {err}"))
        })?;
        let destructive_cmds_per_10m_max =
            usize::try_from(cfg.uplink.schedule.destructive_cmds_per_10m_max)
                .map_err(|_| restore_err("destructive_cmds_per_10m_max overflows usize"))?;
        let max_entries = usize::try_from(cfg.server.enrolment.max_devices_default)
            .map_err(|_| restore_err("max_devices_default overflows usize"))?;
        if destructive_cmds_per_10m_max == 0 || max_entries == 0 {
            return Err(restore_err("embedded operational limits must be positive"));
        }
        Ok(Self {
            rate_window_secs: DESTRUCTIVE_RATE_WINDOW_SECS,
            destructive_cmds_per_10m_max,
            streak_freeze_limit: APPROVAL_TIMEOUT_FREEZE_STREAK,
            max_entries,
        })
    }
}

impl KillSwitchScope {
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Session(id) => format!("session:{id}"),
            Self::Device(id) => format!("device:{id}"),
            Self::Agent(id) => format!("agent:{id}"),
            Self::ModelEndpoint(id) => format!("model:{id}"),
            Self::GatewayRoute(id) => format!("gateway:{id}"),
            Self::Principal(id) => format!("principal:{id}"),
            Self::ArtefactDigest(d) => format!("artefact:{d}"),
            Self::Group(id) => format!("group:{id}"),
            Self::Organisation(id) => format!("org:{id}"),
            Self::Provider(id) => format!("provider:{id}"),
        }
    }

    #[must_use]
    pub fn target_value(&self) -> &str {
        match self {
            Self::Session(id)
            | Self::Device(id)
            | Self::Agent(id)
            | Self::ModelEndpoint(id)
            | Self::GatewayRoute(id)
            | Self::Principal(id)
            | Self::ArtefactDigest(id)
            | Self::Group(id)
            | Self::Organisation(id)
            | Self::Provider(id) => id,
        }
    }
}

impl DeviceContainmentStage {
    #[must_use]
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Frozen => 1,
            Self::Isolated => 2,
            Self::Captured => 3,
            Self::Revoked => 4,
            Self::Released => 5,
        }
    }
}

impl GranularKillSwitchState {
    #[must_use]
    pub fn active_entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn active_entries(&self) -> Vec<ActiveKillEntry> {
        self.entries.values().cloned().collect()
    }

    #[must_use]
    pub fn entry_for_scope(&self, scope: &KillSwitchScope, now: i64) -> Option<&ActiveKillEntry> {
        self.entries.get(&scope.scope_key()).filter(|entry| {
            entry.expires_at_sec > now
                && !matches!(
                    entry.stage,
                    DeviceContainmentStage::Active | DeviceContainmentStage::Released
                )
        })
    }

    /// Applies an ordered containment transition or release for a single scope.
    pub fn apply_stage(
        &mut self,
        req: KillSwitchApplyRequest<'_>,
    ) -> Result<ActiveKillEntry, DetectError> {
        if req.command_id.trim().is_empty()
            || req.reason_code.trim().is_empty()
            || req.scope.target_value().trim().is_empty()
        {
            return Err(breaker_err(
                "kill switch command_id, reason_code, and scope target must be non-empty",
            ));
        }
        if req.target_stage == DeviceContainmentStage::Active {
            return Err(breaker_err(
                "Active is passive baseline state; use Released to lift containment",
            ));
        }
        if (req.epoch, req.counter) <= (self.deployment_epoch, self.last_counter)
            || req.expires_at_sec <= req.now
        {
            return Err(breaker_err("stale epoch, replayed counter, or expired"));
        }

        let limits = KillSwitchLimits::from_embedded()?;
        let scope_key = req.scope.scope_key();
        if matches!(
            req.scope,
            KillSwitchScope::Organisation(_) | KillSwitchScope::Provider(_)
        ) && !req.dual_signed
        {
            return Err(breaker_err(
                "organisation and provider kill scopes require dual signatures",
            ));
        }
        let cutoff = req.now.saturating_sub(limits.rate_window_secs);
        self.entries
            .retain(|_, entry| entry.expires_at_sec > req.now);
        self.destructive_stamps.retain(|_, stamps| {
            stamps.retain(|ts| *ts >= cutoff);
            !stamps.is_empty()
        });

        let prev_entry = self.entries.get(&scope_key);
        if let Some(active) = prev_entry {
            if active.dual_signed && !req.dual_signed {
                return Err(breaker_err(
                    "active dual-signed containment cannot be modified or released without dual signature",
                ));
            }
            if req.target_stage != DeviceContainmentStage::Released
                && req.expires_at_sec < active.expires_at_sec
            {
                return Err(breaker_err(
                    "containment expiry cannot be truncated on active scope update",
                ));
            }
        }

        let executed_stages = if req.target_stage == DeviceContainmentStage::Released {
            vec![DeviceContainmentStage::Released]
        } else {
            let prev = prev_entry.map_or(DeviceContainmentStage::Active, |entry| entry.stage);
            if !matches!(
                prev,
                DeviceContainmentStage::Active | DeviceContainmentStage::Released
            ) && req.target_stage.severity_rank() < prev.severity_rank()
            {
                return Err(breaker_err(
                    "containment stage downgrade rejected; release scope before re-applying lower stage",
                ));
            }
            if prev_entry.is_none() && self.entries.len() >= limits.max_entries {
                return Err(breaker_err("active kill switch capacity exceeded"));
            }
            transition_containment(prev, req.target_stage)?
        };
        let sticky_dual = req.dual_signed || prev_entry.is_some_and(|entry| entry.dual_signed);

        let track_destructive =
            req.target_stage == DeviceContainmentStage::Revoked && !req.dual_signed;
        if track_destructive {
            if !self.destructive_stamps.contains_key(&scope_key)
                && self.destructive_stamps.len() >= limits.max_entries
            {
                return Err(breaker_err(
                    "destructive command tracking capacity exceeded",
                ));
            }
            let current_count = self.destructive_stamps.get(&scope_key).map_or(0, Vec::len);
            if current_count >= limits.destructive_cmds_per_10m_max {
                return Err(breaker_err("destructive command rate limit exceeded"));
            }
        }

        if track_destructive {
            self.destructive_stamps
                .entry(scope_key.clone())
                .or_default()
                .push(req.now);
        }
        self.deployment_epoch = req.epoch;
        self.last_counter = req.counter;

        let entry = ActiveKillEntry {
            command_id: req.command_id.into(),
            scope: req.scope,
            stage: req.target_stage,
            dual_signed: sticky_dual,
            reason_code: req.reason_code.into(),
            expires_at_sec: req.expires_at_sec,
            executed_stages,
        };
        if req.target_stage == DeviceContainmentStage::Released {
            self.entries.remove(&scope_key);
        } else {
            self.entries.insert(scope_key, entry.clone());
        }
        Ok(entry)
    }

    #[must_use]
    pub fn matches_scopes(&self, scopes: &[KillSwitchScope], now: i64) -> Option<&ActiveKillEntry> {
        let mut best: Option<&ActiveKillEntry> = None;
        for scope in scopes {
            let Some(candidate) = self.entry_for_scope(scope, now) else {
                continue;
            };
            let replace = match best {
                None => true,
                Some(current) => candidate.stage.severity_rank() > current.stage.severity_rank(),
            };
            if replace {
                best = Some(candidate);
            }
        }
        best
    }

    pub fn record_approval_signal(
        &mut self,
        session_id: &str,
        sig: ApprovalOutcomeSignal,
    ) -> Result<bool, DetectError> {
        let limits = KillSwitchLimits::from_embedded()?;
        match sig {
            ApprovalOutcomeSignal::Approved => {
                self.timeout_streaks.remove(session_id);
                Ok(false)
            }
            ApprovalOutcomeSignal::ApproverUnreachableOffline => Ok(false),
            ApprovalOutcomeSignal::UnansweredOrDenied => {
                if session_id.trim().is_empty() {
                    return Err(breaker_err("approval signal session_id must be non-empty"));
                }
                if !self.timeout_streaks.contains_key(session_id)
                    && self.timeout_streaks.len() >= limits.max_entries
                    && let Some(evict) = self
                        .timeout_streaks
                        .iter()
                        .min_by_key(|(_, streak)| **streak)
                        .map(|(key, _)| key.clone())
                {
                    self.timeout_streaks.remove(&evict);
                }
                let streak = self
                    .timeout_streaks
                    .entry(session_id.to_owned())
                    .or_insert(0);
                *streak = streak.saturating_add(1);
                Ok(*streak >= limits.streak_freeze_limit)
            }
        }
    }

    pub fn restore_checked(snapshot: Self, min_epoch: u64) -> Result<Self, DetectError> {
        let limits = KillSwitchLimits::from_embedded()?;
        if snapshot.deployment_epoch < min_epoch {
            return Err(restore_err("kill switch epoch lags deployment root"));
        }
        if snapshot.entries.len() > limits.max_entries
            || snapshot.destructive_stamps.len() > limits.max_entries
            || snapshot.timeout_streaks.len() > limits.max_entries
        {
            return Err(restore_err(
                "kill switch snapshot exceeds operational limits",
            ));
        }
        for (key, entry) in &snapshot.entries {
            if key != &entry.scope.scope_key()
                || entry.command_id.trim().is_empty()
                || entry.reason_code.trim().is_empty()
                || entry.scope.target_value().trim().is_empty()
                || entry.expires_at_sec <= 0
                || matches!(
                    entry.stage,
                    DeviceContainmentStage::Active | DeviceContainmentStage::Released
                )
                || entry.executed_stages.last() != Some(&entry.stage)
                || (matches!(
                    entry.scope,
                    KillSwitchScope::Organisation(_) | KillSwitchScope::Provider(_)
                ) && !entry.dual_signed)
            {
                return Err(restore_err("kill switch snapshot contains invalid entry"));
            }
        }
        for stamps in snapshot.destructive_stamps.values() {
            if stamps.len() > limits.max_entries {
                return Err(restore_err(
                    "kill switch snapshot destructive stamps exceed limit",
                ));
            }
        }
        Ok(snapshot)
    }
}

#[must_use]
pub fn compute_preview_rollup(forms: &[ActuatorDeliveryForm]) -> ActuatorDeliveryForm {
    forms
        .iter()
        .copied()
        .max()
        .unwrap_or(ActuatorDeliveryForm::Delegated)
}

fn transition_containment(
    prev: DeviceContainmentStage,
    target: DeviceContainmentStage,
) -> Result<Vec<DeviceContainmentStage>, DetectError> {
    let target_idx = match target {
        DeviceContainmentStage::Frozen => 0,
        DeviceContainmentStage::Isolated => 1,
        DeviceContainmentStage::Captured => 2,
        DeviceContainmentStage::Revoked => 3,
        DeviceContainmentStage::Active | DeviceContainmentStage::Released => {
            return Err(breaker_err("invalid containment escalation target"));
        }
    };
    let start_idx = match prev {
        DeviceContainmentStage::Active | DeviceContainmentStage::Released => 0,
        DeviceContainmentStage::Frozen => 1,
        DeviceContainmentStage::Isolated => 2,
        DeviceContainmentStage::Captured => 3,
        DeviceContainmentStage::Revoked => 4,
    };
    if start_idx > target_idx {
        return Ok(vec![target]);
    }
    let slice = CONTAINMENT_LADDER
        .get(start_idx..=target_idx)
        .ok_or_else(|| breaker_err("containment ladder slice out of range"))?;
    Ok(slice.to_vec())
}

fn breaker_err(msg: &str) -> DetectError {
    DetectError::ResponseBreaker(msg.into())
}

fn restore_err(msg: &str) -> DetectError {
    DetectError::StateRestore(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w3_4_granular_kill_switch_containment_rate_limit_streak_and_preview() {
        let mut ks = GranularKillSwitchState::default();
        let entry = ks
            .apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-1",
                scope: KillSwitchScope::Agent("claude-code".into()),
                target_stage: DeviceContainmentStage::Revoked,
                dual_signed: false,
                reason_code: "det.tamper",
                epoch: 1,
                counter: 1,
                expires_at_sec: 2_000,
                now: 1_000,
            })
            .expect("revoke allowed under rate cap");
        assert_eq!(
            entry.executed_stages,
            vec![
                DeviceContainmentStage::Frozen,
                DeviceContainmentStage::Isolated,
                DeviceContainmentStage::Captured,
                DeviceContainmentStage::Revoked,
            ],
            "SR-32: Revoked must execute all prior containment stages in order"
        );
        assert!(
            ks.matches_scopes(
                &[
                    KillSwitchScope::ModelEndpoint("gpt-4o".into()),
                    KillSwitchScope::Agent("claude-code".into()),
                ],
                1_500
            )
            .is_some()
        );
        assert!(
            ks.matches_scopes(&[KillSwitchScope::Agent("claude-code".into())], 2_500)
                .is_none(),
            "expired kill switch entry must not match"
        );

        // Stale epoch or replayed counter rejected.
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-replay",
                scope: KillSwitchScope::Device("dev-1".into()),
                target_stage: DeviceContainmentStage::Frozen,
                dual_signed: false,
                reason_code: "det.replay",
                epoch: 1,
                counter: 1,
                expires_at_sec: 2_000,
                now: 1_000,
            })
            .is_err()
        );

        // Rate limit from contracts/limits.toml (3 destructive cmds / 10m without dual signature).
        let mut dev_ks = GranularKillSwitchState::default();
        for c in 1..=3_u64 {
            dev_ks
                .apply_stage(KillSwitchApplyRequest {
                    command_id: &format!("c-{c}"),
                    scope: KillSwitchScope::GatewayRoute("gw-1".into()),
                    target_stage: DeviceContainmentStage::Revoked,
                    dual_signed: false,
                    reason_code: "det.gw",
                    epoch: 1,
                    counter: c,
                    expires_at_sec: 5_000,
                    now: 1_000,
                })
                .expect("within 10m cap");
        }
        assert!(
            dev_ks
                .apply_stage(KillSwitchApplyRequest {
                    command_id: "c-4",
                    scope: KillSwitchScope::GatewayRoute("gw-1".into()),
                    target_stage: DeviceContainmentStage::Revoked,
                    dual_signed: false,
                    reason_code: "det.gw",
                    epoch: 1,
                    counter: 4,
                    expires_at_sec: 5_000,
                    now: 1_050,
                })
                .is_err(),
            "4th destructive command in 10m without dual signature must fail"
        );
        dev_ks
            .apply_stage(KillSwitchApplyRequest {
                command_id: "c-4-dual",
                scope: KillSwitchScope::GatewayRoute("gw-1".into()),
                target_stage: DeviceContainmentStage::Revoked,
                dual_signed: true,
                reason_code: "det.gw",
                epoch: 1,
                counter: 4,
                expires_at_sec: 5_000,
                now: 1_050,
            })
            .expect("dual signature bypasses 10m limiter");

        // Snapshot epoch check on restore.
        let json = serde_json::to_string(&dev_ks).expect("serialize snapshot");
        let parsed: GranularKillSwitchState = serde_json::from_str(&json).expect("deserialize");
        assert!(GranularKillSwitchState::restore_checked(parsed.clone(), 2).is_err());
        assert!(GranularKillSwitchState::restore_checked(parsed, 1).is_ok());

        // Approval streak: 3 unanswered/denied freezes, offline unreachable never increments.
        assert!(
            !ks.record_approval_signal("s-1", ApprovalOutcomeSignal::UnansweredOrDenied)
                .expect("streak 1")
        );
        assert!(
            !ks.record_approval_signal("s-1", ApprovalOutcomeSignal::ApproverUnreachableOffline)
                .expect("offline")
        );
        assert!(
            !ks.record_approval_signal("s-1", ApprovalOutcomeSignal::UnansweredOrDenied)
                .expect("streak 2")
        );
        assert!(
            ks.record_approval_signal("s-1", ApprovalOutcomeSignal::UnansweredOrDenied)
                .expect("streak 3")
        );

        // Preview rollup picks weakest guaranteed delivery form.
        assert_eq!(
            compute_preview_rollup(&[ActuatorDeliveryForm::Exact, ActuatorDeliveryForm::Gated]),
            ActuatorDeliveryForm::Gated
        );
        assert_eq!(
            compute_preview_rollup(&[
                ActuatorDeliveryForm::Gated,
                ActuatorDeliveryForm::Cooperative,
                ActuatorDeliveryForm::Delegated
            ]),
            ActuatorDeliveryForm::Delegated
        );
    }

    #[test]
    fn w3_4_kill_switch_rejects_active_downgrade_empty_rollup_and_picks_strictest_match() {
        let mut ks = GranularKillSwitchState::default();
        assert_eq!(
            compute_preview_rollup(&[]),
            ActuatorDeliveryForm::Delegated,
            "empty preview form list must never claim Exact"
        );
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-active",
                scope: KillSwitchScope::Agent("a1".into()),
                target_stage: DeviceContainmentStage::Active,
                dual_signed: false,
                reason_code: "bad",
                epoch: 1,
                counter: 1,
                expires_at_sec: 2_000,
                now: 1_000,
            })
            .is_err(),
            "Active is baseline state, not a containable target stage"
        );

        let iso = ks
            .apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-iso",
                scope: KillSwitchScope::Device("dev-1".into()),
                target_stage: DeviceContainmentStage::Isolated,
                dual_signed: false,
                reason_code: "isolate",
                epoch: 1,
                counter: 5,
                expires_at_sec: 5_000,
                now: 1_000,
            })
            .expect("isolated");
        assert_eq!(
            iso.executed_stages,
            vec![
                DeviceContainmentStage::Frozen,
                DeviceContainmentStage::Isolated
            ]
        );
        let rev = ks
            .apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-rev",
                scope: KillSwitchScope::Device("dev-1".into()),
                target_stage: DeviceContainmentStage::Revoked,
                dual_signed: false,
                reason_code: "revoke",
                epoch: 2,
                counter: 1,
                expires_at_sec: 5_000,
                now: 1_100,
            })
            .expect("epoch bump (2, 1) > (1, 5) must succeed");
        assert_eq!(
            rev.executed_stages,
            vec![
                DeviceContainmentStage::Captured,
                DeviceContainmentStage::Revoked
            ]
        );

        // Stage downgrade Revoked -> Frozen must fail unless released first.
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-down",
                scope: KillSwitchScope::Device("dev-1".into()),
                target_stage: DeviceContainmentStage::Frozen,
                dual_signed: true,
                reason_code: "downgrade",
                epoch: 2,
                counter: 2,
                expires_at_sec: 5_000,
                now: 1_200,
            })
            .is_err()
        );

        // Add Frozen on Agent scope so matches_scopes picks strictest (Revoked Device).
        ks.apply_stage(KillSwitchApplyRequest {
            command_id: "cmd-agent-freeze",
            scope: KillSwitchScope::Agent("a1".into()),
            target_stage: DeviceContainmentStage::Frozen,
            dual_signed: false,
            reason_code: "freeze",
            epoch: 2,
            counter: 3,
            expires_at_sec: 5_000,
            now: 1_250,
        })
        .expect("freeze agent");
        let matched = ks
            .matches_scopes(
                &[
                    KillSwitchScope::Agent("a1".into()),
                    KillSwitchScope::Device("dev-1".into()),
                ],
                1_300,
            )
            .expect("match");
        assert_eq!(matched.stage, DeviceContainmentStage::Revoked);

        // Same-stage TTL truncation rejected; dual-signed entry cannot be modified or released single-signed.
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-agent-trunc",
                scope: KillSwitchScope::Agent("a1".into()),
                target_stage: DeviceContainmentStage::Frozen,
                dual_signed: false,
                reason_code: "truncate",
                epoch: 2,
                counter: 4,
                expires_at_sec: 2_000,
                now: 1_260,
            })
            .is_err()
        );
        ks.apply_stage(KillSwitchApplyRequest {
            command_id: "cmd-agent-dual-iso",
            scope: KillSwitchScope::Agent("a1".into()),
            target_stage: DeviceContainmentStage::Isolated,
            dual_signed: true,
            reason_code: "escalate",
            epoch: 2,
            counter: 5,
            expires_at_sec: 6_000,
            now: 1_270,
        })
        .expect("dual escalation succeeds");
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-agent-overwrite-1s",
                scope: KillSwitchScope::Agent("a1".into()),
                target_stage: DeviceContainmentStage::Isolated,
                dual_signed: false,
                reason_code: "overwrite",
                epoch: 2,
                counter: 6,
                expires_at_sec: 6_001,
                now: 1_280,
            })
            .is_err()
        );
        assert!(
            ks.apply_stage(KillSwitchApplyRequest {
                command_id: "cmd-agent-single-rel",
                scope: KillSwitchScope::Agent("a1".into()),
                target_stage: DeviceContainmentStage::Released,
                dual_signed: false,
                reason_code: "rel",
                epoch: 2,
                counter: 7,
                expires_at_sec: 6_001,
                now: 1_290,
            })
            .is_err()
        );

        // Tampered Organisation entry with dual_signed=false fails restore_checked.
        let forged = serde_json::json!({
            "deployment_epoch": 1,
            "last_counter": 1,
            "entries": {
                "org:o1": {
                    "command_id": "forged",
                    "scope": { "kind": "organisation", "target": "o1" },
                    "stage": "frozen",
                    "dual_signed": false,
                    "reason_code": "forged",
                    "expires_at_sec": 5000,
                    "executed_stages": ["frozen"]
                }
            },
            "destructive_stamps": {},
            "timeout_streaks": {}
        });
        let parsed: GranularKillSwitchState =
            serde_json::from_value(forged).expect("parse snapshot");
        assert!(GranularKillSwitchState::restore_checked(parsed, 1).is_err());
    }
}
