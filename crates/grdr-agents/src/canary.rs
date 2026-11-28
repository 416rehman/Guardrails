// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hook canary handshake verification, passive session canary FSM, and install health evaluation (`docs/design/07`).

use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use grdr_ports::LocalFsPort;

use crate::canary_exec::execute_live_canary_probe;
use crate::catalogue::{AgentCatalogue, AgentManifest};
use crate::hook_codec::parse_hook_stdin_with_catalogue;
use crate::install::{HookInstallState, HookTargetKind, hook_status_with_catalogue};

const FALLBACK_CANARY_TOLERANCE_MS: u64 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookHealthState {
    Configured,
    Effective,
    NotConfigured,
    ConfiguredNotEffective,
    AwaitingOwner,
    Shadowed,
    ForeignLocked,
    UnknownVersion,
    HookDark,
    Tampered,
    CanaryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryStatus {
    Passed,
    Missed,
    Malformed,
    ProbeRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigLayerScope {
    ManagedPolicy,
    EnvOverride,
    ProjectConfig,
    UserConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookLayerDisposition {
    HasGrdrHook,
    DisabledAllHooks,
    FirstWinsOtherHook,
    LockedForeignMdm,
    Unconfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookLayerObservation {
    pub scope: ConfigLayerScope,
    pub disposition: HookLayerDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassiveCanaryPhase {
    #[default]
    Idle,
    AwaitingFirstTool,
    Verified,
    Missed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PassiveCanaryEvent {
    SessionStart {
        pid: u32,
        session_key: String,
        at_ms: u64,
    },
    HookPreTool {
        session_key: String,
        at_ms: u64,
    },
    OsSensorToolEffect {
        pid: u32,
        at_ms: u64,
    },
    TranscriptToolFallback {
        session_key: String,
        at_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveCanaryState {
    pub phase: PassiveCanaryPhase,
    pub health: HookHealthState,
    pub pid: Option<u32>,
    pub session_key: Option<String>,
    pub session_start_ms: Option<u64>,
    pub first_hook_pre_ms: Option<u64>,
    pub first_effect_ms: Option<u64>,
    pub finding_rule: Option<String>,
    #[serde(default)]
    pub os_corroborated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookCanaryReport {
    pub agent_id: String,
    pub health: HookHealthState,
    pub canary: CanaryStatus,
    pub detail: String,
}

fn canary_tolerance_ms() -> u64 {
    static TOLERANCE_MS: OnceLock<u64> = OnceLock::new();
    *TOLERANCE_MS.get_or_init(|| {
        grdr_schema::limits::load_embedded_limits().map_or(FALLBACK_CANARY_TOLERANCE_MS, |limits| {
            u64::from(limits.endpoint.latency_ms.hook_linux_p99).max(1)
        })
    })
}

impl Default for PassiveCanaryState {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveCanaryState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: PassiveCanaryPhase::Idle,
            health: HookHealthState::Configured,
            pid: None,
            session_key: None,
            session_start_ms: None,
            first_hook_pre_ms: None,
            first_effect_ms: None,
            finding_rule: None,
            os_corroborated: false,
        }
    }

    pub fn apply(&mut self, event: PassiveCanaryEvent) -> HookHealthState {
        let tol = canary_tolerance_ms();
        match event {
            PassiveCanaryEvent::SessionStart {
                pid,
                session_key,
                at_ms,
            } => {
                // Do not allow mid-session re-binding of pid or session_key.
                if self.session_start_ms.is_some() || session_key.trim().is_empty() {
                    return self.health;
                }
                self.phase = PassiveCanaryPhase::AwaitingFirstTool;
                self.pid = Some(pid);
                self.session_key = Some(session_key);
                self.session_start_ms = Some(at_ms);
            }
            PassiveCanaryEvent::HookPreTool { session_key, at_ms } => {
                if !self.matches_bound_session(&session_key, at_ms) {
                    return self.health;
                }
                if self.phase == PassiveCanaryPhase::AwaitingFirstTool {
                    if let Some(prev_hook) = self.first_hook_pre_ms {
                        if self.first_effect_ms.is_none() && at_ms > prev_hook.saturating_add(tol) {
                            self.first_hook_pre_ms = Some(at_ms);
                        }
                    } else {
                        self.first_hook_pre_ms = Some(at_ms);
                    }
                    if let Some(effect_ms) = self.first_effect_ms {
                        self.evaluate_effect_timing(effect_ms, self.os_corroborated);
                    }
                }
            }
            PassiveCanaryEvent::OsSensorToolEffect { pid, at_ms } => {
                if !self.matches_bound_pid(pid, at_ms) {
                    return self.health;
                }
                if self.phase == PassiveCanaryPhase::AwaitingFirstTool {
                    self.os_corroborated = true;
                    self.first_effect_ms.get_or_insert(at_ms);
                    self.evaluate_effect_timing(at_ms, true);
                }
            }
            PassiveCanaryEvent::TranscriptToolFallback { session_key, at_ms } => {
                if !self.matches_bound_session(&session_key, at_ms) {
                    return self.health;
                }
                if self.phase == PassiveCanaryPhase::AwaitingFirstTool {
                    self.first_effect_ms.get_or_insert(at_ms);
                    self.evaluate_effect_timing(at_ms, false);
                }
            }
        }
        self.health
    }

    pub fn advance_clock(&mut self, now_ms: u64) -> HookHealthState {
        let tol = canary_tolerance_ms();
        if self.phase == PassiveCanaryPhase::AwaitingFirstTool {
            if let Some(effect_ms) = self.first_effect_ms
                && self.first_hook_pre_ms.is_none()
                && now_ms > effect_ms.saturating_add(tol)
            {
                self.mark_missed();
            } else if let Some(hook_ms) = self.first_hook_pre_ms
                && self.first_effect_ms.is_none()
                && now_ms > hook_ms.saturating_add(tol)
            {
                // Expire an unmatched HookPreTool timestamp instead of latching indefinitely.
                self.first_hook_pre_ms = None;
            }
        }
        self.health
    }

    fn matches_bound_session(&self, session_key: &str, at_ms: u64) -> bool {
        self.session_start_ms.is_some_and(|start| at_ms >= start)
            && self.session_key.as_deref() == Some(session_key)
    }

    fn matches_bound_pid(&self, pid: u32, at_ms: u64) -> bool {
        self.session_start_ms.is_some_and(|start| at_ms >= start) && self.pid == Some(pid)
    }

    fn evaluate_effect_timing(&mut self, effect_ms: u64, is_os_effect: bool) {
        let tol = canary_tolerance_ms();
        if let Some(hook_ms) = self.first_hook_pre_ms {
            if effect_ms.abs_diff(hook_ms) <= tol {
                if is_os_effect {
                    self.mark_verified();
                }
            } else {
                self.mark_missed();
            }
        } else if self.session_start_ms.is_none() {
            self.mark_missed();
        }
    }

    fn mark_verified(&mut self) {
        self.phase = PassiveCanaryPhase::Verified;
        self.health = HookHealthState::Effective;
        self.finding_rule = None;
    }

    fn mark_missed(&mut self) {
        self.phase = PassiveCanaryPhase::Missed;
        self.health = HookHealthState::ConfiguredNotEffective;
        self.finding_rule = Some("canary-missed".into());
    }
}

#[must_use]
pub fn probe_hook_layer_precedence(
    layers: &[HookLayerObservation],
    awaiting_owner_restart: bool,
) -> HookHealthState {
    let scope_rank = |scope: ConfigLayerScope| -> u8 {
        match scope {
            ConfigLayerScope::ManagedPolicy => 0,
            ConfigLayerScope::EnvOverride => 1,
            ConfigLayerScope::ProjectConfig => 2,
            ConfigLayerScope::UserConfig => 3,
        }
    };
    let mut ordered = layers.to_vec();
    ordered.sort_by_key(|obs| scope_rank(obs.scope));

    for obs in &ordered {
        match obs.disposition {
            HookLayerDisposition::DisabledAllHooks => return HookHealthState::Shadowed,
            HookLayerDisposition::LockedForeignMdm => return HookHealthState::ForeignLocked,
            HookLayerDisposition::FirstWinsOtherHook => return HookHealthState::Shadowed,
            HookLayerDisposition::HasGrdrHook => {
                return if awaiting_owner_restart {
                    HookHealthState::AwaitingOwner
                } else {
                    HookHealthState::Configured
                };
            }
            HookLayerDisposition::Unconfigured => {}
        }
    }
    HookHealthState::NotConfigured
}

#[must_use]
pub fn check_adapter_version_support(
    observed_version: Option<&str>,
    min_major_minor: (u32, u32),
    max_major_minor: Option<(u32, u32)>,
) -> HookHealthState {
    let Some(raw) = observed_version else {
        return HookHealthState::UnknownVersion;
    };
    let mut parts = raw.trim().trim_start_matches('v').split('.');
    let major = parts.next().and_then(|s| s.parse::<u32>().ok());
    let minor = parts
        .next()
        .and_then(|s| s.split(['-', '+']).next())
        .and_then(|s| s.parse::<u32>().ok());
    let (Some(maj), Some(min)) = (major, minor) else {
        return HookHealthState::UnknownVersion;
    };
    let ver = (maj, min);
    if ver < min_major_minor || max_major_minor.is_some_and(|max| ver > max) {
        return HookHealthState::UnknownVersion;
    }
    HookHealthState::Configured
}

pub fn verify_hook_canary(
    manifest: &AgentManifest,
    home_dir: &Path,
    hook_command: &str,
    probe_json: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> HookCanaryReport {
    let attempt_summary = match validate_hook_canary_prereqs(
        manifest,
        home_dir,
        hook_command,
        probe_json,
        catalogue,
        fs,
    ) {
        Ok(summary) => summary,
        Err(report) => return report,
    };
    if Path::new(hook_command).is_absolute() {
        return execute_live_canary_probe(manifest, hook_command, probe_json, &attempt_summary, fs);
    }
    HookCanaryReport {
        agent_id: manifest.id.clone(),
        health: HookHealthState::Configured,
        canary: CanaryStatus::Missed,
        detail: format!(
            "probe payload parsed for dialect `{}`; live execution or OS-sensor canary proof required before Effective ({attempt_summary})",
            manifest.hook.dialect
        ),
    }
}

pub fn verify_hook_canary_with_passive(
    manifest: &AgentManifest,
    home_dir: &Path,
    hook_command: &str,
    probe_json: &str,
    passive: &PassiveCanaryState,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> HookCanaryReport {
    let attempt_summary = match validate_hook_canary_prereqs(
        manifest,
        home_dir,
        hook_command,
        probe_json,
        catalogue,
        fs,
    ) {
        Ok(summary) => summary,
        Err(report) => return report,
    };
    if passive.phase == PassiveCanaryPhase::Verified
        && passive.health == HookHealthState::Effective
        && passive.os_corroborated
    {
        return HookCanaryReport {
            agent_id: manifest.id.clone(),
            health: HookHealthState::Effective,
            canary: CanaryStatus::Passed,
            detail: format!(
                "canary verified via passive OS-sensor corroboration for `{}` ({attempt_summary})",
                manifest.hook.dialect
            ),
        };
    }
    HookCanaryReport {
        agent_id: manifest.id.clone(),
        health: HookHealthState::ConfiguredNotEffective,
        canary: CanaryStatus::Missed,
        detail: format!(
            "passive canary did not reach OS-corroborated Verified state (phase={:?}, os_corroborated={})",
            passive.phase, passive.os_corroborated
        ),
    }
}

pub fn verify_hook_canary_exec(
    manifest: &AgentManifest,
    home_dir: &Path,
    hook_command: &str,
    probe_json: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> HookCanaryReport {
    let attempt_summary = match validate_hook_canary_prereqs(
        manifest,
        home_dir,
        hook_command,
        probe_json,
        catalogue,
        fs,
    ) {
        Ok(summary) => summary,
        Err(report) => return report,
    };
    execute_live_canary_probe(manifest, hook_command, probe_json, &attempt_summary, fs)
}

fn validate_hook_canary_prereqs(
    manifest: &AgentManifest,
    home_dir: &Path,
    hook_command: &str,
    probe_json: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> Result<String, HookCanaryReport> {
    let target = HookTargetKind::from_manifest(manifest);
    let status = match hook_status_with_catalogue(&target, home_dir, hook_command, catalogue, fs) {
        Ok(st) => st,
        Err(err) => {
            return Err(HookCanaryReport {
                agent_id: manifest.id.clone(),
                health: HookHealthState::Tampered,
                canary: CanaryStatus::Malformed,
                detail: err,
            });
        }
    };
    if status.state == HookInstallState::NotConfigured || !status.installed {
        return Err(HookCanaryReport {
            agent_id: manifest.id.clone(),
            health: HookHealthState::NotConfigured,
            canary: CanaryStatus::Missed,
            detail: format!("hook entry absent from {}", status.config_path.display()),
        });
    }
    let attempt = parse_hook_stdin_with_catalogue(
        &manifest.hook.dialect,
        probe_json,
        "canary-host",
        catalogue,
    )
    .map_err(|err| HookCanaryReport {
        agent_id: manifest.id.clone(),
        health: HookHealthState::CanaryFailed,
        canary: CanaryStatus::ProbeRejected,
        detail: err,
    })?;
    Ok(format!("class={:?}", attempt.action_class))
}
