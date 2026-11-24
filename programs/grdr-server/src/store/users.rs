// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_core::session::replay_session_states;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{
    ActionAttempt, ArtifactEntry, AuditEntry, CodedError, Device, Finding, FindingSeverity,
    IdentityMode, OrgPrivacyConfig, RiskTier, SessionSummary, UpdatePrivacyConfigInput,
    UserDetailResponse, UserProfile, Verdict, compute_user_risk, summarize_sessions,
};

use super::{AppState, StoreData};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryUserRecord {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub department: String,
    pub idp_source: String,
    pub pseudonym_id: String,
}

pub(crate) fn build_user_profiles(data: &StoreData) -> Vec<UserProfile> {
    let mut records: BTreeMap<String, DirectoryUserRecord> = BTreeMap::new();
    for rec in &data.user_directory {
        records.insert(rec.id.clone(), rec.clone());
    }
    for dev in &data.devices {
        if let Some(uid) = &dev.user_id {
            records
                .entry(uid.clone())
                .or_insert_with(|| fallback_record(uid, dev.user_display.as_deref()));
        }
    }
    for att in &data.attempts {
        if let Some(uid) = &att.user_id {
            records
                .entry(uid.clone())
                .or_insert_with(|| fallback_record(uid, att.user_display.as_deref()));
        }
    }

    let device_owner: BTreeMap<&str, &str> = data
        .devices
        .iter()
        .filter_map(|d| d.user_id.as_deref().map(|uid| (d.id.as_str(), uid)))
        .collect();
    let attempt_user: BTreeMap<&str, &str> = data
        .attempts
        .iter()
        .filter_map(|a| a.user_id.as_deref().map(|uid| (a.id.as_str(), uid)))
        .collect();
    let session_user: BTreeMap<&str, &str> = data
        .attempts
        .iter()
        .filter_map(|a| a.user_id.as_deref().map(|uid| (a.session_id.as_str(), uid)))
        .collect();

    let mut profiles: Vec<UserProfile> = records
        .values()
        .map(|rec| {
            let uid = rec.id.as_str();
            let user_devices: Vec<&Device> = data
                .devices
                .iter()
                .filter(|d| d.user_id.as_deref() == Some(uid))
                .collect();
            let device_ids: Vec<String> = user_devices.iter().map(|d| d.id.clone()).collect();

            let mut agents = BTreeSet::new();
            let mut artifact_ids = BTreeSet::new();
            let mut risky_artifacts: u32 = 0;
            let mut unpinned_mcps: u32 = 0;
            for dev in &user_devices {
                for a in &dev.agents {
                    agents.insert(a.name.clone());
                }
                for art in &dev.artifacts {
                    if artifact_ids.insert(art.id.clone()) && !art.risk_flags.is_empty() {
                        risky_artifacts = risky_artifacts.saturating_add(1);
                    }
                }
                for mcp in &dev.mcp_servers {
                    if !mcp.pinned {
                        unpinned_mcps = unpinned_mcps.saturating_add(1);
                    }
                }
            }

            let user_attempts: Vec<&ActionAttempt> = data
                .attempts
                .iter()
                .filter(|a| {
                    a.user_id.as_deref() == Some(uid)
                        || device_owner.get(a.device_id.as_str()) == Some(&uid)
                })
                .collect();
            for att in &user_attempts {
                agents.insert(att.agent_name.clone());
            }

            let session_ids: BTreeSet<&str> = user_attempts
                .iter()
                .map(|a| a.session_id.as_str())
                .collect();

            let mut blocked: u32 = 0;
            let mut asked: u32 = 0;
            let mut watch: u32 = 0;
            for r in &data.receipts {
                let belongs = attempt_user.get(r.attempt_id.as_str()) == Some(&uid)
                    || session_user.get(r.session_id.as_str()) == Some(&uid)
                    || device_owner.get(r.device_id.as_str()) == Some(&uid);
                if !belongs {
                    continue;
                }
                match r.verdict {
                    Verdict::Deny => blocked = blocked.saturating_add(1),
                    Verdict::StepUp => asked = asked.saturating_add(1),
                    Verdict::Allow if r.mode_applied == Some(grdr_model::Mode::Watch) => {
                        watch = watch.saturating_add(1);
                    }
                    _ => {}
                }
            }

            let user_findings: Vec<&Finding> = data
                .findings
                .iter()
                .filter(|f| {
                    session_user.get(f.session_id.as_str()) == Some(&uid)
                        || device_owner.get(f.device_id.as_str()) == Some(&uid)
                })
                .collect();
            let critical_findings = u32::try_from(
                user_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::Critical)
                    .count(),
            )
            .unwrap_or(u32::MAX);
            let high_findings = u32::try_from(
                user_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::High)
                    .count(),
            )
            .unwrap_or(u32::MAX);

            let last_active = user_attempts
                .iter()
                .map(|a| a.timestamp)
                .chain(user_devices.iter().map(|d| d.last_seen))
                .max()
                .unwrap_or(Timestamp::UNIX_EPOCH);

            let (risk_score, risk_tier, risk_factors) = compute_user_risk(
                blocked,
                asked,
                watch,
                critical_findings,
                high_findings,
                risky_artifacts,
                unpinned_mcps,
            );

            let mut profile = UserProfile {
                id: rec.id.clone(),
                display_name: rec.display_name.clone(),
                email: rec.email.clone(),
                department: rec.department.clone(),
                idp_source: rec.idp_source.clone(),
                pseudonym_id: rec.pseudonym_id.clone(),
                device_ids,
                agent_names: agents.into_iter().collect(),
                artifact_count: artifact_ids.len(),
                session_count: session_ids.len(),
                blocked_count: blocked as usize,
                asked_count: asked as usize,
                watch_count: watch as usize,
                finding_count: user_findings.len(),
                risk_score,
                risk_tier,
                risk_factors,
                last_active,
            };

            apply_privacy_mask(&mut profile, &data.privacy);
            profile
        })
        .collect();

    profiles.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| b.last_active.cmp(&a.last_active))
            .then_with(|| a.id.cmp(&b.id))
    });
    profiles
}

pub(crate) fn apply_privacy_mask(profile: &mut UserProfile, privacy: &OrgPrivacyConfig) {
    if privacy.identity_mode == IdentityMode::Pseudonymous {
        profile.display_name = profile.pseudonym_id.clone();
        profile.email = "masked@works-council.invalid".into();
        profile.department = "Protected group".into();
        profile.idp_source = "vault-sealed".into();
    }
    if !privacy.user_risk_scoring || privacy.identity_mode == IdentityMode::Pseudonymous {
        profile.risk_score = 0;
        profile.risk_tier = RiskTier::Low;
        profile.risk_factors.clear();
    }
}

pub(crate) fn mask_sessions(sessions: &mut [SessionSummary], data: &StoreData) {
    if data.privacy.identity_mode != IdentityMode::Pseudonymous {
        return;
    }
    let pseudo_by_id: BTreeMap<&str, &str> = data
        .user_directory
        .iter()
        .map(|u| (u.id.as_str(), u.pseudonym_id.as_str()))
        .collect();
    for s in sessions {
        if let Some(uid) = &s.user_id {
            let masked = pseudo_by_id
                .get(uid.as_str())
                .copied()
                .unwrap_or("prn_masked");
            s.user_display = Some(masked.to_string());
        }
    }
}

pub(crate) fn mask_attempts(attempts: &mut [ActionAttempt], data: &StoreData) {
    if data.privacy.identity_mode != IdentityMode::Pseudonymous {
        return;
    }
    let pseudo_by_id: BTreeMap<&str, &str> = data
        .user_directory
        .iter()
        .map(|u| (u.id.as_str(), u.pseudonym_id.as_str()))
        .collect();
    for a in attempts {
        if let Some(uid) = &a.user_id {
            let masked = pseudo_by_id
                .get(uid.as_str())
                .copied()
                .unwrap_or("prn_masked");
            a.user_display = Some(masked.to_string());
        }
    }
}

impl AppState {
    pub async fn users(&self) -> Vec<UserProfile> {
        let guard = self.inner.read().await;
        build_user_profiles(&guard)
    }

    pub async fn user_detail(&self, user_id: &str) -> Result<UserDetailResponse, CodedError> {
        let guard = self.inner.read().await;
        let users = build_user_profiles(&guard);
        let user = users
            .into_iter()
            .find(|u| u.id == user_id || u.pseudonym_id == user_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("User `{user_id}` was not found."),
                    "Pick an active user from Users.",
                )
            })?;

        let uid = user.id.clone();
        let devices: Vec<Device> = guard
            .devices
            .iter()
            .filter(|d| d.user_id.as_deref() == Some(uid.as_str()))
            .cloned()
            .collect();
        let dev_ids: BTreeSet<&str> = devices.iter().map(|d| d.id.as_str()).collect();

        let states = replay_session_states(&guard.attempts, &guard.receipts);
        let mut sessions = summarize_sessions(&guard.attempts, &guard.receipts);
        grdr_core::session::attach_session_labels(&mut sessions, &states);
        sessions.retain(|s| {
            s.user_id.as_deref() == Some(uid.as_str()) || dev_ids.contains(s.device_id.as_str())
        });
        mask_sessions(&mut sessions, &guard);

        let session_ids: BTreeSet<&str> = sessions.iter().map(|s| s.id.as_str()).collect();
        let mut recent_attempts: Vec<ActionAttempt> = guard
            .attempts
            .iter()
            .filter(|a| {
                a.user_id.as_deref() == Some(uid.as_str())
                    || session_ids.contains(a.session_id.as_str())
            })
            .cloned()
            .collect();
        recent_attempts.sort_by_key(|a| std::cmp::Reverse(a.timestamp));
        mask_attempts(&mut recent_attempts, &guard);

        let receipts = guard
            .receipts
            .iter()
            .filter(|r| session_ids.contains(r.session_id.as_str()))
            .cloned()
            .collect();
        let findings = guard
            .findings
            .iter()
            .filter(|f| session_ids.contains(f.session_id.as_str()))
            .cloned()
            .collect();
        let artifacts: Vec<ArtifactEntry> = devices
            .iter()
            .flat_map(|d| d.artifacts.iter().cloned())
            .collect();

        Ok(UserDetailResponse {
            user,
            devices,
            sessions,
            recent_attempts,
            receipts,
            findings,
            artifacts,
            identity_mode: guard.privacy.identity_mode,
            recent_session_details: Vec::new(),
        })
    }

    pub async fn artifacts(&self) -> Vec<ArtifactEntry> {
        let guard = self.inner.read().await;
        let mut list: Vec<ArtifactEntry> = guard
            .devices
            .iter()
            .flat_map(|d| d.artifacts.iter().cloned())
            .collect();
        list.sort_by(|a, b| {
            b.risk_flags
                .len()
                .cmp(&a.risk_flags.len())
                .then_with(|| b.usage_count.cmp(&a.usage_count))
                .then_with(|| a.name.cmp(&b.name))
        });
        list
    }

    pub async fn privacy_config(&self) -> OrgPrivacyConfig {
        let guard = self.inner.read().await;
        guard.privacy.clone()
    }

    pub async fn update_privacy_config(
        &self,
        input: UpdatePrivacyConfigInput,
    ) -> Result<OrgPrivacyConfig, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        let actor = input
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("operator")
            .to_string();

        if let Some(mode) = input.identity_mode {
            guard.privacy.identity_mode = mode;
            if mode == IdentityMode::Pseudonymous {
                guard.privacy.user_risk_scoring = false;
            }
        }
        if let Some(scoring) = input.user_risk_scoring {
            if scoring && guard.privacy.identity_mode == IdentityMode::Pseudonymous {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    "Per-user risk scoring cannot be enabled in works-council pseudonymous mode.",
                    "Switch identity_mode to named first.",
                ));
            }
            guard.privacy.user_risk_scoring = scoring;
        }

        let updated = guard.privacy.clone();
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "privacy.config.updated".into(),
                actor,
                summary: format!(
                    "Privacy mode set to {:?} (user risk scoring: {})",
                    updated.identity_mode, updated.user_risk_scoring
                ),
                target: "org-privacy".into(),
            },
        );
        self.persist_store(&guard)?;
        drop(guard);
        self.emit_live(
            "privacy.updated",
            format!("Privacy mode changed to {:?}", updated.identity_mode),
            None,
        );
        Ok(updated)
    }
}

fn fallback_record(user_id: &str, display: Option<&str>) -> DirectoryUserRecord {
    let label = display
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(user_id)
        .to_string();
    DirectoryUserRecord {
        id: user_id.to_string(),
        display_name: label,
        email: format!("{user_id}@local.invalid"),
        department: "Unassigned".into(),
        idp_source: "local-observed".into(),
        pseudonym_id: format!("prn_{}", user_id.trim_start_matches("usr_")),
    }
}
