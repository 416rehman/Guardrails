// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_compat::SemVer;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError, Mode};
use grdr_proto::api::surfaces::{
    GetProviderWorkspaceResponse, ProviderOrgEntry, ProviderRingSummary, SwitchProviderOrgResponse,
};
use grdr_proto::common::ProviderOrgStatus;
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::surfaces_types::{
    ProviderActingSession, ProviderGovernanceState, ProviderOrgHealthState, ProviderOrgRecord,
    ProviderRingRecord,
};
use super::{AppState, StoreData};

impl AppState {
    pub async fn get_provider_workspace(
        &self,
        org_set_filter: Option<&str>,
        principal_id: &str,
    ) -> GetProviderWorkspaceResponse {
        {
            let mut guard = self.inner.write().await;
            ensure_provider_seeded(&mut guard);
        }
        let guard = self.inner.read().await;
        let state = guard.surfaces.provider.as_ref();
        let set_filter = org_set_filter
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));

        let session = state.and_then(|p| p.acting_sessions.get(principal_id));
        let acting_id = session.map(|s| s.org_id.clone());
        let acting_name = acting_id.as_deref().and_then(|id| {
            state
                .and_then(|p| p.orgs.iter().find(|o| o.org_id == id))
                .map(|o| o.name.clone())
        });
        let acting_reason = session.map(|s| s.reason.clone());

        let orgs = state
            .map(|p| {
                p.orgs
                    .iter()
                    .filter(|o| set_filter.is_none_or(|f| o.org_set == f))
                    .map(|o| ProviderOrgEntry {
                        org_id: o.org_id.clone(),
                        name: o.name.clone(),
                        org_set: o.org_set.clone(),
                        ring: o.ring.clone(),
                        devices_count: o.devices_count,
                        open_findings: o.open_findings,
                        pending_approvals: o.pending_approvals,
                        coverage_pct: o.coverage_pct,
                        floor_version: o.floor_version.clone(),
                        delegated_overrides: o.delegated_overrides,
                        status: match o.status {
                            ProviderOrgHealthState::Healthy => ProviderOrgStatus::Healthy as i32,
                            ProviderOrgHealthState::Attention => {
                                ProviderOrgStatus::Attention as i32
                            }
                            ProviderOrgHealthState::Offline => ProviderOrgStatus::Offline as i32,
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();

        let rings = state
            .map(|p| {
                p.rings
                    .iter()
                    .map(|r| ProviderRingSummary {
                        ring: r.ring.clone(),
                        org_count: r.org_count,
                        target_version: r.target_version.clone(),
                        health_state: r.health_state.clone(),
                        soak_hours: r.soak_hours,
                    })
                    .collect()
            })
            .unwrap_or_default();

        GetProviderWorkspaceResponse {
            acting_as_org_id: acting_id,
            acting_as_org_name: acting_name,
            acting_as_reason: acting_reason,
            orgs,
            rings,
            revision: None,
        }
    }

    pub async fn switch_provider_org(
        &self,
        org_id: Option<&str>,
        reason: Option<&str>,
        auth: &AuthContext,
    ) -> Result<SwitchProviderOrgResponse, CodedError> {
        let now = Timestamp::now();
        let actor_label = auth.principal_id.clone();
        let requested_id = org_id.map(str::trim).filter(|s| !s.is_empty());

        let mut guard = self.inner.write().await;
        ensure_provider_seeded(&mut guard);

        let prov = guard.surfaces.provider.as_mut().ok_or_else(|| {
            CodedError::new(
                CODE_NOT_FOUND,
                "Provider workspace not initialized.",
                "Reload Provider Workbench.",
            )
        })?;

        if let Some(target_id) = requested_id {
            let org_name = prov
                .orgs
                .iter()
                .find(|o| o.org_id == target_id)
                .map(|o| o.name.clone())
                .ok_or_else(|| {
                    CodedError::new(
                        CODE_NOT_FOUND,
                        format!("Managed organization `{target_id}` was not found."),
                        "Select an organization listed in the cross-org queue.",
                    )
                })?;
            let clean_reason = sanitize_inert_text(
                reason
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Cross-tenant investigation and review"),
            );
            prov.acting_sessions.insert(
                actor_label.clone(),
                ProviderActingSession {
                    org_id: target_id.to_owned(),
                    reason: clean_reason.clone(),
                },
            );

            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "provider.acting_as.entered".to_owned(),
                    actor: actor_label,
                    summary: format!("Entered delegated acting-as scope for {org_name}"),
                    target: target_id.to_owned(),
                },
            );
            self.persist_store(&guard)?;
            return Ok(SwitchProviderOrgResponse {
                acting_as_org_id: Some(target_id.to_owned()),
                acting_as_org_name: Some(org_name),
                acting_as_reason: Some(clean_reason),
            });
        }

        prov.acting_sessions.remove(&actor_label);
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "provider.acting_as.exited".to_owned(),
                actor: actor_label,
                summary: "Cleared acting-as delegation scope".to_owned(),
                target: "provider-workbench".to_owned(),
            },
        );
        self.persist_store(&guard)?;
        Ok(SwitchProviderOrgResponse {
            acting_as_org_id: None,
            acting_as_org_name: None,
            acting_as_reason: None,
        })
    }

    pub async fn advance_provider_ring(
        &self,
        ring_name: &str,
        target_version: &str,
        auth: &AuthContext,
    ) -> Result<ProviderRingSummary, CodedError> {
        let now = Timestamp::now();
        let ring_norm = ring_name.trim().to_ascii_lowercase();
        let ver_clean = sanitize_inert_text(target_version.trim());
        let next_ver = SemVer::parse(&ver_clean).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                err.to_string(),
                "Provide a semantic floor pack version such as 1.3.0.",
            )
        })?;

        let mut guard = self.inner.write().await;
        ensure_provider_seeded(&mut guard);

        let locked_floor_intact = guard
            .packs
            .iter()
            .flat_map(|p| p.rules.iter())
            .filter(|r| r.locked)
            .all(|r| r.enabled && r.mode == Mode::Block);
        if !locked_floor_intact {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Delegated rollout ring promotion cannot proceed while baseline locked safety floor rules are weakened.",
                "Restore locked Essentials rules to Block mode first.",
            ));
        }

        let prov = guard.surfaces.provider.as_mut().ok_or_else(|| {
            CodedError::new(
                CODE_NOT_FOUND,
                "Provider workspace unavailable.",
                "Refresh Provider Workbench.",
            )
        })?;

        let idx = prov
            .rings
            .iter()
            .position(|r| r.ring == ring_norm)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Unknown rollout ring `{ring_norm}`."),
                    "Pick canary, wave-1, or broad.",
                )
            })?;

        let current_ring_ver = prov
            .rings
            .get(idx)
            .and_then(|r| SemVer::parse(&r.target_version).ok())
            .unwrap_or_else(|| SemVer::new(0, 0, 0));
        if next_ver < current_ring_ver {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                format!(
                    "Rollout ring `{ring_norm}` cannot be downgraded from v{current_ring_ver} to v{next_ver}."
                ),
                "Provide a floor pack version >= current ring floor.",
            ));
        }

        for org in prov.orgs.iter().filter(|o| o.ring == ring_norm) {
            if let Ok(org_floor) = SemVer::parse(&org.floor_version)
                && next_ver < org_floor
            {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!(
                        "Organization `{}` floor v{org_floor} prevents ring downgrade to v{next_ver}.",
                        org.org_id
                    ),
                    "Provide a semantic version >= organization floor version.",
                ));
            }
        }

        let updated_ring = {
            let Some(slot) = prov.rings.get_mut(idx) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    "Rollout ring missing.",
                    "Refresh.",
                ));
            };
            slot.target_version = ver_clean.clone();
            slot.health_state = "healthy".to_owned();
            slot.clone()
        };

        for org in &mut prov.orgs {
            if org.ring == ring_norm {
                org.floor_version = ver_clean.clone();
            }
        }

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "provider.ring.promoted".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!("Promoted {ring_norm} rollout ring to floor v{ver_clean}"),
                target: ring_norm.clone(),
            },
        );
        self.persist_store(&guard)?;

        Ok(ProviderRingSummary {
            ring: updated_ring.ring,
            org_count: updated_ring.org_count,
            target_version: updated_ring.target_version,
            health_state: updated_ring.health_state,
            soak_hours: updated_ring.soak_hours,
        })
    }
}

fn ensure_provider_seeded(data: &mut StoreData) {
    if data.surfaces.provider.is_some() {
        return;
    }
    data.surfaces.provider = Some(ProviderGovernanceState {
        acting_sessions: BTreeMap::new(),
        orgs: vec![
            ProviderOrgRecord {
                org_id: "org-acme-core".to_owned(),
                name: "Acme Engineering".to_owned(),
                org_set: "global-enterprise".to_owned(),
                ring: "canary".to_owned(),
                devices_count: u32::try_from(data.devices.len().max(2)).unwrap_or(2),
                open_findings: u32::try_from(data.findings.len()).unwrap_or(0),
                pending_approvals: u32::try_from(data.approvals.len()).unwrap_or(0),
                coverage_pct: 78,
                floor_version: "1.2.0".to_owned(),
                delegated_overrides: 2,
                status: ProviderOrgHealthState::Attention,
            },
            ProviderOrgRecord {
                org_id: "org-eu-bauhaus".to_owned(),
                name: "Bauhaus Robotics GmbH".to_owned(),
                org_set: "eu-works-council".to_owned(),
                ring: "wave-1".to_owned(),
                devices_count: 14,
                open_findings: 0,
                pending_approvals: 0,
                coverage_pct: 94,
                floor_version: "1.2.0".to_owned(),
                delegated_overrides: 0,
                status: ProviderOrgHealthState::Healthy,
            },
            ProviderOrgRecord {
                org_id: "org-apac-fintech".to_owned(),
                name: "Kuroshio FinTech".to_owned(),
                org_set: "apac-partners".to_owned(),
                ring: "broad".to_owned(),
                devices_count: 9,
                open_findings: 1,
                pending_approvals: 1,
                coverage_pct: 89,
                floor_version: "1.1.4".to_owned(),
                delegated_overrides: 1,
                status: ProviderOrgHealthState::Healthy,
            },
        ],
        rings: vec![
            ProviderRingRecord {
                ring: "canary".to_owned(),
                org_count: 1,
                target_version: "1.2.0".to_owned(),
                health_state: "soaking".to_owned(),
                soak_hours: 18,
            },
            ProviderRingRecord {
                ring: "wave-1".to_owned(),
                org_count: 1,
                target_version: "1.2.0".to_owned(),
                health_state: "healthy".to_owned(),
                soak_hours: 72,
            },
            ProviderRingRecord {
                ring: "broad".to_owned(),
                org_count: 1,
                target_version: "1.1.4".to_owned(),
                health_state: "healthy".to_owned(),
                soak_hours: 168,
            },
        ],
    });
}
