// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 4 fleet 6-state reconciliation and P8-scoped org fingerprint synthesis (`docs/design/05`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_core::discover::{ProgramIdentity, canonical_sha256_hex};
use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

use crate::abom::{DriftKind, ObservedAgentState};

const ORG_CATALOGUE_HMAC_DOMAIN: &str = "grdr.org_catalogue.entry.v1";
const PUBLIC_IMAGE_REGISTRIES: &[&str] =
    &["docker.io/", "ghcr.io/", "registry.k8s.io/", "quay.io/"];
const SECONDS_PER_DAY: u64 = 86_400;
const STALE_DECLARATION_DAYS: u64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FleetInventoryState {
    Matched,
    Shadow,
    DeclaredUnseen,
    DeclaredBlind,
    Mismatch,
    IncumbentOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetDeclarationRecord {
    pub agent_id: String,
    pub declared_at_epoch_secs: u64,
    pub expected_signer: Option<String>,
    pub allowed_hosts: BTreeSet<String>,
    pub approved_artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetReconcileRow {
    pub agent_id: String,
    pub state: FleetInventoryState,
    pub drift_kinds: BTreeSet<DriftKind>,
    pub finding_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgEntryAttributes {
    pub agent_kind: String,
    pub sponsor_team: String,
    pub building_blocks: Vec<String>,
    pub inference_hosts: Vec<String>,
    pub env_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgCatalogueEntry {
    pub id: String,
    pub scope: String,
    pub catalogue_tier: String,
    pub primary_route: String,
    pub agent_kind: String,
    pub session_exclusive: bool,
    pub min_attribution_grade: u8,
    pub containment_default: String,
    pub sponsor_team: String,
    pub initial_mode: String,
    pub signer: Option<String>,
    pub package: Option<String>,
    pub image_repository: Option<String>,
    pub building_blocks: Vec<String>,
    pub inference_hosts: Vec<String>,
    pub env_markers: Vec<String>,
}

#[must_use]
pub fn reconcile_fleet_states(
    declared: &[FleetDeclarationRecord],
    observed: &[ObservedAgentState],
    sensor_blind: bool,
    incumbent_seen_ids: &BTreeSet<String>,
    now_epoch_secs: u64,
) -> Vec<FleetReconcileRow> {
    let decl_map: BTreeMap<&str, &FleetDeclarationRecord> =
        declared.iter().map(|d| (d.agent_id.as_str(), d)).collect();
    let obs_map: BTreeMap<&str, &ObservedAgentState> =
        observed.iter().map(|o| (o.agent_id.as_str(), o)).collect();
    let all_ids: BTreeSet<&str> = decl_map
        .keys()
        .copied()
        .chain(obs_map.keys().copied())
        .chain(incumbent_seen_ids.iter().map(String::as_str))
        .collect();

    let stale_cutoff = STALE_DECLARATION_DAYS.saturating_mul(SECONDS_PER_DAY);
    all_ids
        .into_iter()
        .filter_map(|id| {
            let d = decl_map.get(id).copied();
            let o = obs_map.get(id).copied();
            let inc = incumbent_seen_ids.contains(id);
            match (d, o) {
                (Some(decl), Some(obs)) => {
                    let drift = compute_declaration_drift(decl, obs);
                    let (state, finding_rule) = if drift.is_empty() {
                        (FleetInventoryState::Matched, None)
                    } else {
                        (
                            FleetInventoryState::Mismatch,
                            Some("policy.violation".into()),
                        )
                    };
                    Some(FleetReconcileRow {
                        agent_id: id.into(),
                        state,
                        drift_kinds: drift,
                        finding_rule,
                    })
                }
                (Some(decl), None) => {
                    if sensor_blind {
                        Some(FleetReconcileRow {
                            agent_id: id.into(),
                            state: FleetInventoryState::DeclaredBlind,
                            drift_kinds: BTreeSet::new(),
                            finding_rule: Some("coverage.gap".into()),
                        })
                    } else {
                        let age = now_epoch_secs.saturating_sub(decl.declared_at_epoch_secs);
                        let rule = if age >= stale_cutoff {
                            Some("discovery.declaration-stale".into())
                        } else {
                            None
                        };
                        Some(FleetReconcileRow {
                            agent_id: id.into(),
                            state: FleetInventoryState::DeclaredUnseen,
                            drift_kinds: BTreeSet::new(),
                            finding_rule: rule,
                        })
                    }
                }
                (None, Some(_)) => Some(FleetReconcileRow {
                    agent_id: id.into(),
                    state: FleetInventoryState::Shadow,
                    drift_kinds: BTreeSet::new(),
                    finding_rule: Some("discovery.unknown-agent".into()),
                }),
                (None, None) if inc => Some(FleetReconcileRow {
                    agent_id: id.into(),
                    state: FleetInventoryState::IncumbentOnly,
                    drift_kinds: BTreeSet::new(),
                    finding_rule: Some("coverage.gap.incumbent".into()),
                }),
                _ => None,
            }
        })
        .collect()
}

pub fn generate_org_catalogue_entry(
    identity: &ProgramIdentity,
    tenant_salt: &[u8],
    declared_forges: &[String],
    attrs: OrgEntryAttributes,
) -> Result<OrgCatalogueEntry, CodedError> {
    let scoped_route = identity.try_scoped_identity_id(tenant_salt, declared_forges)?;
    let mac = domain_hmac_sha256(
        tenant_salt,
        ORG_CATALOGUE_HMAC_DOMAIN,
        scoped_route.as_bytes(),
    );
    let hex = encode_lower_hex(&mac);
    let short = hex.get(..12).unwrap_or(hex.as_str());
    let (signer, package, image_repository) = match identity {
        ProgramIdentity::CodeSigned { signer, .. } => (Some(signer.clone()), None, None),
        ProgramIdentity::PackageOwned {
            ecosystem, package, ..
        } => (None, Some(format!("{ecosystem}:{package}")), None),
        ProgramIdentity::ImageDigest { sha256 } => {
            (None, None, sha256.contains('/').then(|| sha256.clone()))
        }
        ProgramIdentity::SourceTree { .. } | ProgramIdentity::RawPath { .. } => (None, None, None),
    };
    Ok(OrgCatalogueEntry {
        id: format!("agt_x_{short}"),
        scope: "organisation".into(),
        catalogue_tier: "bespoke".into(),
        primary_route: scoped_route,
        agent_kind: attrs.agent_kind,
        session_exclusive: true,
        min_attribution_grade: 2,
        containment_default: "watch".into(),
        sponsor_team: attrs.sponsor_team,
        initial_mode: "watch".into(),
        signer,
        package,
        image_repository,
        building_blocks: attrs.building_blocks,
        inference_hosts: attrs.inference_hosts,
        env_markers: attrs.env_markers,
    })
}

#[must_use]
pub fn sanitize_upstream_proposal(entry: &OrgCatalogueEntry) -> Option<OrgCatalogueEntry> {
    let mut sanitized = entry.clone();
    sanitized.scope = "upstream-proposal".into();
    sanitized.sponsor_team = "community".into();
    sanitized.inference_hosts = Vec::new();
    sanitized.building_blocks = Vec::new();
    sanitized.env_markers = Vec::new();
    let confirmed_public_repo = sanitized.image_repository.as_deref().is_some_and(|repo| {
        !repo.contains("hmac_")
            && !repo.contains("internal")
            && sanitized.primary_route.starts_with("img:")
            && !sanitized.primary_route.starts_with("img:hmac_")
            && PUBLIC_IMAGE_REGISTRIES
                .iter()
                .any(|prefix| repo.starts_with(prefix))
    });
    if !confirmed_public_repo {
        sanitized.image_repository = None;
    }
    if sanitized.signer.is_none()
        && sanitized.package.is_none()
        && sanitized.image_repository.is_none()
    {
        return None;
    }
    if !(sanitized.primary_route.starts_with("sig:") || sanitized.primary_route.starts_with("pkg:"))
    {
        sanitized.primary_route = format!("proposal:{}", sanitized.agent_kind);
    }
    let digest = canonical_sha256_hex(sanitized.primary_route.as_bytes());
    sanitized.id = format!("prop_{}", digest.get(..12).unwrap_or(digest.as_str()));
    Some(sanitized)
}

fn compute_declaration_drift(
    decl: &FleetDeclarationRecord,
    obs: &ObservedAgentState,
) -> BTreeSet<DriftKind> {
    let mut drift = BTreeSet::new();
    if decl.expected_signer.is_some() && decl.expected_signer != obs.observed_signer {
        drift.insert(DriftKind::SignerChanged);
    }
    if !decl.allowed_hosts.is_empty()
        && obs
            .observed_hosts
            .iter()
            .any(|h| !decl.allowed_hosts.contains(h))
    {
        drift.insert(DriftKind::RemoteEndpointAdded);
    }
    if !decl.approved_artifacts.is_empty()
        && (decl
            .approved_artifacts
            .iter()
            .any(|(k, v)| obs.observed_artifacts.get(k) != Some(v))
            || obs
                .observed_artifacts
                .keys()
                .any(|k| !decl.approved_artifacts.contains_key(k)))
    {
        drift.insert(DriftKind::ArtifactDigestChanged);
    }
    drift
}
