// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 4 declared-vs-observed inventory reconciliation, drift triage, and ABOM synthesis (`docs/design/05`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_core::discover::{ProgramIdentity, canonical_sha256_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Absent,
    InstalledOnly,
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffState {
    DeclaredAndRunning,
    DeclaredAndInstalled,
    DeclaredAbsent,
    ObservedUndeclared,
    ShadowOrDrift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    SignerChanged,
    ArtifactDigestChanged,
    RemoteEndpointAdded,
    ProgramIdentityChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDeclaration {
    pub agent_id: String,
    pub expected_program_id: Option<String>,
    pub expected_signer: Option<String>,
    pub allowed_hosts: BTreeSet<String>,
    pub approved_artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedAgentState {
    pub agent_id: String,
    pub program_identity: ProgramIdentity,
    pub presence: PresenceState,
    pub observed_signer: Option<String>,
    pub observed_hosts: BTreeSet<String>,
    pub observed_artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryDiffRecord {
    pub agent_id: String,
    pub diff_state: DiffState,
    pub drift_kinds: BTreeSet<DriftKind>,
    pub program_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbomComponent {
    pub agent_id: String,
    pub program_id: String,
    pub diff_state: DiffState,
    pub drift_kinds: BTreeSet<DriftKind>,
    pub artifact_digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBom {
    pub schema: String,
    pub device_id: String,
    pub components: Vec<AbomComponent>,
    pub bom_digest: String,
}

#[must_use]
pub fn reconcile_inventory_diff(
    declared: &[AgentDeclaration],
    observed: &[ObservedAgentState],
) -> Vec<InventoryDiffRecord> {
    let decl_map: BTreeMap<&str, &AgentDeclaration> =
        declared.iter().map(|d| (d.agent_id.as_str(), d)).collect();
    let obs_map: BTreeMap<&str, &ObservedAgentState> =
        observed.iter().map(|o| (o.agent_id.as_str(), o)).collect();
    let all_ids: BTreeSet<&str> = decl_map.keys().chain(obs_map.keys()).copied().collect();

    all_ids
        .into_iter()
        .filter_map(|id| match (decl_map.get(id), obs_map.get(id)) {
            (Some(d), Some(o)) => Some(diff_matched_agent(id, d, o)),
            (Some(d), None) => Some(InventoryDiffRecord {
                agent_id: id.into(),
                diff_state: DiffState::DeclaredAbsent,
                drift_kinds: BTreeSet::new(),
                program_id: d
                    .expected_program_id
                    .clone()
                    .unwrap_or_else(|| format!("declared:{id}")),
            }),
            (None, Some(o)) => Some(InventoryDiffRecord {
                agent_id: id.into(),
                diff_state: DiffState::ObservedUndeclared,
                drift_kinds: BTreeSet::new(),
                program_id: o.program_identity.canonical_id(),
            }),
            (None, None) => None,
        })
        .collect()
}

fn diff_matched_agent(
    id: &str,
    decl: &AgentDeclaration,
    obs: &ObservedAgentState,
) -> InventoryDiffRecord {
    let program_id = obs.program_identity.canonical_id();
    let mut drift_kinds = BTreeSet::new();
    if decl
        .expected_program_id
        .as_deref()
        .is_some_and(|e| e != program_id)
    {
        drift_kinds.insert(DriftKind::ProgramIdentityChanged);
    }
    if decl.expected_signer != obs.observed_signer {
        drift_kinds.insert(DriftKind::SignerChanged);
    }
    if !decl.allowed_hosts.is_empty()
        && obs
            .observed_hosts
            .iter()
            .any(|h| !decl.allowed_hosts.contains(h))
    {
        drift_kinds.insert(DriftKind::RemoteEndpointAdded);
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
        drift_kinds.insert(DriftKind::ArtifactDigestChanged);
    }
    let diff_state = if !drift_kinds.is_empty() {
        DiffState::ShadowOrDrift
    } else {
        match obs.presence {
            PresenceState::Running => DiffState::DeclaredAndRunning,
            PresenceState::InstalledOnly => DiffState::DeclaredAndInstalled,
            PresenceState::Absent => DiffState::DeclaredAbsent,
        }
    };
    InventoryDiffRecord {
        agent_id: id.into(),
        diff_state,
        drift_kinds,
        program_id,
    }
}

#[must_use]
pub fn build_agent_bom(
    device_id: &str,
    diff_records: &[InventoryDiffRecord],
    observed: &[ObservedAgentState],
) -> AgentBom {
    let arts: BTreeMap<&str, &BTreeMap<String, String>> = observed
        .iter()
        .map(|o| (o.agent_id.as_str(), &o.observed_artifacts))
        .collect();
    let components: Vec<AbomComponent> = diff_records
        .iter()
        .map(|rec| AbomComponent {
            agent_id: rec.agent_id.clone(),
            program_id: rec.program_id.clone(),
            diff_state: rec.diff_state,
            drift_kinds: rec.drift_kinds.clone(),
            artifact_digests: arts
                .get(rec.agent_id.as_str())
                .map(|m| (*m).clone())
                .unwrap_or_default(),
        })
        .collect();
    let canonical = serde_json::to_vec(&(&device_id, &components)).unwrap_or_default();
    AgentBom {
        schema: "grdr.abom.v1alpha1".into(),
        device_id: device_id.into(),
        components,
        bom_digest: canonical_sha256_hex(&canonical),
    }
}
