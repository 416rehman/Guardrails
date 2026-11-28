// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Doc 06 `attribution-hops` pack loader, hop resolution, 13-row basis provenance oracle,
//! attribution score calculus, and positive `ActorKind` classifier (`docs/design/06`).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use grdr_model::{CodedError, Mode};
use serde::{Deserialize, Serialize};

use crate::detect::yaml::{YamlValue, parse_yaml};

use super::graph::EdgeKind;
use super::join::{EvidenceGrade, ProvenanceKind, SessionActorKind};

const EMBEDDED_HOPS_YAML: &str = include_str!("../../../../packs/catalogue/attribution-hops.yaml");

static HOPS_PACK_CACHE: OnceLock<Option<AttributionHopsPack>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BasisValue {
    OsPrincipal,
    SessionCredential,
    SessionContainer,
    ExecTag,
    HumanEntry,
    SystemPrincipal,
    DeclaredMatched,
    DeclaredOnly,
    Lineage,
    Brokered,
    Connector,
    Traffic,
    Timing,
    Influenced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopMediationState {
    Mediated,
    #[default]
    UnmediatedSingleSession,
    UnmediatedMultiSessionConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorScopeVisibility {
    #[default]
    FullHostAndVm,
    HostOnlyNoVmSensor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorOriginCandidate {
    ServiceOrComponent,
    SessionOrAgentHost,
    InteractiveHumanEntry,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanDisqualifier {
    AncestorIsSessionOrAgentHost,
    EntryOpenedByBroker,
    SyntheticOrUiActTarget,
    CarriesExecTag,
    ReachedByBrokerOrIpcEdge,
    SensorBlindToBrokerOrIpc,
    NonHumanPrincipal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasisEvidenceItem {
    pub basis: BasisValue,
    pub provenance: ProvenanceKind,
    pub consistency_valid: bool,
    pub is_registered_stamp: bool,
    pub heuristic_weight: u8,
}

// grdr:allow-s4 Independent declarative YAML flags for hop mediation behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopRuleSpec {
    pub id: String,
    pub aliases: Vec<String>,
    pub elevates: bool,
    pub requires_elevate_decision: bool,
    pub broker_executables: Vec<String>,
    pub socket_patterns: Vec<String>,
    pub mediated_env_vars: Vec<String>,
    pub mediated_grade: u8,
    pub mediated_basis: BasisValue,
    pub unmediated_grade: u8,
    pub unmediated_basis: BasisValue,
    pub edge_kind: EdgeKind,
    pub min_sensor_tier: u8,
    pub requires_vm_guest_sensor_on_non_linux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionHopsPack {
    pub default_window_ms: u64,
    pub hops: Vec<HopRuleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HopObservation {
    pub hop_id_or_exec: String,
    pub mediation: HopMediationState,
    pub host_sensor_tier: u8,
    pub scope_visibility: SensorScopeVisibility,
    pub elevate_decided_mode: Option<Mode>,
    pub host_os: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopResolution {
    pub hop_id: String,
    pub edge_kind: Option<EdgeKind>,
    pub basis: BasisValue,
    pub grade: EvidenceGrade,
    pub requires_elevate_decision: bool,
    pub undeclared_elevate_hop: bool,
    pub coverage_gap_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorResolutionInput {
    pub attribution_grade: EvidenceGrade,
    pub min_attribution_grade: EvidenceGrade,
    pub origin_candidate: ActorOriginCandidate,
    pub human_disqualifiers: BTreeSet<HumanDisqualifier>,
    pub candidate_sessions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorDetermination {
    pub actor_kind: SessionActorKind,
    pub added_basis: Option<BasisValue>,
    pub candidate_sessions_local: Vec<String>,
}

impl Default for ActorResolutionInput {
    fn default() -> Self {
        Self {
            attribution_grade: EvidenceGrade::Grade0,
            min_attribution_grade: EvidenceGrade::Grade1,
            origin_candidate: ActorOriginCandidate::Other,
            human_disqualifiers: BTreeSet::new(),
            candidate_sessions: Vec::new(),
        }
    }
}

impl BasisValue {
    #[must_use]
    pub const fn max_grade(self) -> EvidenceGrade {
        match self {
            Self::OsPrincipal | Self::SessionCredential => EvidenceGrade::Grade4,
            Self::SessionContainer | Self::ExecTag | Self::HumanEntry | Self::SystemPrincipal => {
                EvidenceGrade::Grade3
            }
            Self::DeclaredMatched => EvidenceGrade::Grade2,
            Self::DeclaredOnly | Self::Lineage | Self::Brokered | Self::Connector => {
                EvidenceGrade::Grade1
            }
            Self::Traffic | Self::Timing | Self::Influenced => EvidenceGrade::Grade0,
        }
    }

    #[must_use]
    pub const fn may_appear_in_unless(self) -> bool {
        !matches!(
            self,
            Self::DeclaredOnly | Self::Traffic | Self::Timing | Self::Influenced
        )
    }

    #[must_use]
    pub const fn counts_toward_grade(self) -> bool {
        !matches!(self, Self::Influenced)
    }

    fn from_yaml_str(raw: &str) -> Result<Self, CodedError> {
        match raw.trim() {
            "os-principal" => Ok(Self::OsPrincipal),
            "session-credential" => Ok(Self::SessionCredential),
            "session-container" => Ok(Self::SessionContainer),
            "exec-tag" => Ok(Self::ExecTag),
            "human-entry" => Ok(Self::HumanEntry),
            "system-principal" => Ok(Self::SystemPrincipal),
            "declared-matched" => Ok(Self::DeclaredMatched),
            "declared-only" => Ok(Self::DeclaredOnly),
            "lineage" => Ok(Self::Lineage),
            "brokered" => Ok(Self::Brokered),
            "connector" => Ok(Self::Connector),
            "traffic" => Ok(Self::Traffic),
            "timing" => Ok(Self::Timing),
            "influenced" => Ok(Self::Influenced),
            other => Err(hop_err(format!("unknown attribution basis `{other}`"))),
        }
    }
}

impl AttributionHopsPack {
    pub fn embedded() -> Result<&'static Self, CodedError> {
        HOPS_PACK_CACHE
            .get_or_init(|| Self::from_yaml_str(EMBEDDED_HOPS_YAML).ok())
            .as_ref()
            .ok_or_else(|| hop_err("embedded attribution-hops pack invalid"))
    }

    pub fn from_yaml_str(raw: &str) -> Result<Self, CodedError> {
        let doc = parse_yaml(raw).map_err(|e| hop_err(e.to_string()))?;
        let root = doc
            .as_map()
            .ok_or_else(|| hop_err("attribution-hops root must be a YAML map"))?;
        let default_window_ms = root
            .get("default_window_ms")
            .and_then(YamlValue::as_i64)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(5_000);
        let hops_seq = root
            .get("hops")
            .and_then(YamlValue::as_seq)
            .ok_or_else(|| hop_err("attribution-hops missing `hops` list"))?;
        let mut hops = Vec::with_capacity(hops_seq.len());
        for entry in hops_seq {
            let map = entry
                .as_map()
                .ok_or_else(|| hop_err("hop entry must be a YAML map"))?;
            let id = req_hop_str(map, "id")?;
            let edge_kind = match req_hop_str(map, "edge_kind")?.as_str() {
                "brokered" => EdgeKind::Brokered,
                "ipc" => EdgeKind::Ipc,
                "influenced-by" => EdgeKind::InfluencedBy,
                other => return Err(hop_err(format!("unsupported hop edge_kind `{other}`"))),
            };
            hops.push(HopRuleSpec {
                id,
                aliases: str_seq(map, "aliases"),
                elevates: map
                    .get("elevates")
                    .and_then(YamlValue::as_bool)
                    .unwrap_or(false),
                requires_elevate_decision: map
                    .get("requires_elevate_decision")
                    .and_then(YamlValue::as_bool)
                    .unwrap_or(false),
                broker_executables: str_seq(map, "broker_executables"),
                socket_patterns: str_seq(map, "socket_patterns"),
                mediated_env_vars: str_seq(map, "mediated_env_vars"),
                mediated_grade: validated_u8_grade(map, "mediated_grade", 1)?,
                mediated_basis: BasisValue::from_yaml_str(&req_hop_str(map, "mediated_basis")?)?,
                unmediated_grade: validated_u8_grade(map, "unmediated_grade", 1)?,
                unmediated_basis: BasisValue::from_yaml_str(&req_hop_str(
                    map,
                    "unmediated_basis",
                )?)?,
                edge_kind,
                min_sensor_tier: u8_field(map, "min_sensor_tier", 1),
                requires_vm_guest_sensor_on_non_linux: map
                    .get("requires_vm_guest_sensor_on_non_linux")
                    .and_then(YamlValue::as_bool)
                    .unwrap_or(false),
            });
        }
        Ok(Self {
            default_window_ms,
            hops,
        })
    }

    #[must_use]
    pub fn resolve(&self, name_or_exec: &str) -> Option<&HopRuleSpec> {
        let needle = name_or_exec.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        self.hops.iter().find(|h| {
            h.id.eq_ignore_ascii_case(&needle)
                || h.aliases.iter().any(|a| a.eq_ignore_ascii_case(&needle))
                || h.broker_executables
                    .iter()
                    .any(|exe| exe.eq_ignore_ascii_case(&needle))
        })
    }
}

#[must_use]
pub fn provenance_floor_met(item: &BasisEvidenceItem) -> bool {
    if !item.consistency_valid {
        return false;
    }
    match item.basis {
        BasisValue::OsPrincipal | BasisValue::HumanEntry | BasisValue::SessionContainer => {
            matches!(
                item.provenance,
                ProvenanceKind::ObservedKernel | ProvenanceKind::Mediated
            )
        }
        BasisValue::SessionCredential => matches!(item.provenance, ProvenanceKind::Mediated),
        BasisValue::ExecTag => {
            item.is_registered_stamp
                || matches!(
                    item.provenance,
                    ProvenanceKind::ObservedKernel | ProvenanceKind::Mediated
                )
        }
        BasisValue::SystemPrincipal
        | BasisValue::DeclaredMatched
        | BasisValue::Lineage
        | BasisValue::Brokered
        | BasisValue::Influenced => matches!(
            item.provenance,
            ProvenanceKind::ObservedKernel
                | ProvenanceKind::Mediated
                | ProvenanceKind::ObservedUser
        ),
        BasisValue::DeclaredOnly
        | BasisValue::Connector
        | BasisValue::Traffic
        | BasisValue::Timing => true,
    }
}

#[must_use]
pub fn resolve_basis_grade(
    items: &[BasisEvidenceItem],
) -> (EvidenceGrade, Option<BasisValue>, BTreeSet<BasisValue>) {
    let mut best_grade = EvidenceGrade::Grade0;
    let mut best_basis = None;
    let mut active_basis = BTreeSet::new();

    for item in items {
        if !provenance_floor_met(item) {
            continue;
        }
        active_basis.insert(item.basis);
        if !item.basis.counts_toward_grade() {
            continue;
        }
        let g = item.basis.max_grade();
        if best_basis.is_none() || g > best_grade {
            best_grade = g;
            best_basis = Some(item.basis);
        }
    }
    (best_grade, best_basis, active_basis)
}

#[must_use]
pub fn compute_attribution_score(items: &[BasisEvidenceItem], edge_weights_pct: &[u8]) -> u8 {
    let base = items
        .iter()
        .filter(|i| provenance_floor_met(i) && i.basis.counts_toward_grade())
        .map(|i| u64::from(i.heuristic_weight.min(100)))
        .max()
        .unwrap_or(0);
    let score = edge_weights_pct.iter().fold(base, |acc, w| {
        acc.saturating_mul(u64::from((*w).min(100)))
            .checked_div(100)
            .unwrap_or(0)
    });
    u8::try_from(score.min(100)).unwrap_or(100)
}

#[must_use]
pub fn evaluate_hop(spec: &HopRuleSpec, obs: &HopObservation) -> HopResolution {
    if obs.host_sensor_tier < spec.min_sensor_tier {
        return HopResolution {
            hop_id: spec.id.clone(),
            edge_kind: None,
            basis: spec.unmediated_basis,
            grade: EvidenceGrade::Grade0,
            requires_elevate_decision: spec.requires_elevate_decision,
            undeclared_elevate_hop: spec.requires_elevate_decision
                && obs.elevate_decided_mode.is_none(),
            coverage_gap_reason: Some(format!(
                "sensor tier {} below required tier {} for `{}` hop",
                obs.host_sensor_tier, spec.min_sensor_tier, spec.id
            )),
        };
    }

    let undeclared_elevate = spec.requires_elevate_decision && obs.elevate_decided_mode.is_none();
    match obs.mediation {
        HopMediationState::Mediated => {
            let observed_os = obs.host_os.as_deref().unwrap_or(std::env::consts::OS);
            let gap = (spec.requires_vm_guest_sensor_on_non_linux
                && obs.scope_visibility == SensorScopeVisibility::HostOnlyNoVmSensor
                && !observed_os.eq_ignore_ascii_case("linux"))
            .then(|| "far-side container VM requires in-guest sensor".to_string());
            HopResolution {
                hop_id: spec.id.clone(),
                edge_kind: Some(spec.edge_kind),
                basis: spec.mediated_basis,
                grade: grade_from_u8(spec.mediated_grade),
                requires_elevate_decision: spec.requires_elevate_decision,
                undeclared_elevate_hop: undeclared_elevate,
                coverage_gap_reason: gap,
            }
        }
        HopMediationState::UnmediatedMultiSessionConflict => HopResolution {
            hop_id: spec.id.clone(),
            edge_kind: Some(spec.edge_kind),
            basis: BasisValue::Timing,
            grade: EvidenceGrade::Grade0,
            requires_elevate_decision: spec.requires_elevate_decision,
            undeclared_elevate_hop: undeclared_elevate,
            coverage_gap_reason: Some(
                "multiple sessions contacted unmediated broker in window".to_string(),
            ),
        },
        HopMediationState::UnmediatedSingleSession => HopResolution {
            hop_id: spec.id.clone(),
            edge_kind: Some(spec.edge_kind),
            basis: spec.unmediated_basis,
            grade: grade_from_u8(spec.unmediated_grade),
            requires_elevate_decision: spec.requires_elevate_decision,
            undeclared_elevate_hop: undeclared_elevate,
            coverage_gap_reason: None,
        },
    }
}

#[must_use]
pub fn determine_actor_kind(input: &ActorResolutionInput) -> ActorDetermination {
    if input.origin_candidate == ActorOriginCandidate::ServiceOrComponent {
        return ActorDetermination {
            actor_kind: SessionActorKind::System,
            added_basis: Some(BasisValue::SystemPrincipal),
            candidate_sessions_local: Vec::new(),
        };
    }
    if input.attribution_grade >= input.min_attribution_grade
        && !input.candidate_sessions.is_empty()
    {
        return ActorDetermination {
            actor_kind: SessionActorKind::Agent,
            added_basis: None,
            candidate_sessions_local: Vec::new(),
        };
    }
    if input.origin_candidate == ActorOriginCandidate::InteractiveHumanEntry
        && input.human_disqualifiers.is_empty()
    {
        return ActorDetermination {
            actor_kind: SessionActorKind::Human,
            added_basis: Some(BasisValue::HumanEntry),
            candidate_sessions_local: Vec::new(),
        };
    }
    let bounded_candidates = input.candidate_sessions.iter().take(3).cloned().collect();
    ActorDetermination {
        actor_kind: SessionActorKind::Undetermined,
        added_basis: None,
        candidate_sessions_local: bounded_candidates,
    }
}

const fn grade_from_u8(raw: u8) -> EvidenceGrade {
    match raw {
        4 => EvidenceGrade::Grade4,
        3 => EvidenceGrade::Grade3,
        2 => EvidenceGrade::Grade2,
        1 => EvidenceGrade::Grade1,
        _ => EvidenceGrade::Grade0,
    }
}

fn hop_err(detail: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-SESS-0004",
        detail,
        "Verify packs/catalogue/attribution-hops.yaml schema and fields.",
    )
}

fn req_hop_str(
    map: &std::collections::BTreeMap<String, YamlValue>,
    key: &str,
) -> Result<String, CodedError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| hop_err(format!("missing hop string field `{key}`")))
}

fn str_seq(map: &std::collections::BTreeMap<String, YamlValue>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(YamlValue::as_seq)
        .map(|s| {
            s.iter()
                .filter_map(YamlValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn validated_u8_grade(
    map: &std::collections::BTreeMap<String, YamlValue>,
    key: &str,
    default: u8,
) -> Result<u8, CodedError> {
    match map.get(key) {
        None => Ok(default),
        Some(v) => {
            let n = v
                .as_i64()
                .ok_or_else(|| hop_err(format!("hop field `{key}` must be an integer 0..=4")))?;
            if !(0..=4).contains(&n) {
                return Err(hop_err(format!(
                    "hop field `{key}` out of range 0..=4: {n}"
                )));
            }
            Ok(u8::try_from(n).unwrap_or(default))
        }
    }
}

fn u8_field(map: &std::collections::BTreeMap<String, YamlValue>, key: &str, default: u8) -> u8 {
    map.get(key)
        .and_then(YamlValue::as_i64)
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_provenance_floors_and_hops_and_human_entry_gates_hold() {
        let pack = AttributionHopsPack::embedded().expect("hops pack loads");
        assert!(pack.resolve("docker").is_some());
        assert!(pack.resolve("svchost.exe").is_some());

        let docker = pack.resolve("docker").unwrap();
        let mac_gap = evaluate_hop(
            docker,
            &HopObservation {
                hop_id_or_exec: "docker".into(),
                mediation: HopMediationState::Mediated,
                host_sensor_tier: 2,
                scope_visibility: SensorScopeVisibility::HostOnlyNoVmSensor,
                elevate_decided_mode: Some(Mode::Block),
                host_os: Some("macos".into()),
            },
        );
        assert!(mac_gap.coverage_gap_reason.is_some());
        let linux_no_gap = evaluate_hop(
            docker,
            &HopObservation {
                host_os: Some("linux".into()),
                mediation: HopMediationState::Mediated,
                host_sensor_tier: 2,
                scope_visibility: SensorScopeVisibility::HostOnlyNoVmSensor,
                elevate_decided_mode: Some(Mode::Block),
                ..HopObservation::default()
            },
        );
        assert!(linux_no_gap.coverage_gap_reason.is_none());

        assert!(
            AttributionHopsPack::from_yaml_str(
                "hops:\n  - id: bad\n    mediated_grade: 9\n    mediated_basis: exec-tag\n    unmediated_basis: brokered\n    edge_kind: brokered\n"
            )
            .is_err()
        );

        let launchd = pack.resolve("launchd-xpc").unwrap();
        let mac_t2 = evaluate_hop(
            launchd,
            &HopObservation {
                hop_id_or_exec: "osascript".into(),
                mediation: HopMediationState::UnmediatedSingleSession,
                host_sensor_tier: 2,
                scope_visibility: SensorScopeVisibility::FullHostAndVm,
                elevate_decided_mode: None,
                host_os: None,
            },
        );
        assert!(mac_t2.edge_kind.is_none());
        assert!(mac_t2.coverage_gap_reason.is_some());

        let user_exec_tag = BasisEvidenceItem {
            basis: BasisValue::ExecTag,
            provenance: ProvenanceKind::ObservedUser,
            consistency_valid: true,
            is_registered_stamp: false,
            heuristic_weight: 95,
        };
        assert!(!provenance_floor_met(&user_exec_tag));
        let (g, _, _) = resolve_basis_grade(&[user_exec_tag]);
        assert_eq!(g, EvidenceGrade::Grade0);

        let broker_opened = determine_actor_kind(&ActorResolutionInput {
            origin_candidate: ActorOriginCandidate::InteractiveHumanEntry,
            human_disqualifiers: [HumanDisqualifier::EntryOpenedByBroker]
                .into_iter()
                .collect(),
            candidate_sessions: vec!["s1".into(), "s2".into(), "s3".into(), "s4".into()],
            ..ActorResolutionInput::default()
        });
        assert_eq!(broker_opened.actor_kind, SessionActorKind::Undetermined);
        assert_eq!(broker_opened.candidate_sessions_local.len(), 3);
        assert!(!BasisValue::DeclaredOnly.may_appear_in_unless());
        assert!(!BasisValue::Influenced.may_appear_in_unless());
    }
}
