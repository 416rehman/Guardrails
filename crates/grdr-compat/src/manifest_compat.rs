// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Release-manifest compatibility graph and component digest delta evaluation (`D-71`, `E1.7`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::SemVer;
use super::codes::CompatError;
use super::support::SupportContract;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestContractRange {
    pub min: String,
    pub max: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestCompatGraph {
    pub wire_major: u32,
    pub schema_rev: u32,
    pub pack_format: SemVer,
    pub driver_interface: SemVer,
    pub contracts: BTreeMap<String, ManifestContractRange>,
    pub min_upgrade_from: SemVer,
    pub required_stops: Vec<SemVer>,
    pub postgresql_major: u32,
    pub kubernetes_min: String,
    pub helm_min: SemVer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestComponentState {
    pub name: String,
    pub version: SemVer,
    pub sha256: String,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDigestDelta {
    pub name: String,
    pub previous_version: SemVer,
    pub next_version: SemVer,
    pub previous_sha256: String,
    pub next_sha256: String,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ContractStage {
    Alpha(u32),
    Beta(u32),
    Stable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ContractVersion {
    major: u32,
    minor: u32,
    patch: u32,
    stage: ContractStage,
}

pub fn evaluate_manifest_compat(
    support: &SupportContract,
    graph: &ManifestCompatGraph,
) -> Result<(), CompatError> {
    let matrix = &support.compatibility_matrix;
    if graph.wire_major != matrix.wire_major {
        return Err(CompatError::UnsupportedVersion(format!(
            "manifest wire_major {} does not match support contract {}",
            graph.wire_major, matrix.wire_major
        )));
    }
    if graph.schema_rev != matrix.schema_rev {
        return Err(CompatError::UnsupportedVersion(format!(
            "manifest schema_rev {} does not match support contract {}",
            graph.schema_rev, matrix.schema_rev
        )));
    }
    if !matrix.pack_format_range.contains(graph.pack_format) {
        return Err(CompatError::UnsupportedVersion(format!(
            "pack_format {} outside [{}, {:?})",
            graph.pack_format,
            matrix.pack_format_range.min_inclusive,
            matrix.pack_format_range.max_exclusive
        )));
    }
    if !matrix
        .driver_interface_range
        .contains(graph.driver_interface)
    {
        return Err(CompatError::UnsupportedVersion(format!(
            "driver_interface {} outside [{}, {:?})",
            graph.driver_interface,
            matrix.driver_interface_range.min_inclusive,
            matrix.driver_interface_range.max_exclusive
        )));
    }

    for spec in &matrix.contracts {
        let Some(range) = graph.contracts.get(&spec.name) else {
            return Err(CompatError::UnsupportedVersion(format!(
                "manifest compat missing contract `{}`",
                spec.name
            )));
        };
        let min_v = parse_contract_version(&range.min)?;
        let max_v = parse_contract_version(&range.max)?;
        if min_v > max_v {
            return Err(CompatError::InvalidRange {
                component: spec.name.clone(),
            });
        }
        let spec_v = parse_contract_version(&spec.version)?;
        if min_v > spec_v || spec_v > max_v {
            return Err(CompatError::UnsupportedVersion(format!(
                "contract `{}` version `{}` outside manifest range [{}, {}]",
                spec.name, spec.version, range.min, range.max
            )));
        }
        if spec.frozen && (min_v != spec_v || max_v != spec_v) {
            return Err(CompatError::UnsupportedVersion(format!(
                "frozen contract `{}` ({}) cannot widen manifest range [{}, {}]",
                spec.name, spec.version, range.min, range.max
            )));
        }
    }

    validate_upgrade_stops_against_support(support, graph)?;

    if graph.postgresql_major < support.platform.postgresql_major {
        return Err(CompatError::UnsupportedVersion(format!(
            "postgresql_major {} below required {}",
            graph.postgresql_major, support.platform.postgresql_major
        )));
    }
    let k8s_minor = kubernetes_minor_line(&graph.kubernetes_min).ok_or_else(|| {
        CompatError::InvalidSemVer(format!("kubernetes_min `{}`", graph.kubernetes_min))
    })?;
    if !support
        .platform
        .kubernetes_supported
        .iter()
        .any(|v| v == &k8s_minor)
    {
        return Err(CompatError::UnsupportedVersion(format!(
            "kubernetes_min {} ({}) not in supported {:?}",
            graph.kubernetes_min, k8s_minor, support.platform.kubernetes_supported
        )));
    }
    let helm_ok = match graph.helm_min.major {
        3 => graph.helm_min >= support.platform.helm_min_v3,
        4.. => graph.helm_min >= support.platform.helm_min_v4,
        _ => false,
    };
    if !helm_ok {
        return Err(CompatError::UnsupportedVersion(format!(
            "helm_min {} below supported v3 ({}) / v4 ({})",
            graph.helm_min, support.platform.helm_min_v3, support.platform.helm_min_v4
        )));
    }
    Ok(())
}

fn validate_upgrade_stops_against_support(
    support: &SupportContract,
    graph: &ManifestCompatGraph,
) -> Result<(), CompatError> {
    let matrix = &support.compatibility_matrix;
    let interval = support.release_policy.lts_interval_minors;
    if interval == 0 {
        return Err(CompatError::InvalidSupportContract(
            "release_policy.lts_interval_minors must be positive".into(),
        ));
    }
    if graph.min_upgrade_from.major != matrix.wire_major
        || graph.min_upgrade_from < matrix.protocol_version
    {
        return Err(CompatError::UnsupportedVersion(format!(
            "min_upgrade_from {} incompatible with protocol {} (wire_major {})",
            graph.min_upgrade_from, matrix.protocol_version, matrix.wire_major
        )));
    }
    for pair in graph.required_stops.windows(2) {
        if let [prev, next] = pair
            && prev >= next
        {
            return Err(CompatError::ForbiddenUpgradeJump(format!(
                "required_stops must be strictly increasing ({prev} >= {next})"
            )));
        }
    }
    for stop in &graph.required_stops {
        if stop.major != graph.min_upgrade_from.major || *stop < graph.min_upgrade_from {
            return Err(CompatError::UnsupportedVersion(format!(
                "required_stop {stop} invalid relative to min_upgrade_from {}",
                graph.min_upgrade_from
            )));
        }
        if stop.minor == 0 || stop.patch != 0 || stop.minor.checked_rem(interval) != Some(0) {
            return Err(CompatError::ForbiddenUpgradeJump(format!(
                "required_stop {stop} does not align with lts_interval_minors={interval}"
            )));
        }
    }
    if let Some(last_stop) = graph.required_stops.last() {
        let start_m = graph.min_upgrade_from.minor;
        let mut cursor = interval;
        while cursor <= last_stop.minor {
            if cursor > start_m
                && !graph
                    .required_stops
                    .iter()
                    .any(|s| s.minor == cursor && s.patch == 0)
            {
                return Err(CompatError::ForbiddenUpgradeJump(format!(
                    "required_stops omits mandatory LTS stop {}",
                    SemVer::new(graph.min_upgrade_from.major, cursor, 0)
                )));
            }
            cursor = cursor.saturating_add(interval);
        }
    }
    Ok(())
}

fn parse_contract_version(raw: &str) -> Result<ContractVersion, CompatError> {
    let trimmed = raw.trim();
    if let Ok(sv) = SemVer::parse(trimmed) {
        let stage = match trimmed.split_once('-') {
            None => ContractStage::Stable,
            Some((_, pre)) => {
                let lc = pre.to_ascii_lowercase();
                if let Some(rest) = lc.strip_prefix("alpha") {
                    ContractStage::Alpha(parse_digits_or_zero(rest))
                } else if let Some(rest) = lc.strip_prefix("beta") {
                    ContractStage::Beta(parse_digits_or_zero(rest))
                } else {
                    ContractStage::Beta(0)
                }
            }
        };
        return Ok(ContractVersion {
            major: sv.major,
            minor: sv.minor,
            patch: sv.patch,
            stage,
        });
    }

    let Some(after_v) = trimmed.strip_prefix('v') else {
        return Err(CompatError::InvalidSemVer(raw.to_owned()));
    };
    if let Some((maj_raw, alpha_raw)) = after_v.split_once("alpha") {
        let major = parse_strict_u32(maj_raw, raw)?;
        let alpha_n = parse_strict_u32(alpha_raw, raw)?;
        return Ok(ContractVersion {
            major,
            minor: 0,
            patch: 0,
            stage: ContractStage::Alpha(alpha_n),
        });
    }
    if let Some((maj_raw, beta_raw)) = after_v.split_once("beta") {
        let major = parse_strict_u32(maj_raw, raw)?;
        let beta_n = parse_strict_u32(beta_raw, raw)?;
        return Ok(ContractVersion {
            major,
            minor: 0,
            patch: 0,
            stage: ContractStage::Beta(beta_n),
        });
    }
    let major = parse_strict_u32(after_v, raw)?;
    Ok(ContractVersion {
        major,
        minor: 0,
        patch: 0,
        stage: ContractStage::Stable,
    })
}

fn parse_digits_or_zero(s: &str) -> u32 {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().unwrap_or(0)
}

fn parse_strict_u32(part: &str, raw: &str) -> Result<u32, CompatError> {
    if part.is_empty()
        || !part.bytes().all(|b| b.is_ascii_digit())
        || (part.len() > 1 && part.starts_with('0'))
    {
        return Err(CompatError::InvalidSemVer(raw.to_owned()));
    }
    part.parse::<u32>()
        .map_err(|_| CompatError::InvalidSemVer(raw.to_owned()))
}

fn kubernetes_minor_line(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed.starts_with('+') || trimmed.starts_with('-') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    let (maj, min) = match parts.as_slice() {
        [maj, min] => (*maj, *min),
        [maj, min, patch] => {
            let _ = parse_strict_u32(patch, raw).ok()?;
            (*maj, *min)
        }
        _ => return None,
    };
    let major_n = parse_strict_u32(maj, raw).ok()?;
    let minor_n = parse_strict_u32(min, raw).ok()?;
    Some(format!("{major_n}.{minor_n}"))
}

#[must_use]
pub fn diff_component_digests(
    previous: &[ManifestComponentState],
    next: &[ManifestComponentState],
) -> Vec<ComponentDigestDelta> {
    let prev_map: BTreeMap<&str, &ManifestComponentState> =
        previous.iter().map(|c| (c.name.as_str(), c)).collect();
    let mut deltas = Vec::with_capacity(next.len());
    for item in next {
        match prev_map.get(item.name.as_str()) {
            Some(old) => deltas.push(ComponentDigestDelta {
                name: item.name.clone(),
                previous_version: old.version,
                next_version: item.version,
                previous_sha256: old.sha256.clone(),
                next_sha256: item.sha256.clone(),
                changed: old.sha256 != item.sha256 || old.version != item.version,
            }),
            None => deltas.push(ComponentDigestDelta {
                name: item.name.clone(),
                previous_version: SemVer::new(0, 0, 0),
                next_version: item.version,
                previous_sha256: String::new(),
                next_sha256: item.sha256.clone(),
                changed: true,
            }),
        }
    }
    deltas
}
