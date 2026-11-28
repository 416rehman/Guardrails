// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Upgrade-path table generator and forbidden-jump checker (`D-71`, `E1.7`).

use serde::{Deserialize, Serialize};

use super::SemVer;
use super::codes::CompatError;
use super::support::SupportContract;

pub const UPGRADE_PATH_SCHEMA: &str = "grdr.upgrade-path.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePathEntry {
    pub from_version: String,
    pub to_version: String,
    pub hops: Vec<String>,
    pub rollback_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForbiddenJumpEntry {
    pub from_version: String,
    pub to_version: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePathDocument {
    pub schema: String,
    pub series_major: u32,
    pub max_upgrade_minor_hop: u32,
    pub lts_interval_minors: u32,
    pub rollback_window_minors: u32,
    pub lts_minors: Vec<u32>,
    pub allowed_paths: Vec<UpgradePathEntry>,
    pub forbidden_jumps: Vec<ForbiddenJumpEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePlan {
    pub from_version: SemVer,
    pub to_version: SemVer,
    pub hops: Vec<SemVer>,
    pub is_rollback: bool,
}

pub fn generate_upgrade_path_doc(
    support: &SupportContract,
    series_major: u32,
    max_minor: u32,
) -> Result<UpgradePathDocument, CompatError> {
    let policy = &support.release_policy;
    if policy.max_upgrade_minor_hop == 0 || policy.lts_interval_minors == 0 {
        return Err(CompatError::InvalidSupportContract(
            "upgrade minor hop and LTS interval must be positive".into(),
        ));
    }

    let lts_minors: Vec<u32> = (1..=max_minor)
        .filter(|m| m.checked_rem(policy.lts_interval_minors) == Some(0))
        .collect();

    let mut allowed_paths = Vec::new();
    let mut forbidden_jumps = Vec::new();

    for from_m in 0..=max_minor {
        for to_m in 0..=max_minor {
            if from_m == to_m {
                continue;
            }
            let from_str = SemVer::new(series_major, from_m, 0).to_string();
            let to_str = SemVer::new(series_major, to_m, 0).to_string();

            if to_m < from_m {
                let back_span = from_m.saturating_sub(to_m);
                if back_span > policy.rollback_window_minors {
                    forbidden_jumps.push(ForbiddenJumpEntry {
                        from_version: from_str,
                        to_version: to_str,
                        reason: format!(
                            "rollback distance {back_span} exceeds rollback_window_minors ({})",
                            policy.rollback_window_minors
                        ),
                    });
                }
                continue;
            }

            let delta = to_m.saturating_sub(from_m);
            let skipped_lts = lts_minors
                .iter()
                .copied()
                .find(|&lts| from_m < lts && lts < to_m);
            if let Some(lts) = skipped_lts {
                forbidden_jumps.push(ForbiddenJumpEntry {
                    from_version: from_str.clone(),
                    to_version: to_str.clone(),
                    reason: format!(
                        "direct jump skips mandatory LTS stop {}",
                        SemVer::new(series_major, lts, 0)
                    ),
                });
            } else if delta > policy.max_upgrade_minor_hop {
                forbidden_jumps.push(ForbiddenJumpEntry {
                    from_version: from_str.clone(),
                    to_version: to_str.clone(),
                    reason: format!(
                        "direct jump of {delta} minors exceeds max_upgrade_minor_hop ({})",
                        policy.max_upgrade_minor_hop
                    ),
                });
            }

            let hops = compute_stepped_hops(
                series_major,
                from_m,
                to_m,
                policy.max_upgrade_minor_hop,
                &lts_minors,
            );
            let rollback_supported =
                delta <= policy.rollback_window_minors && skipped_lts.is_none();
            allowed_paths.push(UpgradePathEntry {
                from_version: from_str,
                to_version: to_str,
                hops,
                rollback_supported,
            });
        }
    }

    Ok(UpgradePathDocument {
        schema: UPGRADE_PATH_SCHEMA.to_owned(),
        series_major,
        max_upgrade_minor_hop: policy.max_upgrade_minor_hop,
        lts_interval_minors: policy.lts_interval_minors,
        rollback_window_minors: policy.rollback_window_minors,
        lts_minors,
        allowed_paths,
        forbidden_jumps,
    })
}

fn compute_stepped_hops(
    major: u32,
    from_m: u32,
    to_m: u32,
    max_hop: u32,
    lts_minors: &[u32],
) -> Vec<String> {
    let mut hops = Vec::new();
    let mut cursor = from_m;
    hops.push(SemVer::new(major, cursor, 0).to_string());
    while cursor < to_m {
        let mut next = cursor.saturating_add(max_hop).min(to_m);
        if let Some(&lts) = lts_minors
            .iter()
            .find(|&&lts| cursor < lts && lts <= next && lts < to_m)
        {
            next = lts;
        }
        cursor = next;
        hops.push(SemVer::new(major, cursor, 0).to_string());
    }
    hops
}

pub fn validate_direct_transition(
    doc: &UpgradePathDocument,
    from: SemVer,
    to: SemVer,
) -> Result<UpgradePlan, CompatError> {
    if doc.schema != UPGRADE_PATH_SCHEMA {
        return Err(CompatError::InvalidSupportContract(format!(
            "unsupported upgrade path schema `{}` (expected `{UPGRADE_PATH_SCHEMA}`)",
            doc.schema
        )));
    }
    if doc.max_upgrade_minor_hop == 0 || doc.lts_interval_minors == 0 {
        return Err(CompatError::InvalidSupportContract(
            "upgrade_path document requires non-zero max_upgrade_minor_hop and lts_interval_minors"
                .into(),
        ));
    }

    let from_norm = SemVer::new(from.major, from.minor, 0).to_string();
    let to_norm = SemVer::new(to.major, to.minor, 0).to_string();
    let from_exact = from.to_string();
    let to_exact = to.to_string();
    if let Some(jump) = doc.forbidden_jumps.iter().find(|j| {
        (j.from_version == from_exact && j.to_version == to_exact)
            || (j.from_version == from_norm && j.to_version == to_norm)
    }) {
        return Err(CompatError::ForbiddenUpgradeJump(jump.reason.clone()));
    }

    if from.major != doc.series_major || to.major != doc.series_major {
        return Err(CompatError::ForbiddenUpgradeJump(format!(
            "cross-major transition {from} -> {to} is outside series {}.x",
            doc.series_major
        )));
    }
    if from == to {
        return Ok(UpgradePlan {
            from_version: from,
            to_version: to,
            hops: vec![from],
            is_rollback: false,
        });
    }
    if to < from {
        if from.minor == to.minor {
            return Ok(UpgradePlan {
                from_version: from,
                to_version: to,
                hops: vec![from, to],
                is_rollback: true,
            });
        }
        let back = from.minor.saturating_sub(to.minor);
        if back > doc.rollback_window_minors {
            return Err(CompatError::ForbiddenUpgradeJump(format!(
                "rollback {from} -> {to} exceeds rollback window {}",
                doc.rollback_window_minors
            )));
        }
        return Ok(UpgradePlan {
            from_version: from,
            to_version: to,
            hops: vec![from, to],
            is_rollback: true,
        });
    }

    if from.minor == to.minor {
        return Ok(UpgradePlan {
            from_version: from,
            to_version: to,
            hops: vec![from, to],
            is_rollback: false,
        });
    }

    let delta = to.minor.saturating_sub(from.minor);
    if let Some(&lts) = doc
        .lts_minors
        .iter()
        .find(|&&lts| from.minor < lts && lts < to.minor)
    {
        return Err(CompatError::ForbiddenUpgradeJump(format!(
            "transition {from} -> {to} skips mandatory LTS stop {}",
            SemVer::new(doc.series_major, lts, 0)
        )));
    }
    if delta > doc.max_upgrade_minor_hop {
        return Err(CompatError::ForbiddenUpgradeJump(format!(
            "transition {from} -> {to} jumps {delta} minors (max {})",
            doc.max_upgrade_minor_hop
        )));
    }
    Ok(UpgradePlan {
        from_version: from,
        to_version: to,
        hops: vec![from, to],
        is_rollback: false,
    })
}

pub fn validate_hop_sequence(
    doc: &UpgradePathDocument,
    hops: &[SemVer],
) -> Result<UpgradePlan, CompatError> {
    let Some(&first) = hops.first() else {
        return Err(CompatError::ForbiddenUpgradeJump(
            "upgrade plan must contain at least one version".into(),
        ));
    };
    let Some(&last) = hops.last() else {
        return Err(CompatError::ForbiddenUpgradeJump(
            "upgrade plan must contain at least one version".into(),
        ));
    };
    for pair in hops.windows(2) {
        if let [prev, next] = pair {
            let step = validate_direct_transition(doc, *prev, *next)?;
            if step.is_rollback && hops.len() > 2 {
                return Err(CompatError::ForbiddenUpgradeJump(
                    "multi-hop rollback sequences are forbidden".into(),
                ));
            }
        }
    }
    Ok(UpgradePlan {
        from_version: first,
        to_version: last,
        hops: hops.to_vec(),
        is_rollback: last < first,
    })
}
