// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Operational bounds parsed directly from `contracts/limits.toml` (`ADR-0022`).

use std::collections::BTreeMap;

use crate::ComplyError;
use crate::toml_ast::{TomlVal, parse_toml_document};

const EMBEDDED_LIMITS_TOML: &str = include_str!("../../../contracts/limits.toml");
const BYTES_PER_MIB: u64 = 1024 * 1024;
const BYTES_PER_KIB: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComplianceLimits {
    pub(crate) max_pack_file_bytes: u64,
    pub(crate) max_pack_bundle_bytes: u64,
    pub(crate) max_oscal_json_bytes: usize,
    pub(crate) backup_retention_max_days: u32,
    pub(crate) gdpr_response_deadline_days: i64,
}

pub(crate) fn compliance_limits() -> Result<ComplianceLimits, ComplyError> {
    parse_compliance_limits_toml(EMBEDDED_LIMITS_TOML)
}

pub(crate) fn parse_compliance_limits_toml(raw: &str) -> Result<ComplianceLimits, ComplyError> {
    let root = parse_toml_document(raw)?;
    let packs = req_table_path(&root, &["packs"])?;
    let ingest = req_table_path(&root, &["server", "ingest"])?;
    let tenancy = req_table_path(&root, &["server", "tenancy"])?;

    let essentials_kb = req_u64(packs, "essentials_max_kb")?;
    let detections_mb = req_u64(packs, "detections_max_mb")?;
    let max_bundle_mb = req_u64(packs, "max_pack_bundle_mb")?;
    let max_body_bytes = req_u64(ingest, "max_body_bytes")?;
    let copy_life_days = req_u32(tenancy, "copy_life_days")?;
    let pitr_window_days = req_u32(tenancy, "pitr_window_days")?;
    let erasure_days = req_i64(tenancy, "erasure_cancel_window_days")?;

    let max_pack_file_bytes = essentials_kb
        .saturating_mul(BYTES_PER_KIB)
        .max(detections_mb.saturating_mul(BYTES_PER_MIB));
    let max_pack_bundle_bytes = max_bundle_mb.saturating_mul(BYTES_PER_MIB);
    let max_oscal_json_bytes = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
    let backup_retention_max_days = copy_life_days.min(pitr_window_days);

    if max_pack_file_bytes == 0
        || max_pack_bundle_bytes == 0
        || max_oscal_json_bytes == 0
        || backup_retention_max_days == 0
        || erasure_days <= 0
    {
        return Err(ComplyError::VerificationFailed {
            detail: "contracts/limits.toml yielded non-positive compliance limit".into(),
        });
    }

    Ok(ComplianceLimits {
        max_pack_file_bytes,
        max_pack_bundle_bytes,
        max_oscal_json_bytes,
        backup_retention_max_days,
        gdpr_response_deadline_days: erasure_days,
    })
}

fn req_table_path<'a>(
    root: &'a BTreeMap<String, TomlVal>,
    path: &[&str],
) -> Result<&'a BTreeMap<String, TomlVal>, ComplyError> {
    let mut cur = root;
    for seg in path {
        cur = match cur.get(*seg) {
            Some(TomlVal::Table(t)) => t,
            _ => {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("contracts/limits.toml missing table `{seg}`"),
                });
            }
        };
    }
    Ok(cur)
}

fn req_i64(tbl: &BTreeMap<String, TomlVal>, key: &str) -> Result<i64, ComplyError> {
    match tbl.get(key) {
        Some(TomlVal::Int(n)) => Ok(*n),
        _ => Err(ComplyError::VerificationFailed {
            detail: format!("contracts/limits.toml missing integer `{key}`"),
        }),
    }
}

fn req_u64(tbl: &BTreeMap<String, TomlVal>, key: &str) -> Result<u64, ComplyError> {
    let raw = req_i64(tbl, key)?;
    u64::try_from(raw).map_err(|_| ComplyError::VerificationFailed {
        detail: format!("contracts/limits.toml `{key}` negative"),
    })
}

fn req_u32(tbl: &BTreeMap<String, TomlVal>, key: &str) -> Result<u32, ComplyError> {
    let raw = req_i64(tbl, key)?;
    u32::try_from(raw).map_err(|_| ComplyError::VerificationFailed {
        detail: format!("contracts/limits.toml `{key}` out of u32 range"),
    })
}
