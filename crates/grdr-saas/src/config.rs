// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_schema::limits::load_embedded_limits;

use crate::{CODE_SAAS_INVALID_INPUT, CODE_SAAS_OPS_BOUND_EXCEEDED, saas_error};

const EMBEDDED_BOUNDS_TOML: &str = include_str!("../../../docs/ops/bounds.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaasOperationalBounds {
    pub max_blast_radius_pct: u8,
    pub max_concurrent_regions: u8,
    pub cooldown_minutes: u32,
    pub min_gross_margin_bps: i64,
    pub cell_soft_cap_pct: u8,
    pub cell_reserve_pct: u8,
    pub late_window_days: i64,
    pub reconcile_max_drift_bps: u64,
    pub payment_retry_days: u16,
    pub suspended_grace_days: u16,
    pub erasure_retention_days: i64,
    pub max_ledger_samples: usize,
}

impl SaasOperationalBounds {
    pub fn load_embedded() -> Result<Self, CodedError> {
        let limits = load_embedded_limits().map_err(|err| {
            saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!("Failed loading embedded contracts/limits.toml: {err}"),
                "Ensure contracts/limits.toml satisfies grdr-schema validation.",
            )
        })?;
        let soft_cap_from_limits =
            100u32.saturating_sub(limits.server.preflight.disk_headroom_min_pct);
        let parsed = parse_bounds_toml(EMBEDDED_BOUNDS_TOML)?;

        let bounds = Self {
            max_blast_radius_pct: req_u8(&parsed, "max_blast_radius_pct")?,
            max_concurrent_regions: req_u8(&parsed, "max_concurrent_regions")?,
            cooldown_minutes: req_u32(&parsed, "cooldown_minutes")?,
            min_gross_margin_bps: i64::from(req_u32(&parsed, "min_gross_margin_bps")?),
            cell_soft_cap_pct: u8::try_from(soft_cap_from_limits)
                .map_err(|_| bad_bound("disk_headroom_min_pct"))?,
            cell_reserve_pct: req_u8(&parsed, "cell_reserve_pct")?,
            late_window_days: i64::from(limits.server.tenancy.copy_life_days),
            reconcile_max_drift_bps: u64::from(req_u32(&parsed, "reconcile_max_drift_bps")?),
            payment_retry_days: u16::try_from(limits.server.tenancy.payment_retry_days)
                .map_err(|_| bad_bound("payment_retry_days"))?,
            suspended_grace_days: u16::try_from(limits.server.tenancy.suspended_grace_days)
                .map_err(|_| bad_bound("suspended_grace_days"))?,
            erasure_retention_days: i64::from(limits.server.tenancy.erasure_cancel_window_days),
            max_ledger_samples: usize::try_from(req_u32(&parsed, "max_ledger_samples")?)
                .map_err(|_| bad_bound("max_ledger_samples"))?,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        if self.max_blast_radius_pct > 100 || self.max_concurrent_regions == 0 {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Invalid blast radius or concurrent region bound.",
                "Ensure max_blast_radius_pct <= 100 and max_concurrent_regions >= 1.",
            ));
        }
        if self.cell_soft_cap_pct == 0
            || self.cell_soft_cap_pct.saturating_add(self.cell_reserve_pct) > 100
        {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Cell soft cap plus reserve headroom must fit within 100%.",
                "Adjust cell_soft_cap_pct and cell_reserve_pct in bounds configuration.",
            ));
        }
        if self.late_window_days <= 0
            || self.erasure_retention_days <= 0
            || self.payment_retry_days == 0
            || self.suspended_grace_days < self.payment_retry_days
            || self.max_ledger_samples == 0
        {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Tenancy lifecycle or usage ledger bounds failed validation.",
                "Verify contracts/limits.toml and docs/ops/bounds.toml consistency.",
            ));
        }
        Ok(())
    }
}

fn parse_bounds_toml(raw: &str) -> Result<Vec<(String, u32)>, CodedError> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() || trimmed.starts_with('[') || trimmed.starts_with("schema") {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_owned();
            let val = v.trim().parse::<u32>().map_err(|_| {
                saas_error(
                    CODE_SAAS_INVALID_INPUT,
                    format!("Invalid integer bound `{key}` in docs/ops/bounds.toml."),
                    "Ensure all numeric fields in docs/ops/bounds.toml are unsigned integers.",
                )
            })?;
            entries.push((key, val));
        }
    }
    Ok(entries)
}

fn req_u32(entries: &[(String, u32)], key: &str) -> Result<u32, CodedError> {
    entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| *v)
        .ok_or_else(|| bad_bound(key))
}

fn req_u8(entries: &[(String, u32)], key: &str) -> Result<u8, CodedError> {
    let val = req_u32(entries, key)?;
    u8::try_from(val).map_err(|_| bad_bound(key))
}

fn bad_bound(key: &str) -> CodedError {
    saas_error(
        CODE_SAAS_OPS_BOUND_EXCEEDED,
        format!("Invalid or missing operational bound `{key}`."),
        "Check contracts/limits.toml and docs/ops/bounds.toml.",
    )
}
