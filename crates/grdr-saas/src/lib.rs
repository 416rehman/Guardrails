// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod billing;
pub mod cell_types;
pub mod config;
pub(crate) mod framing;
pub mod gates;
pub mod ops;
pub mod portability;
mod redirect;
pub mod route_ticket;
pub mod router;
pub mod usage;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_crypto::domain_sha256_digest;
use grdr_model::CodedError;

pub const CODE_SAAS_INVALID_INPUT: &str = "GRDR-SAAS-0001";
pub const CODE_SAAS_CELL_UNAVAILABLE: &str = "GRDR-SAAS-0002";
pub const CODE_SAAS_REGION_VIOLATION: &str = "GRDR-SAAS-0003";
pub const CODE_SAAS_TENANT_MISMATCH: &str = "GRDR-SAAS-0004";
pub const CODE_SAAS_SIGNATURE_INVALID: &str = "GRDR-SAAS-0005";
pub const CODE_SAAS_LATE_USAGE_WINDOW: &str = "GRDR-SAAS-0006";
pub const CODE_SAAS_RECONCILIATION_BLOCKED: &str = "GRDR-SAAS-0007";
pub const CODE_SAAS_OPS_BOUND_EXCEEDED: &str = "GRDR-SAAS-0008";

pub use billing::{
    BillingProvider, InvoiceAdapter, InvoiceLine, InvoiceUnitPrices, KillBillAdapter,
    ReconciliationReport, ReconciliationStatus, StatementFileAdapter, StripeMeterAdapter,
    reconcile_usage_vs_invoice,
};
pub use cell_types::{
    BUCKET_COUNT, BucketRange, CellCapacityVector, CellEndpoint, CellId, CellSplitResult,
    CellState, OrgPlacement, RegionId, device_bucket,
};
pub use config::SaasOperationalBounds;
pub use gates::{
    DeterministicSanctionsScreen, GateCheckItem, GateEvaluation, GateRequirementStatus,
    HostedGateChecklist, PaidOfferGateChecklist, SanctionsDecision, SanctionsScreen,
    UnitEconomicsInput, UnitEconomicsResult, compute_unit_economics, evaluate_hosted_gate,
    evaluate_paid_offer_gate,
};
pub use ops::{
    ChangeFreezeWindow, MaintenanceStep, OperationsRunner, OpsBounds, RunbookActor,
    StepAuditRecord, TenantLifecycleRecord, TenantLifecycleState,
};
pub use portability::{
    BUNDLE_SCHEMA_VERSION, BundleManifestEntry, DeviceRedirectSpec, ExportOrgBundleRequest,
    ImportBaseline, ImportedOrgState, MigrationStage, MigrationTargetKind, OrgMigrationBundle,
    SignedDeviceRedirect, WatermarkedState, export_org_bundle, import_org_bundle,
    sign_device_redirect, verify_device_redirect,
};
pub use route_ticket::{SignedRouteTicket, sign_route_ticket, verify_route_ticket};
pub use router::{CellRouter, OrgPlacementInput};
pub use usage::{
    InMemoryUsageLedger, MeterPeriod, MonthlyUsageStatement, UsageLedgerSummary, UsageRecorder,
    UsageSample, UsageSampleKind, generate_signed_statement, sample_idempotency_key,
    verify_statement,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct SaasError {
    pub code: &'static str,
    pub message: String,
    pub hint: String,
}

impl SaasError {
    #[must_use]
    pub fn into_coded(self) -> CodedError {
        CodedError::new(self.code, self.message, self.hint)
    }
}

pub(crate) fn saas_error(
    code: &'static str,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> CodedError {
    CodedError::new(code, message, hint)
}

#[must_use]
pub fn deterministic_uuid(domain: &str, key_material: &[u8]) -> Uuid {
    let digest = domain_sha256_digest(domain, key_material);
    let mut bytes = [0u8; 16];
    for (dst, src) in bytes.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    if let Some(b6) = bytes.get_mut(6) {
        *b6 = (*b6 & 0x0f) | 0x50;
    }
    if let Some(b8) = bytes.get_mut(8) {
        *b8 = (*b8 & 0x3f) | 0x80;
    }
    Uuid::from_bytes(bytes)
}

pub(crate) fn utc_year_month(unix_seconds: i64) -> Result<(u16, u8), CodedError> {
    let unix_days = unix_seconds.div_euclid(86_400);
    let z = unix_days.checked_add(719_468).ok_or_else(|| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Timestamp days overflowed UTC calendar conversion.",
            "Supply a timestamp within standard calendar years (2020..=2100).",
        )
    })?;
    let era_numerator = if z >= 0 {
        z
    } else {
        z.checked_sub(146_096).ok_or_else(|| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Timestamp era underflowed UTC calendar conversion.",
                "Supply a timestamp within standard calendar years (2020..=2100).",
            )
        })?
    };
    let era = era_numerator.div_euclid(146_097);
    let era_days = era.checked_mul(146_097).ok_or_else(|| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Timestamp era multiplication overflowed UTC calendar conversion.",
            "Supply a timestamp within standard calendar years (2020..=2100).",
        )
    })?;
    let doe = z.checked_sub(era_days).ok_or_else(|| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Day-of-era subtraction overflowed UTC calendar conversion.",
            "Supply a timestamp within standard calendar years (2020..=2100).",
        )
    })?;
    let doe_adj = doe
        .saturating_sub(doe.div_euclid(1460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096));
    let yoe = doe_adj.div_euclid(365);
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.div_euclid(4))
            .saturating_sub(yoe.div_euclid(100)),
    );
    let mp = doy.saturating_mul(5).saturating_add(2).div_euclid(153);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = if m <= 2 { y.saturating_add(1) } else { y };
    let year_u16 = u16::try_from(year).map_err(|_| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Timestamp year fell outside valid u16 range.",
            "Supply a valid calendar timestamp.",
        )
    })?;
    let month_u8 = u8::try_from(m).map_err(|_| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Timestamp month fell outside valid u8 range.",
            "Supply a valid calendar timestamp.",
        )
    })?;
    Ok((year_u16, month_u8))
}
