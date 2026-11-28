// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::config::SaasOperationalBounds;
use crate::framing::CanonicalFrame;
use crate::usage::{MeterPeriod, MonthlyUsageStatement};
use crate::{
    CODE_SAAS_INVALID_INPUT, CODE_SAAS_RECONCILIATION_BLOCKED, CODE_SAAS_TENANT_MISMATCH,
    deterministic_uuid, saas_error,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingProvider {
    StatementFile,
    StripeMeter,
    KillBill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceUnitPrices {
    pub endpoint_unit_cents: u64,
    pub ephemeral_hour_cents: u64,
    pub endpoint_day_cents: u64,
    pub over_retention_gb_day_cents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceLine {
    pub provider: BillingProvider,
    pub idempotency_key: Uuid,
    pub org_id: OrgId,
    pub period: MeterPeriod,
    pub metric_code: String,
    pub billable_units: u64,
    pub unit_price_cents: u64,
    pub subtotal_cents: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    ExactMatch,
    WithinTolerance,
    BlockedVarianceExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub org_id: OrgId,
    pub period: MeterPeriod,
    pub statement_units: u64,
    pub billed_units: u64,
    pub drift_bps: u64,
    pub status: ReconciliationStatus,
}

pub trait InvoiceAdapter {
    fn provider(&self) -> BillingProvider;
    fn emit_invoice_lines(
        &self,
        statement: &MonthlyUsageStatement,
        prices: InvoiceUnitPrices,
    ) -> Result<Vec<InvoiceLine>, CodedError>;
}

#[derive(Debug, Clone, Default)]
pub struct StatementFileAdapter;

#[derive(Debug, Clone, Default)]
pub struct StripeMeterAdapter;

#[derive(Debug, Clone, Default)]
pub struct KillBillAdapter;

#[derive(Default)]
struct BilledMetricTotals {
    active_endpoints: u64,
    ephemeral_sensor_hours: u64,
    daily_active_endpoint_days: u64,
    over_retention_gb_days: u64,
    total_units: u64,
}

impl InvoiceAdapter for StatementFileAdapter {
    fn provider(&self) -> BillingProvider {
        BillingProvider::StatementFile
    }

    fn emit_invoice_lines(
        &self,
        statement: &MonthlyUsageStatement,
        prices: InvoiceUnitPrices,
    ) -> Result<Vec<InvoiceLine>, CodedError> {
        build_invoice_lines(self.provider(), statement, prices)
    }
}

impl InvoiceAdapter for StripeMeterAdapter {
    fn provider(&self) -> BillingProvider {
        BillingProvider::StripeMeter
    }

    fn emit_invoice_lines(
        &self,
        statement: &MonthlyUsageStatement,
        prices: InvoiceUnitPrices,
    ) -> Result<Vec<InvoiceLine>, CodedError> {
        build_invoice_lines(self.provider(), statement, prices)
    }
}

impl InvoiceAdapter for KillBillAdapter {
    fn provider(&self) -> BillingProvider {
        BillingProvider::KillBill
    }

    fn emit_invoice_lines(
        &self,
        statement: &MonthlyUsageStatement,
        prices: InvoiceUnitPrices,
    ) -> Result<Vec<InvoiceLine>, CodedError> {
        build_invoice_lines(self.provider(), statement, prices)
    }
}

pub fn reconcile_usage_vs_invoice(
    statement: &MonthlyUsageStatement,
    prices: &InvoiceUnitPrices,
    invoice_lines: &[InvoiceLine],
    require_exact_zero_variance: bool,
    bounds: &SaasOperationalBounds,
) -> Result<ReconciliationReport, CodedError> {
    bounds.validate()?;
    ensure_statement_metadata(statement)?;

    let statement_totals = [
        ("active_endpoints", statement.summary.peak_active_endpoints),
        (
            "ephemeral_sensor_hours",
            statement.summary.ephemeral_sensor_hours,
        ),
        (
            "daily_active_endpoint_days",
            statement.summary.daily_active_endpoint_days,
        ),
        (
            "over_retention_gb_days",
            statement.summary.over_retention_gb_days,
        ),
    ];
    let statement_units = statement
        .summary
        .peak_active_endpoints
        .checked_add(statement.summary.ephemeral_sensor_hours)
        .and_then(|v| v.checked_add(statement.summary.daily_active_endpoint_days))
        .and_then(|v| v.checked_add(statement.summary.over_retention_gb_days))
        .ok_or_else(|| blocked("Statement billable unit sum overflowed u64 bounds."))?;

    let mut seen_keys = BTreeSet::new();
    let mut billed = BilledMetricTotals::default();

    for line in invoice_lines {
        if line.org_id != statement.org_id || line.period != statement.period {
            return Err(blocked("Invoice line tenant or billing period mismatch."));
        }
        if !seen_keys.insert(line.idempotency_key) {
            return Err(blocked("Duplicate invoice line idempotency key detected."));
        }
        let expected_price = match line.metric_code.as_str() {
            "active_endpoints" => {
                billed.active_endpoints = billed
                    .active_endpoints
                    .checked_add(line.billable_units)
                    .ok_or_else(|| blocked("Billed active_endpoints sum overflowed."))?;
                prices.endpoint_unit_cents
            }
            "ephemeral_sensor_hours" => {
                billed.ephemeral_sensor_hours = billed
                    .ephemeral_sensor_hours
                    .checked_add(line.billable_units)
                    .ok_or_else(|| blocked("Billed ephemeral_sensor_hours sum overflowed."))?;
                prices.ephemeral_hour_cents
            }
            "daily_active_endpoint_days" => {
                billed.daily_active_endpoint_days = billed
                    .daily_active_endpoint_days
                    .checked_add(line.billable_units)
                    .ok_or_else(|| blocked("Billed daily_active_endpoint_days sum overflowed."))?;
                prices.endpoint_day_cents
            }
            "over_retention_gb_days" => {
                billed.over_retention_gb_days = billed
                    .over_retention_gb_days
                    .checked_add(line.billable_units)
                    .ok_or_else(|| blocked("Billed over_retention_gb_days sum overflowed."))?;
                prices.over_retention_gb_day_cents
            }
            other => {
                return Err(blocked(format!(
                    "Unrecognized invoice metric_code `{other}`."
                )));
            }
        };
        if line.unit_price_cents != expected_price {
            return Err(blocked(format!(
                "Invoice line `{}` unit price mismatch: expected={expected_price}, got={}.",
                line.metric_code, line.unit_price_cents
            )));
        }
        let expected_subtotal = line
            .billable_units
            .checked_mul(line.unit_price_cents)
            .ok_or_else(|| blocked("Invoice line subtotal overflowed u64 bounds."))?;
        if line.subtotal_cents != expected_subtotal {
            return Err(blocked(format!(
                "Invoice line `{}` subtotal mismatch: expected={expected_subtotal}, got={}.",
                line.metric_code, line.subtotal_cents
            )));
        }
        billed.total_units = billed
            .total_units
            .checked_add(line.billable_units)
            .ok_or_else(|| blocked("Total billed unit sum overflowed u64 bounds."))?;
    }

    let billed_by_metric = [
        billed.active_endpoints,
        billed.ephemeral_sensor_hours,
        billed.daily_active_endpoint_days,
        billed.over_retention_gb_days,
    ];
    let allowed_drift_bps = if require_exact_zero_variance {
        0
    } else {
        bounds.reconcile_max_drift_bps
    };

    let mut max_metric_drift_bps: u64 = 0;
    for ((metric_name, expected_units), billed_metric_units) in
        statement_totals.iter().zip(billed_by_metric.iter())
    {
        let metric_drift = compute_drift_bps(*expected_units, *billed_metric_units)?;
        if metric_drift > allowed_drift_bps {
            return Err(blocked(format!(
                "Per-metric reconciliation blocked for `{metric_name}`: statement={expected_units}, billed={billed_metric_units}, drift_bps={metric_drift}."
            )));
        }
        if metric_drift > max_metric_drift_bps {
            max_metric_drift_bps = metric_drift;
        }
    }

    let aggregate_drift_bps = compute_drift_bps(statement_units, billed.total_units)?;
    let drift_bps = max_metric_drift_bps.max(aggregate_drift_bps);
    let status = if statement_units == billed.total_units && max_metric_drift_bps == 0 {
        ReconciliationStatus::ExactMatch
    } else if drift_bps <= allowed_drift_bps {
        ReconciliationStatus::WithinTolerance
    } else {
        return Err(blocked(format!(
            "Invoice reconciliation blocked: statement_units={statement_units}, billed_units={}, drift_bps={drift_bps}.",
            billed.total_units
        )));
    };

    Ok(ReconciliationReport {
        org_id: statement.org_id.clone(),
        period: statement.period,
        statement_units,
        billed_units: billed.total_units,
        drift_bps,
        status,
    })
}

fn build_invoice_lines(
    provider: BillingProvider,
    statement: &MonthlyUsageStatement,
    prices: InvoiceUnitPrices,
) -> Result<Vec<InvoiceLine>, CodedError> {
    ensure_statement_metadata(statement)?;
    let provider_tag = match provider {
        BillingProvider::StatementFile => "statement_file",
        BillingProvider::StripeMeter => "stripe_meter",
        BillingProvider::KillBill => "kill_bill",
    };

    let specs = [
        (
            "active_endpoints",
            statement.summary.peak_active_endpoints,
            prices.endpoint_unit_cents,
        ),
        (
            "ephemeral_sensor_hours",
            statement.summary.ephemeral_sensor_hours,
            prices.ephemeral_hour_cents,
        ),
        (
            "daily_active_endpoint_days",
            statement.summary.daily_active_endpoint_days,
            prices.endpoint_day_cents,
        ),
        (
            "over_retention_gb_days",
            statement.summary.over_retention_gb_days,
            prices.over_retention_gb_day_cents,
        ),
    ];

    let mut lines = Vec::with_capacity(specs.len());
    for (metric_code, units, unit_price) in specs {
        let mut frame = CanonicalFrame::new("grdr.saas.invoice-line.v1");
        frame.push_str(provider_tag);
        frame.push_str(statement.org_id.as_str());
        frame.push_u32(u32::from(statement.period.year));
        frame.push_u32(u32::from(statement.period.month));
        frame.push_str(metric_code);
        let idempotency_key = deterministic_uuid("grdr.saas.invoice-line.v1", frame.as_bytes());
        let subtotal_cents = units.checked_mul(unit_price).ok_or_else(|| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Invoice subtotal overflowed for metric `{metric_code}`."),
                "Keep billable units and unit prices within u64 product bounds.",
            )
        })?;
        lines.push(InvoiceLine {
            provider,
            idempotency_key,
            org_id: statement.org_id.clone(),
            period: statement.period,
            metric_code: metric_code.to_owned(),
            billable_units: units,
            unit_price_cents: unit_price,
            subtotal_cents,
        });
    }
    Ok(lines)
}

fn ensure_statement_metadata(statement: &MonthlyUsageStatement) -> Result<(), CodedError> {
    if statement.org_id != statement.summary.org_id {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            "Usage statement outer org_id does not match summary org_id.",
            "Reject cross-tenant billing statements.",
        ));
    }
    if statement.period != statement.summary.period {
        return Err(blocked(
            "Usage statement outer period does not match summary period.",
        ));
    }
    Ok(())
}

fn compute_drift_bps(statement_units: u64, billed_units: u64) -> Result<u64, CodedError> {
    let diff = statement_units.abs_diff(billed_units);
    if diff == 0 {
        return Ok(0);
    }
    if statement_units == 0 {
        return Ok(10_000);
    }
    let scaled = u128::from(diff)
        .checked_mul(10_000)
        .ok_or_else(|| blocked("Drift basis-point scaling overflowed."))?;
    let ceil_bps = scaled.div_ceil(u128::from(statement_units));
    Ok(u64::try_from(ceil_bps).unwrap_or(u64::MAX))
}

fn blocked(message: impl Into<String>) -> CodedError {
    saas_error(
        CODE_SAAS_RECONCILIATION_BLOCKED,
        message,
        "Halt invoice issuance and investigate meter aggregation lag.",
    )
}
