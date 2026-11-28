// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::config::SaasOperationalBounds;
use crate::framing::{CanonicalFrame, ensure_clean_token};
use crate::{
    CODE_SAAS_INVALID_INPUT, CODE_SAAS_LATE_USAGE_WINDOW, CODE_SAAS_OPS_BOUND_EXCEEDED,
    CODE_SAAS_SIGNATURE_INVALID, CODE_SAAS_TENANT_MISMATCH, deterministic_uuid, saas_error,
    utc_year_month,
};

const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const STATEMENT_DOMAIN: &str = "grdr.saas.usage-statement.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawMeterPeriod")]
pub struct MeterPeriod {
    pub year: u16,
    pub month: u8,
}

#[derive(Debug, Deserialize)]
struct RawMeterPeriod {
    year: u16,
    month: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSampleKind {
    DailyActiveEndpoint,
    EphemeralSensorHour,
    OverRetentionGigabyteDay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSample {
    pub idempotency_key: Uuid,
    pub org_id: OrgId,
    pub actor_or_device_id: String,
    pub kind: UsageSampleKind,
    pub quantity_units: u64,
    pub observed_at: Timestamp,
    pub recorded_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLedgerSummary {
    pub org_id: OrgId,
    pub period: MeterPeriod,
    pub daily_active_endpoint_days: u64,
    pub peak_active_endpoints: u64,
    pub ephemeral_sensor_hours: u64,
    pub over_retention_gb_days: u64,
    pub sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonthlyUsageStatement {
    pub statement_id: Uuid,
    pub org_id: OrgId,
    pub period: MeterPeriod,
    pub summary: UsageLedgerSummary,
    pub statement_sha256: String,
    pub signer_key_id: String,
    pub signature_b64: String,
}

pub trait UsageRecorder {
    fn record_sample(&mut self, sample: UsageSample) -> Result<bool, CodedError>;
    fn summarize_period(
        &self,
        org_id: &OrgId,
        period: MeterPeriod,
    ) -> Result<UsageLedgerSummary, CodedError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryUsageLedger {
    bounds: SaasOperationalBounds,
    seen_keys: BTreeSet<(OrgId, Uuid)>,
    samples: Vec<UsageSample>,
}

impl TryFrom<RawMeterPeriod> for MeterPeriod {
    type Error = CodedError;

    fn try_from(raw: RawMeterPeriod) -> Result<Self, Self::Error> {
        Self::new(raw.year, raw.month)
    }
}

impl MeterPeriod {
    pub fn new(year: u16, month: u8) -> Result<Self, CodedError> {
        if !(2020..=2100).contains(&year) || !(1..=12).contains(&month) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Invalid metering period {year:04}-{month:02}."),
                "Provide a valid calendar year (2020..=2100) and month (1..=12).",
            ));
        }
        Ok(Self { year, month })
    }

    pub fn try_from_timestamp(ts: Timestamp) -> Result<Self, CodedError> {
        let (year, month) = utc_year_month(ts.as_second())?;
        Self::new(year, month)
    }
}

impl InMemoryUsageLedger {
    pub fn try_new(bounds: SaasOperationalBounds) -> Result<Self, CodedError> {
        bounds.validate()?;
        Ok(Self {
            bounds,
            seen_keys: BTreeSet::new(),
            samples: Vec::new(),
        })
    }

    pub fn new() -> Result<Self, CodedError> {
        Self::try_new(SaasOperationalBounds::load_embedded()?)
    }
}

impl UsageRecorder for InMemoryUsageLedger {
    fn record_sample(&mut self, sample: UsageSample) -> Result<bool, CodedError> {
        ensure_clean_token("actor_or_device_id", &sample.actor_or_device_id)?;
        if sample.quantity_units == 0 {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Usage sample quantity_units must be greater than zero.",
                "Validate sample fields before recording usage.",
            ));
        }
        MeterPeriod::try_from_timestamp(sample.observed_at)?;
        let age_seconds = sample
            .recorded_at
            .as_second()
            .checked_sub(sample.observed_at.as_second())
            .ok_or_else(|| {
                saas_error(
                    CODE_SAAS_LATE_USAGE_WINDOW,
                    "Usage sample timestamp difference overflowed.",
                    "Supply valid observed_at and recorded_at timestamps.",
                )
            })?;
        let max_age_seconds = self
            .bounds
            .late_window_days
            .checked_mul(SECONDS_PER_DAY)
            .ok_or_else(|| {
                saas_error(
                    CODE_SAAS_OPS_BOUND_EXCEEDED,
                    "Configured late_window_days overflowed seconds conversion.",
                    "Keep late_window_days within i64 bounds.",
                )
            })?;
        if age_seconds > max_age_seconds || age_seconds < 0 {
            return Err(saas_error(
                CODE_SAAS_LATE_USAGE_WINDOW,
                format!(
                    "Usage sample age {age_seconds}s is outside the {}-day acceptance window.",
                    self.bounds.late_window_days
                ),
                "Drop stale telemetry past the late acceptance window or fix clock drift.",
            ));
        }

        let tenant_key = (sample.org_id.clone(), sample.idempotency_key);
        if self.seen_keys.contains(&tenant_key) {
            return Ok(false);
        }
        if self.samples.len() >= self.bounds.max_ledger_samples {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Usage ledger sample capacity ({}) reached.",
                    self.bounds.max_ledger_samples
                ),
                "Flush summarized periods to durable storage before accepting more samples.",
            ));
        }

        self.seen_keys.insert(tenant_key);
        self.samples.push(sample);
        Ok(true)
    }

    fn summarize_period(
        &self,
        org_id: &OrgId,
        period: MeterPeriod,
    ) -> Result<UsageLedgerSummary, CodedError> {
        let mut daily_devices: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
        let mut ephemeral_sensor_hours: u64 = 0;
        let mut over_retention_gb_days: u64 = 0;
        let mut sample_count: u64 = 0;

        for sample in &self.samples {
            if sample.org_id != *org_id
                || MeterPeriod::try_from_timestamp(sample.observed_at)? != period
            {
                continue;
            }
            sample_count = sample_count
                .checked_add(1)
                .ok_or_else(|| usage_overflow("samples"))?;
            match sample.kind {
                UsageSampleKind::DailyActiveEndpoint => {
                    let day_bucket = sample.observed_at.as_second().div_euclid(SECONDS_PER_DAY);
                    daily_devices
                        .entry(day_bucket)
                        .or_default()
                        .insert(sample.actor_or_device_id.clone());
                }
                UsageSampleKind::EphemeralSensorHour => {
                    ephemeral_sensor_hours = ephemeral_sensor_hours
                        .checked_add(sample.quantity_units)
                        .ok_or_else(|| usage_overflow("ephemeral_sensor_hours"))?;
                }
                UsageSampleKind::OverRetentionGigabyteDay => {
                    over_retention_gb_days = over_retention_gb_days
                        .checked_add(sample.quantity_units)
                        .ok_or_else(|| usage_overflow("over_retention_gb_days"))?;
                }
            }
        }

        let mut daily_active_endpoint_days: u64 = 0;
        let mut peak_active_endpoints: u64 = 0;
        for devices in daily_devices.values() {
            let count = u64::try_from(devices.len())
                .map_err(|_| usage_overflow("daily_active_endpoints"))?;
            daily_active_endpoint_days = daily_active_endpoint_days
                .checked_add(count)
                .ok_or_else(|| usage_overflow("daily_active_endpoint_days"))?;
            if count > peak_active_endpoints {
                peak_active_endpoints = count;
            }
        }

        Ok(UsageLedgerSummary {
            org_id: org_id.clone(),
            period,
            daily_active_endpoint_days,
            peak_active_endpoints,
            ephemeral_sensor_hours,
            over_retention_gb_days,
            sample_count,
        })
    }
}

#[must_use]
pub fn sample_idempotency_key(
    org_id: &OrgId,
    actor_or_device_id: &str,
    kind: UsageSampleKind,
    observed_at: Timestamp,
) -> Uuid {
    let (kind_str, bucket) = match kind {
        UsageSampleKind::DailyActiveEndpoint => {
            ("dae", observed_at.as_second().div_euclid(SECONDS_PER_DAY))
        }
        UsageSampleKind::EphemeralSensorHour => (
            "ephemeral_h",
            observed_at.as_second().div_euclid(SECONDS_PER_HOUR),
        ),
        UsageSampleKind::OverRetentionGigabyteDay => (
            "retention_gb_day",
            observed_at.as_second().div_euclid(SECONDS_PER_DAY),
        ),
    };
    let mut frame = CanonicalFrame::new("grdr.saas.usage-sample.v1");
    frame.push_str(org_id.as_str());
    frame.push_str(actor_or_device_id);
    frame.push_str(kind_str);
    frame.push_i64(bucket);
    deterministic_uuid("grdr.saas.usage-sample.v1", frame.as_bytes())
}

pub fn generate_signed_statement(
    ledger: &dyn UsageRecorder,
    org_id: &OrgId,
    period: MeterPeriod,
    signer: &SigningKeypair,
) -> Result<MonthlyUsageStatement, CodedError> {
    let summary = ledger.summarize_period(org_id, period)?;
    let mut id_frame = CanonicalFrame::new("grdr.saas.statement-id.v1");
    id_frame.push_str(org_id.as_str());
    id_frame.push_u32(u32::from(period.year));
    id_frame.push_u32(u32::from(period.month));
    let statement_id = deterministic_uuid("grdr.saas.statement.v1", id_frame.as_bytes());
    let signer_key_id = signer.key_id().to_owned();
    ensure_clean_token("signer_key_id", &signer_key_id)?;

    let frame = canonical_statement_frame(statement_id, org_id, period, &signer_key_id, &summary);
    let statement_sha256 = sha256_hex(frame.as_bytes());
    let signature_b64 = signer.sign_bytes(STATEMENT_DOMAIN, statement_sha256.as_bytes());
    Ok(MonthlyUsageStatement {
        statement_id,
        org_id: org_id.clone(),
        period,
        summary,
        statement_sha256,
        signer_key_id,
        signature_b64,
    })
}

pub fn verify_statement(
    public_key_b64: &str,
    statement: &MonthlyUsageStatement,
) -> Result<(), CodedError> {
    ensure_clean_token("signer_key_id", &statement.signer_key_id)?;
    if statement.org_id != statement.summary.org_id {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            "Usage statement outer org_id does not match summary org_id.",
            "Reject cross-tenant statement rewrites.",
        ));
    }
    if statement.period != statement.summary.period {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Usage statement outer billing period does not match summary period.",
            "Reject statements with inconsistent outer metadata.",
        ));
    }
    let frame = canonical_statement_frame(
        statement.statement_id,
        &statement.org_id,
        statement.period,
        &statement.signer_key_id,
        &statement.summary,
    );
    let expected_hex = sha256_hex(frame.as_bytes());
    if expected_hex != statement.statement_sha256 {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Usage statement payload digest mismatch.",
            "Recompute the statement from immutable usage ledger samples.",
        ));
    }
    verify_bytes(
        public_key_b64,
        STATEMENT_DOMAIN,
        statement.statement_sha256.as_bytes(),
        &statement.signature_b64,
    )
    .map_err(|_| {
        saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Usage statement Ed25519 signature verification failed.",
            "Verify the billing statement signer key.",
        )
    })
}

fn canonical_statement_frame(
    statement_id: Uuid,
    org_id: &OrgId,
    period: MeterPeriod,
    signer_key_id: &str,
    summary: &UsageLedgerSummary,
) -> CanonicalFrame {
    let mut frame = CanonicalFrame::new(STATEMENT_DOMAIN);
    frame.push_str(&statement_id.to_string());
    frame.push_str(org_id.as_str());
    frame.push_u32(u32::from(period.year));
    frame.push_u32(u32::from(period.month));
    frame.push_str(signer_key_id);
    frame.push_str(summary.org_id.as_str());
    frame.push_u32(u32::from(summary.period.year));
    frame.push_u32(u32::from(summary.period.month));
    frame.push_u64(summary.daily_active_endpoint_days);
    frame.push_u64(summary.peak_active_endpoints);
    frame.push_u64(summary.ephemeral_sensor_hours);
    frame.push_u64(summary.over_retention_gb_days);
    frame.push_u64(summary.sample_count);
    frame
}

fn usage_overflow(field: &str) -> CodedError {
    saas_error(
        CODE_SAAS_INVALID_INPUT,
        format!("Usage counter overflow while aggregating `{field}`."),
        "Keep usage quantities within u64 bounds.",
    )
}
