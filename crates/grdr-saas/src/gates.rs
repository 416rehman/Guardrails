// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::{CODE_SAAS_INVALID_INPUT, saas_error};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitEconomicsInput {
    pub paid_endpoints: u64,
    pub price_per_endpoint_cents: u64,
    pub compute_cents: u64,
    pub storage_cents: u64,
    pub egress_cents: u64,
    pub model_eval_cents: u64,
    pub support_ops_cents: u64,
    pub payment_fee_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitEconomicsResult {
    pub gross_revenue_cents: u64,
    pub variable_cogs_cents: u64,
    pub gross_profit_cents: i64,
    pub gross_margin_bps: i64,
    pub per_endpoint_cogs_cents: u64,
    pub sustainable_above_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GateRequirementStatus {
    Passed,
    Pending { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedGateChecklist {
    pub cell_restore_under_4h_rto: GateRequirementStatus,
    pub backup_restore_verified: GateRequirementStatus,
    pub slo_burn_alerts_active: GateRequirementStatus,
    pub org_export_roundtrip_passed: GateRequirementStatus,
    pub runbooks_complete: GateRequirementStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidOfferGateChecklist {
    pub hosted_gate_passed: GateRequirementStatus,
    pub reconciliation_zero_variance: GateRequirementStatus,
    pub dunning_keeps_enforcement: GateRequirementStatus,
    pub sanctions_screen_wired: GateRequirementStatus,
    pub model_terms_reviewed: GateRequirementStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheckItem {
    pub name: String,
    pub status: GateRequirementStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    pub ready: bool,
    pub items: Vec<GateCheckItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanctionsDecision {
    Clear,
    ManualReview { reason: String },
    Blocked { reason: String },
}

pub trait SanctionsScreen {
    fn screen_org(&self, org_id: &OrgId, iso_country: &str, entity_name: &str)
    -> SanctionsDecision;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawSanctionsScreen")]
pub struct DeterministicSanctionsScreen {
    blocked_countries: BTreeSet<String>,
    review_keywords: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawSanctionsScreen {
    blocked_countries: Vec<String>,
    #[serde(default)]
    review_keywords: Vec<String>,
}

impl TryFrom<RawSanctionsScreen> for DeterministicSanctionsScreen {
    type Error = CodedError;

    fn try_from(raw: RawSanctionsScreen) -> Result<Self, Self::Error> {
        let countries: Vec<&str> = raw.blocked_countries.iter().map(String::as_str).collect();
        let keywords: Vec<&str> = raw.review_keywords.iter().map(String::as_str).collect();
        Self::new(&countries, &keywords)
    }
}

impl GateRequirementStatus {
    #[must_use]
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl DeterministicSanctionsScreen {
    pub fn new(blocked_countries: &[&str], review_keywords: &[&str]) -> Result<Self, CodedError> {
        let mut countries = BTreeSet::new();
        for raw in blocked_countries {
            let code = raw.trim().to_ascii_uppercase();
            if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(saas_error(
                    CODE_SAAS_INVALID_INPUT,
                    format!(
                        "Invalid embargoed ISO country code `{raw}` in sanctions screen config."
                    ),
                    "Supply two-letter ISO-3166 alpha-2 country codes.",
                ));
            }
            countries.insert(code);
        }
        if countries.is_empty() {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Sanctions screen cannot be initialized without a configured denied-jurisdiction list.",
                "Load denied ISO country codes from policy config before accepting tenants.",
            ));
        }
        let keywords = review_keywords
            .iter()
            .map(|k| k.trim().to_ascii_lowercase())
            .filter(|k| !k.is_empty())
            .collect();
        Ok(Self {
            blocked_countries: countries,
            review_keywords: keywords,
        })
    }
}

impl SanctionsScreen for DeterministicSanctionsScreen {
    fn screen_org(
        &self,
        _org_id: &OrgId,
        iso_country: &str,
        entity_name: &str,
    ) -> SanctionsDecision {
        if self.blocked_countries.is_empty() {
            return SanctionsDecision::Blocked {
                reason: "sanctions_policy_unconfigured".to_owned(),
            };
        }
        let clean_name = entity_name.trim();
        if clean_name.is_empty() {
            return SanctionsDecision::Blocked {
                reason: "empty_entity_name".to_owned(),
            };
        }
        let country = iso_country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return SanctionsDecision::Blocked {
                reason: "invalid_iso_country_code".to_owned(),
            };
        }
        if self.blocked_countries.contains(&country) {
            return SanctionsDecision::Blocked {
                reason: format!("embargoed_country:{country}"),
            };
        }
        let lower_name = clean_name.to_ascii_lowercase();
        for kw in &self.review_keywords {
            if lower_name.contains(kw) {
                return SanctionsDecision::ManualReview {
                    reason: format!("matched_review_keyword:{kw}"),
                };
            }
        }
        SanctionsDecision::Clear
    }
}

pub fn compute_unit_economics(
    input: &UnitEconomicsInput,
    min_gross_margin_bps: i64,
) -> Result<UnitEconomicsResult, CodedError> {
    if input.paid_endpoints == 0 || input.price_per_endpoint_cents == 0 {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Paid endpoint count and unit price must be positive for unit economics calculation.",
            "Provide positive paid_endpoints and price_per_endpoint_cents.",
        ));
    }
    if input.payment_fee_bps > 10_000 {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            format!(
                "Payment fee {} bps exceeds 10000 bps (100%).",
                input.payment_fee_bps
            ),
            "Provide payment_fee_bps within 0..=10000.",
        ));
    }
    let gross_revenue_cents = input
        .paid_endpoints
        .checked_mul(input.price_per_endpoint_cents)
        .ok_or_else(|| overflow_err("gross_revenue_cents"))?;
    let fee_num = u128::from(gross_revenue_cents)
        .checked_mul(u128::from(input.payment_fee_bps))
        .ok_or_else(|| overflow_err("payment_fees_cents"))?;
    let payment_fees_cents =
        u64::try_from(fee_num.div_ceil(10_000)).map_err(|_| overflow_err("payment_fees_cents"))?;

    let variable_cogs_cents = input
        .compute_cents
        .checked_add(input.storage_cents)
        .and_then(|v| v.checked_add(input.egress_cents))
        .and_then(|v| v.checked_add(input.model_eval_cents))
        .and_then(|v| v.checked_add(input.support_ops_cents))
        .and_then(|v| v.checked_add(payment_fees_cents))
        .ok_or_else(|| overflow_err("variable_cogs_cents"))?;

    let rev_i128 = i128::from(gross_revenue_cents);
    let cogs_i128 = i128::from(variable_cogs_cents);
    let profit_i128 = rev_i128
        .checked_sub(cogs_i128)
        .ok_or_else(|| overflow_err("gross_profit_cents"))?;
    let gross_profit_cents =
        i64::try_from(profit_i128).map_err(|_| overflow_err("gross_profit_cents"))?;
    let margin_i128 = profit_i128
        .checked_mul(10_000)
        .and_then(|v| v.checked_div(rev_i128))
        .ok_or_else(|| overflow_err("gross_margin_bps"))?;
    let gross_margin_bps =
        i64::try_from(margin_i128).map_err(|_| overflow_err("gross_margin_bps"))?;
    let per_endpoint_cogs_cents = variable_cogs_cents
        .checked_div(input.paid_endpoints)
        .ok_or_else(|| overflow_err("per_endpoint_cogs_cents"))?;

    Ok(UnitEconomicsResult {
        gross_revenue_cents,
        variable_cogs_cents,
        gross_profit_cents,
        gross_margin_bps,
        per_endpoint_cogs_cents,
        sustainable_above_target: gross_margin_bps >= min_gross_margin_bps,
    })
}

#[must_use]
pub fn evaluate_hosted_gate(c: &HostedGateChecklist) -> GateEvaluation {
    let items = vec![
        GateCheckItem {
            name: "cell_restore_under_4h_rto".to_owned(),
            status: c.cell_restore_under_4h_rto.clone(),
        },
        GateCheckItem {
            name: "backup_restore_verified".to_owned(),
            status: c.backup_restore_verified.clone(),
        },
        GateCheckItem {
            name: "slo_burn_alerts_active".to_owned(),
            status: c.slo_burn_alerts_active.clone(),
        },
        GateCheckItem {
            name: "org_export_roundtrip_passed".to_owned(),
            status: c.org_export_roundtrip_passed.clone(),
        },
        GateCheckItem {
            name: "runbooks_complete".to_owned(),
            status: c.runbooks_complete.clone(),
        },
    ];
    let ready = items.iter().all(|i| i.status.is_passed());
    GateEvaluation { ready, items }
}

#[must_use]
pub fn evaluate_paid_offer_gate(c: &PaidOfferGateChecklist) -> GateEvaluation {
    let items = vec![
        GateCheckItem {
            name: "hosted_gate_passed".to_owned(),
            status: c.hosted_gate_passed.clone(),
        },
        GateCheckItem {
            name: "reconciliation_zero_variance".to_owned(),
            status: c.reconciliation_zero_variance.clone(),
        },
        GateCheckItem {
            name: "dunning_keeps_enforcement".to_owned(),
            status: c.dunning_keeps_enforcement.clone(),
        },
        GateCheckItem {
            name: "sanctions_screen_wired".to_owned(),
            status: c.sanctions_screen_wired.clone(),
        },
        GateCheckItem {
            name: "model_terms_reviewed".to_owned(),
            status: c.model_terms_reviewed.clone(),
        },
    ];
    let ready = items.iter().all(|i| i.status.is_passed());
    GateEvaluation { ready, items }
}

fn overflow_err(field: &str) -> CodedError {
    saas_error(
        CODE_SAAS_INVALID_INPUT,
        format!("Arithmetic overflow computing `{field}`."),
        "Keep unit economics inputs within representable bounds.",
    )
}
