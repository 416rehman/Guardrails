// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Tenant-scoped SQL/Sigma hunt execution (blocking content table unless authorized, enforcing 24h
//! retro paging window) and bidirectional ticketing convergence (`docs/design/18`).

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_core::detect::kill_switch::server_operational_limits;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_POLICY_STEP_UP};
use grdr_model::{ActionAttempt, CodedError, DecisionReceipt, Finding, FindingClass};
use grdr_ports::hunt_sql::{HuntTable, parse_hunt_sql};
use grdr_review::inert::render_inert_explanation;

use crate::store::surfaces_respond_ops::ServerResponseActionRecord;

const ONE_HOUR_SECS: i64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedHuntRecord {
    pub hunt_id: String,
    pub org_id: String,
    pub name: String,
    pub query_sql: Option<String>,
    pub sigma_clauses: Vec<SigmaPredicate>,
    pub retroactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaPredicate {
    pub field: String,
    pub op: SigmaMatchOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaMatchOp {
    Equals,
    Contains,
    StartsWith,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntHitRow {
    pub record_id: String,
    pub session_id: String,
    pub device_id: String,
    pub agent_name: String,
    pub target_or_rule: String,
    pub retro: bool,
    pub page_eligible: bool,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntExecutionRecord {
    pub run_id: String,
    pub org_id: String,
    pub retro: bool,
    pub total_hits: usize,
    pub rows: Vec<HuntHitRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketSyncManifest {
    pub vendor_id: String,
    pub open_state: String,
    pub investigating_state: String,
    pub contained_state: String,
    pub resolved_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalTicketLink {
    pub link_id: String,
    #[serde(default)]
    pub org_id: String,
    pub incident_id: String,
    pub vendor_id: String,
    pub external_ticket_id: String,
    pub canonical_state: String,
    pub revision: u64,
    pub updated_at_ms: i64,
    pub last_sync_origin: String,
    pub inert_summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketSyncOutcome {
    Applied,
    IgnoredEcho,
    SkippedStale,
}

pub(crate) struct HuntQueryRequest<'a> {
    pub run_id: &'a str,
    pub org_id: &'a str,
    pub sql: Option<&'a str>,
    pub sigma_clauses: &'a [SigmaPredicate],
    pub include_content: bool,
    pub retro: bool,
    pub now_sec: i64,
    pub session_orgs: &'a BTreeMap<String, String>,
    pub device_orgs: &'a BTreeMap<String, String>,
    pub attempts: &'a [ActionAttempt],
    pub receipts: &'a [DecisionReceipt],
    pub findings: &'a [Finding],
    pub responses: &'a [ServerResponseActionRecord],
}

pub(crate) struct TicketEditRequest<'a> {
    pub org_id: &'a str,
    pub incident_id: &'a str,
    pub vendor_id: &'a str,
    pub external_ticket_id: &'a str,
    pub vendor_state: &'a str,
    pub sync_origin: &'a str,
    pub revision: u64,
    pub raw_summary: &'a str,
    pub now_ms: i64,
}

/// Evaluates SQL (`grdr_ports::hunt_sql`) and/or Sigma queries over tenant-scoped store records.
pub(crate) fn run_hunt_over_store(
    req: HuntQueryRequest<'_>,
) -> Result<HuntExecutionRecord, CodedError> {
    if req.org_id.trim().is_empty() {
        return Err(CodedError::new(
            CODE_INVALID_INPUT,
            "hunt query rejected: tenant org_id context is required (fail-closed)",
            "Authenticate into an active tenant organisation before running hunts.",
        ));
    }

    let cfg = server_operational_limits().map_err(|err| {
        CodedError::new(
            CODE_CONFLICT,
            format!("operational limits unavailable: {err}"),
            "Restore embedded contracts/limits.toml configuration.",
        )
    })?;
    let max_hunt_rows = cfg.max_batch_events.max(1);
    let day_secs = i64::from(cfg.fleet_response_key_hours).saturating_mul(ONE_HOUR_SECS);
    let active_cutoff_sec = req.now_sec.saturating_sub(day_secs);

    let parsed = match req.sql {
        Some(q) => Some(parse_hunt_sql(q, req.include_content)?),
        None => None,
    };
    let table = parsed.as_ref().map_or(HuntTable::Events, |p| p.table);
    if table == HuntTable::Content && !req.include_content {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "hunt query against `content` table denied when include_content=false",
            "Request content-authorized hunt mode or query activity/decision/events.",
        ));
    }

    let sql_preds = parsed.as_ref().map_or(&[][..], |p| p.predicates.as_slice());
    let limit = parsed
        .as_ref()
        .and_then(|p| p.sql_limit)
        .unwrap_or(max_hunt_rows)
        .min(max_hunt_rows);
    let proj = parsed.as_ref().map(|p| p.projection.as_slice());

    let mut rows = Vec::new();
    match table {
        HuntTable::Decision => {
            for r in req.receipts {
                if rows.len() >= limit {
                    break;
                }
                if !record_belongs_to_org(
                    req.org_id,
                    &r.session_id,
                    &r.device_id,
                    req.session_orgs,
                    req.device_orgs,
                ) {
                    continue;
                }
                let map = BTreeMap::from([
                    ("decision_id".into(), r.receipt_id.clone()),
                    ("session_id".into(), r.session_id.clone()),
                    ("device_id".into(), r.device_id.clone()),
                    ("agent_name".into(), r.agent_name.clone()),
                    (
                        "verdict".into(),
                        format!("{:?}", r.verdict).to_ascii_lowercase(),
                    ),
                    ("rule_id".into(), r.rule_id.clone().unwrap_or_default()),
                    ("target".into(), r.target.clone()),
                ]);
                if matches_predicates(&map, sql_preds, req.sigma_clauses) {
                    rows.push(HuntHitRow {
                        record_id: r.receipt_id.clone(),
                        session_id: r.session_id.clone(),
                        device_id: r.device_id.clone(),
                        agent_name: r.agent_name.clone(),
                        target_or_rule: r.rule_id.clone().unwrap_or_else(|| r.target.clone()),
                        retro: req.retro,
                        page_eligible: false,
                        fields: project_map(&map, proj),
                    });
                }
            }
        }
        HuntTable::Activity | HuntTable::Content => {
            for a in req.attempts {
                if rows.len() >= limit {
                    break;
                }
                if !record_belongs_to_org(
                    req.org_id,
                    &a.session_id,
                    &a.device_id,
                    req.session_orgs,
                    req.device_orgs,
                ) {
                    continue;
                }
                let map = BTreeMap::from([
                    ("attempt_id".into(), a.id.clone()),
                    ("session_id".into(), a.session_id.clone()),
                    ("device_id".into(), a.device_id.clone()),
                    ("agent_name".into(), a.agent_name.clone()),
                    ("action_class".into(), a.action_class.as_str().into()),
                    ("target".into(), a.target.clone()),
                ]);
                if matches_predicates(&map, sql_preds, req.sigma_clauses) {
                    rows.push(HuntHitRow {
                        record_id: a.id.clone(),
                        session_id: a.session_id.clone(),
                        device_id: a.device_id.clone(),
                        agent_name: a.agent_name.clone(),
                        target_or_rule: a.target.clone(),
                        retro: req.retro,
                        page_eligible: false,
                        fields: project_map(&map, proj),
                    });
                }
            }
        }
        HuntTable::Events => {
            for f in req.findings {
                if rows.len() >= limit {
                    break;
                }
                if !record_belongs_to_org(
                    req.org_id,
                    &f.session_id,
                    &f.device_id,
                    req.session_orgs,
                    req.device_orgs,
                ) {
                    continue;
                }
                let map = BTreeMap::from([
                    ("finding_id".into(), f.id.clone()),
                    ("session_id".into(), f.session_id.clone()),
                    ("device_id".into(), f.device_id.clone()),
                    ("agent_name".into(), f.agent_name.clone()),
                    (
                        "class".into(),
                        format!("{:?}", f.class).to_ascii_lowercase(),
                    ),
                    ("rule_id".into(), f.rule_id.clone().unwrap_or_default()),
                    ("target".into(), f.target.clone()),
                ]);
                if matches_predicates(&map, sql_preds, req.sigma_clauses) {
                    let is_threat_or_tamper =
                        matches!(f.class, FindingClass::Threat | FindingClass::Tamper);
                    let active_24h = f.detected_at.as_second() >= active_cutoff_sec;
                    let page_eligible = if req.retro {
                        is_threat_or_tamper && active_24h
                    } else {
                        is_threat_or_tamper
                    };
                    rows.push(HuntHitRow {
                        record_id: f.id.clone(),
                        session_id: f.session_id.clone(),
                        device_id: f.device_id.clone(),
                        agent_name: f.agent_name.clone(),
                        target_or_rule: f.rule_id.clone().unwrap_or_else(|| f.target.clone()),
                        retro: req.retro,
                        page_eligible,
                        fields: project_map(&map, proj),
                    });
                }
            }
            for ra in req.responses {
                if rows.len() >= limit {
                    break;
                }
                if ra.org_id != req.org_id {
                    continue;
                }
                let map = BTreeMap::from([
                    ("command_id".into(), ra.command_id.clone()),
                    ("org_id".into(), ra.org_id.clone()),
                    ("scope_key".into(), ra.scope_key.clone()),
                ]);
                if matches_predicates(&map, sql_preds, req.sigma_clauses) {
                    rows.push(HuntHitRow {
                        record_id: ra.command_id.clone(),
                        session_id: String::new(),
                        device_id: String::new(),
                        agent_name: String::new(),
                        target_or_rule: ra.scope_key.clone(),
                        retro: req.retro,
                        page_eligible: false,
                        fields: project_map(&map, proj),
                    });
                }
            }
        }
    }

    Ok(HuntExecutionRecord {
        run_id: req.run_id.to_owned(),
        org_id: req.org_id.to_owned(),
        retro: req.retro,
        total_hits: rows.len(),
        rows,
    })
}

/// Applies bidirectional ticket edit with `sync_origin = "grdr"` echo suppression,
/// manifest state mapping, inert summary sanitization, and monotonic revision convergence.
pub(crate) fn converge_ticket_edit(
    links: &mut Vec<ExternalTicketLink>,
    manifests: &[TicketSyncManifest],
    req: TicketEditRequest<'_>,
) -> Result<TicketSyncOutcome, CodedError> {
    if req.org_id.trim().is_empty() {
        return Err(CodedError::new(
            CODE_INVALID_INPUT,
            "ticket sync requires tenant org_id",
            "Authenticate into an active tenant organisation before syncing tickets.",
        ));
    }
    let norm_origin = req.sync_origin.trim().to_ascii_lowercase();
    if norm_origin == "grdr"
        && links.iter().any(|l| {
            l.org_id == req.org_id
                && l.incident_id == req.incident_id
                && l.external_ticket_id == req.external_ticket_id
                && l.last_sync_origin == "grdr"
                && l.revision == req.revision
        })
    {
        return Ok(TicketSyncOutcome::IgnoredEcho);
    }

    let mapped = map_vendor_state(manifests, req.vendor_id, req.vendor_state)?;
    let inert = render_inert_explanation(req.raw_summary).text;

    if let Some(existing) = links.iter_mut().find(|l| {
        l.org_id == req.org_id
            && l.incident_id == req.incident_id
            && l.external_ticket_id == req.external_ticket_id
    }) {
        if req.revision < existing.revision
            || (req.revision == existing.revision && req.now_ms < existing.updated_at_ms)
        {
            return Ok(TicketSyncOutcome::SkippedStale);
        }
        existing.canonical_state = mapped;
        existing.revision = req.revision;
        existing.updated_at_ms = req.now_ms;
        existing.last_sync_origin = norm_origin;
        existing.inert_summary = inert;
        return Ok(TicketSyncOutcome::Applied);
    }

    links.push(ExternalTicketLink {
        link_id: format!(
            "tkt_{}_{}_{}",
            req.org_id, req.vendor_id, req.external_ticket_id
        ),
        org_id: req.org_id.to_owned(),
        incident_id: req.incident_id.to_owned(),
        vendor_id: req.vendor_id.to_owned(),
        external_ticket_id: req.external_ticket_id.to_owned(),
        canonical_state: mapped,
        revision: req.revision,
        updated_at_ms: req.now_ms,
        last_sync_origin: norm_origin,
        inert_summary: inert,
    });
    Ok(TicketSyncOutcome::Applied)
}

pub(crate) fn record_belongs_to_org(
    org_id: &str,
    session_id: &str,
    device_id: &str,
    session_orgs: &BTreeMap<String, String>,
    device_orgs: &BTreeMap<String, String>,
) -> bool {
    if let Some(owner) = session_orgs.get(session_id) {
        return owner == org_id;
    }
    device_orgs
        .get(device_id)
        .is_some_and(|owner| owner == org_id)
}

fn map_vendor_state(
    manifests: &[TicketSyncManifest],
    vendor_id: &str,
    vendor_state: &str,
) -> Result<String, CodedError> {
    let norm = vendor_state.trim().to_ascii_lowercase();
    let Some(manifest) = manifests
        .iter()
        .find(|m| m.vendor_id.eq_ignore_ascii_case(vendor_id))
    else {
        return Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("no declarative ticket manifest registered for vendor `{vendor_id}`"),
            "Load a TicketSyncManifest pack for this vendor.",
        ));
    };
    if norm == manifest.open_state.to_ascii_lowercase() {
        Ok("open".into())
    } else if norm == manifest.investigating_state.to_ascii_lowercase() {
        Ok("investigating".into())
    } else if norm == manifest.contained_state.to_ascii_lowercase() {
        Ok("contained".into())
    } else if norm == manifest.resolved_state.to_ascii_lowercase() {
        Ok("resolved".into())
    } else {
        Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("unrecognized vendor ticket state `{vendor_state}` for `{vendor_id}`"),
            "Map external ticket state inside TicketSyncManifest.",
        ))
    }
}

fn matches_predicates(
    row: &BTreeMap<String, String>,
    sql_preds: &[(String, String)],
    sigma: &[SigmaPredicate],
) -> bool {
    let sql_ok = sql_preds
        .iter()
        .all(|(k, v)| row.get(k).is_some_and(|rv| rv.eq_ignore_ascii_case(v)));
    let sigma_ok = sigma.iter().all(|clause| {
        let Some(val) = row.get(&clause.field) else {
            return false;
        };
        let lhs = val.to_ascii_lowercase();
        let rhs = clause.value.to_ascii_lowercase();
        match clause.op {
            SigmaMatchOp::Equals => lhs == rhs,
            SigmaMatchOp::Contains => lhs.contains(&rhs),
            SigmaMatchOp::StartsWith => lhs.starts_with(&rhs),
        }
    });
    sql_ok && sigma_ok
}

fn project_map(
    row: &BTreeMap<String, String>,
    proj: Option<&[String]>,
) -> BTreeMap<String, String> {
    let Some(cols) = proj else {
        return row.clone();
    };
    if cols.is_empty() {
        return row.clone();
    }
    cols.iter()
        .filter_map(|c| row.get(c).map(|v| (c.clone(), v.clone())))
        .collect()
}

pub(crate) fn current_ms() -> i64 {
    Timestamp::now().as_millisecond()
}
