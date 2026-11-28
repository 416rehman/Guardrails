// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Query, State};
use grdr_identity::attest::AgentInstanceRecord;
use grdr_identity::registry_correlation::{
    Agent365LicenseState, ExternalRegistryRecord, RegistryCorrelationReport,
    correlate_registry_records,
};
use grdr_identity::standards_adapters::{
    SecurityEventKind, SetSubjectIdentifier, build_security_event_token,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, auth_actor, push_bounded_ssf_event, require_console_scope,
    revoke_tenant_leases,
};
use super::types::{
    AdoptedCredentialMetadata, FedError, FederationState, OutwardReceiptRecord,
    TenantFederationState,
};

#[derive(Debug, Deserialize)]
pub struct CorrelateRegistriesRequest {
    pub external_records: Vec<ExternalRegistryRecord>,
    pub agent365_licensed: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AdoptCredentialRequest {
    pub crd_id: String,
    pub locator_id: String,
    pub store_kind: String,
    pub device_id: String,
}

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerRevokeScope {
    Session,
    Instance,
    Device,
    Principal,
}

#[derive(Debug, Deserialize)]
pub struct RevokeLeaseRequest {
    pub scope: ServerRevokeScope,
    pub target_id: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeLeaseResponse {
    pub revoked_leases: usize,
    pub revoked_jtis: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordOutwardReceiptRequest {
    pub agi_id: String,
    pub session_id: String,
    pub repo: String,
    pub commit_sha: String,
    pub patch_id: Option<String>,
    pub pr_number: Option<u64>,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct OutwardReceiptLookupQuery {
    pub commit_sha: Option<String>,
    pub patch_id: Option<String>,
    pub pr_number: Option<u64>,
}

pub async fn correlate_registries(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<CorrelateRegistriesRequest>,
) -> Result<Json<RegistryCorrelationReport>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let mut rt = st.runtime.write().await;
    let report = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        tenant.external_registries = req.external_records;
        if let Some(licensed) = req.agent365_licensed {
            tenant.agent365_license = if licensed {
                Agent365LicenseState::Licensed
            } else {
                Agent365LicenseState::UnlicensedDegraded
            };
        }
        let local: Vec<AgentInstanceRecord> = tenant.instances.values().cloned().collect();
        correlate_registry_records(&local, &tenant.external_registries, tenant.agent365_license)
    };
    st.persist_runtime(&rt)?;
    Ok(Json(report))
}

pub async fn adopt_credential(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<AdoptCredentialRequest>,
) -> Result<Json<AdoptedCredentialMetadata>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if !req.crd_id.starts_with("crd_") || req.locator_id.trim().is_empty() {
        return Err(api_bad_request(
            "adopt_credential accepts metadata-only crd_* identifier and locator_id",
        ));
    }
    let meta = AdoptedCredentialMetadata {
        crd_id: req.crd_id.clone(),
        locator_id: req.locator_id,
        store_kind: req.store_kind,
        owner_device_id: req.device_id,
        adopted_at: Timestamp::now(),
    };
    let mut rt = st.runtime.write().await;
    rt.tenant_mut(&ctx.tenant_id)
        .adopted_credentials
        .push(meta.clone());
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "identity.credential.adopted",
        auth_actor(auth.as_deref()),
        format!("Adopted credential metadata `{}`", meta.crd_id),
        meta.crd_id.clone(),
    )
    .await?;
    Ok(Json(meta))
}

pub async fn revoke_lease(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<RevokeLeaseRequest>,
) -> Result<Json<RevokeLeaseResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let issuer_url = rt.issuer_url.clone();
    let max_ssf_events = rt.limits.max_ssf_events;
    let mut deny_list = std::mem::take(&mut rt.jti_deny_list);
    let mut tenant = rt.tenant_mut(&ctx.tenant_id).clone();
    let rev_res =
        revoke_tenant_leases(
            &mut tenant,
            &mut deny_list,
            now.as_second(),
            |lease| match req.scope {
                ServerRevokeScope::Session => lease.session_id == req.target_id,
                ServerRevokeScope::Instance => lease.instance_agi_id == req.target_id,
                ServerRevokeScope::Device => lease.device_id == req.target_id,
                ServerRevokeScope::Principal => lease.sponsor_id == req.target_id,
            },
        );
    if let Ok(ref jtis) = rev_res
        && !jtis.is_empty()
    {
        emit_revoke_ssf(
            &mut tenant,
            &issuer_url,
            max_ssf_events,
            &req.target_id,
            now,
        );
    }
    rt.jti_deny_list = deny_list;
    rt.tenants.insert(ctx.tenant_id.clone(), tenant);
    let revoked_jtis = rev_res?;
    let count = revoked_jtis.len();
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "identity.lease.revoked",
        auth_actor(auth.as_deref()),
        format!("Revoked {count} server leases for `{}`", req.target_id),
        req.target_id,
    )
    .await?;

    Ok(Json(RevokeLeaseResponse {
        revoked_leases: count,
        revoked_jtis,
    }))
}

pub async fn record_outward_receipt(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<RecordOutwardReceiptRequest>,
) -> Result<Json<OutwardReceiptRecord>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if req.commit_sha.trim().is_empty() || req.repo.trim().is_empty() {
        return Err(api_bad_request("repo and commit_sha are required"));
    }
    let rec = OutwardReceiptRecord {
        receipt_id: format!("rcp_out_{}", Uuid::now_v7().simple()),
        agi_id: req.agi_id,
        session_id: req.session_id,
        repo: req.repo,
        commit_sha: req.commit_sha,
        patch_id: req.patch_id,
        pr_number: req.pr_number,
        signature: req.signature,
        recorded_at: Timestamp::now(),
    };
    let mut rt = st.runtime.write().await;
    rt.tenant_mut(&ctx.tenant_id)
        .outward_receipts
        .push(rec.clone());
    st.persist_runtime(&rt)?;
    Ok(Json(rec))
}

pub async fn lookup_outward_receipts(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<OutwardReceiptLookupQuery>,
) -> Result<Json<Vec<OutwardReceiptRecord>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let rt = st.runtime.read().await;
    let matches = rt
        .tenant(&ctx.tenant_id)
        .map(|t| {
            t.outward_receipts
                .iter()
                .filter(|r| {
                    let commit_ok = q
                        .commit_sha
                        .as_deref()
                        .is_some_and(|sha| r.commit_sha == sha);
                    let patch_ok = q
                        .patch_id
                        .as_deref()
                        .is_some_and(|pid| r.patch_id.as_deref() == Some(pid));
                    let pr_ok = q.pr_number.is_some_and(|pr| r.pr_number == Some(pr));
                    let no_filter =
                        q.commit_sha.is_none() && q.patch_id.is_none() && q.pr_number.is_none();
                    no_filter || commit_ok || patch_ok || pr_ok
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(matches))
}

fn emit_revoke_ssf(
    tenant: &mut TenantFederationState,
    issuer_url: &str,
    max_ssf_events: usize,
    target_id: &str,
    now: Timestamp,
) {
    let subject = SetSubjectIdentifier {
        format: "iss_sub".to_string(),
        iss: Some(issuer_url.to_owned()),
        sub: target_id.to_owned(),
    };
    let ev = build_security_event_token(
        issuer_url,
        &tenant.ssf_stream.audience,
        &format!("set_{}", Uuid::now_v7().simple()),
        SecurityEventKind::CaepSessionRevoked,
        &subject,
        None,
        now,
    );
    push_bounded_ssf_event(&mut tenant.ssf_events, max_ssf_events, ev);
}
