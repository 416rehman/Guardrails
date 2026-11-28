// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, State};
use grdr_identity::attest::{
    AgentInstanceRecord, InstanceSponsorKind, RetiredSeenEvent, SponsorRef, SponsorState,
};
use grdr_identity::broker_types::Ceiling;
use grdr_identity::jwt_keys::OkpEd25519Jwk;
use grdr_identity::spiffe::{AgentLifecycle, SpiffeId};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_conflict, api_denied, api_not_found, auth_actor, default_instance_ceiling,
    require_console_scope, revoke_tenant_leases, tenant_trust_domain,
};
use super::types::{FedError, FederationState};

#[derive(Debug, Deserialize)]
pub struct RegisterInstanceRequest {
    pub local_agi_id: String,
    pub org_id: String,
    pub aid_id: Option<String>,
    pub sponsor_id: Option<String>,
    pub sponsor_kind: Option<InstanceSponsorKind>,
    pub ceiling: Option<Ceiling>,
}

#[derive(Debug, Serialize)]
pub struct RegisterInstanceResponse {
    pub instance: AgentInstanceRecord,
    pub aliased_spiffe_id: String,
    pub local_history_preserved: bool,
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorKind {
    IdpJag,
    SsfTransmitter,
    WorkloadOidc,
    HardwareCa,
}

#[derive(Debug, Deserialize)]
pub struct RegisterTrustAnchorRequest {
    pub kind: TrustAnchorKind,
    pub jwk: OkpEd25519Jwk,
    pub issuer_url: Option<String>,
    pub hardware_vendor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterTrustAnchorResponse {
    pub kind: TrustAnchorKind,
    pub kid: String,
    pub tenant_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TransferSponsorRequest {
    pub agi_id: String,
    pub action: String,
    pub target_sponsor_id: String,
    pub target_sponsor_kind: Option<InstanceSponsorKind>,
}

#[derive(Debug, Deserialize)]
pub struct RetireInstanceRequest {
    pub agi_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ReportRetiredSeenRequest {
    pub agi_id: String,
    pub session_id: String,
}

pub async fn list_instances(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<AgentInstanceRecord>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let rt = st.runtime.read().await;
    let out = rt
        .tenant(&ctx.tenant_id)
        .map(|t| t.instances.values().cloned().collect())
        .unwrap_or_default();
    Ok(Json(out))
}

pub async fn register_trust_anchor(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<RegisterTrustAnchorRequest>,
) -> Result<Json<RegisterTrustAnchorResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    req.jwk
        .public_key_bytes()
        .map_err(|e| api_bad_request(&e.to_string()))?;
    let kid = req.jwk.kid.clone();
    if kid.trim().is_empty() {
        return Err(api_bad_request("trust anchor JWK requires non-empty kid"));
    }

    let mut rt = st.runtime.write().await;
    {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if let Some(iss) = req
            .issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            grdr_identity::http_security::validate_exact_endpoint_url(iss, false)
                .map_err(|e| api_bad_request(&format!("invalid trusted issuer_url: {e}")))?;
            if !tenant.trusted_federated_issuers.iter().any(|x| x == iss) {
                tenant.trusted_federated_issuers.push(iss.to_owned());
            }
        }
        match req.kind {
            TrustAnchorKind::IdpJag => tenant.trusted_idp_keys.push(req.jwk),
            TrustAnchorKind::SsfTransmitter => tenant.trusted_ssf_keys.push(req.jwk),
            TrustAnchorKind::WorkloadOidc => tenant.trusted_federated_jwks.push(req.jwk),
            TrustAnchorKind::HardwareCa => {
                let vendor = req
                    .hardware_vendor
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        api_bad_request("hardware_vendor required for HardwareCa trust anchor")
                    })?;
                tenant
                    .trusted_hardware_ca_keys
                    .entry(vendor.to_owned())
                    .or_default()
                    .push(req.jwk);
            }
        }
    }
    st.persist_runtime(&rt)?;
    Ok(Json(RegisterTrustAnchorResponse {
        kind: req.kind,
        kid,
        tenant_id: ctx.tenant_id.clone(),
    }))
}

pub async fn register_instance(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<RegisterInstanceRequest>,
) -> Result<Json<RegisterInstanceResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let expected_dom = tenant_trust_domain(&ctx.tenant_id);
    if tenant_trust_domain(&req.org_id) != expected_dom {
        return Err(api_denied(
            "cannot register agent instance in another tenant trust domain",
        ));
    }
    let org_seg = ctx.tenant_id.strip_prefix("org-").unwrap_or(&ctx.tenant_id);
    let spiffe_id = SpiffeId::agent_instance(org_seg, &req.local_agi_id)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    let now = Timestamp::now();

    let mut rt = st.runtime.write().await;
    let issuer_url = rt.issuer_url.clone();
    let mut retired_resighted = false;
    let (rec, aliased_spiffe_id) = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        tenant
            .alias_map
            .record_join_alias(&req.local_agi_id, &spiffe_id)
            .map_err(|e| api_bad_request(&e.to_string()))?;

        if let Some(existing) = tenant.instances.get(&req.local_agi_id)
            && existing.lifecycle == AgentLifecycle::Retired
        {
            retired_resighted = true;
            let resighted =
                AgentInstanceRecord::new_discovered(&req.local_agi_id, spiffe_id.clone());
            (resighted, spiffe_id.as_str().to_owned())
        } else {
            let mut rec = tenant
                .instances
                .remove(&req.local_agi_id)
                .unwrap_or_else(|| {
                    AgentInstanceRecord::new_discovered(&req.local_agi_id, spiffe_id.clone())
                });
            rec.spiffe_id = spiffe_id.clone();
            if req.aid_id.is_some() {
                rec.aid_id = req.aid_id;
            }
            if let Some(sponsor_id) = req.sponsor_id.filter(|s| !s.trim().is_empty()) {
                rec.sponsor = Some(SponsorRef {
                    sponsor_id,
                    sponsor_kind: req.sponsor_kind.unwrap_or(InstanceSponsorKind::HumanUser),
                    state: SponsorState::Active,
                });
            }
            if rec.lifecycle == AgentLifecycle::Discovered && rec.sponsor.is_some() {
                let _ = rec.transition_lifecycle(AgentLifecycle::Active, now);
            }
            let ceiling = req
                .ceiling
                .unwrap_or_else(|| default_instance_ceiling(&issuer_url));
            tenant
                .instance_ceilings
                .insert(req.local_agi_id.clone(), ceiling);
            tenant
                .instances
                .insert(req.local_agi_id.clone(), rec.clone());
            (rec, spiffe_id.as_str().to_owned())
        }
    };
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        if retired_resighted {
            "identity.retired-seen"
        } else {
            "identity.instance.aliased"
        },
        auth_actor(auth.as_deref()),
        if retired_resighted {
            format!(
                "Retired instance `{}` re-sighted; kept in Discovered",
                req.local_agi_id
            )
        } else {
            format!(
                "Aliased local `{}` to `{aliased_spiffe_id}` preserving local history",
                req.local_agi_id
            )
        },
        req.local_agi_id,
    )
    .await?;

    Ok(Json(RegisterInstanceResponse {
        instance: rec,
        aliased_spiffe_id,
        local_history_preserved: true,
    }))
}

pub async fn transfer_sponsor(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<TransferSponsorRequest>,
) -> Result<Json<AgentInstanceRecord>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let actor = ctx.principal_id.clone();
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let updated = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        let inst = tenant
            .instances
            .get_mut(&req.agi_id)
            .ok_or_else(|| api_not_found("agent instance not found"))?;
        match req.action.as_str() {
            "initiate" => {
                inst.initiate_sponsor_transfer(
                    SponsorRef {
                        sponsor_id: req.target_sponsor_id,
                        sponsor_kind: req
                            .target_sponsor_kind
                            .unwrap_or(InstanceSponsorKind::HumanUser),
                        state: SponsorState::Active,
                    },
                    actor,
                    now,
                )
                .map_err(|e| api_conflict(&e.to_string()))?;
            }
            "accept" => {
                if ctx.principal_id != req.target_sponsor_id || !ctx.confirmation.is_confirmed() {
                    return Err(api_denied(
                        "sponsor acceptance requires target sponsor identity and confirmed intent",
                    ));
                }
                inst.accept_sponsor_transfer(&req.target_sponsor_id)
                    .map_err(|e| api_conflict(&e.to_string()))?;
            }
            _ => return Err(api_bad_request("action must be `initiate` or `accept`")),
        }
        inst.clone()
    };
    st.persist_runtime(&rt)?;
    Ok(Json(updated))
}

pub async fn retire_instance(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<RetireInstanceRequest>,
) -> Result<Json<AgentInstanceRecord>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let mut deny_list = std::mem::take(&mut rt.jti_deny_list);
    let mut tenant = rt.tenant_mut(&ctx.tenant_id).clone();
    let retire_res: Result<AgentInstanceRecord, FedError> = (|| {
        {
            let inst = tenant
                .instances
                .get_mut(&req.agi_id)
                .ok_or_else(|| api_not_found("agent instance not found"))?;
            inst.transition_lifecycle(AgentLifecycle::Retired, now)
                .map_err(|e| api_conflict(&e.to_string()))?;
        }
        let _ = revoke_tenant_leases(&mut tenant, &mut deny_list, now.as_second(), |lease| {
            lease.instance_agi_id == req.agi_id
        })?;
        tenant
            .instances
            .get(&req.agi_id)
            .cloned()
            .ok_or_else(|| api_not_found("agent instance not found"))
    })();
    rt.jti_deny_list = deny_list;
    rt.tenants.insert(ctx.tenant_id.clone(), tenant);
    let updated = retire_res?;
    st.persist_runtime(&rt)?;
    Ok(Json(updated))
}

pub async fn report_retired_seen(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<ReportRetiredSeenRequest>,
) -> Result<Json<Option<RetiredSeenEvent>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let rt = st.runtime.read().await;
    let tenant = rt
        .tenant(&ctx.tenant_id)
        .ok_or_else(|| api_not_found("agent instance not found"))?;
    let inst = tenant
        .instances
        .get(&req.agi_id)
        .ok_or_else(|| api_not_found("agent instance not found"))?;
    let ev = inst.observe_runtime_session(&req.session_id, now);
    drop(rt);
    if let Some(ref event) = ev {
        st.append_audit(
            "identity.retired-seen",
            auth_actor(auth.as_deref()),
            format!(
                "Observed retired instance `{}` in `{}`",
                event.agi_id, event.session_id
            ),
            event.agi_id.clone(),
        )
        .await?;
    }
    Ok(Json(ev))
}
