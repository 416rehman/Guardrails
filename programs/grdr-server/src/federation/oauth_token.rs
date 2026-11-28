// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use grdr_identity::jwt_keys::MAX_ACCESS_TOKEN_TTL_SECS;
use grdr_identity::spiffe::{AgentLifecycle, SpiffeId};
use grdr_identity::standards_adapters::{ID_JAG_GRANT_TYPE, MAX_STATUS_LIST_BYTES};
use grdr_identity::token_exchange::{DpopCnfClaim, GrdrAccessClaims, VerifiedDpop};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::id_jag::{handle_id_jag_grant, handle_token_exchange};
use super::runtime::{api_bad_request, api_denied, api_not_found, api_unauthorized};
use super::types::{
    ActiveServerLease, DeviceFlowStatus, FedError, FederationRuntime, FederationState,
    TenantFederationState,
};

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

#[derive(Debug, Deserialize)]
pub struct OAuthTokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub device_code: Option<String>,
    pub subject_token: Option<String>,
    pub actor_token: Option<String>,
    pub assertion: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub federated_trust_domain: Option<String>,
    pub requested_ttl_secs: Option<i64>,
    pub instance_agi_id: Option<String>,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub jti: String,
    pub scope: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf_jkt: Option<String>,
}

pub async fn post_oauth_token(
    State(st): State<FederationState>,
    headers: HeaderMap,
    Json(req): Json<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, FedError> {
    st.ensure_healthy()?;
    let dpop_hdr = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match req.grant_type.as_str() {
        DEVICE_CODE_GRANT => handle_device_code_token(&st, &req, dpop_hdr.as_deref()).await,
        TOKEN_EXCHANGE_GRANT => handle_token_exchange(&st, &req, dpop_hdr.as_deref()).await,
        ID_JAG_GRANT_TYPE => handle_id_jag_grant(&st, &req, dpop_hdr.as_deref()).await,
        other => Err(api_bad_request(&format!(
            "unsupported grant_type `{other}`"
        ))),
    }
}

async fn handle_device_code_token(
    st: &FederationState,
    req: &OAuthTokenRequest,
    dpop_hdr: Option<&str>,
) -> Result<Json<OAuthTokenResponse>, FedError> {
    let code = req
        .device_code
        .as_deref()
        .ok_or_else(|| api_bad_request("device_code is required"))?;
    let client_id = req
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| api_bad_request("client_id is required for device_code grant"))?;
    let now = Timestamp::now();
    let now_sec = now.as_second();

    let mut rt = st.runtime.write().await;
    let verified_dpop = check_dpop_unrecorded(&rt, dpop_hdr, "POST", "/oauth2/token", None, now)?;
    let rec = rt
        .device_codes
        .get(code)
        .cloned()
        .ok_or_else(|| api_not_found("invalid or already consumed device_code"))?;
    if rec.client_id != client_id {
        return Err(api_unauthorized("device_code client_id mismatch"));
    }
    if rec.expires_at <= now_sec {
        return Err(api_denied("expired_token"));
    }
    if rec.status != DeviceFlowStatus::Authorized {
        return Err(api_bad_request("authorization_pending"));
    }
    let tenant_id = rec
        .tenant_id
        .clone()
        .ok_or_else(|| api_denied("device_code has not bound to an authorized tenant"))?;
    let sub = rec
        .pseudonym_sub
        .clone()
        .ok_or_else(|| api_bad_request("missing bound pseudonym"))?;

    let agi_id = req
        .instance_agi_id
        .clone()
        .unwrap_or_else(|| format!("agi_{}", Uuid::now_v7().simple()));
    if let Some(tenant) = rt.tenant(&tenant_id)
        && let Some(inst) = tenant.instances.get(&agi_id)
        && inst.lifecycle != AgentLifecycle::Active
    {
        return Err(api_denied("target agent instance is not active"));
    }
    let org_seg = tenant_id.strip_prefix("org-").unwrap_or(&tenant_id);
    let spiffe =
        SpiffeId::agent_instance(org_seg, &agi_id).map_err(|e| api_bad_request(&e.to_string()))?;
    let ttl = req
        .requested_ttl_secs
        .unwrap_or(MAX_ACCESS_TOKEN_TTL_SECS)
        .clamp(60, MAX_ACCESS_TOKEN_TTL_SECS);
    let jti = format!("jti_{}", Uuid::now_v7().simple());
    let exp = now_sec.saturating_add(ttl);
    let dpop_jkt = verified_dpop.as_ref().map(|v| v.jkt.clone());
    let aud = rt.issuer_url.clone();
    let claims = GrdrAccessClaims {
        iss: rt.issuer_url.clone(),
        sub: sub.clone(),
        aud,
        iat: now_sec,
        exp,
        jti: jti.clone(),
        client_id: rec.client_id.clone(),
        scope: rec.scope.clone(),
        agi_id: agi_id.clone(),
        spiffe_id: spiffe.as_str().to_owned(),
        act: None,
        cnf: dpop_jkt.clone().map(|jkt| DpopCnfClaim { jkt }),
    };

    if let Some(ref verified) = verified_dpop {
        rt.dpop_verifier
            .record_jti(verified, now)
            .map_err(|e| api_unauthorized(&e.to_string()))?;
    }
    rt.device_codes.remove(code);
    rt.user_code_index.remove(&rec.user_code);

    let jwt = rt
        .key_ring
        .sign_jwt("at+jwt", &claims)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    let device_id = req
        .device_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("dev_local")
        .to_owned();
    let session_id = req
        .session_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map_or_else(|| format!("ses_{}", Uuid::now_v7().simple()), str::to_owned);
    let max_leases = rt.limits.max_leases;
    let tenant = rt.tenant_mut(&tenant_id);
    record_tenant_lease(
        tenant,
        max_leases,
        &jti,
        &agi_id,
        &session_id,
        &device_id,
        &sub,
        exp,
    )?;
    st.persist_runtime(&rt)?;

    Ok(Json(OAuthTokenResponse {
        access_token: jwt,
        token_type: token_type_for_dpop(dpop_jkt.as_deref()),
        expires_in: ttl,
        jti,
        scope: rec.scope,
        sub,
        cnf_jkt: dpop_jkt,
    }))
}

pub(crate) fn check_dpop_unrecorded(
    rt: &FederationRuntime,
    dpop_hdr: Option<&str>,
    method: &str,
    path: &str,
    access_token: Option<&str>,
    now: Timestamp,
) -> Result<Option<VerifiedDpop>, FedError> {
    let Some(jwt) = dpop_hdr else {
        return Ok(None);
    };
    let expected_url = format!("{}{path}", rt.issuer_url.trim_end_matches('/'));
    let verified = rt
        .dpop_verifier
        .check_proof_unrecorded(jwt, method, &expected_url, access_token, now)
        .map_err(|e| api_unauthorized(&e.to_string()))?;
    Ok(Some(verified))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_tenant_lease(
    tenant: &mut TenantFederationState,
    max_leases: usize,
    jti: &str,
    agi_id: &str,
    session_id: &str,
    device_id: &str,
    sponsor_id: &str,
    expires_at: i64,
) -> Result<(), FedError> {
    if tenant.leases.len() >= max_leases {
        let now_sec = Timestamp::now().as_second();
        tenant
            .leases
            .retain(|lease| !lease.revoked && lease.expires_at > now_sec);
    }
    if tenant.leases.len() >= max_leases {
        return Err(api_denied("tenant active lease capacity reached"));
    }
    let max_status_bits = MAX_STATUS_LIST_BYTES.saturating_mul(8);
    if tenant.next_status_index >= max_status_bits {
        return Err(api_denied("tenant status list capacity reached"));
    }
    let status_idx = tenant.next_status_index;
    tenant.next_status_index = tenant.next_status_index.saturating_add(1);
    let tenant_id = tenant.tenant_id.clone();
    tenant.leases.push(ActiveServerLease {
        lease_id: format!("lse_{}", Uuid::now_v7().simple()),
        jti: jti.to_owned(),
        tenant_id,
        status_index: status_idx,
        session_id: session_id.to_owned(),
        instance_agi_id: agi_id.to_owned(),
        device_id: device_id.to_owned(),
        sponsor_id: sponsor_id.to_owned(),
        expires_at,
        revoked: false,
    });
    Ok(())
}

pub(crate) fn token_type_for_dpop(dpop_jkt: Option<&str>) -> String {
    if dpop_jkt.is_some() {
        "DPoP".to_string()
    } else {
        "Bearer".to_string()
    }
}
