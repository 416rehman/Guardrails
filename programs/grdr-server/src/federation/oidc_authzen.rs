// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use grdr_crypto::constant_time_eq;
use grdr_identity::attest::SponsorState;
use grdr_identity::jwt_keys::MAX_ACCESS_TOKEN_TTL_SECS;
use grdr_identity::spiffe::{AgentLifecycle, SpiffeId};
use grdr_identity::standards_adapters::TransactionTokenClaims;
use grdr_identity::token_exchange::GrdrAccessClaims;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_denied, api_unauthorized, require_console_scope, tenant_trust_domain,
};
use super::types::{FedError, FederationState, TenantFederationState};

#[derive(Debug, Deserialize)]
pub struct TransactionTokenRequest {
    pub subject_token: String,
    pub audience: String,
    pub purpose: String,
    pub tctx: serde_json::Value,
    pub rctx: serde_json::Value,
    pub ttl_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TransactionTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub txn: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthZenSubject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthZenAction {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthZenResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthZenEvaluationRequest {
    pub subject: AuthZenSubject,
    pub action: AuthZenAction,
    pub resource: AuthZenResource,
    #[serde(default)]
    pub context: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct AuthZenEvaluationResponse {
    pub decision: bool,
    pub context: serde_json::Value,
}

pub async fn post_transaction_token(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Json(req): Json<TransactionTokenRequest>,
) -> Result<Json<TransactionTokenResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let now_sec = now.as_second();
    let dpop_hdr = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let mut rt = st.runtime.write().await;
    let subject: GrdrAccessClaims = rt
        .key_ring
        .verify_jwt(&req.subject_token, Some("at+jwt"))
        .map_err(|e| api_unauthorized(&e.to_string()))?;
    let subj_spiffe =
        SpiffeId::parse(&subject.spiffe_id).map_err(|e| api_denied(&e.to_string()))?;
    if subj_spiffe.trust_domain() != tenant_trust_domain(&ctx.tenant_id) {
        return Err(api_denied("subject token trust domain mismatches tenant"));
    }
    if rt.jti_deny_list.is_revoked(&subject.jti)
        || subject.iss != rt.issuer_url
        || subject.iat > now_sec.saturating_add(rt.limits.max_skew_secs)
        || subject.exp <= now_sec
        || subject.exp.saturating_sub(subject.iat) > MAX_ACCESS_TOKEN_TTL_SECS
    {
        return Err(api_denied("subject token revoked, expired, or untrusted"));
    }
    let inst_active = rt
        .tenant(&ctx.tenant_id)
        .and_then(|t| t.instances.get(&subject.agi_id))
        .is_some_and(|inst| {
            inst.lifecycle == AgentLifecycle::Active
                && inst
                    .sponsor
                    .as_ref()
                    .is_some_and(|sp| sp.state == SponsorState::Active)
        });
    if !inst_active {
        return Err(api_denied(
            "subject agent instance must be Active with an active sponsor",
        ));
    }

    let verified_dpop = if let Some(ref cnf) = subject.cnf {
        let jwt = dpop_hdr
            .as_deref()
            .ok_or_else(|| api_unauthorized("DPoP proof required for bound subject token"))?;
        let expected_url = format!(
            "{}/oauth2/transaction-token",
            rt.issuer_url.trim_end_matches('/')
        );
        let verified = rt
            .dpop_verifier
            .check_proof_unrecorded(jwt, "POST", &expected_url, Some(&req.subject_token), now)
            .map_err(|e| api_unauthorized(&e.to_string()))?;
        if !constant_time_eq(verified.jkt.as_bytes(), cnf.jkt.as_bytes()) {
            return Err(api_unauthorized(
                "DPoP JWK thumbprint mismatches subject cnf.jkt",
            ));
        }
        Some(verified)
    } else {
        None
    };

    let ttl = req.ttl_secs.unwrap_or(180).clamp(15, 300);
    let exp = now_sec.saturating_add(ttl).min(subject.exp);
    if exp <= now_sec {
        return Err(api_denied("subject token remaining lifetime exhausted"));
    }
    let effective_ttl = exp.saturating_sub(now_sec);
    let txn = format!("txn_{}", Uuid::now_v7().simple());
    let claims = TransactionTokenClaims {
        iss: rt.issuer_url.clone(),
        sub: subject.sub,
        aud: req.audience,
        txn: txn.clone(),
        purp: req.purpose,
        tctx: req.tctx,
        rctx: req.rctx,
        iat: now_sec,
        exp,
    };
    claims
        .validate(now)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    if let Some(ref verified) = verified_dpop {
        rt.dpop_verifier
            .record_jti(verified, now)
            .map_err(|e| api_denied(&e.to_string()))?;
    }
    let jwt = rt
        .key_ring
        .sign_jwt("txntoken+jwt", &claims)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    Ok(Json(TransactionTokenResponse {
        access_token: jwt,
        token_type: "txn_token".to_string(),
        expires_in: effective_ttl,
        txn,
    }))
}

pub async fn post_authzen_evaluate(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<AuthZenEvaluationRequest>,
) -> Result<Json<AuthZenEvaluationResponse>, FedError> {
    st.ensure_healthy()?;
    let caller = require_console_scope(auth.as_deref(), "identity:read")?;
    let is_registered_gateway =
        caller.allows_scope("gateway:delegate") || caller.principal_id == "console-admin";
    if !is_registered_gateway && req.subject.id != caller.principal_id {
        return Err(api_denied(
            "ordinary caller cannot assert another AuthZEN subject.id",
        ));
    }

    let rt = st.runtime.read().await;
    let tenant = rt.tenant(&caller.tenant_id);
    let decision = evaluate_authzen_decision(tenant, caller, &req);
    Ok(Json(AuthZenEvaluationResponse {
        decision,
        context: serde_json::json!({
            "caller_principal": caller.principal_id,
            "tenant_id": caller.tenant_id,
            "gateway_delegated": is_registered_gateway,
            "resource": req.resource.id,
            "request_context": req.context,
        }),
    }))
}

fn evaluate_authzen_decision(
    tenant: Option<&TenantFederationState>,
    caller: &AuthContext,
    req: &AuthZenEvaluationRequest,
) -> bool {
    if req.action.name.trim().is_empty()
        || req.subject.subject_type.trim().is_empty()
        || req.resource.resource_type.trim().is_empty()
    {
        return false;
    }
    let Some(tenant_state) = tenant else {
        return false;
    };
    let check_instance_id = |id: &str| -> Option<bool> {
        let resolved_spiffe = tenant_state.alias_map.resolve_enrolled_id(id);
        let inst = tenant_state.instances.values().find(|inst| {
            inst.agi_id == id
                || inst.spiffe_id.as_str() == id
                || resolved_spiffe.is_some_and(|sp| inst.spiffe_id.as_str() == sp)
        })?;
        let active_sponsor = inst
            .sponsor
            .as_ref()
            .is_some_and(|sp| sp.state == SponsorState::Active);
        Some(inst.lifecycle == AgentLifecycle::Active && active_sponsor)
    };

    if req.subject.subject_type == "agent" {
        return check_instance_id(&req.subject.id).unwrap_or(false);
    }
    if req.subject.subject_type != "user" {
        return false;
    }
    if req.subject.id != caller.principal_id
        && !caller.allows_scope("gateway:delegate")
        && caller.principal_id != "console-admin"
    {
        return false;
    }
    for ctx_key in ["agi_id", "session_spiffe_id"] {
        if let Some(raw_val) = req.context.get(ctx_key) {
            let Some(id_val) = raw_val.as_str() else {
                return false;
            };
            if !check_instance_id(id_val).unwrap_or(false) {
                return false;
            }
        }
    }
    true
}
