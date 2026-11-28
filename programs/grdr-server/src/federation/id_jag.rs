// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use grdr_crypto::constant_time_eq;
use grdr_identity::attest::SponsorState;
use grdr_identity::broker_types::Ceiling;
use grdr_identity::ceiling_ref::{CeilingProbe, verify_no_widening};
use grdr_identity::jwt_keys::MAX_ACCESS_TOKEN_TTL_SECS;
use grdr_identity::spiffe::{AgentLifecycle, SpiffeId};
use grdr_identity::token_exchange::{
    DpopCnfClaim, GrdrAccessClaims, TokenExchangeRequest, TokenExchangeService,
};
use jiff::Timestamp;
use uuid::Uuid;

use super::oauth_token::{
    OAuthTokenRequest, OAuthTokenResponse, check_dpop_unrecorded, record_tenant_lease,
    token_type_for_dpop,
};
use super::runtime::{api_bad_request, api_denied, api_unauthorized, tenant_trust_domain};
use super::types::{FedError, FederationRuntime, FederationState};

pub async fn handle_token_exchange(
    st: &FederationState,
    req: &OAuthTokenRequest,
    dpop_hdr: Option<&str>,
) -> Result<Json<OAuthTokenResponse>, FedError> {
    let subject_jwt = req
        .subject_token
        .as_deref()
        .ok_or_else(|| api_bad_request("subject_token required for token-exchange"))?;
    let now = Timestamp::now();
    let now_sec = now.as_second();

    let mut rt = st.runtime.write().await;
    let verified_dpop = check_dpop_unrecorded(
        &rt,
        dpop_hdr,
        "POST",
        "/oauth2/token",
        Some(subject_jwt),
        now,
    )?;
    let subject_claims: GrdrAccessClaims = rt
        .key_ring
        .verify_jwt(subject_jwt, Some("at+jwt"))
        .map_err(|e| api_unauthorized(&e.to_string()))?;
    if rt.jti_deny_list.is_revoked(&subject_claims.jti)
        || subject_claims.iss != rt.issuer_url
        || subject_claims.iat > now_sec.saturating_add(rt.limits.max_skew_secs)
    {
        return Err(api_denied("subject token revoked or untrusted"));
    }
    if let Some(ref cnf) = subject_claims.cnf {
        let matches = verified_dpop
            .as_ref()
            .is_some_and(|v| constant_time_eq(v.jkt.as_bytes(), cnf.jkt.as_bytes()));
        if !matches {
            return Err(api_unauthorized(
                "DPoP proof matching subject cnf.jkt is required",
            ));
        }
    }

    let actor_subject = match req.actor_token.as_deref() {
        Some(actor_jwt) => {
            let actor_claims: GrdrAccessClaims = rt
                .key_ring
                .verify_jwt(actor_jwt, Some("at+jwt"))
                .map_err(|e| api_unauthorized(&format!("invalid actor_token: {e}")))?;
            if rt.jti_deny_list.is_revoked(&actor_claims.jti)
                || actor_claims.iss != rt.issuer_url
                || actor_claims.iat > now_sec.saturating_add(rt.limits.max_skew_secs)
                || actor_claims.exp <= now_sec
                || actor_claims.exp.saturating_sub(actor_claims.iat) > MAX_ACCESS_TOKEN_TTL_SECS
            {
                return Err(api_denied("actor_token revoked, expired, or untrusted"));
            }
            actor_claims.spiffe_id
        }
        None => subject_claims.spiffe_id.clone(),
    };

    let tenant_id = resolve_tenant_for_spiffe(&rt, &subject_claims.spiffe_id)
        .ok_or_else(|| api_denied("subject SPIFFE domain has no active tenant"))?;
    let (parent_ceiling, trusted_domains, sponsor_id, session_id, device_id) = {
        let tenant = rt
            .tenant(&tenant_id)
            .ok_or_else(|| api_denied("tenant not initialized"))?;
        let inst = tenant
            .instances
            .get(&subject_claims.agi_id)
            .ok_or_else(|| api_denied("authoritative agent instance not registered"))?;
        if inst.lifecycle != AgentLifecycle::Active {
            return Err(api_denied("agent instance lifecycle is not Active"));
        }
        let sponsor = inst
            .sponsor
            .as_ref()
            .filter(|sp| sp.state == SponsorState::Active)
            .ok_or_else(|| api_denied("agent instance lacks active sponsor"))?;
        let ceiling = tenant
            .instance_ceilings
            .get(&subject_claims.agi_id)
            .cloned()
            .ok_or_else(|| api_denied("instance lacks server-stored ceiling"))?;
        let auth_lease = tenant
            .leases
            .iter()
            .rev()
            .find(|l| !l.revoked && l.jti == subject_claims.jti);
        let ses = auth_lease
            .map(|l| l.session_id.clone())
            .unwrap_or_else(|| format!("ses_{}", Uuid::now_v7().simple()));
        let dev = auth_lease
            .map(|l| l.device_id.clone())
            .unwrap_or_else(|| "dev_bound".to_string());
        (
            ceiling,
            tenant.trusted_spiffe_domains.clone(),
            sponsor.sponsor_id.clone(),
            ses,
            dev,
        )
    };

    let dpop_jkt = verified_dpop.as_ref().map(|v| v.jkt.clone());
    let svc = TokenExchangeService {
        issuer: rt.issuer_url.clone(),
        trusted_spiffe_domains: trusted_domains,
    };
    let ex_req = TokenExchangeRequest {
        subject_claims: subject_claims.clone(),
        requested_audience: req
            .resource
            .clone()
            .unwrap_or_else(|| rt.issuer_url.clone()),
        requested_scope: req.scope.clone().unwrap_or(subject_claims.scope.clone()),
        actor_subject,
        parent_ceiling: parent_ceiling.clone(),
        child_ceiling: parent_ceiling.clone(),
        requested_ttl_secs: req.requested_ttl_secs.unwrap_or(300),
        federated_trust_domain: req.federated_trust_domain.clone(),
        dpop_jkt: dpop_jkt.clone(),
    };
    let (new_claims, intersected) = svc
        .exchange(&ex_req, &rt.jti_deny_list, now)
        .map_err(|e| api_denied(&e.to_string()))?;
    run_ceiling_probe(&parent_ceiling, &parent_ceiling, &intersected)?;

    if let Some(ref verified) = verified_dpop {
        rt.dpop_verifier
            .record_jti(verified, now)
            .map_err(|e| api_unauthorized(&e.to_string()))?;
    }
    let ttl = new_claims.exp.saturating_sub(new_claims.iat);
    let jwt = rt
        .key_ring
        .sign_jwt("at+jwt", &new_claims)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    let max_leases = rt.limits.max_leases;
    let tenant = rt.tenant_mut(&tenant_id);
    record_tenant_lease(
        tenant,
        max_leases,
        &new_claims.jti,
        &new_claims.agi_id,
        &session_id,
        &device_id,
        &sponsor_id,
        new_claims.exp,
    )?;
    st.persist_runtime(&rt)?;

    Ok(Json(OAuthTokenResponse {
        access_token: jwt,
        token_type: token_type_for_dpop(dpop_jkt.as_deref()),
        expires_in: ttl,
        jti: new_claims.jti,
        scope: new_claims.scope,
        sub: new_claims.sub,
        cnf_jkt: dpop_jkt,
    }))
}

pub async fn handle_id_jag_grant(
    st: &FederationState,
    req: &OAuthTokenRequest,
    dpop_hdr: Option<&str>,
) -> Result<Json<OAuthTokenResponse>, FedError> {
    let assertion = req
        .assertion
        .as_deref()
        .ok_or_else(|| api_bad_request("assertion JWT required for ID-JAG jwt-bearer grant"))?;
    let resource = req
        .resource
        .as_deref()
        .ok_or_else(|| api_bad_request("RFC 8707 resource is required for ID-JAG exchange"))?;
    let now = Timestamp::now();

    let mut rt = st.runtime.write().await;
    let verified_dpop = check_dpop_unrecorded(&rt, dpop_hdr, "POST", "/oauth2/token", None, now)?;
    let expected_aud = rt.issuer_url.clone();

    let mut candidate_claims = None;
    for tenant in rt.tenants.values() {
        if let Ok(claims) = rt.id_jag_replay.validate_unconsumed(
            &tenant.trusted_idp_keys,
            &tenant.trusted_federated_issuers,
            assertion,
            &expected_aud,
            resource,
            now,
        ) {
            candidate_claims = Some(claims);
            break;
        }
    }
    let probe_claims = candidate_claims
        .ok_or_else(|| api_denied("ID-JAG assertion signature or issuer untrusted"))?;
    let spiffe_str = probe_claims
        .spiffe_id
        .as_deref()
        .ok_or_else(|| api_denied("ID-JAG assertion must include valid spiffe_id"))?;
    let spiffe = SpiffeId::parse(spiffe_str).map_err(|e| api_denied(&e.to_string()))?;
    let resolved_tenant = resolve_tenant_for_spiffe(&rt, spiffe.as_str())
        .ok_or_else(|| api_denied("ID-JAG SPIFFE trust domain has no active tenant"))?;
    let agi_id = spiffe
        .path()
        .strip_prefix("/agi/")
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| api_denied("ID-JAG spiffe_id must target /agi/<instance_id>"))?
        .to_owned();

    let jag_claims = {
        let tenant = rt
            .tenant(&resolved_tenant)
            .ok_or_else(|| api_denied("resolved tenant not initialized"))?;
        if !tenant
            .trusted_spiffe_domains
            .contains(spiffe.trust_domain())
        {
            return Err(api_denied(
                "ID-JAG SPIFFE trust domain not trusted by tenant",
            ));
        }
        let verified = rt
            .id_jag_replay
            .validate_unconsumed(
                &tenant.trusted_idp_keys,
                &tenant.trusted_federated_issuers,
                assertion,
                &expected_aud,
                resource,
                now,
            )
            .map_err(|e| api_denied(&e.to_string()))?;
        let inst = tenant
            .instances
            .get(&agi_id)
            .ok_or_else(|| api_denied("ID-JAG target agent instance not registered"))?;
        if inst.lifecycle != AgentLifecycle::Active {
            return Err(api_denied("ID-JAG target instance is not Active"));
        }
        if !inst
            .sponsor
            .as_ref()
            .is_some_and(|sp| sp.state == SponsorState::Active)
        {
            return Err(api_denied("ID-JAG target instance lacks active sponsor"));
        }
        verified
    };

    let now_sec = now.as_second();
    let ttl = jag_claims
        .exp
        .saturating_sub(now_sec)
        .clamp(1, MAX_ACCESS_TOKEN_TTL_SECS);
    let new_jti = format!("jti_{}", Uuid::now_v7().simple());
    let dpop_jkt = verified_dpop.as_ref().map(|v| v.jkt.clone());
    let access = GrdrAccessClaims {
        iss: rt.issuer_url.clone(),
        sub: jag_claims.sub.clone(),
        aud: resource.to_owned(),
        iat: now_sec,
        exp: now_sec.saturating_add(ttl),
        jti: new_jti.clone(),
        client_id: jag_claims.client_id,
        scope: jag_claims.scope.clone(),
        agi_id: agi_id.clone(),
        spiffe_id: spiffe.as_str().to_owned(),
        act: None,
        cnf: dpop_jkt.clone().map(|jkt| DpopCnfClaim { jkt }),
    };
    let jwt = rt
        .key_ring
        .sign_jwt("at+jwt", &access)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    let max_leases = rt.limits.max_leases;
    let session_id = format!("ses_{}", Uuid::now_v7().simple());
    {
        let tenant = rt.tenant_mut(&resolved_tenant);
        record_tenant_lease(
            tenant,
            max_leases,
            &new_jti,
            &agi_id,
            &session_id,
            "dev_local",
            &access.sub,
            access.exp,
        )?;
    }
    rt.id_jag_replay
        .record_jti(&jag_claims.iss, &jag_claims.jti, jag_claims.exp, now)
        .map_err(|e| api_denied(&e.to_string()))?;
    if let Some(ref verified) = verified_dpop {
        rt.dpop_verifier
            .record_jti(verified, now)
            .map_err(|e| api_unauthorized(&e.to_string()))?;
    }
    st.persist_runtime(&rt)?;

    Ok(Json(OAuthTokenResponse {
        access_token: jwt,
        token_type: token_type_for_dpop(dpop_jkt.as_deref()),
        expires_in: ttl,
        jti: new_jti,
        scope: access.scope,
        sub: jag_claims.sub,
        cnf_jkt: dpop_jkt,
    }))
}

fn run_ceiling_probe(
    parent: &Ceiling,
    child: &Ceiling,
    intersected: &Ceiling,
) -> Result<(), FedError> {
    if let Some(cls) = intersected.allowed_classes.iter().next().copied()
        && let Some(acc) = intersected.allowed_accounts.iter().next()
        && let Some(act) = intersected.allowed_actions.iter().next()
        && let Some(pref) = intersected.allowed_resource_prefixes.first()
    {
        let probe = CeilingProbe {
            class: cls,
            account_id: acc,
            action: act,
            resource: pref,
            depth: 0,
        };
        verify_no_widening(parent, child, intersected, &probe)
            .map_err(|e| api_denied(&e.to_string()))?;
    }
    Ok(())
}

fn resolve_tenant_for_spiffe(rt: &FederationRuntime, spiffe_raw: &str) -> Option<String> {
    let parsed = SpiffeId::parse(spiffe_raw).ok()?;
    let dom = parsed.trust_domain();
    for tid in rt.tenants.keys() {
        if tenant_trust_domain(tid) == dom {
            return Some(tid.clone());
        }
    }
    for (tid, tenant) in &rt.tenants {
        if dom != "local" && tenant.trusted_spiffe_domains.contains(dom) {
            return Some(tid.clone());
        }
    }
    None
}
