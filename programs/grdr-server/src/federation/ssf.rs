// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Extension, State};
use grdr_identity::jwt_keys::{MAX_FEDERATION_TOKEN_TTL_SECS, verify_jwt_with_jwks};
use grdr_identity::standards_adapters::{
    SecurityEventKind, SecurityEventToken, SetSubjectIdentifier, build_security_event_token,
};
use grdr_identity::token_exchange::JtiDenyList;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_denied, auth_actor, orphan_sponsor_instances, push_bounded_ssf_event,
    require_console_scope, revoke_tenant_leases,
};
use super::types::{FedError, FederationState, SsfStreamState, TenantFederationState};

#[derive(Debug, Serialize)]
pub struct SsfConfigurationResponse {
    pub issuer: String,
    pub jwks_uri: String,
    pub delivery_methods_supported: Vec<String>,
    pub configuration_endpoint: String,
    pub status_endpoint: String,
    pub poll_endpoint: String,
    pub events_endpoint: String,
}

#[derive(Debug, Deserialize)]
pub struct SsfStreamUpdateRequest {
    pub audience: Option<String>,
    pub events_requested: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SsfPollRequest {
    #[serde(default)]
    pub ack: Vec<String>,
    #[serde(rename = "maxEvents")]
    pub max_events: Option<usize>,
    #[serde(rename = "returnImmediately", default)]
    pub return_immediately: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignedSsfEventRequest {
    #[serde(alias = "set_jwt")]
    pub set: String,
}

#[derive(Debug, Serialize)]
pub struct SsfPollResponse {
    pub sets: BTreeMap<String, String>,
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

#[derive(Debug, Serialize)]
pub struct SsfEventIngestResponse {
    pub processed: bool,
    pub revoked_jtis: Vec<String>,
    pub orphaned_instances: Vec<String>,
    pub outbound_set_jti: Option<String>,
}

#[derive(Default)]
struct SsfApplyOutcome {
    revoked_jtis: Vec<String>,
    orphaned_instances: Vec<String>,
    outbound_jti: Option<String>,
}

pub async fn get_ssf_configuration(
    State(st): State<FederationState>,
) -> Result<Json<SsfConfigurationResponse>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    let base = rt.issuer_url.trim_end_matches('/');
    Ok(Json(SsfConfigurationResponse {
        issuer: base.to_string(),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        delivery_methods_supported: vec!["urn:ietf:rfc:8936".to_string()],
        configuration_endpoint: format!("{base}/ssf/streams"),
        status_endpoint: format!("{base}/ssf/streams"),
        poll_endpoint: format!("{base}/ssf/poll"),
        events_endpoint: format!("{base}/ssf/events"),
    }))
}

pub async fn get_ssf_streams(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<SsfStreamState>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let mut rt = st.runtime.write().await;
    let tenant = rt.tenant_mut(&ctx.tenant_id);
    Ok(Json(tenant.ssf_stream.clone()))
}

pub async fn post_ssf_streams(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<SsfStreamUpdateRequest>,
) -> Result<Json<SsfStreamState>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let mut rt = st.runtime.write().await;
    {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if let Some(aud) = req.audience {
            if aud.trim().is_empty() {
                return Err(api_bad_request("SSF audience cannot be empty"));
            }
            tenant.ssf_stream.audience = aud.trim().to_owned();
        }
        if let Some(ev) = req.events_requested {
            tenant.ssf_stream.events_requested = ev;
        }
    }
    st.persist_runtime(&rt)?;
    let stream = rt.tenant_mut(&ctx.tenant_id).ssf_stream.clone();
    Ok(Json(stream))
}

pub async fn post_ssf_poll(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<SsfPollRequest>,
) -> Result<Json<SsfPollResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let _ = req.return_immediately;
    let mut rt = st.runtime.write().await;
    let ring = rt.key_ring.clone();
    let (sets, more_available) = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if !req.ack.is_empty() {
            tenant.ssf_events.retain(|ev| !req.ack.contains(&ev.jti));
        }
        let limit = req.max_events.unwrap_or(50).clamp(1, 200);
        let mut sets = BTreeMap::new();
        for ev in tenant.ssf_events.iter().take(limit) {
            let jwt = ring
                .sign_jwt("secevent+jwt", ev)
                .map_err(|e| api_bad_request(&e.to_string()))?;
            sets.insert(ev.jti.clone(), jwt);
        }
        let more_available = tenant.ssf_events.len() > sets.len();
        (sets, more_available)
    };
    st.persist_runtime(&rt)?;
    Ok(Json(SsfPollResponse {
        sets,
        more_available,
    }))
}

pub async fn post_ssf_event(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<SignedSsfEventRequest>,
) -> Result<Json<SsfEventIngestResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let now_sec = now.as_second();

    let mut rt = st.runtime.write().await;
    let issuer_url = rt.issuer_url.clone();
    let max_skew = rt.limits.max_skew_secs;
    let max_ssf_events = rt.limits.max_ssf_events;

    let set_tok: SecurityEventToken = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        let tok: SecurityEventToken = verify_jwt_with_jwks(
            req.set.trim(),
            Some("secevent+jwt"),
            &tenant.trusted_ssf_keys,
        )
        .map_err(|e| api_denied(&format!("SET signature verification failed: {e}")))?;
        let iss = tok.iss.trim();
        if iss.is_empty()
            || !tenant
                .trusted_federated_issuers
                .iter()
                .any(|allowed| allowed == iss)
        {
            return Err(api_denied("SET issuer is not trusted"));
        }
        if tok.aud != tenant.ssf_stream.audience && tok.aud != issuer_url {
            return Err(api_denied("SET audience mismatch"));
        }
        if tok.jti.trim().is_empty() || tok.events.is_empty() {
            return Err(api_bad_request("SET jti and events cannot be empty"));
        }
        if tok.iat > now_sec.saturating_add(max_skew)
            || now_sec.saturating_sub(tok.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(api_denied("SET iat is outside 300s freshness window"));
        }
        tok
    };

    let replay_key = format!("{}:{}:{}", ctx.tenant_id, set_tok.iss, set_tok.jti);
    if rt.ssf_jti_replay.is_revoked(&replay_key) {
        return Err(api_denied("SET jti replay rejected"));
    }
    let replay_exp = set_tok
        .iat
        .saturating_add(MAX_FEDERATION_TOKEN_TTL_SECS)
        .saturating_add(max_skew)
        .max(now_sec.saturating_add(60));
    rt.ssf_jti_replay
        .revoke(replay_key, replay_exp, now_sec)
        .map_err(|e| api_denied(&e.to_string()))?;

    let mut deny_list = std::mem::take(&mut rt.jti_deny_list);
    let mut tenant = rt.tenant_mut(&ctx.tenant_id).clone();
    let outcome = apply_ssf_events(
        &mut tenant,
        &mut deny_list,
        &issuer_url,
        max_ssf_events,
        &set_tok,
        now,
    );
    rt.jti_deny_list = deny_list;
    rt.tenants.insert(ctx.tenant_id.clone(), tenant);
    let out = outcome?;

    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "ssf.caep.processed",
        auth_actor(auth.as_deref()),
        format!(
            "Processed signed SSF/CAEP event `{}`; revoked {} JTIs",
            set_tok.jti,
            out.revoked_jtis.len()
        ),
        set_tok.jti,
    )
    .await?;

    Ok(Json(SsfEventIngestResponse {
        processed: true,
        revoked_jtis: out.revoked_jtis,
        orphaned_instances: out.orphaned_instances,
        outbound_set_jti: out.outbound_jti,
    }))
}

fn apply_ssf_events(
    tenant: &mut TenantFederationState,
    deny_list: &mut JtiDenyList,
    issuer_url: &str,
    max_ssf_events: usize,
    set_tok: &SecurityEventToken,
    now: Timestamp,
) -> Result<SsfApplyOutcome, FedError> {
    let mut out = SsfApplyOutcome::default();

    for (uri, payload) in &set_tok.events {
        let Some(subject_id) = payload
            .get("subject")
            .and_then(|s| s.get("sub"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        apply_single_ssf_event(
            tenant,
            deny_list,
            issuer_url,
            max_ssf_events,
            uri,
            subject_id,
            payload,
            now,
            &mut out,
        )?;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn apply_single_ssf_event(
    tenant: &mut TenantFederationState,
    deny_list: &mut JtiDenyList,
    issuer_url: &str,
    max_ssf_events: usize,
    uri: &str,
    subject_id: &str,
    payload: &serde_json::Value,
    now: Timestamp,
    out: &mut SsfApplyOutcome,
) -> Result<(), FedError> {
    let session_revoked = SecurityEventKind::CaepSessionRevoked.event_uri();
    let cred_change = SecurityEventKind::CaepCredentialChange.event_uri();
    let al_change = SecurityEventKind::CaepAssuranceLevelChange.event_uri();
    let risc_disabled = SecurityEventKind::RiscAccountDisabled.event_uri();

    if uri == session_revoked || uri == cred_change || uri == risc_disabled {
        let rev = revoke_tenant_leases(tenant, deny_list, now.as_second(), |lease| {
            lease.session_id == subject_id
                || lease.instance_agi_id == subject_id
                || lease.sponsor_id == subject_id
                || lease.device_id == subject_id
        })?;
        for jti in rev {
            if !out.revoked_jtis.contains(&jti) {
                out.revoked_jtis.push(jti);
            }
        }
        if uri == risc_disabled {
            let (orph, more) = orphan_sponsor_instances(tenant, deny_list, subject_id, now)?;
            out.orphaned_instances.extend(orph);
            for jti in more {
                if !out.revoked_jtis.contains(&jti) {
                    out.revoked_jtis.push(jti);
                }
            }
        }
        out.outbound_jti = Some(emit_outbound_caep_revocation(
            tenant,
            issuer_url,
            max_ssf_events,
            subject_id,
            now,
        ));
    } else if uri == al_change
        && let Some(al) = payload.get("grdr-al").and_then(|v| v.as_str())
        && matches!(al, "AL0" | "AL1")
    {
        let rev = revoke_tenant_leases(tenant, deny_list, now.as_second(), |lease| {
            lease.instance_agi_id == subject_id || lease.session_id == subject_id
        })?;
        out.revoked_jtis.extend(rev);
        out.outbound_jti = Some(emit_outbound_caep_revocation(
            tenant,
            issuer_url,
            max_ssf_events,
            subject_id,
            now,
        ));
    }
    Ok(())
}

fn emit_outbound_caep_revocation(
    tenant: &mut TenantFederationState,
    issuer_url: &str,
    max_ssf_events: usize,
    subject_id: &str,
    now: Timestamp,
) -> String {
    let jti = format!("set_{}", Uuid::now_v7().simple());
    let subject = SetSubjectIdentifier {
        format: "iss_sub".to_string(),
        iss: Some(issuer_url.to_owned()),
        sub: subject_id.to_owned(),
    };
    let ev = build_security_event_token(
        issuer_url,
        &tenant.ssf_stream.audience,
        &jti,
        SecurityEventKind::CaepSessionRevoked,
        &subject,
        None,
        now,
    );
    push_bounded_ssf_event(&mut tenant.ssf_events, max_ssf_events, ev);
    jti
}
