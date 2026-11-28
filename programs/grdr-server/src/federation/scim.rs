// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use grdr_identity::standards_adapters::{
    SecurityEventKind, SetSubjectIdentifier, build_security_event_token,
};
use grdr_identity::token_exchange::JtiDenyList;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_conflict, api_not_found, auth_actor, orphan_sponsor_instances,
    push_bounded_ssf_event, require_console_scope,
};
use super::scim_resources::{
    ScimListQuery, ScimListResponse, ScimUserWire, paginate_cursor, to_scim_user_wire,
};
use super::types::{FedError, FederationState, ScimUserRecord, TenantFederationState};

#[derive(Debug, Deserialize)]
pub struct ScimEmailInput {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ScimUserCreateInput {
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmailInput>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ScimPatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ScimPatchRequest {
    #[serde(rename = "Operations", default)]
    pub operations: Vec<ScimPatchOperation>,
    pub active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ScimDeprovisionResult {
    pub user_id: String,
    pub active: bool,
    pub orphaned_instances: Vec<String>,
    pub revoked_jtis: Vec<String>,
}

pub async fn list_scim_users(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimUserWire>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let identity_mode = st.app.inner.read().await.privacy.identity_mode;
    let rt = st.runtime.read().await;
    let org_key = *rt.org_hmac_key;
    let dev_key = *rt.device_hmac_key;
    let all: Vec<ScimUserWire> = rt
        .tenant(&ctx.tenant_id)
        .map(|t| {
            t.scim_users
                .values()
                .map(|u| to_scim_user_wire(u, identity_mode, &org_key, &dev_key))
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(paginate_cursor(all, &q)?))
}

pub async fn create_scim_user(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<ScimUserCreateInput>,
) -> Result<Json<ScimUserWire>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if req.user_name.trim().is_empty() {
        return Err(api_bad_request("SCIM userName is required"));
    }
    let id = req
        .external_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("usr_{}", Uuid::now_v7().simple()));
    let email = req
        .emails
        .first()
        .map(|e| e.value.clone())
        .unwrap_or_else(|| req.user_name.clone());
    let rec = ScimUserRecord {
        id: id.clone(),
        external_id: req.external_id,
        user_name: req.user_name.trim().to_owned(),
        display_name: req
            .display_name
            .unwrap_or_else(|| req.user_name.trim().to_owned()),
        email,
        active: req.active.unwrap_or(true),
        updated_at: Timestamp::now(),
    };
    let identity_mode = st.app.inner.read().await.privacy.identity_mode;
    let mut rt = st.runtime.write().await;
    let org_key = *rt.org_hmac_key;
    let dev_key = *rt.device_hmac_key;
    let wire = to_scim_user_wire(&rec, identity_mode, &org_key, &dev_key);
    {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if tenant.scim_users.contains_key(&id) {
            return Err(api_conflict(&format!("SCIM user `{id}` already exists")));
        }
        tenant.scim_users.insert(id.clone(), rec);
    }
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "scim.user.provisioned",
        auth_actor(auth.as_deref()),
        format!("Provisioned SCIM sponsor `{}`", wire.user_name),
        id,
    )
    .await?;
    Ok(Json(wire))
}

pub async fn get_scim_user(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> Result<Json<ScimUserWire>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let identity_mode = st.app.inner.read().await.privacy.identity_mode;
    let rt = st.runtime.read().await;
    let org_key = *rt.org_hmac_key;
    let dev_key = *rt.device_hmac_key;
    let user = rt
        .tenant(&ctx.tenant_id)
        .and_then(|t| t.scim_users.get(&id))
        .ok_or_else(|| api_not_found("SCIM user not found"))?;
    Ok(Json(to_scim_user_wire(
        user,
        identity_mode,
        &org_key,
        &dev_key,
    )))
}

pub async fn patch_scim_user(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchRequest>,
) -> Result<Json<ScimDeprovisionResult>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let next_active = resolve_patch_active(&patch)
        .ok_or_else(|| api_bad_request("SCIM PATCH requires active boolean change"))?;
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let issuer_url = rt.issuer_url.clone();
    let max_ssf_events = rt.limits.max_ssf_events;
    let mut tenant = rt.tenant_mut(&ctx.tenant_id).clone();

    let (user_name, existing_id) = {
        let user = tenant
            .scim_users
            .get_mut(&id)
            .ok_or_else(|| api_not_found("SCIM user not found"))?;
        user.active = next_active;
        user.updated_at = now;
        (user.user_name.clone(), user.id.clone())
    };
    let res = if !next_active {
        let mut deny_list = std::mem::take(&mut rt.jti_deny_list);
        let cascade = cascade_sponsor_deprovision(
            &mut tenant,
            &mut deny_list,
            &issuer_url,
            max_ssf_events,
            &existing_id,
            &user_name,
            now,
        );
        rt.jti_deny_list = deny_list;
        cascade
    } else {
        Ok((Vec::new(), Vec::new()))
    };
    let (orphaned, revoked) = res?;
    rt.tenants.insert(ctx.tenant_id.clone(), tenant);
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        if next_active {
            "scim.user.activated"
        } else {
            "scim.user.deprovisioned"
        },
        auth_actor(auth.as_deref()),
        format!(
            "SCIM user `{id}` active={next_active}, orphaned={}",
            orphaned.len()
        ),
        id.clone(),
    )
    .await?;
    if !orphaned.is_empty() || !revoked.is_empty() {
        st.app.emit_live(
            "scim.sponsor.deprovisioned",
            format!(
                "Deprovisioned `{id}`; orphaned {} instances",
                orphaned.len()
            ),
            None,
        );
    }

    Ok(Json(ScimDeprovisionResult {
        user_id: id,
        active: next_active,
        orphaned_instances: orphaned,
        revoked_jtis: revoked,
    }))
}

pub async fn delete_scim_user(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Path(id): Path<String>,
) -> Result<Json<ScimDeprovisionResult>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let issuer_url = rt.issuer_url.clone();
    let max_ssf_events = rt.limits.max_ssf_events;
    let mut tenant = rt.tenant_mut(&ctx.tenant_id).clone();
    let removed = tenant
        .scim_users
        .remove(&id)
        .ok_or_else(|| api_not_found("SCIM user not found"))?;
    let mut deny_list = std::mem::take(&mut rt.jti_deny_list);
    let res = cascade_sponsor_deprovision(
        &mut tenant,
        &mut deny_list,
        &issuer_url,
        max_ssf_events,
        &removed.id,
        &removed.user_name,
        now,
    );
    rt.jti_deny_list = deny_list;
    let (orphaned, revoked) = res?;
    rt.tenants.insert(ctx.tenant_id.clone(), tenant);
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "scim.user.deleted",
        auth_actor(auth.as_deref()),
        format!(
            "Deleted SCIM sponsor `{id}`, orphaned {} instances",
            orphaned.len()
        ),
        id.clone(),
    )
    .await?;

    Ok(Json(ScimDeprovisionResult {
        user_id: id,
        active: false,
        orphaned_instances: orphaned,
        revoked_jtis: revoked,
    }))
}

fn cascade_sponsor_deprovision(
    tenant: &mut TenantFederationState,
    deny_list: &mut JtiDenyList,
    issuer_url: &str,
    max_ssf_events: usize,
    user_id: &str,
    user_name: &str,
    now: Timestamp,
) -> Result<(Vec<String>, Vec<String>), FedError> {
    let (mut orphaned, mut revoked) = orphan_sponsor_instances(tenant, deny_list, user_id, now)?;
    if user_name != user_id {
        let (more_orph, more_rev) = orphan_sponsor_instances(tenant, deny_list, user_name, now)?;
        for agi in more_orph {
            if !orphaned.contains(&agi) {
                orphaned.push(agi);
            }
        }
        for jti in more_rev {
            if !revoked.contains(&jti) {
                revoked.push(jti);
            }
        }
    }
    if !orphaned.is_empty() || !revoked.is_empty() {
        let subject = SetSubjectIdentifier {
            format: "iss_sub".to_string(),
            iss: Some(issuer_url.to_owned()),
            sub: user_id.to_owned(),
        };
        let event = build_security_event_token(
            issuer_url,
            &tenant.ssf_stream.audience,
            &format!("set_{}", Uuid::now_v7().simple()),
            SecurityEventKind::CaepSessionRevoked,
            &subject,
            None,
            now,
        );
        push_bounded_ssf_event(&mut tenant.ssf_events, max_ssf_events, event);
    }
    Ok((orphaned, revoked))
}

fn resolve_patch_active(patch: &ScimPatchRequest) -> Option<bool> {
    if let Some(active) = patch.active {
        return Some(active);
    }
    for op in &patch.operations {
        if !op.op.eq_ignore_ascii_case("replace") {
            continue;
        }
        if op.path.as_deref() == Some("active")
            && let Some(b) = op.value.as_bool()
        {
            return Some(b);
        }
        if op.path.is_none()
            && let Some(b) = op.value.get("active").and_then(|v| v.as_bool())
        {
            return Some(b);
        }
    }
    None
}
