// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Query, State};
use grdr_crypto::fill_random;
use grdr_identity::jwt_keys::{
    JwkSetDocument, OidcDiscoveryMetadata, ProtectedResourceMetadata, discovery_metadata,
    protected_resource_metadata,
};
use grdr_identity::pseudonym::{derive_device_pseudonym, re_pseudonymize_for_org};
use grdr_identity::standards_adapters::{
    CimdClientMetadata, ID_JAG_GRANT_TYPE, TokenStatusListDocument,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_denied, api_internal, api_not_found, auth_actor, random_token_hex,
    require_console_scope,
};
use super::types::{
    DeviceCodeRecord, DeviceFlowStatus, DeviceUserBinding, FedError, FederationState,
};

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizeConfirmRequest {
    pub user_code: String,
    pub os_username: String,
    pub idp_subject: String,
    #[serde(default)]
    pub approve: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizeConfirmResponse {
    pub status: DeviceFlowStatus,
    pub org_pseudonym: String,
}

#[derive(Debug, Deserialize)]
pub struct ProtectedResourceQuery {
    pub resource: Option<String>,
}

pub async fn get_oidc_discovery(
    State(st): State<FederationState>,
) -> Result<Json<OidcDiscoveryMetadata>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    Ok(Json(discovery_metadata(&rt.issuer_url)))
}

pub async fn get_jwks(State(st): State<FederationState>) -> Result<Json<JwkSetDocument>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    Ok(Json(rt.key_ring.jwk_set()))
}

pub async fn get_protected_resource(
    State(st): State<FederationState>,
    Query(q): Query<ProtectedResourceQuery>,
) -> Result<Json<ProtectedResourceMetadata>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    let default_res = format!("{}/mcp", rt.issuer_url.trim_end_matches('/'));
    let resource = q.resource.unwrap_or(default_res);
    grdr_identity::http_security::validate_protected_resource_uri(&resource)
        .map_err(|e| api_bad_request(&e.to_string()))?;
    Ok(Json(protected_resource_metadata(&rt.issuer_url, &resource)))
}

pub async fn get_cimd_document(
    State(st): State<FederationState>,
) -> Result<Json<CimdClientMetadata>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    let base = rt.issuer_url.trim_end_matches('/');
    Ok(Json(CimdClientMetadata {
        client_id: format!("{base}/clients/mcp-broker"),
        client_name: "Guardrails MCP Broker".to_string(),
        grant_types: vec![
            TOKEN_EXCHANGE_GRANT.to_string(),
            ID_JAG_GRANT_TYPE.to_string(),
        ],
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        scope: "broker:lease mcp:invoke identity:read".to_string(),
        jwks_uri: Some(format!("{base}/.well-known/jwks.json")),
        spiffe_trust_domain: Some("org-default".to_string()),
    }))
}

pub async fn get_status_list(
    State(st): State<FederationState>,
) -> Result<Json<TokenStatusListDocument>, FedError> {
    st.ensure_healthy()?;
    let rt = st.runtime.read().await;
    let sub = format!("{}/oauth2/status-list", rt.issuer_url.trim_end_matches('/'));
    let status = rt
        .tenant("org-default")
        .map_or_else(super::types::default_status_list, |t| t.status_list.clone());
    Ok(Json(status.to_document(
        &rt.issuer_url,
        &sub,
        Timestamp::now(),
    )))
}

pub async fn post_device_authorization(
    State(st): State<FederationState>,
    Json(req): Json<DeviceAuthorizationRequest>,
) -> Result<Json<DeviceAuthorizationResponse>, FedError> {
    st.ensure_healthy()?;
    if req.client_id.trim().is_empty() {
        return Err(api_bad_request("client_id is required"));
    }
    let now_sec = Timestamp::now().as_second();
    let device_code = random_token_hex("dvc_", 24)?;
    let user_code = random_user_code()?;

    let mut rt = st.runtime.write().await;
    let requested_scope = req
        .scope
        .unwrap_or_else(|| "broker:lease identity:read".to_string());
    let scopes: Vec<&str> = requested_scope.split_whitespace().collect();
    if scopes.is_empty()
        || !scopes
            .iter()
            .all(|s| rt.defaults.allowed_oidc_scopes.iter().any(|ok| ok == s))
    {
        return Err(api_bad_request(
            "requested device_authorization scope contains disallowed scope",
        ));
    }

    rt.device_codes.retain(|_, rec| rec.expires_at > now_sec);
    let active_codes: std::collections::BTreeSet<String> =
        rt.device_codes.keys().cloned().collect();
    rt.user_code_index.retain(|_, dc| active_codes.contains(dc));
    if rt.device_codes.len() >= rt.limits.max_device_codes {
        return Err(api_denied(
            "device authorization capacity reached; retry later",
        ));
    }

    let expires_in = rt.limits.device_expires_secs;
    let interval = rt.limits.device_poll_interval_secs;
    let issuer = rt.issuer_url.trim_end_matches('/').to_owned();
    rt.user_code_index
        .insert(user_code.clone(), device_code.clone());
    rt.device_codes.insert(
        device_code.clone(),
        DeviceCodeRecord {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: req.client_id.trim().to_owned(),
            scope: scopes.join(" "),
            expires_at: now_sec.saturating_add(expires_in),
            status: DeviceFlowStatus::AuthorizationPending,
            tenant_id: None,
            device_pseudonym: None,
            pseudonym_sub: None,
        },
    );
    let verification_uri = format!("{issuer}/login");
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    Ok(Json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
        interval,
    }))
}

pub async fn post_device_authorize(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<DeviceAuthorizeConfirmRequest>,
) -> Result<Json<DeviceAuthorizeConfirmResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if req.os_username.trim().is_empty() || req.idp_subject.trim().is_empty() {
        return Err(api_bad_request("os_username and idp_subject are required"));
    }
    let now = Timestamp::now();
    let mut rt = st.runtime.write().await;
    let device_code = rt
        .user_code_index
        .get(&req.user_code.trim().to_ascii_uppercase())
        .cloned()
        .ok_or_else(|| api_not_found("unknown device user_code"))?;
    let org_key = *rt.org_hmac_key;
    let dev_key = *rt.device_hmac_key;
    let dev_pseud = derive_device_pseudonym(&dev_key, req.idp_subject.trim());
    let org_pseud = re_pseudonymize_for_org(&org_key, 1, &dev_pseud);

    {
        let Some(record) = rt.device_codes.get_mut(&device_code) else {
            return Err(api_not_found("device_code record missing"));
        };
        if record.expires_at <= now.as_second() {
            record.status = DeviceFlowStatus::Expired;
            return Err(api_denied("device_code has expired"));
        }
        if req.approve == Some(false) {
            record.status = DeviceFlowStatus::Denied;
            return Err(api_denied("device authorization denied by user"));
        }
        record.status = DeviceFlowStatus::Authorized;
        record.tenant_id = Some(ctx.tenant_id.clone());
        record.device_pseudonym = Some(dev_pseud.clone());
        record.pseudonym_sub = Some(org_pseud.clone());
    }

    {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        tenant.user_bindings.insert(
            dev_pseud.clone(),
            DeviceUserBinding {
                device_pseudonym: dev_pseud,
                org_pseudonym: org_pseud.clone(),
                bound_at: now,
            },
        );
    }
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "identity.device_login.bound",
        auth_actor(auth.as_deref()),
        format!("Bound device login to pseudonymous IdP subject `{org_pseud}`"),
        org_pseud.clone(),
    )
    .await?;

    Ok(Json(DeviceAuthorizeConfirmResponse {
        status: DeviceFlowStatus::Authorized,
        org_pseudonym: org_pseud,
    }))
}

fn random_user_code() -> Result<String, FedError> {
    let mut raw = [0u8; 8];
    let mut chars = Vec::with_capacity(8);
    let alphabet_len = USER_CODE_ALPHABET.len().max(1);
    let max_unbiased = 256_usize
        .checked_rem(alphabet_len)
        .map_or(256, |rem| 256_usize.saturating_sub(rem));
    while chars.len() < 8 {
        fill_random(&mut raw).map_err(|e| api_internal(&format!("entropy failed: {e}")))?;
        for b in raw {
            let val = usize::from(b);
            if val < max_unbiased
                && let Some(idx) = val.checked_rem(alphabet_len)
                && let Some(&ch) = USER_CODE_ALPHABET.get(idx)
            {
                chars.push(char::from(ch));
                if chars.len() == 8 {
                    break;
                }
            }
        }
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(4).take(4).collect();
    Ok(format!("{head}-{tail}"))
}
