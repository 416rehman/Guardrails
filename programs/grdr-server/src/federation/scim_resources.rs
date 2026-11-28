// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, Query, State};
use grdr_identity::attest::{AgentInstanceRecord, SponsorState};
use grdr_identity::pseudonym::{derive_device_pseudonym, re_pseudonymize_for_org};
use grdr_identity::spiffe::AgentLifecycle;
use grdr_identity::standards_adapters::{
    SCIM_AGENT_SCHEMA, SCIM_CORE_USER_SCHEMA, ScimAgentExtension, ScimAgentResource,
};
use grdr_model::{IdentityMode, InstallProfile};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{api_bad_request, require_console_scope};
use super::types::{
    FedError, FederationState, ScimGroupRecord, ScimUserRecord, ServerEnrolmentState,
    TenantFederationState,
};

const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    pub cursor: Option<String>,
    pub count: Option<usize>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ScimGroupCreateInput {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(rename = "previousCursor", skip_serializing_if = "Option::is_none")]
    pub previous_cursor: Option<String>,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

#[derive(Debug, Serialize)]
pub struct ScimUserWire {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub email: String,
    pub active: bool,
}

pub async fn list_scim_groups(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<serde_json::Value>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let rt = st.runtime.read().await;
    let groups: Vec<serde_json::Value> = rt
        .tenant(&ctx.tenant_id)
        .map(|t| {
            t.scim_groups
                .values()
                .map(|g| {
                    serde_json::json!({
                        "schemas": [SCIM_GROUP_SCHEMA],
                        "id": g.id,
                        "displayName": g.display_name,
                        "members": g.members,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(paginate_cursor(groups, &q)?))
}

pub async fn create_scim_group(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<ScimGroupCreateInput>,
) -> Result<Json<ScimGroupRecord>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if req.display_name.trim().is_empty() {
        return Err(api_bad_request("SCIM group displayName required"));
    }
    let id = format!("grp_{}", Uuid::now_v7().simple());
    let rec = ScimGroupRecord {
        id: id.clone(),
        display_name: req.display_name.trim().to_owned(),
        members: req.members,
    };
    let mut rt = st.runtime.write().await;
    rt.tenant_mut(&ctx.tenant_id)
        .scim_groups
        .insert(id, rec.clone());
    st.persist_runtime(&rt)?;
    Ok(Json(rec))
}

pub async fn list_scim_agents(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Query(q): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimAgentResource>>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:read")?;
    let rt = st.runtime.read().await;
    let all: Vec<ScimAgentResource> = rt
        .tenant(&ctx.tenant_id)
        .map(|tenant| {
            tenant
                .instances
                .values()
                .map(|inst| ScimAgentResource {
                    schemas: vec![
                        SCIM_CORE_USER_SCHEMA.to_string(),
                        SCIM_AGENT_SCHEMA.to_string(),
                    ],
                    id: inst.agi_id.clone(),
                    external_id: inst.aid_id.clone(),
                    user_name: inst.spiffe_id.as_str().to_owned(),
                    active: inst.lifecycle == AgentLifecycle::Active,
                    agent: ScimAgentExtension {
                        agi_id: inst.agi_id.clone(),
                        aid_id: inst.aid_id.clone(),
                        spiffe_id: inst.spiffe_id.as_str().to_owned(),
                        sponsor_id: inst
                            .sponsor
                            .as_ref()
                            .map_or_else(|| "unassigned".to_string(), |s| s.sponsor_id.clone()),
                        sponsor_active: inst
                            .sponsor
                            .as_ref()
                            .is_some_and(|s| s.state == SponsorState::Active),
                        lifecycle: inst.lifecycle,
                        assurance_level: compute_assurance_level(inst, tenant).to_string(),
                        trust_domain: inst.spiffe_id.trust_domain().to_owned(),
                    },
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(paginate_cursor(all, &q)?))
}

pub(crate) fn compute_assurance_level(
    inst: &AgentInstanceRecord,
    tenant: &TenantFederationState,
) -> &'static str {
    let sponsor_active = inst
        .sponsor
        .as_ref()
        .is_some_and(|s| s.state == SponsorState::Active);
    match inst.lifecycle {
        AgentLifecycle::Orphaned | AgentLifecycle::Retired => "AL0",
        AgentLifecycle::Discovered | AgentLifecycle::Suspended => "AL1",
        AgentLifecycle::Active if !sponsor_active => "AL1",
        AgentLifecycle::Active => {
            let has_admitted_protected = tenant.enrolled_devices.values().any(|d| {
                d.state == ServerEnrolmentState::Admitted && d.profile == InstallProfile::Protected
            });
            if has_admitted_protected { "AL3" } else { "AL2" }
        }
    }
}

pub(crate) fn to_scim_user_wire(
    rec: &ScimUserRecord,
    mode: IdentityMode,
    org_hmac_key: &[u8; 32],
    dev_hmac_key: &[u8; 32],
) -> ScimUserWire {
    if mode == IdentityMode::Pseudonymous {
        let dev = derive_device_pseudonym(dev_hmac_key, &rec.user_name);
        let org_p = re_pseudonymize_for_org(org_hmac_key, 1, &dev);
        return ScimUserWire {
            schemas: vec![SCIM_CORE_USER_SCHEMA.to_string()],
            id: rec.id.clone(),
            external_id: rec.external_id.clone(),
            user_name: org_p.clone(),
            display_name: org_p.clone(),
            email: format!("{org_p}@pseudonymous.invalid"),
            active: rec.active,
        };
    }
    ScimUserWire {
        schemas: vec![SCIM_CORE_USER_SCHEMA.to_string()],
        id: rec.id.clone(),
        external_id: rec.external_id.clone(),
        user_name: rec.user_name.clone(),
        display_name: rec.display_name.clone(),
        email: rec.email.clone(),
        active: rec.active,
    }
}

pub(crate) fn paginate_cursor<T>(
    all: Vec<T>,
    q: &ScimListQuery,
) -> Result<ScimListResponse<T>, FedError> {
    let total = all.len();
    let count = q.count.unwrap_or(50).clamp(1, 200);
    let offset = if let Some(cur) = q.cursor.as_deref() {
        cur.parse::<usize>()
            .map_err(|_| api_bad_request("invalid SCIM cursor"))?
    } else if let Some(start_idx) = q.start_index {
        start_idx.saturating_sub(1)
    } else {
        0
    };
    let end = offset.saturating_add(count).min(total);
    let page: Vec<T> = all.into_iter().skip(offset).take(count).collect();
    let next_cursor = (end < total).then(|| end.to_string());
    let previous_cursor = (offset > 0).then(|| offset.saturating_sub(count).to_string());
    Ok(ScimListResponse {
        schemas: vec![SCIM_LIST_SCHEMA.to_string()],
        total_results: total,
        items_per_page: page.len(),
        start_index: offset.saturating_add(1),
        next_cursor,
        previous_cursor,
        resources: page,
    })
}
