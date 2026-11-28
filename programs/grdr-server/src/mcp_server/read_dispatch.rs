// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::error::CODE_POLICY_DENIED;
use grdr_model::proto_conv::{
    agent_to_proto, artifact_to_proto, device_to_proto, integration_to_proto, mcp_to_proto,
    user_to_proto,
};
use grdr_proto::common::{ErrorClass, MethodDescriptor};
use serde_json::{Value, json};

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::store::AppState;

use super::secrecy::{
    filter_device_for_mcp, is_self_lineage, method_forbidden, sanitize_finding_for_mcp,
    sanitize_incident_for_mcp, sanitize_json_tree_untrusted, sanitize_session_detail_for_mcp,
    sanitize_session_summary_for_mcp, self_lineage_err,
};
use super::tools::str_arg;

pub async fn execute_allowlisted_read_method(
    state: &AppState,
    auth: &AuthContext,
    spec: &'static MethodDescriptor,
    args: &Value,
) -> Result<Value, ApiError> {
    if !auth.allows_scope(spec.scope) {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "INSUFFICIENT_SCOPE".into(),
            class: ErrorClass::Permission,
            message: format!(
                "Caller lacks underlying RPC scope `{}` for {}.",
                spec.scope, spec.method
            ),
            fix: "Obtain an OAuth token carrying both `mcp:api-read` and the target RPC scope."
                .into(),
            metadata: std::collections::BTreeMap::new(),
        }));
    }

    match spec.path {
        "/grdr.api.overview.v1alpha1.OverviewService/GetHealth" => {
            Ok(json!({ "status": "SERVER_HEALTH_HEALTHY" }))
        }
        "/grdr.api.overview.v1alpha1.OverviewService/GetOverview" => {
            let ov = state.overview().await;
            let guard = state.inner.read().await;
            let hidden_findings = guard
                .findings
                .iter()
                .filter(|f| is_self_lineage(auth, Some(&f.session_id), Some(&f.agent_name)))
                .count();
            Ok(json!({
                "totalDevices": ov.total_devices,
                "onlineDevices": ov.online_devices,
                "openFindings": ov.open_findings.saturating_sub(hidden_findings),
            }))
        }
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices" => {
            Ok(filtered_devices_json(state, auth).await)
        }
        "/grdr.api.inventory.v1alpha1.InventoryService/ListAgents" => {
            let guard = state.inner.read().await;
            let mut items = Vec::new();
            for dev in &guard.devices {
                for agent in &dev.agents {
                    if is_self_lineage(auth, None, Some(&agent.id))
                        || is_self_lineage(auth, None, Some(&agent.name))
                    {
                        continue;
                    }
                    items.push(json!({
                        "deviceId": dev.id,
                        "deviceName": dev.hostname,
                        "agent": agent_to_proto(agent),
                    }));
                }
            }
            Ok(sanitize_json_tree_untrusted(
                json!({ "agents": items }),
                "inventory.agents",
            ))
        }
        "/grdr.api.inventory.v1alpha1.InventoryService/ListMcpServers" => {
            let guard = state.inner.read().await;
            let mut items = Vec::new();
            for dev in &guard.devices {
                for server in &dev.mcp_servers {
                    if is_self_lineage(auth, None, Some(&server.source_agent)) {
                        continue;
                    }
                    items.push(json!({
                        "deviceId": dev.id,
                        "deviceName": dev.hostname,
                        "server": mcp_to_proto(server),
                    }));
                }
            }
            Ok(sanitize_json_tree_untrusted(
                json!({ "mcpServers": items }),
                "inventory.mcp_servers",
            ))
        }
        "/grdr.api.inventory.v1alpha1.InventoryService/ListArtifacts" => {
            let artifacts: Vec<_> = state
                .artifacts()
                .await
                .iter()
                .filter(|a| !is_self_lineage(auth, None, Some(&a.source_agent)))
                .map(artifact_to_proto)
                .collect();
            Ok(sanitize_json_tree_untrusted(
                json!({ "artifacts": artifacts }),
                "inventory.artifacts",
            ))
        }
        "/grdr.api.inventory.v1alpha1.InventoryService/ListIntegrations" => {
            let integrations: Vec<_> = state
                .list_integrations()
                .await
                .iter()
                .map(integration_to_proto)
                .collect();
            Ok(sanitize_json_tree_untrusted(
                json!({ "integrations": integrations }),
                "inventory.integrations",
            ))
        }
        "/grdr.api.tenancy.v1alpha1.UserService/ListUsers" => {
            let users: Vec<_> = state.users().await.iter().map(user_to_proto).collect();
            Ok(sanitize_json_tree_untrusted(
                json!({ "users": users }),
                "directory.user",
            ))
        }
        "/grdr.api.activity.v1alpha1.SessionService/ListSessions" => {
            let sessions: Vec<_> = state
                .sessions()
                .await
                .into_iter()
                .filter(|s| !is_self_lineage(auth, Some(&s.id), Some(&s.agent_name)))
                .take(50)
                .map(|s| sanitize_session_summary_for_mcp(&s))
                .collect();
            Ok(json!({ "sessions": sessions }))
        }
        "/grdr.api.activity.v1alpha1.SessionService/GetSession" => {
            let id = str_arg(args, "session_id").or_else(|_| str_arg(args, "id"))?;
            let detail = state.session_detail(&id).await?;
            if is_self_lineage(
                auth,
                Some(&detail.session.id),
                Some(&detail.session.agent_name),
            ) {
                return Err(self_lineage_err());
            }
            Ok(sanitize_session_detail_for_mcp(&detail, auth))
        }
        "/grdr.api.response.v1alpha1.ResponseService/ListFindings" => {
            let guard = state.inner.read().await;
            let findings: Vec<_> = guard
                .findings
                .iter()
                .filter(|f| !is_self_lineage(auth, Some(&f.session_id), Some(&f.agent_name)))
                .map(sanitize_finding_for_mcp)
                .collect();
            Ok(json!({ "findings": findings }))
        }
        "/grdr.api.response.v1alpha1.ResponseService/ListIncidents" => {
            let incidents: Vec<_> = state
                .incidents()
                .await
                .into_iter()
                .filter(|i| !is_self_lineage(auth, Some(&i.session_id), Some(&i.agent_name)))
                .map(|i| sanitize_incident_for_mcp(&i))
                .collect();
            Ok(json!({ "incidents": incidents }))
        }
        _ => Err(method_forbidden(
            "Method is not implemented for MCP read dispatch.",
        )),
    }
}

pub async fn filtered_devices_json(state: &AppState, auth: &AuthContext) -> Value {
    let devices: Vec<_> = state
        .inner
        .read()
        .await
        .devices
        .iter()
        .map(|d| device_to_proto(&filter_device_for_mcp(d, auth)))
        .collect();
    sanitize_json_tree_untrusted(json!({ "devices": devices }), "inventory.devices")
}

pub async fn search_inventory_filtered(state: &AppState, auth: &AuthContext) -> Value {
    let devices: Vec<_> = state
        .inner
        .read()
        .await
        .devices
        .iter()
        .map(|d| device_to_proto(&filter_device_for_mcp(d, auth)))
        .collect();
    let artifact_count = state
        .artifacts()
        .await
        .into_iter()
        .filter(|a| !is_self_lineage(auth, None, Some(&a.source_agent)))
        .count();
    sanitize_json_tree_untrusted(
        json!({
            "devices": devices,
            "artifactCount": artifact_count,
        }),
        "inventory.devices",
    )
}

pub async fn coverage_filtered(state: &AppState, auth: &AuthContext) -> Value {
    let ov = state.overview().await;
    let guard = state.inner.read().await;
    let mut hidden_agents = 0usize;
    let mut hidden_mcp = 0usize;
    for dev in &guard.devices {
        hidden_agents = hidden_agents.saturating_add(
            dev.agents
                .iter()
                .filter(|a| {
                    is_self_lineage(auth, None, Some(&a.id))
                        || is_self_lineage(auth, None, Some(&a.name))
                })
                .count(),
        );
        hidden_mcp = hidden_mcp.saturating_add(
            dev.mcp_servers
                .iter()
                .filter(|s| is_self_lineage(auth, None, Some(&s.source_agent)))
                .count(),
        );
    }
    json!({
        "totalDevices": ov.total_devices,
        "onlineDevices": ov.online_devices,
        "totalAgents": ov.total_agents.saturating_sub(hidden_agents),
        "totalMcpServers": ov.total_mcp_servers.saturating_sub(hidden_mcp),
    })
}
