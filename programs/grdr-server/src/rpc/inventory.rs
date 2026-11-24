// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::proto_conv::{
    agent_to_proto, artifact_to_proto, connect_config_to_proto, deployment_key_to_proto,
    device_to_proto, grant_to_proto, integration_to_proto, key_to_proto, kill_switch_to_proto,
    mcp_to_proto, mdm_render_to_proto, pack_to_proto, proto_to_agent, proto_to_artifact,
    proto_to_install_profile, proto_to_key, proto_to_mcp, proto_to_mdm_format,
};
use grdr_model::{
    CreateDeploymentKeyRequest as ModelCreateKeyReq, DeviceCheckinRequest as ModelCheckinReq,
    MdmRenderRequest as ModelMdmReq,
};
use grdr_proto::api::inventory::{
    AgentInventoryItem, CheckIntegrationReadinessRequest, CheckIntegrationReadinessResponse,
    CreateDeploymentKeyRequest, CreateDeploymentKeyResponse, DeviceCheckinRequest,
    DeviceCheckinResponse, GetConnectConfigRequest, ListAgentsRequest, ListAgentsResponse,
    ListArtifactsRequest, ListArtifactsResponse, ListDevicesRequest, ListDevicesResponse,
    ListIntegrationsRequest, ListIntegrationsResponse, ListMcpServersRequest,
    ListMcpServersResponse, McpInventoryItem, RenderMdmConfigRequest, RevokeDeploymentKeyRequest,
    RevokeDeploymentKeyResponse,
};
use grdr_proto::common::CollectionKind;

use crate::aip::collections::{
    AGENT_DEFAULT_ORDER, AGENT_FILTERS, AGENT_SORT, ARTIFACT_DEFAULT_ORDER, ARTIFACT_FILTERS,
    ARTIFACT_SORT, AgentInventoryRow, DEVICE_DEFAULT_ORDER, DEVICE_FILTERS, DEVICE_SORT,
    MCP_DEFAULT_ORDER, MCP_FILTERS, MCP_SORT, McpInventoryRow,
};
use crate::connect_error::{ApiError, CODE_API_BAD_REQUEST};
use crate::rpc::{CollectionPageSpec, PageParams, page_collection, revision_for, run_rpc};
use crate::store::AppState;

pub async fn list_devices(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices",
        state,
        request,
        |state, req: ListDevicesRequest| async move {
            let devices = state.inner.read().await.devices.clone();
            let (paged, rev) = page_collection(
                &state,
                devices,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Devices,
                    method: "ListDevices",
                    allowed_filters: DEVICE_FILTERS,
                    allowed_sort: DEVICE_SORT,
                    default_order: DEVICE_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListDevicesResponse {
                    devices: paged.items.iter().map(device_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn device_checkin(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin",
        state,
        request,
        |state, req: DeviceCheckinRequest| async move {
            let mut agents = Vec::with_capacity(req.agents.len());
            for a in req.agents {
                agents.push(proto_to_agent(a).map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_AGENT",
                        msg,
                        "Provide valid RFC 3339 detected_at timestamps.",
                    )
                })?);
            }
            let mut artifacts = Vec::with_capacity(req.artifacts.len());
            for art in req.artifacts {
                artifacts.push(proto_to_artifact(art).map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_ARTIFACT",
                        msg,
                        "Provide valid RFC 3339 detected_at timestamps.",
                    )
                })?);
            }
            let model_req = ModelCheckinReq {
                device_id: req.device_id,
                hostname: req.hostname,
                os: req.os,
                arch: req.arch,
                install_profile: proto_to_install_profile(req.install_profile),
                daemon_version: req.daemon_version,
                hook_effective: req.hook_effective,
                agents,
                mcp_servers: req.mcp_servers.into_iter().map(proto_to_mcp).collect(),
                artifacts,
                user_id: req.user_id,
                user_display: req.user_display,
                device_public_key: req.device_public_key.map(proto_to_key),
            };
            let res = state.checkin_device(model_req).await?;
            state.bump_revision(CollectionKind::Devices);
            state.bump_revision(CollectionKind::Agents);
            state.bump_revision(CollectionKind::McpServers);
            state.bump_revision(CollectionKind::Artifacts);
            state.bump_revision(CollectionKind::Users);
            state.bump_revision(CollectionKind::Keys);
            Ok((
                DeviceCheckinResponse {
                    device: Some(device_to_proto(&res.device)),
                    packs: res.packs.iter().map(pack_to_proto).collect(),
                    grants: res.grants.iter().map(grant_to_proto).collect(),
                    kill_switch: Some(kill_switch_to_proto(&res.kill_switch)),
                    server_time: res.server_time.to_string(),
                    trusted_keys: res.trusted_keys.iter().map(key_to_proto).collect(),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_agents(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/ListAgents",
        state,
        request,
        |state, req: ListAgentsRequest| async move {
            let guard = state.inner.read().await;
            let mut rows = Vec::new();
            for dev in &guard.devices {
                for agent in &dev.agents {
                    rows.push(AgentInventoryRow {
                        composite_id: format!("{}:{}", dev.id, agent.id),
                        device_id: dev.id.clone(),
                        device_name: dev.hostname.clone(),
                        agent: agent.clone(),
                    });
                }
            }
            drop(guard);
            let (paged, rev) = page_collection(
                &state,
                rows,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Agents,
                    method: "ListAgents",
                    allowed_filters: AGENT_FILTERS,
                    allowed_sort: AGENT_SORT,
                    default_order: AGENT_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListAgentsResponse {
                    items: paged
                        .items
                        .into_iter()
                        .map(|r| AgentInventoryItem {
                            device_id: r.device_id,
                            device_name: r.device_name,
                            agent: Some(agent_to_proto(&r.agent)),
                        })
                        .collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn list_mcp_servers(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/ListMcpServers",
        state,
        request,
        |state, req: ListMcpServersRequest| async move {
            let guard = state.inner.read().await;
            let mut rows = Vec::new();
            for dev in &guard.devices {
                for server in &dev.mcp_servers {
                    rows.push(McpInventoryRow {
                        composite_id: format!("{}:{}:{}", dev.id, server.source_agent, server.name),
                        device_id: dev.id.clone(),
                        device_name: dev.hostname.clone(),
                        server: server.clone(),
                    });
                }
            }
            drop(guard);
            let (paged, rev) = page_collection(
                &state,
                rows,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::McpServers,
                    method: "ListMcpServers",
                    allowed_filters: MCP_FILTERS,
                    allowed_sort: MCP_SORT,
                    default_order: MCP_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListMcpServersResponse {
                    items: paged
                        .items
                        .into_iter()
                        .map(|r| McpInventoryItem {
                            device_id: r.device_id,
                            device_name: r.device_name,
                            server: Some(mcp_to_proto(&r.server)),
                        })
                        .collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn list_artifacts(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/ListArtifacts",
        state,
        request,
        |state, req: ListArtifactsRequest| async move {
            let artifacts = state.artifacts().await;
            let (paged, rev) = page_collection(
                &state,
                artifacts,
                PageParams {
                    page_size: req.page_size,
                    page_token: &req.page_token,
                    filter: &req.filter,
                    order_by: &req.order_by,
                },
                CollectionPageSpec {
                    collection: CollectionKind::Artifacts,
                    method: "ListArtifacts",
                    allowed_filters: ARTIFACT_FILTERS,
                    allowed_sort: ARTIFACT_SORT,
                    default_order: ARTIFACT_DEFAULT_ORDER,
                },
            )?;
            Ok((
                ListArtifactsResponse {
                    artifacts: paged.items.iter().map(artifact_to_proto).collect(),
                    page_info: Some(paged.page_info),
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn get_connect_config(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/GetConnectConfig",
        state,
        request,
        |state, _req: GetConnectConfigRequest| async move {
            let rev = revision_for(&state, CollectionKind::ConnectConfig, "connect_config");
            let cfg = state.connect_config().await;
            Ok((connect_config_to_proto(&cfg, Some(rev.clone())), Some(rev)))
        },
    )
    .await
}

pub async fn create_deployment_key(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/CreateDeploymentKey",
        state,
        request,
        |state, req: CreateDeploymentKeyRequest| async move {
            let out = state
                .create_deployment_key(ModelCreateKeyReq {
                    label: req.label,
                    wave: req.wave,
                    install_profile: req.install_profile,
                    max_uses: req.max_uses,
                    ttl_days: req.ttl_days,
                })
                .await?;
            state.bump_revision(CollectionKind::ConnectConfig);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                CreateDeploymentKeyResponse {
                    key: Some(deployment_key_to_proto(&out.key)),
                    plaintext_token: out.plaintext_token,
                },
                None,
            ))
        },
    )
    .await
}

pub async fn revoke_deployment_key(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/RevokeDeploymentKey",
        state,
        request,
        |state, req: RevokeDeploymentKeyRequest| async move {
            let key = state.revoke_deployment_key(&req.id).await?;
            state.bump_revision(CollectionKind::ConnectConfig);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                RevokeDeploymentKeyResponse {
                    key: Some(deployment_key_to_proto(&key)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn render_mdm_config(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/RenderMdmConfig",
        state,
        request,
        |state, req: RenderMdmConfigRequest| async move {
            let format = proto_to_mdm_format(req.format).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_MDM_FORMAT",
                    "Missing or unsupported MDM format.",
                    "Supply a valid MdmFormat enum value.",
                )
            })?;
            let rendered = state
                .render_mdm_config(ModelMdmReq {
                    format,
                    deployment_key_id: req.deployment_key_id,
                    include_browser_extension: req.include_browser_extension,
                    update_authority: req.update_authority,
                })
                .await?;
            Ok((mdm_render_to_proto(&rendered), None))
        },
    )
    .await
}

pub async fn list_integrations(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/ListIntegrations",
        state,
        request,
        |state, _req: ListIntegrationsRequest| async move {
            let rev = revision_for(&state, CollectionKind::Integrations, "integrations");
            let integrations = state
                .list_integrations()
                .await
                .iter()
                .map(integration_to_proto)
                .collect();
            Ok((
                ListIntegrationsResponse {
                    integrations,
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn check_integration_readiness(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.inventory.v1alpha1.InventoryService/CheckIntegrationReadiness",
        state,
        request,
        |state, req: CheckIntegrationReadinessRequest| async move {
            let entry = state.check_integration_readiness(&req.id).await?;
            state.bump_revision(CollectionKind::Integrations);
            state.bump_revision(CollectionKind::ConnectConfig);
            Ok((
                CheckIntegrationReadinessResponse {
                    integration: Some(integration_to_proto(&entry)),
                },
                None,
            ))
        },
    )
    .await
}
