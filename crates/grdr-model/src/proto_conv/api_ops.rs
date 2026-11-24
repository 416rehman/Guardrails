// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_proto::api as api_pb;
use grdr_proto::common as pb;

use super::enums::{
    action_class_to_proto, browser_dlp_to_proto, deployment_key_status_to_proto,
    identity_mode_to_proto, integration_category_to_proto, integration_health_to_proto,
    mdm_format_to_proto, mode_to_proto, schema_data_class_to_proto, server_health_to_proto,
    verdict_to_proto,
};
use super::resources::{
    artifact_to_proto, attempt_to_proto, device_to_proto, receipt_to_proto, session_to_proto,
};
use super::resources_ops::{finding_to_proto, kill_switch_to_proto, user_to_proto};
use crate::{
    BrowserAppPolicy, ConnectConfigResponse, DeploymentKey, HealthResponse, IntegrationEntry,
    LiveEvent, MdmRenderResponse, OverviewResponse, QueryCellValue, QuerySampleResponse,
    ReplaySummary, StorageMode, UserDetailResponse, UserIntentDescriptor,
};

pub fn health_to_proto(h: &HealthResponse) -> api_pb::overview::GetHealthResponse {
    let storage_mode = match &h.storage_mode {
        StorageMode::Memory => api_pb::overview::StorageMode {
            kind: pb::StorageKind::Memory as i32,
            path: None,
        },
        StorageMode::Sqlite { path } => api_pb::overview::StorageMode {
            kind: pb::StorageKind::Sqlite as i32,
            path: Some(path.clone()),
        },
    };
    api_pb::overview::GetHealthResponse {
        status: server_health_to_proto(h.status),
        version: h.version.clone(),
        storage_mode: Some(storage_mode),
        timestamp: h.timestamp.to_string(),
    }
}

pub fn overview_to_proto(
    o: &OverviewResponse,
    revision: Option<pb::RevisionMeta>,
) -> api_pb::overview::GetOverviewResponse {
    api_pb::overview::GetOverviewResponse {
        server_status: server_health_to_proto(o.server_status),
        total_devices: u64::try_from(o.total_devices).unwrap_or(u64::MAX),
        online_devices: u64::try_from(o.online_devices).unwrap_or(u64::MAX),
        total_agents: u64::try_from(o.total_agents).unwrap_or(u64::MAX),
        total_mcp_servers: u64::try_from(o.total_mcp_servers).unwrap_or(u64::MAX),
        active_sessions: u64::try_from(o.active_sessions).unwrap_or(u64::MAX),
        pending_approvals: u64::try_from(o.pending_approvals).unwrap_or(u64::MAX),
        open_findings: u64::try_from(o.open_findings).unwrap_or(u64::MAX),
        open_incidents: u64::try_from(o.open_incidents).unwrap_or(u64::MAX),
        kill_switch: Some(kill_switch_to_proto(&o.kill_switch)),
        tiles: o
            .tiles
            .iter()
            .map(|t| api_pb::overview::InsightTile {
                id: t.id.clone(),
                headline: t.headline.clone(),
                metric: t.metric.clone(),
                comparison: t.comparison.clone(),
                action_label: t.action_label.clone(),
                route: t.route.clone(),
                tone: t.tone.clone(),
            })
            .collect(),
        setup_steps: o
            .setup_steps
            .iter()
            .map(|s| api_pb::overview::SetupStep {
                id: s.id.clone(),
                label: s.label.clone(),
                done: s.done,
                detail: s.detail.clone(),
            })
            .collect(),
        revision,
    }
}

pub fn live_event_to_proto(ev: &LiveEvent) -> api_pb::overview::LiveEvent {
    api_pb::overview::LiveEvent {
        id: ev.id.clone(),
        topic: ev.topic.clone(),
        summary: ev.summary.clone(),
        verdict: ev.verdict.map(verdict_to_proto),
        timestamp: ev.timestamp.to_string(),
    }
}

pub fn replay_to_proto(r: &ReplaySummary) -> api_pb::policy::ReplaySummary {
    api_pb::policy::ReplaySummary {
        rule_id: r.rule_id.clone(),
        candidate_mode: mode_to_proto(r.candidate_mode),
        window_label: r.window_label.clone(),
        total_scanned: r.total_scanned,
        matched: r.matched,
        would_ask: r.would_ask,
        would_block: r.would_block,
        not_matched: r.not_matched,
        samples: r
            .samples
            .iter()
            .map(|s| api_pb::policy::ReplaySample {
                attempt_id: s.attempt_id.clone(),
                session_id: s.session_id.clone(),
                agent_name: s.agent_name.clone(),
                action_class: action_class_to_proto(s.action_class),
                target: s.target.clone(),
                current_verdict: verdict_to_proto(s.current_verdict),
                candidate_verdict: verdict_to_proto(s.candidate_verdict),
                timestamp: s.timestamp.to_string(),
            })
            .collect(),
    }
}

pub fn browser_policy_to_proto(b: &BrowserAppPolicy) -> api_pb::policy::BrowserAppPolicy {
    api_pb::policy::BrowserAppPolicy {
        id: b.id.clone(),
        name: b.name.clone(),
        domains: b.domains.clone(),
        mode: mode_to_proto(b.mode),
        block_file_uploads: b.block_file_uploads,
        block_secret_paste: b.block_secret_paste,
        managed_extension_only: b.managed_extension_only,
        events_24h: b.events_24h,
        blocked_24h: b.blocked_24h,
    }
}

pub fn deployment_key_to_proto(k: &DeploymentKey) -> api_pb::inventory::DeploymentKey {
    api_pb::inventory::DeploymentKey {
        id: k.id.clone(),
        label: k.label.clone(),
        token_preview: k.token_preview.clone(),
        install_profile: k.install_profile.clone(),
        wave: k.wave.clone(),
        max_uses: k.max_uses,
        used_count: k.used_count,
        status: deployment_key_status_to_proto(k.status),
        created_at: k.created_at.clone(),
        expires_at: k.expires_at.clone(),
        created_by: k.created_by.clone(),
    }
}

pub fn integration_to_proto(i: &IntegrationEntry) -> api_pb::inventory::IntegrationEntry {
    api_pb::inventory::IntegrationEntry {
        id: i.id.clone(),
        name: i.name.clone(),
        provider: i.provider.clone(),
        category: integration_category_to_proto(i.category),
        state: integration_health_to_proto(i.state),
        synced_users: i.synced_users,
        last_sync_at: i.last_sync_at.clone(),
        credential_expires_in_days: i.credential_expires_in_days,
        detail: i.detail.clone(),
        readiness_checks: i
            .readiness_checks
            .iter()
            .map(|c| api_pb::inventory::ReadinessCheck {
                name: c.name.clone(),
                passed: c.passed,
                detail: c.detail.clone(),
            })
            .collect(),
    }
}

pub fn connect_config_to_proto(
    c: &ConnectConfigResponse,
    revision: Option<pb::RevisionMeta>,
) -> api_pb::inventory::GetConnectConfigResponse {
    api_pb::inventory::GetConnectConfigResponse {
        server_origin: c.server_origin.clone(),
        installers: c
            .installers
            .iter()
            .map(|i| api_pb::inventory::InstallerSpec {
                platform: i.platform.clone(),
                label: i.label.clone(),
                version: i.version.clone(),
                command: i.command.clone(),
                sha256: i.sha256.clone(),
                doctor_command: i.doctor_command.clone(),
                notes: i.notes.clone(),
            })
            .collect(),
        deployment_keys: c
            .deployment_keys
            .iter()
            .map(deployment_key_to_proto)
            .collect(),
        otlp: Some(api_pb::inventory::OtlpFanoutConfig {
            enabled: c.otlp.enabled,
            grpc_port: u32::from(c.otlp.grpc_port),
            http_port: u32::from(c.otlp.http_port),
            bind_address: c.otlp.bind_address.clone(),
            downstream_targets: c.otlp.downstream_targets.clone(),
            loopback_only: c.otlp.loopback_only,
            accepted_spans_24h: c.otlp.accepted_spans_24h,
        }),
        integrations: c.integrations.iter().map(integration_to_proto).collect(),
        revision,
    }
}

pub fn mdm_render_to_proto(r: &MdmRenderResponse) -> api_pb::inventory::RenderMdmConfigResponse {
    api_pb::inventory::RenderMdmConfigResponse {
        format: mdm_format_to_proto(r.format),
        filename: r.filename.clone(),
        content_type: r.content_type.clone(),
        payload: r.payload.clone(),
        deployment_notes: r.deployment_notes.clone(),
    }
}

pub fn user_detail_to_proto(
    d: &UserDetailResponse,
    revision: Option<pb::RevisionMeta>,
) -> api_pb::tenancy::GetUserResponse {
    api_pb::tenancy::GetUserResponse {
        user: Some(user_to_proto(&d.user)),
        devices: d.devices.iter().map(device_to_proto).collect(),
        sessions: d.sessions.iter().map(session_to_proto).collect(),
        recent_attempts: d.recent_attempts.iter().map(attempt_to_proto).collect(),
        receipts: d.receipts.iter().map(receipt_to_proto).collect(),
        findings: d.findings.iter().map(finding_to_proto).collect(),
        artifacts: d.artifacts.iter().map(artifact_to_proto).collect(),
        identity_mode: identity_mode_to_proto(d.identity_mode),
        revision,
    }
}

pub fn query_sample_to_proto(r: &QuerySampleResponse) -> api_pb::activity::SampleQueryResponse {
    let rows = r
        .rows
        .iter()
        .map(|row| {
            let mut columns = BTreeMap::new();
            for (k, v) in row {
                let kind = match v {
                    QueryCellValue::Text(s) => api_pb::activity::QueryCellKind::Text(s.clone()),
                    QueryCellValue::Number(n) => api_pb::activity::QueryCellKind::Number(*n),
                    QueryCellValue::Bool(b) => api_pb::activity::QueryCellKind::Boolean(*b),
                    QueryCellValue::List(l) => {
                        api_pb::activity::QueryCellKind::List(api_pb::activity::StringList {
                            values: l.clone(),
                        })
                    }
                };
                columns.insert(
                    k.clone(),
                    api_pb::activity::QueryCellValue { kind: Some(kind) },
                );
            }
            api_pb::activity::QueryRow { columns }
        })
        .collect();
    api_pb::activity::SampleQueryResponse {
        plan: Some(api_pb::activity::QueryPlanResult {
            entity: r.plan.entity.clone(),
            selected_columns: r.plan.selected_columns.clone(),
            hidden_columns_stripped: u64::try_from(r.plan.hidden_columns_stripped)
                .unwrap_or(u64::MAX),
            effective_limit: r.plan.effective_limit,
        }),
        rows,
        untrusted_warning: r.untrusted_warning.clone(),
    }
}

pub fn user_intent_to_proto(d: &UserIntentDescriptor) -> api_pb::activity::UserIntentDescriptor {
    api_pb::activity::UserIntentDescriptor {
        identity_mode: identity_mode_to_proto(d.identity_mode),
        correlation_guidance: d.correlation_guidance.clone(),
        safe_join_keys: d.safe_join_keys.clone(),
        schema_hidden_fields: d.schema_hidden_fields.clone(),
    }
}

pub fn schema_list_to_proto(
    schemas: &[crate::EntitySchema],
) -> Vec<api_pb::activity::EntitySchema> {
    schemas
        .iter()
        .map(|s| api_pb::activity::EntitySchema {
            name: s.name.clone(),
            description: s.description.clone(),
            columns: s
                .columns
                .iter()
                .map(|c| api_pb::activity::ColumnDef {
                    name: c.name.clone(),
                    data_class: schema_data_class_to_proto(c.data_class),
                    description: c.description.clone(),
                    sensitive: c.sensitive,
                })
                .collect(),
        })
        .collect()
}

pub fn browser_eval_to_proto(
    r: &crate::BrowserEvaluateResponse,
) -> api_pb::verdict::EvaluateBrowserResponse {
    api_pb::verdict::EvaluateBrowserResponse {
        app_id: r.app_id.clone(),
        app_name: r.app_name.clone(),
        verdict: verdict_to_proto(r.verdict),
        rule_id: r.rule_id.clone(),
        reason: r.reason.clone(),
        dlp_class: browser_dlp_to_proto(r.dlp_class),
    }
}
