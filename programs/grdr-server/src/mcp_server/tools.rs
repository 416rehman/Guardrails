// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::QueryRequest;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_POLICY_DENIED};
use grdr_model::proto_conv::user_to_proto;
use grdr_proto::common::ErrorClass;
use serde_json::{Value, json};

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::store::AppState;

use super::super::gitops::{CreatePolicyChangeRequest, GitopsStore};
use super::proposals::McpProposalStore;
use super::read_dispatch::{
    coverage_filtered, execute_allowlisted_read_method, search_inventory_filtered,
};
use super::secrecy::{
    ensure_mcp_caller_allowed, is_self_lineage, redact_policy_secrets, sanitize_finding_for_mcp,
    sanitize_incident_for_mcp, sanitize_json_tree_untrusted, sanitize_session_detail_for_mcp,
    sanitize_session_summary_for_mcp, self_lineage_err, validate_mcp_read_method,
};

pub const SCOPE_MCP_READ: &str = "mcp:read";
pub const SCOPE_MCP_PROPOSE: &str = "mcp:propose";
pub const SCOPE_MCP_API_READ: &str = "mcp:api-read";

#[derive(Debug, Clone, Copy)]
pub struct ToolDefinition {
    pub name: &'static str,
    pub required_scope: &'static str,
    pub description: &'static str,
}

pub const MCP_TOOLS: &[ToolDefinition] = &[
    ToolDefinition {
        name: "describe_schema",
        required_scope: SCOPE_MCP_READ,
        description: "Describe queryable telemetry entities and hidden privacy fields",
    },
    ToolDefinition {
        name: "describe_entities",
        required_scope: SCOPE_MCP_READ,
        description: "Summarize entities visible under current privacy settings",
    },
    ToolDefinition {
        name: "user_intent",
        required_scope: SCOPE_MCP_READ,
        description: "Explain identity mode and correlation guidance",
    },
    ToolDefinition {
        name: "sample",
        required_scope: SCOPE_MCP_READ,
        description: "Sample bounded rows from a queryable entity",
    },
    ToolDefinition {
        name: "search_findings",
        required_scope: SCOPE_MCP_READ,
        description: "Search findings without exposing Cedar policy rules",
    },
    ToolDefinition {
        name: "get_finding",
        required_scope: SCOPE_MCP_READ,
        description: "Fetch finding detail with untrusted text envelopes",
    },
    ToolDefinition {
        name: "get_incident",
        required_scope: SCOPE_MCP_READ,
        description: "Fetch correlated incident detail",
    },
    ToolDefinition {
        name: "list_users",
        required_scope: SCOPE_MCP_READ,
        description: "List tenant users subject to org privacy mode",
    },
    ToolDefinition {
        name: "get_user_activity",
        required_scope: SCOPE_MCP_READ,
        description: "Summarize recent user sessions and activity counts",
    },
    ToolDefinition {
        name: "get_user_risk",
        required_scope: SCOPE_MCP_READ,
        description: "Inspect user risk signal summary",
    },
    ToolDefinition {
        name: "list_sessions",
        required_scope: SCOPE_MCP_READ,
        description: "List recent agent sessions",
    },
    ToolDefinition {
        name: "get_session_timeline",
        required_scope: SCOPE_MCP_READ,
        description: "Fetch ordered attempt timeline for a session",
    },
    ToolDefinition {
        name: "get_session_trace",
        required_scope: SCOPE_MCP_READ,
        description: "Fetch decision receipt trace for a session",
    },
    ToolDefinition {
        name: "get_session_tree",
        required_scope: SCOPE_MCP_READ,
        description: "Inspect turns and child-session tree",
    },
    ToolDefinition {
        name: "search_inventory",
        required_scope: SCOPE_MCP_READ,
        description: "Search discovered devices, agents, MCP servers, and artifacts",
    },
    ToolDefinition {
        name: "get_coverage",
        required_scope: SCOPE_MCP_READ,
        description: "Inspect control-plane coverage metrics",
    },
    ToolDefinition {
        name: "run_saved_hunt",
        required_scope: SCOPE_MCP_READ,
        description: "Execute a named read-only hunting query",
    },
    ToolDefinition {
        name: "propose_policy_change",
        required_scope: SCOPE_MCP_PROPOSE,
        description: "Propose a candidate PolicyChange (draft/awaiting human approval only)",
    },
    ToolDefinition {
        name: "propose_suppression",
        required_scope: SCOPE_MCP_PROPOSE,
        description: "Propose a finding suppression for human review",
    },
    ToolDefinition {
        name: "propose_triage_decision",
        required_scope: SCOPE_MCP_PROPOSE,
        description: "Propose a finding triage decision for human review",
    },
    ToolDefinition {
        name: "get_proposal",
        required_scope: SCOPE_MCP_PROPOSE,
        description: "Fetch status of caller-owned MCP proposals or candidate PolicyChanges",
    },
    ToolDefinition {
        name: "call_read_method",
        required_scope: SCOPE_MCP_API_READ,
        description: "Invoke a descriptor-allowlisted read-only non-policy Connect method",
    },
];

pub fn list_tools_json(auth: &AuthContext) -> Vec<Value> {
    MCP_TOOLS
        .iter()
        .filter(|t| has_scope(auth, t.required_scope))
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": { "type": "object" },
                "annotations": { "readOnlyHint": t.required_scope != SCOPE_MCP_PROPOSE }
            })
        })
        .collect()
}

pub fn is_proposal_write_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "propose_policy_change" | "propose_suppression" | "propose_triage_decision"
    )
}

pub async fn execute_tool(
    state: &AppState,
    gitops: &GitopsStore,
    proposals: &McpProposalStore,
    auth: &AuthContext,
    tool_name: &str,
    args: Value,
) -> Result<Value, ApiError> {
    ensure_mcp_caller_allowed(auth)?;
    if is_direct_mutation_name(tool_name) {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "AGENT_SESSION_PROPOSE_ONLY".into(),
            class: ErrorClass::Permission,
            message: "Direct mutation tools are prohibited over /mcp; use propose_* tools.".into(),
            fix: "Call propose_policy_change, propose_suppression, or propose_triage_decision."
                .into(),
            metadata: std::collections::BTreeMap::new(),
        }));
    }

    let def = MCP_TOOLS
        .iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| {
            ApiError::invalid_argument(
                CODE_NOT_FOUND,
                "UNKNOWN_MCP_TOOL",
                format!("MCP tool `{tool_name}` is not registered."),
                "Call tools/list to discover allowed tools.",
            )
        })?;
    if !has_scope(auth, def.required_scope) {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "INSUFFICIENT_SCOPE".into(),
            class: ErrorClass::Permission,
            message: format!(
                "Caller lacks required scope `{}` for tool `{tool_name}`.",
                def.required_scope
            ),
            fix: "Obtain an OAuth token with the required scope.".into(),
            metadata: std::collections::BTreeMap::new(),
        }));
    }

    let mut out = match tool_name {
        "describe_schema" => json!({ "entities": state.query_schema(false).await }),
        "describe_entities" => json!({ "entities": state.query_entities(false).await }),
        "user_intent" => json!({ "descriptor": state.query_user_intent(false).await }),
        "sample" => {
            let entity = str_arg(&args, "entity")?;
            let columns = args
                .get("columns")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok());
            let filter_text = args
                .get("filter_text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let mut res = state
                .query_sample(
                    QueryRequest {
                        entity,
                        columns,
                        limit,
                        filter_text,
                    },
                    false,
                )
                .await?;
            res.rows
                .retain(|row| !sample_row_is_self_lineage(auth, row));
            sanitize_json_tree_untrusted(
                serde_json::to_value(res).unwrap_or_default(),
                "query.sample",
            )
        }
        "search_findings" => {
            let q = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let guard = state.inner.read().await;
            let items: Vec<Value> = guard
                .findings
                .iter()
                .filter(|f| !is_self_lineage(auth, Some(&f.session_id), Some(&f.agent_name)))
                .filter(|f| {
                    q.is_empty()
                        || f.title.to_ascii_lowercase().contains(&q)
                        || f.target.to_ascii_lowercase().contains(&q)
                })
                .take(50)
                .map(sanitize_finding_for_mcp)
                .collect();
            json!({ "findings": items })
        }
        "get_finding" => {
            let id = str_arg(&args, "id")?;
            let guard = state.inner.read().await;
            let found = guard
                .findings
                .iter()
                .find(|f| f.id == id)
                .cloned()
                .ok_or_else(|| {
                    ApiError::invalid_argument(
                        CODE_NOT_FOUND,
                        "FINDING_NOT_FOUND",
                        "Finding not found",
                        "Check finding ID.",
                    )
                })?;
            if is_self_lineage(auth, Some(&found.session_id), Some(&found.agent_name)) {
                return Err(self_lineage_err());
            }
            json!({ "finding": sanitize_finding_for_mcp(&found) })
        }
        "get_incident" => {
            let id = str_arg(&args, "id")?;
            let found = state
                .incidents()
                .await
                .into_iter()
                .find(|i| i.id == id)
                .ok_or_else(|| {
                    ApiError::invalid_argument(
                        CODE_NOT_FOUND,
                        "INCIDENT_NOT_FOUND",
                        "Incident not found",
                        "Check incident ID.",
                    )
                })?;
            if is_self_lineage(auth, Some(&found.session_id), Some(&found.agent_name)) {
                return Err(self_lineage_err());
            }
            json!({ "incident": sanitize_incident_for_mcp(&found) })
        }
        "list_users" => {
            let users: Vec<_> = state.users().await.iter().map(user_to_proto).collect();
            sanitize_json_tree_untrusted(json!({ "users": users }), "directory.user")
        }
        "get_user_activity" | "get_user_risk" => {
            let id = str_arg(&args, "id")?;
            let detail = state.user_detail(&id).await?;
            let visible_sessions = detail
                .sessions
                .iter()
                .filter(|s| !is_self_lineage(auth, Some(&s.id), Some(&s.agent_name)))
                .count();
            let visible_findings = detail
                .findings
                .iter()
                .filter(|f| !is_self_lineage(auth, Some(&f.session_id), Some(&f.agent_name)))
                .count();
            sanitize_json_tree_untrusted(
                json!({
                    "user": user_to_proto(&detail.user),
                    "deviceCount": detail.devices.len(),
                    "sessionCount": visible_sessions,
                    "findingCount": visible_findings,
                }),
                "directory.user",
            )
        }
        "list_sessions" => {
            let sessions: Vec<Value> = state
                .sessions()
                .await
                .into_iter()
                .filter(|s| !is_self_lineage(auth, Some(&s.id), Some(&s.agent_name)))
                .take(50)
                .map(|s| sanitize_session_summary_for_mcp(&s))
                .collect();
            json!({ "sessions": sessions })
        }
        "get_session_timeline" | "get_session_trace" | "get_session_tree" => {
            let id = str_arg(&args, "session_id").or_else(|_| str_arg(&args, "id"))?;
            let detail = state.session_detail(&id).await?;
            if is_self_lineage(
                auth,
                Some(&detail.session.id),
                Some(&detail.session.agent_name),
            ) {
                return Err(self_lineage_err());
            }
            sanitize_session_detail_for_mcp(&detail, auth)
        }
        "search_inventory" => search_inventory_filtered(state, auth).await,
        "get_coverage" => coverage_filtered(state, auth).await,
        "run_saved_hunt" => {
            let hunt = str_arg(&args, "hunt_id")?;
            let guard = state.inner.read().await;
            let findings: Vec<Value> = guard
                .findings
                .iter()
                .filter(|f| !is_self_lineage(auth, Some(&f.session_id), Some(&f.agent_name)))
                .take(20)
                .map(sanitize_finding_for_mcp)
                .collect();
            json!({ "huntId": hunt, "matchedFindings": findings })
        }
        "propose_policy_change" => {
            let req: CreatePolicyChangeRequest = serde_json::from_value(args).map_err(|e| {
                ApiError::invalid_argument(
                    CODE_INVALID_INPUT,
                    "INVALID_PROPOSAL",
                    e.to_string(),
                    "Provide valid operations.",
                )
            })?;
            let rec = proposals
                .propose_policy_change(state, gitops, auth, req)
                .await?;
            json!({ "proposal": rec })
        }
        "propose_suppression" => {
            let finding_id = str_arg(&args, "finding_id")?;
            let scope = args
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("finding")
                .to_owned();
            let rationale = str_arg(&args, "rationale")?;
            json!({
                "proposal": proposals.propose_suppression(state, auth, finding_id, scope, rationale).await?
            })
        }
        "propose_triage_decision" => {
            let finding_id = str_arg(&args, "finding_id")?;
            let lifecycle = str_arg(&args, "lifecycle")?;
            let note = args
                .get("note")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            json!({
                "proposal": proposals.propose_triage_decision(state, auth, finding_id, lifecycle, note).await?
            })
        }
        "get_proposal" => {
            let id = str_arg(&args, "id")?;
            json!({ "proposal": proposals.get_proposal(gitops, auth, &id).await? })
        }
        "call_read_method" => {
            let method_path = str_arg(&args, "method")?;
            let spec = validate_mcp_read_method(&method_path)?;
            execute_allowlisted_read_method(state, auth, spec, &args).await?
        }
        _ => json!({}),
    };

    redact_policy_secrets(&mut out);
    Ok(out)
}

fn sample_row_is_self_lineage(
    auth: &AuthContext,
    row: &std::collections::BTreeMap<String, grdr_model::QueryCellValue>,
) -> bool {
    let text_cell = |key: &str| match row.get(key) {
        Some(grdr_model::QueryCellValue::Text(s)) => Some(s.as_str()),
        _ => None,
    };
    let sess = text_cell("session_id").or_else(|| text_cell("sessionId"));
    let agent = text_cell("agent_name").or_else(|| text_cell("agentName"));
    is_self_lineage(auth, sess, agent)
}

pub fn has_scope(auth: &AuthContext, required: &str) -> bool {
    auth.allows_scope(required) || auth.allows_scope("*")
}

pub(crate) fn str_arg(args: &Value, key: &str) -> Result<String, ApiError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ApiError::invalid_argument(
                CODE_INVALID_INPUT,
                "MISSING_ARGUMENT",
                format!("Missing required string argument `{key}`."),
                "Supply required tool argument.",
            )
        })
}

fn is_direct_mutation_name(name: &str) -> bool {
    matches!(
        name,
        "create_rule"
            | "update_rule"
            | "delete_rule"
            | "update_rule_mode"
            | "approve_policy_change"
            | "set_kill_switch"
            | "decide_approval"
            | "update_finding"
    )
}

pub fn wrap_tool_result_mcp(data: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string(&data).unwrap_or_else(|_| "{}".into()),
            }
        ],
        "structuredContent": data,
    })
}
