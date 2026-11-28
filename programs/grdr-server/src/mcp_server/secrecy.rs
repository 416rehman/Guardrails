// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::error::CODE_POLICY_DENIED;
use grdr_model::{
    DecisionReceipt, Device, Finding, Incident, SessionDetailResponse, SessionSummary,
};
use grdr_proto::common::{
    ALL_METHODS, ErrorClass, IdempotencyLevel, MethodDescriptor, SURFACES_AND_OPERATOR_METHODS,
    find_method,
};
use grdr_proto::descriptor::load_embedded_descriptor_set;
use grdr_strings::sanitize_untrusted_text;
use serde_json::{Map, Value, json};

use crate::auth::{AuthContext, AuthPlane};
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};

const SECRET_KEYS: &[&str] = &[
    "cedar",
    "matcher",
    "packs",
    "policyPacks",
    "policy_packs",
    "grants",
    "lists",
    "layerSettings",
    "layer_settings",
    "signingKey",
    "signing_key",
    "secret",
    "plaintextToken",
    "plaintext_token",
    "ruleId",
    "rule_id",
    "previousMode",
    "previous_mode",
    "candidateMode",
    "candidate_mode",
    "lockLayer",
    "lock_layer",
];

pub fn wrap_untrusted_text(source: &str, raw: &str) -> Value {
    json!({
        "untrusted": {
            "source": source,
            "data_class": "Restricted",
            "text": sanitize_untrusted_text(raw),
        }
    })
}

pub fn redact_policy_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if SECRET_KEYS.iter().any(|s| s.eq_ignore_ascii_case(&key)) {
                    map.remove(&key);
                    continue;
                }
                if let Some(child) = map.get_mut(&key) {
                    redact_policy_secrets(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_policy_secrets(item);
            }
        }
        _ => {}
    }
}

pub fn is_self_lineage(
    auth: &AuthContext,
    session_id: Option<&str>,
    agent_name: Option<&str>,
) -> bool {
    if let Some(caller_sess) = auth.principal_id.strip_prefix("session:")
        && !caller_sess.is_empty()
        && session_id.is_some_and(|s| s == caller_sess)
    {
        return true;
    }
    if let Some(caller_agent) = auth.principal_id.strip_prefix("agent:")
        && !caller_agent.is_empty()
        && agent_name.is_some_and(|a| {
            !a.is_empty()
                && (a.eq_ignore_ascii_case(caller_agent)
                    || a.eq_ignore_ascii_case(&auth.principal_id))
        })
    {
        return true;
    }
    if session_id.is_some_and(|s| !s.is_empty() && s == auth.principal_id) {
        return true;
    }
    false
}

pub fn filter_device_for_mcp(device: &Device, auth: &AuthContext) -> Device {
    let mut filtered = device.clone();
    filtered.agents.retain(|a| {
        !is_self_lineage(auth, None, Some(&a.id)) && !is_self_lineage(auth, None, Some(&a.name))
    });
    filtered
        .mcp_servers
        .retain(|s| !is_self_lineage(auth, None, Some(&s.source_agent)));
    filtered
        .artifacts
        .retain(|a| !is_self_lineage(auth, None, Some(&a.source_agent)));
    filtered
}

pub fn ensure_mcp_caller_allowed(auth: &AuthContext) -> Result<(), ApiError> {
    if auth.plane != AuthPlane::Console {
        return Err(method_forbidden(
            "Operator plane credentials cannot access tenant MCP server (D-70).",
        ));
    }
    if auth.tenant_id.trim().is_empty() {
        return Err(method_forbidden("MCP caller requires a valid tenant_id."));
    }
    Ok(())
}

pub fn self_lineage_err() -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: CODE_POLICY_DENIED.into(),
        reason: "SELF_LINEAGE_HIDDEN".into(),
        class: ErrorClass::Permission,
        message: "Governed AgentSession cannot inspect records from its own lineage (23 §10)."
            .into(),
        fix: "Query fleet telemetry outside this agent or session lineage.".into(),
        metadata: BTreeMap::new(),
    })
}

pub fn sanitize_finding_for_mcp(f: &Finding) -> Value {
    json!({
        "id": wrap_untrusted_text("finding.id", &f.id),
        "sessionId": f.session_id,
        "deviceId": f.device_id,
        "deviceName": wrap_untrusted_text("device.hostname", &f.device_name),
        "agentName": wrap_untrusted_text("agent.name", &f.agent_name),
        "class": format!("{:?}", f.class),
        "severity": format!("{:?}", f.severity),
        "lifecycle": wrap_untrusted_text("finding.lifecycle", &format!("{:?}", f.lifecycle)),
        "title": wrap_untrusted_text("finding.title", &f.title),
        "summary": wrap_untrusted_text("finding.summary", &f.summary),
        "target": wrap_untrusted_text("finding.target", &f.target),
        "detectedAt": f.detected_at.to_string(),
    })
}

pub fn sanitize_incident_for_mcp(inc: &Incident) -> Value {
    let labels: Vec<String> = inc.labels.iter().map(|l| format!("{l:?}")).collect();
    json!({
        "id": inc.id,
        "sessionId": inc.session_id,
        "deviceId": inc.device_id,
        "agentName": wrap_untrusted_text("agent.name", &inc.agent_name),
        "severity": format!("{:?}", inc.severity),
        "lifecycle": wrap_untrusted_text("incident.lifecycle", &format!("{:?}", inc.lifecycle)),
        "findingIds": inc.finding_ids,
        "findingCount": inc.finding_count,
        "labels": labels,
        "title": wrap_untrusted_text("incident.title", &inc.title),
        "summary": wrap_untrusted_text("incident.summary", &inc.summary),
        "firstSeen": inc.first_seen.to_string(),
        "lastSeen": inc.last_seen.to_string(),
    })
}

pub fn sanitize_session_summary_for_mcp(s: &SessionSummary) -> Value {
    json!({
        "id": s.id,
        "deviceId": s.device_id,
        "deviceName": wrap_untrusted_text("device.hostname", &s.device_name),
        "agentName": wrap_untrusted_text("agent.name", &s.agent_name),
        "userDisplay": s.user_display.as_deref().map(|u| wrap_untrusted_text("user.display", u)),
        "assuranceLevel": format!("{:?}", s.assurance_level),
        "totalActions": s.total_actions,
        "blockedCount": s.blocked_count,
        "stepUpCount": s.step_up_count,
        "turnCount": s.turn_count,
    })
}

pub fn sanitize_receipt_for_mcp(rcpt: &DecisionReceipt) -> Value {
    json!({
        "receiptId": rcpt.receipt_id,
        "attemptId": rcpt.attempt_id,
        "sessionId": rcpt.session_id,
        "agentName": wrap_untrusted_text("agent.name", &rcpt.agent_name),
        "actionClass": rcpt.action_class.as_str(),
        "controlPoint": format!("{:?}", rcpt.control_point),
        "verdict": format!("{:?}", rcpt.verdict),
        "reason": wrap_untrusted_text("receipt.reason", &rcpt.reason),
        "timestamp": rcpt.decided_at.to_string(),
    })
}

pub fn sanitize_session_detail_for_mcp(
    detail: &SessionDetailResponse,
    auth: &AuthContext,
) -> Value {
    let attempts: Vec<Value> = detail
        .attempts
        .iter()
        .filter(|a| !is_self_lineage(auth, Some(&a.session_id), Some(&a.agent_name)))
        .map(|a| {
            json!({
                "id": a.id,
                "agentName": wrap_untrusted_text("agent.name", &a.agent_name),
                "actionClass": a.action_class.as_str(),
                "controlPoint": format!("{:?}", a.control_point),
                "target": wrap_untrusted_text("attempt.target", &a.target),
                "summary": wrap_untrusted_text("attempt.summary", &a.summary),
                "timestamp": a.timestamp.to_string(),
            })
        })
        .collect();
    let receipts: Vec<Value> = detail
        .receipts
        .iter()
        .filter(|r| !is_self_lineage(auth, Some(&r.session_id), Some(&r.agent_name)))
        .map(sanitize_receipt_for_mcp)
        .collect();
    let turns: Vec<Value> = detail
        .turns
        .iter()
        .map(|t| {
            json!({
                "turnIndex": t.turn_index,
                "traceId": wrap_untrusted_text("turn.trace_id", &t.trace_id),
                "spanCount": t.span_count,
                "durationMs": t.duration_ms,
                "blockedCount": t.blocked_count,
                "askedCount": t.asked_count,
                "hasCompaction": t.has_compaction,
                "hasSubagentHandoff": t.has_subagent_handoff,
                "startedAt": t.started_at.to_string(),
            })
        })
        .collect();
    json!({
        "session": {
            "id": detail.session.id,
            "deviceId": detail.session.device_id,
            "deviceName": wrap_untrusted_text("device.hostname", &detail.session.device_name),
            "agentName": wrap_untrusted_text("agent.name", &detail.session.agent_name),
            "userDisplay": detail.session.user_display.as_deref().map(|u| wrap_untrusted_text("user.display", u)),
            "assuranceLevel": format!("{:?}", detail.session.assurance_level),
            "labels": detail.session.labels.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>(),
            "totalActions": detail.session.total_actions,
            "blockedCount": detail.session.blocked_count,
            "stepUpCount": detail.session.step_up_count,
            "turnCount": detail.session.turn_count,
            "startedAt": detail.session.started_at.to_string(),
            "lastActivity": detail.session.last_activity.to_string(),
        },
        "attempts": attempts,
        "receipts": receipts,
        "turns": turns,
    })
}

pub fn validate_mcp_read_method(connect_path: &str) -> Result<&'static MethodDescriptor, ApiError> {
    let normalized = if connect_path.starts_with('/') {
        connect_path.to_owned()
    } else {
        format!("/{connect_path}")
    };
    let spec = ALL_METHODS
        .iter()
        .chain(SURFACES_AND_OPERATOR_METHODS.iter())
        .find(|m| m.path == normalized)
        .or_else(|| find_method(&normalized))
        .ok_or_else(|| method_forbidden("Unknown or unregistered Connect RPC path."))?;

    let is_forbidden_domain = spec.service.contains("Policy")
        || spec.method.contains("Grant")
        || spec.method.contains("Privacy")
        || spec.method.contains("Access")
        || spec.method.contains("DeploymentKey")
        || spec.service.contains("OperatorService");

    if is_forbidden_domain
        || !spec.mcp_exposed
        || spec.idempotency != IdempotencyLevel::NoSideEffects
    {
        return Err(method_forbidden(
            "Method violates MCP policy secrecy (23-22) or read-only idempotency gate.",
        ));
    }

    let desc = load_embedded_descriptor_set()
        .map_err(|_| method_forbidden("Descriptor verification unavailable; failing closed."))?;
    let found_in_desc = desc.files.iter().any(|f| {
        f.services.iter().any(|svc| {
            let fqn = if f.package.is_empty() {
                svc.name.clone()
            } else {
                format!("{}.{}", f.package, svc.name)
            };
            fqn == spec.service && svc.methods.iter().any(|m| m.name == spec.method)
        })
    });
    if !found_in_desc {
        return Err(method_forbidden(
            "Method absent from compiled protobuf descriptor set.",
        ));
    }

    Ok(spec)
}

pub fn sanitize_json_tree_untrusted(value: Value, source: &str) -> Value {
    match value {
        Value::Object(map) => {
            if map.contains_key("untrusted") {
                return Value::Object(map);
            }
            let mut next = Map::new();
            for (k, v) in map {
                let wrap_field = matches!(
                    k.as_str(),
                    "target"
                        | "summary"
                        | "reason"
                        | "title"
                        | "prompt"
                        | "agentName"
                        | "agent_name"
                        | "sourceAgent"
                        | "source_agent"
                        | "deviceName"
                        | "device_name"
                        | "hostname"
                        | "userDisplay"
                        | "user_display"
                        | "displayName"
                        | "display_name"
                        | "email"
                        | "name"
                        | "description"
                        | "note"
                        | "rationale"
                        | "findingId"
                        | "finding_id"
                        | "lifecycle"
                        | "proposedLifecycle"
                );
                if wrap_field && let Value::String(s) = v {
                    next.insert(k, wrap_untrusted_text(source, &s));
                } else {
                    next.insert(k, sanitize_json_tree_untrusted(v, source));
                }
            }
            Value::Object(next)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| sanitize_json_tree_untrusted(v, source))
                .collect(),
        ),
        other => other,
    }
}

pub fn method_forbidden(msg: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: CODE_POLICY_DENIED.into(),
        reason: "METHOD_NOT_MCP_EXPOSED".into(),
        class: ErrorClass::Permission,
        message: msg.into(),
        fix: "Call only read-only mcp_exposed telemetry/inventory RPCs or use propose_* tools."
            .into(),
        metadata: BTreeMap::new(),
    })
}
