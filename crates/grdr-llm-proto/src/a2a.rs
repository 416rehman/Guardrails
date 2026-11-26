// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! A2A 1.0.1 JSON-RPC/REST request inspection and sans-IO type-state JWS Agent Card verification.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ProtoError;
use crate::jws::{build_jws_envelope, canonicalize_jcs_payload};
use crate::strict_json::{
    MAX_JSON_DEPTH, MAX_LLM_REQUEST_BYTES, MAX_SSE_EVENT_BYTES, parse_strict_json_bytes,
};

pub use crate::jws::{JwsSignatureEnvelope, parse_jws_compact};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2aMethodKind {
    MessageSend,
    MessageStream,
    TasksGet,
    TasksCancel,
    TasksResubscribe,
    PushNotificationSet,
    PushNotificationGet,
    AgentCardFetch,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aParsedMessage {
    pub method_kind: A2aMethodKind,
    pub id: Option<Value>,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub skill_id: Option<String>,
    pub push_webhook_url: Option<String>,
    pub part_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCardMeta {
    pub name: String,
    pub url: String,
    pub version: String,
    pub protocol_version: Option<String>,
    pub skills: Vec<String>,
    pub streaming_supported: bool,
    pub push_notifications_supported: bool,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub signatures: Vec<JwsSignatureEnvelope>,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedA2aAgentCard {
    meta: AgentCardMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedA2aAgentCard {
    meta: AgentCardMeta,
    verified_key_id: Option<String>,
}

impl UnverifiedA2aAgentCard {
    #[must_use]
    pub fn unverified_metadata(&self) -> &AgentCardMeta {
        &self.meta
    }

    pub fn verify_ed25519_with<F>(
        self,
        now_unix_s: i64,
        max_clock_skew_s: i64,
        mut verify_raw: F,
    ) -> Result<VerifiedA2aAgentCard, ProtoError>
    where
        F: FnMut(&[u8], &[u8; 64], Option<&str>) -> Result<(), String>,
    {
        if self.meta.signatures.is_empty() {
            return Err(ProtoError::Parse(
                "A2A AgentCard has zero detached JWS signatures".to_string(),
            ));
        }
        let skew = max_clock_skew_s.max(0);
        if let Some(exp) = self.meta.exp
            && now_unix_s > exp.saturating_add(skew)
        {
            return Err(ProtoError::Parse(
                "A2A AgentCard signature exp claim is expired".to_string(),
            ));
        }
        if let Some(nbf) = self.meta.nbf
            && now_unix_s.saturating_add(skew) < nbf
        {
            return Err(ProtoError::Parse(
                "A2A AgentCard nbf claim is not yet valid".to_string(),
            ));
        }
        if let Some(iat) = self.meta.iat
            && iat > now_unix_s.saturating_add(skew)
        {
            return Err(ProtoError::Parse(
                "A2A AgentCard iat claim is in the future".to_string(),
            ));
        }

        for sig in &self.meta.signatures {
            let sig_arr: [u8; 64] = sig.signature.as_slice().try_into().map_err(|_| {
                ProtoError::Parse("EdDSA JWS signature must be exactly 64 bytes".to_string())
            })?;
            if verify_raw(&sig.signing_input, &sig_arr, sig.kid.as_deref()).is_ok() {
                let kid = sig.kid.clone();
                return Ok(VerifiedA2aAgentCard {
                    meta: self.meta,
                    verified_key_id: kid,
                });
            }
        }
        Err(ProtoError::Parse(
            "no A2A AgentCard JWS signature verified under trusted Ed25519 keys".to_string(),
        ))
    }
}

impl VerifiedA2aAgentCard {
    #[must_use]
    pub fn metadata(&self) -> &AgentCardMeta {
        &self.meta
    }

    #[must_use]
    pub fn verified_key_id(&self) -> Option<&str> {
        self.verified_key_id.as_deref()
    }
}

pub fn parse_a2a_request(path: &str, body: &[u8]) -> Result<A2aParsedMessage, ProtoError> {
    let clean_path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = clean_path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if matches!(
        segments.as_slice(),
        [.., ".well-known", "agent-card.json"] | [.., ".well-known", "agent.json"]
    ) {
        return Ok(A2aParsedMessage {
            method_kind: A2aMethodKind::AgentCardFetch,
            id: None,
            task_id: None,
            context_id: None,
            skill_id: None,
            push_webhook_url: None,
            part_count: 0,
        });
    }
    if body.is_empty()
        && let Some(task_res) = parse_empty_body_task_segments(&segments)
    {
        return Ok(task_res);
    }
    let val = parse_strict_json_bytes(body, MAX_LLM_REQUEST_BYTES, MAX_JSON_DEPTH)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("A2A request must be a JSON object".to_string()))?;
    if obj.get("jsonrpc").and_then(Value::as_str) == Some("2.0") {
        return parse_a2a_jsonrpc_object(obj);
    }
    parse_a2a_rest_object(clean_path, &segments, obj)
}

fn parse_empty_body_task_segments(segments: &[&str]) -> Option<A2aParsedMessage> {
    let [version_seg, "tasks", task_seg] = segments else {
        return None;
    };
    if !version_seg.starts_with('v') {
        return None;
    }
    let (task_id, verb) = match task_seg.split_once(':') {
        Some((id, v)) => (id, Some(v)),
        None => (*task_seg, None),
    };
    if task_id.is_empty() {
        return None;
    }
    let kind = match verb {
        Some("cancel") => A2aMethodKind::TasksCancel,
        Some("subscribe") | Some("resubscribe") => A2aMethodKind::TasksResubscribe,
        Some(other) => A2aMethodKind::Custom(format!("tasks:{other}")),
        None => A2aMethodKind::TasksGet,
    };
    Some(A2aParsedMessage {
        method_kind: kind,
        id: None,
        task_id: Some(task_id.to_string()),
        context_id: None,
        skill_id: None,
        push_webhook_url: None,
        part_count: 0,
    })
}

fn parse_a2a_jsonrpc_object(obj: &Map<String, Value>) -> Result<A2aParsedMessage, ProtoError> {
    let id = obj.get("id").filter(|v| !v.is_null()).cloned();
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .filter(|m| !m.trim().is_empty())
        .ok_or_else(|| ProtoError::Parse("A2A JSON-RPC missing method".to_string()))?;
    let method_kind = classify_a2a_method(method);
    let params = obj.get("params").and_then(Value::as_object);
    let (task_id, context_id, skill_id, push_webhook_url, part_count) = extract_a2a_fields(params);
    Ok(A2aParsedMessage {
        method_kind,
        id,
        task_id,
        context_id,
        skill_id,
        push_webhook_url,
        part_count,
    })
}

fn parse_a2a_rest_object(
    clean_path: &str,
    segments: &[&str],
    obj: &Map<String, Value>,
) -> Result<A2aParsedMessage, ProtoError> {
    let method_kind = match segments {
        [_, last] if *last == "message:stream" || *last == "SendStreamingMessage" => {
            A2aMethodKind::MessageStream
        }
        [_, last] if *last == "message:send" || *last == "SendMessage" => {
            A2aMethodKind::MessageSend
        }
        [_, "tasks", task_action] if task_action.ends_with(":cancel") => A2aMethodKind::TasksCancel,
        [_, "tasks", _, "pushNotificationConfig"] => A2aMethodKind::PushNotificationSet,
        _ => A2aMethodKind::Custom(clean_path.to_string()),
    };
    let (task_id, context_id, skill_id, push_webhook_url, part_count) =
        extract_a2a_fields(Some(obj));
    Ok(A2aParsedMessage {
        method_kind,
        id: None,
        task_id,
        context_id,
        skill_id,
        push_webhook_url,
        part_count,
    })
}

fn classify_a2a_method(method: &str) -> A2aMethodKind {
    match method {
        "message/send" | "SendMessage" => A2aMethodKind::MessageSend,
        "message/stream" | "SendStreamingMessage" => A2aMethodKind::MessageStream,
        "tasks/get" | "GetTask" => A2aMethodKind::TasksGet,
        "tasks/cancel" | "CancelTask" => A2aMethodKind::TasksCancel,
        "tasks/resubscribe" | "SubscribeToTask" => A2aMethodKind::TasksResubscribe,
        "tasks/pushNotificationConfig/set" | "SetTaskPushNotificationConfig" => {
            A2aMethodKind::PushNotificationSet
        }
        "tasks/pushNotificationConfig/get" | "GetTaskPushNotificationConfig" => {
            A2aMethodKind::PushNotificationGet
        }
        other => A2aMethodKind::Custom(other.to_string()),
    }
}

fn extract_a2a_fields(
    params: Option<&Map<String, Value>>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    usize,
) {
    let Some(p) = params else {
        return (None, None, None, None, 0);
    };
    let msg = p.get("message");
    let task_id = p
        .get("id")
        .or_else(|| p.get("taskId"))
        .or_else(|| msg.and_then(|m| m.get("taskId")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let context_id = p
        .get("contextId")
        .or_else(|| msg.and_then(|m| m.get("contextId")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let skill_id = p
        .get("skillId")
        .or_else(|| p.get("metadata").and_then(|m| m.get("skillId")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let push_webhook_url = p
        .get("pushNotificationConfig")
        .or_else(|| {
            p.get("configuration")
                .and_then(|c| c.get("pushNotificationConfig"))
        })
        .and_then(|c| c.get("url"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let part_count = msg
        .and_then(|m| m.get("parts"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    (task_id, context_id, skill_id, push_webhook_url, part_count)
}

pub fn parse_a2a_agent_card(raw: &[u8]) -> Result<UnverifiedA2aAgentCard, ProtoError> {
    let val = parse_strict_json_bytes(raw, MAX_SSE_EVENT_BYTES, MAX_JSON_DEPTH)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("agent card must be a JSON object".to_string()))?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ProtoError::Parse("agent card missing name".to_string()))?
        .to_string();
    let url = obj
        .get("url")
        .or_else(|| {
            obj.get("supportedInterfaces")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|iface| iface.get("url"))
        })
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ProtoError::Parse("agent card missing url".to_string()))?
        .to_string();
    let version = obj
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0")
        .to_string();
    let protocol_version = obj
        .get("protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_string);
    let skills = obj
        .get("skills")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    s.get("id")
                        .or_else(|| s.get("name"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let caps = obj.get("capabilities");
    let streaming_supported = caps
        .and_then(|c| c.get("streaming"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let push_notifications_supported = caps
        .and_then(|c| c.get("pushNotifications"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let iat = obj.get("iat").and_then(Value::as_i64);
    let nbf = obj.get("nbf").and_then(Value::as_i64);
    let exp = obj.get("exp").and_then(Value::as_i64);

    let mut unsigned_obj = obj.clone();
    unsigned_obj.remove("signatures");
    let (payload_json, payload_b64) = canonicalize_jcs_payload(unsigned_obj)?;

    let mut signatures = Vec::new();
    if let Some(sigs) = obj.get("signatures").and_then(Value::as_array) {
        for sig_entry in sigs {
            let protected_b64 = sig_entry
                .get("protected")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ProtoError::Parse("agent card signature missing protected".to_string())
                })?;
            let sig_b64 = sig_entry
                .get("signature")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ProtoError::Parse("agent card signature missing signature".to_string())
                })?;
            signatures.push(build_jws_envelope(protected_b64, &payload_b64, sig_b64)?);
        }
    }
    Ok(UnverifiedA2aAgentCard {
        meta: AgentCardMeta {
            name,
            url,
            version,
            protocol_version,
            skills,
            streaming_supported,
            push_notifications_supported,
            iat,
            nbf,
            exp,
            signatures,
            payload_json,
        },
    })
}
