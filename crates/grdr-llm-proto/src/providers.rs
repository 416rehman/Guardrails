// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::LlmRequestMeta;
use crate::compression::{decompress_bounded, parse_content_encoding_header};
use crate::error::ProtoError;
use crate::schema::{ProviderFamily, ProviderSchemaRegistry, ProviderSchemaSpec};
use crate::strict_json::{MAX_TOOL_CALLS, parse_strict_json_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigV4PayloadHashKind {
    Sha256Hex,
    UnsignedPayload,
    StreamingPayload,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigV4Metadata {
    pub access_key_id: String,
    pub date_stamp: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
    pub payload_hash_kind: SigV4PayloadHashKind,
    pub security_token_present: bool,
    pub amz_date: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamDeliveryKind {
    Unary,
    Streaming,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmRequestInspection {
    pub family: ProviderFamily,
    pub meta: LlmRequestMeta,
    pub delivery: StreamDeliveryKind,
    pub system_prompt_bytes: usize,
    pub sigv4: Option<SigV4Metadata>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmParseOutcome {
    Resolved(Box<LlmRequestInspection>),
    Unresolved { reason: String },
    Malformed { code: &'static str, reason: String },
}

pub fn parse_sigv4_headers(
    headers: &[(String, String)],
) -> Result<Option<SigV4Metadata>, ProtoError> {
    let auth = find_header_ci(headers, "authorization");
    let Some(auth_val) = auth else {
        return Ok(None);
    };
    let trimmed = auth_val.trim();
    let Some(rest) = trimmed.strip_prefix("AWS4-HMAC-SHA256") else {
        return Ok(None);
    };
    let (mut cred, mut signed_hdrs, mut sig) = (None, None, None);
    for part in rest.trim().split(',') {
        let piece = part.trim();
        if let Some(v) = piece.strip_prefix("Credential=") {
            cred = Some(v.trim());
        } else if let Some(v) = piece.strip_prefix("SignedHeaders=") {
            signed_hdrs = Some(v.trim());
        } else if let Some(v) = piece.strip_prefix("Signature=") {
            sig = Some(v.trim());
        }
    }
    let cred_str = cred.ok_or_else(|| ProtoError::Parse("sigv4 missing Credential".to_string()))?;
    let sig_str = sig.ok_or_else(|| ProtoError::Parse("sigv4 missing Signature".to_string()))?;
    if sig_str.len() != 64 || !sig_str.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProtoError::Parse("sigv4 invalid Signature hex".to_string()));
    }
    let mut scope_parts = cred_str.split('/');
    let access_key = scope_parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("sigv4 missing access key".to_string()))?;
    let date_stamp = scope_parts
        .next()
        .filter(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| ProtoError::Parse("sigv4 invalid date stamp".to_string()))?;
    let region = scope_parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("sigv4 missing region".to_string()))?;
    let service = scope_parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ProtoError::Parse("sigv4 missing service".to_string()))?;
    let term = scope_parts
        .next()
        .ok_or_else(|| ProtoError::Parse("sigv4 missing terminator".to_string()))?;
    if term != "aws4_request" || scope_parts.next().is_some() {
        return Err(ProtoError::Parse(
            "sigv4 invalid credential scope".to_string(),
        ));
    }
    let signed_headers: Vec<String> = signed_hdrs
        .ok_or_else(|| ProtoError::Parse("sigv4 missing SignedHeaders".to_string()))?
        .split(';')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if !signed_headers.iter().any(|h| h == "host") {
        return Err(ProtoError::Parse(
            "sigv4 SignedHeaders must include host".to_string(),
        ));
    }
    let amz_date = find_header_ci(headers, "x-amz-date").map(str::to_string);
    let payload_hash_kind =
        classify_amz_content_sha256(find_header_ci(headers, "x-amz-content-sha256"))?;
    let security_token_present = find_header_ci(headers, "x-amz-security-token").is_some();
    Ok(Some(SigV4Metadata {
        access_key_id: access_key.to_string(),
        date_stamp: date_stamp.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        signed_headers,
        payload_hash_kind,
        security_token_present,
        amz_date,
    }))
}

fn classify_amz_content_sha256(val: Option<&str>) -> Result<SigV4PayloadHashKind, ProtoError> {
    let Some(raw) = val.map(str::trim) else {
        return Ok(SigV4PayloadHashKind::Missing);
    };
    if raw == "UNSIGNED-PAYLOAD" {
        return Ok(SigV4PayloadHashKind::UnsignedPayload);
    }
    if raw.starts_with("STREAMING-") {
        return Ok(SigV4PayloadHashKind::StreamingPayload);
    }
    if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(SigV4PayloadHashKind::Sha256Hex);
    }
    Err(ProtoError::Parse(
        "invalid x-amz-content-sha256 header".to_string(),
    ))
}

pub fn inspect_llm_http_request(
    registry: &ProviderSchemaRegistry,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    raw_body: &[u8],
) -> Result<LlmRequestInspection, ProtoError> {
    let limits = registry.limits();
    let encodings = match find_header_ci(headers, "content-encoding") {
        Some(hdr) => parse_content_encoding_header(hdr)?,
        None => Vec::new(),
    };
    let decoded = decompress_bounded(
        raw_body,
        &encodings,
        limits.max_request_bytes,
        limits.max_decompression_ratio,
    )?;
    let sigv4 = parse_sigv4_headers(headers)?;
    let val = parse_strict_json_bytes(&decoded, limits.max_request_bytes, limits.max_json_depth)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("LLM request body must be a JSON object".to_string()))?;
    let spec = registry.match_request(host, path, Some(obj));
    let family = spec.map_or(ProviderFamily::Generic, |s| s.family);
    let mut warnings = Vec::new();
    if let Some(sv4) = &sigv4
        && sv4.payload_hash_kind == SigV4PayloadHashKind::UnsignedPayload
    {
        warnings.push("sigv4.unsigned-payload".to_string());
    }
    if let Some(s) = spec
        && s.requires_sigv4
        && sigv4.is_none()
    {
        warnings.push("sigv4.missing-auth".to_string());
    }
    let meta = extract_meta_from_object(family, spec, host, path, obj, limits.max_tool_calls)?;
    let delivery = detect_stream_flag(family, path, spec, obj);
    let system_prompt_bytes = measure_system_prompt_bytes(spec, obj);
    Ok(LlmRequestInspection {
        family,
        meta,
        delivery,
        system_prompt_bytes,
        sigv4,
        warnings,
    })
}

pub(crate) fn extract_meta_from_object(
    family: ProviderFamily,
    spec: Option<&ProviderSchemaSpec>,
    host: &str,
    path: &str,
    obj: &Map<String, Value>,
    max_tools: usize,
) -> Result<LlmRequestMeta, ProtoError> {
    let provider_label = spec.map(|s| s.id.clone()).unwrap_or_else(|| {
        if host.is_empty() {
            "unknown".to_string()
        } else {
            host.to_string()
        }
    });
    let model = extract_model(family, spec, path, obj);
    let tool_names = extract_tool_names(spec, obj, max_tools)?;
    let message_count = extract_message_count(spec, obj);
    let has_system_prompt = measure_system_prompt_bytes(spec, obj) > 0;
    Ok(LlmRequestMeta {
        provider: provider_label,
        model,
        tool_names,
        message_count,
        has_system_prompt,
    })
}

fn extract_model(
    family: ProviderFamily,
    spec: Option<&ProviderSchemaSpec>,
    path: &str,
    obj: &Map<String, Value>,
) -> Option<String> {
    if let Some(s) = spec {
        for key in &s.model_keys {
            if let Some(m) = obj.get(key.as_str()).and_then(Value::as_str) {
                return Some(m.to_string());
            }
        }
    } else if let Some(m) = obj.get("model").and_then(Value::as_str) {
        return Some(m.to_string());
    }
    match family {
        ProviderFamily::GoogleGemini => extract_gemini_path_model(path),
        ProviderFamily::AwsBedrock => extract_bedrock_path_model(path),
        ProviderFamily::OpenAiChat => extract_azure_path_deployment(path),
        _ => None,
    }
}

fn extract_gemini_path_model(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let idx = clean.find("/models/")?;
    let after = clean.get(idx.saturating_add(8)..)?;
    let model = after.split(':').next().unwrap_or(after);
    (!model.is_empty()).then(|| model.to_string())
}

fn extract_bedrock_path_model(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let idx = clean.find("/model/")?;
    let after = clean.get(idx.saturating_add(7)..)?;
    let encoded = after.split('/').next()?;
    if encoded.is_empty() {
        return None;
    }
    Some(percent_decode_ascii(encoded))
}

fn extract_azure_path_deployment(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let idx = clean.find("/openai/deployments/")?;
    let after = clean.get(idx.saturating_add(20)..)?;
    let dep = after.split('/').next()?;
    (!dep.is_empty()).then(|| dep.to_string())
}

fn extract_tool_names(
    spec: Option<&ProviderSchemaSpec>,
    obj: &Map<String, Value>,
    max_tools: usize,
) -> Result<Vec<String>, ProtoError> {
    let mut names = Vec::new();
    let cap = max_tools.min(MAX_TOOL_CALLS);
    let array_keys: Vec<&str> = match spec {
        Some(s) => s.tool_array_keys.iter().map(String::as_str).collect(),
        None => vec!["tools", "functions"],
    };
    for arr_path in array_keys {
        let Some(arr) = resolve_dot_value(obj, arr_path).and_then(Value::as_array) else {
            continue;
        };
        if names.len().saturating_add(arr.len()) > cap {
            return Err(ProtoError::PayloadTooLarge);
        }
        collect_tool_names_from_array(arr, spec, &mut names);
    }
    Ok(names)
}

fn collect_tool_names_from_array(
    arr: &[Value],
    spec: Option<&ProviderSchemaSpec>,
    out: &mut Vec<String>,
) {
    let default_paths = ["name".to_string(), "function.name".to_string()];
    let paths: &[String] = match spec {
        Some(s) => &s.tool_name_paths,
        None => &default_paths,
    };
    for item in arr {
        let before = out.len();
        for path in paths {
            collect_strings_along_path(item, path, out);
            if out.len() > before {
                break;
            }
        }
    }
}

fn collect_strings_along_path(val: &Value, path: &str, out: &mut Vec<String>) {
    let mut current: Vec<&Value> = vec![val];
    for seg in path.split('.') {
        let (key, expand_array) = match seg.strip_suffix("[*]") {
            Some(k) => (k, true),
            None => (seg, false),
        };
        let mut next = Vec::new();
        for node in current {
            let Some(child) = (if key.is_empty() {
                Some(node)
            } else {
                node.get(key)
            }) else {
                continue;
            };
            if expand_array {
                if let Some(arr) = child.as_array() {
                    next.extend(arr.iter());
                }
            } else {
                next.push(child);
            }
        }
        current = next;
    }
    for leaf in current {
        if let Some(s) = leaf.as_str()
            && !s.trim().is_empty()
        {
            out.push(s.to_string());
        }
    }
}

fn extract_message_count(spec: Option<&ProviderSchemaSpec>, obj: &Map<String, Value>) -> usize {
    let keys: Vec<&str> = match spec {
        Some(s) => s.message_array_keys.iter().map(String::as_str).collect(),
        None => vec!["messages", "input", "contents"],
    };
    for key in keys {
        if let Some(v) = resolve_dot_value(obj, key) {
            return match v {
                Value::Array(arr) => arr.len(),
                Value::String(_) => 1,
                Value::Object(_) => 1,
                _ => 0,
            };
        }
    }
    if obj.get("prompt").is_some() || obj.get("inputText").is_some() {
        return 1;
    }
    0
}

fn measure_system_prompt_bytes(
    spec: Option<&ProviderSchemaSpec>,
    obj: &Map<String, Value>,
) -> usize {
    let keys: Vec<&str> = match spec {
        Some(s) => s.system_keys.iter().map(String::as_str).collect(),
        None => vec!["system", "instructions", "systemInstruction"],
    };
    let mut bytes = 0usize;
    for key in keys {
        if let Some(v) = obj.get(key) {
            bytes = bytes.saturating_add(v.to_string().len());
        }
    }
    if let Some(msgs) = obj.get("messages").and_then(Value::as_array) {
        for msg in msgs {
            if msg.get("role").and_then(Value::as_str) == Some("system") {
                bytes = bytes.saturating_add(msg.to_string().len());
            }
        }
    }
    bytes
}

fn detect_stream_flag(
    family: ProviderFamily,
    path: &str,
    spec: Option<&ProviderSchemaSpec>,
    obj: &Map<String, Value>,
) -> StreamDeliveryKind {
    if let Some(s) = spec {
        for key in &s.stream_keys {
            if obj.get(key.as_str()).and_then(Value::as_bool) == Some(true) {
                return StreamDeliveryKind::Streaming;
            }
        }
    }
    match family {
        ProviderFamily::GoogleGemini if path.contains("streamGenerateContent") => {
            StreamDeliveryKind::Streaming
        }
        ProviderFamily::AwsBedrock
            if path.contains("invoke-with-response-stream") || path.contains("converse-stream") =>
        {
            StreamDeliveryKind::Streaming
        }
        _ => StreamDeliveryKind::Unary,
    }
}

fn resolve_dot_value<'a>(obj: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut cur = obj.get(first)?;
    for seg in parts {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn find_header_ci<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(target))
        .map(|(_, v)| v.as_str())
}

fn percent_decode_ascii(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        let cur = bytes.get(idx).copied().unwrap_or(b'?');
        if cur == b'%'
            && let Some(hi) = bytes.get(idx.saturating_add(1)).and_then(|&b| hex_val(b))
            && let Some(lo) = bytes.get(idx.saturating_add(2)).and_then(|&b| hex_val(b))
        {
            out.push((hi << 4) | lo);
            idx = idx.saturating_add(3);
            continue;
        }
        out.push(cur);
        idx = idx.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}
