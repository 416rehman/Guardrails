// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! HTTP header filtering, URL path confinement, P14 provider/A2A/Realtime request inspection,
//! and strict Ed25519 AgentCard JWS verification helpers.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use url::Url;

use grdr_crypto::verify_ed25519_raw;
use grdr_llm_proto::a2a::{parse_a2a_agent_card, parse_a2a_request};
use grdr_llm_proto::providers::{inspect_llm_http_request, parse_sigv4_headers};
use grdr_llm_proto::realtime::{parse_realtime_frame_json, parse_ws_frames};
use grdr_llm_proto::schema::{ProviderFamily, ProviderSchemaRegistry};
use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, MAX_LLM_REQUEST_BYTES, parse_strict_json_bytes};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;
use uuid::Uuid;

use crate::ProxyError;

pub struct ProxyAttemptInput<'a> {
    pub session_id: &'a str,
    pub agent_name: &'a str,
    pub provider: &'a str,
    pub route_host: &'a str,
    pub target_url: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub trusted_a2a_keys: &'a BTreeMap<String, [u8; 32]>,
}

struct InspectContext<'a> {
    family: Option<ProviderFamily>,
    registry: &'a ProviderSchemaRegistry,
    host_matched_spec: bool,
    target_path: &'a str,
    header_pairs: &'a [(String, String)],
    sigv4_note: &'a str,
    now_s: i64,
}

pub fn copy_safe_outbound_headers(headers: &HeaderMap) -> HeaderMap {
    let mut skip_names = BTreeSet::from([
        "connection".to_owned(),
        "keep-alive".to_owned(),
        "proxy-authenticate".to_owned(),
        "proxy-authorization".to_owned(),
        "te".to_owned(),
        "trailer".to_owned(),
        "transfer-encoding".to_owned(),
        "upgrade".to_owned(),
        "host".to_owned(),
        "authorization".to_owned(),
        "x-api-key".to_owned(),
        "cookie".to_owned(),
        "content-length".to_owned(),
        "forwarded".to_owned(),
        "x-forwarded-for".to_owned(),
        "x-forwarded-host".to_owned(),
        "x-forwarded-proto".to_owned(),
        "grdr-session".to_owned(),
        "content-encoding".to_owned(),
        "accept-encoding".to_owned(),
        "content-digest".to_owned(),
        "signature".to_owned(),
        "signature-input".to_owned(),
        "signature-agent".to_owned(),
    ]);
    for conn_val in headers.get_all("connection") {
        if let Ok(raw) = conn_val.to_str() {
            for token in raw.split(',') {
                let lower = token.trim().to_ascii_lowercase();
                if !lower.is_empty() {
                    skip_names.insert(lower);
                }
            }
        }
    }

    let mut outbound = HeaderMap::new();
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        if !skip_names.contains(&lower) {
            outbound.insert(k.clone(), v.clone());
        }
    }
    outbound
}

pub fn build_upstream_url(base: &Url, tail: &str) -> Result<String, ProxyError> {
    let clean_tail = tail.trim_start_matches('/');
    if clean_tail.is_empty() {
        return Ok(base.as_str().to_owned());
    }
    let lower = clean_tail.to_ascii_lowercase();
    if clean_tail.chars().any(char::is_control)
        || clean_tail.contains('?')
        || clean_tail.contains('#')
        || clean_tail.contains('\\')
        || clean_tail.contains("//")
        || clean_tail.contains("..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%00")
    {
        return Err(ProxyError::Sr39Rejected(
            "upstream path tail contains disallowed traversal, query, or control token".into(),
        ));
    }
    let mut segments = clean_tail.split('/').peekable();
    while let Some(seg) = segments.next() {
        let is_trailing_empty = seg.is_empty() && segments.peek().is_none();
        if (!is_trailing_empty && seg.is_empty()) || seg == "." || seg == ".." {
            return Err(ProxyError::Sr39Rejected(
                "upstream path tail contains dot or empty path segment".into(),
            ));
        }
    }
    let base_str = base.as_str().trim_end_matches('/');
    let joined = format!("{base_str}/{clean_tail}");
    let parsed = Url::parse(&joined)
        .map_err(|_| ProxyError::Sr39Rejected("invalid joined upstream route URL".into()))?;
    let base_prefix = base.path().trim_end_matches('/');
    let same_prefix = base_prefix.is_empty()
        || parsed.path() == base_prefix
        || parsed.path().starts_with(&format!("{base_prefix}/"));
    if parsed.origin() != base.origin() || !same_prefix {
        return Err(ProxyError::Sr39Rejected(
            "joined upstream URL escaped registered route origin or base path".into(),
        ));
    }
    Ok(parsed.to_string())
}

pub fn build_proxy_attempt(input: ProxyAttemptInput<'_>) -> Result<ActionAttempt, ProxyError> {
    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?;
    let target_path = Url::parse(input.target_url)
        .map(|u| u.path().to_owned())
        .unwrap_or_else(|_| "/".to_owned());
    let header_pairs: Vec<(String, String)> = input
        .headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    let sigv4_note = parse_sigv4_headers(&header_pairs)
        .ok()
        .flatten()
        .map(|s| format!(" sigv4_region={} sigv4_svc={}", s.region, s.service))
        .unwrap_or_default();

    let registry = ProviderSchemaRegistry::default_embedded()
        .map_err(|e| ProxyError::Transport(format!("embedded provider registry invalid: {e}")))?;
    let body_obj = (!input.body.is_empty())
        .then(|| parse_strict_json_bytes(input.body, MAX_LLM_REQUEST_BYTES, MAX_JSON_DEPTH).ok())
        .flatten()
        .and_then(|v| v.as_object().cloned());
    let matched_spec = registry.match_request(input.route_host, &target_path, body_obj.as_ref());
    let explicit_family =
        resolve_route_family(&registry, input.provider, matched_spec.map(|s| s.family));

    let host_matched_spec = registry
        .match_request(input.route_host, &target_path, None)
        .is_some_and(|s| Some(s.family) == explicit_family);
    let ctx = InspectContext {
        family: explicit_family,
        registry: &registry,
        host_matched_spec,
        target_path: &target_path,
        header_pairs: &header_pairs,
        sigv4_note: &sigv4_note,
        now_s: now.as_second(),
    };
    let (action_class, summary) = inspect_route_payload_ctx(&ctx, &input)?;

    Ok(ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: input.session_id.to_owned(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: input.agent_name.to_owned(),
        action_class,
        control_point: ControlPoint::Proxy,
        target: input.target_url.to_owned(),
        summary: sanitize_untrusted_text(&summary),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    })
}

fn inspect_route_payload_ctx(
    ctx: &InspectContext<'_>,
    input: &ProxyAttemptInput<'_>,
) -> Result<(ActionClass, String), ProxyError> {
    if ctx.family == Some(ProviderFamily::A2a) {
        if (ctx.target_path.ends_with("agent-card.json") || ctx.target_path.ends_with("agent.json"))
            && !input.body.is_empty()
        {
            let unverified = parse_a2a_agent_card(input.body).map_err(|e| {
                ProxyError::PolicyDenied(format!("GRDR-PROXY-0003: malformed A2A AgentCard: {e}"))
            })?;
            let verified = unverified
                .verify_ed25519_with(ctx.now_s, 60, |signing_input, sig_arr, kid| {
                    let key_id = kid.ok_or_else(|| "A2A AgentCard JWS missing kid".to_string())?;
                    let pub_key = input
                        .trusted_a2a_keys
                        .get(key_id)
                        .ok_or_else(|| format!("untrusted A2A AgentCard kid `{key_id}`"))?;
                    verify_ed25519_raw(pub_key, signing_input, sig_arr).map_err(|e| e.to_string())
                })
                .map_err(|e| {
                    ProxyError::PolicyDenied(format!(
                        "GRDR-PROXY-0003: A2A AgentCard JWS verification failed: {e}"
                    ))
                })?;
            return Ok((
                ActionClass::AgentSpawn,
                format!(
                    "a2a-agent-card name={} key={}",
                    verified.metadata().name,
                    verified.verified_key_id().unwrap_or("unknown")
                ),
            ));
        }
        let parsed = parse_a2a_request(ctx.target_path, input.body)
            .map_err(|e| ProxyError::Sr39Rejected(format!("invalid A2A 1.0.1 frame: {e}")))?;
        return Ok((
            ActionClass::AgentSpawn,
            format!(
                "a2a method={:?} parts={}{}",
                parsed.method_kind, parsed.part_count, ctx.sigv4_note
            ),
        ));
    }

    if ctx.family == Some(ProviderFamily::OpenAiRealtime) && !input.body.is_empty() {
        if input.body.first() == Some(&b'{') {
            let rt = parse_realtime_frame_json(input.body)
                .map_err(|e| ProxyError::Sr39Rejected(format!("invalid realtime JSON: {e}")))?;
            return Ok((
                ActionClass::LlmRequest,
                format!(
                    "realtime event={} tools={}{}",
                    rt.event_type,
                    rt.tools.len(),
                    ctx.sigv4_note
                ),
            ));
        }
        let (ws_frames, _) = parse_ws_frames(input.body, MAX_LLM_REQUEST_BYTES)
            .map_err(|e| ProxyError::Sr39Rejected(format!("invalid realtime WS frame: {e}")))?;
        return Ok((
            ActionClass::LlmRequest,
            format!("realtime ws_frames={}{}", ws_frames.len(), ctx.sigv4_note),
        ));
    }

    if input.body.is_empty() {
        return Ok((
            ActionClass::NetRequest,
            format!(
                "http route request target={}{}",
                input.target_url, ctx.sigv4_note
            ),
        ));
    }

    let effective_host = if ctx.host_matched_spec {
        input.route_host.to_owned()
    } else if let Some(fam) = ctx.family.filter(|f| *f != ProviderFamily::Generic) {
        canonical_family_host(ctx.registry, fam, input.route_host)
    } else {
        input.route_host.to_owned()
    };

    // Body was already boundedly decompressed in `inspect_and_decompress_request_body`.
    let llm_headers: Vec<(String, String)> = ctx
        .header_pairs
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"))
        .cloned()
        .collect();

    match inspect_llm_http_request(
        ctx.registry,
        &effective_host,
        ctx.target_path,
        &llm_headers,
        input.body,
    ) {
        Ok(insp) => {
            if insp.family != ProviderFamily::Generic
                || insp.meta.model.is_some()
                || insp.meta.message_count > 0
                || !insp.meta.tool_names.is_empty()
            {
                Ok((
                    ActionClass::LlmRequest,
                    format!(
                        "provider={} model={} msgs={} tools={}{}",
                        insp.meta.provider,
                        insp.meta.model.as_deref().unwrap_or("unspecified"),
                        insp.meta.message_count,
                        insp.meta.tool_names.len(),
                        ctx.sigv4_note
                    ),
                ))
            } else {
                Ok((
                    ActionClass::NetRequest,
                    format!(
                        "http route request target={}{}",
                        input.target_url, ctx.sigv4_note
                    ),
                ))
            }
        }
        Err(err) => {
            let trimmed = input.body.trim_ascii_start();
            if ctx.family.is_some_and(|f| f != ProviderFamily::Generic)
                || trimmed.starts_with(b"{")
                || trimmed.starts_with(b"[")
            {
                Err(ProxyError::Sr39Rejected(format!(
                    "malformed LLM HTTP request payload: {err}"
                )))
            } else {
                Ok((
                    ActionClass::NetRequest,
                    format!(
                        "http route request target={}{}",
                        input.target_url, ctx.sigv4_note
                    ),
                ))
            }
        }
    }
}

fn canonical_family_host(
    registry: &ProviderSchemaRegistry,
    family: ProviderFamily,
    fallback_host: &str,
) -> String {
    let Some(spec) = registry.find_by_family(family) else {
        return fallback_host.to_owned();
    };
    let Some(pat) = spec.host_patterns.first() else {
        return fallback_host.to_owned();
    };
    if pat.starts_with('.') {
        format!("bedrock{pat}")
    } else if pat.starts_with('-') {
        format!("us{pat}")
    } else {
        pat.clone()
    }
}

pub(crate) fn resolve_route_family(
    registry: &ProviderSchemaRegistry,
    provider: &str,
    matched_family: Option<ProviderFamily>,
) -> Option<ProviderFamily> {
    let lower = provider.trim().to_ascii_lowercase();
    for spec in registry.providers() {
        let id_lower = spec.id.to_ascii_lowercase();
        if lower == id_lower
            || lower == family_label(spec.family)
            || spec.host_patterns.iter().any(|p| lower.contains(p))
            || lower.contains(&id_lower)
        {
            return Some(spec.family);
        }
    }
    if lower.contains("a2a") {
        return Some(ProviderFamily::A2a);
    }
    if lower.contains("realtime") {
        return Some(ProviderFamily::OpenAiRealtime);
    }
    matched_family
}

fn family_label(family: ProviderFamily) -> &'static str {
    match family {
        ProviderFamily::AnthropicMessages => "anthropic",
        ProviderFamily::OpenAiChat => "openai",
        ProviderFamily::OpenAiResponses => "responses",
        ProviderFamily::GoogleGemini => "gemini",
        ProviderFamily::AwsBedrock => "bedrock",
        ProviderFamily::OpenAiRealtime => "realtime",
        ProviderFamily::A2a => "a2a",
        ProviderFamily::Generic => "generic",
    }
}

pub fn bad_gateway_response(err: &ProxyError) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(serde_json::json!({
            "error": sanitize_untrusted_text(&err.to_string()),
            "code": "GRDR-PROXY-0006"
        })),
    )
        .into_response()
}

pub fn denial_403(err: &ProxyError) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": sanitize_untrusted_text(&err.to_string()),
            "verdict": "Deny"
        })),
    )
        .into_response()
}
