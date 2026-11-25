// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! SR-39 request validation for explicit base-URL HTTP listeners (`/t/<token>/<route_id>/...`),
//! constant-time instance token matching, fixed route mapping, and D-30 egress cut state.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::HeaderMap;
use url::Url;

use grdr_crypto::fill_random;
use grdr_identity::{AgentLifecycle, ContainmentStatus};

use crate::{ProxyError, TenantHeaderPolicy};

const ALLOWED_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/x-protobuf",
    "application/grpc",
    "application/octet-stream",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpstream {
    pub route_id: String,
    pub provider: String,
    pub base_url: Url,
    pub host: String,
    pub port: u16,
    pub credential_id: Option<String>,
    pub tenant_headers: TenantHeaderPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressState {
    Active,
    Cut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub spiffe_id: String,
    pub device_id: String,
    pub agent_name: String,
    pub caller_program: String,
    pub instance_token: String,
    pub egress: EgressState,
    pub attribution_grade: u8,
    pub has_session_container: bool,
    pub containment: ContainmentStatus,
    pub lifecycle: AgentLifecycle,
    pub expected_phantom_tokens: BTreeMap<String, String>,
    pub routes: BTreeMap<String, RouteUpstream>,
}

#[derive(Debug, Default)]
pub struct InstanceTokenRegistry {
    sessions: BTreeMap<String, SessionRegistration>,
    cut_sessions: BTreeSet<String>,
}

impl RouteUpstream {
    pub fn parse(
        route_id: impl Into<String>,
        provider: impl Into<String>,
        upstream_url: &str,
        credential_id: Option<String>,
        tenant_headers: TenantHeaderPolicy,
    ) -> Result<Self, ProxyError> {
        let parsed = Url::parse(upstream_url.trim())
            .map_err(|e| ProxyError::Sr39Rejected(format!("invalid upstream URL: {e}")))?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ProxyError::Sr39Rejected(format!(
                "unsupported upstream scheme `{scheme}`"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ProxyError::Sr39Rejected("upstream URL missing host".into()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| ProxyError::Sr39Rejected("upstream URL missing port".into()))?;
        Ok(Self {
            route_id: route_id.into(),
            provider: provider.into(),
            base_url: parsed,
            host,
            port,
            credential_id,
            tenant_headers,
        })
    }
}

impl InstanceTokenRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue_token() -> Result<String, ProxyError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut raw = [0_u8; 24];
        fill_random(&mut raw).map_err(|e| ProxyError::Transport(e.to_string()))?;
        let mut hex = String::with_capacity(48);
        for b in raw {
            let hi = usize::from(b >> 4);
            let lo = usize::from(b & 0x0f);
            if let (Some(&c1), Some(&c2)) = (HEX.get(hi), HEX.get(lo)) {
                hex.push(char::from(c1));
                hex.push(char::from(c2));
            }
        }
        Ok(format!("tok_{hex}"))
    }

    pub fn register_session(&mut self, reg: SessionRegistration) -> Result<(), ProxyError> {
        if reg.session_id.trim().is_empty() || reg.instance_token.len() < 16 {
            return Err(ProxyError::Sr39Rejected(
                "invalid session_id or instance_token length".into(),
            ));
        }
        if self.cut_sessions.contains(&reg.session_id) {
            return Err(ProxyError::SessionEgressCut(reg.session_id));
        }
        if self.sessions.values().any(|existing| {
            existing.session_id != reg.session_id
                && constant_time_eq(
                    existing.instance_token.as_bytes(),
                    reg.instance_token.as_bytes(),
                )
        }) {
            return Err(ProxyError::Sr39Rejected(
                "duplicate instance_token rejected".into(),
            ));
        }
        self.sessions.insert(reg.session_id.clone(), reg);
        Ok(())
    }

    pub fn verify_tunnel_token(
        &self,
        presented_token: &str,
    ) -> Result<SessionRegistration, ProxyError> {
        if presented_token.trim().is_empty() {
            return Err(ProxyError::Sr39Rejected(
                "tunnel requires valid instance_token".into(),
            ));
        }
        let mut matched: Option<&SessionRegistration> = None;
        for reg in self.sessions.values() {
            if constant_time_eq(reg.instance_token.as_bytes(), presented_token.as_bytes()) {
                matched = Some(reg);
            }
        }
        let Some(reg) = matched else {
            return Err(ProxyError::Sr39Rejected(
                "unknown or invalid tunnel instance_token".into(),
            ));
        };
        if reg.egress == EgressState::Cut || self.cut_sessions.contains(&reg.session_id) {
            return Err(ProxyError::SessionEgressCut(reg.session_id.clone()));
        }
        Ok(reg.clone())
    }

    pub fn cut_session(&mut self, session_id: &str) -> bool {
        self.cut_sessions.insert(session_id.to_owned());
        if let Some(reg) = self.sessions.get_mut(session_id) {
            reg.egress = EgressState::Cut;
            return true;
        }
        false
    }

    #[must_use]
    pub fn is_session_cut(&self, session_id: &str) -> bool {
        self.cut_sessions.contains(session_id)
            || self
                .sessions
                .get(session_id)
                .is_some_and(|reg| reg.egress == EgressState::Cut)
    }

    pub fn resolve_sr39_route(
        &self,
        headers: &HeaderMap,
        expected_listener_port: u16,
        presented_token: &str,
        route_id: &str,
        has_request_body: bool,
    ) -> Result<(SessionRegistration, RouteUpstream), ProxyError> {
        validate_sr39_headers(headers, expected_listener_port, has_request_body)?;

        let mut matched: Option<&SessionRegistration> = None;
        for reg in self.sessions.values() {
            if constant_time_eq(reg.instance_token.as_bytes(), presented_token.as_bytes()) {
                matched = Some(reg);
            }
        }
        let Some(reg) = matched else {
            return Err(ProxyError::Sr39Rejected(
                "unknown or invalid instance_token".into(),
            ));
        };

        if reg.egress == EgressState::Cut || self.cut_sessions.contains(&reg.session_id) {
            return Err(ProxyError::SessionEgressCut(reg.session_id.clone()));
        }

        let route = reg.routes.get(route_id).ok_or_else(|| {
            ProxyError::Sr39Rejected(format!(
                "route_id `{route_id}` is not mapped for session (open relay forbidden)"
            ))
        })?;

        Ok((reg.clone(), route.clone()))
    }
}

pub fn validate_sr39_headers(
    headers: &HeaderMap,
    expected_listener_port: u16,
    has_request_body: bool,
) -> Result<(), ProxyError> {
    if headers.contains_key("origin") {
        return Err(ProxyError::Sr39Rejected(
            "SR-39 forbids browser Origin header on proxy listener".into(),
        ));
    }
    if headers.get_all("host").iter().count() != 1 {
        return Err(ProxyError::Sr39Rejected(
            "SR-39 requires exactly one Host header".into(),
        ));
    }

    let host_raw = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ProxyError::Sr39Rejected("SR-39 requires Host header".into()))?;

    if !is_allowed_loopback_host(host_raw, expected_listener_port) {
        return Err(ProxyError::Sr39Rejected(format!(
            "SR-39 Host header `{host_raw}` failed listener authority verification"
        )));
    }

    if has_request_body {
        let ctype = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ProxyError::Sr39Rejected("SR-39 requires explicit Content-Type on body".into())
            })?;
        let media = ctype
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !ALLOWED_CONTENT_TYPES.contains(&media.as_str()) {
            return Err(ProxyError::Sr39Rejected(format!(
                "SR-39 rejected Content-Type `{media}`"
            )));
        }
    }

    Ok(())
}

fn is_allowed_loopback_host(host_header: &str, expected_port: u16) -> bool {
    let lower = host_header.to_ascii_lowercase();
    let (host_part, port_part) = if let Some(rest) = lower.strip_prefix('[') {
        let Some((ip6, tail)) = rest.split_once(']') else {
            return false;
        };
        let port = tail.strip_prefix(':');
        (ip6, port)
    } else if let Some((h, p)) = lower.rsplit_once(':') {
        (h, Some(p))
    } else {
        (lower.as_str(), None)
    };

    let host_ok = host_part == "127.0.0.1" || host_part == "localhost" || host_part == "::1";
    if !host_ok || expected_port == 0 {
        return false;
    }
    match port_part {
        Some(raw_port) => raw_port.parse::<u16>().ok() == Some(expected_port),
        None => expected_port == 80 || expected_port == 443,
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
