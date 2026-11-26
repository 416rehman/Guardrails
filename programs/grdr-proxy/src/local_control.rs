// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Daemon `Local` IPC control updates populating `InstanceTokenRegistry`,
//! `ProxyCredentialManager`, D-30 session egress cuts, and global kill switch.

use std::collections::BTreeMap;

use axum::http::header::{HeaderName, HeaderValue};
use grdr_os_clock::{Clock, SystemClock};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use grdr_identity::{AgentLifecycle, ContainmentStatus, CredentialBinding, CredentialClass};

use crate::cred_inject::{VaultedUpstreamSecret, model_class_ceiling};
use crate::ipc_client::IpcProxyDecisionClient;
use crate::router::ProxyGatewayState;
use crate::sr39::{EgressState, RouteUpstream, SessionRegistration};
use crate::{ProxyDecisionClient, ProxyError, TenantHeaderPolicy};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRouteSpec {
    pub route_id: String,
    pub provider: String,
    pub upstream_url: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default)]
    pub tenant_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlSessionSpec {
    pub session_id: String,
    pub spiffe_id: String,
    pub device_id: String,
    pub agent_name: String,
    pub caller_program: String,
    pub instance_token: String,
    #[serde(default = "default_attribution_grade")]
    pub attribution_grade: u8,
    #[serde(default = "default_true")]
    pub has_session_container: bool,
    #[serde(default)]
    pub expected_phantom_tokens: BTreeMap<String, String>,
    #[serde(default)]
    pub routes: Vec<ControlRouteSpec>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlCredentialSpec {
    pub credential_id: String,
    pub account_id: String,
    #[serde(default)]
    pub allowed_programs: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub phantom_prefix: String,
    pub header_name: String,
    #[serde(default)]
    pub header_prefix: String,
    pub secret_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProxyControlUpdate {
    RegisterSession(ControlSessionSpec),
    UpsertCredential(ControlCredentialSpec),
    RevokeCredential { session_id: String },
    CutSessionEgress { session_id: String, reason: String },
    SetGlobalKillSwitch { active: bool, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ControlUpdateBatch {
    pub updates: Vec<ProxyControlUpdate>,
}

impl std::fmt::Debug for ControlCredentialSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCredentialSpec")
            .field("credential_id", &self.credential_id)
            .field("account_id", &self.account_id)
            .field("header_name", &self.header_name)
            .field("secret_value", &"[REDACTED]")
            .finish()
    }
}

const fn default_attribution_grade() -> u8 {
    4
}

const fn default_true() -> bool {
    true
}

pub async fn apply_local_control_update<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    update: ProxyControlUpdate,
) -> Result<String, ProxyError> {
    match update {
        ProxyControlUpdate::RegisterSession(spec) => {
            let mut routes = BTreeMap::new();
            for r in spec.routes {
                let mut tenant_headers = TenantHeaderPolicy::default();
                for (name, val) in r.tenant_headers {
                    tenant_headers.insert(name, val)?;
                }
                let parsed = RouteUpstream::parse(
                    r.route_id.clone(),
                    r.provider,
                    &r.upstream_url,
                    r.credential_id,
                    tenant_headers,
                )?;
                routes.insert(r.route_id, parsed);
            }
            let session_id = spec.session_id.clone();
            let reg = SessionRegistration {
                session_id: spec.session_id,
                spiffe_id: spec.spiffe_id,
                device_id: spec.device_id,
                agent_name: spec.agent_name,
                caller_program: spec.caller_program,
                instance_token: spec.instance_token,
                egress: EgressState::Active,
                attribution_grade: spec.attribution_grade,
                has_session_container: spec.has_session_container,
                containment: if spec.has_session_container {
                    ContainmentStatus::Contained
                } else {
                    ContainmentStatus::Uncontained
                },
                lifecycle: AgentLifecycle::Active,
                expected_phantom_tokens: spec.expected_phantom_tokens,
                routes,
            };
            state.registry.lock().await.register_session(reg)?;
            Ok(format!("registered session `{session_id}`"))
        }
        ProxyControlUpdate::UpsertCredential(spec) => {
            let Some(first_host) = spec.allowed_hosts.first() else {
                return Err(ProxyError::CredentialDenied(
                    "credential update requires at least one allowed_host".to_string(),
                ));
            };
            let hdr_name =
                HeaderName::from_bytes(spec.header_name.trim().as_bytes()).map_err(|e| {
                    ProxyError::CredentialDenied(format!("invalid credential header_name: {e}"))
                })?;
            if matches!(
                hdr_name.as_str(),
                "host" | "content-length" | "transfer-encoding" | "grdr-session"
            ) {
                return Err(ProxyError::CredentialDenied(
                    "credential header_name cannot override protected proxy header".to_string(),
                ));
            }
            let combined_val = format!("{}{}", spec.header_prefix, spec.secret_value);
            if combined_val.bytes().any(|b| b < 0x20 || b == 0x7f)
                || HeaderValue::from_str(&combined_val).is_err()
            {
                return Err(ProxyError::CredentialDenied(
                    "credential header value invalid or contains control bytes".to_string(),
                ));
            }
            let cred_id = spec.credential_id.clone();
            let ceiling = model_class_ceiling(&spec.account_id, first_host);
            let binding = CredentialBinding {
                credential_id: spec.credential_id,
                class: CredentialClass::Model,
                account_id: spec.account_id,
                allowed_programs: spec.allowed_programs,
                allowed_hosts: spec.allowed_hosts,
                upstream_revocable: true,
                upstream_min_ttl_secs: 60,
                phantom_prefix: spec.phantom_prefix,
            };
            let vaulted = VaultedUpstreamSecret {
                binding,
                ceiling,
                header_name: hdr_name.as_str().to_string(),
                header_prefix: spec.header_prefix,
                secret_value: Zeroizing::new(spec.secret_value),
            };
            state.credentials.lock().await.register_secret(vaulted);
            Ok(format!("updated vaulted credential `{cred_id}`"))
        }
        ProxyControlUpdate::RevokeCredential { session_id } => {
            let revoked = state.credentials.lock().await.revoke_session(&session_id);
            Ok(format!(
                "revoked {revoked} leases for session `{session_id}`"
            ))
        }
        ProxyControlUpdate::CutSessionEgress { session_id, reason } => {
            let revoked = state.cut_session_egress(&session_id).await;
            let now_str = SystemClock::new()
                .now_wall()
                .map(|t| t.to_string())
                .unwrap_or_else(|_| "clock-unavailable".to_string());
            tracing::warn!(
                session_id = %session_id,
                revoked_leases = revoked,
                reason = %reason,
                decided_at = %now_str,
                "D-30 session egress cut applied via Local control plane"
            );
            Ok(format!(
                "cut egress for session `{session_id}` (revoked {revoked})"
            ))
        }
        ProxyControlUpdate::SetGlobalKillSwitch { active, reason } => {
            state.set_global_kill_switch(active);
            tracing::warn!(
                active,
                reason = %reason,
                "global proxy kill-switch updated via Local control plane"
            );
            Ok(format!("global kill switch active={active}"))
        }
    }
}

pub async fn apply_local_control_payload<C: ProxyDecisionClient>(
    state: &ProxyGatewayState<C>,
    raw: &[u8],
) -> Result<usize, ProxyError> {
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(0);
    }
    let updates: Vec<ProxyControlUpdate> =
        if let Ok(batch) = serde_json::from_slice::<ControlUpdateBatch>(raw) {
            batch.updates
        } else if let Ok(list) = serde_json::from_slice::<Vec<ProxyControlUpdate>>(raw) {
            list
        } else {
            let single = serde_json::from_slice::<ProxyControlUpdate>(raw).map_err(|e| {
                ProxyError::Sr39Rejected(format!("invalid local control payload JSON: {e}"))
            })?;
            vec![single]
        };

    let mut applied = 0usize;
    for update in updates {
        let _ = apply_local_control_update(state, update).await?;
        applied = applied.saturating_add(1);
    }
    Ok(applied)
}

pub async fn poll_daemon_local_once<C: ProxyDecisionClient>(
    client: &IpcProxyDecisionClient,
    state: &ProxyGatewayState<C>,
) -> Result<usize, ProxyError> {
    let payload = client.fetch_local_control_payload().await?;
    apply_local_control_payload(state, &payload).await
}
