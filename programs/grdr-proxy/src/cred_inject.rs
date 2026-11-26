// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Inject-mode credential substitution powered by `grdr-identity::CredentialBroker`.
//! Real upstream credentials stay vaulted in memory (`Zeroizing`) and are never exposed
//! to child sessions or logs.

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};
use jiff::Timestamp;
use zeroize::Zeroizing;

use grdr_identity::{
    BrokerPolicy, BrokerRequest, Ceiling, CredentialBinding, CredentialBroker, CredentialClass,
    CredentialMode, SpiffeId,
};

use grdr_crypto::constant_time_eq;

use crate::ProxyError;
use crate::sr39::SessionRegistration;

#[derive(Clone)]
pub struct VaultedUpstreamSecret {
    pub binding: CredentialBinding,
    pub ceiling: Ceiling,
    pub header_name: String,
    pub header_prefix: String,
    pub secret_value: Zeroizing<String>,
}

pub struct ProxyCredentialManager {
    broker: CredentialBroker,
    vault: BTreeMap<String, VaultedUpstreamSecret>,
}

impl std::fmt::Debug for VaultedUpstreamSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultedUpstreamSecret")
            .field("credential_id", &self.binding.credential_id)
            .field("header_name", &self.header_name)
            .field("secret_value", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for ProxyCredentialManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentialManager")
            .field("vaulted_count", &self.vault.len())
            .finish()
    }
}

impl Default for ProxyCredentialManager {
    fn default() -> Self {
        Self::new(BrokerPolicy::default())
    }
}

impl ProxyCredentialManager {
    #[must_use]
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            broker: CredentialBroker::new(policy),
            vault: BTreeMap::new(),
        }
    }

    pub fn register_secret(&mut self, entry: VaultedUpstreamSecret) {
        self.vault
            .insert(entry.binding.credential_id.clone(), entry);
    }

    pub fn revoke_session(&mut self, session_id: &str) -> usize {
        self.broker.revoke_by_session(session_id)
    }

    /// Strips any inbound caller `authorization` / `x-api-key` headers carrying phantom or
    /// guessed credentials, validates a `CredentialMode::Inject` lease through
    /// `CredentialBroker`, checks `allowed_hosts`, and injects the vaulted upstream secret.
    pub fn inject_for_route(
        &mut self,
        reg: &SessionRegistration,
        credential_id: &str,
        upstream_host: &str,
        inbound_headers: &HeaderMap,
        outbound_headers: &mut HeaderMap,
        now: Timestamp,
    ) -> Result<String, ProxyError> {
        let entry = self.vault.get(credential_id).ok_or_else(|| {
            ProxyError::CredentialDenied(format!("unknown credential_id `{credential_id}`"))
        })?;

        if !entry
            .binding
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(upstream_host))
        {
            return Err(ProxyError::CredentialDenied(format!(
                "upstream host `{upstream_host}` is not permitted for credential `{credential_id}`"
            )));
        }

        let expected_phantom = reg
            .expected_phantom_tokens
            .get(credential_id)
            .ok_or_else(|| {
                ProxyError::CredentialDenied(format!(
                    "session `{}` holds no issued phantom lease for credential `{credential_id}`",
                    reg.session_id
                ))
            })?;
        let presented =
            extract_presented_token(inbound_headers, &entry.header_name).ok_or_else(|| {
                ProxyError::CredentialDenied(format!(
                    "missing caller phantom token in `{}` header",
                    entry.header_name
                ))
            })?;
        if !presented.starts_with(&entry.binding.phantom_prefix)
            || !constant_time_eq(presented.as_bytes(), expected_phantom.as_bytes())
        {
            return Err(ProxyError::CredentialDenied(
                "caller phantom token mismatch or wrong prefix".into(),
            ));
        }

        let spiffe_id = SpiffeId::parse(&reg.spiffe_id)
            .map_err(|e| ProxyError::CredentialDenied(e.to_string()))?;

        let broker_req = BrokerRequest {
            session_id: reg.session_id.clone(),
            instance_spiffe_id: spiffe_id,
            device_id: reg.device_id.clone(),
            caller_program: reg.caller_program.clone(),
            requested_class: entry.binding.class,
            requested_action: "invoke".into(),
            requested_resource: format!("https://{upstream_host}/"),
            requested_mode: CredentialMode::Inject,
            requested_ttl_secs: 300,
            session_remaining_secs: 3600,
            attribution_grade: reg.attribution_grade,
            has_session_container: reg.has_session_container,
            containment: reg.containment,
            lifecycle: reg.lifecycle,
            ceiling: Some(entry.ceiling.clone()),
            act_chain_depth: 0,
            dpop_jkt: None,
        };

        let brokered = self
            .broker
            .request_credential(&entry.binding, &broker_req, now)
            .map_err(|e| ProxyError::CredentialDenied(e.to_string()))?;

        let hdr_name = HeaderName::from_bytes(entry.header_name.as_bytes())
            .map_err(|e| ProxyError::Transport(format!("invalid auth header name: {e}")))?;
        let combined = Zeroizing::new(format!("{}{}", entry.header_prefix, *entry.secret_value));
        let hdr_val = HeaderValue::from_str(&combined)
            .map_err(|e| ProxyError::Transport(format!("invalid secret header format: {e}")))?;

        while outbound_headers.remove(&hdr_name).is_some() {}
        outbound_headers.insert(hdr_name, hdr_val);

        Ok(brokered.lease_id)
    }
}

fn extract_presented_token<'a>(headers: &'a HeaderMap, header_name: &str) -> Option<&'a str> {
    let val = headers.get(header_name)?.to_str().ok()?.trim();
    if let Some(bearer) = val
        .strip_prefix("Bearer ")
        .or_else(|| val.strip_prefix("bearer "))
    {
        Some(bearer.trim())
    } else {
        Some(val)
    }
}

#[must_use]
pub fn model_class_ceiling(account_id: &str, host: &str) -> Ceiling {
    let mut classes = std::collections::BTreeSet::new();
    classes.insert(CredentialClass::Model);
    let mut accounts = std::collections::BTreeSet::new();
    accounts.insert(account_id.to_owned());
    let mut actions = std::collections::BTreeSet::new();
    actions.insert("invoke".into());
    Ceiling {
        allowed_classes: classes,
        allowed_accounts: accounts,
        allowed_actions: actions,
        allowed_resource_prefixes: vec![format!("https://{host}/")],
        max_ttl_secs: 900,
        max_depth: 1,
    }
}
