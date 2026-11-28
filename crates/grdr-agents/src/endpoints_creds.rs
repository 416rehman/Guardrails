// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 4 model endpoint learner and secret-free credential reference inventory (`docs/design/05`).

use std::collections::BTreeMap;

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

pub use crate::cred_inventory::{
    CredentialExposure, CredentialInventoryRecord, CredentialLocatorSpec, CredentialStoreKind,
    build_credential_inventory_record, load_embedded_credential_locators,
};
use crate::endpoints_pack::{classify_api_shape, load_model_endpoints_pack};

const MIN_SALT_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelEndpointState {
    Declared,
    Learned,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelEndpointBasis {
    DeclaredPack,
    ExplicitListenerApiShape,
    RuntimeListener,
    FleetRuntimeListener,
    EnvBaseUrl,
    ConfigFile,
    TriageConfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEndpointRecord {
    pub id: String,
    pub provider: String,
    pub origin: String,
    pub model_or_deployment: Option<String>,
    pub tenant_marker: Option<String>,
    pub tls_issuer_spki: Option<String>,
    pub state: ModelEndpointState,
    pub basis: ModelEndpointBasis,
    pub contact_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEndpointRegistry {
    org_salt: Vec<u8>,
    endpoints: BTreeMap<String, ModelEndpointRecord>,
}

impl ModelEndpointRegistry {
    pub fn new(org_salt: &[u8]) -> Result<Self, CodedError> {
        validate_org_salt(org_salt)?;
        Ok(Self {
            org_salt: org_salt.to_vec(),
            endpoints: BTreeMap::new(),
        })
    }

    pub fn declare_endpoint(
        &mut self,
        provider: &str,
        origin: &str,
        tenant_marker: Option<&str>,
        tls_issuer_spki: Option<&str>,
    ) -> ModelEndpointRecord {
        let key = origin.trim().to_ascii_lowercase();
        let rec = ModelEndpointRecord {
            id: endpoint_id(&self.org_salt, &key),
            provider: provider.into(),
            origin: key.clone(),
            model_or_deployment: None,
            tenant_marker: tenant_marker.map(str::to_owned),
            tls_issuer_spki: tls_issuer_spki.map(str::to_owned),
            state: ModelEndpointState::Declared,
            basis: ModelEndpointBasis::DeclaredPack,
            contact_count: 0,
        };
        self.endpoints.insert(key, rec.clone());
        rec
    }

    pub fn learn_from_http_shape(
        &mut self,
        origin: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Option<ModelEndpointRecord>, CodedError> {
        let Some(provider) = classify_api_shape(path, headers)? else {
            return Ok(None);
        };
        Ok(Some(self.insert_learned(
            origin,
            provider,
            ModelEndpointBasis::ExplicitListenerApiShape,
        )))
    }

    pub fn learn_from_fleet_runtime_listener(
        &mut self,
        host_port: &str,
        runtime_kind: &str,
    ) -> ModelEndpointRecord {
        self.insert_learned(
            host_port,
            runtime_kind,
            ModelEndpointBasis::FleetRuntimeListener,
        )
    }

    pub fn learn_from_env_base_url(
        &mut self,
        env_var_name: &str,
        raw_url: &str,
    ) -> Result<Option<ModelEndpointRecord>, CodedError> {
        let pack = load_model_endpoints_pack()?;
        if !pack
            .base_url_allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(env_var_name.trim()))
        {
            return Ok(None);
        }
        let Some(host) = extract_host_only(raw_url) else {
            return Ok(None);
        };
        Ok(Some(self.insert_learned(
            &host,
            env_var_name,
            ModelEndpointBasis::EnvBaseUrl,
        )))
    }

    pub fn learn_from_config_file(
        &mut self,
        provider: &str,
        raw_url: &str,
    ) -> Option<ModelEndpointRecord> {
        let host = extract_host_only(raw_url)?;
        Some(self.insert_learned(&host, provider, ModelEndpointBasis::ConfigFile))
    }

    pub fn reject_endpoint(&mut self, origin: &str) -> Result<String, CodedError> {
        let key = origin.trim().to_ascii_lowercase();
        let Some(rec) = self.endpoints.get_mut(&key) else {
            return Err(CodedError::new(
                "GRDR-AGENTS-0005",
                format!("unknown model endpoint `{origin}`"),
                "Register or learn the endpoint before rejecting it.",
            ));
        };
        rec.state = ModelEndpointState::Rejected;
        Ok("audit.admin".into())
    }

    pub fn record_contact(&mut self, origin: &str) -> bool {
        let key = origin.trim().to_ascii_lowercase();
        let Some(rec) = self.endpoints.get_mut(&key) else {
            return false;
        };
        rec.contact_count = rec.contact_count.saturating_add(1);
        rec.state != ModelEndpointState::Rejected
    }

    #[must_use]
    pub fn in_inference_set(&self, origin: &str) -> bool {
        let key = origin.trim().to_ascii_lowercase();
        self.endpoints
            .get(&key)
            .is_some_and(|r| r.state != ModelEndpointState::Rejected)
    }

    #[must_use]
    pub fn list(&self) -> Vec<&ModelEndpointRecord> {
        self.endpoints.values().collect()
    }

    fn insert_learned(
        &mut self,
        origin: &str,
        provider: &str,
        basis: ModelEndpointBasis,
    ) -> ModelEndpointRecord {
        let key = origin.trim().to_ascii_lowercase();
        if let Some(existing) = self.endpoints.get(&key)
            && existing.state != ModelEndpointState::Learned
        {
            return existing.clone();
        }
        let rec = ModelEndpointRecord {
            id: endpoint_id(&self.org_salt, &key),
            provider: provider.into(),
            origin: key.clone(),
            model_or_deployment: None,
            tenant_marker: tenant_marker_from_basis(&key),
            tls_issuer_spki: None,
            state: ModelEndpointState::Learned,
            basis,
            contact_count: 0,
        };
        self.endpoints.insert(key, rec.clone());
        rec
    }
}

fn tenant_marker_from_basis(_origin: &str) -> Option<String> {
    None
}

fn extract_host_only(raw_url: &str) -> Option<String> {
    let without_scheme = raw_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw_url.trim().strip_prefix("http://"))
        .unwrap_or(raw_url.trim());
    let before_query = without_scheme.split(['?', '#']).next().unwrap_or("");
    let authority = before_query.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let clean = host_port.trim().to_ascii_lowercase();
    if clean.is_empty() { None } else { Some(clean) }
}

fn validate_org_salt(org_salt: &[u8]) -> Result<(), CodedError> {
    if org_salt.len() < MIN_SALT_BYTES {
        return Err(CodedError::new(
            "GRDR-AGENTS-0005",
            format!(
                "organization HMAC salt must be at least {MIN_SALT_BYTES} bytes, got {}",
                org_salt.len()
            ),
            "Provide at least 32 random bytes for P8 endpoint/credential pseudonymization.",
        ));
    }
    Ok(())
}

fn endpoint_id(org_salt: &[u8], origin: &str) -> String {
    let mac = domain_hmac_sha256(org_salt, "grdr.model.endpoint.v1", origin.as_bytes());
    let hex = encode_lower_hex(&mac);
    format!("mdl_{}", hex.get(..12).unwrap_or(hex.as_str()))
}
