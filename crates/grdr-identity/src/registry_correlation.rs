// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::attest::AgentInstanceRecord;
use crate::spiffe::SpiffeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRegistryKind {
    MicrosoftEntraAgentId,
    MicrosoftAgent365,
    OktaUniversalDirectory,
    AwsAgentCore,
    GoogleCloudWorkload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agent365LicenseState {
    Licensed,
    UnlicensedDegraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRegistryRecord {
    pub provider: ExternalRegistryKind,
    pub canonical_id: String,
    pub spiffe_id: Option<String>,
    pub aid_id: Option<String>,
    pub external_app_id: Option<String>,
    pub sponsor_id: Option<String>,
    pub display_name: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedPair {
    pub local_agi_id: String,
    pub local_spiffe_id: String,
    pub provider: ExternalRegistryKind,
    pub canonical_id: String,
    pub matched_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCorrelationReport {
    pub correlated: Vec<CorrelatedPair>,
    pub unmatched_local_agi_ids: Vec<String>,
    pub unmanaged_external_ids: Vec<String>,
    pub agent365_license_state: Agent365LicenseState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntraTokenClaims {
    pub oid: String,
    pub azp: Option<String>,
    pub appid: Option<String>,
    pub xms_act_fct: Option<String>,
    pub xms_sub_fct: Option<String>,
    pub xms_idrel: Option<String>,
    pub spiffe_id: Option<String>,
    pub sponsor_oid: Option<String>,
    pub display_name: String,
}

pub fn normalize_entra_agent_id(
    claims: &EntraTokenClaims,
) -> Result<ExternalRegistryRecord, IdentityError> {
    if claims.oid.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "Entra Agent ID claims require non-empty oid".to_string(),
        ));
    }
    let mut attributes = BTreeMap::new();
    if let Some(v) = &claims.xms_act_fct {
        attributes.insert("xms_act_fct".to_string(), v.clone());
    }
    if let Some(v) = &claims.xms_sub_fct {
        attributes.insert("xms_sub_fct".to_string(), v.clone());
    }
    if let Some(v) = &claims.xms_idrel {
        attributes.insert("xms_idrel".to_string(), v.clone());
    }
    let app_id = claims.azp.clone().or_else(|| claims.appid.clone());
    Ok(ExternalRegistryRecord {
        provider: ExternalRegistryKind::MicrosoftEntraAgentId,
        canonical_id: claims.oid.clone(),
        spiffe_id: claims.spiffe_id.clone(),
        aid_id: None,
        external_app_id: app_id,
        sponsor_id: claims.sponsor_oid.clone(),
        display_name: claims.display_name.clone(),
        attributes,
    })
}

pub fn normalize_agent365_entry(
    blueprint_id: &str,
    spiffe_id: Option<String>,
    aid_id: Option<String>,
    display_name: &str,
    licensed: bool,
) -> Result<(ExternalRegistryRecord, Agent365LicenseState), IdentityError> {
    if blueprint_id.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "Agent 365 blueprint_id cannot be empty".to_string(),
        ));
    }
    let state = if licensed {
        Agent365LicenseState::Licensed
    } else {
        Agent365LicenseState::UnlicensedDegraded
    };
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "agent365_licensed".to_string(),
        if licensed { "true" } else { "false" }.to_string(),
    );
    Ok((
        ExternalRegistryRecord {
            provider: ExternalRegistryKind::MicrosoftAgent365,
            canonical_id: blueprint_id.to_owned(),
            spiffe_id,
            aid_id,
            external_app_id: Some(blueprint_id.to_owned()),
            sponsor_id: None,
            display_name: display_name.to_owned(),
            attributes,
        },
        state,
    ))
}

pub fn normalize_okta_ud_agent(
    okta_id: &str,
    aid_id: Option<String>,
    spiffe_id: Option<String>,
    sponsor_id: Option<String>,
    display_name: &str,
) -> Result<ExternalRegistryRecord, IdentityError> {
    if okta_id.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "Okta UD agent id cannot be empty".to_string(),
        ));
    }
    Ok(ExternalRegistryRecord {
        provider: ExternalRegistryKind::OktaUniversalDirectory,
        canonical_id: okta_id.to_owned(),
        spiffe_id,
        aid_id,
        external_app_id: Some(okta_id.to_owned()),
        sponsor_id,
        display_name: display_name.to_owned(),
        attributes: BTreeMap::new(),
    })
}

pub fn normalize_aws_agentcore_arn(
    arn: &str,
    spiffe_id: Option<String>,
    display_name: &str,
) -> Result<ExternalRegistryRecord, IdentityError> {
    let trimmed = arn.trim();
    if !trimmed.starts_with("arn:aws:bedrock-agentcore:") {
        return Err(IdentityError::InvalidSpiffeId(
            "AWS AgentCore ARN must begin with arn:aws:bedrock-agentcore:".to_string(),
        ));
    }
    Ok(ExternalRegistryRecord {
        provider: ExternalRegistryKind::AwsAgentCore,
        canonical_id: trimmed.to_owned(),
        spiffe_id,
        aid_id: None,
        external_app_id: Some(trimmed.to_owned()),
        sponsor_id: None,
        display_name: display_name.to_owned(),
        attributes: BTreeMap::new(),
    })
}

pub fn normalize_google_workload(
    principal_id: &str,
    spiffe_id: &str,
    display_name: &str,
) -> Result<ExternalRegistryRecord, IdentityError> {
    if principal_id.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "Google workload record requires non-empty principal_id".to_string(),
        ));
    }
    let parsed_spiffe = SpiffeId::parse(spiffe_id.trim())?;
    Ok(ExternalRegistryRecord {
        provider: ExternalRegistryKind::GoogleCloudWorkload,
        canonical_id: principal_id.to_owned(),
        spiffe_id: Some(parsed_spiffe.as_str().to_owned()),
        aid_id: None,
        external_app_id: Some(principal_id.to_owned()),
        sponsor_id: None,
        display_name: display_name.to_owned(),
        attributes: BTreeMap::new(),
    })
}

#[must_use]
pub fn correlate_registry_records(
    local_instances: &[AgentInstanceRecord],
    external_records: &[ExternalRegistryRecord],
    agent365_license_state: Agent365LicenseState,
) -> RegistryCorrelationReport {
    let mut correlated = Vec::new();
    let mut matched_local = Vec::new();
    let mut matched_ext = Vec::new();

    for (ext_idx, ext) in external_records.iter().enumerate() {
        for local in local_instances {
            let match_kind = if ext
                .spiffe_id
                .as_deref()
                .is_some_and(|sid| sid == local.spiffe_id.as_str())
            {
                Some("spiffe_id")
            } else if ext
                .aid_id
                .as_deref()
                .is_some_and(|aid| local.aid_id.as_deref() == Some(aid))
            {
                Some("aid_id")
            } else if ext.canonical_id == local.agi_id {
                Some("agi_id")
            } else {
                None
            };

            if let Some(matched_by) = match_kind {
                correlated.push(CorrelatedPair {
                    local_agi_id: local.agi_id.clone(),
                    local_spiffe_id: local.spiffe_id.as_str().to_owned(),
                    provider: ext.provider,
                    canonical_id: ext.canonical_id.clone(),
                    matched_by: matched_by.to_string(),
                });
                matched_local.push(local.agi_id.clone());
                matched_ext.push(ext_idx);
            }
        }
    }

    let unmatched_local_agi_ids = local_instances
        .iter()
        .filter(|inst| !matched_local.contains(&inst.agi_id))
        .map(|inst| inst.agi_id.clone())
        .collect();
    let unmanaged_external_ids = external_records
        .iter()
        .enumerate()
        .filter(|(idx, _)| !matched_ext.contains(idx))
        .map(|(_, ext)| ext.canonical_id.clone())
        .collect();

    RegistryCorrelationReport {
        correlated,
        unmatched_local_agi_ids,
        unmanaged_external_ids,
        agent365_license_state,
    }
}
