// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use grdr_model::InstallProfile;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IdentityError;

pub const MAX_SPIFFE_ID_BYTES: usize = 2048;
const SPIFFE_SCHEME: &str = "spiffe://";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    uri: String,
    trust_domain: String,
    path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityProof {
    Observed,
    SelfAsserted,
    IdpIssued,
    Attested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    Discovered,
    Active,
    Suspended,
    Orphaned,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainmentMode {
    None,
    Delegate,
    WrapTools,
    WrapAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEvidence {
    SessionContainer,
    ExecTag,
    KernelPeerHandle,
    SignedExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAttestation {
    pub process_key: String,
    pub program_identity: String,
    pub session_id: String,
    pub container_ref: Option<String>,
    pub lineage_grade: u8,
    pub evidence: Vec<AttestationEvidence>,
    pub profile: InstallProfile,
    pub attested_at: Timestamp,
    pub boot_id: String,
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl SpiffeId {
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        if raw.len() > MAX_SPIFFE_ID_BYTES {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "exceeds {MAX_SPIFFE_ID_BYTES} bytes"
            )));
        }
        let Some(rest) = raw.strip_prefix(SPIFFE_SCHEME) else {
            return Err(IdentityError::InvalidSpiffeId(
                "must start with spiffe://".into(),
            ));
        };
        if rest.contains('?') || rest.contains('#') || rest.contains('@') {
            return Err(IdentityError::InvalidSpiffeId(
                "query, fragment, and userinfo are forbidden".into(),
            ));
        }

        let (trust_domain, path) = match rest.split_once('/') {
            Some((td, p)) => (td, format!("/{p}")),
            None => (rest, String::new()),
        };

        if trust_domain.is_empty() || trust_domain.contains(':') {
            return Err(IdentityError::InvalidSpiffeId(
                "trust domain must be non-empty and must not carry a port".into(),
            ));
        }
        if !trust_domain.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        }) {
            return Err(IdentityError::InvalidSpiffeId(
                "trust domain contains invalid characters".into(),
            ));
        }
        if !path.is_empty()
            && path
                .split('/')
                .skip(1)
                .any(|seg| !is_valid_spiffe_segment(seg))
        {
            return Err(IdentityError::InvalidSpiffeId(
                "path segments must use [A-Za-z0-9._-] and cannot be empty, `.`, or `..`".into(),
            ));
        }

        Ok(Self {
            uri: raw.to_owned(),
            trust_domain: trust_domain.to_owned(),
            path,
        })
    }

    pub fn agent_instance(org_id: &str, agi_id: &str) -> Result<Self, IdentityError> {
        validate_single_segment(org_id, "org_id")?;
        validate_single_segment(agi_id, "agi_id")?;
        let domain = format!("org-{}", org_id.to_ascii_lowercase());
        let raw = format!("{SPIFFE_SCHEME}{domain}/agi/{agi_id}");
        Self::parse(&raw)
    }

    pub fn session(org_id: &str, agi_id: &str, ses_id: &str) -> Result<Self, IdentityError> {
        validate_single_segment(org_id, "org_id")?;
        validate_single_segment(agi_id, "agi_id")?;
        validate_single_segment(ses_id, "ses_id")?;
        let domain = format!("org-{}", org_id.to_ascii_lowercase());
        let raw = format!("{SPIFFE_SCHEME}{domain}/agi/{agi_id}/ses/{ses_id}");
        Self::parse(&raw)
    }

    pub fn device(org_id: &str, device_id: &str) -> Result<Self, IdentityError> {
        validate_single_segment(org_id, "org_id")?;
        validate_single_segment(device_id, "device_id")?;
        let domain = format!("org-{}", org_id.to_ascii_lowercase());
        let raw = format!("{SPIFFE_SCHEME}{domain}/dev/{device_id}");
        Self::parse(&raw)
    }

    pub fn gateway(org_id: &str, gateway_id: &str) -> Result<Self, IdentityError> {
        validate_single_segment(org_id, "org_id")?;
        validate_single_segment(gateway_id, "gateway_id")?;
        let domain = format!("org-{}", org_id.to_ascii_lowercase());
        let raw = format!("{SPIFFE_SCHEME}{domain}/gw/{gateway_id}");
        Self::parse(&raw)
    }

    pub fn workload(
        trust_domain: &str,
        kind: &str,
        workload_id: &str,
    ) -> Result<Self, IdentityError> {
        validate_single_segment(kind, "kind")?;
        validate_single_segment(workload_id, "workload_id")?;
        let domain = trust_domain.to_ascii_lowercase();
        let raw = format!("{SPIFFE_SCHEME}{domain}/wl/{kind}/{workload_id}");
        Self::parse(&raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[must_use]
pub fn evaluate_attestation_proof(
    attestation: &LocalAttestation,
    expected_program_identity: &str,
    device_key_enrolled: bool,
) -> IdentityProof {
    if attestation.profile != InstallProfile::Protected || !device_key_enrolled {
        return IdentityProof::Observed;
    }
    if expected_program_identity.trim().is_empty()
        || attestation.program_identity != expected_program_identity
    {
        return IdentityProof::Observed;
    }
    let has_container = attestation
        .evidence
        .contains(&AttestationEvidence::SessionContainer);
    let valid_container_ref = attestation
        .container_ref
        .as_deref()
        .is_some_and(|c| !c.trim().is_empty());
    if has_container && valid_container_ref {
        IdentityProof::Attested
    } else {
        IdentityProof::Observed
    }
}

fn is_valid_spiffe_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn validate_single_segment(value: &str, label: &str) -> Result<(), IdentityError> {
    if value.contains('/') || !is_valid_spiffe_segment(value) {
        return Err(IdentityError::InvalidSpiffeId(format!(
            "invalid {label} segment `{value}`"
        )));
    }
    Ok(())
}

fn append_len_prefixed(dst: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    dst.extend_from_slice(&len.to_le_bytes());
    dst.extend_from_slice(bytes);
    dst.push(0);
}

#[must_use]
pub fn derive_agi_id(device_key: &[u8; 32], binary_sha256: &str, config_hash: &str) -> String {
    let mut payload = Vec::with_capacity(
        16_usize
            .saturating_add(binary_sha256.len())
            .saturating_add(config_hash.len()),
    );
    append_len_prefixed(&mut payload, binary_sha256.as_bytes());
    append_len_prefixed(&mut payload, config_hash.as_bytes());
    let mac = grdr_crypto::domain_hmac_sha256(device_key, "grdr.identity.agi.v1", &payload);
    let hex = grdr_crypto::encode_lower_hex(&mac);
    format!("agi_{}", hex.get(..32).unwrap_or(&hex))
}

#[must_use]
pub fn derive_aid_id(org_key: &[u8; 32], agi_id: &str, epoch: u32) -> String {
    let mut payload = Vec::with_capacity(16_usize.saturating_add(agi_id.len()));
    append_len_prefixed(&mut payload, &epoch.to_le_bytes());
    append_len_prefixed(&mut payload, agi_id.as_bytes());
    let mac = grdr_crypto::domain_hmac_sha256(org_key, "grdr.identity.aid.v1", &payload);
    let hex = grdr_crypto::encode_lower_hex(&mac);
    format!("aid_{epoch}_{}", hex.get(..32).unwrap_or(&hex))
}

pub fn derive_k8s_workload_key(
    namespace: &str,
    service_account: &str,
    image_digest: &str,
) -> Result<String, IdentityError> {
    validate_single_segment(namespace, "k8s_namespace")?;
    validate_single_segment(service_account, "k8s_service_account")?;
    if image_digest.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "k8s workload requires non-empty image digest".to_string(),
        ));
    }
    let mut payload = Vec::with_capacity(
        32_usize
            .saturating_add(namespace.len())
            .saturating_add(service_account.len())
            .saturating_add(image_digest.len()),
    );
    append_len_prefixed(&mut payload, b"k8s");
    append_len_prefixed(&mut payload, namespace.as_bytes());
    append_len_prefixed(&mut payload, service_account.as_bytes());
    append_len_prefixed(&mut payload, image_digest.as_bytes());
    let hex = grdr_crypto::sha256_hex(&payload);
    Ok(format!("wl_k8s_{}", hex.get(..24).unwrap_or(&hex)))
}

pub fn derive_ci_workload_key(
    issuer: &str,
    repository: &str,
    workflow_ref: &str,
) -> Result<String, IdentityError> {
    if issuer.trim().is_empty() || repository.trim().is_empty() || workflow_ref.trim().is_empty() {
        return Err(IdentityError::InvalidSpiffeId(
            "CI workload key requires non-empty issuer, repository, and workflow_ref".to_string(),
        ));
    }
    let mut payload = Vec::with_capacity(
        32_usize
            .saturating_add(issuer.len())
            .saturating_add(repository.len())
            .saturating_add(workflow_ref.len()),
    );
    append_len_prefixed(&mut payload, b"ci");
    append_len_prefixed(&mut payload, issuer.as_bytes());
    append_len_prefixed(&mut payload, repository.as_bytes());
    append_len_prefixed(&mut payload, workflow_ref.as_bytes());
    let hex = grdr_crypto::sha256_hex(&payload);
    Ok(format!("wl_ci_{}", hex.get(..24).unwrap_or(&hex)))
}
