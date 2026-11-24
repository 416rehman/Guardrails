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
