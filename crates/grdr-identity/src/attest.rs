// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, constant_time_eq, verify_bytes};
use grdr_model::InstallProfile;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::spiffe::{
    AgentLifecycle, AttestationEvidence, IdentityProof, LocalAttestation, SpiffeId,
    evaluate_attestation_proof,
};

const ATTESTATION_SIG_DOMAIN: &str = "grdr.identity.attest.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedWorkloadSource {
    SpireFederation,
    KubernetesOidc,
    GitHubActionsOidc,
    GitLabOidc,
    AwsIrsa,
    GcpWif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceSponsorKind {
    HumanUser,
    ServiceAccount,
    DeploymentPipeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorState {
    Active,
    Suspended,
    Deprovisioned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootKeyCertificate {
    pub device_id: String,
    pub boot_id: String,
    pub key_id: String,
    pub public_key_b64: String,
    pub issued_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLocalAttestation {
    pub attestation: LocalAttestation,
    pub boot_pubkey_b64: String,
    pub key_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedWorkloadClaim {
    pub source: FederatedWorkloadSource,
    pub issuer: String,
    pub subject: String,
    pub trust_domain: String,
    pub cluster_or_repo: String,
    pub workload_ref: String,
    pub digest: Option<String>,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorRef {
    pub sponsor_id: String,
    pub sponsor_kind: InstanceSponsorKind,
    pub state: SponsorState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorTransfer {
    pub target_sponsor: SponsorRef,
    pub initiated_by: String,
    pub initiated_at: Timestamp,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredSeenEvent {
    pub event_kind: String,
    pub agi_id: String,
    pub spiffe_id: String,
    pub session_id: String,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstanceRecord {
    pub agi_id: String,
    pub aid_id: Option<String>,
    pub spiffe_id: SpiffeId,
    pub lifecycle: AgentLifecycle,
    pub sponsor: Option<SponsorRef>,
    pub pending_transfer: Option<SponsorTransfer>,
    pub retired_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstanceAliasMap {
    local_to_org: BTreeMap<String, String>,
}

pub fn sign_local_attestation(
    attestation: LocalAttestation,
    keypair: &SigningKeypair,
) -> Result<SignedLocalAttestation, IdentityError> {
    let payload = serde_json::to_vec(&attestation)
        .map_err(|e| IdentityError::VaultState(format!("serialize attestation failed: {e}")))?;
    let signature_b64 = keypair.sign_bytes(ATTESTATION_SIG_DOMAIN, &payload);
    Ok(SignedLocalAttestation {
        attestation,
        boot_pubkey_b64: keypair.public_key_b64(),
        key_id: keypair.key_id().to_owned(),
        signature_b64,
    })
}

pub fn verify_signed_local_attestation(
    signed: &SignedLocalAttestation,
    expected_program_identity: &str,
    device_key_enrolled: bool,
    trusted_boot_pubkey_b64: Option<&str>,
) -> Result<IdentityProof, IdentityError> {
    let expected_pk = trusted_boot_pubkey_b64
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            IdentityError::VaultState(
                "enrolled trusted boot public key is required for verification".to_string(),
            )
        })?;
    if !constant_time_eq(
        expected_pk.as_bytes(),
        signed.boot_pubkey_b64.trim().as_bytes(),
    ) {
        return Err(IdentityError::VaultState(
            "attestation boot public key does not match enrolled key".to_string(),
        ));
    }
    let payload = serde_json::to_vec(&signed.attestation)
        .map_err(|e| IdentityError::VaultState(format!("serialize attestation failed: {e}")))?;
    verify_bytes(
        &signed.boot_pubkey_b64,
        ATTESTATION_SIG_DOMAIN,
        &payload,
        &signed.signature_b64,
    )
    .map_err(|e| IdentityError::VaultState(format!("invalid attestation signature: {e}")))?;

    if signed.attestation.profile != InstallProfile::Protected {
        return Ok(IdentityProof::Observed);
    }
    if signed.attestation.evidence == [AttestationEvidence::ExecTag] {
        return Ok(IdentityProof::Observed);
    }
    Ok(evaluate_attestation_proof(
        &signed.attestation,
        expected_program_identity,
        device_key_enrolled,
    ))
}

pub fn verify_federated_workload_claim(
    claim: &FederatedWorkloadClaim,
    trusted_issuers: &[String],
    now: Timestamp,
) -> Result<SpiffeId, IdentityError> {
    if claim.expires_at <= now {
        return Err(IdentityError::InvalidSpiffeId(
            "federated workload assertion expired".to_string(),
        ));
    }
    if claim.issuer.trim().is_empty()
        || claim.subject.trim().is_empty()
        || !trusted_issuers
            .iter()
            .any(|trusted| trusted == claim.issuer.trim())
    {
        return Err(IdentityError::InvalidSpiffeId(
            "untrusted federated workload issuer".to_string(),
        ));
    }
    let kind = match claim.source {
        FederatedWorkloadSource::SpireFederation => "spire",
        FederatedWorkloadSource::KubernetesOidc => "k8s",
        FederatedWorkloadSource::GitHubActionsOidc => "gh-actions",
        FederatedWorkloadSource::GitLabOidc => "gitlab",
        FederatedWorkloadSource::AwsIrsa => "aws-irsa",
        FederatedWorkloadSource::GcpWif => "gcp-wif",
    };
    let clean_scope = normalize_workload_segment(&claim.cluster_or_repo)?;
    let clean_ref = normalize_workload_segment(&claim.workload_ref)?;
    let workload_id = format!("{clean_scope}.{clean_ref}");
    SpiffeId::workload(&claim.trust_domain, kind, &workload_id)
}

fn normalize_workload_segment(raw: &str) -> Result<String, IdentityError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(IdentityError::InvalidSpiffeId(
            "workload segment cannot be empty or dot traversal".to_string(),
        ));
    }
    let mut encoded = String::with_capacity(trimmed.len().saturating_mul(2));
    for byte in trimmed.bytes() {
        if byte == b'_' {
            encoded.push_str("__");
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('_');
            encoded.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            encoded.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
    }
    if encoded.len() > 255 || encoded == "." || encoded == ".." {
        return Err(IdentityError::InvalidSpiffeId(
            "encoded workload segment exceeds bounds or invalid".to_string(),
        ));
    }
    Ok(encoded)
}

impl AgentInstanceRecord {
    #[must_use]
    pub fn new_discovered(agi_id: impl Into<String>, spiffe_id: SpiffeId) -> Self {
        Self {
            agi_id: agi_id.into(),
            aid_id: None,
            spiffe_id,
            lifecycle: AgentLifecycle::Discovered,
            sponsor: None,
            pending_transfer: None,
            retired_at: None,
        }
    }

    pub fn transition_lifecycle(
        &mut self,
        next: AgentLifecycle,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        if self.lifecycle == AgentLifecycle::Retired {
            return Err(IdentityError::InstanceNotActive(AgentLifecycle::Retired));
        }
        if next == AgentLifecycle::Active {
            let has_active_sponsor = self
                .sponsor
                .as_ref()
                .is_some_and(|s| s.state == SponsorState::Active);
            if !has_active_sponsor {
                return Err(IdentityError::VaultState(
                    "active human or service sponsor required before instance activation"
                        .to_string(),
                ));
            }
        }
        match (self.lifecycle, next) {
            (AgentLifecycle::Discovered, AgentLifecycle::Active | AgentLifecycle::Orphaned)
            | (AgentLifecycle::Active, AgentLifecycle::Suspended | AgentLifecycle::Orphaned)
            | (AgentLifecycle::Suspended, AgentLifecycle::Active | AgentLifecycle::Orphaned)
            | (AgentLifecycle::Orphaned, AgentLifecycle::Active) => {
                self.lifecycle = next;
                Ok(())
            }
            (_, AgentLifecycle::Retired) => {
                self.lifecycle = AgentLifecycle::Retired;
                self.retired_at = Some(now);
                Ok(())
            }
            _ => Err(IdentityError::InstanceNotActive(self.lifecycle)),
        }
    }

    pub fn initiate_sponsor_transfer(
        &mut self,
        target: SponsorRef,
        initiated_by: impl Into<String>,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        if self.lifecycle == AgentLifecycle::Retired {
            return Err(IdentityError::InstanceNotActive(AgentLifecycle::Retired));
        }
        if target.state != SponsorState::Active || target.sponsor_id.trim().is_empty() {
            return Err(IdentityError::VaultState(
                "target sponsor must be active and non-empty".to_string(),
            ));
        }
        self.pending_transfer = Some(SponsorTransfer {
            target_sponsor: target,
            initiated_by: initiated_by.into(),
            initiated_at: now,
            accepted: false,
        });
        Ok(())
    }

    pub fn accept_sponsor_transfer(
        &mut self,
        accepting_sponsor_id: &str,
    ) -> Result<(), IdentityError> {
        if self.lifecycle == AgentLifecycle::Retired {
            return Err(IdentityError::InstanceNotActive(AgentLifecycle::Retired));
        }
        let Some(mut transfer) = self.pending_transfer.take() else {
            return Err(IdentityError::VaultState(
                "no pending sponsor transfer exists".to_string(),
            ));
        };
        if transfer.target_sponsor.sponsor_id != accepting_sponsor_id {
            self.pending_transfer = Some(transfer);
            return Err(IdentityError::VaultState(
                "accepting sponsor does not match pending transfer target".to_string(),
            ));
        }
        transfer.accepted = true;
        self.sponsor = Some(transfer.target_sponsor);
        if self.lifecycle == AgentLifecycle::Orphaned {
            self.lifecycle = AgentLifecycle::Active;
        }
        Ok(())
    }

    #[must_use]
    pub fn observe_runtime_session(
        &self,
        session_id: &str,
        now: Timestamp,
    ) -> Option<RetiredSeenEvent> {
        if self.lifecycle != AgentLifecycle::Retired {
            return None;
        }
        Some(RetiredSeenEvent {
            event_kind: "identity.retired-seen".to_string(),
            agi_id: self.agi_id.clone(),
            spiffe_id: self.spiffe_id.as_str().to_owned(),
            session_id: session_id.to_owned(),
            observed_at: now,
        })
    }
}

impl AgentInstanceAliasMap {
    pub fn record_join_alias(
        &mut self,
        local_agi_id: &str,
        enrolled_spiffe_id: &SpiffeId,
    ) -> Result<(), IdentityError> {
        if local_agi_id.trim().is_empty() {
            return Err(IdentityError::InvalidSpiffeId(
                "local agi_id cannot be empty".to_string(),
            ));
        }
        self.local_to_org.insert(
            local_agi_id.to_owned(),
            enrolled_spiffe_id.as_str().to_owned(),
        );
        Ok(())
    }

    #[must_use]
    pub fn resolve_enrolled_id(&self, local_agi_id: &str) -> Option<&str> {
        self.local_to_org.get(local_agi_id).map(String::as_str)
    }
}
