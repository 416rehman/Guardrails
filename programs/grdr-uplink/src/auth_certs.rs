// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Ephemeral transport key certificates and fleet-signed response certificates (`D-22`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use grdr_crypto::SigningKeypair;
use serde::{Deserialize, Serialize};

use crate::error::UplinkError;
use crate::rfc9421::validate_rfc9421_token;

/// Maximum lifetime permitted on an ephemeral per-epoch transport key certificate (24 hours).
pub const MAX_TRANSPORT_CERT_LIFETIME_S: i64 = 86_400;
/// Maximum lifetime permitted on a `ResponseKeyCertificate` (24 hours per `limits.toml`).
pub const MAX_RESPONSE_CERT_LIFETIME_S: i64 = 86_400;

/// Explicit purpose binding preventing transport keys from forging identity certs and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUse {
    DeviceIdentity,
    Transport,
}

/// Request classification (`CheckIn` binds an explicit anti-replay `nonce`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestKind {
    CheckIn,
    PushBatch,
    CommandPoll,
}

/// Short-lived transport key certificate signed by the privileged daemon's device key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportKeyCertificate {
    pub cert_version: u32,
    pub device_id: String,
    pub deployment_id: String,
    pub transport_key_id: String,
    pub transport_public_key_b64: String,
    pub use_kind: KeyUse,
    pub not_before_unix_s: i64,
    pub not_after_unix_s: i64,
    pub device_key_id: String,
    pub device_signature_b64: String,
}

/// Short-lived fleet response-signing certificate anchored by a pinned fleet key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseKeyCertificate {
    pub cert_version: u32,
    pub fleet_key_id: String,
    pub deployment_id: String,
    pub cell_id: String,
    pub response_key_id: String,
    pub response_public_key_b64: String,
    pub not_before_unix_s: i64,
    pub not_after_unix_s: i64,
    pub fleet_signature_b64: String,
}

impl TransportKeyCertificate {
    /// Sign and issue a bounded ephemeral `TransportKeyCertificate`.
    pub fn issue(
        device_signer: &SigningKeypair,
        device_id: impl Into<String>,
        deployment_id: impl Into<String>,
        transport_keypair: &SigningKeypair,
        not_before_unix_s: i64,
        ttl_s: i64,
    ) -> Result<Self, UplinkError> {
        let device_id = device_id.into();
        let deployment_id = deployment_id.into();
        validate_rfc9421_token("device_id", &device_id)?;
        validate_rfc9421_token("deployment_id", &deployment_id)?;
        if ttl_s <= 0 || ttl_s > MAX_TRANSPORT_CERT_LIFETIME_S {
            return Err(UplinkError::CertificateInvalid {
                reason: format!(
                    "transport cert TTL {ttl_s}s out of bounds (1..={MAX_TRANSPORT_CERT_LIFETIME_S})"
                ),
            });
        }
        let not_after_unix_s = not_before_unix_s.saturating_add(ttl_s);
        let mut cert = Self {
            cert_version: 1,
            device_id,
            deployment_id,
            transport_key_id: transport_keypair.key_id().to_string(),
            transport_public_key_b64: transport_keypair.public_key_b64(),
            use_kind: KeyUse::Transport,
            not_before_unix_s,
            not_after_unix_s,
            device_key_id: device_signer.key_id().to_string(),
            device_signature_b64: String::new(),
        };
        let canonical = cert.canonical_payload()?;
        cert.device_signature_b64 = device_signer.sign_bytes("grdr-transport-cert-v1", &canonical);
        Ok(cert)
    }

    /// Validate structural invariants, version, key usage, bounds, and signature shape.
    pub fn validate(&self, now_unix_s: Option<i64>) -> Result<(), UplinkError> {
        if self.cert_version != 1 {
            return Err(UplinkError::CertificateInvalid {
                reason: format!("unsupported transport cert_version {}", self.cert_version),
            });
        }
        if self.use_kind != KeyUse::Transport {
            return Err(UplinkError::CertificateInvalid {
                reason: "ephemeral signer requires KeyUse::Transport certificate".to_string(),
            });
        }
        validate_rfc9421_token("device_id", &self.device_id)?;
        validate_rfc9421_token("deployment_id", &self.deployment_id)?;
        validate_rfc9421_token("transport_key_id", &self.transport_key_id)?;
        validate_rfc9421_token("device_key_id", &self.device_key_id)?;
        if self.not_after_unix_s <= self.not_before_unix_s
            || self.not_after_unix_s.saturating_sub(self.not_before_unix_s)
                > MAX_TRANSPORT_CERT_LIFETIME_S
        {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport cert lifetime invalid or exceeds 24h maximum".to_string(),
            });
        }
        if let Some(now_s) = now_unix_s
            && (now_s < self.not_before_unix_s || now_s > self.not_after_unix_s)
        {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport key certificate outside valid epoch window".to_string(),
            });
        }
        let pub_raw = STANDARD
            .decode(&self.transport_public_key_b64)
            .map_err(|_| UplinkError::CertificateInvalid {
                reason: "invalid base64 transport public key".to_string(),
            })?;
        if pub_raw.len() != 32 {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport Ed25519 public key must be 32 bytes".to_string(),
            });
        }
        let sig_raw = STANDARD
            .decode(self.device_signature_b64.trim())
            .map_err(|_| UplinkError::CertificateInvalid {
                reason: "missing or invalid base64 device signature on transport cert".to_string(),
            })?;
        if sig_raw.len() != 64 {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport cert device signature must be 64 bytes".to_string(),
            });
        }
        Ok(())
    }

    /// Encode this certificate as base64 JSON for the `Grdr-Cert` header.
    pub fn to_header_b64(&self) -> Result<String, UplinkError> {
        let json = serde_json::to_vec(self).map_err(|e| UplinkError::CertificateInvalid {
            reason: format!("failed to serialize transport cert: {e}"),
        })?;
        Ok(STANDARD.encode(json))
    }

    /// Canonical tuple signed over by the device keypair.
    pub fn canonical_payload(&self) -> Result<Vec<u8>, UplinkError> {
        let signable = (
            self.cert_version,
            &self.device_id,
            &self.deployment_id,
            &self.transport_key_id,
            &self.transport_public_key_b64,
            self.use_kind,
            self.not_before_unix_s,
            self.not_after_unix_s,
            &self.device_key_id,
        );
        serde_json::to_vec(&signable).map_err(|e| UplinkError::CertificateInvalid {
            reason: format!("canonical cert encode failed: {e}"),
        })
    }
}

impl ResponseKeyCertificate {
    /// Issue a fleet-signed response certificate anchored by the fleet keypair.
    pub fn issue(
        fleet_signer: &SigningKeypair,
        deployment_id: impl Into<String>,
        cell_id: impl Into<String>,
        response_keypair: &SigningKeypair,
        not_before_unix_s: i64,
        not_after_unix_s: i64,
    ) -> Result<Self, UplinkError> {
        let max_ttl = max_response_cert_lifetime_s();
        if not_after_unix_s <= not_before_unix_s
            || not_after_unix_s.saturating_sub(not_before_unix_s) > max_ttl
        {
            return Err(UplinkError::CertificateInvalid {
                reason: format!("response cert lifetime invalid or exceeds {max_ttl}s ceiling"),
            });
        }
        let mut cert = Self {
            cert_version: 1,
            fleet_key_id: fleet_signer.key_id().to_string(),
            deployment_id: deployment_id.into(),
            cell_id: cell_id.into(),
            response_key_id: response_keypair.key_id().to_string(),
            response_public_key_b64: response_keypair.public_key_b64(),
            not_before_unix_s,
            not_after_unix_s,
            fleet_signature_b64: String::new(),
        };
        let canonical = cert.canonical_payload()?;
        cert.fleet_signature_b64 = fleet_signer.sign_bytes("grdr-response-cert-v1", &canonical);
        Ok(cert)
    }

    /// Canonical tuple signed over by the fleet trust anchor.
    pub fn canonical_payload(&self) -> Result<Vec<u8>, UplinkError> {
        let signable = (
            self.cert_version,
            &self.fleet_key_id,
            &self.deployment_id,
            &self.cell_id,
            &self.response_key_id,
            &self.response_public_key_b64,
            self.not_before_unix_s,
            self.not_after_unix_s,
        );
        serde_json::to_vec(&signable).map_err(|e| UplinkError::CertificateInvalid {
            reason: format!("canonical response cert encode failed: {e}"),
        })
    }
}

/// Resolve response key certificate lifetime cap from embedded `contracts/limits.toml`.
#[must_use]
pub fn max_response_cert_lifetime_s() -> i64 {
    grdr_wire::limits::embedded_limits()
        .ok()
        .map(|l| i64::from(l.fleet_response_key_hours))
        .filter(|&h| h > 0)
        .map(|h| h.saturating_mul(3_600))
        .unwrap_or(MAX_RESPONSE_CERT_LIFETIME_S)
}
