// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! RFC 9421 request signing and `ResponseKeyCertificate` verification (`D-22`).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use grdr_crypto::{SigningKeypair, verify_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::UplinkError;
use crate::rfc9421::{
    MAX_RESPONSE_SIGNATURE_TTL_S, REQUEST_SIGNATURE_TTL_S, REQUIRED_RESPONSE_COVERED, int_param,
    parse_rfc9421_params, quoted_param, sign_fleet_response_with_keyid, validate_rfc9421_token,
};

pub use crate::auth_certs::{
    KeyUse, MAX_RESPONSE_CERT_LIFETIME_S, MAX_TRANSPORT_CERT_LIFETIME_S, RequestKind,
    ResponseKeyCertificate, TransportKeyCertificate,
};
pub use crate::rfc9421::{
    Rfc9421RequestHeaders, VerifiedResponseMeta, compute_rfc9530_sha256_digest,
};

/// Maximum cached `ResponseKeyCertificate` entries to bound unprivileged daemon memory.
pub const MAX_RESPONSE_CERT_CACHE_ENTRIES: usize = 64;
/// Maximum tolerable clock difference before flagging skew (5 minutes).
pub const MAX_CLOCK_SKEW_S: i64 = 300;
const MAX_CLOCK_SKEW_U64: u64 = 300;

/// Pinned fleet trust anchor keyed per `deployment_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetTrustAnchor {
    pub deployment_id: String,
    pub fleet_public_keys: BTreeMap<String, String>,
}

/// Server response headers + body verified against a cached or attached `ResponseKeyCertificate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedResponse<'a> {
    pub content_digest: &'a str,
    pub signature_input: &'a str,
    pub signature: &'a str,
    pub response_cert: Option<&'a ResponseKeyCertificate>,
    pub server_time_unix_s: i64,
    pub body: &'a [u8],
}

/// Per-epoch RFC 9421 signer that never holds long-lived device identity private keys.
pub struct EphemeralTransportSigner {
    transport_keypair: SigningKeypair,
    cert: TransportKeyCertificate,
    cert_b64: String,
}

/// Stateful verifier enforcing `deployment_id` scoping, monotonic server clock tracking,
/// `ResponseKeyCertificate` caching, and `req` signature binding.
#[derive(Clone, Debug)]
pub struct ResponseVerifier {
    anchor: FleetTrustAnchor,
    cached_certs: BTreeMap<String, ResponseKeyCertificate>,
    server_time_anchor_s: i64,
    server_anchor_mono_ms: u64,
}

impl EphemeralTransportSigner {
    /// Construct a per-epoch uplink signer enforcing exact `key_id` and public-key match.
    pub fn new(
        transport_keypair: SigningKeypair,
        cert: TransportKeyCertificate,
    ) -> Result<Self, UplinkError> {
        if cert.use_kind != KeyUse::Transport {
            return Err(UplinkError::CertificateInvalid {
                reason: "ephemeral signer requires KeyUse::Transport certificate".to_string(),
            });
        }
        if cert.transport_key_id != transport_keypair.key_id()
            || cert.transport_public_key_b64 != transport_keypair.public_key_b64()
        {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport certificate key binding does not match ephemeral keypair"
                    .to_string(),
            });
        }
        validate_rfc9421_token("device_id", &cert.device_id)?;
        validate_rfc9421_token("transport_key_id", &cert.transport_key_id)?;
        let cert_b64 = cert.to_header_b64()?;
        Ok(Self {
            transport_keypair,
            cert,
            cert_b64,
        })
    }

    /// Sign an outbound HTTP request per RFC 9421 (`tag="grdr-uplink-v1"`).
    pub fn sign_request(
        &self,
        method: &str,
        target_uri: &str,
        body: &[u8],
        kind: RequestKind,
        created_unix_s: i64,
        nonce: Option<&str>,
    ) -> Result<Rfc9421RequestHeaders, UplinkError> {
        validate_rfc9421_token("method", method)?;
        validate_rfc9421_token("target_uri", target_uri)?;
        if let Some(n) = nonce {
            validate_rfc9421_token("nonce", n)?;
        }
        if created_unix_s < self.cert.not_before_unix_s
            || created_unix_s > self.cert.not_after_unix_s
        {
            return Err(UplinkError::CertificateInvalid {
                reason: "transport key certificate outside valid epoch window".to_string(),
            });
        }
        if kind == RequestKind::CheckIn && nonce.is_none_or(|n| n.trim().is_empty()) {
            return Err(UplinkError::SignatureCreationFailed {
                detail: "CheckIn requests require a fresh anti-replay nonce".to_string(),
            });
        }

        let content_digest = compute_rfc9530_sha256_digest(body);
        let expires_unix_s = created_unix_s.saturating_add(REQUEST_SIGNATURE_TTL_S);
        let keyid = &self.cert.transport_key_id;
        let nonce_param = nonce
            .filter(|n| !n.is_empty())
            .map(|n| format!(";nonce=\"{n}\""))
            .unwrap_or_default();

        let params = format!(
            "(\"@method\" \"@target-uri\" \"content-digest\" \"grdr-device\" \"grdr-cert\");created={created_unix_s};expires={expires_unix_s};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"grdr-uplink-v1\"{nonce_param}"
        );
        let signature_base = format!(
            "\"@method\": {}\n\"@target-uri\": {target_uri}\n\"content-digest\": {content_digest}\n\"grdr-device\": {}\n\"grdr-cert\": {}\n\"@signature-params\": {params}",
            method.to_ascii_uppercase(),
            self.cert.device_id,
            self.cert_b64,
        );
        let sig_b64 = self
            .transport_keypair
            .sign_bytes("grdr-uplink-v1", signature_base.as_bytes());
        let sig_hash = Sha256::digest(sig_b64.as_bytes());
        let request_sig_digest_b64 = STANDARD.encode(sig_hash);

        Ok(Rfc9421RequestHeaders {
            content_digest,
            signature_input: format!("sig1={params}"),
            signature: format!("sig1=:{sig_b64}:"),
            grdr_device: self.cert.device_id.clone(),
            grdr_cert_b64: self.cert_b64.clone(),
            request_sig_digest_b64,
            created_unix_s,
        })
    }
}

impl ResponseVerifier {
    /// Initialize verifier with pinned `FleetTrustAnchor` and trusted initial server time.
    #[must_use]
    pub fn new(anchor: FleetTrustAnchor, initial_server_time_s: i64, initial_mono_ms: u64) -> Self {
        Self {
            anchor,
            cached_certs: BTreeMap::new(),
            server_time_anchor_s: initial_server_time_s,
            server_anchor_mono_ms: initial_mono_ms,
        }
    }

    /// Estimate trusted current server UNIX time from last anchored timestamp + monotonic elapsed.
    #[must_use]
    pub fn estimated_server_time_s(&self, now_mono_ms: u64) -> i64 {
        let elapsed_s = i64::try_from(
            now_mono_ms
                .saturating_sub(self.server_anchor_mono_ms)
                .checked_div(1_000)
                .unwrap_or(0),
        )
        .unwrap_or(i64::MAX);
        self.server_time_anchor_s.saturating_add(elapsed_s)
    }

    /// Verify response RFC 9421 covered list, `alg`, `tag`, `req`, `content-digest`, and cert.
    ///
    /// Mutates cert cache or monotonic server time anchor strictly after Ed25519 signature verification passes.
    pub fn verify_response(
        &mut self,
        request: &Rfc9421RequestHeaders,
        response: &SignedResponse<'_>,
        client_wall_unix_s: i64,
        now_mono_ms: u64,
    ) -> Result<VerifiedResponseMeta, UplinkError> {
        let expected_digest = compute_rfc9530_sha256_digest(response.body);
        if response.content_digest != expected_digest {
            return Err(UplinkError::AckUnverified {
                reason: "response content-digest mismatch".to_string(),
            });
        }

        let params = response
            .signature_input
            .strip_prefix("sig1=")
            .ok_or_else(|| UplinkError::AckUnverified {
                reason: "missing sig1= prefix on response Signature-Input".to_string(),
            })?;

        let parsed = parse_rfc9421_params(params)?;
        if parsed.covered != REQUIRED_RESPONSE_COVERED {
            return Err(UplinkError::AckUnverified {
                reason: format!(
                    "unexpected response covered components '{}'",
                    parsed.covered
                ),
            });
        }

        let alg = quoted_param(&parsed.params, "alg")?;
        if alg != "ed25519" {
            return Err(UplinkError::AckUnverified {
                reason: format!("unsupported RFC 9421 signature algorithm '{alg}'"),
            });
        }
        let keyid = quoted_param(&parsed.params, "keyid")?;
        let tag = quoted_param(&parsed.params, "tag")?;
        let req_binding = quoted_param(&parsed.params, "req")?;
        let created_s = int_param(&parsed.params, "created")?;
        let expires_s = int_param(&parsed.params, "expires")?;

        if tag != "grdr-fleet-v1" {
            return Err(UplinkError::AckUnverified {
                reason: format!("unexpected response signature tag '{tag}'"),
            });
        }
        if req_binding != request.request_sig_digest_b64 {
            return Err(UplinkError::AckUnverified {
                reason: "response req binding does not match request signature".to_string(),
            });
        }
        if response.server_time_unix_s != created_s {
            return Err(UplinkError::AckUnverified {
                reason: "response server_time_unix_s does not match signed created timestamp"
                    .to_string(),
            });
        }

        let monotonic_now_s = self.estimated_server_time_s(now_mono_ms);
        if created_s > expires_s
            || expires_s.saturating_sub(created_s) > MAX_RESPONSE_SIGNATURE_TTL_S
            || monotonic_now_s > expires_s.saturating_add(MAX_CLOCK_SKEW_S)
            || created_s < monotonic_now_s.saturating_sub(MAX_CLOCK_SKEW_S)
        {
            return Err(UplinkError::AckUnverified {
                reason: "response signature outside valid created/expires bounds".to_string(),
            });
        }

        let validated_new_cert = match response.response_cert {
            Some(cert) => Some(self.validate_cert_without_mutating(cert)?),
            None => None,
        };

        let signing_cert = match validated_new_cert.as_ref() {
            Some(cert) if cert.response_key_id == keyid => cert,
            _ => self
                .cached_certs
                .get(&keyid)
                .ok_or_else(|| UplinkError::AckUnverified {
                    reason: format!("unknown response signing key_id '{keyid}'"),
                })?,
        };

        if monotonic_now_s
            > signing_cert
                .not_after_unix_s
                .saturating_add(MAX_CLOCK_SKEW_S)
            || created_s < signing_cert.not_before_unix_s
            || created_s > signing_cert.not_after_unix_s
        {
            return Err(UplinkError::AckUnverified {
                reason: format!("ResponseKeyCertificate '{keyid}' outside valid lifetime"),
            });
        }

        let sig_b64 = response
            .signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| UplinkError::AckUnverified {
                reason: "malformed RFC 9421 Signature header".to_string(),
            })?;

        let signature_base = format!(
            "\"content-digest\": {}\n\"@signature-params\": {params}",
            response.content_digest
        );
        verify_bytes(
            &signing_cert.response_public_key_b64,
            "grdr-fleet-v1",
            signature_base.as_bytes(),
            sig_b64,
        )
        .map_err(|_| UplinkError::AckUnverified {
            reason: "response Ed25519 signature verification failed".to_string(),
        })?;

        let authenticated_now_s = monotonic_now_s.max(created_s);
        if authenticated_now_s < signing_cert.not_before_unix_s
            || authenticated_now_s > signing_cert.not_after_unix_s
        {
            if validated_new_cert.is_none() {
                self.cached_certs.remove(&keyid);
            }
            return Err(UplinkError::AckUnverified {
                reason: format!("ResponseKeyCertificate '{keyid}' is expired"),
            });
        }

        if let Some(new_cert) = validated_new_cert {
            self.commit_cert_to_cache(new_cert);
        }
        if created_s > self.server_time_anchor_s {
            self.server_time_anchor_s = created_s;
            self.server_anchor_mono_ms = now_mono_ms;
        }
        let clock_skew_detected = client_wall_unix_s.abs_diff(created_s) > MAX_CLOCK_SKEW_U64;

        Ok(VerifiedResponseMeta {
            server_time_unix_s: created_s,
            clock_skew_detected,
        })
    }

    fn validate_cert_without_mutating(
        &self,
        cert: &ResponseKeyCertificate,
    ) -> Result<ResponseKeyCertificate, UplinkError> {
        if cert.deployment_id != self.anchor.deployment_id {
            return Err(UplinkError::AckUnverified {
                reason: format!(
                    "cross-deployment ResponseKeyCertificate rejected (got {}, expected {})",
                    cert.deployment_id, self.anchor.deployment_id
                ),
            });
        }
        validate_rfc9421_token("response_key_id", &cert.response_key_id)?;
        let raw_pub = STANDARD
            .decode(&cert.response_public_key_b64)
            .map_err(|_| UplinkError::AckUnverified {
                reason: "invalid base64 response public key".to_string(),
            })?;
        if raw_pub.len() != 32 {
            return Err(UplinkError::AckUnverified {
                reason: "response Ed25519 public key must be 32 bytes".to_string(),
            });
        }
        if let Some(existing) = self.cached_certs.get(&cert.response_key_id)
            && existing.response_public_key_b64 != cert.response_public_key_b64
        {
            return Err(UplinkError::AckUnverified {
                reason: format!(
                    "conflicting public key for response_key_id '{}'",
                    cert.response_key_id
                ),
            });
        }

        let fleet_pub = self
            .anchor
            .fleet_public_keys
            .get(&cert.fleet_key_id)
            .ok_or_else(|| UplinkError::AckUnverified {
                reason: format!("unpinned fleet_key_id '{}'", cert.fleet_key_id),
            })?;

        let canonical = cert
            .canonical_payload()
            .map_err(|e| UplinkError::AckUnverified {
                reason: e.to_string(),
            })?;
        verify_bytes(
            fleet_pub,
            "grdr-response-cert-v1",
            &canonical,
            &cert.fleet_signature_b64,
        )
        .map_err(|_| UplinkError::AckUnverified {
            reason: "ResponseKeyCertificate fleet signature invalid".to_string(),
        })?;

        if cert.not_after_unix_s <= cert.not_before_unix_s
            || cert.not_after_unix_s.saturating_sub(cert.not_before_unix_s)
                > MAX_RESPONSE_CERT_LIFETIME_S
        {
            return Err(UplinkError::AckUnverified {
                reason: "ResponseKeyCertificate lifetime invalid or exceeds 7-day maximum"
                    .to_string(),
            });
        }
        Ok(cert.clone())
    }

    fn commit_cert_to_cache(&mut self, cert: ResponseKeyCertificate) {
        if !self.cached_certs.contains_key(&cert.response_key_id)
            && self.cached_certs.len() >= MAX_RESPONSE_CERT_CACHE_ENTRIES
            && let Some(evict_key) = self
                .cached_certs
                .iter()
                .min_by_key(|(_, entry)| entry.not_after_unix_s)
                .map(|(k, _)| k.clone())
        {
            self.cached_certs.remove(&evict_key);
        }
        self.cached_certs.insert(cert.response_key_id.clone(), cert);
    }
}

/// Sign a fleet server response matching `ResponseVerifier::verify_response`.
pub fn sign_fleet_response(
    response_signer: &SigningKeypair,
    cert: Option<&ResponseKeyCertificate>,
    request_sig_digest_b64: &str,
    body: &[u8],
    server_time_unix_s: i64,
) -> Result<(String, String, String), UplinkError> {
    let keyid = cert.map_or_else(|| response_signer.key_id(), |c| c.response_key_id.as_str());
    sign_fleet_response_with_keyid(
        response_signer,
        keyid,
        request_sig_digest_b64,
        body,
        server_time_unix_s,
    )
}
