// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_crypto::{SigningKeypair, fill_random, hmac_sha256, sha256_hex};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;

use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};

use super::webhooks::{
    PublicWebhookEndpoint, SigningMaterial, StoredWebhookEndpoint, WebhookSigningAlg,
};

pub(crate) fn generate_signing_material(
    alg: WebhookSigningAlg,
) -> Result<(SigningMaterial, Option<String>), ApiError> {
    match alg {
        WebhookSigningAlg::Ed25519 => {
            let kp = SigningKeypair::generate().map_err(|e| {
                ApiError::invalid_argument(
                    CODE_INVALID_INPUT,
                    "KEYGEN_FAILED",
                    e.to_string(),
                    "Retry.",
                )
            })?;
            let key_id = kp.key_id().to_owned();
            Ok((
                SigningMaterial {
                    alg,
                    ed25519: Some(kp),
                    hmac_secret: None,
                    key_id,
                    expires_at_unix: None,
                },
                None,
            ))
        }
        WebhookSigningAlg::HmacSha256 => {
            let mut secret = [0u8; 32];
            fill_random(&mut secret).map_err(|e| {
                ApiError::invalid_argument(
                    CODE_INVALID_INPUT,
                    "KEYGEN_FAILED",
                    e.to_string(),
                    "Retry.",
                )
            })?;
            let whsec = format!("whsec_{}", B64.encode(secret));
            let key_id = sha256_hex(&secret).get(..12).unwrap_or("hmac").to_owned();
            Ok((
                SigningMaterial {
                    alg,
                    ed25519: None,
                    hmac_secret: Some(secret.to_vec()),
                    key_id,
                    expires_at_unix: None,
                },
                Some(whsec),
            ))
        }
    }
}

pub(crate) fn sign_webhook_header(
    ep: &StoredWebhookEndpoint,
    msg_id: &str,
    ts_unix: i64,
    payload: &[u8],
) -> String {
    let mut signed = format!("{msg_id}.{ts_unix}.").into_bytes();
    signed.extend_from_slice(payload);
    let mut parts = Vec::new();
    if let Some(sig) = sign_one(&ep.primary, &signed) {
        parts.push(sig);
    }
    let now = Timestamp::now().as_second();
    if let Some(prev) = &ep.previous
        && prev.expires_at_unix.is_none_or(|exp| now <= exp)
        && let Some(sig) = sign_one(prev, &signed)
    {
        parts.push(sig);
    }
    parts.join(" ")
}

fn sign_one(mat: &SigningMaterial, msg: &[u8]) -> Option<String> {
    match mat.alg {
        WebhookSigningAlg::Ed25519 => {
            let sig = mat.ed25519.as_ref()?.sign_ed25519_raw(msg);
            Some(format!("v1a,{}", B64.encode(sig)))
        }
        WebhookSigningAlg::HmacSha256 => {
            let secret = mat.hmac_secret.as_deref()?;
            let mac = hmac_sha256(secret, msg);
            Some(format!("v1,{}", B64.encode(mac)))
        }
    }
}

pub(crate) fn to_public_endpoint(ep: &StoredWebhookEndpoint) -> PublicWebhookEndpoint {
    PublicWebhookEndpoint {
        id: ep.id.clone(),
        url: ep.url.clone(),
        topics: ep.topics.clone(),
        signing_algorithm: ep.signing_algorithm,
        state: ep.state,
        key_id: ep.primary.key_id.clone(),
        public_key_b64: ep.primary.ed25519.as_ref().map(|k| k.public_key_b64()),
        previous_key_id: ep.previous.as_ref().map(|p| p.key_id.clone()),
        created_at: ep.created_at.clone(),
        updated_at: ep.updated_at.clone(),
    }
}

pub(crate) fn not_found_endpoint(id: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::NotFound,
        grdr_code: CODE_NOT_FOUND.into(),
        reason: "WEBHOOK_NOT_FOUND".into(),
        class: ErrorClass::NotFound,
        message: format!("WebhookEndpoint `{id}` does not exist."),
        fix: "Verify webhook endpoint ID.".into(),
        metadata: BTreeMap::new(),
    })
}
