// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{SigningKeypair, verify_ed25519_raw};
use serde::{Deserialize, Serialize};

use crate::IdentityError;

pub const MAX_ACCESS_TOKEN_TTL_SECS: i64 = 900;
pub const MAX_FEDERATION_TOKEN_TTL_SECS: i64 = 300;
pub const MAX_ACT_CHAIN_DEPTH: u32 = 4;
const MAX_JWT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpEd25519Jwk {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub x: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSetDocument {
    pub keys: Vec<OkpEd25519Jwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtHeaderFields {
    pub alg: String,
    pub typ: String,
    pub kid: Option<String>,
    pub jwk: Option<OkpEd25519Jwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscoveryMetadata {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub device_authorization_endpoint: String,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub jwks_uri: String,
    pub bearer_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone)]
pub struct TokenKeyRing {
    active: Arc<SigningKeypair>,
    previous: Vec<Arc<SigningKeypair>>,
}

impl OkpEd25519Jwk {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        if self.kty != "OKP"
            || self.crv != "Ed25519"
            || self.alg != "EdDSA"
            || self.key_use != "sig"
            || self.x.trim().is_empty()
        {
            return Err(IdentityError::IssuerError(
                "JWK must be OKP Ed25519 with alg=EdDSA and use=sig".to_string(),
            ));
        }
        let raw_pk = B64_URL
            .decode(self.x.trim())
            .map_err(|_| IdentityError::IssuerError("invalid JWK x coordinate".to_string()))?;
        raw_pk
            .try_into()
            .map_err(|_| IdentityError::IssuerError("Ed25519 public key must be 32 bytes".into()))
    }

    pub fn thumbprint_sha256_b64(&self) -> Result<String, IdentityError> {
        let pk_arr = self.public_key_bytes()?;
        let canonical_x = B64_URL.encode(pk_arr);
        let canonical = format!(
            "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
            canonical_x
        );
        let digest = grdr_crypto::sha256_digest(canonical.as_bytes());
        Ok(B64_URL.encode(digest))
    }
}

impl TokenKeyRing {
    pub fn generate() -> Result<Self, IdentityError> {
        let active = SigningKeypair::generate()
            .map_err(|e| IdentityError::VaultState(format!("key generation failed: {e}")))?;
        Ok(Self {
            active: Arc::new(active),
            previous: Vec::new(),
        })
    }

    #[must_use]
    pub fn from_active(active: Arc<SigningKeypair>) -> Self {
        Self {
            active,
            previous: Vec::new(),
        }
    }

    pub fn rotate(&mut self, next_active: SigningKeypair) {
        let prev = Arc::clone(&self.active);
        self.active = Arc::new(next_active);
        self.previous.insert(0, prev);
        self.previous.truncate(4);
    }

    #[must_use]
    pub fn active_kid(&self) -> &str {
        self.active.key_id()
    }

    #[must_use]
    pub fn active_jwk(&self) -> OkpEd25519Jwk {
        keypair_to_jwk(&self.active)
    }

    #[must_use]
    pub fn jwk_set(&self) -> JwkSetDocument {
        let mut keys = Vec::with_capacity(1_usize.saturating_add(self.previous.len()));
        keys.push(keypair_to_jwk(&self.active));
        for prev in &self.previous {
            keys.push(keypair_to_jwk(prev));
        }
        JwkSetDocument { keys }
    }

    pub fn sign_jwt<T: Serialize>(&self, typ: &str, claims: &T) -> Result<String, IdentityError> {
        let header = JwtHeaderFields {
            alg: "EdDSA".to_string(),
            typ: typ.to_string(),
            kid: Some(self.active.key_id().to_owned()),
            jwk: None,
        };
        sign_jwt_with_key(&self.active, &header, claims)
    }

    pub fn verify_jwt<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        expected_typ: Option<&str>,
    ) -> Result<T, IdentityError> {
        let (header, p_raw, signing_input, sig_arr) = split_jwt_raw(token)?;
        if header.alg != "EdDSA" {
            return Err(IdentityError::IssuerError(
                "unsupported JWT algorithm; expected EdDSA".to_string(),
            ));
        }
        if let Some(req_typ) = expected_typ
            && header.typ != req_typ
        {
            return Err(IdentityError::IssuerError(format!(
                "unexpected JWT typ `{}`",
                header.typ
            )));
        }
        let req_kid = header
            .kid
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| IdentityError::IssuerError("JWT header missing kid".to_string()))?;

        let mut verified = false;
        let candidates = std::iter::once(&self.active).chain(self.previous.iter());
        for kp in candidates {
            if kp.key_id() != req_kid {
                continue;
            }
            if verify_ed25519_raw(&kp.public_key_bytes(), signing_input.as_bytes(), &sig_arr)
                .is_ok()
            {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(IdentityError::IssuerError(
                "JWT EdDSA signature verification failed".to_string(),
            ));
        }
        serde_json::from_slice(&p_raw)
            .map_err(|e| IdentityError::IssuerError(format!("parse JWT claims: {e}")))
    }
}

pub fn verify_jwt_with_jwks<T: for<'de> Deserialize<'de>>(
    token: &str,
    expected_typ: Option<&str>,
    jwks: &[OkpEd25519Jwk],
) -> Result<T, IdentityError> {
    let (header, p_raw, signing_input, sig_arr) = split_jwt_raw(token)?;
    if header.alg != "EdDSA" {
        return Err(IdentityError::IssuerError(
            "unsupported JWT algorithm; expected EdDSA".to_string(),
        ));
    }
    if let Some(req_typ) = expected_typ
        && header.typ != req_typ
    {
        return Err(IdentityError::IssuerError(format!(
            "unexpected JWT typ `{}`",
            header.typ
        )));
    }
    let req_kid = header
        .kid
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| IdentityError::IssuerError("JWT header missing kid".to_string()))?;

    let mut verified = false;
    for jwk in jwks {
        if jwk.kid != req_kid {
            continue;
        }
        let Ok(pk_arr) = jwk.public_key_bytes() else {
            continue;
        };
        if verify_ed25519_raw(&pk_arr, signing_input.as_bytes(), &sig_arr).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(IdentityError::IssuerError(
            "external JWT EdDSA signature verification failed".to_string(),
        ));
    }
    serde_json::from_slice(&p_raw)
        .map_err(|e| IdentityError::IssuerError(format!("parse JWT claims: {e}")))
}

#[must_use]
pub fn default_issuer_origin() -> String {
    let brand = grdr_schema::brand::brand_identity();
    format!("https://auth.{}", brand.domain)
}

#[must_use]
pub fn keypair_to_jwk(kp: &SigningKeypair) -> OkpEd25519Jwk {
    OkpEd25519Jwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        alg: "EdDSA".to_string(),
        key_use: "sig".to_string(),
        kid: kp.key_id().to_owned(),
        x: B64_URL.encode(kp.public_key_bytes()),
    }
}

pub fn sign_jwt_with_key<T: Serialize>(
    kp: &SigningKeypair,
    header: &JwtHeaderFields,
    claims: &T,
) -> Result<String, IdentityError> {
    let h_json = serde_json::to_vec(header)
        .map_err(|e| IdentityError::IssuerError(format!("serialize JWT header: {e}")))?;
    let c_json = serde_json::to_vec(claims)
        .map_err(|e| IdentityError::IssuerError(format!("serialize JWT claims: {e}")))?;
    let signing_input = format!("{}.{}", B64_URL.encode(h_json), B64_URL.encode(c_json));
    let sig = kp.sign_ed25519_raw(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", B64_URL.encode(sig)))
}

pub fn split_jwt_raw(
    token: &str,
) -> Result<(JwtHeaderFields, Vec<u8>, String, [u8; 64]), IdentityError> {
    if token.len() > MAX_JWT_BYTES {
        return Err(IdentityError::IssuerError(
            "JWT exceeds max token size".to_string(),
        ));
    }
    let mut parts = token.split('.');
    let h_b64 = parts
        .next()
        .ok_or_else(|| IdentityError::IssuerError("missing JWT header segment".to_string()))?;
    let p_b64 = parts
        .next()
        .ok_or_else(|| IdentityError::IssuerError("missing JWT payload segment".to_string()))?;
    let s_b64 = parts
        .next()
        .ok_or_else(|| IdentityError::IssuerError("missing JWT signature segment".to_string()))?;
    if parts.next().is_some() {
        return Err(IdentityError::IssuerError(
            "JWT contains unexpected fourth segment".to_string(),
        ));
    }

    let h_raw = B64_URL
        .decode(h_b64)
        .map_err(|_| IdentityError::IssuerError("invalid base64url JWT header".to_string()))?;
    let p_raw = B64_URL
        .decode(p_b64)
        .map_err(|_| IdentityError::IssuerError("invalid base64url JWT payload".to_string()))?;
    let s_raw = B64_URL
        .decode(s_b64)
        .map_err(|_| IdentityError::IssuerError("invalid base64url JWT signature".to_string()))?;

    let sig_arr: [u8; 64] = s_raw
        .try_into()
        .map_err(|_| IdentityError::IssuerError("EdDSA signature must be 64 bytes".to_string()))?;
    let header: JwtHeaderFields = serde_json::from_slice(&h_raw)
        .map_err(|e| IdentityError::IssuerError(format!("parse JWT header: {e}")))?;
    Ok((header, p_raw, format!("{h_b64}.{p_b64}"), sig_arr))
}

#[must_use]
pub fn discovery_metadata(issuer: &str) -> OidcDiscoveryMetadata {
    let base = issuer.trim_end_matches('/');
    OidcDiscoveryMetadata {
        issuer: base.to_string(),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        token_endpoint: format!("{base}/oauth2/token"),
        device_authorization_endpoint: format!("{base}/oauth2/device_authorization"),
        id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        ],
        dpop_signing_alg_values_supported: vec!["EdDSA".to_string()],
    }
}

#[must_use]
pub fn protected_resource_metadata(issuer: &str, resource: &str) -> ProtectedResourceMetadata {
    let base = issuer.trim_end_matches('/');
    ProtectedResourceMetadata {
        resource: resource.to_string(),
        authorization_servers: vec![base.to_string()],
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        bearer_methods_supported: vec!["header".to_string(), "dpop".to_string()],
        scopes_supported: vec![
            "broker:lease".to_string(),
            "identity:read".to_string(),
            "mcp:invoke".to_string(),
        ],
        dpop_signing_alg_values_supported: vec!["EdDSA".to_string()],
    }
}
