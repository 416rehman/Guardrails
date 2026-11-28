// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::ceiling_ref::is_safe_resource_string;
use crate::http_security::validate_exact_endpoint_url;
use crate::jwt_keys::{MAX_FEDERATION_TOKEN_TTL_SECS, OkpEd25519Jwk, verify_jwt_with_jwks};
use crate::spiffe::{AgentLifecycle, SpiffeId};

pub const ID_JAG_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const ID_JAG_TYP_V04: &str = "id-jag+jwt";
pub const ID_JAG_TYP_V06: &str = "oauth-id-jag+jwt";
pub const SCIM_CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_AGENT_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:agent:2.0:Agent";
const MAX_ID_JAG_REPLAY_ENTRIES: usize = 32_768;
pub const MAX_STATUS_LIST_BYTES: usize = 131_072;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdJagClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub resource: String,
    pub client_id: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub scope: String,
    pub spiffe_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IdJagReplayCache {
    seen_expiries: BTreeMap<(String, String), i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CimdClientMetadata {
    pub client_id: String,
    pub client_name: String,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
    pub jwks_uri: Option<String>,
    pub spiffe_trust_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub txn: String,
    pub purp: String,
    pub tctx: serde_json::Value,
    pub rctx: serde_json::Value,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenStatusListDocument {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub bits: u8,
    pub lst: String,
}

#[derive(Debug, Clone)]
pub struct TokenStatusList {
    bits: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimAgentExtension {
    pub agi_id: String,
    pub aid_id: Option<String>,
    pub spiffe_id: String,
    pub sponsor_id: String,
    pub sponsor_active: bool,
    pub lifecycle: AgentLifecycle,
    pub assurance_level: String,
    pub trust_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimAgentResource {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub active: bool,
    #[serde(rename = "urn:ietf:params:scim:schemas:extension:agent:2.0:Agent")]
    pub agent: ScimAgentExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityEventKind {
    CaepSessionRevoked,
    CaepCredentialChange,
    CaepAssuranceLevelChange,
    RiscAccountDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSubjectIdentifier {
    pub format: String,
    pub iss: Option<String>,
    pub sub: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventToken {
    pub iss: String,
    pub jti: String,
    pub iat: i64,
    pub aud: String,
    pub events: BTreeMap<String, serde_json::Value>,
}

impl IdJagReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_unconsumed(
        &self,
        trusted_idp_keys: &[OkpEd25519Jwk],
        trusted_issuers: &[String],
        assertion_jwt: &str,
        expected_audience: &str,
        expected_resource: &str,
        now: Timestamp,
    ) -> Result<IdJagClaims, IdentityError> {
        let claims = match verify_jwt_with_jwks::<IdJagClaims>(
            assertion_jwt,
            Some(ID_JAG_TYP_V06),
            trusted_idp_keys,
        ) {
            Ok(c) => c,
            Err(_) => verify_jwt_with_jwks::<IdJagClaims>(
                assertion_jwt,
                Some(ID_JAG_TYP_V04),
                trusted_idp_keys,
            )?,
        };
        let now_sec = now.as_second();
        let iss = claims.iss.trim();
        if iss.is_empty() || !trusted_issuers.iter().any(|allowed| allowed == iss) {
            return Err(IdentityError::IssuerError(
                "ID-JAG issuer is not in trusted IdP allow-list".to_string(),
            ));
        }
        if claims.aud != expected_audience {
            return Err(IdentityError::IssuerError(
                "ID-JAG aud mismatch".to_string(),
            ));
        }
        if claims.resource != expected_resource || !is_safe_resource_string(&claims.resource) {
            return Err(IdentityError::ScopeExceedsCeiling(
                "ID-JAG RFC 8707 resource mismatch or unsafe resource".to_string(),
            ));
        }
        if claims.iat > now_sec.saturating_add(60)
            || claims.exp <= now_sec
            || claims.exp.saturating_sub(claims.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(IdentityError::IssuerError(
                "ID-JAG assertion iat/exp invalid or exceeds 300s TTL cap".to_string(),
            ));
        }
        if let Some(ref spiffe) = claims.spiffe_id {
            let _ = SpiffeId::parse(spiffe)?;
        }
        let jti = claims.jti.trim();
        if jti.is_empty() {
            return Err(IdentityError::IssuerError(
                "ID-JAG missing jti claim".to_string(),
            ));
        }
        let replay_key = (iss.to_owned(), jti.to_owned());
        if self
            .seen_expiries
            .get(&replay_key)
            .is_some_and(|exp| *exp > now_sec)
        {
            return Err(IdentityError::IssuerError(
                "ID-JAG single-use jti replay rejected".to_string(),
            ));
        }
        Ok(claims)
    }

    pub fn record_jti(
        &mut self,
        iss: &str,
        jti: &str,
        exp: i64,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        let now_sec = now.as_second();
        self.seen_expiries.retain(|_, seen_exp| *seen_exp > now_sec);
        let replay_key = (iss.trim().to_owned(), jti.trim().to_owned());
        if self.seen_expiries.contains_key(&replay_key) {
            return Err(IdentityError::IssuerError(
                "ID-JAG single-use jti replay rejected".to_string(),
            ));
        }
        if self.seen_expiries.len() >= MAX_ID_JAG_REPLAY_ENTRIES {
            return Err(IdentityError::RateLimitExceeded("id-jag-replay".into()));
        }
        self.seen_expiries.insert(replay_key, exp);
        Ok(())
    }

    pub fn validate_and_consume(
        &mut self,
        trusted_idp_keys: &[OkpEd25519Jwk],
        trusted_issuers: &[String],
        assertion_jwt: &str,
        expected_audience: &str,
        expected_resource: &str,
        now: Timestamp,
    ) -> Result<IdJagClaims, IdentityError> {
        let claims = self.validate_unconsumed(
            trusted_idp_keys,
            trusted_issuers,
            assertion_jwt,
            expected_audience,
            expected_resource,
            now,
        )?;
        self.record_jti(&claims.iss, &claims.jti, claims.exp, now)?;
        Ok(claims)
    }

    #[must_use]
    pub fn export_active(&self, now_sec: i64) -> Vec<(String, String, i64)> {
        self.seen_expiries
            .iter()
            .filter(|(_, exp)| **exp > now_sec)
            .map(|((iss, jti), exp)| (iss.clone(), jti.clone(), *exp))
            .collect()
    }

    pub fn import_active(&mut self, entries: Vec<(String, String, i64)>, now_sec: i64) {
        for (iss, jti, exp) in entries {
            if exp > now_sec && self.seen_expiries.len() < MAX_ID_JAG_REPLAY_ENTRIES {
                self.seen_expiries.insert((iss, jti), exp);
            }
        }
    }
}

impl CimdClientMetadata {
    pub fn validate(&self) -> Result<(), IdentityError> {
        let parsed = validate_exact_endpoint_url(self.client_id.trim(), false)?;
        if parsed.path() == "/" || parsed.path().is_empty() {
            return Err(IdentityError::InvalidHttpEndpoint(
                "CIMD client_id URL must include metadata path".to_string(),
            ));
        }
        if let Some(ref jwks) = self.jwks_uri {
            let _ = validate_exact_endpoint_url(jwks.trim(), false)?;
        }
        if self.client_name.trim().is_empty() {
            return Err(IdentityError::IssuerError(
                "CIMD client_name must be non-empty".to_string(),
            ));
        }
        Ok(())
    }
}

impl TransactionTokenClaims {
    pub fn validate(&self, now: Timestamp) -> Result<(), IdentityError> {
        let now_sec = now.as_second();
        if self.iss.trim().is_empty()
            || self.sub.trim().is_empty()
            || self.aud.trim().is_empty()
            || self.txn.trim().is_empty()
            || self.purp.trim().is_empty()
        {
            return Err(IdentityError::IssuerError(
                "transaction token requires non-empty iss, sub, aud, txn, and purp".to_string(),
            ));
        }
        if !is_safe_resource_string(&self.aud) {
            return Err(IdentityError::ScopeExceedsCeiling(
                "transaction token audience is not a safe resource".to_string(),
            ));
        }
        if self.iat > now_sec.saturating_add(60)
            || self.exp <= now_sec
            || self.exp.saturating_sub(self.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(IdentityError::IssuerError(
                "transaction token iat/exp invalid or exceeds 300s max lifetime".to_string(),
            ));
        }
        Ok(())
    }
}

impl TokenStatusList {
    #[must_use]
    pub fn with_capacity_bits(bit_count: usize) -> Self {
        let bytes = bit_count.div_ceil(8).clamp(1, MAX_STATUS_LIST_BYTES);
        Self {
            bits: vec![0u8; bytes],
        }
    }

    pub fn set_revoked(&mut self, index: usize, revoked: bool) -> Result<(), IdentityError> {
        let byte_idx = index / 8;
        if byte_idx >= MAX_STATUS_LIST_BYTES {
            return Err(IdentityError::IssuerError(
                "status list index exceeds maximum capacity".to_string(),
            ));
        }
        let needed_len = byte_idx.saturating_add(1);
        if needed_len > self.bits.len() {
            self.bits.resize(needed_len, 0);
        }
        let bit_offset = u8::try_from(index % 8).unwrap_or(0);
        let slot = self.bits.get_mut(byte_idx).ok_or_else(|| {
            IdentityError::IssuerError("status list index out of range".to_string())
        })?;
        let mask = 1u8 << bit_offset;
        if revoked {
            *slot |= mask;
        } else {
            *slot &= !mask;
        }
        Ok(())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() || bytes.len() > MAX_STATUS_LIST_BYTES {
            return Err(IdentityError::IssuerError(
                "status list byte length out of bounds".to_string(),
            ));
        }
        Ok(Self { bits: bytes })
    }

    #[must_use]
    pub fn is_revoked(&self, index: usize) -> bool {
        let byte_idx = index / 8;
        let bit_offset = u8::try_from(index % 8).unwrap_or(0);
        self.bits
            .get(byte_idx)
            .is_some_and(|b| (*b & (1u8 << bit_offset)) != 0)
    }

    #[must_use]
    pub fn to_document(&self, iss: &str, sub: &str, now: Timestamp) -> TokenStatusListDocument {
        TokenStatusListDocument {
            iss: iss.to_owned(),
            sub: sub.to_owned(),
            iat: now.as_second(),
            bits: 1,
            lst: B64_URL.encode(&self.bits),
        }
    }

    pub fn from_document(doc: &TokenStatusListDocument) -> Result<Self, IdentityError> {
        if doc.bits != 1 {
            return Err(IdentityError::IssuerError(
                "unsupported token status list bit width".to_string(),
            ));
        }
        let bits = B64_URL
            .decode(doc.lst.trim())
            .map_err(|_| IdentityError::IssuerError("invalid base64url status list".to_string()))?;
        Self::from_bytes(bits)
    }
}

impl SecurityEventKind {
    #[must_use]
    pub fn event_uri(self) -> &'static str {
        match self {
            Self::CaepSessionRevoked => {
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            }
            Self::CaepCredentialChange => {
                "https://schemas.openid.net/secevent/caep/event-type/credential-change"
            }
            Self::CaepAssuranceLevelChange => {
                "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
            }
            Self::RiscAccountDisabled => {
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
            }
        }
    }
}

#[must_use]
pub fn build_security_event_token(
    iss: &str,
    aud: &str,
    jti: &str,
    kind: SecurityEventKind,
    subject: &SetSubjectIdentifier,
    grdr_assurance_level: Option<&str>,
    now: Timestamp,
) -> SecurityEventToken {
    let mut payload = serde_json::json!({
        "subject": subject,
        "event_timestamp": now.as_second(),
    });
    if let Some(al) = grdr_assurance_level
        && let Some(obj) = payload.as_object_mut()
    {
        obj.insert(
            "grdr-al".to_string(),
            serde_json::Value::String(al.to_owned()),
        );
    }
    let mut events = BTreeMap::new();
    events.insert(kind.event_uri().to_string(), payload);
    SecurityEventToken {
        iss: iss.to_owned(),
        jti: jti.to_owned(),
        iat: now.as_second(),
        aud: aud.to_owned(),
        events,
    }
}
