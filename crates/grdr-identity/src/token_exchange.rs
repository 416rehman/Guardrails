// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{SigningKeypair, constant_time_eq, sha256_digest, verify_ed25519_raw};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::IdentityError;
use crate::broker_types::Ceiling;
use crate::ceiling_ref::reference_prefix_allows;
use crate::jwt_keys::{
    JwtHeaderFields, MAX_ACCESS_TOKEN_TTL_SECS, MAX_ACT_CHAIN_DEPTH, MAX_FEDERATION_TOKEN_TTL_SECS,
    keypair_to_jwk, sign_jwt_with_key, split_jwt_raw,
};
use crate::spiffe::SpiffeId;

const MAX_JTI_REPLAY_CACHE: usize = 32_768;
const MAX_JTI_PER_JKT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorClaim {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopCnfClaim {
    pub jkt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrdrAccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub client_id: String,
    pub scope: String,
    pub agi_id: String,
    pub spiffe_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<DpopCnfClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrdrFederationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub trust_domain: String,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorProfileClaims {
    pub sub: String,
    pub actor_type: String,
    pub act: ActorClaim,
    pub trust_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopPayload {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub ath: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    pub subject_claims: GrdrAccessClaims,
    pub requested_audience: String,
    pub requested_scope: String,
    pub actor_subject: String,
    pub parent_ceiling: Ceiling,
    pub child_ceiling: Ceiling,
    pub requested_ttl_secs: i64,
    pub federated_trust_domain: Option<String>,
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct JtiDenyList {
    revoked_expiries: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpop {
    pub jti: String,
    pub jkt: String,
}

#[derive(Debug, Clone, Default)]
pub struct DpopProofVerifier {
    seen_jti_expiries: BTreeMap<(String, String), i64>,
}

#[derive(Debug, Clone)]
pub struct TokenExchangeService {
    pub issuer: String,
    pub trusted_spiffe_domains: BTreeSet<String>,
}

impl ActorClaim {
    #[must_use]
    pub fn depth(&self) -> u32 {
        let mut count: u32 = 1;
        let mut cursor = self.act.as_deref();
        while let Some(inner) = cursor {
            count = count.saturating_add(1);
            cursor = inner.act.as_deref();
        }
        count
    }
}

pub fn sign_dpop_proof(
    client_kp: &SigningKeypair,
    payload: &DpopPayload,
) -> Result<String, IdentityError> {
    let header = JwtHeaderFields {
        alg: "EdDSA".to_string(),
        typ: "dpop+jwt".to_string(),
        kid: None,
        jwk: Some(keypair_to_jwk(client_kp)),
    };
    sign_jwt_with_key(client_kp, &header, payload)
}

impl DpopProofVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_proof_unrecorded(
        &self,
        dpop_jwt: &str,
        expected_method: &str,
        expected_url: &str,
        presented_access_token: Option<&str>,
        now: Timestamp,
    ) -> Result<VerifiedDpop, IdentityError> {
        let (header, p_raw, signing_input, sig_arr) = split_jwt_raw(dpop_jwt)?;
        if header.typ != "dpop+jwt" || header.alg != "EdDSA" {
            return Err(IdentityError::IssuerError(
                "DPoP proof must use typ=dpop+jwt and alg=EdDSA".to_string(),
            ));
        }
        let jwk = header
            .jwk
            .as_ref()
            .ok_or_else(|| IdentityError::IssuerError("DPoP header missing jwk".to_string()))?;
        let pk_arr = jwk.public_key_bytes()?;
        verify_ed25519_raw(&pk_arr, signing_input.as_bytes(), &sig_arr).map_err(|_| {
            IdentityError::IssuerError("DPoP proof signature verification failed".to_string())
        })?;
        let payload: DpopPayload = serde_json::from_slice(&p_raw)
            .map_err(|e| IdentityError::IssuerError(format!("parse DPoP payload: {e}")))?;

        if !payload.htm.eq_ignore_ascii_case(expected_method) || payload.htu != expected_url {
            return Err(IdentityError::IssuerError(
                "DPoP proof htm/htu does not match request".to_string(),
            ));
        }
        let now_sec = now.as_second();
        if payload.iat > now_sec.saturating_add(60)
            || now_sec.saturating_sub(payload.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(IdentityError::IssuerError(
                "DPoP proof iat outside accepted window".to_string(),
            ));
        }
        if let Some(tok) = presented_access_token {
            let expected_ath = B64_URL.encode(sha256_digest(tok.as_bytes()));
            if !payload
                .ath
                .as_deref()
                .is_some_and(|ath| constant_time_eq(ath.as_bytes(), expected_ath.as_bytes()))
            {
                return Err(IdentityError::IssuerError(
                    "DPoP ath claim does not match presented access token".to_string(),
                ));
            }
        }
        if payload.jti.trim().is_empty() {
            return Err(IdentityError::IssuerError(
                "DPoP proof jti cannot be empty".to_string(),
            ));
        }
        let jkt = jwk.thumbprint_sha256_b64()?;
        let key = (jkt.clone(), payload.jti.clone());
        if self
            .seen_jti_expiries
            .get(&key)
            .is_some_and(|exp| *exp > now_sec)
        {
            return Err(IdentityError::IssuerError(
                "DPoP proof jti replayed".to_string(),
            ));
        }
        Ok(VerifiedDpop {
            jti: payload.jti,
            jkt,
        })
    }

    pub fn record_jti(
        &mut self,
        verified: &VerifiedDpop,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        let now_sec = now.as_second();
        self.seen_jti_expiries.retain(|_, exp| *exp > now_sec);
        let key = (verified.jkt.clone(), verified.jti.clone());
        if self.seen_jti_expiries.contains_key(&key) {
            return Err(IdentityError::IssuerError(
                "DPoP proof jti replayed".to_string(),
            ));
        }
        let per_key_count = self
            .seen_jti_expiries
            .keys()
            .filter(|(k, _)| k == &verified.jkt)
            .count();
        if per_key_count >= MAX_JTI_PER_JKT || self.seen_jti_expiries.len() >= MAX_JTI_REPLAY_CACHE
        {
            return Err(IdentityError::RateLimitExceeded("dpop-jti-cache".into()));
        }
        self.seen_jti_expiries
            .insert(key, now_sec.saturating_add(MAX_FEDERATION_TOKEN_TTL_SECS));
        Ok(())
    }

    pub fn verify_proof(
        &mut self,
        dpop_jwt: &str,
        expected_method: &str,
        expected_url: &str,
        presented_access_token: Option<&str>,
        now: Timestamp,
    ) -> Result<String, IdentityError> {
        let verified = self.check_proof_unrecorded(
            dpop_jwt,
            expected_method,
            expected_url,
            presented_access_token,
            now,
        )?;
        self.record_jti(&verified, now)?;
        Ok(verified.jkt)
    }
}

impl JtiDenyList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(
        &mut self,
        jti: impl Into<String>,
        expires_at_epoch: i64,
        now_epoch: i64,
    ) -> Result<(), IdentityError> {
        self.revoked_expiries.retain(|_, exp| *exp > now_epoch);
        if expires_at_epoch <= now_epoch {
            return Ok(());
        }
        let key = jti.into();
        if !self.revoked_expiries.contains_key(&key)
            && self.revoked_expiries.len() >= MAX_JTI_REPLAY_CACHE
        {
            return Err(IdentityError::RateLimitExceeded("jti-deny-list".into()));
        }
        self.revoked_expiries.insert(key, expires_at_epoch);
        Ok(())
    }

    #[must_use]
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked_expiries.contains_key(jti)
    }

    pub fn prune_expired(&mut self, now_epoch: i64) {
        self.revoked_expiries.retain(|_, exp| *exp > now_epoch);
    }

    #[must_use]
    pub fn export_active(&self, now_epoch: i64) -> Vec<(String, i64)> {
        self.revoked_expiries
            .iter()
            .filter(|(_, exp)| **exp > now_epoch)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    pub fn import_active(&mut self, entries: Vec<(String, i64)>, now_epoch: i64) {
        for (jti, exp) in entries {
            if exp > now_epoch && self.revoked_expiries.len() < MAX_JTI_REPLAY_CACHE {
                self.revoked_expiries.insert(jti, exp);
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked_expiries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked_expiries.is_empty()
    }
}

impl TokenExchangeService {
    pub fn exchange(
        &self,
        req: &TokenExchangeRequest,
        deny_list: &JtiDenyList,
        now: Timestamp,
    ) -> Result<(GrdrAccessClaims, Ceiling), IdentityError> {
        let now_sec = now.as_second();
        if req.subject_claims.iss != self.issuer {
            return Err(IdentityError::IssuerError(
                "subject token issuer does not match local authorization server".to_string(),
            ));
        }
        if deny_list.is_revoked(&req.subject_claims.jti) {
            return Err(IdentityError::IssuerError(
                "subject token jti is revoked".to_string(),
            ));
        }
        if req.subject_claims.iat > now_sec.saturating_add(60) {
            return Err(IdentityError::IssuerError(
                "subject token issued in the future".to_string(),
            ));
        }
        if req.subject_claims.exp <= now_sec {
            return Err(IdentityError::IssuerError(
                "subject token expired".to_string(),
            ));
        }
        if req
            .subject_claims
            .exp
            .saturating_sub(req.subject_claims.iat)
            > MAX_ACCESS_TOKEN_TTL_SECS
        {
            return Err(IdentityError::ScopeExceedsCeiling(
                "subject token TTL exceeds 900s maximum".to_string(),
            ));
        }
        if let Some(ref cnf) = req.subject_claims.cnf {
            let matches_bound = req
                .dpop_jkt
                .as_deref()
                .is_some_and(|jkt| constant_time_eq(jkt.as_bytes(), cnf.jkt.as_bytes()));
            if !matches_bound {
                return Err(IdentityError::IssuerError(
                    "DPoP proof matching cnf.jkt is required for token exchange".to_string(),
                ));
            }
        }
        let subj_spiffe = SpiffeId::parse(&req.subject_claims.spiffe_id)?;
        if !self
            .trusted_spiffe_domains
            .contains(subj_spiffe.trust_domain())
        {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "untrusted subject SPIFFE domain `{}`",
                subj_spiffe.trust_domain()
            )));
        }
        let actor_spiffe = SpiffeId::parse(&req.actor_subject)?;
        if !self
            .trusted_spiffe_domains
            .contains(actor_spiffe.trust_domain())
        {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "untrusted actor SPIFFE domain `{}`",
                actor_spiffe.trust_domain()
            )));
        }
        if let Some(domain) = req.federated_trust_domain.as_deref()
            && !self.trusted_spiffe_domains.contains(domain)
        {
            return Err(IdentityError::InvalidSpiffeId(format!(
                "untrusted federated SPIFFE domain `{domain}`"
            )));
        }

        let delegated = ActorClaim {
            sub: req.actor_subject.clone(),
            act: req.subject_claims.act.clone().map(Box::new),
        };
        if delegated.depth() > MAX_ACT_CHAIN_DEPTH {
            return Err(IdentityError::ScopeExceedsCeiling(
                "nested act chain exceeds max depth 4".to_string(),
            ));
        }

        let effective_ceiling = req.parent_ceiling.intersect(&req.child_ceiling);
        if effective_ceiling.allowed_classes.is_empty()
            || effective_ceiling.allowed_accounts.is_empty()
            || effective_ceiling.allowed_actions.is_empty()
            || effective_ceiling.allowed_resource_prefixes.is_empty()
        {
            return Err(IdentityError::ScopeExceedsCeiling(
                "effective ceiling intersection is empty".to_string(),
            ));
        }
        if !effective_ceiling
            .allowed_resource_prefixes
            .iter()
            .any(|prefix| reference_prefix_allows(prefix, &req.requested_audience))
        {
            return Err(IdentityError::ScopeExceedsCeiling(
                "requested audience exceeds effective ceiling resource prefixes".to_string(),
            ));
        }

        let ttl = req
            .requested_ttl_secs
            .min(effective_ceiling.max_ttl_secs)
            .min(MAX_ACCESS_TOKEN_TTL_SECS)
            .min(req.subject_claims.exp.saturating_sub(now_sec));
        if ttl <= 0 {
            return Err(IdentityError::ScopeExceedsCeiling(
                "exchanged token effective TTL must be positive".to_string(),
            ));
        }

        let intersected_scopes: Vec<&str> = req
            .requested_scope
            .split_whitespace()
            .filter(|wanted| {
                req.subject_claims
                    .scope
                    .split_whitespace()
                    .any(|granted| granted == *wanted)
            })
            .collect();
        if intersected_scopes.is_empty() {
            return Err(IdentityError::ScopeExceedsCeiling(
                "token exchange requested scopes not held by subject".to_string(),
            ));
        }

        let bound_jkt = req
            .subject_claims
            .cnf
            .as_ref()
            .map(|c| c.jkt.clone())
            .or_else(|| req.dpop_jkt.clone());
        let claims = GrdrAccessClaims {
            iss: self.issuer.clone(),
            sub: req.subject_claims.sub.clone(),
            aud: req.requested_audience.clone(),
            iat: now_sec,
            exp: now_sec.saturating_add(ttl),
            jti: format!("jti_{}", Uuid::now_v7().simple()),
            client_id: req.subject_claims.client_id.clone(),
            scope: intersected_scopes.join(" "),
            agi_id: req.subject_claims.agi_id.clone(),
            spiffe_id: req.subject_claims.spiffe_id.clone(),
            act: Some(delegated),
            cnf: bound_jkt.map(|jkt| DpopCnfClaim { jkt }),
        };
        Ok((claims, effective_ceiling))
    }
}

#[must_use]
pub fn normalize_actor_profile(claims: &GrdrAccessClaims) -> ActorProfileClaims {
    let act = claims.act.clone().unwrap_or(ActorClaim {
        sub: claims.spiffe_id.clone(),
        act: None,
    });
    let domain = claims
        .spiffe_id
        .strip_prefix("spiffe://")
        .and_then(|s| s.split('/').next())
        .unwrap_or("local")
        .to_string();
    ActorProfileClaims {
        sub: claims.sub.clone(),
        actor_type: "agent_instance".to_string(),
        act,
        trust_domain: domain,
    }
}
