// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jiff::Timestamp;
use serde::Serialize;
use sha2::{Digest, Sha256};

use grdr_model::{
    ActionClass, ApprovalGrade, CompiledFloorRule, CompiledFloorTable, ControlPoint,
    DecisionReceipt, Grant, GrantScope, Mode, PolicyPack, RuleMatch, SignatureStatus,
    TrustedKeyInfo, Verdict,
};

const SIGNATURE_DOMAIN_PREFIX: &[u8] = b"grdr.sig.v1\0";
const DOMAIN_PACK: &str = "policy_pack";
const DOMAIN_GRANT: &str = "grant";
const DOMAIN_RECEIPT: &str = "decision_receipt";
const DOMAIN_FLOOR: &str = "compiled_floor_table";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("GRDR-CRYPTO-0001: OS entropy generation failed: {0}")]
    Entropy(String),
    #[error("GRDR-CRYPTO-0002: invalid Ed25519 key material: {0}")]
    InvalidKey(String),
    #[error("GRDR-CRYPTO-0003: invalid Ed25519 signature encoding: {0}")]
    InvalidSignature(String),
    #[error("GRDR-CRYPTO-0004: signature verification failed")]
    VerificationFailed,
    #[error("GRDR-CRYPTO-0005: canonical payload serialization failed: {0}")]
    Serialization(String),
    #[error("GRDR-CRYPTO-0006: key storage I/O failed: {0}")]
    Io(String),
}

#[derive(Clone)]
pub struct SigningKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
}

#[derive(Serialize)]
struct CanonicalRule<'a> {
    id: &'a str,
    title: &'a str,
    description: &'a str,
    mode: Mode,
    min_grade: ApprovalGrade,
    enabled: bool,
    locked: bool,
    matcher: &'a RuleMatch,
    reason_template: &'a str,
}

#[derive(Serialize)]
struct CanonicalPack<'a> {
    id: &'a str,
    name: &'a str,
    description: &'a str,
    version: &'a str,
    channel: &'a str,
    rules: Vec<CanonicalRule<'a>>,
}

#[derive(Serialize)]
struct CanonicalGrant<'a> {
    grant_id: &'a str,
    rule_id: &'a str,
    session_id: &'a str,
    device_id: &'a str,
    action_class: ActionClass,
    target_pattern: &'a str,
    scope: GrantScope,
    grade: ApprovalGrade,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,
    remaining_uses: Option<u32>,
    note: &'a str,
}

#[derive(Serialize)]
struct CanonicalReceipt<'a> {
    receipt_id: &'a str,
    attempt_id: &'a str,
    session_id: &'a str,
    device_id: &'a str,
    agent_name: &'a str,
    action_class: ActionClass,
    control_point: ControlPoint,
    target: &'a str,
    verdict: Verdict,
    would_be: Option<Verdict>,
    rule_id: Option<&'a str>,
    pack_id: Option<&'a str>,
    mode_applied: Option<Mode>,
    grant_id: Option<&'a str>,
    reason: &'a str,
    next_step: &'a str,
    receipt_digest: &'a str,
    decided_at: Timestamp,
}

#[derive(Serialize)]
struct CanonicalFloorTable<'a> {
    version: u32,
    compiled_at: Timestamp,
    rules: &'a [CompiledFloorRule],
}

impl SigningKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let key_id = compute_key_id(verifying_key.as_bytes());
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    pub fn from_seed_b64(raw: &str) -> Result<Self, CryptoError> {
        let bytes = B64
            .decode(raw.trim())
            .map_err(|e| CryptoError::InvalidKey(format!("base64 decode failed: {e}")))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("seed must be 32 bytes".into()))?;
        Ok(Self::from_seed(seed))
    }

    pub fn seed_b64(&self) -> String {
        B64.encode(self.signing_key.to_bytes())
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying_key.as_bytes())
    }

    pub fn public_info(&self) -> TrustedKeyInfo {
        TrustedKeyInfo {
            key_id: self.key_id.clone(),
            public_key_b64: self.public_key_b64(),
        }
    }

    pub fn sign_bytes(&self, domain: &str, payload: &[u8]) -> String {
        let message = domain_separated_message(domain, payload);
        let sig = self.signing_key.sign(&message);
        B64.encode(sig.to_bytes())
    }

    pub fn sign_pack(&self, pack: &mut PolicyPack) -> Result<(), CryptoError> {
        let payload = canonical_pack_bytes(pack)?;
        pack.key_id = Some(self.key_id.clone());
        pack.signature = Some(self.sign_bytes(DOMAIN_PACK, &payload));
        Ok(())
    }

    pub fn sign_grant(&self, grant: &mut Grant) -> Result<(), CryptoError> {
        let payload = canonical_grant_bytes(grant)?;
        grant.key_id = Some(self.key_id.clone());
        grant.signature = Some(self.sign_bytes(DOMAIN_GRANT, &payload));
        Ok(())
    }

    pub fn sign_receipt(&self, receipt: &mut DecisionReceipt) -> Result<(), CryptoError> {
        let payload = canonical_receipt_bytes(receipt)?;
        receipt.key_id = Some(self.key_id.clone());
        receipt.signature = Some(self.sign_bytes(DOMAIN_RECEIPT, &payload));
        receipt.signature_verified = Some(true);
        Ok(())
    }

    pub fn sign_floor_table(&self, table: &mut CompiledFloorTable) -> Result<(), CryptoError> {
        let payload = canonical_floor_bytes(table)?;
        table.key_id = Some(self.key_id.clone());
        table.signature = Some(self.sign_bytes(DOMAIN_FLOOR, &payload));
        Ok(())
    }
}

pub fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|e| CryptoError::Entropy(e.to_string()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

pub fn load_or_create_keypair(path: &Path) -> Result<SigningKeypair, CryptoError> {
    if path.exists() {
        let raw = fs::read_to_string(path)
            .map_err(|e| CryptoError::Io(format!("read {}: {e}", path.display())))?;
        return SigningKeypair::from_seed_b64(&raw);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CryptoError::Io(format!("create {}: {e}", parent.display())))?;
    }
    let kp = SigningKeypair::generate()?;
    let tmp = path.with_extension("key.tmp");
    fs::write(&tmp, kp.seed_b64())
        .map_err(|e| CryptoError::Io(format!("write {}: {e}", tmp.display())))?;
    fs::rename(&tmp, path)
        .map_err(|e| CryptoError::Io(format!("rename {}: {e}", path.display())))?;
    Ok(kp)
}

pub fn verify_bytes(
    public_key_b64: &str,
    domain: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), CryptoError> {
    let pk_bytes = B64
        .decode(public_key_b64.trim())
        .map_err(|e| CryptoError::InvalidKey(format!("base64 decode failed: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("public key must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 public key: {e}")))?;

    let sig_bytes = B64
        .decode(signature_b64.trim())
        .map_err(|e| CryptoError::InvalidSignature(format!("base64 decode failed: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let message = domain_separated_message(domain, payload);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

pub fn verify_pack(pack: &PolicyPack, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        pack.key_id.as_deref(),
        pack.signature.as_deref(),
        keys,
        DOMAIN_PACK,
        || canonical_pack_bytes(pack),
    )
}

pub fn verify_grant(grant: &Grant, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        grant.key_id.as_deref(),
        grant.signature.as_deref(),
        keys,
        DOMAIN_GRANT,
        || canonical_grant_bytes(grant),
    )
}

pub fn verify_receipt(receipt: &DecisionReceipt, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        receipt.key_id.as_deref(),
        receipt.signature.as_deref(),
        keys,
        DOMAIN_RECEIPT,
        || canonical_receipt_bytes(receipt),
    )
}

pub fn verify_floor_table(table: &CompiledFloorTable, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        table.key_id.as_deref(),
        table.signature.as_deref(),
        keys,
        DOMAIN_FLOOR,
        || canonical_floor_bytes(table),
    )
}

fn verify_with_metadata<F>(
    key_id: Option<&str>,
    signature: Option<&str>,
    keys: &[TrustedKeyInfo],
    domain: &str,
    build_payload: F,
) -> SignatureStatus
where
    F: FnOnce() -> Result<Vec<u8>, CryptoError>,
{
    let (Some(kid), Some(sig)) = (key_id, signature) else {
        return SignatureStatus::Unsigned;
    };
    let Some(trusted) = keys.iter().find(|k| k.key_id == kid) else {
        return SignatureStatus::Invalid;
    };
    let Ok(payload) = build_payload() else {
        return SignatureStatus::Invalid;
    };
    match verify_bytes(&trusted.public_key_b64, domain, &payload, sig) {
        Ok(()) => SignatureStatus::Verified,
        Err(_) => SignatureStatus::Invalid,
    }
}

fn canonical_pack_bytes(pack: &PolicyPack) -> Result<Vec<u8>, CryptoError> {
    let rules = pack
        .rules
        .iter()
        .map(|r| CanonicalRule {
            id: &r.id,
            title: &r.title,
            description: &r.description,
            mode: r.mode,
            min_grade: r.min_grade,
            enabled: r.enabled,
            locked: r.locked,
            matcher: &r.matcher,
            reason_template: &r.reason_template,
        })
        .collect();
    let canonical = CanonicalPack {
        id: &pack.id,
        name: &pack.name,
        description: &pack.description,
        version: &pack.version,
        channel: &pack.channel,
        rules,
    };
    serde_json::to_vec(&canonical).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn canonical_grant_bytes(grant: &Grant) -> Result<Vec<u8>, CryptoError> {
    let canonical = CanonicalGrant {
        grant_id: &grant.grant_id,
        rule_id: &grant.rule_id,
        session_id: &grant.session_id,
        device_id: &grant.device_id,
        action_class: grant.action_class,
        target_pattern: &grant.target_pattern,
        scope: grant.scope,
        grade: grant.grade,
        granted_at: grant.granted_at,
        expires_at: grant.expires_at,
        remaining_uses: grant.remaining_uses,
        note: &grant.note,
    };
    serde_json::to_vec(&canonical).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn canonical_receipt_bytes(receipt: &DecisionReceipt) -> Result<Vec<u8>, CryptoError> {
    let canonical = CanonicalReceipt {
        receipt_id: &receipt.receipt_id,
        attempt_id: &receipt.attempt_id,
        session_id: &receipt.session_id,
        device_id: &receipt.device_id,
        agent_name: &receipt.agent_name,
        action_class: receipt.action_class,
        control_point: receipt.control_point,
        target: &receipt.target,
        verdict: receipt.verdict,
        would_be: receipt.would_be,
        rule_id: receipt.rule_id.as_deref(),
        pack_id: receipt.pack_id.as_deref(),
        mode_applied: receipt.mode_applied,
        grant_id: receipt.grant_id.as_deref(),
        reason: &receipt.reason,
        next_step: &receipt.next_step,
        receipt_digest: &receipt.receipt_digest,
        decided_at: receipt.decided_at,
    };
    serde_json::to_vec(&canonical).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn canonical_floor_bytes(table: &CompiledFloorTable) -> Result<Vec<u8>, CryptoError> {
    let canonical = CanonicalFloorTable {
        version: table.version,
        compiled_at: table.compiled_at,
        rules: &table.rules,
    };
    serde_json::to_vec(&canonical).map_err(|e| CryptoError::Serialization(e.to_string()))
}

fn domain_separated_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SIGNATURE_DOMAIN_PREFIX
            .len()
            .saturating_add(domain.len())
            .saturating_add(1)
            .saturating_add(payload.len()),
    );
    out.extend_from_slice(SIGNATURE_DOMAIN_PREFIX);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

fn compute_key_id(public_key: &[u8; 32]) -> String {
    let hex = sha256_hex(public_key);
    let prefix: String = hex.chars().take(16).collect();
    format!("kid_{prefix}")
}

fn hex_nibble(value: u8) -> char {
    match value & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::eval::essentials_pack;

    #[test]
    fn ed25519_pack_signing_verifies_and_detects_tampering() {
        let kp = SigningKeypair::generate().unwrap();
        let keys = vec![kp.public_info()];

        let mut pack = essentials_pack();
        assert_eq!(verify_pack(&pack, &keys), SignatureStatus::Unsigned);

        kp.sign_pack(&mut pack).unwrap();
        assert_eq!(verify_pack(&pack, &keys), SignatureStatus::Verified);

        // Telemetry counter bumps must not invalidate the signed policy definition.
        pack.rules[0].hits = 42;
        assert_eq!(verify_pack(&pack, &keys), SignatureStatus::Verified);

        // Mutating rule mode must invalidate the signature.
        pack.rules[0].mode = Mode::Off;
        assert_eq!(verify_pack(&pack, &keys), SignatureStatus::Invalid);
    }

    #[test]
    fn keypair_persists_and_reloads_from_disk() {
        let dir = std::env::temp_dir().join(format!("grdr-crypto-test-{}", std::process::id()));
        let key_path = dir.join("signing.key");
        let _ = fs::remove_dir_all(&dir);

        let kp1 = load_or_create_keypair(&key_path).unwrap();
        let kp2 = load_or_create_keypair(&key_path).unwrap();
        assert_eq!(kp1.key_id(), kp2.key_id());
        assert_eq!(kp1.public_key_b64(), kp2.public_key_b64());

        let _ = fs::remove_dir_all(&dir);
    }
}
