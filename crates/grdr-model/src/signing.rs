// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Domain-separated Ed25519 signing and verification helpers for policy packs, grants, receipts, and floor tables.

use grdr_crypto::{CryptoError, SigningKeypair, verify_bytes};
use jiff::Timestamp;
use serde::Serialize;

use crate::{
    ActionClass, ApprovalGrade, CompiledFloorRule, CompiledFloorTable, ControlPoint,
    DecisionReceipt, Grant, GrantScope, Mode, PolicyPack, RuleMatch, SignatureStatus,
    TrustedKeyInfo, Verdict,
};

const DOMAIN_PACK: &str = "policy_pack";
const DOMAIN_GRANT: &str = "grant";
const DOMAIN_RECEIPT: &str = "decision_receipt";
const DOMAIN_FLOOR: &str = "compiled_floor_table";

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
    cedar: Option<&'a str>,
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

pub trait SigningKeypairExt {
    fn public_info(&self) -> TrustedKeyInfo;
    fn sign_pack(&self, pack: &mut PolicyPack) -> Result<(), CryptoError>;
    fn sign_grant(&self, grant: &mut Grant) -> Result<(), CryptoError>;
    fn sign_receipt(&self, receipt: &mut DecisionReceipt) -> Result<(), CryptoError>;
    fn sign_floor_table(&self, table: &mut CompiledFloorTable) -> Result<(), CryptoError>;
}

impl SigningKeypairExt for SigningKeypair {
    fn public_info(&self) -> TrustedKeyInfo {
        TrustedKeyInfo {
            key_id: self.key_id().to_owned(),
            public_key_b64: self.public_key_b64(),
        }
    }

    fn sign_pack(&self, pack: &mut PolicyPack) -> Result<(), CryptoError> {
        let payload = canonical_pack_bytes(pack)?;
        pack.key_id = Some(self.key_id().to_owned());
        pack.signature = Some(self.sign_bytes(DOMAIN_PACK, &payload));
        Ok(())
    }

    fn sign_grant(&self, grant: &mut Grant) -> Result<(), CryptoError> {
        let payload = canonical_grant_bytes(grant)?;
        grant.key_id = Some(self.key_id().to_owned());
        grant.signature = Some(self.sign_bytes(DOMAIN_GRANT, &payload));
        Ok(())
    }

    fn sign_receipt(&self, receipt: &mut DecisionReceipt) -> Result<(), CryptoError> {
        let payload = canonical_receipt_bytes(receipt)?;
        receipt.key_id = Some(self.key_id().to_owned());
        receipt.signature = Some(self.sign_bytes(DOMAIN_RECEIPT, &payload));
        receipt.signature_verified = Some(true);
        Ok(())
    }

    fn sign_floor_table(&self, table: &mut CompiledFloorTable) -> Result<(), CryptoError> {
        let payload = canonical_floor_bytes(table)?;
        table.key_id = Some(self.key_id().to_owned());
        table.signature = Some(self.sign_bytes(DOMAIN_FLOOR, &payload));
        Ok(())
    }
}

#[must_use]
pub fn verify_pack(pack: &PolicyPack, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        pack.key_id.as_deref(),
        pack.signature.as_deref(),
        keys,
        DOMAIN_PACK,
        || canonical_pack_bytes(pack),
    )
}

#[must_use]
pub fn verify_grant(grant: &Grant, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        grant.key_id.as_deref(),
        grant.signature.as_deref(),
        keys,
        DOMAIN_GRANT,
        || canonical_grant_bytes(grant),
    )
}

#[must_use]
pub fn verify_receipt(receipt: &DecisionReceipt, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    verify_with_metadata(
        receipt.key_id.as_deref(),
        receipt.signature.as_deref(),
        keys,
        DOMAIN_RECEIPT,
        || canonical_receipt_bytes(receipt),
    )
}

#[must_use]
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

fn serialize_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(value).map_err(|e| CryptoError::Serialization(e.to_string()))
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
            cedar: r.cedar.as_deref(),
        })
        .collect();
    serialize_canonical(&CanonicalPack {
        id: &pack.id,
        name: &pack.name,
        description: &pack.description,
        version: &pack.version,
        channel: &pack.channel,
        rules,
    })
}

fn canonical_grant_bytes(grant: &Grant) -> Result<Vec<u8>, CryptoError> {
    serialize_canonical(&CanonicalGrant {
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
    })
}

fn canonical_receipt_bytes(receipt: &DecisionReceipt) -> Result<Vec<u8>, CryptoError> {
    serialize_canonical(&CanonicalReceipt {
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
    })
}

fn canonical_floor_bytes(table: &CompiledFloorTable) -> Result<Vec<u8>, CryptoError> {
    serialize_canonical(&CanonicalFloorTable {
        version: table.version,
        compiled_at: table.compiled_at,
        rules: &table.rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::essentials_pack;

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
}
