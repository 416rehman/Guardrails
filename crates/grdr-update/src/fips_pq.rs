// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_crypto::{SigningKeypair, constant_time_eq, hmac_sha256, sha256_hex};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;
use crate::tuf_types::{
    RootMetadata, SignatureAlgorithm, SignedMetadata, TufRole, canonical_json,
    verify_role_signatures,
};

pub const ML_DSA_65_SIG_BYTES: usize = 3_309;
pub const ML_DSA_65_PUBKEY_BYTES: usize = 1_952;

const NIST_SHA256_ABC_EXPECTED: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const RFC8032_VEC1_PUBKEY_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const RFC4231_TC1_EXPECTED: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOsProfile {
    Linux,
    Windows,
    MacOs,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FipsMode {
    Disabled,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KatOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsKatCheck {
    pub primitive: String,
    pub outcome: KatOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fips_state", rename_all = "snake_case")]
pub enum FipsSelfTestState {
    Passed {
        module_name: String,
        provider_id: String,
        tested_at: Timestamp,
    },
    NotSupportedNoClaim {
        os: HostOsProfile,
        detail: String,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsSbomProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsSelfTestReport {
    pub os: HostOsProfile,
    pub fips_policy: FipsMode,
    pub state: FipsSelfTestState,
    pub kat_checks: Vec<FipsKatCheck>,
    pub sbom_properties: Vec<FipsSbomProperty>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPolicyActivation {
    ClassicalOnly,
    HybridDualRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublicKeyRecord {
    pub keyid: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key_b64: String,
    pub pubkey_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEntry {
    pub keyid: String,
    pub algorithm: SignatureAlgorithm,
    pub sig_b64: String,
    pub pubkey_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSignedPayload<T> {
    pub classical: SignedMetadata<T>,
    pub pq_signatures: Vec<PqSignatureEntry>,
}

pub trait PqVerifierBackend {
    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), UpdateError>;
}

pub struct FailClosedPqBackend;

impl PqVerifierBackend for FailClosedPqBackend {
    fn verify_ml_dsa_65(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), UpdateError> {
        Err(UpdateError::InvalidSignature(
            "UnsupportedAlgorithm: FIPS 204 ML-DSA-65 cryptographic verification backend is not active in this build"
                .into(),
        ))
    }
}

pub fn run_fips_startup_self_test(
    os: HostOsProfile,
    fips_policy: FipsMode,
    now: Timestamp,
) -> Result<FipsSelfTestReport, UpdateError> {
    let mut kat_checks = Vec::new();
    let sha_ok = sha256_hex(b"abc") == NIST_SHA256_ABC_EXPECTED;
    kat_checks.push(FipsKatCheck {
        primitive: "SHA-256-CAVP".into(),
        outcome: bool_kat(sha_ok),
    });

    let hmac_out = hmac_sha256(&[0x0bu8; 20], b"Hi There");
    let hmac_ok = hmac_out == RFC4231_TC1_EXPECTED;
    kat_checks.push(FipsKatCheck {
        primitive: "HMAC-SHA256-RFC4231".into(),
        outcome: bool_kat(hmac_ok),
    });

    let ed_seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let kp = SigningKeypair::from_seed(ed_seed);
    let sig = kp.sign_bytes("fips.kat.v1", b"grdr-kat");
    let ed_ok = kp.public_key_b64() == RFC8032_VEC1_PUBKEY_B64
        && grdr_crypto::verify_bytes(&kp.public_key_b64(), "fips.kat.v1", b"grdr-kat", &sig)
            .is_ok();
    kat_checks.push(FipsKatCheck {
        primitive: "Ed25519-RFC8032".into(),
        outcome: bool_kat(ed_ok),
    });

    if !sha_ok || !hmac_ok || !ed_ok {
        return Err(UpdateError::SecurityFloorViolation { found: 0, floor: 1 });
    }

    // Pure-Rust build does not link an OS-validated CMVP FIPS 140-3 provider (ARCH-006).
    if fips_policy == FipsMode::Required {
        return Err(UpdateError::SecurityFloorViolation { found: 0, floor: 1 });
    }

    let (status_value, detail) = match os {
        HostOsProfile::MacOs => (
            "not-claimed-macos",
            "macOS host does not claim active FIPS 140-3 validated cryptography in Guardrails ADR",
        ),
        HostOsProfile::Linux | HostOsProfile::Windows | HostOsProfile::Other => (
            "not-claimed-non-fips-build",
            "pure-Rust cryptographic build has no active CMVP FIPS 140-3 validated module",
        ),
    };

    Ok(FipsSelfTestReport {
        os,
        fips_policy,
        state: FipsSelfTestState::NotSupportedNoClaim {
            os,
            detail: detail.to_owned(),
        },
        kat_checks,
        sbom_properties: vec![
            FipsSbomProperty {
                name: "guardrails:fips:status".into(),
                value: status_value.into(),
            },
            FipsSbomProperty {
                name: "guardrails:fips:kat_checked_at".into(),
                value: now.to_string(),
            },
        ],
    })
}

pub fn verify_dual_signed_payload<T: Serialize>(
    root: &RootMetadata,
    role: TufRole,
    pq_activation: PqPolicyActivation,
    pq_keys: &[PqPublicKeyRecord],
    bundle: &DualSignedPayload<T>,
    backend: &dyn PqVerifierBackend,
) -> Result<(), UpdateError> {
    verify_role_signatures(root, role, &bundle.classical)?;

    if pq_activation == PqPolicyActivation::ClassicalOnly {
        return Ok(());
    }

    let Some(pq_role_def) = root.roles.get(&TufRole::PostQuantum) else {
        return Err(UpdateError::UnauthorizedRoot(
            "dual PQ mode requires TufRole::PostQuantum authorization in root".into(),
        ));
    };
    if pq_role_def.threshold < 1 {
        return Err(UpdateError::InvalidSignature(
            "PostQuantum TUF role threshold must be >= 1".into(),
        ));
    }
    if bundle.pq_signatures.is_empty() {
        return Err(UpdateError::InvalidSignature(
            "dual classical + ML-DSA-65 policy active: missing ML-DSA-65 signature".into(),
        ));
    }

    let raw_payload = canonical_json(&bundle.classical.signed)?;
    let mut verified_kids: BTreeSet<&str> = BTreeSet::new();
    let mut verified_pubkeys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut verified_pq: u32 = 0;

    for sig_entry in &bundle.pq_signatures {
        if sig_entry.algorithm != SignatureAlgorithm::MlDsa65 {
            continue;
        }
        if verified_kids.contains(sig_entry.keyid.as_str()) {
            continue;
        }
        if !pq_role_def.key_ids.iter().any(|k| k == &sig_entry.keyid) {
            continue;
        }
        let Some(pk_rec) = pq_keys.iter().find(|k| {
            k.keyid == sig_entry.keyid
                && k.algorithm == SignatureAlgorithm::MlDsa65
                && pq_role_def.key_ids.iter().any(|id| id == &k.keyid)
        }) else {
            continue;
        };
        let pk_bytes = B64.decode(pk_rec.public_key_b64.trim()).map_err(|e| {
            UpdateError::InvalidSignature(format!("invalid ML-DSA-65 public key b64: {e}"))
        })?;
        if pk_bytes.len() != ML_DSA_65_PUBKEY_BYTES {
            return Err(UpdateError::InvalidSignature(format!(
                "ML-DSA-65 public key length {} != {}",
                pk_bytes.len(),
                ML_DSA_65_PUBKEY_BYTES
            )));
        }
        if verified_pubkeys.contains(&pk_bytes) {
            continue;
        }
        let actual_pk_sha = sha256_hex(&pk_bytes);
        if !constant_time_eq(actual_pk_sha.as_bytes(), pk_rec.pubkey_sha256.as_bytes())
            || !constant_time_eq(actual_pk_sha.as_bytes(), sig_entry.pubkey_sha256.as_bytes())
        {
            continue;
        }
        let sig_bytes = B64.decode(sig_entry.sig_b64.trim()).map_err(|e| {
            UpdateError::InvalidSignature(format!("invalid ML-DSA-65 signature b64: {e}"))
        })?;
        if sig_bytes.len() != ML_DSA_65_SIG_BYTES {
            return Err(UpdateError::InvalidSignature(format!(
                "ML-DSA-65 signature length {} != {}",
                sig_bytes.len(),
                ML_DSA_65_SIG_BYTES
            )));
        }
        if backend
            .verify_ml_dsa_65(&pk_bytes, &raw_payload, &sig_bytes)
            .is_ok()
        {
            verified_kids.insert(sig_entry.keyid.as_str());
            verified_pubkeys.insert(pk_bytes);
            verified_pq = verified_pq.saturating_add(1);
        }
    }

    if verified_pq < pq_role_def.threshold {
        return Err(UpdateError::InvalidSignature(format!(
            "ML-DSA-65 threshold failed: verified {verified_pq} < required {}",
            pq_role_def.threshold
        )));
    }
    Ok(())
}

fn bool_kat(passed: bool) -> KatOutcome {
    if passed {
        KatOutcome::Passed
    } else {
        KatOutcome::Failed
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use grdr_crypto::domain_sha256_digest;
    use grdr_model::TrustedKeyInfo;

    use super::*;
    use crate::tuf_types::{RootKeyRole, TargetsMetadata, TufRootKind, sign_metadata};

    struct TestOnlyPqBackend;

    impl PqVerifierBackend for TestOnlyPqBackend {
        fn verify_ml_dsa_65(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), UpdateError> {
            let expected = domain_sha256_digest("test.pq.mldsa65", &[public_key, message].concat());
            let prefix = signature.get(..32).ok_or_else(|| {
                UpdateError::InvalidSignature("missing test signature prefix".into())
            })?;
            if !constant_time_eq(prefix, &expected) {
                return Err(UpdateError::InvalidSignature("test PQ mismatch".into()));
            }
            Ok(())
        }
    }

    fn mk_test_pq_sig(keyid: &str, pk: &[u8], msg: &[u8]) -> PqSignatureEntry {
        let digest = domain_sha256_digest("test.pq.mldsa65", &[pk, msg].concat());
        let mut sig = vec![0x24u8; ML_DSA_65_SIG_BYTES];
        for (d, s) in sig.iter_mut().zip(digest.iter()) {
            *d = *s;
        }
        PqSignatureEntry {
            keyid: keyid.to_owned(),
            algorithm: SignatureAlgorithm::MlDsa65,
            sig_b64: B64.encode(sig),
            pubkey_sha256: sha256_hex(pk),
        }
    }

    #[test]
    fn fips_non_claim_and_fail_closed_pq_checks() {
        let now = Timestamp::from_second(1_750_000_000).expect("ts");
        let disabled =
            run_fips_startup_self_test(HostOsProfile::Linux, FipsMode::Disabled, now).expect("ok");
        assert!(matches!(
            disabled.state,
            FipsSelfTestState::NotSupportedNoClaim { .. }
        ));
        assert!(
            disabled
                .sbom_properties
                .iter()
                .any(|p| p.name == "guardrails:fips:status"
                    && p.value == "not-claimed-non-fips-build")
        );
        assert!(matches!(
            run_fips_startup_self_test(HostOsProfile::Linux, FipsMode::Required, now),
            Err(UpdateError::SecurityFloorViolation { .. })
        ));
        assert!(matches!(
            run_fips_startup_self_test(HostOsProfile::Windows, FipsMode::Required, now),
            Err(UpdateError::SecurityFloorViolation { .. })
        ));

        let k1 = SigningKeypair::generate().expect("k1");
        let pq_pub = vec![0x99u8; ML_DSA_65_PUBKEY_BYTES];
        let pq_rec_a = PqPublicKeyRecord {
            keyid: "pq-a".into(),
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key_b64: B64.encode(&pq_pub),
            pubkey_sha256: sha256_hex(&pq_pub),
        };
        let pq_rec_b = PqPublicKeyRecord {
            keyid: "pq-b".into(),
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key_b64: B64.encode(&pq_pub),
            pubkey_sha256: sha256_hex(&pq_pub),
        };
        let root = RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires: Timestamp::from_second(1_780_000_000).expect("exp"),
            keys: BTreeMap::from([(
                k1.key_id().to_owned(),
                TrustedKeyInfo {
                    key_id: k1.key_id().to_owned(),
                    public_key_b64: k1.public_key_b64(),
                },
            )]),
            roles: BTreeMap::from([
                (
                    TufRole::Targets,
                    RootKeyRole {
                        key_ids: vec![k1.key_id().to_owned()],
                        threshold: 1,
                    },
                ),
                (
                    TufRole::PostQuantum,
                    RootKeyRole {
                        key_ids: vec!["pq-a".into(), "pq-b".into()],
                        threshold: 2,
                    },
                ),
            ]),
        };
        let targets = TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires: Timestamp::from_second(1_780_000_000).expect("exp"),
            targets: BTreeMap::new(),
        };
        let classical = sign_metadata(targets, &[&k1]).expect("sign");
        let raw = serde_json::to_vec(&classical.signed).expect("json");
        let dup_bundle = DualSignedPayload {
            classical,
            pq_signatures: vec![
                mk_test_pq_sig("pq-a", &pq_pub, &raw),
                mk_test_pq_sig("pq-b", &pq_pub, &raw),
            ],
        };
        assert!(matches!(
            verify_dual_signed_payload(
                &root,
                TufRole::Targets,
                PqPolicyActivation::HybridDualRequired,
                &[pq_rec_a.clone(), pq_rec_b.clone()],
                &dup_bundle,
                &FailClosedPqBackend,
            ),
            Err(UpdateError::InvalidSignature(_))
        ));
        assert!(matches!(
            verify_dual_signed_payload(
                &root,
                TufRole::Targets,
                PqPolicyActivation::HybridDualRequired,
                &[pq_rec_a, pq_rec_b],
                &dup_bundle,
                &TestOnlyPqBackend,
            ),
            Err(UpdateError::InvalidSignature(_))
        ));
    }
}
