// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Cryptographic Ed25519 verification for signed detection packs (`packs/*/signature.json`, `P14`, `D-09`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use grdr_crypto::sha256_hex;
use serde::Deserialize;

use crate::analyze::pack_io::{
    collect_signed_pack_digests, detections_max_bytes, ensure_real_dir, pack_list_max_bytes,
    read_bounded_regular_bytes, read_bounded_regular_text, safe_pack_child_path,
};
use crate::detect::json_strict::reject_duplicate_json_keys;
pub use crate::detect::pack_trust::parse_trust_roots_toml;
use crate::detect::pack_trust::{is_lower_hex_sha256, verify_pack_ed25519_strict};
use crate::detect::types::{DetectError, VerifiedDetectionContent};
use grdr_model::Mode;

const PACK_SIG_FORMAT: &str = "grdr.pack.signature.v1";
const PACK_SIG_DOMAIN: &str = "grdr.pack.manifest.v1";
const MAX_SIG_JSON_BYTES: u64 = 1_048_576;
const MAX_RULE_FILE_BYTES: u64 = 1_048_576;

const EMBEDDED_TRUST_ROOTS_TOML: &str = include_str!("../../../../packs/trust-roots.toml");
const EMBEDDED_DETECTIONS_SIG_JSON: &str =
    include_str!("../../../../packs/detections/signature.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackFileDigest {
    path: String,
    sha256: String,
    length: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackSignatureDoc {
    format: String,
    pack_id: String,
    version: String,
    domain: String,
    signer_ref: String,
    verifier_ed25519_b64: String,
    manifest_sha256: String,
    files: Vec<RawPackFileDigest>,
    signature_b64: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedSignedPack {
    pub pack_id: String,
    pub version: String,
    pub signer_ref: String,
    pub verified_file_sha256s: BTreeMap<String, (String, u64)>,
    pub verified_rule_sha256s: BTreeSet<String>,
}

/// Cryptographically verifies a pack `signature.json` document against active `trust-roots.toml` keys.
pub fn verify_pack_signature_json(
    sig_json: &str,
    trust_roots_toml: &str,
    expected_pack_id: &str,
) -> Result<VerifiedSignedPack, DetectError> {
    if u64::try_from(sig_json.len()).unwrap_or(u64::MAX) > MAX_SIG_JSON_BYTES {
        return Err(DetectError::ResponseBreaker(
            "pack signature JSON exceeds byte bound".into(),
        ));
    }
    reject_duplicate_json_keys(sig_json).map_err(DetectError::ResponseBreaker)?;
    let active = parse_trust_roots_toml(trust_roots_toml)?;
    let sig: RawPackSignatureDoc = serde_json::from_str(sig_json)
        .map_err(|e| DetectError::ResponseBreaker(format!("invalid pack signature JSON: {e}")))?;
    if sig.format != PACK_SIG_FORMAT || sig.domain != PACK_SIG_DOMAIN {
        return Err(DetectError::ResponseBreaker(
            "invalid pack signature format or domain".into(),
        ));
    }
    if sig.pack_id != expected_pack_id || sig.version.is_empty() {
        return Err(DetectError::ResponseBreaker(format!(
            "pack signature pack_id `{}` != expected `{expected_pack_id}`",
            sig.pack_id
        )));
    }
    if sig.files.is_empty() {
        return Err(DetectError::ResponseBreaker(
            "pack signature file manifest cannot be empty".into(),
        ));
    }
    let trusted_pub = active.get(&sig.signer_ref).ok_or_else(|| {
        DetectError::ResponseBreaker(format!(
            "untrusted or revoked signer_ref `{}`",
            sig.signer_ref
        ))
    })?;
    if trusted_pub.trim() != sig.verifier_ed25519_b64.trim() {
        return Err(DetectError::ResponseBreaker(
            "signature verifier key disagrees with trust-roots.toml".into(),
        ));
    }
    if !is_lower_hex_sha256(&sig.manifest_sha256) {
        return Err(DetectError::ResponseBreaker(
            "invalid manifest_sha256 hex digest".into(),
        ));
    }

    let payload = canonical_manifest_text(&sig.pack_id, &sig.version, &sig.files)?;
    let manifest_digest = sha256_hex(payload.as_bytes());
    if manifest_digest != sig.manifest_sha256 {
        return Err(DetectError::ResponseBreaker(
            "pack manifest_sha256 mismatch".into(),
        ));
    }
    verify_pack_ed25519_strict(
        trusted_pub,
        &sig.domain,
        payload.as_bytes(),
        &sig.signature_b64,
    )?;

    let mut verified_file_sha256s = BTreeMap::new();
    let mut verified_rule_sha256s = BTreeSet::new();
    let mut prev_path: Option<&str> = None;
    for f in &sig.files {
        if !is_lower_hex_sha256(&f.sha256) {
            return Err(DetectError::ResponseBreaker(format!(
                "invalid sha256 hex for `{}`",
                f.path
            )));
        }
        if let Some(prev) = prev_path
            && prev >= f.path.as_str()
        {
            return Err(DetectError::ResponseBreaker(
                "signed pack file list is unsorted or contains duplicates".into(),
            ));
        }
        prev_path = Some(&f.path);
        verified_file_sha256s.insert(f.path.clone(), (f.sha256.clone(), f.length));
        if f.path.starts_with("rules/") && f.path.ends_with(".yaml") {
            verified_rule_sha256s.insert(f.sha256.clone());
        }
    }

    Ok(VerifiedSignedPack {
        pack_id: sig.pack_id,
        version: sig.version,
        signer_ref: sig.signer_ref,
        verified_file_sha256s,
        verified_rule_sha256s,
    })
}

/// Loads and cryptographically verifies a signed detection pack directory on disk against `trust-roots.toml`.
pub fn load_signed_detection_pack_from_dir(
    pack_dir: &Path,
    trust_roots_path: &Path,
    expected_pack_id: &str,
    pack_mode: Mode,
) -> Result<(VerifiedDetectionContent, VerifiedSignedPack), DetectError> {
    let max_pack_bytes = detections_max_bytes().map_err(DetectError::ResponseBreaker)?;
    let max_list_bytes = pack_list_max_bytes().map_err(DetectError::ResponseBreaker)?;
    let per_file_cap = MAX_RULE_FILE_BYTES.min(max_pack_bytes);
    ensure_real_dir(pack_dir, "detection pack dir").map_err(DetectError::ResponseBreaker)?;

    let trust_raw = read_bounded_regular_text(trust_roots_path, max_list_bytes)
        .map_err(DetectError::ResponseBreaker)?;
    let sig_path =
        safe_pack_child_path(pack_dir, "signature.json").map_err(DetectError::ResponseBreaker)?;
    let sig_raw = read_bounded_regular_text(&sig_path, MAX_SIG_JSON_BYTES.min(max_pack_bytes))
        .map_err(DetectError::ResponseBreaker)?;
    let verified = verify_pack_signature_json(&sig_raw, &trust_raw, expected_pack_id)?;

    let mut total_bytes: u64 = 0;
    for (_, expected_len) in verified.verified_file_sha256s.values() {
        total_bytes = total_bytes
            .checked_add(*expected_len)
            .filter(|sum| *sum <= max_pack_bytes)
            .ok_or_else(|| {
                DetectError::ResponseBreaker(
                    "signed detection pack exceeds schema byte limit".into(),
                )
            })?;
    }

    let mut raw_rules_yaml = Vec::new();
    for (rel_path, (expected_sha, expected_len)) in &verified.verified_file_sha256s {
        let full =
            safe_pack_child_path(pack_dir, rel_path).map_err(DetectError::ResponseBreaker)?;
        let bytes = read_bounded_regular_bytes(&full, per_file_cap)
            .map_err(DetectError::ResponseBreaker)?;
        let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_len != *expected_len {
            return Err(DetectError::ResponseBreaker(format!(
                "signed file length mismatch for `{rel_path}`"
            )));
        }
        let actual_sha = sha256_hex(&bytes);
        if actual_sha != *expected_sha {
            return Err(DetectError::ResponseBreaker(format!(
                "signed file SHA-256 mismatch for `{rel_path}`"
            )));
        }
        if rel_path.starts_with("rules/") && rel_path.ends_with(".yaml") {
            let text = String::from_utf8(bytes).map_err(|_| {
                DetectError::InvalidRule(format!("signed rule `{rel_path}` is not UTF-8"))
            })?;
            raw_rules_yaml.push(text);
        }
    }

    let actual_digests = collect_signed_pack_digests(pack_dir, per_file_cap, max_pack_bytes)
        .map_err(DetectError::ResponseBreaker)?;
    if actual_digests.len() != verified.verified_file_sha256s.len() {
        return Err(DetectError::ResponseBreaker(
            "signed detection pack directory contains unsigned or extra files".into(),
        ));
    }
    for (rel_path, actual_sha, actual_len) in actual_digests {
        let Some((expected_sha, expected_len)) = verified.verified_file_sha256s.get(&rel_path)
        else {
            return Err(DetectError::ResponseBreaker(format!(
                "unsigned extra file `{rel_path}` in signed detection pack directory"
            )));
        };
        if actual_len != *expected_len || actual_sha != *expected_sha {
            return Err(DetectError::ResponseBreaker(format!(
                "directory parity mismatch for signed file `{rel_path}`"
            )));
        }
    }

    let content = VerifiedDetectionContent {
        pack_id: verified.pack_id.clone(),
        version: verified.version.clone(),
        raw_rules_yaml,
        pack_mode,
    };
    Ok((content, verified))
}

pub(crate) fn shipped_core_verified_rule_digests() -> Result<&'static BTreeSet<String>, DetectError>
{
    static CACHE: OnceLock<Result<BTreeSet<String>, String>> = OnceLock::new();
    let res = CACHE.get_or_init(|| {
        verify_pack_signature_json(
            EMBEDDED_DETECTIONS_SIG_JSON,
            EMBEDDED_TRUST_ROOTS_TOML,
            "grdr.det.core",
        )
        .map(|pack| pack.verified_rule_sha256s)
        .map_err(|e| e.to_string())
    });
    match res {
        Ok(set) => Ok(set),
        Err(msg) => Err(DetectError::ResponseBreaker(msg.clone())),
    }
}

fn canonical_manifest_text(
    pack_id: &str,
    version: &str,
    files: &[RawPackFileDigest],
) -> Result<String, DetectError> {
    validate_manifest_token(pack_id, "pack_id")?;
    validate_manifest_token(version, "version")?;
    let mut lines = Vec::with_capacity(files.len().saturating_add(3));
    lines.push(PACK_SIG_DOMAIN.to_owned());
    lines.push(pack_id.to_owned());
    lines.push(version.to_owned());
    for f in files {
        validate_manifest_token(&f.path, "file.path")?;
        validate_manifest_token(&f.sha256, "file.sha256")?;
        lines.push(format!("{} {} {}", f.path, f.sha256, f.length));
    }
    Ok(lines.join("\n"))
}

fn validate_manifest_token(val: &str, label: &str) -> Result<(), DetectError> {
    if val.is_empty() || val.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(DetectError::ResponseBreaker(format!(
            "canonical manifest `{label}` contains empty, whitespace, or control chars"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::engine::SigmaDetectionEngine;
    use crate::detect::types::{DeploymentScope, HostProfile};

    #[test]
    fn verifies_shipped_ed25519_detections_pack_and_rejects_tamper() {
        let verified = verify_pack_signature_json(
            EMBEDDED_DETECTIONS_SIG_JSON,
            EMBEDDED_TRUST_ROOTS_TOML,
            "grdr.det.core",
        )
        .expect("shipped signed detections pack");
        assert!(verified.verified_rule_sha256s.len() >= 46);

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let host = HostProfile {
            device_id: "dev".into(),
            device_name: "dev".into(),
            organisation_id: "org".into(),
            scope: DeploymentScope::Any,
            provenance_grade: 3,
            expand_vars: crate::detect::l0_vars::embedded_l0_expand_vars()
                .expect("embedded l0 vars"),
            model_audit_passed: false,
            remediate_approvers: BTreeMap::new(),
        };
        let (_eng, report) = SigmaDetectionEngine::load_signed_pack(
            &repo_root.join("packs/detections"),
            &repo_root.join("packs/trust-roots.toml"),
            "grdr.det.core",
            Mode::Watch,
            &host,
        )
        .expect("load signed detections pack from disk");
        assert_eq!(report.loaded_rules.len(), 46);
        assert!(report.skipped_rules.is_empty());

        let tampered_sig =
            EMBEDDED_DETECTIONS_SIG_JSON.replace("grdr-content-release-v1", "rogue-release-v1");
        assert!(
            verify_pack_signature_json(&tampered_sig, EMBEDDED_TRUST_ROOTS_TOML, "grdr.det.core",)
                .is_err()
        );

        let revoked_roots =
            EMBEDDED_TRUST_ROOTS_TOML.replace("status = \"active\"", "status = \"revoked\"");
        assert!(
            verify_pack_signature_json(
                EMBEDDED_DETECTIONS_SIG_JSON,
                &revoked_roots,
                "grdr.det.core",
            )
            .is_err()
        );

        let dup_json_sig = EMBEDDED_DETECTIONS_SIG_JSON.replace(
            "\"pack_id\": \"grdr.det.core\",",
            "\"pack_id\": \"grdr.det.core\", \"pack_id\": \"grdr.det.core\",",
        );
        assert!(
            verify_pack_signature_json(&dup_json_sig, EMBEDDED_TRUST_ROOTS_TOML, "grdr.det.core")
                .is_err()
        );

        let dup_ref_roots = format!(
            "{EMBEDDED_TRUST_ROOTS_TOML}\n[[signers]]\nsigner_ref = \"grdr-content-release-v1\"\nverifier_ed25519_b64 = \"yZLUmIo+llGBxrCT49SMCiFp7wpDhnA5NP+EX1pG+Wg=\"\nstatus = \"retired\"\n"
        );
        assert!(parse_trust_roots_toml(&dup_ref_roots).is_err());

        let garbage_roots = format!("{EMBEDDED_TRUST_ROOTS_TOML}\nnot_a_toml_line\n");
        assert!(parse_trust_roots_toml(&garbage_roots).is_err());

        let extra_key_roots = format!("{EMBEDDED_TRUST_ROOTS_TOML}\nunknown = \"x\"\n");
        assert!(parse_trust_roots_toml(&extra_key_roots).is_err());

        let empty_files_sig = serde_json::json!({
            "format": "grdr.pack.signature.v1",
            "pack_id": "grdr.det.core",
            "version": "1.0.0",
            "domain": "grdr.pack.manifest.v1",
            "signer_ref": "grdr-content-release-v1",
            "verifier_ed25519_b64": "yZLUmIo+llGBxrCT49SMCiFp7wpDhnA5NP+EX1pG+Wg=",
            "manifest_sha256": "0".repeat(64),
            "files": [],
            "signature_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        })
        .to_string();
        assert!(
            verify_pack_signature_json(
                &empty_files_sig,
                EMBEDDED_TRUST_ROOTS_TOML,
                "grdr.det.core"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_extra_unsigned_and_crlf_tampered_detection_pack_files() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let src_pack = repo_root.join("packs/detections");
        let tmp =
            std::env::temp_dir().join(format!("grdr-w1-2-pack-parity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("rules")).expect("mkdir");
        for entry in std::fs::read_dir(&src_pack).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_file() {
                std::fs::copy(&path, tmp.join(entry.file_name())).expect("copy root");
            } else if path.is_dir() {
                let dst_sub = tmp.join(entry.file_name());
                std::fs::create_dir_all(&dst_sub).expect("mkdir sub");
                for sub in std::fs::read_dir(&path).expect("read sub") {
                    let sub = sub.expect("sub");
                    std::fs::copy(sub.path(), dst_sub.join(sub.file_name())).expect("copy sub");
                }
            }
        }

        let host = HostProfile {
            device_id: "dev".into(),
            device_name: "dev".into(),
            organisation_id: "org".into(),
            scope: DeploymentScope::Any,
            provenance_grade: 3,
            expand_vars: BTreeMap::new(),
            model_audit_passed: false,
            remediate_approvers: BTreeMap::new(),
        };
        let rogue = tmp.join("rules/det-99-unsigned.yaml");
        std::fs::write(&rogue, "title: rogue\n").expect("write rogue");
        assert!(
            SigmaDetectionEngine::load_signed_pack(
                &tmp,
                &repo_root.join("packs/trust-roots.toml"),
                "grdr.det.core",
                Mode::Watch,
                &host,
            )
            .is_err()
        );
        std::fs::remove_file(&rogue).expect("remove rogue");

        let r01_path = tmp.join("rules/det-01-agent-control-write.yaml");
        let r01 = std::fs::read_to_string(&r01_path).expect("read r01");
        std::fs::write(&r01_path, r01.replace('\n', "\r\n")).expect("write crlf");
        assert!(
            SigmaDetectionEngine::load_signed_pack(
                &tmp,
                &repo_root.join("packs/trust-roots.toml"),
                "grdr.det.core",
                Mode::Watch,
                &host,
            )
            .is_err()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
