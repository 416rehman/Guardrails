// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Pinned Ed25519 pack signature verification, P7 lint, and default pack suite validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_comply::default_registry;
use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::IdentityMode;
use grdr_schema_lint::{lint_cedar_policy_in_mode, lint_pack_manifest, parse_vocabulary_toml};
use serde::{Deserialize, Serialize};

use crate::ConformanceError;
use crate::pack_fixtures::{
    collect_response_action_ids, execute_detection_fixtures, validate_cra_workspace_refs,
};
use crate::pack_manifest::{
    MAX_PACK_FILE_BYTES, check_no_em_dash_or_vocab, conf_err, parse_pack_manifest_toml,
    read_regular_text,
};
use crate::pack_policy_vectors::execute_essentials_vectors;

pub const PACK_SIG_DOMAIN: &str = "grdr.pack.manifest.v1";
pub const DEFAULT_PACK_SIGNER_REF: &str = "grdr-content-release-v1";
pub const PINNED_DEFAULT_PACK_PUBKEYS: &[(&str, &str)] = &[(
    DEFAULT_PACK_SIGNER_REF,
    "K6QXib9RtdnlYIN+Nr+dCxKafTDTBVRsFSArrrBV6U8=",
)];
const MAX_PARAPHRASE_WORDS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFileDigest {
    pub path: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSignatureDoc {
    pub format: String,
    pub pack_id: String,
    pub version: String,
    pub domain: String,
    pub signer_ref: String,
    pub verifier_ed25519_b64: String,
    pub manifest_sha256: String,
    pub files: Vec<PackFileDigest>,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackValidationSummary {
    pub essentials_rules_ok: bool,
    pub essentials_vectors_passed: usize,
    pub detection_rules_count: usize,
    pub detection_fixtures_passed: usize,
    pub response_actions_count: usize,
    pub compliance_capabilities_count: usize,
    pub compliance_frameworks_count: usize,
    pub signed_packs_verified: usize,
}

pub fn build_signed_pack_doc(
    pack_dir: &Path,
    pack_id: &str,
    version: &str,
    signer_ref: &str,
    keypair: &SigningKeypair,
) -> Result<PackSignatureDoc, ConformanceError> {
    let files = collect_pack_digests(pack_dir, pack_dir, 0)?;
    if files.is_empty() {
        return Err(conf_err(
            "pack-sign",
            "no regular files found in pack directory",
        ));
    }
    let payload = canonical_manifest_text(pack_id, version, &files);
    let manifest_sha256 = sha256_hex(payload.as_bytes());
    let signature_b64 = keypair.sign_bytes(PACK_SIG_DOMAIN, payload.as_bytes());
    Ok(PackSignatureDoc {
        format: "grdr.pack.signature.v1".into(),
        pack_id: pack_id.to_owned(),
        version: version.to_owned(),
        domain: PACK_SIG_DOMAIN.into(),
        signer_ref: signer_ref.to_owned(),
        verifier_ed25519_b64: keypair.public_key_b64(),
        manifest_sha256,
        files,
        signature_b64,
    })
}

pub fn verify_signed_pack_dir(
    pack_dir: &Path,
    expected_pack_id: &str,
) -> Result<PackSignatureDoc, ConformanceError> {
    verify_signed_pack_dir_with_trusted(pack_dir, expected_pack_id, PINNED_DEFAULT_PACK_PUBKEYS)
}

pub fn verify_signed_pack_dir_with_trusted(
    pack_dir: &Path,
    expected_pack_id: &str,
    trusted_verifiers: &[(&str, &str)],
) -> Result<PackSignatureDoc, ConformanceError> {
    let sig_path = pack_dir.join("signature.json");
    let raw = read_regular_text(&sig_path)?;
    let sig: PackSignatureDoc = serde_json::from_str(&raw).map_err(|e| {
        conf_err(
            "pack-sig",
            &format!("malformed `{}`: {e}", sig_path.display()),
        )
    })?;

    if sig.format != "grdr.pack.signature.v1" || sig.domain != PACK_SIG_DOMAIN {
        return Err(conf_err(
            "pack-sig",
            "unexpected signature format or domain",
        ));
    }
    if sig.pack_id != expected_pack_id {
        return Err(conf_err(
            "pack-sig",
            &format!("pack_id `{}` != expected `{expected_pack_id}`", sig.pack_id),
        ));
    }

    let (_, pinned_pubkey_b64) = trusted_verifiers
        .iter()
        .find(|(sref, pk)| *sref == sig.signer_ref && *pk == sig.verifier_ed25519_b64)
        .copied()
        .ok_or_else(|| {
            conf_err(
                "pack-sig",
                &format!(
                    "unpinned or untrusted pack signer `{}` for `{expected_pack_id}`",
                    sig.signer_ref
                ),
            )
        })?;

    let payload = canonical_manifest_text(&sig.pack_id, &sig.version, &sig.files);
    if sha256_hex(payload.as_bytes()) != sig.manifest_sha256 {
        return Err(conf_err("pack-sig", "manifest_sha256 mismatch"));
    }
    verify_bytes(
        pinned_pubkey_b64,
        PACK_SIG_DOMAIN,
        payload.as_bytes(),
        &sig.signature_b64,
    )
    .map_err(|e| conf_err("pack-sig", &format!("Ed25519 verification failed: {e}")))?;

    let actual_files = collect_pack_digests(pack_dir, pack_dir, 0)?;
    if actual_files != sig.files {
        return Err(conf_err(
            "pack-sig",
            &format!("disk files in `{expected_pack_id}` diverge from signed manifest"),
        ));
    }
    Ok(sig)
}

pub fn validate_live_packs(repo_root: &Path) -> Result<PackValidationSummary, ConformanceError> {
    let packs_dir = repo_root.join("packs");
    let vocab_raw = read_regular_text(&repo_root.join("interface").join("vocabulary.toml"))?;
    let vocab = parse_vocabulary_toml(&vocab_raw).map_err(|e| conf_err("vocab", &e.to_string()))?;

    let essentials_dir = packs_dir.join("essentials");
    let detections_dir = packs_dir.join("detections");
    let compliance_dir = packs_dir.join("compliance");

    for (dir, id) in [
        (&essentials_dir, "grdr.essentials"),
        (&detections_dir, "grdr.det.core"),
        (&compliance_dir, "grdr.compliance"),
    ] {
        let toml_raw = read_regular_text(&dir.join("pack.toml"))?;
        let manifest = parse_pack_manifest_toml(&toml_raw)?;
        if manifest.id != id {
            return Err(conf_err(
                "pack-lint",
                &format!("expected pack `{id}`, got `{}`", manifest.id),
            ));
        }
        lint_pack_manifest(&manifest, IdentityMode::Named)
            .map_err(|e| conf_err("pack-lint", &e.to_string()))?;
        lint_pack_manifest(&manifest, IdentityMode::Pseudonymous)
            .map_err(|e| conf_err("pack-lint", &e.to_string()))?;
        verify_signed_pack_dir(dir, id)?;
    }

    let cedar_src = read_regular_text(&essentials_dir.join("rules").join("essentials.cedar"))?;
    lint_cedar_policy_in_mode("grdr.essentials", &cedar_src, IdentityMode::Named)
        .map_err(|e| conf_err("cedar-lint", &e.to_string()))?;
    lint_cedar_policy_in_mode("grdr.essentials", &cedar_src, IdentityMode::Pseudonymous)
        .map_err(|e| conf_err("cedar-lint", &e.to_string()))?;
    let ess_vectors = execute_essentials_vectors(
        &cedar_src,
        &essentials_dir.join("tests/essentials-vectors.yaml"),
    )?;

    let (det_count, det_fixtures, resp_count) = validate_detection_pack(&detections_dir, &vocab)?;
    let (cap_count, fw_count) = validate_compliance_pack(&compliance_dir, &vocab)?;
    validate_cra_workspace_refs(repo_root)?;

    Ok(PackValidationSummary {
        essentials_rules_ok: true,
        essentials_vectors_passed: ess_vectors,
        detection_rules_count: det_count,
        detection_fixtures_passed: det_fixtures,
        response_actions_count: resp_count,
        compliance_capabilities_count: cap_count,
        compliance_frameworks_count: fw_count,
        signed_packs_verified: 3,
    })
}

fn validate_detection_pack(
    dir: &Path,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(usize, usize, usize), ConformanceError> {
    let rules_dir = dir.join("rules");
    let mut seen_rows = BTreeSet::new();
    let mut rule_files = Vec::new();
    for entry in fs::read_dir(&rules_dir).map_err(|e| conf_err("det-pack", &e.to_string()))? {
        let p = entry
            .map_err(|e| conf_err("det-pack", &e.to_string()))?
            .path();
        if p.extension().and_then(|s| s.to_str()) == Some("yaml") {
            rule_files.push(p);
        }
    }
    rule_files.sort();
    for path in &rule_files {
        let text = read_regular_text(path)?;
        check_no_em_dash_or_vocab(path, &text, vocab)?;
        for req in [
            "product: grdr",
            "license: \"Apache-2.0\"",
            "mode: simulate",
            "max_scope: session",
            "max_share_bp: 500",
        ] {
            if !text.contains(req) {
                return Err(conf_err(
                    "det-pack",
                    &format!("`{}` missing `{req}`", path.display()),
                ));
            }
        }
        if let Some(row_line) = text.lines().find(|l| l.trim_start().starts_with("row:"))
            && let Some(num_str) = row_line.split(':').nth(1)
            && let Ok(num) = num_str.trim().parse::<u32>()
        {
            seen_rows.insert(num);
        }
    }
    if rule_files.len() != 30 || seen_rows.len() != 30 {
        return Err(conf_err(
            "det-pack",
            "expected 30 distinct Sigma detection rules (rows 1..=30)",
        ));
    }

    let actions_raw = read_regular_text(&dir.join("response-actions.yaml"))?;
    check_no_em_dash_or_vocab(&dir.join("response-actions.yaml"), &actions_raw, vocab)?;
    let known_actions = collect_response_action_ids(&actions_raw);
    let sim_count = actions_raw
        .lines()
        .filter(|l| l.trim() == "mode: simulate")
        .count();
    if known_actions.len() != 10 || sim_count != 10 {
        return Err(conf_err(
            "det-pack",
            "response-actions.yaml must define 10 actions all in simulate mode",
        ));
    }

    let fixtures_passed = execute_detection_fixtures(
        &rule_files,
        &dir.join("tests").join("detection-fixtures.yaml"),
        &known_actions,
    )?;
    Ok((rule_files.len(), fixtures_passed, known_actions.len()))
}

fn validate_compliance_pack(
    dir: &Path,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(usize, usize), ConformanceError> {
    let controls_dir = dir.join("controls");
    let caps_raw = read_regular_text(&controls_dir.join("capabilities.yaml"))?;
    let fws_raw = read_regular_text(&controls_dir.join("frameworks.yaml"))?;
    let cw_raw = read_regular_text(&controls_dir.join("crosswalks.yaml"))?;
    for (p, t) in [
        (controls_dir.join("capabilities.yaml"), &caps_raw),
        (controls_dir.join("frameworks.yaml"), &fws_raw),
        (controls_dir.join("crosswalks.yaml"), &cw_raw),
    ] {
        check_no_em_dash_or_vocab(&p, t, vocab)?;
    }

    let registry = default_registry();
    for cap_id in registry.capabilities.keys() {
        if !caps_raw.contains(cap_id) {
            return Err(conf_err(
                "comply-pack",
                &format!("capabilities.yaml missing `{cap_id}`"),
            ));
        }
    }
    for fw_id in registry.frameworks.keys() {
        if !fws_raw.contains(fw_id) {
            return Err(conf_err(
                "comply-pack",
                &format!("frameworks.yaml missing `{fw_id}`"),
            ));
        }
    }

    for line in fws_raw.lines() {
        if let Some(idx) = line.find("paraphrase:") {
            let phrase = line
                .get(idx.saturating_add("paraphrase:".len())..)
                .unwrap_or("");
            let cleaned = phrase.trim().trim_end_matches('}').trim().trim_matches('"');
            let words = cleaned.split_whitespace().count();
            if words > MAX_PARAPHRASE_WORDS {
                return Err(conf_err(
                    "comply-pack",
                    &format!("control paraphrase exceeds {MAX_PARAPHRASE_WORDS} words: {cleaned}"),
                ));
            }
        }
    }
    Ok((registry.capabilities.len(), registry.frameworks.len()))
}

fn collect_pack_digests(
    root: &Path,
    dir: &Path,
    depth: usize,
) -> Result<Vec<PackFileDigest>, ConformanceError> {
    if depth > 8 {
        return Err(conf_err("pack-sig", "directory depth exceeded"));
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| conf_err("pack-sig", &e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| conf_err("pack-sig", &e.to_string()))?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    let mut out = Vec::new();
    for p in children {
        let meta = fs::symlink_metadata(&p).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(conf_err("pack-sig", "symlinks forbidden in pack directory"));
        }
        if meta.is_dir() {
            out.extend(collect_pack_digests(root, &p, depth.saturating_add(1))?);
        } else if meta.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| conf_err("pack-sig", &e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "signature.json" {
                continue;
            }
            if meta.len() > MAX_PACK_FILE_BYTES {
                return Err(conf_err("pack-sig", "pack file exceeds size limit"));
            }
            let raw = fs::read(&p).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
            out.push(PackFileDigest {
                path: rel,
                sha256: sha256_hex(&raw),
                length: u64::try_from(raw.len()).unwrap_or(u64::MAX),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn canonical_manifest_text(pack_id: &str, version: &str, files: &[PackFileDigest]) -> String {
    let mut lines = Vec::with_capacity(files.len().saturating_add(3));
    lines.push(PACK_SIG_DOMAIN.to_owned());
    lines.push(pack_id.to_owned());
    lines.push(version.to_owned());
    for f in files {
        lines.push(format!("{} {} {}", f.path, f.sha256, f.length));
    }
    lines.join("\n")
}
