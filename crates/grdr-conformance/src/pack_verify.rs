// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! External trust-root Ed25519 pack signature verification, P7 lint, and default pack validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_core::session::rules::SessionRuleSet;
use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::IdentityMode;
use grdr_schema_lint::{lint_cedar_policy_in_mode, lint_pack_manifest, parse_vocabulary_toml};
use serde::{Deserialize, Serialize};

use crate::ConformanceError;
use crate::pack_compliance::validate_compliance_pack;
use crate::pack_fixtures::{
    collect_response_action_ids, execute_detection_fixtures, validate_cra_workspace_refs,
};
use crate::pack_manifest::{
    MAX_PACK_FILE_BYTES, check_no_em_dash_or_vocab, conf_err, is_symlink_or_reparse,
    parse_pack_manifest_toml, read_regular_bounded_bytes, read_regular_text,
};
use crate::pack_policy_vectors::execute_essentials_vectors;
use crate::pack_trust::{TRUST_ROOTS_FILENAME, load_pack_trust_roots};

pub const PACK_SIG_DOMAIN: &str = "grdr.pack.manifest.v1";
pub const DEFAULT_PACK_SIGNER_REF: &str = "grdr-content-release-v1";

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
    let payload = canonical_manifest_text(pack_id, version, &files)?;
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
    let pack_meta = fs::symlink_metadata(pack_dir)
        .map_err(|e| conf_err("pack-trust", &format!("{}: {e}", pack_dir.display())))?;
    if is_symlink_or_reparse(&pack_meta) || !pack_meta.is_dir() {
        return Err(conf_err(
            "pack-trust",
            &format!(
                "pack directory `{}` must be a real non-symlink directory",
                pack_dir.display()
            ),
        ));
    }
    let packs_root = pack_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            conf_err(
                "pack-trust",
                &format!(
                    "pack directory `{}` must have a non-empty parent directory for `{TRUST_ROOTS_FILENAME}`",
                    pack_dir.display()
                ),
            )
        })?;
    let root_meta = fs::symlink_metadata(packs_root)
        .map_err(|e| conf_err("pack-trust", &format!("{}: {e}", packs_root.display())))?;
    if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
        return Err(conf_err(
            "pack-trust",
            &format!(
                "packs root `{}` must be a real non-symlink directory",
                packs_root.display()
            ),
        ));
    }
    let active = load_pack_trust_roots(&packs_root.join(TRUST_ROOTS_FILENAME))?;
    let refs: Vec<(&str, &str)> = active
        .iter()
        .map(|(sref, pk)| (sref.as_str(), pk.as_str()))
        .collect();
    verify_signed_pack_dir_with_trusted(pack_dir, expected_pack_id, &refs)
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
                    "untrusted pack signer `{}` for `{expected_pack_id}`",
                    sig.signer_ref
                ),
            )
        })?;

    let payload = canonical_manifest_text(&sig.pack_id, &sig.version, &sig.files)?;
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
    let packs_meta = fs::symlink_metadata(&packs_dir)
        .map_err(|e| conf_err("pack-sig", &format!("{}: {e}", packs_dir.display())))?;
    if is_symlink_or_reparse(&packs_meta) || !packs_meta.is_dir() {
        return Err(conf_err(
            "pack-sig",
            "packs root must be a real non-symlink directory",
        ));
    }

    let vocab_raw = read_regular_text(
        &repo_root
            .join("contracts")
            .join("interface")
            .join("vocabulary.toml"),
    )?;
    let vocab = parse_vocabulary_toml(&vocab_raw).map_err(|e| conf_err("vocab", &e.to_string()))?;

    let mut signed_dirs = collect_signed_pack_dirs(&packs_dir)?;
    signed_dirs.sort();
    let mut verified_ids = BTreeSet::new();
    for dir in &signed_dirs {
        let toml_raw = read_regular_text(&dir.join("pack.toml"))?;
        let manifest = parse_pack_manifest_toml(&toml_raw)?;
        lint_pack_manifest(&manifest, IdentityMode::Named)
            .map_err(|e| conf_err("pack-lint", &e.to_string()))?;
        lint_pack_manifest(&manifest, IdentityMode::Pseudonymous)
            .map_err(|e| conf_err("pack-lint", &e.to_string()))?;
        let sig = verify_signed_pack_dir(dir, &manifest.id)?;
        if sig.version != manifest.version {
            return Err(conf_err(
                "pack-sig",
                &format!(
                    "signed version `{}` != pack.toml version `{}` for `{}`",
                    sig.version, manifest.version, manifest.id
                ),
            ));
        }
        verified_ids.insert(manifest.id);
    }

    for required_id in ["grdr.essentials", "grdr.det.core", "grdr.compliance"] {
        if !verified_ids.contains(required_id) {
            return Err(conf_err(
                "pack-sig",
                &format!("required signed pack `{required_id}` missing under packs/"),
            ));
        }
    }

    let essentials_dir = packs_dir.join("essentials");
    let detections_dir = packs_dir.join("detections");
    let compliance_dir = packs_dir.join("compliance");

    let cedar_src = read_regular_text(&essentials_dir.join("rules").join("essentials.cedar"))?;
    lint_cedar_policy_in_mode("grdr.essentials", &cedar_src, IdentityMode::Named)
        .map_err(|e| conf_err("cedar-lint", &e.to_string()))?;
    lint_cedar_policy_in_mode("grdr.essentials", &cedar_src, IdentityMode::Pseudonymous)
        .map_err(|e| conf_err("cedar-lint", &e.to_string()))?;
    let ess_vectors = execute_essentials_vectors(
        &cedar_src,
        &essentials_dir.join("tests/essentials-vectors.yaml"),
    )?;
    validate_session_rule_packs(&essentials_dir, &detections_dir, &vocab)?;

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
        signed_packs_verified: signed_dirs.len(),
    })
}

fn collect_signed_pack_dirs(packs_dir: &Path) -> Result<Vec<PathBuf>, ConformanceError> {
    let dir_meta =
        fs::symlink_metadata(packs_dir).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
    if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
        return Err(conf_err(
            "pack-sig",
            "packs directory must be a real non-symlink directory",
        ));
    }
    let mut dirs = Vec::new();
    for entry in fs::read_dir(packs_dir).map_err(|e| conf_err("pack-sig", &e.to_string()))? {
        let p = entry
            .map_err(|e| conf_err("pack-sig", &e.to_string()))?
            .path();
        let meta = fs::symlink_metadata(&p).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(conf_err(
                "pack-sig",
                &format!(
                    "symlink or reparse point forbidden in packs/: `{}`",
                    p.display()
                ),
            ));
        }
        if !meta.is_dir() && !meta.is_file() {
            return Err(conf_err(
                "pack-sig",
                &format!("non-regular entry forbidden in packs/: `{}`", p.display()),
            ));
        }
        if meta.is_dir() && p.join("signature.json").is_file() {
            dirs.push(p);
        }
    }
    Ok(dirs)
}

fn validate_session_rule_packs(
    essentials_dir: &Path,
    detections_dir: &Path,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(), ConformanceError> {
    let ess_path = essentials_dir.join("session-rules.yaml");
    let det_path = detections_dir.join("session-rules.yaml");
    let ess_raw = read_regular_text(&ess_path)?;
    let det_raw = read_regular_text(&det_path)?;
    check_no_em_dash_or_vocab(&ess_path, &ess_raw, vocab)?;
    check_no_em_dash_or_vocab(&det_path, &det_raw, vocab)?;
    let ess_set = SessionRuleSet::from_yaml(&ess_raw)
        .map_err(|e| conf_err("session-pack", &e.to_string()))?;
    let det_set = SessionRuleSet::from_yaml(&det_raw)
        .map_err(|e| conf_err("session-pack", &e.to_string()))?;
    if ess_set.rules.is_empty() || det_set.rules.is_empty() {
        return Err(conf_err(
            "session-pack",
            "session-rules.yaml must contain at least one rule",
        ));
    }
    SessionRuleSet::merge_restrict_only(&ess_set, &det_set)
        .map_err(|e| conf_err("session-pack", &e.to_string()))?;
    Ok(())
}

fn validate_detection_pack(
    dir: &Path,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(usize, usize, usize), ConformanceError> {
    let rules_dir = dir.join("rules");
    let mut seen_rows = BTreeSet::new();
    let rule_files = collect_sorted_yaml_files(&rules_dir, "det-pack")?;
    for path in &rule_files {
        let text = read_regular_text(path)?;
        check_no_em_dash_or_vocab(path, &text, vocab)?;
        for req in [
            "product: grdr",
            "license: \"Apache-2.0\"",
            "mode: simulate",
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
    if rule_files.is_empty() || seen_rows.len() != rule_files.len() {
        return Err(conf_err(
            "det-pack",
            "expected >= 1 Sigma rule and distinct `x_grdr.row` values across all detection rules",
        ));
    }

    let actions_raw = read_regular_text(&dir.join("response-actions.yaml"))?;
    check_no_em_dash_or_vocab(&dir.join("response-actions.yaml"), &actions_raw, vocab)?;
    let known_actions = collect_response_action_ids(&actions_raw);
    let sim_count = actions_raw
        .lines()
        .filter(|l| l.trim() == "mode: simulate")
        .count();
    if known_actions.is_empty() || sim_count != known_actions.len() {
        return Err(conf_err(
            "det-pack",
            "response-actions.yaml must define >= 1 action all in simulate mode",
        ));
    }

    let fixture_files = collect_sorted_yaml_files(&dir.join("tests"), "det-fixtures")?;
    for path in &fixture_files {
        let raw = read_regular_text(path)?;
        check_no_em_dash_or_vocab(path, &raw, vocab)?;
    }
    let fixtures_passed = execute_detection_fixtures(&rule_files, &fixture_files, &known_actions)?;
    Ok((rule_files.len(), fixtures_passed, known_actions.len()))
}

fn collect_sorted_yaml_files(dir: &Path, domain: &str) -> Result<Vec<PathBuf>, ConformanceError> {
    let dir_meta = fs::symlink_metadata(dir).map_err(|e| conf_err(domain, &e.to_string()))?;
    if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
        return Err(conf_err(
            domain,
            &format!("`{}` must be a real non-symlink directory", dir.display()),
        ));
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| conf_err(domain, &e.to_string()))? {
        let p = entry.map_err(|e| conf_err(domain, &e.to_string()))?.path();
        let meta = fs::symlink_metadata(&p).map_err(|e| conf_err(domain, &e.to_string()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(conf_err(
                domain,
                &format!("symlink or reparse point forbidden at `{}`", p.display()),
            ));
        }
        if p.extension().and_then(|s| s.to_str()) == Some("yaml") {
            if !meta.is_file() {
                return Err(conf_err(
                    domain,
                    &format!("YAML path `{}` must be a regular file", p.display()),
                ));
            }
            files.push(p);
        }
    }
    files.sort();
    Ok(files)
}

fn collect_pack_digests(
    root: &Path,
    dir: &Path,
    depth: usize,
) -> Result<Vec<PackFileDigest>, ConformanceError> {
    if depth == 0 {
        let root_meta =
            fs::symlink_metadata(root).map_err(|e| conf_err("pack-sig", &e.to_string()))?;
        if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
            return Err(conf_err(
                "pack-sig",
                "pack root must be a real non-symlink directory",
            ));
        }
    }
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
        if is_symlink_or_reparse(&meta) {
            return Err(conf_err(
                "pack-sig",
                "symlinks or reparse points forbidden in pack directory",
            ));
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
            let raw = read_regular_bounded_bytes(&p, MAX_PACK_FILE_BYTES)?;
            out.push(PackFileDigest {
                path: rel,
                sha256: sha256_hex(&raw),
                length: u64::try_from(raw.len()).unwrap_or(u64::MAX),
            });
        } else {
            return Err(conf_err(
                "pack-sig",
                &format!(
                    "non-regular filesystem entry `{}` forbidden in pack directory",
                    p.display()
                ),
            ));
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn validate_manifest_token(val: &str, label: &str) -> Result<(), ConformanceError> {
    if val.is_empty() || val.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(conf_err(
            "pack-sig",
            &format!("canonical manifest `{label}` contains empty, whitespace, or control chars"),
        ));
    }
    Ok(())
}

fn canonical_manifest_text(
    pack_id: &str,
    version: &str,
    files: &[PackFileDigest],
) -> Result<String, ConformanceError> {
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
