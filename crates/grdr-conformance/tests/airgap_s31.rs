// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-Gap S-31 conformance and default pack lint/signature/fixture integration tests.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_comply::default_registry;
use grdr_conformance::{
    DEFAULT_PACK_SIGNER_REF, ScenarioCategory, ScenarioOutcome, build_signed_pack_doc,
    load_pack_trust_roots, run_airgap_s31_checks, validate_live_packs, verify_signed_pack_dir,
    verify_signed_pack_dir_with_trusted,
};
use grdr_crypto::SigningKeypair;
use grdr_model::IdentityMode;
use grdr_schema_lint::{LintError, lint_cedar_policy_in_mode};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn count_yaml_files(dir: &Path) -> Result<usize, Box<dyn Error>> {
    let mut count = 0_usize;
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) == Some("yaml") {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn count_signed_pack_dirs(packs_dir: &Path) -> Result<usize, Box<dyn Error>> {
    let mut count = 0_usize;
    for entry in fs::read_dir(packs_dir)? {
        let p = entry?.path();
        if p.is_dir() && p.join("signature.json").is_file() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn check_airgap_s31_scenarios() -> Result<(), Box<dyn Error>> {
    let results = run_airgap_s31_checks()?;
    if results.len() != 4 {
        return Err(format!("expected 4 S-31 scenarios, got {}", results.len()).into());
    }
    for res in &results {
        if res.category != ScenarioCategory::Airgap || res.outcome != ScenarioOutcome::Pass {
            return Err(format!("scenario {} failed: {}", res.id, res.detail).into());
        }
    }
    Ok(())
}

fn check_negative_trust_roots(tmp_root: &Path, trusted_pub: &str) -> Result<(), Box<dyn Error>> {
    let tr_path = tmp_root.join("trust-roots.toml");

    let bad_trust_docs = [
        (
            "retired",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"retired\"\n"
            ),
        ),
        (
            "unknown_status",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"pending\"\n"
            ),
        ),
        (
            "duplicate_signer",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n"
            ),
        ),
        (
            "wrong_format",
            format!(
                "format = \"grdr.wrong.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n"
            ),
        ),
        (
            "missing_signers",
            "format = \"grdr.trust-roots.v1\"\n".to_string(),
        ),
        (
            "empty_signers",
            "format = \"grdr.trust-roots.v1\"\nsigners = []\n".to_string(),
        ),
        (
            "unknown_top_key",
            format!(
                "format = \"grdr.trust-roots.v1\"\nextra = true\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n"
            ),
        ),
        (
            "unknown_signer_key",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\nextra = \"x\"\n"
            ),
        ),
        (
            "malformed_toml",
            "format = \"unclosed\n[[signers]]\n".to_string(),
        ),
        (
            "invalid_b64_key",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"not!valid!b64\"\nstatus = \"active\"\n"
            ),
        ),
        (
            "short_key",
            format!(
                "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"AQIDBA==\"\nstatus = \"active\"\n"
            ),
        ),
    ];

    for (label, doc) in bad_trust_docs {
        fs::write(&tr_path, doc)?;
        if load_pack_trust_roots(&tr_path).is_ok() {
            return Err(format!("negative trust-roots case `{label}` unexpectedly passed").into());
        }
    }

    let real_tr = tmp_root.join("real-trust-roots.toml");
    fs::write(
        &real_tr,
        format!(
            "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n"
        ),
    )?;
    let _ = fs::remove_file(&tr_path);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_tr, &tr_path)?;
        if load_pack_trust_roots(&tr_path).is_ok() {
            return Err("symlinked trust-roots.toml bypassed loader".into());
        }
        let _ = fs::remove_file(&tr_path);
    }

    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_file(&real_tr, &tr_path).is_ok() {
            let res = load_pack_trust_roots(&tr_path);
            let _ = fs::remove_file(&tr_path);
            if res.is_ok() {
                return Err("symlinked trust-roots.toml bypassed loader".into());
            }
        }
    }

    Ok(())
}

fn check_live_packs_and_mutations() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let expected_rules = count_yaml_files(&root.join("packs/detections/rules"))?;
    let expected_signed_packs = count_signed_pack_dirs(&root.join("packs"))?;
    let registry = default_registry();

    let summary = validate_live_packs(&root)?;
    if !summary.essentials_rules_ok
        || summary.essentials_vectors_passed == 0
        || expected_rules == 0
        || summary.detection_rules_count != expected_rules
        || summary.detection_fixtures_passed != expected_rules.saturating_mul(2)
        || summary.response_actions_count == 0
        || summary.compliance_capabilities_count != registry.capabilities.len()
        || summary.compliance_frameworks_count != registry.frameworks.len()
        || summary.credential_locator_vectors_passed < 7
        || expected_signed_packs == 0
        || summary.signed_packs_verified != expected_signed_packs
    {
        return Err(format!("unexpected pack validation summary: {summary:?}").into());
    }

    let trust_roots = load_pack_trust_roots(&root.join("packs/trust-roots.toml"))?;
    if trust_roots.is_empty() {
        return Err("expected at least one active signer in packs/trust-roots.toml".into());
    }

    let bad_permit = r#"permit (principal is Grdr::Session, action == Grdr::Action::"exec", resource is Grdr::Executable);"#;
    if !matches!(
        lint_cedar_policy_in_mode("grdr.essentials", bad_permit, IdentityMode::Named),
        Err(LintError::CedarViolation { .. })
    ) {
        return Err("permit policy outside grdr.base should be rejected".into());
    }

    let bad_user = r#"forbid (principal is Grdr::User, action == Grdr::Action::"exec", resource is Grdr::Executable);"#;
    if !matches!(
        lint_cedar_policy_in_mode("grdr.essentials", bad_user, IdentityMode::Pseudonymous),
        Err(LintError::CedarViolation { .. })
    ) {
        return Err("Grdr::User policy under Pseudonymous mode should be rejected".into());
    }

    if verify_signed_pack_dir(Path::new("essentials"), "grdr.essentials").is_ok() {
        return Err("single-segment relative pack_dir without explicit parent must fail".into());
    }

    let tmp_root = std::env::temp_dir().join(format!("grdr-pack-tamper-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_root);
    let tmp_pack = tmp_root.join("sample");
    fs::create_dir_all(&tmp_pack)?;
    fs::write(
        tmp_pack.join("pack.toml"),
        b"id = \"grdr.sample\"\nversion = \"1.0.0\"\nkind = \"policy\"\n",
    )?;
    let trusted_kp = SigningKeypair::generate()?;
    let trusted_pub = trusted_kp.public_key_b64();
    let sig = build_signed_pack_doc(
        &tmp_pack,
        "grdr.sample",
        "1.0.0",
        DEFAULT_PACK_SIGNER_REF,
        &trusted_kp,
    )?;
    fs::write(
        tmp_pack.join("signature.json"),
        serde_json::to_vec_pretty(&sig)?,
    )?;
    verify_signed_pack_dir_with_trusted(
        &tmp_pack,
        "grdr.sample",
        &[(DEFAULT_PACK_SIGNER_REF, trusted_pub.as_str())],
    )?;

    // Missing trust-roots.toml MUST fail closed.
    if verify_signed_pack_dir(&tmp_pack, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp_root);
        return Err("pack verification succeeded without trust-roots.toml".into());
    }

    check_negative_trust_roots(&tmp_root, &trusted_pub)?;

    // Real trust-roots.toml MUST reject self-signed untrusted attacker pack.
    fs::copy(
        root.join("packs/trust-roots.toml"),
        tmp_root.join("trust-roots.toml"),
    )?;
    if verify_signed_pack_dir(&tmp_pack, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp_root);
        return Err("untrusted self-signed pack bypassed trust-roots.toml verifier".into());
    }

    // Revoked signer status in trust-roots.toml MUST be rejected; active status MUST pass.
    fs::write(
        tmp_root.join("trust-roots.toml"),
        format!(
            "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"revoked\"\n"
        ),
    )?;
    if verify_signed_pack_dir(&tmp_pack, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp_root);
        return Err("revoked signer bypassed trust-roots.toml verifier".into());
    }
    fs::write(
        tmp_root.join("trust-roots.toml"),
        format!(
            "format = \"grdr.trust-roots.v1\"\n\n[[signers]]\nsigner_ref = \"{DEFAULT_PACK_SIGNER_REF}\"\nverifier_ed25519_b64 = \"{trusted_pub}\"\nstatus = \"active\"\n"
        ),
    )?;
    verify_signed_pack_dir(&tmp_pack, "grdr.sample")?;

    // Tampered pack file without re-signing MUST fail trusted verification.
    fs::write(
        tmp_pack.join("pack.toml"),
        b"id = \"grdr.sample\"\nversion = \"1.0.1\"\nkind = \"policy\"\n",
    )?;
    if verify_signed_pack_dir(&tmp_pack, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp_root);
        return Err("tampered pack.toml without re-signing bypassed verifier".into());
    }

    // Reparse-point/junction pack_dir MUST be rejected on Windows.
    #[cfg(windows)]
    {
        let junc = tmp_root.join("sample_junc");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junc)
            .arg(&tmp_pack)
            .status()?;
        if status.success() && verify_signed_pack_dir(&junc, "grdr.sample").is_ok() {
            let _ = fs::remove_dir(&junc);
            let _ = fs::remove_dir_all(&tmp_root);
            return Err("junction pack_dir bypassed reparse-point check".into());
        }
        let _ = fs::remove_dir(&junc);
    }

    // Mutated pack re-signed with rogue keypair MUST fail trusted verification.
    let rogue_kp = SigningKeypair::generate()?;
    fs::write(
        tmp_pack.join("pack.toml"),
        b"id = \"grdr.sample\"\nversion = \"9.9.9\"\nkind = \"policy\"\n",
    )?;
    let rogue_sig = build_signed_pack_doc(
        &tmp_pack,
        "grdr.sample",
        "9.9.9",
        DEFAULT_PACK_SIGNER_REF,
        &rogue_kp,
    )?;
    fs::write(
        tmp_pack.join("signature.json"),
        serde_json::to_vec_pretty(&rogue_sig)?,
    )?;
    if verify_signed_pack_dir(&tmp_pack, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp_root);
        return Err("rogue re-signed pack passed trust-roots.toml verifier".into());
    }

    let _ = fs::remove_dir_all(&tmp_root);
    Ok(())
}

#[test]
fn airgap_s31_conformance_scenarios_pass_offline() {
    let res = check_airgap_s31_scenarios();
    assert!(res.is_ok(), "S-31 conformance failed: {res:?}");
}

#[test]
fn live_packs_signatures_and_negative_mutations_are_enforced() {
    let res = check_live_packs_and_mutations();
    assert!(res.is_ok(), "live packs check failed: {res:?}");
}
