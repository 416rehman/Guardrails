// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-Gap S-31 conformance and default pack lint/signature/fixture integration tests.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use grdr_conformance::{
    DEFAULT_PACK_SIGNER_REF, ScenarioCategory, ScenarioOutcome, build_signed_pack_doc,
    run_airgap_s31_checks, validate_live_packs, verify_signed_pack_dir,
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

fn check_live_packs_and_mutations() -> Result<(), Box<dyn Error>> {
    let root = repo_root();
    let summary = validate_live_packs(&root)?;
    if !summary.essentials_rules_ok
        || summary.essentials_vectors_passed < 6
        || summary.detection_rules_count != 30
        || summary.detection_fixtures_passed != 60
        || summary.response_actions_count != 10
        || summary.compliance_capabilities_count != 15
        || summary.compliance_frameworks_count != 9
        || summary.signed_packs_verified != 3
    {
        return Err(format!("unexpected pack validation summary: {summary:?}").into());
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

    let tmp = std::env::temp_dir().join(format!("grdr-pack-tamper-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;
    fs::write(
        tmp.join("pack.toml"),
        b"id = \"grdr.sample\"\nversion = \"1.0.0\"\nkind = \"policy\"\n",
    )?;
    let trusted_kp = SigningKeypair::generate()?;
    let trusted_pub = trusted_kp.public_key_b64();
    let sig = build_signed_pack_doc(
        &tmp,
        "grdr.sample",
        "1.0.0",
        DEFAULT_PACK_SIGNER_REF,
        &trusted_kp,
    )?;
    fs::write(tmp.join("signature.json"), serde_json::to_vec_pretty(&sig)?)?;
    verify_signed_pack_dir_with_trusted(
        &tmp,
        "grdr.sample",
        &[(DEFAULT_PACK_SIGNER_REF, trusted_pub.as_str())],
    )?;

    // Self-signed unpinned attacker pack MUST be rejected by pinned verify_signed_pack_dir.
    if verify_signed_pack_dir(&tmp, "grdr.sample").is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("unpinned self-signed pack bypassed pinned verifier".into());
    }

    // Mutated pack re-signed with rogue keypair MUST fail pinned verification.
    let rogue_kp = SigningKeypair::generate()?;
    fs::write(
        tmp.join("pack.toml"),
        b"id = \"grdr.sample\"\nversion = \"9.9.9\"\nkind = \"policy\"\n",
    )?;
    let rogue_sig = build_signed_pack_doc(
        &tmp,
        "grdr.sample",
        "9.9.9",
        DEFAULT_PACK_SIGNER_REF,
        &rogue_kp,
    )?;
    fs::write(
        tmp.join("signature.json"),
        serde_json::to_vec_pretty(&rogue_sig)?,
    )?;
    if verify_signed_pack_dir_with_trusted(
        &tmp,
        "grdr.sample",
        &[(DEFAULT_PACK_SIGNER_REF, trusted_pub.as_str())],
    )
    .is_ok()
    {
        let _ = fs::remove_dir_all(&tmp);
        return Err("rogue re-signed pack passed pinned trusted verifier".into());
    }

    let _ = fs::remove_dir_all(&tmp);
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
