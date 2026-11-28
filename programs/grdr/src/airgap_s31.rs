// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline S-31 / E3.2 / E3.3 air-gap end-to-end verification harness.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use grdr_crypto::SigningKeypair;
use grdr_update::{
    FreshnessStatement, SnapshotMetadata, SnapshotTargetRef, TargetsMetadata, TimestampMetadata,
    TufRole, TufRootKind, UpdateFreshness, UpdateTrust, canonical_sha256, sign_metadata,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::airgap_policy::{
    CopyleftCategory, DependenciesLockFile, LockedDependency, OpenVexDocument, OpenVexStatement,
    VexStatus, evaluate_openvex_exposure,
};
use crate::airgap::airgap_s31_artefact::s31_verify_artefact_offline_and_forgeries;
use crate::airgap::airgap_s31_extended::{
    empty_s31_req, mk_s31_root, s31_ext_err, s31_mirror_convergence_and_yank,
    s31_server_import_resumable_and_audit, write_s31_file,
};
use crate::airgap::{AirgapCliError, verify_airgap_tar_file};
use crate::airgap_bundle::{AirgapBuildRequest, AirgapFullBuildRequest, build_full_airgap_tar};
use crate::airgap_verify::{load_parsed_tar_bundle, verify_extended_bundle_rules};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S31ScenarioReport {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S31SuiteSummary {
    pub scenarios: Vec<S31ScenarioReport>,
    pub all_passed: bool,
}

pub fn run_s31_offline_suite(work_root: &Path) -> Result<S31SuiteSummary, AirgapCliError> {
    let _ = fs::remove_dir_all(work_root);
    fs::create_dir_all(work_root).map_err(|e| s31_ext_err("INIT", &e.to_string()))?;

    let scenarios = vec![
        s31_build_multi_asset_split_tamper(&work_root.join("case1"))?,
        s31_delta_upgrade_and_base_refusal(&work_root.join("case2"))?,
        s31_server_import_resumable_and_audit(&work_root.join("case3"))?,
        s31_mirror_convergence_and_yank(&work_root.join("case4"))?,
        s31_verify_artefact_offline_and_forgeries(&work_root.join("case5"))?,
        s31_clock_bounds_and_openvex(&work_root.join("case6"))?,
    ];
    let all_passed = scenarios.iter().all(|s| s.passed);
    let _ = fs::remove_dir_all(work_root);
    Ok(S31SuiteSummary {
        scenarios,
        all_passed,
    })
}

fn s31_build_multi_asset_split_tamper(root: &Path) -> Result<S31ScenarioReport, AirgapCliError> {
    let packs = root.join("packs/essentials");
    let bins = root.join("bins");
    let images = root.join("images");
    let charts = root.join("charts");
    let apt = root.join("apt");
    let rpm = root.join("rpm");
    let docs = root.join("docs");
    let tf = root.join("terraform");
    let models = root.join("models");
    let csaf = root.join("csaf");
    let sources = root.join("sources");
    let keys = root.join("keys");
    for d in [
        &packs, &bins, &images, &charts, &apt, &rpm, &docs, &tf, &models, &csaf, &sources, &keys,
    ] {
        fs::create_dir_all(d).map_err(|e| s31_ext_err("S31-01", &e.to_string()))?;
    }
    write_s31_file(&packs.join("pack.toml"), b"id = \"grdr.essentials\"\n")?;
    write_s31_file(&bins.join("linux-amd64/grdr"), &vec![0x55u8; 24_000])?;
    write_s31_file(&bins.join("windows-amd64/grdr.exe"), b"win-bin")?;
    write_s31_file(&images.join("oci.tar"), b"oci-image-layout")?;
    write_s31_file(&charts.join("grdr-server.tgz"), b"helm-chart")?;
    write_s31_file(&apt.join("grdr.deb"), b"deb-pkg")?;
    write_s31_file(&rpm.join("grdr.rpm"), b"rpm-pkg")?;
    write_s31_file(&docs.join("airgap.md"), b"# Offline Docs\n")?;
    write_s31_file(&tf.join("provider.zip"), b"tf-provider")?;
    write_s31_file(&models.join("classifier.onnx"), b"onnx-model")?;
    write_s31_file(&csaf.join("advisory.json"), b"{}")?;
    write_s31_file(&sources.join("weak-dep-1.0.tar.gz"), b"source-archive")?;

    let sbom = root.join("cyclonedx.json");
    let vex = root.join("openvex.json");
    write_s31_file(&sbom, br#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#)?;
    write_s31_file(&vex, br#"{"document_id":"vex-1","statements":[]}"#)?;

    let deps_lock = root.join("dependencies.lock.json");
    let non_redist = DependenciesLockFile {
        schema: "v1".into(),
        dependencies: vec![LockedDependency {
            name: "prop-blob".into(),
            version: "1.0".into(),
            license: "Proprietary".into(),
            redistributable: false,
            copyleft_category: CopyleftCategory::Permissive,
            source_tarball: None,
            copyright_notice: None,
        }],
    };
    write_s31_file(
        &deps_lock,
        &serde_json::to_vec(&non_redist).map_err(|e| s31_ext_err("S31-01", &e.to_string()))?,
    )?;

    let tar_out = root.join("bundle.tar");
    let linux_only = vec!["linux-amd64".to_owned()];
    let mut full_req = AirgapFullBuildRequest {
        base: AirgapBuildRequest {
            packs_dir: &root.join("packs"),
            out: &tar_out,
            bundle_id: "s31-multi",
            version: "2.0.0",
            expires_days: 90,
            halted_releases: &[],
            key_dir: Some(&keys),
            allow_ephemeral_dev_keys: false,
        },
        binaries_dir: Some(&bins),
        images_dir: Some(&images),
        charts_dir: Some(&charts),
        apt_dir: Some(&apt),
        rpm_dir: Some(&rpm),
        docs_dir: Some(&docs),
        terraform_dir: Some(&tf),
        models_dir: Some(&models),
        csaf_dir: Some(&csaf),
        sources_dir: Some(&sources),
        sbom_path: Some(&sbom),
        vex_path: Some(&vex),
        dependencies_lock_path: Some(&deps_lock),
        release_manifest_path: None,
        trusted_root_path: None,
        rollout_path: None,
        platforms: &linux_only,
        delta_from_version: None,
        delta_from_manifest_sha256: None,
        minimum_base_version: None,
        yanked_releases: &[],
        split_bytes: Some(12_000),
    };
    if build_full_airgap_tar(&full_req).is_ok() {
        return Err(s31_ext_err(
            "S31-01",
            "missing signing keys without --ephemeral-dev-keys was accepted",
        ));
    }
    full_req.base.allow_ephemeral_dev_keys = true;
    if build_full_airgap_tar(&full_req).is_ok() {
        return Err(s31_ext_err(
            "S31-01",
            "non-redistributable dependency was accepted",
        ));
    }

    let missing_copyleft_src = DependenciesLockFile {
        schema: "v1".into(),
        dependencies: vec![LockedDependency {
            name: "copyleft-lib".into(),
            version: "1.0".into(),
            license: "MPL-2.0".into(),
            redistributable: true,
            copyleft_category: CopyleftCategory::WeakCopyleft,
            source_tarball: Some("sources/missing.tar.gz".into()),
            copyright_notice: Some("Copyright 2026".into()),
        }],
    };
    write_s31_file(
        &deps_lock,
        &serde_json::to_vec(&missing_copyleft_src)
            .map_err(|e| s31_ext_err("S31-01", &e.to_string()))?,
    )?;
    if build_full_airgap_tar(&full_req).is_ok() {
        return Err(s31_ext_err(
            "S31-01",
            "missing copyleft source tarball was accepted",
        ));
    }

    let valid_deps = DependenciesLockFile {
        schema: "v1".into(),
        dependencies: vec![LockedDependency {
            name: "weak-dep".into(),
            version: "1.0".into(),
            license: "MPL-2.0".into(),
            redistributable: true,
            copyleft_category: CopyleftCategory::WeakCopyleft,
            source_tarball: Some("sources/weak-dep-1.0.tar.gz".into()),
            copyright_notice: Some("Copyright 2026".into()),
        }],
    };
    write_s31_file(
        &deps_lock,
        &serde_json::to_vec(&valid_deps).map_err(|e| s31_ext_err("S31-01", &e.to_string()))?,
    )?;
    let summary = build_full_airgap_tar(&full_req)?;
    if summary.parts_count < 2 {
        return Err(s31_ext_err(
            "S31-01",
            "expected multi-part split bundle >= 2 parts",
        ));
    }

    let parts_manifest = root.join("bundle.tar.parts.json");
    let extract_dir = root.join("extracted");
    verify_airgap_tar_file(
        &parts_manifest,
        None,
        Some(&summary.root_fingerprint),
        None,
        Some(&summary.manifest_sha256),
        "op-s31",
        &[],
        Some(&extract_dir),
    )?;
    if !extract_dir.join("binaries/linux-amd64/grdr").is_file()
        || extract_dir
            .join("binaries/windows-amd64/grdr.exe")
            .is_file()
    {
        return Err(s31_ext_err("S31-01", "platform subset filtering failed"));
    }

    let part2 = root.join("bundle.tar.part-0002");
    let mut part2_bytes = fs::read(&part2).map_err(|e| s31_ext_err("S31-01", &e.to_string()))?;
    if let Some(first) = part2_bytes.first_mut() {
        *first ^= 0x01;
    }
    write_s31_file(&part2, &part2_bytes)?;
    if load_parsed_tar_bundle(&parts_manifest).is_ok() {
        return Err(s31_ext_err(
            "S31-01",
            "1-byte part tamper passed verification",
        ));
    }

    Ok(S31ScenarioReport {
        id: "S31-01".into(),
        passed: true,
        detail: format!(
            "multi-asset + {} FAT32 parts + copyleft + tamper rejected",
            summary.parts_count
        ),
    })
}

fn s31_delta_upgrade_and_base_refusal(root: &Path) -> Result<S31ScenarioReport, AirgapCliError> {
    let packs = root.join("packs/essentials");
    let keys = root.join("keys");
    fs::create_dir_all(&packs).map_err(|e| s31_ext_err("S31-02", &e.to_string()))?;
    fs::create_dir_all(&keys).map_err(|e| s31_ext_err("S31-02", &e.to_string()))?;
    write_s31_file(&packs.join("pack.toml"), b"version = \"1.0.0\"\n")?;

    let packs_root = root.join("packs");
    let base_tar = root.join("n.tar");
    let base_sum = build_full_airgap_tar(&empty_s31_req(
        &packs_root,
        &base_tar,
        "b-1",
        "1.0.0",
        &keys,
    ))?;

    write_s31_file(&packs.join("pack.toml"), b"version = \"1.1.0\"\n")?;
    let delta_tar = root.join("n-plus-1.tar");
    let mut delta_req = empty_s31_req(&packs_root, &delta_tar, "b-1", "1.1.0", &keys);
    delta_req.delta_from_version = Some("1.0.0");
    delta_req.delta_from_manifest_sha256 = Some(&base_sum.manifest_sha256);
    let delta_sum = build_full_airgap_tar(&delta_req)?;

    let parsed = load_parsed_tar_bundle(&delta_tar)?;
    // Missing base without state_dir fails naming required base digest.
    let no_base_err = verify_airgap_tar_file(
        &delta_tar,
        None,
        Some(&delta_sum.root_fingerprint),
        None,
        Some(&delta_sum.manifest_sha256),
        "op",
        &[],
        None,
    )
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    if !no_base_err.contains(&base_sum.manifest_sha256) {
        return Err(s31_ext_err(
            "S31-02",
            "delta refusal without base did not name missing base digest",
        ));
    }

    // Matching installed base passes cleanly.
    let state_dir = root.join("state");
    write_s31_file(
        &state_dir.join("installed-manifest.sha256"),
        base_sum.manifest_sha256.as_bytes(),
    )?;
    let (ok_outcome, _) = verify_airgap_tar_file(
        &delta_tar,
        None,
        Some(&delta_sum.root_fingerprint),
        Some(&state_dir),
        Some(&delta_sum.manifest_sha256),
        "op",
        &[],
        None,
    )?;
    verify_extended_bundle_rules(&parsed, &ok_outcome, Some(&base_sum.manifest_sha256), &[])?;

    let err_missing =
        verify_extended_bundle_rules(&parsed, &ok_outcome, Some("n-minus-1-sha"), &[])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
    if !err_missing.contains(&base_sum.manifest_sha256) {
        return Err(s31_ext_err(
            "S31-02",
            "delta refusal did not name missing base digest",
        ));
    }

    Ok(S31ScenarioReport {
        id: "S31-02".into(),
        passed: true,
        detail: "delta N->N+1 accepted and N-1 base mismatch rejected naming missing base".into(),
    })
}

fn s31_clock_bounds_and_openvex(_root: &Path) -> Result<S31ScenarioReport, AirgapCliError> {
    let vex = OpenVexDocument {
        document_id: "vex-s31".into(),
        statements: vec![OpenVexStatement {
            vulnerability_id: "CVE-2026-0001".into(),
            product_id: "grdr".into(),
            status: VexStatus::NotAffected,
            justification: Some("component_not_present".into()),
        }],
    };
    let vex_report = evaluate_openvex_exposure(&vex, &["CVE-2026-0001", "CVE-2026-9999"]);
    if vex_report.suppressed_cves != vec!["CVE-2026-0001".to_owned()]
        || vex_report.active_affected_cves != vec!["CVE-2026-9999".to_owned()]
    {
        return Err(s31_ext_err("S31-06", "OpenVEX suppression logic failed"));
    }
    let conflict_vex = OpenVexDocument {
        document_id: "vex-conflict".into(),
        statements: vec![
            OpenVexStatement {
                vulnerability_id: "CVE-2026-1234".into(),
                product_id: "grdr".into(),
                status: VexStatus::Affected,
                justification: None,
            },
            OpenVexStatement {
                vulnerability_id: "CVE-2026-1234".into(),
                product_id: "grdr".into(),
                status: VexStatus::NotAffected,
                justification: Some("trailing-claim".into()),
            },
        ],
    };
    let conflict_report = evaluate_openvex_exposure(&conflict_vex, &["CVE-2026-1234"]);
    if !conflict_report.suppressed_cves.is_empty()
        || conflict_report.active_affected_cves != vec!["CVE-2026-1234".to_owned()]
    {
        return Err(s31_ext_err(
            "S31-06",
            "OpenVEX trailing NotAffected wrongly overrode Affected",
        ));
    }

    let proj_k = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-06", &e.to_string()))?;
    let dep_k = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-06", &e.to_string()))?;
    let t0 = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let ts_exp = Timestamp::from_second(t0.as_second().saturating_add(7 * 86_400)).unwrap_or(t0);
    let root_exp =
        Timestamp::from_second(t0.as_second().saturating_add(365 * 86_400)).unwrap_or(t0);
    let dep_exp = Timestamp::from_second(t0.as_second().saturating_add(60 * 86_400)).unwrap_or(t0);

    let proj_root = mk_s31_root(TufRootKind::Project, &proj_k, root_exp)?;
    let dep_root = mk_s31_root(TufRootKind::Deployment, &dep_k, dep_exp)?;
    let trust = UpdateTrust::new(proj_root, t0)?.with_deployment_root(dep_root, t0)?;

    let tgt = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires: ts_exp,
            targets: BTreeMap::new(),
        },
        &[&proj_k],
    )?;
    let tgt_bytes =
        serde_json::to_vec(&tgt.signed).map_err(|e| s31_ext_err("S31-06", &e.to_string()))?;
    let tgt_sha = canonical_sha256(&tgt_bytes);
    let snap = sign_metadata(
        SnapshotMetadata {
            version: 1,
            expires: ts_exp,
            meta: BTreeMap::from([(
                TufRole::Targets,
                SnapshotTargetRef {
                    version: 1,
                    sha256: tgt_sha,
                    length: u64::try_from(tgt_bytes.len()).unwrap_or(0),
                },
            )]),
        },
        &[&proj_k],
    )?;
    let snap_bytes =
        serde_json::to_vec(&snap.signed).map_err(|e| s31_ext_err("S31-06", &e.to_string()))?;
    let snap_sha = canonical_sha256(&snap_bytes);
    let ts_meta = TimestampMetadata {
        version: 1,
        expires: ts_exp,
        snapshot: SnapshotTargetRef {
            version: 1,
            sha256: snap_sha.clone(),
            length: u64::try_from(snap_bytes.len()).unwrap_or(0),
        },
    };
    let vouch = sign_metadata(
        FreshnessStatement {
            deployment_id: "dep-1".into(),
            project_root_version: 1,
            project_snapshot_version: 1,
            project_snapshot_sha256: snap_sha,
            imported_at: t0,
            issued_at: t0,
            expires: dep_exp,
        },
        &[&dep_k],
    )?;

    let day_45 = Timestamp::from_second(t0.as_second().saturating_add(45 * 86_400)).unwrap_or(t0);
    let eval_no_vouch =
        trust.evaluate_freshness(&ts_meta, &snap.signed, &tgt.signed, None, None, day_45)?;
    if eval_no_vouch.freshness != UpdateFreshness::Stale || eval_no_vouch.install_permitted {
        return Err(s31_ext_err(
            "S31-06",
            "day 45 without vouch should be stale/blocked",
        ));
    }
    let eval_with_vouch = trust.evaluate_freshness(
        &ts_meta,
        &snap.signed,
        &tgt.signed,
        None,
        Some(&vouch),
        day_45,
    )?;
    if !eval_with_vouch.install_permitted {
        return Err(s31_ext_err(
            "S31-06",
            "day 45 with valid vouch should be permitted",
        ));
    }
    let year_2 = Timestamp::from_second(t0.as_second().saturating_add(730 * 86_400)).unwrap_or(t0);
    let eval_y2 = trust.evaluate_freshness(
        &ts_meta,
        &snap.signed,
        &tgt.signed,
        None,
        Some(&vouch),
        year_2,
    )?;
    if eval_y2.install_permitted {
        return Err(s31_ext_err(
            "S31-06",
            "year 2 past root expiry must not be permitted",
        ));
    }

    Ok(S31ScenarioReport {
        id: "S31-06".into(),
        passed: true,
        detail: "OpenVEX suppression and 45d/2y freshness boundary rules verified".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_s31_conformance_suite_passes_all_scenarios() -> Result<(), AirgapCliError> {
        let dir = std::env::temp_dir().join(format!("grdr-s31-{}", uuid::Uuid::now_v7().simple()));
        let report = run_s31_offline_suite(&dir)?;
        if !report.all_passed || report.scenarios.len() != 6 {
            return Err(s31_ext_err(
                "SUITE",
                &format!("incomplete failure: {report:?}"),
            ));
        }
        Ok(())
    }
}
