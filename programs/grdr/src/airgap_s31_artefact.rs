// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline S31-05 checks for `grdr verify-artefact`: Sigstore, Rekor Merkle, platform DSSE, and TUF.

use std::collections::BTreeMap;
use std::path::Path;

use grdr_crypto::SigningKeypair;
use grdr_model::TrustedKeyInfo;
use grdr_update::{
    PackKind, RootKeyRole, RootMetadata, SignerClass, SnapshotMetadata, SnapshotTargetRef,
    TargetDescriptor, TargetsMetadata, TimestampMetadata, TufRole, TufRootKind, canonical_sha256,
    sign_dsse_envelope, sign_metadata,
};
use jiff::Timestamp;

use crate::airgap::AirgapCliError;
use crate::airgap::airgap_s31::S31ScenarioReport;
use crate::airgap::airgap_s31_extended::{mk_s31_root, s31_ext_err, write_s31_file};
use crate::airgap::verify_artefact::{
    VerifyArtefactTufInputs, verify_artefact_offline, verify_artefact_offline_with_tuf,
};
use crate::airgap::verify_artefact_sigstore::VerifyArtefactPolicy;
use crate::airgap::verify_artefact_types::{
    DEFAULT_GITHUB_BUILDER, DEFAULT_SLSA_BUILD_TYPE, OfflineBundleSignParams,
    PLATFORM_SIG_PAYLOAD_TYPE, PlatformSignaturePayload, PlatformSignatureStatus,
    RELEASE_MANIFEST_PAYLOAD_TYPE, SignedPlatformSignatureAttestation, build_signed_trusted_root,
    create_signed_offline_sigstore_bundle, create_signed_platform_sig_attestation,
};

pub fn s31_verify_artefact_offline_and_forgeries(
    root: &Path,
) -> Result<S31ScenarioReport, AirgapCliError> {
    std::fs::create_dir_all(root).map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let eph = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let ca = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let rekor = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let tsa = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;

    let signed_at = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let cert_end = Timestamp::from_second(1_750_086_400).unwrap_or(signed_at);
    let now = Timestamp::now();
    let root_valid_end =
        Timestamp::from_second(now.as_second().saturating_add(86_400 * 30)).unwrap_or(signed_at);

    let bin_bytes = b"grdr-release-binary-v1";
    let bin_sha = canonical_sha256(bin_bytes);
    let bin_path = root.join("grdr");
    write_s31_file(&bin_path, bin_bytes)?;

    let trusted_root = build_signed_trusted_root(
        "https://token.actions.githubusercontent.com",
        "416rehman/Guardrails",
        ".github/workflows/release.yml",
        &ca,
        &rekor,
        &tsa,
        Timestamp::from_second(1_740_000_000).unwrap_or(signed_at),
        root_valid_end,
    );
    let tr_path = root.join("trusted_root.json");
    write_json(&tr_path, &trusted_root)?;

    let valid_bundle = create_signed_offline_sigstore_bundle(&OfflineBundleSignParams {
        subject_name: "grdr",
        artefact_bytes: bin_bytes,
        issuer: "https://token.actions.githubusercontent.com",
        repository: "416rehman/Guardrails",
        workflow_path: ".github/workflows/release.yml",
        source_ref: "refs/tags/v0.1.0",
        builder_id: "https://github.com/actions/runner",
        signed_at,
        cert_not_before: signed_at,
        cert_not_after: cert_end,
        eph_signer: &eph,
        ca_signer: &ca,
        rekor_signer: &rekor,
        tsa_signer: &tsa,
    })?;
    let bundle_path = root.join("grdr.sigstore.json");
    write_json(&bundle_path, &valid_bundle)?;

    let policy = VerifyArtefactPolicy {
        expected_issuer: "https://token.actions.githubusercontent.com",
        expected_repository: "416rehman/Guardrails",
        expected_workflow: ".github/workflows/release.yml",
        expected_ref_prefix: "refs/tags/v",
        expected_builder: DEFAULT_GITHUB_BUILDER,
        expected_build_type: DEFAULT_SLSA_BUILD_TYPE,
        require_platform_signature: false,
    };
    let report =
        verify_artefact_offline(&bin_path, &bundle_path, &tr_path, None, None, None, &policy)?;
    if !report.offline_mode || !report.verified {
        return Err(s31_ext_err("S31-05", "valid offline bundle failed"));
    }

    let fork_bundle = create_signed_offline_sigstore_bundle(&OfflineBundleSignParams {
        subject_name: "grdr",
        artefact_bytes: bin_bytes,
        issuer: "https://token.actions.githubusercontent.com",
        repository: "evil-fork/Guardrails",
        workflow_path: ".github/workflows/release.yml",
        source_ref: "refs/tags/v0.1.0",
        builder_id: "https://github.com/actions/runner",
        signed_at,
        cert_not_before: signed_at,
        cert_not_after: cert_end,
        eph_signer: &eph,
        ca_signer: &ca,
        rekor_signer: &rekor,
        tsa_signer: &tsa,
    })?;
    let fork_path = root.join("fork.sigstore.json");
    write_json(&fork_path, &fork_bundle)?;
    if verify_artefact_offline(&bin_path, &fork_path, &tr_path, None, None, None, &policy).is_ok() {
        return Err(s31_ext_err("S31-05", "fork repo bundle was accepted"));
    }

    let mut bad_merkle = valid_bundle.clone();
    if let Some(entry) = bad_merkle.verification_material.tlog_entries.get_mut(0)
        && let Some(slot) = entry.inclusion_proof_hashes.get_mut(0)
    {
        *slot = "00".repeat(32);
    }
    let bad_merkle_path = root.join("bad-merkle.json");
    write_json(&bad_merkle_path, &bad_merkle)?;
    if verify_artefact_offline(
        &bin_path,
        &bad_merkle_path,
        &tr_path,
        None,
        None,
        None,
        &policy,
    )
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-05",
            "tampered Rekor Merkle proof was accepted",
        ));
    }

    let signed_att = create_signed_platform_sig_attestation(
        &PlatformSignaturePayload {
            platform: "windows".into(),
            artefact_sha256: bin_sha.clone(),
            signer_subject: "416rehman/Guardrails".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
            verified_at: signed_at,
            status: PlatformSignatureStatus::Verified,
            detail: "authenticode-verified".into(),
        },
        &ca,
    )?;
    let sig_ok_path = root.join("win-sig-ok.json");
    write_json(&sig_ok_path, &signed_att)?;
    let strict_platform = VerifyArtefactPolicy {
        require_platform_signature: true,
        ..policy.clone()
    };
    let sig_report = verify_artefact_offline(
        &bin_path,
        &bundle_path,
        &tr_path,
        None,
        None,
        Some(&sig_ok_path),
        &strict_platform,
    )?;
    if sig_report.platform_signature_status != PlatformSignatureStatus::Verified {
        return Err(s31_ext_err("S31-05", "signed platform attestation failed"));
    }

    let unsigned_sidecar_path = root.join("win-sig-unsigned.json");
    write_s31_file(
        &unsigned_sidecar_path,
        br#"{"platform":"windows","status":"verified","detail":"forged"}"#,
    )?;
    if verify_artefact_offline(
        &bin_path,
        &bundle_path,
        &tr_path,
        None,
        None,
        Some(&unsigned_sidecar_path),
        &strict_platform,
    )
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-05",
            "unsigned platform sidecar passed strict check",
        ));
    }

    let expired_att = create_signed_platform_sig_attestation(
        &PlatformSignaturePayload {
            platform: "windows".into(),
            artefact_sha256: bin_sha.clone(),
            signer_subject: "416rehman/Guardrails".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
            verified_at: Timestamp::from_second(root_valid_end.as_second().saturating_add(60))
                .unwrap_or(root_valid_end),
            status: PlatformSignatureStatus::Verified,
            detail: "after-ca-expiry".into(),
        },
        &ca,
    )?;
    let sig_expired_path = root.join("win-sig-expired.json");
    write_json(&sig_expired_path, &expired_att)?;
    if verify_artefact_offline(
        &bin_path,
        &bundle_path,
        &tr_path,
        None,
        None,
        Some(&sig_expired_path),
        &strict_platform,
    )
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-05",
            "expired CA window platform attestation passed strict check",
        ));
    }

    verify_tuf_and_manifest_binding(
        root,
        &bin_path,
        &bundle_path,
        &tr_path,
        &trusted_root,
        bin_bytes,
        &bin_sha,
        root_valid_end,
        &policy,
    )?;

    Ok(S31ScenarioReport {
        id: "S31-05".into(),
        passed: true,
        detail: "offline Sigstore, Merkle proof, TUF/manifest binding, and signed platform attestation verified"
            .into(),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_tuf_and_manifest_binding(
    root: &Path,
    bin_path: &Path,
    bundle_path: &Path,
    tr_path: &Path,
    trusted_root: &grdr_update::SigstoreTrustedRoot,
    bin_bytes: &[u8],
    bin_sha: &str,
    expires: Timestamp,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<(), AirgapCliError> {
    let tuf_k = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let tuf_root = mk_s31_root(TufRootKind::Project, &tuf_k, expires)?;
    let targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Binaries,
            version: 1,
            expires,
            targets: BTreeMap::from([(
                "bin/grdr".into(),
                TargetDescriptor {
                    role: TufRole::Binaries,
                    pack_kind: PackKind::Binary,
                    signer_class: SignerClass::ProjectBinaries,
                    version: "0.1.0".into(),
                    generation: 1,
                    sha256: bin_sha.to_owned(),
                    length: u64::try_from(bin_bytes.len()).unwrap_or(0),
                },
            )]),
        },
        &[&tuf_k],
    )?;
    let tgt_raw =
        serde_json::to_vec(&targets.signed).map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let snap = sign_metadata(
        SnapshotMetadata {
            version: 1,
            expires,
            meta: BTreeMap::from([(
                TufRole::Binaries,
                SnapshotTargetRef {
                    version: 1,
                    sha256: canonical_sha256(&tgt_raw),
                    length: u64::try_from(tgt_raw.len()).unwrap_or(0),
                },
            )]),
        },
        &[&tuf_k],
    )?;
    let snap_raw =
        serde_json::to_vec(&snap.signed).map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let ts = sign_metadata(
        TimestampMetadata {
            version: 1,
            expires,
            snapshot: SnapshotTargetRef {
                version: 1,
                sha256: canonical_sha256(&snap_raw),
                length: u64::try_from(snap_raw.len()).unwrap_or(0),
            },
        },
        &[&tuf_k],
    )?;

    let root_p = root.join("tuf-root.json");
    let ts_p = root.join("tuf-ts.json");
    let snap_p = root.join("tuf-snap.json");
    let tgt_p = root.join("tuf-tgt.json");
    let rel_p = root.join("release-manifest.json");
    let rel_dsse_p = root.join("release-manifest.dsse.json");
    write_json(&root_p, &tuf_root)?;
    write_json(&ts_p, &ts)?;
    write_json(&snap_p, &snap)?;
    write_json(&tgt_p, &targets)?;

    let rel_bytes = serde_json::to_vec(&serde_json::json!({
        "trusted_root": trusted_root,
        "oidc": {
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "416rehman/Guardrails",
            "workflow_path": ".github/workflows/release.yml",
            "ref_prefix": "refs/tags/v",
            "builder_id": DEFAULT_GITHUB_BUILDER,
            "build_type": DEFAULT_SLSA_BUILD_TYPE
        },
        "artefacts": [{
            "name": "grdr",
            "sha256": bin_sha
        }]
    }))
    .map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let rel_dsse = sign_dsse_envelope(RELEASE_MANIFEST_PAYLOAD_TYPE, &rel_bytes, &[&tuf_k])?;
    write_s31_file(&rel_p, &rel_bytes)?;
    write_json(&rel_dsse_p, &rel_dsse)?;

    let tuf_inputs = VerifyArtefactTufInputs {
        tuf_root: Some(&root_p),
        tuf_timestamp: Some(&ts_p),
        tuf_snapshot: Some(&snap_p),
        tuf_targets: Some(&tgt_p),
        release_manifest_dsse: Some(&rel_dsse_p),
        ..VerifyArtefactTufInputs::default()
    };
    verify_artefact_offline_with_tuf(
        bin_path,
        bundle_path,
        tr_path,
        Some(&rel_p),
        &tuf_inputs,
        None,
        policy,
    )?;

    write_s31_file(&rel_p, br#"{"artefact_sha256":"deadbeef"}"#)?;
    if verify_artefact_offline_with_tuf(
        bin_path,
        bundle_path,
        tr_path,
        Some(&rel_p),
        &tuf_inputs,
        None,
        policy,
    )
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-05",
            "tampered release manifest bypassed DSSE verification",
        ));
    }
    verify_binaries_quorum_platform_sig(
        root,
        bin_path,
        bundle_path,
        tr_path,
        bin_sha,
        &tuf_k,
        expires,
        policy,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_binaries_quorum_platform_sig(
    root: &Path,
    bin_path: &Path,
    bundle_path: &Path,
    tr_path: &Path,
    bin_sha: &str,
    tuf_k: &SigningKeypair,
    expires: Timestamp,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<(), AirgapCliError> {
    let k1 = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let k2 = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let keys = [tuf_k, &k1, &k2]
        .into_iter()
        .map(|k| {
            (
                k.key_id().to_owned(),
                TrustedKeyInfo {
                    key_id: k.key_id().to_owned(),
                    public_key_b64: k.public_key_b64(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut roles = [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
    ]
    .into_iter()
    .map(|r| {
        (
            r,
            RootKeyRole {
                key_ids: vec![tuf_k.key_id().to_owned()],
                threshold: 1,
            },
        )
    })
    .collect::<BTreeMap<_, _>>();
    roles.insert(
        TufRole::Binaries,
        RootKeyRole {
            key_ids: vec![k1.key_id().to_owned(), k2.key_id().to_owned()],
            threshold: 2,
        },
    );
    let q_root = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys,
            roles,
        },
        &[tuf_k],
    )?;
    let q_root_p = root.join("tuf-root-2of2.json");
    write_json(&q_root_p, &q_root)?;
    let plat_bytes = serde_json::to_vec(&PlatformSignaturePayload {
        platform: "windows".into(),
        artefact_sha256: bin_sha.to_owned(),
        signer_subject: "416rehman/Guardrails".into(),
        issuer: "https://token.actions.githubusercontent.com".into(),
        verified_at: Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        status: PlatformSignatureStatus::Verified,
        detail: "2of2-binaries-quorum".into(),
    })
    .map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    let one_p = root.join("tuf-plat-1of2.json");
    let two_p = root.join("tuf-plat-2of2.json");
    let one = SignedPlatformSignatureAttestation {
        dsse_envelope: sign_dsse_envelope(PLATFORM_SIG_PAYLOAD_TYPE, &plat_bytes, &[&k1])?,
    };
    let two = SignedPlatformSignatureAttestation {
        dsse_envelope: sign_dsse_envelope(PLATFORM_SIG_PAYLOAD_TYPE, &plat_bytes, &[&k1, &k2])?,
    };
    write_json(&one_p, &one)?;
    write_json(&two_p, &two)?;
    let strict = VerifyArtefactPolicy {
        require_platform_signature: true,
        ..policy.clone()
    };
    let tuf = VerifyArtefactTufInputs {
        tuf_root: Some(&q_root_p),
        ..VerifyArtefactTufInputs::default()
    };
    if verify_artefact_offline_with_tuf(
        bin_path,
        bundle_path,
        tr_path,
        None,
        &tuf,
        Some(&one_p),
        &strict,
    )
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-05",
            "1-of-2 TUF Binaries platform sig bypassed 2-of-2 quorum",
        ));
    }
    let rep = verify_artefact_offline_with_tuf(
        bin_path,
        bundle_path,
        tr_path,
        None,
        &tuf,
        Some(&two_p),
        &strict,
    )?;
    if rep.platform_signature_status != PlatformSignatureStatus::Verified {
        return Err(s31_ext_err(
            "S31-05",
            "2-of-2 TUF Binaries platform sig failed",
        ));
    }
    Ok(())
}

fn write_json<T: serde::Serialize>(path: &Path, val: &T) -> Result<(), AirgapCliError> {
    let bytes = serde_json::to_vec(val).map_err(|e| s31_ext_err("S31-05", &e.to_string()))?;
    write_s31_file(path, &bytes)
}
