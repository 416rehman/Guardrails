// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extended offline S-31 scenarios: server import staging/promotion and signed mirror convergence/delta.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use grdr_blob::FilesystemBlobStore;
use grdr_crypto::SigningKeypair;
use grdr_ports::{BlobPort as _, OrgId, SingleCtx, TenantCtx, TenantPath};
use grdr_update::{
    RootKeyRole, RootMetadata, SnapshotMetadata, SnapshotTargetRef, TargetDescriptor,
    TargetsMetadata, TimestampMetadata, TufRole, TufRootKind, canonical_sha256, sign_metadata,
};
use jiff::Timestamp;

use crate::airgap::AirgapCliError;
use crate::airgap::airgap_import::{ServerAirgapImportArgs, run_server_airgap_import};
use crate::airgap::airgap_mirror::{
    CeremonyKindCli, KeysCeremonyArgs, MirrorExportArgs, MirrorKindCli, MirrorSyncArgs,
    run_keys_ceremony, run_mirror_export, run_mirror_sync,
};
use crate::airgap::airgap_s31::S31ScenarioReport;
use crate::airgap_bundle::{AirgapBuildRequest, AirgapFullBuildRequest, build_full_airgap_tar};

pub fn s31_server_import_resumable_and_audit(
    root: &Path,
) -> Result<S31ScenarioReport, AirgapCliError> {
    let packs = root.join("packs/essentials");
    let images = root.join("images");
    let keys = root.join("keys");
    let proj_ceremony = root.join("proj-ceremony");
    let dep_keys = root.join("dep-keys");
    let ceremony_out = root.join("dep-ceremony");
    for d in [&packs, &images, &keys, &dep_keys] {
        fs::create_dir_all(d).map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;
    }
    write_s31_file(&packs.join("a.toml"), b"a=1")?;
    write_s31_file(&packs.join("b.toml"), b"b=2")?;
    write_s31_file(&images.join("server.oci"), b"img-bytes")?;

    run_keys_ceremony(&KeysCeremonyArgs {
        kind: CeremonyKindCli::Project,
        ceremony_id: "proj-c1".into(),
        deployment_id: "site-airgap".into(),
        out_dir: proj_ceremony.clone(),
        custodians: 2,
        threshold: 2,
        expires_days: 90,
        json: false,
    })?;
    fs::copy(
        proj_ceremony.join("private/release-signer.key"),
        keys.join("release-signer.key"),
    )
    .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;
    fs::copy(
        proj_ceremony.join("private/rebuilder.key"),
        keys.join("rebuilder.key"),
    )
    .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;

    run_keys_ceremony(&KeysCeremonyArgs {
        kind: CeremonyKindCli::Deployment,
        ceremony_id: "dep-c1".into(),
        deployment_id: "site-airgap".into(),
        out_dir: ceremony_out.clone(),
        custodians: 1,
        threshold: 1,
        expires_days: 90,
        json: false,
    })?;

    let packs_root = root.join("packs");
    let tar_out = root.join("srv.tar");
    let mut req = empty_s31_req(&packs_root, &tar_out, "srv-b1", "1.0.0", &keys);
    req.base.allow_ephemeral_dev_keys = false;
    req.images_dir = Some(&images);
    let summary = build_full_airgap_tar(&req)?;

    let state_dir = root.join("state");
    let blob_dir = root.join("blobs");
    let reg_out = root.join("reg");

    let mut import_args = ServerAirgapImportArgs {
        bundle: tar_out,
        root: None,
        expected_fingerprint: Some(summary.root_fingerprint),
        state_dir,
        blob_store_dir: blob_dir.clone(),
        org_id: "site-airgap".into(),
        registry_out: Some(reg_out),
        installed_base_sha256: None,
        print_root: false,
        accept_terms: Some("wrong-digest".into()),
        operator_id: "alice".into(),
        yanks_file: None,
        deployment_root: Some(ceremony_out.join("public/1.root.json")),
        deployment_key_dir: Some(dep_keys.clone()),
        valid_hours: 720,
        resume_session: Some("sess-1".into()),
        chunk_bytes: 1024,
        interrupt_after_blobs: Some(2),
        json: false,
    };
    if run_server_airgap_import(&import_args).is_ok() {
        return Err(s31_ext_err("S31-03", "mismatched --accept-terms succeeded"));
    }

    import_args.accept_terms = Some(summary.manifest_sha256.clone());
    if run_server_airgap_import(&import_args).is_ok() {
        return Err(s31_ext_err(
            "S31-03",
            "missing deployment-fleet key should fail closed",
        ));
    }

    fs::copy(
        ceremony_out.join("private/custodian-1.key"),
        dep_keys.join("deployment-fleet.key"),
    )
    .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;

    if run_server_airgap_import(&import_args).is_ok() {
        return Err(s31_ext_err("S31-03", "interrupted session should pause"));
    }

    let store =
        FilesystemBlobStore::open(&blob_dir).map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;
    let org = OrgId::new("site-airgap").map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;
    let single = SingleCtx::new(org);
    let final_tp = TenantPath::parse(&single, "bundles/1.0.0/images/server.oci")
        .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?;
    let ctx = TenantCtx::Single(single);
    if store
        .get(&ctx, &final_tp)
        .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?
        .is_some()
    {
        return Err(s31_ext_err(
            "S31-03",
            "interrupted upload leaked blob before promotion",
        ));
    }

    import_args.interrupt_after_blobs = None;
    let audit = run_server_airgap_import(&import_args)?;
    if audit.resumed_skipped_blobs != 2
        || audit.outbound_requests != 0
        || !audit.freshness_vouch_issued
    {
        return Err(s31_ext_err(
            "S31-03",
            "resumable import or audit invariants failed",
        ));
    }

    if store
        .get(&ctx, &final_tp)
        .map_err(|e| s31_ext_err("S31-03", &e.to_string()))?
        .is_none()
    {
        return Err(s31_ext_err(
            "S31-03",
            "promoted blob missing from FilesystemBlobStore",
        ));
    }

    Ok(S31ScenarioReport {
        id: "S31-03".into(),
        passed: true,
        detail:
            "server importer verified two-phase staging/promotion, audit JSONL, vouch, zero egress"
                .into(),
    })
}

pub fn s31_mirror_convergence_and_yank(root: &Path) -> Result<S31ScenarioReport, AirgapCliError> {
    let origin = root.join("origin");
    let mirror = root.join("mirror");
    fs::create_dir_all(origin.join("tuf")).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?;
    fs::create_dir_all(origin.join("targets/p"))
        .map_err(|e| s31_ext_err("S31-04", &e.to_string()))?;

    let k = SigningKeypair::generate().map_err(|e| s31_ext_err("S31-04", &e.to_string()))?;
    let exp = Timestamp::from_second(Timestamp::now().as_second().saturating_add(86_400))
        .unwrap_or(Timestamp::UNIX_EPOCH);
    let root_meta = mk_s31_root(TufRootKind::Project, &k, exp)?;
    let root_path = origin.join("tuf/root.json");
    write_s31_file(
        &root_path,
        &serde_json::to_vec(&root_meta).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?,
    )?;

    let mut map = BTreeMap::new();
    for i in 0..10usize {
        let name = format!("p/f{i}.json");
        let payload = format!("{{\"n\":{i}}}").into_bytes();
        let sha = canonical_sha256(&payload);
        if i < 7 {
            write_s31_file(&origin.join("targets").join(&name), &payload)?;
        }
        map.insert(
            name,
            TargetDescriptor {
                role: TufRole::ContentPolicy,
                pack_kind: grdr_update::PackKind::SchemaPolicy,
                signer_class: grdr_update::SignerClass::ProjectContent,
                version: "1.0.0".into(),
                generation: 1,
                sha256: sha,
                length: u64::try_from(payload.len()).unwrap_or(0),
            },
        );
    }
    write_mirror_tuf_meta(&origin, &k, exp, 1, map.clone())?;

    if run_mirror_sync(&MirrorSyncArgs {
        origin_dir: origin.clone(),
        mirror_dir: mirror.clone(),
        root: Some(root_path.clone()),
        deployment_root: None,
        freshness: None,
        platforms: Vec::new(),
        all: true,
        json: false,
    })
    .is_ok()
    {
        return Err(s31_ext_err(
            "S31-04",
            "mirror sync must fail when requested origin files are missing",
        ));
    }

    for i in 7..10usize {
        let payload = format!("{{\"n\":{i}}}").into_bytes();
        write_s31_file(&origin.join(format!("targets/p/f{i}.json")), &payload)?;
    }
    let sync_v1 = run_mirror_sync(&MirrorSyncArgs {
        origin_dir: origin.clone(),
        mirror_dir: mirror.clone(),
        root: None,
        deployment_root: None,
        freshness: None,
        platforms: Vec::new(),
        all: true,
        json: false,
    });
    if sync_v1.is_ok() {
        return Err(s31_ext_err(
            "S31-04",
            "initial unpinned mirror sync without --root succeeded",
        ));
    }

    let second_sync = run_mirror_sync(&MirrorSyncArgs {
        origin_dir: origin.clone(),
        mirror_dir: mirror.clone(),
        root: Some(root_path),
        deployment_root: None,
        freshness: None,
        platforms: Vec::new(),
        all: true,
        json: false,
    })?;
    if !second_sync.active_snapshot_committed || !second_sync.convergence.fully_converged {
        return Err(s31_ext_err(
            "S31-04",
            "completed mirror sync failed convergence",
        ));
    }

    let exp_v1 = run_mirror_export(&MirrorExportArgs {
        mirror_dir: mirror.clone(),
        out: root.join("content.tar"),
        kind: MirrorKindCli::Content,
        base: None,
        split_bytes: None,
        json: false,
    })?;
    if exp_v1.files_exported != 10 || exp_v1.metadata_files_exported < 4 {
        return Err(s31_ext_err(
            "S31-04",
            "mirror content export count != 10 or missing TUF metadata",
        ));
    }

    let delta_payload = br#"{"n":99}"#.to_vec();
    write_s31_file(&origin.join("targets/p/f10.json"), &delta_payload)?;
    map.insert(
        "p/f10.json".into(),
        TargetDescriptor {
            role: TufRole::ContentPolicy,
            pack_kind: grdr_update::PackKind::SchemaPolicy,
            signer_class: grdr_update::SignerClass::ProjectContent,
            version: "1.1.0".into(),
            generation: 2,
            sha256: canonical_sha256(&delta_payload),
            length: u64::try_from(delta_payload.len()).unwrap_or(0),
        },
    );
    write_mirror_tuf_meta(&origin, &k, exp, 2, map)?;
    run_mirror_sync(&MirrorSyncArgs {
        origin_dir: origin,
        mirror_dir: mirror.clone(),
        root: None,
        deployment_root: None,
        freshness: None,
        platforms: Vec::new(),
        all: true,
        json: false,
    })?;
    let delta_exp = run_mirror_export(&MirrorExportArgs {
        mirror_dir: mirror,
        out: root.join("delta.tar"),
        kind: MirrorKindCli::Delta,
        base: Some(exp_v1.target_snapshot_sha256),
        split_bytes: None,
        json: false,
    })?;
    if delta_exp.files_exported != 1 || delta_exp.metadata_files_exported < 4 {
        return Err(s31_ext_err(
            "S31-04",
            "mirror delta export did not isolate single changed file",
        ));
    }

    Ok(S31ScenarioReport {
        id: "S31-04".into(),
        passed: true,
        detail: "10-target verified TUF mirror sync, fail-closed missing target check, and 1-file delta export verified"
            .into(),
    })
}

fn write_mirror_tuf_meta(
    origin: &Path,
    k: &SigningKeypair,
    expires: Timestamp,
    version: u64,
    map: BTreeMap<String, TargetDescriptor>,
) -> Result<(), AirgapCliError> {
    let targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version,
            expires,
            targets: map,
        },
        &[k],
    )?;
    let tgt_raw =
        serde_json::to_vec(&targets.signed).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?;
    let snap = sign_metadata(
        SnapshotMetadata {
            version,
            expires,
            meta: BTreeMap::from([(
                TufRole::Targets,
                SnapshotTargetRef {
                    version,
                    sha256: canonical_sha256(&tgt_raw),
                    length: u64::try_from(tgt_raw.len()).unwrap_or(0),
                },
            )]),
        },
        &[k],
    )?;
    let snap_raw =
        serde_json::to_vec(&snap.signed).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?;
    let ts = sign_metadata(
        TimestampMetadata {
            version,
            expires,
            snapshot: SnapshotTargetRef {
                version,
                sha256: canonical_sha256(&snap_raw),
                length: u64::try_from(snap_raw.len()).unwrap_or(0),
            },
        },
        &[k],
    )?;
    write_s31_file(
        &origin.join("tuf/targets.json"),
        &serde_json::to_vec(&targets).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?,
    )?;
    write_s31_file(
        &origin.join("tuf/snapshot.json"),
        &serde_json::to_vec(&snap).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?,
    )?;
    write_s31_file(
        &origin.join("tuf/timestamp.json"),
        &serde_json::to_vec(&ts).map_err(|e| s31_ext_err("S31-04", &e.to_string()))?,
    )
}

pub fn empty_s31_req<'a>(
    packs_dir: &'a Path,
    out: &'a Path,
    bundle_id: &'a str,
    version: &'a str,
    key_dir: &'a Path,
) -> AirgapFullBuildRequest<'a> {
    AirgapFullBuildRequest {
        base: AirgapBuildRequest {
            packs_dir,
            out,
            bundle_id,
            version,
            expires_days: 90,
            halted_releases: &[],
            key_dir: Some(key_dir),
            allow_ephemeral_dev_keys: true,
        },
        binaries_dir: None,
        images_dir: None,
        charts_dir: None,
        apt_dir: None,
        rpm_dir: None,
        docs_dir: None,
        terraform_dir: None,
        models_dir: None,
        csaf_dir: None,
        sources_dir: None,
        sbom_path: None,
        vex_path: None,
        dependencies_lock_path: None,
        release_manifest_path: None,
        trusted_root_path: None,
        rollout_path: None,
        platforms: &[],
        delta_from_version: None,
        delta_from_manifest_sha256: None,
        minimum_base_version: None,
        yanked_releases: &[],
        split_bytes: None,
    }
}

pub fn mk_s31_root(
    kind: TufRootKind,
    k: &SigningKeypair,
    expires: Timestamp,
) -> Result<grdr_update::SignedMetadata<RootMetadata>, AirgapCliError> {
    let role = RootKeyRole {
        key_ids: vec![k.key_id().to_owned()],
        threshold: 1,
    };
    let mut roles = BTreeMap::from([
        (TufRole::Root, role.clone()),
        (TufRole::Timestamp, role.clone()),
        (TufRole::Snapshot, role.clone()),
        (TufRole::Targets, role.clone()),
        (TufRole::Binaries, role.clone()),
    ]);
    if kind == TufRootKind::Deployment {
        roles.insert(TufRole::Fleet, role);
    }
    Ok(sign_metadata(
        RootMetadata {
            root_kind: kind,
            version: 1,
            expires,
            keys: BTreeMap::from([(
                k.key_id().to_owned(),
                grdr_model::TrustedKeyInfo {
                    key_id: k.key_id().to_owned(),
                    public_key_b64: k.public_key_b64(),
                },
            )]),
            roles,
        },
        &[k],
    )?)
}

pub fn write_s31_file(path: &Path, bytes: &[u8]) -> Result<(), AirgapCliError> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| s31_ext_err("IO", &e.to_string()))?;
    }
    fs::write(path, bytes).map_err(|e| s31_ext_err("IO", &e.to_string()))
}

pub fn s31_ext_err(id: &str, detail: &str) -> AirgapCliError {
    AirgapCliError::InvalidInput(format!("S31[{id}]: {detail}"))
}
