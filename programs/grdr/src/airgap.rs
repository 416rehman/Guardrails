// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap CLI commands and offline S-31 TUF/DSSE/Sigstore verification.

#[path = "airgap_bundle_tuf.rs"]
pub mod airgap_bundle_tuf;
#[path = "airgap_ceremony.rs"]
pub mod airgap_ceremony;
#[path = "airgap_cli_args.rs"]
pub mod airgap_cli_args;
#[path = "airgap_import.rs"]
pub mod airgap_import;
#[path = "airgap_import_ops.rs"]
pub mod airgap_import_ops;
#[path = "airgap_mirror.rs"]
pub mod airgap_mirror;
#[path = "airgap_mirror_export.rs"]
pub mod airgap_mirror_export;
#[path = "airgap_policy.rs"]
pub mod airgap_policy;
#[path = "airgap_s31.rs"]
pub mod airgap_s31;
#[path = "airgap_s31_artefact.rs"]
pub mod airgap_s31_artefact;
#[path = "airgap_s31_extended.rs"]
pub mod airgap_s31_extended;
#[path = "airgap_state.rs"]
pub mod airgap_state;
#[path = "verify_artefact.rs"]
pub mod verify_artefact;
#[path = "verify_artefact_binding.rs"]
pub mod verify_artefact_binding;
#[path = "verify_artefact_manifest.rs"]
pub mod verify_artefact_manifest;
#[path = "verify_artefact_sigstore.rs"]
pub mod verify_artefact_sigstore;
#[path = "verify_artefact_types.rs"]
pub mod verify_artefact_types;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use grdr_update::{
    AirgapVerificationOutcome, BundleApprovalState, RolloutHaltEntry, UpdateError, UpdateTrust,
    verify_airgap_bundle,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::airgap_cli_args::{
    AirgapBuildArgs, AirgapVerifyArgs, handle_build_args, handle_verify_args, print_json_pretty,
};
use crate::airgap::airgap_import::{
    ServerAirgapCommand, ServerAirgapImportArgs, handle_server_airgap_command,
};
use crate::airgap::airgap_mirror::{
    KeysCeremonyArgs, MirrorExportArgs, MirrorSyncArgs, MirrorVouchArgs, run_keys_ceremony,
    run_mirror_export, run_mirror_sync, run_mirror_vouch,
};
use crate::airgap::airgap_s31::run_s31_offline_suite;
use crate::airgap::airgap_state::{
    check_and_update_watermarks, load_yanks_for_verify, resolve_and_persist_trust_anchor,
    yanks_to_halts,
};
use crate::airgap::verify_artefact::{VerifyArtefactCliArgs, handle_verify_artefact_args};
use crate::airgap_bundle::{PATH_MANIFEST_JSON, root_fingerprint};
use crate::airgap_verify::{
    extract_verified_artifacts, load_parsed_tar_bundle, read_root_metadata_file,
    verify_extended_bundle_rules, verify_required_bundle_envelope,
};
use crate::fs_safe::read_bounded_regular;

#[derive(Debug, Subcommand)]
pub enum AirgapCommand {
    /// Package signed packs and optional site assets into an offline OCI-layout / POSIX tar bundle.
    Build(Box<AirgapBuildArgs>),
    /// Verify an air-gap bundle (or `.parts.json` split parts) offline against project TUF/DSSE roots.
    Verify(Box<AirgapVerifyArgs>),
    /// Verify an individual artefact offline using Sigstore bundle, inclusion proof, and trusted_root.json.
    VerifyArtefact(Box<VerifyArtefactCliArgs>),
    /// Server-side air-gap bundle importer (resumable blob import, audit log, zero egress).
    ServerImport(Box<ServerAirgapImportArgs>),
    /// Synchronize a site TUF mirror from an upstream origin directory with immutable caching.
    MirrorSync(Box<MirrorSyncArgs>),
    /// Export a delta, content, or metadata bundle from a site TUF mirror.
    MirrorExport(Box<MirrorExportArgs>),
    /// Issue a deployment-signed freshness statement vouching for imported TUF snapshot freshness.
    MirrorVouch(Box<MirrorVouchArgs>),
    /// Run a TUF project (2-of-2) or deployment root ceremony writing `1.root.json` and transcript.
    KeysCeremony(Box<KeysCeremonyArgs>),
    /// Execute offline S-31 air-gap supply-chain and verification conformance checks.
    S31 {
        #[arg(long)]
        work_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapRootReport {
    pub verified: bool,
    pub root_fingerprint: String,
    pub root_version: u64,
    pub root_expires: Timestamp,
    pub manifest_sha256: String,
    pub key_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AirgapCliError {
    #[error("GRDR-AIRGAP-0001: I/O failure on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-AIRGAP-0002: {0}")]
    InvalidInput(String),
    #[error("{0}")]
    Update(#[from] UpdateError),
}

pub fn handle_airgap_command(cmd: AirgapCommand) -> ExitCode {
    match cmd {
        AirgapCommand::VerifyArtefact(args) => handle_verify_artefact_args(*args),
        AirgapCommand::ServerImport(args) => {
            handle_server_airgap_command(ServerAirgapCommand::Import(*args))
        }
        other => match run_airgap(other) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run_airgap(cmd: AirgapCommand) -> Result<ExitCode, AirgapCliError> {
    match cmd {
        AirgapCommand::Build(args) => handle_build_args(&args),
        AirgapCommand::Verify(args) => handle_verify_args(&args),
        AirgapCommand::MirrorSync(args) => {
            let summary = run_mirror_sync(&args)?;
            if args.json {
                print_json_pretty(&summary)?;
            } else {
                println!(
                    "Mirror sync: synced={} cache_hits={} converged={}",
                    summary.synced_files,
                    summary.cache_hits_immutable,
                    summary.active_snapshot_committed
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        AirgapCommand::MirrorExport(args) => {
            let summary = run_mirror_export(&args)?;
            if args.json {
                print_json_pretty(&summary)?;
            } else {
                println!(
                    "Mirror exported {} files -> {} (parts={})",
                    summary.files_exported, summary.out, summary.parts_count
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        AirgapCommand::MirrorVouch(args) => {
            run_mirror_vouch(&args)?;
            println!(
                "Issued deployment freshness vouch -> {}",
                args.out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        AirgapCommand::KeysCeremony(args) => {
            let fp = run_keys_ceremony(&args)?;
            if args.json {
                print_json_pretty(&serde_json::json!({"root_fingerprint": fp}))?;
            } else {
                println!("Completed ceremony {} -> {fp}", args.ceremony_id);
            }
            Ok(ExitCode::SUCCESS)
        }
        AirgapCommand::S31 { work_dir, json } => {
            let dir = work_dir.unwrap_or_else(|| {
                std::env::temp_dir().join(format!("grdr-s31-cli-{}", uuid::Uuid::now_v7().simple()))
            });
            let report = run_s31_offline_suite(&dir)?;
            if json {
                print_json_pretty(&report)?;
            } else {
                println!("S-31 suite passed: {} scenarios", report.scenarios.len());
            }
            Ok(if report.all_passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        AirgapCommand::VerifyArtefact(_) | AirgapCommand::ServerImport(_) => Ok(ExitCode::SUCCESS),
    }
}

pub fn inspect_bundle_root(
    bundle_path: &Path,
    override_root: Option<&Path>,
) -> Result<AirgapRootReport, AirgapCliError> {
    let parsed = load_parsed_tar_bundle(bundle_path)?;
    let root = match override_root {
        Some(p) => read_root_metadata_file(p)?,
        None => parsed.embedded_root.ok_or_else(|| {
            UpdateError::MalformedMetadata("missing meta/project-root.json".into())
        })?,
    };
    Ok(AirgapRootReport {
        verified: false,
        root_fingerprint: root_fingerprint(&root.signed)?,
        root_version: root.signed.version,
        root_expires: root.signed.expires,
        manifest_sha256: parsed.manifest_sha256,
        key_ids: root.signed.keys.keys().cloned().collect(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_airgap_tar_file(
    bundle_path: &Path,
    override_root: Option<&Path>,
    expected_fingerprint: Option<&str>,
    state_dir: Option<&Path>,
    accept_terms_digest: Option<&str>,
    operator_id: &str,
    external_halts: &[RolloutHaltEntry],
    extract_dir: Option<&Path>,
) -> Result<(AirgapVerificationOutcome, String), AirgapCliError> {
    verify_airgap_tar_with_base(
        bundle_path,
        override_root,
        expected_fingerprint,
        state_dir,
        None,
        accept_terms_digest,
        operator_id,
        external_halts,
        None,
        extract_dir,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_airgap_tar_with_base(
    bundle_path: &Path,
    override_root: Option<&Path>,
    expected_fingerprint: Option<&str>,
    state_dir: Option<&Path>,
    installed_base_override: Option<&str>,
    accept_terms_digest: Option<&str>,
    operator_id: &str,
    external_halts: &[RolloutHaltEntry],
    yanks_file: Option<&Path>,
    extract_dir: Option<&Path>,
) -> Result<(AirgapVerificationOutcome, String), AirgapCliError> {
    let parsed = load_parsed_tar_bundle(bundle_path)?;
    let now = Timestamp::now();
    let trusted_root = resolve_and_persist_trust_anchor(
        override_root,
        state_dir,
        expected_fingerprint,
        &parsed,
        now,
        false,
    )?;
    let actual_root_fp = root_fingerprint(&trusted_root.signed)?;
    let root_version = trusted_root.signed.version;
    let trust = UpdateTrust::new(trusted_root, now)?;
    let approval = match accept_terms_digest {
        None => BundleApprovalState::AwaitingTermsAcceptance,
        Some(accepted) if accepted != parsed.manifest_sha256 => {
            return Err(AirgapCliError::InvalidInput(format!(
                "GRDR-UPD-0010: --accept-terms digest `{accepted}` != bundle manifest `{}`",
                parsed.manifest_sha256
            )));
        }
        Some(_) => BundleApprovalState::TermsAccepted {
            operator_id: operator_id.to_owned(),
            accepted_at: now,
        },
    };

    let dsse_payload = parsed.envelope.decode_payload()?;
    if dsse_payload != parsed.manifest_bytes {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_MANIFEST_JSON.into(),
            detail: "meta/airgap-manifest.json diverges from DSSE payload".into(),
        }
        .into());
    }

    let external_yanks = load_yanks_for_verify(state_dir, yanks_file)?;
    let mut combined_halts = external_halts.to_vec();
    combined_halts.extend(yanks_to_halts(&external_yanks));
    let outcome = verify_airgap_bundle(
        &trust,
        &parsed.envelope,
        &parsed.artifacts,
        &approval,
        &combined_halts,
        now,
    )?;
    verify_required_bundle_envelope(&parsed, &outcome, &actual_root_fp)?;

    let installed_base = match installed_base_override {
        Some(v) => Some(v.to_owned()),
        None => state_dir
            .map(|d| d.join("installed-manifest.sha256"))
            .filter(|p| p.is_file())
            .and_then(|p| read_bounded_regular(&p, 256).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.trim().to_owned()),
    };
    verify_extended_bundle_rules(
        &parsed,
        &outcome,
        installed_base.as_deref(),
        &external_yanks,
    )?;
    if let Some(dir) = state_dir {
        check_and_update_watermarks(
            dir,
            &outcome,
            root_version,
            parsed.manifest.created_at,
            &parsed.manifest_sha256,
            false,
        )?;
    }

    if let Some(dest) = extract_dir {
        extract_verified_artifacts(dest, &parsed.artifacts)?;
    }
    if let Some(dir) = state_dir {
        resolve_and_persist_trust_anchor(
            override_root,
            Some(dir),
            expected_fingerprint,
            &parsed,
            now,
            true,
        )?;
        check_and_update_watermarks(
            dir,
            &outcome,
            root_version,
            parsed.manifest.created_at,
            &parsed.manifest_sha256,
            true,
        )?;
    }
    Ok((outcome, parsed.manifest_sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airgap_bundle::{AirgapBuildRequest, AirgapFullBuildRequest, build_full_airgap_tar};
    use std::fs;

    #[test]
    fn build_and_verify_airgap_tar_rejects_unaccepted_terms_and_tamper() {
        let base =
            std::env::temp_dir().join(format!("grdr-airgap-cli-{}", uuid::Uuid::now_v7().simple()));
        let packs_dir = base.join("src-packs");
        let keys_dir = base.join("keys");
        fs::create_dir_all(packs_dir.join("essentials")).unwrap();
        fs::write(
            packs_dir.join("essentials/pack.toml"),
            b"id = \"grdr.essentials\"\n",
        )
        .unwrap();
        let tar_path = base.join("grdr-airgap.tar");
        let missing_keys_err = build_full_airgap_tar(&AirgapFullBuildRequest {
            base: AirgapBuildRequest {
                packs_dir: &packs_dir,
                out: &tar_path,
                bundle_id: "test-airgap",
                version: "1.0.0",
                expires_days: 90,
                halted_releases: &[],
                key_dir: Some(&keys_dir),
                allow_ephemeral_dev_keys: false,
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
        });
        assert!(matches!(
            missing_keys_err,
            Err(AirgapCliError::InvalidInput(_))
        ));

        let summary = build_full_airgap_tar(&AirgapFullBuildRequest {
            base: AirgapBuildRequest {
                packs_dir: &packs_dir,
                out: &tar_path,
                bundle_id: "test-airgap",
                version: "1.0.0",
                expires_days: 90,
                halted_releases: &[],
                key_dir: Some(&keys_dir),
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
        })
        .unwrap();
        assert_eq!(summary.entries_count, 4);

        let wrong_fp = verify_airgap_tar_file(
            &tar_path,
            None,
            Some("fp_0000"),
            None,
            Some(&summary.manifest_sha256),
            "op-1",
            &[],
            None,
        );
        assert!(matches!(
            wrong_fp,
            Err(AirgapCliError::Update(UpdateError::UnauthorizedRoot(_)))
        ));

        let no_anchor = verify_airgap_tar_file(
            &tar_path,
            None,
            None,
            None,
            Some(&summary.manifest_sha256),
            "op-1",
            &[],
            None,
        );
        assert!(matches!(
            no_anchor,
            Err(AirgapCliError::Update(UpdateError::UnauthorizedRoot(_)))
        ));

        let no_terms = verify_airgap_tar_file(
            &tar_path,
            None,
            Some(&summary.root_fingerprint),
            None,
            None,
            "op-1",
            &[],
            None,
        );
        assert!(matches!(
            no_terms,
            Err(AirgapCliError::Update(UpdateError::TermsNotAccepted))
        ));

        let state_dir = base.join("state");
        let extract_dir = base.join("out-packs");
        let (ok, _) = verify_airgap_tar_file(
            &tar_path,
            None,
            Some(&summary.root_fingerprint),
            Some(&state_dir),
            Some(&summary.manifest_sha256),
            "op-1",
            &[],
            Some(&extract_dir),
        )
        .unwrap();
        assert_eq!(ok.verified_entries, 4);
        assert!(extract_dir.join("packs/essentials/pack.toml").is_file());
        assert!(state_dir.join("project-root.json").is_file());

        let old_tar = base.join("old.tar");
        let old_sum = build_full_airgap_tar(&AirgapFullBuildRequest {
            base: AirgapBuildRequest {
                packs_dir: &packs_dir,
                out: &old_tar,
                bundle_id: "test-airgap",
                version: "0.9.0",
                expires_days: 90,
                halted_releases: &[],
                key_dir: Some(&keys_dir),
                allow_ephemeral_dev_keys: false,
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
        })
        .unwrap();
        let rollback_err = verify_airgap_tar_file(
            &old_tar,
            None,
            None,
            Some(&state_dir),
            Some(&old_sum.manifest_sha256),
            "op-1",
            &[],
            None,
        );
        assert!(matches!(
            rollback_err,
            Err(AirgapCliError::Update(UpdateError::RollbackDetected { .. }))
        ));
        let _ = fs::remove_dir_all(&base);
    }
}
