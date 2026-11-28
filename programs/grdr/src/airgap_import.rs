// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Server air-gap bundle importer: two-half verification, resumable upload to
//! `FilesystemBlobStore`, operator audit logging, and offline freshness vouching.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use grdr_crypto::SigningKeypair;
use grdr_ports::{OrgId, SingleCtx};
use grdr_update::{
    BundleApprovalState, RootMetadata, SignedMetadata, SnapshotMetadata, UpdateError, UpdateTrust,
    canonical_sha256, issue_freshness_vouch, verify_airgap_bundle, verify_root_self,
};
use jiff::Timestamp;

use crate::airgap::airgap_bundle_tuf::load_deployment_signers;
#[allow(unused_imports)]
pub use crate::airgap::airgap_import_ops::{
    ResumableUploadState, ServerImportAuditEntry, UploadSessionStatus,
};
use crate::airgap::airgap_import_ops::{append_audit_entry, stage_and_promote_bundle_blobs};
use crate::airgap::airgap_state::{
    check_and_update_watermarks, load_yanks_for_verify, resolve_and_persist_trust_anchor,
    validate_safe_path_segment, yanks_to_halts,
};
use crate::airgap::{AirgapCliError, inspect_bundle_root};
use crate::airgap_bundle::{PATH_MANIFEST_JSON, root_fingerprint};
use crate::airgap_verify::{
    ParsedTarBundle, extract_verified_artifacts, load_parsed_tar_bundle, read_root_metadata_file,
    verify_extended_bundle_rules, verify_required_bundle_envelope,
};
use crate::fs_safe::{atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular};

#[derive(Debug, Clone, Subcommand)]
pub enum ServerAirgapCommand {
    /// Verify and import an air-gap bundle offline into server blob storage and local image archive.
    Import(ServerAirgapImportArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ServerAirgapImportArgs {
    #[arg(long)]
    pub bundle: PathBuf,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long)]
    pub expected_fingerprint: Option<String>,
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub blob_store_dir: PathBuf,
    #[arg(long, default_value = "airgap-site")]
    pub org_id: String,
    #[arg(long)]
    pub registry_out: Option<PathBuf>,
    #[arg(long)]
    pub installed_base_sha256: Option<String>,
    #[arg(long, default_value_t = false)]
    pub print_root: bool,
    #[arg(long)]
    pub accept_terms: Option<String>,
    #[arg(long, default_value = "airgap-operator")]
    pub operator_id: String,
    #[arg(long)]
    pub yanks_file: Option<PathBuf>,
    #[arg(long)]
    pub deployment_root: Option<PathBuf>,
    #[arg(long)]
    pub deployment_key_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 720)]
    pub valid_hours: i64,
    #[arg(long)]
    pub resume_session: Option<String>,
    #[arg(long, default_value_t = 65_536)]
    pub chunk_bytes: usize,
    #[arg(long)]
    pub interrupt_after_blobs: Option<usize>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn handle_server_airgap_command(cmd: ServerAirgapCommand) -> ExitCode {
    match cmd {
        ServerAirgapCommand::Import(args) => handle_server_airgap_import(args),
    }
}

pub fn handle_server_airgap_import(args: ServerAirgapImportArgs) -> ExitCode {
    if args.print_root {
        return match inspect_bundle_root(&args.bundle, args.root.as_deref()) {
            Ok(report) => {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Project root_fp={} version={} manifest_sha256={} (unverified; pass --accept-terms <sha> to import)",
                        report.root_fingerprint, report.root_version, report.manifest_sha256
                    );
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        };
    }

    match run_server_airgap_import(&args) {
        Ok(audit) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "server.airgap.import",
                        "audit": audit,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!(
                    "Imported bundle {}@{} (blobs={}, resumed_skipped={}, outbound_requests={}) operator={}",
                    audit.bundle_id,
                    audit.bundle_version,
                    audit.imported_blobs,
                    audit.resumed_skipped_blobs,
                    audit.outbound_requests,
                    audit.operator_id
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "server.airgap.import",
                        "ok": false,
                        "error": err.to_string(),
                    })
                );
            } else {
                eprintln!("{err}");
            }
            ExitCode::FAILURE
        }
    }
}

pub fn run_server_airgap_import(
    args: &ServerAirgapImportArgs,
) -> Result<ServerImportAuditEntry, AirgapCliError> {
    let org = OrgId::new(&args.org_id)
        .map_err(|e| AirgapCliError::InvalidInput(format!("invalid --org-id: {e}")))?;
    let ctx = SingleCtx::new(org);
    if let Some(ref sid) = args.resume_session {
        validate_safe_path_segment(sid, "resume_session")?;
    }

    let parsed = load_parsed_tar_bundle(&args.bundle)?;
    let now = Timestamp::now();
    let trusted_root = resolve_and_persist_trust_anchor(
        args.root.as_deref(),
        Some(&args.state_dir),
        args.expected_fingerprint.as_deref(),
        &parsed,
        now,
        false,
    )?;
    let actual_root_fp = root_fingerprint(&trusted_root.signed)?;
    let root_version = trusted_root.signed.version;
    let mut trust = UpdateTrust::new(trusted_root, now)?;

    let accepted_terms_digest = match args.accept_terms.as_deref() {
        None => return Err(UpdateError::TermsNotAccepted.into()),
        Some(accepted) if accepted != parsed.manifest_sha256 => {
            return Err(AirgapCliError::InvalidInput(format!(
                "GRDR-UPD-0010: --accept-terms digest `{accepted}` != bundle manifest `{}`",
                parsed.manifest_sha256
            )));
        }
        Some(accepted) => accepted.to_owned(),
    };
    let approval = BundleApprovalState::TermsAccepted {
        operator_id: args.operator_id.clone(),
        accepted_at: now,
    };

    let dsse_payload = parsed.envelope.decode_payload()?;
    if dsse_payload != parsed.manifest_bytes {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_MANIFEST_JSON.into(),
            detail: "meta/airgap-manifest.json diverges from DSSE payload".into(),
        }
        .into());
    }

    let yanks = load_yanks_for_verify(Some(&args.state_dir), args.yanks_file.as_deref())?;
    let halts = yanks_to_halts(&yanks);
    let outcome = verify_airgap_bundle(
        &trust,
        &parsed.envelope,
        &parsed.artifacts,
        &approval,
        &halts,
        now,
    )?;
    verify_required_bundle_envelope(&parsed, &outcome, &actual_root_fp)?;

    let installed_base =
        resolve_installed_base(args.installed_base_sha256.as_deref(), &args.state_dir);
    verify_extended_bundle_rules(&parsed, &outcome, installed_base.as_deref(), &yanks)?;
    let verified_tuf_snap = verify_embedded_tuf_snapshot(&mut trust, &parsed, now)?;
    let prepared_vouch =
        prepare_freshness_vouch(args, verified_tuf_snap.as_ref(), root_version, now)?;

    check_and_update_watermarks(
        &args.state_dir,
        &outcome,
        root_version,
        parsed.manifest.created_at,
        &parsed.manifest_sha256,
        false,
    )?;

    ensure_safe_dir_all(&args.state_dir, false)
        .map_err(|e| io_err(&args.state_dir, &e.to_string()))?;

    let session_id = match &args.resume_session {
        Some(id) => id.clone(),
        None => {
            let short = parsed
                .manifest_sha256
                .get(..12)
                .unwrap_or(&parsed.manifest_sha256);
            format!("import-{short}")
        }
    };
    let (imported_blobs, resumed_skipped_blobs) = stage_and_promote_bundle_blobs(
        &args.blob_store_dir,
        &args.state_dir,
        &ctx,
        &session_id,
        &outcome.bundle_version,
        &parsed.manifest_sha256,
        &parsed.artifacts,
        args.chunk_bytes,
        args.interrupt_after_blobs,
        now,
    )?;

    let mut registry_images_staged = 0usize;
    if let Some(reg_dir) = &args.registry_out {
        let image_items: Vec<_> = parsed
            .artifacts
            .iter()
            .filter(|a| a.path.starts_with("images/") || a.path.starts_with("charts/"))
            .cloned()
            .collect();
        registry_images_staged = image_items.len();
        extract_verified_artifacts(reg_dir, &image_items)?;
    }

    let freshness_vouch_issued = if let Some(vouch_bytes) = prepared_vouch {
        atomic_write_bytes(
            &args.state_dir.join("freshness-vouch.json"),
            &vouch_bytes,
            false,
        )
        .map_err(|e| io_err(&args.state_dir, &e.to_string()))?;
        true
    } else {
        false
    };

    resolve_and_persist_trust_anchor(
        args.root.as_deref(),
        Some(&args.state_dir),
        args.expected_fingerprint.as_deref(),
        &parsed,
        now,
        true,
    )?;
    check_and_update_watermarks(
        &args.state_dir,
        &outcome,
        root_version,
        parsed.manifest.created_at,
        &parsed.manifest_sha256,
        true,
    )?;

    let audit = ServerImportAuditEntry {
        operator_id: args.operator_id.clone(),
        org_id: args.org_id.clone(),
        bundle_id: outcome.bundle_id,
        bundle_version: outcome.bundle_version,
        manifest_sha256: canonical_sha256(&parsed.manifest_bytes),
        root_fingerprint: actual_root_fp,
        terms_accepted_digest: accepted_terms_digest,
        imported_blobs,
        resumed_skipped_blobs,
        registry_images_staged,
        freshness_vouch_issued,
        outbound_requests: 0,
        imported_at: now,
    };
    append_audit_entry(&args.state_dir.join("airgap-import-audit.jsonl"), &audit)?;
    Ok(audit)
}

fn verify_embedded_tuf_snapshot(
    trust: &mut UpdateTrust,
    parsed: &ParsedTarBundle,
    now: Timestamp,
) -> Result<Option<SignedMetadata<SnapshotMetadata>>, AirgapCliError> {
    let (Some(ts), Some(snap), Some(targets)) = (
        parsed.tuf_timestamp.as_ref(),
        parsed.tuf_snapshot.as_ref(),
        parsed.tuf_targets.as_ref(),
    ) else {
        return Ok(None);
    };
    trust.verify_project_chain(ts, snap, targets, None, None, now)?;
    let desc = targets
        .signed
        .targets
        .get(PATH_MANIFEST_JSON)
        .ok_or_else(|| {
            UpdateError::MalformedMetadata(format!(
                "embedded TUF targets missing `{PATH_MANIFEST_JSON}` descriptor"
            ))
        })?;
    let expected_len = u64::try_from(parsed.manifest_bytes.len()).unwrap_or(u64::MAX);
    if desc.sha256 != parsed.manifest_sha256 || desc.length != expected_len {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_MANIFEST_JSON.into(),
            detail: "embedded TUF targets descriptor diverges from airgap manifest".into(),
        }
        .into());
    }
    Ok(Some(snap.clone()))
}

fn prepare_freshness_vouch(
    args: &ServerAirgapImportArgs,
    verified_tuf_snap: Option<&SignedMetadata<SnapshotMetadata>>,
    root_version: u64,
    now: Timestamp,
) -> Result<Option<Vec<u8>>, AirgapCliError> {
    let (Some(dep_root_path), Some(dep_key_dir)) =
        (&args.deployment_root, &args.deployment_key_dir)
    else {
        return Ok(None);
    };
    let snap = verified_tuf_snap.ok_or_else(|| {
        UpdateError::MalformedMetadata(
            "bundle missing verified TUF timestamp/snapshot/targets chain required for freshness vouch"
                .into(),
        )
    })?;
    let dep_root: SignedMetadata<RootMetadata> = read_root_metadata_file(dep_root_path)?;
    verify_root_self(&dep_root, now)?;
    let fleet_keys = load_deployment_signers(dep_key_dir, &dep_root.signed)?;
    let key_refs: Vec<&SigningKeypair> = fleet_keys.iter().collect();
    let vouch_exp = Timestamp::from_second(
        now.as_second()
            .saturating_add(args.valid_hours.max(1).saturating_mul(3_600)),
    )
    .unwrap_or(now);
    let vouch = issue_freshness_vouch(
        &dep_root.signed,
        &key_refs,
        &args.org_id,
        root_version,
        &snap.signed,
        now,
        now,
        vouch_exp,
    )?;
    let vouch_bytes = serde_json::to_vec_pretty(&vouch)
        .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    Ok(Some(vouch_bytes))
}

fn resolve_installed_base(override_base: Option<&str>, state_dir: &Path) -> Option<String> {
    override_base.map(ToOwned::to_owned).or_else(|| {
        let p = state_dir.join("installed-manifest.sha256");
        p.is_file()
            .then(|| read_bounded_regular(&p, 256).ok())
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.trim().to_owned())
    })
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
