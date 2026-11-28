// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline `grdr verify-artefact` Sigstore/SLSA v1, TUF chain, and platform attestation verifier.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use grdr_update::{
    RootMetadata, SignedMetadata, SigstoreTrustedRoot, TargetsMetadata, UpdateError, UpdateTrust,
    canonical_sha256,
};
use jiff::Timestamp;

use crate::airgap::AirgapCliError;
pub use crate::airgap::verify_artefact_binding::VerifyArtefactTufInputs;
use crate::airgap::verify_artefact_binding::{
    MAX_META_JSON_BYTES, read_file_bounded, read_json_meta, resolve_platform_sig_status,
    verify_release_manifest_binding, verify_tuf_targets_chain,
};
use crate::airgap::verify_artefact_sigstore::{
    VerifyArtefactPolicy, decode_and_verify_slsa_dsse, verify_fulcio_certificate,
    verify_rekor_inclusion, verify_signed_timestamp,
};
use crate::airgap::verify_artefact_types::{
    ArtefactVerificationReport, DEFAULT_GITHUB_BUILDER, DEFAULT_SLSA_BUILD_TYPE,
    OfflineSigstoreBundle, PlatformSignatureStatus,
};

const MAX_ARTEFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Args)]
pub struct VerifyArtefactCliArgs {
    #[arg(long)]
    pub artefact: PathBuf,
    #[arg(long)]
    pub bundle: PathBuf,
    #[arg(long)]
    pub trusted_root: PathBuf,
    #[arg(long)]
    pub release_manifest: Option<PathBuf>,
    #[arg(long)]
    pub release_manifest_dsse: Option<PathBuf>,
    #[arg(long)]
    pub tuf_root: Option<PathBuf>,
    #[arg(long)]
    pub tuf_timestamp: Option<PathBuf>,
    #[arg(long)]
    pub tuf_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub tuf_targets: Option<PathBuf>,
    #[arg(long)]
    pub deployment_root: Option<PathBuf>,
    #[arg(long)]
    pub tuf_freshness: Option<PathBuf>,
    #[arg(long)]
    pub tuf_state_dir: Option<PathBuf>,
    #[arg(long)]
    pub platform_sig: Option<PathBuf>,
    #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
    pub expected_issuer: String,
    #[arg(long, default_value = "416rehman/Guardrails")]
    pub expected_repository: String,
    #[arg(long, default_value = ".github/workflows/release.yml")]
    pub expected_workflow: String,
    #[arg(long, default_value = "refs/tags/v")]
    pub expected_ref_prefix: String,
    #[arg(long, default_value = DEFAULT_GITHUB_BUILDER)]
    pub expected_builder: String,
    #[arg(long, default_value = DEFAULT_SLSA_BUILD_TYPE)]
    pub expected_build_type: String,
    #[arg(long, default_value_t = false)]
    pub require_platform_signature: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn handle_verify_artefact_args(args: VerifyArtefactCliArgs) -> ExitCode {
    let policy = VerifyArtefactPolicy {
        expected_issuer: &args.expected_issuer,
        expected_repository: &args.expected_repository,
        expected_workflow: &args.expected_workflow,
        expected_ref_prefix: &args.expected_ref_prefix,
        expected_builder: &args.expected_builder,
        expected_build_type: &args.expected_build_type,
        require_platform_signature: args.require_platform_signature,
    };
    let tuf_inputs = VerifyArtefactTufInputs {
        tuf_root: args.tuf_root.as_deref(),
        tuf_timestamp: args.tuf_timestamp.as_deref(),
        tuf_snapshot: args.tuf_snapshot.as_deref(),
        tuf_targets: args.tuf_targets.as_deref(),
        deployment_root: args.deployment_root.as_deref(),
        tuf_freshness: args.tuf_freshness.as_deref(),
        tuf_state_dir: args.tuf_state_dir.as_deref(),
        release_manifest_dsse: args.release_manifest_dsse.as_deref(),
    };
    match verify_artefact_offline_with_tuf(
        &args.artefact,
        &args.bundle,
        &args.trusted_root,
        args.release_manifest.as_deref(),
        &tuf_inputs,
        args.platform_sig.as_deref(),
        &policy,
    ) {
        Ok(report) => {
            if args.json {
                match serde_json::to_string_pretty(&serde_json::json!({
                    "apiVersion": "grdr.cli.v1alpha1",
                    "type": "verify.artefact",
                    "report": report,
                })) {
                    Ok(txt) => println!("{txt}"),
                    Err(e) => {
                        eprintln!("GRDR-AIRGAP-0002: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "Verified offline artefact {} (sha256={}, workflow={}@{}, platform_sig={})",
                    report.artefact_path,
                    report.artefact_sha256,
                    report.workflow_path,
                    report.source_ref,
                    platform_status_label(report.platform_signature_status)
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
                        "type": "verify.artefact",
                        "verified": false,
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

pub fn verify_artefact_offline(
    artefact_path: &Path,
    bundle_path: &Path,
    trusted_root_path: &Path,
    release_manifest_path: Option<&Path>,
    tuf_targets_path: Option<&Path>,
    platform_sig_path: Option<&Path>,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<ArtefactVerificationReport, AirgapCliError> {
    let tuf_inputs = VerifyArtefactTufInputs {
        tuf_targets: tuf_targets_path,
        ..VerifyArtefactTufInputs::default()
    };
    verify_artefact_offline_with_tuf(
        artefact_path,
        bundle_path,
        trusted_root_path,
        release_manifest_path,
        &tuf_inputs,
        platform_sig_path,
        policy,
    )
}

pub fn verify_artefact_offline_with_tuf(
    artefact_path: &Path,
    bundle_path: &Path,
    trusted_root_path: &Path,
    release_manifest_path: Option<&Path>,
    tuf: &VerifyArtefactTufInputs<'_>,
    platform_sig_path: Option<&Path>,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<ArtefactVerificationReport, AirgapCliError> {
    let artefact_bytes = read_file_bounded(artefact_path, MAX_ARTEFACT_BYTES)?;
    let artefact_sha256 = canonical_sha256(&artefact_bytes);

    let tr_raw = read_file_bounded(trusted_root_path, MAX_META_JSON_BYTES)?;
    let trusted_root_sha256 = canonical_sha256(&tr_raw);
    let trusted_root: SigstoreTrustedRoot = serde_json::from_slice(&tr_raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid trusted_root.json: {e}")))?;
    let bundle: OfflineSigstoreBundle = read_json_meta(bundle_path, "Sigstore bundle")?;
    if !bundle
        .media_type
        .starts_with("application/vnd.dev.sigstore.bundle+json")
    {
        return Err(UpdateError::MalformedMetadata(format!(
            "unsupported Sigstore bundle mediaType `{}`",
            bundle.media_type
        ))
        .into());
    }

    let now = Timestamp::now();
    let verified_ts = verify_signed_timestamp(&bundle, &trusted_root, &artefact_sha256)?;
    verify_fulcio_certificate(&bundle, &trusted_root, verified_ts, policy)?;
    let (stmt, dsse_payload_sha256) =
        decode_and_verify_slsa_dsse(&bundle, &artefact_sha256, policy)?;
    verify_rekor_inclusion(
        &bundle,
        &trusted_root,
        &artefact_sha256,
        &dsse_payload_sha256,
        verified_ts,
    )?;

    let tuf_root_info = match tuf.tuf_root {
        Some(p) => {
            let raw = read_file_bounded(p, MAX_META_JSON_BYTES)?;
            let sha = canonical_sha256(&raw);
            let meta: SignedMetadata<RootMetadata> = serde_json::from_slice(&raw)
                .map_err(|e| UpdateError::MalformedMetadata(format!("invalid TUF root: {e}")))?;
            let _ = UpdateTrust::new(meta.clone(), now)?;
            Some((meta, sha))
        }
        None => None,
    };
    let verified_tuf_root = tuf_root_info.as_ref().map(|(m, _)| m);
    let tuf_root_sha256 = tuf_root_info.as_ref().map(|(_, s)| s.as_str());
    let verified_targets: Option<SignedMetadata<TargetsMetadata>> = tuf
        .tuf_targets
        .map(|p| verify_tuf_targets_chain(p, tuf, &artefact_bytes, &artefact_sha256, now))
        .transpose()?;

    if let Some(manifest_path) = release_manifest_path {
        verify_release_manifest_binding(
            manifest_path,
            tuf.release_manifest_dsse,
            verified_tuf_root,
            tuf_root_sha256,
            verified_targets.as_ref(),
            &trusted_root,
            &trusted_root_sha256,
            policy,
            &artefact_sha256,
            now,
        )?;
    }

    let platform_signature_status = resolve_platform_sig_status(
        platform_sig_path,
        &artefact_sha256,
        &trusted_root,
        verified_tuf_root,
        policy,
        now,
    )?;
    if policy.require_platform_signature
        && platform_signature_status != PlatformSignatureStatus::Verified
    {
        return Err(UpdateError::InvalidSignature(format!(
            "platform signature required but status is `{}`",
            platform_status_label(platform_signature_status)
        ))
        .into());
    }

    Ok(ArtefactVerificationReport {
        verified: true,
        artefact_path: artefact_path.display().to_string(),
        artefact_sha256,
        verified_at_signed_timestamp: verified_ts,
        oidc_issuer: bundle.verification_material.certificate.issuer,
        repository: stmt
            .predicate
            .build_definition
            .external_parameters
            .workflow
            .repository,
        workflow_path: stmt
            .predicate
            .build_definition
            .external_parameters
            .workflow
            .workflow_path,
        source_ref: stmt
            .predicate
            .build_definition
            .external_parameters
            .workflow
            .source_ref,
        builder_id: stmt.predicate.run_details.builder.id,
        platform_signature_status,
        offline_mode: true,
    })
}

const fn platform_status_label(status: PlatformSignatureStatus) -> &'static str {
    match status {
        PlatformSignatureStatus::Verified => "verified",
        PlatformSignatureStatus::AuthenticodeChainUntrusted => "authenticode-chain-untrusted",
        PlatformSignatureStatus::NotPlatformSigned => "not platform-signed",
        PlatformSignatureStatus::Invalid => "invalid",
    }
}
