// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! CLI argument structs and dispatch formatting helpers for `grdr airgap build|verify`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use grdr_update::{AirgapVerificationOutcome, RolloutHaltEntry, YankReason, YankRecord};
use jiff::Timestamp;
use serde::Serialize;

use crate::airgap::{AirgapCliError, inspect_bundle_root, verify_airgap_tar_with_base};
use crate::airgap_bundle::{
    AirgapBuildRequest, AirgapBuildSummary, AirgapFullBuildRequest, build_full_airgap_tar,
};

#[derive(Debug, Clone, Args)]
pub struct AirgapBuildArgs {
    #[arg(long, default_value = "packs")]
    pub packs_dir: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, default_value = "grdr-airgap-bundle")]
    pub bundle_id: String,
    #[arg(long, default_value = "0.1.0")]
    pub version: String,
    #[arg(long, default_value_t = 365)]
    pub expires_days: i64,
    #[arg(long = "halt")]
    pub halts: Vec<String>,
    #[arg(long)]
    pub key_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub ephemeral_dev_keys: bool,
    #[arg(long)]
    pub binaries_dir: Option<PathBuf>,
    #[arg(long)]
    pub images_dir: Option<PathBuf>,
    #[arg(long)]
    pub charts_dir: Option<PathBuf>,
    #[arg(long)]
    pub apt_dir: Option<PathBuf>,
    #[arg(long)]
    pub rpm_dir: Option<PathBuf>,
    #[arg(long)]
    pub docs_dir: Option<PathBuf>,
    #[arg(long)]
    pub terraform_dir: Option<PathBuf>,
    #[arg(long)]
    pub models_dir: Option<PathBuf>,
    #[arg(long)]
    pub csaf_dir: Option<PathBuf>,
    #[arg(long)]
    pub sources_dir: Option<PathBuf>,
    #[arg(long)]
    pub sbom: Option<PathBuf>,
    #[arg(long)]
    pub vex: Option<PathBuf>,
    #[arg(long)]
    pub dependencies_lock: Option<PathBuf>,
    #[arg(long)]
    pub release_manifest: Option<PathBuf>,
    #[arg(long)]
    pub trusted_root: Option<PathBuf>,
    #[arg(long)]
    pub rollout_json: Option<PathBuf>,
    #[arg(long = "platform")]
    pub platforms: Vec<String>,
    #[arg(long)]
    pub delta_from_version: Option<String>,
    #[arg(long)]
    pub delta_from_sha256: Option<String>,
    #[arg(long)]
    pub minimum_base_version: Option<String>,
    #[arg(long = "yank")]
    pub yanks: Vec<String>,
    #[arg(long)]
    pub split_bytes: Option<u64>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AirgapVerifyArgs {
    #[arg(long)]
    pub bundle: PathBuf,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long)]
    pub expected_fingerprint: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub installed_base_sha256: Option<String>,
    #[arg(long, default_value_t = false)]
    pub print_root: bool,
    #[arg(long)]
    pub accept_terms: Option<String>,
    #[arg(long, default_value = "local-operator")]
    pub operator_id: String,
    #[arg(long = "halt")]
    pub halts: Vec<String>,
    #[arg(long)]
    pub yanks_file: Option<PathBuf>,
    #[arg(long)]
    pub extract: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn handle_build_args(args: &AirgapBuildArgs) -> Result<ExitCode, AirgapCliError> {
    let halted = parse_halts(&args.halts)?;
    let parsed_yanks = parse_yanks(&args.yanks)?;
    let summary = build_full_airgap_tar(&AirgapFullBuildRequest {
        base: AirgapBuildRequest {
            packs_dir: &args.packs_dir,
            out: &args.out,
            bundle_id: &args.bundle_id,
            version: &args.version,
            expires_days: args.expires_days,
            halted_releases: &halted,
            key_dir: args.key_dir.as_deref(),
            allow_ephemeral_dev_keys: args.ephemeral_dev_keys,
        },
        binaries_dir: args.binaries_dir.as_deref(),
        images_dir: args.images_dir.as_deref(),
        charts_dir: args.charts_dir.as_deref(),
        apt_dir: args.apt_dir.as_deref(),
        rpm_dir: args.rpm_dir.as_deref(),
        docs_dir: args.docs_dir.as_deref(),
        terraform_dir: args.terraform_dir.as_deref(),
        models_dir: args.models_dir.as_deref(),
        csaf_dir: args.csaf_dir.as_deref(),
        sources_dir: args.sources_dir.as_deref(),
        sbom_path: args.sbom.as_deref(),
        vex_path: args.vex.as_deref(),
        dependencies_lock_path: args.dependencies_lock.as_deref(),
        release_manifest_path: args.release_manifest.as_deref(),
        trusted_root_path: args.trusted_root.as_deref(),
        rollout_path: args.rollout_json.as_deref(),
        platforms: &args.platforms,
        delta_from_version: args.delta_from_version.as_deref(),
        delta_from_manifest_sha256: args.delta_from_sha256.as_deref(),
        minimum_base_version: args.minimum_base_version.as_deref(),
        yanked_releases: &parsed_yanks,
        split_bytes: args.split_bytes,
    })?;
    emit_build_summary(&summary, args.json)
}

pub fn handle_verify_args(args: &AirgapVerifyArgs) -> Result<ExitCode, AirgapCliError> {
    if args.print_root {
        let report = inspect_bundle_root(&args.bundle, args.root.as_deref())?;
        if args.json {
            print_json_pretty(&report)?;
        } else {
            println!(
                "Project root_fp={} version={} expires={} manifest_sha256={} (unverified; confirm out-of-band)",
                report.root_fingerprint,
                report.root_version,
                report.root_expires,
                report.manifest_sha256
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    let halted = parse_halts(&args.halts)?;
    let res = verify_airgap_tar_with_base(
        &args.bundle,
        args.root.as_deref(),
        args.expected_fingerprint.as_deref(),
        args.state_dir.as_deref(),
        args.installed_base_sha256.as_deref(),
        args.accept_terms.as_deref(),
        &args.operator_id,
        &halted,
        args.yanks_file.as_deref(),
        args.extract.as_deref(),
    );
    print_verify_result(res, args.json)
}

pub fn print_json_pretty<T: Serialize>(value: &T) -> Result<(), AirgapCliError> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?
    );
    Ok(())
}

fn emit_build_summary(
    summary: &AirgapBuildSummary,
    json: bool,
) -> Result<ExitCode, AirgapCliError> {
    if json {
        print_json_pretty(summary)?;
    } else {
        println!(
            "Built {}@{} ({} entries, parts={}) -> {} (root_fp={} manifest_sha256={})",
            summary.bundle_id,
            summary.bundle_version,
            summary.entries_count,
            summary.parts_count,
            summary.out,
            summary.root_fingerprint,
            summary.manifest_sha256
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn print_verify_result(
    res: Result<(AirgapVerificationOutcome, String), AirgapCliError>,
    json: bool,
) -> Result<ExitCode, AirgapCliError> {
    match res {
        Ok((verified, manifest_sha)) => {
            if json {
                print_json_pretty(&serde_json::json!({
                    "apiVersion": "grdr.cli.v1alpha1",
                    "type": "airgap.verify",
                    "verified": true,
                    "manifest_sha256": manifest_sha,
                    "outcome": verified,
                }))?;
            } else {
                println!(
                    "Verified air-gap bundle {}@{} ({} entries, operator={})",
                    verified.bundle_id,
                    verified.bundle_version,
                    verified.verified_entries,
                    verified.operator_id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            if json {
                print_json_pretty(&serde_json::json!({
                    "apiVersion": "grdr.cli.v1alpha1",
                    "type": "airgap.verify",
                    "verified": false,
                    "error": err.to_string(),
                }))?;
            } else {
                eprintln!("{err}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn parse_halts(raw: &[String]) -> Result<Vec<RolloutHaltEntry>, AirgapCliError> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let Some((pack_and_ver, reason)) = item.split_once(':') else {
            return Err(AirgapCliError::InvalidInput(format!(
                "halt `{item}` must be `<pack>@<ver>:<reason>`"
            )));
        };
        let Some((pack_id, version)) = pack_and_ver.split_once('@') else {
            return Err(AirgapCliError::InvalidInput(format!(
                "halt `{item}` missing `@<ver>`"
            )));
        };
        out.push(RolloutHaltEntry {
            pack_id: pack_id.to_owned(),
            version: version.to_owned(),
            reason: reason.to_owned(),
        });
    }
    Ok(out)
}

fn parse_yanks(raw: &[String]) -> Result<Vec<YankRecord>, AirgapCliError> {
    let now = Timestamp::now();
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let Some((pack_and_ver, sha)) = item.split_once(':') else {
            return Err(AirgapCliError::InvalidInput(format!(
                "yank `{item}` must be `<pack>@<ver>:<sha256>`"
            )));
        };
        let Some((pack_id, version)) = pack_and_ver.split_once('@') else {
            return Err(AirgapCliError::InvalidInput(format!(
                "yank `{item}` missing `@<ver>`"
            )));
        };
        out.push(YankRecord {
            pack_id: pack_id.to_owned(),
            version: version.to_owned(),
            sha256: sha.to_owned(),
            reason: YankReason::Compromised,
            issued_at: now,
            replacement_version: None,
            replacement_sha256: None,
        });
    }
    Ok(out)
}
