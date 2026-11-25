// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap CLI commands (`grdr airgap build|verify`) and offline S-31 TUF/DSSE verification.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use grdr_update::{
    AirgapVerificationOutcome, BundleApprovalState, RolloutHaltEntry, UpdateError, UpdateTrust,
    verify_airgap_bundle,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap_bundle::{
    AirgapBuildRequest, PATH_MANIFEST_JSON, build_airgap_tar, root_fingerprint,
};
use crate::airgap_verify::{
    extract_verified_artifacts, load_parsed_tar_bundle, read_root_metadata_file,
    resolve_trust_anchor, verify_required_bundle_envelope,
};

#[derive(Debug, Subcommand)]
pub enum AirgapCommand {
    /// Package signed content packs into an offline OCI-layout / POSIX tar air-gap bundle.
    Build {
        #[arg(long, default_value = "packs")]
        packs_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "grdr-airgap-bundle")]
        bundle_id: String,
        #[arg(long, default_value = "0.1.0")]
        version: String,
        #[arg(long, default_value_t = 365)]
        expires_days: i64,
        #[arg(long = "halt")]
        halts: Vec<String>,
        #[arg(long)]
        key_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        ephemeral_dev_keys: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify an air-gap bundle offline against project TUF/DSSE roots before extraction.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        expected_fingerprint: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        print_root: bool,
        #[arg(long)]
        accept_terms: Option<String>,
        #[arg(long, default_value = "local-operator")]
        operator_id: String,
        #[arg(long = "halt")]
        halts: Vec<String>,
        #[arg(long)]
        extract: Option<PathBuf>,
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
    match run_airgap(cmd) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run_airgap(cmd: AirgapCommand) -> Result<ExitCode, AirgapCliError> {
    match cmd {
        AirgapCommand::Build {
            packs_dir,
            out,
            bundle_id,
            version,
            expires_days,
            halts,
            key_dir,
            ephemeral_dev_keys,
            json,
        } => {
            let halted = parse_halts(&halts)?;
            let summary = build_airgap_tar(&AirgapBuildRequest {
                packs_dir: &packs_dir,
                out: &out,
                bundle_id: &bundle_id,
                version: &version,
                expires_days,
                halted_releases: &halted,
                key_dir: key_dir.as_deref(),
                allow_ephemeral_dev_keys: ephemeral_dev_keys,
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary)
                        .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?
                );
            } else {
                println!(
                    "Built {}@{} ({} entries) -> {} (root_fp={} manifest_sha256={})",
                    summary.bundle_id,
                    summary.bundle_version,
                    summary.entries_count,
                    summary.out,
                    summary.root_fingerprint,
                    summary.manifest_sha256
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        AirgapCommand::Verify {
            bundle,
            root,
            expected_fingerprint,
            state_dir,
            print_root,
            accept_terms,
            operator_id,
            halts,
            extract,
            json,
        } => {
            if print_root {
                let report = inspect_bundle_root(&bundle, root.as_deref())?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report)
                            .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?
                    );
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
            let halted = parse_halts(&halts)?;
            let res = verify_airgap_tar_file(
                &bundle,
                root.as_deref(),
                expected_fingerprint.as_deref(),
                state_dir.as_deref(),
                accept_terms.as_deref(),
                &operator_id,
                &halted,
                extract.as_deref(),
            );
            print_verify_result(res, json)
        }
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
    let parsed = load_parsed_tar_bundle(bundle_path)?;
    let trusted_root =
        resolve_trust_anchor(override_root, state_dir, expected_fingerprint, &parsed)?;
    let actual_root_fp = root_fingerprint(&trusted_root.signed)?;
    if let Some(expected_fp) = expected_fingerprint
        && actual_root_fp != expected_fp
    {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "project root fingerprint `{actual_root_fp}` != expected `{expected_fp}`"
        ))
        .into());
    }

    let now = Timestamp::now();
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

    let outcome = verify_airgap_bundle(
        &trust,
        &parsed.envelope,
        &parsed.artifacts,
        &approval,
        external_halts,
        now,
    )?;

    verify_required_bundle_envelope(&parsed, &outcome, &actual_root_fp)?;

    if let Some(dest) = extract_dir {
        extract_verified_artifacts(dest, &parsed.artifacts)?;
    }
    Ok((outcome, parsed.manifest_sha256))
}

fn print_verify_result(
    res: Result<(AirgapVerificationOutcome, String), AirgapCliError>,
    json: bool,
) -> Result<ExitCode, AirgapCliError> {
    match res {
        Ok((verified, manifest_sha)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "airgap.verify",
                        "verified": true,
                        "manifest_sha256": manifest_sha,
                        "outcome": verified,
                    })
                );
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
                println!(
                    "{}",
                    serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "airgap.verify",
                        "verified": false,
                        "error": err.to_string(),
                    })
                );
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let summary = build_airgap_tar(&AirgapBuildRequest {
            packs_dir: &packs_dir,
            out: &tar_path,
            bundle_id: "test-airgap",
            version: "1.0.0",
            expires_days: 90,
            halted_releases: &[],
            key_dir: Some(&keys_dir),
            allow_ephemeral_dev_keys: false,
        })
        .unwrap();
        assert_eq!(summary.entries_count, 4);

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

        let wrong_fp = verify_airgap_tar_file(
            &tar_path,
            None,
            Some("fp_wrong"),
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

        let extract_dir = base.join("out-packs");
        let (ok, _) = verify_airgap_tar_file(
            &tar_path,
            None,
            Some(&summary.root_fingerprint),
            None,
            Some(&summary.manifest_sha256),
            "op-1",
            &[],
            Some(&extract_dir),
        )
        .unwrap();
        assert_eq!(ok.verified_entries, 4);
        assert!(extract_dir.join("packs/essentials/pack.toml").is_file());
        let _ = fs::remove_dir_all(&base);
    }
}
