// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance evidence, OSCAL export, offline bundle verification, and RFP commands (`docs/design/29`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use grdr_comply::{
    EvidenceItem, OfflineEvidenceBundle, default_registry, deployment_fingerprint,
    export_assessment_results, export_component_definition, export_evidence_csv,
    export_evidence_markdown, export_offline_bundle, generate_rfp_response, render_rfp_markdown,
    verify_evidence_bundle,
};
use grdr_crypto::SigningKeypair;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::comply_evidence::{build_local_evidence_items, build_platform_readiness};
use crate::fs_safe::{atomic_write_bytes, load_or_create_private_keypair, read_bounded_utf8};

const MAX_COMPLY_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormatArg {
    Bundle,
    OscalComponent,
    OscalAssessment,
    Csv,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyArg {
    Standalone,
    ServerAvailable,
}

#[derive(Debug, Subcommand)]
pub enum ComplyCommand {
    /// Evaluate compliance capability evidence items from verified local audit metadata.
    Evidence {
        #[arg(long, default_value = "standalone-org")]
        organisation: String,
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        pipeline_lag: u64,
        #[arg(long, default_value_t = 300)]
        max_lag: u64,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Export OSCAL 1.2.3 component/assessment documents, CSV/Markdown, or signed offline bundle.
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormatArg::Bundle)]
        format: ExportFormatArg,
        #[arg(long, default_value = "standalone-org")]
        organisation: String,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify a signed offline compliance evidence bundle against an attested root fingerprint.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Generate a buyer RFP T1-T17 readiness parity report.
    Rfp {
        #[arg(long, default_value = "0.1.0")]
        version: String,
        #[arg(long, value_enum, default_value_t = TopologyArg::Standalone)]
        topology: TopologyArg,
        #[arg(
            long,
            default_value = "Endpoint local enforcement + signed receipt chain"
        )]
        assurance: String,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long)]
        acceptance_report: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceOutputEnvelope {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "type")]
    kind: String,
    deployment_fingerprint: String,
    items: Vec<EvidenceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComplyCliError {
    #[error("GRDR-COMPLY-0101: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-COMPLY-0102: {0}")]
    Domain(String),
}

pub fn handle_comply_command(cmd: ComplyCommand) -> ExitCode {
    match run_comply(cmd) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run_comply(cmd: ComplyCommand) -> Result<ExitCode, ComplyCliError> {
    match cmd {
        ComplyCommand::Evidence {
            organisation,
            capability,
            audit_log,
            pipeline_lag,
            max_lag,
            key_file,
            out,
            json,
        } => {
            let keypair = resolve_keypair(key_file.as_deref())?;
            let fp = deployment_fingerprint(&keypair.public_info());
            let items = build_local_evidence_items(
                &organisation,
                capability.as_deref(),
                audit_log.as_deref(),
                pipeline_lag,
                max_lag,
                &keypair,
            )?;
            let env = EvidenceOutputEnvelope {
                api_version: "grdr.cli.v1alpha1".into(),
                kind: "comply.evidence".into(),
                deployment_fingerprint: fp.clone(),
                items: items.clone(),
            };
            if let Some(dest) = out.as_deref() {
                let s = serde_json::to_string_pretty(&env).map_err(ser_err)?;
                write_text_file(dest, &s)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&env).map_err(ser_err)?);
            } else {
                println!(
                    "Compliance evidence evaluated ({} item(s), fp={fp}):",
                    items.len()
                );
                for item in &items {
                    println!("  - {} [{}] {:?}", item.capability, item.id, item.result);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        ComplyCommand::Export {
            format,
            organisation,
            audit_log,
            input,
            key_file,
            out,
            json,
        } => run_export(
            format,
            &organisation,
            audit_log.as_deref(),
            input.as_deref(),
            key_file.as_deref(),
            out.as_deref(),
            json,
        ),
        ComplyCommand::Verify {
            bundle,
            fingerprint,
            json,
        } => run_verify(&bundle, &fingerprint, json),
        ComplyCommand::Rfp {
            version,
            topology,
            assurance,
            audit_log,
            acceptance_report,
            out,
            json,
        } => run_rfp(
            &version,
            topology,
            &assurance,
            audit_log.as_deref(),
            acceptance_report.as_deref(),
            out.as_deref(),
            json,
        ),
    }
}

fn run_export(
    format: ExportFormatArg,
    organisation: &str,
    audit_log: Option<&Path>,
    input: Option<&Path>,
    key_file: Option<&Path>,
    out: Option<&Path>,
    json: bool,
) -> Result<ExitCode, ComplyCliError> {
    let keypair = resolve_keypair(key_file)?;
    let now = Timestamp::now();
    let registry = default_registry();
    let items = if let Some(src) = input {
        load_evidence_items(src)?
    } else {
        build_local_evidence_items(organisation, None, audit_log, 0, 300, &keypair)?
    };

    let rendered = match format {
        ExportFormatArg::OscalComponent => serde_json::to_string_pretty(
            &export_component_definition(&registry, "Guardrails ADR", "0.1.0", now),
        )
        .map_err(ser_err)?,
        ExportFormatArg::OscalAssessment => serde_json::to_string_pretty(
            &export_assessment_results(organisation, &items, now).map_err(dom_err)?,
        )
        .map_err(ser_err)?,
        ExportFormatArg::Csv => export_evidence_csv(&items),
        ExportFormatArg::Markdown => export_evidence_markdown(organisation, &items),
        ExportFormatArg::Bundle => serde_json::to_string_pretty(
            &export_offline_bundle(&keypair, organisation, &items, now).map_err(dom_err)?,
        )
        .map_err(ser_err)?,
    };

    if let Some(dest) = out {
        write_text_file(dest, &rendered)?;
    }

    if json && matches!(format, ExportFormatArg::Csv | ExportFormatArg::Markdown) {
        let doc = serde_json::json!({
            "apiVersion": "grdr.cli.v1alpha1",
            "type": "comply.export",
            "format": format,
            "deployment_fingerprint": deployment_fingerprint(&keypair.public_info()),
            "bytes": rendered.len(),
            "out": out.map(|p| p.display().to_string()),
            "content": rendered,
        });
        println!("{doc}");
    } else if out.is_none() || json {
        println!("{rendered}");
    } else if let Some(dest) = out {
        println!(
            "Exported {:?} compliance artefact to {} (fp={})",
            format,
            dest.display(),
            deployment_fingerprint(&keypair.public_info())
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_verify(
    bundle_path: &Path,
    fingerprint: &str,
    json: bool,
) -> Result<ExitCode, ComplyCliError> {
    let raw = read_bounded_text(bundle_path)?;
    let bundle: OfflineEvidenceBundle = serde_json::from_str(&raw).map_err(dom_err)?;
    match verify_evidence_bundle(&bundle, fingerprint) {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "comply.verify",
                        "verified": true,
                        "report": report,
                    })
                );
            } else {
                println!(
                    "Verified offline evidence bundle: items={} oscal={} fingerprint={}",
                    report.verified_items, report.oscal_version, report.deployment_fingerprint
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
                        "type": "comply.verify",
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

fn run_rfp(
    version: &str,
    topology: TopologyArg,
    assurance: &str,
    audit_log: Option<&Path>,
    acceptance_report: Option<&Path>,
    out: Option<&Path>,
    json: bool,
) -> Result<ExitCode, ComplyCliError> {
    let readiness =
        build_platform_readiness(version, topology, assurance, audit_log, acceptance_report)?;
    let report = generate_rfp_response(&readiness);
    let markdown = render_rfp_markdown(&report);
    if let Some(dest) = out {
        let body = if json {
            serde_json::to_string_pretty(&report).map_err(ser_err)?
        } else {
            markdown.clone()
        };
        write_text_file(dest, &body)?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(ser_err)?
        );
    } else if out.is_none() {
        println!("{markdown}");
    } else if let Some(dest) = out {
        println!("Wrote buyer RFP parity report to {}", dest.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn load_evidence_items(src: &Path) -> Result<Vec<EvidenceItem>, ComplyCliError> {
    let text = read_bounded_text(src)?;
    if let Ok(env) = serde_json::from_str::<EvidenceOutputEnvelope>(&text) {
        return Ok(env.items);
    }
    serde_json::from_str::<Vec<EvidenceItem>>(&text).map_err(dom_err)
}

fn resolve_keypair(path: Option<&Path>) -> Result<SigningKeypair, ComplyCliError> {
    match path {
        Some(key_path) => load_or_create_private_keypair(key_path).map_err(dom_err),
        None => SigningKeypair::generate().map_err(dom_err),
    }
}

fn ser_err(err: serde_json::Error) -> ComplyCliError {
    ComplyCliError::Domain(err.to_string())
}

fn dom_err(err: impl ToString) -> ComplyCliError {
    ComplyCliError::Domain(err.to_string())
}

fn read_bounded_text(path: &Path) -> Result<String, ComplyCliError> {
    read_bounded_utf8(path, MAX_COMPLY_INPUT_BYTES).map_err(|e| ComplyCliError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

fn write_text_file(dest: &Path, content: &str) -> Result<(), ComplyCliError> {
    atomic_write_bytes(dest, content.as_bytes(), false).map_err(|e| ComplyCliError::Io {
        path: dest.display().to_string(),
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_comply::EvidenceResult;
    use grdr_core::audit::{GENESIS_PREV_HASH, compute_chain_hash};
    use std::fs;

    #[test]
    fn offline_evidence_export_verify_and_audit_check_work() {
        let dir =
            std::env::temp_dir().join(format!("grdr-comply-cli-{}", uuid::Uuid::now_v7().simple()));
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("device.key");
        let bundle_path = dir.join("bundle.json");
        let kp = load_or_create_private_keypair(&key_path).unwrap();
        let fp = deployment_fingerprint(&kp.public_info());

        // Without an audit log, honest evidence reports NotMet (never synthetic 100%).
        let no_log = build_local_evidence_items("airgap-org", None, None, 0, 300, &kp).unwrap();
        assert!(no_log.iter().all(|i| i.result == EvidenceResult::NotMet));

        // With a valid signed hash-chained audit log, evidence verifies and reports Met.
        let payload = format!(
            "{{\"event\":\"decision\",\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"receipt_id\":\"rcp_real_01\",\"seq\":0}}"
        );
        let h0 = compute_chain_hash(GENESIS_PREV_HASH, payload.as_bytes());
        let audit_path = dir.join("audit.log.jsonl");
        fs::write(
            &audit_path,
            format!("{{\"event\":\"decision\",\"receipt_id\":\"rcp_real_01\",\"seq\":0,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\"}}\n"),
        )
        .unwrap();

        assert_eq!(
            run_export(
                ExportFormatArg::Bundle,
                "airgap-org",
                Some(&audit_path),
                None,
                Some(&key_path),
                Some(&bundle_path),
                true,
            )
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_verify(&bundle_path, &fp, true).unwrap(),
            ExitCode::SUCCESS
        );

        // Tampered audit log fails closed.
        fs::write(
            &audit_path,
            b"{\"receipt_id\":\"rcp_bad\",\"prev_hash\":\"bad\",\"entry_hash\":\"bad\"}\n",
        )
        .unwrap();
        assert!(
            build_local_evidence_items("airgap-org", None, Some(&audit_path), 0, 300, &kp).is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
