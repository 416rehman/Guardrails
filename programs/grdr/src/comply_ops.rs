// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance subcommand execution handlers (`grdr comply`).

use std::path::Path;
use std::process::ExitCode;

use grdr_comply::{
    EvidenceItem, IncidentFixtureInput, LoadedCompliancePack, NoticeLocale, OfflineEvidenceBundle,
    PrivacyCeilingProfile, deployment_fingerprint, load_compliance_pack_from_dir,
    load_embedded_compliance_pack, render_compliance_artifact, render_incident_output,
    render_notice_output, render_rfp_output, render_ropa_output, verify_cargo_lock_crypto,
    verify_evidence_bundle,
};
use grdr_crypto::SigningKeypair;
use grdr_model::SigningKeypairExt as _;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::comply::{
    ComplyCliError, ComplyCommand, EvidenceArgs, ExportArgs, LocaleArg, PackSourceArgs, ProfileArg,
};
use crate::comply_evidence::{build_local_evidence_items, build_platform_readiness};
use crate::fs_safe::{atomic_write_bytes, load_or_create_private_keypair, read_bounded_utf8};

const MAX_COMPLY_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceOutputEnvelope {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "type")]
    kind: String,
    deployment_fingerprint: String,
    items: Vec<EvidenceItem>,
}

pub(crate) fn run_comply(cmd: ComplyCommand) -> Result<ExitCode, ComplyCliError> {
    match cmd {
        ComplyCommand::Evidence(a) => run_evidence(a),
        ComplyCommand::Export(a) => run_export(a),
        ComplyCommand::Verify(a) => run_verify(&a.bundle, &a.fingerprint, a.json),
        ComplyCommand::Rfp(a) => {
            let loaded = resolve_pack(&a.pack)?;
            let readiness = build_platform_readiness(
                &a.version,
                a.topology,
                &a.assurance,
                a.audit_log.as_deref(),
                a.acceptance_report.as_deref(),
            )?;
            let body = render_rfp_output(&loaded, &readiness, a.output.json).map_err(dom_err)?;
            write_or_print(a.output.out.as_deref(), &body, "buyer RFP parity report")
        }
        ComplyCommand::Catalogue(a) => run_catalogue(&a.pack, a.framework.as_deref(), a.json),
        ComplyCommand::Ropa(a) => {
            let loaded = resolve_pack(&a.pack)?;
            let prof = map_profile(a.profile);
            let body = render_ropa_output(
                a.organisation,
                a.controller,
                a.dpo,
                a.org_region,
                a.judge_region,
                a.capture_level,
                prof,
                &loaded,
                a.output.json,
                Timestamp::now(),
            )
            .map_err(dom_err)?;
            write_or_print(a.output.out.as_deref(), &body, "GDPR Art. 30 RoPA")
        }
        ComplyCommand::Notice(a) => {
            let prof = map_profile(a.profile);
            let loc = match a.locale {
                LocaleArg::En => NoticeLocale::En,
                LocaleArg::De => NoticeLocale::De,
                LocaleArg::Pseudo => NoticeLocale::Pseudo,
            };
            let body = render_notice_output(
                &a.organisation,
                loc,
                &a.capture_level,
                prof,
                &a.contact,
                a.output.json,
                Timestamp::now(),
            )
            .map_err(dom_err)?;
            write_or_print(a.output.out.as_deref(), &body, "monitored person notice")
        }
        ComplyCommand::IncidentTimeline(a) => {
            let detected = parse_opt_ts(a.detected_at.as_deref())?.unwrap_or_else(Timestamp::now);
            let input = IncidentFixtureInput {
                incident_id: a.incident_id,
                regime_id: a.regime,
                summary: a.summary,
                detected_at: detected,
                fixed_at: parse_opt_ts(a.fixed_at.as_deref())?,
                notified_at: parse_opt_ts(a.notified_at.as_deref())?,
                materiality_determined_at: parse_opt_ts(a.materiality_at.as_deref())?,
            };
            let body = render_incident_output(&input, a.output.json).map_err(dom_err)?;
            write_or_print(a.output.out.as_deref(), &body, "incident timeline")
        }
        ComplyCommand::AuditCrypto(a) => {
            let lock_text = read_bounded_text(&a.cargo_lock)?;
            let export_text = a.export_doc.as_deref().map(read_bounded_text).transpose()?;
            let report =
                verify_cargo_lock_crypto(&lock_text, export_text.as_deref()).map_err(dom_err)?;
            if a.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(dom_err)?
                );
            } else {
                println!(
                    "Crypto allow-list verified ({} approved entries)",
                    report.approved_crates.len()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn map_profile(p: ProfileArg) -> PrivacyCeilingProfile {
    match p {
        ProfileArg::Standard => PrivacyCeilingProfile::Standard,
        ProfileArg::WorksCouncil => PrivacyCeilingProfile::WorksCouncil,
    }
}

fn run_evidence(a: EvidenceArgs) -> Result<ExitCode, ComplyCliError> {
    let loaded = resolve_pack(&a.pack)?;
    if let Some(cap) = a.capability.as_deref()
        && !loaded.registry.capabilities.contains_key(cap)
    {
        return Err(ComplyCliError::Domain(format!(
            "capability `{cap}` not found in pack `{}`",
            loaded.manifest.id
        )));
    }
    let keypair = resolve_keypair(a.key_file.as_deref())?;
    let fp = deployment_fingerprint(&keypair.public_info());
    let items = build_local_evidence_items(
        &a.organisation,
        a.capability.as_deref(),
        a.audit_log.as_deref(),
        a.pipeline_lag,
        a.max_lag,
        &loaded,
        &keypair,
    )?;
    let env = EvidenceOutputEnvelope {
        api_version: "grdr.cli.v1alpha1".into(),
        kind: "comply.evidence".into(),
        deployment_fingerprint: fp.clone(),
        items: items.clone(),
    };
    let s = serde_json::to_string_pretty(&env).map_err(dom_err)?;
    if let Some(dest) = a.output.out.as_deref() {
        write_text_file(dest, &s)?;
    }
    if a.output.json {
        println!("{s}");
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

fn run_export(a: ExportArgs) -> Result<ExitCode, ComplyCliError> {
    let loaded = resolve_pack(&a.pack)?;
    let keypair = resolve_keypair(a.key_file.as_deref())?;
    let items = match a.input.as_deref() {
        Some(src) => load_evidence_items(src)?,
        None => build_local_evidence_items(
            &a.organisation,
            None,
            a.audit_log.as_deref(),
            0,
            300,
            &loaded,
            &keypair,
        )?,
    };
    let rendered = render_compliance_artifact(
        a.format.into(),
        &a.organisation,
        &loaded,
        &items,
        &keypair,
        a.validate_oscal,
        Timestamp::now(),
    )
    .map_err(dom_err)?;
    if let Some(dest) = a.output.out.as_deref() {
        write_text_file(dest, &rendered)?;
    }
    if a.output.json && !rendered.trim_start().starts_with('{') {
        println!(
            "{}",
            serde_json::json!({ "apiVersion": "grdr.cli.v1alpha1", "type": "comply.export", "format": format!("{:?}", a.format), "deployment_fingerprint": deployment_fingerprint(&keypair.public_info()), "bytes": rendered.len(), "content": rendered })
        );
    } else if a.output.out.is_none() || a.output.json {
        println!("{rendered}");
    } else if let Some(dest) = a.output.out.as_deref() {
        println!(
            "Exported {:?} compliance artefact to {} (fp={})",
            a.format,
            dest.display(),
            deployment_fingerprint(&keypair.public_info())
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_catalogue(
    pack: &PackSourceArgs,
    framework: Option<&str>,
    json: bool,
) -> Result<ExitCode, ComplyCliError> {
    let loaded = resolve_pack(pack)?;
    let cov = framework
        .map(|fw| loaded.registry.framework_coverage(fw))
        .transpose()
        .map_err(dom_err)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "pack_id": loaded.manifest.id, "version": loaded.manifest.version, "digest_sha256": loaded.digest_sha256, "signer_ref": loaded.signer_ref, "capabilities": loaded.registry.capabilities.len(), "frameworks": loaded.registry.frameworks.keys().collect::<Vec<_>>(), "framework_coverage": cov })
        );
    } else {
        println!(
            "Verified pack {}@{} (sha256={}): {} capabilities, {} frameworks",
            loaded.manifest.id,
            loaded.manifest.version,
            loaded.digest_sha256,
            loaded.registry.capabilities.len(),
            loaded.registry.frameworks.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_verify(
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
                    serde_json::json!({ "apiVersion": "grdr.cli.v1alpha1", "type": "comply.verify", "verified": true, "report": report })
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
                    serde_json::json!({ "apiVersion": "grdr.cli.v1alpha1", "type": "comply.verify", "verified": false, "error": err.to_string() })
                );
            } else {
                eprintln!("{err}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn resolve_pack(args: &PackSourceArgs) -> Result<LoadedCompliancePack, ComplyCliError> {
    match args.pack_dir.as_deref() {
        Some(dir) => {
            load_compliance_pack_from_dir(dir, args.trust_roots.as_deref()).map_err(dom_err)
        }
        None => load_embedded_compliance_pack().map_err(dom_err),
    }
}

fn write_or_print(out: Option<&Path>, body: &str, label: &str) -> Result<ExitCode, ComplyCliError> {
    if let Some(dest) = out {
        write_text_file(dest, body)?;
        println!("Wrote {label} to {}", dest.display());
    } else {
        println!("{body}");
    }
    Ok(ExitCode::SUCCESS)
}

fn load_evidence_items(src: &Path) -> Result<Vec<EvidenceItem>, ComplyCliError> {
    let text = read_bounded_text(src)?;
    serde_json::from_str::<EvidenceOutputEnvelope>(&text)
        .map(|env| env.items)
        .or_else(|_| serde_json::from_str::<Vec<EvidenceItem>>(&text).map_err(dom_err))
}

fn resolve_keypair(path: Option<&Path>) -> Result<SigningKeypair, ComplyCliError> {
    match path {
        Some(key_path) => load_or_create_private_keypair(key_path).map_err(dom_err),
        None => SigningKeypair::generate().map_err(dom_err),
    }
}

fn parse_opt_ts(raw: Option<&str>) -> Result<Option<Timestamp>, ComplyCliError> {
    raw.map(|s| s.trim().parse::<Timestamp>().map_err(dom_err))
        .transpose()
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
