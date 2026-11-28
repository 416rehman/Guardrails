// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance CLI argument definitions and command entrypoint (`docs/design/29`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use grdr_comply::ComplianceArtifactFormat;
use serde::{Deserialize, Serialize};

#[path = "comply_ops.rs"]
mod ops;

#[derive(Debug, Clone, Args, Default)]
pub struct PackSourceArgs {
    #[arg(long)]
    pub(crate) pack_dir: Option<PathBuf>,
    #[arg(long)]
    pub(crate) trust_roots: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct OutputArgs {
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormatArg {
    Bundle,
    OscalComponent,
    OscalAssessment,
    Csv,
    Markdown,
    Soc2,
    CraAnnexI,
    VpatWeb,
    VpatDesktop,
    MonitoringCatalogue,
    Dpia,
    WorksAnnex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyArg {
    Standalone,
    ServerAvailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileArg {
    Standard,
    WorksCouncil,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocaleArg {
    En,
    De,
    Pseudo,
}

#[derive(Debug, Clone, Args)]
pub struct EvidenceArgs {
    #[arg(long, default_value = "standalone-org")]
    pub(crate) organisation: String,
    #[arg(long)]
    pub(crate) capability: Option<String>,
    #[arg(long)]
    pub(crate) audit_log: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub(crate) pipeline_lag: u64,
    #[arg(long, default_value_t = 300)]
    pub(crate) max_lag: u64,
    #[command(flatten)]
    pub(crate) pack: PackSourceArgs,
    #[arg(long)]
    pub(crate) key_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    #[arg(long, value_enum, default_value_t = ExportFormatArg::Bundle)]
    pub(crate) format: ExportFormatArg,
    #[arg(long, default_value = "standalone-org")]
    pub(crate) organisation: String,
    #[arg(long)]
    pub(crate) audit_log: Option<PathBuf>,
    #[arg(long)]
    pub(crate) input: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) pack: PackSourceArgs,
    #[arg(long, default_value_t = false)]
    pub(crate) validate_oscal: bool,
    #[arg(long)]
    pub(crate) key_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub(crate) bundle: PathBuf,
    #[arg(long)]
    pub(crate) fingerprint: String,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RfpArgs {
    #[arg(long, default_value = "0.1.0")]
    pub(crate) version: String,
    #[arg(long, value_enum, default_value_t = TopologyArg::Standalone)]
    pub(crate) topology: TopologyArg,
    #[arg(
        long,
        default_value = "Endpoint local enforcement + signed receipt chain"
    )]
    pub(crate) assurance: String,
    #[arg(long)]
    pub(crate) audit_log: Option<PathBuf>,
    #[arg(long)]
    pub(crate) acceptance_report: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) pack: PackSourceArgs,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct CatalogueArgs {
    #[command(flatten)]
    pub(crate) pack: PackSourceArgs,
    #[arg(long)]
    pub(crate) framework: Option<String>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RopaArgs {
    #[arg(long, default_value = "standalone-org")]
    pub(crate) organisation: String,
    #[arg(long, default_value = "Organisation Controller")]
    pub(crate) controller: String,
    #[arg(long, default_value = "privacy@guardrailshq.com")]
    pub(crate) dpo: String,
    #[arg(long, default_value = "eu-central-1")]
    pub(crate) org_region: String,
    #[arg(long, default_value = "eu-central-1")]
    pub(crate) judge_region: String,
    #[arg(long, default_value = "metadata-only")]
    pub(crate) capture_level: String,
    #[arg(long, value_enum, default_value_t = ProfileArg::WorksCouncil)]
    pub(crate) profile: ProfileArg,
    #[command(flatten)]
    pub(crate) pack: PackSourceArgs,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct NoticeArgs {
    #[arg(long, default_value = "standalone-org")]
    pub(crate) organisation: String,
    #[arg(long, value_enum, default_value_t = LocaleArg::En)]
    pub(crate) locale: LocaleArg,
    #[arg(long, default_value = "metadata-only")]
    pub(crate) capture_level: String,
    #[arg(long, value_enum, default_value_t = ProfileArg::WorksCouncil)]
    pub(crate) profile: ProfileArg,
    #[arg(long, default_value = "privacy@guardrailshq.com")]
    pub(crate) contact: String,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct IncidentArgs {
    #[arg(long, default_value = "inc-001")]
    pub(crate) incident_id: String,
    #[arg(long, default_value = "cra-eu-2024-2847")]
    pub(crate) regime: String,
    #[arg(long, default_value = "Security vulnerability report")]
    pub(crate) summary: String,
    #[arg(long)]
    pub(crate) detected_at: Option<String>,
    #[arg(long)]
    pub(crate) fixed_at: Option<String>,
    #[arg(long)]
    pub(crate) notified_at: Option<String>,
    #[arg(long)]
    pub(crate) materiality_at: Option<String>,
    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

#[derive(Debug, Clone, Args)]
pub struct AuditCryptoArgs {
    #[arg(long, default_value = "Cargo.lock")]
    pub(crate) cargo_lock: PathBuf,
    #[arg(long)]
    pub(crate) export_doc: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ComplyCommand {
    Evidence(EvidenceArgs),
    Export(ExportArgs),
    Verify(VerifyArgs),
    Rfp(RfpArgs),
    Catalogue(CatalogueArgs),
    Ropa(RopaArgs),
    Notice(NoticeArgs),
    IncidentTimeline(IncidentArgs),
    AuditCrypto(AuditCryptoArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComplyCliError {
    #[error("GRDR-COMPLY-0101: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-COMPLY-0102: {0}")]
    Domain(String),
}

impl From<ExportFormatArg> for ComplianceArtifactFormat {
    fn from(arg: ExportFormatArg) -> Self {
        match arg {
            ExportFormatArg::Bundle => Self::Bundle,
            ExportFormatArg::OscalComponent => Self::OscalComponent,
            ExportFormatArg::OscalAssessment => Self::OscalAssessment,
            ExportFormatArg::Csv => Self::Csv,
            ExportFormatArg::Markdown => Self::Markdown,
            ExportFormatArg::Soc2 => Self::Soc2,
            ExportFormatArg::CraAnnexI => Self::CraAnnexI,
            ExportFormatArg::VpatWeb => Self::VpatWeb,
            ExportFormatArg::VpatDesktop => Self::VpatDesktop,
            ExportFormatArg::MonitoringCatalogue => Self::MonitoringCatalogue,
            ExportFormatArg::Dpia => Self::Dpia,
            ExportFormatArg::WorksAnnex => Self::WorksAnnex,
        }
    }
}

pub fn handle_comply_command(cmd: ComplyCommand) -> ExitCode {
    match ops::run_comply(cmd) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comply_evidence::build_local_evidence_items;
    use crate::fs_safe::load_or_create_private_keypair;
    use grdr_comply::{
        EvidenceResult, deployment_fingerprint, extract_workspace_crypto_crates,
        load_compliance_pack_from_dir, load_embedded_compliance_pack,
        validate_oscal_component_json,
    };
    use grdr_core::audit::{GENESIS_PREV_HASH, compute_chain_hash};
    use grdr_model::SigningKeypairExt as _;
    use std::fs;
    use std::path::Path;

    fn test_scratch_dir(tag: &str) -> PathBuf {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| std::env::var_os("HOME"))
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!("{tag}-{}", uuid::Uuid::now_v7().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn offline_evidence_export_verify_and_audit_check_work() {
        let dir = test_scratch_dir("grdr-comply-cli");
        let key_path = dir.join("device.key");
        let bundle_path = dir.join("bundle.json");
        let kp = load_or_create_private_keypair(&key_path).unwrap();
        let fp = deployment_fingerprint(&kp.public_info());
        let loaded = load_embedded_compliance_pack().unwrap();

        let no_log =
            build_local_evidence_items("airgap-org", None, None, 0, 300, &loaded, &kp).unwrap();
        assert!(no_log.iter().all(|i| i.result == EvidenceResult::NotMet));
        assert!(no_log.iter().all(|i| i.pack_digest == loaded.digest_sha256));

        let payload = format!(
            "{{\"event\":\"decision\",\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"receipt_id\":\"rcp_real_01\",\"seq\":0}}"
        );
        let h0 = compute_chain_hash(GENESIS_PREV_HASH, payload.as_bytes());
        let audit_path = dir.join("audit.log.jsonl");
        fs::write(
            &audit_path,
            format!(
                "{{\"event\":\"decision\",\"receipt_id\":\"rcp_real_01\",\"seq\":0,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\"}}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            ops::run_comply(ComplyCommand::Export(ExportArgs {
                format: ExportFormatArg::Bundle,
                organisation: "airgap-org".into(),
                audit_log: Some(audit_path.clone()),
                input: None,
                pack: PackSourceArgs::default(),
                validate_oscal: true,
                key_file: Some(key_path),
                output: OutputArgs {
                    out: Some(bundle_path.clone()),
                    json: true
                },
            }))
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            ops::run_verify(&bundle_path, &fp, true).unwrap(),
            ExitCode::SUCCESS
        );

        fs::write(
            &audit_path,
            b"{\"receipt_id\":\"rcp_bad\",\"prev_hash\":\"bad\",\"entry_hash\":\"bad\"}\n",
        )
        .unwrap();
        assert!(
            build_local_evidence_items("airgap-org", None, Some(&audit_path), 0, 300, &loaded, &kp)
                .is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_pack_dir_tamper_oscal_incident_notice_and_crypto_audit_work() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        let pack_dir = root.join("packs").join("compliance");
        let tmp = test_scratch_dir("grdr-comply-cli-ext");

        let loaded = load_compliance_pack_from_dir(&pack_dir, None).unwrap();
        assert_eq!(
            ops::run_catalogue(
                &PackSourceArgs {
                    pack_dir: Some(pack_dir.clone()),
                    trust_roots: None
                },
                None,
                true
            )
            .unwrap(),
            ExitCode::SUCCESS
        );

        let ev_out = tmp.join("evidence.json");
        assert_eq!(
            ops::run_comply(ComplyCommand::Evidence(EvidenceArgs {
                organisation: "acme-org".into(),
                capability: None,
                audit_log: None,
                pipeline_lag: 0,
                max_lag: 300,
                pack: PackSourceArgs {
                    pack_dir: Some(pack_dir.clone()),
                    trust_roots: None
                },
                key_file: None,
                output: OutputArgs {
                    out: Some(ev_out.clone()),
                    json: true
                },
            }))
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert!(
            fs::read_to_string(&ev_out)
                .unwrap()
                .contains(&loaded.digest_sha256)
        );

        let oscal_out = tmp.join("oscal.json");
        assert_eq!(
            ops::run_comply(ComplyCommand::Export(ExportArgs {
                format: ExportFormatArg::OscalComponent,
                organisation: "acme-org".into(),
                audit_log: None,
                input: None,
                pack: PackSourceArgs {
                    pack_dir: Some(pack_dir),
                    trust_roots: None
                },
                validate_oscal: true,
                key_file: None,
                output: OutputArgs {
                    out: Some(oscal_out.clone()),
                    json: true
                },
            }))
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert!(validate_oscal_component_json(&fs::read_to_string(&oscal_out).unwrap()).is_ok());

        let timeline_out = tmp.join("timeline.json");
        assert_eq!(
            ops::run_comply(ComplyCommand::IncidentTimeline(IncidentArgs {
                incident_id: "inc-99".into(),
                regime: "cra-eu-2024-2847".into(),
                summary: "Test CVE".into(),
                detected_at: Some("2026-10-09T12:00:00Z".into()),
                fixed_at: None,
                notified_at: None,
                materiality_at: None,
                output: OutputArgs {
                    out: Some(timeline_out.clone()),
                    json: true
                },
            }))
            .unwrap(),
            ExitCode::SUCCESS
        );
        let tl_raw = fs::read_to_string(&timeline_out).unwrap();
        assert!(tl_raw.contains("2026-10-10T12:00:00Z"));
        assert!(tl_raw.contains("2026-10-12T12:00:00Z"));

        // Clean approved workspace/third-party Cargo.lock passes with docs/legal/export.md.
        let clean_lock = tmp.join("CleanCargo.lock");
        fs::write(
            &clean_lock,
            "[[package]]\nname = \"grdr-crypto\"\nversion = \"0.1.0\"\ndependencies = [\"ed25519-dalek\", \"chacha20poly1305\", \"sha2\"]\n\n[[package]]\nname = \"rustls\"\nversion = \"0.23.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\n \"aws-lc-rs\",\n]\n",
        )
        .unwrap();
        assert_eq!(
            ops::run_comply(ComplyCommand::AuditCrypto(AuditCryptoArgs {
                cargo_lock: clean_lock,
                export_doc: Some(root.join("docs").join("legal").join("export.md")),
                json: true,
            }))
            .unwrap(),
            ExitCode::SUCCESS
        );

        // Workspace Cargo.lock transitive `ring` (via quinn-proto/rustls-webpki) is caught honestly.
        let repo_lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
        assert!(
            extract_workspace_crypto_crates(&repo_lock)
                .iter()
                .any(|c| c == "ring")
        );
        assert!(
            ops::run_comply(ComplyCommand::AuditCrypto(AuditCryptoArgs {
                cargo_lock: root.join("Cargo.lock"),
                export_doc: Some(root.join("docs").join("legal").join("export.md")),
                json: true,
            }))
            .is_err()
        );

        let bad_lock = tmp.join("Cargo.lock");
        fs::write(
            &bad_lock,
            "[[package]]\nname = \"third-party-client\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\ndependencies = [\"md5\", \"sha-1 0.10.0\"]\n",
        )
        .unwrap();
        assert!(
            ops::run_comply(ComplyCommand::AuditCrypto(AuditCryptoArgs {
                cargo_lock: bad_lock,
                export_doc: None,
                json: true,
            }))
            .is_err()
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
