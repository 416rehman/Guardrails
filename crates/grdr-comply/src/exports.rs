// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Unified compliance artifact exporter shared by CLI and server workflows (`docs/design/29`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_crypto::SigningKeypair;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::evidence::{EvidenceItem, EvidenceResult};
use crate::incident::{
    IncidentFixtureInput, export_incident_timeline, render_incident_timeline_markdown,
};
use crate::markdown_safe;
use crate::oscal::{export_assessment_results, export_component_definition, export_offline_bundle};
use crate::oscal_validate::{validate_oscal_assessment_json, validate_oscal_component_json};
use crate::pack_loader::LoadedCompliancePack;
use crate::privacy_docs::{
    NoticeLocale, PrivacyDocConfig, RuleCatalogSummary, generate_impact_assessment_pack,
    generate_monitoring_catalogue, generate_worker_notice, generate_works_agreement_annex,
    render_worker_notice_markdown,
};
use crate::privacy_floor::{CaptureLevel, NoticeChangeState, schedule_capture_change};
use crate::regulatory::{
    VpatSurface, generate_cra_annex_i_matrix, generate_soc2_readiness_pack, generate_vpat_report,
    render_vpat_markdown,
};
use crate::retention::{
    PrivacyCeilingProfile, RetentionPolicy, RetentionPreset, RetentionProposal,
    resolve_retention_policy,
};
use crate::rfp::{PlatformReadiness, generate_rfp_response_with_registry, render_rfp_markdown};
use crate::subject_request::{ErasureLegalBasis, RopaInput, generate_ropa, render_ropa_markdown};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceArtifactFormat {
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

pub const DEFAULT_PRIVACY_CONTACT: &str = "privacy@guardrailshq.com";

pub fn default_privacy_doc_config(
    organisation: &str,
    profile: PrivacyCeilingProfile,
    capture_level: &str,
    contact: &str,
    now: Timestamp,
) -> Result<PrivacyDocConfig, ComplyError> {
    let policy = resolve_default_retention(organisation, profile)?;
    let sched = schedule_capture_change(
        profile,
        CaptureLevel::MetadataOnly,
        CaptureLevel::MetadataAndSignals,
        now,
    )?;
    let effective_change_notice = match sched.schedule {
        NoticeChangeState::Scheduled { notice_days, .. } => {
            format!("{notice_days} days advance notice")
        }
        NoticeChangeState::Immediate => "immediate".into(),
    };
    Ok(PrivacyDocConfig {
        organisation: organisation.to_owned(),
        profile,
        capture_level: capture_level.to_owned(),
        retention_summary: format!(
            "{}d activity / {}d audit / {}d max backup age-out",
            policy.activity_days, policy.audit_days, policy.backup_days_max
        ),
        exclusions: Vec::new(),
        reader_roles: vec![(
            "privacy-officer".into(),
            1,
            "dual-quorum + audit.access".into(),
        )],
        privacy_contact: contact.to_owned(),
        co_approver_group: BTreeSet::new(),
        effective_change_notice,
        is_annex_iii_deployer: true,
        recipients: vec!["security-reviewers".into()],
        generated_at: now,
    })
}

pub fn resolve_default_retention(
    organisation: &str,
    profile: PrivacyCeilingProfile,
) -> Result<RetentionPolicy, ComplyError> {
    let mut legal = BTreeMap::new();
    legal.insert(
        RetentionPreset::Default,
        "Legitimate security interest".into(),
    );
    resolve_retention_policy(&RetentionProposal {
        organisation: organisation.to_owned(),
        presets: vec![RetentionPreset::Default],
        ceiling_profile: profile,
        legal_basis: legal,
        override_legal_basis: None,
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    })
}

pub fn render_compliance_artifact(
    format: ComplianceArtifactFormat,
    organisation: &str,
    loaded: &LoadedCompliancePack,
    items: &[EvidenceItem],
    keypair: &SigningKeypair,
    validate_oscal: bool,
    now: Timestamp,
) -> Result<String, ComplyError> {
    let reg = &loaded.registry;
    let doc_cfg = default_privacy_doc_config(
        organisation,
        PrivacyCeilingProfile::WorksCouncil,
        "metadata-only",
        DEFAULT_PRIVACY_CONTACT,
        now,
    )?;
    match format {
        ComplianceArtifactFormat::OscalComponent => {
            let doc =
                export_component_definition(reg, "Guardrails ADR", &loaded.manifest.version, now);
            let s = serde_json::to_string_pretty(&doc).map_err(ser_err)?;
            if validate_oscal {
                validate_oscal_component_json(&s)?;
            }
            Ok(s)
        }
        ComplianceArtifactFormat::OscalAssessment => {
            let doc = export_assessment_results(organisation, items, now)?;
            let s = serde_json::to_string_pretty(&doc).map_err(ser_err)?;
            if validate_oscal {
                validate_oscal_assessment_json(&s)?;
            }
            Ok(s)
        }
        ComplianceArtifactFormat::Csv => Ok(export_evidence_csv(items)),
        ComplianceArtifactFormat::Markdown => Ok(export_evidence_markdown(organisation, items)),
        ComplianceArtifactFormat::Bundle => {
            serde_json::to_string_pretty(&export_offline_bundle(keypair, organisation, items, now)?)
                .map_err(ser_err)
        }
        ComplianceArtifactFormat::Soc2 => {
            serde_json::to_string_pretty(&generate_soc2_readiness_pack(reg)?).map_err(ser_err)
        }
        ComplianceArtifactFormat::CraAnnexI => {
            serde_json::to_string_pretty(&generate_cra_annex_i_matrix(reg)?).map_err(ser_err)
        }
        ComplianceArtifactFormat::VpatWeb => {
            let rep = generate_vpat_report(
                VpatSurface::WebConsole,
                &loaded.manifest.version,
                &BTreeMap::new(),
                now,
            )?;
            Ok(render_vpat_markdown(&rep))
        }
        ComplianceArtifactFormat::VpatDesktop => {
            let rep = generate_vpat_report(
                VpatSurface::RuneDesktop,
                &loaded.manifest.version,
                &BTreeMap::new(),
                now,
            )?;
            Ok(render_vpat_markdown(&rep))
        }
        ComplianceArtifactFormat::MonitoringCatalogue => {
            let cat = generate_monitoring_catalogue(
                &doc_cfg,
                Vec::<RuleCatalogSummary>::new(),
                Vec::new(),
            )?;
            serde_json::to_string_pretty(&cat).map_err(ser_err)
        }
        ComplianceArtifactFormat::Dpia => {
            serde_json::to_string_pretty(&generate_impact_assessment_pack(&doc_cfg)?)
                .map_err(ser_err)
        }
        ComplianceArtifactFormat::WorksAnnex => {
            serde_json::to_string_pretty(&generate_works_agreement_annex(&doc_cfg)?)
                .map_err(ser_err)
        }
    }
}

fn ser_err(err: serde_json::Error) -> ComplyError {
    ComplyError::Serialization {
        detail: err.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render_ropa_output(
    organisation: String,
    controller_name: String,
    dpo_contact: String,
    org_region: String,
    judge_region: String,
    capture_level: String,
    profile: PrivacyCeilingProfile,
    loaded: &LoadedCompliancePack,
    json: bool,
    now: Timestamp,
) -> Result<String, ComplyError> {
    let policy = resolve_default_retention(&organisation, profile)?;
    let doc = generate_ropa(
        &RopaInput {
            organisation,
            controller_name,
            dpo_contact,
            org_region,
            judge_region,
            capture_level,
            data_categories: vec!["pseudonymous-session-metadata".into()],
            recipients: vec!["security-reviewers".into()],
            subprocessors: vec!["optional-model-judge".into()],
            residual_erasure_basis: ErasureLegalBasis::Art17_3bLegalObligation,
            generated_at: now,
        },
        &policy,
        &loaded.registry,
    )?;
    if json {
        serde_json::to_string_pretty(&doc).map_err(ser_err)
    } else {
        Ok(render_ropa_markdown(&doc))
    }
}

pub fn render_notice_output(
    organisation: &str,
    locale: NoticeLocale,
    capture_level: &str,
    profile: PrivacyCeilingProfile,
    contact: &str,
    json: bool,
    now: Timestamp,
) -> Result<String, ComplyError> {
    let cfg = default_privacy_doc_config(organisation, profile, capture_level, contact, now)?;
    let doc = generate_worker_notice(&cfg, locale)?;
    if json {
        serde_json::to_string_pretty(&doc).map_err(ser_err)
    } else {
        Ok(render_worker_notice_markdown(&doc))
    }
}

pub fn render_incident_output(
    input: &IncidentFixtureInput,
    json: bool,
) -> Result<String, ComplyError> {
    let report = export_incident_timeline(input)?;
    if json {
        serde_json::to_string_pretty(&report).map_err(ser_err)
    } else {
        Ok(render_incident_timeline_markdown(&report))
    }
}

pub fn render_rfp_output(
    loaded: &LoadedCompliancePack,
    readiness: &PlatformReadiness,
    json: bool,
) -> Result<String, ComplyError> {
    let report = generate_rfp_response_with_registry(&loaded.registry, readiness, None)?;
    if json {
        serde_json::to_string_pretty(&report).map_err(ser_err)
    } else {
        Ok(render_rfp_markdown(&report))
    }
}

pub fn export_evidence_csv(items: &[EvidenceItem]) -> String {
    let mut out = String::from(
        "item_id,organisation,capability,result,period_start,period_end,sample_count,controls\n",
    );
    for item in items {
        let result_label = match item.result {
            EvidenceResult::Met => "met",
            EvidenceResult::Partial => "partial",
            EvidenceResult::NotMet => "not-met",
            EvidenceResult::NotEvaluable => "not-evaluable",
        };
        let line = format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"\n",
            csv_safe(&item.id),
            csv_safe(&item.organisation),
            csv_safe(&item.capability),
            csv_safe(result_label),
            item.period_start,
            item.period_end,
            item.sample_ids.len(),
            csv_safe(&item.control_refs.join(";"))
        );
        out.push_str(&line);
    }
    out
}

pub fn export_evidence_markdown(organisation: &str, items: &[EvidenceItem]) -> String {
    let mut out = format!(
        "# Compliance Evidence Report ({})\n\n| Item | Capability | Result | Samples | Controls |\n|---|---|---|---|---|\n",
        markdown_safe(organisation)
    );
    for item in items {
        out.push_str(&format!(
            "| `{}` | `{}` | `{:?}` | {} | {} |\n",
            markdown_safe(&item.id),
            markdown_safe(&item.capability),
            item.result,
            item.sample_ids.len(),
            markdown_safe(&item.control_refs.join(", "))
        ));
    }
    out
}

fn csv_safe(raw: &str) -> String {
    let single_line = raw.replace(['\n', '\r'], " ");
    let trimmed = single_line.trim_start();
    let formula_prefix =
        single_line.starts_with('\t') || trimmed.starts_with(['=', '+', '-', '@', '\t']);
    let neutralized = if formula_prefix {
        format!("'{single_line}")
    } else {
        single_line
    };
    neutralized.replace('"', "\"\"")
}
