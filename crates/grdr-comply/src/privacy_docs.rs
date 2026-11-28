// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Auto-generated privacy documents, localization (`en`/`de`/`pseudo`), and privacy pack diff gate.

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceDataClass;
use crate::pack_loader::{load_yaml_checked, yaml_req_bool, yaml_req_seq, yaml_req_str};
use crate::retention::PrivacyCeilingProfile;
use crate::{ComplyError, markdown_safe};

const EMBEDDED_PRIVACY_TEMPLATES_YAML: &str = include_str!("../data/privacy-templates.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeLocale {
    En,
    De,
    Pseudo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPromotionVerdict {
    AutoPromoted,
    BlockedAwaitingAcknowledgement,
    ApprovedByQuorum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFieldReadSpec {
    pub field_path: String,
    pub data_class: EvidenceDataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCatalogSummary {
    pub pack_id: String,
    pub rule_id: String,
    pub rule_sentence: String,
    pub reads: Vec<PackFieldReadSpec>,
    pub outputs: Vec<String>,
    pub reader_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyDocConfig {
    pub organisation: String,
    pub profile: PrivacyCeilingProfile,
    pub capture_level: String,
    pub retention_summary: String,
    pub exclusions: Vec<String>,
    pub reader_roles: Vec<(String, usize, String)>,
    pub privacy_contact: String,
    pub co_approver_group: BTreeSet<String>,
    pub effective_change_notice: String,
    pub is_annex_iii_deployer: bool,
    pub recipients: Vec<String>,
    pub generated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringCatalogueDoc {
    pub schema: String,
    pub organisation: String,
    pub user_risk_scoring_enabled: bool,
    pub never_collected_telemetry: Vec<String>,
    pub rules: Vec<RuleCatalogSummary>,
    pub retention_summary: String,
    pub diff_history: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerNoticeDoc {
    pub schema: String,
    pub locale: NoticeLocale,
    pub organisation: String,
    pub title: String,
    pub protection_line: String,
    pub collected_summary: String,
    pub never_collected: String,
    pub content_access_rule: String,
    pub retention_and_exclusions: String,
    pub privacy_contact: String,
    pub contest_and_dsar: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiaRiskItem {
    pub id: String,
    pub title: String,
    pub mitigation: String,
    pub residual: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactAssessmentPackDoc {
    pub schema: String,
    pub organisation: String,
    pub gdpr_article: String,
    pub system_description: String,
    pub data_flows: Vec<String>,
    pub recipients: Vec<String>,
    pub technical_measures: String,
    pub risks: Vec<DpiaRiskItem>,
    pub controller_prompts: Vec<String>,
    pub fria_appendix_applicable: bool,
    pub fria_appendix_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NationalVariantTemplate {
    pub id: String,
    pub country: String,
    pub statute: String,
    pub requires_local_counsel_review: bool,
    pub clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorksAgreementAnnexDoc {
    pub schema: String,
    pub organisation: String,
    pub en_title: String,
    pub de_title: String,
    pub en_prohibited_evaluations: String,
    pub de_prohibited_evaluations: String,
    pub en_quorum_clause: String,
    pub de_quorum_clause: String,
    pub en_expert_access: String,
    pub de_expert_access: String,
    pub retention_and_notice_clause: String,
    pub national_variants: Vec<NationalVariantTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPackDiffReport {
    pub privacy_relevant: bool,
    pub added_or_elevated_fields: Vec<String>,
    pub verdict: PackPromotionVerdict,
    pub missing_acknowledgements: Vec<String>,
}

#[derive(Debug, Clone)]
struct LocaleStrings {
    notice_title: String,
    status_prefix: String,
    never_collected_statement: String,
    content_access_rule: String,
    contest_instructions: String,
    works_annex_title: String,
    works_annex_prohibited: String,
    works_annex_quorum: String,
    works_annex_expert: String,
}

#[derive(Debug, Clone)]
struct PrivacyTemplatesBundle {
    never_collected: Vec<String>,
    dpia_risks: Vec<DpiaRiskItem>,
    locales: BTreeMap<String, LocaleStrings>,
    national_variants: Vec<NationalVariantTemplate>,
}

pub fn assess_privacy_pack_promotion(
    profile: PrivacyCeilingProfile,
    current_reads: &[PackFieldReadSpec],
    candidate_reads: &[PackFieldReadSpec],
    privacy_officer_ack: Option<&str>,
    co_approver_ack: Option<&str>,
    co_approver_group: &BTreeSet<String>,
) -> PrivacyPackDiffReport {
    let mut current_max: BTreeMap<&str, EvidenceDataClass> = BTreeMap::new();
    for r in current_reads {
        current_max
            .entry(r.field_path.as_str())
            .and_modify(|existing| {
                if r.data_class > *existing {
                    *existing = r.data_class;
                }
            })
            .or_insert(r.data_class);
    }

    let mut changed = Vec::new();
    for cand in candidate_reads {
        match current_max.get(cand.field_path.as_str()) {
            None => changed.push(format!(
                "{}:{:?} (new field)",
                cand.field_path, cand.data_class
            )),
            Some(prev) if cand.data_class > *prev => changed.push(format!(
                "{}:{:?}->{:?} (class elevated)",
                cand.field_path, prev, cand.data_class
            )),
            _ => {}
        }
    }
    let privacy_relevant = !changed.is_empty();
    if !privacy_relevant {
        return PrivacyPackDiffReport {
            privacy_relevant: false,
            added_or_elevated_fields: Vec::new(),
            verdict: PackPromotionVerdict::AutoPromoted,
            missing_acknowledgements: Vec::new(),
        };
    }

    let mut missing = Vec::new();
    let po_norm = privacy_officer_ack
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase);
    if po_norm.is_none() {
        missing.push("privacy_officer".to_owned());
    }
    if profile == PrivacyCeilingProfile::WorksCouncil {
        let norm_group: BTreeSet<String> = co_approver_group
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| !m.is_empty())
            .collect();
        let co_valid = !norm_group.is_empty()
            && co_approver_ack
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .is_some_and(|co| norm_group.contains(&co) && Some(co) != po_norm);
        if !co_valid {
            missing.push("co_approver_group_member".to_owned());
        }
    }

    let verdict = if missing.is_empty() {
        PackPromotionVerdict::ApprovedByQuorum
    } else {
        PackPromotionVerdict::BlockedAwaitingAcknowledgement
    };

    PrivacyPackDiffReport {
        privacy_relevant: true,
        added_or_elevated_fields: changed,
        verdict,
        missing_acknowledgements: missing,
    }
}

pub fn generate_monitoring_catalogue(
    cfg: &PrivacyDocConfig,
    rules: Vec<RuleCatalogSummary>,
    diff_history: Vec<String>,
) -> Result<MonitoringCatalogueDoc, ComplyError> {
    let tpl = load_templates(EMBEDDED_PRIVACY_TEMPLATES_YAML)?;
    Ok(MonitoringCatalogueDoc {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: cfg.organisation.clone(),
        user_risk_scoring_enabled: cfg.profile != PrivacyCeilingProfile::WorksCouncil,
        never_collected_telemetry: tpl.never_collected,
        rules,
        retention_summary: cfg.retention_summary.clone(),
        diff_history,
    })
}

pub fn generate_worker_notice(
    cfg: &PrivacyDocConfig,
    locale: NoticeLocale,
) -> Result<WorkerNoticeDoc, ComplyError> {
    let tpl = load_templates(EMBEDDED_PRIVACY_TEMPLATES_YAML)?;
    let key = match locale {
        NoticeLocale::En => "en",
        NoticeLocale::De => "de",
        NoticeLocale::Pseudo => "pseudo",
    };
    let strings = tpl
        .locales
        .get(key)
        .ok_or_else(|| ComplyError::Serialization {
            detail: format!("missing locale `{key}` in privacy-templates.yaml"),
        })?;
    let readers_summary: Vec<String> = cfg
        .reader_roles
        .iter()
        .map(|(role, count, cond)| format!("{role} ({count} accounts; {cond})"))
        .collect();
    let excls = if cfg.exclusions.is_empty() {
        "none".to_owned()
    } else {
        cfg.exclusions.join(", ")
    };

    Ok(WorkerNoticeDoc {
        schema: "grdr.comply.v1alpha1".into(),
        locale,
        organisation: cfg.organisation.clone(),
        title: strings.notice_title.clone(),
        protection_line: format!(
            "{}: {:?} | capture={} | {}",
            strings.status_prefix, cfg.profile, cfg.capture_level, cfg.effective_change_notice
        ),
        collected_summary: format!(
            "Capture level `{}` over agent tool invocations; authorized readers: {}",
            cfg.capture_level,
            if readers_summary.is_empty() {
                "none configured".to_owned()
            } else {
                readers_summary.join("; ")
            }
        ),
        never_collected: strings.never_collected_statement.clone(),
        content_access_rule: strings.content_access_rule.clone(),
        retention_and_exclusions: format!(
            "Retention: {} | Exclusions: {}",
            cfg.retention_summary, excls
        ),
        privacy_contact: cfg.privacy_contact.clone(),
        contest_and_dsar: strings.contest_instructions.clone(),
    })
}

pub fn generate_impact_assessment_pack(
    cfg: &PrivacyDocConfig,
) -> Result<ImpactAssessmentPackDoc, ComplyError> {
    let tpl = load_templates(EMBEDDED_PRIVACY_TEMPLATES_YAML)?;
    let fria_note = if cfg.is_annex_iii_deployer {
        "EU AI Act Art. 27 Fundamental Rights Impact Assessment (FRIA) applies: assess affected worker groups, governance controls, and human-oversight remedies before deployment.".to_owned()
    } else {
        "FRIA (EU AI Act Art. 27) not triggered for non-Annex III developer-tool security deployment; review if scope changes.".to_owned()
    };
    Ok(ImpactAssessmentPackDoc {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: cfg.organisation.clone(),
        gdpr_article: "GDPR Art. 35(7)".into(),
        system_description: format!(
            "Guardrails ADR policy evaluation and containment for {} under {:?} profile (capture={}).",
            cfg.organisation, cfg.profile, cfg.capture_level
        ),
        data_flows: vec![
            "Endpoint sensor/hook emits structural/derived event with device pseudonym".into(),
            "Identity boundary re-pseudonymizes principal ID under server-held HMAC key".into(),
            "Encrypted object/archive store isolates session content under per-session DEKs".into(),
        ],
        recipients: cfg.recipients.clone(),
        technical_measures:
            "Ed25519 receipt signatures, ChaCha20-Poly1305 encrypted lake segments, dual-approver holds, SR-26 strict narrowing"
                .into(),
        risks: tpl.dpia_risks,
        controller_prompts: vec![
            "Confirm necessity and proportionality of enabled policy packs against workplace purpose.".into(),
            "Confirm whether deployment falls within EU AI Act Annex III high-risk use.".into(),
        ],
        fria_appendix_applicable: cfg.is_annex_iii_deployer,
        fria_appendix_note: fria_note,
    })
}

pub fn generate_works_agreement_annex(
    cfg: &PrivacyDocConfig,
) -> Result<WorksAgreementAnnexDoc, ComplyError> {
    let tpl = load_templates(EMBEDDED_PRIVACY_TEMPLATES_YAML)?;
    let en = tpl
        .locales
        .get("en")
        .ok_or_else(|| ComplyError::Serialization {
            detail: "missing `en` locale in privacy-templates.yaml".into(),
        })?;
    let de = tpl
        .locales
        .get("de")
        .ok_or_else(|| ComplyError::Serialization {
            detail: "missing `de` locale in privacy-templates.yaml".into(),
        })?;
    Ok(WorksAgreementAnnexDoc {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: cfg.organisation.clone(),
        en_title: en.works_annex_title.clone(),
        de_title: de.works_annex_title.clone(),
        en_prohibited_evaluations: en.works_annex_prohibited.clone(),
        de_prohibited_evaluations: de.works_annex_prohibited.clone(),
        en_quorum_clause: en.works_annex_quorum.clone(),
        de_quorum_clause: de.works_annex_quorum.clone(),
        en_expert_access: en.works_annex_expert.clone(),
        de_expert_access: de.works_annex_expert.clone(),
        retention_and_notice_clause: format!(
            "Retention: {} | Capture raise notice period: 14 days (works-council) / 7 days (standard).",
            cfg.retention_summary
        ),
        national_variants: tpl.national_variants,
    })
}

pub fn render_worker_notice_markdown(notice: &WorkerNoticeDoc) -> String {
    format!(
        "# {} ({})\n\n- **Status:** {}\n- **Collected:** {}\n- **Never collected:** {}\n- **Content access:** {}\n- **Retention & exclusions:** {}\n- **Privacy contact:** {}\n- **Redress / DSAR:** {}\n",
        markdown_safe(&notice.title),
        markdown_safe(&notice.organisation),
        markdown_safe(&notice.protection_line),
        markdown_safe(&notice.collected_summary),
        markdown_safe(&notice.never_collected),
        markdown_safe(&notice.content_access_rule),
        markdown_safe(&notice.retention_and_exclusions),
        markdown_safe(&notice.privacy_contact),
        markdown_safe(&notice.contest_and_dsar),
    )
}

fn load_templates(raw: &str) -> Result<PrivacyTemplatesBundle, ComplyError> {
    let doc = load_yaml_checked(raw, "privacy-templates.yaml")?;
    let mut never_collected = Vec::new();
    for item in yaml_req_seq(&doc, "never_collected_telemetry", "privacy-templates.yaml")? {
        if let Some(s) = item.as_str() {
            never_collected.push(s.to_owned());
        }
    }

    let mut dpia_risks = Vec::new();
    for node in yaml_req_seq(&doc, "dpia_default_risks", "privacy-templates.yaml")? {
        let id = yaml_req_str(node, "id", "dpia_default_risks")?.to_owned();
        dpia_risks.push(DpiaRiskItem {
            id: id.clone(),
            title: yaml_req_str(node, "title", &id)?.to_owned(),
            mitigation: yaml_req_str(node, "mitigation", &id)?.to_owned(),
            residual: yaml_req_str(node, "residual", &id)?.to_owned(),
        });
    }

    let mut locales = BTreeMap::new();
    for node in yaml_req_seq(&doc, "locales", "privacy-templates.yaml")? {
        let code = yaml_req_str(node, "code", "locales")?.to_owned();
        locales.insert(
            code.clone(),
            LocaleStrings {
                notice_title: yaml_req_str(node, "notice_title", &code)?.to_owned(),
                status_prefix: yaml_req_str(node, "status_prefix", &code)?.to_owned(),
                never_collected_statement: yaml_req_str(node, "never_collected_statement", &code)?
                    .to_owned(),
                content_access_rule: yaml_req_str(node, "content_access_rule", &code)?.to_owned(),
                contest_instructions: yaml_req_str(node, "contest_instructions", &code)?.to_owned(),
                works_annex_title: yaml_req_str(node, "works_annex_title", &code)?.to_owned(),
                works_annex_prohibited: yaml_req_str(node, "works_annex_prohibited", &code)?
                    .to_owned(),
                works_annex_quorum: yaml_req_str(node, "works_annex_quorum", &code)?.to_owned(),
                works_annex_expert: yaml_req_str(node, "works_annex_expert", &code)?.to_owned(),
            },
        );
    }

    let mut national_variants = Vec::new();
    for node in yaml_req_seq(&doc, "national_variants", "privacy-templates.yaml")? {
        let id = yaml_req_str(node, "id", "national_variants")?.to_owned();
        national_variants.push(NationalVariantTemplate {
            id: id.clone(),
            country: yaml_req_str(node, "country", &id)?.to_owned(),
            statute: yaml_req_str(node, "statute", &id)?.to_owned(),
            requires_local_counsel_review: yaml_req_bool(
                node,
                "requires_local_counsel_review",
                &id,
            )?,
            clause: yaml_req_str(node, "clause", &id)?.to_owned(),
        });
    }

    Ok(PrivacyTemplatesBundle {
        never_collected,
        dpia_risks,
        locales,
        national_variants,
    })
}
