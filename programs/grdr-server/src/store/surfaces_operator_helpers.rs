// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_comply::{PrivacyCeilingProfile, RetentionPreset};
use grdr_model::CodedError;
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_proto::api::operator::{ConfigDiffEntry, ConfigRevisionEntry, OperatorRuntimeConfig};
use grdr_proto::common::ConfigRevisionLifecycle;

use super::surfaces_types::{
    ConfigRevLifecycle, OperatorConfigSnapshot, OperatorDiffRecord, OperatorRevisionRecord,
};

pub(crate) fn compute_config_diff(
    prev: &OperatorConfigSnapshot,
    next: &OperatorConfigSnapshot,
) -> Vec<OperatorDiffRecord> {
    let mut diffs = Vec::new();
    let pairs = [
        (
            "capture_level",
            prev.capture_level.as_str(),
            next.capture_level.as_str(),
        ),
        (
            "privacy_profile",
            prev.privacy_profile.as_str(),
            next.privacy_profile.as_str(),
        ),
        (
            "retention_preset",
            prev.retention_preset.as_str(),
            next.retention_preset.as_str(),
        ),
        (
            "release_channel",
            prev.release_channel.as_str(),
            next.release_channel.as_str(),
        ),
    ];
    for (field, p, n) in pairs {
        if p != n {
            diffs.push(OperatorDiffRecord {
                field: field.to_owned(),
                previous: p.to_owned(),
                next: n.to_owned(),
            });
        }
    }
    if prev.otlp_enabled != next.otlp_enabled {
        diffs.push(OperatorDiffRecord {
            field: "otlp_enabled".to_owned(),
            previous: prev.otlp_enabled.to_string(),
            next: next.otlp_enabled.to_string(),
        });
    }
    diffs
}

pub(crate) fn config_to_proto(c: &OperatorConfigSnapshot) -> OperatorRuntimeConfig {
    OperatorRuntimeConfig {
        revision_id: c.revision_id.clone(),
        version: c.version,
        capture_level: c.capture_level.clone(),
        privacy_profile: c.privacy_profile.clone(),
        retention_preset: c.retention_preset.clone(),
        hot_days: c.hot_days,
        activity_days: c.activity_days,
        decision_days: c.decision_days,
        audit_days: c.audit_days,
        otlp_enabled: c.otlp_enabled,
        release_channel: c.release_channel.clone(),
        summary: c.summary.clone(),
    }
}

pub(crate) fn revision_to_proto(r: &OperatorRevisionRecord) -> ConfigRevisionEntry {
    ConfigRevisionEntry {
        revision_id: r.revision_id.clone(),
        version: r.version,
        state: match r.state {
            ConfigRevLifecycle::Draft => ConfigRevisionLifecycle::Draft as i32,
            ConfigRevLifecycle::Validated => ConfigRevisionLifecycle::Validated as i32,
            ConfigRevLifecycle::Applying => ConfigRevisionLifecycle::Applying as i32,
            ConfigRevLifecycle::Applied => ConfigRevisionLifecycle::Applied as i32,
            ConfigRevLifecycle::RolledBack => ConfigRevisionLifecycle::RolledBack as i32,
            ConfigRevLifecycle::Superseded => ConfigRevisionLifecycle::Superseded as i32,
            ConfigRevLifecycle::Discarded => ConfigRevisionLifecycle::Discarded as i32,
        },
        author: r.author.clone(),
        summary: r.summary.clone(),
        created_at: r.created_at.clone(),
        applied_at: r.applied_at.clone(),
        diff_lines: r
            .diff_lines
            .iter()
            .map(|d| ConfigDiffEntry {
                field: d.field.clone(),
                previous: d.previous.clone(),
                next: d.next.clone(),
            })
            .collect(),
        config: Some(config_to_proto(&r.config)),
    }
}

pub(crate) fn parse_op_preset(raw: &str) -> Result<RetentionPreset, CodedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(RetentionPreset::Default),
        "eu-ai-act-deployer" => Ok(RetentionPreset::EuAiActDeployer),
        "pci-dss-4" => Ok(RetentionPreset::PciDss4),
        "hipaa" => Ok(RetentionPreset::Hipaa),
        "nydfs-500" => Ok(RetentionPreset::Nydfs500),
        "colorado-adm" => Ok(RetentionPreset::ColoradoAdm),
        "sox-itgc" => Ok(RetentionPreset::SoxItgc),
        _ => Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("Unsupported retention preset `{raw}`."),
            "Select a supported retention preset.",
        )),
    }
}

pub(crate) fn profile_str(p: PrivacyCeilingProfile) -> &'static str {
    match p {
        PrivacyCeilingProfile::Standard => "standard",
        PrivacyCeilingProfile::WorksCouncil => "works-council",
    }
}
