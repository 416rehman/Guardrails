// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compliance local audit receipt verification, query digestion, and readiness probe evaluation.

use std::collections::BTreeMap;
use std::path::Path;

use grdr_comply::{
    BrokerReadiness, CertificationStatus, ConnectorCoverage, DeploymentTopology, EvidenceDataClass,
    EvidenceItem, EvidencePipelineInput, EvidenceQuery, FieldRead, LoadedCompliancePack,
    PlatformReadiness, evaluate_evidence_item,
};
use grdr_crypto::{SigningKeypair, sha256_hex};
use jiff::Timestamp;

use crate::audit::verify_audit_file;
use crate::comply::{ComplyCliError, TopologyArg};
use crate::fs_safe::read_bounded_utf8;

const MAX_COMPLY_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const EVIDENCE_WINDOW_SECONDS: i64 = 86_400;

pub struct VerifiedAuditObservations {
    pub total_observations: u64,
    pub covered_observations: u64,
    pub sample_ids: Vec<String>,
}

pub fn build_local_evidence_items(
    organisation: &str,
    capability_filter: Option<&str>,
    audit_log: Option<&Path>,
    pipeline_lag: u64,
    max_lag: u64,
    loaded: &LoadedCompliancePack,
    keypair: &SigningKeypair,
) -> Result<Vec<EvidenceItem>, ComplyCliError> {
    let registry = &loaded.registry;
    let now = Timestamp::now();
    let period_start =
        Timestamp::from_second(now.as_second().saturating_sub(EVIDENCE_WINDOW_SECONDS))
            .unwrap_or(Timestamp::UNIX_EPOCH);
    let obs = collect_verified_observations(audit_log)?;
    let pack_digest = loaded.digest_sha256.clone();

    let target_caps: Vec<String> = match capability_filter {
        Some(cap) => vec![cap.to_owned()],
        None => vec![
            "cap.inventory.agents".into(),
            "cap.preexec.enforce".into(),
            "cap.receipts.signed".into(),
            "cap.privacy.floor".into(),
        ],
    };

    let mut items = Vec::with_capacity(target_caps.len());
    for cap in target_caps {
        let query = loaded
            .manifest
            .evidence_queries
            .iter()
            .find(|q| q.capability == cap)
            .cloned()
            .unwrap_or_else(|| EvidenceQuery {
                id: format!("q.{cap}"),
                version: "1.0.0".into(),
                capability: cap,
                reads: vec![
                    FieldRead {
                        field_path: "receipt.verdict".into(),
                        data_class: EvidenceDataClass::Derived,
                    },
                    FieldRead {
                        field_path: "receipt.action_class".into(),
                        data_class: EvidenceDataClass::Structural,
                    },
                ],
                max_class: EvidenceDataClass::Derived,
                group_by: vec!["capability".into(), "period".into()],
            });
        let query_bytes =
            serde_json::to_vec(&query).map_err(|e| ComplyCliError::Domain(e.to_string()))?;
        let query_digest = sha256_hex(&query_bytes);
        let input = EvidencePipelineInput {
            organisation: organisation.to_owned(),
            period_start,
            period_end: now,
            pipeline_lag_seconds: pipeline_lag,
            max_lag_seconds: max_lag,
            total_observations: obs.total_observations,
            covered_observations: obs.covered_observations,
            sample_ids: obs.sample_ids.clone(),
            query_digest,
            pack_digest: pack_digest.clone(),
            schema_rev: "v1alpha1".into(),
        };
        items.push(
            evaluate_evidence_item(&query, &input, registry, keypair)
                .map_err(|e| ComplyCliError::Domain(e.to_string()))?,
        );
    }
    Ok(items)
}

fn collect_verified_observations(
    audit_log: Option<&Path>,
) -> Result<VerifiedAuditObservations, ComplyCliError> {
    let Some(path) = audit_log else {
        return Ok(VerifiedAuditObservations {
            total_observations: 0,
            covered_observations: 0,
            sample_ids: Vec::new(),
        });
    };
    let summary = verify_audit_file(path).map_err(|e| {
        ComplyCliError::Domain(format!(
            "GRDR-COMPLY-0103: audit log `{}` failed cryptographic verification: {e}",
            path.display()
        ))
    })?;
    let text = read_bounded_utf8(path, MAX_COMPLY_INPUT_BYTES).map_err(|e| ComplyCliError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;

    let mut sample_ids = Vec::new();
    let mut covered: u64 = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let val: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| ComplyCliError::Domain(e.to_string()))?;
        let has_id = val
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());
        let has_hash = val
            .get("entry_hash")
            .or_else(|| val.get("hash"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());
        if let Some(id) = has_id {
            covered = covered.saturating_add(1);
            if sample_ids.len() < 10 {
                sample_ids.push(id.to_owned());
            }
        } else if let Some(h) = has_hash {
            covered = covered.saturating_add(1);
            if sample_ids.len() < 10 {
                sample_ids.push(h.to_owned());
            }
        }
    }
    let total = u64::try_from(summary.entries).unwrap_or(u64::MAX);
    Ok(VerifiedAuditObservations {
        total_observations: total,
        covered_observations: covered.min(total),
        sample_ids,
    })
}

pub fn build_platform_readiness(
    version: &str,
    topology: TopologyArg,
    assurance: &str,
    audit_log: Option<&Path>,
    acceptance_report: Option<&Path>,
) -> Result<PlatformReadiness, ComplyCliError> {
    if let Some(path) = audit_log {
        verify_audit_file(path).map_err(|e| {
            ComplyCliError::Domain(format!(
                "GRDR-COMPLY-0103: audit log `{}` failed cryptographic verification: {e}",
                path.display()
            ))
        })?;
    }

    let mut green = BTreeMap::new();
    if let Some(report_path) = acceptance_report {
        let raw = read_bounded_utf8(report_path, MAX_COMPLY_INPUT_BYTES).map_err(|e| {
            ComplyCliError::Io {
                path: report_path.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        let parsed = serde_json::from_str::<BTreeMap<String, bool>>(&raw)
            .map_err(|e| ComplyCliError::Domain(format!("invalid acceptance report JSON: {e}")))?;
        for num in 1_u8..=17 {
            let key = format!("T{num}");
            let status = parsed.get(&key).copied().unwrap_or(false);
            green.insert(key, status);
        }
    } else {
        for num in 1_u8..=17 {
            green.insert(format!("T{num}"), false);
        }
    }

    Ok(PlatformReadiness {
        release_version: version.to_owned(),
        os_assurance_summary: assurance.to_owned(),
        topology: match topology {
            TopologyArg::Standalone => DeploymentTopology::Standalone,
            TopologyArg::ServerAvailable => DeploymentTopology::ServerAvailable,
        },
        broker: match topology {
            TopologyArg::Standalone => BrokerReadiness::Unavailable,
            TopologyArg::ServerAvailable => BrokerReadiness::Ready,
        },
        connectors: ConnectorCoverage::ReadOnlyPair,
        certification: CertificationStatus::NoneHeld,
        acceptance_tests_green: green,
    })
}
