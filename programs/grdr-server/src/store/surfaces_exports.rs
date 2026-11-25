// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    default_registry, export_assessment_results, export_component_definition, export_evidence_csv,
    export_evidence_markdown,
};
use grdr_crypto::sha256_hex;
use grdr_integrations::{GrcEvidenceInput, GrcTarget, build_grc_evidence_push};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{AssuranceLevel, CodedError, Verdict};
use grdr_proto::api::surfaces::{ExportComplianceArtifactResponse, PushGrcEvidenceResponse};

use crate::auth::AuthContext;

use super::AppState;
use super::surfaces_comply_helpers::{comply_to_coded, evaluate_live_evidence};
use super::surfaces_comply_seed::ensure_compliance_seeded;
use super::surfaces_holds::push_compliance_audit;
use super::surfaces_types::DisclosureRecord;

impl AppState {
    pub async fn export_compliance_artifact(
        &self,
        format: &str,
        auth: &AuthContext,
    ) -> Result<ExportComplianceArtifactResponse, CodedError> {
        let now = Timestamp::now();
        let format_norm = format.trim().to_ascii_lowercase();
        let registry = default_registry();

        let (items, mut guard) = {
            let mut g = self.inner.write().await;
            ensure_compliance_seeded(&mut g, now);
            let evaluated = evaluate_live_evidence(&g, &self.signing_key, &auth.tenant_id, now);
            (evaluated, g)
        };

        let (filename, content_type, payload, oscal_version) = match format_norm.as_str() {
            "oscal-component" | "oscal_component" => {
                let doc = export_component_definition(
                    &registry,
                    "Guardrails ADR Control Definition",
                    "1.0.0",
                    now,
                );
                let json = serde_json::to_string_pretty(&doc).map_err(|e| {
                    CodedError::new(
                        CODE_INVALID_INPUT,
                        format!("Failed encoding OSCAL component definition: {e}"),
                        "Retry OSCAL export.",
                    )
                })?;
                (
                    "guardrails-oscal-component-definition.json".to_owned(),
                    "application/json".to_owned(),
                    json,
                    grdr_comply::oscal::OSCAL_VERSION.to_owned(),
                )
            }
            "oscal-assessment" | "oscal_assessment" => {
                let doc = export_assessment_results(&auth.tenant_id, &items, now)
                    .map_err(comply_to_coded)?;
                let json = serde_json::to_string_pretty(&doc).map_err(|e| {
                    CodedError::new(
                        CODE_INVALID_INPUT,
                        format!("Failed encoding OSCAL assessment results: {e}"),
                        "Retry OSCAL assessment export.",
                    )
                })?;
                (
                    "guardrails-oscal-assessment-results.json".to_owned(),
                    "application/json".to_owned(),
                    json,
                    grdr_comply::oscal::OSCAL_VERSION.to_owned(),
                )
            }
            "csv" => (
                "guardrails-compliance-evidence.csv".to_owned(),
                "text/csv".to_owned(),
                export_evidence_csv(&items),
                "1.0".to_owned(),
            ),
            "markdown" | "md" => (
                "guardrails-compliance-evidence.md".to_owned(),
                "text/markdown".to_owned(),
                export_evidence_markdown(&auth.tenant_id, &items),
                "1.0".to_owned(),
            ),
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unsupported compliance export format `{format_norm}`."),
                    "Use oscal-component, oscal-assessment, csv, or markdown.",
                ));
            }
        };

        let digest = sha256_hex(payload.as_bytes());
        let short_dig: String = digest.chars().take(12).collect();
        let actor_label = auth.principal_id.clone();

        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.disclosures.insert(
                0,
                DisclosureRecord {
                    id: format!("disc_{}", Uuid::now_v7().simple()),
                    organisation: auth.tenant_id.clone(),
                    kind: "export".to_owned(),
                    actor: actor_label.clone(),
                    target_ref: filename.clone(),
                    legal_basis: "Audit and regulator evidence disclosure".to_owned(),
                    timestamp: now.to_string(),
                    quarter: "2026-Q4".to_owned(),
                    summary: format!("Exported {filename} ({format_norm}, sha256:{short_dig})"),
                },
            );
        }
        push_compliance_audit(
            &mut guard,
            now,
            "compliance.artifact.exported",
            actor_label,
            format!("Exported {filename}"),
            format_norm.clone(),
        );
        self.persist_store(&guard)?;

        Ok(ExportComplianceArtifactResponse {
            format: format_norm,
            filename,
            content_type,
            payload,
            oscal_version,
            digest,
        })
    }

    pub async fn push_grc_evidence(
        &self,
        target_raw: &str,
        auth: &AuthContext,
    ) -> Result<PushGrcEvidenceResponse, CodedError> {
        let now = Timestamp::now();
        let target_norm = target_raw.trim().to_ascii_lowercase();
        let target = match target_norm.as_str() {
            "ciso-assistant" | "ciso_assistant" => GrcTarget::CisoAssistant,
            "probo" => GrcTarget::Probo,
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unknown GRC target `{target_norm}`."),
                    "Choose ciso-assistant or probo.",
                ));
            }
        };

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);
        let evaluated = evaluate_live_evidence(&guard, &self.signing_key, &auth.tenant_id, now);
        let evidence_bytes = serde_json::to_vec(&evaluated).map_err(|e| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("Failed canonicalizing compliance evidence: {e}"),
                "Verify evidence queries and retry.",
            )
        })?;
        let evidence_digest = sha256_hex(&evidence_bytes);

        let blocked_count = u64::try_from(
            guard
                .receipts
                .iter()
                .filter(|r| matches!(r.verdict, Verdict::Deny))
                .count(),
        )
        .unwrap_or(0);
        let assurance_level = guard
            .devices
            .iter()
            .flat_map(|d| d.agents.iter())
            .map(|a| a.assurance_level)
            .min()
            .unwrap_or(AssuranceLevel::Al0Inventoried);
        let finding_count = u64::try_from(guard.findings.len()).unwrap_or(0);
        let envelope = build_grc_evidence_push(
            target,
            &GrcEvidenceInput {
                organization_id: auth.tenant_id.clone(),
                control_id: "CC7.2".to_owned(),
                framework: "aicpa-tsc-2017".to_owned(),
                control_title: "Tamper-evident monitoring of security events".to_owned(),
                summary: format!(
                    "Evidence digest prepared: {finding_count} findings, {blocked_count} denied actions"
                ),
                assurance_level,
                finding_count,
                blocked_count,
                evidence_digest,
                collected_at: now,
                artifact_refs: vec![
                    "cap.preexec.enforce".to_owned(),
                    "cap.receipts.signed".to_owned(),
                ],
            },
        )
        .map_err(|e| {
            CodedError::new(
                CODE_INVALID_INPUT,
                e.to_string(),
                "Verify GRC payload fields.",
            )
        })?;

        let preview = serde_json::to_string_pretty(&envelope).unwrap_or_default();
        let circuit_state = if let Some(ref mut comp) = guard.surfaces.compliance
            && let Some(conn) = comp.connectors.iter_mut().find(|c| c.id == target_norm)
        {
            conn.queued_items = conn.queued_items.saturating_add(1);
            conn.circuit_state.clone()
        } else {
            "closed".to_owned()
        };
        push_compliance_audit(
            &mut guard,
            now,
            "compliance.grc.queued",
            auth.principal_id.clone(),
            format!(
                "Queued signed GRC evidence envelope {} for {target_norm} outbox",
                envelope.dedup_key
            ),
            target_norm.clone(),
        );
        self.persist_store(&guard)?;

        Ok(PushGrcEvidenceResponse {
            target: target_norm,
            envelope_id: envelope.dedup_key,
            outbox_state: "queued".to_owned(),
            circuit_state,
            summary: format!(
                "Signed evidence envelope queued in outbox for {target:?} (awaiting configured webhook delivery)"
            ),
            payload_preview: preview,
        })
    }
}
