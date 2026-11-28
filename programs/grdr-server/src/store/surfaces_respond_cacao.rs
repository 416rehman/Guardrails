// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! CACAO workflow import, 7-day non-author Live promotion proof, and server-side
//! blast-radius calculation for SOAR playbooks (`docs/design/18`).

use std::collections::BTreeSet;

use serde::Deserialize;

use grdr_core::detect::response::KillSwitchScope;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_POLICY_STEP_UP};
use grdr_model::{CodedError, Device};

use crate::store::surfaces_respond_playbooks::{
    PlaybookMode, PlaybookPromotionProof, PlaybookStepKind, PlaybookStepSpec, SoarPlaybookSpec,
    soar_err,
};

const DAY_SECS: i64 = 86_400;
const SOAR_MIN_SIMULATE_DAYS: i64 = 7;
const MAX_CACAO_JSON_BYTES: usize = 256 * 1024;
const MAX_CACAO_STEPS: usize = 64;

#[derive(Debug, Clone, Deserialize)]
struct CacaoWorkflow {
    id: String,
    #[serde(default)]
    workflow: Vec<CacaoStep>,
}

#[derive(Debug, Clone, Deserialize)]
struct CacaoStep {
    id: String,
    #[serde(default)]
    action_type: String,
    #[serde(default)]
    target: String,
}

/// Verifies a 7-day simulation window and distinct non-author approver before Live promotion.
pub(crate) fn verify_and_build_promotion_proof(
    org_id: &str,
    spec: &SoarPlaybookSpec,
    author_id: &str,
    approver_id: &str,
    simulated_at_sec: i64,
    now_sec: i64,
) -> Result<PlaybookPromotionProof, CodedError> {
    spec.validate()?;
    if org_id.trim().is_empty()
        || author_id.trim().is_empty()
        || approver_id.trim().is_empty()
        || author_id.trim().eq_ignore_ascii_case(approver_id.trim())
    {
        return Err(soar_err(
            CODE_POLICY_STEP_UP,
            "SOAR Live promotion requires distinct non-author second approver",
            "Route SOAR Live promotion approval to a second operator.",
        ));
    }
    if now_sec.saturating_sub(simulated_at_sec) < SOAR_MIN_SIMULATE_DAYS.saturating_mul(DAY_SECS) {
        return Err(soar_err(
            CODE_POLICY_STEP_UP,
            format!(
                "SOAR Live promotion requires >= {SOAR_MIN_SIMULATE_DAYS} days in Simulate mode"
            ),
            "Keep playbook in Simulate for the full 7-day window before promoting.",
        ));
    }
    Ok(PlaybookPromotionProof {
        org_id: org_id.to_owned(),
        playbook_id: spec.playbook_id.clone(),
        spec_digest_sha256: spec.digest_sha256()?,
        max_share_bp: spec.max_share_bp,
        author_id: author_id.trim().to_owned(),
        approver_id: approver_id.trim().to_owned(),
        simulated_at_sec,
        approved_at_sec: now_sec,
    })
}

/// Imports a CACAO workflow JSON document, mapping unknown external actions safely to `ManualReview`.
pub fn import_cacao_playbook(raw_json: &str) -> Result<SoarPlaybookSpec, CodedError> {
    if raw_json.trim().is_empty() || raw_json.len() > MAX_CACAO_JSON_BYTES {
        return Err(soar_err(
            CODE_INVALID_INPUT,
            format!(
                "CACAO payload size {} outside 1..={MAX_CACAO_JSON_BYTES}",
                raw_json.len()
            ),
            "Provide bounded CACAO workflow JSON within 256 KiB.",
        ));
    }
    let cacao: CacaoWorkflow = serde_json::from_str(raw_json).map_err(|e| {
        soar_err(
            CODE_INVALID_INPUT,
            format!("invalid CACAO JSON: {e}"),
            "Fix JSON.",
        )
    })?;
    if cacao.workflow.len() > MAX_CACAO_STEPS {
        return Err(soar_err(
            CODE_INVALID_INPUT,
            format!("CACAO workflow step count exceeds max {MAX_CACAO_STEPS}"),
            "Limit imported CACAO playbooks to 64 steps.",
        ));
    }
    let steps = cacao
        .workflow
        .into_iter()
        .map(|cs| {
            let norm = cs.action_type.trim().to_ascii_lowercase();
            let (kind, undo_ref) = match norm.as_str() {
                "freeze-session" | "freeze" => {
                    (PlaybookStepKind::FreezeSession, Some("release".into()))
                }
                "isolate-device" | "isolate" => {
                    (PlaybookStepKind::IsolateDevice, Some("release".into()))
                }
                "capture-evidence" | "capture" => (PlaybookStepKind::CaptureEvidence, None),
                "disable-artefact" => (PlaybookStepKind::DisableArtefact, Some("enable".into())),
                _ => (PlaybookStepKind::ManualReview, None),
            };
            PlaybookStepSpec {
                step_id: cs.id,
                kind,
                idempotent: matches!(
                    kind,
                    PlaybookStepKind::FreezeSession
                        | PlaybookStepKind::CaptureEvidence
                        | PlaybookStepKind::ManualReview
                ),
                undo_ref,
                raw_target: cs.target,
            }
        })
        .collect();
    let spec = SoarPlaybookSpec {
        playbook_id: cacao.id,
        version: "1.0.0".into(),
        mode: PlaybookMode::Simulate,
        max_share_bp: 500,
        steps,
    };
    spec.validate()?;
    Ok(spec)
}

pub(crate) fn compute_soar_fleet_share_bp(devices: &[Device], scope: &KillSwitchScope) -> u16 {
    let total = devices.len().max(1);
    let affected = match scope {
        KillSwitchScope::Session(_) | KillSwitchScope::Device(_) => 1usize,
        KillSwitchScope::Agent(agent_name) => devices
            .iter()
            .filter(|d| {
                d.agents
                    .iter()
                    .any(|a| a.name.eq_ignore_ascii_case(agent_name))
            })
            .count()
            .max(1),
        KillSwitchScope::ArtefactDigest(digest) => devices
            .iter()
            .filter(|d| d.artifacts.iter().any(|art| art.content_digest == *digest))
            .count()
            .max(1),
        _ => {
            let ids: BTreeSet<&str> = devices.iter().map(|d| d.id.as_str()).collect();
            ids.len().max(1)
        }
    };
    if affected <= 1 {
        return 0;
    }
    u16::try_from(
        affected
            .saturating_mul(10_000)
            .checked_div(total)
            .unwrap_or(10_000),
    )
    .unwrap_or(10_000)
}
