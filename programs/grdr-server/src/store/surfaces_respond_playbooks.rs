// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Crash-safe simulate-first SOAR playbook engine, CACAO import, 7-day non-author promotion
//! gate, server-computed blast-radius compensation, and manual approval parking (`docs/design/18`).

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_core::detect::response::{DeviceContainmentStage, KillSwitchScope};
use grdr_crypto::{encode_lower_hex, sha256_digest};
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_POLICY_STEP_UP};
use grdr_model::{CodedError, Finding, FindingClass, FindingLifecycle, FindingSeverity};

#[cfg(test)]
pub use crate::store::surfaces_respond_cacao::import_cacao_playbook;
pub(crate) use crate::store::surfaces_respond_cacao::{
    compute_soar_fleet_share_bp, verify_and_build_promotion_proof,
};

const MAX_PLAYBOOK_ID_LEN: usize = 128;
const MAX_TARGET_ID_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookMode {
    Simulate,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPrincipal {
    HumanApprover,
    SoarServiceKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStepKind {
    FreezeSession,
    IsolateDevice,
    CaptureEvidence,
    DisableArtefact,
    RevokeSession,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepJournalStatus {
    Pending,
    Completed,
    Compensated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookRunState {
    Simulated,
    Running,
    PausedForManualApproval,
    Completed,
    DroppedToSimulateAndCompensated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepAdvanceOutcome {
    Executed(usize),
    PausedForManual,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookStepSpec {
    pub step_id: String,
    pub kind: PlaybookStepKind,
    pub idempotent: bool,
    pub undo_ref: Option<String>,
    pub raw_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoarPlaybookSpec {
    pub playbook_id: String,
    pub version: String,
    pub mode: PlaybookMode,
    pub max_share_bp: u16,
    pub steps: Vec<PlaybookStepSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookPromotionProof {
    pub org_id: String,
    pub playbook_id: String,
    pub spec_digest_sha256: String,
    pub max_share_bp: u16,
    pub author_id: String,
    pub approver_id: String,
    pub simulated_at_sec: i64,
    pub approved_at_sec: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepJournalEntry {
    pub step_index: usize,
    pub step_id: String,
    pub kind: PlaybookStepKind,
    pub idempotent: bool,
    pub status: StepJournalStatus,
    pub undo_ref: Option<String>,
    pub executions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookRunJournal {
    pub run_id: String,
    pub org_id: String,
    pub playbook_id: String,
    pub spec_digest_sha256: String,
    pub max_share_bp: u16,
    pub spec_mode: PlaybookMode,
    pub scope: KillSwitchScope,
    pub effective_mode: PlaybookMode,
    pub state: PlaybookRunState,
    pub steps: Vec<StepJournalEntry>,
    pub compensated_undo_refs: Vec<String>,
}

pub(crate) struct PlaybookAdvanceCtx<'a> {
    pub org_id: &'a str,
    pub spec: &'a SoarPlaybookSpec,
    pub principal: ExecutionPrincipal,
    pub scope: &'a KillSwitchScope,
    pub fleet_share_bp: u16,
    pub approve_manual_step_idx: Option<usize>,
    pub promotion_proof: Option<&'a PlaybookPromotionProof>,
}

pub(crate) fn soar_err(
    code: &'static str,
    msg: impl Into<String>,
    fix: &'static str,
) -> CodedError {
    CodedError::new(code, msg, fix)
}

impl SoarPlaybookSpec {
    pub fn digest_sha256(&self) -> Result<String, CodedError> {
        let canonical = (
            &self.playbook_id,
            &self.version,
            self.max_share_bp,
            &self.steps,
        );
        let bytes = serde_json::to_vec(&canonical)
            .map_err(|e| soar_err(CODE_INVALID_INPUT, format!("spec encode: {e}"), "Fix spec."))?;
        Ok(encode_lower_hex(&sha256_digest(&bytes)))
    }

    /// Rejects outbound URLs, URI schemes, metacharacters, empty steps, or out-of-range blast caps (`E10.1`).
    pub fn validate(&self) -> Result<(), CodedError> {
        if !is_safe_identifier(&self.playbook_id, MAX_PLAYBOOK_ID_LEN)
            || !is_safe_identifier(&self.version, MAX_PLAYBOOK_ID_LEN)
            || self.steps.is_empty()
            || self.max_share_bp == 0
            || self.max_share_bp > 10_000
        {
            return Err(soar_err(
                CODE_INVALID_INPUT,
                "SOAR playbook requires safe id/version, non-empty steps, and 1..=10000 max_share_bp",
                "Fix playbook pack structure.",
            ));
        }
        for step in &self.steps {
            if !is_safe_identifier(&step.step_id, MAX_PLAYBOOK_ID_LEN)
                || !is_safe_playbook_target(&step.raw_target)
            {
                return Err(soar_err(
                    CODE_INVALID_INPUT,
                    format!(
                        "SOAR step `{}` has unsafe id, URI, or metacharacter",
                        step.step_id
                    ),
                    "Use typed Guardrails targets; URIs and metacharacters are banned.",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn initialize_or_validate_journal(
    ctx: &PlaybookAdvanceCtx<'_>,
    existing: Option<&PlaybookRunJournal>,
) -> Result<PlaybookRunJournal, CodedError> {
    if ctx.org_id.trim().is_empty() {
        return Err(soar_err(
            CODE_INVALID_INPUT,
            "SOAR playbook requires org_id",
            "Set org_id.",
        ));
    }
    ctx.spec.validate()?;
    let spec_digest = ctx.spec.digest_sha256()?;

    if ctx.spec.mode == PlaybookMode::Live {
        let Some(proof) = ctx.promotion_proof else {
            return Err(soar_err(
                CODE_POLICY_STEP_UP,
                "SOAR Live execution requires verified 7-day Simulate promotion proof",
                "Run in Simulate >= 7 days and approve promotion with a second operator.",
            ));
        };
        if proof.org_id != ctx.org_id
            || proof.playbook_id != ctx.spec.playbook_id
            || proof.spec_digest_sha256 != spec_digest
            || proof.max_share_bp != ctx.spec.max_share_bp
            || proof.author_id.eq_ignore_ascii_case(&proof.approver_id)
        {
            return Err(soar_err(
                CODE_POLICY_STEP_UP,
                "SOAR promotion proof digest, blast-radius cap, or approver mismatch",
                "Re-promote edited SOAR playbook spec cleanly.",
            ));
        }
    }

    if ctx.principal == ExecutionPrincipal::SoarServiceKey {
        let scope_ok = matches!(
            ctx.scope,
            KillSwitchScope::Session(_) | KillSwitchScope::Device(_)
        );
        let verbs_auto = ctx.spec.steps.iter().all(|s| {
            matches!(
                s.kind,
                PlaybookStepKind::FreezeSession
                    | PlaybookStepKind::CaptureEvidence
                    | PlaybookStepKind::DisableArtefact
                    | PlaybookStepKind::ManualReview
            )
        });
        if !scope_ok || !verbs_auto {
            return Err(soar_err(
                CODE_POLICY_STEP_UP,
                "SOAR service key refused above device scope or on non-automatic verbs",
                "Require human WebAuthn sign-off for revoke/isolation/org scope.",
            ));
        }
    }

    if let Some(prev) = existing {
        if matches!(
            prev.state,
            PlaybookRunState::Completed
                | PlaybookRunState::Simulated
                | PlaybookRunState::DroppedToSimulateAndCompensated
        ) {
            return Err(soar_err(
                CODE_CONFLICT,
                "cannot resume SOAR playbook from terminal state",
                "Start fresh run.",
            ));
        }
        if prev.org_id != ctx.org_id
            || prev.playbook_id != ctx.spec.playbook_id
            || prev.spec_digest_sha256 != spec_digest
            || prev.max_share_bp != ctx.spec.max_share_bp
            || prev.spec_mode != ctx.spec.mode
            || &prev.scope != ctx.scope
        {
            return Err(soar_err(
                CODE_CONFLICT,
                "resumed SOAR playbook spec, max_share_bp, scope, mode, or org_id mismatch",
                "Resume with identical immutable playbook specification and scope.",
            ));
        }
        return Ok(prev.clone());
    }

    Ok(PlaybookRunJournal {
        run_id: format!("pbrun_{}", Uuid::now_v7().simple()),
        org_id: ctx.org_id.to_owned(),
        playbook_id: ctx.spec.playbook_id.clone(),
        spec_digest_sha256: spec_digest,
        max_share_bp: ctx.spec.max_share_bp,
        spec_mode: ctx.spec.mode,
        scope: ctx.scope.clone(),
        effective_mode: ctx.spec.mode,
        state: if ctx.spec.mode == PlaybookMode::Simulate {
            PlaybookRunState::Simulated
        } else {
            PlaybookRunState::Running
        },
        steps: ctx
            .spec
            .steps
            .iter()
            .enumerate()
            .map(|(idx, s)| StepJournalEntry {
                step_index: idx,
                step_id: s.step_id.clone(),
                kind: s.kind,
                idempotent: s.idempotent,
                status: StepJournalStatus::Pending,
                undo_ref: s.undo_ref.clone(),
                executions: 0,
            })
            .collect(),
        compensated_undo_refs: Vec::new(),
    })
}

pub(crate) fn apply_blast_radius_drop(
    journal: &mut PlaybookRunJournal,
    ctx: &PlaybookAdvanceCtx<'_>,
    findings: &mut Vec<Finding>,
) -> bool {
    if ctx.spec.mode != PlaybookMode::Live || ctx.fleet_share_bp <= ctx.spec.max_share_bp {
        return false;
    }
    journal.effective_mode = PlaybookMode::Simulate;
    journal.state = PlaybookRunState::DroppedToSimulateAndCompensated;
    for step in journal.steps.iter_mut().rev() {
        if step.status == StepJournalStatus::Completed {
            step.status = StepJournalStatus::Compensated;
            if let Some(ref undo) = step.undo_ref {
                journal
                    .compensated_undo_refs
                    .push(format!("{}:{undo}", step.step_id));
            }
        }
    }
    findings.push(Finding {
        id: format!("fnd_soar_{}", Uuid::now_v7().simple()),
        session_id: String::new(),
        device_id: String::new(),
        device_name: String::new(),
        agent_name: "soar-engine".into(),
        class: FindingClass::Tamper,
        finding_class_other: None,
        severity: FindingSeverity::High,
        lifecycle: FindingLifecycle::Open,
        rule_id: Some("soar.blast-radius-tripped".into()),
        title: "SOAR playbook exceeded blast-radius cap and dropped to simulate".into(),
        summary: format!(
            "Playbook {} reached {} bps > {} bps cap",
            ctx.spec.playbook_id, ctx.fleet_share_bp, ctx.spec.max_share_bp
        ),
        target: ctx.spec.playbook_id.clone(),
        detected_at: Timestamp::now(),
    });
    true
}

pub(crate) fn advance_next_pending_step(
    journal: &mut PlaybookRunJournal,
    ctx: &PlaybookAdvanceCtx<'_>,
) -> Result<StepAdvanceOutcome, CodedError> {
    for step in &mut journal.steps {
        if step.status != StepJournalStatus::Pending {
            continue;
        }
        if journal.effective_mode == PlaybookMode::Live
            && step.kind == PlaybookStepKind::ManualReview
            && !(ctx.principal == ExecutionPrincipal::HumanApprover
                && ctx.approve_manual_step_idx == Some(step.step_index))
        {
            journal.state = PlaybookRunState::PausedForManualApproval;
            return Ok(StepAdvanceOutcome::PausedForManual);
        }
        if journal.effective_mode == PlaybookMode::Live
            && step.kind != PlaybookStepKind::ManualReview
        {
            let _ = stage_for_step(step.kind)?;
        }
        step.executions = step.executions.saturating_add(1);
        step.status = StepJournalStatus::Completed;
        journal.state = if journal.effective_mode == PlaybookMode::Simulate {
            PlaybookRunState::Simulated
        } else {
            PlaybookRunState::Running
        };
        return Ok(StepAdvanceOutcome::Executed(step.step_index));
    }

    journal.state = if journal.effective_mode == PlaybookMode::Simulate {
        PlaybookRunState::Simulated
    } else {
        PlaybookRunState::Completed
    };
    Ok(StepAdvanceOutcome::Finished)
}

fn stage_for_step(kind: PlaybookStepKind) -> Result<DeviceContainmentStage, CodedError> {
    match kind {
        PlaybookStepKind::FreezeSession => Ok(DeviceContainmentStage::Frozen),
        PlaybookStepKind::IsolateDevice | PlaybookStepKind::DisableArtefact => {
            Ok(DeviceContainmentStage::Isolated)
        }
        PlaybookStepKind::CaptureEvidence => Ok(DeviceContainmentStage::Captured),
        PlaybookStepKind::RevokeSession => Ok(DeviceContainmentStage::Revoked),
        PlaybookStepKind::ManualReview => Err(soar_err(
            CODE_CONFLICT,
            "manual review step requires operator approval before dispatch",
            "Approve manual step explicitly.",
        )),
    }
}

fn is_safe_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_safe_playbook_target(target: &str) -> bool {
    if target.is_empty() || target.len() > MAX_TARGET_ID_LEN {
        return false;
    }
    let lower = target.to_ascii_lowercase();
    if lower.contains("://") || lower.contains("//") || lower.contains("..") {
        return false;
    }
    if let Some(hex) = lower.strip_prefix("sha256:") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    is_safe_identifier(target, MAX_TARGET_ID_LEN)
}
