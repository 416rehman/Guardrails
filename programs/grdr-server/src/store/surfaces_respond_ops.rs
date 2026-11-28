// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Server-side granular kill-switch execution, authority matrix, provider org caps,
//! release parity checks, and actuator delivery preview (`docs/design/18`, `22`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_core::detect::kill_switch::server_operational_limits;
use grdr_core::detect::response::{
    ActiveKillEntry, ActuatorDeliveryForm, ApprovalOutcomeSignal, DeviceContainmentStage,
    GranularKillSwitchState, KillSwitchApplyRequest, KillSwitchScope, compute_preview_rollup,
};
use grdr_crypto::verify_bytes;
use grdr_model::CodedError;
use grdr_model::error::{
    CODE_CONFLICT, CODE_INVALID_INPUT, CODE_POLICY_STEP_UP, CODE_UNAUTHORIZED,
};

use crate::store::surfaces_respond_webauthn::{
    ApproverRole, ApproverRosterState, VerifiedSigner, WebAuthnReplayState,
    WebAuthnStepUpAssertion, verify_distinct_signers,
};

const ONE_HOUR_SECS: i64 = 3_600;
const LONE_FREEZE_MAX_SECS: i64 = ONE_HOUR_SECS;
const PROVIDER_HOURLY_ORG_CAP: usize = 5;
pub(crate) const DEPLOY_KILL_SIG_DOMAIN: &str = "grdr.kill_switch.deploy.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedServerKillRequest {
    pub command_id: String,
    pub org_id: String,
    pub epoch: u64,
    pub counter: u64,
    pub scope: KillSwitchScope,
    pub target_stage: DeviceContainmentStage,
    pub reason_code: String,
    pub expires_at_sec: i64,
    pub assertions: Vec<WebAuthnStepUpAssertion>,
    #[serde(default)]
    pub deployment_sig_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerResponseActionRecord {
    pub command_id: String,
    pub org_id: String,
    pub scope_key: String,
    pub executed_stages: Vec<DeviceContainmentStage>,
    pub verified_signers: Vec<String>,
    pub issued_at_sec: i64,
    pub expires_at_sec: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActuatorCapPreview {
    pub os_family: String,
    pub delivery_form: ActuatorDeliveryForm,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewResponseResult {
    pub rollup_form: ActuatorDeliveryForm,
    pub actuators: Vec<ActuatorCapPreview>,
}

pub(crate) struct ServerKillExecCtx<'a> {
    pub roster: &'a ApproverRosterState,
    pub kill_state: &'a mut GranularKillSwitchState,
    pub replay_state: &'a mut WebAuthnReplayState,
    pub provider_hourly_orgs: &'a mut BTreeMap<String, Vec<(String, i64)>>,
    pub freeze_by_key_scope: &'a mut BTreeMap<String, i64>,
    pub deployment_public_key_b64: &'a str,
    pub req: &'a SignedServerKillRequest,
    pub now_sec: i64,
}

#[derive(Debug, Clone, Copy)]
struct OpsLimits {
    day_secs: i64,
    max_entries: usize,
}

impl OpsLimits {
    fn from_embedded() -> Result<Self, CodedError> {
        let cfg = server_operational_limits().map_err(|err| {
            CodedError::new(
                CODE_CONFLICT,
                format!("operational limits unavailable: {err}"),
                "Restore valid embedded contracts/limits.toml configuration.",
            )
        })?;
        let fleet_hours = i64::from(cfg.fleet_response_key_hours);
        let max_entries = usize::try_from(cfg.max_devices_default).unwrap_or(10_000);
        Ok(Self {
            day_secs: fleet_hours.saturating_mul(ONE_HOUR_SECS),
            max_entries,
        })
    }
}

impl SignedServerKillRequest {
    pub fn canonical_signing_body(&self) -> Result<Vec<u8>, CodedError> {
        let payload = (
            "grdr.kill_cmd.v1",
            &self.command_id,
            &self.org_id,
            self.epoch,
            self.counter,
            &self.scope,
            self.target_stage,
            &self.reason_code,
            self.expires_at_sec,
        );
        serde_json::to_vec(&payload).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("failed to encode canonical kill command body: {err}"),
                "Verify kill command fields.",
            )
        })
    }
}

pub(crate) fn execute_signed_kill_on_server(
    mut ctx: ServerKillExecCtx<'_>,
) -> Result<(ActiveKillEntry, ServerResponseActionRecord), CodedError> {
    let limits = OpsLimits::from_embedded()?;
    let req = ctx.req;
    if req.org_id != ctx.roster.org_id || !scope_belongs_to_org(&req.scope, &req.org_id) {
        return Err(CodedError::new(
            CODE_UNAUTHORIZED,
            "kill switch org_id mismatch with roster or scope target",
            "Execute kill switch commands strictly within owning tenant org.",
        ));
    }

    let canonical_body = req.canonical_signing_body()?;
    let (signers, staged_replay) = if req.assertions.is_empty() {
        let Some(sig_b64) = req.deployment_sig_b64.as_deref() else {
            return Err(CodedError::new(
                CODE_POLICY_STEP_UP,
                "0-signer kill command requires verified deployment key signature",
                "Sign command with authorized deployment key or provide hardware WebAuthn assertions.",
            ));
        };
        verify_bytes(
            ctx.deployment_public_key_b64,
            DEPLOY_KILL_SIG_DOMAIN,
            &canonical_body,
            sig_b64,
        )
        .map_err(|_| {
            CodedError::new(
                CODE_UNAUTHORIZED,
                "deployment key signature verification failed",
                "Sign canonical kill body with active deployment signing key.",
            )
        })?;
        (Vec::new(), None)
    } else {
        let (v, s) = verify_distinct_signers(
            ctx.roster,
            &canonical_body,
            &req.assertions,
            ctx.replay_state,
        )?;
        (v, Some(s))
    };

    let ttl = req.expires_at_sec.saturating_sub(ctx.now_sec);
    let scope_key = req.scope.scope_key();
    enforce_server_kill_authority(&mut ctx, &limits, &signers, &scope_key, ttl)?;

    let dual_signed = signers.len() >= 2;
    let entry = ctx
        .kill_state
        .apply_stage(KillSwitchApplyRequest {
            command_id: &req.command_id,
            scope: req.scope.clone(),
            target_stage: req.target_stage,
            dual_signed,
            reason_code: &req.reason_code,
            epoch: req.epoch,
            counter: req.counter,
            expires_at_sec: req.expires_at_sec,
            now: ctx.now_sec,
        })
        .map_err(|err| {
            CodedError::new(
                CODE_CONFLICT,
                format!("response containment gate rejected command: {err}"),
                "Verify command epoch, counter, stage transitions, and 10m rate limits.",
            )
        })?;

    if let Some(staged) = staged_replay {
        staged.commit(ctx.replay_state);
    }
    let freeze_cutoff = ctx.now_sec.saturating_sub(limits.day_secs);
    ctx.freeze_by_key_scope.retain(|_, ts| *ts >= freeze_cutoff);
    if req.target_stage == DeviceContainmentStage::Frozen
        && let [single] = signers.as_slice()
        && let Ok(fk) = serde_json::to_string(&(&req.org_id, &single.public_key_hex, &scope_key))
    {
        if !ctx.freeze_by_key_scope.contains_key(&fk)
            && ctx.freeze_by_key_scope.len() >= limits.max_entries
            && let Some(oldest) = ctx
                .freeze_by_key_scope
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
        {
            ctx.freeze_by_key_scope.remove(&oldest);
        }
        ctx.freeze_by_key_scope.insert(fk, ctx.now_sec);
    }

    let record = ServerResponseActionRecord {
        command_id: req.command_id.clone(),
        org_id: req.org_id.clone(),
        scope_key,
        executed_stages: entry.executed_stages.clone(),
        verified_signers: signers.into_iter().map(|s| s.key_id).collect(),
        issued_at_sec: ctx.now_sec,
        expires_at_sec: req.expires_at_sec,
    };
    Ok((entry, record))
}

fn enforce_server_kill_authority(
    ctx: &mut ServerKillExecCtx<'_>,
    limits: &OpsLimits,
    signers: &[VerifiedSigner],
    scope_key: &str,
    ttl: i64,
) -> Result<(), CodedError> {
    let req = ctx.req;
    if ttl <= 0 {
        return Err(CodedError::new(
            CODE_INVALID_INPUT,
            "kill command expiry must be in the future",
            "Set valid positive expiry.",
        ));
    }
    if req.target_stage == DeviceContainmentStage::Active {
        return Err(CodedError::new(
            CODE_INVALID_INPUT,
            "Active is passive baseline state; use Released to lift containment",
            "Specify Frozen, Isolated, Captured, Revoked, or Released.",
        ));
    }
    let existing = ctx.kill_state.entry_for_scope(&req.scope, ctx.now_sec);
    if existing.is_some_and(|e| e.dual_signed) && signers.len() < 2 {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "active dual-signed containment cannot be modified or released without dual signature",
            "Collect 2 distinct FIDO2 approver signatures.",
        ));
    }
    if req.target_stage != DeviceContainmentStage::Released
        && existing.is_some_and(|e| req.expires_at_sec < e.expires_at_sec)
    {
        return Err(CodedError::new(
            CODE_CONFLICT,
            "containment expiry cannot be truncated on active scope update",
            "Specify expires_at_sec >= active entry expiry.",
        ));
    }
    if signers.is_empty() {
        let auto_ok = matches!(
            req.scope,
            KillSwitchScope::Session(_) | KillSwitchScope::Device(_)
        ) && matches!(
            req.target_stage,
            DeviceContainmentStage::Frozen
                | DeviceContainmentStage::Captured
                | DeviceContainmentStage::Isolated
        ) && ttl <= limits.day_secs;
        if !auto_ok {
            return Err(CodedError::new(
                CODE_POLICY_STEP_UP,
                "deployment-signed server kill is restricted to session/device reversible containment <= 24h",
                "Collect hardware WebAuthn approver assertion(s).",
            ));
        }
        return Ok(());
    }

    let org_signers = signers
        .iter()
        .filter(|s| matches!(s.role, ApproverRole::OrgAdmin | ApproverRole::OrgResponder))
        .count();
    let provider_signers: Vec<&VerifiedSigner> = signers
        .iter()
        .filter(|s| s.role == ApproverRole::ProviderResponder)
        .collect();

    if !provider_signers.is_empty() {
        if ctx.roster.claimed_org
            && req.target_stage != DeviceContainmentStage::Frozen
            && org_signers == 0
        {
            return Err(CodedError::new(
                CODE_POLICY_STEP_UP,
                "provider responder action beyond reversible freeze requires claimed org co-signature (R-25)",
                "Obtain an organisation roster co-signature.",
            ));
        }
        let window_start = ctx.now_sec.saturating_sub(ONE_HOUR_SECS);
        ctx.provider_hourly_orgs.retain(|_, entries| {
            entries.retain(|(_, ts)| *ts >= window_start);
            !entries.is_empty()
        });
        for prov in &provider_signers {
            if !ctx.provider_hourly_orgs.contains_key(&prov.public_key_hex)
                && ctx.provider_hourly_orgs.len() >= limits.max_entries
            {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    "provider tracking table capacity reached",
                    "Wait for hourly provider tracking entries to expire.",
                ));
            }
            if let Some(hits) = ctx.provider_hourly_orgs.get(&prov.public_key_hex) {
                let distinct_orgs: BTreeSet<&str> = hits.iter().map(|(o, _)| o.as_str()).collect();
                if !distinct_orgs.contains(ctx.roster.org_id.as_str())
                    && distinct_orgs.len() >= PROVIDER_HOURLY_ORG_CAP
                {
                    return Err(CodedError::new(
                        CODE_CONFLICT,
                        "provider hourly 5-organisation containment limit reached",
                        "Escalate through organisation dual approval or wait out window.",
                    ));
                }
            }
        }
    }

    if req.target_stage == DeviceContainmentStage::Released {
        enforce_release_parity(ctx, signers, org_signers, &provider_signers)?;
        return commit_provider_org_hits(ctx, &provider_signers);
    }

    match &req.scope {
        KillSwitchScope::Provider(_) => {
            if provider_signers.len() < 2 {
                return Err(CodedError::new(
                    CODE_POLICY_STEP_UP,
                    "provider scope kill switch requires 2 distinct ProviderResponder approvers",
                    "Collect 2 ProviderResponder WebAuthn signatures (plus org co-sig beyond freeze).",
                ));
            }
        }
        KillSwitchScope::Organisation(_) => {
            if org_signers < 2 {
                return Err(CodedError::new(
                    CODE_POLICY_STEP_UP,
                    "organisation scope kill switch requires 2 distinct organisation approvers",
                    "Collect 2 OrgAdmin/OrgResponder WebAuthn signatures.",
                ));
            }
        }
        KillSwitchScope::Session(_) | KillSwitchScope::Device(_) => match req.target_stage {
            DeviceContainmentStage::Frozen => {
                enforce_freeze_signers(ctx, limits, signers, scope_key, ttl)?;
            }
            DeviceContainmentStage::Isolated | DeviceContainmentStage::Captured => {
                if signers.len() < 2 && ttl > limits.day_secs {
                    return Err(CodedError::new(
                        CODE_POLICY_STEP_UP,
                        "single-signer session/device containment > 24h requires 2 approvers",
                        "Collect 2 distinct FIDO2 approver signatures or cap TTL <= 24h.",
                    ));
                }
            }
            DeviceContainmentStage::Revoked => {
                if signers.len() < 2 {
                    return Err(CodedError::new(
                        CODE_POLICY_STEP_UP,
                        "revoke stage requires 2 distinct hardware-attested approvers",
                        "Collect 2 distinct FIDO2 approver signatures.",
                    ));
                }
            }
            DeviceContainmentStage::Active | DeviceContainmentStage::Released => {}
        },
        _ => match req.target_stage {
            DeviceContainmentStage::Frozen => {
                enforce_freeze_signers(ctx, limits, signers, scope_key, ttl)?;
            }
            _ => {
                if signers.len() < 2 {
                    return Err(CodedError::new(
                        CODE_POLICY_STEP_UP,
                        "fleet/artefact/agent/model containment requires 2 distinct approvers",
                        "Collect 2 distinct FIDO2 approver signatures.",
                    ));
                }
            }
        },
    }

    commit_provider_org_hits(ctx, &provider_signers)
}

fn enforce_freeze_signers(
    ctx: &ServerKillExecCtx<'_>,
    limits: &OpsLimits,
    signers: &[VerifiedSigner],
    scope_key: &str,
    ttl: i64,
) -> Result<(), CodedError> {
    if signers.len() >= 2 {
        return Ok(());
    }
    if ttl > LONE_FREEZE_MAX_SECS {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "single-signer freeze TTL must be <= 1 hour (3600s)",
            "Reduce TTL <= 3600s or obtain a second distinct approver signature.",
        ));
    }
    if let Some(single) = signers.first()
        && let Ok(fk) = serde_json::to_string(&(&ctx.req.org_id, &single.public_key_hex, scope_key))
        && ctx
            .freeze_by_key_scope
            .get(&fk)
            .is_some_and(|t| *t >= ctx.now_sec.saturating_sub(limits.day_secs))
    {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "same-key repeat freeze on scope within 24h requires second distinct approver",
            "Authenticate a second distinct approver.",
        ));
    }
    Ok(())
}

fn enforce_release_parity(
    ctx: &ServerKillExecCtx<'_>,
    signers: &[VerifiedSigner],
    org_signers: usize,
    provider_signers: &[&VerifiedSigner],
) -> Result<(), CodedError> {
    let existing = ctx.kill_state.entry_for_scope(&ctx.req.scope, ctx.now_sec);
    let was_dual_signed = existing.is_some_and(|entry| entry.dual_signed);
    let requires_dual = was_dual_signed
        || existing.is_some_and(|e| e.stage == DeviceContainmentStage::Revoked)
        || matches!(
            ctx.req.scope,
            KillSwitchScope::Organisation(_) | KillSwitchScope::Provider(_)
        );
    if requires_dual && signers.len() < 2 {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "releasing Revoked, org/provider, or dual-signed entry requires 2 distinct approvers",
            "Collect 2 distinct FIDO2 approver signatures for release.",
        ));
    }
    if matches!(ctx.req.scope, KillSwitchScope::Organisation(_)) && org_signers < 2 {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "releasing organisation containment requires 2 organisation approvers",
            "Collect 2 OrgAdmin/OrgResponder signatures.",
        ));
    }
    if matches!(ctx.req.scope, KillSwitchScope::Provider(_)) && provider_signers.len() < 2 {
        return Err(CodedError::new(
            CODE_POLICY_STEP_UP,
            "releasing provider containment requires 2 ProviderResponder approvers",
            "Collect 2 ProviderResponder signatures.",
        ));
    }
    Ok(())
}

fn commit_provider_org_hits(
    ctx: &mut ServerKillExecCtx<'_>,
    provider_signers: &[&VerifiedSigner],
) -> Result<(), CodedError> {
    for prov in provider_signers {
        ctx.provider_hourly_orgs
            .entry(prov.public_key_hex.clone())
            .or_default()
            .push((ctx.roster.org_id.clone(), ctx.now_sec));
    }
    Ok(())
}

fn scope_belongs_to_org(scope: &KillSwitchScope, org_id: &str) -> bool {
    match scope {
        KillSwitchScope::Organisation(target) => target == org_id,
        _ => true,
    }
}

#[must_use]
pub fn preview_response_capabilities(actuators: Vec<ActuatorCapPreview>) -> PreviewResponseResult {
    let forms: Vec<ActuatorDeliveryForm> = actuators.iter().map(|a| a.delivery_form).collect();
    PreviewResponseResult {
        rollup_form: compute_preview_rollup(&forms),
        actuators,
    }
}

pub(crate) fn record_server_approval_signal(
    kill_state: &mut GranularKillSwitchState,
    session_id: &str,
    signal: ApprovalOutcomeSignal,
) -> Result<bool, CodedError> {
    kill_state
        .record_approval_signal(session_id, signal)
        .map_err(|err| {
            CodedError::new(
                CODE_CONFLICT,
                format!("approval signal error: {err}"),
                "Verify session_id and embedded operational limits.",
            )
        })
}
