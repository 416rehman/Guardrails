// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Persisted per-org granular kill switch, server response actuators, triage/incident grouping,
//! hunts, and ticketing sync (`docs/design/18`).

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_core::detect::response::{
    ActiveKillEntry, ApprovalOutcomeSignal, GranularKillSwitchState, KillSwitchScope,
};
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_UNAUTHORIZED};
use grdr_model::{AuditEntry, CodedError, Finding, FindingLifecycle};
use grdr_review::queue::ReviewCandidate;
use grdr_review::verifier::ExtendedReviewSignals;

use crate::store::AppState;
use crate::store::surfaces_respond_hunts::{
    ExternalTicketLink, HuntExecutionRecord, HuntQueryRequest, SavedHuntRecord, SigmaPredicate,
    TicketEditRequest, TicketSyncManifest, TicketSyncOutcome, converge_ticket_edit, current_ms,
    run_hunt_over_store,
};
use crate::store::surfaces_respond_ops::{
    ServerKillExecCtx, ServerResponseActionRecord, SignedServerKillRequest,
    execute_signed_kill_on_server, record_server_approval_signal,
};
use crate::store::surfaces_respond_playbooks::{
    PlaybookPromotionProof, PlaybookRunJournal, SoarPlaybookSpec,
};
use crate::store::surfaces_respond_store::{
    operational_caps, push_bounded, validate_respond_snapshot,
};
use crate::store::surfaces_respond_triage::{
    FindingSuppression, RespondIncident, TriageSessionEntry, classify_and_enqueue_session,
    group_finding_into_incident, worth_a_look_within_cap,
};
use crate::store::surfaces_respond_webauthn::{
    ApproverRole, ApproverRosterState, WebAuthnReplayState, WebAuthnStepUpAssertion,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RespondOperationsState {
    pub rosters: BTreeMap<String, ApproverRosterState>,
    pub kill_states_by_org: BTreeMap<String, GranularKillSwitchState>,
    #[serde(default)]
    pub replay_state: WebAuthnReplayState,
    pub provider_hourly_orgs: BTreeMap<String, Vec<(String, i64)>>,
    pub freeze_by_key_scope: BTreeMap<String, i64>,
    #[serde(default)]
    pub session_orgs: BTreeMap<String, String>,
    #[serde(default)]
    pub device_orgs: BTreeMap<String, String>,
    pub response_actions: Vec<ServerResponseActionRecord>,
    pub incidents: Vec<RespondIncident>,
    pub triage_queue: Vec<TriageSessionEntry>,
    pub suppressions: Vec<FindingSuppression>,
    pub ticket_manifests: Vec<TicketSyncManifest>,
    pub ticket_links: Vec<ExternalTicketLink>,
    pub saved_hunts: Vec<SavedHuntRecord>,
    pub hunt_runs: Vec<HuntExecutionRecord>,
    pub playbooks: Vec<SoarPlaybookSpec>,
    #[serde(default)]
    pub playbook_simulate_started: BTreeMap<String, i64>,
    #[serde(default)]
    pub playbook_promotions: BTreeMap<String, PlaybookPromotionProof>,
    pub playbook_runs: Vec<PlaybookRunJournal>,
}

pub struct RunHuntRequest<'a> {
    pub run_id: &'a str,
    pub org_id: &'a str,
    pub sql: Option<&'a str>,
    pub sigma: &'a [SigmaPredicate],
    pub include_content: bool,
    pub retro: bool,
    pub now_sec: i64,
}

pub struct SyncTicketRequest<'a> {
    pub org_id: &'a str,
    pub incident_id: &'a str,
    pub vendor_id: &'a str,
    pub external_ticket_id: &'a str,
    pub vendor_state: &'a str,
    pub sync_origin: &'a str,
    pub revision: u64,
    pub raw_summary: &'a str,
}

impl RespondOperationsState {
    /// Validates restored kill-switch snapshots, approver rosters, and collection bounds upon startup.
    pub fn validate_on_restore(&self) -> Result<(), CodedError> {
        validate_respond_snapshot(self)
    }

    pub fn register_tenant_binding(
        &mut self,
        org_id: &str,
        session_id: Option<&str>,
        device_id: Option<&str>,
    ) -> Result<(), CodedError> {
        if org_id.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "tenant binding requires non-empty org_id",
                "Authenticate owning organisation.",
            ));
        }
        let (max_entries, _) = operational_caps()?;
        let clean_sid = session_id.filter(|s| !s.trim().is_empty());
        let clean_did = device_id.filter(|d| !d.trim().is_empty());
        if let Some(sid) = clean_sid {
            if self.session_orgs.get(sid).is_some_and(|o| o != org_id) {
                return Err(CodedError::new(
                    CODE_UNAUTHORIZED,
                    "session_id already bound to a different organisation",
                    "Refuse cross-tenant session reassignment.",
                ));
            }
            if !self.session_orgs.contains_key(sid) && self.session_orgs.len() >= max_entries {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    "session tenant binding capacity reached",
                    "Prune stale tenant bindings before registering new sessions.",
                ));
            }
        }
        if let Some(did) = clean_did {
            if self.device_orgs.get(did).is_some_and(|o| o != org_id) {
                return Err(CodedError::new(
                    CODE_UNAUTHORIZED,
                    "device_id already bound to a different organisation",
                    "Refuse cross-tenant device reassignment.",
                ));
            }
            if !self.device_orgs.contains_key(did) && self.device_orgs.len() >= max_entries {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    "device tenant binding capacity reached",
                    "Prune stale tenant bindings before registering new devices.",
                ));
            }
        }
        if let Some(sid) = clean_sid {
            self.session_orgs.insert(sid.to_owned(), org_id.to_owned());
        }
        if let Some(did) = clean_did {
            self.device_orgs.insert(did.to_owned(), org_id.to_owned());
        }
        Ok(())
    }

    /// Groups Open findings deterministically within a 24h window and enforces tenant binding.
    pub fn group_finding_into_incident(
        &mut self,
        org_id: &str,
        artefact_or_rule_key: &str,
        finding: &Finding,
        now_sec: i64,
    ) -> Option<&RespondIncident> {
        if org_id.trim().is_empty()
            || artefact_or_rule_key.trim().is_empty()
            || finding.id.trim().is_empty()
            || finding.session_id.trim().is_empty()
            || finding.lifecycle != FindingLifecycle::Open
        {
            return None;
        }
        self.register_tenant_binding(org_id, Some(&finding.session_id), Some(&finding.device_id))
            .ok()?;
        group_finding_into_incident(
            &mut self.incidents,
            org_id,
            artefact_or_rule_key,
            finding,
            now_sec,
        )
    }

    /// Evaluates triage priority bucket with 0.2% HMAC sample and analyst canary routing.
    pub fn classify_and_enqueue_session(
        &mut self,
        org_id: &str,
        candidate: &ReviewCandidate,
        ext: &ExtendedReviewSignals,
        sample_key: &[u8; 32],
        is_canary: bool,
        has_deterministic_threat_or_tamper: bool,
    ) -> Result<TriageSessionEntry, CodedError> {
        self.register_tenant_binding(org_id, Some(&candidate.session_id), None)?;
        Ok(classify_and_enqueue_session(
            &mut self.triage_queue,
            org_id,
            candidate,
            ext,
            sample_key,
            is_canary,
            has_deterministic_threat_or_tamper,
        ))
    }

    #[must_use]
    pub fn worth_a_look_within_cap(&self) -> bool {
        worth_a_look_within_cap(&self.triage_queue)
    }
}

impl AppState {
    pub async fn respond_register_roster(
        &self,
        roster: ApproverRosterState,
        quorum_min: usize,
        rotation_assertions: Vec<WebAuthnStepUpAssertion>,
    ) -> Result<String, CodedError> {
        let mut guard = self.inner.write().await;
        let prev = guard.respond.rosters.get(&roster.org_id).cloned();
        roster.validate_registration_or_rotation(
            prev.as_ref(),
            quorum_min,
            &rotation_assertions,
            &mut guard.respond.replay_state,
        )?;
        let digest = roster.digest_sha256()?;
        let org = roster.org_id.clone();
        guard.respond.rosters.insert(org.clone(), roster);
        guard.audit.insert(
            0,
            build_audit(
                "roster.updated",
                &org,
                &format!("Roster updated ({digest})"),
            ),
        );
        self.persist_store(&guard)?;
        Ok(digest)
    }

    pub async fn respond_revoke_provider_delegation(
        &self,
        org_id: &str,
        approver_assertions: Vec<WebAuthnStepUpAssertion>,
        quorum_min: usize,
    ) -> Result<ApproverRosterState, CodedError> {
        let mut guard = self.inner.write().await;
        let prev = guard
            .respond
            .rosters
            .get(org_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    "org roster not found",
                    "Register roster first.",
                )
            })?
            .clone();
        let next_entries = prev
            .entries
            .iter()
            .filter(|e| e.role != ApproverRole::ProviderResponder)
            .cloned()
            .collect();
        let next = ApproverRosterState {
            version: prev.version.saturating_add(1),
            org_id: prev.org_id.clone(),
            claimed_org: prev.claimed_org,
            rp_id: prev.rp_id.clone(),
            origin: prev.origin.clone(),
            prev_digest_sha256: prev.digest_sha256()?,
            provider_delegated: false,
            entries: next_entries,
        };
        next.validate_registration_or_rotation(
            Some(&prev),
            quorum_min,
            &approver_assertions,
            &mut guard.respond.replay_state,
        )?;
        guard
            .respond
            .rosters
            .insert(org_id.to_owned(), next.clone());
        guard.audit.insert(
            0,
            build_audit(
                "provider_delegation.revoked",
                org_id,
                "Provider responder delegation revoked",
            ),
        );
        self.persist_store(&guard)?;
        Ok(next)
    }

    pub async fn respond_execute_kill_command(
        &self,
        req: SignedServerKillRequest,
        now_sec: i64,
    ) -> Result<ActiveKillEntry, CodedError> {
        let mut guard = self.inner.write().await;
        let roster = guard
            .respond
            .rosters
            .get(&req.org_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    "org roster not found",
                    "Register roster first.",
                )
            })?
            .clone();
        let deploy_pk = self.signing_key.public_key_b64();
        let org_id = req.org_id.clone();
        let (entry, rec) = {
            let respond = &mut guard.respond;
            let mut ks = respond
                .kill_states_by_org
                .get(&org_id)
                .cloned()
                .unwrap_or_default();
            let mut replay = respond.replay_state.clone();
            let mut prov_hits = respond.provider_hourly_orgs.clone();
            let mut freeze_map = respond.freeze_by_key_scope.clone();
            let res = execute_signed_kill_on_server(ServerKillExecCtx {
                roster: &roster,
                kill_state: &mut ks,
                replay_state: &mut replay,
                provider_hourly_orgs: &mut prov_hits,
                freeze_by_key_scope: &mut freeze_map,
                deployment_public_key_b64: &deploy_pk,
                req: &req,
                now_sec,
            })?;
            respond.kill_states_by_org.insert(org_id.clone(), ks);
            respond.replay_state = replay;
            respond.provider_hourly_orgs = prov_hits;
            respond.freeze_by_key_scope = freeze_map;
            res
        };
        let (max_actions, _) = operational_caps()?;
        push_bounded(&mut guard.respond.response_actions, rec, max_actions);
        guard.audit.insert(
            0,
            build_audit(
                "response.action",
                &org_id,
                &format!(
                    "Containment {:?} executed for {:?}",
                    entry.stage, entry.scope
                ),
            ),
        );
        self.persist_store(&guard)?;
        self.emit_live(
            "response.action",
            format!("Response containment {:?} persisted", entry.stage),
            None,
        );
        Ok(entry)
    }

    pub async fn respond_is_scope_blocked(
        &self,
        org_id: &str,
        scopes: &[KillSwitchScope],
        now_sec: i64,
    ) -> Option<ActiveKillEntry> {
        let guard = self.inner.read().await;
        guard
            .respond
            .kill_states_by_org
            .get(org_id)
            .and_then(|ks| ks.matches_scopes(scopes, now_sec))
            .cloned()
    }

    pub async fn respond_record_approval_signal(
        &self,
        org_id: &str,
        session_id: &str,
        signal: ApprovalOutcomeSignal,
    ) -> Result<bool, CodedError> {
        if org_id.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "approval signal requires org_id",
                "Authenticate tenant organisation.",
            ));
        }
        let mut guard = self.inner.write().await;
        let ks = guard
            .respond
            .kill_states_by_org
            .entry(org_id.to_owned())
            .or_default();
        let should_freeze = record_server_approval_signal(ks, session_id, signal)?;
        self.persist_store(&guard)?;
        Ok(should_freeze)
    }

    pub async fn respond_run_hunt(
        &self,
        req: RunHuntRequest<'_>,
    ) -> Result<HuntExecutionRecord, CodedError> {
        let mut guard = self.inner.write().await;
        let exec = run_hunt_over_store(HuntQueryRequest {
            run_id: req.run_id,
            org_id: req.org_id,
            sql: req.sql,
            sigma_clauses: req.sigma,
            include_content: req.include_content,
            retro: req.retro,
            now_sec: req.now_sec,
            session_orgs: &guard.respond.session_orgs,
            device_orgs: &guard.respond.device_orgs,
            attempts: &guard.attempts,
            receipts: &guard.receipts,
            findings: &guard.findings,
            responses: &guard.respond.response_actions,
        })?;
        let (_, max_runs) = operational_caps()?;
        push_bounded(&mut guard.respond.hunt_runs, exec.clone(), max_runs);
        self.persist_store(&guard)?;
        Ok(exec)
    }

    pub async fn respond_sync_ticket(
        &self,
        req: SyncTicketRequest<'_>,
    ) -> Result<TicketSyncOutcome, CodedError> {
        let (max_links, _) = operational_caps()?;
        let mut guard = self.inner.write().await;
        let respond = &mut guard.respond;
        let outcome = converge_ticket_edit(
            &mut respond.ticket_links,
            &respond.ticket_manifests,
            TicketEditRequest {
                org_id: req.org_id,
                incident_id: req.incident_id,
                vendor_id: req.vendor_id,
                external_ticket_id: req.external_ticket_id,
                vendor_state: req.vendor_state,
                sync_origin: req.sync_origin,
                revision: req.revision,
                raw_summary: req.raw_summary,
                now_ms: current_ms(),
            },
        )?;
        if respond.ticket_links.len() > max_links {
            let excess = respond.ticket_links.len().saturating_sub(max_links);
            respond.ticket_links.drain(..excess);
        }
        self.persist_store(&guard)?;
        Ok(outcome)
    }
}

fn build_audit(kind: &str, target: &str, summary: &str) -> AuditEntry {
    AuditEntry {
        id: format!("aud_{}", Uuid::now_v7().simple()),
        timestamp: Timestamp::now(),
        kind: kind.to_owned(),
        actor: "respond-control".to_owned(),
        summary: summary.to_owned(),
        target: target.to_owned(),
    }
}
