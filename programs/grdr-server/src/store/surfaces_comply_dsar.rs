// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    HoldsLedger, SubjectRequestExecution, SubjectRequestKind,
    SubjectRequestLifecycle as ComplySubjectLifecycle, format_utc_quarter,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ApprovalState, AuditEntry, CodedError};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;
use crate::store::surfaces_comply_helpers::comply_to_coded;
use crate::store::surfaces_comply_seed::ensure_compliance_seeded;
use crate::store::surfaces_types::{
    CollectionExclusionRecord, DisclosureRecord, SubjectReqRecord, SubjectRequestLifecycle,
};
use crate::store::{AppState, StoreData};

const REDACTED_SUBJECT_LABEL: &str = "[erased under GDPR Art. 17]";

struct ReadyPendingErasure {
    idx: usize,
    subject_ref: String,
    exec: SubjectRequestExecution,
}

impl AppState {
    // Awaits W5 proto/RPC surface exposure outside surfaces_comply* ownership.
    #[allow(dead_code)]
    pub async fn execute_server_subject_request(
        &self,
        kind: SubjectRequestKind,
        subject_ref: &str,
        auth: &AuthContext,
    ) -> Result<SubjectRequestExecution, CodedError> {
        let now = Timestamp::now();
        let trimmed = subject_ref.trim();
        if trimmed.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Subject reference cannot be empty.",
                "Provide a user identifier, email, or pseudonym.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let (pseudonyms, root_sessions) = collect_subject_targets(&guard, trimmed);
        let ledger = HoldsLedger {
            holds: guard
                .surfaces
                .compliance
                .as_ref()
                .map(|c| c.legal_holds.clone())
                .unwrap_or_default(),
        };
        let exec = grdr_comply::execute_subject_request(
            &auth.tenant_id,
            kind,
            trimmed,
            &pseudonyms,
            &root_sessions,
            &ledger,
            now,
        )
        .map_err(comply_to_coded)?;

        // Fail closed before mutating store state or recording Executed status.
        if let Some(ref cascade) = exec.erasure_cascade
            && self.storage.is_some()
        {
            let now_ms = now.as_millisecond();
            for sid in &cascade.destroyed_session_content_keys {
                self.erase_lake_session(sid, &exec.record.id, now_ms)?;
            }
        }

        let (status, hold_ids) = match &exec.record.lifecycle {
            ComplySubjectLifecycle::PendingHeld {
                hold_ids,
                disclose_hold,
            } => (
                SubjectRequestLifecycle::PendingHeld,
                if *disclose_hold {
                    hold_ids.clone()
                } else {
                    Vec::new()
                },
            ),
            ComplySubjectLifecycle::Submitted | ComplySubjectLifecycle::Fulfilled { .. } => {
                (SubjectRequestLifecycle::Executed, Vec::new())
            }
        };

        let is_executed_erasure =
            kind == SubjectRequestKind::Erasure && status == SubjectRequestLifecycle::Executed;
        let stored_subject_ref = if is_executed_erasure {
            "[erased]".to_owned()
        } else {
            sanitize_inert_text(&exec.record.subject_ref)
        };

        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.subject_requests.insert(
                0,
                SubjectReqRecord {
                    request_id: exec.record.id.clone(),
                    organisation: auth.tenant_id.clone(),
                    kind: format!("{kind:?}").to_ascii_lowercase(),
                    subject_ref: stored_subject_ref,
                    status,
                    hold_ids,
                    requested_at: now.to_string(),
                    detail: sanitize_inert_text(&exec.record.detail),
                },
            );
            for raw_entry in &exec.exclusion_added {
                let entry = sanitize_inert_text(raw_entry);
                let already = comp
                    .exclusions
                    .iter()
                    .any(|e| e.organisation == auth.tenant_id && e.entry == entry);
                if !already {
                    comp.exclusions.push(CollectionExclusionRecord {
                        organisation: auth.tenant_id.clone(),
                        request_id: exec.record.id.clone(),
                        entry,
                        recorded_at: now.to_string(),
                    });
                }
            }
        }

        if !exec.exclusion_added.is_empty() {
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "compliance.dsar.exclusion_recorded".to_owned(),
                    actor: auth.principal_id.clone(),
                    summary: format!(
                        "Recorded {} collection exclusion(s) under GDPR Art. 18/21",
                        exec.exclusion_added.len()
                    ),
                    target: exec.record.id.clone(),
                },
            );
        }

        if let Some(ref cascade) = exec.erasure_cascade {
            let scrubbed = apply_store_erasure_cascade(
                &mut guard,
                &auth.tenant_id,
                trimmed,
                &cascade.pseudonyms_unlinked,
                &cascade.destroyed_session_content_keys,
                &exec.record.id,
                now,
            );
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "compliance.dsar.erased".to_owned(),
                    actor: auth.principal_id.clone(),
                    summary: format!(
                        "GDPR Art. 17 erasure executed across {scrubbed} record(s) and {} session(s)",
                        cascade.destroyed_session_content_keys.len()
                    ),
                    target: exec.record.id.clone(),
                },
            );
        }

        self.persist_store(&guard)?;
        Ok(exec)
    }

    #[allow(dead_code)]
    pub async fn reprocess_held_erasures(&self, auth: &AuthContext) -> Result<usize, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let ledger = HoldsLedger {
            holds: guard
                .surfaces
                .compliance
                .as_ref()
                .map(|c| c.legal_holds.clone())
                .unwrap_or_default(),
        };
        self.reprocess_held_erasures_with_holds(&mut guard, &ledger, auth, now)
            .await
    }

    #[allow(dead_code)]
    pub(crate) async fn reprocess_held_erasures_with_holds(
        &self,
        guard: &mut StoreData,
        ledger: &HoldsLedger,
        auth: &AuthContext,
        now: Timestamp,
    ) -> Result<usize, CodedError> {
        let pending: Vec<(usize, String)> = guard
            .surfaces
            .compliance
            .as_ref()
            .map(|c| {
                c.subject_requests
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        r.organisation == auth.tenant_id
                            && r.kind == "erasure"
                            && r.status == SubjectRequestLifecycle::PendingHeld
                    })
                    .map(|(idx, r)| (idx, r.subject_ref.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let mut ready = Vec::new();
        for (idx, subject_ref) in pending {
            let (pseudonyms, root_sessions) = collect_subject_targets(guard, &subject_ref);
            let exec = grdr_comply::execute_subject_request(
                &auth.tenant_id,
                SubjectRequestKind::Erasure,
                &subject_ref,
                &pseudonyms,
                &root_sessions,
                ledger,
                now,
            )
            .map_err(comply_to_coded)?;
            if exec.erasure_cascade.is_some() {
                ready.push(ReadyPendingErasure {
                    idx,
                    subject_ref,
                    exec,
                });
            }
        }

        // Checkpoint each cleared request immediately after its lake DEKs are destroyed.
        let now_ms = now.as_millisecond();
        let mut executed_count = 0usize;
        for item in ready {
            let Some(cascade) = item.exec.erasure_cascade else {
                continue;
            };
            if self.storage.is_some() {
                for sid in &cascade.destroyed_session_content_keys {
                    self.erase_lake_session(sid, &item.exec.record.id, now_ms)?;
                }
            }
            let scrubbed = apply_store_erasure_cascade(
                guard,
                &auth.tenant_id,
                &item.subject_ref,
                &cascade.pseudonyms_unlinked,
                &cascade.destroyed_session_content_keys,
                &item.exec.record.id,
                now,
            );
            if let Some(ref mut comp) = guard.surfaces.compliance
                && let Some(rec) = comp.subject_requests.get_mut(item.idx)
            {
                rec.status = SubjectRequestLifecycle::Executed;
                rec.hold_ids.clear();
                rec.subject_ref = "[erased]".to_owned();
                rec.detail = sanitize_inert_text(&item.exec.record.detail);
            }
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "compliance.dsar.erased".to_owned(),
                    actor: auth.principal_id.clone(),
                    summary: format!(
                        "Post-hold GDPR Art. 17 erasure executed across {scrubbed} record(s) and {} session(s)",
                        cascade.destroyed_session_content_keys.len()
                    ),
                    target: item.exec.record.id,
                },
            );
            self.persist_store(guard)?;
            executed_count = executed_count.saturating_add(1);
        }
        Ok(executed_count)
    }
}

pub(crate) fn collect_subject_targets(
    data: &StoreData,
    subject_ref: &str,
) -> (Vec<String>, Vec<String>) {
    let target = subject_ref.trim();
    let mut user_ids = BTreeSet::new();
    let mut pseudonyms = BTreeSet::new();
    if target.starts_with("prn_") {
        pseudonyms.insert(target.to_owned());
    }
    for u in &data.user_directory {
        if u.id == target || u.email == target || u.pseudonym_id == target {
            user_ids.insert(u.id.clone());
            if !u.pseudonym_id.is_empty() {
                pseudonyms.insert(u.pseudonym_id.clone());
            }
        }
    }
    if user_ids.is_empty() && !target.is_empty() {
        user_ids.insert(target.to_owned());
    }

    let owned_devices: BTreeSet<&str> = data
        .devices
        .iter()
        .filter(|d| {
            d.user_id
                .as_deref()
                .is_some_and(|uid| user_ids.contains(uid))
        })
        .map(|d| d.id.as_str())
        .collect();

    let mut sessions = BTreeSet::new();
    for att in &data.attempts {
        if att
            .user_id
            .as_deref()
            .is_some_and(|uid| user_ids.contains(uid))
            || owned_devices.contains(att.device_id.as_str())
        {
            sessions.insert(att.session_id.clone());
        }
    }
    for apr in &data.approvals {
        if owned_devices.contains(apr.device_id.as_str()) {
            sessions.insert(apr.session_id.clone());
        }
    }
    for g in &data.grants {
        if owned_devices.contains(g.device_id.as_str()) {
            sessions.insert(g.session_id.clone());
        }
    }
    for rcp in &data.receipts {
        if owned_devices.contains(rcp.device_id.as_str()) {
            sessions.insert(rcp.session_id.clone());
        }
    }
    for f in &data.findings {
        if owned_devices.contains(f.device_id.as_str()) {
            sessions.insert(f.session_id.clone());
        }
    }

    (
        pseudonyms.into_iter().collect(),
        sessions.into_iter().collect(),
    )
}

pub(crate) fn apply_store_erasure_cascade(
    data: &mut StoreData,
    organisation: &str,
    subject_ref: &str,
    pseudonyms: &[String],
    sessions: &[String],
    req_id: &str,
    now: Timestamp,
) -> usize {
    let ps_set: BTreeSet<&str> = pseudonyms.iter().map(String::as_str).collect();
    let sess_set: BTreeSet<&str> = sessions.iter().map(String::as_str).collect();
    let target = subject_ref.trim();
    let uid_set: BTreeSet<String> = data
        .user_directory
        .iter()
        .filter(|u| u.id == target || u.email == target || ps_set.contains(u.pseudonym_id.as_str()))
        .map(|u| u.id.clone())
        .collect();

    let mut scrubbed = 0usize;
    let before_dir = data.user_directory.len();
    data.user_directory.retain(|u| {
        !(u.id == target || u.email == target || ps_set.contains(u.pseudonym_id.as_str()))
    });
    scrubbed = scrubbed.saturating_add(before_dir.saturating_sub(data.user_directory.len()));

    for dev in &mut data.devices {
        if dev
            .user_id
            .as_deref()
            .is_some_and(|uid| uid == target || uid_set.contains(uid))
        {
            dev.user_id = None;
            dev.user_display = None;
            scrubbed = scrubbed.saturating_add(1);
        }
        for art in &mut dev.artifacts {
            if art
                .user_id
                .as_deref()
                .is_some_and(|uid| uid == target || uid_set.contains(uid))
            {
                art.user_id = None;
                scrubbed = scrubbed.saturating_add(1);
            }
        }
    }
    for att in &mut data.attempts {
        let matched = sess_set.contains(att.session_id.as_str())
            || att
                .user_id
                .as_deref()
                .is_some_and(|uid| uid == target || uid_set.contains(uid));
        if matched {
            att.user_id = None;
            att.user_display = None;
            att.target = REDACTED_SUBJECT_LABEL.to_owned();
            att.summary = REDACTED_SUBJECT_LABEL.to_owned();
            scrubbed = scrubbed.saturating_add(1);
        }
    }
    for rcp in &mut data.receipts {
        if sess_set.contains(rcp.session_id.as_str()) {
            rcp.target = REDACTED_SUBJECT_LABEL.to_owned();
            rcp.reason = REDACTED_SUBJECT_LABEL.to_owned();
            rcp.next_step = REDACTED_SUBJECT_LABEL.to_owned();
            scrubbed = scrubbed.saturating_add(1);
        }
    }
    for apr in &mut data.approvals {
        if sess_set.contains(apr.session_id.as_str()) {
            apr.target = REDACTED_SUBJECT_LABEL.to_owned();
            apr.reason = REDACTED_SUBJECT_LABEL.to_owned();
            match &mut apr.state {
                ApprovalState::Approved { note, .. } | ApprovalState::Denied { note, .. } => {
                    *note = REDACTED_SUBJECT_LABEL.to_owned();
                }
                ApprovalState::Pending { .. } | ApprovalState::Expired { .. } => {}
            }
            scrubbed = scrubbed.saturating_add(1);
        }
    }
    for gr in &mut data.grants {
        if sess_set.contains(gr.session_id.as_str()) {
            gr.target_pattern = REDACTED_SUBJECT_LABEL.to_owned();
            gr.note = REDACTED_SUBJECT_LABEL.to_owned();
            scrubbed = scrubbed.saturating_add(1);
        }
    }
    for f in &mut data.findings {
        if sess_set.contains(f.session_id.as_str()) {
            f.title = REDACTED_SUBJECT_LABEL.to_owned();
            f.summary = REDACTED_SUBJECT_LABEL.to_owned();
            f.target = REDACTED_SUBJECT_LABEL.to_owned();
            scrubbed = scrubbed.saturating_add(1);
        }
    }
    if let Some(ref mut comp) = data.surfaces.compliance {
        for r in &mut comp.reid_requests {
            if r.organisation == organisation
                && (ps_set.contains(r.pseudonym_id.as_str()) || r.pseudonym_id == target)
            {
                r.resolved_identity = None;
                r.pseudonym_id = "[unlinked]".to_owned();
                scrubbed = scrubbed.saturating_add(1);
            }
        }
        for sr in &mut comp.subject_requests {
            let sr_ref = sr.subject_ref.trim();
            if sr.organisation == organisation
                && (sr_ref == target || ps_set.contains(sr_ref) || uid_set.contains(sr_ref))
            {
                sr.subject_ref = "[erased]".to_owned();
                scrubbed = scrubbed.saturating_add(1);
            }
        }
        comp.disclosures.insert(
            0,
            DisclosureRecord {
                id: format!("disc_{}", Uuid::now_v7().simple()),
                organisation: organisation.to_owned(),
                kind: "erasure".to_owned(),
                actor: "dsar-engine".to_owned(),
                target_ref: format!("request:{req_id}"),
                legal_basis: "GDPR Art. 17(3)(b)".to_owned(),
                timestamp: now.to_string(),
                quarter: format_utc_quarter(now),
                summary: format!(
                    "Unlinked {} pseudonym(s) and destroyed {} session key(s)",
                    pseudonyms.len(),
                    sessions.len()
                ),
            },
        );
    }
    scrubbed
}
