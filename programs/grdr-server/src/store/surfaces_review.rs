// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_crypto::sha256_hex;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError, Mode, UpdateRuleModeInput, Verdict};
use grdr_proto::api::surfaces::{
    DecideReviewClusterRequest, ListReviewQueueResponse, ReviewCluster,
};
use grdr_proto::common::ReviewClusterStatus;
use grdr_review::{ChangeRisk, diff_policy_packs};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::surfaces_types::{ReviewDecisionOverride, ReviewDecisionState};
use super::surfaces_why::resolve_rule_meta;
use super::{AppState, StoreData};

struct ClusterAccum {
    id: String,
    bucket: &'static str,
    score: u32,
    rule_id: String,
    rule_title: String,
    observable_digest: String,
    agent_name: String,
    device_id: String,
    device_name: String,
    session_id: String,
    receipt_ref: String,
    occurrence_count: u32,
    latest_timestamp: Timestamp,
    target_preview: String,
    current_mode: Mode,
    suggested_mode: Mode,
    reason: String,
}

impl AppState {
    pub async fn list_review_queue(
        &self,
        tenant_id: &str,
        bucket_filter: &str,
        search: &str,
    ) -> ListReviewQueueResponse {
        let guard = self.inner.read().await;
        let clusters = build_review_clusters(&guard, tenant_id);

        let mut worth_a_look_count: u32 = 0;
        let mut routine_count: u32 = 0;
        let mut noise_count: u32 = 0;

        for c in &clusters {
            match c.bucket.as_str() {
                "worth_a_look" => worth_a_look_count = worth_a_look_count.saturating_add(1),
                "routine" => routine_count = routine_count.saturating_add(1),
                _ => noise_count = noise_count.saturating_add(1),
            }
        }

        let bucket_norm = bucket_filter.trim().to_ascii_lowercase();
        let search_norm = search.trim().to_ascii_lowercase();

        let filtered = clusters
            .into_iter()
            .filter(|c| bucket_norm.is_empty() || bucket_norm == "all" || c.bucket == bucket_norm)
            .filter(|c| {
                if search_norm.is_empty() {
                    return true;
                }
                c.rule_title.to_ascii_lowercase().contains(&search_norm)
                    || c.agent_name.to_ascii_lowercase().contains(&search_norm)
                    || c.target_preview.to_ascii_lowercase().contains(&search_norm)
                    || c.device_name.to_ascii_lowercase().contains(&search_norm)
            })
            .collect();

        ListReviewQueueResponse {
            clusters: filtered,
            worth_a_look_count,
            routine_count,
            noise_count,
            revision: None,
        }
    }

    pub async fn decide_review_cluster(
        &self,
        req: DecideReviewClusterRequest,
        auth: &AuthContext,
    ) -> Result<ReviewCluster, CodedError> {
        let cluster_id = req.id.trim();
        if cluster_id.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Review cluster identifier must not be empty.",
                "Select a lineage cluster from Review Queue.",
            ));
        }

        let decision_norm = req.decision.trim().to_ascii_lowercase();
        let target_state = match decision_norm.as_str() {
            "promote" => ReviewDecisionState::Promoted,
            "suppress" => ReviewDecisionState::Suppressed,
            "dismiss" => ReviewDecisionState::Dismissed,
            "escalate" => ReviewDecisionState::Escalated,
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unsupported review decision `{decision_norm}`."),
                    "Choose promote, suppress, dismiss, or escalate.",
                ));
            }
        };

        let (existing, rule_record) = {
            let guard = self.inner.read().await;
            let cluster = build_review_clusters(&guard, &auth.tenant_id)
                .into_iter()
                .find(|c| c.id == cluster_id)
                .ok_or_else(|| {
                    CodedError::new(
                        CODE_NOT_FOUND,
                        format!("Review cluster `{cluster_id}` was not found."),
                        "Refresh Review Queue and retry.",
                    )
                })?;
            let found_rule = guard
                .packs
                .iter()
                .flat_map(|p| p.rules.iter())
                .find(|r| r.id == cluster.rule_id)
                .cloned();
            (cluster, found_rule)
        };

        if target_state == ReviewDecisionState::Promoted {
            let requested_mode_raw = req
                .target_mode
                .as_deref()
                .unwrap_or(&existing.suggested_mode);
            let next_mode = parse_mode(requested_mode_raw)?;
            let Some(rule) = rule_record else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    format!(
                        "Cluster rule `{}` is not registered in an editable policy pack.",
                        existing.rule_id
                    ),
                    "Create or select an editable rule before promoting via Review Queue.",
                ));
            };
            if rule.locked {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!(
                        "Locked baseline floor rule `{}` cannot be modified via Review Queue.",
                        rule.id
                    ),
                    "Use policy exceptions or create a scoped rule instead.",
                ));
            }
            if mode_rank(next_mode) < mode_rank(rule.mode) && !auth.confirmation.is_step_up() {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!(
                        "Weakening rule `{}` from {} to {} requires step-up verification.",
                        rule.id,
                        rule.mode.label(),
                        next_mode.label()
                    ),
                    "Supply a valid X-Grdr-Step-Up credential or StepUpVerified principal before weakening.",
                ));
            }
            let replay = self.replay_rule(&existing.rule_id, next_mode).await?;
            let replay_verified = replay.total_scanned > 0 || auth.confirmation.is_step_up();
            if !replay_verified && next_mode == Mode::Block {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    "Promotion to Block requires recorded replay impact or step-up authorization.",
                    "Run rule replay against recent observations before promoting to Block.",
                ));
            }
            let _ = self
                .update_rule_mode(
                    &existing.rule_id,
                    UpdateRuleModeInput {
                        mode: next_mode,
                        replay_confirmed: Some(replay_verified),
                        actor: Some(auth.principal_id.clone()),
                    },
                )
                .await?;
        }

        let now = Timestamp::now();
        let actor = auth.principal_id.clone();
        let note = sanitize_inert_text(req.note.as_deref().unwrap_or(&decision_norm));

        let mut guard = self.inner.write().await;
        guard.surfaces.review_overrides.insert(
            review_override_key(&auth.tenant_id, cluster_id),
            ReviewDecisionOverride {
                status: target_state,
                note: note.clone(),
                updated_at: now.to_string(),
            },
        );
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_rev_{}", sha256_prefix(&format!("{cluster_id}:{now}"))),
                timestamp: now,
                kind: format!("review.{decision_norm}"),
                actor,
                summary: format!(
                    "Review cluster `{}` ({}) marked {}",
                    existing.rule_title, existing.observable_digest, decision_norm
                ),
                target: existing.rule_id.clone(),
            },
        );
        self.persist_store(&guard)?;

        let updated = build_review_clusters(&guard, &auth.tenant_id)
            .into_iter()
            .find(|c| c.id == cluster_id)
            .unwrap_or(existing);
        drop(guard);

        self.emit_live(
            "policy.changed",
            format!("Review triage applied on {}", updated.rule_id),
            None,
        );
        Ok(updated)
    }
}

fn mode_rank(mode: Mode) -> u8 {
    match mode {
        Mode::Off => 0,
        Mode::Watch => 1,
        Mode::Ask => 2,
        Mode::Block => 3,
    }
}

fn review_override_key(tenant_id: &str, cluster_id: &str) -> String {
    format!("{tenant_id}::{cluster_id}")
}

fn build_review_clusters(data: &StoreData, tenant_id: &str) -> Vec<ReviewCluster> {
    let mut rules_by_id = BTreeMap::new();
    for pack in &data.packs {
        for rule in &pack.rules {
            rules_by_id.insert(rule.id.as_str(), rule);
        }
    }
    let attempt_by_id: BTreeMap<&str, _> =
        data.attempts.iter().map(|a| (a.id.as_str(), a)).collect();

    let mut groups: BTreeMap<String, ClusterAccum> = BTreeMap::new();

    for receipt in &data.receipts {
        let Some(attempt) = attempt_by_id.get(receipt.attempt_id.as_str()) else {
            continue;
        };
        let rule_id = receipt
            .rule_id
            .as_deref()
            .unwrap_or("essentials.baseline-activity");
        let rule_meta = rules_by_id.get(rule_id).copied();
        let (_, rule_title) = resolve_rule_meta(data, rule_id, receipt.verdict);
        let current_mode = receipt
            .mode_applied
            .or_else(|| rule_meta.map(|r| r.mode))
            .unwrap_or(Mode::Watch);

        let target_norm = sanitize_inert_text(&attempt.target);
        let key = format!("{rule_id}::{}::{target_norm}", attempt.agent_name);
        let digest = sha256_prefix(&key);

        let (bucket, base_score, suggested_mode) = match receipt.verdict {
            Verdict::Deny => ("worth_a_look", 92_u32, Mode::Block),
            Verdict::StepUp | Verdict::Modify | Verdict::Defer => {
                ("worth_a_look", 78_u32, Mode::Ask)
            }
            Verdict::Allow if receipt.mode_applied == Some(Mode::Watch) => {
                ("worth_a_look", 74_u32, Mode::Ask)
            }
            Verdict::Allow if receipt.rule_id.is_some() => ("routine", 42_u32, current_mode),
            Verdict::Allow => ("noise", 14_u32, Mode::Off),
        };

        let entry = groups.entry(key).or_insert_with(|| ClusterAccum {
            id: format!("rev-{digest}"),
            bucket,
            score: base_score,
            rule_id: rule_id.to_owned(),
            rule_title,
            observable_digest: digest,
            agent_name: sanitize_inert_text(&attempt.agent_name),
            device_id: attempt.device_id.clone(),
            device_name: sanitize_inert_text(&attempt.device_name),
            session_id: attempt.session_id.clone(),
            receipt_ref: receipt.receipt_id.clone(),
            occurrence_count: 0,
            latest_timestamp: receipt.decided_at,
            target_preview: target_norm.clone(),
            current_mode,
            suggested_mode,
            reason: sanitize_inert_text(&receipt.reason),
        });

        entry.occurrence_count = entry.occurrence_count.saturating_add(1);
        if receipt.decided_at >= entry.latest_timestamp {
            entry.latest_timestamp = receipt.decided_at;
            entry.receipt_ref = receipt.receipt_id.clone();
        }
        entry.score = entry.score.max(base_score).saturating_add(2).min(99);
    }

    let base_pack = data.packs.first();
    let mut out: Vec<ReviewCluster> = groups
        .into_values()
        .map(|acc| {
            let risk_label = assess_suggestion_risk(base_pack, &acc.rule_id, acc.suggested_mode);
            let override_entry = data
                .surfaces
                .review_overrides
                .get(&review_override_key(tenant_id, &acc.id));
            let status_enum = override_entry
                .map(|o| match o.status {
                    ReviewDecisionState::Open => ReviewClusterStatus::Open,
                    ReviewDecisionState::Promoted => ReviewClusterStatus::Promoted,
                    ReviewDecisionState::Suppressed => ReviewClusterStatus::Suppressed,
                    ReviewDecisionState::Dismissed => ReviewClusterStatus::Dismissed,
                    ReviewDecisionState::Escalated => ReviewClusterStatus::Escalated,
                })
                .unwrap_or(ReviewClusterStatus::Open);

            ReviewCluster {
                id: acc.id,
                bucket: acc.bucket.to_owned(),
                score: acc.score,
                rule_id: acc.rule_id,
                rule_title: acc.rule_title,
                observable_digest: acc.observable_digest,
                agent_name: acc.agent_name,
                device_id: acc.device_id,
                device_name: acc.device_name,
                session_id: acc.session_id,
                receipt_ref: acc.receipt_ref,
                occurrence_count: acc.occurrence_count,
                latest_timestamp: acc.latest_timestamp.to_string(),
                target_preview: acc.target_preview,
                current_mode: mode_str(acc.current_mode).to_owned(),
                suggested_mode: mode_str(acc.suggested_mode).to_owned(),
                risk_label,
                status: status_enum as i32,
                reason: acc.reason,
                note: override_entry.map(|o| o.note.clone()).unwrap_or_default(),
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.occurrence_count.cmp(&a.occurrence_count))
    });
    out
}

fn assess_suggestion_risk(
    base_pack: Option<&grdr_model::PolicyPack>,
    rule_id: &str,
    suggested: Mode,
) -> String {
    let Some(base) = base_pack else {
        return "Neutral".to_owned();
    };
    let mut candidate = base.clone();
    if let Some(rule) = candidate.rules.iter_mut().find(|r| r.id == rule_id) {
        rule.mode = suggested;
    } else {
        return "Neutral".to_owned();
    }
    match diff_policy_packs(base, &candidate) {
        Ok(diff) => match diff.overall_risk {
            ChangeRisk::FloorViolation => "Floor locked".to_owned(),
            ChangeRisk::Widening => "Step-up approval required".to_owned(),
            ChangeRisk::Narrowing => "Tightening change".to_owned(),
            ChangeRisk::Neutral => "Neutral".to_owned(),
        },
        Err(_) => "Review required".to_owned(),
    }
}

fn parse_mode(raw: &str) -> Result<Mode, CodedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(Mode::Off),
        "watch" => Ok(Mode::Watch),
        "ask" => Ok(Mode::Ask),
        "block" => Ok(Mode::Block),
        _ => Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("Invalid target mode `{raw}`."),
            "Use off, watch, ask, or block.",
        )),
    }
}

fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "off",
        Mode::Watch => "watch",
        Mode::Ask => "ask",
        Mode::Block => "block",
    }
}

fn sha256_prefix(seed: &str) -> String {
    sha256_hex(seed.as_bytes()).chars().take(12).collect()
}
