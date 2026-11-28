// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::Arc;

use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_POLICY_DENIED};
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::routes::rest::limits::rest_limits;
use crate::routes::rest::rate_limit::{
    RateDecision, RateLimitConfig, TenantRateLimiter, TrafficClass,
};
use crate::store::AppState;

use super::super::gitops::{CreatePolicyChangeRequest, GitopsStore, PolicyChangeState};
use super::secrecy::{is_self_lineage, self_lineage_err, wrap_untrusted_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProposalKind {
    PolicyChange,
    Suppression,
    TriageDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum McpProposalState {
    AwaitingApproval,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpProposalRecord {
    pub id: String,
    pub tenant_id: String,
    pub proposer_id: String,
    pub kind: McpProposalKind,
    pub state: McpProposalState,
    pub title: Value,
    pub summary: Value,
    pub linked_policy_change_id: Option<String>,
    pub requires_human_approval: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct McpProposalStore {
    proposals: Arc<RwLock<BTreeMap<String, McpProposalRecord>>>,
    read_limiter: TenantRateLimiter,
    propose_limiter: TenantRateLimiter,
}

impl Default for McpProposalStore {
    fn default() -> Self {
        let limits = rest_limits();
        Self {
            proposals: Arc::new(RwLock::new(BTreeMap::new())),
            read_limiter: TenantRateLimiter::new(RateLimitConfig {
                window_seconds: limits.rate_limit_window_secs,
                default_limit: limits.mcp_read_limit_per_min,
            }),
            propose_limiter: TenantRateLimiter::new(RateLimitConfig {
                window_seconds: limits.mcp_propose_window_secs,
                default_limit: limits.mcp_propose_limit_per_hour,
            }),
        }
    }
}

impl McpProposalStore {
    pub async fn check_tool_quota(&self, auth: &AuthContext, is_proposal: bool) -> RateDecision {
        if is_proposal {
            self.propose_limiter
                .check(&auth.tenant_id, &auth.principal_id, TrafficClass::Critical)
                .await
        } else {
            self.read_limiter
                .check(&auth.tenant_id, &auth.principal_id, TrafficClass::Critical)
                .await
        }
    }

    pub async fn propose_policy_change(
        &self,
        app_state: &AppState,
        gitops: &GitopsStore,
        auth: &AuthContext,
        req: CreatePolicyChangeRequest,
    ) -> Result<McpProposalRecord, ApiError> {
        // Mask diff/lock/existence oracle errors uniformly so probing rules fails opaquely (23-22).
        let draft = gitops
            .create_change(auth, req, true)
            .await
            .map_err(mask_policy_oracle_err)?;
        let checked = gitops
            .check_change(app_state, auth, &draft.id)
            .await
            .map_err(mask_policy_oracle_err)?;
        let final_change =
            if checked.state == PolicyChangeState::Checked && checked.check_errors.is_empty() {
                let _ = gitops
                    .simulate_change(app_state, auth, &draft.id)
                    .await
                    .map_err(mask_policy_oracle_err)?;
                gitops
                    .apply_change(app_state, auth, &draft.id)
                    .await
                    .map_err(mask_policy_oracle_err)?
            } else {
                return Err(masked_policy_oracle_err());
            };

        let prop_id = format!("prop_{}", Uuid::now_v7().simple());
        // Redact rule IDs, modes, and lock layers from MCP diff/error oracle responses (23-22).
        let diff_entries = final_change
            .diff
            .as_ref()
            .map(|d| {
                d.entries
                    .iter()
                    .map(|e| {
                        json!({
                            "changeKind": e.change_kind,
                            "effect": format!("{:?}", e.effect),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let redacted_errors: Vec<Value> = final_change
            .check_errors
            .iter()
            .map(|_| {
                wrap_untrusted_text(
                    "policy.validation",
                    "Candidate policy change failed validation.",
                )
            })
            .collect();

        let rec = McpProposalRecord {
            id: prop_id.clone(),
            tenant_id: auth.tenant_id.clone(),
            proposer_id: auth.principal_id.clone(),
            kind: McpProposalKind::PolicyChange,
            state: McpProposalState::AwaitingApproval,
            title: wrap_untrusted_text("mcp.title", &final_change.title),
            summary: json!({
                "policyChangeState": format!("{:?}", final_change.state),
                "diffEntries": diff_entries,
                "hasValidationErrors": !final_change.check_errors.is_empty(),
                "checkErrors": redacted_errors,
                "replaySummary": final_change.replay_summary,
            }),
            linked_policy_change_id: Some(final_change.id),
            requires_human_approval: true,
            created_at: Timestamp::now().to_string(),
        };
        self.insert_bounded(prop_id, rec.clone()).await?;
        Ok(rec)
    }

    pub async fn propose_suppression(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        finding_id: String,
        scope: String,
        rationale: String,
    ) -> Result<McpProposalRecord, ApiError> {
        if finding_id.trim().is_empty() || rationale.trim().is_empty() {
            return Err(ApiError::invalid_argument(
                CODE_INVALID_INPUT,
                "INVALID_PROPOSAL",
                "finding_id and rationale are required.",
                "Provide finding_id and rationale.",
            ));
        }
        ensure_finding_not_self_lineage(app_state, auth, &finding_id).await?;
        let prop_id = format!("prop_{}", Uuid::now_v7().simple());
        let rec = McpProposalRecord {
            id: prop_id.clone(),
            tenant_id: auth.tenant_id.clone(),
            proposer_id: auth.principal_id.clone(),
            kind: McpProposalKind::Suppression,
            state: McpProposalState::AwaitingApproval,
            title: wrap_untrusted_text("mcp.title", &format!("Suppress finding {finding_id}")),
            summary: json!({
                "findingId": wrap_untrusted_text("mcp.finding_id", &finding_id),
                "scope": wrap_untrusted_text("mcp.scope", &scope),
                "rationale": wrap_untrusted_text("mcp.rationale", &rationale),
            }),
            linked_policy_change_id: None,
            requires_human_approval: true,
            created_at: Timestamp::now().to_string(),
        };
        self.insert_bounded(prop_id, rec.clone()).await?;
        Ok(rec)
    }

    pub async fn propose_triage_decision(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        finding_id: String,
        lifecycle: String,
        note: String,
    ) -> Result<McpProposalRecord, ApiError> {
        if finding_id.trim().is_empty() || lifecycle.trim().is_empty() {
            return Err(ApiError::invalid_argument(
                CODE_INVALID_INPUT,
                "INVALID_PROPOSAL",
                "finding_id and lifecycle are required.",
                "Provide finding_id and target lifecycle.",
            ));
        }
        ensure_finding_not_self_lineage(app_state, auth, &finding_id).await?;
        let prop_id = format!("prop_{}", Uuid::now_v7().simple());
        let rec = McpProposalRecord {
            id: prop_id.clone(),
            tenant_id: auth.tenant_id.clone(),
            proposer_id: auth.principal_id.clone(),
            kind: McpProposalKind::TriageDecision,
            state: McpProposalState::AwaitingApproval,
            title: wrap_untrusted_text(
                "mcp.title",
                &format!("Triage finding {finding_id} -> {lifecycle}"),
            ),
            summary: json!({
                "findingId": wrap_untrusted_text("mcp.finding_id", &finding_id),
                "proposedLifecycle": wrap_untrusted_text("mcp.lifecycle", &lifecycle),
                "note": wrap_untrusted_text("mcp.note", &note),
            }),
            linked_policy_change_id: None,
            requires_human_approval: true,
            created_at: Timestamp::now().to_string(),
        };
        self.insert_bounded(prop_id, rec.clone()).await?;
        Ok(rec)
    }

    pub async fn get_proposal(
        &self,
        gitops: &GitopsStore,
        auth: &AuthContext,
        id: &str,
    ) -> Result<McpProposalRecord, ApiError> {
        let mut rec = self
            .proposals
            .read()
            .await
            .get(id)
            .filter(|p| p.tenant_id == auth.tenant_id && p.proposer_id == auth.principal_id)
            .cloned()
            .ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_NOT_FOUND,
                    "PROPOSAL_NOT_FOUND",
                    format!("Proposal `{id}` does not exist for caller."),
                    "Verify proposal ID and proposer identity.",
                )
            })?;
        if let Some(chg_id) = &rec.linked_policy_change_id
            && let Ok(chg) = gitops.get_change(auth, chg_id).await
        {
            rec.state = match chg.state {
                PolicyChangeState::Applied | PolicyChangeState::RollingOut => {
                    McpProposalState::Approved
                }
                PolicyChangeState::Denied | PolicyChangeState::Superseded => {
                    McpProposalState::Denied
                }
                _ => McpProposalState::AwaitingApproval,
            };
        }
        Ok(rec)
    }

    async fn insert_bounded(
        &self,
        prop_id: String,
        rec: McpProposalRecord,
    ) -> Result<(), ApiError> {
        let max_items = rest_limits().max_store_items.max(1);
        let mut guard = self.proposals.write().await;
        if guard.len() >= max_items {
            let terminal = guard
                .iter()
                .find(|(_, p)| p.state != McpProposalState::AwaitingApproval)
                .map(|(k, _)| k.clone());
            if let Some(evict) = terminal {
                guard.remove(&evict);
            } else {
                return Err(ApiError::new(ApiErrorInner {
                    code: ConnectCode::FailedPrecondition,
                    grdr_code: CODE_POLICY_DENIED.into(),
                    reason: "PROPOSAL_LIMIT_EXCEEDED".into(),
                    class: ErrorClass::RateLimit,
                    message: "MCP proposal store capacity reached.".into(),
                    fix: "Wait for pending proposals to be reviewed.".into(),
                    metadata: BTreeMap::new(),
                }));
            }
        }
        guard.insert(prop_id, rec);
        Ok(())
    }
}

async fn ensure_finding_not_self_lineage(
    app_state: &AppState,
    auth: &AuthContext,
    finding_id: &str,
) -> Result<(), ApiError> {
    let guard = app_state.inner.read().await;
    if let Some(finding) = guard.findings.iter().find(|f| f.id == finding_id)
        && is_self_lineage(auth, Some(&finding.session_id), Some(&finding.agent_name))
    {
        return Err(self_lineage_err());
    }
    Ok(())
}

fn masked_policy_oracle_err() -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: CODE_POLICY_DENIED.into(),
        reason: "POLICY_PROPOSAL_REJECTED".into(),
        class: ErrorClass::Permission,
        message: "Candidate policy change proposal could not be staged.".into(),
        fix: "Submit an unlocked candidate policy proposal or contact a human policy admin.".into(),
        metadata: BTreeMap::new(),
    })
}

fn mask_policy_oracle_err(_err: ApiError) -> ApiError {
    masked_policy_oracle_err()
}
