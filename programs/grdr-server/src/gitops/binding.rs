// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use grdr_model::error::CODE_POLICY_DENIED;
use grdr_model::{Finding, FindingClass, FindingLifecycle, FindingSeverity};
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;
use uuid::Uuid;

use crate::auth::{AuthContext, ConfirmAssertion, ServerSecurityConfig};
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::store::AppState;

pub(crate) use super::binding_verify::{
    apply_packs_to_store, failed_precondition, invalid_arg, not_found_change,
    verify_reconcile_packs, verify_second_approver,
};
use super::diff::{compute_effective_hash, compute_policy_diff};
use super::store::GitopsStore;
use super::types::{
    DriftStatus, EditAnywayRequest, GitopsBinding, GitopsBundle, GitopsSourceKind,
    ReconcileBundleRequest, UpsertGitopsBindingRequest,
};

impl GitopsStore {
    pub async fn get_binding(&self, app_state: &AppState, auth: &AuthContext) -> GitopsBinding {
        let packs = app_state.inner.read().await.packs.clone();
        let actual = compute_effective_hash(&packs);
        let mut guard = self.inner.write().await;
        let binding = guard.bindings.entry(auth.tenant_id.clone()).or_default();
        binding.actual_effective_hash = actual;
        binding.clone()
    }

    pub async fn upsert_binding(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        req: UpsertGitopsBindingRequest,
    ) -> Result<GitopsBinding, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(failed_precondition(
                "AGENT_SESSION_PROPOSE_ONLY",
                "AgentSession cannot modify GitOps bindings.",
            ));
        }
        {
            let guard = self.inner.read().await;
            let currently_locked = guard
                .bindings
                .get(&auth.tenant_id)
                .is_some_and(|b| b.source != GitopsSourceKind::None);
            if currently_locked
                && req.source == GitopsSourceKind::None
                && !auth.confirmation.is_step_up()
            {
                return Err(ApiError::new(ApiErrorInner {
                    code: ConnectCode::PermissionDenied,
                    grdr_code: CODE_POLICY_DENIED.into(),
                    reason: "STEP_UP_REQUIRED".into(),
                    class: ErrorClass::Permission,
                    message: "Disabling GitOps lock requires step-up authentication.".into(),
                    fix: "Provide a verified step-up token via X-Grdr-Step-Up.".into(),
                    metadata: BTreeMap::new(),
                }));
            }
        }

        let packs = app_state.inner.read().await.packs.clone();
        let actual = compute_effective_hash(&packs);
        let now = Timestamp::now().to_string();
        let expected = if req.expected_effective_hash.trim().is_empty() {
            actual.clone()
        } else {
            req.expected_effective_hash
        };
        let drift = if req.source != GitopsSourceKind::None && expected != actual {
            DriftStatus::Drifted
        } else {
            DriftStatus::InSync
        };
        let next = GitopsBinding {
            source: req.source,
            repo_url: req.repo_url,
            branch: req.branch,
            path: req.path,
            drift_status: drift,
            expected_effective_hash: expected,
            actual_effective_hash: actual,
            locked_by: auth.principal_id.clone(),
            last_reconciled_at: Some(now.clone()),
            updated_at: now,
            edit_anyway_approvers: Vec::new(),
        };
        let mut guard = self.inner.write().await;
        guard.bindings.insert(auth.tenant_id.clone(), next.clone());
        Ok(next)
    }

    pub async fn edit_anyway(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        security: &ServerSecurityConfig,
        headers: &HeaderMap,
        req: EditAnywayRequest,
    ) -> Result<GitopsBinding, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "AGENT_SESSION_PROPOSE_ONLY".into(),
                class: ErrorClass::Permission,
                message: "AgentSession cannot perform dual-approver edit-anyway.".into(),
                fix: "Require two human operators.".into(),
                metadata: BTreeMap::new(),
            }));
        }
        if auth.confirmation != ConfirmAssertion::StepUpVerified {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "STEP_UP_REQUIRED".into(),
                class: ErrorClass::Permission,
                message: "Primary approver must hold StepUpVerified assurance for EditAnyway."
                    .into(),
                fix: "Authenticate primary approver with step-up confirmation.".into(),
                metadata: BTreeMap::new(),
            }));
        }

        let second = verify_second_approver(auth, security, headers, &req)?;
        let current_packs = app_state.inner.read().await.packs.clone();
        let (diff, candidate_packs, errors) = compute_policy_diff(&current_packs, &req.operations)?;
        if !errors.is_empty() {
            return Err(invalid_arg("CHECK_FAILED", &errors.join("; ")));
        }
        apply_packs_to_store(
            app_state,
            candidate_packs,
            &auth.principal_id,
            &format!("GitOps EditAnyway bypass: {}", req.reason),
            Some(Finding {
                id: format!("fnd_{}", Uuid::now_v7().simple()),
                session_id: "gitops-drift".into(),
                device_id: "control-plane".into(),
                device_name: "gitops".into(),
                agent_name: "gitops".into(),
                class: FindingClass::Tamper,
                finding_class_other: None,
                severity: FindingSeverity::High,
                lifecycle: FindingLifecycle::Open,
                rule_id: None,
                title: "GitOps policy drift detected (EditAnyway)".into(),
                summary: req.reason,
                target: diff.effective_hash_after.clone(),
                detected_at: Timestamp::now(),
            }),
        )
        .await;

        let mut guard = self.inner.write().await;
        let binding = guard.bindings.entry(auth.tenant_id.clone()).or_default();
        binding.drift_status = DriftStatus::Drifted;
        binding.actual_effective_hash = diff.effective_hash_after;
        binding.updated_at = Timestamp::now().to_string();
        binding.edit_anyway_approvers = vec![auth.principal_id.clone(), second.principal_id];
        Ok(binding.clone())
    }

    pub async fn export_bundle(&self, app_state: &AppState, auth: &AuthContext) -> GitopsBundle {
        let packs = app_state.inner.read().await.packs.clone();
        let effective_hash = compute_effective_hash(&packs);
        let source_ref = self
            .inner
            .read()
            .await
            .bindings
            .get(&auth.tenant_id)
            .map(|b| b.branch.clone())
            .unwrap_or_default();
        GitopsBundle {
            schema: "grdr.gitops-bundle.v1alpha1".into(),
            effective_hash,
            source_ref,
            packs,
        }
    }

    pub async fn reconcile_bundle(
        &self,
        app_state: &AppState,
        auth: &AuthContext,
        req: ReconcileBundleRequest,
    ) -> Result<GitopsBinding, ApiError> {
        if Self::is_agent_lineage(auth) {
            return Err(failed_precondition(
                "AGENT_SESSION_PROPOSE_ONLY",
                "AgentSession cannot reconcile GitOps bundles.",
            ));
        }
        if !auth.confirmation.is_confirmed() {
            return Err(failed_precondition(
                "CONFIRMATION_REQUIRED",
                "Explicit confirmation is required to reconcile a GitOps bundle.",
            ));
        }
        if req.bundle.packs.is_empty() {
            return Err(invalid_arg(
                "EMPTY_BUNDLE",
                "GitopsBundle must include at least one policy pack.",
            ));
        }
        let computed = compute_effective_hash(&req.bundle.packs);
        if req.bundle.effective_hash.trim().is_empty() || req.bundle.effective_hash != computed {
            return Err(invalid_arg(
                "BUNDLE_HASH_MISMATCH",
                "Supplied GitopsBundle effectiveHash is missing or mismatches canonical pack hash.",
            ));
        }

        let trusted_keys = app_state.trusted_keys();
        let current_packs = app_state.inner.read().await.packs.clone();
        verify_reconcile_packs(&current_packs, &req.bundle.packs, &trusted_keys)?;

        apply_packs_to_store(
            app_state,
            req.bundle.packs,
            &auth.principal_id,
            &format!("Reconciled GitOps bundle {}", req.bundle.source_ref),
            None,
        )
        .await;

        let now = Timestamp::now().to_string();
        let mut guard = self.inner.write().await;
        let binding = guard.bindings.entry(auth.tenant_id.clone()).or_default();
        binding.expected_effective_hash = computed.clone();
        binding.actual_effective_hash = computed;
        binding.drift_status = DriftStatus::InSync;
        binding.last_reconciled_at = Some(now.clone());
        binding.updated_at = now;
        Ok(binding.clone())
    }
}
