// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use grdr_model::error::{CODE_CONFLICT, CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_POLICY_DENIED};
use grdr_model::{
    AuditEntry, Finding, PolicyPack, PolicyRule, SignatureStatus, SigningKeypairExt as _,
    verify_pack,
};
use grdr_proto::common::{CollectionKind, ErrorClass};
use jiff::Timestamp;
use uuid::Uuid;

use crate::auth::{
    AuthContext, AuthPlane, ConfirmAssertion, PrincipalIdentity, ServerSecurityConfig,
    constant_time_eq,
};
use crate::connect_error::{ApiError, ApiErrorInner, ConnectCode};
use crate::store::AppState;

use super::diff::{is_reserved_base_pack, locked_rule_unchanged, validate_candidate_rule};
use super::types::EditAnywayRequest;

pub(crate) fn verify_second_approver(
    primary: &AuthContext,
    security: &ServerSecurityConfig,
    headers: &HeaderMap,
    req: &EditAnywayRequest,
) -> Result<PrincipalIdentity, ApiError> {
    let token = headers
        .get("x-grdr-second-approver-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            req.second_approver_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| {
            failed_precondition(
                "DUAL_APPROVER_REQUIRED",
                "EditAnyway requires a server-verifiable second human approver credential.",
            )
        })?;

    let second = resolve_second_principal(security, token).ok_or_else(|| {
        ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "INVALID_SECOND_APPROVER".into(),
            class: ErrorClass::Permission,
            message: "Second approver credential failed verification.".into(),
            fix: "Provide a valid tenant Console human token for the second approver.".into(),
            metadata: BTreeMap::new(),
        })
    })?;

    if second.tenant_id != primary.tenant_id || second.principal_id == primary.principal_id {
        return Err(failed_precondition(
            "DUAL_APPROVER_REQUIRED",
            "EditAnyway requires two distinct confirmed human approvers in the same tenant.",
        ));
    }
    if !req.second_approver_id.trim().is_empty()
        && req.second_approver_id.trim() != second.principal_id
    {
        return Err(failed_precondition(
            "SECOND_APPROVER_MISMATCH",
            "Verified second approver identity does not match declared secondApproverId.",
        ));
    }
    if second.principal_id.starts_with("agent:")
        || second.principal_id.starts_with("session:")
        || second
            .scopes
            .iter()
            .any(|s| s.starts_with("mcp:") || s == "agent:session")
    {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "AGENT_SESSION_PROPOSE_ONLY".into(),
            class: ErrorClass::Permission,
            message: "AgentSession or session principals cannot co-approve EditAnyway.".into(),
            fix: "Authenticate a second human approver.".into(),
            metadata: BTreeMap::new(),
        }));
    }
    let has_approve_scope = second
        .scopes
        .iter()
        .any(|s| s == "*" || s == "policy:*" || s == "policy:approve" || s == "policy:write");
    if !has_approve_scope {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "SECOND_APPROVER_MISSING_SCOPE".into(),
            class: ErrorClass::Permission,
            message: "Second approver lacks policy approval scope.".into(),
            fix: "Use a second human approver with `policy:approve` or `policy:write`.".into(),
            metadata: BTreeMap::new(),
        }));
    }

    let second_step_up_hdr = headers
        .get("x-grdr-second-approver-step-up")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            req.second_approver_step_up
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });
    let valid_step_up = second.assurance == ConfirmAssertion::StepUpVerified
        || (second_step_up_hdr.is_some()
            && security.step_up_token.as_deref().is_some_and(|exp| {
                !exp.is_empty() && second_step_up_hdr.is_some_and(|got| constant_time_eq(got, exp))
            }));
    if !valid_step_up {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::PermissionDenied,
            grdr_code: CODE_POLICY_DENIED.into(),
            reason: "STEP_UP_REQUIRED".into(),
            class: ErrorClass::Permission,
            message: "Second approver requires StepUpVerified confirmation.".into(),
            fix: "Supply second approver step-up proof or verified principal token.".into(),
            metadata: BTreeMap::new(),
        }));
    }
    Ok(second)
}

fn resolve_second_principal(
    security: &ServerSecurityConfig,
    token: &str,
) -> Option<PrincipalIdentity> {
    if security
        .operator_token
        .as_deref()
        .is_some_and(|op| constant_time_eq(token, op))
    {
        return None;
    }
    if let Some(api) = security.api_token.as_deref()
        && constant_time_eq(token, api)
    {
        return Some(PrincipalIdentity {
            principal_id: "console-admin".into(),
            tenant_id: "org-default".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::None,
        });
    }
    for (cand, id) in &security.principal_tokens {
        if id.plane == AuthPlane::Console && constant_time_eq(token, cand) {
            return Some(id.clone());
        }
    }
    None
}

pub(crate) fn verify_reconcile_packs(
    current_packs: &[PolicyPack],
    incoming_packs: &[PolicyPack],
    trusted_keys: &[grdr_model::TrustedKeyInfo],
) -> Result<(), ApiError> {
    let incoming_by_id: BTreeMap<&str, &PolicyPack> =
        incoming_packs.iter().map(|p| (p.id.as_str(), p)).collect();
    for pack in incoming_packs {
        if is_reserved_base_pack(&pack.id) {
            return Err(invalid_arg(
                "RESERVED_PACK_ID",
                "Bundle cannot target reserved `grdr.base` pack.",
            ));
        }
        if verify_pack(pack, trusted_keys) != SignatureStatus::Verified {
            return Err(ApiError::new(ApiErrorInner {
                code: ConnectCode::PermissionDenied,
                grdr_code: CODE_POLICY_DENIED.into(),
                reason: "UNTRUSTED_BUNDLE_SIGNATURE".into(),
                class: ErrorClass::Permission,
                message: format!(
                    "PolicyPack `{}` failed Ed25519 signature verification.",
                    pack.id
                ),
                fix:
                    "Export and reconcile a bundle signed by the trusted control plane signing key."
                        .into(),
                metadata: BTreeMap::new(),
            }));
        }
        for rule in &pack.rules {
            if let Err(msg) = validate_candidate_rule(&pack.id, rule) {
                return Err(invalid_arg(
                    "BUNDLE_LINT_FAILED",
                    &format!("{}: {msg}", rule.id),
                ));
            }
        }
    }
    for current in current_packs {
        let locked_rules: Vec<&PolicyRule> = current.rules.iter().filter(|r| r.locked).collect();
        if locked_rules.is_empty() {
            continue;
        }
        let Some(next_pack) = incoming_by_id.get(current.id.as_str()) else {
            return Err(failed_precondition(
                "LOCKED_PACK_MISSING",
                &format!("Locked baseline pack `{}` cannot be removed.", current.id),
            ));
        };
        let next_rules: BTreeMap<&str, &PolicyRule> =
            next_pack.rules.iter().map(|r| (r.id.as_str(), r)).collect();
        for locked in locked_rules {
            let Some(next_rule) = next_rules.get(locked.id.as_str()) else {
                return Err(failed_precondition(
                    "RULE_LOCKED",
                    &format!(
                        "Locked rule `{}` cannot be removed by reconcile.",
                        locked.id
                    ),
                ));
            };
            if !locked_rule_unchanged(locked, next_rule) {
                return Err(failed_precondition(
                    "RULE_LOCKED",
                    &format!(
                        "Locked rule `{}` cannot be modified by reconcile.",
                        locked.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub async fn apply_packs_to_store(
    app_state: &AppState,
    mut next_packs: Vec<PolicyPack>,
    actor: &str,
    summary: &str,
    drift_finding: Option<Finding>,
) {
    for pack in &mut next_packs {
        let _ = app_state.signing_key.sign_pack(pack);
    }
    let mut store = app_state.inner.write().await;
    store.packs = next_packs;
    if let Some(finding) = drift_finding {
        store.findings.insert(0, finding);
    }
    store.audit.insert(
        0,
        AuditEntry {
            id: format!("aud_{}", Uuid::now_v7().simple()),
            timestamp: Timestamp::now(),
            kind: "policy.gitops.applied".into(),
            actor: actor.to_owned(),
            summary: summary.to_owned(),
            target: "policy".into(),
        },
    );
    drop(store);
    app_state.bump_revision(CollectionKind::Packs);
    app_state.bump_revision(CollectionKind::AuditEvents);
    app_state.bump_revision(CollectionKind::Findings);
}

pub(crate) fn not_found_change(id: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::NotFound,
        grdr_code: CODE_NOT_FOUND.into(),
        reason: "POLICY_CHANGE_NOT_FOUND".into(),
        class: ErrorClass::NotFound,
        message: format!("PolicyChange `{id}` does not exist."),
        fix: "Verify policy change identifier.".into(),
        metadata: BTreeMap::new(),
    })
}

pub(crate) fn failed_precondition(reason: &str, message: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::FailedPrecondition,
        grdr_code: CODE_CONFLICT.into(),
        reason: reason.into(),
        class: ErrorClass::Conflict,
        message: message.into(),
        fix: "Satisfy precondition before retrying.".into(),
        metadata: BTreeMap::new(),
    })
}

pub(crate) fn invalid_arg(reason: &str, message: &str) -> ApiError {
    ApiError::invalid_argument(
        CODE_INVALID_INPUT,
        reason,
        message,
        "Check request fields and try again.",
    )
}
