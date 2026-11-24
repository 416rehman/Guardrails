// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;

use grdr_model::proto_conv::{
    browser_policy_to_proto, pack_to_proto, proto_to_approval_grade, proto_to_mode,
    proto_to_rule_match, replay_to_proto, rule_to_proto,
};
use grdr_model::{
    CreateRuleInput, UpdateBrowserAppPolicyInput, UpdateRuleInput, UpdateRuleModeInput,
};
use grdr_proto::api::policy::{
    CreateRuleRequest, CreateRuleResponse, DeleteRuleRequest, DeleteRuleResponse,
    ListBrowserPoliciesRequest, ListBrowserPoliciesResponse, ListPacksRequest, ListPacksResponse,
    ReplayRuleRequest, ReplayRuleResponse, UpdateBrowserPolicyRequest, UpdateBrowserPolicyResponse,
    UpdateRuleModeRequest, UpdateRuleModeResponse, UpdateRuleRequest, UpdateRuleResponse,
};
use grdr_proto::common::CollectionKind;

use crate::connect_error::{ApiError, CODE_API_BAD_REQUEST};
use crate::rpc::{revision_for, run_rpc};
use crate::store::AppState;

pub async fn list_packs(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/ListPacks",
        state,
        request,
        |state, _req: ListPacksRequest| async move {
            let rev = revision_for(&state, CollectionKind::Packs, "packs");
            let guard = state.inner.read().await;
            let packs = guard.packs.iter().map(pack_to_proto).collect();
            Ok((
                ListPacksResponse {
                    packs,
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn create_rule(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/CreateRule",
        state,
        request,
        |state, req: CreateRuleRequest| async move {
            let mode = proto_to_mode(req.mode).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_MODE",
                    "Missing or invalid enforcement mode.",
                    "Supply Off, Watch, Ask, or Block.",
                )
            })?;
            let matcher = req
                .matcher
                .map(proto_to_rule_match)
                .transpose()
                .map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_MATCHER",
                        msg,
                        "Ensure matcher action classes are valid.",
                    )
                })?
                .ok_or_else(|| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_MATCHER",
                        "Rule matcher is required.",
                        "Provide matcher conditions.",
                    )
                })?;
            let rule = state
                .create_rule(CreateRuleInput {
                    pack_id: req.pack_id,
                    title: req.title,
                    description: req.description,
                    mode,
                    min_grade: req.min_grade.and_then(proto_to_approval_grade),
                    matcher,
                    reason_template: req.reason_template,
                    cedar: req.cedar,
                })
                .await?;
            state.bump_revision(CollectionKind::Packs);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                CreateRuleResponse {
                    rule: Some(rule_to_proto(&rule)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn update_rule(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateRule",
        state,
        request,
        |state, req: UpdateRuleRequest| async move {
            let matcher = req
                .matcher
                .map(proto_to_rule_match)
                .transpose()
                .map_err(|msg| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_MATCHER",
                        msg,
                        "Ensure matcher action classes are valid.",
                    )
                })?;
            let rule = state
                .update_rule(
                    &req.id,
                    UpdateRuleInput {
                        title: req.title,
                        description: req.description,
                        mode: req.mode.and_then(proto_to_mode),
                        min_grade: req.min_grade.and_then(proto_to_approval_grade),
                        matcher,
                        reason_template: req.reason_template,
                        cedar: req.cedar,
                        actor: req.actor,
                    },
                )
                .await?;
            state.bump_revision(CollectionKind::Packs);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdateRuleResponse {
                    rule: Some(rule_to_proto(&rule)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn delete_rule(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/DeleteRule",
        state,
        request,
        |state, req: DeleteRuleRequest| async move {
            state.delete_rule(&req.id).await?;
            state.bump_revision(CollectionKind::Packs);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((DeleteRuleResponse {}, None))
        },
    )
    .await
}

pub async fn update_rule_mode(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateRuleMode",
        state,
        request,
        |state, req: UpdateRuleModeRequest| async move {
            let mode = proto_to_mode(req.mode).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_MODE",
                    "Missing or invalid enforcement mode.",
                    "Supply Off, Watch, Ask, or Block.",
                )
            })?;
            let rule = state
                .update_rule_mode(
                    &req.id,
                    UpdateRuleModeInput {
                        mode,
                        actor: req.actor,
                        replay_confirmed: req.replay_confirmed,
                    },
                )
                .await?;
            state.bump_revision(CollectionKind::Packs);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdateRuleModeResponse {
                    rule: Some(rule_to_proto(&rule)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn replay_rule(State(state): State<AppState>, request: Request<Body>) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/ReplayRule",
        state,
        request,
        |state, req: ReplayRuleRequest| async move {
            let candidate_mode = proto_to_mode(req.candidate_mode).ok_or_else(|| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_MODE",
                    "Missing or invalid candidate_mode.",
                    "Supply Off, Watch, Ask, or Block.",
                )
            })?;
            let summary = state.replay_rule(&req.id, candidate_mode).await?;
            Ok((
                ReplayRuleResponse {
                    summary: Some(replay_to_proto(&summary)),
                },
                None,
            ))
        },
    )
    .await
}

pub async fn list_browser_policies(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/ListBrowserPolicies",
        state,
        request,
        |state, _req: ListBrowserPoliciesRequest| async move {
            let rev = revision_for(&state, CollectionKind::BrowserPolicies, "browser_policies");
            let policies = state
                .list_browser_policies()
                .await
                .iter()
                .map(browser_policy_to_proto)
                .collect();
            Ok((
                ListBrowserPoliciesResponse {
                    policies,
                    revision: Some(rev.clone()),
                },
                Some(rev),
            ))
        },
    )
    .await
}

pub async fn update_browser_policy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    run_rpc(
        "/grdr.api.policy.v1alpha1.PolicyService/UpdateBrowserPolicy",
        state,
        request,
        |state, req: UpdateBrowserPolicyRequest| async move {
            let updated = state
                .update_browser_policy(
                    &req.id,
                    UpdateBrowserAppPolicyInput {
                        mode: req.mode.and_then(proto_to_mode),
                        block_file_uploads: req.block_file_uploads,
                        block_secret_paste: req.block_secret_paste,
                        managed_extension_only: req.managed_extension_only,
                    },
                )
                .await?;
            state.bump_revision(CollectionKind::BrowserPolicies);
            state.bump_revision(CollectionKind::AuditEvents);
            Ok((
                UpdateBrowserPolicyResponse {
                    policy: Some(browser_policy_to_proto(&updated)),
                },
                None,
            ))
        },
    )
    .await
}
