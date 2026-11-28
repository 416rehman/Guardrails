// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::auth::{AuthPlane, ConfirmAssertion, PrincipalIdentity, ServerSecurityConfig};
use crate::routes;
use crate::store::{AppState, StorageBackend};

fn test_security() -> ServerSecurityConfig {
    let mut tokens = BTreeMap::new();
    tokens.insert(
        "human-admin".into(),
        PrincipalIdentity {
            principal_id: "alice".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::StepUpVerified,
        },
    );
    tokens.insert(
        "human-reviewer".into(),
        PrincipalIdentity {
            principal_id: "carol".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::StepUpVerified,
        },
    );
    tokens.insert(
        "human-normal".into(),
        PrincipalIdentity {
            principal_id: "bob".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::ConfirmedIntent,
        },
    );
    tokens.insert(
        "org2-admin".into(),
        PrincipalIdentity {
            principal_id: "dave".into(),
            tenant_id: "org-2".into(),
            plane: AuthPlane::Console,
            scopes: vec!["*".into()],
            assurance: ConfirmAssertion::StepUpVerified,
        },
    );
    tokens.insert(
        "agent-tok".into(),
        PrincipalIdentity {
            principal_id: "agent:triage".into(),
            tenant_id: "org-1".into(),
            plane: AuthPlane::Console,
            scopes: vec!["mcp:read".into(), "mcp:propose".into()],
            assurance: ConfirmAssertion::ConfirmedIntent,
        },
    );
    ServerSecurityConfig {
        api_token: Some("console-fallback".into()),
        step_up_token: Some("step-up-secret".into()),
        principal_tokens: tokens,
        ..Default::default()
    }
}

async fn send_req(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    idem: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-grdr-confirm", "confirmed");
    if let Some(k) = idem {
        builder = builder.header("idempotency-key", k);
    }
    let bytes = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            serde_json::to_vec(&v).unwrap()
        }
        None => Vec::new(),
    };
    let req = builder.body(Body::from(bytes)).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let out = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_val: Value = serde_json::from_slice(&out).unwrap_or_else(|_| json!({}));
    (status, json_val)
}

#[tokio::test]
async fn policy_change_narrowing_autostarts_while_widening_and_agent_require_human_approval() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_console_router_with_security(state, None, test_security());

    // 1. Human narrowing change (new Watch rule) checks, simulates via SQLite jobs, and auto-rolls out.
    let (st, created) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-1"),
        Some(json!({
            "title": "Watch suspicious curl",
            "operations": [{
                "kind": "upsert_rule",
                "pack_id": "pack-essentials-slice0",
                "id": "custom.watch_curl",
                "title": "Watch curl",
                "description": "Audit curl exec",
                "mode": "watch",
                "matcher": {
                    "action_classes": ["exec"],
                    "target_prefixes": [],
                    "target_contains": ["curl "],
                    "agents": []
                },
                "reason_template": "curl observed"
            }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let chg_id = created["change"]["id"].as_str().unwrap().to_owned();

    let (st_chk, checked) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{chg_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(st_chk, StatusCode::OK);
    assert_eq!(checked["change"]["state"], "CHECKED");
    assert_eq!(checked["change"]["diff"]["isWidening"], false);

    let (st_sim, simulated) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{chg_id}:simulate"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(st_sim, StatusCode::OK);
    assert!(simulated["change"]["simulationJobId"].as_str().is_some());
    assert!(simulated["change"]["replaySummary"].is_object());

    let job_id = simulated["change"]["simulationJobId"].as_str().unwrap();
    let (st_op, op) = send_req(
        &app,
        "GET",
        &format!("/v1/operations/{job_id}"),
        "human-admin",
        None,
        None,
    )
    .await;
    assert_eq!(st_op, StatusCode::OK);
    assert!(op["operation"]["id"].as_str().is_some());

    let (st_app, applied) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{chg_id}:apply"),
        "human-admin",
        Some("idem-pc-apply-1"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_app, StatusCode::OK);
    assert_eq!(applied["change"]["state"], "ROLLING_OUT");

    // 2. Widening change waits in AWAITING_APPROVAL and demands step-up confirmation to approve.
    let (st_w, w_created) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-2"),
        Some(json!({
            "title": "Relax credential stores rule to Off",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "off"
            }]
        })),
    )
    .await;
    assert_eq!(st_w, StatusCode::OK);
    let widen_id = w_created["change"]["id"].as_str().unwrap().to_owned();

    let (st_wa, w_applied) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_id}:apply"),
        "human-admin",
        Some("idem-pc-apply-2"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_wa, StatusCode::OK);
    assert_eq!(w_applied["change"]["state"], "AWAITING_APPROVAL");
    assert_eq!(w_applied["change"]["diff"]["isWidening"], true);

    // Non-step-up human approval fails; agent self-approval fails; proposer self-approval fails.
    let (st_agent_app, _) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_id}:approve"),
        "agent-tok",
        Some("idem-pc-app-agent"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_agent_app, StatusCode::FORBIDDEN);

    let (st_self, self_err) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_id}:approve"),
        "human-admin",
        Some("idem-pc-app-self"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_self, StatusCode::FORBIDDEN);
    assert_eq!(
        self_err["details"][0]["debug"]["reason"],
        "PROPOSER_SELF_APPROVAL_FORBIDDEN"
    );

    let (st_nostep, _) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_id}:approve"),
        "human-normal",
        Some("idem-pc-app-nostep"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_nostep, StatusCode::FORBIDDEN);

    let (st_ok, approved) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_id}:approve"),
        "human-reviewer",
        Some("idem-pc-app-ok"),
        Some(json!({ "note": "step-up approved" })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK);
    assert_eq!(approved["change"]["state"], "APPLIED");
}

#[tokio::test]
async fn gitops_lock_blocks_direct_writes_supports_dual_approver_edit_anyway_and_reconciles() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_console_router_with_security(state, None, test_security());

    let (st_b, bound) = send_req(
        &app,
        "PUT",
        "/v1/gitops-binding",
        "human-admin",
        Some("idem-bind-1"),
        Some(json!({
            "source": "git",
            "repoUrl": "https://git.example/security-policy",
            "branch": "main",
            "path": "packs/"
        })),
    )
    .await;
    assert_eq!(st_b, StatusCode::OK);
    assert_eq!(bound["binding"]["driftStatus"], "IN_SYNC");

    // Direct REST rule creation fails closed with GITOPS_LOCKED (412).
    let (st_rest, err_rest) = send_req(
        &app,
        "POST",
        "/v1/rules",
        "human-admin",
        Some("idem-lock-1"),
        Some(json!({
            "title": "Blocked UI rule",
            "description": "must fail",
            "mode": "MODE_WATCH",
            "reasonTemplate": "blocked",
            "matcher": { "actionClasses": ["ACTION_CLASS_EXEC"] }
        })),
    )
    .await;
    assert_eq!(st_rest, StatusCode::PRECONDITION_FAILED);
    assert_eq!(err_rest["details"][0]["debug"]["reason"], "GITOPS_LOCKED");

    // Direct Connect PolicyService/CreateRule ALSO fails closed with GITOPS_LOCKED!
    let (st_rpc, err_rpc) = send_req(
        &app,
        "POST",
        "/grdr.api.policy.v1alpha1.PolicyService/CreateRule",
        "human-admin",
        None,
        Some(json!({
            "title": "Blocked RPC rule",
            "description": "must fail",
            "mode": "MODE_WATCH",
            "reasonTemplate": "blocked",
            "matcher": { "actionClasses": ["ACTION_CLASS_EXEC"] }
        })),
    )
    .await;
    assert_eq!(st_rpc, StatusCode::PRECONDITION_FAILED);
    assert_eq!(err_rpc["details"][0]["debug"]["reason"], "GITOPS_LOCKED");

    // Export current bundle before drift bypass so we can reconcile back later.
    let (st_exp, bundle_doc) =
        send_req(&app, "GET", "/v1/gitops-bundle", "human-admin", None, None).await;
    assert_eq!(st_exp, StatusCode::OK);

    // Single-approver or unverified EditAnyway JSON is rejected.
    let (st_single, _) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:edit-anyway",
        "human-admin",
        Some("idem-ea-1"),
        Some(json!({
            "reason": "emergency",
            "secondApproverId": "bob",
            "secondApproverConfirmed": true,
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "watch"
            }]
        })),
    )
    .await;
    assert_eq!(st_single, StatusCode::PRECONDITION_FAILED);

    // Agent token or non-step-up second approver token cannot co-approve EditAnyway.
    let (st_ea_agent, _) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:edit-anyway",
        "human-admin",
        Some("idem-ea-agent"),
        Some(json!({
            "reason": "emergency",
            "secondApproverToken": "agent-tok",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "watch"
            }]
        })),
    )
    .await;
    assert_eq!(st_ea_agent, StatusCode::FORBIDDEN);

    let (st_ea_nostep, _) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:edit-anyway",
        "human-admin",
        Some("idem-ea-nostep"),
        Some(json!({
            "reason": "emergency",
            "secondApproverToken": "human-normal",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "watch"
            }]
        })),
    )
    .await;
    assert_eq!(st_ea_nostep, StatusCode::FORBIDDEN);

    // Dual StepUpVerified human approver EditAnyway succeeds, marks DRIFTED, and emits a drift finding.
    let (st_ea, drifted) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:edit-anyway",
        "human-admin",
        Some("idem-ea-2"),
        Some(json!({
            "reason": "emergency break-glass",
            "secondApproverId": "carol",
            "secondApproverToken": "human-reviewer",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "watch"
            }]
        })),
    )
    .await;
    assert_eq!(st_ea, StatusCode::OK);
    assert_eq!(drifted["binding"]["driftStatus"], "DRIFTED");

    // Tampered bundle hash rejected (400), and matching hash with unsigned pack rejected (403).
    let mut bad_bundle_hash = bundle_doc.clone();
    bad_bundle_hash["packs"][0]["signature"] = json!(null);
    let (st_bad_hash, _) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:reconcile",
        "human-admin",
        Some("idem-rec-bad-hash"),
        Some(json!({ "bundle": bad_bundle_hash })),
    )
    .await;
    assert_eq!(st_bad_hash, StatusCode::BAD_REQUEST);

    let mut bad_bundle_sig = bad_bundle_hash;
    let unsigned_packs: Vec<grdr_model::PolicyPack> =
        serde_json::from_value(bad_bundle_sig["packs"].clone()).unwrap();
    bad_bundle_sig["effectiveHash"] = json!(super::diff::compute_effective_hash(&unsigned_packs));
    let (st_bad_sig, _) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:reconcile",
        "human-admin",
        Some("idem-rec-bad-sig"),
        Some(json!({ "bundle": bad_bundle_sig })),
    )
    .await;
    assert_eq!(st_bad_sig, StatusCode::FORBIDDEN);

    // Reconcile committed bundle restores IN_SYNC.
    let (st_rec, reconciled) = send_req(
        &app,
        "POST",
        "/v1/gitops-binding:reconcile",
        "human-admin",
        Some("idem-rec-1"),
        Some(json!({ "bundle": bundle_doc })),
    )
    .await;
    assert_eq!(st_rec, StatusCode::OK);
    assert_eq!(reconciled["binding"]["driftStatus"], "IN_SYNC");
}

#[tokio::test]
async fn gitops_cross_tenant_isolation_lock_on_apply_terminal_states_and_diff_hardening() {
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_console_router_with_security(state, None, test_security());

    // Bind org-1 to Git. org-2 must stay unlocked and isolated.
    let (st_b, _) = send_req(
        &app,
        "PUT",
        "/v1/gitops-binding",
        "human-admin",
        Some("idem-b-t1"),
        Some(json!({
            "source": "git",
            "repoUrl": "https://git.example/org1",
            "branch": "main",
            "path": "packs/"
        })),
    )
    .await;
    assert_eq!(st_b, StatusCode::OK);

    let (st_b2, b2) = send_req(&app, "GET", "/v1/gitops-binding", "org2-admin", None, None).await;
    assert_eq!(st_b2, StatusCode::OK);
    assert_eq!(b2["binding"]["source"], "none");

    // Org-1 PolicyChange cannot bypass GITOPS_LOCKED via :apply, and org-2 cannot access it.
    let (_, c1) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-lock"),
        Some(json!({
            "title": "Blocked apply under GitOps lock",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "block"
            }]
        })),
    )
    .await;
    let c1_id = c1["change"]["id"].as_str().unwrap();
    let _ = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c1_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    let (st_apply_locked, err_locked) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c1_id}:apply"),
        "human-admin",
        Some("idem-pc-apply-lock"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_apply_locked, StatusCode::PRECONDITION_FAILED);
    assert_eq!(err_locked["details"][0]["debug"]["reason"], "GITOPS_LOCKED");

    let (st_cross, _) = send_req(
        &app,
        "GET",
        &format!("/v1/policy-changes/{c1_id}"),
        "org2-admin",
        None,
        None,
    )
    .await;
    assert_eq!(st_cross, StatusCode::NOT_FOUND);

    // Non-step-up cannot unlock GitOps binding to source=none; StepUpVerified can.
    let (st_unlock_fail, _) = send_req(
        &app,
        "PUT",
        "/v1/gitops-binding",
        "human-normal",
        Some("idem-unlock-fail"),
        Some(json!({ "source": "none" })),
    )
    .await;
    assert_eq!(st_unlock_fail, StatusCode::FORBIDDEN);

    let (st_unlock_ok, _) = send_req(
        &app,
        "PUT",
        "/v1/gitops-binding",
        "human-admin",
        Some("idem-unlock-ok"),
        Some(json!({ "source": "none" })),
    )
    .await;
    assert_eq!(st_unlock_ok, StatusCode::OK);

    // Promoted enforcement (Ask -> Block) awaits human step-up; Watch addition auto-starts rollout.
    let (st_app_ok, app_ok) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c1_id}:apply"),
        "human-admin",
        Some("idem-pc-apply-unlocked"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_app_ok, StatusCode::OK);
    assert_eq!(app_ok["change"]["state"], "AWAITING_APPROVAL");
    let _ = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c1_id}:cancel"),
        "human-admin",
        Some("idem-pc-cancel-ok"),
        Some(json!({})),
    )
    .await;

    let (_, c_watch) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-watch"),
        Some(json!({
            "title": "Narrow Watch rule",
            "operations": [{
                "kind": "upsert_rule",
                "pack_id": "pack-essentials-slice0",
                "id": "custom.watch_env",
                "title": "Watch env",
                "description": "Observe env reads",
                "mode": "watch",
                "matcher": {
                    "action_classes": ["file.read"],
                    "target_prefixes": [],
                    "target_contains": [".env.local"],
                    "agents": []
                },
                "reason_template": "env read observed"
            }]
        })),
    )
    .await;
    let cw_id = c_watch["change"]["id"].as_str().unwrap();
    let _ = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{cw_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    let (st_watch_app, watch_app) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{cw_id}:apply"),
        "human-admin",
        Some("idem-pc-watch-apply"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_watch_app, StatusCode::OK);
    assert_eq!(watch_app["change"]["state"], "ROLLING_OUT");
    // Create, check, apply a fresh change cleanly to APPLIED (via non-widening approval? Create Watch then approve, or org-2) and assert cancel fails on terminal Applied.
    let (_, c2) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-term"),
        Some(json!({
            "title": "Widen then approve then cancel-deny",
            "operations": [{
                "kind": "update_rule_mode",
                "rule_id": "essentials.credential-stores",
                "mode": "off"
            }]
        })),
    )
    .await;
    let c2_id = c2["change"]["id"].as_str().unwrap();
    let _ = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c2_id}:apply"),
        "human-admin",
        Some("idem-pc-term-app"),
        Some(json!({})),
    )
    .await;
    let (st_rev, _) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c2_id}:approve"),
        "human-reviewer",
        Some("idem-pc-term-rev"),
        Some(json!({ "note": "ok" })),
    )
    .await;
    assert_eq!(st_rev, StatusCode::OK);
    let (st_cancel_term, _) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{c2_id}:cancel"),
        "human-admin",
        Some("idem-pc-term-cancel"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st_cancel_term, StatusCode::PRECONDITION_FAILED);

    // ReplacePackRules locked rule bypass, Effect::Permit/grdr.base smuggling, and min_grade weakening detected.
    let (st_base, bad_base) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-base"),
        Some(json!({
            "title": "Permit smuggling",
            "operations": [{
                "kind": "upsert_rule",
                "pack_id": "grdr.base",
                "id": "evil.permit",
                "title": "Permit all",
                "description": "bad",
                "mode": "block",
                "matcher": {
                    "action_classes": ["exec"],
                    "target_prefixes": [],
                    "target_contains": [],
                    "agents": []
                },
                "reason_template": "evil",
                "cedar": "permit(principal, action, resource);"
            }]
        })),
    )
    .await;
    assert_eq!(st_base, StatusCode::OK);
    let bad_base_id = bad_base["change"]["id"].as_str().unwrap();
    let (_, checked_base) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{bad_base_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    assert!(
        !checked_base["change"]["checkErrors"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // ReplacePackRules trying to drop locked Essentials rule fails check.
    let (st_rep, bad_replace) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-replace"),
        Some(json!({
            "title": "Replace pack dropping locked rule",
            "operations": [{
                "kind": "replace_pack_rules",
                "pack_id": "pack-essentials-slice0",
                "packs": []
            }]
        })),
    )
    .await;
    assert_eq!(st_rep, StatusCode::OK);
    let bad_rep_id = bad_replace["change"]["id"].as_str().unwrap();
    let (_, checked_rep) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{bad_rep_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    assert!(
        !checked_rep["change"]["checkErrors"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Weakening min_grade (G3 -> G0) is classified as widening.
    let (st_mg_create, mg_create) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-mg-seed"),
        Some(json!({
            "title": "Seed G3 rule",
            "operations": [{
                "kind": "upsert_rule",
                "pack_id": "pack-essentials-slice0",
                "id": "custom.grade_rule",
                "title": "Strict grade rule",
                "description": "requires G3",
                "mode": "ask",
                "min_grade": "G3",
                "matcher": {
                    "action_classes": ["exec"],
                    "target_prefixes": [],
                    "target_contains": ["danger_grade_cmd"],
                    "agents": []
                },
                "reason_template": "g3 required"
            }]
        })),
    )
    .await;
    assert_eq!(st_mg_create, StatusCode::OK);
    let mg_seed_id = mg_create["change"]["id"].as_str().unwrap();
    let _ = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{mg_seed_id}:apply"),
        "human-admin",
        Some("idem-pc-mg-seed-app"),
        Some(json!({})),
    )
    .await;
    let (st_mg_app, _) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{mg_seed_id}:approve"),
        "human-reviewer",
        Some("idem-pc-mg-seed-rev"),
        Some(json!({ "note": "seed" })),
    )
    .await;
    assert_eq!(st_mg_app, StatusCode::OK);

    let (st_widen_mg, widen_mg) = send_req(
        &app,
        "POST",
        "/v1/policy-changes",
        "human-admin",
        Some("idem-pc-mg-widen"),
        Some(json!({
            "title": "Downgrade G3 to G0",
            "operations": [{
                "kind": "upsert_rule",
                "pack_id": "pack-essentials-slice0",
                "id": "custom.grade_rule",
                "title": "Strict grade rule",
                "description": "downgraded",
                "mode": "ask",
                "min_grade": "G0",
                "matcher": {
                    "action_classes": ["exec"],
                    "target_prefixes": [],
                    "target_contains": ["danger_grade_cmd"],
                    "agents": []
                },
                "reason_template": "g0 weakened"
            }]
        })),
    )
    .await;
    assert_eq!(st_widen_mg, StatusCode::OK);
    let widen_mg_id = widen_mg["change"]["id"].as_str().unwrap();
    let (_, checked_mg) = send_req(
        &app,
        "POST",
        &format!("/v1/policy-changes/{widen_mg_id}:check"),
        "human-admin",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(checked_mg["change"]["diff"]["isWidening"], true);
}

#[tokio::test]
async fn rest_gitops_conformance_vectors_hold_end_to_end() {
    let raw = include_str!("../../../../sdk/conformance/rest-gitops-vectors.json");
    let vec_doc: Value = serde_json::from_str(raw).unwrap();
    let transitions = vec_doc["policy_change_transitions"].as_array().unwrap();

    for (idx, tc) in transitions.iter().enumerate() {
        let state = AppState::init(StorageBackend::Memory, true).unwrap();
        let app = routes::build_console_router_with_security(state, None, test_security());
        let name = tc["name"].as_str().unwrap();
        let proposer_kind = tc["proposer_kind"].as_str().unwrap();
        let diff_effect = tc["diff_effect"].as_str().unwrap();
        let expected_after_apply = tc["expected_after_apply"].as_str().unwrap();

        let (token, rule_id, mode, target) = if proposer_kind == "agent_session" {
            (
                "agent-tok",
                format!("conformance.agent_{idx}"),
                "watch",
                "drop.example",
            )
        } else if diff_effect == "widening" {
            (
                "human-admin",
                "essentials.credential-stores".to_owned(),
                "off",
                "",
            )
        } else {
            (
                "human-admin",
                format!("conformance.narrow_{idx}"),
                "watch",
                "exfil.example",
            )
        };
        let op = if diff_effect == "widening" {
            json!({ "kind": "update_rule_mode", "rule_id": rule_id, "mode": mode })
        } else {
            json!({
                "kind": "upsert_rule",
                "pack_id": "pack-essentials-slice0",
                "id": rule_id,
                "title": name,
                "description": "conformance vector",
                "mode": mode,
                "matcher": {
                    "action_classes": ["net.request"],
                    "target_prefixes": [],
                    "target_contains": [target],
                    "agents": []
                },
                "reason_template": "conformance"
            })
        };
        let hdr_token = if diff_effect == "widening" && proposer_kind == "human" {
            "human-admin"
        } else {
            token
        };
        let (st_c, created) = send_req(
            &app,
            "POST",
            "/v1/policy-changes",
            hdr_token,
            Some(&format!("idem-conf-{idx}")),
            Some(json!({ "title": name, "operations": [op] })),
        )
        .await;
        assert_eq!(st_c, StatusCode::OK, "create failed for {name}");
        let chg_id = created["change"]["id"].as_str().unwrap();
        let _ = send_req(
            &app,
            "POST",
            &format!("/v1/policy-changes/{chg_id}:check"),
            hdr_token,
            None,
            Some(json!({})),
        )
        .await;
        let _ = send_req(
            &app,
            "POST",
            &format!("/v1/policy-changes/{chg_id}:simulate"),
            hdr_token,
            None,
            Some(json!({})),
        )
        .await;
        let (st_a, applied) = send_req(
            &app,
            "POST",
            &format!("/v1/policy-changes/{chg_id}:apply"),
            hdr_token,
            Some(&format!("idem-conf-apply-{idx}")),
            Some(json!({})),
        )
        .await;
        assert_eq!(st_a, StatusCode::OK, "apply failed for {name}");
        assert_eq!(
            applied["change"]["state"].as_str().unwrap(),
            expected_after_apply,
            "transition vector {name} mismatch"
        );
    }

    let lock_rules = &vec_doc["gitops_lock_rules"];
    let state = AppState::init(StorageBackend::Memory, true).unwrap();
    let app = routes::build_console_router_with_security(state, None, test_security());
    let (st_bind, _) = send_req(
        &app,
        "PUT",
        "/v1/gitops-binding",
        "human-admin",
        Some("idem-conf-lock"),
        Some(json!({
            "source": lock_rules["locked_source"].as_str().unwrap(),
            "repoUrl": "https://git.example/policies",
            "branch": "main",
            "path": "packs/",
            "expectedEffectiveHash": ""
        })),
    )
    .await;
    assert_eq!(st_bind, StatusCode::OK);
    let (st_ui_write, ui_write_err) = send_req(
        &app,
        "POST",
        "/v1/rules",
        "human-admin",
        Some("idem-conf-ui-write"),
        Some(json!({ "pack_id": "pack-essentials-slice0", "rule": {} })),
    )
    .await;
    assert_eq!(
        st_ui_write.as_u16(),
        u16::try_from(lock_rules["ui_write_http_status"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        ui_write_err["details"][0]["debug"]["reason"]
            .as_str()
            .unwrap(),
        lock_rules["ui_write_error_code"].as_str().unwrap()
    );
    assert!(lock_rules["edit_anyway_min_approvers"].as_u64().unwrap() >= 2);
}
