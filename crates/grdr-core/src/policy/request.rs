// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Builds schema-validated Cedar 4.x Requests, uncertainty sets, and derived `data.flow` checks.

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::{Entities, Request};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, BoundaryObserver, Grant, IdentityMode,
    InstallProfile, Mode, PolicyPack,
};
use jiff::Timestamp;

use super::PolicyError;
use super::compiler::{CompiledRuleMeta, runtime_schema};
use super::entities::{build_entities, entity_uid, req_err};
use super::request_ctx::{build_context, populate_uncertainty};
use super::signals::extract_cedar_signals;
use crate::analyze::{classify_target, normalize_attempt_target};
use crate::session::SessionRuleState;

const SINK_CLASSES: &[&str] = &[
    "egress-outside-profile",
    "push-outside-org",
    "pkg.publish",
    "message.send",
    "mcp-unpinned-write",
    "llm-non-tenant",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextField {
    SessionLabels,
    CommandClasses,
    PathWorkspace,
    RecursiveFlag,
    EndpointPort,
    HttpClasses,
    CloudMeta,
    LlmTenant,
    McpServerPin,
    McpToolPin,
    McpArgs,
    ChildAgentMeta,
    ConfigClasses,
    UserIdentity,
    TargetClasses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    Agent,
    Human,
    System,
    Undetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CredUseMode {
    #[default]
    Inject,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SessionFreezeState {
    #[default]
    Active,
    Frozen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssuranceHints {
    pub visibility: u8,
    pub control: u8,
    pub tamper: u8,
    pub fail_closed: bool,
}

// grdr:allow-s4 orthogonal Cedar Skill entity attributes matching v1alpha1.cedarschema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRequestMeta {
    pub id: String,
    pub kind: String,
    pub digest_pinned: bool,
    pub has_scripts: bool,
    pub requests_broad_tools: bool,
    pub bidi_obfuscation: bool,
    pub classes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpRequestHints {
    pub server_pinned: Option<bool>,
    pub tool_pinned: Option<bool>,
    pub args_extracted: bool,
    pub read_only_hint: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerificationHints {
    pub llm_tenant_verified: bool,
    pub cloud_verified: bool,
}

// grdr:allow-s4 orthogonal Cedar request build inputs matching v1alpha1.cedarschema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBuildOptions {
    pub identity_mode: IdentityMode,
    pub host_profile: InstallProfile,
    pub actor_kind: ActorKind,
    pub agent_capable_host: bool,
    pub attribution_grade: ApprovalGrade,
    pub min_attribution_grade: ApprovalGrade,
    pub os_name: String,
    pub org_id: String,
    pub group_id: String,
    pub department: String,
    pub user_risk_tier: String,
    pub agent_tier: String,
    pub session_depth: i64,
    pub session_contained: bool,
    pub session_containment: String,
    pub session_freeze: SessionFreezeState,
    pub label_epoch: u64,
    pub child_depth: i64,
    pub child_contained: bool,
    pub child_tier: String,
    pub child_classes: BTreeSet<String>,
    pub cred_mode: CredUseMode,
    pub assurance: Option<AssuranceHints>,
    pub observer: BoundaryObserver,
    pub parsed_port: Option<i64>,
    pub mcp_transport: String,
    pub mcp_server_id: String,
    pub mcp_hints: McpRequestHints,
    pub verification: VerificationHints,
    pub extra_absent: BTreeSet<ContextField>,
    pub extra_pending: BTreeSet<ContextField>,
    pub skill_meta: Option<SkillRequestMeta>,
}

#[derive(Debug)]
pub struct CedarRequest {
    pub request: Request,
    pub entities: Entities,
    pub request_without_grants: Option<Request>,
    pub data_flow_request_without_grants: Option<Request>,
    pub lifted_grant_by_rule_id: BTreeMap<String, String>,
    pub data_flow_request: Option<Request>,
    pub absent: BTreeSet<ContextField>,
    pub pending: BTreeSet<ContextField>,
    pub principal_is_process: bool,
    pub command_status: grdr_model::CommandParseStatus,
}

impl Default for RequestBuildOptions {
    fn default() -> Self {
        Self {
            identity_mode: IdentityMode::Named,
            host_profile: InstallProfile::User,
            actor_kind: ActorKind::Agent,
            agent_capable_host: true,
            attribution_grade: ApprovalGrade::G2,
            min_attribution_grade: ApprovalGrade::G1,
            os_name: "unknown".into(),
            org_id: "default".into(),
            group_id: "default".into(),
            department: "engineering".into(),
            user_risk_tier: "standard".into(),
            agent_tier: "A".into(),
            session_depth: 0,
            session_contained: false,
            session_containment: "none".into(),
            session_freeze: SessionFreezeState::Active,
            label_epoch: 0,
            child_depth: 1,
            child_contained: false,
            child_tier: "A".into(),
            child_classes: BTreeSet::new(),
            cred_mode: CredUseMode::Inject,
            assurance: None,
            observer: BoundaryObserver::None,
            parsed_port: None,
            mcp_transport: "stdio".into(),
            mcp_server_id: "default".into(),
            mcp_hints: McpRequestHints::default(),
            verification: VerificationHints::default(),
            extra_absent: BTreeSet::new(),
            extra_pending: BTreeSet::new(),
            skill_meta: None,
        }
    }
}

pub(crate) fn build_cedar_request(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    active_rules: &[CompiledRuleMeta],
    grants: &[Grant],
    session_state: Option<&SessionRuleState>,
    now: Timestamp,
) -> Result<CedarRequest, PolicyError> {
    build_cedar_request_with_options(
        attempt,
        packs,
        active_rules,
        grants,
        session_state,
        &RequestBuildOptions::default(),
        now,
    )
}

pub fn build_cedar_request_with_options(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    active_rules: &[CompiledRuleMeta],
    grants: &[Grant],
    session_state: Option<&SessionRuleState>,
    opts: &RequestBuildOptions,
    now: Timestamp,
) -> Result<CedarRequest, PolicyError> {
    let schema = runtime_schema()?;
    let analysis = classify_target(attempt.action_class, &attempt.target);
    let signals = extract_cedar_signals(attempt, &analysis, packs, opts);

    let (granted_rule_ids, lifted_grant_by_rule_id) =
        collect_matching_grants(attempt, active_rules, grants, now);

    let mut absent = opts.extra_absent.clone();
    let mut pending = opts.extra_pending.clone();
    populate_uncertainty(
        attempt,
        analysis.command_status,
        &signals,
        opts,
        &mut absent,
        &mut pending,
    );

    let graph = build_entities(attempt, &signals, opts)?;
    let action_uid = entity_uid("Grdr::Action", attempt.action_class.as_str())?;
    let principal_uid = if graph.principal_is_process {
        graph.process_uid.clone()
    } else {
        graph.session_uid.clone()
    };

    let ctx_grants = build_context(
        attempt,
        analysis.command_status,
        &signals,
        session_state,
        &granted_rule_ids,
        opts,
        attempt.action_class,
    )?;
    let request = Request::new(
        principal_uid.clone(),
        action_uid.clone(),
        graph.resource_uid.clone(),
        ctx_grants,
        Some(schema),
    )
    .map_err(req_err)?;

    let request_without_grants = if granted_rule_ids.is_empty() {
        None
    } else {
        let empty = BTreeSet::new();
        let ctx_none = build_context(
            attempt,
            analysis.command_status,
            &signals,
            session_state,
            &empty,
            opts,
            attempt.action_class,
        )?;
        Some(
            Request::new(
                principal_uid,
                action_uid,
                graph.resource_uid,
                ctx_none,
                Some(schema),
            )
            .map_err(req_err)?,
        )
    };

    let has_data_flow = attempt.action_class != ActionClass::DataFlow
        && signals
            .sink_classes
            .iter()
            .any(|c| SINK_CLASSES.contains(&c.as_str()));
    let (data_flow_request, data_flow_request_without_grants) = if has_data_flow {
        let df_action = entity_uid("Grdr::Action", ActionClass::DataFlow.as_str())?;
        let df_ctx = build_context(
            attempt,
            analysis.command_status,
            &signals,
            session_state,
            &granted_rule_ids,
            opts,
            ActionClass::DataFlow,
        )?;
        let df_req = Request::new(
            graph.session_uid.clone(),
            df_action.clone(),
            graph.sink_uid.clone(),
            df_ctx,
            Some(schema),
        )
        .map_err(req_err)?;
        let df_no_grants = if granted_rule_ids.is_empty() {
            None
        } else {
            let empty = BTreeSet::new();
            let df_ctx_none = build_context(
                attempt,
                analysis.command_status,
                &signals,
                session_state,
                &empty,
                opts,
                ActionClass::DataFlow,
            )?;
            Some(
                Request::new(
                    graph.session_uid,
                    df_action,
                    graph.sink_uid,
                    df_ctx_none,
                    Some(schema),
                )
                .map_err(req_err)?,
            )
        };
        (Some(df_req), df_no_grants)
    } else {
        (None, None)
    };

    Ok(CedarRequest {
        request,
        entities: graph.entities,
        request_without_grants,
        data_flow_request_without_grants,
        lifted_grant_by_rule_id,
        data_flow_request,
        absent,
        pending,
        principal_is_process: graph.principal_is_process,
        command_status: analysis.command_status,
    })
}

fn collect_matching_grants(
    attempt: &ActionAttempt,
    active_rules: &[CompiledRuleMeta],
    grants: &[Grant],
    now: Timestamp,
) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let match_attempt = if matches!(
        attempt.action_class,
        ActionClass::FileRead
            | ActionClass::FileWrite
            | ActionClass::FileDelete
            | ActionClass::ConfigChange
    ) {
        attempt.clone()
    } else {
        let (norm_target, _) = normalize_attempt_target(attempt.action_class, &attempt.target);
        let mut cloned = attempt.clone();
        if !norm_target.is_empty() {
            cloned.target = norm_target;
        }
        cloned
    };

    let mut granted_rule_ids = BTreeSet::new();
    let mut lifted = BTreeMap::new();
    for rule_meta in active_rules {
        let liftable = !rule_meta.is_final && matches!(rule_meta.mode, Mode::Ask | Mode::Block);
        if !liftable {
            continue;
        }
        if let Some(grant) = grants.iter().find(|g| {
            g.rule_id == rule_meta.rule_id
                && grant_satisfies_rule(rule_meta, g)
                && g.matches(&match_attempt, now)
        }) {
            granted_rule_ids.insert(rule_meta.rule_id.clone());
            lifted.insert(rule_meta.rule_id.clone(), grant.grant_id.clone());
        }
    }
    (granted_rule_ids, lifted)
}

fn extract_approver_kind(note: &str) -> Option<&str> {
    let trimmed = note.trim();
    let after = trimmed.strip_prefix("approver:")?;
    let kind = after
        .trim_start()
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | ';' | '['))
        .next()
        .unwrap_or("")
        .trim();
    (!kind.is_empty()).then_some(kind)
}

fn is_non_self_exception_role(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "sponsor" | "admin" | "quorum"
    )
}

fn grant_satisfies_rule(rule: &CompiledRuleMeta, grant: &Grant) -> bool {
    if rule.is_final || grant.grade < rule.min_grade {
        return false;
    }
    if rule.mode == Mode::Block {
        if grant.grade < ApprovalGrade::G1 {
            return false;
        }
        let Some(kind) = extract_approver_kind(&grant.note) else {
            return false;
        };
        if kind.eq_ignore_ascii_case("self") || !is_non_self_exception_role(kind) {
            return false;
        }
        if rule.approver != "self" && !kind.eq_ignore_ascii_case(&rule.approver) {
            return false;
        }
        return true;
    }
    if rule.approver != "self" {
        if grant.note.trim().eq_ignore_ascii_case("self") {
            return false;
        }
        let Some(kind) = extract_approver_kind(&grant.note) else {
            return false;
        };
        return !kind.eq_ignore_ascii_case("self") && kind.eq_ignore_ascii_case(&rule.approver);
    }
    true
}
