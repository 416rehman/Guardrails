// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Context record assembly and uncertainty classification for Cedar 4.x requests.

use std::collections::BTreeSet;

use cedar_policy::{Context, RestrictedExpression};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, CommandParseStatus, ControlPoint, IdentityMode,
    SessionLabel,
};

use super::PolicyError;
use super::entities::req_err;
use super::request::{
    ActorKind, AssuranceHints, ContextField, CredUseMode, RequestBuildOptions, SessionFreezeState,
};
use super::signals::CedarSignals;
use crate::session::SessionRuleState;

pub(crate) fn effective_actor_kind(opts: &RequestBuildOptions) -> ActorKind {
    if opts.attribution_grade < opts.min_attribution_grade {
        ActorKind::Undetermined
    } else {
        opts.actor_kind
    }
}

pub(crate) fn populate_uncertainty(
    attempt: &ActionAttempt,
    command_status: CommandParseStatus,
    signals: &CedarSignals,
    opts: &RequestBuildOptions,
    absent: &mut BTreeSet<ContextField>,
    pending: &mut BTreeSet<ContextField>,
) {
    let target_empty = attempt.target.trim().is_empty();
    if opts.identity_mode == IdentityMode::Pseudonymous
        || attempt
            .user_id
            .as_deref()
            .is_none_or(|u| u.trim().is_empty())
    {
        absent.insert(ContextField::UserIdentity);
    }
    if target_empty {
        absent.insert(ContextField::TargetClasses);
    }
    if attempt.action_class == ActionClass::Exec && command_status != CommandParseStatus::Resolved {
        absent.insert(ContextField::CommandClasses);
    }
    if matches!(
        attempt.action_class,
        ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete
    ) && target_empty
    {
        absent.insert(ContextField::PathWorkspace);
        absent.insert(ContextField::RecursiveFlag);
    }
    if matches!(
        attempt.action_class,
        ActionClass::NetConnect | ActionClass::NetRequest
    ) && opts.parsed_port.is_none()
    {
        absent.insert(ContextField::EndpointPort);
    }
    if attempt.action_class == ActionClass::NetRequest {
        if target_empty {
            absent.insert(ContextField::HttpClasses);
        }
        if !signals.cloud_provider.is_empty() && signals.cloud_account_classes.is_empty() {
            absent.insert(ContextField::CloudMeta);
        }
    }
    if attempt.action_class == ActionClass::LlmRequest && !opts.verification.llm_tenant_verified {
        absent.insert(ContextField::LlmTenant);
    }
    if matches!(
        attempt.action_class,
        ActionClass::McpConnect | ActionClass::McpCall
    ) {
        if opts.mcp_hints.server_pinned.is_none() {
            pending.insert(ContextField::McpServerPin);
        }
        if attempt.action_class == ActionClass::McpCall {
            if opts.mcp_hints.tool_pinned.is_none() {
                pending.insert(ContextField::McpToolPin);
            }
            if !opts.mcp_hints.args_extracted {
                absent.insert(ContextField::McpArgs);
            }
        }
    }
    if attempt.action_class == ActionClass::AgentSpawn && target_empty {
        absent.insert(ContextField::ChildAgentMeta);
    }
    if attempt.action_class == ActionClass::ConfigChange && target_empty {
        absent.insert(ContextField::ConfigClasses);
    }
}

pub(crate) fn build_context(
    attempt: &ActionAttempt,
    command_status: CommandParseStatus,
    signals: &CedarSignals,
    session_state: Option<&SessionRuleState>,
    grants: &BTreeSet<String>,
    opts: &RequestBuildOptions,
    action_class: ActionClass,
) -> Result<Context, PolicyError> {
    let effective_actor = effective_actor_kind(opts);
    let agent_context = effective_actor == ActorKind::Agent
        || matches!(
            action_class,
            ActionClass::AgentSpawn | ActionClass::DataFlow
        );
    let (mut session_labels, state_epoch) = match (agent_context, session_state) {
        (true, Some(state)) => {
            let mut labels: BTreeSet<String> = state
                .labels
                .iter()
                .map(|l| l.as_str().to_string())
                .filter(|s| !s.starts_with("advisory.") && !s.starts_with("model."))
                .collect();
            if state.labels.contains(&SessionLabel::CredentialAccessed) {
                labels.insert("sensitive".into());
                labels.insert("secret-read".into());
            }
            if state.labels.contains(&SessionLabel::UntrustedWebFetched) {
                labels.insert("untrusted".into());
            }
            (labels, state.event_seq)
        }
        (false, Some(state)) => (BTreeSet::new(), state.event_seq),
        (_, None) => (BTreeSet::new(), 0),
    };
    if opts.session_freeze == SessionFreezeState::Frozen && agent_context {
        session_labels.insert("session:frozen".into());
    }
    let label_epoch = i64::try_from(opts.label_epoch.max(state_epoch)).unwrap_or(i64::MAX);

    let session_rec = record_expr([
        ("labels", set_expr(&session_labels)),
        ("label_epoch", RestrictedExpression::new_long(label_epoch)),
    ])?;
    let grade_num = match opts.attribution_grade {
        ApprovalGrade::G0 => 0,
        ApprovalGrade::G1 => 1,
        ApprovalGrade::G2 => 2,
        ApprovalGrade::G3 => 3,
    };
    let attribution_rec = record_expr([
        ("grade", RestrictedExpression::new_long(grade_num)),
        (
            "actor_kind",
            RestrictedExpression::new_string(actor_kind_name(effective_actor).into()),
        ),
        ("evidence", RestrictedExpression::new_set([])),
    ])?;
    let assurance = opts
        .assurance
        .unwrap_or_else(|| default_assurance_for_control_point(attempt.control_point));
    let assurance_rec = record_expr([
        (
            "visibility",
            RestrictedExpression::new_long(i64::from(assurance.visibility)),
        ),
        (
            "control",
            RestrictedExpression::new_long(i64::from(assurance.control)),
        ),
        (
            "tamper",
            RestrictedExpression::new_long(i64::from(assurance.tamper)),
        ),
        (
            "fail_closed",
            RestrictedExpression::new_bool(assurance.fail_closed),
        ),
    ])?;
    let schedule_rec = record_expr([])?;

    let mut pairs: Vec<(String, RestrictedExpression)> = vec![
        ("session".into(), session_rec),
        ("grants".into(), set_expr(grants)),
        ("attribution".into(), attribution_rec),
        ("assurance".into(), assurance_rec),
        ("facts".into(), set_expr(&signals.facts)),
        (
            "control_point".into(),
            RestrictedExpression::new_string(control_point_name(attempt.control_point).into()),
        ),
        ("schedule".into(), schedule_rec),
    ];

    match action_class {
        ActionClass::Exec => {
            let cmd_classes = if command_status == CommandParseStatus::Resolved {
                set_expr(&signals.command_classes)
            } else {
                RestrictedExpression::new_set([])
            };
            pairs.push(("command".into(), record_expr([("classes", cmd_classes)])?));
        }
        ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete => {
            pairs.push((
                "recursive".into(),
                RestrictedExpression::new_bool(signals.recursive),
            ));
        }
        ActionClass::NetRequest => {
            pairs.push((
                "http".into(),
                record_expr([("classes", set_expr(&signals.http_classes))])?,
            ));
            pairs.push((
                "cloud".into(),
                record_expr([
                    (
                        "provider",
                        RestrictedExpression::new_string(signals.cloud_provider.clone()),
                    ),
                    ("account_classes", set_expr(&signals.cloud_account_classes)),
                    ("tenant_classes", set_expr(&signals.cloud_tenant_classes)),
                    (
                        "verified",
                        RestrictedExpression::new_bool(opts.verification.cloud_verified),
                    ),
                ])?,
            ));
        }
        ActionClass::LlmRequest => {
            pairs.push((
                "tenant".into(),
                record_expr([
                    ("classes", set_expr(&signals.llm_tenant_classes)),
                    (
                        "verified",
                        RestrictedExpression::new_bool(opts.verification.llm_tenant_verified),
                    ),
                ])?,
            ));
        }
        ActionClass::McpCall => {
            pairs.push((
                "args".into(),
                record_expr([
                    ("classes", set_expr(&signals.mcp_arg_classes)),
                    (
                        "extracted",
                        RestrictedExpression::new_bool(opts.mcp_hints.args_extracted),
                    ),
                ])?,
            ));
        }
        ActionClass::CredUse => {
            let mode_str = match opts.cred_mode {
                CredUseMode::Inject => "inject",
                CredUseMode::Release => "release",
            };
            pairs.push((
                "mode".into(),
                RestrictedExpression::new_string(mode_str.into()),
            ));
        }
        ActionClass::AgentSpawn => {
            let mut child_classes = opts.child_classes.clone();
            child_classes.extend(signals.resource_classes.iter().cloned());
            pairs.push((
                "child".into(),
                record_expr([
                    ("depth", RestrictedExpression::new_long(opts.child_depth)),
                    (
                        "contained",
                        RestrictedExpression::new_bool(opts.child_contained),
                    ),
                    ("classes", set_expr(&child_classes)),
                ])?,
            ));
        }
        ActionClass::ConfigChange => {
            pairs.push(("change_classes".into(), set_expr(&signals.resource_classes)));
        }
        ActionClass::DataFlow => {
            pairs.push(("source_labels".into(), set_expr(&session_labels)));
        }
        ActionClass::NetConnect
        | ActionClass::McpConnect
        | ActionClass::Elevate
        | ActionClass::UiAct => {}
    }

    Context::from_pairs(pairs).map_err(req_err)
}

fn default_assurance_for_control_point(cp: ControlPoint) -> AssuranceHints {
    match cp {
        ControlPoint::Sandbox => AssuranceHints {
            visibility: 3,
            control: 3,
            tamper: 1,
            fail_closed: true,
        },
        ControlPoint::Proxy | ControlPoint::McpBroker | ControlPoint::Gateway => AssuranceHints {
            visibility: 2,
            control: 2,
            tamper: 1,
            fail_closed: true,
        },
        ControlPoint::Browser | ControlPoint::Connector => AssuranceHints {
            visibility: 2,
            control: 1,
            tamper: 0,
            fail_closed: true,
        },
        ControlPoint::Hook => AssuranceHints {
            visibility: 2,
            control: 1,
            tamper: 0,
            fail_closed: false,
        },
        ControlPoint::Sensor => AssuranceHints {
            visibility: 1,
            control: 0,
            tamper: 0,
            fail_closed: false,
        },
    }
}

pub(crate) fn set_expr(values: &BTreeSet<String>) -> RestrictedExpression {
    RestrictedExpression::new_set(
        values
            .iter()
            .map(|val| RestrictedExpression::new_string(val.clone())),
    )
}

fn record_expr<const N: usize>(
    fields: [(&str, RestrictedExpression); N],
) -> Result<RestrictedExpression, PolicyError> {
    RestrictedExpression::new_record(fields.into_iter().map(|(k, v)| (k.to_string(), v)))
        .map_err(req_err)
}

pub(crate) fn non_empty_or<'a>(raw: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

pub(crate) fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Agent => "agent",
        ActorKind::Human => "human",
        ActorKind::System => "system",
        ActorKind::Undetermined => "undetermined",
    }
}

fn control_point_name(cp: ControlPoint) -> &'static str {
    match cp {
        ControlPoint::Hook => "hook",
        ControlPoint::McpBroker => "mcp-broker",
        ControlPoint::Proxy => "proxy",
        ControlPoint::Sandbox => "sandbox",
        ControlPoint::Sensor => "sensor",
        ControlPoint::Browser => "browser",
        ControlPoint::Gateway => "gateway",
        ControlPoint::Connector => "connector",
    }
}
