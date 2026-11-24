// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Builds schema-validated Cedar 4.x Entities and Requests from ActionAttempts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use grdr_model::{ActionAttempt, ActionClass, Grant, Mode, PolicyPack, SessionLabel};
use grdr_schema::cedar::resource_entity_type_for_action;
use jiff::Timestamp;

use super::PolicyError;
use super::compiler::{CompiledRuleMeta, runtime_schema};
use super::signals::{CedarSignals, extract_cedar_signals};
use crate::analyze::classify_target;
use crate::session::SessionRuleState;

#[derive(Debug)]
pub(crate) struct BuiltCedarRequest {
    pub(crate) request: Request,
    pub(crate) entities: Entities,
    pub(crate) request_without_grants: Option<Request>,
    pub(crate) lifted_grant_by_rule_id: BTreeMap<String, String>,
}

pub(crate) fn build_cedar_request(
    attempt: &ActionAttempt,
    packs: &[PolicyPack],
    active_rules: &[CompiledRuleMeta],
    grants: &[Grant],
    session_state: Option<&SessionRuleState>,
    now: Timestamp,
) -> Result<BuiltCedarRequest, PolicyError> {
    let schema = runtime_schema()?;
    let analysis = classify_target(attempt.action_class, &attempt.target);
    let signals = extract_cedar_signals(attempt, &analysis, packs);

    let mut lifted_grant_by_rule_id = BTreeMap::new();
    let mut granted_rule_ids = BTreeSet::new();
    for rule_meta in active_rules {
        let liftable =
            rule_meta.mode == Mode::Ask || (rule_meta.mode == Mode::Block && !rule_meta.is_final);
        if !liftable {
            continue;
        }
        if let Some(grant) = grants.iter().find(|g| {
            g.rule_id == rule_meta.rule_id
                && g.grade >= rule_meta.min_grade
                && g.matches(attempt, now)
        }) {
            granted_rule_ids.insert(rule_meta.rule_id.clone());
            lifted_grant_by_rule_id.insert(rule_meta.rule_id.clone(), grant.grant_id.clone());
        }
    }

    let (principal_uid, resource_uid, entities) = build_entities(attempt, &signals)?;
    let action_uid = entity_uid("Grdr::Action", attempt.action_class.as_str())?;

    let context_with_grants = build_context(attempt, &signals, session_state, &granted_rule_ids)?;
    let request = Request::new(
        principal_uid.clone(),
        action_uid.clone(),
        resource_uid.clone(),
        context_with_grants,
        Some(schema),
    )
    .map_err(|e| PolicyError::RequestBuildFailed {
        detail: e.to_string(),
    })?;

    let request_without_grants = if granted_rule_ids.is_empty() {
        None
    } else {
        let empty = BTreeSet::new();
        let context_no_grants = build_context(attempt, &signals, session_state, &empty)?;
        Some(
            Request::new(
                principal_uid,
                action_uid,
                resource_uid,
                context_no_grants,
                Some(schema),
            )
            .map_err(|e| PolicyError::RequestBuildFailed {
                detail: e.to_string(),
            })?,
        )
    };

    Ok(BuiltCedarRequest {
        request,
        entities,
        request_without_grants,
        lifted_grant_by_rule_id,
    })
}

fn build_entities(
    attempt: &ActionAttempt,
    signals: &CedarSignals,
) -> Result<(EntityUid, EntityUid, Entities), PolicyError> {
    let schema = runtime_schema()?;
    let org_id = "default";
    let group_id = "default";
    let device_id = non_empty_or(&attempt.device_id, "device-unknown");
    let agent_lower = attempt.agent_name.trim().to_ascii_lowercase();
    let agent_id = non_empty_or(&agent_lower, "agent-unknown");
    let instance_id = format!("{device_id}:{agent_id}");
    let session_id = non_empty_or(&attempt.session_id, "session-unknown");

    let org_uid = entity_uid("Grdr::Organisation", org_id)?;
    let group_uid = entity_uid("Grdr::Group", group_id)?;
    let device_uid = entity_uid("Grdr::Device", device_id)?;
    let agent_uid = entity_uid("Grdr::Agent", agent_id)?;
    let instance_uid = entity_uid("Grdr::AgentInstance", &instance_id)?;
    let session_uid = entity_uid("Grdr::Session", session_id)?;

    let mut entities = vec![
        Entity::new_no_attrs(org_uid.clone(), HashSet::new()),
        Entity::new_no_attrs(group_uid.clone(), HashSet::from([org_uid])),
        Entity::new(
            device_uid.clone(),
            HashMap::from([
                (
                    "os".into(),
                    RestrictedExpression::new_string("unknown".into()),
                ),
                (
                    "profile".into(),
                    RestrictedExpression::new_string("user".into()),
                ),
            ]),
            HashSet::from([group_uid.clone()]),
        )
        .map_err(entity_err)?,
    ];

    let agent_classes = if attempt.action_class == ActionClass::AgentSpawn {
        set_expr(&signals.resource_classes)
    } else {
        RestrictedExpression::new_set([])
    };
    entities.push(
        Entity::new(
            agent_uid.clone(),
            HashMap::from([
                ("tier".into(), RestrictedExpression::new_string("A".into())),
                ("classes".into(), agent_classes),
            ]),
            HashSet::new(),
        )
        .map_err(entity_err)?,
    );

    entities.push(Entity::new_no_attrs(
        instance_uid.clone(),
        HashSet::from([agent_uid.clone(), device_uid, group_uid]),
    ));

    entities.push(
        Entity::new(
            session_uid.clone(),
            HashMap::from([
                ("depth".into(), RestrictedExpression::new_long(0)),
                ("contained".into(), RestrictedExpression::new_bool(false)),
                (
                    "containment".into(),
                    RestrictedExpression::new_string("none".into()),
                ),
                ("classes".into(), RestrictedExpression::new_set([])),
            ]),
            HashSet::from([instance_uid]),
        )
        .map_err(entity_err)?,
    );

    let resource_type = resource_entity_type_for_action(attempt.action_class.as_str());
    let resource_id = non_empty_or(&attempt.id, "target");
    let resource_uid = if attempt.action_class == ActionClass::AgentSpawn {
        agent_uid
    } else {
        let uid = entity_uid(resource_type, resource_id)?;
        let res_entity = build_resource_entity(attempt, uid.clone(), signals, &mut entities)?;
        entities.push(res_entity);
        uid
    };

    let compiled_entities = Entities::from_entities(entities, Some(schema)).map_err(|e| {
        PolicyError::RequestBuildFailed {
            detail: e.to_string(),
        }
    })?;

    Ok((session_uid, resource_uid, compiled_entities))
}

fn build_resource_entity(
    attempt: &ActionAttempt,
    uid: EntityUid,
    signals: &CedarSignals,
    extra_entities: &mut Vec<Entity>,
) -> Result<Entity, PolicyError> {
    let mut attrs = HashMap::from([("classes".into(), set_expr(&signals.resource_classes))]);
    let mut parents = HashSet::new();

    match attempt.action_class {
        ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete => {
            attrs.insert(
                "in_workspace".into(),
                RestrictedExpression::new_bool(signals.in_workspace),
            );
        }
        ActionClass::NetConnect | ActionClass::NetRequest => {
            attrs.insert("port".into(), RestrictedExpression::new_long(443));
        }
        ActionClass::LlmRequest => {
            attrs.insert(
                "provider".into(),
                RestrictedExpression::new_string("unknown".into()),
            );
        }
        ActionClass::McpConnect => {
            attrs.insert(
                "transport".into(),
                RestrictedExpression::new_string("stdio".into()),
            );
            attrs.insert(
                "identity_pinned".into(),
                RestrictedExpression::new_bool(false),
            );
        }
        ActionClass::McpCall => {
            let server_uid = entity_uid("Grdr::McpServer", "default")?;
            let server = Entity::new(
                server_uid.clone(),
                HashMap::from([
                    (
                        "transport".into(),
                        RestrictedExpression::new_string("stdio".into()),
                    ),
                    (
                        "identity_pinned".into(),
                        RestrictedExpression::new_bool(false),
                    ),
                    ("classes".into(), RestrictedExpression::new_set([])),
                ]),
                HashSet::new(),
            )
            .map_err(entity_err)?;
            extra_entities.push(server);
            parents.insert(server_uid);
            attrs.insert(
                "manifest_pinned".into(),
                RestrictedExpression::new_bool(false),
            );
            attrs.insert(
                "write_capable".into(),
                RestrictedExpression::new_bool(signals.write_capable),
            );
        }
        _ => {}
    }

    Entity::new(uid, attrs, parents).map_err(entity_err)
}

fn build_context(
    attempt: &ActionAttempt,
    signals: &CedarSignals,
    session_state: Option<&SessionRuleState>,
    grants: &BTreeSet<String>,
) -> Result<Context, PolicyError> {
    let (session_labels, label_epoch) = match session_state {
        Some(state) => {
            let mut labels: BTreeSet<String> = state
                .labels
                .iter()
                .map(|l| l.as_str().to_string())
                .collect();
            if state.labels.contains(&SessionLabel::CredentialAccessed) {
                labels.insert("sensitive".into());
                labels.insert("secret-read".into());
            }
            if state.labels.contains(&SessionLabel::UntrustedWebFetched) {
                labels.insert("untrusted".into());
            }
            let epoch = i64::try_from(state.event_seq).unwrap_or(i64::MAX);
            (labels, epoch)
        }
        None => (BTreeSet::new(), 0),
    };

    let session_rec = record_expr([
        ("labels", set_expr(&session_labels)),
        ("label_epoch", RestrictedExpression::new_long(label_epoch)),
    ])?;
    let attribution_rec = record_expr([
        ("grade", RestrictedExpression::new_long(2)),
        (
            "actor_kind",
            RestrictedExpression::new_string("agent".into()),
        ),
        ("evidence", RestrictedExpression::new_set([])),
    ])?;
    let assurance_rec = record_expr([
        ("visibility", RestrictedExpression::new_long(2)),
        ("control", RestrictedExpression::new_long(1)),
        ("tamper", RestrictedExpression::new_long(0)),
        ("fail_closed", RestrictedExpression::new_bool(false)),
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

    match attempt.action_class {
        ActionClass::Exec => {
            pairs.push((
                "command".into(),
                record_expr([("classes", set_expr(&signals.command_classes))])?,
            ));
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
                record_expr([("classes", RestrictedExpression::new_set([]))])?,
            ));
            pairs.push((
                "cloud".into(),
                record_expr([
                    ("provider", RestrictedExpression::new_string(String::new())),
                    ("account_classes", RestrictedExpression::new_set([])),
                    ("tenant_classes", RestrictedExpression::new_set([])),
                    ("verified", RestrictedExpression::new_bool(false)),
                ])?,
            ));
        }
        ActionClass::LlmRequest => {
            pairs.push((
                "tenant".into(),
                record_expr([
                    ("classes", RestrictedExpression::new_set([])),
                    ("verified", RestrictedExpression::new_bool(false)),
                ])?,
            ));
        }
        ActionClass::McpCall => {
            pairs.push((
                "args".into(),
                record_expr([
                    ("classes", RestrictedExpression::new_set([])),
                    ("extracted", RestrictedExpression::new_bool(false)),
                ])?,
            ));
        }
        ActionClass::CredUse => {
            pairs.push((
                "mode".into(),
                RestrictedExpression::new_string("inject".into()),
            ));
        }
        ActionClass::AgentSpawn => {
            pairs.push((
                "child".into(),
                record_expr([
                    ("depth", RestrictedExpression::new_long(1)),
                    ("contained", RestrictedExpression::new_bool(false)),
                    ("classes", RestrictedExpression::new_set([])),
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

    Context::from_pairs(pairs).map_err(|e| PolicyError::RequestBuildFailed {
        detail: e.to_string(),
    })
}

fn entity_uid(ty: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let type_name = EntityTypeName::from_str(ty).map_err(|e| PolicyError::RequestBuildFailed {
        detail: e.to_string(),
    })?;
    let eid = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(type_name, eid))
}

fn set_expr(values: &BTreeSet<String>) -> RestrictedExpression {
    RestrictedExpression::new_set(
        values
            .iter()
            .map(|val| RestrictedExpression::new_string(val.clone())),
    )
}

fn record_expr<const N: usize>(
    fields: [(&str, RestrictedExpression); N],
) -> Result<RestrictedExpression, PolicyError> {
    RestrictedExpression::new_record(fields.into_iter().map(|(k, v)| (k.to_string(), v))).map_err(
        |e| PolicyError::RequestBuildFailed {
            detail: e.to_string(),
        },
    )
}

fn entity_err(err: impl std::fmt::Display) -> PolicyError {
    PolicyError::RequestBuildFailed {
        detail: err.to_string(),
    }
}

fn non_empty_or<'a>(raw: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn control_point_name(cp: grdr_model::ControlPoint) -> &'static str {
    match cp {
        grdr_model::ControlPoint::Hook => "hook",
        grdr_model::ControlPoint::McpBroker => "mcp-broker",
        grdr_model::ControlPoint::Proxy => "proxy",
        grdr_model::ControlPoint::Sandbox => "sandbox",
        grdr_model::ControlPoint::Sensor => "sensor",
        grdr_model::ControlPoint::Browser => "browser",
        grdr_model::ControlPoint::Gateway => "gateway",
        grdr_model::ControlPoint::Connector => "connector",
    }
}
