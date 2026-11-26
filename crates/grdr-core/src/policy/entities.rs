// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Constructs complete schema-validated Cedar 4.x `v1alpha1` entity graphs.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{Entities, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use grdr_model::{ActionAttempt, ActionClass, IdentityMode, InstallProfile};
use grdr_schema::cedar::resource_entity_type_for_action;

use super::PolicyError;
use super::compiler::runtime_schema;
use super::request::{ActorKind, RequestBuildOptions};
use super::request_ctx::{actor_kind_name, effective_actor_kind, non_empty_or, set_expr};
use super::signals::CedarSignals;

pub(crate) struct EntityGraph {
    pub(crate) session_uid: EntityUid,
    pub(crate) process_uid: EntityUid,
    pub(crate) resource_uid: EntityUid,
    pub(crate) sink_uid: EntityUid,
    pub(crate) principal_is_process: bool,
    pub(crate) entities: Entities,
}

pub(crate) fn build_entities(
    attempt: &ActionAttempt,
    signals: &CedarSignals,
    opts: &RequestBuildOptions,
) -> Result<EntityGraph, PolicyError> {
    let schema = runtime_schema()?;
    let device_id = non_empty_or(&attempt.device_id, "device-unknown");
    let agent_lower = attempt.agent_name.trim().to_ascii_lowercase();
    let agent_id = non_empty_or(&agent_lower, "agent-unknown");
    let instance_id = format!("{device_id}:{agent_id}");
    let session_id = non_empty_or(&attempt.session_id, "session-unknown");

    let org_uid = entity_uid("Grdr::Organisation", &opts.org_id)?;
    let group_uid = entity_uid("Grdr::Group", &opts.group_id)?;
    let device_uid = entity_uid("Grdr::Device", device_id)?;
    let agent_uid = entity_uid("Grdr::Agent", agent_id)?;
    let instance_uid = entity_uid("Grdr::AgentInstance", &instance_id)?;
    let session_uid = entity_uid("Grdr::Session", session_id)?;
    let process_uid = entity_uid("Grdr::Process", &format!("{session_id}:proc"))?;

    let mut entities = vec![
        Entity::new_no_attrs(org_uid.clone(), HashSet::new()),
        Entity::new_no_attrs(group_uid.clone(), HashSet::from([org_uid])),
    ];
    let mut device_parents = HashSet::from([group_uid.clone()]);
    let mut instance_parents =
        HashSet::from([agent_uid.clone(), device_uid.clone(), group_uid.clone()]);

    if opts.identity_mode == IdentityMode::Named
        && let Some(raw_user) = attempt.user_id.as_deref()
        && !raw_user.trim().is_empty()
    {
        let user_uid = entity_uid("Grdr::User", raw_user.trim())?;
        entities.push(
            Entity::new(
                user_uid.clone(),
                HashMap::from([
                    (
                        "department".into(),
                        RestrictedExpression::new_string(opts.department.clone()),
                    ),
                    (
                        "risk_tier".into(),
                        RestrictedExpression::new_string(opts.user_risk_tier.clone()),
                    ),
                ]),
                HashSet::from([group_uid]),
            )
            .map_err(req_err)?,
        );
        device_parents.insert(user_uid.clone());
        instance_parents.insert(user_uid);
    }

    let profile_str = match opts.host_profile {
        InstallProfile::User => "user",
        InstallProfile::Protected => "protected",
    };
    entities.push(
        Entity::new(
            device_uid.clone(),
            HashMap::from([
                (
                    "os".into(),
                    RestrictedExpression::new_string(opts.os_name.clone()),
                ),
                (
                    "profile".into(),
                    RestrictedExpression::new_string(profile_str.into()),
                ),
            ]),
            device_parents,
        )
        .map_err(req_err)?,
    );

    entities.push(
        Entity::new(
            agent_uid.clone(),
            HashMap::from([
                (
                    "tier".into(),
                    RestrictedExpression::new_string(opts.agent_tier.clone()),
                ),
                ("classes".into(), RestrictedExpression::new_set([])),
            ]),
            HashSet::new(),
        )
        .map_err(req_err)?,
    );
    entities.push(Entity::new_no_attrs(instance_uid.clone(), instance_parents));
    entities.push(
        Entity::new(
            session_uid.clone(),
            HashMap::from([
                (
                    "depth".into(),
                    RestrictedExpression::new_long(opts.session_depth),
                ),
                (
                    "contained".into(),
                    RestrictedExpression::new_bool(opts.session_contained),
                ),
                (
                    "containment".into(),
                    RestrictedExpression::new_string(opts.session_containment.clone()),
                ),
                ("classes".into(), RestrictedExpression::new_set([])),
            ]),
            HashSet::from([instance_uid]),
        )
        .map_err(req_err)?,
    );
    let effective_actor = effective_actor_kind(opts);
    let agent_capable_host = opts.agent_capable_host || opts.actor_kind == ActorKind::Agent;
    entities.push(
        Entity::new(
            process_uid.clone(),
            HashMap::from([
                (
                    "actor_kind".into(),
                    RestrictedExpression::new_string(actor_kind_name(effective_actor).into()),
                ),
                (
                    "agent_capable_host".into(),
                    RestrictedExpression::new_bool(agent_capable_host),
                ),
                ("classes".into(), RestrictedExpression::new_set([])),
            ]),
            HashSet::from([device_uid]),
        )
        .map_err(req_err)?,
    );

    push_skill_entity(attempt, opts, &mut entities)?;

    let resource_type = resource_entity_type_for_action(attempt.action_class.as_str());
    let resource_id = non_empty_or(&attempt.id, "target");
    let resource_uid = if attempt.action_class == ActionClass::AgentSpawn {
        let child_lower = attempt.target.trim().to_ascii_lowercase();
        let child_id = non_empty_or(&child_lower, "child-agent");
        let child_uid = if child_id == agent_id {
            entity_uid("Grdr::Agent", &format!("{child_id}:child"))?
        } else {
            entity_uid("Grdr::Agent", child_id)?
        };
        let mut child_classes = opts.child_classes.clone();
        child_classes.extend(signals.resource_classes.iter().cloned());
        entities.push(
            Entity::new(
                child_uid.clone(),
                HashMap::from([
                    (
                        "tier".into(),
                        RestrictedExpression::new_string(opts.child_tier.clone()),
                    ),
                    ("classes".into(), set_expr(&child_classes)),
                ]),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
        child_uid
    } else {
        let uid = entity_uid(resource_type, resource_id)?;
        let res = build_resource_entity(attempt, uid.clone(), signals, opts, &mut entities)?;
        entities.push(res);
        uid
    };

    let sink_uid = if attempt.action_class == ActionClass::DataFlow {
        resource_uid.clone()
    } else {
        let uid = entity_uid("Grdr::Sink", "_derived_sink")?;
        entities.push(
            Entity::new(
                uid.clone(),
                HashMap::from([("classes".into(), set_expr(&signals.sink_classes))]),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
        uid
    };

    append_baseline_resource_entities(resource_type, resource_id, &mut entities)?;

    let principal_is_process = (effective_actor != ActorKind::Agent)
        && !matches!(
            attempt.action_class,
            ActionClass::AgentSpawn | ActionClass::DataFlow
        );

    let compiled_entities = Entities::from_entities(entities, Some(schema)).map_err(req_err)?;
    Ok(EntityGraph {
        session_uid,
        process_uid,
        resource_uid,
        sink_uid,
        principal_is_process,
        entities: compiled_entities,
    })
}

fn push_skill_entity(
    attempt: &ActionAttempt,
    opts: &RequestBuildOptions,
    entities: &mut Vec<Entity>,
) -> Result<(), PolicyError> {
    let skill_id = opts
        .skill_meta
        .as_ref()
        .map(|m| m.id.as_str())
        .or(attempt.skill_used.as_deref())
        .unwrap_or("_baseline_skill");
    let skill_attrs = match opts.skill_meta.as_ref() {
        Some(meta) => HashMap::from([
            (
                "kind".into(),
                RestrictedExpression::new_string(meta.kind.clone()),
            ),
            (
                "digest_pinned".into(),
                RestrictedExpression::new_bool(meta.digest_pinned),
            ),
            (
                "has_scripts".into(),
                RestrictedExpression::new_bool(meta.has_scripts),
            ),
            (
                "requests_broad_tools".into(),
                RestrictedExpression::new_bool(meta.requests_broad_tools),
            ),
            (
                "bidi_obfuscation".into(),
                RestrictedExpression::new_bool(meta.bidi_obfuscation),
            ),
            ("classes".into(), set_expr(&meta.classes)),
        ]),
        None => HashMap::from([
            (
                "kind".into(),
                RestrictedExpression::new_string("none".into()),
            ),
            ("digest_pinned".into(), RestrictedExpression::new_bool(true)),
            ("has_scripts".into(), RestrictedExpression::new_bool(false)),
            (
                "requests_broad_tools".into(),
                RestrictedExpression::new_bool(false),
            ),
            (
                "bidi_obfuscation".into(),
                RestrictedExpression::new_bool(false),
            ),
            ("classes".into(), RestrictedExpression::new_set([])),
        ]),
    };
    entities.push(
        Entity::new(
            entity_uid("Grdr::Skill", skill_id)?,
            skill_attrs,
            HashSet::new(),
        )
        .map_err(req_err)?,
    );
    Ok(())
}

fn build_resource_entity(
    attempt: &ActionAttempt,
    uid: EntityUid,
    signals: &CedarSignals,
    opts: &RequestBuildOptions,
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
            attrs.insert(
                "port".into(),
                RestrictedExpression::new_long(opts.parsed_port.unwrap_or(0)),
            );
        }
        ActionClass::LlmRequest => {
            attrs.insert(
                "provider".into(),
                RestrictedExpression::new_string(signals.llm_provider.clone()),
            );
        }
        ActionClass::McpConnect => {
            attrs.extend(mcp_server_attrs(
                non_empty_or(&opts.mcp_transport, "stdio"),
                opts.mcp_hints.server_pinned.unwrap_or(false),
            ));
            attrs.insert("classes".into(), set_expr(&signals.resource_classes));
        }
        ActionClass::McpCall => {
            let server_uid = entity_uid(
                "Grdr::McpServer",
                non_empty_or(&opts.mcp_server_id, "default"),
            )?;
            let server = Entity::new(
                server_uid.clone(),
                mcp_server_attrs(
                    non_empty_or(&opts.mcp_transport, "stdio"),
                    opts.mcp_hints.server_pinned.unwrap_or(false),
                ),
                HashSet::new(),
            )
            .map_err(req_err)?;
            extra_entities.push(server);
            parents.insert(server_uid);
            attrs.insert(
                "manifest_pinned".into(),
                RestrictedExpression::new_bool(opts.mcp_hints.tool_pinned.unwrap_or(false)),
            );
            attrs.insert(
                "write_capable".into(),
                RestrictedExpression::new_bool(signals.write_capable),
            );
        }
        _ => {}
    }

    Entity::new(uid, attrs, parents).map_err(req_err)
}

fn append_baseline_resource_entities(
    active_ty: &str,
    active_id: &str,
    entities: &mut Vec<Entity>,
) -> Result<(), PolicyError> {
    let base_id = if active_id == "_baseline" {
        "_baseline_alt"
    } else {
        "_baseline"
    };
    for ty in [
        "Grdr::Executable",
        "Grdr::Credential",
        "Grdr::ConfigTarget",
        "Grdr::ElevationRoute",
        "Grdr::UiTarget",
    ] {
        if ty != active_ty {
            entities.push(
                Entity::new(
                    entity_uid(ty, base_id)?,
                    HashMap::from([("classes".into(), RestrictedExpression::new_set([]))]),
                    HashSet::new(),
                )
                .map_err(req_err)?,
            );
        }
    }
    if active_ty != "Grdr::Path" {
        entities.push(
            Entity::new(
                entity_uid("Grdr::Path", base_id)?,
                HashMap::from([
                    ("in_workspace".into(), RestrictedExpression::new_bool(false)),
                    ("classes".into(), RestrictedExpression::new_set([])),
                ]),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
    }
    if active_ty != "Grdr::Endpoint" {
        entities.push(
            Entity::new(
                entity_uid("Grdr::Endpoint", base_id)?,
                HashMap::from([
                    ("port".into(), RestrictedExpression::new_long(0)),
                    ("classes".into(), RestrictedExpression::new_set([])),
                ]),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
    }
    if active_ty != "Grdr::ModelEndpoint" {
        entities.push(
            Entity::new(
                entity_uid("Grdr::ModelEndpoint", base_id)?,
                HashMap::from([
                    (
                        "provider".into(),
                        RestrictedExpression::new_string("unknown".into()),
                    ),
                    ("classes".into(), RestrictedExpression::new_set([])),
                ]),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
    }
    if active_ty != "Grdr::McpServer" && active_ty != "Grdr::McpTool" {
        let srv_uid = entity_uid("Grdr::McpServer", base_id)?;
        entities.push(
            Entity::new(
                srv_uid.clone(),
                mcp_server_attrs("stdio", false),
                HashSet::new(),
            )
            .map_err(req_err)?,
        );
        entities.push(
            Entity::new(
                entity_uid("Grdr::McpTool", base_id)?,
                HashMap::from([
                    (
                        "manifest_pinned".into(),
                        RestrictedExpression::new_bool(false),
                    ),
                    (
                        "write_capable".into(),
                        RestrictedExpression::new_bool(false),
                    ),
                    ("classes".into(), RestrictedExpression::new_set([])),
                ]),
                HashSet::from([srv_uid]),
            )
            .map_err(req_err)?,
        );
    }
    Ok(())
}

fn mcp_server_attrs(
    transport: &str,
    identity_pinned: bool,
) -> HashMap<String, RestrictedExpression> {
    HashMap::from([
        (
            "transport".into(),
            RestrictedExpression::new_string(transport.into()),
        ),
        (
            "identity_pinned".into(),
            RestrictedExpression::new_bool(identity_pinned),
        ),
        ("classes".into(), RestrictedExpression::new_set([])),
    ])
}

pub(crate) fn entity_uid(ty: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let type_name = EntityTypeName::from_str(ty).map_err(req_err)?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

pub(crate) fn req_err(err: impl std::fmt::Display) -> PolicyError {
    PolicyError::RequestBuildFailed {
        detail: err.to_string(),
    }
}
