// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_proto::common as pb;

use super::enums::{
    action_class_to_proto, approval_grade_to_proto, artifact_kind_to_proto, artifact_risk_to_proto,
    artifact_scope_to_proto, assurance_to_proto, control_point_to_proto, control_strength_to_proto,
    install_profile_to_proto, mode_to_proto, on_failure_to_proto, proto_to_action_class,
    proto_to_approval_grade, proto_to_artifact_kind, proto_to_artifact_risk,
    proto_to_artifact_scope, proto_to_assurance, proto_to_control_point, proto_to_control_strength,
    proto_to_install_profile, proto_to_mode, proto_to_on_failure, proto_to_provenance,
    proto_to_span_kind, proto_to_tamper_grade, proto_to_verdict, proto_to_visibility,
    provenance_to_proto, span_kind_to_proto, tamper_grade_to_proto, validate_other_label,
    verdict_to_proto, visibility_to_proto,
};
use crate::{
    ActionAttempt, ActionClass, ArtifactEntry, ArtifactKind, AssuranceRecord, ControlPoint,
    DecisionReceipt, Device, DiscoveredAgent, McpServerEntry, PolicyPack, PolicyRule, RuleMatch,
    SecondaryAction, SessionSummary, TrustedKeyInfo, TurnSummary, Verdict,
};

pub fn parse_ts(raw: &str) -> Result<Timestamp, String> {
    if raw.trim().is_empty() {
        return Ok(Timestamp::UNIX_EPOCH);
    }
    raw.parse::<Timestamp>()
        .map_err(|e| format!("invalid RFC 3339 timestamp '{raw}': {e}"))
}

pub fn key_to_proto(k: &TrustedKeyInfo) -> pb::TrustedKeyInfo {
    pb::TrustedKeyInfo {
        key_id: k.key_id.clone(),
        public_key_b64: k.public_key_b64.clone(),
    }
}

pub fn proto_to_key(k: pb::TrustedKeyInfo) -> TrustedKeyInfo {
    TrustedKeyInfo {
        key_id: k.key_id,
        public_key_b64: k.public_key_b64,
    }
}

pub fn mcp_to_proto(m: &McpServerEntry) -> pb::McpServerEntry {
    pb::McpServerEntry {
        name: m.name.clone(),
        transport: m.transport.clone(),
        command: m.command.clone(),
        source_agent: m.source_agent.clone(),
        config_path: m.config_path.clone(),
        pinned: m.pinned,
    }
}

pub fn proto_to_mcp(m: pb::McpServerEntry) -> McpServerEntry {
    McpServerEntry {
        name: m.name,
        transport: m.transport,
        command: m.command,
        source_agent: m.source_agent,
        config_path: m.config_path,
        pinned: m.pinned,
    }
}

pub fn agent_to_proto(a: &DiscoveredAgent) -> pb::DiscoveredAgent {
    pb::DiscoveredAgent {
        id: a.id.clone(),
        name: a.name.clone(),
        kind: a.kind.clone(),
        config_path: a.config_path.clone(),
        hook_installed: a.hook_installed,
        mcp_count: u64::try_from(a.mcp_count).unwrap_or(u64::MAX),
        assurance: Some(pb::AssuranceRecord {
            visibility: visibility_to_proto(a.assurance.visibility),
            control: control_strength_to_proto(a.assurance.control),
            on_failure: on_failure_to_proto(a.assurance.on_failure),
            tamper: tamper_grade_to_proto(a.assurance.tamper),
        }),
        assurance_level: assurance_to_proto(a.assurance_level),
        sponsor: a.sponsor.clone(),
        detected_at: a.detected_at.to_string(),
    }
}

pub fn proto_to_agent(a: pb::DiscoveredAgent) -> Result<DiscoveredAgent, String> {
    let rec = a.assurance.unwrap_or_default();
    Ok(DiscoveredAgent {
        id: a.id,
        name: a.name,
        kind: a.kind,
        config_path: a.config_path,
        hook_installed: a.hook_installed,
        mcp_count: usize::try_from(a.mcp_count).unwrap_or(usize::MAX),
        assurance: AssuranceRecord {
            visibility: proto_to_visibility(rec.visibility),
            control: proto_to_control_strength(rec.control),
            on_failure: proto_to_on_failure(rec.on_failure),
            tamper: proto_to_tamper_grade(rec.tamper),
        },
        assurance_level: proto_to_assurance(a.assurance_level),
        sponsor: a.sponsor,
        detected_at: parse_ts(&a.detected_at)?,
    })
}

pub fn artifact_to_proto(a: &ArtifactEntry) -> pb::ArtifactEntry {
    pb::ArtifactEntry {
        id: a.id.clone(),
        name: a.name.clone(),
        kind: artifact_kind_to_proto(a.kind),
        kind_other: (a.kind == ArtifactKind::Other)
            .then(|| a.kind_other.clone())
            .flatten(),
        scope: artifact_scope_to_proto(a.scope),
        source_agent: a.source_agent.clone(),
        path: a.path.clone(),
        content_digest: a.content_digest.clone(),
        file_count: u64::try_from(a.file_count).unwrap_or(u64::MAX),
        total_bytes: a.total_bytes,
        usage_count: a.usage_count,
        pinned: a.pinned,
        risk_flags: a
            .risk_flags
            .iter()
            .copied()
            .map(artifact_risk_to_proto)
            .collect(),
        device_id: a.device_id.clone(),
        device_name: a.device_name.clone(),
        user_id: a.user_id.clone(),
        detected_at: a.detected_at.to_string(),
    }
}

pub fn proto_to_artifact(a: pb::ArtifactEntry) -> Result<ArtifactEntry, String> {
    let kind = proto_to_artifact_kind(a.kind);
    let kind_other = validate_other_label(a.kind_other, kind == ArtifactKind::Other, "kind_other")?;
    Ok(ArtifactEntry {
        id: a.id,
        name: a.name,
        kind,
        kind_other,
        scope: proto_to_artifact_scope(a.scope),
        source_agent: a.source_agent,
        path: a.path,
        content_digest: a.content_digest,
        file_count: usize::try_from(a.file_count).unwrap_or(usize::MAX),
        total_bytes: a.total_bytes,
        usage_count: a.usage_count,
        pinned: a.pinned,
        risk_flags: a
            .risk_flags
            .into_iter()
            .filter_map(proto_to_artifact_risk)
            .collect(),
        device_id: a.device_id,
        device_name: a.device_name,
        user_id: a.user_id,
        detected_at: parse_ts(&a.detected_at)?,
    })
}

pub fn device_to_proto(d: &Device) -> pb::Device {
    pb::Device {
        id: d.id.clone(),
        hostname: d.hostname.clone(),
        os: d.os.clone(),
        arch: d.arch.clone(),
        install_profile: install_profile_to_proto(d.install_profile),
        daemon_version: d.daemon_version.clone(),
        online: d.online,
        hook_effective: d.hook_effective,
        agents: d.agents.iter().map(agent_to_proto).collect(),
        mcp_servers: d.mcp_servers.iter().map(mcp_to_proto).collect(),
        artifacts: d.artifacts.iter().map(artifact_to_proto).collect(),
        user_id: d.user_id.clone(),
        user_display: d.user_display.clone(),
        last_seen: d.last_seen.to_string(),
        public_key: d.public_key.as_ref().map(key_to_proto),
    }
}

pub fn proto_to_device(d: pb::Device) -> Result<Device, String> {
    let mut agents = Vec::with_capacity(d.agents.len());
    for a in d.agents {
        agents.push(proto_to_agent(a)?);
    }
    let mut artifacts = Vec::with_capacity(d.artifacts.len());
    for art in d.artifacts {
        artifacts.push(proto_to_artifact(art)?);
    }
    Ok(Device {
        id: d.id,
        hostname: d.hostname,
        os: d.os,
        arch: d.arch,
        install_profile: proto_to_install_profile(d.install_profile),
        daemon_version: d.daemon_version,
        online: d.online,
        hook_effective: d.hook_effective,
        agents,
        mcp_servers: d.mcp_servers.into_iter().map(proto_to_mcp).collect(),
        artifacts,
        user_id: d.user_id,
        user_display: d.user_display,
        last_seen: parse_ts(&d.last_seen)?,
        public_key: d.public_key.map(proto_to_key),
    })
}

pub fn attempt_to_proto(a: &ActionAttempt) -> pb::ActionAttempt {
    pb::ActionAttempt {
        id: a.id.clone(),
        session_id: a.session_id.clone(),
        device_id: a.device_id.clone(),
        device_name: a.device_name.clone(),
        agent_name: a.agent_name.clone(),
        action_class: action_class_to_proto(a.action_class),
        control_point: control_point_to_proto(a.control_point),
        target: a.target.clone(),
        summary: a.summary.clone(),
        timestamp: a.timestamp.to_string(),
        user_id: a.user_id.clone(),
        user_display: a.user_display.clone(),
        turn_index: a.turn_index,
        span_id: a.span_id.clone(),
        parent_span_id: a.parent_span_id.clone(),
        span_kind: span_kind_to_proto(a.span_kind),
        duration_ms: a.duration_ms,
        provenance: provenance_to_proto(a.provenance),
        secondary_actions: a
            .secondary_actions
            .iter()
            .map(|s| pb::SecondaryAction {
                command: s.command.clone(),
                action_class: action_class_to_proto(s.action_class),
                target: s.target.clone(),
            })
            .collect(),
        skill_used: a.skill_used.clone(),
        compaction: a.compaction,
    }
}

pub fn proto_to_attempt(a: pb::ActionAttempt) -> Result<ActionAttempt, String> {
    let mut secondary = Vec::with_capacity(a.secondary_actions.len());
    for s in a.secondary_actions {
        secondary.push(SecondaryAction {
            command: s.command,
            action_class: proto_to_action_class(s.action_class).unwrap_or(ActionClass::Exec),
            target: s.target,
        });
    }
    Ok(ActionAttempt {
        id: a.id,
        session_id: a.session_id,
        device_id: a.device_id,
        device_name: a.device_name,
        agent_name: a.agent_name,
        action_class: proto_to_action_class(a.action_class).unwrap_or(ActionClass::Exec),
        control_point: proto_to_control_point(a.control_point).unwrap_or(ControlPoint::Hook),
        target: a.target,
        summary: a.summary,
        timestamp: parse_ts(&a.timestamp)?,
        user_id: a.user_id,
        user_display: a.user_display,
        turn_index: a.turn_index.max(1),
        span_id: a.span_id,
        parent_span_id: a.parent_span_id,
        span_kind: proto_to_span_kind(a.span_kind),
        duration_ms: a.duration_ms,
        provenance: proto_to_provenance(a.provenance),
        secondary_actions: secondary,
        skill_used: a.skill_used,
        compaction: a.compaction,
    })
}

pub fn receipt_to_proto(r: &DecisionReceipt) -> pb::DecisionReceipt {
    pb::DecisionReceipt {
        receipt_id: r.receipt_id.clone(),
        attempt_id: r.attempt_id.clone(),
        session_id: r.session_id.clone(),
        device_id: r.device_id.clone(),
        agent_name: r.agent_name.clone(),
        action_class: action_class_to_proto(r.action_class),
        control_point: control_point_to_proto(r.control_point),
        target: r.target.clone(),
        verdict: verdict_to_proto(r.verdict),
        would_be: r.would_be.map(verdict_to_proto),
        rule_id: r.rule_id.clone(),
        pack_id: r.pack_id.clone(),
        mode_applied: r.mode_applied.map(mode_to_proto),
        grant_id: r.grant_id.clone(),
        reason: r.reason.clone(),
        next_step: r.next_step.clone(),
        receipt_digest: r.receipt_digest.clone(),
        key_id: r.key_id.clone(),
        signature: r.signature.clone(),
        signature_verified: r.signature_verified,
        decided_at: r.decided_at.to_string(),
    }
}

pub fn proto_to_receipt(r: pb::DecisionReceipt) -> Result<DecisionReceipt, String> {
    Ok(DecisionReceipt {
        receipt_id: r.receipt_id,
        attempt_id: r.attempt_id,
        session_id: r.session_id,
        device_id: r.device_id,
        agent_name: r.agent_name,
        action_class: proto_to_action_class(r.action_class).unwrap_or(ActionClass::Exec),
        control_point: proto_to_control_point(r.control_point).unwrap_or(ControlPoint::Hook),
        target: r.target,
        verdict: proto_to_verdict(r.verdict).unwrap_or(Verdict::Allow),
        would_be: r.would_be.and_then(proto_to_verdict),
        rule_id: r.rule_id,
        pack_id: r.pack_id,
        mode_applied: r.mode_applied.and_then(proto_to_mode),
        grant_id: r.grant_id,
        reason: r.reason,
        next_step: r.next_step,
        receipt_digest: r.receipt_digest,
        key_id: r.key_id,
        signature: r.signature,
        signature_verified: r.signature_verified,
        decided_at: parse_ts(&r.decided_at)?,
    })
}

pub fn turn_to_proto(t: &TurnSummary) -> pb::TurnSummary {
    pb::TurnSummary {
        turn_index: t.turn_index,
        trace_id: t.trace_id.clone(),
        span_count: u64::try_from(t.span_count).unwrap_or(u64::MAX),
        duration_ms: t.duration_ms,
        blocked_count: u64::try_from(t.blocked_count).unwrap_or(u64::MAX),
        asked_count: u64::try_from(t.asked_count).unwrap_or(u64::MAX),
        has_compaction: t.has_compaction,
        has_subagent_handoff: t.has_subagent_handoff,
        started_at: t.started_at.to_string(),
    }
}

pub fn session_to_proto(s: &SessionSummary) -> pb::SessionSummary {
    pb::SessionSummary {
        id: s.id.clone(),
        device_id: s.device_id.clone(),
        device_name: s.device_name.clone(),
        agent_name: s.agent_name.clone(),
        user_id: s.user_id.clone(),
        user_display: s.user_display.clone(),
        turn_count: u64::try_from(s.turn_count).unwrap_or(u64::MAX),
        parent_session_id: s.parent_session_id.clone(),
        started_at: s.started_at.to_string(),
        last_activity: s.last_activity.to_string(),
        total_actions: s.total_actions,
        blocked_count: s.blocked_count,
        step_up_count: s.step_up_count,
        watch_hits: s.watch_hits,
        assurance_level: assurance_to_proto(s.assurance_level),
        labels: s
            .labels
            .iter()
            .copied()
            .map(super::enums::session_label_to_proto)
            .collect(),
    }
}

pub fn rule_match_to_proto(m: &RuleMatch) -> pb::RuleMatch {
    pb::RuleMatch {
        action_classes: m
            .action_classes
            .iter()
            .copied()
            .map(action_class_to_proto)
            .collect(),
        target_prefixes: m.target_prefixes.clone(),
        target_contains: m.target_contains.clone(),
        agents: m.agents.clone(),
    }
}

pub fn proto_to_rule_match(m: pb::RuleMatch) -> Result<RuleMatch, String> {
    let mut classes = Vec::with_capacity(m.action_classes.len());
    for raw in m.action_classes {
        let parsed = proto_to_action_class(raw)
            .ok_or_else(|| format!("unsupported action_class tag {raw}"))?;
        classes.push(parsed);
    }
    Ok(RuleMatch {
        action_classes: classes,
        target_prefixes: m.target_prefixes,
        target_contains: m.target_contains,
        agents: m.agents,
    })
}

pub fn rule_to_proto(r: &PolicyRule) -> pb::PolicyRule {
    pb::PolicyRule {
        id: r.id.clone(),
        title: r.title.clone(),
        description: r.description.clone(),
        mode: mode_to_proto(r.mode),
        min_grade: approval_grade_to_proto(r.min_grade),
        enabled: r.enabled,
        locked: r.locked,
        matcher: Some(rule_match_to_proto(&r.matcher)),
        hits: r.hits,
        would_ask_hits: r.would_ask_hits,
        would_block_hits: r.would_block_hits,
        reason_template: r.reason_template.clone(),
        cedar: r.cedar.clone(),
    }
}

pub fn proto_to_rule(r: pb::PolicyRule) -> Result<PolicyRule, String> {
    Ok(PolicyRule {
        id: r.id,
        title: r.title,
        description: r.description,
        mode: proto_to_mode(r.mode).unwrap_or(crate::Mode::Watch),
        min_grade: proto_to_approval_grade(r.min_grade).unwrap_or(crate::ApprovalGrade::G1),
        enabled: r.enabled,
        locked: r.locked,
        matcher: r
            .matcher
            .map(proto_to_rule_match)
            .transpose()?
            .unwrap_or(RuleMatch {
                action_classes: Vec::new(),
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            }),
        hits: r.hits,
        would_ask_hits: r.would_ask_hits,
        would_block_hits: r.would_block_hits,
        reason_template: r.reason_template,
        cedar: r.cedar,
    })
}

pub fn pack_to_proto(p: &PolicyPack) -> pb::PolicyPack {
    pb::PolicyPack {
        id: p.id.clone(),
        name: p.name.clone(),
        description: p.description.clone(),
        version: p.version.clone(),
        channel: p.channel.clone(),
        rules: p.rules.iter().map(rule_to_proto).collect(),
        key_id: p.key_id.clone(),
        signature: p.signature.clone(),
    }
}

pub fn proto_to_pack(p: pb::PolicyPack) -> Result<PolicyPack, String> {
    let mut rules = Vec::with_capacity(p.rules.len());
    for r in p.rules {
        rules.push(proto_to_rule(r)?);
    }
    Ok(PolicyPack {
        id: p.id,
        name: p.name,
        description: p.description,
        version: p.version,
        channel: p.channel,
        rules,
        key_id: p.key_id,
        signature: p.signature,
    })
}
