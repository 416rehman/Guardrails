// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_proto::common as pb;

use super::enums::{
    action_class_to_proto, approval_grade_to_proto, finding_class_to_proto,
    finding_lifecycle_to_proto, finding_severity_to_proto, grant_scope_to_proto,
    identity_mode_to_proto, kill_scope_to_proto, proto_to_action_class, proto_to_approval_grade,
    proto_to_finding_class, proto_to_finding_lifecycle, proto_to_finding_severity,
    proto_to_grant_scope, risk_tier_to_proto, session_label_to_proto, validate_other_label,
};
use super::resources::parse_ts;
use crate::{
    ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, AuditEntry, Finding, FindingClass,
    FindingLifecycle, Grant, GrantScope, Incident, KillSwitchState, OrgPrivacyConfig, UserProfile,
};

pub fn grant_to_proto(g: &Grant) -> pb::Grant {
    pb::Grant {
        grant_id: g.grant_id.clone(),
        rule_id: g.rule_id.clone(),
        session_id: g.session_id.clone(),
        device_id: g.device_id.clone(),
        action_class: action_class_to_proto(g.action_class),
        target_pattern: g.target_pattern.clone(),
        scope: grant_scope_to_proto(g.scope),
        grade: approval_grade_to_proto(g.grade),
        granted_at: g.granted_at.to_string(),
        expires_at: g.expires_at.map(|ts| ts.to_string()),
        remaining_uses: g.remaining_uses,
        note: g.note.clone(),
        key_id: g.key_id.clone(),
        signature: g.signature.clone(),
    }
}

pub fn proto_to_grant(g: pb::Grant) -> Result<Grant, String> {
    Ok(Grant {
        grant_id: g.grant_id,
        rule_id: g.rule_id,
        session_id: g.session_id,
        device_id: g.device_id,
        action_class: proto_to_action_class(g.action_class).unwrap_or(ActionClass::Exec),
        target_pattern: g.target_pattern,
        scope: proto_to_grant_scope(g.scope).unwrap_or(GrantScope::Once),
        grade: proto_to_approval_grade(g.grade).unwrap_or(ApprovalGrade::G1),
        granted_at: parse_ts(&g.granted_at)?,
        expires_at: g.expires_at.as_deref().map(parse_ts).transpose()?,
        remaining_uses: g.remaining_uses,
        note: g.note,
        key_id: g.key_id,
        signature: g.signature,
    })
}

pub fn approval_to_proto(a: &ApprovalRequest) -> pb::ApprovalRequest {
    let (status, expires_at, grant_id, scope, decided_at, note) = match &a.state {
        ApprovalState::Pending { expires_at } => (
            pb::ApprovalStatus::Pending as i32,
            Some(expires_at.to_string()),
            None,
            None,
            None,
            None,
        ),
        ApprovalState::Approved {
            grant_id,
            scope,
            decided_at,
            note,
        } => (
            pb::ApprovalStatus::Approved as i32,
            None,
            Some(grant_id.clone()),
            Some(grant_scope_to_proto(*scope)),
            Some(decided_at.to_string()),
            Some(note.clone()),
        ),
        ApprovalState::Denied { decided_at, note } => (
            pb::ApprovalStatus::Denied as i32,
            None,
            None,
            None,
            Some(decided_at.to_string()),
            Some(note.clone()),
        ),
        ApprovalState::Expired { expired_at } => (
            pb::ApprovalStatus::Expired as i32,
            Some(expired_at.to_string()),
            None,
            None,
            None,
            None,
        ),
    };
    pb::ApprovalRequest {
        id: a.id.clone(),
        receipt_id: a.receipt_id.clone(),
        session_id: a.session_id.clone(),
        device_id: a.device_id.clone(),
        device_name: a.device_name.clone(),
        agent_name: a.agent_name.clone(),
        action_class: action_class_to_proto(a.action_class),
        target: a.target.clone(),
        rule_id: a.rule_id.clone(),
        rule_title: a.rule_title.clone(),
        required_grade: approval_grade_to_proto(a.required_grade),
        reason: a.reason.clone(),
        requested_at: a.requested_at.to_string(),
        status,
        expires_at,
        grant_id,
        scope,
        decided_at,
        note,
    }
}

pub fn finding_to_proto(f: &Finding) -> pb::Finding {
    pb::Finding {
        id: f.id.clone(),
        session_id: f.session_id.clone(),
        device_id: f.device_id.clone(),
        device_name: f.device_name.clone(),
        agent_name: f.agent_name.clone(),
        finding_class: finding_class_to_proto(f.class),
        finding_class_other: (f.class == FindingClass::Other)
            .then(|| f.finding_class_other.clone())
            .flatten(),
        severity: finding_severity_to_proto(f.severity),
        lifecycle: finding_lifecycle_to_proto(f.lifecycle),
        rule_id: f.rule_id.clone(),
        title: f.title.clone(),
        summary: f.summary.clone(),
        target: f.target.clone(),
        detected_at: f.detected_at.to_string(),
    }
}

pub fn proto_to_finding(f: pb::Finding) -> Result<Finding, String> {
    let class = proto_to_finding_class(f.finding_class);
    let finding_class_other = validate_other_label(
        f.finding_class_other,
        class == FindingClass::Other,
        "finding_class_other",
    )?;
    Ok(Finding {
        id: f.id,
        session_id: f.session_id,
        device_id: f.device_id,
        device_name: f.device_name,
        agent_name: f.agent_name,
        class,
        finding_class_other,
        severity: proto_to_finding_severity(f.severity),
        lifecycle: proto_to_finding_lifecycle(f.lifecycle).unwrap_or(FindingLifecycle::Open),
        rule_id: f.rule_id,
        title: f.title,
        summary: f.summary,
        target: f.target,
        detected_at: parse_ts(&f.detected_at)?,
    })
}

pub fn incident_to_proto(i: &Incident) -> pb::Incident {
    pb::Incident {
        id: i.id.clone(),
        session_id: i.session_id.clone(),
        device_id: i.device_id.clone(),
        device_name: i.device_name.clone(),
        agent_name: i.agent_name.clone(),
        title: i.title.clone(),
        summary: i.summary.clone(),
        severity: finding_severity_to_proto(i.severity),
        lifecycle: finding_lifecycle_to_proto(i.lifecycle),
        finding_ids: i.finding_ids.clone(),
        finding_count: u64::try_from(i.finding_count).unwrap_or(u64::MAX),
        labels: i
            .labels
            .iter()
            .copied()
            .map(session_label_to_proto)
            .collect(),
        first_seen: i.first_seen.to_string(),
        last_seen: i.last_seen.to_string(),
    }
}

pub fn audit_to_proto(a: &AuditEntry) -> pb::AuditEntry {
    pb::AuditEntry {
        id: a.id.clone(),
        timestamp: a.timestamp.to_string(),
        kind: a.kind.clone(),
        actor: a.actor.clone(),
        summary: a.summary.clone(),
        target: a.target.clone(),
    }
}

pub fn kill_switch_to_proto(k: &KillSwitchState) -> pb::KillSwitchState {
    match k {
        KillSwitchState::Inactive => pb::KillSwitchState {
            state: pb::KillState::Inactive as i32,
            scope: None,
            target_id: None,
            reason: None,
            issued_at: None,
            expires_at: None,
        },
        KillSwitchState::Frozen {
            scope,
            target_id,
            reason,
            issued_at,
            expires_at,
        } => pb::KillSwitchState {
            state: pb::KillState::Frozen as i32,
            scope: Some(kill_scope_to_proto(*scope)),
            target_id: Some(target_id.clone()),
            reason: Some(reason.clone()),
            issued_at: Some(issued_at.to_string()),
            expires_at: Some(expires_at.to_string()),
        },
        KillSwitchState::Killed {
            scope,
            target_id,
            reason,
            issued_at,
        } => pb::KillSwitchState {
            state: pb::KillState::Killed as i32,
            scope: Some(kill_scope_to_proto(*scope)),
            target_id: Some(target_id.clone()),
            reason: Some(reason.clone()),
            issued_at: Some(issued_at.to_string()),
            expires_at: None,
        },
    }
}

pub fn proto_to_kill_switch(k: pb::KillSwitchState) -> Result<KillSwitchState, String> {
    let state = pb::KillState::try_from(k.state).unwrap_or(pb::KillState::Inactive);
    match state {
        pb::KillState::Frozen => Ok(KillSwitchState::Frozen {
            scope: k
                .scope
                .and_then(super::enums::proto_to_kill_scope)
                .unwrap_or(crate::KillScope::Organisation),
            target_id: k.target_id.unwrap_or_default(),
            reason: k.reason.unwrap_or_default(),
            issued_at: parse_ts(k.issued_at.as_deref().unwrap_or_default())?,
            expires_at: parse_ts(k.expires_at.as_deref().unwrap_or_default())?,
        }),
        pb::KillState::Killed => Ok(KillSwitchState::Killed {
            scope: k
                .scope
                .and_then(super::enums::proto_to_kill_scope)
                .unwrap_or(crate::KillScope::Organisation),
            target_id: k.target_id.unwrap_or_default(),
            reason: k.reason.unwrap_or_default(),
            issued_at: parse_ts(k.issued_at.as_deref().unwrap_or_default())?,
        }),
        _ => Ok(KillSwitchState::Inactive),
    }
}

pub fn user_to_proto(u: &UserProfile) -> pb::UserProfile {
    pb::UserProfile {
        id: u.id.clone(),
        display_name: u.display_name.clone(),
        email: u.email.clone(),
        department: u.department.clone(),
        idp_source: u.idp_source.clone(),
        pseudonym_id: u.pseudonym_id.clone(),
        device_ids: u.device_ids.clone(),
        agent_names: u.agent_names.clone(),
        artifact_count: u64::try_from(u.artifact_count).unwrap_or(u64::MAX),
        session_count: u64::try_from(u.session_count).unwrap_or(u64::MAX),
        blocked_count: u64::try_from(u.blocked_count).unwrap_or(u64::MAX),
        asked_count: u64::try_from(u.asked_count).unwrap_or(u64::MAX),
        watch_count: u64::try_from(u.watch_count).unwrap_or(u64::MAX),
        finding_count: u64::try_from(u.finding_count).unwrap_or(u64::MAX),
        risk_score: u.risk_score,
        risk_tier: risk_tier_to_proto(u.risk_tier),
        risk_factors: u
            .risk_factors
            .iter()
            .map(|f| pb::UserRiskFactor {
                code: f.code.clone(),
                label: f.label.clone(),
                points: f.points,
                count: f.count,
            })
            .collect(),
        last_active: u.last_active.to_string(),
    }
}

pub fn privacy_to_proto(c: &OrgPrivacyConfig) -> pb::OrgPrivacyConfig {
    pb::OrgPrivacyConfig {
        identity_mode: identity_mode_to_proto(c.identity_mode),
        user_risk_scoring: c.user_risk_scoring,
    }
}
