// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_proto::common as pb;

use crate::{
    ArtifactKind, ArtifactRiskFlag, ArtifactScope, FindingClass, FindingLifecycle, FindingSeverity,
    MAX_OTHER_LABEL_CHARS,
};

pub(crate) fn validate_other_label(
    raw: Option<String>,
    is_other: bool,
    field_name: &str,
) -> Result<Option<String>, String> {
    if !is_other {
        return Ok(None);
    }
    let Some(val) = raw else {
        return Ok(None);
    };
    if val.trim().is_empty() {
        return Err(format!("{field_name} cannot be empty or whitespace-only"));
    }
    if val.chars().any(char::is_control) {
        return Err(format!("{field_name} cannot contain control characters"));
    }
    if val.chars().count() > MAX_OTHER_LABEL_CHARS {
        return Err(format!(
            "{field_name} exceeds {MAX_OTHER_LABEL_CHARS} character limit"
        ));
    }
    Ok(Some(val))
}

pub fn finding_class_to_proto(val: FindingClass) -> i32 {
    match val {
        FindingClass::Threat => pb::FindingClass::Threat as i32,
        FindingClass::PolicyViolation => pb::FindingClass::PolicyViolation as i32,
        FindingClass::Overeager => pb::FindingClass::Overeager as i32,
        FindingClass::Tamper => pb::FindingClass::Tamper as i32,
        FindingClass::CoverageGap => pb::FindingClass::CoverageGap as i32,
        FindingClass::Other => pb::FindingClass::Other as i32,
    }
}

pub fn proto_to_finding_class(val: i32) -> FindingClass {
    match pb::FindingClass::try_from(val).ok() {
        Some(pb::FindingClass::Threat | pb::FindingClass::Unspecified) => FindingClass::Threat,
        Some(pb::FindingClass::PolicyViolation) => FindingClass::PolicyViolation,
        Some(pb::FindingClass::Overeager) => FindingClass::Overeager,
        Some(pb::FindingClass::Tamper) => FindingClass::Tamper,
        Some(pb::FindingClass::CoverageGap) => FindingClass::CoverageGap,
        Some(pb::FindingClass::Other) | None => FindingClass::Other,
    }
}

pub fn finding_severity_to_proto(val: FindingSeverity) -> i32 {
    match val {
        FindingSeverity::Low => pb::FindingSeverity::Low as i32,
        FindingSeverity::Medium => pb::FindingSeverity::Medium as i32,
        FindingSeverity::High => pb::FindingSeverity::High as i32,
        FindingSeverity::Critical => pb::FindingSeverity::Critical as i32,
    }
}

pub fn proto_to_finding_severity(val: i32) -> FindingSeverity {
    match pb::FindingSeverity::try_from(val).ok() {
        Some(pb::FindingSeverity::Medium) => FindingSeverity::Medium,
        Some(pb::FindingSeverity::High) => FindingSeverity::High,
        Some(pb::FindingSeverity::Critical) => FindingSeverity::Critical,
        _ => FindingSeverity::Low,
    }
}

pub fn finding_lifecycle_to_proto(val: FindingLifecycle) -> i32 {
    match val {
        FindingLifecycle::Open => pb::FindingLifecycle::Open as i32,
        FindingLifecycle::Acknowledged => pb::FindingLifecycle::Acknowledged as i32,
        FindingLifecycle::Contained => pb::FindingLifecycle::Contained as i32,
        FindingLifecycle::Resolved => pb::FindingLifecycle::Resolved as i32,
    }
}

pub fn proto_to_finding_lifecycle(val: i32) -> Option<FindingLifecycle> {
    match pb::FindingLifecycle::try_from(val).ok()? {
        pb::FindingLifecycle::Open => Some(FindingLifecycle::Open),
        pb::FindingLifecycle::Acknowledged => Some(FindingLifecycle::Acknowledged),
        pb::FindingLifecycle::Contained => Some(FindingLifecycle::Contained),
        pb::FindingLifecycle::Resolved => Some(FindingLifecycle::Resolved),
        pb::FindingLifecycle::Unspecified => None,
    }
}

pub fn artifact_kind_to_proto(val: ArtifactKind) -> i32 {
    match val {
        ArtifactKind::Skill => pb::ArtifactKind::Skill as i32,
        ArtifactKind::Rule => pb::ArtifactKind::Rule as i32,
        ArtifactKind::Plugin => pb::ArtifactKind::Plugin as i32,
        ArtifactKind::Command => pb::ArtifactKind::Command as i32,
        ArtifactKind::Subagent => pb::ArtifactKind::Subagent as i32,
        ArtifactKind::Other => pb::ArtifactKind::Other as i32,
    }
}

pub fn proto_to_artifact_kind(val: i32) -> ArtifactKind {
    match pb::ArtifactKind::try_from(val).ok() {
        Some(pb::ArtifactKind::Skill | pb::ArtifactKind::Unspecified) => ArtifactKind::Skill,
        Some(pb::ArtifactKind::Rule) => ArtifactKind::Rule,
        Some(pb::ArtifactKind::Plugin) => ArtifactKind::Plugin,
        Some(pb::ArtifactKind::Command) => ArtifactKind::Command,
        Some(pb::ArtifactKind::Subagent) => ArtifactKind::Subagent,
        Some(pb::ArtifactKind::Other) | None => ArtifactKind::Other,
    }
}

pub fn artifact_scope_to_proto(val: ArtifactScope) -> i32 {
    match val {
        ArtifactScope::User => pb::ArtifactScope::User as i32,
        ArtifactScope::Workspace => pb::ArtifactScope::Workspace as i32,
        ArtifactScope::Managed => pb::ArtifactScope::Managed as i32,
    }
}

pub fn proto_to_artifact_scope(val: i32) -> ArtifactScope {
    match pb::ArtifactScope::try_from(val).ok() {
        Some(pb::ArtifactScope::Workspace) => ArtifactScope::Workspace,
        Some(pb::ArtifactScope::Managed) => ArtifactScope::Managed,
        _ => ArtifactScope::User,
    }
}

pub fn artifact_risk_to_proto(val: ArtifactRiskFlag) -> i32 {
    match val {
        ArtifactRiskFlag::HasScripts => pb::ArtifactRiskFlag::HasScripts as i32,
        ArtifactRiskFlag::RequestsBroadTools => pb::ArtifactRiskFlag::RequestsBroadTools as i32,
        ArtifactRiskFlag::BidiObfuscation => pb::ArtifactRiskFlag::BidiObfuscation as i32,
        ArtifactRiskFlag::UnpinnedDigest => pb::ArtifactRiskFlag::UnpinnedDigest as i32,
    }
}

pub fn proto_to_artifact_risk(val: i32) -> Option<ArtifactRiskFlag> {
    match pb::ArtifactRiskFlag::try_from(val).ok()? {
        pb::ArtifactRiskFlag::HasScripts => Some(ArtifactRiskFlag::HasScripts),
        pb::ArtifactRiskFlag::RequestsBroadTools => Some(ArtifactRiskFlag::RequestsBroadTools),
        pb::ArtifactRiskFlag::BidiObfuscation => Some(ArtifactRiskFlag::BidiObfuscation),
        pb::ArtifactRiskFlag::UnpinnedDigest => Some(ArtifactRiskFlag::UnpinnedDigest),
        pb::ArtifactRiskFlag::Unspecified => None,
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use crate::proto_conv::{
        artifact_to_proto, finding_to_proto, proto_to_artifact, proto_to_finding,
    };
    use crate::{
        ArtifactEntry, ArtifactKind, ArtifactRiskFlag, ArtifactScope, Finding, FindingClass,
        FindingLifecycle, FindingSeverity,
    };

    #[test]
    fn artifact_kind_other_lossless_round_trip() {
        let ts = "2026-06-01T12:00:00Z".parse::<Timestamp>().expect("ts");
        let entry = ArtifactEntry {
            id: "art_oth_ws_prompt".into(),
            name: "review-template".into(),
            kind: ArtifactKind::Other,
            kind_other: Some("prompt-template".into()),
            scope: ArtifactScope::Workspace,
            source_agent: "claude-code".into(),
            path: ".claude/prompts/review.md".into(),
            content_digest: "abc123".into(),
            file_count: 1,
            total_bytes: 512,
            usage_count: 2,
            pinned: true,
            risk_flags: vec![ArtifactRiskFlag::RequestsBroadTools],
            device_id: "dev-1".into(),
            device_name: "ws-1".into(),
            user_id: Some("usr-1".into()),
            detected_at: ts,
        };

        let proto = artifact_to_proto(&entry);
        assert_eq!(proto.kind_other.as_deref(), Some("prompt-template"));
        let decoded = proto_to_artifact(proto).expect("proto_to_artifact");
        assert_eq!(decoded, entry);

        let json = serde_json::to_string(&entry).expect("serialize");
        let from_json: ArtifactEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(from_json, entry);
    }

    #[test]
    fn finding_class_other_lossless_round_trip() {
        let ts = "2026-06-01T12:00:00Z".parse::<Timestamp>().expect("ts");
        let finding = Finding {
            id: "fnd-oth-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "ws-1".into(),
            agent_name: "codex".into(),
            class: FindingClass::Other,
            finding_class_other: Some("supply_chain_drift".into()),
            severity: FindingSeverity::High,
            lifecycle: FindingLifecycle::Acknowledged,
            rule_id: Some("custom.rule".into()),
            title: "Custom drift".into(),
            summary: "Detected out-of-band manifest edit".into(),
            target: "mcp.json".into(),
            detected_at: ts,
        };

        let proto = finding_to_proto(&finding);
        assert_eq!(
            proto.finding_class_other.as_deref(),
            Some("supply_chain_drift")
        );
        let decoded = proto_to_finding(proto).expect("proto_to_finding");
        assert_eq!(decoded, finding);

        let json = serde_json::to_string(&finding).expect("serialize");
        let from_json: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(from_json, finding);
    }

    #[test]
    fn other_labels_enforce_bounds_clear_on_non_other_and_fallback_unknown_enum() {
        use grdr_proto::common as pb;

        assert_eq!(
            crate::proto_conv::proto_to_artifact_kind(9_999),
            ArtifactKind::Other
        );
        assert_eq!(
            crate::proto_conv::proto_to_finding_class(9_999),
            FindingClass::Other
        );

        let mut base_art = artifact_to_proto(&ArtifactEntry {
            id: "art-1".into(),
            name: "n".into(),
            kind: ArtifactKind::Skill,
            kind_other: Some("stale".into()),
            scope: ArtifactScope::Workspace,
            source_agent: "claude".into(),
            path: "p".into(),
            content_digest: "d".into(),
            file_count: 1,
            total_bytes: 1,
            usage_count: 1,
            pinned: false,
            risk_flags: vec![],
            device_id: "dev".into(),
            device_name: "ws".into(),
            user_id: None,
            detected_at: "2026-06-01T12:00:00Z".parse::<Timestamp>().expect("ts"),
        });
        assert!(base_art.kind_other.is_none());
        base_art.kind_other = Some("stale".into());
        let cleared_art = proto_to_artifact(base_art.clone()).expect("non-Other clears stale");
        assert_eq!(cleared_art.kind_other, None);

        base_art.kind = pb::ArtifactKind::Other as i32;
        base_art.kind_other = None;
        assert_eq!(
            proto_to_artifact(base_art.clone())
                .expect("Other without label")
                .kind_other,
            None
        );

        for bad in ["", "   ", "bad\nline", "bad\0nul", &"x".repeat(129)] {
            base_art.kind_other = Some(bad.to_owned());
            assert!(
                proto_to_artifact(base_art.clone()).is_err(),
                "expected rejection for kind_other={bad:?}"
            );
        }
        base_art.kind_other = Some("a".repeat(128));
        assert!(proto_to_artifact(base_art).is_ok());

        let mut base_finding = finding_to_proto(&Finding {
            id: "f-1".into(),
            session_id: "s-1".into(),
            device_id: "d-1".into(),
            device_name: "ws".into(),
            agent_name: "claude".into(),
            class: FindingClass::Threat,
            finding_class_other: Some("stale".into()),
            severity: FindingSeverity::Low,
            lifecycle: FindingLifecycle::Open,
            rule_id: None,
            title: "t".into(),
            summary: "s".into(),
            target: "x".into(),
            detected_at: "2026-06-01T12:00:00Z".parse::<Timestamp>().expect("ts"),
        });
        assert!(base_finding.finding_class_other.is_none());
        base_finding.finding_class_other = Some("stale".into());
        let cleared_finding =
            proto_to_finding(base_finding.clone()).expect("non-Other finding clears stale");
        assert_eq!(cleared_finding.finding_class_other, None);

        base_finding.finding_class = pb::FindingClass::Other as i32;
        base_finding.finding_class_other = None;
        assert_eq!(
            proto_to_finding(base_finding.clone())
                .expect("Other finding without label")
                .finding_class_other,
            None
        );

        for bad in ["", " \t ", "ctrl\rbad", "null\0byte", &"y".repeat(129)] {
            base_finding.finding_class_other = Some(bad.to_owned());
            assert!(
                proto_to_finding(base_finding.clone()).is_err(),
                "expected rejection for finding_class_other={bad:?}"
            );
        }
    }
}
