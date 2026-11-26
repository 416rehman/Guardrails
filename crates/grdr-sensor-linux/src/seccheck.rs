// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::log_safe::sanitize_log_fragment;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

use crate::SensorError;
use crate::cri::CriWorkloadIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccheckLimits {
    pub max_line_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccheckEventKind {
    Execve,
    Open,
    Connect,
    ContainerStart,
    ContainerExit,
    Syscall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccheckRawEvent {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub container_id: String,
    pub kind: SeccheckEventKind,
    #[serde(default)]
    pub is_exec_session: bool,
    #[serde(default)]
    pub exec_id: Option<String>,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub write_intent: bool,
}

pub fn parse_seccheck_json_line(
    line: &str,
    workload: Option<&CriWorkloadIdentity>,
    limits: &SeccheckLimits,
) -> Result<ActionAttempt, SensorError> {
    if limits.max_line_bytes == 0 {
        return Err(SensorError::SeccheckParse {
            detail: "seccheck max_line_bytes limit must be > 0".into(),
        });
    }
    if line.len() > limits.max_line_bytes {
        return Err(SensorError::SeccheckParse {
            detail: format!("seccheck line exceeds {} byte limit", limits.max_line_bytes),
        });
    }
    let raw: SeccheckRawEvent =
        serde_json::from_str(line).map_err(|err| SensorError::SeccheckParse {
            detail: err.to_string(),
        })?;
    let cid = raw.container_id.trim();
    if cid.is_empty()
        || cid.chars().any(char::is_control)
        || cid.contains('/')
        || cid.contains(':')
        || cid.contains('\\')
    {
        return Err(SensorError::SeccheckParse {
            detail: "seccheck container_id invalid".into(),
        });
    }
    if let Some(eid) = raw.exec_id.as_deref()
        && (eid.chars().any(char::is_control)
            || eid.contains('/')
            || eid.contains(':')
            || eid.contains('\\'))
    {
        return Err(SensorError::SeccheckParse {
            detail: "seccheck exec_id invalid".into(),
        });
    }

    let action_class = match raw.kind {
        SeccheckEventKind::Execve
        | SeccheckEventKind::ContainerStart
        | SeccheckEventKind::ContainerExit
        | SeccheckEventKind::Syscall => ActionClass::Exec,
        SeccheckEventKind::Open => {
            if raw.write_intent {
                ActionClass::FileWrite
            } else {
                ActionClass::FileRead
            }
        }
        SeccheckEventKind::Connect => ActionClass::NetConnect,
    };

    let (base_session, device_id, device_name, agent_name) = match workload {
        Some(meta) => (
            meta.agent_session_id.clone(),
            meta.canonical_device_id(),
            meta.pod.clone(),
            meta.agent_name.clone(),
        ),
        None => {
            let short: String = cid.chars().take(12).collect();
            (
                format!("gvisor-{short}"),
                format!("gvisor/{short}"),
                short,
                "gvisor-workload".into(),
            )
        }
    };

    let session_id = if raw.is_exec_session {
        let exec_suffix = raw
            .exec_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or("interactive");
        format!("{base_session}:exec:{exec_suffix}")
    } else {
        base_session
    };

    let target_raw = if raw.argv.is_empty() {
        raw.target.clone()
    } else {
        raw.argv.join(" ")
    };
    let target = sanitize_log_fragment(&target_raw, 512);

    let summary_raw = format!(
        "gVisor seccheck kind={:?} pid={} exec_session={}",
        raw.kind, raw.pid, raw.is_exec_session
    );
    let summary = sanitize_log_fragment(&summary_raw, 256);
    let ts = i64::try_from(raw.timestamp_ns)
        .ok()
        .and_then(|ns| Timestamp::from_nanosecond(i128::from(ns)).ok())
        .unwrap_or_else(Timestamp::now);

    Ok(ActionAttempt {
        id: format!("att-gvisor-{}", raw.seq),
        session_id,
        device_id,
        device_name,
        agent_name,
        action_class,
        control_point: ControlPoint::Sensor,
        target,
        summary,
        timestamp: ts,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::cri::{CriLimits, CriRawContainerMeta, CriRuntimeKind, normalize_cri_metadata};

    #[test]
    fn keeps_kubectl_exec_session_separate_from_pod_entrypoint_session() {
        let mut labels = BTreeMap::new();
        labels.insert("io.kubernetes.pod.namespace".into(), "agents".into());
        labels.insert("io.kubernetes.pod.name".into(), "worker-0".into());
        labels.insert("io.kubernetes.container.name".into(), "agent".into());
        let mut annotations = BTreeMap::new();
        annotations.insert("agents.x-k8s.io/session-id".into(), "sess-pod-1".into());
        annotations.insert("agents.x-k8s.io/agent-name".into(), "runner".into());

        let cri_limits = CriLimits {
            max_field_bytes: 512,
            max_annotations: 128,
        };
        let sec_limits = SeccheckLimits {
            max_line_bytes: 32_768,
        };
        let meta = normalize_cri_metadata(
            &CriRawContainerMeta {
                runtime: CriRuntimeKind::Containerd,
                cluster: "prod".into(),
                container_id: "abcdef123456".into(),
                image_digest: "sha256:abc".into(),
                runtime_class: "gvisor".into(),
                cgroup_path: "/kubepods".into(),
                cgroup_inode: 55,
                labels,
                annotations,
            },
            &cri_limits,
        )
        .unwrap();

        let root_line = r#"{"seq":1,"timestamp_ns":1700000000000000000,"container_id":"abcdef123456","kind":"execve","is_exec_session":false,"pid":1,"target":"/usr/bin/python3","argv":["python3","main.py"]}"#;
        let exec_line = r#"{"seq":2,"timestamp_ns":1700000001000000000,"container_id":"abcdef123456","kind":"execve","is_exec_session":true,"exec_id":"kubectl-77","pid":9,"target":"/bin/sh","argv":["sh","-c","env"]}"#;

        let root_attempt = parse_seccheck_json_line(root_line, Some(&meta), &sec_limits).unwrap();
        let exec_attempt = parse_seccheck_json_line(exec_line, Some(&meta), &sec_limits).unwrap();

        assert_eq!(root_attempt.session_id, "sess-pod-1");
        assert_eq!(exec_attempt.session_id, "sess-pod-1:exec:kubectl-77");
        assert_ne!(root_attempt.session_id, exec_attempt.session_id);
        assert_eq!(exec_attempt.action_class, ActionClass::Exec);
    }

    #[test]
    fn rejects_oversized_seccheck_line_and_bad_container_id() {
        let sec_limits = SeccheckLimits {
            max_line_bytes: 32_768,
        };
        let oversized = "x".repeat(sec_limits.max_line_bytes + 1);
        assert!(matches!(
            parse_seccheck_json_line(&oversized, None, &sec_limits),
            Err(SensorError::SeccheckParse { .. })
        ));
        let bad_cid = r#"{"seq":3,"timestamp_ns":1,"container_id":"abc/evil:x","kind":"execve"}"#;
        assert!(matches!(
            parse_seccheck_json_line(bad_cid, None, &sec_limits),
            Err(SensorError::SeccheckParse { .. })
        ));
    }
}
