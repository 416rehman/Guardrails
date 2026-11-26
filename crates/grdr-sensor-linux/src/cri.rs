// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SensorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriLimits {
    pub max_field_bytes: usize,
    pub max_annotations: usize,
}

const LABEL_POD_NAMESPACE: &str = "io.kubernetes.pod.namespace";
const LABEL_POD_NAME: &str = "io.kubernetes.pod.name";
const LABEL_CONTAINER_NAME: &str = "io.kubernetes.container.name";
const ANN_AGENT_SESSION: &str = "agents.x-k8s.io/session-id";
const ANN_AGENT_NAME: &str = "agents.x-k8s.io/agent-name";
const ANN_EXEC_ID: &str = "agents.x-k8s.io/exec-id";
const ANN_SPIFFE_ID: &str = "spiffe.io/spiffe-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriRuntimeKind {
    Containerd,
    CriO,
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriRawContainerMeta {
    pub runtime: CriRuntimeKind,
    pub cluster: String,
    pub container_id: String,
    pub image_digest: String,
    pub runtime_class: String,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriWorkloadIdentity {
    pub runtime: CriRuntimeKind,
    pub cluster: String,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub container_id: String,
    pub image_digest: String,
    pub runtime_class: String,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub agent_session_id: String,
    pub agent_name: String,
    pub spiffe_id: Option<String>,
    pub exec_id: Option<String>,
}

impl CriWorkloadIdentity {
    pub fn canonical_device_id(&self) -> String {
        format!("{}/{}/{}", self.cluster, self.namespace, self.pod)
    }

    pub fn canonical_session_id(&self) -> String {
        if let Some(exec_id) = &self.exec_id {
            return format!("{}:exec:{}", self.agent_session_id, exec_id);
        }
        self.agent_session_id.clone()
    }
}

pub fn normalize_cri_metadata(
    raw: &CriRawContainerMeta,
    limits: &CriLimits,
) -> Result<CriWorkloadIdentity, SensorError> {
    if limits.max_field_bytes == 0 || limits.max_annotations == 0 {
        return Err(SensorError::CriNormalize {
            detail: "CRI limits must be > 0".into(),
        });
    }
    if raw.labels.len() > limits.max_annotations || raw.annotations.len() > limits.max_annotations {
        return Err(SensorError::CriNormalize {
            detail: format!("metadata map exceeds {} entries", limits.max_annotations),
        });
    }

    let container_id = sanitize_segment("container_id", &raw.container_id, false, limits)?;
    let cluster = if raw.cluster.trim().is_empty() {
        "default-cluster".to_string()
    } else {
        sanitize_segment("cluster", &raw.cluster, false, limits)?
    };
    let namespace = pick_map_segment(&raw.labels, LABEL_POD_NAMESPACE, "default", limits)?;
    let pod = pick_map_segment(&raw.labels, LABEL_POD_NAME, "unknown-pod", limits)?;
    let container = pick_map_segment(&raw.labels, LABEL_CONTAINER_NAME, "main", limits)?;
    let image_digest = sanitize_field("image_digest", &raw.image_digest, true, limits)?;
    let runtime_class = if raw.runtime_class.trim().is_empty() {
        "runc".to_string()
    } else {
        sanitize_segment("runtime_class", &raw.runtime_class, false, limits)?
    };
    let cgroup_path = sanitize_field("cgroup_path", &raw.cgroup_path, true, limits)?;

    let short_cid: String = container_id.chars().take(12).collect();
    let default_session = format!("k8s-{namespace}-{pod}-{short_cid}");
    let agent_session_id = pick_map_segment(
        &raw.annotations,
        ANN_AGENT_SESSION,
        &default_session,
        limits,
    )?;
    let agent_name = pick_map_segment(&raw.annotations, ANN_AGENT_NAME, &container, limits)?;
    let spiffe_id = optional_map_field(&raw.annotations, ANN_SPIFFE_ID, limits)?;
    let exec_id = optional_map_segment(&raw.annotations, ANN_EXEC_ID, limits)?;

    Ok(CriWorkloadIdentity {
        runtime: raw.runtime,
        cluster,
        namespace,
        pod,
        container,
        container_id,
        image_digest,
        runtime_class,
        cgroup_path,
        cgroup_inode: raw.cgroup_inode,
        agent_session_id,
        agent_name,
        spiffe_id,
        exec_id,
    })
}

fn sanitize_field(
    name: &str,
    value: &str,
    allow_empty: bool,
    limits: &CriLimits,
) -> Result<String, SensorError> {
    let trimmed = value.trim();
    if !allow_empty && trimmed.is_empty() {
        return Err(SensorError::CriNormalize {
            detail: format!("CRI field `{name}` cannot be empty"),
        });
    }
    if trimmed.len() > limits.max_field_bytes {
        return Err(SensorError::CriNormalize {
            detail: format!(
                "CRI field `{name}` exceeds {} bytes",
                limits.max_field_bytes
            ),
        });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(SensorError::CriNormalize {
            detail: format!("CRI field `{name}` contains disallowed control characters"),
        });
    }
    Ok(trimmed.to_string())
}

fn sanitize_segment(
    name: &str,
    value: &str,
    allow_empty: bool,
    limits: &CriLimits,
) -> Result<String, SensorError> {
    let cleaned = sanitize_field(name, value, allow_empty, limits)?;
    if cleaned.contains('/') || cleaned.contains(':') || cleaned.contains('\\') {
        return Err(SensorError::CriNormalize {
            detail: format!("CRI identity segment `{name}` contains disallowed delimiter"),
        });
    }
    Ok(cleaned)
}

fn pick_map_segment(
    map: &BTreeMap<String, String>,
    key: &str,
    fallback: &str,
    limits: &CriLimits,
) -> Result<String, SensorError> {
    match map.get(key) {
        Some(val) if !val.trim().is_empty() => sanitize_segment(key, val, false, limits),
        _ => Ok(fallback.to_string()),
    }
}

fn optional_map_field(
    map: &BTreeMap<String, String>,
    key: &str,
    limits: &CriLimits,
) -> Result<Option<String>, SensorError> {
    match map.get(key) {
        Some(val) if !val.trim().is_empty() => sanitize_field(key, val, false, limits).map(Some),
        _ => Ok(None),
    }
}

fn optional_map_segment(
    map: &BTreeMap<String, String>,
    key: &str,
    limits: &CriLimits,
) -> Result<Option<String>, SensorError> {
    match map.get(key) {
        Some(val) if !val.trim().is_empty() => sanitize_segment(key, val, false, limits).map(Some),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_containerd_and_crio_metadata_with_agent_handles() {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_POD_NAMESPACE.into(), "agent-prod".into());
        labels.insert(LABEL_POD_NAME.into(), "coder-pod-7".into());
        labels.insert(LABEL_CONTAINER_NAME.into(), "runner".into());

        let mut annotations = BTreeMap::new();
        annotations.insert(ANN_AGENT_SESSION.into(), "sess-k8s-42".into());
        annotations.insert(ANN_AGENT_NAME.into(), "codex-runner".into());
        annotations.insert(
            ANN_SPIFFE_ID.into(),
            "spiffe://cluster.local/ns/agent-prod/sa/runner".into(),
        );
        annotations.insert(ANN_EXEC_ID.into(), "exec-99".into());

        let raw = CriRawContainerMeta {
            runtime: CriRuntimeKind::Containerd,
            cluster: "us-east-1".into(),
            container_id: "0123456789abcdef0123456789abcdef".into(),
            image_digest: "sha256:deadbeef".into(),
            runtime_class: "gvisor".into(),
            cgroup_path: "/kubepods.slice/kubepods-burstable.slice/cri-containerd-0123.scope"
                .into(),
            cgroup_inode: 88_123,
            labels,
            annotations,
        };

        let limits = CriLimits {
            max_field_bytes: 512,
            max_annotations: 128,
        };
        let norm = normalize_cri_metadata(&raw, &limits).unwrap();
        assert_eq!(
            norm.canonical_device_id(),
            "us-east-1/agent-prod/coder-pod-7"
        );
        assert_eq!(norm.canonical_session_id(), "sess-k8s-42:exec:exec-99");
        assert_eq!(norm.agent_name, "codex-runner");
        assert_eq!(norm.cgroup_inode, 88_123);
    }

    #[test]
    fn rejects_empty_container_id_control_chars_and_delimiters() {
        let limits = CriLimits {
            max_field_bytes: 512,
            max_annotations: 128,
        };
        let bad = CriRawContainerMeta {
            runtime: CriRuntimeKind::CriO,
            cluster: "prod".into(),
            container_id: "   ".into(),
            image_digest: String::new(),
            runtime_class: "runc".into(),
            cgroup_path: "/kubepods".into(),
            cgroup_inode: 1,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        };
        assert!(matches!(
            normalize_cri_metadata(&bad, &limits),
            Err(SensorError::CriNormalize { .. })
        ));

        let mut ansi = bad.clone();
        ansi.container_id = "cid\x1b[31m".into();
        assert!(matches!(
            normalize_cri_metadata(&ansi, &limits),
            Err(SensorError::CriNormalize { .. })
        ));

        let mut slash = bad.clone();
        slash.container_id = "abc123".into();
        slash
            .labels
            .insert(LABEL_POD_NAME.into(), "evil/pod:x".into());
        assert!(matches!(
            normalize_cri_metadata(&slash, &limits),
            Err(SensorError::CriNormalize { .. })
        ));

        let mut sess_inject = bad;
        sess_inject.container_id = "abc123".into();
        sess_inject
            .annotations
            .insert(ANN_AGENT_SESSION.into(), "sess:exec:hijack".into());
        assert!(matches!(
            normalize_cri_metadata(&sess_inject, &limits),
            Err(SensorError::CriNormalize { .. })
        ));
    }
}
