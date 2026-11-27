// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Causal session graph, constraint carry-over, lineage breaks, and outward P8 identity (`docs/design/06`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use grdr_crypto::{domain_sha256_digest, encode_lower_hex};
use grdr_model::{
    ActionClass, ApprovalGrade, CodedError, IdentityMode, Mode, sanitize_log_fragment,
};
use serde::{Deserialize, Serialize};

use super::lifecycle::SessionConstraints;

const MAX_GRAPH_EDGES: usize = 8_192;
const OUTWARD_PSEUDONYM_DOMAIN: &str = "grdr.session.outward.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    Session,
    Process,
    Socket,
    Credential,
    Artefact,
    ExternalSink,
    Subagent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Fork,
    Exec,
    Member,
    Bound,
    Ipc,
    Brokered,
    Artefact,
    InfluencedBy,
    ChildSession,
    Resume,
    Handoff,
    Outward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageBreakKind {
    MissingParentExec,
    PidReuseMismatch,
    OrphanedCrossSessionIpc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    pub from_id: String,
    pub from_kind: GraphNodeKind,
    pub to_id: String,
    pub to_kind: GraphNodeKind,
    pub kind: EdgeKind,
    pub grade: ApprovalGrade,
    pub observed_at_ms: u64,
    pub labels_carried: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildSessionSpawnPlan {
    pub parent_session_id: String,
    pub child_session_id: String,
    pub constraints: SessionConstraints,
    pub inherited_labels: BTreeSet<String>,
    pub edge: LineageEdge,
}

#[derive(Debug, Clone)]
pub struct ChildSpawnRequest<'a> {
    pub parent_id: &'a str,
    pub child_id: &'a str,
    pub parent_constraints: &'a SessionConstraints,
    pub parent_labels: &'a BTreeSet<String>,
    pub requested_max_depth: u8,
    pub requested_ceiling: Mode,
    pub extra_disallowed: &'a [ActionClass],
    pub grade: ApprovalGrade,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineageGraph {
    edges: Vec<LineageEdge>,
}

impl LineageGraph {
    #[must_use]
    pub fn new() -> Self {
        Self { edges: Vec::new() }
    }

    #[must_use]
    pub fn edges(&self) -> &[LineageEdge] {
        &self.edges
    }

    pub fn add_edge(&mut self, edge: LineageEdge) -> Result<(), CodedError> {
        if edge.from_id.trim().is_empty() || edge.to_id.trim().is_empty() {
            return Err(CodedError::new(
                "GRDR-SESS-0003",
                "lineage edge endpoints must not be empty",
                "Provide non-empty from_id and to_id.",
            ));
        }
        if edge.from_id == edge.to_id && edge.from_kind == edge.to_kind {
            return Err(CodedError::new(
                "GRDR-SESS-0003",
                "self-referential lineage edge rejected",
                "Ensure from_id/from_kind differs from to_id/to_kind.",
            ));
        }
        if self.edges.len() >= MAX_GRAPH_EDGES {
            return Err(CodedError::new(
                "GRDR-SESS-0002",
                "session lineage graph edge capacity limit reached",
                "Prune archived session edges before appending new lineage.",
            ));
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn spawn_child_session(
        &mut self,
        req: &ChildSpawnRequest<'_>,
    ) -> Result<ChildSessionSpawnPlan, CodedError> {
        if req.parent_id.trim().is_empty()
            || req.child_id.trim().is_empty()
            || req.parent_id == req.child_id
        {
            return Err(CodedError::new(
                "GRDR-SESS-0003",
                "child session spawn requires distinct non-empty parent and child IDs",
                "Provide valid parent_id and child_id.",
            ));
        }
        if req.parent_constraints.max_depth == 0 {
            return Err(CodedError::new(
                "GRDR-SESS-0003",
                "child session spawn exceeds parent max_depth constraint",
                "Deny nested subagent spawn or increase top-level max_depth.",
            ));
        }
        let child_constraints = req.parent_constraints.narrow_for_child(
            req.requested_max_depth,
            req.requested_ceiling,
            req.extra_disallowed,
        );
        let edge = LineageEdge {
            from_id: req.parent_id.to_owned(),
            from_kind: GraphNodeKind::Session,
            to_id: req.child_id.to_owned(),
            to_kind: GraphNodeKind::Subagent,
            kind: EdgeKind::ChildSession,
            grade: req.grade,
            observed_at_ms: req.observed_at_ms,
            labels_carried: req.parent_labels.clone(),
        };
        self.add_edge(edge.clone())?;
        Ok(ChildSessionSpawnPlan {
            parent_session_id: req.parent_id.to_owned(),
            child_session_id: req.child_id.to_owned(),
            constraints: child_constraints,
            inherited_labels: req.parent_labels.clone(),
            edge,
        })
    }

    #[must_use]
    pub fn ancestors_bounded(&self, start_id: &str, max_hops: usize) -> Vec<String> {
        self.walk_bounded(start_id, max_hops, false)
    }

    #[must_use]
    pub fn descendants_bounded(&self, start_id: &str, max_hops: usize) -> Vec<String> {
        self.walk_bounded(start_id, max_hops, true)
    }

    #[must_use]
    pub fn detect_lineage_breaks(
        &self,
        known_nodes: &BTreeSet<String>,
    ) -> Vec<(String, LineageBreakKind)> {
        let mut breaks = Vec::new();
        let mut spawn_parents: BTreeMap<&str, (&str, u64)> = BTreeMap::new();
        let mut exec_times: BTreeMap<&str, u64> = BTreeMap::new();
        for edge in &self.edges {
            if matches!(edge.kind, EdgeKind::Fork | EdgeKind::Exec) {
                exec_times
                    .entry(edge.to_id.as_str())
                    .and_modify(|ts| *ts = (*ts).min(edge.observed_at_ms))
                    .or_insert(edge.observed_at_ms);
                if !known_nodes.contains(&edge.from_id) {
                    breaks.push((edge.to_id.clone(), LineageBreakKind::MissingParentExec));
                }
                if let Some((prev_parent, _)) = spawn_parents.insert(
                    edge.to_id.as_str(),
                    (edge.from_id.as_str(), edge.observed_at_ms),
                ) && prev_parent != edge.from_id
                {
                    breaks.push((edge.to_id.clone(), LineageBreakKind::PidReuseMismatch));
                }
            }
            if edge.kind == EdgeKind::Ipc
                && (!known_nodes.contains(&edge.from_id) || !known_nodes.contains(&edge.to_id))
            {
                breaks.push((
                    edge.to_id.clone(),
                    LineageBreakKind::OrphanedCrossSessionIpc,
                ));
            }
        }
        for edge in &self.edges {
            if matches!(
                edge.kind,
                EdgeKind::Fork | EdgeKind::Exec | EdgeKind::ChildSession
            ) && let Some(&parent_start) = exec_times.get(edge.from_id.as_str())
                && parent_start > edge.observed_at_ms
            {
                breaks.push((edge.to_id.clone(), LineageBreakKind::PidReuseMismatch));
            }
        }
        breaks
    }

    fn walk_bounded(&self, start_id: &str, max_hops: usize, forward: bool) -> Vec<String> {
        let mut visited = BTreeSet::new();
        let mut out = Vec::new();
        let mut queue = VecDeque::new();
        visited.insert(start_id.to_owned());
        queue.push_back((start_id.to_owned(), 0usize));

        while let Some((cur, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            for edge in &self.edges {
                let next = if forward && edge.from_id == cur {
                    Some(&edge.to_id)
                } else if !forward && edge.to_id == cur {
                    Some(&edge.from_id)
                } else {
                    None
                };
                if let Some(target) = next
                    && visited.insert(target.clone())
                {
                    out.push(target.clone());
                    queue.push_back((target.clone(), depth.saturating_add(1)));
                }
            }
        }
        out
    }
}

#[must_use]
pub fn format_outward_identity(
    mode: IdentityMode,
    raw_session_id: &str,
    tenant_salt: &str,
) -> String {
    match mode {
        IdentityMode::Named => sanitize_log_fragment(raw_session_id, raw_session_id.len()),
        IdentityMode::Pseudonymous => {
            let input = format!(
                "{}:{}:{}:{}",
                tenant_salt.len(),
                tenant_salt,
                raw_session_id.len(),
                raw_session_id
            );
            let digest = encode_lower_hex(&domain_sha256_digest(
                OUTWARD_PSEUDONYM_DOMAIN,
                input.as_bytes(),
            ));
            let prefix: String = digest.chars().take(16).collect();
            format!("ses_{prefix}")
        }
    }
}
