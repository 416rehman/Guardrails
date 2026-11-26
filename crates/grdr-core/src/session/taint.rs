// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Two-axis taint/confidentiality tracking, quarantined sub-sessions, and URL-boundary + epoch-bound declassification (`D-28`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use grdr_crypto::{constant_time_eq, sha256_hex};
use grdr_model::ActionClass;
use serde::{Deserialize, Serialize};

use crate::session::taint_validate::{
    is_sha256_hex, parse_grant_prefix_url, parse_grant_url, url_matches_prefix,
};

pub(super) const MAX_QUARANTINED_CHILDREN: usize = 256;
pub(super) const MAX_DECLASSIFICATION_GRANTS: usize = 256;
pub(super) const MAX_CONSUMED_GRANTS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityTaintAxis {
    UntrustedWeb,
    UntrustedRepo,
    UntrustedMcp,
    UntrustedPaste,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidentialityAxis {
    SecretRead,
    SensitiveConfidential,
    SensitiveSecret,
    SensitiveRegulated,
    HoneytokenTouched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnFieldSchema {
    Bool,
    Integer,
    Enum(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedReturnValue {
    Bool(bool),
    Integer(i64),
    Enum(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedSubSession {
    pub child_session_id: String,
    pub parent_session_id: String,
    pub inherited_taint_epoch: u64,
    #[serde(default)]
    pub inherited_integrity: BTreeSet<IntegrityTaintAxis>,
    #[serde(default)]
    pub inherited_confidentiality: BTreeSet<ConfidentialityAxis>,
    pub allowed_return_fields: BTreeMap<String, ReturnFieldSchema>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestDeclassificationGrant {
    pub grant_id: String,
    pub session_id: String,
    pub sink: Option<ActionClass>,
    pub content_digest_sha256: String,
    pub destination_prefix: String,
    pub issued_taint_epoch: u64,
    pub single_use: bool,
    #[serde(default)]
    pub consumed: bool,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclassificationDecision {
    VerifiedMatch,
    NoMatchingGrant,
    DigestMismatch,
    ExpiredGrant,
    InvalidDestination,
    EscalationInvalidated,
    AlreadyConsumed,
}

#[derive(Clone, PartialEq, Eq, Default, Serialize)]
pub struct TwoAxisTaintState {
    pub integrity: BTreeSet<IntegrityTaintAxis>,
    pub confidentiality: BTreeSet<ConfidentialityAxis>,
    pub taint_epoch: u64,
    pub quarantined_children: BTreeMap<String, QuarantinedSubSession>,
    pub declassification_grants: VecDeque<DigestDeclassificationGrant>,
    pub consumed_grant_ids: BTreeSet<String>,
    pub consumed_grant_order: VecDeque<String>,
}

impl core::fmt::Debug for DigestDeclassificationGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DigestDeclassificationGrant")
            .field("grant_id", &self.grant_id)
            .field("session_id", &self.session_id)
            .field("sink", &self.sink)
            .field("destination_prefix_len", &self.destination_prefix.len())
            .field("issued_taint_epoch", &self.issued_taint_epoch)
            .field("single_use", &self.single_use)
            .field("consumed", &self.consumed)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl core::fmt::Debug for TwoAxisTaintState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TwoAxisTaintState")
            .field("integrity_count", &self.integrity.len())
            .field("confidentiality_count", &self.confidentiality.len())
            .field("taint_epoch", &self.taint_epoch)
            .field(
                "quarantined_children_count",
                &self.quarantined_children.len(),
            )
            .field("grants_count", &self.declassification_grants.len())
            .field("consumed_grant_ids_count", &self.consumed_grant_ids.len())
            .finish()
    }
}

impl QuarantinedSubSession {
    /// Validates sub-session return strictly for exact key completeness and schema conformance (P8-redacted errors).
    pub fn validate_typed_return(
        &self,
        values: &BTreeMap<String, TypedReturnValue>,
    ) -> Result<(), &'static str> {
        for req_key in self.allowed_return_fields.keys() {
            if !values.contains_key(req_key) {
                return Err("sub-session return omitted a declared schema field");
            }
        }
        for (k, v) in values {
            let schema = self
                .allowed_return_fields
                .get(k)
                .ok_or("undeclared sub-session return field rejected")?;
            match (schema, v) {
                (ReturnFieldSchema::Bool, TypedReturnValue::Bool(_))
                | (ReturnFieldSchema::Integer, TypedReturnValue::Integer(_)) => {}
                (ReturnFieldSchema::Enum(allowed), TypedReturnValue::Enum(chosen)) => {
                    if !allowed.iter().any(|a| a == chosen) {
                        return Err("sub-session enum return outside declared allowed set");
                    }
                }
                _ => {
                    return Err("sub-session return value type mismatched schema");
                }
            }
        }
        Ok(())
    }

    /// Quarantined sub-sessions enforce a strict read-only (`FileRead`) allowlist.
    #[must_use]
    pub const fn permits_action(&self, action: ActionClass) -> bool {
        matches!(action, ActionClass::FileRead)
    }
}

impl TwoAxisTaintState {
    /// Records an integrity taint axis label and bumps `taint_epoch` (voiding prior declassification grants).
    pub fn record_integrity_taint(&mut self, taint: IntegrityTaintAxis) {
        self.integrity.insert(taint);
        self.taint_epoch = self.taint_epoch.saturating_add(1);
    }

    /// Records a confidentiality label and bumps `taint_epoch` (voiding prior declassification grants).
    pub fn record_confidentiality(&mut self, label: ConfidentialityAxis) {
        self.confidentiality.insert(label);
        self.taint_epoch = self.taint_epoch.saturating_add(1);
    }

    /// Spawns a non-overwriting quarantined sub-session inheriting parent taint state.
    pub fn spawn_quarantined_child(
        &mut self,
        parent_session_id: &str,
        child_session_id: &str,
        allowed_return_fields: BTreeMap<String, ReturnFieldSchema>,
    ) -> Result<QuarantinedSubSession, &'static str> {
        let p = parent_session_id.trim();
        let c = child_session_id.trim();
        if p.is_empty()
            || c.is_empty()
            || p == c
            || p.chars().any(char::is_control)
            || c.chars().any(char::is_control)
        {
            return Err("invalid quarantined child/parent session identifier");
        }
        if self.quarantined_children.contains_key(c) {
            return Err("quarantined child session already exists; schema overwrite refused");
        }
        if self.quarantined_children.len() >= MAX_QUARANTINED_CHILDREN {
            return Err("quarantined sub-session capacity reached");
        }
        let sub = QuarantinedSubSession {
            child_session_id: c.to_owned(),
            parent_session_id: p.to_owned(),
            inherited_taint_epoch: self.taint_epoch,
            inherited_integrity: self.integrity.clone(),
            inherited_confidentiality: self.confidentiality.clone(),
            allowed_return_fields,
        };
        self.quarantined_children.insert(c.to_owned(), sub.clone());
        Ok(sub)
    }

    /// Registers a bounded, sink-scoped, URL-validated, epoch-bound SHA-256 declassification grant.
    pub fn issue_declassification_grant(
        &mut self,
        mut grant: DigestDeclassificationGrant,
    ) -> Result<(), &'static str> {
        let gid = grant.grant_id.trim().to_owned();
        let sid = grant.session_id.trim().to_owned();
        if gid.is_empty()
            || sid.is_empty()
            || gid.chars().any(char::is_control)
            || sid.chars().any(char::is_control)
        {
            return Err("declassification grant requires valid grant_id and session_id");
        }
        if self.consumed_grant_ids.contains(&gid)
            || self
                .declassification_grants
                .iter()
                .any(|g| g.grant_id == gid)
        {
            return Err("duplicate or already-consumed declassification grant_id rejected");
        }
        if grant.sink.is_none() {
            return Err("declassification grant requires explicit non-wildcard sink");
        }
        if grant.issued_taint_epoch != self.taint_epoch {
            return Err("declassification grant epoch must equal current taint_epoch");
        }
        if !is_sha256_hex(&grant.content_digest_sha256) {
            return Err("declassification grant requires 64-hex SHA-256 digest");
        }
        if parse_grant_prefix_url(&grant.destination_prefix).is_none() {
            return Err(
                "declassification grant requires canonical public URL prefix without query/userinfo",
            );
        }
        grant.grant_id = gid;
        grant.session_id = sid;
        if self.declassification_grants.len() >= MAX_DECLASSIFICATION_GRANTS {
            self.declassification_grants.pop_front();
        }
        self.declassification_grants.push_back(grant);
        Ok(())
    }

    /// Evaluates sink-scoped digest-bound declassification (`ActionClass` required, no wildcard matching).
    #[must_use]
    pub fn verify_egress_declassification(
        &self,
        session_id: &str,
        sink: ActionClass,
        payload_bytes: &[u8],
        destination: &str,
        now_ms: i64,
    ) -> DeclassificationDecision {
        self.verify_egress_declassification_for_sink(
            session_id,
            Some(sink),
            payload_bytes,
            destination,
            now_ms,
        )
    }

    /// Sink-scoped verification and single-use consumption variant.
    pub fn consume_egress_declassification(
        &mut self,
        session_id: &str,
        sink: ActionClass,
        payload_bytes: &[u8],
        destination: &str,
        now_ms: i64,
    ) -> DeclassificationDecision {
        let Some(matched_idx) =
            self.find_matching_grant_index(session_id, sink, payload_bytes, destination, now_ms)
        else {
            return self.verify_egress_declassification_for_sink(
                session_id,
                Some(sink),
                payload_bytes,
                destination,
                now_ms,
            );
        };
        if let Some(grant) = self.declassification_grants.get_mut(matched_idx)
            && grant.single_use
        {
            grant.consumed = true;
            let gid = grant.grant_id.clone();
            if self.consumed_grant_ids.insert(gid.clone()) {
                if self.consumed_grant_order.len() >= MAX_CONSUMED_GRANTS
                    && let Some(oldest) = self.consumed_grant_order.pop_front()
                {
                    self.consumed_grant_ids.remove(&oldest);
                }
                self.consumed_grant_order.push_back(gid);
            }
        }
        DeclassificationDecision::VerifiedMatch
    }

    #[must_use]
    pub fn verify_egress_declassification_for_sink(
        &self,
        session_id: &str,
        sink: Option<ActionClass>,
        payload_bytes: &[u8],
        destination: &str,
        now_ms: i64,
    ) -> DeclassificationDecision {
        let Some(req_sink) = sink else {
            return DeclassificationDecision::NoMatchingGrant;
        };
        let Some((dest_url, dest_host)) = parse_grant_url(destination) else {
            return DeclassificationDecision::InvalidDestination;
        };
        let payload_digest = sha256_hex(payload_bytes);
        let mut saw_dest = false;
        let mut saw_expired = false;
        let mut saw_escalated = false;
        let mut saw_consumed = false;

        for grant in &self.declassification_grants {
            if grant.session_id != session_id || grant.sink != Some(req_sink) {
                continue;
            }
            let Some((grant_url, grant_host)) = parse_grant_prefix_url(&grant.destination_prefix)
            else {
                continue;
            };
            if !url_matches_prefix(&grant_url, &grant_host, &dest_url, &dest_host) {
                continue;
            }
            saw_dest = true;
            if grant.issued_taint_epoch != self.taint_epoch {
                saw_escalated = true;
                continue;
            }
            if grant.consumed
                || (grant.single_use && self.consumed_grant_ids.contains(&grant.grant_id))
            {
                saw_consumed = true;
                continue;
            }
            if now_ms > grant.expires_at_ms {
                saw_expired = true;
                continue;
            }
            let expected = grant.content_digest_sha256.to_ascii_lowercase();
            if expected.len() == payload_digest.len()
                && constant_time_eq(expected.as_bytes(), payload_digest.as_bytes())
            {
                return DeclassificationDecision::VerifiedMatch;
            }
        }

        if saw_escalated {
            DeclassificationDecision::EscalationInvalidated
        } else if saw_consumed {
            DeclassificationDecision::AlreadyConsumed
        } else if saw_expired {
            DeclassificationDecision::ExpiredGrant
        } else if saw_dest {
            DeclassificationDecision::DigestMismatch
        } else {
            DeclassificationDecision::NoMatchingGrant
        }
    }

    fn find_matching_grant_index(
        &self,
        session_id: &str,
        sink: ActionClass,
        payload_bytes: &[u8],
        destination: &str,
        now_ms: i64,
    ) -> Option<usize> {
        let (dest_url, dest_host) = parse_grant_url(destination)?;
        let payload_digest = sha256_hex(payload_bytes);
        for (idx, grant) in self.declassification_grants.iter().enumerate() {
            if grant.session_id != session_id
                || grant.sink != Some(sink)
                || grant.issued_taint_epoch != self.taint_epoch
            {
                continue;
            }
            if grant.consumed
                || (grant.single_use && self.consumed_grant_ids.contains(&grant.grant_id))
            {
                continue;
            }
            if now_ms > grant.expires_at_ms {
                continue;
            }
            let Some((grant_url, grant_host)) = parse_grant_prefix_url(&grant.destination_prefix)
            else {
                continue;
            };
            if !url_matches_prefix(&grant_url, &grant_host, &dest_url, &dest_host) {
                continue;
            }
            let expected = grant.content_digest_sha256.to_ascii_lowercase();
            if expected.len() == payload_digest.len()
                && constant_time_eq(expected.as_bytes(), payload_digest.as_bytes())
            {
                return Some(idx);
            }
        }
        None
    }

    #[must_use]
    pub fn has_dual_exfil_exposure(&self) -> bool {
        !self.integrity.is_empty() && !self.confidentiality.is_empty()
    }
}
