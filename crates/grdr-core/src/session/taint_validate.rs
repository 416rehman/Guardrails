// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Validated taint-state deserialization and declassification URL boundary verification (`D-28`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::analyze::net::{
    HostClass, HostClassifierConfig, IpExposureClass, UserinfoPresence, classify_url_or_host,
};
use crate::analyze::types::Resolution;
use crate::session::taint::{
    ConfidentialityAxis, DigestDeclassificationGrant, IntegrityTaintAxis, MAX_CONSUMED_GRANTS,
    MAX_DECLASSIFICATION_GRANTS, MAX_QUARANTINED_CHILDREN, QuarantinedSubSession,
    TwoAxisTaintState,
};

#[derive(Deserialize)]
struct RawTwoAxisTaintState {
    integrity: BTreeSet<IntegrityTaintAxis>,
    confidentiality: BTreeSet<ConfidentialityAxis>,
    taint_epoch: u64,
    quarantined_children: BTreeMap<String, QuarantinedSubSession>,
    declassification_grants: VecDeque<DigestDeclassificationGrant>,
    consumed_grant_ids: BTreeSet<String>,
    #[serde(default)]
    consumed_grant_order: Option<VecDeque<String>>,
}

impl<'de> Deserialize<'de> for TwoAxisTaintState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawTwoAxisTaintState::deserialize(deserializer)?;
        if raw.quarantined_children.len() > MAX_QUARANTINED_CHILDREN
            || raw.declassification_grants.len() > MAX_DECLASSIFICATION_GRANTS
            || raw.consumed_grant_ids.len() > MAX_CONSUMED_GRANTS
            || raw
                .consumed_grant_order
                .as_ref()
                .is_some_and(|o| o.len() > MAX_CONSUMED_GRANTS)
        {
            return Err(D::Error::custom(
                "restored taint state exceeds capacity bounds",
            ));
        }
        for (k, sub) in &raw.quarantined_children {
            if !is_clean_id(k)
                || !is_clean_id(&sub.parent_session_id)
                || !is_clean_id(&sub.child_session_id)
                || sub.parent_session_id == sub.child_session_id
                || sub.child_session_id != k.as_str()
                || sub.inherited_taint_epoch > raw.taint_epoch
            {
                return Err(D::Error::custom("invalid restored quarantined sub-session"));
            }
        }
        for cid in &raw.consumed_grant_ids {
            if !is_clean_id(cid) {
                return Err(D::Error::custom("invalid consumed grant identifier"));
            }
        }
        let mut seen_grants = BTreeSet::new();
        for g in &raw.declassification_grants {
            if !is_clean_id(&g.grant_id)
                || !is_clean_id(&g.session_id)
                || g.sink.is_none()
                || g.issued_taint_epoch > raw.taint_epoch
                || (!g.consumed && raw.consumed_grant_ids.contains(&g.grant_id))
                || !is_sha256_hex(&g.content_digest_sha256)
                || parse_grant_prefix_url(&g.destination_prefix).is_none()
                || !seen_grants.insert(g.grant_id.as_str())
            {
                return Err(D::Error::custom("invalid restored declassification grant"));
            }
        }
        let order = match raw.consumed_grant_order {
            Some(existing_order) => {
                let mut seen_order = BTreeSet::new();
                for id in &existing_order {
                    if !is_clean_id(id)
                        || !seen_order.insert(id.as_str())
                        || !raw.consumed_grant_ids.contains(id)
                    {
                        return Err(D::Error::custom(
                            "restored consumed_grant_order invariant mismatch",
                        ));
                    }
                }
                if seen_order.len() != raw.consumed_grant_ids.len() {
                    return Err(D::Error::custom(
                        "restored consumed_grant_order diverges from consumed_grant_ids",
                    ));
                }
                existing_order
            }
            None => raw.consumed_grant_ids.iter().cloned().collect(),
        };
        Ok(Self {
            integrity: raw.integrity,
            confidentiality: raw.confidentiality,
            taint_epoch: raw.taint_epoch,
            quarantined_children: raw.quarantined_children,
            declassification_grants: raw.declassification_grants,
            consumed_grant_ids: raw.consumed_grant_ids,
            consumed_grant_order: order,
        })
    }
}

pub(super) fn is_clean_id(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty() && trimmed == raw && !raw.chars().any(char::is_control)
}

pub(super) fn parse_grant_prefix_url(raw: &str) -> Option<(Url, String)> {
    let (parsed, host) = parse_grant_url(raw)?;
    if parsed.query().is_some() {
        return None;
    }
    Some((parsed, host))
}

pub(super) fn parse_grant_url(raw: &str) -> Option<(Url, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '#' | '@'))
    {
        return None;
    }
    let low = trimmed.to_ascii_lowercase();
    if [
        "%2f", "%5c", "%2e", "%00", "%0d", "%0a", "%3f", "%23", "%3b", "%40", "%25", "..;", "/../",
        "/./",
    ]
    .iter()
    .any(|bad| low.contains(bad))
        || trimmed.contains(';')
    {
        return None;
    }
    let parsed = Url::parse(trimmed).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return None;
    }
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return None;
    }
    parsed.host_str()?;
    let Resolution::Resolved(norm) =
        classify_url_or_host(trimmed, &HostClassifierConfig::default())
    else {
        return None;
    };
    if norm.userinfo == UserinfoPresence::Present
        || norm.classes.contains(&HostClass::CloudMetadata)
        || matches!(
            norm.ip_exposure,
            Some(
                IpExposureClass::Loopback
                    | IpExposureClass::CloudMetadataLinkLocal
                    | IpExposureClass::PrivateRfc1918
            )
        )
    {
        return None;
    }
    Some((parsed, norm.canonical_host))
}

pub(super) fn url_matches_prefix(
    grant: &Url,
    grant_host: &str,
    dest: &Url,
    dest_host: &str,
) -> bool {
    if grant.scheme() != dest.scheme()
        || !grant_host.eq_ignore_ascii_case(dest_host)
        || grant.port_or_known_default() != dest.port_or_known_default()
        || grant.query() != dest.query()
    {
        return false;
    }
    let g_path = grant.path().trim_end_matches('/');
    if g_path.is_empty() {
        return true;
    }
    let d_path = dest.path().trim_end_matches('/');
    d_path == g_path || d_path.starts_with(&format!("{g_path}/"))
}

pub(super) fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}
