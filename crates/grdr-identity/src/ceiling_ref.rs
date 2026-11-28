// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use crate::IdentityError;
use crate::broker_types::{Ceiling, CredentialClass};

#[derive(Debug, Clone, Copy)]
pub struct CeilingProbe<'a> {
    pub class: CredentialClass,
    pub account_id: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub depth: u32,
}

#[must_use]
pub fn reference_intersect_ceilings(parent: &Ceiling, child: &Ceiling) -> Ceiling {
    let allowed_classes: BTreeSet<CredentialClass> = parent
        .allowed_classes
        .iter()
        .filter(|cls| child.allowed_classes.contains(cls))
        .copied()
        .collect();
    let allowed_accounts: BTreeSet<String> = parent
        .allowed_accounts
        .iter()
        .filter(|acc| child.allowed_accounts.contains(*acc))
        .cloned()
        .collect();
    let allowed_actions: BTreeSet<String> = parent
        .allowed_actions
        .iter()
        .filter(|act| child.allowed_actions.contains(*act))
        .cloned()
        .collect();

    let mut allowed_resource_prefixes = BTreeSet::new();
    for p_pref in &parent.allowed_resource_prefixes {
        for c_pref in &child.allowed_resource_prefixes {
            if reference_prefix_allows(p_pref, c_pref) {
                allowed_resource_prefixes.insert(c_pref.clone());
            } else if reference_prefix_allows(c_pref, p_pref) {
                allowed_resource_prefixes.insert(p_pref.clone());
            }
        }
    }

    Ceiling {
        allowed_classes,
        allowed_accounts,
        allowed_actions,
        allowed_resource_prefixes: allowed_resource_prefixes.into_iter().collect(),
        max_ttl_secs: parent.max_ttl_secs.min(child.max_ttl_secs),
        max_depth: parent.max_depth.min(child.max_depth),
    }
}

#[must_use]
pub fn reference_permits(
    ceiling: &Ceiling,
    class: CredentialClass,
    account_id: &str,
    action: &str,
    resource: &str,
    depth: u32,
) -> bool {
    depth <= ceiling.max_depth
        && ceiling.allowed_classes.contains(&class)
        && ceiling.allowed_accounts.contains(account_id)
        && ceiling.allowed_actions.contains(action)
        && ceiling
            .allowed_resource_prefixes
            .iter()
            .any(|prefix| reference_prefix_allows(prefix, resource))
}

#[must_use]
pub fn is_safe_resource_string(resource: &str) -> bool {
    if resource.is_empty()
        || resource.contains('\\')
        || resource
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
    {
        return false;
    }
    let lower = resource.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("..;")
        || lower.contains(";..")
    {
        return false;
    }
    if let Some((_, after_scheme)) = resource.split_once("://") {
        let raw_before_qf = after_scheme.split(['?', '#']).next().unwrap_or("");
        if let Some((_, raw_path)) = raw_before_qf.split_once('/')
            && raw_path
                .split('/')
                .any(|seg| seg == ".." || seg == "." || seg.starts_with("..;") || seg == ";")
        {
            return false;
        }
        let Ok(url) = url::Url::parse(resource) else {
            return false;
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url
                .host_str()
                .is_none_or(|h| h.trim_end_matches('.').is_empty())
        {
            return false;
        }
        return !url
            .path()
            .split('/')
            .any(|seg| seg == ".." || seg == "." || seg.starts_with("..;") || seg == ";");
    }
    !resource
        .split(['/', '?', '#'])
        .any(|seg| seg == ".." || seg == "." || seg.starts_with("..;"))
}

#[must_use]
pub fn reference_prefix_allows(prefix: &str, candidate: &str) -> bool {
    if !is_safe_resource_string(prefix) || !is_safe_resource_string(candidate) {
        return false;
    }
    let prefix_is_url = prefix.contains("://");
    let cand_is_url = candidate.contains("://");
    if prefix_is_url || cand_is_url {
        if !(prefix_is_url && cand_is_url) {
            return false;
        }
        let (Ok(p_url), Ok(c_url)) = (url::Url::parse(prefix), url::Url::parse(candidate)) else {
            return false;
        };
        if !p_url.scheme().eq_ignore_ascii_case(c_url.scheme())
            || p_url.port_or_known_default() != c_url.port_or_known_default()
        {
            return false;
        }
        let p_host = p_url
            .host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
        let c_host = c_url
            .host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
        if p_host != c_host || p_host.is_none() {
            return false;
        }
        if let Some(pq) = p_url.query() {
            return c_url.path() == p_url.path() && c_url.query() == Some(pq);
        }
        if p_url.path() == "/" {
            return true;
        }
        let p_clean = p_url.path().trim_end_matches('/');
        let c_path = c_url.path();
        return c_path == p_clean || c_path.starts_with(&format!("{p_clean}/"));
    }

    if candidate == prefix {
        return true;
    }
    let Some(rest) = candidate.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with(['/', ':']) || rest.starts_with('/')
}

pub fn verify_no_widening(
    parent: &Ceiling,
    child: &Ceiling,
    candidate_intersection: &Ceiling,
    probe: &CeilingProbe<'_>,
) -> Result<(), IdentityError> {
    let ref_ceiled = reference_intersect_ceilings(parent, child);
    verify_no_widening_with_ref(parent, child, &ref_ceiled, candidate_intersection, probe)
}

pub fn verify_no_widening_with_ref(
    parent: &Ceiling,
    child: &Ceiling,
    ref_ceiled: &Ceiling,
    candidate_intersection: &Ceiling,
    probe: &CeilingProbe<'_>,
) -> Result<(), IdentityError> {
    let ref_allowed = reference_permits(
        ref_ceiled,
        probe.class,
        probe.account_id,
        probe.action,
        probe.resource,
        probe.depth,
    );
    let cand_allowed = candidate_intersection.permits(
        probe.class,
        probe.account_id,
        probe.action,
        probe.resource,
        probe.depth,
    );
    let parent_allowed = reference_permits(
        parent,
        probe.class,
        probe.account_id,
        probe.action,
        probe.resource,
        probe.depth,
    );
    let child_allowed = reference_permits(
        child,
        probe.class,
        probe.account_id,
        probe.action,
        probe.resource,
        probe.depth,
    );

    if cand_allowed != ref_allowed {
        return Err(IdentityError::ScopeExceedsCeiling(format!(
            "differential ceiling mismatch: cand={cand_allowed} ref={ref_allowed}"
        )));
    }
    if cand_allowed && (!parent_allowed || !child_allowed) {
        return Err(IdentityError::ScopeExceedsCeiling(
            "ceiling intersection widened parent or child scope".to_string(),
        ));
    }
    Ok(())
}
