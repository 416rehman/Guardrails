// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Protected path class matching, NTFS ADS extraction, and Windows path checks (`D-10`).

use serde::{Deserialize, Serialize};

use crate::analyze::pack_lists::{ProtectedPathCatalog, default_protected_path_catalog};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedPathClass {
    AgentControl,
    GrdrControl,
    MonitoringConfig,
    CredStore,
    PrivateKey,
    AgentStore,
    BrowserStore,
    Autorun,
    SessionTmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeCase {
    CaseSensitive,
    CaseInsensitive,
}

/// Maps normalized path (without NTFS ADS stream) to guardrails protected path classes from YAML packs.
#[must_use]
pub fn classify_protected_path(path: &str) -> Vec<ProtectedPathClass> {
    try_classify_protected_path(path).unwrap_or_else(|_| {
        vec![
            ProtectedPathClass::AgentControl,
            ProtectedPathClass::GrdrControl,
            ProtectedPathClass::CredStore,
            ProtectedPathClass::PrivateKey,
        ]
    })
}

/// Maps normalized path (without NTFS ADS stream) and reports catalog availability failures.
pub fn try_classify_protected_path(path: &str) -> Result<Vec<ProtectedPathClass>, &'static str> {
    default_protected_path_catalog().map(|catalog| catalog.classify(path))
}

/// Maps normalized path against a caller-supplied runtime `ProtectedPathCatalog`.
#[must_use]
pub fn classify_protected_path_with_catalog(
    path: &str,
    catalog: &ProtectedPathCatalog,
) -> Vec<ProtectedPathClass> {
    catalog.classify(path)
}

/// Splits an NTFS alternate data stream `:stream` from the final component of a path only.
#[must_use]
pub fn split_ntfs_ads(path: &str) -> (&str, Option<&str>) {
    let drive_floor = match path.as_bytes().get(1) {
        Some(&b':') => 2,
        _ => 0,
    };
    let last_sep = path
        .rfind(['/', '\\'])
        .map_or(0, |idx| idx.saturating_add(1));
    let search_start = drive_floor.max(last_sep);
    let Some(tail) = path.get(search_start..) else {
        return (path, None);
    };
    let Some(rel_colon) = tail.find(':') else {
        return (path, None);
    };
    let colon_idx = search_start.saturating_add(rel_colon);
    let base = path.get(..colon_idx).unwrap_or(path);
    let stream = path.get(colon_idx.saturating_add(1)..).unwrap_or("");
    if stream.is_empty() {
        (base, None)
    } else {
        (base, Some(stream))
    }
}

#[must_use]
pub(crate) fn is_windows_drive_head(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(drive) = chars.next() else {
        return false;
    };
    let Some(':') = chars.next() else {
        return false;
    };
    drive.is_ascii_alphabetic() && matches!(chars.next(), Some('/' | '\\') | None)
}

#[must_use]
pub(crate) fn contains_windows_short_name(path: &str) -> bool {
    for segment in path.split('/') {
        let base = segment.split(':').next().unwrap_or(segment);
        let stem = base.split('.').next().unwrap_or(base);
        if let Some((left, digits)) = stem.rsplit_once('~')
            && !left.is_empty()
            && !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

#[must_use]
pub(crate) fn is_tilde_user_path(path: &str) -> bool {
    path.starts_with('~') && path != "~" && !path.starts_with("~/")
}

#[must_use]
pub(crate) fn is_windows_drive_relative(path: &str) -> bool {
    let mut chars = path.chars();
    let Some(drive) = chars.next() else {
        return false;
    };
    let Some(':') = chars.next() else {
        return false;
    };
    drive.is_ascii_alphabetic() && !matches!(chars.next(), Some('/' | '\\'))
}

#[must_use]
pub(crate) fn has_unresolved_parent_escape(path: &str) -> bool {
    path == ".." || path.starts_with("../") || path == "~/.." || path.starts_with("~/../")
}

#[must_use]
pub(crate) fn path_within_workspace(path: &str, root: &str, volume_case: VolumeCase) -> bool {
    if is_tilde_user_path(path) || is_windows_drive_relative(path) {
        return false;
    }
    let is_abs_path =
        path.starts_with('/') || path.starts_with("~/") || is_windows_drive_head(path);
    if !is_abs_path {
        return !has_unresolved_parent_escape(path);
    }
    let (p_cmp, r_cmp) = if volume_case == VolumeCase::CaseInsensitive {
        (path.to_ascii_lowercase(), root.to_ascii_lowercase())
    } else {
        (path.to_owned(), root.to_owned())
    };
    if p_cmp == r_cmp {
        return true;
    }
    let Some(rest) = p_cmp.strip_prefix(&r_cmp) else {
        return false;
    };
    r_cmp.ends_with('/') || rest.starts_with('/')
}
