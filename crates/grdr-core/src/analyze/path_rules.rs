// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Protected path class matching, NTFS ADS extraction, and Windows path checks (`D-10`).

use serde::{Deserialize, Serialize};

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

/// Maps normalized path (without NTFS ADS stream) to guardrails protected path classes.
#[must_use]
pub fn classify_protected_path(path: &str) -> Vec<ProtectedPathClass> {
    let lower = path.to_ascii_lowercase();
    let mut classes = Vec::new();

    if contains_any(
        &lower,
        &[
            ".claude/",
            ".claude.json",
            ".cursor/",
            ".codex/",
            ".gemini/",
            ".vscode/settings.json",
            ".vscode/tasks.json",
            ".git/hooks/",
            ".git/config",
        ],
    ) || ends_with_any_segment(
        &lower,
        &[
            ".claude",
            ".cursor",
            ".codex",
            ".gemini",
            ".git/hooks",
            "agents.md",
            "claude.md",
        ],
    ) {
        classes.push(ProtectedPathClass::AgentControl);
    }

    if contains_any(&lower, &["grdr-data/", "security/", "/etc/guardrails/"]) {
        classes.push(ProtectedPathClass::GrdrControl);
    }

    if contains_any(
        &lower,
        &[
            "monitoring",
            "alertmanager",
            "prometheus",
            "siem-forwarder",
            "auditd",
        ],
    ) {
        classes.push(ProtectedPathClass::MonitoringConfig);
    }

    if contains_any(
        &lower,
        &[
            ".aws/credentials",
            ".aws/config",
            ".config/gh/",
            ".docker/config.json",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".kube/config",
            ".env.production",
        ],
    ) || has_env_file_segment(&lower)
    {
        classes.push(ProtectedPathClass::CredStore);
    }

    if contains_any(
        &lower,
        &[
            ".ssh/id_",
            ".ssh/",
            ".gnupg/",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            ".pem",
            ".p12",
            ".pfx",
        ],
    ) {
        classes.push(ProtectedPathClass::PrivateKey);
    }

    if contains_any(
        &lower,
        &[
            ".claude/projects/",
            ".claude/history.jsonl",
            ".cursor/user/",
            ".codex/sessions/",
        ],
    ) {
        classes.push(ProtectedPathClass::AgentStore);
    }

    if contains_any(
        &lower,
        &[
            "google/chrome/",
            "chromium/",
            "mozilla/firefox/",
            "cookies",
            "login data",
        ],
    ) {
        classes.push(ProtectedPathClass::BrowserStore);
    }

    if contains_any(
        &lower,
        &[
            "/launchagents/",
            "/launchdaemons/",
            "systemd/user/",
            "/etc/systemd/",
            "authorized_keys",
            "/cron.d/",
            "/etc/cron",
            "/var/spool/cron/",
            "/etc/xdg/autostart/",
            "/etc/profile.d/",
            "/etc/rc.local",
            ".config/autostart/",
            "/start menu/programs/startup/",
        ],
    ) || lower == "/etc/profile.d"
        || ends_with_any_segment(
            &lower,
            &[
                ".config/autostart",
                ".bashrc",
                ".zshrc",
                ".profile",
                ".bash_profile",
                ".zprofile",
            ],
        )
    {
        classes.push(ProtectedPathClass::Autorun);
    }

    if lower == "/tmp"
        || lower.starts_with("/tmp/")
        || lower == "/private/tmp"
        || lower == "/var/tmp"
        || contains_any(
            &lower,
            &[
                "/private/tmp/",
                "/private/var/folders/",
                "/var/tmp/",
                "appdata/local/temp/",
            ],
        )
    {
        classes.push(ProtectedPathClass::SessionTmp);
    }

    classes
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

fn ends_with_any_segment(path: &str, segs: &[&str]) -> bool {
    segs.iter().any(|seg| {
        path == *seg
            || path
                .strip_suffix(seg)
                .is_some_and(|prefix| prefix.ends_with('/'))
    })
}

fn has_env_file_segment(lower: &str) -> bool {
    lower
        .split('/')
        .any(|seg| seg == ".env" || seg.starts_with(".env."))
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}
